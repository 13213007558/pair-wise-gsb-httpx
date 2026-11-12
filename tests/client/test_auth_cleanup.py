"""
Regression tests for the auth-flow cleanup contract.

A custom `Auth` implementation may dispatch several requests (for example
answering a `401` challenge) and release a credential lease from a generator
`finally` block. These tests pin down the cleanup guarantees that such an
auth class relies on when a failure occurs at any boundary:

* The auth generator is always closed, so its `finally` block runs and the
  lease is returned.
* Response streams are closed (`close`/`aclose`) before the auth generator
  is closed.
* No further requests are dispatched to the transport once a failure occurs.
* If closing a response stream itself raises, the original failure remains
  traceable through exception chaining, and a cancellation is never
  disguised as a successful response.

The `Client` and `AsyncClient` drivers below share a single table of
expected event orderings.
"""

from __future__ import annotations

import dataclasses
import threading
import typing

import anyio
import pytest

import httpx

URL = "http://example.org/"
TIMEOUT = 5.0


class TransportBoom(Exception):
    pass


class BodyBoom(Exception):
    pass


class HookBoom(Exception):
    pass


class NextRequestBoom(Exception):
    pass


class CloseBoom(Exception):
    pass


class SimulatedCancellation(BaseException):
    pass


@dataclasses.dataclass(frozen=True)
class Scenario:
    fail_transport_on: int | None = None
    fail_read_on: int | None = None
    fail_close_on: int | None = None
    fail_hook_on_status: int | None = None
    hook_error: type[BaseException] = HookBoom
    fail_next_request: bool = False
    redirect_on: int | None = None

    @property
    def follow_redirects(self) -> bool:
        return self.redirect_on is not None


@dataclasses.dataclass(frozen=True)
class Case:
    scenario: Scenario
    expected_events: tuple[str, ...]
    expected_error: type[BaseException] | None
    expected_context: type[BaseException] | None
    transport_calls: int


CHALLENGE_FLOW_CASES: dict[str, Case] = {
    "success": Case(
        scenario=Scenario(),
        expected_events=(
            "transport:1",
            "hook:response:401",
            "stream-close:1",
            "transport:2",
            "hook:response:200",
            "auth-finally",
            "stream-close:2",
        ),
        expected_error=None,
        expected_context=None,
        transport_calls=2,
    ),
    "transport_error_on_challenge": Case(
        scenario=Scenario(fail_transport_on=1),
        expected_events=("transport:1", "auth-finally"),
        expected_error=TransportBoom,
        expected_context=None,
        transport_calls=1,
    ),
    "challenge_body_error": Case(
        scenario=Scenario(fail_read_on=1),
        expected_events=(
            "transport:1",
            "hook:response:401",
            "stream-close:1",
            "auth-finally",
        ),
        expected_error=BodyBoom,
        expected_context=None,
        transport_calls=1,
    ),
    # The auth generator raises itself here, so its `finally` returns the
    # lease while the exception unwinds, before the client closes the stream.
    "next_request_error": Case(
        scenario=Scenario(fail_next_request=True),
        expected_events=(
            "transport:1",
            "hook:response:401",
            "auth-finally",
            "stream-close:1",
        ),
        expected_error=NextRequestBoom,
        expected_context=None,
        transport_calls=1,
    ),
    "redirect_transport_error": Case(
        scenario=Scenario(redirect_on=2, fail_transport_on=3),
        expected_events=(
            "transport:1",
            "hook:response:401",
            "stream-close:1",
            "transport:2",
            "hook:response:303",
            "stream-close:2",
            "transport:3",
            "auth-finally",
        ),
        expected_error=TransportBoom,
        expected_context=None,
        transport_calls=3,
    ),
    "response_hook_error": Case(
        scenario=Scenario(fail_hook_on_status=401),
        expected_events=(
            "transport:1",
            "hook:response:401",
            "stream-close:1",
            "auth-finally",
        ),
        expected_error=HookBoom,
        expected_context=None,
        transport_calls=1,
    ),
    "final_response_hook_error": Case(
        scenario=Scenario(fail_hook_on_status=200),
        expected_events=(
            "transport:1",
            "hook:response:401",
            "stream-close:1",
            "transport:2",
            "hook:response:200",
            "stream-close:2",
            "auth-finally",
        ),
        expected_error=HookBoom,
        expected_context=None,
        transport_calls=2,
    ),
    "final_close_error": Case(
        scenario=Scenario(fail_close_on=2),
        expected_events=(
            "transport:1",
            "hook:response:401",
            "stream-close:1",
            "transport:2",
            "hook:response:200",
            "auth-finally",
            "stream-close:2",
        ),
        expected_error=CloseBoom,
        expected_context=None,
        transport_calls=2,
    ),
    "close_error_during_hook_failure": Case(
        scenario=Scenario(fail_hook_on_status=401, fail_close_on=1),
        expected_events=(
            "transport:1",
            "hook:response:401",
            "stream-close:1",
            "auth-finally",
        ),
        expected_error=CloseBoom,
        expected_context=HookBoom,
        transport_calls=1,
    ),
    "cancellation_propagates": Case(
        scenario=Scenario(fail_hook_on_status=401, hook_error=SimulatedCancellation),
        expected_events=(
            "transport:1",
            "hook:response:401",
            "stream-close:1",
            "auth-finally",
        ),
        expected_error=SimulatedCancellation,
        expected_context=None,
        transport_calls=1,
    ),
    "cancellation_not_disguised_by_close_error": Case(
        scenario=Scenario(
            fail_hook_on_status=401,
            fail_close_on=1,
            hook_error=SimulatedCancellation,
        ),
        expected_events=(
            "transport:1",
            "hook:response:401",
            "stream-close:1",
            "auth-finally",
        ),
        expected_error=CloseBoom,
        expected_context=SimulatedCancellation,
        transport_calls=1,
    ),
}


class LeaseAuth(httpx.Auth):
    """
    A two-request auth scheme that leases a credential, answers a `401`
    challenge, and returns the lease from the generator `finally` block.
    """

    def __init__(self, events: list[str], scenario: Scenario) -> None:
        self._events = events
        self._scenario = scenario
        self.leases_acquired = 0
        self.leases_returned = 0

    def _acquire_lease(self) -> None:
        self.leases_acquired += 1

    def _return_lease(self) -> None:
        self.leases_returned += 1
        self._events.append("auth-finally")

    def _authorized(self, request: httpx.Request) -> httpx.Request:
        if self._scenario.fail_next_request:
            raise NextRequestBoom("could not build the authenticated request")
        request.headers["Authorization"] = "Bearer leased-credential"
        return request

    def sync_auth_flow(
        self, request: httpx.Request
    ) -> typing.Generator[httpx.Request, httpx.Response, None]:
        self._acquire_lease()
        try:
            response = yield request
            if response.status_code == 401:
                yield self._authorized(request)
        finally:
            self._return_lease()

    async def async_auth_flow(
        self, request: httpx.Request
    ) -> typing.AsyncGenerator[httpx.Request, httpx.Response]:
        self._acquire_lease()
        try:
            response = yield request
            if response.status_code == 401:
                yield self._authorized(request)
        finally:
            self._return_lease()


class TrackedStream(httpx.SyncByteStream, httpx.AsyncByteStream):
    """
    A response stream that records closure and fails on demand, standing in
    for a real connection-backed stream that must be closed.
    """

    def __init__(self, events: list[str], name: int, scenario: Scenario) -> None:
        self._events = events
        self._name = name
        self._scenario = scenario

    def _body(self) -> typing.Iterator[bytes]:
        yield b'{"leased": true}'
        if self._scenario.fail_read_on == self._name:
            raise BodyBoom(f"stream {self._name} failed while being read")

    def __iter__(self) -> typing.Iterator[bytes]:
        return self._body()

    async def __aiter__(self) -> typing.AsyncIterator[bytes]:
        for chunk in self._body():
            yield chunk

    def _record_close(self) -> None:
        self._events.append(f"stream-close:{self._name}")
        if self._scenario.fail_close_on == self._name:
            raise CloseBoom(f"stream {self._name} failed while closing")

    def close(self) -> None:
        self._record_close()

    async def aclose(self) -> None:
        self._record_close()


class BarrierTransport(httpx.BaseTransport, httpx.AsyncBaseTransport):
    """
    An in-memory transport that records call ordering, signals an event
    barrier on each call, and injects the failures described by `scenario`.
    """

    def __init__(self, events: list[str], scenario: Scenario) -> None:
        self._events = events
        self._scenario = scenario
        self.calls = 0
        self.entered: list[threading.Event] = []

    def _next_response(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        call = self.calls
        self._events.append(f"transport:{call}")
        entered = threading.Event()
        entered.set()
        self.entered.append(entered)

        if self._scenario.fail_transport_on == call:
            raise TransportBoom(f"transport call {call} failed")
        if self._scenario.redirect_on == call:
            status, headers = 303, {"location": "/final"}
        elif call == 1:
            status, headers = 401, {}
        else:
            status, headers = 200, {}

        stream = TrackedStream(self._events, call, self._scenario)
        return httpx.Response(status, headers=headers, stream=stream)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        return self._next_response(request)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return self._next_response(request)


def check_case(
    case: Case,
    events: list[str],
    transport: BarrierTransport,
    auth: LeaseAuth,
    exc: BaseException | None,
) -> None:
    if case.expected_error is None:
        assert exc is None
    else:
        assert isinstance(exc, case.expected_error)
        if case.expected_context is not None:
            assert isinstance(exc.__context__, case.expected_context)
    assert events == list(case.expected_events)
    assert transport.calls == case.transport_calls
    assert auth.leases_acquired == 1
    assert auth.leases_returned == 1


@pytest.mark.parametrize("case_name", sorted(CHALLENGE_FLOW_CASES))
def test_sync_auth_cleanup_contract(case_name: str) -> None:
    case = CHALLENGE_FLOW_CASES[case_name]
    events: list[str] = []
    transport = BarrierTransport(events, case.scenario)
    auth = LeaseAuth(events, case.scenario)

    def on_response(response: httpx.Response) -> None:
        events.append(f"hook:response:{response.status_code}")
        if case.scenario.fail_hook_on_status == response.status_code:
            raise case.scenario.hook_error("response hook failed")

    exc: BaseException | None = None
    with httpx.Client(
        transport=transport,
        auth=auth,
        event_hooks={"response": [on_response]},
        follow_redirects=case.scenario.follow_redirects,
    ) as client:
        try:
            response = client.get(URL)
        except BaseException as raised:  # noqa: BLE001
            exc = raised
        else:
            assert response.status_code == 200
            assert response.is_closed

    check_case(case, events, transport, auth, exc)


@pytest.mark.anyio
@pytest.mark.parametrize("case_name", sorted(CHALLENGE_FLOW_CASES))
async def test_async_auth_cleanup_contract(case_name: str) -> None:
    case = CHALLENGE_FLOW_CASES[case_name]
    events: list[str] = []
    transport = BarrierTransport(events, case.scenario)
    auth = LeaseAuth(events, case.scenario)

    async def on_response(response: httpx.Response) -> None:
        events.append(f"hook:response:{response.status_code}")
        if case.scenario.fail_hook_on_status == response.status_code:
            raise case.scenario.hook_error("response hook failed")

    exc: BaseException | None = None
    async with httpx.AsyncClient(
        transport=transport,
        auth=auth,
        event_hooks={"response": [on_response]},
        follow_redirects=case.scenario.follow_redirects,
    ) as client:
        try:
            response = await client.get(URL)
        except BaseException as raised:  # noqa: BLE001
            exc = raised
        else:
            assert response.status_code == 200
            assert response.is_closed

    check_case(case, events, transport, auth, exc)


class BlockingTransport(httpx.BaseTransport, httpx.AsyncBaseTransport):
    """
    A transport that blocks its first call behind an event barrier, so that
    tests can observe a request in-flight before failing it. Every wait has
    a short timeout as a fail-safe.
    """

    def __init__(
        self,
        events: list[str],
        entered: typing.Any,
        release: typing.Any,
    ) -> None:
        self._events = events
        self._entered = entered
        self._release = release
        self.calls = 0

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        self._events.append(f"transport:{self.calls}")
        self._entered.set()
        if not self._release.wait(timeout=TIMEOUT):
            raise TransportBoom("timed out waiting for the release barrier")
        raise TransportBoom("request failed while blocked in the transport")

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        self._events.append(f"transport:{self.calls}")
        self._entered.set()
        with anyio.fail_after(TIMEOUT):
            await self._release.wait()
        raise TransportBoom("request failed while blocked in the transport")


def test_sync_transport_failure_while_blocked() -> None:
    events: list[str] = []
    entered = threading.Event()
    release = threading.Event()
    transport = BlockingTransport(events, entered, release)
    auth = LeaseAuth(events, Scenario())
    outcome: list[BaseException] = []

    def send_request() -> None:
        with httpx.Client(transport=transport, auth=auth) as client:
            try:
                client.get(URL)
            except TransportBoom as raised:
                outcome.append(raised)

    worker = threading.Thread(target=send_request)
    worker.start()
    try:
        assert entered.wait(timeout=TIMEOUT)
        release.set()
        worker.join(timeout=TIMEOUT)
        assert not worker.is_alive()
    finally:
        release.set()
        worker.join(timeout=TIMEOUT)

    assert len(outcome) == 1
    assert events == ["transport:1", "auth-finally"]
    assert transport.calls == 1
    assert auth.leases_returned == 1


@pytest.mark.anyio
async def test_async_cancellation_completes_auth_cleanup() -> None:
    events: list[str] = []
    entered = anyio.Event()
    release = anyio.Event()
    transport = BlockingTransport(events, entered, release)
    auth = LeaseAuth(events, Scenario())

    async with httpx.AsyncClient(transport=transport, auth=auth) as client:
        with anyio.fail_after(TIMEOUT):
            async with anyio.create_task_group() as task_group:

                async def send_request() -> None:
                    try:
                        await client.get(URL)
                    except anyio.get_cancelled_exc_class():
                        events.append("request-cancelled")
                        raise

                task_group.start_soon(send_request)
                await entered.wait()
                task_group.cancel_scope.cancel()

    assert events == ["transport:1", "auth-finally", "request-cancelled"]
    assert transport.calls == 1
    assert auth.leases_acquired == 1
    assert auth.leases_returned == 1
