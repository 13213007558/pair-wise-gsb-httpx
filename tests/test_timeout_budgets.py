import pytest

import httpx
from httpx import _timeouts


class RecordingSyncStream:
    def __init__(self, backend: "RecordingSyncBackend") -> None:
        self.backend = backend
        self.response = b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n"

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        self.backend.read_timeouts.append(timeout)
        if self.response:
            chunk = self.response
            self.response = b""
            return chunk
        return b""

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self.backend.write_timeouts.append(timeout)

    def close(self) -> None:
        self.backend.closed = True

    def start_tls(
        self,
        ssl_context: object,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> "RecordingSyncStream":
        self.backend.tls_timeouts.append(timeout)
        return self

    def get_extra_info(self, info: str) -> None:
        return None


class RecordingSyncBackend:
    def __init__(self) -> None:
        self.connect_timeouts: list[float | None] = []
        self.read_timeouts: list[float | None] = []
        self.write_timeouts: list[float | None] = []
        self.tls_timeouts: list[float | None] = []
        self.closed = False

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: object = None,
    ) -> RecordingSyncStream:
        self.connect_timeouts.append(timeout)
        return RecordingSyncStream(self)

    def sleep(self, seconds: float) -> None:
        pass


def test_request_phase_budgets_are_clipped_to_total(monkeypatch):
    monkeypatch.setattr(
        _timeouts, "_resolved_addresses", lambda host, port: [("127.0.0.1", port)]
    )
    recording_backend = RecordingSyncBackend()
    network_backend = _timeouts.BudgetSyncBackend.__new__(_timeouts.BudgetSyncBackend)
    network_backend._backend = recording_backend
    timeout = httpx.Timeout(
        total=30.0, dns=2.0, connect=5.0, read=10.0, write=None, pool=5.0
    )

    transport = httpx.HTTPTransport()
    transport._pool._network_backend = network_backend
    with httpx.Client(transport=transport) as client:
        response = client.get("http://example.com/", timeout=timeout)

    assert response.status_code == 200
    assert recording_backend.connect_timeouts[0] == pytest.approx(5.0, abs=0.01)
    assert recording_backend.read_timeouts[0] == pytest.approx(10.0, abs=0.01)
    assert recording_backend.write_timeouts[0] == pytest.approx(30.0, abs=0.01)
    assert recording_backend.closed


def test_reused_stream_uses_active_budget_for_later_request():
    inner_stream = RecordingSyncStream(RecordingSyncBackend())
    first_budget = _timeouts.TimeoutBudget(
        {
            "total": 1.0,
            "dns": 1.0,
            "connect": 1.0,
            "read": 1.0,
            "write": 1.0,
            "pool": 1.0,
        }
    )
    second_budget = _timeouts.TimeoutBudget(
        {
            "total": 30.0,
            "dns": 30.0,
            "connect": 30.0,
            "read": 10.0,
            "write": None,
            "pool": 30.0,
        }
    )
    stream = _timeouts.BudgetSyncStream(inner_stream, first_budget)

    with second_budget.activate():
        stream.read(1)

    assert inner_stream.backend.read_timeouts[0] == pytest.approx(10.0, abs=0.01)


def test_tls_uses_remaining_connect_budget(monkeypatch):
    monkeypatch.setattr(
        _timeouts, "_resolved_addresses", lambda host, port: [("127.0.0.1", port)]
    )
    recording_backend = RecordingSyncBackend()
    network_backend = _timeouts.BudgetSyncBackend.__new__(_timeouts.BudgetSyncBackend)
    network_backend._backend = recording_backend
    budget = _timeouts.TimeoutBudget(
        {
            "total": 30.0,
            "dns": 2.0,
            "connect": 5.0,
            "read": 10.0,
            "write": None,
            "pool": 5.0,
        }
    )

    with budget.activate():
        stream = network_backend.connect_tcp("example.com", 443)
        tls_stream = stream.start_tls(
            ssl_context=object(), server_hostname="example.com"
        )

    assert tls_stream is not None
    assert recording_backend.tls_timeouts[0] == pytest.approx(5.0, abs=0.01)


def test_remaining_phase_budget_resets_but_keeps_total(monkeypatch):
    values = iter([0.0, 1.0, 2.0, 2.0, 2.0, 3.0, 3.0])
    monkeypatch.setattr(_timeouts.time, "monotonic", lambda: next(values))
    budget = _timeouts.TimeoutBudget(
        {
            "total": 10.0,
            "dns": 2.0,
            "connect": 5.0,
            "read": 4.0,
            "write": None,
            "pool": 6.0,
        }
    )

    budget.begin("read")
    assert budget.remaining("read", 4.0) == pytest.approx(3.0)
    budget.begin("read")
    assert budget.remaining("read", 4.0) == pytest.approx(3.0)


def test_pool_wait_is_clipped_to_total_deadline(monkeypatch):
    values = iter([0.0, 0.0, 2.0, 2.0])
    monkeypatch.setattr(_timeouts.time, "monotonic", lambda: next(values))
    budget = _timeouts.TimeoutBudget(
        {
            "total": 3.0,
            "dns": 2.0,
            "connect": 5.0,
            "read": 10.0,
            "write": None,
            "pool": 5.0,
        }
    )
    timeouts = _timeouts.TimeoutValues(budget)

    assert timeouts.get("pool") == pytest.approx(1.0)


def test_connection_retry_keeps_connect_budget_within_one_pool_wait(monkeypatch):
    times = iter([0.0, 0.0, 0.0, 0.0, 1.0, 1.0])
    monkeypatch.setattr(_timeouts.time, "monotonic", lambda: next(times))
    budget = _timeouts.TimeoutBudget(
        {
            "total": 30.0,
            "dns": 2.0,
            "connect": 5.0,
            "read": 10.0,
            "write": None,
            "pool": 5.0,
        }
    )
    timeouts = _timeouts.TimeoutValues(budget)

    assert timeouts.get("pool") == pytest.approx(5.0)
    budget._phase_starts["connect"] = 0.5
    budget._phase_starts["connect_for_pool"] = 0.0
    budget.begin_connect_after_pool()
    assert budget._phase_starts["connect"] == 0.5
    budget.begin_connect_after_pool()
    assert budget._phase_starts["connect"] == 0.5
    assert budget.remaining("connect", 5.0) == pytest.approx(4.5)


def test_redirect_requests_share_request_budget():
    seen_budgets: list[_timeouts.TimeoutBudget] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_budgets.append(request.extensions["timeout_budget"])
        if len(seen_budgets) == 1:
            return httpx.Response(302, headers={"location": "/target"})
        return httpx.Response(200)

    with httpx.Client(
        transport=httpx.MockTransport(handler), follow_redirects=True
    ) as client:
        response = client.get(
            "http://example.com/",
            timeout=httpx.Timeout(total=30.0, dns=2.0, connect=5.0, read=10.0),
        )

    assert response.status_code == 200
    assert len(seen_budgets) == 2
    assert seen_budgets[0] is seen_budgets[1]


class TimeoutSyncStream:
    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        import httpcore

        assert timeout == 0.0
        raise httpcore.ReadTimeout("Timed out")

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        raise AssertionError("write should not be called")

    def close(self) -> None:
        pass

    def get_extra_info(self, info: str) -> None:
        return None


class TimeoutAsyncStream(TimeoutSyncStream):
    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return TimeoutSyncStream.read(self, max_bytes, timeout)

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        TimeoutSyncStream.write(self, buffer, timeout)

    async def aclose(self) -> None:
        pass


def test_expired_total_reports_read_timeout_sync():
    budget = _timeouts.TimeoutBudget(
        {
            "total": 0.0,
            "dns": None,
            "connect": None,
            "read": None,
            "write": None,
            "pool": None,
        }
    )
    stream = _timeouts.BudgetSyncStream(TimeoutSyncStream(), budget)

    import httpcore

    with pytest.raises(httpcore.ReadTimeout):
        stream.read(1)


@pytest.mark.asyncio
async def test_expired_total_reports_read_timeout_async():
    import httpcore

    budget = _timeouts.TimeoutBudget(
        {
            "total": 0.0,
            "dns": None,
            "connect": None,
            "read": None,
            "write": None,
            "pool": None,
        }
    )
    stream = _timeouts.BudgetAsyncStream(TimeoutAsyncStream(), budget)

    with pytest.raises(httpcore.ReadTimeout):
        await stream.read(1)


@pytest.mark.asyncio
async def test_async_dns_uses_dns_and_total_budget(monkeypatch):
    async def getaddrinfo(host: str, port: int, type: int) -> list[object]:
        return [(0, 0, 0, "", ("127.0.0.1", port))]

    class AsyncBackend:
        async def connect_tcp(
            self,
            host: str,
            port: int,
            timeout: float | None = None,
            local_address: str | None = None,
            socket_options: object = None,
        ) -> TimeoutAsyncStream:
            connect_timeout.append(timeout)
            return TimeoutAsyncStream()

        async def connect_unix_socket(self, *args: object, **kwargs: object) -> None:
            raise AssertionError("unix sockets are not used")

        async def sleep(self, seconds: float) -> None:
            pass

    connect_timeout: list[float | None] = []
    monkeypatch.setattr(_timeouts.anyio, "getaddrinfo", getaddrinfo)
    backend = _timeouts.BudgetAsyncBackend.__new__(_timeouts.BudgetAsyncBackend)
    backend._backend = AsyncBackend()
    budget = _timeouts.TimeoutBudget(
        {
            "total": 30.0,
            "dns": 2.0,
            "connect": 5.0,
            "read": 10.0,
            "write": None,
            "pool": 5.0,
        }
    )

    with budget.activate():
        await backend.connect_tcp("example.com", 443)

    assert connect_timeout[0] == pytest.approx(5.0, abs=0.01)


def test_zero_total_times_out_during_pool_wait():
    budget = _timeouts.TimeoutBudget(
        {
            "total": 0.0,
            "dns": 0.0,
            "connect": 0.0,
            "read": 0.0,
            "write": 0.0,
            "pool": 5.0,
        }
    )
    timeouts = _timeouts.TimeoutValues(budget)

    assert timeouts.get("pool") == 0.0
