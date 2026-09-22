from __future__ import annotations

import contextlib
import contextvars
import ipaddress
import queue
import socket
import ssl
import threading
import time
import typing

import anyio
import httpcore

current_timeout_budget: contextvars.ContextVar[TimeoutBudget | None] = (
    contextvars.ContextVar("timeout_budget", default=None)
)

SOCKET_OPTION = httpcore.SOCKET_OPTION


class TimeoutBudget:
    def __init__(self, timeouts: dict[str, float | None]) -> None:
        self._timeouts = dict(timeouts)
        self._start = time.monotonic()
        self._phase_starts: dict[str, float] = {}

    def begin(self, phase: str) -> None:
        self._phase_starts[phase] = time.monotonic()

    def begin_connect_after_pool(self) -> None:
        pool_start = self._phase_starts.get("pool")
        connect_pool_start = self._phase_starts.get("connect_for_pool")
        if pool_start is None or connect_pool_start != pool_start:
            self.begin("connect")
            if pool_start is not None:
                self._phase_starts["connect_for_pool"] = pool_start

    def remaining(
        self,
        phase: str,
        timeout: float | None = None,
        *,
        parent_phase: str | None = None,
        parent_timeout: float | None = None,
    ) -> float | None:
        total = self._timeouts.get("total")
        values: list[float] = []
        if total is not None:
            values.append(max(0.0, self._start + total - time.monotonic()))

        if timeout is not None:
            phase_start = self._phase_starts.get(phase, self._start)
            values.append(max(0.0, phase_start + timeout - time.monotonic()))

        if parent_phase is not None and parent_timeout is not None:
            phase_start = self._phase_starts.get(parent_phase, self._start)
            values.append(max(0.0, phase_start + parent_timeout - time.monotonic()))

        return min(values) if values else None

    @contextlib.contextmanager
    def activate(self) -> typing.Iterator[TimeoutBudget]:
        token = current_timeout_budget.set(self)
        try:
            yield self
        finally:
            current_timeout_budget.reset(token)

    @staticmethod
    def current() -> TimeoutBudget | None:
        return current_timeout_budget.get()


@contextlib.contextmanager
def budget_context(
    budget: TimeoutBudget | None,
) -> typing.Iterator[None]:
    if budget is None:
        yield
    else:
        with budget.activate():
            yield


class TimeoutValues(dict[str, float | None]):
    def __init__(self, budget: TimeoutBudget) -> None:
        super().__init__()
        self._budget = budget
        self.update(budget._timeouts)

    def get(self, key: typing.Any, default: typing.Any = None) -> typing.Any:
        if key == "pool":
            self._budget.begin("pool")
            return self._budget.remaining("pool", super().get("pool"))
        return super().get(key, default)


def _is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def _resolved_addresses(host: str, port: int) -> list[tuple[str, int]]:
    addresses = socket.getaddrinfo(
        host, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
    )
    return [(str(item[4][0]), int(item[4][1])) for item in addresses]


class BudgetSyncStream(httpcore.NetworkStream):
    def __init__(
        self,
        stream: httpcore.NetworkStream,
        budget: TimeoutBudget,
    ) -> None:
        self._stream = stream
        self._budget = budget

    def _budget_for(self, phase: str) -> TimeoutBudget:
        budget = TimeoutBudget.current() or self._budget
        budget.begin(phase)
        return budget

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        budget = self._budget_for("read")
        configured = budget._timeouts["read"]
        return self._stream.read(max_bytes, budget.remaining("read", configured))

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        budget = self._budget_for("write")
        configured = budget._timeouts["write"]
        self._stream.write(buffer, budget.remaining("write", configured))

    def close(self) -> None:
        self._stream.close()

    def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.NetworkStream:
        budget = self._budget_for("tls")
        configured = budget._timeouts["connect"]
        tls_timeout = budget.remaining(
            "tls",
            configured,
            parent_phase="connect",
            parent_timeout=configured,
        )
        stream = self._stream.start_tls(
            ssl_context,
            server_hostname=server_hostname,
            timeout=tls_timeout,
        )
        return BudgetSyncStream(stream, budget)

    def get_extra_info(self, info: str) -> typing.Any:
        return self._stream.get_extra_info(info)


class BudgetSyncBackend(httpcore.NetworkBackend):
    def __init__(self) -> None:
        import httpcore

        self._backend = httpcore.SyncBackend()

    def _tcp_addresses(
        self, host: str, port: int, timeout: float | None
    ) -> list[tuple[str, int]]:
        budget = TimeoutBudget.current()
        if _is_ip_address(host):
            return [(host.strip("[]"), port)]
        if budget is None:  # pragma: no cover
            return [(host, port)]

        budget.begin("dns")
        dns_timeout = budget.remaining(
            "dns",
            budget._timeouts["dns"],
            parent_phase="connect",
            parent_timeout=budget._timeouts["connect"],
        )
        result: queue.Queue[tuple[OSError | None, list[tuple[str, int]]]] = (
            queue.Queue()
        )

        def resolve() -> None:
            try:
                result.put((None, _resolved_addresses(host, port)))
            except OSError as exc:
                result.put((exc, []))

        thread = threading.Thread(target=resolve, daemon=True)
        thread.start()
        try:
            exc, addresses = result.get(timeout=dns_timeout)
        except queue.Empty:
            import httpcore

            raise httpcore.ConnectTimeout("Timed out while resolving hostname")
        if exc is not None:
            import httpcore

            raise httpcore.ConnectError(str(exc)) from exc
        if not addresses:
            import httpcore

            raise httpcore.ConnectError("No DNS addresses were returned.")
        return addresses

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: typing.Iterable[SOCKET_OPTION] | None = None,
    ) -> httpcore.NetworkStream:
        import httpcore

        budget = TimeoutBudget.current()
        if budget is None:  # pragma: no cover
            stream = self._backend.connect_tcp(host, port, timeout)
            return stream

        budget.begin_connect_after_pool()
        addresses = self._tcp_addresses(host, port, timeout)
        last_exc: Exception | None = None
        for address_host, address_port in addresses:
            try:
                connect_timeout = budget.remaining(
                    "connect", budget._timeouts["connect"]
                )
                stream = self._backend.connect_tcp(
                    address_host,
                    address_port,
                    connect_timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
                return BudgetSyncStream(stream, budget)
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last_exc = exc
        assert last_exc is not None  # pragma: no cover
        raise last_exc

    def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: typing.Iterable[SOCKET_OPTION] | None = None,
    ) -> httpcore.NetworkStream:
        budget = TimeoutBudget.current()
        if budget is not None:
            budget.begin_connect_after_pool()
            timeout = budget.remaining("connect", budget._timeouts["connect"])
        stream = self._backend.connect_unix_socket(
            path, timeout=timeout, socket_options=socket_options
        )
        if budget is None:  # pragma: no cover
            return stream
        return BudgetSyncStream(stream, budget)

    def sleep(self, seconds: float) -> None:
        self._backend.sleep(seconds)


class BudgetAsyncStream(httpcore.AsyncNetworkStream):
    def __init__(
        self,
        stream: httpcore.AsyncNetworkStream,
        budget: TimeoutBudget,
    ) -> None:
        self._stream = stream
        self._budget = budget

    def _budget_for(self, phase: str) -> TimeoutBudget:
        budget = TimeoutBudget.current() or self._budget
        budget.begin(phase)
        return budget

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        budget = self._budget_for("read")
        configured = budget._timeouts["read"]
        return await self._stream.read(max_bytes, budget.remaining("read", configured))

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        budget = self._budget_for("write")
        configured = budget._timeouts["write"]
        await self._stream.write(buffer, budget.remaining("write", configured))

    async def aclose(self) -> None:
        await self._stream.aclose()

    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.AsyncNetworkStream:
        budget = self._budget_for("tls")
        configured = budget._timeouts["connect"]
        tls_timeout = budget.remaining(
            "tls",
            configured,
            parent_phase="connect",
            parent_timeout=configured,
        )
        stream = await self._stream.start_tls(
            ssl_context,
            server_hostname=server_hostname,
            timeout=tls_timeout,
        )
        return BudgetAsyncStream(stream, budget)

    def get_extra_info(self, info: str) -> typing.Any:
        return self._stream.get_extra_info(info)


class BudgetAsyncBackend(httpcore.AsyncNetworkBackend):
    def __init__(self) -> None:
        from httpcore._backends.auto import AutoBackend

        self._backend: httpcore.AsyncNetworkBackend = AutoBackend()

    async def _tcp_addresses(self, host: str, port: int) -> list[tuple[str, int]]:
        budget = TimeoutBudget.current()
        if _is_ip_address(host):
            return [(host.strip("[]"), port)]
        if budget is None:  # pragma: no cover
            return [(host, port)]

        import httpcore

        budget.begin("dns")
        dns_timeout = budget.remaining(
            "dns",
            budget._timeouts["dns"],
            parent_phase="connect",
            parent_timeout=budget._timeouts["connect"],
        )
        try:
            with anyio.fail_after(dns_timeout):
                addresses = await anyio.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except TimeoutError:
            raise httpcore.ConnectTimeout("Timed out while resolving hostname")
        except OSError as exc:
            raise httpcore.ConnectError(str(exc))
        if not addresses:
            raise httpcore.ConnectError("No DNS addresses were returned.")
        return [(item[4][0], item[4][1]) for item in addresses]

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: typing.Iterable[SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        import httpcore

        budget = TimeoutBudget.current()
        if budget is None:  # pragma: no cover
            return await self._backend.connect_tcp(host, port, timeout)

        budget.begin_connect_after_pool()
        addresses = await self._tcp_addresses(host, port)
        last_exc: Exception | None = None
        for address_host, address_port in addresses:
            try:
                connect_timeout = budget.remaining(
                    "connect", budget._timeouts["connect"]
                )
                stream = await self._backend.connect_tcp(
                    address_host,
                    address_port,
                    connect_timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
                return BudgetAsyncStream(stream, budget)
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last_exc = exc
        assert last_exc is not None  # pragma: no cover
        raise last_exc

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: typing.Iterable[SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        budget = TimeoutBudget.current()
        if budget is not None:
            budget.begin_connect_after_pool()
            timeout = budget.remaining("connect", budget._timeouts["connect"])
        stream = await self._backend.connect_unix_socket(
            path, timeout=timeout, socket_options=socket_options
        )
        if budget is None:  # pragma: no cover
            return stream
        return BudgetAsyncStream(stream, budget)

    async def sleep(self, seconds: float) -> None:
        await self._backend.sleep(seconds)
