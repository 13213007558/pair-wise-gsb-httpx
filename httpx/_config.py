from __future__ import annotations

import os
import time
import typing

from ._models import Headers
from ._types import CertTypes, HeaderTypes, TimeoutTypes
from ._urls import URL

if typing.TYPE_CHECKING:
    import ssl  # pragma: no cover

__all__ = ["Limits", "Proxy", "Timeout", "create_ssl_context"]


class UnsetType:
    pass  # pragma: no cover


UNSET = UnsetType()


def create_ssl_context(
    verify: ssl.SSLContext | str | bool = True,
    cert: CertTypes | None = None,
    trust_env: bool = True,
) -> ssl.SSLContext:
    import ssl
    import warnings

    import certifi

    if verify is True:
        if trust_env and os.environ.get("SSL_CERT_FILE"):  # pragma: nocover
            ctx = ssl.create_default_context(cafile=os.environ["SSL_CERT_FILE"])
        elif trust_env and os.environ.get("SSL_CERT_DIR"):  # pragma: nocover
            ctx = ssl.create_default_context(capath=os.environ["SSL_CERT_DIR"])
        else:
            # Default case...
            ctx = ssl.create_default_context(cafile=certifi.where())
    elif verify is False:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    elif isinstance(verify, str):  # pragma: nocover
        message = (
            "`verify=<str>` is deprecated. "
            "Use `verify=ssl.create_default_context(cafile=...)` "
            "or `verify=ssl.create_default_context(capath=...)` instead."
        )
        warnings.warn(message, DeprecationWarning)
        if os.path.isdir(verify):
            return ssl.create_default_context(capath=verify)
        return ssl.create_default_context(cafile=verify)
    else:
        ctx = verify

    if cert:  # pragma: nocover
        message = (
            "`cert=...` is deprecated. Use `verify=<ssl_context>` instead,"
            "with `.load_cert_chain()` to configure the certificate chain."
        )
        warnings.warn(message, DeprecationWarning)
        if isinstance(cert, str):
            ctx.load_cert_chain(cert)
        else:
            ctx.load_cert_chain(*cert)

    return ctx


class Timeout:
    """
    Timeout configuration.

    **Usage**:

    Timeout(None)               # No timeouts.
    Timeout(5.0)                # 5s timeout on all operations.
    Timeout(None, connect=5.0)  # 5s timeout on connect, no other timeouts.
    Timeout(5.0, connect=10.0)  # 10s timeout on connect. 5s timeout elsewhere.
    Timeout(5.0, pool=None)     # No timeout on acquiring connection from pool.
                                # 5s timeout elsewhere.

    A `total` budget may also be included, bounding the entire request,
    including any redirects...

    Timeout(None, total=30.0)                      # 30s total budget.
    Timeout(None, connect=5.0, read=10.0,
            write=None, total=30.0)                # 30s total budget, with
                                                   # per-operation allowances.

    The per-operation timeouts and the `total` budget compose using
    'remaining time' semantics: each phase of a request may only consume
    its own remaining allowance, given by `min(phase, total - elapsed)`.

    The values `None`, 'unset', and `0` are distinct...

    * `None` means 'no limit' for that phase.
    * An unset phase inherits the default, if one was given.
    * `0` means the phase must complete immediately, and will
      raise a timeout if any time is spent on it.

    Contradictory configurations, such as a negative value, or a
    per-operation timeout that exceeds the `total` budget, are rejected
    with a `ValueError`.
    """

    def __init__(
        self,
        timeout: TimeoutTypes | UnsetType = UNSET,
        *,
        connect: None | float | UnsetType = UNSET,
        read: None | float | UnsetType = UNSET,
        write: None | float | UnsetType = UNSET,
        pool: None | float | UnsetType = UNSET,
        total: None | float | UnsetType = UNSET,
    ) -> None:
        if isinstance(timeout, Timeout):
            # Passed as a single explicit Timeout.
            assert connect is UNSET
            assert read is UNSET
            assert write is UNSET
            assert pool is UNSET
            assert total is UNSET
            self.connect = timeout.connect  # type: typing.Optional[float]
            self.read = timeout.read  # type: typing.Optional[float]
            self.write = timeout.write  # type: typing.Optional[float]
            self.pool = timeout.pool  # type: typing.Optional[float]
            self.total = timeout.total  # type: typing.Optional[float]
        elif isinstance(timeout, tuple):
            # Passed as a tuple.
            self.connect = timeout[0]
            self.read = timeout[1]
            self.write = None if len(timeout) < 3 else timeout[2]
            self.pool = None if len(timeout) < 4 else timeout[3]
            self.total = None if len(timeout) < 5 else timeout[4]
        elif not (
            isinstance(connect, UnsetType)
            or isinstance(read, UnsetType)
            or isinstance(write, UnsetType)
            or isinstance(pool, UnsetType)
        ):
            self.connect = connect
            self.read = read
            self.write = write
            self.pool = pool
            self.total = None if isinstance(total, UnsetType) else total
        else:
            if isinstance(timeout, UnsetType) and isinstance(total, UnsetType):
                raise ValueError(
                    "httpx.Timeout must either include a default, or set all "
                    "four parameters explicitly."
                )
            default = None if isinstance(timeout, UnsetType) else timeout
            self.connect = default if isinstance(connect, UnsetType) else connect
            self.read = default if isinstance(read, UnsetType) else read
            self.write = default if isinstance(write, UnsetType) else write
            self.pool = default if isinstance(pool, UnsetType) else pool
            self.total = None if isinstance(total, UnsetType) else total

        self._validate()

    def _validate(self) -> None:
        phases = {
            "connect": self.connect,
            "read": self.read,
            "write": self.write,
            "pool": self.pool,
            "total": self.total,
        }
        for name, value in phases.items():
            if value is not None and value < 0:
                raise ValueError(
                    f"httpx.Timeout {name} must not be negative, but got {value}."
                )
        if self.total is not None:
            for name in ("connect", "read", "write", "pool"):
                value = phases[name]
                if value is not None and value > self.total:
                    raise ValueError(
                        "httpx.Timeout is contradictory: "
                        f"{name}={value} exceeds the total budget of {self.total}."
                    )

    def as_dict(self) -> dict[str, float | None]:
        return {
            "connect": self.connect,
            "read": self.read,
            "write": self.write,
            "pool": self.pool,
        }

    def clamped(self, elapsed: float) -> dict[str, float | None]:
        """
        Return the per-phase timeouts that apply once `elapsed` seconds
        of the total budget have been consumed.

        Each phase may only consume its own remaining allowance, given by
        the smaller of its configured timeout and the remaining portion
        of the total budget. Phases configured as `None` (no limit) are
        still bounded by the remaining total budget.
        """
        phases = self.as_dict()
        if self.total is None:
            return phases
        remaining = max(self.total - elapsed, 0.0)
        return {
            name: remaining if value is None else min(value, remaining)
            for name, value in phases.items()
        }

    def __eq__(self, other: typing.Any) -> bool:
        return (
            isinstance(other, self.__class__)
            and self.connect == other.connect
            and self.read == other.read
            and self.write == other.write
            and self.pool == other.pool
            and self.total == other.total
        )

    def __repr__(self) -> str:
        class_name = self.__class__.__name__
        total = "" if self.total is None else f", total={self.total}"
        if len({self.connect, self.read, self.write, self.pool}) == 1:
            return f"{class_name}(timeout={self.connect}{total})"
        return (
            f"{class_name}(connect={self.connect}, "
            f"read={self.read}, write={self.write}, pool={self.pool}{total})"
        )


class TimeoutBudget:
    """
    Tracks consumption of a `Timeout(total=...)` budget across the phases
    of a request, including any redirects that are followed.

    A monotonic clock is used, so the budget is not affected by system
    clock changes. The budget is started once, as the request first hits
    the network, and is never reset by redirects: DNS, pool acquisition,
    connecting, TLS, reads, writes, and any redirects each consume their
    own remaining allowance of the one shared budget.

    The budget is a pure calculation over the monotonic clock. It does
    not register any timers or cancellation handlers, so there is nothing
    to leak into the connection pool on cancellation, connection reuse,
    or when a response stream is closed in the background.
    """

    def __init__(self, timeout: Timeout) -> None:
        self._timeout = timeout
        self._start: float | None = None

    @property
    def timeout(self) -> Timeout:
        return self._timeout

    def start(self) -> None:
        # Called as a request is about to hit the network. Only the first
        # call takes effect, so that every request in a redirect chain
        # shares a single budget.
        if self._start is None:
            self._start = time.monotonic()

    def reset(self) -> None:
        self._start = None

    @property
    def started(self) -> bool:
        return self._start is not None

    @property
    def elapsed(self) -> float:
        if self._start is None:
            return 0.0
        return time.monotonic() - self._start

    @property
    def remaining(self) -> float | None:
        if self._timeout.total is None:
            return None
        return max(self._timeout.total - self.elapsed, 0.0)

    @property
    def is_expired(self) -> bool:
        remaining = self.remaining
        return remaining is not None and remaining <= 0.0

    def as_dict(self) -> dict[str, float | None]:
        return self._timeout.clamped(self.elapsed)


class Limits:
    """
    Configuration for limits to various client behaviors.

    **Parameters:**

    * **max_connections** - The maximum number of concurrent connections that may be
            established.
    * **max_keepalive_connections** - Allow the connection pool to maintain
            keep-alive connections below this point. Should be less than or equal
            to `max_connections`.
    * **keepalive_expiry** - Time limit on idle keep-alive connections in seconds.
    """

    def __init__(
        self,
        *,
        max_connections: int | None = None,
        max_keepalive_connections: int | None = None,
        keepalive_expiry: float | None = 5.0,
    ) -> None:
        self.max_connections = max_connections
        self.max_keepalive_connections = max_keepalive_connections
        self.keepalive_expiry = keepalive_expiry

    def __eq__(self, other: typing.Any) -> bool:
        return (
            isinstance(other, self.__class__)
            and self.max_connections == other.max_connections
            and self.max_keepalive_connections == other.max_keepalive_connections
            and self.keepalive_expiry == other.keepalive_expiry
        )

    def __repr__(self) -> str:
        class_name = self.__class__.__name__
        return (
            f"{class_name}(max_connections={self.max_connections}, "
            f"max_keepalive_connections={self.max_keepalive_connections}, "
            f"keepalive_expiry={self.keepalive_expiry})"
        )


class Proxy:
    def __init__(
        self,
        url: URL | str,
        *,
        ssl_context: ssl.SSLContext | None = None,
        auth: tuple[str, str] | None = None,
        headers: HeaderTypes | None = None,
    ) -> None:
        url = URL(url)
        headers = Headers(headers)

        if url.scheme not in ("http", "https", "socks5", "socks5h"):
            raise ValueError(f"Unknown scheme for proxy URL {url!r}")

        if url.username or url.password:
            # Remove any auth credentials from the URL.
            auth = (url.username, url.password)
            url = url.copy_with(username=None, password=None)

        self.url = url
        self.auth = auth
        self.headers = headers
        self.ssl_context = ssl_context

    @property
    def raw_auth(self) -> tuple[bytes, bytes] | None:
        # The proxy authentication as raw bytes.
        return (
            None
            if self.auth is None
            else (self.auth[0].encode("utf-8"), self.auth[1].encode("utf-8"))
        )

    def __repr__(self) -> str:
        # The authentication is represented with the password component masked.
        auth = (self.auth[0], "********") if self.auth else None

        # Build a nice concise representation.
        url_str = f"{str(self.url)!r}"
        auth_str = f", auth={auth!r}" if auth else ""
        headers_str = f", headers={dict(self.headers)!r}" if self.headers else ""
        return f"Proxy({url_str}{auth_str}{headers_str})"


DEFAULT_TIMEOUT_CONFIG = Timeout(timeout=5.0)
DEFAULT_LIMITS = Limits(max_connections=100, max_keepalive_connections=20)
DEFAULT_MAX_REDIRECTS = 20
