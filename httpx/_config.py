from __future__ import annotations

import math
import os
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


def _timeout_or_default(
    value: None | float | UnsetType, default: None | float
) -> None | float:
    return default if isinstance(value, UnsetType) else value


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

    Timeout(5.0)                  # 5s timeout on each operation.
    Timeout(None)                 # No timeouts.
    Timeout(total=30.0)           # 30s total and per-operation budget.
    Timeout(None, total=30.0)     # 30s total budget; operations are uncapped.
    Timeout(total=30, dns=2)      # DNS has its own smaller connect sub-budget.
    """

    total: float | None
    dns: float | None
    connect: float | None
    read: float | None
    write: float | None
    pool: float | None

    def __init__(
        self,
        timeout: TimeoutTypes | UnsetType = UNSET,
        *,
        total: None | float | UnsetType = UNSET,
        dns: None | float | UnsetType = UNSET,
        connect: None | float | UnsetType = UNSET,
        read: None | float | UnsetType = UNSET,
        write: None | float | UnsetType = UNSET,
        pool: None | float | UnsetType = UNSET,
    ) -> None:
        if isinstance(timeout, Timeout):
            # Passed as a single explicit Timeout.
            assert total is UNSET
            assert dns is UNSET
            assert connect is UNSET
            assert read is UNSET
            assert write is UNSET
            assert pool is UNSET
            self.total = timeout.total
            self.dns = timeout.dns
            self.connect = timeout.connect  # type: typing.Optional[float]
            self.read = timeout.read  # type: typing.Optional[float]
            self.write = timeout.write  # type: typing.Optional[float]
            self.pool = timeout.pool  # type: typing.Optional[float]
        elif isinstance(timeout, tuple):
            # Passed as a tuple.
            self.connect = timeout[0]
            self.read = timeout[1]
            self.write = None if len(timeout) < 3 else timeout[2]
            self.pool = None if len(timeout) < 4 else timeout[3]
            self.dns = self.connect if isinstance(dns, UnsetType) else dns
            self.total = None if isinstance(total, UnsetType) else total
            self._validate()
        else:
            operations = (connect, read, write, pool)
            all_operations_set = not any(
                isinstance(value, UnsetType) for value in operations
            )
            if (
                isinstance(timeout, UnsetType)
                and isinstance(total, UnsetType)
                and not all_operations_set
            ):
                raise ValueError(
                    "httpx.Timeout must either include a default, or set all "
                    "four parameters explicitly."
                )

            default = typing.cast(
                None | float, total if isinstance(timeout, UnsetType) else timeout
            )
            self.total = None if isinstance(total, UnsetType) else total
            self.connect = _timeout_or_default(connect, default)
            self.read = _timeout_or_default(read, default)
            self.write = _timeout_or_default(write, default)
            self.pool = _timeout_or_default(pool, default)
            self.dns = _timeout_or_default(dns, self.connect)
            self._validate()

    @staticmethod
    def _valid_timeout_value(value: None | float, name: str) -> None:
        if value is None:
            return
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise TypeError(f"Timeout {name} must be a number or None.")
        if not math.isfinite(value) or value < 0:
            raise ValueError(f"Timeout {name} must be a finite, non-negative value.")

    def _validate(self) -> None:
        values = {
            "total": self.total,
            "dns": self.dns,
            "connect": self.connect,
            "read": self.read,
            "write": self.write,
            "pool": self.pool,
        }
        for name, value in values.items():
            self._valid_timeout_value(value, name)

        if self.total is not None:
            for name in ("connect", "read", "write", "pool"):
                value = getattr(self, name)
                if value is not None and value > self.total:
                    raise ValueError(
                        f"Timeout {name} cannot exceed the total request timeout."
                    )

        if (
            self.dns is not None
            and self.connect is not None
            and self.dns > self.connect
        ):
            raise ValueError("Timeout dns cannot exceed the connect timeout.")

    def as_dict(self) -> dict[str, float | None]:
        return {
            "total": self.total,
            "dns": self.dns,
            "connect": self.connect,
            "read": self.read,
            "write": self.write,
            "pool": self.pool,
        }

    def __eq__(self, other: typing.Any) -> bool:
        return (
            isinstance(other, self.__class__)
            and self.total == other.total
            and self.dns == other.dns
            and self.connect == other.connect
            and self.read == other.read
            and self.write == other.write
            and self.pool == other.pool
        )

    def __repr__(self) -> str:
        class_name = self.__class__.__name__
        operation_values = {self.connect, self.read, self.write, self.pool}
        if (
            self.total is None
            and self.dns == self.connect
            and len(operation_values) == 1
        ):
            return f"{class_name}(timeout={self.connect})"
        if len(operation_values | {self.total, self.dns}) == 1:
            return f"{class_name}(total={self.total})"
        return (
            f"{class_name}(total={self.total}, dns={self.dns}, "
            f"connect={self.connect}, read={self.read}, "
            f"write={self.write}, pool={self.pool})"
        )


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
