from __future__ import annotations

import hashlib
import os
import re
import tempfile
import time
import typing
from base64 import b64encode
from urllib.request import parse_http_list

from ._content import ByteStream
from ._exceptions import ProtocolError, StreamConsumed
from ._models import Cookies, Request, Response
from ._types import AsyncByteStream, SyncByteStream
from ._utils import to_bytes, to_str, unquote

if typing.TYPE_CHECKING:  # pragma: no cover
    from hashlib import _Hash


__all__ = ["Auth", "BasicAuth", "DigestAuth", "FunctionAuth", "NetRCAuth"]


class Auth:
    """
    Base class for all authentication schemes.

    To implement a custom authentication scheme, subclass `Auth` and override
    the `.auth_flow()` method.

    If the authentication scheme does I/O such as disk access or network calls, or uses
    synchronization primitives such as locks, you should override `.sync_auth_flow()`
    and/or `.async_auth_flow()` instead of `.auth_flow()` to provide specialized
    implementations that will be used by `Client` and `AsyncClient` respectively.
    """

    requires_request_body = False
    requires_response_body = False

    def auth_flow(self, request: Request) -> typing.Generator[Request, Response, None]:
        """
        Execute the authentication flow.

        To dispatch a request, `yield` it:

        ```
        yield request
        ```

        The client will `.send()` the response back into the flow generator. You can
        access it like so:

        ```
        response = yield request
        ```

        A `return` (or reaching the end of the generator) will result in the
        client returning the last response obtained from the server.

        You can dispatch as many requests as is necessary.
        """
        yield request

    def sync_auth_flow(
        self, request: Request
    ) -> typing.Generator[Request, Response, None]:
        """
        Execute the authentication flow synchronously.

        By default, this defers to `.auth_flow()`. You should override this method
        when the authentication scheme does I/O and/or uses concurrency primitives.
        """
        if self.requires_request_body:
            request.read()

        flow = self.auth_flow(request)
        request = next(flow)

        while True:
            response = yield request
            if self.requires_response_body:
                response.read()

            try:
                request = flow.send(response)
            except StopIteration:
                break

    async def async_auth_flow(
        self, request: Request
    ) -> typing.AsyncGenerator[Request, Response]:
        """
        Execute the authentication flow asynchronously.

        By default, this defers to `.auth_flow()`. You should override this method
        when the authentication scheme does I/O and/or uses concurrency primitives.
        """
        if self.requires_request_body:
            await request.aread()

        flow = self.auth_flow(request)
        request = next(flow)

        while True:
            response = yield request
            if self.requires_response_body:
                await response.aread()

            try:
                request = flow.send(response)
            except StopIteration:
                break


class FunctionAuth(Auth):
    """
    Allows the 'auth' argument to be passed as a simple callable function,
    that takes the request, and returns a new, modified request.
    """

    def __init__(self, func: typing.Callable[[Request], Request]) -> None:
        self._func = func

    def auth_flow(self, request: Request) -> typing.Generator[Request, Response, None]:
        yield self._func(request)


class BasicAuth(Auth):
    """
    Allows the 'auth' argument to be passed as a (username, password) pair,
    and uses HTTP Basic authentication.
    """

    def __init__(self, username: str | bytes, password: str | bytes) -> None:
        self._auth_header = self._build_auth_header(username, password)

    def auth_flow(self, request: Request) -> typing.Generator[Request, Response, None]:
        request.headers["Authorization"] = self._auth_header
        yield request

    def _build_auth_header(self, username: str | bytes, password: str | bytes) -> str:
        userpass = b":".join((to_bytes(username), to_bytes(password)))
        token = b64encode(userpass).decode()
        return f"Basic {token}"


class NetRCAuth(Auth):
    """
    Use a 'netrc' file to lookup basic auth credentials based on the url host.
    """

    def __init__(self, file: str | None = None) -> None:
        # Lazily import 'netrc'.
        # There's no need for us to load this module unless 'NetRCAuth' is being used.
        import netrc

        self._netrc_info = netrc.netrc(file)

    def auth_flow(self, request: Request) -> typing.Generator[Request, Response, None]:
        auth_info = self._netrc_info.authenticators(request.url.host)
        if auth_info is None or not auth_info[2]:
            # The netrc file did not have authentication credentials for this host.
            yield request
        else:
            # Build a basic auth header with credentials from the netrc file.
            request.headers["Authorization"] = self._build_auth_header(
                username=auth_info[0], password=auth_info[2]
            )
            yield request

    def _build_auth_header(self, username: str | bytes, password: str | bytes) -> str:
        userpass = b":".join((to_bytes(username), to_bytes(password)))
        token = b64encode(userpass).decode()
        return f"Basic {token}"


class DigestAuth(Auth):
    _ALGORITHM_TO_HASH_FUNCTION: dict[str, typing.Callable[[bytes], _Hash]] = {
        "MD5": hashlib.md5,
        "MD5-SESS": hashlib.md5,
        "SHA": hashlib.sha1,
        "SHA-SESS": hashlib.sha1,
        "SHA-256": hashlib.sha256,
        "SHA-256-SESS": hashlib.sha256,
        "SHA-512": hashlib.sha512,
        "SHA-512-SESS": hashlib.sha512,
    }

    # Keep small request entities in memory and only spill to a real file once
    # they grow beyond this size, so auth-int does not force large uploads to
    # be buffered fully in RAM in order to compute the entity checksum.
    _SPOOL_MAX_SIZE = 1024 * 1024

    def __init__(
        self,
        username: str | bytes,
        password: str | bytes,
        qop: str | bytes = "auth",
    ) -> None:
        self._username = to_bytes(username)
        self._password = to_bytes(password)
        self._qop = to_bytes(qop)
        if self._qop not in (b"auth", b"auth-int"):
            raise ValueError(
                'Unsupported qop value for digest auth, expected "auth" or "auth-int"'
            )
        self._last_challenge: _DigestAuthChallenge | None = None
        self._nonce_count = 1

    def sync_auth_flow(
        self, request: Request
    ) -> typing.Generator[Request, Response, None]:
        spool: _SyncSpooledByteStream | None = None
        if self._qop == b"auth-int":
            # The integrity checksum is derived from the exact entity bytes,
            # and the (possibly one-shot) body must be replayed after a 401,
            # so drain it into a replayable spool before anything is sent.
            spool = self._spool_sync_request(request)
        try:
            yield from self.auth_flow(request)
        finally:
            if spool is not None:
                spool.close()

    async def async_auth_flow(
        self, request: Request
    ) -> typing.AsyncGenerator[Request, Response]:
        spool: _AsyncSpooledByteStream | None = None
        if self._qop == b"auth-int":
            spool = await self._spool_async_request(request)
        try:
            # `auth_flow` is a plain (sync) generator, so drive it manually
            # from within this async generator.
            flow = self.auth_flow(request)
            try:
                next_request = next(flow)
                while True:
                    response = yield next_request
                    next_request = flow.send(response)
            except StopIteration:
                pass
            finally:
                flow.close()
        finally:
            if spool is not None:
                await spool.aclose()

    def auth_flow(self, request: Request) -> typing.Generator[Request, Response, None]:
        if self._last_challenge:
            request.headers["Authorization"] = self._build_auth_header(
                request, self._last_challenge
            )

        response = yield request

        if response.status_code != 401 or "www-authenticate" not in response.headers:
            # If the response is not a 401 then we don't
            # need to build an authenticated request.
            return

        for auth_header in response.headers.get_list("www-authenticate"):
            if auth_header.lower().startswith("digest "):
                break
        else:
            # If the response does not include a 'WWW-Authenticate: Digest ...'
            # header, then we don't need to build an authenticated request.
            return

        self._last_challenge = self._parse_challenge(request, response, auth_header)
        self._nonce_count = 1

        request.headers["Authorization"] = self._build_auth_header(
            request, self._last_challenge
        )
        if response.cookies:
            Cookies(response.cookies).set_cookie_header(request=request)
        yield request

    def _parse_challenge(
        self, request: Request, response: Response, auth_header: str
    ) -> _DigestAuthChallenge:
        """
        Returns a challenge from a Digest WWW-Authenticate header.
        These take the form of:
        `Digest realm="realm@host.com",qop="auth,auth-int",nonce="abc",opaque="xyz"`
        """
        scheme, _, fields = auth_header.partition(" ")

        # This method should only ever have been called with a Digest auth header.
        assert scheme.lower() == "digest"

        header_dict: dict[str, str] = {}
        for field in parse_http_list(fields):
            key, value = field.strip().split("=", 1)
            header_dict[key] = unquote(value)

        try:
            realm = header_dict["realm"].encode()
            nonce = header_dict["nonce"].encode()
            algorithm = header_dict.get("algorithm", "MD5")
            opaque = header_dict["opaque"].encode() if "opaque" in header_dict else None
            qop = header_dict["qop"].encode() if "qop" in header_dict else None
            return _DigestAuthChallenge(
                realm=realm, nonce=nonce, algorithm=algorithm, opaque=opaque, qop=qop
            )
        except KeyError as exc:
            message = "Malformed Digest WWW-Authenticate header"
            raise ProtocolError(message, request=request) from exc

    def _build_auth_header(
        self, request: Request, challenge: _DigestAuthChallenge
    ) -> str:
        hash_func = self._ALGORITHM_TO_HASH_FUNCTION[challenge.algorithm.upper()]

        def digest(data: bytes) -> bytes:
            return hash_func(data).hexdigest().encode()

        A1 = b":".join((self._username, challenge.realm, self._password))

        path = request.url.raw_path
        qop = self._resolve_qop(challenge.qop, request=request)
        if qop == b"auth-int":
            # H(entity-body) is computed once, over the exact raw entity bytes.
            entity_digest = digest(self._get_entity_body(request))
            A2 = b":".join((request.method.encode(), path, entity_digest))
        else:
            A2 = b":".join((request.method.encode(), path))
        HA2 = digest(A2)

        nc_value = b"%08x" % self._nonce_count
        cnonce = self._get_client_nonce(self._nonce_count, challenge.nonce)
        self._nonce_count += 1

        HA1 = digest(A1)
        if challenge.algorithm.lower().endswith("-sess"):
            HA1 = digest(b":".join((HA1, challenge.nonce, cnonce)))

        if qop is None:
            # Following RFC 2069
            digest_data = [HA1, challenge.nonce, HA2]
        else:
            # Following RFC 2617/7616
            digest_data = [HA1, challenge.nonce, nc_value, cnonce, qop, HA2]

        format_args = {
            "username": self._username,
            "realm": challenge.realm,
            "nonce": challenge.nonce,
            "uri": path,
            "response": digest(b":".join(digest_data)),
            "algorithm": challenge.algorithm.encode(),
        }
        if challenge.opaque:
            format_args["opaque"] = challenge.opaque
        if qop:
            format_args["qop"] = qop
            format_args["nc"] = nc_value
            format_args["cnonce"] = cnonce

        return "Digest " + self._get_header_value(format_args)

    def _get_entity_body(self, request: Request) -> bytes:
        """
        Return the raw entity bytes used by the 'auth-int' checksum.

        The checksum must cover the exact bytes on the wire, excluding any
        transfer framing (e.g. chunked encoding), so we always operate on the
        decoded byte chunks rather than request text.
        """
        stream = request.stream
        if isinstance(stream, (_SyncSpooledByteStream, _AsyncSpooledByteStream)):
            return stream.read_entity()
        if hasattr(request, "_content"):
            # Bytes, str, JSON and form bodies are already fully buffered.
            return request._content
        if isinstance(stream, ByteStream):
            # A replayable raw-bytes stream that has not been read yet.
            return stream._stream
        # A generator/iterator body that was already consumed by the first
        # request cannot be re-read, and re-iterating it could yield different
        # bytes. Refuse rather than silently hashing and sending an empty body.
        raise StreamConsumed()

    def _spool_sync_request(self, request: Request) -> "_SyncSpooledByteStream":
        # `ByteStream` implements both the sync and async stream interfaces, so
        # reject genuinely async streams rather than relying on class ordering.
        stream = request.stream
        if isinstance(stream, AsyncByteStream) and not isinstance(
            stream, SyncByteStream
        ):
            raise RuntimeError(
                "Attempted to buffer an async request stream using the sync "
                "digest auth flow."
            )

        spool = _SyncSpooledByteStream()
        try:
            for chunk in stream:
                spool.write(chunk)
        except BaseException:
            spool.close()
            raise
        spool.seek(0)
        request.stream = spool
        return spool

    async def _spool_async_request(self, request: Request) -> "_AsyncSpooledByteStream":
        if isinstance(request.stream, AsyncByteStream):
            stream = request.stream
        else:
            raise RuntimeError(
                "Attempted to buffer a sync request stream using the async "
                "digest auth flow."
            )

        spool = _AsyncSpooledByteStream()
        try:
            async for chunk in stream:
                spool.write(chunk)
        except BaseException:
            await spool.aclose()
            raise
        spool.seek(0)
        request.stream = spool
        return spool

    def _get_client_nonce(self, nonce_count: int, nonce: bytes) -> bytes:
        s = str(nonce_count).encode()
        s += nonce
        s += time.ctime().encode()
        s += os.urandom(8)

        return hashlib.sha1(s).hexdigest()[:16].encode()

    def _get_header_value(self, header_fields: dict[str, bytes]) -> str:
        NON_QUOTED_FIELDS = ("algorithm", "qop", "nc")
        QUOTED_TEMPLATE = '{}="{}"'
        NON_QUOTED_TEMPLATE = "{}={}"

        header_value = ""
        for i, (field, value) in enumerate(header_fields.items()):
            if i > 0:
                header_value += ", "
            template = (
                QUOTED_TEMPLATE
                if field not in NON_QUOTED_FIELDS
                else NON_QUOTED_TEMPLATE
            )
            header_value += template.format(field, to_str(value))

        return header_value

    def _resolve_qop(self, qop: bytes | None, request: Request) -> bytes | None:
        if qop is None:
            if self._qop == b"auth-int":
                # RFC 7616 only defines auth-int together with a qop.
                raise ProtocolError(
                    "Server does not support the 'auth-int' qop required by "
                    "this DigestAuth instance.",
                    request=request,
                )
            return None
        qops = re.split(b", ?", qop)
        if self._qop in qops:
            return self._qop
        if self._qop == b"auth-int" and b"auth" in qops:
            # Never silently downgrade an explicit integrity-protection request.
            raise ProtocolError(
                "Server only supports the 'auth' qop, but this DigestAuth "
                "instance requires 'auth-int' integrity protection.",
                request=request,
            )
        if b"auth" in qops:
            return b"auth"
        if qops == [b"auth-int"]:
            # Default ('auth') clients still work against an auth-int-only server.
            return b"auth-int"

        message = f'Unexpected qop value "{qop!r}" in digest auth'
        raise ProtocolError(message, request=request)


class _DigestAuthChallenge(typing.NamedTuple):
    realm: bytes
    nonce: bytes
    algorithm: str
    opaque: bytes | None
    qop: bytes | None


class _SyncSpooledByteStream(SyncByteStream):
    """
    A replayable request body backed by a `SpooledTemporaryFile`.

    Small bodies stay in memory and only spill to a temporary file once they
    exceed `DigestAuth._SPOOL_MAX_SIZE`, keeping the memory footprint bounded
    while still allowing one-shot sources to be replayed after a 401.
    """

    def __init__(self) -> None:
        self._spool = tempfile.SpooledTemporaryFile(max_size=DigestAuth._SPOOL_MAX_SIZE)

    def write(self, chunk: bytes) -> int:
        return self._spool.write(chunk)

    def seek(self, offset: int) -> int:
        return self._spool.seek(offset)

    def read_entity(self) -> bytes:
        self._spool.seek(0)
        return self._spool.read()

    def __iter__(self) -> typing.Iterator[bytes]:
        self._spool.seek(0)
        while True:
            chunk = self._spool.read(65_536)
            if not chunk:
                break
            yield chunk

    def close(self) -> None:
        self._spool.close()


class _AsyncSpooledByteStream(AsyncByteStream):
    def __init__(self) -> None:
        self._spool = tempfile.SpooledTemporaryFile(max_size=DigestAuth._SPOOL_MAX_SIZE)

    def write(self, chunk: bytes) -> int:
        return self._spool.write(chunk)

    def seek(self, offset: int) -> int:
        return self._spool.seek(offset)

    def read_entity(self) -> bytes:
        self._spool.seek(0)
        return self._spool.read()

    async def __aiter__(self) -> typing.AsyncIterator[bytes]:
        self._spool.seek(0)
        while True:
            chunk = self._spool.read(65_536)
            if not chunk:
                break
            yield chunk

    async def aclose(self) -> None:
        self._spool.close()
