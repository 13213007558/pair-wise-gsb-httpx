from __future__ import annotations

import hashlib
import os
import re
import threading
import time
import typing
from base64 import b64encode
from urllib.request import parse_http_list

from ._exceptions import ProtocolError
from ._models import Cookies, Request, Response
from ._urls import URL
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

    def __init__(self, username: str | bytes, password: str | bytes) -> None:
        self._username = to_bytes(username)
        self._password = to_bytes(password)
        # Received challenges are cached by protection space, keyed on
        # the scheme, host, effective port, and realm. This ensures that
        # a challenge is only ever reused against the origin it came from.
        self._challenges: dict[tuple[str, str, int, bytes], _DigestAuthState] = {}
        self._lock = threading.Lock()

    def auth_flow(self, request: Request) -> typing.Generator[Request, Response, None]:
        cached = self._get_cached_challenge(request.url)
        if cached is not None:
            challenge, nonce_count = cached
            request.headers["Authorization"] = self._build_auth_header(
                request, challenge, nonce_count
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

        # The challenge belongs to the origin that sent the 401 response,
        # which may differ from the origin of the original request if
        # redirects were followed.
        try:
            challenge_url = response.request.url
        except RuntimeError:
            challenge_url = request.url

        challenge = self._parse_challenge(request, response, auth_header)
        self._validate_challenge(challenge, request=request)

        if self._origin_key(challenge_url) != self._origin_key(request.url):
            # The 401 response came from a different origin, for example
            # after a redirect stripped the 'Authorization' header. The
            # challenge is cached for future requests to that origin, but
            # must not be attached to a request sent to this origin.
            self._cache_challenge(challenge_url, challenge, consume=False)
            return

        nonce_count = self._cache_challenge(challenge_url, challenge)

        request.headers["Authorization"] = self._build_auth_header(
            request, challenge, nonce_count
        )
        if response.cookies:
            Cookies(response.cookies).set_cookie_header(request=request)
        yield request

    def _origin_key(self, url: URL) -> tuple[str, str, int]:
        port = url.port
        if port is None:
            port = 443 if url.scheme == "https" else 80
        return (url.scheme, url.host, port)

    def _get_cached_challenge(
        self, url: URL
    ) -> tuple[_DigestAuthChallenge, int] | None:
        origin = self._origin_key(url)
        with self._lock:
            matches = [
                state for key, state in self._challenges.items() if key[:3] == origin
            ]
            if len(matches) != 1:
                # No cached challenge for this origin, or several realms
                # cached and we cannot tell which one applies. The request
                # is sent unauthenticated, and any 401 challenge is handled.
                return None
            state = matches[0]
            nonce_count = state.nonce_count
            state.nonce_count += 1
            return state.challenge, nonce_count

    def _cache_challenge(
        self, url: URL, challenge: _DigestAuthChallenge, consume: bool = True
    ) -> int:
        key = self._origin_key(url) + (challenge.realm,)
        with self._lock:
            state = self._challenges.get(key)
            if state is not None and state.challenge.nonce == challenge.nonce:
                # A re-challenge under the same nonce continues the
                # nonce count, so that 'nc' values are never repeated.
                nonce_count = state.nonce_count
            else:
                # A new nonce starts the nonce count over.
                nonce_count = 1
            next_count = nonce_count + 1 if consume else nonce_count
            self._challenges[key] = _DigestAuthState(challenge, next_count)
            return nonce_count

    def _validate_challenge(
        self, challenge: _DigestAuthChallenge, request: Request
    ) -> None:
        # Challenges that we cannot use must not replace any usable
        # cached state, so they are rejected before being cached.
        if challenge.algorithm.upper() not in self._ALGORITHM_TO_HASH_FUNCTION:
            message = f'Unsupported digest algorithm "{challenge.algorithm}"'
            raise ProtocolError(message, request=request)
        self._resolve_qop(challenge.qop, request=request)

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
        self, request: Request, challenge: _DigestAuthChallenge, nonce_count: int
    ) -> str:
        hash_func = self._ALGORITHM_TO_HASH_FUNCTION[challenge.algorithm.upper()]

        def digest(data: bytes) -> bytes:
            return hash_func(data).hexdigest().encode()

        A1 = b":".join((self._username, challenge.realm, self._password))

        path = request.url.raw_path
        A2 = b":".join((request.method.encode(), path))
        # TODO: implement auth-int
        HA2 = digest(A2)

        nc_value = b"%08x" % nonce_count
        cnonce = self._get_client_nonce(nonce_count, challenge.nonce)

        HA1 = digest(A1)
        if challenge.algorithm.lower().endswith("-sess"):
            HA1 = digest(b":".join((HA1, challenge.nonce, cnonce)))

        qop = self._resolve_qop(challenge.qop, request=request)
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
            format_args["qop"] = b"auth"
            format_args["nc"] = nc_value
            format_args["cnonce"] = cnonce

        return "Digest " + self._get_header_value(format_args)

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
            return None
        qops = re.split(b", ?", qop)
        if b"auth" in qops:
            return b"auth"

        if qops == [b"auth-int"]:
            raise NotImplementedError("Digest auth-int support is not yet implemented")

        message = f'Unexpected qop value "{qop!r}" in digest auth'
        raise ProtocolError(message, request=request)


class _DigestAuthChallenge(typing.NamedTuple):
    realm: bytes
    nonce: bytes
    algorithm: str
    opaque: bytes | None
    qop: bytes | None


class _DigestAuthState:
    def __init__(self, challenge: _DigestAuthChallenge, nonce_count: int) -> None:
        self.challenge = challenge
        # The next nonce count to use under the challenge nonce.
        self.nonce_count = nonce_count
