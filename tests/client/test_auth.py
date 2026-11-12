"""
Integration tests for authentication.

Unit tests for auth classes also exist in tests/test_auth.py
"""

import hashlib
import netrc
import os
import sys
import threading
import typing
from urllib.request import parse_keqv_list

import anyio
import pytest

import httpx

from ..common import FIXTURES_DIR


class App:
    """
    A mock app to test auth credentials.
    """

    def __init__(self, auth_header: str = "", status_code: int = 200) -> None:
        self.auth_header = auth_header
        self.status_code = status_code

    def __call__(self, request: httpx.Request) -> httpx.Response:
        headers = {"www-authenticate": self.auth_header} if self.auth_header else {}
        data = {"auth": request.headers.get("Authorization")}
        return httpx.Response(self.status_code, headers=headers, json=data)


class DigestApp:
    def __init__(
        self,
        algorithm: str = "SHA-256",
        send_response_after_attempt: int = 1,
        qop: str = "auth",
        regenerate_nonce: bool = True,
    ) -> None:
        self.algorithm = algorithm
        self.send_response_after_attempt = send_response_after_attempt
        self.qop = qop
        self._regenerate_nonce = regenerate_nonce
        self._response_count = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if self._response_count < self.send_response_after_attempt:
            return self.challenge_send(request)

        data = {"auth": request.headers.get("Authorization")}
        return httpx.Response(200, json=data)

    def challenge_send(self, request: httpx.Request) -> httpx.Response:
        self._response_count += 1
        nonce = (
            hashlib.sha256(os.urandom(8)).hexdigest()
            if self._regenerate_nonce
            else "ee96edced2a0b43e4869e96ebe27563f369c1205a049d06419bb51d8aeddf3d3"
        )
        challenge_data = {
            "nonce": nonce,
            "qop": self.qop,
            "opaque": (
                "ee6378f3ee14ebfd2fff54b70a91a7c9390518047f242ab2271380db0e14bda1"
            ),
            "algorithm": self.algorithm,
            "stale": "FALSE",
        }
        challenge_str = ", ".join(
            '{}="{}"'.format(key, value)
            for key, value in challenge_data.items()
            if value
        )

        headers = {
            "www-authenticate": f'Digest realm="httpx@example.org", {challenge_str}',
        }
        return httpx.Response(401, headers=headers)


class RepeatAuth(httpx.Auth):
    """
    A mock authentication scheme that requires clients to send
    the request a fixed number of times, and then send a last request containing
    an aggregation of nonces that the server sent in 'WWW-Authenticate' headers
    of intermediate responses.
    """

    requires_request_body = True

    def __init__(self, repeat: int) -> None:
        self.repeat = repeat

    def auth_flow(
        self, request: httpx.Request
    ) -> typing.Generator[httpx.Request, httpx.Response, None]:
        nonces = []

        for index in range(self.repeat):
            request.headers["Authorization"] = f"Repeat {index}"
            response = yield request
            nonces.append(response.headers["www-authenticate"])

        key = ".".join(nonces)
        request.headers["Authorization"] = f"Repeat {key}"
        yield request


class ResponseBodyAuth(httpx.Auth):
    """
    A mock authentication scheme that requires clients to send an 'Authorization'
    header, then send back the contents of the response in the 'Authorization'
    header.
    """

    requires_response_body = True

    def __init__(self, token: str) -> None:
        self.token = token

    def auth_flow(
        self, request: httpx.Request
    ) -> typing.Generator[httpx.Request, httpx.Response, None]:
        request.headers["Authorization"] = self.token
        response = yield request
        data = response.text
        request.headers["Authorization"] = data
        yield request


class SyncOrAsyncAuth(httpx.Auth):
    """
    A mock authentication scheme that uses a different implementation for the
    sync and async cases.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._async_lock = anyio.Lock()

    def sync_auth_flow(
        self, request: httpx.Request
    ) -> typing.Generator[httpx.Request, httpx.Response, None]:
        with self._lock:
            request.headers["Authorization"] = "sync-auth"
        yield request

    async def async_auth_flow(
        self, request: httpx.Request
    ) -> typing.AsyncGenerator[httpx.Request, httpx.Response]:
        async with self._async_lock:
            request.headers["Authorization"] = "async-auth"
        yield request


@pytest.mark.anyio
async def test_basic_auth() -> None:
    url = "https://example.org/"
    auth = ("user", "password123")
    app = App()

    async with httpx.AsyncClient(transport=httpx.MockTransport(app)) as client:
        response = await client.get(url, auth=auth)

    assert response.status_code == 200
    assert response.json() == {"auth": "Basic dXNlcjpwYXNzd29yZDEyMw=="}


@pytest.mark.anyio
async def test_basic_auth_with_stream() -> None:
    """
    See: https://github.com/encode/httpx/pull/1312
    """
    url = "https://example.org/"
    auth = ("user", "password123")
    app = App()

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(app), auth=auth
    ) as client:
        async with client.stream("GET", url) as response:
            await response.aread()

    assert response.status_code == 200
    assert response.json() == {"auth": "Basic dXNlcjpwYXNzd29yZDEyMw=="}


@pytest.mark.anyio
async def test_basic_auth_in_url() -> None:
    url = "https://user:password123@example.org/"
    app = App()

    async with httpx.AsyncClient(transport=httpx.MockTransport(app)) as client:
        response = await client.get(url)

    assert response.status_code == 200
    assert response.json() == {"auth": "Basic dXNlcjpwYXNzd29yZDEyMw=="}


@pytest.mark.anyio
async def test_basic_auth_on_session() -> None:
    url = "https://example.org/"
    auth = ("user", "password123")
    app = App()

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(app), auth=auth
    ) as client:
        response = await client.get(url)

    assert response.status_code == 200
    assert response.json() == {"auth": "Basic dXNlcjpwYXNzd29yZDEyMw=="}


@pytest.mark.anyio
async def test_custom_auth() -> None:
    url = "https://example.org/"
    app = App()

    def auth(request: httpx.Request) -> httpx.Request:
        request.headers["Authorization"] = "Token 123"
        return request

    async with httpx.AsyncClient(transport=httpx.MockTransport(app)) as client:
        response = await client.get(url, auth=auth)

    assert response.status_code == 200
    assert response.json() == {"auth": "Token 123"}


def test_netrc_auth_credentials_exist() -> None:
    """
    When netrc auth is being used and a request is made to a host that is
    in the netrc file, then the relevant credentials should be applied.
    """
    netrc_file = str(FIXTURES_DIR / ".netrc")
    url = "http://netrcexample.org"
    app = App()
    auth = httpx.NetRCAuth(netrc_file)

    with httpx.Client(transport=httpx.MockTransport(app), auth=auth) as client:
        response = client.get(url)

    assert response.status_code == 200
    assert response.json() == {
        "auth": "Basic ZXhhbXBsZS11c2VybmFtZTpleGFtcGxlLXBhc3N3b3Jk"
    }


def test_netrc_auth_credentials_do_not_exist() -> None:
    """
    When netrc auth is being used and a request is made to a host that is
    not in the netrc file, then no credentials should be applied.
    """
    netrc_file = str(FIXTURES_DIR / ".netrc")
    url = "http://example.org"
    app = App()
    auth = httpx.NetRCAuth(netrc_file)

    with httpx.Client(transport=httpx.MockTransport(app), auth=auth) as client:
        response = client.get(url)

    assert response.status_code == 200
    assert response.json() == {"auth": None}


@pytest.mark.skipif(
    sys.version_info >= (3, 11),
    reason="netrc files without a password are valid from Python >= 3.11",
)
def test_netrc_auth_nopassword_parse_error() -> None:  # pragma: no cover
    """
    Python has different netrc parsing behaviours with different versions.
    For Python < 3.11 a netrc file with no password is invalid. In this case
    we want to allow the parse error to be raised.
    """
    netrc_file = str(FIXTURES_DIR / ".netrc-nopassword")
    with pytest.raises(netrc.NetrcParseError):
        httpx.NetRCAuth(netrc_file)


@pytest.mark.anyio
async def test_auth_disable_per_request() -> None:
    url = "https://example.org/"
    auth = ("user", "password123")
    app = App()

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(app), auth=auth
    ) as client:
        response = await client.get(url, auth=None)

    assert response.status_code == 200
    assert response.json() == {"auth": None}


def test_auth_hidden_url() -> None:
    url = "http://example-username:example-password@example.org/"
    expected = "URL('http://example-username:[secure]@example.org/')"
    assert url == httpx.URL(url)
    assert expected == repr(httpx.URL(url))


@pytest.mark.anyio
async def test_auth_hidden_header() -> None:
    url = "https://example.org/"
    auth = ("example-username", "example-password")
    app = App()

    async with httpx.AsyncClient(transport=httpx.MockTransport(app)) as client:
        response = await client.get(url, auth=auth)

    assert "'authorization': '[secure]'" in str(response.request.headers)


@pytest.mark.anyio
async def test_auth_property() -> None:
    app = App()

    async with httpx.AsyncClient(transport=httpx.MockTransport(app)) as client:
        assert client.auth is None

        client.auth = ("user", "password123")
        assert isinstance(client.auth, httpx.BasicAuth)

        url = "https://example.org/"
        response = await client.get(url)
        assert response.status_code == 200
        assert response.json() == {"auth": "Basic dXNlcjpwYXNzd29yZDEyMw=="}


@pytest.mark.anyio
async def test_auth_invalid_type() -> None:
    app = App()

    with pytest.raises(TypeError):
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(app),
            auth="not a tuple, not a callable",  # type: ignore
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(app)) as client:
        with pytest.raises(TypeError):
            await client.get(auth="not a tuple, not a callable")  # type: ignore

        with pytest.raises(TypeError):
            client.auth = "not a tuple, not a callable"  # type: ignore


@pytest.mark.anyio
async def test_digest_auth_returns_no_auth_if_no_digest_header_in_response() -> None:
    url = "https://example.org/"
    auth = httpx.DigestAuth(username="user", password="password123")
    app = App()

    async with httpx.AsyncClient(transport=httpx.MockTransport(app)) as client:
        response = await client.get(url, auth=auth)

    assert response.status_code == 200
    assert response.json() == {"auth": None}
    assert len(response.history) == 0


def test_digest_auth_returns_no_auth_if_alternate_auth_scheme() -> None:
    url = "https://example.org/"
    auth = httpx.DigestAuth(username="user", password="password123")
    auth_header = "Token ..."
    app = App(auth_header=auth_header, status_code=401)

    client = httpx.Client(transport=httpx.MockTransport(app))
    response = client.get(url, auth=auth)

    assert response.status_code == 401
    assert response.json() == {"auth": None}
    assert len(response.history) == 0


@pytest.mark.anyio
async def test_digest_auth_200_response_including_digest_auth_header() -> None:
    url = "https://example.org/"
    auth = httpx.DigestAuth(username="user", password="password123")
    auth_header = 'Digest realm="realm@host.com",qop="auth",nonce="abc",opaque="xyz"'
    app = App(auth_header=auth_header, status_code=200)

    async with httpx.AsyncClient(transport=httpx.MockTransport(app)) as client:
        response = await client.get(url, auth=auth)

    assert response.status_code == 200
    assert response.json() == {"auth": None}
    assert len(response.history) == 0


@pytest.mark.anyio
async def test_digest_auth_401_response_without_digest_auth_header() -> None:
    url = "https://example.org/"
    auth = httpx.DigestAuth(username="user", password="password123")
    app = App(auth_header="", status_code=401)

    async with httpx.AsyncClient(transport=httpx.MockTransport(app)) as client:
        response = await client.get(url, auth=auth)

    assert response.status_code == 401
    assert response.json() == {"auth": None}
    assert len(response.history) == 0


@pytest.mark.parametrize(
    "algorithm,expected_hash_length,expected_response_length",
    [
        ("MD5", 64, 32),
        ("MD5-SESS", 64, 32),
        ("SHA", 64, 40),
        ("SHA-SESS", 64, 40),
        ("SHA-256", 64, 64),
        ("SHA-256-SESS", 64, 64),
        ("SHA-512", 64, 128),
        ("SHA-512-SESS", 64, 128),
    ],
)
@pytest.mark.anyio
async def test_digest_auth(
    algorithm: str, expected_hash_length: int, expected_response_length: int
) -> None:
    url = "https://example.org/"
    auth = httpx.DigestAuth(username="user", password="password123")
    app = DigestApp(algorithm=algorithm)

    async with httpx.AsyncClient(transport=httpx.MockTransport(app)) as client:
        response = await client.get(url, auth=auth)

    assert response.status_code == 200
    assert len(response.history) == 1

    authorization = typing.cast(typing.Dict[str, typing.Any], response.json())["auth"]
    scheme, _, fields = authorization.partition(" ")
    assert scheme == "Digest"

    response_fields = [field.strip() for field in fields.split(",")]
    digest_data = dict(field.split("=") for field in response_fields)

    assert digest_data["username"] == '"user"'
    assert digest_data["realm"] == '"httpx@example.org"'
    assert "nonce" in digest_data
    assert digest_data["uri"] == '"/"'
    assert len(digest_data["response"]) == expected_response_length + 2  # extra quotes
    assert len(digest_data["opaque"]) == expected_hash_length + 2
    assert digest_data["algorithm"] == algorithm
    assert digest_data["qop"] == "auth"
    assert digest_data["nc"] == "00000001"
    assert len(digest_data["cnonce"]) == 16 + 2


@pytest.mark.anyio
async def test_digest_auth_no_specified_qop() -> None:
    url = "https://example.org/"
    auth = httpx.DigestAuth(username="user", password="password123")
    app = DigestApp(qop="")

    async with httpx.AsyncClient(transport=httpx.MockTransport(app)) as client:
        response = await client.get(url, auth=auth)

    assert response.status_code == 200
    assert len(response.history) == 1

    authorization = typing.cast(typing.Dict[str, typing.Any], response.json())["auth"]
    scheme, _, fields = authorization.partition(" ")
    assert scheme == "Digest"

    response_fields = [field.strip() for field in fields.split(",")]
    digest_data = dict(field.split("=") for field in response_fields)

    assert "qop" not in digest_data
    assert "nc" not in digest_data
    assert "cnonce" not in digest_data
    assert digest_data["username"] == '"user"'
    assert digest_data["realm"] == '"httpx@example.org"'
    assert len(digest_data["nonce"]) == 64 + 2  # extra quotes
    assert digest_data["uri"] == '"/"'
    assert len(digest_data["response"]) == 64 + 2
    assert len(digest_data["opaque"]) == 64 + 2
    assert digest_data["algorithm"] == "SHA-256"


@pytest.mark.parametrize("qop", ("auth, auth-int", "auth,auth-int", "unknown,auth"))
@pytest.mark.anyio
async def test_digest_auth_qop_including_spaces_and_auth_returns_auth(qop: str) -> None:
    url = "https://example.org/"
    auth = httpx.DigestAuth(username="user", password="password123")
    app = DigestApp(qop=qop)

    async with httpx.AsyncClient(transport=httpx.MockTransport(app)) as client:
        response = await client.get(url, auth=auth)

    assert response.status_code == 200
    assert len(response.history) == 1


@pytest.mark.anyio
async def test_digest_auth_qop_auth_int_not_implemented() -> None:
    url = "https://example.org/"
    auth = httpx.DigestAuth(username="user", password="password123")
    app = DigestApp(qop="auth-int")

    async with httpx.AsyncClient(transport=httpx.MockTransport(app)) as client:
        with pytest.raises(NotImplementedError):
            await client.get(url, auth=auth)


@pytest.mark.anyio
async def test_digest_auth_qop_must_be_auth_or_auth_int() -> None:
    url = "https://example.org/"
    auth = httpx.DigestAuth(username="user", password="password123")
    app = DigestApp(qop="not-auth")

    async with httpx.AsyncClient(transport=httpx.MockTransport(app)) as client:
        with pytest.raises(httpx.ProtocolError):
            await client.get(url, auth=auth)


@pytest.mark.anyio
async def test_digest_auth_incorrect_credentials() -> None:
    url = "https://example.org/"
    auth = httpx.DigestAuth(username="user", password="password123")
    app = DigestApp(send_response_after_attempt=2)

    async with httpx.AsyncClient(transport=httpx.MockTransport(app)) as client:
        response = await client.get(url, auth=auth)

    assert response.status_code == 401
    assert len(response.history) == 1


@pytest.mark.anyio
async def test_digest_auth_reuses_challenge() -> None:
    url = "https://example.org/"
    auth = httpx.DigestAuth(username="user", password="password123")
    app = DigestApp()

    async with httpx.AsyncClient(transport=httpx.MockTransport(app)) as client:
        response_1 = await client.get(url, auth=auth)
        response_2 = await client.get(url, auth=auth)

        assert response_1.status_code == 200
        assert response_2.status_code == 200

        assert len(response_1.history) == 1
        assert len(response_2.history) == 0


@pytest.mark.anyio
async def test_digest_auth_resets_nonce_count_after_401() -> None:
    url = "https://example.org/"
    auth = httpx.DigestAuth(username="user", password="password123")
    app = DigestApp()

    async with httpx.AsyncClient(transport=httpx.MockTransport(app)) as client:
        response_1 = await client.get(url, auth=auth)
        assert response_1.status_code == 200
        assert len(response_1.history) == 1

        first_nonce = parse_keqv_list(
            response_1.request.headers["Authorization"].split(", ")
        )["nonce"]
        first_nc = parse_keqv_list(
            response_1.request.headers["Authorization"].split(", ")
        )["nc"]

        # with this we now force a 401 on a subsequent (but initial) request
        app.send_response_after_attempt = 2

        # we expect the client again to try to authenticate,
        # i.e. the history length must be 1
        response_2 = await client.get(url, auth=auth)
        assert response_2.status_code == 200
        assert len(response_2.history) == 1

        second_nonce = parse_keqv_list(
            response_2.request.headers["Authorization"].split(", ")
        )["nonce"]
        second_nc = parse_keqv_list(
            response_2.request.headers["Authorization"].split(", ")
        )["nc"]

    assert first_nonce != second_nonce  # ensures that the auth challenge was reset
    assert (
        first_nc == second_nc
    )  # ensures the nonce count is reset when the authentication failed


@pytest.mark.parametrize(
    "auth_header",
    [
        'Digest realm="httpx@example.org", qop="auth"',  # missing fields
        'Digest realm="httpx@example.org", qop="auth,au',  # malformed fields list
    ],
)
@pytest.mark.anyio
async def test_async_digest_auth_raises_protocol_error_on_malformed_header(
    auth_header: str,
) -> None:
    url = "https://example.org/"
    auth = httpx.DigestAuth(username="user", password="password123")
    app = App(auth_header=auth_header, status_code=401)

    async with httpx.AsyncClient(transport=httpx.MockTransport(app)) as client:
        with pytest.raises(httpx.ProtocolError):
            await client.get(url, auth=auth)


@pytest.mark.parametrize(
    "auth_header",
    [
        'Digest realm="httpx@example.org", qop="auth"',  # missing fields
        'Digest realm="httpx@example.org", qop="auth,au',  # malformed fields list
    ],
)
def test_sync_digest_auth_raises_protocol_error_on_malformed_header(
    auth_header: str,
) -> None:
    url = "https://example.org/"
    auth = httpx.DigestAuth(username="user", password="password123")
    app = App(auth_header=auth_header, status_code=401)

    with httpx.Client(transport=httpx.MockTransport(app)) as client:
        with pytest.raises(httpx.ProtocolError):
            client.get(url, auth=auth)


def parse_digest_auth_header(header: str) -> typing.Dict[str, str]:
    scheme, _, fields = header.partition(" ")
    assert scheme == "Digest"
    return parse_keqv_list(fields.split(", "))


def test_digest_auth_caches_challenges_per_origin() -> None:
    """
    A 'DigestAuth' instance reused across origins must not send the
    challenge cached for one origin to a different origin.
    """
    challenges = {
        "a.example.org": (
            'Digest realm="realm-a", qop="auth", nonce="nonce-a", opaque="opaque-a"'
        ),
        "b.example.org": (
            'Digest realm="realm-b", qop="auth", nonce="nonce-b", opaque="opaque-b"'
        ),
    }
    requests: typing.List[typing.Tuple[httpx.Request, typing.Optional[str]]] = []

    def app(request: httpx.Request) -> httpx.Response:
        requests.append((request, request.headers.get("Authorization")))
        if "Authorization" not in request.headers:
            challenge = challenges[request.url.host]
            return httpx.Response(401, headers={"www-authenticate": challenge})
        return httpx.Response(200)

    auth = httpx.DigestAuth(username="user", password="password123")
    with httpx.Client(transport=httpx.MockTransport(app), auth=auth) as client:
        response = client.get("http://a.example.org/")
        assert response.status_code == 200

        # The first request to another origin is sent unauthenticated,
        # and the 401 response is handled with that origin's challenge.
        response = client.get("http://b.example.org/")
        assert response.status_code == 200

        # The cached challenge is reused for further requests to its origin.
        response = client.get("http://a.example.org/")
        assert response.status_code == 200

        # A different scheme and effective port is a different protection space.
        response = client.get("https://a.example.org/")
        assert response.status_code == 200

    a_requests = [
        authorization
        for request, authorization in requests
        if request.url.host == "a.example.org" and request.url.scheme == "http"
    ]
    b_requests = [
        authorization
        for request, authorization in requests
        if request.url.host == "b.example.org"
    ]
    https_requests = [
        authorization
        for request, authorization in requests
        if request.url.scheme == "https"
    ]

    assert len(a_requests) == 3
    assert a_requests[0] is None
    fields = parse_digest_auth_header(typing.cast(str, a_requests[1]))
    assert fields["realm"] == "realm-a"
    assert fields["nonce"] == "nonce-a"
    assert fields["nc"] == "00000001"
    fields = parse_digest_auth_header(typing.cast(str, a_requests[2]))
    assert fields["realm"] == "realm-a"
    assert fields["nonce"] == "nonce-a"
    assert fields["nc"] == "00000002"

    # Host B never sees the challenge cached for host A.
    assert len(b_requests) == 2
    assert b_requests[0] is None
    fields = parse_digest_auth_header(typing.cast(str, b_requests[1]))
    assert fields["realm"] == "realm-b"
    assert fields["nonce"] == "nonce-b"
    assert fields["nc"] == "00000001"

    assert len(https_requests) == 2
    assert https_requests[0] is None
    fields = parse_digest_auth_header(typing.cast(str, https_requests[1]))
    assert fields["realm"] == "realm-a"
    assert fields["nonce"] == "nonce-a"
    assert fields["nc"] == "00000001"


def test_digest_auth_caches_challenges_per_realm() -> None:
    """
    Challenges for different realms on the same origin are cached separately,
    and interleaved authentication flows each use the challenge they received.
    """
    realms = {
        "/one": ("realm-one", "nonce-one"),
        "/two": ("realm-two", "nonce-two"),
    }
    requests: typing.List[typing.Tuple[httpx.Request, typing.Optional[str]]] = []

    def app(request: httpx.Request) -> httpx.Response:
        requests.append((request, request.headers.get("Authorization")))
        realm, nonce = realms[request.url.path]
        header = request.headers.get("Authorization")
        if header is not None:
            fields = parse_digest_auth_header(header)
            if fields["realm"] == realm and fields["nonce"] == nonce:
                return httpx.Response(200)
        challenge = f'Digest realm="{realm}", qop="auth", nonce="{nonce}"'
        return httpx.Response(401, headers={"www-authenticate": challenge})

    auth = httpx.DigestAuth(username="user", password="password123")
    with httpx.Client(transport=httpx.MockTransport(app), auth=auth) as client:
        response = client.get("http://example.org/one")
        assert response.status_code == 200

        # The cached realm does not match, so the server re-challenges,
        # and the retry uses the challenge that was actually received.
        response = client.get("http://example.org/two")
        assert response.status_code == 200

        # With two realms cached for the origin the client cannot pick one,
        # so the request is sent unauthenticated and the 401 is handled.
        response = client.get("http://example.org/one")
        assert response.status_code == 200

    one_requests = [
        authorization
        for request, authorization in requests
        if request.url.path == "/one"
    ]
    two_requests = [
        authorization
        for request, authorization in requests
        if request.url.path == "/two"
    ]

    assert len(one_requests) == 4
    assert one_requests[0] is None
    fields = parse_digest_auth_header(typing.cast(str, one_requests[1]))
    assert fields["realm"] == "realm-one"
    assert fields["nonce"] == "nonce-one"
    assert fields["nc"] == "00000001"
    assert one_requests[2] is None
    # A re-challenge under the same nonce continues the nonce count.
    # (The preemptive request to '/two' already used nc=2 for this nonce.)
    fields = parse_digest_auth_header(typing.cast(str, one_requests[3]))
    assert fields["realm"] == "realm-one"
    assert fields["nonce"] == "nonce-one"
    assert fields["nc"] == "00000003"

    assert len(two_requests) == 2
    fields = parse_digest_auth_header(typing.cast(str, two_requests[0]))
    assert fields["realm"] == "realm-one"
    fields = parse_digest_auth_header(typing.cast(str, two_requests[1]))
    assert fields["realm"] == "realm-two"
    assert fields["nonce"] == "nonce-two"
    assert fields["nc"] == "00000001"


def test_digest_auth_stale_nonce_switches_nonce_and_resets_count() -> None:
    """
    A 401 with a new nonce, such as a 'stale=true' response, switches the
    cached challenge over to the new nonce and restarts the nonce count.
    """
    state = {"nonce": "nonce-1", "stale": "false"}
    requests: typing.List[typing.Tuple[httpx.Request, typing.Optional[str]]] = []

    def app(request: httpx.Request) -> httpx.Response:
        requests.append((request, request.headers.get("Authorization")))
        header = request.headers.get("Authorization")
        if header is not None:
            fields = parse_digest_auth_header(header)
            if fields["nonce"] == state["nonce"]:
                return httpx.Response(200)
        challenge = (
            f'Digest realm="realm", qop="auth", nonce="{state["nonce"]}", '
            f'stale={state["stale"]}'
        )
        return httpx.Response(401, headers={"www-authenticate": challenge})

    auth = httpx.DigestAuth(username="user", password="password123")
    with httpx.Client(transport=httpx.MockTransport(app), auth=auth) as client:
        response = client.get("http://example.org/")
        assert response.status_code == 200

        # The server rotates its nonce and rejects the previous one as stale.
        state["nonce"] = "nonce-2"
        state["stale"] = "true"
        response = client.get("http://example.org/")
        assert response.status_code == 200

    assert len(requests) == 4
    fields = parse_digest_auth_header(typing.cast(str, requests[1][1]))
    assert fields["nonce"] == "nonce-1"
    assert fields["nc"] == "00000001"
    fields = parse_digest_auth_header(typing.cast(str, requests[2][1]))
    assert fields["nonce"] == "nonce-1"
    assert fields["nc"] == "00000002"
    # The retry after the stale response uses the new nonce, with the
    # nonce count restarted.
    fields = parse_digest_auth_header(typing.cast(str, requests[3][1]))
    assert fields["nonce"] == "nonce-2"
    assert fields["nc"] == "00000001"


def test_digest_auth_concurrent_retries_do_not_repeat_nonce_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Concurrent authentication flows against the same challenge must not
    reuse the same nonce count.
    """
    barrier = threading.Barrier(2)
    nonce_counts: typing.List[str] = []
    lock = threading.Lock()

    def app(request: httpx.Request) -> httpx.Response:
        if "Authorization" not in request.headers:
            # Ensure both requests are challenged with the same nonce,
            # before either retry is sent.
            barrier.wait(timeout=10)
            challenge = 'Digest realm="realm", qop="auth", nonce="shared-nonce"'
            return httpx.Response(401, headers={"www-authenticate": challenge})
        fields = parse_digest_auth_header(request.headers["Authorization"])
        assert fields["nonce"] == "shared-nonce"
        with lock:
            nonce_counts.append(fields["nc"])
        return httpx.Response(200)

    def fixed_client_nonce(nonce_count: int, nonce: bytes) -> bytes:
        return b"fixed-cnonce"

    auth = httpx.DigestAuth(username="user", password="password123")
    monkeypatch.setattr(auth, "_get_client_nonce", fixed_client_nonce)

    responses: typing.List[httpx.Response] = []
    with httpx.Client(transport=httpx.MockTransport(app), auth=auth) as client:
        threads = [
            threading.Thread(
                target=lambda: responses.append(client.get("http://example.org/"))
            )
            for _ in range(2)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    assert [response.status_code for response in responses] == [200, 200]
    assert sorted(nonce_counts) == ["00000001", "00000002"]


def test_digest_auth_does_not_reapply_cached_challenge_across_redirect() -> None:
    """
    When a redirect strips the 'Authorization' header, the cached challenge
    of the original origin must not be re-applied to the redirect target,
    and the target's own challenge must not replace it.
    """
    challenges = {
        "a.example.org": 'Digest realm="realm-a", qop="auth", nonce="nonce-a"',
        "b.example.org": 'Digest realm="realm-b", qop="auth", nonce="nonce-b"',
    }
    requests: typing.List[typing.Tuple[httpx.Request, typing.Optional[str]]] = []

    def app(request: httpx.Request) -> httpx.Response:
        requests.append((request, request.headers.get("Authorization")))
        if request.url.host == "a.example.org" and request.url.path == "/redirect":
            return httpx.Response(302, headers={"Location": "http://b.example.org/"})
        if "Authorization" not in request.headers:
            challenge = challenges[request.url.host]
            return httpx.Response(401, headers={"www-authenticate": challenge})
        return httpx.Response(200)

    auth = httpx.DigestAuth(username="user", password="password123")
    with httpx.Client(transport=httpx.MockTransport(app), auth=auth) as client:
        response = client.get("http://a.example.org/")
        assert response.status_code == 200

        # The redirect strips the 'Authorization' header, and the challenge
        # cached for 'a.example.org' is not re-applied to 'b.example.org'.
        # The 401 from the other origin is returned as-is.
        response = client.get("http://a.example.org/redirect", follow_redirects=True)
        assert response.status_code == 401

        # The challenge from 'b.example.org' was cached under its own
        # protection space, and is used for requests to that origin.
        response = client.get("http://b.example.org/")
        assert response.status_code == 200

        # The challenge cached for 'a.example.org' is still in place.
        response = client.get("http://a.example.org/")
        assert response.status_code == 200

    a_requests = [
        authorization
        for request, authorization in requests
        if request.url.host == "a.example.org"
    ]
    b_requests = [
        authorization
        for request, authorization in requests
        if request.url.host == "b.example.org"
    ]

    assert len(a_requests) == 4
    fields = parse_digest_auth_header(typing.cast(str, a_requests[3]))
    assert fields["realm"] == "realm-a"
    assert fields["nonce"] == "nonce-a"
    assert fields["nc"] == "00000003"

    # The redirected request reached 'b.example.org' unauthenticated...
    assert len(b_requests) == 2
    assert b_requests[0] is None
    # ... and the follow-up request uses the challenge that B issued.
    fields = parse_digest_auth_header(typing.cast(str, b_requests[1]))
    assert fields["realm"] == "realm-b"
    assert fields["nonce"] == "nonce-b"
    assert fields["nc"] == "00000001"


@pytest.mark.parametrize(
    "bad_challenge",
    [
        # Missing the required 'nonce' field.
        'Digest realm="realm", qop="auth"',
        # An algorithm that we do not support.
        'Digest realm="realm", qop="auth", nonce="nonce-2", algorithm=MD5-404',
    ],
)
def test_digest_auth_invalid_challenge_does_not_clobber_cache(
    bad_challenge: str,
) -> None:
    """
    A malformed or unsupported challenge must not replace a usable
    cached challenge.
    """
    state: typing.Dict[str, typing.Any] = {
        "challenge": 'Digest realm="realm", qop="auth", nonce="nonce-1"',
        "challenge_next": False,
    }
    requests: typing.List[typing.Tuple[httpx.Request, typing.Optional[str]]] = []

    def app(request: httpx.Request) -> httpx.Response:
        requests.append((request, request.headers.get("Authorization")))
        if state["challenge_next"] or "Authorization" not in request.headers:
            state["challenge_next"] = False
            return httpx.Response(401, headers={"www-authenticate": state["challenge"]})
        return httpx.Response(200)

    auth = httpx.DigestAuth(username="user", password="password123")
    with httpx.Client(transport=httpx.MockTransport(app), auth=auth) as client:
        response = client.get("http://example.org/")
        assert response.status_code == 200

        state["challenge"] = bad_challenge
        state["challenge_next"] = True
        with pytest.raises(httpx.ProtocolError):
            client.get("http://example.org/")

        # The previously cached challenge is still in place.
        response = client.get("http://example.org/")
        assert response.status_code == 200

    fields = parse_digest_auth_header(typing.cast(str, requests[-1][1]))
    assert fields["nonce"] == "nonce-1"
    assert fields["nc"] == "00000003"


@pytest.mark.anyio
async def test_async_auth_history() -> None:
    """
    Test that intermediate requests sent as part of an authentication flow
    are recorded in the response history.
    """
    url = "https://example.org/"
    auth = RepeatAuth(repeat=2)
    app = App(auth_header="abc")

    async with httpx.AsyncClient(transport=httpx.MockTransport(app)) as client:
        response = await client.get(url, auth=auth)

    assert response.status_code == 200
    assert response.json() == {"auth": "Repeat abc.abc"}

    assert len(response.history) == 2
    resp1, resp2 = response.history
    assert resp1.json() == {"auth": "Repeat 0"}
    assert resp2.json() == {"auth": "Repeat 1"}

    assert len(resp2.history) == 1
    assert resp2.history == [resp1]

    assert len(resp1.history) == 0


def test_sync_auth_history() -> None:
    """
    Test that intermediate requests sent as part of an authentication flow
    are recorded in the response history.
    """
    url = "https://example.org/"
    auth = RepeatAuth(repeat=2)
    app = App(auth_header="abc")

    with httpx.Client(transport=httpx.MockTransport(app)) as client:
        response = client.get(url, auth=auth)

    assert response.status_code == 200
    assert response.json() == {"auth": "Repeat abc.abc"}

    assert len(response.history) == 2
    resp1, resp2 = response.history
    assert resp1.json() == {"auth": "Repeat 0"}
    assert resp2.json() == {"auth": "Repeat 1"}

    assert len(resp2.history) == 1
    assert resp2.history == [resp1]

    assert len(resp1.history) == 0


class ConsumeBodyTransport(httpx.MockTransport):
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        assert isinstance(request.stream, httpx.AsyncByteStream)
        [_ async for _ in request.stream]
        return self.handler(request)  # type: ignore[return-value]


@pytest.mark.anyio
async def test_digest_auth_unavailable_streaming_body():
    url = "https://example.org/"
    auth = httpx.DigestAuth(username="user", password="password123")
    app = DigestApp()

    async def streaming_body() -> typing.AsyncIterator[bytes]:
        yield b"Example request body"  # pragma: no cover

    async with httpx.AsyncClient(transport=ConsumeBodyTransport(app)) as client:
        with pytest.raises(httpx.StreamConsumed):
            await client.post(url, content=streaming_body(), auth=auth)


@pytest.mark.anyio
async def test_async_auth_reads_response_body() -> None:
    """
    Test that we can read the response body in an auth flow if `requires_response_body`
    is set.
    """
    url = "https://example.org/"
    auth = ResponseBodyAuth("xyz")
    app = App()

    async with httpx.AsyncClient(transport=httpx.MockTransport(app)) as client:
        response = await client.get(url, auth=auth)

    assert response.status_code == 200
    assert response.json() == {"auth": '{"auth":"xyz"}'}


def test_sync_auth_reads_response_body() -> None:
    """
    Test that we can read the response body in an auth flow if `requires_response_body`
    is set.
    """
    url = "https://example.org/"
    auth = ResponseBodyAuth("xyz")
    app = App()

    with httpx.Client(transport=httpx.MockTransport(app)) as client:
        response = client.get(url, auth=auth)

    assert response.status_code == 200
    assert response.json() == {"auth": '{"auth":"xyz"}'}


@pytest.mark.anyio
async def test_async_auth() -> None:
    """
    Test that we can use an auth implementation specific to the async case, to
    support cases that require performing I/O or using concurrency primitives (such
    as checking a disk-based cache or fetching a token from a remote auth server).
    """
    url = "https://example.org/"
    auth = SyncOrAsyncAuth()
    app = App()

    async with httpx.AsyncClient(transport=httpx.MockTransport(app)) as client:
        response = await client.get(url, auth=auth)

    assert response.status_code == 200
    assert response.json() == {"auth": "async-auth"}


def test_sync_auth() -> None:
    """
    Test that we can use an auth implementation specific to the sync case.
    """
    url = "https://example.org/"
    auth = SyncOrAsyncAuth()
    app = App()

    with httpx.Client(transport=httpx.MockTransport(app)) as client:
        response = client.get(url, auth=auth)

    assert response.status_code == 200
    assert response.json() == {"auth": "sync-auth"}
