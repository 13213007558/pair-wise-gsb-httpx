"""
Unit tests for auth classes.

Integration tests also exist in tests/client/test_auth.py
"""

import typing
from urllib.request import parse_http_list, parse_keqv_list

import pytest

import httpx


def test_basic_auth():
    auth = httpx.BasicAuth(username="user", password="pass")
    request = httpx.Request("GET", "https://www.example.com")

    # The initial request should include a basic auth header.
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert request.headers["Authorization"].startswith("Basic")

    # No other requests are made.
    response = httpx.Response(content=b"Hello, world!", status_code=200)
    with pytest.raises(StopIteration):
        flow.send(response)


def test_digest_auth_with_200():
    auth = httpx.DigestAuth(username="user", password="pass")
    request = httpx.Request("GET", "https://www.example.com")

    # The initial request should not include an auth header.
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert "Authorization" not in request.headers

    # If a 200 response is returned, then no other requests are made.
    response = httpx.Response(content=b"Hello, world!", status_code=200)
    with pytest.raises(StopIteration):
        flow.send(response)


def test_digest_auth_with_401():
    auth = httpx.DigestAuth(username="user", password="pass")
    request = httpx.Request("GET", "https://www.example.com")

    # The initial request should not include an auth header.
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert "Authorization" not in request.headers

    # If a 401 response is returned, then a digest auth request is made.
    headers = {
        "WWW-Authenticate": 'Digest realm="...", qop="auth", nonce="...", opaque="..."'
    }
    response = httpx.Response(
        content=b"Auth required", status_code=401, headers=headers, request=request
    )
    request = flow.send(response)
    assert request.headers["Authorization"].startswith("Digest")

    # No other requests are made.
    response = httpx.Response(content=b"Hello, world!", status_code=200)
    with pytest.raises(StopIteration):
        flow.send(response)


def test_digest_auth_with_401_nonce_counting():
    auth = httpx.DigestAuth(username="user", password="pass")
    request = httpx.Request("GET", "https://www.example.com")

    # The initial request should not include an auth header.
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert "Authorization" not in request.headers

    # If a 401 response is returned, then a digest auth request is made.
    headers = {
        "WWW-Authenticate": 'Digest realm="...", qop="auth", nonce="...", opaque="..."'
    }
    response = httpx.Response(
        content=b"Auth required", status_code=401, headers=headers, request=request
    )
    first_request = flow.send(response)
    assert first_request.headers["Authorization"].startswith("Digest")

    # Each subsequent request contains the digest header by default...
    request = httpx.Request("GET", "https://www.example.com")
    flow = auth.sync_auth_flow(request)
    second_request = next(flow)
    assert second_request.headers["Authorization"].startswith("Digest")

    # ... and the client nonce count (nc) is increased
    first_nc = parse_keqv_list(first_request.headers["Authorization"].split(", "))["nc"]
    second_nc = parse_keqv_list(second_request.headers["Authorization"].split(", "))[
        "nc"
    ]
    assert int(first_nc, 16) + 1 == int(second_nc, 16)

    # No other requests are made.
    response = httpx.Response(content=b"Hello, world!", status_code=200)
    with pytest.raises(StopIteration):
        flow.send(response)


def set_cookies(request: httpx.Request) -> httpx.Response:
    headers = {
        "Set-Cookie": "session=.session_value...",
        "WWW-Authenticate": 'Digest realm="...", qop="auth", nonce="...", opaque="..."',
    }
    if request.url.path == "/auth":
        return httpx.Response(
            content=b"Auth required", status_code=401, headers=headers
        )
    else:
        raise NotImplementedError()  # pragma: no cover


def test_digest_auth_setting_cookie_in_request():
    url = "https://www.example.com/auth"
    client = httpx.Client(transport=httpx.MockTransport(set_cookies))
    request = client.build_request("GET", url)

    auth = httpx.DigestAuth(username="user", password="pass")
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert "Authorization" not in request.headers

    response = client.get(url)
    assert len(response.cookies) > 0
    assert response.cookies["session"] == ".session_value..."

    request = flow.send(response)
    assert request.headers["Authorization"].startswith("Digest")
    assert request.headers["Cookie"] == "session=.session_value..."

    # No other requests are made.
    response = httpx.Response(
        content=b"Hello, world!", status_code=200, request=request
    )
    with pytest.raises(StopIteration):
        flow.send(response)


def test_digest_auth_rfc_2069():
    # Example from https://datatracker.ietf.org/doc/html/rfc2069#section-2.4
    # with corrected response from https://www.rfc-editor.org/errata/eid749

    auth = httpx.DigestAuth(username="Mufasa", password="CircleOfLife")
    request = httpx.Request("GET", "https://www.example.com/dir/index.html")

    # The initial request should not include an auth header.
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert "Authorization" not in request.headers

    # If a 401 response is returned, then a digest auth request is made.
    headers = {
        "WWW-Authenticate": (
            'Digest realm="testrealm@host.com", '
            'nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", '
            'opaque="5ccc069c403ebaf9f0171e9517f40e41"'
        )
    }
    response = httpx.Response(
        content=b"Auth required", status_code=401, headers=headers, request=request
    )
    request = flow.send(response)
    assert request.headers["Authorization"].startswith("Digest")
    assert 'username="Mufasa"' in request.headers["Authorization"]
    assert 'realm="testrealm@host.com"' in request.headers["Authorization"]
    assert (
        'nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093"' in request.headers["Authorization"]
    )
    assert 'uri="/dir/index.html"' in request.headers["Authorization"]
    assert (
        'opaque="5ccc069c403ebaf9f0171e9517f40e41"' in request.headers["Authorization"]
    )
    assert (
        'response="1949323746fe6a43ef61f9606e7febea"'
        in request.headers["Authorization"]
    )

    # No other requests are made.
    response = httpx.Response(content=b"Hello, world!", status_code=200)
    with pytest.raises(StopIteration):
        flow.send(response)


def test_digest_auth_rfc_7616_md5(monkeypatch):
    # Example from https://datatracker.ietf.org/doc/html/rfc7616#section-3.9.1

    def mock_get_client_nonce(nonce_count: int, nonce: bytes) -> bytes:
        return "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ".encode()

    auth = httpx.DigestAuth(username="Mufasa", password="Circle of Life")
    monkeypatch.setattr(auth, "_get_client_nonce", mock_get_client_nonce)

    request = httpx.Request("GET", "https://www.example.com/dir/index.html")

    # The initial request should not include an auth header.
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert "Authorization" not in request.headers

    # If a 401 response is returned, then a digest auth request is made.
    headers = {
        "WWW-Authenticate": (
            'Digest realm="http-auth@example.org", '
            'qop="auth, auth-int", '
            "algorithm=MD5, "
            'nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", '
            'opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"'
        )
    }
    response = httpx.Response(
        content=b"Auth required", status_code=401, headers=headers, request=request
    )
    request = flow.send(response)
    assert request.headers["Authorization"].startswith("Digest")
    assert 'username="Mufasa"' in request.headers["Authorization"]
    assert 'realm="http-auth@example.org"' in request.headers["Authorization"]
    assert 'uri="/dir/index.html"' in request.headers["Authorization"]
    assert "algorithm=MD5" in request.headers["Authorization"]
    assert (
        'nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v"'
        in request.headers["Authorization"]
    )
    assert "nc=00000001" in request.headers["Authorization"]
    assert (
        'cnonce="f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ"'
        in request.headers["Authorization"]
    )
    assert "qop=auth" in request.headers["Authorization"]
    assert (
        'opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"'
        in request.headers["Authorization"]
    )
    assert (
        'response="8ca523f5e9506fed4657c9700eebdbec"'
        in request.headers["Authorization"]
    )

    # No other requests are made.
    response = httpx.Response(content=b"Hello, world!", status_code=200)
    with pytest.raises(StopIteration):
        flow.send(response)


def test_digest_auth_rfc_7616_sha_256(monkeypatch):
    # Example from https://datatracker.ietf.org/doc/html/rfc7616#section-3.9.1

    def mock_get_client_nonce(nonce_count: int, nonce: bytes) -> bytes:
        return "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ".encode()

    auth = httpx.DigestAuth(username="Mufasa", password="Circle of Life")
    monkeypatch.setattr(auth, "_get_client_nonce", mock_get_client_nonce)

    request = httpx.Request("GET", "https://www.example.com/dir/index.html")

    # The initial request should not include an auth header.
    flow = auth.sync_auth_flow(request)
    request = next(flow)
    assert "Authorization" not in request.headers

    # If a 401 response is returned, then a digest auth request is made.
    headers = {
        "WWW-Authenticate": (
            'Digest realm="http-auth@example.org", '
            'qop="auth, auth-int", '
            "algorithm=SHA-256, "
            'nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", '
            'opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"'
        )
    }
    response = httpx.Response(
        content=b"Auth required", status_code=401, headers=headers, request=request
    )
    request = flow.send(response)
    assert request.headers["Authorization"].startswith("Digest")
    assert 'username="Mufasa"' in request.headers["Authorization"]
    assert 'realm="http-auth@example.org"' in request.headers["Authorization"]
    assert 'uri="/dir/index.html"' in request.headers["Authorization"]
    assert "algorithm=SHA-256" in request.headers["Authorization"]
    assert (
        'nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v"'
        in request.headers["Authorization"]
    )
    assert "nc=00000001" in request.headers["Authorization"]
    assert (
        'cnonce="f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ"'
        in request.headers["Authorization"]
    )
    assert "qop=auth" in request.headers["Authorization"]
    assert (
        'opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"'
        in request.headers["Authorization"]
    )
    assert (
        'response="753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1"'
        in request.headers["Authorization"]
    )

    # No other requests are made.
    response = httpx.Response(content=b"Hello, world!", status_code=200)
    with pytest.raises(StopIteration):
        flow.send(response)


# Fixed challenge material so the auth-int vectors can be recomputed by hand
# from the RFC 7616 section 3.4.2 formulas.
_AUTH_INT_REALM = "http-auth@example.org"
_AUTH_INT_NONCE = "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v"
_AUTH_INT_CNONCE = "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ"
_AUTH_INT_OPAQUE = "FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"
_AUTH_INT_BODY = b"Hello, world"


def _auth_int_challenge(algorithm: str) -> dict[str, str]:
    return {
        "WWW-Authenticate": (
            f'Digest realm="{_AUTH_INT_REALM}", '
            'qop="auth, auth-int", '
            f"algorithm={algorithm}, "
            f'nonce="{_AUTH_INT_NONCE}", '
            f'opaque="{_AUTH_INT_OPAQUE}"'
        )
    }


def _run_auth_int_flow(algorithm: str, body: typing.Any) -> dict[str, str]:
    auth = httpx.DigestAuth(
        username="Mufasa", password="Circle of Life", qop="auth-int"
    )
    auth._get_client_nonce = lambda nonce_count, nonce: _AUTH_INT_CNONCE.encode()

    request = httpx.Request(
        "POST", "https://www.example.com/dir/index.html", content=body
    )
    flow = auth.sync_auth_flow(request)
    next(flow)

    response = httpx.Response(
        content=b"Auth required",
        status_code=401,
        headers=_auth_int_challenge(algorithm),
        request=request,
    )
    authenticated = flow.send(response)
    fields = parse_keqv_list(
        parse_http_list(authenticated.headers["Authorization"].partition(" ")[2])
    )
    flow.close()
    return fields


@pytest.mark.parametrize(
    "algorithm,expected_response",
    [
        ("MD5", "0d787b614185382aaa6e3fb0fcf31aa1"),
        ("MD5-SESS", "012301b1737a4ea1a0fd6c3c4131ed97"),
        ("SHA-256", "5dd87cb278bd95db9693bc233c99f6f09c859465d7ea1650b8c7aa606b8e7511"),
        (
            "SHA-256-SESS",
            "4608f171ce3590fa845225288bb17165d4e9468ddc4f2b77a3d76d7453889c53",
        ),
    ],
)
def test_digest_auth_int_rfc_7616_vectors(
    algorithm: str, expected_response: str
) -> None:
    fields = _run_auth_int_flow(algorithm, _AUTH_INT_BODY)

    assert fields["qop"] == "auth-int"
    assert fields["algorithm"] == algorithm
    assert fields["nc"] == "00000001"
    assert fields["cnonce"] == _AUTH_INT_CNONCE
    assert fields["uri"] == "/dir/index.html"
    assert fields["response"] == expected_response


def test_digest_auth_int_empty_body_vector() -> None:
    # H(entity-body) of an empty body is the hash of b"", per RFC 7616 3.4.2.
    fields = _run_auth_int_flow("MD5", b"")

    assert fields["qop"] == "auth-int"
    assert fields["response"] == "35ec75c6389a8fd8412c13222b3affe8"


def test_digest_auth_int_hashes_raw_bytes_not_text() -> None:
    # A non-ASCII str body must be hashed as its UTF-8 encoded entity bytes,
    # not as the decoded text.
    fields_text = _run_auth_int_flow("MD5", "Hëllo")
    fields_bytes = _run_auth_int_flow("MD5", "Hëllo".encode("utf-8"))

    assert fields_text["response"] == fields_bytes["response"]


def test_digest_auth_int_ignores_chunked_framing() -> None:
    # The same logical entity delivered via a chunked iterator must produce
    # the same response as a plain bytes body: framing bytes are excluded.
    def chunked() -> typing.Iterator[bytes]:
        yield _AUTH_INT_BODY[:5]
        yield _AUTH_INT_BODY[5:]

    fields_iter = _run_auth_int_flow("MD5", chunked())
    fields_bytes = _run_auth_int_flow("MD5", _AUTH_INT_BODY)

    assert fields_iter["response"] == fields_bytes["response"]
    assert fields_iter["response"] == "0d787b614185382aaa6e3fb0fcf31aa1"


def test_digest_auth_int_bytes_body_is_replayable() -> None:
    fields = _run_auth_int_flow("SHA-256", _AUTH_INT_BODY)
    assert fields["qop"] == "auth-int"
    assert fields["response"] == (
        "5dd87cb278bd95db9693bc233c99f6f09c859465d7ea1650b8c7aa606b8e7511"
    )


def test_digest_auth_explicit_auth_int_not_downgraded() -> None:
    auth = httpx.DigestAuth(username="user", password="pass", qop="auth-int")
    request = httpx.Request("GET", "https://www.example.com")
    flow = auth.sync_auth_flow(request)
    next(flow)

    response = httpx.Response(
        content=b"Auth required",
        status_code=401,
        headers={"WWW-Authenticate": 'Digest realm="r", qop="auth", nonce="n"'},
        request=request,
    )
    with pytest.raises(httpx.ProtocolError):
        flow.send(response)


def test_digest_auth_server_offering_both_prefers_auth_by_default() -> None:
    auth = httpx.DigestAuth(username="user", password="pass")
    request = httpx.Request("GET", "https://www.example.com")
    flow = auth.sync_auth_flow(request)
    next(flow)

    response = httpx.Response(
        content=b"Auth required",
        status_code=401,
        headers={
            "WWW-Authenticate": 'Digest realm="r", qop="auth, auth-int", nonce="n"'
        },
        request=request,
    )
    authenticated = flow.send(response)
    assert "qop=auth" in authenticated.headers["Authorization"]
    assert "qop=auth-int" not in authenticated.headers["Authorization"]
