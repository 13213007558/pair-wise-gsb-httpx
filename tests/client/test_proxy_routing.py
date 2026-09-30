import logging

import httpx
import pytest


PROXY_A = "http://proxy-a.example"
PROXY_B = "http://proxy-b.example"


def test_no_proxy_ipv6_cidr_port_and_defaults():
    policy = httpx.ProxyPolicy(
        proxies={"all://": PROXY_A}, no_proxy=["[2001:db8::]/32:443"]
    )

    assert policy.route(httpx.URL("https://[2001:db8::1]")).direct
    assert not policy.route(httpx.URL("https://[2001:db8::1]:8443")).direct
    assert not policy.route(httpx.URL("https://[2002:db8::1]")).direct


def test_no_proxy_ipv6_cidr_inside_brackets():
    policy = httpx.ProxyPolicy(
        proxies={"all://": PROXY_A},
        no_proxy=["[2001:db8::/32]:443"],
    )

    assert policy.route(httpx.URL("https://[2001:db8::1]")).direct
    assert not policy.route(httpx.URL("https://[2001:db8::1]:8443")).direct


def test_no_proxy_ipv4_cidr_and_literal():
    policy = httpx.ProxyPolicy(
        proxies={"all://": PROXY_A},
        no_proxy=["10.0.0.0/8", "192.168.1.1"],
    )

    assert policy.route(httpx.URL("https://10.1.2.3")).direct
    assert policy.route(httpx.URL("https://192.168.1.1")).direct
    assert policy.route(httpx.URL("https://192.168.1.2")).proxy is not None


@pytest.mark.parametrize(
    "token,url",
    [
        ("example.com:bad", "https://example.com"),
        ("example.com:70000", "https://example.com"),
        ("10.0.0.0/33", "https://10.0.0.1"),
        ("10.0.0.1/8", "https://10.0.0.1"),
        ("::1:8080", "https://[::1]:8080"),
        ("[::1", "https://[::1]"),
        ("[2001:db8::/32]/32:443", "https://[2001:db8::1]"),
        ("http://10.0.0.1/path", "http://10.0.0.1"),
        ("foo..example.com", "https://foo.example.com"),
        ("10.0.0.0/8/path", "https://10.0.0.1"),
        ("*example.com", "https://foo.example.com"),
    ],
)
def test_ambiguous_no_proxy_token_rejected(token, url):
    with pytest.raises(ValueError, match="Invalid NO_PROXY token"):
        httpx.ProxyPolicy(proxies={"all://": PROXY_A}, no_proxy=[token]).route(
            httpx.URL(url)
        )


def test_no_proxy_normalization():
    policy = httpx.ProxyPolicy(
        proxies={"all://": PROXY_A},
        no_proxy=[".Example.COM.", "127.0.0.1:443", "*:8080"],
    )

    assert policy.route(httpx.URL("https://WWW.example.com.")).direct
    assert not policy.route(httpx.URL("https://example.com.")).direct
    assert policy.route(httpx.URL("https://127.0.0.1")).direct
    assert not policy.route(httpx.URL("https://127.0.0.1:8443")).direct
    assert policy.route(httpx.URL("http://example.com:8080")).direct


def test_client_mapping_takes_precedence_over_environment(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", PROXY_A)
    client = httpx.Client(proxies={"https://": PROXY_B})

    decision = client.proxy_policy.route(httpx.URL("https://example.com"))
    assert decision.proxy == httpx.Proxy(PROXY_B)


def test_invalid_client_proxy_mapping_is_rejected():
    with pytest.raises(ValueError, match="Proxy keys should use proper URL forms"):
        httpx.Client(proxies={"http": PROXY_A})


def test_invalid_proxy_url_is_rejected():
    with pytest.raises(ValueError, match="Unknown scheme for proxy URL"):
        httpx.Client(proxies={"http://": "ftp://proxy.example"})


def test_environment_no_proxy_beats_all_proxy(monkeypatch):
    monkeypatch.setenv("ALL_PROXY", PROXY_A)
    monkeypatch.setenv("NO_PROXY", "example.com")
    client = httpx.Client()

    assert client.proxy_route("https://example.com").direct
    assert client.proxy_route("https://other.example").proxy is not None


def test_per_request_override_and_direct():
    client = httpx.Client(proxies={"all://": PROXY_A})

    request = client.build_request("GET", "https://example.com", proxy=PROXY_B)
    decision = client.proxy_policy.route(
        request.url, override=request.extensions["proxy_override"]
    )
    assert decision.proxy == httpx.Proxy(PROXY_B)

    request = client.build_request("GET", "https://example.com", proxy=False)
    decision = client.proxy_policy.route(
        request.url, override=request.extensions["proxy_override"]
    )
    assert decision.direct


def test_no_proxy_beats_per_request_override():
    policy = httpx.ProxyPolicy(
        proxies={"all://": PROXY_A}, no_proxy=["example.com"]
    )
    decision = policy.route(httpx.URL("https://example.com"), override=PROXY_B)
    assert decision.direct
    assert decision.rule == "example.com"


def test_https_decision_includes_connect_line_and_auth():
    proxy = "http://user:pass@proxy.example"
    client = httpx.Client(proxies={"all://": proxy})
    request = client.build_request("GET", "https://[2001:DB8::1]:443", proxy=proxy)
    decision = client.proxy_policy.route(
        request.url, override=request.extensions.get("proxy_override")
    )

    assert decision.authenticated
    assert decision.connect_line(request.url) == "CONNECT [2001:db8::1]:443 HTTP/1.1"

    http_decision = client.proxy_policy.route(httpx.URL("http://example.com"))
    assert http_decision.connect_line(httpx.URL("http://example.com")) is None


def test_socks_proxy_has_no_connect_line():
    client = httpx.Client(proxies={"all://": "socks5://proxy.example"})
    decision = client.proxy_policy.route(httpx.URL("https://example.com"))
    assert decision.proxy.url.scheme == "socks5"
    assert decision.connect_line(httpx.URL("https://example.com")) is None


def test_decision_is_logged_and_attached(caplog):
    def handler(request):
        return httpx.Response(200)

    client = httpx.Client(
        proxies={"all://": PROXY_A},
        mounts={"https://example.com": httpx.MockTransport(handler)},
        no_proxy=["example.com"],
    )
    caplog.set_level(logging.DEBUG, logger="httpx")

    response = client.get("https://example.com")
    assert response.extensions["proxy_route"].direct
    assert "Client mount selected transport" in caplog.text


def test_redirect_does_not_reuse_cross_origin_request_proxy():
    def handler(request):
        return httpx.Response(302, headers={"location": "https://end.example/"})
    client = httpx.Client(transport=httpx.MockTransport(handler))
    request = client.build_request("GET", "https://start.example/", proxy=PROXY_B)
    response = handler(request)

    redirected = client._build_redirect_request(request, response)
    assert "proxy_override" not in redirected.extensions


def test_same_origin_redirect_keeps_request_proxy():
    def handler(request):
        return httpx.Response(302, headers={"location": "/end"})
    client = httpx.Client(transport=httpx.MockTransport(handler))
    request = client.build_request(
        "GET", "https://start.example/start", proxy=PROXY_B
    )
    response = handler(request)

    redirected = client._build_redirect_request(request, response)
    assert redirected.extensions["proxy_override"] == httpx.Proxy(PROXY_B)


def test_per_request_override_uses_dedicated_transport():
    client = httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200))
    )
    request = client.build_request("GET", "https://example.com", proxy=PROXY_B)

    transport, decision = client._transport_for_request(request)

    assert transport is not client._transport
    assert transport is client._proxy_transports[httpx.Proxy(PROXY_B)]
    assert decision.source == "request"


@pytest.mark.anyio
async def test_asgi_transport_rejects_explicit_proxy():
    async def app(scope, receive, send):
        await send(
            {"type": "http.response.start", "status": 200, "headers": []}
        )
        await send({"type": "http.response.body", "body": b""})

    transport = httpx.ASGITransport(app=app)
    client = httpx.AsyncClient(transport=transport, proxies={"all://": PROXY_A})
    with pytest.raises(ValueError, match="Cannot route ASGI"):
        await client.get("https://example.com")


def test_wsgi_transport_rejects_explicit_proxy():
    def app(environ, start_response):
        start_response("200 OK", [])
        return [b""]

    transport = httpx.WSGITransport(app=app)
    client = httpx.Client(transport=transport, proxies={"all://": PROXY_A})
    with pytest.raises(ValueError, match="Cannot route ASGI/WSGI"):
        client.get("https://example.com")
