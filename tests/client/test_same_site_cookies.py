from __future__ import annotations

import asyncio
import threading

import pytest

import httpx


def recording_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path.startswith("/redirect"):
        location = request.headers.get("x-location")
        set_cookie = request.headers.get_list("x-set-cookie")
        headers = {"location": location}
        for cookie in set_cookie:
            headers.setdefault("set-cookie", cookie)
        return httpx.Response(303, headers=headers)
    return httpx.Response(200, json={"cookie": request.headers.get("Cookie")})


def test_same_site_policy_is_rfc6265_compatible_by_default() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/start":
            return httpx.Response(
                303,
                headers={"location": "https://other.example.org/end"},
            )
        return httpx.Response(200)

    with httpx.Client(
        transport=httpx.MockTransport(handler), follow_redirects=True
    ) as client:
        client.cookies.set(
            "a", "b", domain="other.example.org", secure=True, same_site="Strict"
        )
        client.get("https://example.com/start")

    assert requests[1].headers["Cookie"] == "a=b"


def test_strict_cookie_is_not_sent_on_cross_site_redirect() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/start":
            return httpx.Response(
                303,
                headers={"location": "https://other.example.org/end"},
            )
        return httpx.Response(200)

    with httpx.Client(
        transport=httpx.MockTransport(handler),
        same_site_policy="strict",
        follow_redirects=True,
    ) as client:
        client.cookies.set(
            "a", "b", domain="other.example.org", secure=True, same_site="Strict"
        )
        client.get("https://example/start")

    assert requests[0].headers.get("Cookie") is None
    assert requests[1].headers.get("Cookie") is None


def test_lax_policy_allows_top_level_get_but_blocks_post() -> None:
    get_requests: list[httpx.Request] = []
    post_requests: list[httpx.Request] = []

    def handler(request: httpx.Request, seen: list[httpx.Request]) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/start":
            status_code = 308 if request.method == "POST" else 303
            return httpx.Response(
                status_code,
                headers={"location": "https://other.example.org/end"},
            )
        return httpx.Response(200)

    with httpx.Client(
        transport=httpx.MockTransport(lambda request: handler(request, get_requests)),
        same_site_policy="lax",
        follow_redirects=True,
    ) as client:
        client.cookies.set(
            "a", "b", domain="other.example.org", secure=True, same_site="Lax"
        )
        client.get("https://example/start")
    with httpx.Client(
        transport=httpx.MockTransport(lambda request: handler(request, post_requests)),
        same_site_policy="lax",
        follow_redirects=True,
    ) as client:
        client.cookies.set(
            "a", "b", domain="other.example.org", secure=True, same_site="Lax"
        )
        client.post("https://example/start")

    assert get_requests[1].headers["Cookie"] == "a=b"
    assert post_requests[1].headers.get("Cookie") is None


def test_domain_public_suffix_and_subdomains() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/start":
            return httpx.Response(
                303,
                headers=[
                    (
                        "set-cookie",
                        "host=1; Path=/; Secure",
                    ),
                    (
                        "set-cookie",
                        "rejected=2; Domain=co.uk; Path=/; Secure",
                    ),
                    (
                        "set-cookie",
                        "allowed=3; Domain=.example.co.uk; Path=/; Secure",
                    ),
                    (
                        "location",
                        "https://shop.example.co.uk/end",
                    ),
                ],
            )
        return httpx.Response(200)

    with httpx.Client(
        transport=httpx.MockTransport(handler),
        same_site_policy="lax",
        follow_redirects=True,
    ) as client:
        client.get("https://example.co.uk/start")

    assert seen[1].headers["Cookie"] == "allowed=3"


def test_path_boundary_and_secure_are_recomputed_each_hop() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/start":
            return httpx.Response(
                303,
                    headers=[
                        (
                            "set-cookie",
                            "exact=1; Path=/app/; SameSite=Lax",
                        ),
                        ("set-cookie", "other=2; Path=/; SameSite=Lax"),
                        (
                            "set-cookie",
                            "secret=3; Path=/; Secure; SameSite=Lax",
                        ),
                    ("location", "http://example/application"),
                ],
            )
        return httpx.Response(200)

    with httpx.Client(
        transport=httpx.MockTransport(handler),
        same_site_policy="lax",
        follow_redirects=True,
    ) as client:
        client.get("https://example/start")

    assert seen[1].headers["Cookie"] == "other=2"


def test_ipv6_requires_exact_host_match() -> None:
    cookies = httpx.Cookies(same_site_policy="strict")
    cookies.set("a", "b", domain="2001:db8::1", path="/", secure=True)
    request = httpx.Request("GET", "https://[2001:db8::1]/")
    cookies.set_cookie_header(request)
    other = httpx.Request("GET", "https://[2001:db8::2]/")
    cookies.set_cookie_header(other)

    assert request.headers["Cookie"] == "a=b"
    assert other.headers.get("Cookie") is None


def test_ipv6_cookie_set_by_response_is_replayed_on_next_hop() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/start":
            return httpx.Response(
                303,
                headers=[
                    ("location", "http://[2001:db8::1]/end"),
                    ("set-cookie", "a=b; Path=/; SameSite=Lax"),
                ],
            )
        return httpx.Response(200)

    with httpx.Client(
        transport=httpx.MockTransport(handler),
        same_site_policy="lax",
        follow_redirects=True,
    ) as client:
        client.get("http://[2001:db8::1]/start")

    assert seen[1].headers["Cookie"] == "a=b"


def test_expired_cookie_is_removed_on_redirect() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/start":
            return httpx.Response(
                303,
                headers=[
                    ("set-cookie", "a=1; Path=/; Max-Age=100"),
                    ("set-cookie", "b=2; Path=/; Max-Age=0"),
                    ("location", "/end"),
                ],
            )
        return httpx.Response(200)

    with httpx.Client(
        transport=httpx.MockTransport(handler), same_site_policy="lax"
    ) as client:
        response = client.get("http://example/start", follow_redirects=True)

    assert response.status_code == 200
    assert seen[1].headers["Cookie"] == "a=1"
    assert "b" not in client.cookies


def test_manual_cookie_header_does_not_bypass_policy() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/start":
            return httpx.Response(
                303, headers={"location": "https://other.example.org/end"}
            )
        return httpx.Response(200)

    with httpx.Client(
        transport=httpx.MockTransport(handler),
        same_site_policy="strict",
        follow_redirects=True,
    ) as client:
        client.get("https://example/start", headers={"Cookie": "a=b"})

    assert seen[0].headers["Cookie"] == "a=b"
    assert seen[1].headers.get("Cookie") is None


def test_auth_retry_does_not_bypass_policy() -> None:
    seen: list[str | None] = []

    class HeaderAuth(httpx.Auth):
        def auth_flow(self, request: httpx.Request):
            response = yield request
            if response.status_code == 401:
                request.headers["Cookie"] = "a=b"
                yield request

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("Cookie"))
        if request.url.path == "/start":
            return httpx.Response(
                303, headers={"location": "https://other.example.org/"}
            )
        return httpx.Response(401 if len(seen) < 3 else 200)

    with httpx.Client(
        transport=httpx.MockTransport(handler), same_site_policy="strict"
    ) as client:
        client.send(
            httpx.Request("GET", "https://example.com/start"),
            auth=HeaderAuth(),
            follow_redirects=True,
        )

    assert seen[0] is None
    assert seen[1] is None
    assert seen[-1] is None


def test_port_is_recomputed_with_same_site_redirect() -> None:
    cookies = httpx.Cookies(same_site_policy="strict")
    cookies.set("a", "b", domain="localhost", path="/")
    cookie = cookies.jar._cookies["localhost"]["/"]["a"]
    cookie.port = "8000"
    cookie.port_specified = True

    matching = httpx.Request("GET", "http://localhost:8000/")
    different = httpx.Request("GET", "http://localhost:9000/")
    cookies.set_cookie_header(matching)
    cookies.set_cookie_header(different)

    assert matching.headers["Cookie"] == "a=b"
    assert different.headers.get("Cookie") is None


def test_sync_concurrent_requests_use_independent_headers() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"cookie": request.headers.get("Cookie")})

    with httpx.Client(
        transport=httpx.MockTransport(handler), same_site_policy="lax"
    ) as client:
        client.cookies.set("a", "b", domain="example.com", path="/")
        responses = []

        def request_once() -> None:
            responses.append(client.get("http://example.com/").json()["cookie"])

        threads = [threading.Thread(target=request_once) for _ in range(20)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    assert responses == ["a=b"] * 20


def test_cookie_copy_does_not_share_jar_iterator() -> None:
    cookies = httpx.Cookies(same_site_policy="lax")
    cookies.set("a", "b")
    copied = cookies.copy()
    copied.set("c", "d")

    assert list(cookies) == ["a"]
    assert list(copied) == ["a", "c"]


def test_client_replaces_cookies_without_losing_policy() -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(recording_handler),
        same_site_policy="strict",
    )
    try:
        client.cookies = {"a": "b"}
        assert client.same_site_policy == "strict"
        assert client.cookies.same_site_policy is httpx.SameSitePolicy.STRICT
    finally:
        client.close()


@pytest.mark.anyio
async def test_async_concurrent_requests_use_independent_headers() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"cookie": request.headers.get("Cookie")})

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), same_site_policy="lax"
    ) as client:
        client.cookies.set("a", "b", domain="example.com", path="/")

        async def request_once() -> str:
            return (await client.get("http://example.com/")).json()["cookie"]

        responses = await asyncio.gather(*(request_once() for _ in range(20)))

    assert responses == ["a=b"] * 20
