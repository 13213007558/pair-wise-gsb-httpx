import copy
import threading
from urllib.parse import urlsplit

import anyio
import pytest

import httpx
from httpx._cookies import public_suffix, registrable_domain, same_site


def make_cookie(
    name: str,
    *,
    value: str,
    domain: str,
    path: str = "/",
    secure: bool = False,
    samesite: str | None = None,
    max_age: int | None = None,
    port: str | None = None,
) -> str:
    parts = [f"{name}={value}", f"path={path}"]
    parts.append(f"domain={domain}")
    if secure:
        parts.append("secure")
    if samesite is not None:
        parts.append(f"samesite={samesite}")
    if max_age is not None:
        parts.append(f"max-age={max_age}")
    if port is not None:
        parts.append(f'port="{port}"')
    return "; ".join(parts)


class RedirectHandler:
    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.set_cookie: str | None = None

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        parts = urlsplit(str(request.url))
        if parts.path.startswith("/set-and-redirect"):
            return httpx.Response(
                302,
                headers={
                    "location": parts.query,
                    "set-cookie": self.set_cookie or "policy=default",
                },
            )
        return httpx.Response(200, json={"cookie": request.headers.get("Cookie")})


def test_same_site_lax_cookie_not_sent_cross_site_get() -> None:
    cookies = httpx.Cookies(same_site_policy="lax")
    cookies.set("session", "value", domain=".example.com")
    cookie = next(iter(cookies.jar))
    cookie.set_nonstandard_attr("SameSite", "Lax")
    client = httpx.Client(
        cookies=cookies,
        same_site_policy="lax",
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200, json={"cookie": request.headers.get("Cookie")}
            )
        ),
    )

    same_site = client.get("https://www.example.com/")
    cross_site = client.get("https://www.example.net/")

    assert same_site.json()["cookie"] == "session=value"
    assert cross_site.json()["cookie"] is None


def test_rfc6265_default_remains_legacy_compatible() -> None:
    cookies = httpx.Cookies()
    cookies.set("session", "value", domain=".example.com")
    next(iter(cookies.jar)).set_nonstandard_attr("SameSite", "Strict")
    client = httpx.Client(
        cookies=cookies,
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200, json={"cookie": request.headers.get("Cookie")}
            )
        ),
    )

    response = client.get("https://other.example.com/")

    assert response.json()["cookie"] == "session=value"


def test_same_site_none_secure_cookie_can_be_cross_site() -> None:
    cookies = httpx.Cookies(same_site_policy="none")
    cookies.set("session", "value", domain=".example.com", )
    cookie = next(iter(cookies.jar))
    cookie.secure = True
    cookie.set_nonstandard_attr("SameSite", "None")
    client = httpx.Client(
        cookies=cookies,
        same_site_policy="none",
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200, json={"cookie": request.headers.get("Cookie")}
            )
        ),
    )

    response = client.get("https://other.example.com/")

    assert response.json()["cookie"] == "session=value"


def test_same_site_strict_blocks_cross_site_redirect() -> None:
    handler = RedirectHandler()
    cookies = httpx.Cookies(same_site_policy="strict")
    cookies.set("session", "value", domain=".example.com")
    next(iter(cookies.jar)).set_nonstandard_attr("SameSite", "Strict")
    client = httpx.Client(
        cookies=cookies,
        same_site_policy="strict",
        transport=httpx.MockTransport(handler),
        follow_redirects=True,
    )

    response = client.get(
        "https://www.example.com/set-and-redirect?https://www.example.net/landing",
        headers={"Cookie": "manual=initial"},
        follow_redirects=True,
    )

    assert response.request.url == "https://www.example.net/landing"
    assert response.json()["cookie"] is None
    assert [request.headers.get("Cookie") for request in handler.requests] == [
        "session=value; manual=initial",
        None,
    ]


def test_manual_cookie_header_does_not_bypass_path_boundary() -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200, json={"cookie": request.headers.get("Cookie")}
            )
        )
    )

    cookies = httpx.Cookies()
    cookies.set("manual", "value", domain="www.example.com", path="/api")
    client.cookies = cookies

    response = client.get("http://www.example.com/apiv2/items")

    assert response.json()["cookie"] is None


def test_path_boundary_and_subdomain_match() -> None:
    handler = RedirectHandler()
    handler.set_cookie = "root=1; path=/; domain=example.com"
    client = httpx.Client(
        same_site_policy="lax",
        transport=httpx.MockTransport(handler),
        follow_redirects=True,
    )

    client.get("https://example.com/set-and-redirect?https://api.example.com/api/items")
    handler.set_cookie = "api=1; path=/api"
    client.get(
        "https://api.example.com/set-and-redirect?https://api.example.com/api/items"
    )
    client.get("https://api.example.com/api-other/items")

    assert handler.requests[-2].headers["Cookie"] == "api=1; root=1"
    assert handler.requests[-1].headers.get("Cookie") == "root=1"


def test_response_host_only_cookie_is_not_sent_to_subdomain() -> None:
    handler = RedirectHandler()
    handler.set_cookie = "hostonly=1; path=/"
    client = httpx.Client(
        same_site_policy="lax",
        transport=httpx.MockTransport(handler),
        follow_redirects=True,
    )

    response = client.get(
        "https://example.com/set-and-redirect?https://www.example.com/landing"
    )

    assert response.request.headers.get("Cookie") is None


def test_secure_cookie_not_sent_over_http() -> None:
    handler = RedirectHandler()
    handler.set_cookie = make_cookie(
        "secure_cookie", value="1", domain=".example.com", secure=True
    )
    client = httpx.Client(
        same_site_policy="lax",
        transport=httpx.MockTransport(handler),
        follow_redirects=True,
    )

    response = client.get(
        "https://example.com/set-and-redirect?http://example.com/landing"
    )

    assert response.json()["cookie"] is None


def test_expired_cookie_is_deleted_and_recalculated() -> None:
    handler = RedirectHandler()
    handler.set_cookie = make_cookie(
        "session", value="old", domain="example.com", max_age=0
    )
    client = httpx.Client(
        same_site_policy="lax",
        transport=httpx.MockTransport(handler),
        follow_redirects=True,
    )

    response = client.get(
        "https://example.com/set-and-redirect?https://example.com/landing"
    )

    assert response.json()["cookie"] is None
    assert len(client.cookies) == 0


def test_port_restricted_cookie_is_matched_per_request() -> None:
    handler = RedirectHandler()
    handler.set_cookie = make_cookie(
        "port_cookie", value="1", domain="example.com", port="443"
    )
    client = httpx.Client(
        same_site_policy="lax",
        transport=httpx.MockTransport(handler),
        follow_redirects=True,
    )

    allowed = client.get(
        "https://example.com/set-and-redirect?https://example.com/allowed"
    )
    assert allowed.json()["cookie"] == "port_cookie=1"
    blocked = client.get("https://example.com:8443/blocked")

    assert allowed.json()["cookie"] == "port_cookie=1"
    assert blocked.json()["cookie"] is None


def test_ip_literal_cannot_use_domain_cookie() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/set":
            return httpx.Response(
                302,
                headers={
                    "location": "/landing",
                        "set-cookie": make_cookie(
                            "ip", value="1", domain="127.0.0.1"
                        ),
                },
            )
        return httpx.Response(200, json={"cookie": request.headers.get("Cookie")})

    client = httpx.Client(
        same_site_policy="lax",
        transport=httpx.MockTransport(handler),
        follow_redirects=True,
    )

    response = client.get("http://127.0.0.1/set")

    assert response.json()["cookie"] is None
    assert len(client.cookies) == 0


def test_ipv6_host_only_cookies_match_exact_literal() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/set":
            return httpx.Response(
                302,
                headers={"location": "/landing"},
            )
        return httpx.Response(200, json={"cookie": request.headers.get("Cookie")})

    client = httpx.Client(
        same_site_policy="lax", transport=httpx.MockTransport(handler)
    )
    client.cookies.set("ipv6", "1", domain="2001:db8::1", path="/")

    allowed = client.get("http://[2001:db8::1]/landing")
    blocked = client.get("http://[2001:db8::2]/landing")

    assert allowed.json()["cookie"] == "ipv6=1"
    assert blocked.json()["cookie"] is None


def test_ip_response_host_only_cookie_is_exact() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/set":
            return httpx.Response(
                302,
                headers={"location": "/landing", "set-cookie": "ipv4=1"},
            )
        return httpx.Response(200, json={"cookie": request.headers.get("Cookie")})

    client = httpx.Client(
        same_site_policy="lax",
        transport=httpx.MockTransport(handler),
        follow_redirects=True,
    )

    client.get("http://127.0.0.1/set")
    allowed = client.get("http://127.0.0.1/landing")
    blocked = client.get("http://127.0.0.2/landing")

    assert allowed.json()["cookie"] == "ipv4=1"
    assert blocked.json()["cookie"] is None


@pytest.mark.parametrize(
    ("host", "suffix", "site"),
    [
        ("www.example.co.uk", "co.uk", "example.co.uk"),
        ("www.example.com", "com", "example.com"),
        ("foo.github.io", "github.io", "foo.github.io"),
        ("[2001:db8::1]", "2001:db8::1", "[2001:db8::1]"),
    ],
)
def test_site_uses_public_suffix_and_ip_literals(
    host: str, suffix: str, site: str
) -> None:
    assert public_suffix(host) == suffix
    assert registrable_domain(host) == site


def test_schemeful_same_site_includes_scheme() -> None:
    assert same_site("https", "example.com", "https", "www.example.com")
    assert not same_site("http", "example.com", "https", "www.example.com")


def test_cross_port_redirect_still_recalculates_cookies() -> None:
    handler = RedirectHandler()
    handler.set_cookie = "origin=1; path=/"
    client = httpx.Client(
        same_site_policy="lax",
        transport=httpx.MockTransport(handler),
        follow_redirects=True,
    )

    response = client.get(
        "https://example.com/set-and-redirect?https://example.com:8443/landing"
    )

    assert response.request.url == "https://example.com:8443/landing"
    assert response.request.headers["Cookie"] == "origin=1"


def test_same_site_lax_blocks_cross_site_post_redirect() -> None:
    cookies = httpx.Cookies(same_site_policy="lax")
    cookies.set("session", "value", domain=".example.com")
    next(iter(cookies.jar)).set_nonstandard_attr("SameSite", "Lax")
    seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("Cookie"))
        if request.url.path == "/redirect":
            return httpx.Response(
                307, headers={"location": "https://example.net/landing"}
            )
        return httpx.Response(200)

    client = httpx.Client(
        cookies=cookies,
        same_site_policy="lax",
        transport=httpx.MockTransport(handler),
        follow_redirects=True,
    )

    client.post("https://www.example.com/redirect")

    assert seen == ["session=value", None]


def test_redirect_history_records_cookie_header_for_every_hop() -> None:
    handler = RedirectHandler()
    handler.set_cookie = "session=value; path=/"
    client = httpx.Client(
        same_site_policy="lax",
        transport=httpx.MockTransport(handler),
        follow_redirects=True,
    )

    response = client.get(
        "https://example.com/set-and-redirect?https://example.com/landing"
    )

    assert response.history[0].request.headers.get("Cookie") is None
    assert response.request.headers["Cookie"] == "session=value"


def test_auth_retry_uses_current_cookie_policy() -> None:
    seen: list[str | None] = []

    class SetCookieAuth(httpx.Auth):
        def auth_flow(self, request: httpx.Request):
            seen.append(request.headers.get("Cookie"))
            response = yield request
            seen.append(request.headers.get("Cookie"))
            request.headers["Authorization"] = "Bearer retry"
            yield request

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("Cookie"))
        if request.headers.get("Authorization") is None:
            return httpx.Response(
                401,
                headers=[
                    (
                        "set-cookie",
                        make_cookie("session", value="1", domain="example.com"),
                    )
                ],
            )
        return httpx.Response(200)

    client = httpx.Client(
        same_site_policy="lax",
        transport=httpx.MockTransport(handler),
        auth=SetCookieAuth(),
    )

    response = client.get("https://example.com/")

    assert response.status_code == 200
    assert seen == [None, None, None, "session=1"]


def test_cookie_copy_does_not_share_mutable_state() -> None:
    cookies = httpx.Cookies(same_site_policy="lax")
    cookies.set("name", "original", domain="example.com")
    copied = cookies.copy()
    cloned = copy.deepcopy(cookies)
    copied.set("name", "changed", domain="example.com")
    cloned.set("name", "cloned", domain="example.com")

    assert cookies["name"] == "original"
    assert copied["name"] == "changed"
    assert cloned["name"] == "cloned"
    assert copied.same_site_policy == "lax"


def test_cookies_setter_preserves_cookie_policy() -> None:
    client = httpx.Client(same_site_policy="strict")
    client.cookies = {"name": "value"}

    assert client.cookies.same_site_policy == "strict"

    client.cookies = httpx.Cookies(same_site_policy="lax")

    assert client.cookies.same_site_policy == "lax"


def test_client_inherits_explicit_cookies_policy() -> None:
    client = httpx.Client(cookies=httpx.Cookies(same_site_policy="strict"))

    assert client.cookies.same_site_policy == "strict"


def test_sync_concurrent_cookie_requests_do_not_share_state() -> None:
    seen: list[str | None] = []
    barrier = threading.Barrier(8)

    def handler(request: httpx.Request) -> httpx.Response:
        barrier.wait()
        seen.append(request.headers.get("Cookie"))
        return httpx.Response(200)

    cookies = httpx.Cookies(same_site_policy="lax")
    cookies.set("session", "shared", domain="example.com")
    client = httpx.Client(cookies=cookies, transport=httpx.MockTransport(handler))
    threads = [
        threading.Thread(target=client.get, args=(f"https://example.com/{index}",))
        for index in range(8)
    ]

    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert seen == ["session=shared"] * 8


@pytest.mark.anyio
async def test_async_concurrent_cookie_requests_do_not_share_state() -> None:
    seen: list[str | None] = []
    active = 0
    lock = anyio.Lock()

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal active
        async with lock:
            active += 1
            assert active <= 8
        await anyio.sleep(0)
        seen.append(request.headers.get("Cookie"))
        async with lock:
            active -= 1
        return httpx.Response(200)

    cookies = httpx.Cookies(same_site_policy="lax")
    cookies.set("session", "shared", domain="example.com")
    async with httpx.AsyncClient(
        cookies=cookies, transport=httpx.MockTransport(handler)
    ) as client:
        async with anyio.create_task_group() as task_group:
            for index in range(8):
                task_group.start_soon(
                    client.get, f"https://example.com/{index}"
                )

    assert seen == ["session=shared"] * 8
