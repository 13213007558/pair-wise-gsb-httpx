"""
Tests for explicit cookie partitions on `Client` and `AsyncClient`.

Cookie partitions allow a single client (and its connection pool) to be
shared between multiple users, while keeping each user's cookie state
isolated from the others.
"""

import typing
import warnings

import anyio
import pytest

import httpx


def login_app(
    sent: list[tuple[str, str | None]],
) -> typing.Callable[[httpx.Request], httpx.Response]:
    """
    An app where each user logs in and is redirected to a homepage,
    recording the `Cookie` header of every request it receives.
    """

    def app(request: httpx.Request) -> httpx.Response:
        sent.append((request.url.path, request.headers.get("cookie")))
        if request.url.path == "/login":
            user = request.url.params["user"]
            return httpx.Response(
                302,
                headers={
                    "location": "/home",
                    "set-cookie": f"session={user}; Path=/",
                },
            )
        elif request.url.path == "/home":
            return httpx.Response(200, json={"cookie": request.headers.get("cookie")})
        raise NotImplementedError()  # pragma: no cover

    return app


def test_interleaved_partitions() -> None:
    """
    Two users sharing one client keep their login cookies isolated,
    across redirects, with nothing leaking into the default partition.
    """
    sent: list[tuple[str, str | None]] = []
    client = httpx.Client(
        transport=httpx.MockTransport(login_app(sent)), follow_redirects=True
    )

    # Interleave requests for two different users against the same origin.
    client.get("http://example.org/login?user=alice", cookie_partition="alice")
    client.get("http://example.org/login?user=bob", cookie_partition="bob")
    alice = client.get("http://example.org/home", cookie_partition="alice")
    bob = client.get("http://example.org/home", cookie_partition="bob")

    # Each request only ever carried the cookie of its own partition.
    assert sent == [
        ("/login", None),
        ("/home", "session=alice"),
        ("/login", None),
        ("/home", "session=bob"),
        ("/home", "session=alice"),
        ("/home", "session=bob"),
    ]
    assert alice.json() == {"cookie": "session=alice"}
    assert bob.json() == {"cookie": "session=bob"}

    # `Set-Cookie` responses only landed in the matching partition.
    assert dict(client.cookies_for("alice")) == {"session": "alice"}
    assert dict(client.cookies_for("bob")) == {"session": "bob"}

    # The default partition is not polluted by partitioned requests.
    assert dict(client.cookies) == {}


@pytest.mark.anyio
async def test_interleaved_partitions_async() -> None:
    """
    Concurrent async requests for different users stay bound to their
    own partition, even when the requests genuinely overlap in-flight.
    """
    sent: list[tuple[str, str | None]] = []
    alice_started = anyio.Event()
    bob_started = anyio.Event()

    async def app(request: httpx.Request) -> httpx.Response:
        sent.append((request.url.path, request.headers.get("cookie")))
        if request.url.path == "/login":
            user = request.url.params["user"]
            # Force both logins to be in-flight at the same time.
            if user == "alice":
                alice_started.set()
                await bob_started.wait()
            else:
                bob_started.set()
                await alice_started.wait()
            return httpx.Response(
                302,
                headers={
                    "location": "/home",
                    "set-cookie": f"session={user}; Path=/",
                },
            )
        elif request.url.path == "/home":
            return httpx.Response(200, json={"cookie": request.headers.get("cookie")})
        raise NotImplementedError()  # pragma: no cover

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(app), follow_redirects=True
    ) as client:
        async with anyio.create_task_group() as task_group:
            results: dict[str, typing.Any] = {}

            async def login(user: str) -> None:
                response = await client.get(
                    f"http://example.org/login?user={user}", cookie_partition=user
                )
                results[user] = response.json()

            task_group.start_soon(login, "alice")
            task_group.start_soon(login, "bob")

        assert results == {
            "alice": {"cookie": "session=alice"},
            "bob": {"cookie": "session=bob"},
        }
        assert dict(client.cookies_for("alice")) == {"session": "alice"}
        assert dict(client.cookies_for("bob")) == {"session": "bob"}
        assert dict(client.cookies) == {}


def test_partition_is_bound_through_auth_flow() -> None:
    """
    A 401 authentication retry stays within the selected partition:
    `Set-Cookie` from the challenge response lands in that partition only.
    """

    class RetryAuth(httpx.Auth):
        def auth_flow(
            self, request: httpx.Request
        ) -> typing.Generator[httpx.Request, httpx.Response, None]:
            response = yield request
            if response.status_code == 401:
                request.headers["X-Retry"] = "true"
                yield request

    def app(request: httpx.Request) -> httpx.Response:
        if "x-retry" not in request.headers:
            return httpx.Response(
                401, headers={"set-cookie": "session=retried; Path=/"}
            )
        return httpx.Response(200)

    client = httpx.Client(transport=httpx.MockTransport(app))
    response = client.get(
        "http://example.org/", auth=RetryAuth(), cookie_partition="alice"
    )

    assert response.status_code == 200
    assert dict(client.cookies_for("alice")) == {"session": "retried"}
    assert dict(client.cookies) == {}


def test_same_name_cookies_by_path_and_domain() -> None:
    """
    Cookies sharing a name but differing by path or domain are stored
    separately within a partition, and stay isolated across partitions.
    """

    def app(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/set":
            return httpx.Response(
                200,
                headers=[
                    ("set-cookie", "shared=root; Path=/"),
                    ("set-cookie", "shared=sub; Path=/sub"),
                ],
            )
        return httpx.Response(200, json={"cookie": request.headers.get("cookie")})

    client = httpx.Client(transport=httpx.MockTransport(app))
    client.get("http://example.org/set", cookie_partition="user")
    # A same-named cookie for a different domain, in the same partition.
    client.cookies_for("user").set("shared", "elsewhere", domain="example.net")

    jar = client.cookies_for("user")
    assert jar.get("shared", domain="example.org", path="/") == "root"
    assert jar.get("shared", domain="example.org", path="/sub") == "sub"
    assert jar.get("shared", domain="example.net") == "elsewhere"

    # The most specific cookie is sent first on matching paths.
    response = client.get("http://example.org/sub/page", cookie_partition="user")
    assert response.json() == {"cookie": "shared=sub; shared=root"}
    response = client.get("http://example.org/other", cookie_partition="user")
    assert response.json() == {"cookie": "shared=root"}
    response = client.get("http://example.net/", cookie_partition="user")
    assert response.json() == {"cookie": "shared=elsewhere"}

    # Another partition on the same client is unaffected.
    response = client.get("http://example.org/sub/page", cookie_partition="other")
    assert response.json() == {"cookie": None}
    assert dict(client.cookies_for("other")) == {}


def test_request_level_cookies_merge_with_partition() -> None:
    """
    Request-level cookies are merged over the partition cookies using the
    existing override rules, without persisting back into the partition,
    and without triggering the per-request cookies deprecation warning.
    """

    def app(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"cookie": request.headers.get("cookie")})

    client = httpx.Client(transport=httpx.MockTransport(app))
    client.cookies_for("alice").set("session", "from-jar")
    client.cookies_for("alice").set("theme", "dark")

    with warnings.catch_warnings(record=True) as record:
        warnings.simplefilter("always")
        response = client.get(
            "http://example.org/",
            cookie_partition="alice",
            cookies={"session": "override", "extra": "1"},
        )
    assert not [
        warning
        for warning in record
        if issubclass(warning.category, DeprecationWarning)
    ]

    # Request-level cookies win over the partition cookies...
    assert response.json() == {"cookie": "session=override; theme=dark; extra=1"}
    # ...but are not persisted into the partition.
    assert dict(client.cookies_for("alice")) == {"session": "from-jar", "theme": "dark"}


def test_per_request_cookies_without_partition_still_deprecated() -> None:
    def app(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    client = httpx.Client(transport=httpx.MockTransport(app))
    with pytest.warns(DeprecationWarning):
        client.get("http://example.org/", cookies={"session": "value"})


def test_default_partition_compatibility() -> None:
    """
    The default partition keeps the existing `client.cookies` behaviour,
    and never exposes cookies from other partitions.
    """

    def app(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/set":
            return httpx.Response(200, headers={"set-cookie": "server=default; Path=/"})
        return httpx.Response(200, json={"cookie": request.headers.get("cookie")})

    client = httpx.Client(
        transport=httpx.MockTransport(app), cookies={"client": "default"}
    )
    client.cookies_for("alice").set("session", "alice")

    # Requests without a partition use the default partition only.
    response = client.get("http://example.org/")
    assert response.json() == {"cookie": "client=default"}

    # `Set-Cookie` from unpartitioned requests lands in the default partition.
    client.get("http://example.org/set")
    assert dict(client.cookies) == {"client": "default", "server": "default"}

    # The default partition never includes other partitions' cookies,
    # and partitioned requests never include the default cookies.
    assert "session" not in client.cookies
    response = client.get("http://example.org/", cookie_partition="alice")
    assert response.json() == {"cookie": "session=alice"}

    # The `cookies` property setter replaces the default partition.
    client.cookies = {"fresh": "default"}
    assert dict(client.cookies) == {"fresh": "default"}
    assert dict(client.cookies_for("alice")) == {"session": "alice"}

    # Clearing the default partition directly keeps working.
    client.cookies.clear()
    assert dict(client.cookies) == {}

    # The partitions view is read-only.
    with pytest.raises(TypeError):
        client.cookie_partitions["mallory"] = httpx.Cookies()  # type: ignore


def test_clear_cookie_partition_releases_single_user() -> None:
    """
    Releasing one user's partition drops only their state, while another
    user keeps their cookies and continues on the same client/transport.
    """
    sent: list[tuple[str, str | None]] = []
    client = httpx.Client(
        transport=httpx.MockTransport(login_app(sent)), follow_redirects=True
    )
    client.get("http://example.org/login?user=alice", cookie_partition="alice")
    client.get("http://example.org/login?user=bob", cookie_partition="bob")

    client.clear_cookie_partition("alice")

    assert "alice" not in client.cookie_partitions
    assert dict(client.cookies_for("bob")) == {"session": "bob"}

    # Bob continues to reuse the client, with his login state intact.
    response = client.get("http://example.org/home", cookie_partition="bob")
    assert response.json() == {"cookie": "session=bob"}

    # Alice starts again from a fresh, empty partition.
    response = client.get("http://example.org/home", cookie_partition="alice")
    assert response.json() == {"cookie": None}


def test_inflight_request_does_not_recreate_cleared_partition() -> None:
    """
    If a partition is cleared while one of its requests is still in-flight,
    `Set-Cookie` from that request must not recreate the partition.
    """

    def app(request: httpx.Request) -> httpx.Response:
        # The partition is cleared while this request is in-flight.
        client.clear_cookie_partition("alice")
        return httpx.Response(200, headers={"set-cookie": "session=stale; Path=/"})

    client = httpx.Client(transport=httpx.MockTransport(app))
    response = client.get("http://example.org/", cookie_partition="alice")

    assert response.status_code == 200
    assert "alice" not in client.cookie_partitions


def test_clear_default_cookie_partition() -> None:
    def app(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"cookie": request.headers.get("cookie")})

    client = httpx.Client(transport=httpx.MockTransport(app))
    client.cookies.set("session", "default")
    client.cookies_for("alice").set("session", "alice")

    client.clear_cookie_partition()

    assert dict(client.cookies) == {}
    assert dict(client.cookies_for("alice")) == {"session": "alice"}
    response = client.get("http://example.org/")
    assert response.json() == {"cookie": None}


@pytest.mark.anyio
async def test_cancelled_request_leaves_partitions_consistent() -> None:
    """
    Cancelling an in-flight request does not disturb other partitions,
    and the client remains fully usable afterwards.
    """
    started = anyio.Event()
    never = anyio.Event()

    async def app(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/slow":
            started.set()
            await never.wait()
        return httpx.Response(200, headers={"set-cookie": "session=bob; Path=/"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(app)) as client:
        client.cookies_for("alice").set("existing", "kept")

        async with anyio.create_task_group() as task_group:
            cancelled = False

            async def slow_request() -> None:
                nonlocal cancelled
                try:
                    await client.get(
                        "http://example.org/slow", cookie_partition="alice"
                    )
                except anyio.get_cancelled_exc_class():
                    cancelled = True
                    raise

            task_group.start_soon(slow_request)
            await started.wait()
            task_group.cancel_scope.cancel()

        assert cancelled

        # The cancelled request left the pre-existing partition state alone.
        assert dict(client.cookies_for("alice")) == {"existing": "kept"}

        # Other users can immediately continue on the same client.
        response = await client.get("http://example.org/", cookie_partition="bob")
        assert response.status_code == 200
        assert dict(client.cookies_for("bob")) == {"session": "bob"}
        assert dict(client.cookies_for("alice")) == {"existing": "kept"}


@pytest.mark.anyio
async def test_async_per_request_cookies_without_partition_still_deprecated() -> None:
    async def app(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    async with httpx.AsyncClient(transport=httpx.MockTransport(app)) as client:
        with pytest.warns(DeprecationWarning):
            await client.get("http://example.org/", cookies={"session": "value"})
