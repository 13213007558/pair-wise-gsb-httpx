import typing

import pytest

import httpx
from tests.concurrency import sleep


@pytest.mark.anyio
async def test_read_timeout(server):
    timeout = httpx.Timeout(None, read=1e-6)

    async with httpx.AsyncClient(timeout=timeout) as client:
        with pytest.raises(httpx.ReadTimeout):
            await client.get(server.url.copy_with(path="/slow_response"))


@pytest.mark.anyio
async def test_write_timeout(server):
    timeout = httpx.Timeout(None, write=1e-6)

    async with httpx.AsyncClient(timeout=timeout) as client:
        with pytest.raises(httpx.WriteTimeout):
            data = b"*" * 1024 * 1024 * 100
            await client.put(server.url.copy_with(path="/slow_response"), content=data)


@pytest.mark.anyio
@pytest.mark.network
async def test_connect_timeout(server):
    timeout = httpx.Timeout(None, connect=1e-6)

    async with httpx.AsyncClient(timeout=timeout) as client:
        with pytest.raises(httpx.ConnectTimeout):
            # See https://stackoverflow.com/questions/100841/
            await client.get("http://10.255.255.1/")


@pytest.mark.anyio
async def test_pool_timeout(server):
    limits = httpx.Limits(max_connections=1)
    timeout = httpx.Timeout(None, pool=1e-4)

    async with httpx.AsyncClient(limits=limits, timeout=timeout) as client:
        with pytest.raises(httpx.PoolTimeout):
            async with client.stream("GET", server.url):
                await client.get(server.url)


@pytest.mark.anyio
async def test_async_client_new_request_send_timeout(server):
    timeout = httpx.Timeout(1e-6)

    async with httpx.AsyncClient(timeout=timeout) as client:
        with pytest.raises(httpx.TimeoutException):
            await client.send(
                httpx.Request("GET", server.url.copy_with(path="/slow_response"))
            )


@pytest.mark.anyio
async def test_total_timeout(server):
    timeout = httpx.Timeout(None, total=1e-3)

    async with httpx.AsyncClient(timeout=timeout) as client:
        with pytest.raises(httpx.TimeoutException):
            await client.get(server.url.copy_with(path="/slow_response"))


@pytest.mark.anyio
async def test_total_timeout_spans_redirects(server):
    # The total budget is shared across the redirect chain, so a 'None'
    # read timeout is still bounded by the remaining budget.
    timeout = httpx.Timeout(None, read=None, total=0.5)

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        with pytest.raises(httpx.ReadTimeout):
            await client.get(server.url.copy_with(path="/redirect_to_slow"))


@pytest.mark.anyio
async def test_pool_timeout_with_total_budget(server):
    # Pool waits report PoolTimeout, bounded by the remaining total budget.
    limits = httpx.Limits(max_connections=1)
    timeout = httpx.Timeout(None, total=0.5)

    async with httpx.AsyncClient(limits=limits, timeout=timeout) as client:
        with pytest.raises(httpx.PoolTimeout):
            async with client.stream("GET", server.url):
                await client.get(server.url)


@pytest.mark.anyio
async def test_write_timeout_disabled_with_total_budget(server):
    # An explicit 'write=None' disables the write timeout, while the
    # total budget still bounds the request overall.
    timeout = httpx.Timeout(None, write=None, total=30.0)

    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.put(
            server.url.copy_with(path="/echo_body"), content=b"*" * 1024
        )
        assert response.status_code == 200
        assert response.content == b"*" * 1024


def test_total_budget_is_shared_across_redirects():
    seen = []

    def handler(request):
        seen.append(dict(request.extensions["timeout"]))
        if request.url.path == "/redirect":
            return httpx.Response(303, headers={"location": "/target"})
        return httpx.Response(200, content=b"Hello, world!")

    timeout = httpx.Timeout(None, read=10.0, total=30.0)
    with httpx.Client(
        transport=httpx.MockTransport(handler), follow_redirects=True, timeout=timeout
    ) as client:
        response = client.get("http://example.org/redirect")

    assert response.status_code == 200
    assert len(seen) == 2
    # Phases without their own timeout consume the remaining total budget...
    assert seen[0]["pool"] <= 30.0
    # ...which decreases across the redirect chain rather than resetting.
    assert seen[1]["pool"] < seen[0]["pool"]
    # Per-operation timeouts apply while they fit within the budget.
    assert seen[0]["read"] == 10.0
    assert seen[1]["read"] == 10.0


@pytest.mark.anyio
async def test_total_budget_is_shared_across_redirects_async():
    seen = []

    def handler(request):
        seen.append(dict(request.extensions["timeout"]))
        if request.url.path == "/redirect":
            return httpx.Response(303, headers={"location": "/target"})
        return httpx.Response(200, content=b"Hello, world!")

    timeout = httpx.Timeout(None, read=10.0, total=30.0)
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), follow_redirects=True, timeout=timeout
    ) as client:
        response = await client.get("http://example.org/redirect")

    assert response.status_code == 200
    assert len(seen) == 2
    assert seen[0]["pool"] <= 30.0
    assert seen[1]["pool"] < seen[0]["pool"]
    assert seen[0]["read"] == 10.0
    assert seen[1]["read"] == 10.0


def test_total_budget_exhausted_during_streaming():
    import time

    def handler(request):
        def body() -> typing.Iterator[bytes]:
            for _ in range(100):
                time.sleep(0.01)
                yield b"chunk"

        if request.url.path == "/fast":
            return httpx.Response(200, content=b"Hello, world!")
        return httpx.Response(200, content=body())

    timeout = httpx.Timeout(None, total=0.05)
    with httpx.Client(
        transport=httpx.MockTransport(handler), timeout=timeout
    ) as client:
        # Response stream reads report ReadTimeout once the budget is spent.
        with client.stream("GET", "http://example.org/") as response:
            with pytest.raises(httpx.ReadTimeout):
                response.read()
        # The client remains usable: nothing is left behind in the pool,
        # and a fresh request gets a fresh total budget.
        response = client.get("http://example.org/fast")
        assert response.status_code == 200


@pytest.mark.anyio
async def test_total_budget_exhausted_during_async_streaming():
    def handler(request):
        async def body() -> typing.AsyncIterator[bytes]:
            for _ in range(100):
                await sleep(0.01)
                yield b"chunk"

        if request.url.path == "/fast":
            return httpx.Response(200, content=b"Hello, world!")
        return httpx.Response(200, content=body())

    timeout = httpx.Timeout(None, total=0.05)
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), timeout=timeout
    ) as client:
        async with client.stream("GET", "http://example.org/") as response:
            with pytest.raises(httpx.ReadTimeout):
                await response.aread()
        response = await client.get("http://example.org/fast")
        assert response.status_code == 200
