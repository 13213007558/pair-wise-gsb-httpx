"""
Tests for instance-level custom content decoders on Client/AsyncClient.
"""

import gzip as gzip_module
import typing

import pytest

import httpx


class HexDecoder(httpx.ContentDecoder):
    """
    A stateful custom decoder for 'x-hex' content.

    Decodes hex-encoded bytes, buffering a trailing nibble across
    chunk boundaries.
    """

    def __init__(self) -> None:
        self._buffer = b""

    def decode(self, data: bytes) -> bytes:
        data = self._buffer + data
        if len(data) % 2:
            self._buffer, data = data[-1:], data[:-1]
        else:
            self._buffer = b""
        return bytes.fromhex(data.decode("ascii"))

    def flush(self) -> bytes:
        if self._buffer:
            raise httpx.DecodingError("Truncated hex content.")
        return b""


class BufferedDecoder(httpx.ContentDecoder):
    """
    A custom decoder for 'x-buffered' content.

    Buffers all incoming data, only producing output on flush.
    """

    def __init__(self) -> None:
        self._buffer = bytearray()

    def decode(self, data: bytes) -> bytes:
        self._buffer += data
        return b""

    def flush(self) -> bytes:
        data = bytes(self._buffer)
        self._buffer.clear()
        return data


class ReversingDecoder(httpx.ContentDecoder):
    """
    A custom decoder for 'x-reversed' content.

    Buffers everything, emitting the reversed content as tail
    bytes on flush.
    """

    def __init__(self) -> None:
        self._buffer = bytearray()

    def decode(self, data: bytes) -> bytes:
        self._buffer += data
        return b""

    def flush(self) -> bytes:
        data = bytes(self._buffer)
        self._buffer.clear()
        return data[::-1]


class RunningXorDecoder(httpx.ContentDecoder):
    """
    A stateful custom decoder for 'x-xor' content.

    Each byte is XORed with its running position in the stream, so
    decoding state must be kept per-response.
    """

    def __init__(self) -> None:
        self._position = 0

    def decode(self, data: bytes) -> bytes:
        output = bytearray()
        for byte in data:
            output.append(byte ^ (self._position % 256))
            self._position += 1
        return bytes(output)

    def flush(self) -> bytes:
        return b""


def xor_encode(data: bytes) -> bytes:
    return bytes(byte ^ (index % 256) for index, byte in enumerate(data))


class ChunkedStream(httpx.SyncByteStream):
    def __init__(self, chunks: typing.List[bytes]) -> None:
        self._chunks = chunks

    def __iter__(self) -> typing.Iterator[bytes]:
        yield from self._chunks

    def close(self) -> None:
        pass


class AsyncChunkedStream(httpx.AsyncByteStream):
    def __init__(self, chunks: typing.List[bytes]) -> None:
        self._chunks = chunks

    async def __aiter__(self) -> typing.AsyncIterator[bytes]:
        for chunk in self._chunks:
            yield chunk

    async def aclose(self) -> None:
        pass


def hex_client(chunks: typing.List[bytes], **kwargs: typing.Any) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Encoding": "x-hex"},
            stream=ChunkedStream(chunks),
        )

    return httpx.Client(
        transport=httpx.MockTransport(handler),
        decoders={"x-hex": HexDecoder},
        **kwargs,
    )


def test_custom_decoder_sync() -> None:
    content = b"Hello, world! " * 10
    encoded = content.hex().encode("ascii")
    # Split the hex stream on an odd boundary, so that decoding
    # requires state to be carried across chunks.
    chunks = [encoded[:7], encoded[7:50], encoded[50:]]
    with hex_client(chunks) as client:
        response = client.get("http://example.org/")
        assert response.read() == content
        assert response.content == content
        assert response.text == content.decode("utf-8")


def test_custom_decoder_streaming_consistency() -> None:
    content = b"Hello, world! " * 10
    encoded = content.hex().encode("ascii")
    chunks = [encoded[:7], encoded[7:50], encoded[50:]]
    with hex_client(chunks) as client:
        with client.stream("GET", "http://example.org/") as response:
            streamed = b"".join(response.iter_bytes(chunk_size=5))
        assert streamed == content
        with client.stream("GET", "http://example.org/") as response:
            text = "".join(response.iter_text())
        assert text == content.decode("utf-8")


@pytest.mark.anyio
async def test_custom_decoder_async() -> None:
    content = b"Hello, world! " * 10
    encoded = content.hex().encode("ascii")
    chunks = [encoded[:7], encoded[7:50], encoded[50:]]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Encoding": "x-hex"},
            stream=AsyncChunkedStream(chunks),
        )

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), decoders={"x-hex": HexDecoder}
    ) as client:
        response = await client.get("http://example.org/")
        assert response.content == content

        async with client.stream("GET", "http://example.org/") as response:
            streamed = b"".join([part async for part in response.aiter_bytes(5)])
        assert streamed == content
        async with client.stream("GET", "http://example.org/") as response:
            text = "".join([part async for part in response.aiter_text()])
        assert text == content.decode("utf-8")


def test_custom_decoder_raw_bytes_untouched() -> None:
    content = b"Hello, world!"
    encoded = content.hex().encode("ascii")
    chunks = [encoded[:9], encoded[9:]]
    with hex_client(chunks) as client:
        with client.stream("GET", "http://example.org/") as response:
            raw = b"".join(response.iter_raw())
            assert response.num_bytes_downloaded == len(encoded)
        assert raw == encoded


def test_custom_decoder_with_eagerly_loaded_content() -> None:
    # Responses constructed with `content=...`, as is typical in mock
    # transports, are eagerly decoded on instantiation. The client must
    # still apply its custom decoders in this case.
    content = b"Hello, world!"
    encoded = content.hex().encode("ascii")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Encoding": "x-hex"},
            content=encoded,
        )

    client = httpx.Client(
        transport=httpx.MockTransport(handler),
        decoders={"x-hex": HexDecoder},
    )
    with client:
        response = client.get("http://example.org/")
        assert response.content == content
        assert response.text == content.decode("utf-8")


def test_nested_custom_and_builtin_decoders() -> None:
    # 'Content-Encoding: gzip, x-buffered' indicates gzip was applied
    # first, then the custom encoding. Decoding reverses the order, and
    # the custom decoder only emits its buffered data on flush, which
    # must then be propagated through the gzip layer.
    content = b"Hello, world! " * 10
    wire = gzip_module.compress(content)
    chunks = [wire[:5], wire[5:20], wire[20:]]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Encoding": "gzip, x-buffered"},
            stream=ChunkedStream(chunks),
        )

    client = httpx.Client(
        transport=httpx.MockTransport(handler),
        decoders={"x-buffered": BufferedDecoder},
    )
    with client:
        response = client.get("http://example.org/")
        assert response.content == content
        assert response.text == content.decode("utf-8")


def test_flush_tail_bytes() -> None:
    content = b"Hello, world!"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Encoding": "x-reversed"},
            stream=ChunkedStream([content[:5], content[5:]]),
        )

    client = httpx.Client(
        transport=httpx.MockTransport(handler),
        decoders={"x-reversed": ReversingDecoder},
    )
    with client:
        with client.stream("GET", "http://example.org/") as response:
            # Nothing is emitted until the final flush.
            assert b"".join(response.iter_bytes()) == content[::-1]


def test_concurrent_responses_do_not_share_decoder_state() -> None:
    instantiations = []

    def counting_factory() -> RunningXorDecoder:
        decoder = RunningXorDecoder()
        instantiations.append(decoder)
        return decoder

    content_one = b"first response " * 20
    content_two = b"second response, different " * 20
    wire_one = xor_encode(content_one)
    wire_two = xor_encode(content_two)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/one":
            return httpx.Response(
                200,
                headers={"Content-Encoding": "x-xor"},
                stream=ChunkedStream([wire_one[:10], wire_one[10:]]),
            )
        return httpx.Response(
            200,
            headers={"Content-Encoding": "x-xor"},
            stream=ChunkedStream([wire_two[:10], wire_two[10:]]),
        )

    client = httpx.Client(
        transport=httpx.MockTransport(handler),
        decoders={"x-xor": counting_factory},
    )
    with client:
        with client.stream("GET", "http://example.org/one") as response_one:
            with client.stream("GET", "http://example.org/two") as response_two:
                # Interleave the two responses chunk-by-chunk. If decoder
                # state were shared, the running XOR position would corrupt
                # both outputs.
                chunks_one = response_one.iter_bytes(chunk_size=7)
                chunks_two = response_two.iter_bytes(chunk_size=7)
                output_one, output_two = [], []
                while True:
                    try:
                        output_one.append(next(chunks_one))
                    except StopIteration:
                        break
                    output_two.append(next(chunks_two))
                output_two.extend(chunks_two)
        assert b"".join(output_one) == content_one
        assert b"".join(output_two) == content_two
    assert len(instantiations) == 2


def test_accept_encoding_includes_custom_decoders() -> None:
    client = httpx.Client(decoders={"x-hex": HexDecoder})
    assert client.headers["Accept-Encoding"] == "gzip, deflate, br, zstd, x-hex"


def test_accept_encoding_not_modified_when_set_explicitly() -> None:
    client = httpx.Client(
        headers={"Accept-Encoding": "gzip"}, decoders={"x-hex": HexDecoder}
    )
    assert client.headers["Accept-Encoding"] == "gzip"


def test_accept_encoding_request_level_override() -> None:
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers["Accept-Encoding"])
        return httpx.Response(200, content=b"ok")

    client = httpx.Client(
        transport=httpx.MockTransport(handler), decoders={"x-hex": HexDecoder}
    )
    with client:
        client.get("http://example.org/")
        client.get("http://example.org/", headers={"Accept-Encoding": "identity"})
    assert seen[0] == "gzip, deflate, br, zstd, x-hex"
    assert seen[1] == "identity"


def test_builtin_decoders_and_other_clients_unchanged() -> None:
    client = httpx.Client(decoders={"x-hex": HexDecoder})
    assert "x-hex" in client.headers["Accept-Encoding"]

    # The process-level registry is not modified...
    assert "x-hex" not in httpx._decoders.SUPPORTED_DECODERS

    # ...and other client instances are unaffected.
    other = httpx.Client()
    assert "x-hex" not in other.headers["Accept-Encoding"]


def test_invalid_decoder_registrations() -> None:
    with pytest.raises(ValueError, match="Invalid content-encoding token"):
        httpx.Client(decoders={"not a token": HexDecoder})

    with pytest.raises(ValueError, match="built-in content-encoding"):
        httpx.Client(decoders={"gzip": HexDecoder})

    with pytest.raises(ValueError, match="built-in content-encoding"):
        httpx.Client(decoders={"GZIP": HexDecoder})

    with pytest.raises(ValueError, match="Duplicate decoder registration"):
        httpx.Client(decoders={"X-Hex": HexDecoder, "x-hex": HexDecoder})

    with pytest.raises(TypeError, match="must be callable"):
        httpx.Client(decoders={"x-hex": "not-a-factory"})  # type: ignore[dict-item]


def test_invalid_decoder_instance() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Encoding": "x-bogus"},
            stream=ChunkedStream([b"data"]),
        )

    client = httpx.Client(
        transport=httpx.MockTransport(handler),
        decoders={"x-bogus": lambda: object()},  # type: ignore[dict-item, return-value]
    )
    with client, pytest.raises(httpx.DecodingError, match="decode.*flush"):
        client.get("http://example.org/")


def test_broken_decoder_factory() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Encoding": "x-broken"},
            stream=ChunkedStream([b"data"]),
        )

    def factory() -> HexDecoder:
        raise RuntimeError("cannot create decoder")

    client = httpx.Client(
        transport=httpx.MockTransport(handler),
        decoders={"x-broken": factory},
    )
    with client, pytest.raises(httpx.DecodingError, match="factory"):
        client.get("http://example.org/")


def test_failing_decoder_raises_decoding_error() -> None:
    # Truncated hex content fails on flush.
    encoded = b"68656c6c6f0"  # Odd number of hex characters.
    with hex_client([encoded]) as client:
        with pytest.raises(httpx.DecodingError, match="Truncated hex"):
            client.get("http://example.org/")


def test_decoder_exception_is_normalized() -> None:
    class BuggyDecoder(httpx.ContentDecoder):
        def decode(self, data: bytes) -> bytes:
            raise ValueError("bug in decoder")

        def flush(self) -> bytes:
            return b""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Encoding": "x-buggy"},
            stream=ChunkedStream([b"data"]),
        )

    client = httpx.Client(
        transport=httpx.MockTransport(handler),
        decoders={"x-buggy": BuggyDecoder},
    )
    with client, pytest.raises(httpx.DecodingError, match="bug in decoder"):
        client.get("http://example.org/")


def test_response_level_decoders_argument() -> None:
    # The decoder registry can also be provided when constructing
    # a response directly.
    content = b"Hello, world!"
    response = httpx.Response(
        200,
        headers={"Content-Encoding": "x-hex"},
        content=content.hex().encode("ascii"),
        decoders={"x-hex": HexDecoder},
    )
    assert response.content == content
    assert response.text == content.decode("utf-8")
