from __future__ import annotations

import concurrent.futures
import io
import typing
import zlib

import anyio
import chardet
import pytest
import zstandard as zstd

import httpx


def test_deflate():
    """
    Deflate encoding may use either 'zlib' or 'deflate' in the wild.

    https://stackoverflow.com/questions/1838699/how-can-i-decompress-a-gzip-stream-with-zlib#answer-22311297
    """
    body = b"test 123"
    compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    compressed_body = compressor.compress(body) + compressor.flush()

    headers = [(b"Content-Encoding", b"deflate")]
    response = httpx.Response(
        200,
        headers=headers,
        content=compressed_body,
    )
    assert response.content == body


def test_zlib():
    """
    Deflate encoding may use either 'zlib' or 'deflate' in the wild.

    https://stackoverflow.com/questions/1838699/how-can-i-decompress-a-gzip-stream-with-zlib#answer-22311297
    """
    body = b"test 123"
    compressed_body = zlib.compress(body)

    headers = [(b"Content-Encoding", b"deflate")]
    response = httpx.Response(
        200,
        headers=headers,
        content=compressed_body,
    )
    assert response.content == body


def test_gzip():
    body = b"test 123"
    compressor = zlib.compressobj(9, zlib.DEFLATED, zlib.MAX_WBITS | 16)
    compressed_body = compressor.compress(body) + compressor.flush()

    headers = [(b"Content-Encoding", b"gzip")]
    response = httpx.Response(
        200,
        headers=headers,
        content=compressed_body,
    )
    assert response.content == body


def test_brotli():
    body = b"test 123"
    compressed_body = b"\x8b\x03\x80test 123\x03"

    headers = [(b"Content-Encoding", b"br")]
    response = httpx.Response(
        200,
        headers=headers,
        content=compressed_body,
    )
    assert response.content == body


def test_zstd():
    body = b"test 123"
    compressed_body = zstd.compress(body)

    headers = [(b"Content-Encoding", b"zstd")]
    response = httpx.Response(
        200,
        headers=headers,
        content=compressed_body,
    )
    assert response.content == body


def test_zstd_decoding_error():
    compressed_body = "this_is_not_zstd_compressed_data"

    headers = [(b"Content-Encoding", b"zstd")]
    with pytest.raises(httpx.DecodingError):
        httpx.Response(
            200,
            headers=headers,
            content=compressed_body,
        )


def test_zstd_empty():
    headers = [(b"Content-Encoding", b"zstd")]
    response = httpx.Response(200, headers=headers, content=b"")
    assert response.content == b""


def test_zstd_truncated():
    body = b"test 123"
    compressed_body = zstd.compress(body)

    headers = [(b"Content-Encoding", b"zstd")]
    with pytest.raises(httpx.DecodingError):
        httpx.Response(
            200,
            headers=headers,
            content=compressed_body[1:3],
        )


def test_zstd_multiframe():
    # test inspired by urllib3 test suite
    data = (
        # Zstandard frame
        zstd.compress(b"foo")
        # skippable frame (must be ignored)
        + bytes.fromhex(
            "50 2A 4D 18"  # Magic_Number (little-endian)
            "07 00 00 00"  # Frame_Size (little-endian)
            "00 00 00 00 00 00 00"  # User_Data
        )
        # Zstandard frame
        + zstd.compress(b"bar")
    )
    compressed_body = io.BytesIO(data)

    headers = [(b"Content-Encoding", b"zstd")]
    response = httpx.Response(200, headers=headers, content=compressed_body)
    response.read()
    assert response.content == b"foobar"


def test_multi():
    body = b"test 123"

    deflate_compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    compressed_body = deflate_compressor.compress(body) + deflate_compressor.flush()

    gzip_compressor = zlib.compressobj(9, zlib.DEFLATED, zlib.MAX_WBITS | 16)
    compressed_body = (
        gzip_compressor.compress(compressed_body) + gzip_compressor.flush()
    )

    headers = [(b"Content-Encoding", b"deflate, gzip")]
    response = httpx.Response(
        200,
        headers=headers,
        content=compressed_body,
    )
    assert response.content == body


def test_multi_with_identity():
    body = b"test 123"
    compressed_body = b"\x8b\x03\x80test 123\x03"

    headers = [(b"Content-Encoding", b"br, identity")]
    response = httpx.Response(
        200,
        headers=headers,
        content=compressed_body,
    )
    assert response.content == body

    headers = [(b"Content-Encoding", b"identity, br")]
    response = httpx.Response(
        200,
        headers=headers,
        content=compressed_body,
    )
    assert response.content == body


@pytest.mark.anyio
async def test_streaming():
    body = b"test 123"
    compressor = zlib.compressobj(9, zlib.DEFLATED, zlib.MAX_WBITS | 16)

    async def compress(body: bytes) -> typing.AsyncIterator[bytes]:
        yield compressor.compress(body)
        yield compressor.flush()

    headers = [(b"Content-Encoding", b"gzip")]
    response = httpx.Response(
        200,
        headers=headers,
        content=compress(body),
    )
    assert not hasattr(response, "body")
    assert await response.aread() == body


@pytest.mark.parametrize("header_value", (b"deflate", b"gzip", b"br", b"identity"))
def test_empty_content(header_value):
    headers = [(b"Content-Encoding", header_value)]
    response = httpx.Response(
        200,
        headers=headers,
        content=b"",
    )
    assert response.content == b""


@pytest.mark.parametrize("header_value", (b"deflate", b"gzip", b"br", b"identity"))
def test_decoders_empty_cases(header_value):
    headers = [(b"Content-Encoding", header_value)]
    response = httpx.Response(content=b"", status_code=200, headers=headers)
    assert response.read() == b""


@pytest.mark.parametrize("header_value", (b"deflate", b"gzip", b"br"))
def test_decoding_errors(header_value):
    headers = [(b"Content-Encoding", header_value)]
    compressed_body = b"invalid"
    with pytest.raises(httpx.DecodingError):
        request = httpx.Request("GET", "https://example.org")
        httpx.Response(200, headers=headers, content=compressed_body, request=request)

    with pytest.raises(httpx.DecodingError):
        httpx.Response(200, headers=headers, content=compressed_body)


@pytest.mark.parametrize(
    ["data", "encoding"],
    [
        ((b"Hello,", b" world!"), "ascii"),
        ((b"\xe3\x83", b"\x88\xe3\x83\xa9", b"\xe3", b"\x83\x99\xe3\x83\xab"), "utf-8"),
        ((b"Euro character: \x88! abcdefghijklmnopqrstuvwxyz", b""), "cp1252"),
        ((b"Accented: \xd6sterreich abcdefghijklmnopqrstuvwxyz", b""), "iso-8859-1"),
    ],
)
@pytest.mark.anyio
async def test_text_decoder_with_autodetect(data, encoding):
    async def iterator() -> typing.AsyncIterator[bytes]:
        nonlocal data
        for chunk in data:
            yield chunk

    def autodetect(content):
        return chardet.detect(content).get("encoding")

    # Accessing `.text` on a read response.
    response = httpx.Response(200, content=iterator(), default_encoding=autodetect)
    await response.aread()
    assert response.text == (b"".join(data)).decode(encoding)

    # Streaming `.aiter_text` iteratively.
    # Note that if we streamed the text *without* having read it first, then
    # we won't get a `charset_normalizer` guess, and will instead always rely
    # on utf-8 if no charset is specified.
    text = "".join([part async for part in response.aiter_text()])
    assert text == (b"".join(data)).decode(encoding)


@pytest.mark.anyio
async def test_text_decoder_known_encoding():
    async def iterator() -> typing.AsyncIterator[bytes]:
        yield b"\x83g"
        yield b"\x83"
        yield b"\x89\x83x\x83\x8b"

    response = httpx.Response(
        200,
        headers=[(b"Content-Type", b"text/html; charset=shift-jis")],
        content=iterator(),
    )

    await response.aread()
    assert "".join(response.text) == "トラベル"


def test_text_decoder_empty_cases():
    response = httpx.Response(200, content=b"")
    assert response.text == ""

    response = httpx.Response(200, content=[b""])
    response.read()
    assert response.text == ""


@pytest.mark.parametrize(
    ["data", "expected"],
    [((b"Hello,", b" world!"), ["Hello,", " world!"])],
)
def test_streaming_text_decoder(
    data: typing.Iterable[bytes], expected: list[str]
) -> None:
    response = httpx.Response(200, content=iter(data))
    assert list(response.iter_text()) == expected


def test_line_decoder_nl():
    response = httpx.Response(200, content=[b""])
    assert list(response.iter_lines()) == []

    response = httpx.Response(200, content=[b"", b"a\n\nb\nc"])
    assert list(response.iter_lines()) == ["a", "", "b", "c"]

    # Issue #1033
    response = httpx.Response(
        200, content=[b"", b"12345\n", b"foo ", b"bar ", b"baz\n"]
    )
    assert list(response.iter_lines()) == ["12345", "foo bar baz"]


def test_line_decoder_cr():
    response = httpx.Response(200, content=[b"", b"a\r\rb\rc"])
    assert list(response.iter_lines()) == ["a", "", "b", "c"]

    response = httpx.Response(200, content=[b"", b"a\r\rb\rc\r"])
    assert list(response.iter_lines()) == ["a", "", "b", "c"]

    # Issue #1033
    response = httpx.Response(
        200, content=[b"", b"12345\r", b"foo ", b"bar ", b"baz\r"]
    )
    assert list(response.iter_lines()) == ["12345", "foo bar baz"]


def test_line_decoder_crnl():
    response = httpx.Response(200, content=[b"", b"a\r\n\r\nb\r\nc"])
    assert list(response.iter_lines()) == ["a", "", "b", "c"]

    response = httpx.Response(200, content=[b"", b"a\r\n\r\nb\r\nc\r\n"])
    assert list(response.iter_lines()) == ["a", "", "b", "c"]

    response = httpx.Response(200, content=[b"", b"a\r", b"\n\r\nb\r\nc"])
    assert list(response.iter_lines()) == ["a", "", "b", "c"]

    # Issue #1033
    response = httpx.Response(200, content=[b"", b"12345\r\n", b"foo bar baz\r\n"])
    assert list(response.iter_lines()) == ["12345", "foo bar baz"]


def test_invalid_content_encoding_header():
    headers = [(b"Content-Encoding", b"invalid-header")]
    body = b"test 123"

    response = httpx.Response(
        200,
        headers=headers,
        content=body,
    )
    with pytest.raises(httpx.DecodingError, match="Unsupported content encoding"):
        response.read()


class BufferedDecoder(httpx.ContentDecoder):
    def __init__(self) -> None:
        self.buffer = b""

    def decode(self, data: bytes) -> bytes:
        self.buffer += data
        content = b""

        while len(self.buffer) >= 8:
            frame_length = int.from_bytes(self.buffer[:8], "big")
            frame_end = frame_length + 8
            if len(self.buffer) < frame_end:
                break
            content += self.buffer[8:frame_end]
            self.buffer = self.buffer[frame_end:]

        return content

    def flush(self) -> bytes:
        tail = self.buffer
        self.buffer = b""
        return tail


class SplitSyncStream(httpx.SyncByteStream):
    def __init__(self, chunks: typing.Iterable[bytes]) -> None:
        self.chunks = list(chunks)

    def __iter__(self) -> typing.Iterator[bytes]:
        yield from self.chunks


class SplitAsyncStream(httpx.AsyncByteStream):
    def __init__(self, chunks: typing.Iterable[bytes]) -> None:
        self.chunks = list(chunks)

    async def __aiter__(self) -> typing.AsyncIterator[bytes]:
        for chunk in self.chunks:
            yield chunk


def gzip_compress(body: bytes) -> bytes:
    compressor = zlib.compressobj(9, zlib.DEFLATED, zlib.MAX_WBITS | 16)
    return compressor.compress(body) + compressor.flush()


def buffered_encode(frames: list[bytes], tail: bytes = b"") -> bytes:
    encoded = b"".join(
        len(frame).to_bytes(8, "big") + frame for frame in frames
    )
    return encoded + tail


def split_every_byte(data: bytes) -> list[bytes]:
    return [data[index : index + 1] for index in range(len(data))]


def buffered_response(
    encoded_body: bytes,
    *,
    stream_cls: type[typing.Any] = SplitSyncStream,
    encoding: str = "buffered",
) -> httpx.Response:
    return httpx.Response(
        200,
        headers=[(b"Content-Encoding", encoding.encode("ascii"))],
        stream=stream_cls(split_every_byte(encoded_body)),
        content_decoders={"buffered": BufferedDecoder},
    )


def test_custom_decoder_state_across_chunks():
    response = buffered_response(buffered_encode([b"hel", b"lo"], b"world"))

    assert b"".join(response.iter_bytes()) == b"helloworld"


def test_custom_decoder_flush_tail_and_text():
    response = buffered_response(buffered_encode([b"hello"], b"w"))
    response.headers["Content-Type"] = "text/plain; charset=utf-8"

    assert response.read() == b"hellow"
    assert response.text == "hellow"
    assert list(response.iter_text()) == ["hellow"]
    assert list(response.iter_lines()) == ["hellow"]


@pytest.mark.anyio
async def test_custom_decoder_async_flush_tail_and_text():
    response = buffered_response(
        buffered_encode([b"hello"], b"w"), stream_cls=SplitAsyncStream
    )
    response.headers["Content-Type"] = "text/plain; charset=utf-8"

    assert await response.aread() == b"hellow"
    assert "".join([part async for part in response.aiter_text()]) == "hellow"
    assert [line async for line in response.aiter_lines()] == ["hellow"]


@pytest.mark.parametrize("header_value", [b"gzip, buffered", b"buffered, gzip"])
def test_custom_decoder_nested_with_gzip(header_value: bytes) -> None:
    body = b"hello|world"
    if header_value == b"gzip, buffered":
        compressed_body = gzip_compress(body)
        encoded_body = buffered_encode(
            [compressed_body[:10]], compressed_body[10:]
        )
    else:
        encoded_body = gzip_compress(buffered_encode([b"hello"], b"|world"))

    response = httpx.Response(
        200,
        headers=[(b"Content-Encoding", header_value)],
        stream=SplitSyncStream(split_every_byte(encoded_body)),
        content_decoders={"buffered": BufferedDecoder},
    )

    assert response.read() == body


def test_custom_decoder_nested_flush_propagation() -> None:
    compressed_body = gzip_compress(b"hello|w")
    encoded_body = buffered_encode([compressed_body[:10]], compressed_body[10:])
    response = httpx.Response(
        200,
        headers=[(b"Content-Encoding", b"gzip, buffered")],
        stream=SplitSyncStream(split_every_byte(encoded_body)),
        content_decoders={"buffered": BufferedDecoder},
    )

    assert b"".join(response.iter_bytes()) == b"hello|w"


def test_custom_decoder_raw_bytes_are_not_decoded() -> None:
    encoded_body = buffered_encode([b"hello"], b"w")
    response = buffered_response(encoded_body)

    assert b"".join(response.iter_raw()) == encoded_body
    assert response.num_bytes_downloaded == len(encoded_body)


@pytest.mark.anyio
async def test_custom_decoder_async_raw_bytes_are_not_decoded() -> None:
    encoded_body = buffered_encode([b"hello"], b"w")
    response = buffered_response(encoded_body, stream_cls=SplitAsyncStream)

    assert b"".join([part async for part in response.aiter_raw()]) == encoded_body
    assert response.num_bytes_downloaded == len(encoded_body)


def test_custom_decoder_registration_and_accept_encoding() -> None:
    with httpx.Client(content_decoders={"buffered": BufferedDecoder}) as client:
        assert dict(client.content_decoders) == {"buffered": BufferedDecoder}
        assert client.headers["Accept-Encoding"].endswith(", buffered")

    with httpx.Client(headers={"Accept-Encoding": "identity"}) as client:
        assert client.headers["Accept-Encoding"] == "identity"

    with httpx.Client(content_decoders={"buffered": BufferedDecoder}) as client:
        request = client.build_request(
            "GET", "https://example.org", headers={"Accept-Encoding": "identity"}
        )
        assert request.headers["Accept-Encoding"] == "identity"


def test_custom_decoder_does_not_change_other_clients_or_builtin_registry() -> None:
    with httpx.Client(content_decoders={"buffered": BufferedDecoder}):
        with httpx.Client() as other:
            assert "buffered" not in other.content_decoders
            assert "buffered" not in httpx._decoders.SUPPORTED_DECODERS


@pytest.mark.parametrize(
    ["encoding", "factory", "exception"],
    [
        ("bad name", BufferedDecoder, ValueError),
        ("buffered", b"not callable", TypeError),
    ],
)
def test_invalid_custom_decoder_registration(
    encoding: str, factory: typing.Any, exception: type[Exception]
) -> None:
    with pytest.raises(exception):
        httpx.Client(content_decoders={encoding: factory})


def test_custom_decoder_factory_must_return_content_decoder() -> None:
    response = buffered_response(buffered_encode([b"hello"]))
    response.content_decoders = {"buffered": lambda: object()}

    with pytest.raises(httpx.DecodingError, match="must be a ContentDecoder instance"):
        response.read()


class FailingDecoder(httpx.ContentDecoder):
    def decode(self, data: bytes) -> bytes:
        if data:
            raise ValueError("boom")
        return b""

    def flush(self) -> bytes:
        return b""


class FlushFailingDecoder(httpx.ContentDecoder):
    def decode(self, data: bytes) -> bytes:
        return data

    def flush(self) -> bytes:
        raise ValueError("flush boom")


class DelayedDecoder(httpx.ContentDecoder):
    def __init__(self, tail: bytes) -> None:
        self.buffer = b""
        self.tail = tail

    def decode(self, data: bytes) -> bytes:
        self.buffer += data
        return b""

    def flush(self) -> bytes:
        output = self.tail + self.buffer
        self.buffer = b""
        return output


def test_custom_decoder_failure_is_decoding_error() -> None:
    response = buffered_response(buffered_encode([b"hello"]))
    response.content_decoders = {"buffered": FailingDecoder}

    with pytest.raises(httpx.DecodingError, match="boom"):
        response.read()


def test_custom_decoder_flush_failure_is_decoding_error() -> None:
    response = buffered_response(buffered_encode([b"hello"], b"w"))
    response.content_decoders = {"buffered": FlushFailingDecoder}

    with pytest.raises(httpx.DecodingError, match="flush boom"):
        response.read()


@pytest.mark.anyio
async def test_custom_decoder_async_failure_is_decoding_error() -> None:
    response = buffered_response(
        buffered_encode([b"hello"]), stream_cls=SplitAsyncStream
    )
    response.content_decoders = {"buffered": FlushFailingDecoder}

    try:
        with pytest.raises(httpx.DecodingError, match="flush boom"):
            await response.aread()
    finally:
        await response.aclose()


def test_multiple_custom_decoders_flush_each_layer() -> None:
    response = httpx.Response(
        200,
        headers=[(b"Content-Encoding", b"first, second")],
        content=b"",
        content_decoders={
            "first": lambda: DelayedDecoder(b"first-"),
            "second": lambda: DelayedDecoder(b"second"),
        },
    )

    assert response.content == b"first-second"


def test_custom_decoder_client_sync_path() -> None:
    encoded_body = buffered_encode([b"hello"], b"w")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Accept-Encoding"] == "gzip, deflate, br, zstd, buffered"
        return httpx.Response(
            200,
            headers=[(b"Content-Encoding", b"buffered")],
            content=encoded_body,
        )

    with httpx.Client(
        transport=httpx.MockTransport(handler),
        content_decoders={"buffered": BufferedDecoder},
    ) as client:
        assert client.get("https://example.org").content == b"hellow"


def test_custom_decoder_client_sync_concurrency_isolation() -> None:
    encoded_body = buffered_encode([b"hello"], b"w")
    decoder_instances: list[BufferedDecoder] = []

    def factory() -> BufferedDecoder:
        decoder = BufferedDecoder()
        decoder_instances.append(decoder)
        return decoder

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers=[(b"Content-Encoding", b"buffered")],
            content=encoded_body,
        )

    with httpx.Client(
        transport=httpx.MockTransport(handler),
        content_decoders={"buffered": factory},
    ) as client:
        responses = [
            client.send(
                client.build_request("GET", "https://example.org"), stream=True
            )
            for _ in range(2)
        ]
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            contents = list(executor.map(httpx.Response.read, responses))

    assert contents == [b"hellow", b"hellow"]
    assert decoder_instances[0] is not decoder_instances[1]


@pytest.mark.anyio
async def test_custom_decoder_client_async_path_and_concurrency() -> None:
    encoded_body = buffered_encode([b"hello"], b"w")
    decoder_instances: list[BufferedDecoder] = []

    def factory() -> BufferedDecoder:
        decoder = BufferedDecoder()
        decoder_instances.append(decoder)
        return decoder

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Accept-Encoding"] == "gzip, deflate, br, zstd, buffered"
        return httpx.Response(
            200,
            headers=[(b"Content-Encoding", b"buffered")],
            content=encoded_body,
        )

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        content_decoders={"buffered": factory},
    ) as client:
        responses = [
            await client.send(
                client.build_request("GET", "https://example.org"), stream=True
            )
            for _ in range(2)
        ]
        contents: list[bytes] = []

        async def consume(response: httpx.Response, index: int) -> None:
            content = b"".join([part async for part in response.aiter_bytes()])
            contents.insert(index, content)

        async with anyio.create_task_group() as task_group:
            task_group.start_soon(consume, responses[0], 0)
            task_group.start_soon(consume, responses[1], 1)

    assert contents == [b"hellow", b"hellow"]
    assert len(decoder_instances) == 2
    assert decoder_instances[0] is not decoder_instances[1]
    assert decoder_instances[0].buffer == b""
    assert decoder_instances[1].buffer == b""
