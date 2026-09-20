from __future__ import annotations

import io
import tempfile
import typing

import anyio
import pytest

import httpx
from tests.concurrency import sleep


def echo_request_content(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, content=request.content)


@pytest.mark.parametrize(("value,output"), (("abc", b"abc"), (b"abc", b"abc")))
def test_multipart(value, output):
    client = httpx.Client(transport=httpx.MockTransport(echo_request_content))

    # Test with a single-value 'data' argument, and a plain file 'files' argument.
    data = {"text": value}
    files = {"file": io.BytesIO(b"<file content>")}
    response = client.post("http://127.0.0.1:8000/", data=data, files=files)
    boundary = response.request.headers["Content-Type"].split("boundary=")[-1]
    boundary_bytes = boundary.encode("ascii")

    assert response.status_code == 200
    assert response.content == b"".join(
        [
            b"--" + boundary_bytes + b"\r\n",
            b'Content-Disposition: form-data; name="text"\r\n',
            b"\r\n",
            b"abc\r\n",
            b"--" + boundary_bytes + b"\r\n",
            b'Content-Disposition: form-data; name="file"; filename="upload"\r\n',
            b"Content-Type: application/octet-stream\r\n",
            b"\r\n",
            b"<file content>\r\n",
            b"--" + boundary_bytes + b"--\r\n",
        ]
    )


@pytest.mark.parametrize(
    "header",
    [
        "multipart/form-data; boundary=+++; charset=utf-8",
        "multipart/form-data; charset=utf-8; boundary=+++",
        "multipart/form-data; boundary=+++",
        "multipart/form-data; boundary=+++ ;",
        'multipart/form-data; boundary="+++"; charset=utf-8',
        'multipart/form-data; charset=utf-8; boundary="+++"',
        'multipart/form-data; boundary="+++"',
        'multipart/form-data; boundary="+++" ;',
    ],
)
def test_multipart_explicit_boundary(header: str) -> None:
    client = httpx.Client(transport=httpx.MockTransport(echo_request_content))

    files = {"file": io.BytesIO(b"<file content>")}
    headers = {"content-type": header}
    response = client.post("http://127.0.0.1:8000/", files=files, headers=headers)
    boundary_bytes = b"+++"

    assert response.status_code == 200
    assert response.request.headers["Content-Type"] == header
    assert response.content == b"".join(
        [
            b"--" + boundary_bytes + b"\r\n",
            b'Content-Disposition: form-data; name="file"; filename="upload"\r\n',
            b"Content-Type: application/octet-stream\r\n",
            b"\r\n",
            b"<file content>\r\n",
            b"--" + boundary_bytes + b"--\r\n",
        ]
    )


@pytest.mark.parametrize(
    "header",
    [
        "multipart/form-data; charset=utf-8",
        "multipart/form-data; charset=utf-8; ",
    ],
)
def test_multipart_header_without_boundary(header: str) -> None:
    client = httpx.Client(transport=httpx.MockTransport(echo_request_content))

    files = {"file": io.BytesIO(b"<file content>")}
    headers = {"content-type": header}
    response = client.post("http://127.0.0.1:8000/", files=files, headers=headers)

    assert response.status_code == 200
    assert response.request.headers["Content-Type"] == header


@pytest.mark.parametrize(("key"), (b"abc", 1, 2.3, None))
def test_multipart_invalid_key(key):
    client = httpx.Client(transport=httpx.MockTransport(echo_request_content))

    data = {key: "abc"}
    files = {"file": io.BytesIO(b"<file content>")}
    with pytest.raises(TypeError) as e:
        client.post(
            "http://127.0.0.1:8000/",
            data=data,
            files=files,
        )
    assert "Invalid type for name" in str(e.value)
    assert repr(key) in str(e.value)


@pytest.mark.parametrize(("value"), (object(), {"key": "value"}))
def test_multipart_invalid_value(value):
    client = httpx.Client(transport=httpx.MockTransport(echo_request_content))

    data = {"text": value}
    files = {"file": io.BytesIO(b"<file content>")}
    with pytest.raises(TypeError) as e:
        client.post("http://127.0.0.1:8000/", data=data, files=files)
    assert "Invalid type for value" in str(e.value)


def test_multipart_file_tuple():
    client = httpx.Client(transport=httpx.MockTransport(echo_request_content))

    # Test with a list of values 'data' argument,
    #     and a tuple style 'files' argument.
    data = {"text": ["abc"]}
    files = {"file": ("name.txt", io.BytesIO(b"<file content>"))}
    response = client.post("http://127.0.0.1:8000/", data=data, files=files)
    boundary = response.request.headers["Content-Type"].split("boundary=")[-1]
    boundary_bytes = boundary.encode("ascii")

    assert response.status_code == 200
    assert response.content == b"".join(
        [
            b"--" + boundary_bytes + b"\r\n",
            b'Content-Disposition: form-data; name="text"\r\n',
            b"\r\n",
            b"abc\r\n",
            b"--" + boundary_bytes + b"\r\n",
            b'Content-Disposition: form-data; name="file"; filename="name.txt"\r\n',
            b"Content-Type: text/plain\r\n",
            b"\r\n",
            b"<file content>\r\n",
            b"--" + boundary_bytes + b"--\r\n",
        ]
    )


@pytest.mark.parametrize("file_content_type", [None, "text/plain"])
def test_multipart_file_tuple_headers(file_content_type: str | None) -> None:
    file_name = "test.txt"
    file_content = io.BytesIO(b"<file content>")
    file_headers = {"Expires": "0"}

    url = "https://www.example.com/"
    headers = {"Content-Type": "multipart/form-data; boundary=BOUNDARY"}
    files = {"file": (file_name, file_content, file_content_type, file_headers)}

    request = httpx.Request("POST", url, headers=headers, files=files)
    request.read()

    assert request.headers == {
        "Host": "www.example.com",
        "Content-Type": "multipart/form-data; boundary=BOUNDARY",
        "Content-Length": str(len(request.content)),
    }
    assert request.content == (
        f'--BOUNDARY\r\nContent-Disposition: form-data; name="file"; '
        f'filename="{file_name}"\r\nExpires: 0\r\nContent-Type: '
        f"text/plain\r\n\r\n<file content>\r\n--BOUNDARY--\r\n"
        "".encode("ascii")
    )


def test_multipart_headers_include_content_type() -> None:
    """
    Content-Type from 4th tuple parameter (headers) should
    override the 3rd parameter (content_type)
    """
    file_name = "test.txt"
    file_content = io.BytesIO(b"<file content>")
    file_content_type = "text/plain"
    file_headers = {"Content-Type": "image/png"}

    url = "https://www.example.com/"
    headers = {"Content-Type": "multipart/form-data; boundary=BOUNDARY"}
    files = {"file": (file_name, file_content, file_content_type, file_headers)}

    request = httpx.Request("POST", url, headers=headers, files=files)
    request.read()

    assert request.headers == {
        "Host": "www.example.com",
        "Content-Type": "multipart/form-data; boundary=BOUNDARY",
        "Content-Length": str(len(request.content)),
    }
    assert request.content == (
        f'--BOUNDARY\r\nContent-Disposition: form-data; name="file"; '
        f'filename="{file_name}"\r\nContent-Type: '
        f"image/png\r\n\r\n<file content>\r\n--BOUNDARY--\r\n"
        "".encode("ascii")
    )


def test_multipart_encode(tmp_path: typing.Any) -> None:
    path = str(tmp_path / "name.txt")
    with open(path, "wb") as f:
        f.write(b"<file content>")

    url = "https://www.example.com/"
    headers = {"Content-Type": "multipart/form-data; boundary=BOUNDARY"}
    data = {
        "a": "1",
        "b": b"C",
        "c": ["11", "22", "33"],
        "d": "",
        "e": True,
        "f": "",
    }
    with open(path, "rb") as input_file:
        files = {"file": ("name.txt", input_file)}

        request = httpx.Request("POST", url, headers=headers, data=data, files=files)
        request.read()

        assert request.headers == {
            "Host": "www.example.com",
            "Content-Type": "multipart/form-data; boundary=BOUNDARY",
            "Content-Length": str(len(request.content)),
        }
        assert request.content == (
            '--BOUNDARY\r\nContent-Disposition: form-data; name="a"\r\n\r\n1\r\n'
            '--BOUNDARY\r\nContent-Disposition: form-data; name="b"\r\n\r\nC\r\n'
            '--BOUNDARY\r\nContent-Disposition: form-data; name="c"\r\n\r\n11\r\n'
            '--BOUNDARY\r\nContent-Disposition: form-data; name="c"\r\n\r\n22\r\n'
            '--BOUNDARY\r\nContent-Disposition: form-data; name="c"\r\n\r\n33\r\n'
            '--BOUNDARY\r\nContent-Disposition: form-data; name="d"\r\n\r\n\r\n'
            '--BOUNDARY\r\nContent-Disposition: form-data; name="e"\r\n\r\ntrue\r\n'
            '--BOUNDARY\r\nContent-Disposition: form-data; name="f"\r\n\r\n\r\n'
            '--BOUNDARY\r\nContent-Disposition: form-data; name="file";'
            ' filename="name.txt"\r\n'
            "Content-Type: text/plain\r\n\r\n<file content>\r\n"
            "--BOUNDARY--\r\n"
            "".encode("ascii")
        )


def test_multipart_encode_unicode_file_contents() -> None:
    url = "https://www.example.com/"
    headers = {"Content-Type": "multipart/form-data; boundary=BOUNDARY"}
    files = {"file": ("name.txt", b"<bytes content>")}

    request = httpx.Request("POST", url, headers=headers, files=files)
    request.read()

    assert request.headers == {
        "Host": "www.example.com",
        "Content-Type": "multipart/form-data; boundary=BOUNDARY",
        "Content-Length": str(len(request.content)),
    }
    assert request.content == (
        b'--BOUNDARY\r\nContent-Disposition: form-data; name="file";'
        b' filename="name.txt"\r\n'
        b"Content-Type: text/plain\r\n\r\n<bytes content>\r\n"
        b"--BOUNDARY--\r\n"
    )


def test_multipart_encode_files_allows_filenames_as_none() -> None:
    url = "https://www.example.com/"
    headers = {"Content-Type": "multipart/form-data; boundary=BOUNDARY"}
    files = {"file": (None, io.BytesIO(b"<file content>"))}

    request = httpx.Request("POST", url, headers=headers, data={}, files=files)
    request.read()

    assert request.headers == {
        "Host": "www.example.com",
        "Content-Type": "multipart/form-data; boundary=BOUNDARY",
        "Content-Length": str(len(request.content)),
    }
    assert request.content == (
        '--BOUNDARY\r\nContent-Disposition: form-data; name="file"\r\n\r\n'
        "<file content>\r\n--BOUNDARY--\r\n"
        "".encode("ascii")
    )


@pytest.mark.parametrize(
    "file_name,expected_content_type",
    [
        ("example.json", "application/json"),
        ("example.txt", "text/plain"),
        ("no-extension", "application/octet-stream"),
    ],
)
def test_multipart_encode_files_guesses_correct_content_type(
    file_name: str, expected_content_type: str
) -> None:
    url = "https://www.example.com/"
    headers = {"Content-Type": "multipart/form-data; boundary=BOUNDARY"}
    files = {"file": (file_name, io.BytesIO(b"<file content>"))}

    request = httpx.Request("POST", url, headers=headers, data={}, files=files)
    request.read()

    assert request.headers == {
        "Host": "www.example.com",
        "Content-Type": "multipart/form-data; boundary=BOUNDARY",
        "Content-Length": str(len(request.content)),
    }
    assert request.content == (
        f'--BOUNDARY\r\nContent-Disposition: form-data; name="file"; '
        f'filename="{file_name}"\r\nContent-Type: '
        f"{expected_content_type}\r\n\r\n<file content>\r\n--BOUNDARY--\r\n"
        "".encode("ascii")
    )


def test_multipart_encode_files_allows_bytes_content() -> None:
    url = "https://www.example.com/"
    headers = {"Content-Type": "multipart/form-data; boundary=BOUNDARY"}
    files = {"file": ("test.txt", b"<bytes content>", "text/plain")}

    request = httpx.Request("POST", url, headers=headers, data={}, files=files)
    request.read()

    assert request.headers == {
        "Host": "www.example.com",
        "Content-Type": "multipart/form-data; boundary=BOUNDARY",
        "Content-Length": str(len(request.content)),
    }
    assert request.content == (
        '--BOUNDARY\r\nContent-Disposition: form-data; name="file"; '
        'filename="test.txt"\r\n'
        "Content-Type: text/plain\r\n\r\n<bytes content>\r\n"
        "--BOUNDARY--\r\n"
        "".encode("ascii")
    )


def test_multipart_encode_files_allows_str_content() -> None:
    url = "https://www.example.com/"
    headers = {"Content-Type": "multipart/form-data; boundary=BOUNDARY"}
    files = {"file": ("test.txt", "<str content>", "text/plain")}

    request = httpx.Request("POST", url, headers=headers, data={}, files=files)
    request.read()

    assert request.headers == {
        "Host": "www.example.com",
        "Content-Type": "multipart/form-data; boundary=BOUNDARY",
        "Content-Length": str(len(request.content)),
    }
    assert request.content == (
        '--BOUNDARY\r\nContent-Disposition: form-data; name="file"; '
        'filename="test.txt"\r\n'
        "Content-Type: text/plain\r\n\r\n<str content>\r\n"
        "--BOUNDARY--\r\n"
        "".encode("ascii")
    )


def test_multipart_encode_files_raises_exception_with_StringIO_content() -> None:
    url = "https://www.example.com"
    files = {"file": ("test.txt", io.StringIO("content"), "text/plain")}
    with pytest.raises(TypeError):
        httpx.Request("POST", url, data={}, files=files)  # type: ignore


def test_multipart_encode_files_raises_exception_with_text_mode_file() -> None:
    url = "https://www.example.com"
    with tempfile.TemporaryFile(mode="w") as upload:
        files = {"file": ("test.txt", upload, "text/plain")}
        with pytest.raises(TypeError):
            httpx.Request("POST", url, data={}, files=files)  # type: ignore


def test_multipart_encode_non_seekable_filelike() -> None:
    """
    Test that special readable but non-seekable filelike objects are supported.
    In this case uploads with use 'Transfer-Encoding: chunked', instead of
    a 'Content-Length' header.
    """

    class IteratorIO(io.IOBase):
        def __init__(self, iterator: typing.Iterator[bytes]) -> None:
            self._iterator = iterator

        def read(self, *args: typing.Any) -> bytes:
            return b"".join(self._iterator)

    def data() -> typing.Iterator[bytes]:
        yield b"Hello"
        yield b"World"

    url = "https://www.example.com/"
    headers = {"Content-Type": "multipart/form-data; boundary=BOUNDARY"}
    fileobj: typing.Any = IteratorIO(data())
    files = {"file": fileobj}

    request = httpx.Request("POST", url, headers=headers, files=files)
    request.read()

    assert request.headers == {
        "Host": "www.example.com",
        "Content-Type": "multipart/form-data; boundary=BOUNDARY",
        "Transfer-Encoding": "chunked",
    }
    assert request.content == (
        b"--BOUNDARY\r\n"
        b'Content-Disposition: form-data; name="file"; filename="upload"\r\n'
        b"Content-Type: application/octet-stream\r\n"
        b"\r\n"
        b"HelloWorld\r\n"
        b"--BOUNDARY--\r\n"
    )


def test_multipart_rewinds_files():
    with tempfile.TemporaryFile() as upload:
        upload.write(b"Hello, world!")

        transport = httpx.MockTransport(echo_request_content)
        client = httpx.Client(transport=transport)

        files = {"file": upload}
        response = client.post("http://127.0.0.1:8000/", files=files)
        assert response.status_code == 200
        assert b"\r\nHello, world!\r\n" in response.content

        # POSTing the same file instance a second time should have the same content.
        files = {"file": upload}
        response = client.post("http://127.0.0.1:8000/", files=files)
        assert response.status_code == 200
        assert b"\r\nHello, world!\r\n" in response.content


class TestHeaderParamHTML5Formatting:
    def test_unicode(self):
        filename = "n\u00e4me"
        expected = b'filename="n\xc3\xa4me"'
        files = {"upload": (filename, b"<file content>")}
        request = httpx.Request("GET", "https://www.example.com", files=files)
        assert expected in request.read()

    def test_ascii(self):
        filename = "name"
        expected = b'filename="name"'
        files = {"upload": (filename, b"<file content>")}
        request = httpx.Request("GET", "https://www.example.com", files=files)
        assert expected in request.read()

    def test_unicode_escape(self):
        filename = "hello\\world\u0022"
        expected = b'filename="hello\\\\world%22"'
        files = {"upload": (filename, b"<file content>")}
        request = httpx.Request("GET", "https://www.example.com", files=files)
        assert expected in request.read()

    def test_unicode_with_control_character(self):
        filename = "hello\x1a\x1b\x1c"
        expected = b'filename="hello%1A\x1b%1C"'
        files = {"upload": (filename, b"<file content>")}
        request = httpx.Request("GET", "https://www.example.com", files=files)
        assert expected in request.read()


class ControlledAsyncReader:
    """
    A controlled async byte source, mimicking an async object storage reader.

    Records every read, yields to the event loop on each read, and tracks
    closure, so that tests can assert non-blocking streaming behavior and
    reliable closing.
    """

    def __init__(self, chunks: typing.List[bytes], read_delay: float = 0.0) -> None:
        self._buffer = b"".join(chunks)
        self._read_delay = read_delay
        self.reads: typing.List[int] = []
        self.closed = False

    async def aread(self, n: int = -1) -> bytes:
        await sleep(self._read_delay)
        self.reads.append(n)
        if n < 0:
            n = len(self._buffer)
        chunk, self._buffer = self._buffer[:n], self._buffer[n:]
        return chunk

    async def aclose(self) -> None:
        self.closed = True


@pytest.mark.anyio
async def test_multipart_async_file_mixed_with_other_parts():
    reader = ControlledAsyncReader([b"<async file content>"])
    files: typing.List[typing.Tuple[str, typing.Any]] = [
        ("plain", b"<bytes content>"),
        ("upload", ("name.txt", io.BytesIO(b"<file content>"))),
        (
            "upload",
            httpx.AsyncFile(reader, filename="async.txt", content_length=20),
        ),
    ]
    request = httpx.Request(
        "POST",
        "https://www.example.com/",
        headers={"Content-Type": "multipart/form-data; boundary=BOUNDARY"},
        data={"text": "abc"},
        files=files,
    )
    await request.aread()

    # Field order, duplicate field names, and escaping are preserved,
    # and all lengths are known, so an accurate Content-Length is sent.
    assert request.headers["Content-Length"] == str(len(request.content))
    assert request.content == (
        b"--BOUNDARY\r\n"
        b'Content-Disposition: form-data; name="text"\r\n'
        b"\r\n"
        b"abc\r\n"
        b"--BOUNDARY\r\n"
        b'Content-Disposition: form-data; name="plain"; filename="upload"\r\n'
        b"Content-Type: application/octet-stream\r\n"
        b"\r\n"
        b"<bytes content>\r\n"
        b"--BOUNDARY\r\n"
        b'Content-Disposition: form-data; name="upload"; filename="name.txt"\r\n'
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"<file content>\r\n"
        b"--BOUNDARY\r\n"
        b'Content-Disposition: form-data; name="upload"; filename="async.txt"\r\n'
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"<async file content>\r\n"
        b"--BOUNDARY--\r\n"
    )
    assert reader.closed


@pytest.mark.anyio
async def test_multipart_async_file_with_async_client():
    reader = ControlledAsyncReader([b"<async file content>"])
    files = {"file": httpx.AsyncFile(reader, filename="name.txt", content_length=20)}

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(echo_request_content)
    ) as client:
        response = await client.post(
            "http://127.0.0.1:8000/", data={"text": "abc"}, files=files
        )

    boundary = response.request.headers["Content-Type"].split("boundary=")[-1]
    boundary_bytes = boundary.encode("ascii")

    assert response.status_code == 200
    assert "Content-Length" in response.request.headers
    assert response.content == b"".join(
        [
            b"--" + boundary_bytes + b"\r\n",
            b'Content-Disposition: form-data; name="text"\r\n',
            b"\r\n",
            b"abc\r\n",
            b"--" + boundary_bytes + b"\r\n",
            b'Content-Disposition: form-data; name="file"; filename="name.txt"\r\n',
            b"Content-Type: text/plain\r\n",
            b"\r\n",
            b"<async file content>\r\n",
            b"--" + boundary_bytes + b"--\r\n",
        ]
    )
    assert reader.closed


@pytest.mark.anyio
async def test_multipart_async_file_unknown_content_length():
    reader = ControlledAsyncReader([b"<async file content>"])
    files = {"file": httpx.AsyncFile(reader, filename="name.txt")}
    request = httpx.Request(
        "POST",
        "https://www.example.com/",
        headers={"Content-Type": "multipart/form-data; boundary=BOUNDARY"},
        files=files,
    )

    # An unknown part length means a streamed, chunked transfer encoding.
    assert request.headers == {
        "Host": "www.example.com",
        "Content-Type": "multipart/form-data; boundary=BOUNDARY",
        "Transfer-Encoding": "chunked",
    }

    await request.aread()
    assert request.content == (
        b"--BOUNDARY\r\n"
        b'Content-Disposition: form-data; name="file"; filename="name.txt"\r\n'
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"<async file content>\r\n"
        b"--BOUNDARY--\r\n"
    )
    assert reader.closed


@pytest.mark.anyio
async def test_multipart_async_file_from_async_generator():
    closed = False

    async def stream() -> typing.AsyncIterator[bytes]:
        nonlocal closed
        try:
            yield b"<async "
            yield b"file content>"
        finally:
            closed = True

    files = {"file": httpx.AsyncFile(stream(), filename="name.txt")}
    request = httpx.Request(
        "POST",
        "https://www.example.com/",
        headers={"Content-Type": "multipart/form-data; boundary=BOUNDARY"},
        files=files,
    )
    await request.aread()

    assert request.content == (
        b"--BOUNDARY\r\n"
        b'Content-Disposition: form-data; name="file"; filename="name.txt"\r\n'
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"<async file content>\r\n"
        b"--BOUNDARY--\r\n"
    )
    assert closed


@pytest.mark.anyio
async def test_multipart_async_file_reads_do_not_block_the_event_loop():
    reader = ControlledAsyncReader([b"x" * 4096] * 4, read_delay=0.01)
    files = {"file": httpx.AsyncFile(reader, filename="name.bin")}
    request = httpx.Request("POST", "https://www.example.com/", files=files)

    ticks = 0

    async def ticker() -> None:
        nonlocal ticks
        while not stopped:
            await sleep(0.001)
            ticks += 1

    stopped = False
    async with anyio.create_task_group() as task_group:
        task_group.start_soon(ticker)
        await request.aread()
        stopped = True

    # If reading the source blocked the event loop, then the ticker
    # would never have been scheduled while the upload was encoded.
    assert ticks > 0
    assert reader.closed


@pytest.mark.anyio
async def test_multipart_async_file_content_length_too_short():
    reader = ControlledAsyncReader([b"short"])
    files = {"file": httpx.AsyncFile(reader, filename="name.bin", content_length=100)}
    request = httpx.Request("POST", "https://www.example.com/", files=files)

    with pytest.raises(httpx.StreamError, match="exhausted after 5 bytes"):
        await request.aread()
    assert reader.closed


@pytest.mark.anyio
async def test_multipart_async_file_content_length_too_long():
    reader = ControlledAsyncReader([b"<async file content>"])
    files = {"file": httpx.AsyncFile(reader, filename="name.bin", content_length=2)}
    request = httpx.Request("POST", "https://www.example.com/", files=files)

    with pytest.raises(httpx.StreamError, match="more data than declared"):
        await request.aread()
    assert reader.closed


@pytest.mark.anyio
async def test_multipart_async_file_closed_on_cancellation():
    reader = ControlledAsyncReader([b"x" * 4096] * 100)
    files = {"file": httpx.AsyncFile(reader, filename="name.bin")}
    request = httpx.Request("POST", "https://www.example.com/", files=files)

    stream = request.stream
    assert isinstance(stream, httpx.AsyncByteStream)
    aiterator = typing.cast(typing.AsyncGenerator[bytes, None], stream.__aiter__())
    # Read far enough to have started streaming the file part,
    # then cancel the upload by closing the stream.
    for _ in range(4):
        await aiterator.__anext__()
    await aiterator.aclose()

    assert reader.closed


@pytest.mark.anyio
async def test_multipart_async_file_cannot_be_replayed():
    reader = ControlledAsyncReader([b"<async file content>"])
    files = {"file": httpx.AsyncFile(reader, filename="name.txt")}
    request = httpx.Request("POST", "https://www.example.com/", files=files)

    # A read-once async source must not be silently replayed.
    stream = request.stream
    assert isinstance(stream, httpx.AsyncByteStream)
    [chunk async for chunk in stream]
    with pytest.raises(httpx.StreamConsumed):
        [chunk async for chunk in stream]


def test_multipart_async_file_with_sync_client():
    reader = ControlledAsyncReader([b"<async file content>"])
    client = httpx.Client(transport=httpx.MockTransport(echo_request_content))
    files = {"file": httpx.AsyncFile(reader, filename="name.txt")}

    with pytest.raises(RuntimeError, match="httpx.AsyncClient"):
        client.post("http://127.0.0.1:8000/", files=files)

    # The request fails before anything is sent, without touching the source.
    assert reader.reads == []
    assert not reader.closed


def test_multipart_async_file_sync_iteration():
    reader = ControlledAsyncReader([b"<async file content>"])
    files = {"file": httpx.AsyncFile(reader, filename="name.txt")}
    request = httpx.Request("POST", "https://www.example.com/", files=files)

    stream = request.stream
    assert isinstance(stream, httpx.SyncByteStream)
    with pytest.raises(RuntimeError, match="httpx.AsyncClient"):
        b"".join(stream)


@pytest.mark.anyio
async def test_multipart_async_file_headers_and_content_type():
    reader = ControlledAsyncReader([b"<async file content>"])
    files = {
        "file": httpx.AsyncFile(
            reader,
            filename="report.csv",
            content_type="text/csv",
            headers={"X-Custom": "example"},
        )
    }
    request = httpx.Request(
        "POST",
        "https://www.example.com/",
        headers={"Content-Type": "multipart/form-data; boundary=BOUNDARY"},
        files=files,
    )
    await request.aread()

    assert request.content == (
        b"--BOUNDARY\r\n"
        b'Content-Disposition: form-data; name="file"; filename="report.csv"\r\n'
        b"X-Custom: example\r\n"
        b"Content-Type: text/csv\r\n"
        b"\r\n"
        b"<async file content>\r\n"
        b"--BOUNDARY--\r\n"
    )


@pytest.mark.anyio
async def test_multipart_async_file_content_type_header_takes_precedence():
    reader = ControlledAsyncReader([b"<async file content>"])
    files = {
        "file": httpx.AsyncFile(
            reader,
            filename="report.csv",
            content_type="text/csv",
            headers={"Content-Type": "image/png"},
        )
    }
    request = httpx.Request(
        "POST",
        "https://www.example.com/",
        headers={"Content-Type": "multipart/form-data; boundary=BOUNDARY"},
        files=files,
    )
    await request.aread()

    assert b"Content-Type: image/png\r\n" in request.content
    assert b"text/csv" not in request.content


@pytest.mark.anyio
async def test_multipart_async_file_filename_escaping():
    reader = ControlledAsyncReader([b"<file content>"])
    files = {"upload": httpx.AsyncFile(reader, filename='hello\\world"')}
    request = httpx.Request("GET", "https://www.example.com", files=files)
    await request.aread()
    assert b'filename="hello\\\\world%22"' in request.content


def test_multipart_async_file_invalid_source():
    with pytest.raises(TypeError, match="Invalid type for 'source'"):
        httpx.AsyncFile(b"<sync bytes>")


def test_multipart_async_file_invalid_content_length():
    reader = ControlledAsyncReader([])
    with pytest.raises(ValueError, match="Invalid 'content_length'"):
        httpx.AsyncFile(reader, content_length=-1)
