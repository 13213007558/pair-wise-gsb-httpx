from __future__ import annotations

import io
import tempfile
import typing

import pytest

import httpx


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


def tracked_async_file(
    chunks: typing.List[bytes], log: typing.List[tuple]
) -> typing.AsyncIterator[bytes]:
    """
    An async generator that records 'read' and 'close' events,
    so that tests can assert on the resource lifecycle.
    """

    async def gen() -> typing.AsyncIterator[bytes]:
        try:
            for chunk in chunks:
                log.append(("read", chunk))
                yield chunk
        finally:
            log.append(("close",))

    return gen()


@pytest.mark.anyio
async def test_multipart_encode_async_iterator_file() -> None:
    """
    Non-seekable async iterators are supported as multipart file content.
    The length is unknown upfront, so 'Transfer-Encoding: chunked' is used,
    and the source is not read until the request is sent.
    """
    log: typing.List[tuple] = []
    fileobj = tracked_async_file([b"Hello", b"World"], log)

    url = "https://www.example.com/"
    headers = {"Content-Type": "multipart/form-data; boundary=BOUNDARY"}
    files = {"file": ("name.txt", fileobj)}

    request = httpx.Request("POST", url, headers=headers, files=files)

    # The source must not be pre-read when building the request.
    assert log == []
    assert request.headers == {
        "Host": "www.example.com",
        "Content-Type": "multipart/form-data; boundary=BOUNDARY",
        "Transfer-Encoding": "chunked",
    }

    content = b"".join([part async for part in request.stream])
    assert content == (
        b"--BOUNDARY\r\n"
        b'Content-Disposition: form-data; name="file"; filename="name.txt"\r\n'
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"HelloWorld\r\n"
        b"--BOUNDARY--\r\n"
    )
    assert log == [("read", b"Hello"), ("read", b"World"), ("close",)]

    # The source is only ever closed once.
    await request.stream.aclose()
    assert log.count(("close",)) == 1


@pytest.mark.anyio
async def test_multipart_encode_async_iterator_file_empty() -> None:
    """
    Zero-byte async iterator sources use chunked encoding,
    and are still closed exactly once.
    """
    log: typing.List[tuple] = []
    fileobj = tracked_async_file([], log)

    url = "https://www.example.com/"
    headers = {"Content-Type": "multipart/form-data; boundary=BOUNDARY"}
    files = {"file": ("name.txt", fileobj)}

    request = httpx.Request("POST", url, headers=headers, files=files)
    assert request.headers["Transfer-Encoding"] == "chunked"
    assert "Content-Length" not in request.headers

    content = b"".join([part async for part in request.stream])
    assert content == (
        b"--BOUNDARY\r\n"
        b'Content-Disposition: form-data; name="file"; filename="name.txt"\r\n'
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"\r\n"
        b"--BOUNDARY--\r\n"
    )
    assert log == [("close",)]


@pytest.mark.anyio
async def test_multipart_encode_async_filelike_across_chunks() -> None:
    """
    Async file-like objects using 'aread' are read across multiple chunks,
    and closed exactly once.
    """

    class AsyncFile:
        def __init__(self, content: bytes) -> None:
            self._content = content
            self._pos = 0
            self.reads: typing.List[bytes] = []
            self.closes = 0

        async def aread(self, chunk_size: int) -> bytes:
            chunk = self._content[self._pos : self._pos + chunk_size]
            self._pos += len(chunk)
            self.reads.append(chunk)
            return chunk

        async def aclose(self) -> None:
            self.closes += 1

    content = b"x" * (64 * 1024 * 2 + 1)
    fileobj = AsyncFile(content)

    url = "https://www.example.com/"
    headers = {"Content-Type": "multipart/form-data; boundary=BOUNDARY"}
    files = {"file": ("name.txt", fileobj)}

    request = httpx.Request("POST", url, headers=headers, files=files)
    assert request.headers["Transfer-Encoding"] == "chunked"
    assert fileobj.reads == []

    body = b"".join([part async for part in request.stream])
    assert body.count(b"x" * 64 * 1024) >= 2
    assert content in body
    assert len(fileobj.reads) == 4  # 64k, 64k, 1 byte, then b""
    assert fileobj.closes == 1

    await request.stream.aclose()
    assert fileobj.closes == 1


@pytest.mark.anyio
async def test_multipart_encode_async_iterator_cancelled() -> None:
    """
    Cancelling a multipart send part-way through closes the source,
    exactly once.
    """
    log: typing.List[tuple] = []
    fileobj = tracked_async_file([b"x" * 1024] * 100, log)

    url = "https://www.example.com/"
    files = {"file": ("name.txt", fileobj)}
    request = httpx.Request("POST", url, files=files)

    stream = request.stream.__aiter__()
    await stream.__anext__()  # Boundary.
    await stream.__anext__()  # File headers.
    await stream.__anext__()  # First file chunk.
    await stream.aclose()

    assert log.count(("close",)) == 1

    await request.stream.aclose()
    assert log.count(("close",)) == 1


@pytest.mark.anyio
async def test_multipart_encode_async_iterator_not_replayable() -> None:
    """
    Non-replayable async iterators cannot be sent twice. Re-sending raises
    'StreamConsumed' rather than silently sending an empty body.
    """
    log: typing.List[tuple] = []
    fileobj = tracked_async_file([b"Hello"], log)

    url = "https://www.example.com/"
    files = {"file": ("name.txt", fileobj)}
    request = httpx.Request("POST", url, files=files)

    content = b"".join([part async for part in request.stream])
    assert b"Hello" in content

    with pytest.raises(httpx.StreamConsumed):
        [part async for part in request.stream]

    assert log.count(("close",)) == 1


def test_multipart_encode_async_iterator_sync_read_raises() -> None:
    """
    Async file sources cannot be read by a synchronous stream.
    """
    log: typing.List[tuple] = []
    fileobj = tracked_async_file([b"Hello"], log)

    url = "https://www.example.com/"
    files = {"file": ("name.txt", fileobj)}
    request = httpx.Request("POST", url, files=files)

    with pytest.raises(RuntimeError):
        request.read()


def test_multipart_encode_sync_iterator_file() -> None:
    """
    Sync iterators are supported as multipart file content, using
    'Transfer-Encoding: chunked', and are closed once consumed.
    """
    log: typing.List[str] = []

    def data() -> typing.Iterator[bytes]:
        try:
            yield b"Hello"
            yield b"World"
        finally:
            log.append("closed")

    url = "https://www.example.com/"
    headers = {"Content-Type": "multipart/form-data; boundary=BOUNDARY"}
    files = {"file": ("name.txt", data())}

    request = httpx.Request("POST", url, headers=headers, files=files)
    assert request.headers["Transfer-Encoding"] == "chunked"
    assert log == []

    content = request.read()
    assert content == (
        b"--BOUNDARY\r\n"
        b'Content-Disposition: form-data; name="file"; filename="name.txt"\r\n'
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"HelloWorld\r\n"
        b"--BOUNDARY--\r\n"
    )
    assert log == ["closed"]


def test_multipart_encode_non_seekable_filelike_not_replayable() -> None:
    """
    Non-seekable file-like objects cannot be sent twice. Re-sending raises
    'StreamConsumed' rather than silently sending an empty body.
    """

    class IteratorIO(io.IOBase):
        def __init__(self, iterator: typing.Iterator[bytes]) -> None:
            self._iterator = iterator

        def read(self, *args: typing.Any) -> bytes:
            return b"".join(self._iterator)

    def data() -> typing.Iterator[bytes]:
        yield b"Hello"

    url = "https://www.example.com/"
    files = {"file": IteratorIO(data())}
    request = httpx.Request("POST", url, files=files)

    assert b"Hello" in b"".join(request.stream)

    with pytest.raises(httpx.StreamConsumed):
        b"".join(request.stream)


def test_multipart_stream_closed_exactly_once() -> None:
    """
    Closing a multipart stream closes any non-replayable sources,
    exactly once, even if the stream was never consumed.
    """

    class NonSeekableFile(io.IOBase):
        closes = 0

        def read(self, *args: typing.Any) -> bytes:
            return b""

        def close(self) -> None:
            self.closes += 1

    fileobj = NonSeekableFile()
    url = "https://www.example.com/"
    files = {"file": ("name.txt", fileobj)}
    request = httpx.Request("POST", url, files=files)

    request.stream.close()
    request.stream.close()
    assert fileobj.closes == 1


def test_multipart_redirect_non_replayable_raises() -> None:
    """
    Redirects that require the request body to be re-sent raise
    'StreamConsumed' for non-replayable sources, rather than
    silently sending an empty body.
    """
    bodies: typing.List[bytes] = []

    class ConsumeBodyTransport(httpx.MockTransport):
        def handle_request(self, request: httpx.Request) -> httpx.Response:
            bodies.append(b"".join(request.stream))
            return self.handler(request)  # type: ignore[return-value]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/redirect":
            return httpx.Response(308, headers={"location": "/target"})
        return httpx.Response(200)

    class IteratorIO(io.IOBase):
        def __init__(self, iterator: typing.Iterator[bytes]) -> None:
            self._iterator = iterator

        def read(self, *args: typing.Any) -> bytes:
            return b"".join(self._iterator)

    def data() -> typing.Iterator[bytes]:
        yield b"Hello"

    client = httpx.Client(transport=ConsumeBodyTransport(handler))
    files = {"file": ("name.txt", IteratorIO(data()))}
    with pytest.raises(httpx.StreamConsumed):
        client.post("http://example.org/redirect", files=files, follow_redirects=True)

    assert len(bodies) == 1
    assert b"Hello" in bodies[0]


@pytest.mark.anyio
async def test_multipart_redirect_async_iterator_raises() -> None:
    """
    Redirects that require the request body to be re-sent raise
    'StreamConsumed' for non-replayable async sources, rather than
    silently sending an empty body.
    """
    bodies: typing.List[bytes] = []

    class ConsumeBodyTransport(httpx.MockTransport):
        async def handle_async_request(
            self, request: httpx.Request
        ) -> httpx.Response:
            bodies.append(b"".join([part async for part in request.stream]))
            return self.handler(request)  # type: ignore[return-value]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/redirect":
            return httpx.Response(308, headers={"location": "/target"})
        return httpx.Response(200)

    log: typing.List[tuple] = []
    fileobj = tracked_async_file([b"Hello"], log)

    async with httpx.AsyncClient(transport=ConsumeBodyTransport(handler)) as client:
        files = {"file": ("name.txt", fileobj)}
        with pytest.raises(httpx.StreamConsumed):
            await client.post(
                "http://example.org/redirect", files=files, follow_redirects=True
            )

    assert len(bodies) == 1
    assert b"Hello" in bodies[0]
    assert log.count(("close",)) == 1


def test_multipart_redirect_with_factory() -> None:
    """
    A caller-provided factory allows non-replayable sources to be
    re-sent across redirects. Each instance is closed exactly once.
    """
    bodies: typing.List[bytes] = []

    class ConsumeBodyTransport(httpx.MockTransport):
        def handle_request(self, request: httpx.Request) -> httpx.Response:
            bodies.append(b"".join(request.stream))
            return self.handler(request)  # type: ignore[return-value]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/redirect":
            return httpx.Response(308, headers={"location": "/target"})
        return httpx.Response(200)

    instances: typing.List[io.BytesIO] = []

    def factory() -> io.BytesIO:
        instance = io.BytesIO(b"<file content>")
        instances.append(instance)
        return instance

    client = httpx.Client(transport=ConsumeBodyTransport(handler))
    files = {"file": ("name.txt", factory)}
    response = client.post(
        "http://example.org/redirect", files=files, follow_redirects=True
    )

    assert response.status_code == 200
    assert len(bodies) == 2
    assert bodies[0] == bodies[1]
    assert b"<file content>" in bodies[1]
    assert len(instances) == 2
    assert all(instance.closed for instance in instances)
