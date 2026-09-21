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


class TrackingFile:
    """
    A non-seekable file-like object that records read/close calls,
    so that tests can assert on the resource lifecycle.
    """

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = list(chunks)
        self.reads: list[int] = []
        self.closes = 0

    def read(self, chunk_size: int = -1) -> bytes:
        self.reads.append(chunk_size)
        if not self._chunks:
            return b""
        return self._chunks.pop(0)

    def close(self) -> None:
        self.closes += 1


class TrackingAsyncFile:
    """
    An async file-like object that records aread/aclose calls,
    so that tests can assert on the resource lifecycle.
    """

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = list(chunks)
        self.reads: list[int] = []
        self.closes = 0

    async def aread(self, chunk_size: int = -1) -> bytes:
        self.reads.append(chunk_size)
        if not self._chunks:
            return b""
        return self._chunks.pop(0)

    async def aclose(self) -> None:
        self.closes += 1


@pytest.mark.anyio
async def test_multipart_encode_async_iterator_file() -> None:
    """
    Async iterators are supported as multipart file content. Their length
    cannot be determined upfront, so 'Transfer-Encoding: chunked' is used,
    and no invalid 'Content-Length' is sent.
    """

    async def file_content() -> typing.AsyncIterator[bytes]:
        yield b"<file "
        yield b"content>"

    url = "https://www.example.com/"
    headers = {"Content-Type": "multipart/form-data; boundary=BOUNDARY"}
    files = {"file": ("name.txt", file_content())}

    request = httpx.Request("POST", url, headers=headers, files=files)
    await request.aread()

    assert request.headers == {
        "Host": "www.example.com",
        "Content-Type": "multipart/form-data; boundary=BOUNDARY",
        "Transfer-Encoding": "chunked",
    }
    assert request.content == (
        b"--BOUNDARY\r\n"
        b'Content-Disposition: form-data; name="file"; filename="name.txt"\r\n'
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"<file content>\r\n"
        b"--BOUNDARY--\r\n"
    )


@pytest.mark.anyio
async def test_multipart_encode_async_aread_file() -> None:
    """
    Async file-like objects with an 'aread' method are supported as
    multipart file content, and are only read during iteration.
    """
    fileobj = TrackingAsyncFile([b"<file ", b"content>"])

    url = "https://www.example.com/"
    headers = {"Content-Type": "multipart/form-data; boundary=BOUNDARY"}
    files = {"file": ("name.txt", fileobj)}

    request = httpx.Request("POST", url, headers=headers, files=files)

    # The source must not be pre-read, either when the request is
    # created or when the headers are determined.
    assert fileobj.reads == []
    assert request.headers["Transfer-Encoding"] == "chunked"
    assert "Content-Length" not in request.headers
    assert fileobj.reads == []

    await request.aread()

    assert fileobj.reads != []
    assert request.content == (
        b"--BOUNDARY\r\n"
        b'Content-Disposition: form-data; name="file"; filename="name.txt"\r\n'
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"<file content>\r\n"
        b"--BOUNDARY--\r\n"
    )


@pytest.mark.anyio
async def test_multipart_encode_zero_byte_async_file() -> None:
    async def file_content() -> typing.AsyncIterator[bytes]:
        if False:
            yield b""  # pragma: no cover

    url = "https://www.example.com/"
    headers = {"Content-Type": "multipart/form-data; boundary=BOUNDARY"}
    files = {"file": ("name.txt", file_content())}

    request = httpx.Request("POST", url, headers=headers, files=files)
    await request.aread()

    assert request.headers == {
        "Host": "www.example.com",
        "Content-Type": "multipart/form-data; boundary=BOUNDARY",
        "Transfer-Encoding": "chunked",
    }
    assert request.content == (
        b"--BOUNDARY\r\n"
        b'Content-Disposition: form-data; name="file"; filename="name.txt"\r\n'
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"\r\n"
        b"--BOUNDARY--\r\n"
    )


@pytest.mark.anyio
async def test_multipart_encode_async_file_crossing_chunks() -> None:
    """
    Content larger than the multipart chunk size is read across
    multiple reads, without any pre-reading.
    """
    content = b"x" * (64 * 1024 + 1)
    fileobj = TrackingAsyncFile([content[: 64 * 1024], content[64 * 1024 :]])

    url = "https://www.example.com/"
    headers = {"Content-Type": "multipart/form-data; boundary=BOUNDARY"}
    files = {"file": ("name.txt", fileobj)}

    request = httpx.Request("POST", url, headers=headers, files=files)
    await request.aread()

    assert len(fileobj.reads) == 3  # Two chunks, plus a final empty read.
    assert content in request.content


def test_multipart_async_file_sync_iteration_raises() -> None:
    """
    A multipart stream including async files cannot be iterated
    synchronously, and must raise a clear error.
    """

    async def file_content() -> typing.AsyncIterator[bytes]:
        yield b"<file content>"  # pragma: no cover

    url = "https://www.example.com/"
    files = {"file": ("name.txt", file_content())}

    request = httpx.Request("POST", url, files=files)
    with pytest.raises(RuntimeError):
        request.read()


@pytest.mark.anyio
async def test_multipart_async_file_is_not_replayable() -> None:
    """
    Async iterators cannot be replayed. A second iteration must raise
    'StreamConsumed' rather than silently sending an empty body.
    """

    async def file_content() -> typing.AsyncIterator[bytes]:
        yield b"<file content>"

    url = "https://www.example.com/"
    files = {"file": ("name.txt", file_content())}

    request = httpx.Request("POST", url, files=files)
    stream = request.stream
    async for _ in stream:
        pass
    with pytest.raises(httpx.StreamConsumed):
        async for _ in stream:
            pass  # pragma: no cover


def test_multipart_non_seekable_file_is_not_replayable() -> None:
    """
    Non-seekable files cannot be replayed. A second iteration must raise
    'StreamConsumed' rather than silently sending an empty body.
    """
    fileobj = TrackingFile([b"<file content>"])

    url = "https://www.example.com/"
    files = {"file": ("name.txt", fileobj)}

    request = httpx.Request("POST", url, files=files)
    stream = request.stream
    assert isinstance(stream, typing.Iterable)
    for _ in stream:
        pass
    with pytest.raises(httpx.StreamConsumed):
        for _ in stream:
            pass  # pragma: no cover


def test_multipart_seekable_file_is_replayable() -> None:
    """
    Seekable files can be rendered more than once, supporting
    redirects and auth retries that resend the request body.
    """
    fileobj = io.BytesIO(b"<file content>")

    url = "https://www.example.com/"
    headers = {"Content-Type": "multipart/form-data; boundary=BOUNDARY"}
    files = {"file": ("name.txt", fileobj)}

    request = httpx.Request("POST", url, headers=headers, files=files)
    stream = request.stream
    assert isinstance(stream, typing.Iterable)
    first = b"".join(stream)
    second = b"".join(stream)
    assert first == second
    assert b"<file content>" in first


def test_multipart_close_closes_files_exactly_once() -> None:
    fileobj = TrackingFile([b"<file content>"])

    url = "https://www.example.com/"
    files = {"file": ("name.txt", fileobj)}

    request = httpx.Request("POST", url, files=files)
    request.stream.close()
    request.stream.close()
    assert fileobj.closes == 1


@pytest.mark.anyio
async def test_multipart_aclose_closes_async_files_exactly_once() -> None:
    fileobj = TrackingAsyncFile([b"<file content>"])

    url = "https://www.example.com/"
    files = {"file": ("name.txt", fileobj)}

    request = httpx.Request("POST", url, files=files)
    await request.stream.aclose()
    await request.stream.aclose()
    assert fileobj.closes == 1


def test_multipart_file_closed_on_send_failure() -> None:
    """
    If sending the request fails partway through the body, the request
    stream is closed, closing any underlying files exactly once.
    """
    fileobj = TrackingFile([b"<file content>"])

    class FailingTransport(httpx.BaseTransport):
        def handle_request(self, request: httpx.Request) -> httpx.Response:
            for _ in request.stream:
                raise RuntimeError("Failed mid-upload")
            return httpx.Response(200)  # pragma: no cover

    client = httpx.Client(transport=FailingTransport())
    with pytest.raises(RuntimeError):
        client.post("http://127.0.0.1:8000/", files={"file": ("name.txt", fileobj)})

    assert fileobj.reads == []  # Failure occurred before any file content.
    assert fileobj.closes == 1


@pytest.mark.anyio
async def test_multipart_async_file_closed_on_send_failure() -> None:
    """
    If sending the request fails partway through the body, the request
    stream is closed, closing any underlying async files exactly once.
    """
    fileobj = TrackingAsyncFile([b"<file content>"])

    class FailingTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            async for _ in request.stream:
                raise RuntimeError("Failed mid-upload")
            return httpx.Response(200)  # pragma: no cover

    async with httpx.AsyncClient(transport=FailingTransport()) as client:
        with pytest.raises(RuntimeError):
            await client.post(
                "http://127.0.0.1:8000/", files={"file": ("name.txt", fileobj)}
            )

    assert fileobj.reads == []  # Failure occurred before any file content.
    assert fileobj.closes == 1


def test_multipart_non_seekable_file_redirect_is_rejected() -> None:
    """
    A redirect that requires resending a non-replayable request body
    must raise 'StreamConsumed' rather than silently sending an empty
    body, and must close the underlying file exactly once.
    """
    fileobj = TrackingFile([b"<file content>"])

    class RedirectTransport(httpx.BaseTransport):
        def handle_request(self, request: httpx.Request) -> httpx.Response:
            if request.url.path == "/redirect":
                # Consume the request body, as a real transport would.
                for _ in request.stream:
                    pass
                return httpx.Response(308, headers=[("Location", "/target")])
            # The resent request body is consumed, as a real transport would.
            for _ in request.stream:
                pass  # pragma: no cover
            return httpx.Response(200)  # pragma: no cover

    client = httpx.Client(transport=RedirectTransport(), follow_redirects=True)
    with pytest.raises(httpx.StreamConsumed):
        client.post(
            "http://127.0.0.1:8000/redirect", files={"file": ("name.txt", fileobj)}
        )

    assert fileobj.closes == 1


@pytest.mark.anyio
async def test_multipart_async_file_redirect_is_rejected() -> None:
    """
    A redirect that requires resending a non-replayable async request
    body must raise 'StreamConsumed' rather than silently sending an
    empty body, and must close the underlying file exactly once.
    """
    fileobj = TrackingAsyncFile([b"<file content>"])

    class RedirectTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            if request.url.path == "/redirect":
                # Consume the request body, as a real transport would.
                async for _ in request.stream:
                    pass
                return httpx.Response(308, headers=[("Location", "/target")])
            # The resent request body is consumed, as a real transport would.
            async for _ in request.stream:
                pass  # pragma: no cover
            return httpx.Response(200)  # pragma: no cover

    async with httpx.AsyncClient(
        transport=RedirectTransport(), follow_redirects=True
    ) as client:
        with pytest.raises(httpx.StreamConsumed):
            await client.post(
                "http://127.0.0.1:8000/redirect", files={"file": ("name.txt", fileobj)}
            )

    assert fileobj.closes == 1


@pytest.mark.anyio
async def test_async_multipart_file_upload() -> None:
    """
    End-to-end async multipart upload with an async iterator file,
    using 'Transfer-Encoding: chunked' framing.
    """

    async def file_content() -> typing.AsyncIterator[bytes]:
        yield b"<file "
        yield b"content>"

    def echo_request(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=request.content)

    async with httpx.AsyncClient(transport=httpx.MockTransport(echo_request)) as client:
        files = {"file": ("name.txt", file_content())}
        response = await client.post("http://127.0.0.1:8000/", files=files)

    boundary = response.request.headers["Content-Type"].split("boundary=")[-1]
    boundary_bytes = boundary.encode("ascii")

    assert response.status_code == 200
    assert response.request.headers["Transfer-Encoding"] == "chunked"
    assert "Content-Length" not in response.request.headers
    assert response.content == b"".join(
        [
            b"--" + boundary_bytes + b"\r\n",
            b'Content-Disposition: form-data; name="file"; filename="name.txt"\r\n',
            b"Content-Type: text/plain\r\n",
            b"\r\n",
            b"<file content>\r\n",
            b"--" + boundary_bytes + b"--\r\n",
        ]
    )
