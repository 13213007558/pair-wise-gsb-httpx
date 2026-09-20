from __future__ import annotations

import io
import tempfile
import typing

import anyio
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


class ControlledAsyncReader:
    """
    A controlled async file-like reader, used to exercise async file uploads.

    Tracks read calls and closure, and always yields to the event loop
    when reading, so that tests can prove reads do not block the loop.
    """

    def __init__(
        self,
        chunks: typing.List[bytes],
        *,
        gate: "anyio.Event | None" = None,
        fail_on_read: "int | None" = None,
        delay: float = 0.0,
    ) -> None:
        self._chunks = list(chunks)
        self._gate = gate
        self._fail_on_read = fail_on_read
        self._delay = delay
        self.reads = 0
        self.closes = 0

    @property
    def closed(self) -> bool:
        return self.closes > 0

    async def aread(self, n: int = -1) -> bytes:
        self.reads += 1
        if self._delay:
            await anyio.sleep(self._delay)
        else:
            await anyio.sleep(0)
        if self._gate is not None:
            await self._gate.wait()
        if self._fail_on_read is not None and self.reads == self._fail_on_read:
            raise OSError("Simulated read failure.")
        if self._chunks:
            return self._chunks.pop(0)
        return b""

    async def aclose(self) -> None:
        self.closes += 1


@pytest.mark.anyio
async def test_multipart_async_file_upload():
    reader = ControlledAsyncReader([b"<async file content>"])
    data = {"text": "abc"}
    files: typing.List[typing.Tuple[str, typing.Any]] = [
        ("file", b"<bytes content>"),
        ("tuple-file", ("name.txt", io.BytesIO(b"<tuple content>"), "text/plain")),
        (
            "async-file",
            httpx.AsyncFileUpload(
                reader,
                filename="async.bin",
                content_type="application/octet-stream",
                headers={"X-Custom": "example"},
                content_length=20,
            ),
        ),
    ]

    transport = httpx.MockTransport(echo_request_content)
    async with httpx.AsyncClient(transport=transport) as client:
        response = await client.post("http://127.0.0.1:8000/", data=data, files=files)
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
            b"<bytes content>\r\n",
            b"--" + boundary_bytes + b"\r\n",
            b'Content-Disposition: form-data; name="tuple-file"; '
            b'filename="name.txt"\r\n',
            b"Content-Type: text/plain\r\n",
            b"\r\n",
            b"<tuple content>\r\n",
            b"--" + boundary_bytes + b"\r\n",
            b'Content-Disposition: form-data; name="async-file"; '
            b'filename="async.bin"\r\n',
            b"X-Custom: example\r\n",
            b"Content-Type: application/octet-stream\r\n",
            b"\r\n",
            b"<async file content>\r\n",
            b"--" + boundary_bytes + b"--\r\n",
        ]
    )
    # All part lengths were known, so an accurate Content-Length is used.
    assert response.request.headers["Content-Length"] == str(len(response.content))
    assert "Transfer-Encoding" not in response.request.headers
    # The source is closed once the upload completes.
    assert reader.closed


@pytest.mark.anyio
async def test_multipart_async_file_upload_repeated_filenames():
    readers = [
        ControlledAsyncReader([b"<content 1>"]),
        ControlledAsyncReader([b"<content 2>"]),
    ]
    files = [
        ("file", httpx.AsyncFileUpload(readers[0], filename="same.txt")),
        ("file", httpx.AsyncFileUpload(readers[1], filename="same.txt")),
    ]

    transport = httpx.MockTransport(echo_request_content)
    async with httpx.AsyncClient(transport=transport) as client:
        response = await client.post("http://127.0.0.1:8000/", files=files)

    assert response.status_code == 200
    assert response.content.count(b'filename="same.txt"') == 2
    assert response.content.index(b"<content 1>") < response.content.index(
        b"<content 2>"
    )
    assert all(reader.closed for reader in readers)


@pytest.mark.anyio
async def test_multipart_async_file_upload_from_async_iterator():
    finalized = False

    async def stream() -> typing.AsyncIterator[bytes]:
        nonlocal finalized
        try:
            yield b"hello "
            yield b"world"
        finally:
            finalized = True

    files = {"file": httpx.AsyncFileUpload(stream(), filename="data.txt")}

    transport = httpx.MockTransport(echo_request_content)
    async with httpx.AsyncClient(transport=transport) as client:
        response = await client.post("http://127.0.0.1:8000/", files=files)

    assert response.status_code == 200
    assert b"\r\nhello world\r\n" in response.content
    # The async generator is closed once the upload completes.
    assert finalized


@pytest.mark.anyio
async def test_multipart_async_file_upload_known_content_length():
    reader = ControlledAsyncReader([b"<async file content>"])
    files = {
        "file": httpx.AsyncFileUpload(reader, filename="data.txt", content_length=20)
    }
    request = httpx.Request("POST", "http://127.0.0.1:8000/", files=files)

    assert "Transfer-Encoding" not in request.headers
    body = await request.aread()
    assert request.headers["Content-Length"] == str(len(body))


@pytest.mark.anyio
async def test_multipart_async_file_upload_unknown_content_length():
    reader = ControlledAsyncReader([b"<async file content>"])
    files = {"file": httpx.AsyncFileUpload(reader, filename="data.txt")}
    request = httpx.Request("POST", "http://127.0.0.1:8000/", files=files)

    # Unknown length streams use chunked transfer encoding.
    assert request.headers["Transfer-Encoding"] == "chunked"
    assert "Content-Length" not in request.headers
    body = await request.aread()
    assert b"<async file content>" in body


@pytest.mark.anyio
async def test_multipart_async_file_upload_is_not_buffered():
    # The source is read lazily, as the encoded output is consumed,
    # rather than being read into memory upfront.
    reader = ControlledAsyncReader([b"chunk-1", b"chunk-2", b"chunk-3"])
    files = {"file": httpx.AsyncFileUpload(reader, filename="data.txt")}
    request = httpx.Request("POST", "http://127.0.0.1:8000/", files=files)

    stream = typing.cast(httpx.AsyncByteStream, request.stream)
    assert reader.reads == 0

    chunks = []
    async for chunk in stream:
        chunks.append(chunk)
        if chunk == b"chunk-1":
            # Only a single read has occurred at the point the first
            # file chunk is emitted.
            assert reader.reads == 1

    assert b"".join(chunks).count(b"chunk-") == 3
    assert reader.closed


@pytest.mark.anyio
async def test_multipart_async_file_upload_does_not_block_event_loop():
    reader = ControlledAsyncReader([b"x" * 1024] * 10, delay=0.01)
    files = {"file": httpx.AsyncFileUpload(reader, filename="data.txt")}
    ticks = 0
    uploading = True

    async def ticker() -> None:
        nonlocal ticks
        while uploading:
            ticks += 1
            await anyio.sleep(0)

    async def upload() -> None:
        nonlocal uploading
        transport = httpx.MockTransport(echo_request_content)
        async with httpx.AsyncClient(transport=transport) as client:
            await client.post("http://127.0.0.1:8000/", files=files)
        uploading = False

    async with anyio.create_task_group() as task_group:
        task_group.start_soon(ticker)
        await upload()

    # The ticker task progressed while the upload was in flight,
    # demonstrating that reads did not block the event loop.
    assert ticks > 0


@pytest.mark.anyio
async def test_multipart_async_file_upload_content_length_too_small():
    reader = ControlledAsyncReader([b"<async file content>"])
    files = {
        "file": httpx.AsyncFileUpload(reader, filename="data.txt", content_length=10)
    }

    transport = httpx.MockTransport(echo_request_content)
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(httpx.StreamError, match="content_length"):
            await client.post("http://127.0.0.1:8000/", files=files)

    # The stream is closed on failure.
    assert reader.closed


@pytest.mark.anyio
async def test_multipart_async_file_upload_content_length_too_large():
    reader = ControlledAsyncReader([b"<async file content>"])
    files = {
        "file": httpx.AsyncFileUpload(reader, filename="data.txt", content_length=100)
    }

    transport = httpx.MockTransport(echo_request_content)
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(httpx.StreamError, match="content_length"):
            await client.post("http://127.0.0.1:8000/", files=files)

    # The stream is closed on failure.
    assert reader.closed


@pytest.mark.anyio
async def test_multipart_async_file_upload_read_failure_closes_stream():
    reader = ControlledAsyncReader([b"chunk-1", b"chunk-2"], fail_on_read=2)
    files = {"file": httpx.AsyncFileUpload(reader, filename="data.txt")}

    transport = httpx.MockTransport(echo_request_content)
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(OSError, match="Simulated read failure"):
            await client.post("http://127.0.0.1:8000/", files=files)

    # The stream is closed when the source fails.
    assert reader.closed


@pytest.mark.anyio
async def test_multipart_async_file_upload_cancellation_closes_stream():
    gate = anyio.Event()
    reader = ControlledAsyncReader([b"chunk-1", b"chunk-2"], gate=gate)
    files = {"file": httpx.AsyncFileUpload(reader, filename="data.txt")}

    async def upload() -> None:
        transport = httpx.MockTransport(echo_request_content)
        async with httpx.AsyncClient(transport=transport) as client:
            await client.post("http://127.0.0.1:8000/", files=files)

    # The reader blocks on the gate, so the upload is cancelled
    # once the deadline expires.
    with anyio.move_on_after(0.2):
        await upload()

    # The stream is closed when the upload is cancelled.
    assert reader.closed
    assert reader.reads > 0


@pytest.mark.anyio
async def test_multipart_async_file_upload_transport_failure_closes_stream():
    reader = ControlledAsyncReader([b"chunk-1", b"chunk-2"])

    class FailingTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            # Start consuming the request content, then fail.
            aiterator = request.stream.__aiter__()
            await aiterator.__anext__()
            raise httpx.TransportError("Simulated transport failure.")

    files = {"file": httpx.AsyncFileUpload(reader, filename="data.txt")}
    async with httpx.AsyncClient(transport=FailingTransport()) as client:
        with pytest.raises(httpx.TransportError, match="Simulated"):
            await client.post("http://127.0.0.1:8000/", files=files)

    # The stream is closed when the transport fails.
    assert reader.closed


@pytest.mark.anyio
async def test_multipart_async_file_upload_cannot_be_replayed():
    reader = ControlledAsyncReader([b"<async file content>"])
    upload = httpx.AsyncFileUpload(reader, filename="data.txt", content_length=20)

    transport = httpx.MockTransport(echo_request_content)
    async with httpx.AsyncClient(transport=transport) as client:
        response = await client.post("http://127.0.0.1:8000/", files={"file": upload})
        assert response.status_code == 200

        # Read-once async sources cannot be automatically replayed.
        with pytest.raises(httpx.StreamConsumed):
            await client.post("http://127.0.0.1:8000/", files={"file": upload})


@pytest.mark.anyio
async def test_multipart_stream_aclose_closes_async_parts():
    reader = ControlledAsyncReader([b"<async file content>"])
    files = {"file": httpx.AsyncFileUpload(reader, filename="data.txt")}
    request = httpx.Request("POST", "http://127.0.0.1:8000/", files=files)

    stream = typing.cast(httpx.AsyncByteStream, request.stream)
    await stream.aclose()
    assert reader.closed


@pytest.mark.anyio
async def test_multipart_async_file_upload_close_is_idempotent():
    reader = ControlledAsyncReader([b"<async file content>"])
    upload = httpx.AsyncFileUpload(reader, filename="data.txt", content_length=20)

    transport = httpx.MockTransport(echo_request_content)
    async with httpx.AsyncClient(transport=transport) as client:
        response = await client.post("http://127.0.0.1:8000/", files={"file": upload})

    assert response.status_code == 200
    stream = typing.cast(httpx.AsyncByteStream, response.request.stream)
    await stream.aclose()
    # The underlying source is only ever closed once.
    assert reader.closes == 1


@pytest.mark.anyio
async def test_multipart_async_file_upload_content_type_guessing_and_escaping():
    reader = ControlledAsyncReader([b"x"])
    files = {
        "file": httpx.AsyncFileUpload(
            reader, filename='hello "world".json', content_length=1
        )
    }
    request = httpx.Request("POST", "http://127.0.0.1:8000/", files=files)
    body = await request.aread()

    # Filenames use the same HTML5 form escaping as existing file parts,
    # and the content type is guessed from the filename by default.
    assert b'filename="hello %22world%22.json"' in body
    assert b"Content-Type: application/json" in body


def test_multipart_async_file_upload_with_sync_client():
    reader = ControlledAsyncReader([b"<async file content>"])
    files = {"file": httpx.AsyncFileUpload(reader, filename="data.txt")}

    transport = httpx.MockTransport(echo_request_content)
    with httpx.Client(transport=transport) as client:
        with pytest.raises(RuntimeError, match="async file parts"):
            client.post("http://127.0.0.1:8000/", files=files)


def test_async_file_upload_requires_async_stream():
    with pytest.raises(TypeError, match="async byte stream"):
        httpx.AsyncFileUpload(b"<not an async stream>")  # type: ignore[arg-type]


def test_async_file_upload_requires_valid_content_length():
    reader = ControlledAsyncReader([])
    with pytest.raises(ValueError, match="content_length"):
        httpx.AsyncFileUpload(reader, content_length=-1)
