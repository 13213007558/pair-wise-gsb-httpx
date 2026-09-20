from __future__ import annotations

import io
import mimetypes
import os
import re
import typing
from pathlib import Path

from ._exceptions import StreamConsumed, StreamError
from ._types import (
    AsyncByteStream,
    FileContent,
    FileTypes,
    RequestData,
    RequestFiles,
    SyncByteStream,
)
from ._utils import (
    peek_filelike_length,
    primitive_value_to_str,
    to_bytes,
)

_HTML5_FORM_ENCODING_REPLACEMENTS = {'"': "%22", "\\": "\\\\"}
_HTML5_FORM_ENCODING_REPLACEMENTS.update(
    {chr(c): "%{:02X}".format(c) for c in range(0x1F + 1) if c != 0x1B}
)
_HTML5_FORM_ENCODING_RE = re.compile(
    r"|".join([re.escape(c) for c in _HTML5_FORM_ENCODING_REPLACEMENTS.keys()])
)


def _format_form_param(name: str, value: str) -> bytes:
    """
    Encode a name/value pair within a multipart form.
    """

    def replacer(match: typing.Match[str]) -> str:
        return _HTML5_FORM_ENCODING_REPLACEMENTS[match.group(0)]

    value = _HTML5_FORM_ENCODING_RE.sub(replacer, value)
    return f'{name}="{value}"'.encode()


def _guess_content_type(filename: str | None) -> str | None:
    """
    Guesses the mimetype based on a filename. Defaults to `application/octet-stream`.

    Returns `None` if `filename` is `None` or empty.
    """
    if filename:
        return mimetypes.guess_type(filename)[0] or "application/octet-stream"
    return None


def _render_file_headers(
    name: str, filename: str | None, headers: dict[str, str]
) -> bytes:
    parts = [
        b"Content-Disposition: form-data; ",
        _format_form_param("name", name),
    ]
    if filename:
        filename_param = _format_form_param("filename", filename)
        parts.extend([b"; ", filename_param])
    for header_name, header_value in headers.items():
        key, val = f"\r\n{header_name}: ".encode(), header_value.encode()
        parts.extend([key, val])
    parts.append(b"\r\n\r\n")
    return b"".join(parts)


@typing.runtime_checkable
class AsyncReadable(typing.Protocol):
    """
    A file-like async byte source, such as an async object storage reader,
    with an async `aread()` method.
    """

    async def aread(self, n: int = -1) -> bytes: ...  # pragma: no cover


def get_multipart_boundary_from_content_type(
    content_type: bytes | None,
) -> bytes | None:
    if not content_type or not content_type.startswith(b"multipart/form-data"):
        return None
    # parse boundary according to
    # https://www.rfc-editor.org/rfc/rfc2046#section-5.1.1
    if b";" in content_type:
        for section in content_type.split(b";"):
            if section.strip().lower().startswith(b"boundary="):
                return section.strip()[len(b"boundary=") :].strip(b'"')
    return None


class DataField:
    """
    A single form field item, within a multipart form field.
    """

    def __init__(self, name: str, value: str | bytes | int | float | None) -> None:
        if not isinstance(name, str):
            raise TypeError(
                f"Invalid type for name. Expected str, got {type(name)}: {name!r}"
            )
        if value is not None and not isinstance(value, (str, bytes, int, float)):
            raise TypeError(
                "Invalid type for value. Expected primitive type,"
                f" got {type(value)}: {value!r}"
            )
        self.name = name
        self.value: str | bytes = (
            value if isinstance(value, bytes) else primitive_value_to_str(value)
        )

    def render_headers(self) -> bytes:
        if not hasattr(self, "_headers"):
            name = _format_form_param("name", self.name)
            self._headers = b"".join(
                [b"Content-Disposition: form-data; ", name, b"\r\n\r\n"]
            )

        return self._headers

    def render_data(self) -> bytes:
        if not hasattr(self, "_data"):
            self._data = to_bytes(self.value)

        return self._data

    def get_length(self) -> int:
        headers = self.render_headers()
        data = self.render_data()
        return len(headers) + len(data)

    def render(self) -> typing.Iterator[bytes]:
        yield self.render_headers()
        yield self.render_data()

    async def arender(self) -> typing.AsyncGenerator[bytes, None]:
        yield self.render_headers()
        yield self.render_data()


class FileField:
    """
    A single file field item, within a multipart form field.
    """

    CHUNK_SIZE = 64 * 1024

    def __init__(self, name: str, value: FileTypes) -> None:
        self.name = name

        fileobj: FileContent

        headers: dict[str, str] = {}
        content_type: str | None = None

        # This large tuple based API largely mirror's requests' API
        # It would be good to think of better APIs for this that we could
        # include in httpx 2.0 since variable length tuples(especially of 4 elements)
        # are quite unwieldly
        if isinstance(value, tuple):
            if len(value) == 2:
                # neither the 3rd parameter (content_type) nor the 4th (headers)
                # was included
                filename, fileobj = value
            elif len(value) == 3:
                filename, fileobj, content_type = value
            else:
                # all 4 parameters included
                filename, fileobj, content_type, headers = value  # type: ignore
        else:
            filename = Path(str(getattr(value, "name", "upload"))).name
            fileobj = typing.cast(FileContent, value)

        if content_type is None:
            content_type = _guess_content_type(filename)

        has_content_type_header = any("content-type" in key.lower() for key in headers)
        if content_type is not None and not has_content_type_header:
            # note that unlike requests, we ignore the content_type provided in the 3rd
            # tuple element if it is also included in the headers requests does
            # the opposite (it overwrites the headerwith the 3rd tuple element)
            headers["Content-Type"] = content_type

        if isinstance(fileobj, io.StringIO):
            raise TypeError(
                "Multipart file uploads require 'io.BytesIO', not 'io.StringIO'."
            )
        if isinstance(fileobj, io.TextIOBase):
            raise TypeError(
                "Multipart file uploads must be opened in binary mode, not text mode."
            )

        self.filename = filename
        self.file = fileobj
        self.headers = headers

    def get_length(self) -> int | None:
        headers = self.render_headers()

        if isinstance(self.file, (str, bytes)):
            return len(headers) + len(to_bytes(self.file))

        file_length = peek_filelike_length(self.file)

        # If we can't determine the filesize without reading it into memory,
        # then return `None` here, to indicate an unknown file length.
        if file_length is None:
            return None

        return len(headers) + file_length

    def render_headers(self) -> bytes:
        if not hasattr(self, "_headers"):
            self._headers = _render_file_headers(self.name, self.filename, self.headers)

        return self._headers

    def render_data(self) -> typing.Iterator[bytes]:
        if isinstance(self.file, (str, bytes)):
            yield to_bytes(self.file)
            return

        if hasattr(self.file, "seek"):
            try:
                self.file.seek(0)
            except io.UnsupportedOperation:
                pass

        chunk = self.file.read(self.CHUNK_SIZE)
        while chunk:
            yield to_bytes(chunk)
            chunk = self.file.read(self.CHUNK_SIZE)

    def render(self) -> typing.Iterator[bytes]:
        yield self.render_headers()
        yield from self.render_data()

    async def arender(self) -> typing.AsyncGenerator[bytes, None]:
        yield self.render_headers()
        for chunk in self.render_data():
            yield chunk


class AsyncFile:
    """
    An async file part for multipart form uploads.

    This allows an async byte source, such as an async object storage reader,
    to be uploaded as a streaming multipart file part, without loading the
    entire content into memory or performing any synchronous I/O.

    The `source` may be either an async iterable of `bytes`, or a file-like
    object with an async `aread()` method.

    The source is always closed exactly once: when the part has been fully
    read, when the declared `content_length` does not match the actual
    content, or if the upload is interrupted for any other reason, such as
    cancellation or a transport failure. Sources that should remain open
    after the request must be wrapped so that closing is a no-op.

    Note that async sources are typically read-once streams, and cannot be
    replayed. Requests including an `AsyncFile` part cannot be automatically
    retried or redirected with a `307`/`308` status code unless the content
    has been buffered, for example by calling `request.aread()` first.

    Example:

        async with httpx.AsyncClient() as client:
            source = await bucket.open_read("report.csv")
            file = httpx.AsyncFile(source, filename="report.csv")
            await client.post(url, files={"upload": file})
    """

    def __init__(
        self,
        source: typing.AsyncIterable[bytes] | AsyncReadable,
        *,
        filename: str | None = None,
        content_type: str | None = None,
        headers: typing.Mapping[str, str] | None = None,
        content_length: int | None = None,
    ) -> None:
        if content_length is not None and content_length < 0:
            raise ValueError(
                f"Invalid 'content_length'. Expected a non-negative integer,"
                f" got {content_length!r}."
            )
        if not (hasattr(source, "aread") or hasattr(source, "__aiter__")):
            raise TypeError(
                "Invalid type for 'source'. Expected an async iterable of"
                f" bytes, or an object with an async 'aread()' method,"
                f" got {type(source)}: {source!r}"
            )
        self.source = source
        self.filename = filename
        self.content_type = content_type
        self.headers = dict(headers) if headers is not None else {}
        self.content_length = content_length


class AsyncFileField:
    """
    A single async file field item, within a multipart form field.
    """

    CHUNK_SIZE = 64 * 1024

    def __init__(self, name: str, value: AsyncFile) -> None:
        self.name = name
        self.filename = value.filename
        self.source = value.source
        self.content_length = value.content_length
        self._is_consumed = False

        headers = dict(value.headers)
        content_type = value.content_type
        if content_type is None:
            content_type = _guess_content_type(self.filename)

        has_content_type_header = any("content-type" in key.lower() for key in headers)
        if content_type is not None and not has_content_type_header:
            headers["Content-Type"] = content_type
        self.headers = headers

    def get_length(self) -> int | None:
        if self.content_length is None:
            # The length of the source is unknown upfront, indicating
            # that the multipart content requires a chunked transfer encoding.
            return None
        headers = self.render_headers()
        return len(headers) + self.content_length

    def render_headers(self) -> bytes:
        if not hasattr(self, "_headers"):
            self._headers = _render_file_headers(self.name, self.filename, self.headers)

        return self._headers

    async def render_data(self) -> typing.AsyncGenerator[bytes, None]:
        if self._is_consumed:
            # Async sources are read-once, and cannot be replayed.
            raise StreamConsumed()
        self._is_consumed = True

        bytes_read = 0
        try:
            if isinstance(self.source, AsyncReadable):
                # File-like interfaces should use 'aread' directly.
                chunk = await self.source.aread(self.CHUNK_SIZE)
                while chunk:
                    bytes_read += len(chunk)
                    self._check_length(bytes_read)
                    yield chunk
                    chunk = await self.source.aread(self.CHUNK_SIZE)
            else:
                # Otherwise iterate.
                async for chunk in self.source:
                    bytes_read += len(chunk)
                    self._check_length(bytes_read)
                    yield chunk
        finally:
            # The source is closed exactly once, on completion, failure,
            # or cancellation of the upload.
            await self._aclose_source()

        if self.content_length is not None and bytes_read != self.content_length:
            raise StreamError(
                f"Multipart file part {self.name!r} declared a 'content_length'"
                f" of {self.content_length} bytes, but the source was exhausted"
                f" after {bytes_read} bytes."
            )

    def _check_length(self, bytes_read: int) -> None:
        if self.content_length is not None and bytes_read > self.content_length:
            raise StreamError(
                f"Multipart file part {self.name!r} declared a 'content_length'"
                f" of {self.content_length} bytes, but the source returned"
                f" more data than declared."
            )

    async def _aclose_source(self) -> None:
        aclose = getattr(self.source, "aclose", None)
        if aclose is not None:
            await aclose()
            return
        close = getattr(self.source, "close", None)
        if close is not None:
            close()

    def render(self) -> typing.Iterator[bytes]:
        raise RuntimeError(
            "Cannot render an async file part using a sync stream."
            " Use 'httpx.AsyncClient' to send requests including"
            " 'httpx.AsyncFile' parts."
        )

    async def arender(self) -> typing.AsyncGenerator[bytes, None]:
        yield self.render_headers()
        rendered = self.render_data()
        try:
            async for chunk in rendered:
                yield chunk
        finally:
            # Ensure the source is closed if the upload is interrupted
            # part-way through rendering this field.
            await rendered.aclose()


class MultipartStream(SyncByteStream, AsyncByteStream):
    """
    Request content as streaming multipart encoded form data.
    """

    def __init__(
        self,
        data: RequestData,
        files: RequestFiles,
        boundary: bytes | None = None,
    ) -> None:
        if boundary is None:
            boundary = os.urandom(16).hex().encode("ascii")

        self.boundary = boundary
        self.content_type = "multipart/form-data; boundary=%s" % boundary.decode(
            "ascii"
        )
        self.fields = list(self._iter_fields(data, files))
        self.is_async = any(isinstance(field, AsyncFileField) for field in self.fields)

    def _iter_fields(
        self, data: RequestData, files: RequestFiles
    ) -> typing.Iterator[FileField | AsyncFileField | DataField]:
        for name, value in data.items():
            if isinstance(value, (tuple, list)):
                for item in value:
                    yield DataField(name=name, value=item)
            else:
                yield DataField(name=name, value=value)

        file_items = files.items() if isinstance(files, typing.Mapping) else files
        for name, value in file_items:
            if isinstance(value, AsyncFile):
                yield AsyncFileField(name=name, value=value)
            else:
                yield FileField(name=name, value=value)

    def iter_chunks(self) -> typing.Iterator[bytes]:
        for field in self.fields:
            yield b"--%s\r\n" % self.boundary
            yield from field.render()
            yield b"\r\n"
        yield b"--%s--\r\n" % self.boundary

    def get_content_length(self) -> int | None:
        """
        Return the length of the multipart encoded content, or `None` if
        any of the files have a length that cannot be determined upfront.
        """
        boundary_length = len(self.boundary)
        length = 0

        for field in self.fields:
            field_length = field.get_length()
            if field_length is None:
                return None

            length += 2 + boundary_length + 2  # b"--{boundary}\r\n"
            length += field_length
            length += 2  # b"\r\n"

        length += 2 + boundary_length + 4  # b"--{boundary}--\r\n"
        return length

    # Content stream interface.

    def get_headers(self) -> dict[str, str]:
        content_length = self.get_content_length()
        content_type = self.content_type
        if content_length is None:
            return {"Transfer-Encoding": "chunked", "Content-Type": content_type}
        return {"Content-Length": str(content_length), "Content-Type": content_type}

    def __iter__(self) -> typing.Iterator[bytes]:
        if self.is_async:
            raise RuntimeError(
                "Attempted to send an async multipart request with a sync"
                " Client instance. Use 'httpx.AsyncClient' to send requests"
                " including 'httpx.AsyncFile' parts."
            )
        for chunk in self.iter_chunks():
            yield chunk

    async def __aiter__(self) -> typing.AsyncGenerator[bytes, None]:
        for field in self.fields:
            yield b"--%s\r\n" % self.boundary
            rendered = field.arender()
            try:
                async for chunk in rendered:
                    yield chunk
            finally:
                await rendered.aclose()
            yield b"\r\n"
        yield b"--%s--\r\n" % self.boundary
