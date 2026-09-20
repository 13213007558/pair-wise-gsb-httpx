from __future__ import annotations

import io
import mimetypes
import os
import re
import typing
from pathlib import Path

from ._exceptions import StreamConsumed, StreamError
from ._types import (
    AsyncByteReader,
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


class AsyncFileUpload:
    """
    An async file part, for inclusion within a multipart form upload.

    This allows async byte sources, such as async object-storage readers,
    to be uploaded as multipart file parts, without reading the entire
    source into memory upfront.

    Usage:

        files = {
            "file": httpx.AsyncFileUpload(
                reader,
                filename="data.bin",
                content_type="application/octet-stream",
                content_length=size,  # Optional, if known upfront.
            )
        }
        async with httpx.AsyncClient() as client:
            response = await client.post(url, files=files)

    The stream may be any async iterable of bytes, or an async
    file-like object supporting 'aread()'. If the stream provides an
    'aclose()' method then it is always called once the part has been
    fully read, or if reading fails or is cancelled partway through.
    Streams are read-once, and cannot be replayed.
    """

    CHUNK_SIZE = 64 * 1024

    def __init__(
        self,
        stream: typing.AsyncIterable[bytes] | AsyncByteReader,
        *,
        filename: str | None = None,
        content_type: str | None = None,
        headers: typing.Mapping[str, str] | None = None,
        content_length: int | None = None,
    ) -> None:
        if not hasattr(stream, "__aiter__") and not hasattr(stream, "aread"):
            raise TypeError(
                "AsyncFileUpload requires an async byte stream, supporting "
                f"either 'aread()' or async iteration. Got {type(stream)!r}."
            )
        if content_length is not None and content_length < 0:
            raise ValueError(
                "AsyncFileUpload 'content_length' must be greater than or "
                f"equal to zero. Got {content_length}."
            )
        self.stream = stream
        self.filename = filename
        self.content_type = content_type
        self.headers = {} if headers is None else dict(headers)
        self.content_length = content_length
        self._is_consumed = False
        self._is_closed = False

    async def __aiter__(self) -> typing.AsyncIterator[bytes]:
        if self._is_consumed:
            # Async streams are read-once, and cannot be replayed.
            raise StreamConsumed()
        self._is_consumed = True

        bytes_read = 0
        try:
            if hasattr(self.stream, "aread"):
                # Async file-like interfaces should use 'aread' directly.
                chunk = await self.stream.aread(self.CHUNK_SIZE)
                while chunk:
                    bytes_read += len(chunk)
                    self._check_length(bytes_read, complete=False)
                    yield chunk
                    chunk = await self.stream.aread(self.CHUNK_SIZE)
            else:
                # Otherwise use async iteration.
                async for chunk in self.stream:
                    bytes_read += len(chunk)
                    self._check_length(bytes_read, complete=False)
                    yield chunk
        finally:
            # Ensure the source is closed on completion, failure,
            # or cancellation.
            await self.aclose()

        self._check_length(bytes_read, complete=True)

    def _check_length(self, bytes_read: int, complete: bool) -> None:
        if self.content_length is None:
            return
        if bytes_read > self.content_length or (
            complete and bytes_read != self.content_length
        ):
            raise StreamError(
                "Async file upload declared a 'content_length' of "
                f"{self.content_length} bytes, but the stream produced "
                f"{bytes_read} bytes."
            )

    async def aclose(self) -> None:
        """
        Close the underlying stream, if it provides an 'aclose()' method.

        This is idempotent, and is a no-op for streams that do not
        require closing.
        """
        if not self._is_closed:
            self._is_closed = True
            aclose = getattr(self.stream, "aclose", None)
            if aclose is not None:
                await aclose()


class FileField:
    """
    A single file field item, within a multipart form field.
    """

    CHUNK_SIZE = 64 * 1024

    def __init__(self, name: str, value: FileTypes) -> None:
        self.name = name

        fileobj: FileContent | AsyncFileUpload

        headers: dict[str, str] = {}
        content_type: str | None = None

        # This large tuple based API largely mirror's requests' API
        # It would be good to think of better APIs for this that we could
        # include in httpx 2.0 since variable length tuples(especially of 4 elements)
        # are quite unwieldly
        if isinstance(value, AsyncFileUpload):
            filename = value.filename
            fileobj = value
            content_type = value.content_type
            headers = dict(value.headers)
        elif isinstance(value, tuple):
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
            fileobj = value

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

    @property
    def is_async(self) -> bool:
        return isinstance(self.file, AsyncFileUpload)

    def get_length(self) -> int | None:
        headers = self.render_headers()

        if isinstance(self.file, AsyncFileUpload):
            if self.file.content_length is None:
                # The length of the async stream is not known upfront.
                return None
            return len(headers) + self.file.content_length

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
            parts = [
                b"Content-Disposition: form-data; ",
                _format_form_param("name", self.name),
            ]
            if self.filename:
                filename = _format_form_param("filename", self.filename)
                parts.extend([b"; ", filename])
            for header_name, header_value in self.headers.items():
                key, val = f"\r\n{header_name}: ".encode(), header_value.encode()
                parts.extend([key, val])
            parts.append(b"\r\n\r\n")
            self._headers = b"".join(parts)

        return self._headers

    def render_data(self) -> typing.Iterator[bytes]:
        if isinstance(self.file, (str, bytes)):
            yield to_bytes(self.file)
            return

        if isinstance(self.file, AsyncFileUpload):
            raise RuntimeError(
                "Cannot render an async file part using the sync multipart API."
            )

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

    async def arender_data(self) -> typing.AsyncIterator[bytes]:
        if isinstance(self.file, AsyncFileUpload):
            async for chunk in self.file:
                yield chunk
            return

        for chunk in self.render_data():
            yield chunk

    async def arender(self) -> typing.AsyncIterator[bytes]:
        yield self.render_headers()
        async for chunk in self.arender_data():
            yield chunk


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
        self._iterator: typing.AsyncGenerator[bytes, None] | None = None

    @property
    def has_async_parts(self) -> bool:
        return any(
            isinstance(field, FileField) and field.is_async for field in self.fields
        )

    def _iter_fields(
        self, data: RequestData, files: RequestFiles
    ) -> typing.Iterator[FileField | DataField]:
        for name, value in data.items():
            if isinstance(value, (tuple, list)):
                for item in value:
                    yield DataField(name=name, value=item)
            else:
                yield DataField(name=name, value=value)

        file_items = files.items() if isinstance(files, typing.Mapping) else files
        for name, value in file_items:
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
        if self.has_async_parts:
            raise RuntimeError(
                "Cannot send a multipart request including async file parts "
                "using a sync Client. Use 'httpx.AsyncClient' instead."
            )
        for chunk in self.iter_chunks():
            yield chunk

    def __aiter__(self) -> typing.AsyncGenerator[bytes, None]:
        self._iterator = self._aiter_chunks()
        return self._iterator

    async def _aiter_chunks(self) -> typing.AsyncGenerator[bytes, None]:
        for field in self.fields:
            yield b"--%s\r\n" % self.boundary
            if isinstance(field, FileField):
                async for chunk in field.arender():
                    yield chunk
            else:
                for chunk in field.render():
                    yield chunk
            yield b"\r\n"
        yield b"--%s--\r\n" % self.boundary

    async def aclose(self) -> None:
        if self._iterator is not None:
            # Ensure any in-progress iteration is closed off, so that
            # async file parts are not left suspended mid-read.
            await self._iterator.aclose()
            self._iterator = None
        for field in self.fields:
            if isinstance(field, FileField) and isinstance(field.file, AsyncFileUpload):
                await field.file.aclose()
