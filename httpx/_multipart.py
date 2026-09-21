from __future__ import annotations

import inspect
import io
import mimetypes
import os
import re
import typing
from pathlib import Path

from ._exceptions import StreamConsumed
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


def _is_factory(fileobj: typing.Any) -> bool:
    """
    A file object may be given as a zero-argument callable, returning a
    fresh file-like object or iterator for each render. This allows
    non-replayable sources to be re-sent, for example across redirects.
    """
    return (
        callable(fileobj)
        and not isinstance(fileobj, (str, bytes))
        and not any(
            hasattr(fileobj, attr)
            for attr in ("read", "aread", "__iter__", "__aiter__")
        )
    )


def _is_replayable(fileobj: typing.Any) -> bool:
    """
    Determine if a file source can be rendered more than once.

    Replayable sources are `bytes`/`str`, seekable file-like objects,
    and re-iterable collections. Non-replayable sources are iterators,
    generators, async iterables, and non-seekable file-like objects.
    """
    if isinstance(fileobj, (str, bytes)):
        return True

    seekable = getattr(fileobj, "seekable", None)
    if callable(seekable):
        try:
            return bool(seekable())
        except Exception:  # pragma: no cover
            return False

    if hasattr(fileobj, "seek"):
        return True

    if any(hasattr(fileobj, attr) for attr in ("read", "aread", "__aiter__")):
        return False

    try:
        # Iterators return themselves from `iter(...)`, and are single-use.
        # Re-iterable collections return a fresh iterator each time.
        return iter(fileobj) is not fileobj
    except TypeError:  # pragma: no cover
        return False


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

    async def arender(self) -> typing.AsyncIterator[bytes]:
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

        # A file source may be a zero-argument factory, returning a fresh
        # file-like object or iterator on each render. This is the only way
        # to make an otherwise non-replayable source re-usable, for example
        # when a redirect or authentication flow requires re-sending the body.
        self._is_factory = _is_factory(fileobj)
        self._replayable = self._is_factory or _is_replayable(fileobj)
        self._consumed = False
        # Track every source instance we have closed, so that any file or
        # stream is closed at most once. Strong references are kept so that
        # identity checks remain valid for the lifetime of the field.
        self._closed_files: list[typing.Any] = []

    def get_length(self) -> int | None:
        headers = self.render_headers()

        if self._is_factory:
            # The length of a factory-produced source cannot be determined
            # without creating an instance, which we avoid doing upfront.
            return None

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

    def _acquire_file(self) -> typing.Any:
        if self._is_factory:
            factory = typing.cast(typing.Callable[[], typing.Any], self.file)
            return factory()
        return self.file

    def _mark_consumed(self) -> None:
        if self._replayable:
            return
        if self._consumed:
            # Non-replayable sources may only be rendered once. Any attempt
            # to re-send them, such as across a redirect or an authentication
            # flow requiring the request body to be sent again, is an error,
            # rather than silently sending an empty or partial body.
            raise StreamConsumed()
        self._consumed = True

    def _should_close(self, fileobj: typing.Any) -> bool:
        if isinstance(fileobj, (str, bytes)):
            return False
        if self._is_factory:
            # Factory-produced instances are owned by this field.
            return True
        # Non-replayable sources are cleaned up once rendered, since they
        # cannot be used again. Replayable caller-owned files are left open.
        return not self._replayable

    def _close_file(self, fileobj: typing.Any) -> None:
        if not self._should_close(fileobj):
            return
        if any(fileobj is closed for closed in self._closed_files):
            return
        close = getattr(fileobj, "close", None)
        if close is not None:
            self._closed_files.append(fileobj)
            close()

    async def _aclose_file(self, fileobj: typing.Any) -> None:
        if not self._should_close(fileobj):
            return
        if any(fileobj is closed for closed in self._closed_files):
            return
        aclose = getattr(fileobj, "aclose", None)
        close = getattr(fileobj, "close", None)
        if aclose is not None:
            self._closed_files.append(fileobj)
            await aclose()
        elif close is not None:
            self._closed_files.append(fileobj)
            result = close()
            if inspect.isawaitable(result):
                await result

    def render_data(self) -> typing.Iterator[bytes]:
        fileobj = self._acquire_file()
        try:
            if hasattr(fileobj, "__aiter__") or hasattr(fileobj, "aread"):
                raise RuntimeError(
                    "Attempted to read an asynchronous file "
                    "in a synchronous multipart stream."
                )

            self._mark_consumed()

            if isinstance(fileobj, (str, bytes)):
                yield to_bytes(fileobj)
                return

            if hasattr(fileobj, "seek"):
                try:
                    fileobj.seek(0)
                except io.UnsupportedOperation:
                    pass

            if hasattr(fileobj, "read"):
                chunk = fileobj.read(self.CHUNK_SIZE)
                while chunk:
                    yield to_bytes(chunk)
                    chunk = fileobj.read(self.CHUNK_SIZE)
            else:
                for chunk in fileobj:
                    yield to_bytes(chunk)
        finally:
            self._close_file(fileobj)

    async def arender_data(self) -> typing.AsyncIterator[bytes]:
        fileobj = self._acquire_file()
        try:
            self._mark_consumed()

            if isinstance(fileobj, (str, bytes)):
                yield to_bytes(fileobj)
                return

            if hasattr(fileobj, "seek"):
                try:
                    fileobj.seek(0)
                except io.UnsupportedOperation:
                    pass

            if hasattr(fileobj, "aread"):
                chunk = await fileobj.aread(self.CHUNK_SIZE)
                while chunk:
                    yield to_bytes(chunk)
                    chunk = await fileobj.aread(self.CHUNK_SIZE)
            elif hasattr(fileobj, "__aiter__"):
                async for chunk in fileobj:
                    yield to_bytes(chunk)
            elif hasattr(fileobj, "read"):
                chunk = fileobj.read(self.CHUNK_SIZE)
                while chunk:
                    yield to_bytes(chunk)
                    chunk = fileobj.read(self.CHUNK_SIZE)
            else:
                for chunk in fileobj:
                    yield to_bytes(chunk)
        finally:
            await self._aclose_file(fileobj)

    def render(self) -> typing.Iterator[bytes]:
        yield self.render_headers()
        yield from self.render_data()

    async def arender(self) -> typing.AsyncIterator[bytes]:
        yield self.render_headers()
        data = self.arender_data()
        try:
            async for chunk in data:
                yield chunk
        finally:
            # Ensure the source is cleaned up, even if iteration
            # is abandoned or cancelled part-way through.
            await data.aclose()

    def close(self) -> None:
        if not self._is_factory:
            self._close_file(self.file)

    async def aclose(self) -> None:
        if not self._is_factory:
            await self._aclose_file(self.file)


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

    async def aiter_chunks(self) -> typing.AsyncIterator[bytes]:
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
        yield from self.iter_chunks()

    async def __aiter__(self) -> typing.AsyncIterator[bytes]:
        chunks = self.aiter_chunks()
        try:
            async for chunk in chunks:
                yield chunk
        finally:
            # Closing the stream also closes any inner generators,
            # ensuring sources are cleaned up on cancellation.
            await chunks.aclose()

    def close(self) -> None:
        for field in self.fields:
            if isinstance(field, FileField):
                field.close()

    async def aclose(self) -> None:
        for field in self.fields:
            if isinstance(field, FileField):
                await field.aclose()
