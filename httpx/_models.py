from __future__ import annotations

import codecs
import datetime
import email.message
import enum
import json as jsonlib
import re
import time
import typing
import urllib.parse
import urllib.request
from collections.abc import Mapping
from http.cookiejar import (
    Cookie,
    CookieJar,
    DefaultCookiePolicy,
)
from ipaddress import ip_address

from ._content import ByteStream, UnattachedStream, encode_request, encode_response
from ._decoders import (
    SUPPORTED_DECODERS,
    ByteChunker,
    ContentDecoder,
    IdentityDecoder,
    LineDecoder,
    MultiDecoder,
    TextChunker,
    TextDecoder,
)
from ._exceptions import (
    CookieConflict,
    HTTPStatusError,
    RequestNotRead,
    ResponseNotRead,
    StreamClosed,
    StreamConsumed,
    request_context,
)
from ._multipart import get_multipart_boundary_from_content_type
from ._public_suffix import public_suffix, registrable_domain
from ._status_codes import codes
from ._types import (
    AsyncByteStream,
    CookieTypes,
    HeaderTypes,
    QueryParamTypes,
    RequestContent,
    RequestData,
    RequestExtensions,
    RequestFiles,
    ResponseContent,
    ResponseExtensions,
    SyncByteStream,
)
from ._urls import URL
from ._utils import to_bytes_or_str, to_str

__all__ = ["Cookies", "Headers", "Request", "Response", "SameSitePolicy"]


class SameSitePolicy(str, enum.Enum):
    RFC6265 = "rfc6265"
    LAX = "lax"
    STRICT = "strict"


def _eff_request_host(request: typing.Any) -> tuple[str, str]:
    host = urllib.parse.urlsplit(request.get_full_url()).hostname or ""
    try:
        ip_address(host)
    except ValueError:
        if "." not in host:
            return host, f"{host}.local"
    return host, host


SENSITIVE_HEADERS = {"authorization", "proxy-authorization"}


def _is_known_encoding(encoding: str) -> bool:
    """
    Return `True` if `encoding` is a known codec.
    """
    try:
        codecs.lookup(encoding)
    except LookupError:
        return False
    return True


def _normalize_header_key(key: str | bytes, encoding: str | None = None) -> bytes:
    """
    Coerce str/bytes into a strictly byte-wise HTTP header key.
    """
    return key if isinstance(key, bytes) else key.encode(encoding or "ascii")


def _normalize_header_value(value: str | bytes, encoding: str | None = None) -> bytes:
    """
    Coerce str/bytes into a strictly byte-wise HTTP header value.
    """
    if isinstance(value, bytes):
        return value
    if not isinstance(value, str):
        raise TypeError(f"Header value must be str or bytes, not {type(value)}")
    return value.encode(encoding or "ascii")


def _parse_content_type_charset(content_type: str) -> str | None:
    # We used to use `cgi.parse_header()` here, but `cgi` became a dead battery.
    # See: https://peps.python.org/pep-0594/#cgi
    msg = email.message.Message()
    msg["content-type"] = content_type
    return msg.get_content_charset(failobj=None)


def _parse_header_links(value: str) -> list[dict[str, str]]:
    """
    Returns a list of parsed link headers, for more info see:
    https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Link
    The generic syntax of those is:
    Link: < uri-reference >; param1=value1; param2="value2"
    So for instance:
    Link; '<http:/.../front.jpeg>; type="image/jpeg",<http://.../back.jpeg>;'
    would return
        [
            {"url": "http:/.../front.jpeg", "type": "image/jpeg"},
            {"url": "http://.../back.jpeg"},
        ]
    :param value: HTTP Link entity-header field
    :return: list of parsed link headers
    """
    links: list[dict[str, str]] = []
    replace_chars = " '\""
    value = value.strip(replace_chars)
    if not value:
        return links
    for val in re.split(", *<", value):
        try:
            url, params = val.split(";", 1)
        except ValueError:
            url, params = val, ""
        link = {"url": url.strip("<> '\"")}
        for param in params.split(";"):
            try:
                key, value = param.split("=")
            except ValueError:
                break
            link[key.strip(replace_chars)] = value.strip(replace_chars)
        links.append(link)
    return links


def _obfuscate_sensitive_headers(
    items: typing.Iterable[tuple[typing.AnyStr, typing.AnyStr]],
) -> typing.Iterator[tuple[typing.AnyStr, typing.AnyStr]]:
    for k, v in items:
        if to_str(k.lower()) in SENSITIVE_HEADERS:
            v = to_bytes_or_str("[secure]", match_type_of=v)
        yield k, v


class Headers(typing.MutableMapping[str, str]):
    """
    HTTP headers, as a case-insensitive multi-dict.
    """

    def __init__(
        self,
        headers: HeaderTypes | None = None,
        encoding: str | None = None,
    ) -> None:
        self._list = []  # type: typing.List[typing.Tuple[bytes, bytes, bytes]]

        if isinstance(headers, Headers):
            self._list = list(headers._list)
        elif isinstance(headers, Mapping):
            for k, v in headers.items():
                bytes_key = _normalize_header_key(k, encoding)
                bytes_value = _normalize_header_value(v, encoding)
                self._list.append((bytes_key, bytes_key.lower(), bytes_value))
        elif headers is not None:
            for k, v in headers:
                bytes_key = _normalize_header_key(k, encoding)
                bytes_value = _normalize_header_value(v, encoding)
                self._list.append((bytes_key, bytes_key.lower(), bytes_value))

        self._encoding = encoding

    @property
    def encoding(self) -> str:
        """
        Header encoding is mandated as ascii, but we allow fallbacks to utf-8
        or iso-8859-1.
        """
        if self._encoding is None:
            for encoding in ["ascii", "utf-8"]:
                for key, value in self.raw:
                    try:
                        key.decode(encoding)
                        value.decode(encoding)
                    except UnicodeDecodeError:
                        break
                else:
                    # The else block runs if 'break' did not occur, meaning
                    # all values fitted the encoding.
                    self._encoding = encoding
                    break
            else:
                # The ISO-8859-1 encoding covers all 256 code points in a byte,
                # so will never raise decode errors.
                self._encoding = "iso-8859-1"
        return self._encoding

    @encoding.setter
    def encoding(self, value: str) -> None:
        self._encoding = value

    @property
    def raw(self) -> list[tuple[bytes, bytes]]:
        """
        Returns a list of the raw header items, as byte pairs.
        """
        return [(raw_key, value) for raw_key, _, value in self._list]

    def keys(self) -> typing.KeysView[str]:
        return {key.decode(self.encoding): None for _, key, value in self._list}.keys()

    def values(self) -> typing.ValuesView[str]:
        values_dict: dict[str, str] = {}
        for _, key, value in self._list:
            str_key = key.decode(self.encoding)
            str_value = value.decode(self.encoding)
            if str_key in values_dict:
                values_dict[str_key] += f", {str_value}"
            else:
                values_dict[str_key] = str_value
        return values_dict.values()

    def items(self) -> typing.ItemsView[str, str]:
        """
        Return `(key, value)` items of headers. Concatenate headers
        into a single comma separated value when a key occurs multiple times.
        """
        values_dict: dict[str, str] = {}
        for _, key, value in self._list:
            str_key = key.decode(self.encoding)
            str_value = value.decode(self.encoding)
            if str_key in values_dict:
                values_dict[str_key] += f", {str_value}"
            else:
                values_dict[str_key] = str_value
        return values_dict.items()

    def multi_items(self) -> list[tuple[str, str]]:
        """
        Return a list of `(key, value)` pairs of headers. Allow multiple
        occurrences of the same key without concatenating into a single
        comma separated value.
        """
        return [
            (key.decode(self.encoding), value.decode(self.encoding))
            for _, key, value in self._list
        ]

    def get(self, key: str, default: typing.Any = None) -> typing.Any:
        """
        Return a header value. If multiple occurrences of the header occur
        then concatenate them together with commas.
        """
        try:
            return self[key]
        except KeyError:
            return default

    def get_list(self, key: str, split_commas: bool = False) -> list[str]:
        """
        Return a list of all header values for a given key.
        If `split_commas=True` is passed, then any comma separated header
        values are split into multiple return strings.
        """
        get_header_key = key.lower().encode(self.encoding)

        values = [
            item_value.decode(self.encoding)
            for _, item_key, item_value in self._list
            if item_key.lower() == get_header_key
        ]

        if not split_commas:
            return values

        split_values = []
        for value in values:
            split_values.extend([item.strip() for item in value.split(",")])
        return split_values

    def update(self, headers: HeaderTypes | None = None) -> None:  # type: ignore
        headers = Headers(headers)
        for key in headers.keys():
            if key in self:
                self.pop(key)
        self._list.extend(headers._list)

    def copy(self) -> Headers:
        return Headers(self, encoding=self.encoding)

    def __getitem__(self, key: str) -> str:
        """
        Return a single header value.

        If there are multiple headers with the same key, then we concatenate
        them with commas. See: https://tools.ietf.org/html/rfc7230#section-3.2.2
        """
        normalized_key = key.lower().encode(self.encoding)

        items = [
            header_value.decode(self.encoding)
            for _, header_key, header_value in self._list
            if header_key == normalized_key
        ]

        if items:
            return ", ".join(items)

        raise KeyError(key)

    def __setitem__(self, key: str, value: str) -> None:
        """
        Set the header `key` to `value`, removing any duplicate entries.
        Retains insertion order.
        """
        set_key = key.encode(self._encoding or "utf-8")
        set_value = value.encode(self._encoding or "utf-8")
        lookup_key = set_key.lower()

        found_indexes = [
            idx
            for idx, (_, item_key, _) in enumerate(self._list)
            if item_key == lookup_key
        ]

        for idx in reversed(found_indexes[1:]):
            del self._list[idx]

        if found_indexes:
            idx = found_indexes[0]
            self._list[idx] = (set_key, lookup_key, set_value)
        else:
            self._list.append((set_key, lookup_key, set_value))

    def __delitem__(self, key: str) -> None:
        """
        Remove the header `key`.
        """
        del_key = key.lower().encode(self.encoding)

        pop_indexes = [
            idx
            for idx, (_, item_key, _) in enumerate(self._list)
            if item_key.lower() == del_key
        ]

        if not pop_indexes:
            raise KeyError(key)

        for idx in reversed(pop_indexes):
            del self._list[idx]

    def __contains__(self, key: typing.Any) -> bool:
        header_key = key.lower().encode(self.encoding)
        return header_key in [key for _, key, _ in self._list]

    def __iter__(self) -> typing.Iterator[typing.Any]:
        return iter(self.keys())

    def __len__(self) -> int:
        return len(self._list)

    def __eq__(self, other: typing.Any) -> bool:
        try:
            other_headers = Headers(other)
        except ValueError:
            return False

        self_list = [(key, value) for _, key, value in self._list]
        other_list = [(key, value) for _, key, value in other_headers._list]
        return sorted(self_list) == sorted(other_list)

    def __repr__(self) -> str:
        class_name = self.__class__.__name__

        encoding_str = ""
        if self.encoding != "ascii":
            encoding_str = f", encoding={self.encoding!r}"

        as_list = list(_obfuscate_sensitive_headers(self.multi_items()))
        as_dict = dict(as_list)

        no_duplicate_keys = len(as_dict) == len(as_list)
        if no_duplicate_keys:
            return f"{class_name}({as_dict!r}{encoding_str})"
        return f"{class_name}({as_list!r}{encoding_str})"


class Request:
    def __init__(
        self,
        method: str,
        url: URL | str,
        *,
        params: QueryParamTypes | None = None,
        headers: HeaderTypes | None = None,
        cookies: CookieTypes | None = None,
        content: RequestContent | None = None,
        data: RequestData | None = None,
        files: RequestFiles | None = None,
        json: typing.Any | None = None,
        stream: SyncByteStream | AsyncByteStream | None = None,
        extensions: RequestExtensions | None = None,
    ) -> None:
        self.method = method.upper()
        self.url = URL(url) if params is None else URL(url, params=params)
        self.headers = Headers(headers)
        self.extensions = {} if extensions is None else dict(extensions)

        if cookies:
            Cookies(cookies).set_cookie_header(self)

        if stream is None:
            content_type: str | None = self.headers.get("content-type")
            headers, stream = encode_request(
                content=content,
                data=data,
                files=files,
                json=json,
                boundary=get_multipart_boundary_from_content_type(
                    content_type=content_type.encode(self.headers.encoding)
                    if content_type
                    else None
                ),
            )
            self._prepare(headers)
            self.stream = stream
            # Load the request body, except for streaming content.
            if isinstance(stream, ByteStream):
                self.read()
        else:
            # There's an important distinction between `Request(content=...)`,
            # and `Request(stream=...)`.
            #
            # Using `content=...` implies automatically populated `Host` and content
            # headers, of either `Content-Length: ...` or `Transfer-Encoding: chunked`.
            #
            # Using `stream=...` will not automatically include *any*
            # auto-populated headers.
            #
            # As an end-user you don't really need `stream=...`. It's only
            # useful when:
            #
            # * Preserving the request stream when copying requests, eg for redirects.
            # * Creating request instances on the *server-side* of the transport API.
            self.stream = stream

    def _prepare(self, default_headers: dict[str, str]) -> None:
        for key, value in default_headers.items():
            # Ignore Transfer-Encoding if the Content-Length has been set explicitly.
            if key.lower() == "transfer-encoding" and "Content-Length" in self.headers:
                continue
            self.headers.setdefault(key, value)

        auto_headers: list[tuple[bytes, bytes]] = []

        has_host = "Host" in self.headers
        has_content_length = (
            "Content-Length" in self.headers or "Transfer-Encoding" in self.headers
        )

        if not has_host and self.url.host:
            auto_headers.append((b"Host", self.url.netloc))
        if not has_content_length and self.method in ("POST", "PUT", "PATCH"):
            auto_headers.append((b"Content-Length", b"0"))

        self.headers = Headers(auto_headers + self.headers.raw)

    @property
    def content(self) -> bytes:
        if not hasattr(self, "_content"):
            raise RequestNotRead()
        return self._content

    def read(self) -> bytes:
        """
        Read and return the request content.
        """
        if not hasattr(self, "_content"):
            assert isinstance(self.stream, typing.Iterable)
            self._content = b"".join(self.stream)
            if not isinstance(self.stream, ByteStream):
                # If a streaming request has been read entirely into memory, then
                # we can replace the stream with a raw bytes implementation,
                # to ensure that any non-replayable streams can still be used.
                self.stream = ByteStream(self._content)
        return self._content

    async def aread(self) -> bytes:
        """
        Read and return the request content.
        """
        if not hasattr(self, "_content"):
            assert isinstance(self.stream, typing.AsyncIterable)
            self._content = b"".join([part async for part in self.stream])
            if not isinstance(self.stream, ByteStream):
                # If a streaming request has been read entirely into memory, then
                # we can replace the stream with a raw bytes implementation,
                # to ensure that any non-replayable streams can still be used.
                self.stream = ByteStream(self._content)
        return self._content

    def __repr__(self) -> str:
        class_name = self.__class__.__name__
        url = str(self.url)
        return f"<{class_name}({self.method!r}, {url!r})>"

    def __getstate__(self) -> dict[str, typing.Any]:
        return {
            name: value
            for name, value in self.__dict__.items()
            if name not in ["extensions", "stream"]
        }

    def __setstate__(self, state: dict[str, typing.Any]) -> None:
        for name, value in state.items():
            setattr(self, name, value)
        self.extensions = {}
        self.stream = UnattachedStream()


class Response:
    def __init__(
        self,
        status_code: int,
        *,
        headers: HeaderTypes | None = None,
        content: ResponseContent | None = None,
        text: str | None = None,
        html: str | None = None,
        json: typing.Any = None,
        stream: SyncByteStream | AsyncByteStream | None = None,
        request: Request | None = None,
        extensions: ResponseExtensions | None = None,
        history: list[Response] | None = None,
        default_encoding: str | typing.Callable[[bytes], str] = "utf-8",
    ) -> None:
        self.status_code = status_code
        self.headers = Headers(headers)

        self._request: Request | None = request

        # When follow_redirects=False and a redirect is received,
        # the client will set `response.next_request`.
        self.next_request: Request | None = None

        self.extensions = {} if extensions is None else dict(extensions)
        self.history = [] if history is None else list(history)

        self.is_closed = False
        self.is_stream_consumed = False

        self.default_encoding = default_encoding

        if stream is None:
            headers, stream = encode_response(content, text, html, json)
            self._prepare(headers)
            self.stream = stream
            if isinstance(stream, ByteStream):
                # Load the response body, except for streaming content.
                self.read()
        else:
            # There's an important distinction between `Response(content=...)`,
            # and `Response(stream=...)`.
            #
            # Using `content=...` implies automatically populated content headers,
            # of either `Content-Length: ...` or `Transfer-Encoding: chunked`.
            #
            # Using `stream=...` will not automatically include any content headers.
            #
            # As an end-user you don't really need `stream=...`. It's only
            # useful when creating response instances having received a stream
            # from the transport API.
            self.stream = stream

        self._num_bytes_downloaded = 0

    def _prepare(self, default_headers: dict[str, str]) -> None:
        for key, value in default_headers.items():
            # Ignore Transfer-Encoding if the Content-Length has been set explicitly.
            if key.lower() == "transfer-encoding" and "content-length" in self.headers:
                continue
            self.headers.setdefault(key, value)

    @property
    def elapsed(self) -> datetime.timedelta:
        """
        Returns the time taken for the complete request/response
        cycle to complete.
        """
        if not hasattr(self, "_elapsed"):
            raise RuntimeError(
                "'.elapsed' may only be accessed after the response "
                "has been read or closed."
            )
        return self._elapsed

    @elapsed.setter
    def elapsed(self, elapsed: datetime.timedelta) -> None:
        self._elapsed = elapsed

    @property
    def request(self) -> Request:
        """
        Returns the request instance associated to the current response.
        """
        if self._request is None:
            raise RuntimeError(
                "The request instance has not been set on this response."
            )
        return self._request

    @request.setter
    def request(self, value: Request) -> None:
        self._request = value

    @property
    def http_version(self) -> str:
        try:
            http_version: bytes = self.extensions["http_version"]
        except KeyError:
            return "HTTP/1.1"
        else:
            return http_version.decode("ascii", errors="ignore")

    @property
    def reason_phrase(self) -> str:
        try:
            reason_phrase: bytes = self.extensions["reason_phrase"]
        except KeyError:
            return codes.get_reason_phrase(self.status_code)
        else:
            return reason_phrase.decode("ascii", errors="ignore")

    @property
    def url(self) -> URL:
        """
        Returns the URL for which the request was made.
        """
        return self.request.url

    @property
    def content(self) -> bytes:
        if not hasattr(self, "_content"):
            raise ResponseNotRead()
        return self._content

    @property
    def text(self) -> str:
        if not hasattr(self, "_text"):
            content = self.content
            if not content:
                self._text = ""
            else:
                decoder = TextDecoder(encoding=self.encoding or "utf-8")
                self._text = "".join([decoder.decode(self.content), decoder.flush()])
        return self._text

    @property
    def encoding(self) -> str | None:
        """
        Return an encoding to use for decoding the byte content into text.
        The priority for determining this is given by...

        * `.encoding = <>` has been set explicitly.
        * The encoding as specified by the charset parameter in the Content-Type header.
        * The encoding as determined by `default_encoding`, which may either be
          a string like "utf-8" indicating the encoding to use, or may be a callable
          which enables charset autodetection.
        """
        if not hasattr(self, "_encoding"):
            encoding = self.charset_encoding
            if encoding is None or not _is_known_encoding(encoding):
                if isinstance(self.default_encoding, str):
                    encoding = self.default_encoding
                elif hasattr(self, "_content"):
                    encoding = self.default_encoding(self._content)
            self._encoding = encoding or "utf-8"
        return self._encoding

    @encoding.setter
    def encoding(self, value: str) -> None:
        """
        Set the encoding to use for decoding the byte content into text.

        If the `text` attribute has been accessed, attempting to set the
        encoding will throw a ValueError.
        """
        if hasattr(self, "_text"):
            raise ValueError(
                "Setting encoding after `text` has been accessed is not allowed."
            )
        self._encoding = value

    @property
    def charset_encoding(self) -> str | None:
        """
        Return the encoding, as specified by the Content-Type header.
        """
        content_type = self.headers.get("Content-Type")
        if content_type is None:
            return None

        return _parse_content_type_charset(content_type)

    def _get_content_decoder(self) -> ContentDecoder:
        """
        Returns a decoder instance which can be used to decode the raw byte
        content, depending on the Content-Encoding used in the response.
        """
        if not hasattr(self, "_decoder"):
            decoders: list[ContentDecoder] = []
            values = self.headers.get_list("content-encoding", split_commas=True)
            for value in values:
                value = value.strip().lower()
                try:
                    decoder_cls = SUPPORTED_DECODERS[value]
                    decoders.append(decoder_cls())
                except KeyError:
                    continue

            if len(decoders) == 1:
                self._decoder = decoders[0]
            elif len(decoders) > 1:
                self._decoder = MultiDecoder(children=decoders)
            else:
                self._decoder = IdentityDecoder()

        return self._decoder

    @property
    def is_informational(self) -> bool:
        """
        A property which is `True` for 1xx status codes, `False` otherwise.
        """
        return codes.is_informational(self.status_code)

    @property
    def is_success(self) -> bool:
        """
        A property which is `True` for 2xx status codes, `False` otherwise.
        """
        return codes.is_success(self.status_code)

    @property
    def is_redirect(self) -> bool:
        """
        A property which is `True` for 3xx status codes, `False` otherwise.

        Note that not all responses with a 3xx status code indicate a URL redirect.

        Use `response.has_redirect_location` to determine responses with a properly
        formed URL redirection.
        """
        return codes.is_redirect(self.status_code)

    @property
    def is_client_error(self) -> bool:
        """
        A property which is `True` for 4xx status codes, `False` otherwise.
        """
        return codes.is_client_error(self.status_code)

    @property
    def is_server_error(self) -> bool:
        """
        A property which is `True` for 5xx status codes, `False` otherwise.
        """
        return codes.is_server_error(self.status_code)

    @property
    def is_error(self) -> bool:
        """
        A property which is `True` for 4xx and 5xx status codes, `False` otherwise.
        """
        return codes.is_error(self.status_code)

    @property
    def has_redirect_location(self) -> bool:
        """
        Returns True for 3xx responses with a properly formed URL redirection,
        `False` otherwise.
        """
        return (
            self.status_code
            in (
                # 301 (Cacheable redirect. Method may change to GET.)
                codes.MOVED_PERMANENTLY,
                # 302 (Uncacheable redirect. Method may change to GET.)
                codes.FOUND,
                # 303 (Client should make a GET or HEAD request.)
                codes.SEE_OTHER,
                # 307 (Equiv. 302, but retain method)
                codes.TEMPORARY_REDIRECT,
                # 308 (Equiv. 301, but retain method)
                codes.PERMANENT_REDIRECT,
            )
            and "Location" in self.headers
        )

    def raise_for_status(self) -> Response:
        """
        Raise the `HTTPStatusError` if one occurred.
        """
        request = self._request
        if request is None:
            raise RuntimeError(
                "Cannot call `raise_for_status` as the request "
                "instance has not been set on this response."
            )

        if self.is_success:
            return self

        if self.has_redirect_location:
            message = (
                "{error_type} '{0.status_code} {0.reason_phrase}' for url '{0.url}'\n"
                "Redirect location: '{0.headers[location]}'\n"
                "For more information check: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/{0.status_code}"
            )
        else:
            message = (
                "{error_type} '{0.status_code} {0.reason_phrase}' for url '{0.url}'\n"
                "For more information check: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/{0.status_code}"
            )

        status_class = self.status_code // 100
        error_types = {
            1: "Informational response",
            3: "Redirect response",
            4: "Client error",
            5: "Server error",
        }
        error_type = error_types.get(status_class, "Invalid status code")
        message = message.format(self, error_type=error_type)
        raise HTTPStatusError(message, request=request, response=self)

    def json(self, **kwargs: typing.Any) -> typing.Any:
        return jsonlib.loads(self.content, **kwargs)

    @property
    def cookies(self) -> Cookies:
        if not hasattr(self, "_cookies"):
            self._cookies = Cookies()
            self._cookies.extract_cookies(self)
        return self._cookies

    @property
    def links(self) -> dict[str | None, dict[str, str]]:
        """
        Returns the parsed header links of the response, if any
        """
        header = self.headers.get("link")
        if header is None:
            return {}

        return {
            (link.get("rel") or link.get("url")): link
            for link in _parse_header_links(header)
        }

    @property
    def num_bytes_downloaded(self) -> int:
        return self._num_bytes_downloaded

    def __repr__(self) -> str:
        return f"<Response [{self.status_code} {self.reason_phrase}]>"

    def __getstate__(self) -> dict[str, typing.Any]:
        return {
            name: value
            for name, value in self.__dict__.items()
            if name not in ["extensions", "stream", "is_closed", "_decoder"]
        }

    def __setstate__(self, state: dict[str, typing.Any]) -> None:
        for name, value in state.items():
            setattr(self, name, value)
        self.is_closed = True
        self.extensions = {}
        self.stream = UnattachedStream()

    def read(self) -> bytes:
        """
        Read and return the response content.
        """
        if not hasattr(self, "_content"):
            self._content = b"".join(self.iter_bytes())
        return self._content

    def iter_bytes(self, chunk_size: int | None = None) -> typing.Iterator[bytes]:
        """
        A byte-iterator over the decoded response content.
        This allows us to handle gzip, deflate, brotli, and zstd encoded responses.
        """
        if hasattr(self, "_content"):
            chunk_size = len(self._content) if chunk_size is None else chunk_size
            for i in range(0, len(self._content), max(chunk_size, 1)):
                yield self._content[i : i + chunk_size]
        else:
            decoder = self._get_content_decoder()
            chunker = ByteChunker(chunk_size=chunk_size)
            with request_context(request=self._request):
                for raw_bytes in self.iter_raw():
                    decoded = decoder.decode(raw_bytes)
                    for chunk in chunker.decode(decoded):
                        yield chunk
                decoded = decoder.flush()
                for chunk in chunker.decode(decoded):
                    yield chunk  # pragma: no cover
                for chunk in chunker.flush():
                    yield chunk

    def iter_text(self, chunk_size: int | None = None) -> typing.Iterator[str]:
        """
        A str-iterator over the decoded response content
        that handles both gzip, deflate, etc but also detects the content's
        string encoding.
        """
        decoder = TextDecoder(encoding=self.encoding or "utf-8")
        chunker = TextChunker(chunk_size=chunk_size)
        with request_context(request=self._request):
            for byte_content in self.iter_bytes():
                text_content = decoder.decode(byte_content)
                for chunk in chunker.decode(text_content):
                    yield chunk
            text_content = decoder.flush()
            for chunk in chunker.decode(text_content):
                yield chunk  # pragma: no cover
            for chunk in chunker.flush():
                yield chunk

    def iter_lines(self) -> typing.Iterator[str]:
        decoder = LineDecoder()
        with request_context(request=self._request):
            for text in self.iter_text():
                for line in decoder.decode(text):
                    yield line
            for line in decoder.flush():
                yield line

    def iter_raw(self, chunk_size: int | None = None) -> typing.Iterator[bytes]:
        """
        A byte-iterator over the raw response content.
        """
        if self.is_stream_consumed:
            raise StreamConsumed()
        if self.is_closed:
            raise StreamClosed()
        if not isinstance(self.stream, SyncByteStream):
            raise RuntimeError("Attempted to call a sync iterator on an async stream.")

        self.is_stream_consumed = True
        self._num_bytes_downloaded = 0
        chunker = ByteChunker(chunk_size=chunk_size)

        with request_context(request=self._request):
            for raw_stream_bytes in self.stream:
                self._num_bytes_downloaded += len(raw_stream_bytes)
                for chunk in chunker.decode(raw_stream_bytes):
                    yield chunk

        for chunk in chunker.flush():
            yield chunk

        self.close()

    def close(self) -> None:
        """
        Close the response and release the connection.
        Automatically called if the response body is read to completion.
        """
        if not isinstance(self.stream, SyncByteStream):
            raise RuntimeError("Attempted to call an sync close on an async stream.")

        if not self.is_closed:
            self.is_closed = True
            with request_context(request=self._request):
                self.stream.close()

    async def aread(self) -> bytes:
        """
        Read and return the response content.
        """
        if not hasattr(self, "_content"):
            self._content = b"".join([part async for part in self.aiter_bytes()])
        return self._content

    async def aiter_bytes(
        self, chunk_size: int | None = None
    ) -> typing.AsyncIterator[bytes]:
        """
        A byte-iterator over the decoded response content.
        This allows us to handle gzip, deflate, brotli, and zstd encoded responses.
        """
        if hasattr(self, "_content"):
            chunk_size = len(self._content) if chunk_size is None else chunk_size
            for i in range(0, len(self._content), max(chunk_size, 1)):
                yield self._content[i : i + chunk_size]
        else:
            decoder = self._get_content_decoder()
            chunker = ByteChunker(chunk_size=chunk_size)
            with request_context(request=self._request):
                async for raw_bytes in self.aiter_raw():
                    decoded = decoder.decode(raw_bytes)
                    for chunk in chunker.decode(decoded):
                        yield chunk
                decoded = decoder.flush()
                for chunk in chunker.decode(decoded):
                    yield chunk  # pragma: no cover
                for chunk in chunker.flush():
                    yield chunk

    async def aiter_text(
        self, chunk_size: int | None = None
    ) -> typing.AsyncIterator[str]:
        """
        A str-iterator over the decoded response content
        that handles both gzip, deflate, etc but also detects the content's
        string encoding.
        """
        decoder = TextDecoder(encoding=self.encoding or "utf-8")
        chunker = TextChunker(chunk_size=chunk_size)
        with request_context(request=self._request):
            async for byte_content in self.aiter_bytes():
                text_content = decoder.decode(byte_content)
                for chunk in chunker.decode(text_content):
                    yield chunk
            text_content = decoder.flush()
            for chunk in chunker.decode(text_content):
                yield chunk  # pragma: no cover
            for chunk in chunker.flush():
                yield chunk

    async def aiter_lines(self) -> typing.AsyncIterator[str]:
        decoder = LineDecoder()
        with request_context(request=self._request):
            async for text in self.aiter_text():
                for line in decoder.decode(text):
                    yield line
            for line in decoder.flush():
                yield line

    async def aiter_raw(
        self, chunk_size: int | None = None
    ) -> typing.AsyncIterator[bytes]:
        """
        A byte-iterator over the raw response content.
        """
        if self.is_stream_consumed:
            raise StreamConsumed()
        if self.is_closed:
            raise StreamClosed()
        if not isinstance(self.stream, AsyncByteStream):
            raise RuntimeError("Attempted to call an async iterator on an sync stream.")

        self.is_stream_consumed = True
        self._num_bytes_downloaded = 0
        chunker = ByteChunker(chunk_size=chunk_size)

        with request_context(request=self._request):
            async for raw_stream_bytes in self.stream:
                self._num_bytes_downloaded += len(raw_stream_bytes)
                for chunk in chunker.decode(raw_stream_bytes):
                    yield chunk

        for chunk in chunker.flush():
            yield chunk

        await self.aclose()

    async def aclose(self) -> None:
        """
        Close the response and release the connection.
        Automatically called if the response body is read to completion.
        """
        if not isinstance(self.stream, AsyncByteStream):
            raise RuntimeError("Attempted to call an async close on an sync stream.")

        if not self.is_closed:
            self.is_closed = True
            with request_context(request=self._request):
                await self.stream.aclose()


class Cookies(typing.MutableMapping[str, str]):
    """
    HTTP Cookies, as a mutable mapping.
    """

    def __init__(
        self,
        cookies: CookieTypes | None = None,
        *,
        same_site_policy: SameSitePolicy | str = SameSitePolicy.RFC6265,
        ) -> None:
        self.same_site_policy = SameSitePolicy(same_site_policy)
        if cookies is None or isinstance(cookies, dict):
            self.jar = self._new_jar()
            if isinstance(cookies, dict):
                for key, value in cookies.items():
                    self.set(key, value)
        elif isinstance(cookies, list):
            self.jar = self._new_jar()
            for key, value in cookies:
                self.set(key, value)
        elif isinstance(cookies, Cookies):
            if same_site_policy is SameSitePolicy.RFC6265:
                self.same_site_policy = cookies.same_site_policy
            else:
                self.same_site_policy = SameSitePolicy(same_site_policy)
            self.jar = self._new_jar()
            for cookie in cookies._snapshot():
                self.jar.set_cookie(self._copy_cookie(cookie))
        else:
            if same_site_policy is SameSitePolicy.RFC6265:
                self.jar = cookies
            else:
                self.jar = self._new_jar()
                with typing.cast(typing.Any, cookies)._cookies_lock:
                    for cookie in list(cookies):
                        self.jar.set_cookie(self._copy_cookie(cookie))

    def __copy__(self) -> Cookies:
        return Cookies(self, same_site_policy=self.same_site_policy)

    def __deepcopy__(self, memo: dict[int, typing.Any]) -> Cookies:
        return self.__copy__()

    def _new_jar(self) -> CookieJar:
        if self.same_site_policy is SameSitePolicy.RFC6265:
            return CookieJar()
        return CookieJar(_CookiePolicy(self.same_site_policy))

    def copy(self) -> Cookies:
        return self.__copy__()

    @staticmethod
    def _copy_cookie(cookie: Cookie) -> Cookie:
        return Cookie(
            version=cookie.version,
            name=cookie.name,
            value=cookie.value,
            port=cookie.port,
            port_specified=cookie.port_specified,
            domain=cookie.domain,
            domain_specified=cookie.domain_specified,
            domain_initial_dot=cookie.domain_initial_dot,
            path=cookie.path,
            path_specified=cookie.path_specified,
            secure=cookie.secure,
            expires=cookie.expires,
            discard=cookie.discard,
            comment=cookie.comment,
            comment_url=cookie.comment_url,
            rest=dict(typing.cast(dict[str, typing.Any], cookie.__dict__["_rest"])),
            rfc2109=cookie.rfc2109,
        )

    def _snapshot(self) -> list[Cookie]:
        with typing.cast(typing.Any, self.jar)._cookies_lock:
            return list(self.jar)

    def extract_cookies(self, response: Response) -> None:
        """
        Loads any cookies based on the response `Set-Cookie` headers.
        """
        urllib_response = self._CookieCompatResponse(response)
        urllib_request = self._CookieCompatRequest(response.request)

        self.jar.extract_cookies(urllib_response, urllib_request)  # type: ignore

    def set_cookie_header(self, request: Request) -> None:
        """
        Sets an appropriate 'Cookie:' HTTP header on the `Request`.
        """
        if self.same_site_policy is SameSitePolicy.RFC6265:
            if "Cookie" in request.headers:
                return
            self._set_filtered_cookie_header(request, same_site=False)
            return

        self._set_filtered_cookie_header(request, same_site=True)

    def _set_filtered_cookie_header(self, request: Request, same_site: bool) -> None:
        manual_cookies = (
            self._cookies_from_header(request) if same_site else []
        )
        request.headers.pop("Cookie", None)
        initiator = request.extensions.get("samesite_initiator") if same_site else None
        cookies = [
            cookie
            for cookie in self._snapshot()
            if self._cookie_return_ok(cookie, request, initiator, same_site)
        ]
        cookies.extend(
            cookie
            for cookie in manual_cookies
            if self._cookie_return_ok(cookie, request, initiator, same_site)
        )

        selected: dict[str, Cookie] = {}
        for cookie in sorted(cookies, key=lambda item: len(item.path), reverse=True):
            selected.setdefault(cookie.name, cookie)

        if selected:
            request.headers["Cookie"] = "; ".join(
                f"{cookie.name}={cookie.value}" for cookie in selected.values()
            )

        self._clear_expired_cookies()

    def _clear_expired_cookies(self) -> None:
        now = int(time.time())
        with typing.cast(typing.Any, self.jar)._cookies_lock:
            for cookie in list(self.jar):
                if cookie.is_expired(now):
                    self.jar.clear(cookie.domain, cookie.path, cookie.name)

    def _cookies_from_header(self, request: Request) -> list[Cookie]:
        request_path = request.url.path or "/"
        if not request_path.startswith("/"):
            request_path = "/"
        path_index = request_path.rfind("/")
        default_path = request_path[: path_index + 1] or "/"
        host = request.url.host
        cookies = []

        for header in request.headers.get_list("Cookie"):
            for item in header.split(";"):
                name, separator, value = item.strip().partition("=")
                if not separator or not name:
                    continue
                cookies.append(
                    Cookie(
                        version=0,
                        name=name,
                        value=value,
                        port=None,
                        port_specified=False,
                        domain=host,
                        domain_specified=False,
                        domain_initial_dot=False,
                        path=default_path,
                        path_specified=True,
                        secure=request.url.scheme in ("https", "wss"),
                        expires=None,
                        discard=True,
                        comment=None,
                        comment_url=None,
                        rest={},
                        rfc2109=False,
                    )
                )
        return cookies

    def _cookie_return_ok(
        self,
        cookie: Cookie,
        request: Request,
        initiator: tuple[str, str] | None,
        same_site: bool,
    ) -> bool:
        if cookie.is_expired(int(time.time())):
            return False
        if cookie.secure and request.url.scheme not in ("https", "wss"):
            return False
        if (
            same_site
            and self._same_site_attribute(cookie) == "none"
            and not cookie.secure
        ):
            return False
        if cookie.port and str(self._request_port(request.url)) not in (
            cookie.port.split(",")
        ):
            return False
        if not self._path_return_ok(cookie.path, request.url.path):
            return False
        if not self._domain_return_ok(cookie, request.url.host):
            return False
        return not same_site or self._same_site_return_ok(cookie, request, initiator)

    @staticmethod
    def _request_port(url: URL) -> int:
        if url.port is not None:
            return url.port
        return {"http": 80, "ws": 80, "https": 443, "wss": 443}.get(
            url.scheme, 0
        )

    @staticmethod
    def _path_return_ok(cookie_path: str | None, request_path: str) -> bool:
        cookie_path = cookie_path or "/"
        if not request_path.startswith("/"):
            request_path = "/"
        return (
            request_path == cookie_path
            or request_path.startswith(cookie_path)
            and (
                cookie_path.endswith("/")
                or request_path[len(cookie_path) : len(cookie_path) + 1] == "/"
            )
        )

    @staticmethod
    def _domain_return_ok(cookie: Cookie, host: str) -> bool:
        host = host.lower().rstrip(".")
        domain = cookie.domain.lower().rstrip(".")
        if domain.endswith(".local"):
            domain = domain[: -len(".local")]
        if len(domain) >= 2 and domain.startswith("[") and domain.endswith("]"):
            domain = domain[1:-1]
        if Cookies._is_ip_address(host) or Cookies._is_ip_address(domain):
            return Cookies._ip_address(host) == Cookies._ip_address(domain)

        if cookie.domain_specified:
            if domain.startswith("."):
                domain = domain[1:]
            if not domain:
                return False
            if ("." in domain or domain.endswith(".local")) and public_suffix(
                domain
            ) == domain:
                return False
            return host == domain or host.endswith(f".{domain}")

        return not domain or host == domain

    def _same_site_return_ok(
        self,
        cookie: Cookie,
        request: Request,
        initiator: tuple[str, str] | None,
    ) -> bool:
        if initiator is None:
            return True

        target = self._site_key(request.url)
        same_site = target == initiator
        if same_site:
            return True

        attribute = self._same_site_attribute(cookie)
        if attribute == "strict":
            return False
        if attribute == "none":
            return cookie.secure
        return request.method in ("GET", "HEAD")

    def _same_site_attribute(self, cookie: Cookie) -> str:
        return self._same_site_attribute_value(cookie, self.same_site_policy.value)

    @staticmethod
    def _same_site_attribute_value(cookie: Cookie, default: str) -> str:
        rest = typing.cast(dict[str, typing.Any], cookie.__dict__["_rest"])
        value = rest.get("SameSite") or rest.get("samesite")
        if value is None:
            return default
        normalized = str(value).lower()
        if normalized in ("strict", "lax", "none"):
            return normalized
        return "strict"

    @staticmethod
    def _site_key(url: URL) -> tuple[str, str]:
        host = url.raw_host.decode("ascii")
        address = Cookies._ip_address(host)
        if address is not None:
            return url.scheme, str(address)
        return url.scheme, registrable_domain(host)

    @staticmethod
    def _is_ip_address(host: str) -> bool:
        return Cookies._ip_address(host) is not None

    @staticmethod
    def _ip_address(host: str) -> str | None:
        try:
            return str(ip_address(host))
        except ValueError:
            return None

    def set(
        self,
        name: str,
        value: str,
        domain: str = "",
        path: str = "/",
        secure: bool = False,
        same_site: str | None = None,
    ) -> None:
        """
        Set a cookie value by name. May optionally include domain and path.
        """
        rest: dict[str, typing.Any] = {"HttpOnly": None}
        if same_site is not None:
            rest["SameSite"] = same_site
        kwargs = {
            "version": 0,
            "name": name,
            "value": value,
            "port": None,
            "port_specified": False,
            "domain": domain,
            "domain_specified": bool(domain),
            "domain_initial_dot": domain.startswith("."),
            "path": path,
            "path_specified": bool(path),
            "secure": secure,
            "expires": None,
            "discard": True,
            "comment": None,
            "comment_url": None,
            "rest": rest,
            "rfc2109": False,
        }
        cookie = Cookie(**kwargs)  # type: ignore
        self.jar.set_cookie(cookie)

    def get(  # type: ignore
        self,
        name: str,
        default: str | None = None,
        domain: str | None = None,
        path: str | None = None,
    ) -> str | None:
        """
        Get a cookie by name. May optionally include domain and path
        in order to specify exactly which cookie to retrieve.
        """
        value = None
        for cookie in self._snapshot():
            if cookie.name == name:
                if domain is None or cookie.domain == domain:
                    if path is None or cookie.path == path:
                        if value is not None:
                            message = f"Multiple cookies exist with name={name}"
                            raise CookieConflict(message)
                        value = cookie.value

        if value is None:
            return default
        return value

    def delete(
        self,
        name: str,
        domain: str | None = None,
        path: str | None = None,
    ) -> None:
        """
        Delete a cookie by name. May optionally include domain and path
        in order to specify exactly which cookie to delete.
        """
        if domain is not None and path is not None:
            return self.jar.clear(domain, path, name)

        remove = [
            cookie
            for cookie in self._snapshot()
            if cookie.name == name
            and (domain is None or cookie.domain == domain)
            and (path is None or cookie.path == path)
        ]

        for cookie in remove:
            self.jar.clear(cookie.domain, cookie.path, cookie.name)

    def clear(self, domain: str | None = None, path: str | None = None) -> None:
        """
        Delete all cookies. Optionally include a domain and path in
        order to only delete a subset of all the cookies.
        """
        args = []
        if domain is not None:
            args.append(domain)
        if path is not None:
            assert domain is not None
            args.append(path)
        self.jar.clear(*args)

    def update(self, cookies: CookieTypes | None = None) -> None:  # type: ignore
        cookies = Cookies(cookies)
        for cookie in cookies._snapshot():
            self.jar.set_cookie(self._copy_cookie(cookie))

    def __setitem__(self, name: str, value: str) -> None:
        return self.set(name, value)

    def __getitem__(self, name: str) -> str:
        value = self.get(name)
        if value is None:
            raise KeyError(name)
        return value

    def __delitem__(self, name: str) -> None:
        return self.delete(name)

    def __len__(self) -> int:
        return len(self._snapshot())

    def __iter__(self) -> typing.Iterator[str]:
        return iter([cookie.name for cookie in self._snapshot()])

    def __bool__(self) -> bool:
        for _ in self._snapshot():
            return True
        return False

    def __repr__(self) -> str:
        cookies_repr = ", ".join(
            [
                f"<Cookie {cookie.name}={cookie.value} for {cookie.domain} />"
                for cookie in self._snapshot()
            ]
        )

        return f"<Cookies[{cookies_repr}]>"

    class _CookieCompatRequest(urllib.request.Request):
        """
        Wraps a `Request` instance up in a compatibility interface suitable
        for use with `CookieJar` operations.
        """

        def __init__(self, request: Request) -> None:
            super().__init__(
                url=str(request.url),
                headers=dict(request.headers),
                method=request.method,
            )
            self.request = request

        def add_unredirected_header(self, key: str, value: str) -> None:
            super().add_unredirected_header(key, value)
            self.request.headers[key] = value

    class _CookieCompatResponse:
        """
        Wraps a `Request` instance up in a compatibility interface suitable
        for use with `CookieJar` operations.
        """

        def __init__(self, response: Response) -> None:
            self.response = response

        def info(self) -> email.message.Message:
            info = email.message.Message()
            for key, value in self.response.headers.multi_items():
                # Note that setting `info[key]` here is an "append" operation,
                # not a "replace" operation.
                # https://docs.python.org/3/library/email.compat32-message.html#email.message.Message.__setitem__
                info[key] = value
            return info


class _CookiePolicy(DefaultCookiePolicy):
    def __init__(self, same_site_policy: SameSitePolicy) -> None:
        super().__init__()
        self.same_site_policy = same_site_policy

    def set_ok(self, cookie: Cookie, request: typing.Any) -> bool:
        if self.same_site_policy is not SameSitePolicy.RFC6265:
            samesite = Cookies._same_site_attribute_value(
                cookie, self.same_site_policy.value
            )
            if samesite == "none" and not cookie.secure:
                return False
        return super().set_ok(cookie, request)

    def set_ok_domain(self, cookie: Cookie, request: typing.Any) -> bool:
        if not super().set_ok_domain(cookie, request):
            return False
        if not cookie.domain_specified:
            return True

        _, request_host = _eff_request_host(request)
        host = request_host.rstrip(".")
        domain = cookie.domain.lstrip(".").rstrip(".")
        if Cookies._is_ip_address(host) or Cookies._is_ip_address(domain):
            return bool(host == domain)
        if public_suffix(domain) == domain:
            return False
        return bool(host == domain or host.endswith(f".{domain}"))
