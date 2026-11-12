"""
Diagnostic formatting helpers.

Centralizes the *safe*, human-facing rendering of URLs for logs and exception
messages. The values produced here are display-only: the `Request` instance,
`Response.request`, and the URL actually handed to the transport are never
rewritten.

Two kinds of secrets are handled:

* URL `userinfo` (the `username:password@` component) is always masked,
  including the username, since a username embedded in a URL is itself a
  credential.
* Query parameters whose names match a configurable sensitive set have their
  values masked. Matching is case-insensitive and ignores percent-encoding, so
  repeated keys, encoded keys, and empty values are all covered by the same
  policy.

The underlying transport libraries (such as `httpcore`) emit their own logs and
are outside of this module's scope; those loggers need to be configured
independently.
"""

from __future__ import annotations

import typing
from urllib.parse import unquote

from ._urls import URL

__all__ = ["DEFAULT_SENSITIVE_QUERY_PARAMS", "redact_url"]


# Query parameter names that carry one-time credentials or other secrets by
# convention. Callers can extend or replace this set per client.
DEFAULT_SENSITIVE_QUERY_PARAMS: frozenset[str] = frozenset(
    [
        "access_token",
        "api_key",
        "apikey",
        "auth",
        "code",
        "key",
        "password",
        "secret",
        "session",
        "sessionid",
        "sig",
        "signature",
        "token",
        "username",
    ]
)

# The replacement shown in place of any masked value. Kept consistent with the
# header and URL userinfo masking used elsewhere in the package.
REDACTED = "[secure]"


def _redact_query(
    query: str | None, sensitive_params: typing.Container[str]
) -> str | None:
    """
    Mask the values of sensitive parameters within a raw query string.

    The raw bytes of the string (including percent-encoding and parameter
    ordering) are preserved; only the values of matching parameters change.
    Every occurrence of a repeated key is masked, and parameters with empty or
    missing values are masked just like any other match.
    """
    if query is None:
        return None

    parts: list[str] = []
    for part in query.split("&"):
        key, separator, _value = part.partition("=")
        if unquote(key).lower() in sensitive_params:
            part = key + separator + REDACTED if separator else key + "=" + REDACTED
        parts.append(part)
    return "&".join(parts)


def redact_url(
    url: URL | str,
    *,
    sensitive_params: typing.Container[str] = DEFAULT_SENSITIVE_QUERY_PARAMS,
) -> str:
    """
    Return a safe string representation of a URL for diagnostic output.

    * Any `userinfo` component is replaced entirely by `[secure]`.
    * Values of the configured sensitive query parameters are replaced by
      `[secure]`.
    * The scheme, host, port, path, fragment, and non-sensitive parameters are
      rendered unchanged.

    The input `URL` object is not modified; callers continue to send the
    original URL to the transport.
    """
    url = URL(url)
    scheme, userinfo, host, port, path, query, fragment = url._uri_reference

    if userinfo:
        userinfo = REDACTED

    authority = "".join(
        [
            f"{userinfo}@" if userinfo else "",
            f"[{host}]" if ":" in host else host,
            f":{port}" if port is not None else "",
        ]
    )
    return "".join(
        [
            f"{scheme}:" if scheme else "",
            f"//{authority}" if authority else "",
            path,
            f"?{_redact_query(query, sensitive_params)}" if query is not None else "",
            f"#{fragment}" if fragment is not None else "",
        ]
    )
