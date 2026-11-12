from __future__ import annotations

import logging

import pytest

import httpx
from httpx._diagnostics import (
    DEFAULT_SENSITIVE_QUERY_PARAMS,
    redact_url,
)

# Searchable, obviously fake secrets. If any of these show up in diagnostic
# output, a test failure names the exact value that leaked.
FAKE_QUERY_SECRET = "FAKE-QUERY-SECRET-AAA111"
FAKE_CODE_SECRET = "FAKE-CODE-SECRET-BBB222"
FAKE_USERINFO_SECRET = "FAKE-USERINFO-SECRET-CCC333"
FAKE_REDIRECT_SECRET = "FAKE-REDIRECT-SECRET-DDD444"

ALL_FAKE_SECRETS = (
    FAKE_QUERY_SECRET,
    FAKE_CODE_SECRET,
    FAKE_USERINFO_SECRET,
    FAKE_REDIRECT_SECRET,
)

SENSITIVE_URL = (
    "https://tester:"
    + FAKE_USERINFO_SECRET
    + "@example.test/callback"
    "?token="
    + FAKE_QUERY_SECRET
    + "&code="
    + FAKE_CODE_SECRET
    + "&token=duplicate-value"
    "&to%6ben=encoded-key-value"
    "&empty="
    "&valueless"
    "&safe=visible"
)


def assert_clean(text: str) -> None:
    for secret in ALL_FAKE_SECRETS:
        assert secret not in text
    assert "duplicate-value" not in text
    assert "encoded-key-value" not in text


def test_redact_url_masks_userinfo_and_sensitive_params() -> None:
    safe = redact_url(httpx.URL(SENSITIVE_URL))
    assert_clean(safe)
    # Userinfo is fully masked, including the username.
    assert "tester" not in safe
    assert "https://[secure]@example.test/" in safe
    # Every occurrence of a repeated key is masked.
    assert safe.count("token=[secure]") == 2
    # Percent-encoded keys are matched after decoding (`to%6ben` == `token`).
    assert "to%6ben=[secure]" in safe
    # Non-sensitive parameters and structural characters survive untouched.
    assert "safe=visible" in safe
    assert "empty=" in safe
    assert "valueless" in safe


def test_redact_url_handles_empty_and_missing_values() -> None:
    assert redact_url(httpx.URL("https://example.test/?token=")) == (
        "https://example.test/?token=[secure]"
    )
    assert redact_url(httpx.URL("https://example.test/?token")) == (
        "https://example.test/?token=[secure]"
    )


def test_redact_url_without_query_or_userinfo() -> None:
    assert redact_url(httpx.URL("https://example.test/path")) == (
        "https://example.test/path"
    )
    # A trailing '?' denotes a present-but-empty query string and is kept.
    assert redact_url(httpx.URL("https://example.test/path?")) == (
        "https://example.test/path?"
    )
    # Relative URLs go through the same path.
    assert redact_url(httpx.URL("/path?token=" + FAKE_QUERY_SECRET)) == (
        "/path?token=[secure]"
    )


def test_redact_url_accepts_custom_sensitive_set() -> None:
    url = httpx.URL(
        "https://example.test/?custom=" + FAKE_QUERY_SECRET + "&token=kept"
    )
    safe = redact_url(url, sensitive_params=frozenset(["custom"]))
    assert FAKE_QUERY_SECRET not in safe
    assert "custom=[secure]" in safe
    assert "token=kept" in safe

    # An empty set disables query masking; userinfo masking stays on.
    no_masking = redact_url(url, sensitive_params=frozenset())
    assert FAKE_QUERY_SECRET in no_masking


def test_redact_url_does_not_mutate_input() -> None:
    url = httpx.URL(SENSITIVE_URL)
    redact_url(url)
    assert str(url) == SENSITIVE_URL
    assert url.password == FAKE_USERINFO_SECRET
    assert url.params["token"] == FAKE_QUERY_SECRET


def test_url_repr_is_safe_but_str_is_not() -> None:
    url = httpx.URL(SENSITIVE_URL)
    assert_clean(repr(url))
    # `str()` remains the unmasked form used for the actual request.
    assert str(url) == SENSITIVE_URL
    assert FAKE_QUERY_SECRET in str(url)


def test_request_repr_is_safe_with_default_set() -> None:
    request = httpx.Request("GET", SENSITIVE_URL)
    assert_clean(repr(request))
    # The request itself still holds the original URL.
    assert str(request.url) == SENSITIVE_URL


def test_client_logs_redacted_url(caplog: pytest.LogCaptureFixture) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, request=request)

    caplog.set_level(logging.INFO, logger="httpx")
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        response = client.get(SENSITIVE_URL)

    assert len(caplog.records) == 1
    message = caplog.records[0].getMessage()
    assert_clean(message)
    assert "HTTP Request: GET" in message
    assert "200" in message
    # The response/request objects retain the raw URL.
    assert str(response.request.url) == SENSITIVE_URL


def test_client_custom_sensitive_params_apply_to_log_and_repr() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, request=request)

    url = "https://example.test/?widget=" + FAKE_QUERY_SECRET + "&token=kept"
    with httpx.Client(
        transport=httpx.MockTransport(handler),
        sensitive_query_params=frozenset(["widget"]),
    ) as client:
        response = client.get(url)

    assert FAKE_QUERY_SECRET not in repr(response.request)
    assert "widget=[secure]" in repr(response.request)
    assert "token=kept" in repr(response.request)
    # Customization never rewrites the URL held on the request.
    assert str(response.request.url) == url
    assert response.request._sensitive_query_params == frozenset(["widget"])


def test_transport_receives_unredacted_url() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, request=request)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        client.get(SENSITIVE_URL)

    assert seen == [SENSITIVE_URL]
    assert FAKE_USERINFO_SECRET in seen[0]
    assert FAKE_QUERY_SECRET in seen[0]


def test_connect_error_text_is_safe() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("simulated failure", request=request)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(httpx.ConnectError) as exc_info:
            client.get(SENSITIVE_URL)

    assert_clean(str(exc_info.value))
    assert_clean(repr(exc_info.value.request))
    # The request attached to the exception is still the original.
    assert str(exc_info.value.request.url) == SENSITIVE_URL


def test_status_error_text_is_safe() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            headers={"location": "https://other.test/?code=" + FAKE_REDIRECT_SECRET},
            request=request,
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        response = client.get(SENSITIVE_URL)
        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            response.raise_for_status()

    text = str(exc_info.value)
    assert_clean(text)
    assert FAKE_REDIRECT_SECRET not in text
    assert "code=[secure]" in text
    assert "safe=visible" in text
    assert str(exc_info.value.request.url) == SENSITIVE_URL


def test_redirect_chain_logs_and_exhaustion_are_safe(
    caplog: pytest.LogCaptureFixture,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        # Loop straight back at the secret-bearing URL.
        return httpx.Response(
            302, headers={"location": str(request.url)}, request=request
        )

    caplog.set_level(logging.INFO, logger="httpx")
    with httpx.Client(
        transport=httpx.MockTransport(handler),
        max_redirects=2,
    ) as client:
        with pytest.raises(httpx.TooManyRedirects) as exc_info:
            client.get(SENSITIVE_URL, follow_redirects=True)

    assert_clean(str(exc_info.value))
    assert_clean(repr(exc_info.value.request))
    for record in caplog.records:
        assert_clean(record.getMessage())
    # Each hop, including the redirected addresses, was logged masked.
    assert caplog.records, "expected per-hop request logs"
    assert all("token=[secure]" in record.getMessage() for record in caplog.records)
    # The final request still points at the raw redirect target.
    assert str(exc_info.value.request.url) == SENSITIVE_URL


def test_default_sensitive_set_covers_common_credential_names() -> None:
    for name in ("token", "code", "password", "secret", "api_key", "signature"):
        assert name in DEFAULT_SENSITIVE_QUERY_PARAMS


def test_sensitive_params_matching_is_case_insensitive() -> None:
    url = httpx.URL(
        "https://example.test/?TOKEN="
        + FAKE_QUERY_SECRET
        + "&Api_Key="
        + FAKE_CODE_SECRET
    )
    safe = redact_url(url)
    assert FAKE_QUERY_SECRET not in safe
    assert FAKE_CODE_SECRET not in safe
    assert "TOKEN=[secure]" in safe
    assert "Api_Key=[secure]" in safe


def test_proxy_repr_is_safe() -> None:
    proxy = httpx.Proxy(
        "http://proxy.test/?token=" + FAKE_QUERY_SECRET,
    )
    assert FAKE_QUERY_SECRET not in repr(proxy)
    assert "token=[secure]" in repr(proxy)
    assert FAKE_QUERY_SECRET in str(proxy.url)
