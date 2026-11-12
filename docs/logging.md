# Logging

If you need to inspect the internal behaviour of `httpx`, you can use Python's standard logging to output information about the underlying network behaviour.

For example, the following configuration...

```python
import logging
import httpx

logging.basicConfig(
    format="%(levelname)s [%(asctime)s] %(name)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.DEBUG
)

httpx.get("https://www.example.com")
```

Will send debug level output to the console, or wherever `stdout` is directed too...

```
DEBUG [2024-09-28 17:27:40] httpcore.connection - connect_tcp.started host='www.example.com' port=443 local_address=None timeout=5.0 socket_options=None
DEBUG [2024-09-28 17:27:41] httpcore.connection - connect_tcp.complete return_value=<httpcore._backends.sync.SyncStream object at 0x101f1e8e0>
DEBUG [2024-09-28 17:27:41] httpcore.connection - start_tls.started ssl_context=SSLContext(verify=True) server_hostname='www.example.com' timeout=5.0
DEBUG [2024-09-28 17:27:41] httpcore.connection - start_tls.complete return_value=<httpcore._backends.sync.SyncStream object at 0x1020f49a0>
DEBUG [2024-09-28 17:27:41] httpcore.http11 - send_request_headers.started request=<Request [b'GET']>
DEBUG [2024-09-28 17:27:41] httpcore.http11 - send_request_headers.complete
DEBUG [2024-09-28 17:27:41] httpcore.http11 - send_request_body.started request=<Request [b'GET']>
DEBUG [2024-09-28 17:27:41] httpcore.http11 - send_request_body.complete
DEBUG [2024-09-28 17:27:41] httpcore.http11 - receive_response_headers.started request=<Request [b'GET']>
DEBUG [2024-09-28 17:27:41] httpcore.http11 - receive_response_headers.complete return_value=(b'HTTP/1.1', 200, b'OK', [(b'Content-Encoding', b'gzip'), (b'Accept-Ranges', b'bytes'), (b'Age', b'407727'), (b'Cache-Control', b'max-age=604800'), (b'Content-Type', b'text/html; charset=UTF-8'), (b'Date', b'Sat, 28 Sep 2024 13:27:42 GMT'), (b'Etag', b'"3147526947+gzip"'), (b'Expires', b'Sat, 05 Oct 2024 13:27:42 GMT'), (b'Last-Modified', b'Thu, 17 Oct 2019 07:18:26 GMT'), (b'Server', b'ECAcc (dcd/7D43)'), (b'Vary', b'Accept-Encoding'), (b'X-Cache', b'HIT'), (b'Content-Length', b'648')])
INFO [2024-09-28 17:27:41] httpx - HTTP Request: GET https://www.example.com "HTTP/1.1 200 OK"
DEBUG [2024-09-28 17:27:41] httpcore.http11 - receive_response_body.started request=<Request [b'GET']>
DEBUG [2024-09-28 17:27:41] httpcore.http11 - receive_response_body.complete
DEBUG [2024-09-28 17:27:41] httpcore.http11 - response_closed.started
DEBUG [2024-09-28 17:27:41] httpcore.http11 - response_closed.complete
DEBUG [2024-09-28 17:27:41] httpcore.connection - close.started
DEBUG [2024-09-28 17:27:41] httpcore.connection - close.complete
```

Logging output includes information from both the high-level `httpx` logger, and the network-level `httpcore` logger, which can be configured separately.

For handling more complex logging configurations you might want to use the dictionary configuration style...

```python
import logging.config
import httpx

LOGGING_CONFIG = {
    "version": 1,
    "handlers": {
        "default": {
            "class": "logging.StreamHandler",
            "formatter": "http",
            "stream": "ext://sys.stderr"
        }
    },
    "formatters": {
        "http": {
            "format": "%(levelname)s [%(asctime)s] %(name)s - %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        }
    },
    'loggers': {
        'httpx': {
            'handlers': ['default'],
            'level': 'DEBUG',
        },
        'httpcore': {
            'handlers': ['default'],
            'level': 'DEBUG',
        },
    }
}

logging.config.dictConfig(LOGGING_CONFIG)
httpx.get('https://www.example.com')
```

The exact formatting of the debug logging may be subject to change across different versions of `httpx` and `httpcore`. If you need to rely on a particular format it is recommended that you pin installation of these packages to fixed versions.

## Redacting sensitive URL data

Request URLs sometimes carry credentials, such as a one-time token in the query string (`https://example.com/callback?token=...`) or a username and password in the userinfo (`https://user:password@example.com`). Because the `httpx` request log is typically forwarded into long-term log storage, `httpx` only ever writes a *safe view* of a URL to its own logs and to human-facing exception text:

* Any userinfo component is masked in full, including the username, as `[secure]`.
* The values of sensitive query parameters are masked as `[secure]`. By default the set includes common credential-bearing names such as `token`, `code`, `password`, `secret`, `api_key`, and `signature`. Matching is case-insensitive, ignores percent-encoding, and applies to every occurrence of a repeated key as well as empty values. Redirected URLs follow the same policy.

Which parameter names are treated as sensitive is configurable per client:

```python
httpx.Client(sensitive_query_params={"token", "widget"})
```

Pass an empty collection (`frozenset()`) to disable query-parameter masking. The setting only affects diagnostic output. The actual `Request`, `Response.request`, and the URL handed to the transport are never rewritten, so request hooks and the network layer continue to receive the original values.

The same safe view is used by `repr(request)`, `repr(url)`, `Proxy.__repr__`, and the messages of `HTTPStatusError` and other request exceptions. Use `str(url)` when you need the unmasked URL.

Note that `httpx` only controls its own output. The network-level `httpcore` logger (and any other underlying transport library) emits its own records and is configured separately; adjust those loggers independently if they can contain sensitive data.

