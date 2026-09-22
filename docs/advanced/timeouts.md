HTTPX is careful to enforce timeouts everywhere by default.

The default behavior is to raise a `TimeoutException` after 5 seconds of
network inactivity.

## Setting and disabling timeouts

You can set timeouts for an individual request:

```python
# Using the top-level API:
httpx.get('http://example.com/api/v1/example', timeout=10.0)

# Using a client instance:
with httpx.Client() as client:
    client.get("http://example.com/api/v1/example", timeout=10.0)
```

Or disable timeouts for an individual request:

```python
# Using the top-level API:
httpx.get('http://example.com/api/v1/example', timeout=None)

# Using a client instance:
with httpx.Client() as client:
    client.get("http://example.com/api/v1/example", timeout=None)
```

## Setting a default timeout on a client

You can set a timeout on a client instance, which results in the given
`timeout` being used as the default for requests made with this client:

```python
client = httpx.Client()              # Use a default 5s timeout everywhere.
client = httpx.Client(timeout=10.0)  # Use a default 10s timeout everywhere.
client = httpx.Client(timeout=None)  # Disable all timeouts by default.
```

## Fine tuning the configuration

HTTPX also allows you to specify the timeout behavior in more fine grained detail.

There are four different types of timeouts that may occur. These are **connect**,
**read**, **write**, and **pool** timeouts.

* The **connect** timeout specifies the maximum amount of time to wait until
a socket connection to the requested host is established. If HTTPX is unable to connect
within this time frame, a `ConnectTimeout` exception is raised.
* The **read** timeout specifies the maximum duration to wait for a chunk of
data to be received (for example, a chunk of the response body). If HTTPX is
unable to receive data within this time frame, a `ReadTimeout` exception is raised.
* The **write** timeout specifies the maximum duration to wait for a chunk of
data to be sent (for example, a chunk of the request body). If HTTPX is unable
to send data within this time frame, a `WriteTimeout` exception is raised.
* The **pool** timeout specifies the maximum duration to wait for acquiring
a connection from the connection pool. If HTTPX is unable to acquire a connection
within this time frame, a `PoolTimeout` exception is raised. A related
configuration here is the maximum number of allowable connections in the
connection pool, which is configured by the `limits` argument.

You can configure the timeout behavior for any of these values...

```python
# A client with a 60s timeout for connecting, and a 10s timeout elsewhere.
timeout = httpx.Timeout(10.0, connect=60.0)
client = httpx.Client(timeout=timeout)

response = client.get('http://example.com/')
```

## Total timeout budgets

In addition to the four per-operation timeouts, a `total` budget may be
set, bounding the entire request. The total budget is tracked using a
monotonic clock, and is shared across any redirects that are followed,
rather than being reset by each redirect.

```python
# A 30s total budget, with a 5s connect timeout, a 10s read timeout,
# and the write timeout explicitly disabled.
timeout = httpx.Timeout(None, connect=5.0, read=10.0, write=None, total=30.0)
client = httpx.Client(timeout=timeout)
```

Each phase of a request may only consume its own remaining allowance,
given by `min(phase, total - elapsed)`. Phases configured as `None` have
no limit of their own, but are still bounded by the remaining budget...

```
|<------------------------- total budget ------------------------->|

  DNS    pool    TCP/TLS    write     read      redirect    read
 |2s|   |wait|  |connect|  |send|   |chunks|  |follow...|  |remaining|

 ^^^^^ each phase consumes min(phase timeout, remaining budget)
```

DNS resolution and the TLS handshake are part of the **connect** phase,
and consume its allowance. Pool waits that exceed the remaining budget
raise `PoolTimeout`, and reads of a streaming response body that exceed
the remaining budget raise `ReadTimeout`, identically for sync and async
clients.

The values `None`, "unset", and `0` are distinct...

* `None` means "no limit" for that phase.
* An unset phase inherits the default, if one was given.
* `0` means the phase must complete immediately.

Contradictory configurations are rejected at construction time. For
example a per-operation timeout that exceeds the `total` budget can
never be used, and raises a `ValueError`...

```python
httpx.Timeout(None, connect=60.0, total=30.0)  # Raises ValueError.
```
