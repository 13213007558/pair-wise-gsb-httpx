HTTPX is careful to enforce timeouts everywhere by default.

The default behavior is to raise a `TimeoutException` after 5 seconds of
network inactivity. Simple numeric timeouts apply independently to each
network operation. The `total` timeout additionally bounds the complete
request budget.

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

There are six different timeout budgets. These are **total**, **dns**,
**connect**, **read**, **write**, and **pool** timeouts.

* The **total** timeout is the absolute request deadline, measured using a
monotonic clock. Redirects, authentication retries, pool waits, TLS, and response
stream reads all consume the same remaining total budget.
* The **dns** timeout bounds hostname resolution. It is capped by the remaining
**connect** and **total** budgets.

* The **connect** timeout specifies the maximum amount of time to wait until
a socket connection to the requested host is established, including DNS, TCP,
and TLS. If HTTPX is unable to connect within this time frame, a
`ConnectTimeout` exception is raised.
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

To set an overall request deadline while retaining per-operation limits:

```python
timeout = httpx.Timeout(
    total=30.0,
    dns=2.0,
    connect=5.0,
    read=10.0,
    write=None,
    pool=5.0,
)
client = httpx.Client(timeout=timeout)
```

`None` explicitly disables a timeout, `0` means time out immediately, and
omitting a value lets it inherit the configured default. A sub-budget cannot be
larger than its parent: `dns` cannot exceed `connect`, and operation budgets
cannot exceed `total`.

## Request budget timeline

Each phase receives the smaller of its own remaining budget and the remaining
total deadline. The total clock starts once the request begins and is not reset
for redirects.

```text
total deadline: |=========================== 30s ===========================>|
redirect 1:    |pool|dns|TCP/TLS|write|read headers|
redirect 2:                  |pool|dns|TCP/TLS|write|read stream chunks ...|
phase limits:    5   2    5     none  10 per chunk
```
