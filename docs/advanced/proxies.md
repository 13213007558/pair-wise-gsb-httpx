HTTPX supports setting up [HTTP proxies](https://en.wikipedia.org/wiki/Proxy_server#Web_proxy_servers) via the `proxy` parameter to be passed on client initialization or top-level API functions like `httpx.get(..., proxy=...)`.

<div align="center">
    <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/2/27/Open_proxy_h2g2bob.svg/480px-Open_proxy_h2g2bob.svg.png"/>
    <figcaption><em>Diagram of how a proxy works (source: Wikipedia). The left hand side "Internet" blob may be your HTTPX client requesting <code>example.com</code> through a proxy.</em></figcaption>
</div>

## HTTP Proxies

To route all traffic (HTTP and HTTPS) to a proxy located at `http://localhost:8030`, pass the proxy URL to the client...

```python
with httpx.Client(proxy="http://localhost:8030") as client:
    ...
```

For more advanced use cases, pass a mounts `dict`. For example, to route HTTP and HTTPS requests to 2 different proxies, respectively located at `http://localhost:8030`, and `http://localhost:8031`, pass a `dict` of proxy URLs:

```python
proxy_mounts = {
    "http://": httpx.HTTPTransport(proxy="http://localhost:8030"),
    "https://": httpx.HTTPTransport(proxy="http://localhost:8031"),
}

with httpx.Client(mounts=proxy_mounts) as client:
    ...
```

For detailed information about proxy routing, see the [Routing](#routing) section.

!!! tip "Gotcha"
    In most cases, the proxy URL for the `https://` key _should_ use the `http://` scheme (that's not a typo!).

    This is because HTTP proxying requires initiating a connection with the proxy server. While it's possible that your proxy supports doing it via HTTPS, most proxies only support doing it via HTTP.

    For more information, see [FORWARD vs TUNNEL](#forward-vs-tunnel).

## Routing policy

Use `httpx.ProxyPolicy` when proxy routing needs to be explicit. The policy can
read environment variables, accept a client mapping, and be overridden for an
individual request:

```python
policy = httpx.ProxyPolicy(
    proxies={
        "http://": "http://localhost:8030",
        "https://": "http://localhost:8031",
    },
    no_proxy=[".internal.example", "10.0.0.0/8", "[::1]:443"],
)

with httpx.Client(proxy_policy=policy) as client:
    # Force one request through a specific proxy.
    client.get("https://example.com", proxy="http://localhost:8032")

    # Bypass every configured proxy for one request.
    client.get("https://example.com", proxy=False)
```

`NO_PROXY` is evaluated before selecting `HTTP_PROXY`, `HTTPS_PROXY`, or
`ALL_PROXY`. It matches scheme, normalized host, and effective port: absent
ports mean 80 for HTTP and 443 for HTTPS. Hostnames are case-insensitive,
trailing dots are ignored, IPv6 literals use square brackets, and CIDR ranges
can include a port such as `10.0.0.0/8:443` or `[2001:db8::]/32:443`.

The selected route is available on the response as
`response.extensions["proxy_route"]`. Its `reason` field records whether the
connection is direct or proxied; for HTTPS through an HTTP proxy, `connect_line`
contains the CONNECT authority. Ambiguous or malformed `NO_PROXY` tokens raise
`ValueError` when the policy is constructed.

## Authentication

Proxy credentials can be passed as the `userinfo` section of the proxy URL. For example:

```python
with httpx.Client(proxy="http://username:password@localhost:8030") as client:
    ...
```

## Proxy mechanisms

!!! note
    This section describes **advanced** proxy concepts and functionality.

### FORWARD vs TUNNEL

In general, the flow for making an HTTP request through a proxy is as follows:

1. The client connects to the proxy (initial connection request).
2. The proxy transfers data to the server on your behalf.

How exactly step 2/ is performed depends on which of two proxying mechanisms is used:

* **Forwarding**: the proxy makes the request for you, and sends back the response it obtained from the server.
* **Tunnelling**: the proxy establishes a TCP connection to the server on your behalf, and the client reuses this connection to send the request and receive the response. This is known as an [HTTP Tunnel](https://en.wikipedia.org/wiki/HTTP_tunnel). This mechanism is how you can access websites that use HTTPS from an HTTP proxy (the client "upgrades" the connection to HTTPS by performing the TLS handshake with the server over the TCP connection provided by the proxy).

### Troubleshooting proxies

If you encounter issues when setting up proxies, please refer to our [Troubleshooting guide](../troubleshooting.md#proxies).

## SOCKS

In addition to HTTP proxies, `httpcore` also supports proxies using the SOCKS protocol.
This is an optional feature that requires an additional third-party library be installed before use.

You can install SOCKS support using `pip`:

```shell
$ pip install httpx[socks]
```

You can now configure a client to make requests via a proxy using the SOCKS protocol:

```python
httpx.Client(proxy='socks5://user:pass@host:port')
```
