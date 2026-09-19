# Content Encodings

HTTPX includes decoders for `gzip`, `deflate`, `br`, and `zstd`. Custom
`Content-Encoding` tokens can be registered on an individual client without
modifying the global decoder table or other clients.

## Custom decoders

A decoder is a class implementing the `ContentDecoder` contract. Each response
calls the registered zero-argument factory once, so concurrent responses get
independent decoder state and buffers.

```python
import httpx


class XorDecoder(httpx.ContentDecoder):
    def __init__(self) -> None:
        self.key = 0x5A

    def decode(self, data: bytes) -> bytes:
        return bytes(byte ^ self.key for byte in data)

    def flush(self) -> bytes:
        return b""


client = httpx.Client(content_decoders={"x-xor": XorDecoder})
response = client.get("https://example.com")
```

Factories must take no arguments and return a fresh decoder instance.
`decode()` receives each chunk of online bytes and may return an empty chunk
while buffering state. `flush()` is called once at the end and must return any
remaining bytes. Both methods must return `bytes`; failures should raise an
exception, which HTTPX reports as `httpx.DecodingError`.

Multiple encodings are decoded in the reverse order of the `Content-Encoding`
header, matching HTTP semantics. The custom token is added to the client's
automatic `Accept-Encoding` header only when no `Accept-Encoding` header is
explicitly configured. Raw iterators and `num_bytes_downloaded` continue to
represent the original bytes received from the transport.
