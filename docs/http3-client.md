# HTTP/3 client

WaveX can make HTTP/3 requests (RFC 9114) over its own QUIC transport. There are two ways in.

## 1. Through `HttpClient`

```cpp
wavex::client::ClientOptions o;
o.version = wavex::client::HttpVersion::Http3;      // https:// only, no TCP fallback
auto res = co_await wavex::client::HttpClient::get("https://example.com/", o);
// res.http_version() == HttpVersion::Http3
```

`HttpVersion::Auto` stays on TCP (HTTP/2 or HTTP/1.1) unless discovery is switched on:

```cpp
o.h3_discovery = true;   // Auto only
```

With discovery on, HTTP/3 is used for an origin when

* an earlier TCP response carried `Alt-Svc: h3=":443"; ma=...` (same host only; `clear` and `ma=0` forget it), or
* the host publishes a DNS HTTPS record (RFC 9460) whose `alpn` contains `h3` (a different `port` is honoured).

If the HTTP/3 attempt fails, the request falls back to TCP and HTTP/3 is not retried for that origin for five
minutes, so a network that drops UDP costs one handshake timeout, not one per request. Discovery is off by default
for exactly that reason.

## 2. `Http3Client`: one connection, many requests

```cpp
wavex::client::Http3Client c(co_await asio::this_coro::executor);
if (auto ec = co_await c.connect("example.com", 443); !ec) {
    auto a = co_await c.send(wavex::client::ClientRequest(wavex::client::method::GET, "https://example.com/a"));
    auto b = co_await c.send(wavex::client::ClientRequest(wavex::client::method::GET, "https://example.com/b"));
}
```

`connect()` resolves the name with the native DNS resolver, tries up to three addresses, runs the QUIC handshake
(ALPN `h3`) and opens the control stream (SETTINGS) and the two QPACK streams. Every `send()` uses its own
bidirectional stream, so requests from different coroutines run concurrently on the same connection without
head-of-line blocking between them. The QPACK dynamic table is not used (capacity 0).

`is_open()` turns false when the connection is lost or the server sends GOAWAY; reconnect with `connect()`.
Errors use `http3_category()` (`not_connected`, `handshake_failed`, `timeout`, `protocol_error`,
`response_too_large`, `stream_reset`).

## Limits

* `send()` buffers the whole response (`Http3Options::max_response_size`, 64 MiB); use `send_streaming()` for large or endless bodies (see `streaming-bodies.md`). `request_timeout` is the longest wait for the next bytes, not a deadline for the whole response.
* `HttpClient` opens one QUIC connection per request (like its HTTP/1.1 and HTTP/2 paths); reuse needs `Http3Client`.
* No 0-RTT, no connection migration, no server push, no interim (1xx) responses.
* Discovery follows alternatives on the same host name only.
* The default handshake timeout is 5 seconds.
