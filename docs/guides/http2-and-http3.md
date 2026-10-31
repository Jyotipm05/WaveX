# HTTP/2 and HTTP/3 Servers

The same router API serves HTTP/1.1, HTTP/2 and HTTP/3; pick the server and router type for the protocol you want.

| Protocol | Server                         | Router                       | Transport                                 |
|:---------|:-------------------------------|:-----------------------------|:------------------------------------------|
| HTTP/1.1 | `Http1Server` (alias `Server`) | `Http1Router` / `HttpRouter` | TCP, TCP + TLS 1.3                        |
| HTTP/2   | `Http2Server`                  | `Http2Router`                | h2c (cleartext) or TLS 1.3 with ALPN `h2` |
| HTTP/3   | `Http3Server`                  | `Http3Router`                | QUIC over UDP, TLS 1.3                    |

## HTTP/2 (RFC 7540 + HPACK RFC 7541)

WaveX provides native HTTP/2 server support via `Http2Server` and `Http2Router`, implementing RFC 7540 binary framing and RFC 7541 HPACK header compression:

```c++
#include <wavex/wavex.hpp>

int main() {
    auto &router = wavex::engine::Http2Router::instance();

    // Stream-aware HTTP/2 JSON endpoint
    router.get("/api/h2", [](auto &req, auto &res) -> asio::awaitable<void> {
        res.status(200).json({
            {"protocol", "HTTP/2"},
            {"stream_id", req.stream_id()},
            {"framework", "WaveX"}
        });
        co_return;
    });

    // Option A: Cleartext HTTP/2 (h2c) on port 8082
    wavex::server::Http2Server server(router, "127.0.0.1", 8082);

    // Option B: HTTP/2 over TLS 1.3 (ALPN 'h2' negotiated automatically on port 8444)
    // wavex::server::Http2Server server(router, "127.0.0.1", 8444);
    // server.enable_tls("ssl/test.crt", "ssl/test.key");

    wavex::log::info("WaveX HTTP/2 server running on http://127.0.0.1:8082");
    server.run();

    return 0;
}
```

## HTTP/3 over QUIC (RFC 9114, RFC 9000/9001, QPACK RFC 9204)

> [!NOTE]
> The QUIC transport uses the OpenSSL 3.5+ QUIC TLS callback API (`SSL_set_quic_tls_cbs`). HTTP/3 and QUIC are the newest parts of WaveX; see [Component status](../components.md).

WaveX delivers native HTTP/3 server support via `Http3Server` and `Http3Router`, running over UDP-based QUIC with TLS 1.3 encryption and QPACK header compression:

```c++
#include <wavex/wavex.hpp>
#include <wavex/protos/http/http3codec.hpp>

int main() {
    auto &router = wavex::engine::Http3Router::instance();

    // Stream-aware HTTP/3 JSON endpoint
    router.get("/api/h3", [](auto &req, auto &res) -> asio::awaitable<void> {
        res.status(200).json({
            {"protocol", "HTTP/3"},
            {"transport", "QUIC (RFC 9000)"},
            {"framework", "WaveX"}
        });
        co_return;
    });

    // Run HTTP/3 over QUIC on UDP port 8445 with TLS 1.3
    wavex::server::Http3Server server(router, "127.0.0.1", 8445);
    server.enable_tls("ssl/test.crt", "ssl/test.key");

    wavex::log::info("WaveX HTTP/3 server running on https://127.0.0.1:8445");
    server.run();

    return 0;
}
```

---

**See also:** [TLS guide](tls.md) · [Dev servers & cURL](../dev-servers.md) · [Architecture](../architecture.md)

## How the HTTP/2 server handles a connection

After the client preface, `protocol_traits<http2codec>::serve_connection` hands the connection to a
multiplexed session (`protos/http/http2session.hpp`) instead of the one-request-at-a-time loop used by
HTTP/1.1:

- Requests on different streams run concurrently on the connection's worker; a slow handler no longer delays
  the other streams.
- Flow control follows RFC 9113: response DATA respects the client's stream and connection windows and the
  peer's maximum frame size; request bodies are credited back with WINDOW_UPDATE.
- PING, SETTINGS (acknowledged when received), RST_STREAM, CONTINUATION, trailers and GOAWAY are handled; the
  server advertises at most 100 concurrent streams and refuses more with `REFUSED_STREAM`.
- Streaming responses (`write_chunk`, `send_file`) are framed as DATA frames of their own stream.
- On `exit()`, idle connections get GOAWAY; streams in flight finish (or are closed at the deadline).
- Extended CONNECT is enabled (`SETTINGS_ENABLE_CONNECT_PROTOCOL`), which carries
  [WebSocket over HTTP/2](websocket-and-webtransport.md).

Every request still goes through the same routing, middleware, limits and error handling as on HTTP/1.1.
