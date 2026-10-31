# WebSocket and WebTransport

WaveX serves WebSocket (RFC 6455) on HTTP/1.1, WebSocket over HTTP/3 (RFC 9220) and WebTransport over HTTP/3.
All three start as an ordinary routed request, so route middlewares (authentication, rate limits) run before
the protocol switch and can refuse it.

| Protocol           | Server                              | Handshake                                                | Register with                    |
|:-------------------|:------------------------------------|:---------------------------------------------------------|:---------------------------------|
| WebSocket          | `Http1Server` (TCP or TLS)          | `GET` + `Upgrade: websocket` → `101 Switching Protocols` | `Http1Router::websocket()`       |
| WebSocket over H2  | `Http2Server`, `ComposedHttpServer` | extended CONNECT, `:protocol = websocket` → `200`        | `Http2Router::websocket()`       |
| WebSocket over H3  | `Http3Server`, `ComposedHttpServer` | extended CONNECT, `:protocol = websocket` → `200`        | `Http3Router::websocket()`       |
| WebTransport       | `Http3Server`, `ComposedHttpServer` | extended CONNECT, `:protocol = webtransport` → `200`     | `Http3Router::webtransport()`    |

The HTTP/2 server advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL`, so browsers open their WebSocket as one
stream of the HTTP/2 connection they already use for the page (RFC 8441). The rest of the page keeps loading
on that connection while the socket is open; see [HTTP/2 and HTTP/3](http2-and-http3.md) for how the HTTP/2
server multiplexes streams.

## WebSocket

```cpp
#include <wavex/wavex.hpp>

namespace ws = wavex::protos::websocket;
using wavex::protos::http::Http1Request;

int main() {
    auto router = wavex::engine::Http1Router::make_instance();

    router.websocket("/echo", [](Http1Request &req, std::shared_ptr<ws::connection> conn)
        -> asio::awaitable<void> {
        while (auto msg = co_await conn->read()) {   // text or binary, fragments reassembled
            conn->send(*msg);                        // queued; safe from any thread
        }
        // read() failed: ws::error::closed after a close handshake, or a transport error.
        // conn->close_code() / close_reason() tell why.
    });

    wavex::server::Http1Server server(router, "0.0.0.0", 8080);
    server.run();
}
```

What the session does for you:

- Validates the handshake (`Sec-WebSocket-Key`, `Sec-WebSocket-Version: 13`, `Upgrade`, `Connection`) and
  answers `101` with `Sec-WebSocket-Accept`. Bad handshakes get `400` or `426`.
- Answers pings, reassembles fragmented messages, validates UTF-8 in text messages and close reasons.
- Closes with `1002` on protocol violations (unmasked client frames, reserved bits or opcodes, bad
  fragmentation), `1007` on invalid UTF-8 and `1009` when a message exceeds `options::max_message_size`.
- Completes the close handshake when your handler returns (sends `1000` if you did not close first) and
  waits up to `options::close_timeout` for the peer's reply before the server closes the TCP connection.

The request (`req`) stays valid for the whole session, so path parameters and headers can be read at any
time. Copy anything you hand to other threads (see [Memory & lifetimes](memory-and-lifetimes.md)).

### Sending from other connections

`send_text`, `send_binary`, `ping` and `close` only queue a frame; a writer on the connection's own
executor performs the socket writes. That makes broadcasting from other sessions (which run on other
worker threads) safe:

```cpp
std::mutex room_mtx;
std::vector<std::weak_ptr<ws::connection>> room;

router.websocket("/chat", [&](Http1Request &, std::shared_ptr<ws::connection> conn) -> asio::awaitable<void> {
    { std::lock_guard lock(room_mtx); room.push_back(conn); }
    while (auto msg = co_await conn->read()) {
        std::lock_guard lock(room_mtx);
        for (auto &w : room) if (auto peer = w.lock()) peer->send_text(msg->data);
    }
});
```

A send returns `false` once the connection is closing or when more than `options::max_buffered_amount`
bytes are already queued (`buffered_amount()` reports the current backlog).

### Options and subprotocols

```cpp
ws::options opts;
opts.subprotocols = {"chat.v2", "chat.v1"};          // server preference order
opts.max_message_size = 1 << 20;                      // 1 MiB, then close 1009
opts.read_timeout = std::chrono::seconds(60);         // read() fails with ws::error::read_timeout
router.websocket("/chat", handler, opts);
// conn->subprotocol() holds the negotiated value.
```

Outside a router, `ws::accept(req, res, handler, opts)` performs the same handshake from any handler.

## WebTransport (HTTP/3)

```cpp
namespace wt = wavex::protos::webtransport;
using wavex::protos::http::Http3Request;

wavex::engine::Http3Router router;
router.webtransport("/wt", [](Http3Request &req, std::shared_ptr<wt::session> session)
    -> asio::awaitable<void> {
    // Echo every bidirectional stream the browser opens.
    while (auto stream = co_await session->accept_bidirectional_stream()) {
        auto [ec, data] = co_await stream->read_all();
        if (!ec) co_await stream->write(data);
        stream->finish();
    }
    // accept_*() returns nullptr once the session is closed.
});
```

The session API:

| Call                                                               | Purpose                                                                |
|:-------------------------------------------------------------------|:-----------------------------------------------------------------------|
| `accept_bidirectional_stream()` / `accept_unidirectional_stream()` | next stream the client opened                                          |
| `open_bidirectional_stream()` / `open_unidirectional_stream()`     | server-initiated streams                                               |
| `receive_datagram()` / `send_datagram()`                           | unreliable datagrams (RFC 9297 HTTP datagrams in QUIC DATAGRAM frames) |
| `close(code, reason)` / `drain()`                                  | `CLOSE_WEBTRANSPORT_SESSION` / `DRAIN_WEBTRANSPORT_SESSION` capsules   |
| `path()`, `authority()`, `origin()`                                | from the CONNECT request; check `origin()` before trusting a browser   |

Each `wt::stream` has `read_some`, `read_all`, `write`, `finish` (FIN) and `close`.

The QUIC layer advertises `max_datagram_frame_size`, and the HTTP/3 SETTINGS include
`SETTINGS_ENABLE_CONNECT_PROTOCOL`, `SETTINGS_H3_DATAGRAM`, `SETTINGS_WEBTRANSPORT_MAX_SESSIONS` and the
draft-02 `SETTINGS_ENABLE_WEBTRANSPORT` that Chromium-based browsers still require. Draft-02 clients also get
the `sec-webtransport-http3-draft: draft02` response header.

On `ComposedHttpServer` use `server.webtransport("/wt", handler)` (HTTP/3) and
`server.websocket("/ws", [](std::shared_ptr<ws::connection> conn) -> asio::awaitable<void> { ... })`, which
registers the endpoint on both the HTTP/2 and the HTTP/3 router.

### Limits and caveats

- Streams that arrive before their session's CONNECT has been accepted are parked (32 per connection) and
  delivered once the session registers; incoming streams and datagrams queue up to
  `wt::options::max_incoming_streams` / `max_incoming_datagrams`, beyond which streams are refused and
  datagrams dropped.
- Closing a session finishes (FIN) its streams; QUIC `RESET_STREAM` / `STOP_SENDING` with WebTransport
  error codes are not sent yet.
- WebTransport needs a build with `WAVEX_HAS_SSL` (HTTP/3).

## Graceful shutdown

Upgraded connections count as active connections. `server.exit(timeout)` waits for them up to `timeout`
and then closes them. To say goodbye first, close the sessions you track before calling `exit()` with
`conn->close(ws::close_code::going_away)` or `session->close()`. If you shut down through a `ShutdownEvent`
(see [Connections & shutdown](connections-and-shutdown.md)), subscribe a handler to that same event and do
it there; the event is multicast.

---

**See also:** [HTTP/2 & HTTP/3](http2-and-http3.md) · [Custom protocols](custom-protocols.md) · [Routing & middleware](routing-and-middleware.md)
