# WaveX WebSocket, WebTransport, Takeover & HTTP/2 Session Invariants

Split out of `future-protocols-architecture.md` to keep each rule file small. Sections keep their original numbers (§C, §D, §5, §6).

### C. WebSockets Protocol (RFC 6455, RFC 9220)
- **Status**: **Implemented (Beta)** — `include/wavex/protos/websocket/WebSocket.hpp`, `src/protos/websocket/WebSocket.cpp`, tests in `tests/test_websocket.cpp` and `tests/test_webtransport.cpp` (HTTP/3 variant).
- **Layer**: Protocol switch after an HTTP exchange. HTTP/1.1 `Upgrade` (`101`); extended CONNECT with `:protocol = websocket` (`200`) on HTTP/2 (RFC 8441, the multiplexed session hands the stream over as a byte stream) and HTTP/3 (RFC 9220, frames carried in DATA frames).
- **Architecture**:
  - `websocket::accept(req, res, handler, opts)` validates the handshake, fills `101` / `200` (or `400` / `426` / `501`) and installs `res.upgrade(fn)`. `HttpRouter::websocket()` wraps it (GET on HTTP/1.x routers, CONNECT on `Http3Router`).
  - The server reaches the handler only through `protocol_traits<Codec>::wants_takeover` / `take_over` (§5); the session runs on the connection coroutine over a `network::AnyStream`.
  - `websocket::codec` (pure frame codec), `websocket::connection` (reassembly, auto-pong, close handshake, UTF-8, limits). Sends are queued under a mutex and written by a writer coroutine spawned on the connection's executor, so any thread may send.
  - HTTP/3: the transport is wrapped with `http3::make_data_tunnel()` (`protos/http/http3tunnel.hpp`).

### D. WebTransport over HTTP/3
- **Status**: **Implemented (Beta)** — `include/wavex/protos/webtransport/WebTransport.hpp`, `src/protos/webtransport/WebTransport.cpp`. Wire format of draft-ietf-webtrans-http3, compatible with draft-02 (Chromium).
- **Architecture**:
  - Session = extended CONNECT (`:protocol = webtransport`) on a client bidirectional stream; session ID = that stream ID. `webtransport::accept()` / `Http3Router::webtransport()` answer `200` and install the takeover (§5).
  - Streams: client/server bidirectional streams begin with `0x41` + session ID; unidirectional streams with type `0x54` + session ID. `QuicTransportListener` and `ComposedHttpServer` call `webtransport::dispatch_bidirectional_stream()` before treating a client bidirectional stream as a request; `http3::session_handler::handle_unidirectional_stream()` routes type `0x54`.
  - Datagrams: RFC 9297 (quarter session ID + payload) in RFC 9221 QUIC DATAGRAM frames (`QuicConnection::send_datagram()` / `set_datagram_callback()`).
  - Capsules (`CLOSE_WEBTRANSPORT_SESSION` 0x2843, `DRAIN_WEBTRANSPORT_SESSION` 0x78ae) travel in DATA frames on the CONNECT stream.
  - Per-connection state: `http3::connection_context::webtransport` (`session_registry`, created via `registry_for()` under `extension_mtx`). Streams that overtake their CONNECT are parked (`kMaxPendingStreams`).

---

## 5. Connection Takeover (Protocol Switch) Contract

1. A handler (via `websocket::accept`, `webtransport::accept` or directly) installs `res.upgrade(fn)`; `fn` has the signature `wavex::task<void>(network::AnyStream, std::string unread)`.
2. After `res` is on the wire the kernel asks the policy. `detail::http_wants_takeover` (synchronous, no coroutine frame for ordinary requests) says yes only when an upgrade handler is installed and the status is `101` on HTTP/1.x or a 2xx on HTTP/3 (otherwise the handler is ignored and the request completes normally). `detail::http_take_over` then runs `fn` with `AnyStream::wrap(stream_ptr, <connection coroutine executor>)`.
3. `unread` (an owned `std::string`) holds the bytes already received past the request: pipelined WebSocket frames, tunnel DATA.
4. `req` and `res` stay alive while `fn` runs; anything escaping to other threads must be copied (string_view contract).
5. When `fn` returns, the kernel tears the connection (HTTP/1.x) or request stream (HTTP/3) down as usual. Upgraded connections count as active for graceful drain (`exit(timeout)` force-closes them at the deadline).
6. HTTP/2 never reaches the sequential loop: its policy defines `serve_connection` (§6), and the session applies `detail::http_wants_takeover` per stream, running the handler on that stream while the others continue.

---

## 6. Policy-Driven Connections (`serve_connection`) — Multiplexed HTTP/2

1. A policy may define `template<class Stream, class Services> static wavex::task<void> serve_connection(std::shared_ptr<Stream>, std::string buffered, Services &)`. The kernel then calls it after `on_connection_start` instead of running its loop. Only HTTP/2 defines it.
2. `Services` is `Server::ConnectionServices<Codec, Router>`: protocol-neutral (`memory()`, `accepting()`, `idle_timeout()`, `max_request_size()`, `limits()`, `mark_idle()/mark_active()`, `handle(req, res, sink)`). `handle()` is `Server::process_request()`, the same routing/middleware/error/prepare_response pipeline the sequential loop uses: never duplicate that logic in a protocol.
3. `serve_connection` must not return while any task it spawned can still touch `Services` or the connection memory pool (they live on the kernel coroutine's frame). The HTTP/2 session joins its stream tasks in `shutdown()`.
4. The session runs entirely on the connection's executor: reader, writer and stream tasks. No locks; the memory pool is unsynchronized. Cross-thread entry points (WebSocket sends) must re-dispatch onto that executor.
5. HPACK: the session decodes header blocks in arrival order with one persistent table; the request handed to the codec parser is re-encoded with literals only, so parsing it touches no table. The response encoder never indexes, so frames of different streams may be written in any order.
6. Every frame for the socket goes through the session's writer queue; only the writer writes to the socket. DATA respects the peer's stream and connection windows and `SETTINGS_MAX_FRAME_SIZE`.
7. The HTTP/3 parser stops at the HEADERS of a CONNECT request: the stream's DATA frames are the tunnel, never a request body (`bytes_consumed` ends after HEADERS).
