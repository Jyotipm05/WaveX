# Protocol Takeover, WebSocket, WebTransport & HTTP/2 Session Gotchas

Pitfalls 46-53 moved out of `SKILL.md` to keep it small. Architecture: `.agents/rules/websocket-takeover-http2-session.md`.

46. **Connection Takeover Lives in the Policy Seam**:
    - After each response `ServerConnection.ipp` asks `protocol_traits<Codec>::wants_takeover(req, res)` (synchronous,
      only if the policy defines it); on yes it awaits `take_over(stream_ptr, req, res, std::string unread)` and stops
      serving the connection. It must never test for `101`, `CONNECT` or a protocol name. HTTP/1.x takes over on `101`,
      HTTP/3 on a 2xx to an (extended) CONNECT. HTTP/2 never runs this loop (see 52); its session applies the same
      `detail::http_wants_takeover` rule per stream.
    - Keep `wants_takeover` synchronous: a coroutine there would allocate a frame for every request.
    - `req`/`res` stay alive during the takeover.
    - `protocol_traits<http1codec>::prepare_response` leaves `101` responses alone (no `Connection: keep-alive`).

47. **HTTP/3 CONNECT Requests Are Tunnels**:
    - The parser returns after the HEADERS of a CONNECT; never fold following DATA frames into a body. `:protocol` is
      only valid with CONNECT and then requires `:scheme`, `:path`, `:authority`.

48. **WebSocket Writes Are Serialized on the Connection Executor**:
    - `websocket::connection::send_*` queue frames under `write_mtx_`; a single writer coroutine (co_spawned on the
      connection executor with a `shared_from_this()` capture) drains them. Never write to the socket from another
      thread, and never invoke user code while holding `write_mtx_`.
    - Timer callbacks that may outlive a coroutine frame share their flags through `std::shared_ptr` (see
      `connection::fill`).

49. **Peeked QUIC Bytes Must Be Restored**:
    - `webtransport::dispatch_bidirectional_stream()` reads a client bidirectional stream's first varint. Anything that is
      not the WT_STREAM signal (0x41) is pushed back with `QuicStream::unread()` so the HTTP/3 request path sees the
      stream byte-for-byte.

50. **Receive-Only QUIC Streams Never Get a FIN**:
    - Calling `QuicStream::close()` on a peer-initiated unidirectional stream queues a FIN on a stream we cannot send on
      (STREAM_STATE_ERROR). WebTransport closes only streams it can write to.

51. **DATAGRAM Frames Are Unreliable by Design**:
    - `retransmit_frame()` ignores `DatagramFrame`; payloads are delivered to `set_datagram_callback()` outside the
      connection lock. Accept DATAGRAM frames only when `local_max_datagram_frame_size_ > 0`.

52. **HTTP/2 Is Served by a Multiplexed Session, Not the Loop**:
    - `protocol_traits<http2codec>::serve_connection` runs `http2::server_session` (`protos/http/http2session.hpp`)
      after the preface. Per-request work goes through `ConnectionServices::handle()` → `Server::process_request()`;
      never re-implement routing, middleware or error mapping in a protocol.
    - The session must join its stream tasks before returning (they use `ConnectionServices` and the connection
      pool, both on the kernel coroutine frame). Everything runs on the connection executor: no locks, unsynchronized pool.
    - HPACK decoding happens in the reader in arrival order (persistent table); requests are rebuilt with literal-only
      blocks for `parse_stream`. Responses never index, so cross-stream write order is free.
    - Only the session writer touches the socket. DATA honours the peer's stream/connection windows and max frame size;
      tests that open only a stream window will (correctly) stall at the 65,535-byte connection window.
    - `HttpClient` opens its windows to the maximum because it never sends WINDOW_UPDATE.

53. **Streamed Responses Frame Per Codec**:
    - `HttpResponse::write_chunk` / `end_chunked` / `send_file` use `frame_body_chunk` / `terminal_chunk`: chunked
      coding for HTTP/1.1, DATA frames on the response's own stream for HTTP/2 and HTTP/3. Never hard-code stream 1,
      and never add `Transfer-Encoding` / `Connection` for version ≥ 2.

---
