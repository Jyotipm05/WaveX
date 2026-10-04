# WaveX Future Protocols & Architectural Design Decisions

> [!IMPORTANT]
> **Scope Invariant for AI Agents**:
> **Do NOT implement GraphQL or WebSocket protocols right now.**
> **HTTP/3 (RFC 9114 & RFC 9204) over QUIC (RFC 9000 & RFC 9001) is FULLY IMPLEMENTED and verified.**
> These protocol designs are documented here so that any agent working on WaveX understands the architectural choices, maintains compatibility with future designs, and avoids re-introducing tight coupling in `Server.hpp` or `HttpResponse.hpp`.

---

## 1. Architectural Core: The 3-Seam Foundation

WaveX server architecture is built around three strictly decoupled seams:

```
┌───────────────────────────────────────────────────────────┐
│                      Server<Codec>                        │
└─────────────┬─────────────────┬───────────────────┬───────┘
              │                 │                   │
              ▼                 ▼                   ▼
      ┌───────────────┐ ┌───────────────┐ ┌───────────────────┐
      │ 1. Transport  │ │   2. Codec    │ │ 3. ProtocolTraits │
      │     Seam      │ │     Seam      │ │       Seam        │
      └───────┬───────┘ └───────┬───────┘ └─────────┬─────────┘
              │                 │                   │
     AsyncStream concept  parse_stream()    on_connection_start()
     (TCP, TLS, QUIC)     serialize()       keep_alive()
                          result            prepare_response()
                                            configure_alpn()
```

### Seam 1: Transport Seam (`AsyncStream`)
- Handled uniformly via `template<typename Stream> asio::awaitable<void> handle_connection(std::shared_ptr<Stream> stream_ptr)`.
- Stream concept requires `stream.async_read_some(...)` and `stream.async_write_some(...)`.
- Worker-pool TLS handshake is guarded with C++20 requires:
  ```cpp
  if constexpr (requires { stream.async_handshake(asio::ssl::stream_base::server, asio::use_awaitable); }) {
      // Executes only for ssl::stream<tcp::socket>
  }
  ```
- Plain TCP and UDP/QUIC streams automatically evaluate this concept constraint to `false`, with zero runtime cost and zero coupling.

### Seam 2: Codec Seam (`Codec`)
- Codec defines:
  - `request_type`: concrete request class (e.g., `HttpRequest<http1codec>`, `HttpRequest<http3codec>`).
  - `response_type`: concrete response class (e.g., `HttpResponse<http1codec>`, `HttpResponse<http3codec>`).
  - `parse_stream(buffer, request)` -> returns parsing state (`complete`, `indeterminate`, `error`).
  - `serialize(response)` -> returns byte representation for wire transmission.

### Seam 3: Protocol Traits Seam (`protocol_traits<Codec>`)
- Governs protocol-level connection policies:
  - `has_connection_preface`: whether the protocol requires opening handshake frames (HTTP/2 preface, HTTP/3 SETTINGS, WebSocket upgrade).
  - `has_quic_transport`: activates UDP/QUIC listener on standalone `Server`.
  - `has_tcp_transport`: controls TCP listener activation.
  - `on_connection_start(stream, buffer)`: async coroutine for exchanging connection prefaces/settings.
  - `keep_alive(req, request_count, max_keep_alive)`: evaluates connection persistence (`false` for HTTP/3 request streams, which are one-request-per-stream).
  - `prepare_response(req, res, keep_alive, timeout, remaining_requests, alt_svc_port)`: attaches protocol-specific headers (`Connection`, `Keep-Alive`, `Alt-Svc`, pseudo-headers).
  - `configure_alpn(SSL_CTX*)`: configures server-side ALPN negotiation callbacks (`h3`, `h3-29`, `h2`, `http/1.1`).

### Seam 4: Multi-Protocol Composition (`ComposedHttpServer`)
- `Server<Codec, Router>` represents a single-protocol engine (e.g. `Http1Server`, `Http2Server`, `Http3Server`).
- Multi-protocol concurrency (running HTTP/1.1 + HTTP/2 on TCP alongside HTTP/3 on UDP on the same port) is strictly decoupled into `ComposedHttpServer`:
  - Holds `Http2Server server_` (handles TCP listener and HTTP/1.1 / HTTP/2 routing).
  - Holds `std::unique_ptr<QuicServer> quic_server_` (handles UDP listener and TLS 1.3 QUIC transport).
  - Sets `server_.set_alt_svc_port(port)` so TCP responses automatically advertise HTTP/3 support via `protocol_traits<http1codec>` and `protocol_traits<http2codec>`.
  - Dispatches incoming QUIC client request streams directly into `h3_router_` using `server_.pool()`.
  - Unifies lifecycle management and graceful shutdown across both TCP and UDP transports.

---

## 2. Response Lifecycle & Write Sink Invariants

### Response Commitment vs. Header Transmission
- `res.send(...)`: Signals **commitment** (`is_sent_ = true`). Does NOT write to the socket synchronously. Used by middleware chains (`run_chain`) to immediately halt execution when a route/guard has handled the request.
- `res.is_headers_sent()`: Signals whether response headers have already been transmitted to the wire (e.g., during chunked streaming via `res.start_chunked()` or file transfer via `res.send_file()`).
- In `Server::handle_connection`:
  ```cpp
  if (!res.is_headers_sent()) {
      co_await asio::async_write(stream, asio::buffer(res.serialize()), asio::use_awaitable);
  }
  ```
- **Streaming Sink**: All streaming operations in `HttpResponse` write through `write_sink_fn`:
  ```cpp
  using write_sink_fn = std::function<asio::awaitable<std::expected<void, std::error_code>>(
      std::string_view, std::chrono::milliseconds)>;
  ```
  `Server` binds `write_sink_` to the active `Stream` before executing route handlers, making chunked streaming and file transfers 100% transport-agnostic (working identically over Plain TCP, TLS 1.3, and QUIC streams).

---

## 3. Protocol Implementations & Blueprints

### A. HTTP/3 (QUIC / UDP) Protocol (`http3codec` & `Network/QUIC`)
- **Status**: **Fully Implemented and Verified** (RFC 9000, RFC 9001, RFC 9114, RFC 9204).
- **Layer**: Transport layer (`wavex::network::quic`) + Application/Binary framing (`wavex::protos::http::http3`).
- **Core Architecture & Invariants**:
  1. **Server-Initiated Unidirectional Streams (RFC 9114 §6.2)**:
     - Instantly established upon TLS 1.3 handshake completion (`SSL_do_handshake == 1`) after emitting `HANDSHAKE_DONE`:
       - **Stream 3 (Type `0x00` Control Stream)**: VarInt `0x00` followed by initial `SETTINGS` frame (`0x04`) at offset 0 (`SETTINGS_MAX_FIELD_SECTION_SIZE 65536`, `SETTINGS_QPACK_MAX_TABLE_CAPACITY 0`, `SETTINGS_QPACK_BLOCKED_STREAMS 0`).
       - **Stream 7 (Type `0x02` QPACK Encoder Stream)**: VarInt `0x02`.
       - **Stream 11 (Type `0x03` QPACK Decoder Stream)**: VarInt `0x03`.
  2. **Stream Demultiplexing & Inbound Categorization (RFC 9000 §2.1)**:
     - Stream IDs identify initiator and direction:
       - `(sid & 0x03) == 0x00`: Client-initiated bidirectional stream -> Dispatched to `Server` / `HttpRouter` as an HTTP/3 request stream.
       - `(sid & 0x03) == 0x02`: Client-initiated unidirectional stream -> Drained/handled in background as peer Control or QPACK streams. **NEVER** treated as request streams and **NEVER** written to.
  3. **Transport Parameter Lifetime Invariant**:
     - `local_transport_params_` in `QuicConnection` is connection-scoped. `SSL_set_quic_tls_transport_params` registers a non-owning pointer dereferenced asynchronously during `SSL_do_handshake()`; it must never point to stack-local memory.
  4. **QPACK 2-Byte Field Section Prefix & RFC 9000 VarInt Framing**:
     - Responses begin with a 2-byte QPACK prefix (`0x00 0x00`) followed by indexed static entries (e.g. `:status: 200` = `0xD9`), wrapped in RFC 9000 VarInt frames (`HEADERS 0x01` + `DATA 0x00`), and terminated by QUIC stream FIN.
  5. **AsyncStream Concept Compliance**:
     - `QuicStream` adheres to the `AsyncStream` concept (`async_read_some`, `async_write_some`, `close()`), allowing zero-overhead integration with `Server::handle_connection`.

### B. GraphQL Protocol (`graphql_codec`)
- **Status**: Future design. Do NOT implement now.
- **Layer**: Protocol / Application layer (sits above HTTP/1.1, HTTP/2, or HTTP/3).
- **Architecture**:
  - `graphql_codec` parses GraphQL POST requests (`{"query": "...", "variables": {...}}`) and GET requests (`?query=...`).
  - Specialized `protocol_traits<graphql_codec>`:
    - `has_connection_preface = false`
    - `prepare_response`: Injects `Content-Type: application/graphql-response+json; charset=utf-8` (RFC specification) or `application/json`.
  - Schema execution and query resolution run within the route handler, returning JSON results formatted through `res.json(...)`.
  - Can be hosted directly on `Server<graphql_codec>` or within standard HTTP routes via `router.post("/graphql", graphql_handler)`.

### C. WebSockets Protocol (RFC 6455)
- **Status**: Future design. Do NOT implement now.
- **Layer**: Protocol upgrade over HTTP/1.1.
- **Architecture**:
  - Initiated via HTTP/1.1 `Upgrade: websocket` and `Sec-WebSocket-Key`.
  - Server sends HTTP `101 Switching Protocols` using `res.status(101).set("Upgrade", "websocket")...`.
  - Stream ownership or codec transitions to `websocket_codec` framing (FIN bit, Opcode, Masking key, Payload length).

---

## 4. Invariants for Future Agents
1. **Strict 3-Seam Decoupling & Zero Protocol Leakage**:
   - `Server<Codec, Router>` must remain strictly protocol-agnostic.
   - NEVER add protocol router pointers (`h3_router_`), protocol enable flags (`http3_enabled_`), or protocol dispatchers (`handle_http3_connection`, `spawn_http3_stream`) to `Server<Codec, Router>`.
   - Generic connection loops (`ServerConnection.ipp`) must NEVER contain codec-specific debug logging (`if constexpr (is_http3_codec_v)`).
2. **Multi-Protocol Composition Belongs in `ComposedHttpServer`**:
   - When serving multiple protocols concurrently (HTTP/1.1, HTTP/2, and HTTP/3 on the same port), use `ComposedHttpServer`.
   - `ComposedHttpServer` owns both the TCP `Http2Server` and the UDP `QuicServer`, coordinates thread pool spawning, and synchronizes graceful shutdown.
3. **Protocol-Driven Header Injection (`prepare_response`)**:
   - All protocol advertisements (e.g. RFC 9114 `Alt-Svc: h3=":4433"; ma=86400`) must be injected through `protocol_traits<Codec>::prepare_response(req, res, keep_alive, timeout, remaining, alt_svc_port)`.
   - Never format or inject protocol headers directly inside `ServerConnection.ipp`.
4. **Never execute synchronous socket writes in `HttpResponse::send_impl()`**:
   - `send_impl()` must only set response state (`body_`, `is_sent_ = true`). All wire transmission is performed either by `Server` via `res.serialize()` or through the injected `write_sink_`.
5. **Preserve Client Subsystem (`include/wavex/Client`)**:
   - Refactoring the server must never break client-side request construction, response parsing, or test coverage.
6. **Never run CMake configure commands**:
   - Only run `cmake --build --preset fast-dev` and `ctest --preset run-tests`. Never run `cmake --preset ...` or `cmake -B ...`.
