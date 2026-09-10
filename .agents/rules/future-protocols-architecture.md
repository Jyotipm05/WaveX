# WaveX Future Protocols & Architectural Design Decisions

> [!IMPORTANT]
> **Scope Invariant for AI Agents**:
> **Do NOT implement GraphQL, HTTP/3 (QUIC / UDP), or WebSocket protocols right now.**
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
- Handled uniformly via `template<typename Stream> asio::awaitable<void> handle_connection(std::unique_ptr<Stream> stream_ptr)`.
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
  - `request_type`: concrete request class (e.g., `HttpRequest<http1codec>`).
  - `response_type`: concrete response class (e.g., `HttpResponse<http1codec>`).
  - `parse_stream(buffer, request)` -> returns parsing state (`complete`, `indeterminate`, `error`).
  - `serialize(response)` -> returns byte representation for wire transmission.

### Seam 3: Protocol Traits Seam (`protocol_traits<Codec>`)
- Governs protocol-level connection policies:
  - `has_connection_preface`: whether the protocol requires opening handshake frames (HTTP/2 preface, HTTP/3 SETTINGS, WebSocket upgrade).
  - `on_connection_start(stream, buffer)`: async coroutine for exchanging connection prefaces/settings.
  - `keep_alive(req, request_count, max_keep_alive)`: evaluates connection persistence.
  - `prepare_response(res, req, keep_alive, timeout, remaining_requests)`: attaches protocol-specific headers (`Connection`, `Keep-Alive`, pseudo-headers).
  - `configure_alpn(SSL_CTX*)`: configures server-side ALPN negotiation callbacks.

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
  `Server` binds `write_sink_` to the active `Stream` before executing route handlers, making chunked streaming and file transfers 100% transport-agnostic (working identically over Plain TCP and TLS 1.3).

---

## 3. Future Protocol Blueprints (Design Recall)

### A. GraphQL Protocol (`graphql_codec`)
- **Status**: Future design. Do NOT implement now.
- **Layer**: Protocol / Application layer (sits above HTTP/1.1 or HTTP/2).
- **Architecture**:
  - `graphql_codec` parses GraphQL POST requests (`{"query": "...", "variables": {...}}`) and GET requests (`?query=...`).
  - Specialized `protocol_traits<graphql_codec>`:
    - `has_connection_preface = false`
    - `prepare_response`: Injects `Content-Type: application/graphql-response+json; charset=utf-8` (RFC specification) or `application/json`.
  - Schema execution and query resolution run within the route handler, returning JSON results formatted through `res.json(...)`.
  - Can be hosted directly on `Server<graphql_codec>` or within standard HTTP routes via `router.post("/graphql", graphql_handler)`.

### B. HTTP/3 (QUIC / UDP) Protocol (`http3codec`)
- **Status**: Future design. Do NOT implement now.
- **Layer**: Transport layer (QUIC over UDP) + Binary framing (HTTP/3 + QPACK).
- **Key Insight on QUIC vs TLS**:
  - In QUIC, TLS 1.3 handshake occurs at the UDP datagram / connection level via the QUIC handshake engine, NOT per individual virtual stream.
  - Virtual QUIC streams (`QuicStream`) are lightweight multiplexed streams over the UDP connection. They have `async_read_some` and `async_write_some`, but do NOT have `stream.async_handshake()`.
- **How `Server.hpp` Supports HTTP/3 without changes**:
  - In `handle_connection<Stream>`:
    `if constexpr (requires { stream.async_handshake(...); })` automatically evaluates to `false` for `QuicStream`.
    The compiler strips the TLS handshake branch with zero overhead.
  - `protocol_traits<http3codec>`:
    - `has_connection_preface = true`: `on_connection_start` writes the initial HTTP/3 `SETTINGS` frame and sets up the QPACK encoder/decoder dynamic tables.
    - `keep_alive`: returns `true` (QUIC streams are natively multiplexed and managed by QUIC connection state).
    - `configure_alpn`: registers `"h3"`.
  - UDP connection manager handles the UDP socket, demuxes QUIC packets into `QuicStream` instances, and forwards each stream to `server.handle_connection(std::move(quic_stream))`.

### C. WebSockets Protocol (RFC 6455)
- **Status**: Future design. Do NOT implement now.
- **Layer**: Protocol upgrade over HTTP/1.1.
- **Architecture**:
  - Initiated via HTTP/1.1 `Upgrade: websocket` and `Sec-WebSocket-Key`.
  - Server sends HTTP `101 Switching Protocols` using `res.status(101).set("Upgrade", "websocket")...`.
  - Stream ownership or codec transitions to `websocket_codec` framing (FIN bit, Opcode, Masking key, Payload length).

---

## 4. Invariants for Future Agents
1. **Never add protocol-specific branching to `Server.hpp`**:
   Do not introduce `if constexpr (is_http2)` or `if constexpr (is_http3)`. All protocol-specific logic belongs in `protocol_traits<Codec>`.
2. **Never execute synchronous socket writes in `HttpResponse::send_impl()`**:
   `send_impl()` must only set response state (`body_`, `is_sent_ = true`). All wire transmission is performed either by `Server` via `res.serialize()` or through the injected `write_sink_`.
3. **Preserve Client Subsystem (`include/wavex/Client`)**:
   Refactoring the server must never break client-side request construction, response parsing, or test coverage.
4. **Never run CMake configure commands**:
   Only run `cmake --build --preset fast-dev` and `ctest --preset run-tests`. Never run `cmake --preset ...` or `cmake -B ...`.
