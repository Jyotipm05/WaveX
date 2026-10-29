# WaveX 3-Seam Architecture & Protocol Composition Guide

This document explains the architectural principles, mistakes resolved, and rules for extending WaveX with custom protocols, codecs, and transport layers.

---

## 1. The Core 3-Seam Invariant

The WaveX server kernel (`Server<Codec, Router>`) must remain **completely protocol-agnostic**. It is designed around three strict, orthogonal seams:

```
┌────────────────────────────────────────────────────────┐
│                   Server<Codec, Router>                │
│                                                        │
│  1. Transport Seam                                     │
│     handle_connection<AsyncStream>(stream_ptr)         │
│     (TCP, TLS, QuicStream, Unix domain sockets)        │
│                                                        │
│  2. Codec Seam                                         │
│     CustomCodec::parse_stream(buffer, req, consumed)   │
│     CustomCodec::serialize(res)                        │
│                                                        │
│  3. Policy Seam                                        │
│     protocol_traits<CustomCodec>::prepare_response(...)│
│     protocol_traits<CustomCodec>::wants_closing(...)   │
│     protocol_traits<CustomCodec>::alpn_protocol()      │
└────────────────────────────────────────────────────────┘
```

---

## 2. Protocol Leakage: Anti-Patterns Faced & Fixed

### Mistake 1: Codec-Specific Debug Logging in Generic Connection Loops
- **Anti-Pattern**: Placing `if constexpr (is_http3_codec_v<CustomCodec>)` blocks throughout `ServerConnection.ipp` to log `[H3]` handshake status.
- **Problem**: Structurally violates generic programming. Generic server loops should only log protocol-neutral transport lifecycle events (`Connection opened`, `Bytes received`, `Response sent`).
- **Fix**: Removed all codec-specific branches from `ServerConnection.ipp`. Protocol-specific tracing belongs strictly inside the codec's own parsing/encoding methods.

### Mistake 2: Secondary Routers and Protocol Enable Flags on `Server`
- **Anti-Pattern**: Adding `h3_router_`, `http3_enabled_`, `spawn_http3_stream()` directly to `ServerCore.hpp`.
- **Problem**: Causes `Server<http1codec>` to compile and store state for HTTP/3, leaking UDP transport concerns into a TCP server.
- **Fix**: Re-encapsulated protocol composition in `ComposedHttpServer`.

### Mistake 3: Transport Objects and HTTP Response Fields in the Generic Server
- **Anti-Pattern**: `Server` owning a `QuicServer` (plus its mutex and an "insecure QUIC" flag), starting it in `run()` and stopping it in `stop()`; and the connection loop calling `res.status(431)`, `req.header_count()`, `req.query.size()` for every codec.
- **Problem**: A custom binary protocol could not use the server without HTTP-shaped request and response types, and `Server` compiled against QUIC.
- **Fix**:
  - Extra transports go through `network::TransportListener`. The protocol policy supplies one with `protocol_traits<Codec>::make_transport_listener<Host>(host)` (only HTTP/3 does, via `network::quic::QuicTransportListener`). `Server` stores `std::unique_ptr<TransportListener>` and calls `start()`/`stop()`.
  - Kernel-level rejections and limits go through the policy: `exceeds_limits(req, request_limits)`, `write_error(res, protocol_error)`, `set_default_status(res, route_found)`, `write_not_found(res, body, media_type)` (behind `Server::set_not_found*`) and `request_label(req)` (log text). Defaults are no-ops; the HTTP specializations map them to 400/413/431/500 and 200/404.
- **Rule**: if `Server` code must name a codec, a transport implementation or a response field, add a hook to `protocol_traits` instead.
- **Contract kept on purpose**: the loop requires `consumed_bytes()`, `method_type()`, `path()` from the request (codec/router seams) and `is_sent()`, `is_headers_sent()`, `serialize_to()` from the response; these are `static_assert`ed in `handle_connection_impl`.

---

## 3. Multi-Protocol Composition (`ComposedHttpServer`)

When an application needs to serve HTTP/1.1 and HTTP/2 over TCP alongside HTTP/3 over QUIC on the same logical endpoint:
- **`ComposedHttpServer` owns**:
  - `Http2Server server_`: TCP listener handling HTTP/1.1 and HTTP/2 with ALPN negotiation.
  - `QuicServer quic_server_`: UDP listener handling QUIC datagrams and HTTP/3 streams.
- **Unified Routing**:
  - The single `HttpRouter router_` is passed to both listeners.
  - QUIC streams are processed by dispatching to worker threads via `server_.pool()`.
- **Synchronized Shutdown**:
  - Graceful draining (`server.exit()`) stops both the TCP listener and the UDP QUIC listener in lockstep, canceling idle sockets and waiting for in-flight requests.

---

## 4. Policy-Driven Header Advertisement (`Alt-Svc`)

- Protocol advertisement (e.g. `Alt-Svc: h3=":4433"; ma=86400`) must **never** be hard-coded into generic response handlers.
- Injected exclusively via the policy seam:
  ```cpp
  protocol_traits<Codec>::prepare_response(req, res, keep_alive, timeout, remaining, alt_svc_port);
  ```
- If `alt_svc_port > 0`, `protocol_traits<http2codec>` or `protocol_traits<http1codec>` appends the `Alt-Svc` header automatically.

---

## 5. Connection Takeover (Protocol Switch)

WebSocket and WebTransport begin as an HTTP request and then own the connection (HTTP/1.1) or the request
stream (HTTP/3). This is a fourth, optional policy hook, not a kernel feature:

```
handler ──► res.upgrade(fn)                         (websocket::accept / webtransport::accept)
kernel  ──► write response
        ──► protocol_traits<Codec>::wants_takeover(req, res)        (sync: res.has_upgrade() and
              │                                                       101 on HTTP/1.x / 2xx on HTTP/3)
              └─ yes ──► co_await protocol_traits<Codec>::take_over(stream_ptr, req, res, std::string unread)
                           └─ co_await fn(network::AnyStream::wrap(stream_ptr, executor), unread)
                         ──► kernel stops serving, tears the transport down
```

- `network::AnyStream` erases TCP / TLS / `QuicStream` (and adapters such as the HTTP/3 DATA tunnel) behind
  `read_some` / `write` / `shutdown_send` / `cancel` / `close`, with `native<T>()` to recover the concrete type
  (WebTransport needs the `QuicStream` and its connection).
- The kernel's contract grew by nothing: it calls the hooks only `if constexpr` the policy defines them, and
  the synchronous `wants_takeover` keeps coroutine frames off the path of ordinary requests.

---

## 6. Policy-Driven Connections (`serve_connection`)

Some protocols cannot be served one request at a time. HTTP/2 multiplexes streams, applies flow control and
keeps RFC 8441 tunnels open next to ordinary requests, so its policy drives the connection:

```
kernel ──► on_connection_start()            (strip the client preface)
       ──► protocol_traits<Codec>::serve_connection(stream_ptr, buffered, services)   if defined
             └─ http2::server_session: reader (frames, HPACK, flow control)
                                       writer (single frame queue)
                                       one task per stream ──► services.handle(req, res, sink)
                                                                 = Server::process_request()
       ──► otherwise: the sequential loop, which also calls Server::process_request()
```

- `Server::ConnectionServices<Codec, Router>` is the only thing the policy gets from the kernel; it is
  protocol-neutral (memory, state, limits, idle tracking, the request pipeline).
- The kernel still names no protocol; it only checks `if constexpr` for `serve_connection`.
