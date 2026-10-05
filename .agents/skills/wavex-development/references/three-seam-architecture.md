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
