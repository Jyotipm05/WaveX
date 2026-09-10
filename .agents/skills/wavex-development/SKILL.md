---
name: wavex-development
description: Comprehensive architecture, component map, and development guide for the WaveX modern C++23 backend framework.
---

# WaveX Framework Development Guide

This skill provides essential domain context for developing, extending, and debugging WaveX.

## Subsystem Architecture Map

1. **Base Layer (`include/wavex/Base/`)**:
   - `Request.hpp`, `Response.hpp`: Protocol-agnostic CRTP base classes with fluent APIs.
   - `Chainable.hpp`: C++23 "deducing this" static dispatch mixin (`StaticChain`, `make_chain`, `KeepAlivePolicy`).
   - `MiddleWare.hpp`: Runtime coroutine middleware chains (`run_chain`, `keep_alive`, `sse_stay_active`).
   - `MimeTypes.hpp`: High-speed binary-searched MIME lookup (`mime_type_from_path`, `mime_type_from_ext`).
   - `Logger.hpp`: Zero-macro levelled logger with `std::source_location` and ANSI colors.
   - `Uri.hpp`, `Url.hpp`: RFC 3986 URI and query string parsers.

2. **Routing Engine (`include/wavex/Engine/`)**:
   - `Router.hpp`: Protocol-agnostic radix tree with RE2 regex (`{id:[0-9]+}`), dynamic `:param`, wildcard `*param`, scoped middlewares, and 404 handler.
   - `HttpRouter.hpp`: HTTP-specific convenience wrapper (`get`, `post`, `put`, `del`, `patch`, `query`).

3. **Server Subsystem (`include/wavex/Server/`)**:
   - `Server.hpp`: Coroutine TCP & TLS 1.3 server (`Server<Codec, RouterType>`), completely protocol-agnostic. Employs the 3-Seam Architecture (Transport Seam via `handle_connection<Stream>`, Codec Seam via `parse_stream`/`serialize`, and Policy Seam via `protocol_traits`).
   - `TlsConfig.hpp`: TLS 1.3 configuration struct (`cert_file`, `key_file`, `key_password`, `dh_file`, `force_tls13`).
   - `ThreadPool.hpp`: Adaptive Tokio-style work-stealing thread pool with proportional hysteresis scaling.
   - `WorkStealingQueue.hpp`: Per-worker 256-slot ring buffer (`LocalQueue`) and global MPMC overflow queue (`InjectorQueue`).

4. **Protocol Codecs & Traits (`include/wavex/protos/`)**:
   - `ProtocolTraits.hpp`: Protocol session policy seam (`protocol_traits<Codec>`) answering opening prefaces, persistence, response preparation, and ALPN registration.
   - `http/http1codec.hpp`: Zero-copy HTTP/1.x parser, encoder, chunked decoder, and status text mapping.
   - `http/http2codec.hpp`: RFC 7540 binary framing parser, encoder, and RFC 7541 HPACK compression engine.
   - `http/HttpRequest.hpp`: Concrete request parsing from socket streams (`parse_stream`, `consumed_bytes`).
   - `http/HttpResponse.hpp`: Concrete response with injected write sink for streaming (`write_chunk`, `send_file`), committed state (`is_sent`), and headers sent state (`is_headers_sent`).

## Common Pitfalls & Gotchas

1. **HTTP Body Consumption on Requests without Content-Length**:
   - In `http1codec::extract_body`, requests without `Content-Length` or `Transfer-Encoding` have a body length of 0 (RFC 7230 §3.3.3). Never default to remaining buffer size on requests; doing so swallows pipelined requests into the first request's body.

2. **Status Text Synchronization**:
   - `HttpResponse::serialize_impl()` emits `HTTP/1.1 <code_int> <status_text>`. Whenever `status(code)` is called, `status_text_` must be updated using `Codec::status_text_for(code)`.

3. **Header Case-Insensitivity & Mutation**:
   - `Response::set(name, value)` must search for existing headers case-insensitively and mutate the existing value in-place, rather than appending duplicate keys.

4. **C++20 Module Export Mirroring**:
   - WaveX provides dual distribution (headers and modules). Any header change must be checked against `src/<Subsystem>/<Component>.ixx`.

5. **Server Must Not Name Specific Codecs**:
   - `Server.hpp` must remain protocol-agnostic. Never branch on `if constexpr (is_http2)` in `Server.hpp`; all protocol connection behavior must query `protocol_traits<Codec>`.

6. **Future Protocols (GraphQL, HTTP/3 QUIC, WebSockets)**:
   - Refer to `.agents/rules/future-protocols-architecture.md` for architectural blueprints.
   - Do NOT implement these protocols right now; they are future additions. Maintain the 3-seam architecture so they can be integrated seamlessly when scheduled.

