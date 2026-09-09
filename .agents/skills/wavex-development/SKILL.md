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
   - `Server.hpp`: Coroutine TCP & TLS 1.3 server with persistent stay-active loop and Asio steady timer timeouts.
   - `TlsConfig.hpp`: TLS 1.3 configuration struct (`cert_file`, `key_file`, `key_password`, `dh_file`, `force_tls13`).
   - `ThreadPool.hpp`: Adaptive Tokio-style work-stealing thread pool with proportional hysteresis scaling.
   - `WorkStealingQueue.hpp`: Per-worker 256-slot ring buffer (`LocalQueue`) and global MPMC overflow queue (`InjectorQueue`).

4. **Protocol Codecs (`include/wavex/protos/http/`)**:
   - `http1codec.hpp`: Zero-copy HTTP/1.x parser, encoder, chunked decoder, and status text mapping.
   - `HttpRequest.hpp`: Concrete request parsing from socket streams (`parse_stream`, `consumed_bytes`).
   - `HttpResponse.hpp`: Concrete response with socket writing, chunked streaming, and keep-alive headers.

## Common Pitfalls & Gotchas

1. **HTTP Body Consumption on Requests without Content-Length**:
   - In `http1codec::extract_body`, requests without `Content-Length` or `Transfer-Encoding` have a body length of 0 (RFC 7230 §3.3.3). Never default to remaining buffer size on requests; doing so swallows pipelined requests into the first request's body.

2. **Status Text Synchronization**:
   - `HttpResponse::serialize_impl()` emits `HTTP/1.1 <code_int> <status_text>`. Whenever `status(code)` is called, `status_text_` must be updated using `Codec::status_text_for(code)`.

3. **Header Case-Insensitivity & Mutation**:
   - `Response::set(name, value)` must search for existing headers case-insensitively and mutate the existing value in-place, rather than appending duplicate keys.

4. **C++20 Module Export Mirroring**:
   - WaveX provides dual distribution (headers and modules). Any header change must be checked against `src/<Subsystem>/<Component>.ixx`.
