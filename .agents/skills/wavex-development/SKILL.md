---
name: wavex-development
description: Comprehensive architecture, component map, and development guide for the WaveX modern C++23 backend framework.
---

# WaveX Framework Development Guide

This skill provides essential domain context for developing, extending, and debugging WaveX.

## Subsystem Architecture Map

1. **Base Layer (`include/wavex/Base/`)**:
   - `Request.hpp`: Protocol-agnostic CRTP base class with fluent query/param accessors and `is_multipart()`.
   - `Response.hpp`: Protocol-agnostic CRTP base class with fluent APIs (`status`, `set`, `send`, `json`) and redirect helpers (`redirect`, `permanent_redirect`, `temporary_redirect`).
   - `Chainable.hpp`: C++23 "deducing this" static dispatch mixin (`StaticChain`, `make_chain`, `KeepAlivePolicy`).
   - `MiddleWare.hpp`: Runtime coroutine middleware chains (`run_chain`, `keep_alive`, `sse_stay_active`, `body_limit`).
   - `MimeTypes.hpp`: High-speed binary-searched MIME lookup (`mime_type_from_path`, `mime_type_from_ext`).
   - `Logger.hpp`: Zero-macro levelled logger with `std::source_location` and ANSI colors.
   - `Uri.hpp`, `Url.hpp`: RFC 3986 URI and query string parsers.

2. **Routing Engine (`include/wavex/Engine/`)**:
   - `Router.hpp`: Protocol-agnostic radix tree with RE2 regex (`{id:[0-9]+}`), dynamic `:param`, wildcard `*param`, scoped middlewares, and 404 handler.
   - `HttpRouter.hpp`: HTTP-specific convenience wrapper (`get`, `post`, `put`, `del`, `patch`, `query`).

3. **Server Subsystem (`include/wavex/Server/`)**:
   - `Server.hpp`: Coroutine TCP & TLS 1.3 server (`Server<Codec, RouterType>`), completely protocol-agnostic. Employs the 3-Seam Architecture (Transport Seam via `handle_connection<Stream>`, Codec Seam via `parse_stream`/`serialize`, and Policy Seam via `protocol_traits`). Supports configurable payload ceilings (`max_request_size`) and disk spooling thresholds (`max_memory_buffer`).
   - `TlsConfig.hpp`: TLS 1.3 configuration struct (`cert_file`, `key_file`, `key_password`, `dh_file`, `force_tls13`).
   - `ThreadPool.hpp`: Adaptive Tokio-style work-stealing thread pool with proportional hysteresis scaling.
   - `BlockingPool.hpp`: Dedicated elastic thread pool (`BlockingThreadPool`) for offloading synchronous, CPU-intensive, or legacy blocking tasks.
   - `WorkStealingQueue.hpp`: Per-worker 256-slot ring buffer (`LocalQueue`) and global MPMC overflow queue (`InjectorQueue`).

4. **Async & Offloading Subsystem (`include/wavex/Async/`)**:
   - `SpawnBlocking.hpp`: Tokio-equivalent coroutine awaitable (`co_await wavex::spawn_blocking([=]{ ... })`). Offloads heavy computation/blocking calls to `BlockingThreadPool` and reschedules resumption cleanly on the caller's Asio `io_context` executor with full exception propagation.

5. **Protocol Codecs & Traits (`include/wavex/protos/`)**:
   - `ProtocolTraits.hpp`: Protocol session policy seam (`protocol_traits<Codec>`) answering opening prefaces, persistence, response preparation, and ALPN registration.
   - `http/http1codec.hpp`: Zero-copy HTTP/1.x parser, encoder, chunked decoder, and standard status text mapping (including 301, 302, 303, 304, 307, 308).
   - `http/http2codec.hpp`: RFC 7540 binary framing parser, encoder, and RFC 7541 HPACK compression engine.
   - `http/HttpRequest.hpp`: Concrete request parsing from socket streams (`parse_stream`, `consumed_bytes`), multipart form accessors (`is_multipart`, `multipart`, `file`, `files`), decompression (`decompressed_body`), and disk persistence (`save_body_to_file`).
   - `http/HttpResponse.hpp`: Concrete response with injected write sink for streaming (`write_chunk`, `send_file`), committed state (`is_sent`), and headers sent state (`is_headers_sent`).

6. **Utils Subsystem (`include/wavex/Utils/`, `src/Utils/`)**:
   - `Utils.hpp` (`wavex:utils`): Umbrella header and primary C++ module interface partition for utilities.
   - `AsyncFs.hpp` (`wavex::fs`): Non-blocking file I/O operations (`read_file`, `read_bytes`, `write_file`, `append_file`, `copy_file`, `remove`) built on `spawn_blocking`.
   - `TempFile.hpp` (`wavex:utils_temp_file`): RAII temporary file management (`TempFileGuard`) with atomic move/rename to destination, size tracking, and auto-cleanup.
   - `Compression.hpp` (`wavex:utils_compression`): Zero-overhead Gzip & Deflate memory buffer and stream compression/decompression (`Compressor`, `CompressionFormat`) guarded by CMake definition `WAVEX_HAS_ZLIB`.
   - `Multipart.hpp` (`wavex:utils_multipart`): Complete RFC 7578 multipart/form-data parser, builder, and disk spooler (`MultipartFormData`, `MultipartLimits`, `UploadedFile`, `FormField`).

7. **Client Subsystem (`include/wavex/Client/`)**:
   - `HttpClient.hpp`: Async coroutine client supporting HTTP/1.1 & HTTP/2, plain TCP & TLS 1.3, fluent query builders, JSON, binary bodies, multipart/form-data uploads (`add_field`, `add_file`, `add_file_from_path`), payload compression (`compress`), response decompression (`decompressed_body`), and response saving (`save_to_file`).

## Common Pitfalls & Gotchas

1. **HTTP Body Consumption on Requests without Content-Length**:
   - In `http1codec::extract_body`, requests without `Content-Length` or `Transfer-Encoding` have a body length of 0 (RFC 7230 §3.3.3). Never default to remaining buffer size on requests; doing so swallows pipelined requests into the first request's body.

2. **Status Text Synchronization**:
   - `HttpResponse::serialize_impl()` emits `HTTP/1.1 <code_int> <status_text>`. Whenever `status(code)` is called, `status_text_` must be updated using `Codec::status_text_for(code)`.

3. **Header Case-Insensitivity & Mutation**:
   - `Response::set(name, value)` must search for existing headers case-insensitively and mutate the existing value in-place, rather than appending duplicate keys.

4. **Optional Dependency Header Guards**:
   - When guarding `#include` of optional dependencies (such as `<zlib.h>`), NEVER use `__has_include(...)` with `||`. ALWAYS use CMake-injected defines exclusively:
     ```cpp
     #if defined(WAVEX_HAS_ZLIB) && WAVEX_HAS_ZLIB
     #include <zlib.h>
     #endif
     ```

5. **Deducing-This Forwarding Invariants**:
   - Methods in `base::Request` and `base::Response` using C++23 explicit object parameters (`this Self&& self`) must forward to derived `_impl()` helpers (e.g. `is_multipart_impl()`, `send_impl()`). Calling the same method name directly from base can cause infinite recursion or MSVC template deduction failure.

6. **C++20 Module Export Mirroring**:
   - WaveX provides dual distribution (headers and modules). Any header change must be checked against `src/<Subsystem>/<Component>.ixx`.

7. **Server Must Not Name Specific Codecs**:
   - `Server.hpp` must remain protocol-agnostic. Never branch on `if constexpr (is_http2)` in `Server.hpp`; all protocol connection behavior must query `protocol_traits<Codec>`.

8. **Future Protocols (GraphQL, HTTP/3 QUIC, WebSockets)**:
   - Refer to `.agents/rules/future-protocols-architecture.md` for architectural blueprints.
   - Maintain the 3-seam architecture so new protocols integrate seamlessly when scheduled.

