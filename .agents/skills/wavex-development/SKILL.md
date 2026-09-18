---
name: wavex-development
description: Comprehensive architecture, component map, and development guide for the WaveX modern C++23 backend framework.
---

# WaveX Framework Development Guide

This skill provides essential domain context for developing, extending, and debugging WaveX.

## Subsystem Architecture Map

1. **Base Layer (`include/wavex/Base/`)**:
    - `Request.hpp`: Protocol-agnostic CRTP base class with fluent query/param accessors and `is_multipart()`.
    - `Response.hpp`: Protocol-agnostic CRTP base class with fluent APIs (`status`, `set`, `send`, `json`) and redirect
      helpers (`redirect`, `permanent_redirect`, `temporary_redirect`).
    - `Chainable.hpp`: C++23 "deducing this" static dispatch mixin (`StaticChain`, `make_chain`, `KeepAlivePolicy`).
    - `MiddleWare.hpp`: Runtime coroutine middleware chains (`run_chain`, `keep_alive`, `sse_stay_active`,
      `body_limit`).
    - `MimeTypes.hpp`: High-speed binary-searched MIME lookup (`mime_type_from_path`, `mime_type_from_ext`).
    - `Logger.hpp`: Zero-macro levelled logger with `std::source_location` and ANSI colors.
    - `Uri.hpp`, `Url.hpp`: RFC 3986 URI and query string parsers.
    - `FlatMap.hpp`: Cache-line contiguous key-value container (`FlatMap<K, V>`) used for request `params`, `query`, and
      response `headers_`. Backed by a contiguous array of `std::pair<std::string_view, std::string_view>`. Drop-in API
      mirrors `std::map` (`.at()`, `operator[]`, `.contains()`, `.find()`, `begin()`/`end()`). Case-insensitive header
      search via `.find_ci()`. Hard-capped at **64 query params** and **100 headers** — exceeding these limits causes
      `431 Request Header Fields Too Large`.
    - `Memory.hpp`: Per-request arena allocator (`wavex::memory::RequestArena`). Wraps
      `std::pmr::monotonic_buffer_resource` with a **4KB inline buffer** scoped to a single request (not the connection
      lifetime). Chains to a thread-local `std::pmr::unsynchronized_pool_resource` on overflow. `arena.release()`
      reclaims all memory in O(1). Thread-local pool trims via `get_thread_local_pool().release()` on idle.

2. **Routing Engine (`include/wavex/Engine/`)**:
    - `Router.hpp`: Protocol-agnostic radix tree with RE2 regex (`{id:[0-9]+}`), dynamic `:param`, wildcard `*param`,
      scoped middlewares, and 404 handler. Wildcard captures are zero-allocation contiguous string slices
      `std::string_view(w_begin, w_end - w_begin)` guarded by a contiguous path buffer invariant assertion.
    - `HttpRouter.hpp`: HTTP-specific convenience wrapper (`get`, `post`, `put`, `del`, `patch`, `query`).

3. **Server Subsystem (`include/wavex/Server/`)**:
    - `Server.hpp`: Coroutine TCP & TLS 1.3 server (`Server<Codec, RouterType>`), completely protocol-agnostic. Employs
      the 3-Seam Architecture (Transport Seam via `handle_connection<Stream>`, Codec Seam via `parse_stream`/
      `serialize`, and Policy Seam via `protocol_traits`). Configures `TCP_NODELAY` immediately upon socket accept.
      Employs an offset cursor (`stream_buf_consumed`) to amortize `stream_buf` compaction until >= 4096 bytes.
      Supports configurable payload ceilings (`max_request_size`) and disk spooling thresholds (`max_memory_buffer`).
    - `TlsConfig.hpp`: TLS 1.3 configuration struct (`cert_file`, `key_file`, `key_password`, `dh_file`, `force_tls13`).
    - `ThreadPool.hpp`: Adaptive Tokio-style work-stealing thread pool with proportional hysteresis scaling. Hot paths
      (stealing and round-robin dispatch) access an atomic pointer table (`worker_table_`) without `workers_mutex_` lock
      contention. Worker threads hold an `asio::executor_work_guard` to prevent premature context stop and achieve
      microsecond latency via non-blocking `poll()` followed by `run_one_for(100us)` IOCP/epoll wait. Includes fast-path
      burst spill triggers for immediate scaling evaluations.
    - `BlockingPool.hpp`: Dedicated elastic thread pool (`BlockingThreadPool`) for offloading synchronous,
      CPU-intensive, or legacy blocking tasks.
    - `WorkStealingQueue.hpp`: Per-worker 256-slot ring buffer (`LocalQueue`) and global MPMC overflow queue (
      `InjectorQueue`). Uses `InlineTask<64>`: a type-erased, move-only task wrapper with 64-byte SBO aligned to
      `std::max_align_t` (zero heap allocations on the hot dispatch path).

4. **Async & Offloading Subsystem (`include/wavex/Async/`)**:
    - `SpawnBlocking.hpp`: Tokio-equivalent coroutine awaitable (`co_await wavex::spawn_blocking([=]{ ... })`). Offloads
      heavy computation/blocking calls to `BlockingThreadPool` and reschedules resumption cleanly on the caller's Asio
      `io_context` executor with full exception propagation.

5. **Protocol Codecs & Traits (`include/wavex/protos/`)**:
    - `ProtocolTraits.hpp`: Protocol session policy seam (`protocol_traits<Codec>`) answering opening prefaces,
      persistence, response preparation, and ALPN registration.
    - `http/http1codec.hpp`: Zero-copy HTTP/1.x parser, encoder, chunked decoder, and standard status text mapping (
      including 301, 302, 303, 304, 307, 308).
    - `http/http2codec.hpp`: RFC 7540 binary framing parser, encoder, and RFC 7541 HPACK compression engine.
    - `http/HttpRequest.hpp`: Concrete request parsing from socket streams (`parse_stream`, `consumed_bytes`), multipart
      form accessors (`is_multipart`, `multipart`, `file`, `files`), decompression (`decompressed_body`), and disk
      persistence (`save_body_to_file`).
    - `http/HttpResponse.hpp`: Concrete response with injected write sink for streaming (`write_chunk`, `send_file`),
      committed state (`is_sent`), and headers sent state (`is_headers_sent`).

6. **Utils Subsystem (`include/wavex/Utils/`, `src/Utils/`)**:
    - `Utils.hpp` (`wavex:utils`): Umbrella header and primary C++ module interface partition for utilities.
    - `AsyncFs.hpp` (`wavex::fs`): Non-blocking file I/O operations (`read_file`, `read_bytes`, `write_file`,
      `append_file`, `copy_file`, `remove`) built on `spawn_blocking`.
    - `TempFile.hpp` (`wavex:utils_temp_file`): RAII temporary file management (`TempFileGuard`) with atomic move/rename
      to destination, size tracking, and auto-cleanup.
    - `Compression.hpp` (`wavex:utils_compression`): Zero-overhead Gzip & Deflate memory buffer and stream
      compression/decompression (`Compressor`, `CompressionFormat`) guarded by CMake definition `WAVEX_HAS_ZLIB`.
    - `Multipart.hpp` (`wavex:utils_multipart`): Complete RFC 7578 multipart/form-data parser, builder, and disk
      spooler (`MultipartFormData`, `MultipartLimits`, `UploadedFile`, `FormField`).

7. **Client Subsystem (`include/wavex/Client/`)**:
    - `HttpClient.hpp`: Async coroutine client supporting HTTP/1.1 & HTTP/2, plain TCP & TLS 1.3, fluent query builders,
      JSON, binary bodies, multipart/form-data uploads (`add_field`, `add_file`, `add_file_from_path`), payload
      compression (`compress`), response decompression (`decompressed_body`), and response saving (`save_to_file`).

## Common Pitfalls & Gotchas

1. **HTTP Body Consumption on Requests without Content-Length**:
    - In `http1codec::extract_body`, requests without `Content-Length` or `Transfer-Encoding` have a body length of 0 (
      RFC 7230 §3.3.3). Never default to remaining buffer size on requests; doing so swallows pipelined requests into
      the first request's body.

2. **Status Text Synchronization**:
    - `HttpResponse::serialize_impl()` emits `HTTP/1.1 <code_int> <status_text>`. Whenever `status(code)` is called,
      `status_text_` must be updated using `Codec::status_text_for(code)`.

3. **Header Case-Insensitivity & Mutation**:
    - `Response::set(name, value)` must search for existing headers case-insensitively and mutate the existing value
      in-place, rather than appending duplicate keys.

4. **Optional Dependency Header Guards**:
    - When guarding `#include` of optional dependencies (such as `<zlib.h>`), NEVER use `__has_include(...)` with `||`.
      ALWAYS use CMake-injected defines exclusively:
      ```cpp
      #if defined(WAVEX_HAS_ZLIB) && WAVEX_HAS_ZLIB
      #include <zlib.h>
      #endif
      ```

5. **Deducing-This Forwarding Invariants**:
    - Methods in `base::Request` and `base::Response` using C++23 explicit object parameters (`this Self&& self`) must
      forward to derived `_impl()` helpers (e.g. `is_multipart_impl()`, `send_impl()`). Calling the same method name
      directly from base can cause infinite recursion or MSVC template deduction failure.

6. **C++20 Module Export Mirroring**:
    - WaveX provides dual distribution (headers and modules). Any header change must be checked against
      `src/<Subsystem>/<Component>.ixx`.

7. **Server Must Not Name Specific Codecs**:
    - `Server.hpp` must remain protocol-agnostic. Never branch on `if constexpr (is_http2)` in `Server.hpp`; all
      protocol connection behavior must query `protocol_traits<Codec>`.

8. **Future Protocols (GraphQL, HTTP/3 QUIC, WebSockets)**:
    - Refer to `.agents/rules/future-protocols-architecture.md` for architectural blueprints.
    - Maintain the 3-seam architecture so new protocols integrate seamlessly when scheduled.

9. **`string_view` Lifetime Safety Contract**:
    - `req.param(name)`, `req.query[key]`, and `res.get_body()` return `std::string_view` that is valid only within the
      **current request coroutine turn** — until the next `co_await` that can reach `arena.release()`.
    - **Safe (ephemeral use)**: Passing `string_view` to a filter, validator, format conversion (`std::from_chars`), or
      a direct DB query within the same coroutine turn — no copy needed.
    - **Unsafe (escaping use)**: Capturing `string_view` into a `spawn_blocking` lambda, a global/static cache, or any
      data structure with a lifetime beyond the current request. Always convert to `std::string` at the escape boundary:
      `std::string(req.param("id"))`.
    - There is no compiler enforcement. Correctness relies on docstrings, this safety contract, and the developer
      understanding the arena lifecycle.

10. **`FlatMap` Hard Caps — HTTP Protection**:
    - Max query parameters per request: **64** (configurable via `set_max_query_params(N)`).
    - Max headers per request: **100** (configurable via `set_max_headers(N)`).
    - Violations are rejected with `431 Request Header Fields Too Large` before populating `req.query` or `req.params`,
      preventing O(N²) linear scan degeneration.

11. **Idle Memory Trimming**:
    - Each worker thread's `thread_local std::pmr::unsynchronized_pool_resource` retains slab memory after burst
      traffic.
    - The pool releases cached slabs automatically after a configurable idle window (default 30s) by calling
      `get_thread_local_pool().release()`.
    - `stream_buf` is shrunk with `shrink_to_fit()` at end of request if its capacity exceeds 64KB, and it is currently
      empty.
    - `server.trim_memory()` posts explicit `pool.release()` tasks to all worker threads for container/embedded
      deployments.

12. **Vector SSO Reallocation & View Synchronization**:
    - Storing `std::string` inside `std::vector` while exposing `std::string_view` into those strings can cause dangling pointers if the vector reallocates, as short strings (SSO <= 15 bytes on MSVC) move in memory.
    - For incoming requests (`HttpRequest`), decode all query parameters into a single contiguous linear buffer (`query_decoded_buf_`), constructing `query` FlatMap views *after* buffer finalization to eliminate per-key allocations entirely.
    - For outgoing responses (`HttpResponse`), use a contiguous `std::vector<std::pair<std::string, std::string>>` (`header_store_`) and re-synchronize `headers_` and `headers_views_` views immediately after insertions or reallocations to guarantee memory validity without `std::deque` heap chunk overhead.

13. **Asio `io_context` Premature Stopped State in Worker Loops**:
    - When combining Asio with custom task loops (`ThreadPool::worker_loop`), calling `run_one_for` on an `io_context` without outstanding work causes Asio to stop the context. Subsequent calls skip event processing, causing `asio::co_spawn` connection handlers to deadlock.
    - Always maintain an `asio::executor_work_guard` on the worker's `io_context`. Poll ready work non-blocking via `poll()`, and sleep via `run_one_for(100us)` when idle. Reset the work guard prior to calling `io_ctx->stop()`.

14. **Wildcard Path Segment Contiguity Invariant**:
    - Router wildcard captures (`*` or `*name`) rely on pointer arithmetic spanning from the wildcard start segment to the end of the last segment.
    - This invariant requires all segments in the resolution array to be contiguous slices of the same normalized request path buffer.
    - Guard pointer differences with `assert(w_begin <= w_end)`. Never construct resolution segments from separately allocated strings.
