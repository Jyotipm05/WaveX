---
trigger: always_on
---

# WaveX Architectural & Development Invariants

## 1. C++20 Module Interface Synchronization
- Whenever any new public class, struct, function, type alias, or template is added or modified in `include/wavex/`, you MUST update the corresponding C++20 module partition in `src/` (`.ixx` files).
- Ensure all public symbols are explicitly exported via `export namespace wavex::... { using ...; }`.

## 2. Zero-VTable & Modern C++ Invariants
- Never introduce virtual functions (`virtual`) in `Request` or `Response` base classes. Use CRTP and C++23 explicit object parameter ("deducing this": `this Self&& self`).
- Responses must support in-place mutation and zero-copy string views (`std::string_view`) referencing owned buffers where appropriate.
- Status code mutations must ensure `status_text_` synchronizes with standard RFC reason phrases (`Codec::status_text_for(code)`).

## 3. Build & Test Invariants
- **Allowed**: Compile and run tests (`cmake --build --preset fast-dev`, `ctest --preset run-tests --output-on-failure`).
- **Prohibited**: NEVER run CMake configuration commands (`cmake --preset ...`, `cmake -B ...`). See [never-config-cmake.md](file:///d:/programming/Cpp-files/Projects/WaveX/.agents/rules/never-config-cmake.md).

## 4. Protocol Traits & Server Decoupling (The 3-Seam Architecture)
- `Server<Codec, RouterType>` must remain completely protocol-agnostic. It speaks ONLY to concepts and traits, never directly naming specific codecs (`http1codec`/`http2codec`).
  - **Seam 1 (Transport)**: Single `handle_connection<Stream>()` generic over any `AsyncStream` (plain TCP, TLS 1.3 `ssl::stream`, or QUIC).
  - **Seam 2 (Codec)**: `parse_stream`, `serialize`, `result`.
  - **Seam 3 (Protocol Traits)**: `wavex::protos::protocol_traits<Codec>` answering prefaces, keep-alive persistence, response header setup, and ALPN.
- Never embed protocol-specific logic or `if constexpr (is_http2)` inside the generic `Server` class body. See [future-protocols-architecture.md](file:///d:/programming/Cpp-files/Projects/WaveX/.agents/rules/future-protocols-architecture.md).

## 5. `HttpResponse` Decoupling & Injected Write Sink
- `res.send(...)` strictly means "mark committed" with payload ready. Never perform synchronous socket writes in `send_impl()`.
- Streaming APIs (`start_chunked()`, `write_chunk()`, `end_chunked()`, `send_file()`) must write through an injected type-erased write sink (`write_sink_fn`), bound per-connection by `Server`.
- `is_sent_` signals response commitment to middleware chains (`run_chain`) for immediate short-circuiting.
- `is_headers_sent_` signals whether headers and data have already been flushed directly to the wire via streaming. `Server` writes `res.serialize()` if and only if `!res.is_headers_sent()`.

## 6. Zero-Allocation Arena Memory & FlatMap Invariants
- Never use node-based `std::unordered_map` or `std::vector<std::pair<...>>` for per-request key-value structures (route parameters, query parameters, response headers). Use `wavex::base::FlatMap<K, V, InlineCap=16>` for contiguous cache-line storage and zero heap allocation for N <= 16.
- Case-insensitive search on HTTP headers must be performed using `.find_ci()` and `.insert_or_assign_ci()`.
- Use `wavex::memory::RequestArena` (per-request monotonic bump allocator with 4KB inline buffer) for request-scoped dynamic allocations. Memory must be reclaimed in O(1) via `arena.release()` at the end of each request lifecycle.
- Connection stream buffers (`stream_buf`) exceeding 64KB must be shrunk via `shrink_to_fit()` upon emptying. Thread-local slab pools must be trimmable via `server.trim_memory()`.

## 7. Resource Protection & Hard Caps (DoS Mitigation)
- Query parameters are hard-capped at 64 (`kMaxQueryParams`). Any query exceeding this cap sets `query_param_overflow_ = true` and must be rejected with `431 Request Header Fields Too Large` in `Server::handle_connection()` before routing.
- Headers are capped at 100 by default (configurable via `server.set_max_headers(N)` and `server.set_max_query_params(N)`).

## 8. `string_view` Lifetime & Safety Contract
- All `std::string_view` instances obtained from `req.param(name)`, `req.query_param(name)`, `req.params`, `req.query`, and `res.header(name)` point into the current request's backing storage (`RequestArena`, `query_decoded_buf_`, or `header_store_`).
- **In-Turn Usage (Zero-Copy)**: Reading, validating, parsing (`std::from_chars`, JSON parsing), or passing to database queries executed synchronously within the current coroutine turn is completely safe. Use `std::string_view` directly.
- **Escaping Usage (Owning Copy)**: Crossing coroutine boundaries, offloading to background threads via `spawn_blocking`, caching in global data structures, or storing across request turns MUST make an explicit owning copy (`std::string(req.param("id"))`).

## 9. Container Pointer Stability & Synchronization for `string_view` Backing Stores
- Never expose `std::string_view` into an incrementally grown `std::vector` without post-mutation view synchronization, as vector reallocation moves small SSO strings and invalidates earlier views.
- **Incoming Requests (`HttpRequest`)**: Use a single contiguous linear buffer (`query_decoded_buf_`). Decode all query keys/values into this buffer, and populate `query` FlatMap string views *after* buffer finalization.
- **Outgoing Responses (`HttpResponse`)**: Use a contiguous `std::vector<std::pair<std::string, std::string>>` (`header_store_`), and safely synchronize `headers_` and `headers_views_` after insertions or reallocations. This guarantees complete pointer validity without `std::deque` heap chunk overhead.

## 10. Router Wildcard Pointer Arithmetic Invariant
- When capturing wildcard routes (`*` or `*name`), path segments must be contiguous slices of the single normalized request path buffer.
- Pointer arithmetic `(segments.back().data() + segments.back().size()) - segments[depth].data()` must be guarded with `assert(w_begin <= w_end)`.
- Never construct path segments from individually allocated `std::string` objects.

## 11. Per-Request Allocation Boundaries
- `FlatMap<K, V, 16>` handles path params, query parameters, and response headers inline with zero heap allocation for N <= 16.
- Never instantiate `wavex::memory::RequestArena` in coroutine connection loops unless request/response structures are explicitly wired to consume its `pmr::memory_resource*`, as an unused 4KB arena bloats the coroutine frame.

## 12. HTTP/1.1 Message Framing & Client Response Completion
- `HttpClient` must never read until TCP EOF in an unbounded loop when exchanging HTTP/1.1 messages with known framing. It must evaluate `parser::parse_response` as chunks arrive and exit the read loop immediately once `result::success` is achieved.
- In `http1codec::extract_body`, when `Content-Length` (`cl`) is present, `buffer.size() - cursor < content_length` MUST evaluate to `result::incomplete` for both requests and responses. Returning `result::success` with partial body truncates responses and breaks stream framing.
- Status codes `1xx`, `204` (No Content), and `304` (Not Modified) have no message body (RFC 7230 §3.3.3 / RFC 9112 §6.3); `parse_response` must finalize them immediately with `bytes_consumed = cursor` and `body = ""`.

## 13. Test Integrity & Invariance
- NEVER modify test assertions, expected output strings, mock response fixtures, or test payloads when debugging test failures unless the user explicitly grants permission and provides the reason.
- All test failures must be resolved strictly at the root cause within framework implementations (engine, codecs, server, memory architecture).

## 14. Associated Rule References
- **Class / Struct Layout & Minimum Padding**: See [class-struct-layout.md](file:///d:/programming/Cpp-files/Projects/WaveX/.agents/rules/class-struct-layout.md).
- **Asio Sockets & Coroutine Lifecycle**: See [asio-socket-lifecycle.md](file:///d:/programming/Cpp-files/Projects/WaveX/.agents/rules/asio-socket-lifecycle.md).
- **Optional Dependency Header Guards**: See [optional-dependency-guards.md](file:///d:/programming/Cpp-files/Projects/WaveX/.agents/rules/optional-dependency-guards.md).
- **Future Protocol Architecture (GraphQL, WebSockets, QUIC)**: See [future-protocols-architecture.md](file:///d:/programming/Cpp-files/Projects/WaveX/.agents/rules/future-protocols-architecture.md).
