# WaveX Architectural & Development Invariants

1. **C++20 Module Interface Synchronization**:
   - Whenever any new public class, struct, function, type alias, or template is added or modified in `include/wavex/`, you MUST update the corresponding C++20 module partition in `src/` (`.ixx` files).
   - Ensure all public symbols are explicitly exported via `export namespace wavex::... { using ...; }`.

2. **Zero-VTable & Modern C++ Invariants**:
   - Never introduce virtual functions (`virtual`) in `Request` or `Response` base classes. Use CRTP and C++23 explicit object parameter ("deducing this": `this Self&& self`).
   - Responses must support in-place mutation and zero-copy string views (`std::string_view`) referencing owned buffers where appropriate.
   - Status code mutations must ensure `status_text_` synchronizes with standard RFC reason phrases (`Codec::status_text_for(code)`).

3. **Build & Test Invariants**:
   - **Allowed**: You ARE allowed to compile/build and run tests for the project:
     - Build: `cmake --build --preset fast-dev` (or `cmake --build build/test-profile -j 10`)
     - Test: `ctest --preset run-tests --output-on-failure` (or `ctest --test-dir build/test-profile --output-on-failure`)
   - **Prohibited (No CMake Configure)**: NEVER run CMake configuration commands directly (e.g. `cmake --preset test-profile`, `cmake -B ...`, or changing generator/toolchain cache). The configuration step must ONLY be performed by the user.

4. **Protocol Traits & Server Decoupling (The 3-Seam Architecture)**:
   - `Server<Codec, RouterType>` must remain completely protocol-agnostic. It speaks ONLY to concepts and traits, never directly naming specific codecs (`http1codec`/`http2codec`):
     - **Seam 1 (Transport)**: Single `handle_connection<Stream>()` generic over any `AsyncStream` (plain TCP or TLS 1.3 `ssl::stream`). Handshake happens on the worker pool via `if constexpr (requires { stream.async_handshake(...); })`.
     - **Seam 2 (Codec)**: `parse_stream`, `serialize`, `result`.
     - **Seam 3 (Protocol Traits)**: `wavex::protos::protocol_traits<Codec>` answering opening connection prefaces (`has_connection_preface`, `on_connection_start`), persistence decisions (`keep_alive`), response header setup (`prepare_response`), and ALPN registration (`configure_alpn`).
   - Never embed protocol-specific logic or `if constexpr (is_http2)` inside the generic `Server` class body.

5. **`HttpResponse` Decoupling & Injected Write Sink**:
   - `res.send(...)` strictly means "mark committed" with payload ready. Never perform synchronous socket writes in `send_impl()`.
   - Streaming APIs (`start_chunked()`, `write_chunk()`, `end_chunked()`, `send_file()`) must write through an injected type-erased write sink (`write_sink_fn`), bound per-connection by `Server`.
   - `is_sent_` signals response commitment to middleware chains (`run_chain`) for immediate short-circuiting.
   - `is_headers_sent_` signals whether headers and data have already been flushed directly to the wire via streaming. `Server` writes `res.serialize()` if and only if `!res.is_headers_sent()`.

6. **Future Protocol Extension Invariants (GraphQL, WebSockets, HTTP/3 QUIC)**:
   - **GraphQL**: Operates at the Protocol/Codec layer (`Router<GraphqlProto>` with `graphql_codec`), running over standard HTTP/TLS streams. It specializes `protocol_traits<graphql_codec>` for any custom session behavior.
   - **WebSockets**: Operates as a protocol upgrade over HTTP/1.1; the opening handshake and frame streaming map cleanly to `traits::on_connection_start` and codec framing.
   - **HTTP/3 (QUIC / UDP)**: In QUIC, packet encryption and stream multiplexing are integrated at the UDP connection level; individual virtual QUIC streams (`QuicStream`) do NOT have or need `stream.async_handshake()`. Because `handle_connection<Stream>` uses `requires { stream.async_handshake(...); }`, passing a `QuicStream` automatically evaluates to false, skipping TCP/TLS handshakes and routing directly to QPACK/frame handling via `traits::on_connection_start`.

7. **Zero-Allocation Arena Memory & FlatMap Invariants**:
   - Never use node-based `std::unordered_map` or `std::vector<std::pair<...>>` for per-request key-value structures (route parameters, query parameters, response headers). Use `wavex::base::FlatMap<K, V, InlineCap=16>` to ensure contiguous cache-line storage and zero heap allocation for N <= 16.
   - Case-insensitive search on HTTP headers must be performed using `.find_ci()` and `.insert_or_assign_ci()`.
   - Use `wavex::memory::RequestArena` (per-request monotonic bump allocator with 4KB inline buffer) for request-scoped dynamic allocations. Memory must be reclaimed in O(1) via `arena.release()` at the end of each request lifecycle.
   - Connection stream buffers (`stream_buf`) exceeding 64KB must be shrunk via `shrink_to_fit()` upon emptying. Thread-local slab pools must be trimmable via `server.trim_memory()`.

8. **Resource Protection & Hard Caps (DoS Mitigation)**:
   - Query parameters are hard-capped at 64 (`kMaxQueryParams`). Any query exceeding this cap sets `query_param_overflow_ = true` and must be rejected with `431 Request Header Fields Too Large` in `Server::handle_connection()` before routing.
   - Headers are capped at 100 by default (configurable via `server.set_max_headers(N)` and `server.set_max_query_params(N)`).

9. **`string_view` Lifetime & Safety Contract**:
   - All `std::string_view` instances obtained from `req.param(name)`, `req.query_param(name)`, `req.params`, `req.query`, and `res.header(name)` point into the current request's backing storage (`RequestArena`, `query_decoded_buf_`, or `header_store_`).
   - **In-Turn Usage (Zero-Copy)**: Reading, validating, parsing (`std::from_chars`, JSON parsing), or passing to database queries executed synchronously within the current coroutine turn is completely safe. Use `std::string_view` directly.
   - **Escaping Usage (Owning Copy)**: Crossing coroutine boundaries, offloading to background threads via `spawn_blocking`, caching in global data structures, or storing across request turns MUST make an explicit owning copy (`std::string(req.param("id"))`).

10. **Test Integrity & Invariance**:
    - NEVER modify test assertions, expected output strings, mock response fixtures, or test payloads when debugging test failures unless the user explicitly grants permission and provides the reason.
    - All test failures must be resolved strictly at the root cause within framework implementations (engine, codecs, server, memory architecture).

11. **Constructor Member Initializer Ordering (MSVC C5038 / Clang -Wreorder-ctor)**:
    - Constructor member initializer lists must strictly follow the declaration order of member variables within the class definition.
    - Never omit or reorder members in initializer lists in a way that triggers compiler warnings or masks member dependency order during construction.

12. **Container Pointer Stability & Synchronization for `string_view` Backing Stores**:
    - Never expose `std::string_view` into an incrementally grown `std::vector` without post-mutation view synchronization, as vector reallocation moves small SSO strings and invalidates earlier views.
    - **Incoming Requests (`HttpRequest`)**: Use a single contiguous linear buffer (`query_decoded_buf_`). Decode all query keys/values into this buffer, and populate `query` FlatMap string views *after* buffer finalization.
    - **Outgoing Responses (`HttpResponse`)**: Use a contiguous `std::vector<std::pair<std::string, std::string>>` (`header_store_`), and safely synchronize `headers_` and `headers_views_` after insertions or reallocations. This guarantees complete pointer validity without `std::deque` heap chunk overhead.
