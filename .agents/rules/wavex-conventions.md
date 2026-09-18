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

13. **Asio `io_context` Lifecycle in Custom Worker Loops**:
    - When embedding an `asio::io_context` alongside custom task queues (e.g. work-stealing rings in `ThreadPool`), NEVER call `run()`, `run_one()`, or `run_one_for()` without an active `asio::executor_work_guard`.
    - Without a work guard, running out of ready work immediately transitions `io_context` into the `stopped()` state, permanently dropping subsequent `asio::co_spawn` tasks and causing server deadlocks.
    - Use `io_ctx->poll()` to drain ready handlers with 0μs latency, and `io_ctx->run_one_for(100us)` with an active `work_guard` to sleep inside the OS kernel (IOCP/epoll) when idle.
    - Always call `work_guard.reset()` before `io_ctx->stop()` during pool shutdown or thread decommissioning.

14. **Router Wildcard Pointer Arithmetic Invariant**:
    - When capturing wildcard routes (`*` or `*name`), path segments must be contiguous slices of the single normalized request path buffer.
    - Pointer arithmetic `(segments.back().data() + segments.back().size()) - segments[depth].data()` must be guarded with `assert(w_begin <= w_end)`.
    - Never construct path segments from individually allocated `std::string` objects.

15. **Per-Request Allocation Boundaries**:
    - `FlatMap<K, V, 16>` handles path params, query parameters, and response headers inline with zero heap allocation for N <= 16.
    - Never instantiate `wavex::memory::RequestArena` in coroutine connection loops unless request/response structures are explicitly wired to consume its `pmr::memory_resource*`, as an unused 4KB arena bloats the coroutine frame.

16. **HTTP/1.1 Message Framing & Client Response Completion**:
    - `HttpClient` must never read until TCP EOF in an unbounded loop when exchanging HTTP/1.1 messages with known framing. It must evaluate `parser::parse_response` as chunks arrive and exit the read loop immediately once `result::success` is achieved.
    - In `http1codec::extract_body`, when `Content-Length` (`cl`) is present, `buffer.size() - cursor < content_length` MUST evaluate to `result::incomplete` for both requests and responses. Returning `result::success` with partial body truncates responses and breaks stream framing.
    - Status codes `1xx`, `204` (No Content), and `304` (Not Modified) have no message body (RFC 7230 §3.3.3 / RFC 9112 §6.3); `parse_response` must finalize them immediately with `bytes_consumed = cursor` and `body = ""`.

17. **Domainless IP Resolution & TCP Socket Options**:
    - When connecting to an IP literal (e.g. `127.0.0.1`, `::1`), never invoke `resolver.async_resolve()`. Directly construct endpoint sequences via `asio::ip::tcp::resolver::results_type::create(endpoint, host, port_str)`. Calling `getaddrinfo` on IP literals introduces thread scheduling latency and NetBIOS/LLMNR stalls on Windows.
    - Both server-accepted and client-initiated TCP sockets must enable `TCP_NODELAY` (`no_delay(true)`) to prevent Nagle's algorithm and 40–200ms delayed-ACK penalties from deadlocking ping-pong localhost exchanges.

18. **Graceful TCP Teardown vs. Connection Abort**:
    - Server-side connection termination must use `asio::ip::tcp::socket::shutdown_send` (`SD_SEND` / `SHUT_WR`), not `shutdown_both`. Calling `shutdown_both` immediately followed by `close()` instructs Winsock to reject subsequent incoming packets (including client ACKs or FINs), causing Winsock to issue a TCP RST packet and abort in-flight response transmission.

19. **Asio Async Operation Buffer Lifetime (Temporary vs. Coro-Frame Lvalue)**:
    - NEVER pass temporary `std::string` expressions directly into `asio::buffer()` inside asynchronous calls (`co_await asio::async_write(stream, asio::buffer(res.serialize()), ...)`).
    - `asio::buffer()` holds a raw memory pointer without ownership. When an asynchronous operation suspends, temporary strings in the expression may be destroyed while the OS kernel (Windows IOCP / `WSASend` or Linux epoll) is actively transmitting the buffer, leading to memory corruption or intermittent `0xC0000005` SegFaults.
    - Always pin serialized output to a named variable on the coroutine frame:
      ```cpp
      std::string wire_resp = res.serialize();
      co_await asio::async_write(stream, asio::buffer(wire_resp), asio::use_awaitable);
      ```

20. **Connection Lifetime & Thread-Safe Socket Registry (`std::weak_ptr` vs. Raw Reference)**:
    - In socket tracking and graceful shutdown registries (`ConnectionTracker`), NEVER capture raw socket references (`[&lowest_sock]`) in cancellation or closure callbacks.
    - If a connection coroutine completes and exits while a server stop or force-close sequence executes concurrently on another thread, invoking `lowest_sock.close()` on a deallocated socket causes a fatal use-after-free SegFault.
    - Connection streams must be managed via `std::shared_ptr<Stream>` in `handle_connection` and captured via `std::weak_ptr<Stream>` by value in tracker callbacks. Checking `if (auto s = weak_stream.lock())` guarantees the socket remains alive for the duration of the cancellation/close call, or safely no-ops if already closed.

21. **Server Graceful Drain, Deadlock Immunity & Test Signal Isolation**:
    - **Idle Keep-Alive Cancellation**: When initiating shutdown (`server.exit()`, `ShutdownEvent`), the server must proactively cancel idle sockets waiting on empty buffers (`cancel_all_idle()`) to prevent draining hangs.
    - **Worker Thread Deadlock Immunity**: During programmatic shutdown, the final shutdown step (`finish_shutdown()`) must be posted to `master_io_` rather than calling `pool_.stop_pool()` directly from inside a worker thread, ensuring worker threads never attempt to join themselves.
    - **Response Stamping**: In-flight requests finishing during shutdown must have their responses stamped with `Connection: close`.
    - **Test Signal Isolation**: Automated unit tests using loopback test servers must configure `server.enable_signal_handling(false)` to prevent background signal registration from interfering with the test runner's global signal table.
