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
    - `Logger.hpp`: Zero-macro leveled logger with `std::source_location` and ANSI colors.
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
    - `Event.hpp`: Generic C++23 pub-sub event architecture (`Event<Args...>`, `EventBus`, `Subscription`, `ShutdownEvent`).
      Multicast signal dispatch with snapshot isolation, RAII subscriptions (`sub.unsubscribe()`, `sub.detach()`), and
      `mutable std::mutex` in `EventBus` allowing `subscriber_count() const`.

2. **Routing Engine (`include/wavex/Engine/`)**:
    - `Router.hpp`: Protocol-agnostic radix tree with RE2 regex (`{id:[0-9]+}`), dynamic `:param`, wildcard `*param`,
      scoped middlewares, and 404 handler. Wildcard captures are zero-allocation contiguous string slices
      `std::string_view(w_begin, w_end - w_begin)` guarded by a contiguous path buffer invariant assertion.
    - `HttpRouter.hpp`: HTTP-specific convenience wrapper (`get`, `post`, `put`, `del`, `patch`, `query`). Aliases
      `Http1Router`, `Http2Router`, and `Http3Router`.

3. **Server Subsystem (`include/wavex/Server/`)**:
    - `Server.hpp`: Coroutine TCP & TLS 1.3 server (`Server<Codec, RouterType>`), completely protocol-agnostic. Employs
      the 3-Seam Architecture (Transport Seam via `handle_connection<Stream>`, Codec Seam via `parse_stream`/
      `serialize`, and Policy Seam via `protocol_traits`). Configures `TCP_NODELAY` immediately upon socket accept.
      Employs an offset cursor (`stream_buf_consumed`) to amortize `stream_buf` compaction until >= 4096 bytes.
      Supports configurable payload ceilings (`max_request_size`) and disk spooling thresholds (`max_memory_buffer`).
      Features atomic `ServerState` (`Stopped`, `Running`, `ShuttingDown`), type-erased `ConnectionTracker` for thread-safe
      socket lifecycle management, proactive idle cancellation (`cancel_all_idle()`), and graceful in-flight request
      drain (`server.exit()`, `server.shutdown()`, `attach_shutdown_event()`). Supports complete server restartability
      across `run()` / `exit()` lifecycles without process termination. Concrete server aliases include `Http1Server`,
      `Http2Server`, `Http3Server`, and multi-protocol orchestrator `ComposedHttpServer`.
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
    - `http/http3codec.hpp`: RFC 9114 HTTP/3 binary framing parser and encoder (`http3codec`), RFC 9204 QPACK encoder/decoder,
      static table lookup, literal field section processing, and VarInt framed streams. Provides `Http3Request`,
      `Http3Response`, and `Http3Router`.
    - `http/HttpRequest.hpp`: Concrete request parsing from socket streams (`parse_stream`, `consumed_bytes`), multipart
      form accessors (`is_multipart`, `multipart`, `file`, `files`), decompression (`decompressed_body`), and disk
      persistence (`save_body_to_file`). Concrete specializations include `Http1Request`, `Http2Request`, and `Http3Request`.
    - `http/HttpResponse.hpp`: Concrete response with injected write sink for streaming (`write_chunk`, `send_file`),
      committed state (`is_sent`), and headers sent state (`is_headers_sent`). Concrete specializations include
      `Http1Response`, `Http2Response`, and `Http3Response`.

6. **Network Subsystem (`include/wavex/Network/QUIC/`, `src/Network/QUIC/`)**:
    - Modular architecture split across 13 headers and 10 implementation files:
      - `QuicConstants.hpp`: RFC 9000/9001 limits, constants, and packet types (`PacketType`).
      - `VarInt.hpp`, `VarInt.cpp`: RFC 9000 §16 62-bit variable-length integer encoding/decoding.
      - `ConnectionId.hpp`, `ConnectionId.cpp`: Connection ID handling with boundary validation (0–20 bytes).
      - `QuicFrames.hpp`, `QuicFrames.cpp`: Type-safe `std::variant<...>` framing for all RFC 9000 frame types.
      - `QuicPacket.hpp`, `QuicPacket.cpp`: Header packing/unpacking and short/long form parsing.
      - `QuicCrypto.hpp`, `QuicCrypto.cpp`: RFC 9001 AEAD (AES-128-GCM) packet protection, header protection (AES-128-ECB), and HKDF secret derivation.
      - `CongestionControl.hpp`: RFC 9002 NewReno congestion control and RTT estimator (`RttStats`).
      - `QuicStream.hpp`, `QuicStream.cpp`: Per-stream offset reassembly buffer, flow control, and `AsyncStream` concept compliance.
      - `QuicConnection.hpp`, `QuicConnection.cpp`: Core connection state machine, packet loss tracking, PTO, and TLS handshake integration.
      - `QuicServer.hpp`, `QuicServer.cpp`: UDP master listener, CID dispatching, and connection lifecycle management.
      - `QuicClient.hpp`, `QuicClient.cpp`: Client-side QUIC endpoint and handshake initiator.
      - `QuicSocket.hpp`, `QuicSocket.cpp`: Asio coroutine stream socket interface and acceptor bridge.
      - `QUIC.hpp`: Master aggregator forwarding header.

7. **Utils Subsystem (`include/wavex/Utils/`, `src/Utils/`)**:
    - `Utils.hpp` (`wavex:utils`): Umbrella header and primary C++ module interface partition for utilities.
    - `AsyncFs.hpp` (`wavex::fs`): Non-blocking file I/O operations (`read_file`, `read_bytes`, `write_file`,
      `append_file`, `copy_file`, `remove`) built on `spawn_blocking`.
    - `TempFile.hpp` (`wavex:utils_temp_file`): RAII temporary file management (`TempFileGuard`) with atomic move/rename
      to destination, size tracking, and auto-cleanup.
    - `Compression.hpp` (`wavex:utils_compression`): Zero-overhead Gzip & Deflate memory buffer and stream
      compression/decompression (`Compressor`, `CompressionFormat`) guarded by CMake definition `WAVEX_HAS_ZLIB`.
    - `Multipart.hpp` (`wavex:utils_multipart`): Complete RFC 7578 multipart/form-data parser, builder, and disk
      spooler (`MultipartFormData`, `MultipartLimits`, `UploadedFile`, `FormField`).

8. **Client Subsystem (`include/wavex/Client/`)**:
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

7. **Server Must Not Name Specific Codecs & 3-Seam Decoupling**:
    - `Server.hpp` must remain strictly protocol-agnostic. Never branch on `if constexpr (is_http2)` or `is_http3` in `Server.hpp` or `ServerConnection.ipp`.
    - All protocol connection behavior must query `protocol_traits<Codec>`.
    - `Server<Codec, Router>` must never hold secondary protocol routers (e.g. `h3_router_`), protocol enable flags (`http3_enabled_`), or secondary dispatch methods (`handle_http3_connection`).
    - Protocol advertisement headers (e.g. RFC 9114 `Alt-Svc: h3=":4433"; ma=86400`) must be injected exclusively via `protocol_traits<Codec>::prepare_response(...)`.
    - Multi-protocol concurrency (running HTTP/1.1 & HTTP/2 over TCP alongside HTTP/3 over QUIC on the same port) must be managed exclusively through `ComposedHttpServer`.

8. **Future Protocols (GraphQL, WebSockets)**:
    - Refer to `.agents/rules/future-protocols-architecture.md` for architectural blueprints.
    - Native HTTP/3 (RFC 9114, RFC 9204) over QUIC (RFC 9000, RFC 9001) is fully implemented and verified.
    - Maintain the 3-seam architecture so remaining future protocols (GraphQL, WebSockets) integrate seamlessly when scheduled.

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

15. **HTTP/1.1 Response Read Completion**:
    - Never implement client read loops that blindly wait for EOF (`while (true) { stream.async_read_some(...); if (read_ec) break; }`).
    - Parse framing (`http1codec::parser::parse_response`) as bytes arrive. When `Content-Length` bytes are received, the chunked terminal `0\r\n\r\n` is reached, or a `204`/`304`/`1xx` status is parsed, break immediately. Waiting for EOF causes clients to hang indefinitely when connections stay open or FINs are delayed.

16. **Direct IP Literal Resolution**:
    - Avoid invoking Asio's resolver (`resolver.async_resolve`) when the target host is an IP literal (`127.0.0.1`, `::1`). Construct endpoint sequences directly via `asio::ip::tcp::resolver::results_type::create(endpoint, host, port_str)` to eliminate OS resolver thread dispatch and NetBIOS/LLMNR lookup latency on Windows.

17. **Graceful Socket Shutdown via `shutdown_send`**:
    - In TCP servers, terminate connections using `stream.shutdown(shutdown_send)` before `close()`. Using `shutdown_both` aborts incoming packet reception, prompting Windows Winsock to reset the connection (TCP RST) upon receiving the client's ACK or FIN.

18. **Dangling Buffers in `co_await asio::async_write`**:
    - `asio::buffer()` takes a raw pointer/reference and does NOT own or copy data. Never pass temporary `std::string` expressions directly into `asio::buffer()` in asynchronous calls (`co_await asio::async_write(stream, asio::buffer(res.serialize()), ...)`).
    - When `async_write` suspends the coroutine, the temporary string can be destroyed while the OS kernel (Windows IOCP / `WSASend` or Linux epoll) is actively transmitting the buffer, causing intermittent heap corruption or `0xC0000005` SegFaults.
    - Always pin serialized output to a named variable on the coroutine frame (`std::string wire = res.serialize(); co_await asio::async_write(stream, asio::buffer(wire), ...);`).

19. **Socket Use-After-Free in Multi-Threaded Connection Tracking**:
    - In connection registries (`ConnectionTracker`), never capture raw socket references (`[&lowest_sock]`) in cancellation or closure callbacks.
    - If a connection coroutine completes and exits while a server stop or force-close sequence executes concurrently on another thread, invoking `lowest_sock.close()` on a deallocated socket causes a fatal use-after-free SegFault.
    - Manage connection streams via `std::shared_ptr<Stream>` in `handle_connection` and capture `std::weak_ptr<Stream>` by value in tracker callbacks. Checking `if (auto s = weak_stream.lock())` guarantees the socket remains alive for the duration of the cancellation/close call, or safely no-ops if already closed.

20. **Worker Thread Self-Join Deadlock on `server.exit()`**:
    - If a route handler invokes `server.exit()` on a worker thread and attempts to shut down the pool synchronously, the worker thread deadlocks trying to `join()` itself.
    - Always post the final shutdown step (`finish_shutdown()`) to `master_io_` so that the main thread coordinates thread pool joining.

21. **Unit Test Signal Guard Isolation**:
    - Automated unit tests running multiple short-lived server instances concurrently or sequentially can conflict over the process's OS signal table (`SIGINT`/`SIGTERM`).
    - Test servers should always configure `server.enable_signal_handling(false)` to ensure clean test isolation.

22. **MinGW Winsock Missing Link Libraries (`ws2_32`, `mswsock`)**:
    - Under MinGW GCC, GNU `ld` ignores MSVC's `#pragma comment(lib, "ws2_32.lib")` auto-linking pragmas.
    - Always ensure `target_link_libraries(wavex PUBLIC ws2_32 mswsock)` is present under `if (WIN32)` in `CMakeLists.txt`.

23. **Header-Polluting `ASIO_USE_TS_EXECUTOR_AS_DEFAULT` causing MSVC `C2371`**:
    - Defining `ASIO_USE_TS_EXECUTOR_AS_DEFAULT` in headers pollutes downstream translation units. If an earlier header forward-declares `class any_completion_executor;`, a subsequent macro definition attempts to define it as `typedef executor any_completion_executor;`, producing `error C2371: 'asio::any_completion_executor': redefinition; different basic types`.
    - Never define this macro; use modern C++20 Asio defaults.

24. **MinGW GCC C++20 Module Assembly Collision on PE/COFF (GCC PR 98718, ISO P2808R0)**:
    - GCC's `-fmodules-ts` on Windows duplicates unnamed-namespace symbols from the GMF when assembling partition aggregations, yielding `Error: symbol '...queryE' is already defined`.
    - Always respect the `WAVEX_USE_MODULE=OFF` setting on MinGW builds, consuming WaveX through `<wavex/wavex.hpp>`.

25. **Header AST Bloat & MSVC Front-End ParseTree C1001 Crash**:
    - Inlining large non-template functions into header files can trigger MSVC Front-End AST buffer exhaustion (`fatal error C1001` in `ParseTree...`, VS Developer Community #11155591).
    - Always place non-template implementations into `.cpp` files in `src/` rather than defining them entirely in `include/wavex/`.

26. **Unsupported Pre-C++23 Compilers (GCC < 16, Clang < 18.1, MSVC < 19.44)**:
    - As specified in `README.md`, attempting to compile WaveX on pre-baseline compilers (GCC < 16, Clang < 18.1, or MSVC < 19.44) is unsupported and fails due to missing C++23 explicit object parameter ("deducing this", P0847R7), missing `<print>` (P2093R14), or module partition regressions.

27. **QUIC TLS Transport Parameter Lifetime (`SSL_set_quic_tls_transport_params`)**:
    - The OpenSSL / BoringSSL QUIC API (`SSL_set_quic_tls_transport_params`) registers a non-owning raw pointer to encoded transport parameters without copying them.
    - The underlying buffer is read asynchronously during TLS handshake execution (`SSL_do_handshake()`).
    - Never store transport parameters in stack-local or temporary variables. On Windows under MSVC Debug CRT, stack deallocations overwrite memory with `0xDD` ("dead land"), causing BoringSSL to abort the handshake with `PROTOCOL_VIOLATION: Unknown transport parameter 0x1ddddddddddddddd`.
    - Always bind encoded transport parameters to the lifetime of the connection object (`local_transport_params_` in `QuicConnection`).

28. **QUIC Stream Demultiplexing & Peer Unidirectional Stream Drain (RFC 9000 §2.1 & RFC 9114 §6.2)**:
    - In QUIC, stream IDs encode the stream initiator and direction via the lowest 2 bits:
      - `(sid & 0x03) == 0x00`: Client-initiated bidirectional (HTTP/3 request stream).
      - `(sid & 0x03) == 0x02`: Client-initiated unidirectional (Peer Control or QPACK stream).
      - `(sid & 0x03) == 0x03`: Server-initiated unidirectional (Server Control Stream 3, QPACK streams 7 and 11).
    - Servers must never treat client unidirectional streams (`0x02`) as HTTP request streams or attempt to write HTTP responses to them; doing so violates RFC 9000 §2.1 (writing to a unidirectional stream opened by the peer is a fatal stream state error) and stalls clients like `curl --http3`. Peer unidirectional streams must be drained and processed asynchronously.

29. **HTTP/3 Server Unidirectional Control & QPACK Streams**:
    - Per RFC 9114 §6.2, both endpoints must open a control stream and send a `SETTINGS` frame (`0x04`) as the very first frame.
    - WaveX servers must immediately open Stream 3 (`0x00` VarInt control stream type followed by `SETTINGS`), Stream 7 (`0x02` QPACK encoder), and Stream 11 (`0x03` QPACK decoder) upon handshake completion (`SSL_do_handshake == 1`) after emitting `HANDSHAKE_DONE`.

30. **MSVC Debug C++20 Module `<deque>` Proxy Allocator Incompatibility**:
    - In MSVC Debug builds (`/MDd`), `std::deque` constructs internal proxy allocators (`std::allocator<std::_Container_proxy>`). When referenced inside a C++20 module partition (e.g. `http3codec.ixx`), AST instantiation bugs trigger `error C2665: 'std::allocator<std::_Container_proxy>::allocator': no overloaded function could convert all the argument types`.
    - **Rule**: Inside C++20 module partitions, use `std::vector` instead of `std::deque` for dynamic FIFO tables, using `entries_.erase(entries_.begin())` for eviction.

31. **QUIC Header Protection Offset Calculation & Uninitialized `pn_offset`**:
    - `PacketHeader::pn_offset` is not provided by the caller when encrypting with `protect_packet`. It MUST be computed as `const std::size_t pn_offset = header_bytes.size() - hdr.packet_number_len` after packing the unmasked header.
    - Masking at `hdr.pn_offset + i` when `pn_offset` is 0 corrupts the leading header bytes instead of the packet number field, breaking subsequent AAD verification.

32. **QUIC Long Header `Length` Field Invariant**:
    - In RFC 9000 §17.2, long header packets (Initial, Handshake, 0-RTT) require a `Length` VarInt specifying the length of the packet number plus payload ciphertext plus the 16-byte AEAD authentication tag.
    - `protect_packet` must set `hdr.length = plaintext.size() + 16 + hdr.packet_number_len` prior to packing `header_bytes`.

33. **OpenSSL AES-128-ECB Header Protection Zero Padding**:
    - OpenSSL `EVP_CIPHER_CTX` defaults to PKCS#7 padding. Header protection requires raw 16-byte block cipher operations.
    - Both `protect_packet` and `unprotect_packet` must invoke `EVP_CIPHER_CTX_set_padding(hp_ctx, 0)` immediately after `EVP_EncryptInit_ex`.

34. **ConnectionId Hex Validation Bounds**:
    - `ConnectionId::from_hex` must reject odd-length strings, strings with non-hex characters, and lengths exceeding `MAX_CONNECTION_ID_LEN` (20 bytes), cleanly returning `ConnectionId{}` rather than partial or malformed IDs.

