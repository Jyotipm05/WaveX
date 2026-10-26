# Changelog

All notable changes to WaveX are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/), and versions follow [Semantic Versioning](https://semver.org/) (pre-1.0: minor releases may contain breaking changes).

Tagged releases before 0.4.0 (`v0.1.0-alpha` to `v0.3.0-alpha`) are listed under [Releases](https://github.com/Jyotipm05/WaveX/tags).

## [Unreleased] (0.4.0 development)

### Added
- Native HTTP/3 codec, router and server with QPACK, built on a new in-tree QUIC transport (packets, frames, congestion control, loss detection, key update, idle timeout, datagram coalescing).
- `ComposedHttpServer`: one server hosting HTTP/1.1, HTTP/2 and HTTP/3 together; `ServerState` and `ConnectionTracker` for lifecycle management.
- `ConnectionMemoryPool` (per-connection pool) and allocator-aware `HttpRequest` / `HttpResponse` (`std::pmr`), including cross-arena move construction.
- `serialize_into` for HTTP responses, emitting into any `StringSink` without intermediate copies.
- `SipHash-2-4` connection-ID hashing with a process-wide seed; reusable cipher contexts for QUIC packet protection.
- `CHANGELOG.md` and a restructured `docs/` tree.
- GitHub Actions: `ci.yml` (Linux/GCC 14 build + tests on every push and PR), `sanitizers.yml` (TSan and ASan/UBSan nightly and on `dev`), `bench.yml` (manual). All sized for the free 2 vCPU hosted runner; actions are pinned by commit SHA.
- Benchmark harness (`-DWAVEX_BENCH=ON`): `wavex_bench_server`, a dependency-free `wavex_loadgen` (p50/p99/p99.9, idle connections) and `benchmarks/run.sh` with `ci` and `full` tiers.
- Tests for `ConnectionTracker` and for the configurable request header / query-parameter limits.
- Tests for `Server::stop()` with idle keep-alive connections followed by in-process restart, and for elastic scale-down never retiring a worker that still runs connection coroutines.

### Changed
- `ConnectionTracker` uses 16 lock stripes instead of one global mutex.
- Async logger skips the per-record condition-variable notification when the worker is not asleep.
- FetchContent dependencies (asio, abseil, RE2, nlohmann/json) are pinned to commit SHAs; the asio fallback uses `FetchContent_MakeAvailable` (CMake 4 rejects `FetchContent_Populate(<name>)`).
- CTest runs every test under one resource lock so `ctest -j` is safe with the tests' fixed loopback ports, and sets a 120 s timeout.
- `RequestArena` is now a movable RAII handle over a heap-stable `monotonic_buffer_resource`; the connection loop destroys request objects before the arena.
- Query and route-parameter buffers use `std::pmr::string`.
- README split into a short landing page plus guides, architecture, build and reference pages under `docs/`.
- `CONTRIBUTING.md` prerequisites aligned with the supported toolchains (GCC 16+, Clang 18.1+, MSVC 19.44+, CMake 4.0+).

### Changed (performance)
- Accepted TCP sockets are registered with the reactor of the worker that serves them (`ThreadPool::lease_worker()` / `spawn_leased()`, `Server::adopt_on_worker`), instead of every socket's readiness being handled by the single master `io_context` thread. A lease reserves the worker (counts as a live coroutine) so it cannot be retired between accept and connection start. On POSIX the socket is re-registered with `release()`/`assign()`; on Windows IOCP it stays on the master context. Same-machine A/B on the 2 vCPU box (32 active + 1,000 idle, closed loop, 3 rounds): ~19k -> ~30-32k requests/s, p50 ~1.55 ms -> ~0.95 ms, p99 ~2.6-3.8 ms -> ~1.6-2.0 ms.

### Changed (architecture)
- `Server<Codec, Router>` no longer owns, creates or includes any QUIC type. Extra transports are produced by `protocol_traits<Codec>::make_transport_listener` and held as `network::TransportListener` (new `Network/TransportListener.hpp`); the HTTP/3 policy supplies `network::quic::QuicTransportListener` (new `Network/QUIC/QuicListener.hpp`). `ServerQuic.ipp` is gone; `allow_insecure()` is now a transport-neutral flag with an `allow_insecure_transports()` getter. `is_http3_codec_v` was removed (unused).
- The connection loop no longer calls HTTP members. 400/413/431/500 responses, the request header/query limit check and the 200/404 default status go through new `protocol_traits` hooks (`write_error`, `exceeds_limits`, `set_default_status`, with `protocol_error` and `request_limits` types); custom protocols need none of them. Alt-Svc advertisement by default is the policy trait `advertises_alt_svc_by_default`. `Server::set_not_found*()` and the log label of a request use the policy hooks `write_not_found` and `request_label`; the request/response contract the loop still needs is `static_assert`ed.

### Fixed
- Connections beyond the 1024th were dropped: `ConnectionMemoryPool` used `std::pmr::synchronized_pool_resource`, which in libstdc++ takes one `pthread_key` per instance, and Linux allows only 1024 keys, so the constructor threw `EAGAIN`. The pool is now unsynchronized (a connection coroutine never runs concurrently with itself).
- `Server::stop()` is now a full in-process quiesce so the same `Server` can `run()` again without leaking or racing: sockets are cancelled and closed on their owning worker (not from the caller's thread), the reactor is kept alive by a work guard until every connection has drained (bounded at 2 s), and only then are the worker pools stopped. The graceful-shutdown timeout path uses the same drain.
- Elastic scale-down could retire a worker that still ran connection coroutines and strand them; workers now track live coroutines and are only retired when empty.
- ThreadSanitizer-clean test suite (TSan CI job is now strict):
  - `ThreadPool::dispatch()` pushed from arbitrary threads into a worker's single-owner `LocalQueue`, racing the owner's `pop()` and other dispatchers (lost or corrupted tasks). External submissions now go through the mutex-protected injector; local rings are filled only by their owner (stealing).
  - Retired workers were destroyed while peers could still hold a raw pointer to them from the steal loop. They are parked and freed only once no thread is in the steal loop after they were unpublished.
  - `Logger::flush()` could wait forever: the worker notified `cv_flush_` without taking `flush_mutex_`, so the wakeup could fall between the waiter's predicate check and its wait.
  - QUIC acceptor / `QuicServer`: `close()`/`stop()` closed the UDP socket from another thread while the io thread was receiving; the flags are now atomic and socket access is serialized.
  - `Server::stop()` closed the TCP acceptor from the caller's thread; the close now runs on the reactor thread. `Server::is_acceptor_open()` reads an atomic mirror, and the `quic_server_` pointer handoff between `run()` and `stop()` is mutex-guarded (also in `ComposedHttpServer`).
  - `spawn_blocking` released its work guard from the posted completion handler, letting `io_context::run()` return and the caller destroy the context while the worker was still inside `post()`; the worker now releases the guard after `post()` returns.
- Tests are always built with assertions enabled (`-UNDEBUG`), because some asserts wrap the call under test and Release builds silently removed them.
- `Server::set_max_headers()` and `set_max_query_params()` were stored but never enforced; requests over either limit now get `431` (HTTP/1.x; HTTP/2 and HTTP/3 still rely on HPACK/QPACK limits).
- `HttpRequest::set_params` kept a pointer into a vector that was destroyed at the end of its `else` block when a route had more than 32 percent-encoded parameters (use-after-scope).
- Async logger: WARN/ERROR/FATAL headroom was only reserved in the queue, not in the buffer pool, so priority records could be dropped while the worker was still holding popped buffers.
- Missing standard includes in `Logger.hpp` (`<atomic>`, `<thread>`, `<condition_variable>`, `<cstring>`; listed under `#if !defined(_MSC_VER)` because MSVC's headers already pull them in) that failed to compile on GCC; `ClientRequest::method` no longer shadows the `method` type (rejected by GCC 14).
- Flaky tests: logger overflow tests assumed the worker lags the producer, and the chunked-server test raced the listener start-up. The two `example.com` client tests now run only with `WAVEX_TEST_NETWORK=1`.
- `send_file()` no longer blocks a worker thread: open, `stat` and every disk read run on the blocking pool.
- Use-after-release hazard when a request was still alive after `arena.release()` in the 431 path.
- HTTP/3 and QUIC hardening: Content-Length verification, stream-count limits, flow control, crypto-stream reassembly limits, reserved HTTP/2 frame rejection, max field section size.
- Documentation: corrected the `CLI/CLI.hpp` include path, the `-h` (help) short-option clash in the CLI example, the `set_max_request_size` / `set_max_memory_buffer` setter names, and the preset names used for configure, build and test.
