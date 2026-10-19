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

### Changed
- `RequestArena` is now a movable RAII handle over a heap-stable `monotonic_buffer_resource`; the connection loop destroys request objects before the arena.
- Query and route-parameter buffers use `std::pmr::string`.
- README split into a short landing page plus guides, architecture, build and reference pages under `docs/`.
- `CONTRIBUTING.md` prerequisites aligned with the supported toolchains (GCC 16+, Clang 18.1+, MSVC 19.44+, CMake 4.0+).

### Fixed
- Use-after-release hazard when a request was still alive after `arena.release()` in the 431 path.
- HTTP/3 and QUIC hardening: Content-Length verification, stream-count limits, flow control, crypto-stream reassembly limits, reserved HTTP/2 frame rejection, max field section size.
- Documentation: corrected the `CLI/CLI.hpp` include path, the `-h` (help) short-option clash in the CLI example, the `set_max_request_size` / `set_max_memory_buffer` setter names, and the preset names used for configure, build and test.
