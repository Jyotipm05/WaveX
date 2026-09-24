---
trigger: always_on
---

# WaveX Architectural & Development Invariants

## 1. C++20 Module Synchronization
- All public types, functions, and aliases in `include/wavex/` must be exported in `src/*.ixx` partitions via `export namespace wavex::... { using ...; }`.

## 2. Zero-VTable Architecture
- No `virtual` methods in `Request` or `Response`. Use CRTP and C++23 explicit object parameter (`this Self&& self`).
- Responses must support in-place mutation and zero-copy `std::string_view` referencing owned buffers.
- `status_text_` must synchronize with RFC reason phrases via `Codec::status_text_for(code)`.

## 3. Protocol Traits & 3-Seam Decoupling
- `Server<Codec, Router>` must remain protocol-agnostic (never branch on `is_http2` in Server):
  - **Transport**: `handle_connection<Stream>` generic over `AsyncStream` (TCP, TLS, QUIC).
  - **Codec**: `parse_stream`, `serialize`, `result`.
  - **Policy**: `wavex::protos::protocol_traits<Codec>` for prefaces, keep-alive, headers, and ALPN.

## 4. Response Lifecycle & Streaming Sinks
- `res.send(...)` only commits the response payload in memory; never write directly to sockets in `send_impl()`.
- Streaming (`start_chunked`, `write_chunk`, `end_chunked`, `send_file`) writes via the injected `write_sink_fn`.
- `is_sent_` short-circuits middlewares. `Server` writes `res.serialize()` only if `!res.is_headers_sent()`.

## 5. Memory Architecture & FlatMap
- Per-request key-values (params, query, headers) must use `FlatMap<K, V, InlineCap=16>` (contiguous, zero heap allocation for N <= 16).
- Case-insensitive header lookups must use `.find_ci()` and `.insert_or_assign_ci()`.
- Use `wavex::memory::RequestArena` (4KB inline bump allocator) for request-scoped dynamic allocations, reclaimed in O(1) via `arena.release()`. Never instantiate it in connection loops if unused.
- Socket buffers exceeding 64KB must be shrunk via `shrink_to_fit()` on empty.

## 6. Resource Limits & DoS Hard Caps
- Query parameters hard-capped at 64 (`kMaxQueryParams`). Overflow sets `query_param_overflow_ = true` -> reject with `431 Request Header Fields Too Large`.
- Headers capped at 100 by default (`set_max_headers(N)`).

## 7. `string_view` Lifetime & Container Stability
- Views from `req.param()`, `req.query_param()`, and `res.header()` point to ephemeral backing storage:
  - **In-Turn (Zero-Copy)**: Valid synchronously within current turn.
  - **Escaping (Owning Copy)**: Crossing coroutine turns, `spawn_blocking`, or caching requires `std::string(view)`.
- Never point `string_view` into an incrementally grown `std::vector` without post-mutation view resynchronization.
- Route wildcard slices must be contiguous pointers into the single normalized path buffer (`assert(w_begin <= w_end)`).

## 8. HTTP Framing & Connection Completion
- `HttpClient` must evaluate `parser::parse_response` per chunk and exit immediately upon complete framing; never loop until EOF.
- When `Content-Length` is present, `buffer.size() - cursor < content_length` must yield `result::incomplete`.
- Status `1xx`, `204`, and `304` have no body; finalize immediately with `body = ""`.

## 9. Test Integrity
- NEVER modify test assertions, expected output, or fixtures when debugging test failures without explicit user consent. Root causes must be fixed in framework implementations.

## 10. Associated Rules
- [toolchain-and-build.md](file:///d:/programming/Cpp-files/Projects/WaveX/.agents/rules/toolchain-and-build.md) (Compilers, Winsock, CMake)
- [class-struct-layout.md](file:///d:/programming/Cpp-files/Projects/WaveX/.agents/rules/class-struct-layout.md) (Member packing & layout)
- [asio-socket-lifecycle.md](file:///d:/programming/Cpp-files/Projects/WaveX/.agents/rules/asio-socket-lifecycle.md) (Sockets, coroutines, buffers)
- [optional-dependency-guards.md](file:///d:/programming/Cpp-files/Projects/WaveX/.agents/rules/optional-dependency-guards.md) (Dependency header guards)
- [never-config-cmake.md](file:///d:/programming/Cpp-files/Projects/WaveX/.agents/rules/never-config-cmake.md) (CMake configure safety)
- [future-protocols-architecture.md](file:///d:/programming/Cpp-files/Projects/WaveX/.agents/rules/future-protocols-architecture.md) (Protocol extensions)
