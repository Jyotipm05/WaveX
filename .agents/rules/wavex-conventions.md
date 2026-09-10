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

