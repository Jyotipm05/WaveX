# Component Status

✅ Complete = implemented and covered by the automated tests. 🧪 Beta = implemented and tested, but newer; expect fixes and API adjustments.

| Component                  | Status      | Description                                                                                                                                              |
|:---------------------------|:------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------|
| `Base/Logger`              | ✅ Complete | Levelled logger (TRACE, DEBUG, INFO, WARN, ERROR, FATAL)                                                                                                 |
| `Base/Uri` / `Base/Url`    | ✅ Complete | RFC 3986 URI encode/decode & URL query string parser                                                                                                     |
| `Base/MimeTypes`           | ✅ Complete | Fast file extension to MIME type mappings (`mime_type_from_ext`)                                                                                         |
| `Base/Chainable`           | ✅ Complete | C++23 "Deducing `this`" static pipeline dispatch (`StaticChain`, `make_chain`, `KeepAlivePolicy`, `ConditionalChainable`)                                |
| `Base/FlatMap`             | ✅ Complete | Cache-line contiguous KV container (`InlineCap=16`) with case-insensitive search (`find_ci`)                                                             |
| `Base/Memory`              | ✅ Complete | Movable per-request arena handle (`RequestArena`, 4 KB first block) over a per-connection pool (`ConnectionMemoryPool`)                                  |
| `Base/Request`             | ✅ Complete | Protocol-agnostic C++23 deducing-this request base (`Request`, zero-vtable, multipart & query accessors)                                                 |
| `Base/Response`            | ✅ Complete | Protocol-agnostic C++23 deducing-this response builder (`Response`, zero-vtable, fluent API & `redirect` helpers)                                        |
| `Base/MiddleWare`          | ✅ Complete | Coroutine-aware middleware template (`GenericMiddlewareFn`), linear pipeline, `keep_alive`, `sse_stay_active` & `body_limit`                             |
| `Engine/Router`            | ✅ Complete | Protocol-agnostic radix tree with RE2 regex, wildcard matching & configurable 404 handler                                                                |
| `Engine/HttpRouter`        | ✅ Complete | HTTP/1.1 (`Http1Router`), HTTP/2 (`Http2Router`) & HTTP/3 (`Http3Router`) method convenience routing (`get`, `post`, etc.) & 404 customization           |
| `Server/LocalQueue`        | ✅ Complete | Per-worker 256-slot ring buffer for ultra-fast task stealing                                                                                             |
| `Server/InjectorQueue`     | ✅ Complete | Global unbounded MPMC task overflow queue with atomic size tracking                                                                                      |
| `Server/ThreadPool`        | ✅ Complete | Adaptive Tokio-style work-stealing thread pool with load hysteresis                                                                                      |
| `Server/Server`            | ✅ Complete | Coroutine TCP, TLS 1.3 & QUIC UDP server (`Http1Server`, `Http2Server`, `Http3Server`) with worker pool, ALPN, Keep-Alive, 404, limits & memory spooling |
| `Server/TlsConfig`         | ✅ Complete | TLS 1.3 server encryption config (`cert_file`, `key_file`, `key_password`, `dh_file`, `force_tls13`)                                                     |
| `protos/ProtocolTraits`    | ✅ Complete | Protocol session traits (`protocol_traits<Codec>`) for prefaces, keep-alive, response prep & ALPN                                                        |
| `protos/http/http1codec`   | ✅ Complete | Zero-copy HTTP/1.x parser, encoder, response decoder, chunked framing, status text & stream pipelining                                                   |
| `protos/http/http2codec`   | ✅ Complete | Full RFC 7540 binary framing, RFC 7541 HPACK encoder/decoder, stream multiplexing & SETTINGS negotiation                                                 |
| `protos/http/http3codec`   | 🧪 Beta     | Full RFC 9114 HTTP/3 binary framing, RFC 9204 QPACK encoder/decoder, VarInt streams & SETTINGS                                                           |
| `protos/http/HttpRequest`  | ✅ Complete | HTTP/1.1, HTTP/2 & HTTP/3 with zero-copy stream parsing, keep-alive, multipart form parsing, decompressed body & file save                               |
| `protos/http/HttpResponse` | ✅ Complete | HTTP/1.1, HTTP/2 & HTTP/3 with injected write sink for streaming, commitment & fluent builder API                                                        |
| `Network/QUIC`             | 🧪 Beta     | Native RFC 9000 & 9001 QUIC UDP transport engine, packet framing, connection ID routing, TLS 1.3 QUIC method & `QuicStream`                              |
| `Client/HttpClient`        | ✅ Complete | Coroutine HTTP/1.1 & HTTP/2 client with plain/TLS 1.3, multipart form upload, payload compression, and file saving                                       |
| `Utils/TempFile`           | ✅ Complete | RAII temporary file management (`TempFileGuard`) with atomic move/cleanup and custom directory support                                                   |
| `Utils/Compression`        | ✅ Complete | Zero-overhead Gzip & Deflate compression/decompression (`Compressor`, `CompressionFormat`) via CMake-controlled zlib integration                         |
| `Utils/Multipart`          | ✅ Complete | RFC 7578 multipart/form-data parser, builder, in-memory buffering & disk spooling thresholds (`MultipartFormData`)                                       |
| `Utils/Utils`              | ✅ Complete | Umbrella utilities module (`wavex:utils`) and header (`Utils.hpp`) bundling TempFile, Compression, and Multipart                                         |
| `CLI/CLI`                  | ✅ Complete | Type-safe CLI argument parser (`wavex::cli::CliParser`), flag validator, and option engine                                                               |

Also present: `Base/Event` (generic pub-sub and `ShutdownEvent`), `Base/StringSink` (allocation-free serialization sinks), `Server/ConnectionTracker`, `Server/BlockingPool`, `Utils/AsyncFs`, `Utils/BinaryFile`, `Utils/FsUtils` and `Utils/StreamBuffer`.

---

**See also:** [Roadmap](roadmap.md) · [Architecture](architecture.md)
