# Roadmap

Planned and optional work. Nothing here is a commitment to a date.

- 🔮 **Future Protocols (GraphQL)** — High-performance GraphQL query execution engine layered onto the 3-Seam architecture. (HTTP/3 over QUIC, WebSocket and WebTransport already ship; see [Component status](components.md)).
- 🔌 **WebSocket / WebTransport follow-ups** — `permessage-deflate` (RFC 7692), a WebSocket client in `HttpClient`, and QUIC `RESET_STREAM` / `STOP_SENDING` with WebTransport error codes.
- 🔀 **HTTP/2** — stream priorities (RFC 9218) and serving HTTP/1.1 on `Http2Server` when ALPN or the first bytes say so.
- 🛡 **DDoS Protection & OOM Backpressure Safeguard** — Optional network-level queue capacity watermarks (`max_injector_capacity`) that reject overload traffic with immediate HTTP `503 Service Unavailable` responses (`Retry-After: 5`) before allocation.
- 🗜 **Zlib File Compression** — Optional Gzip / Brotli response compression choices in `send_file()`.
- 🌐 **Compile-Time File Routing** — Build-time CMake directory scanner generating static route headers for static files (`StaticMount`) and C++ handler modules (`FolderMode`).
