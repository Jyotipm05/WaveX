# Roadmap

Planned and optional work. Nothing here is a commitment to a date.

- 🔮 **Future Protocols (GraphQL, WebSockets)** — High-performance GraphQL query execution engine and RFC 6455 WebSocket upgrades cleanly layered onto the 3-Seam architecture. (HTTP/3 over QUIC already ships; see [Component status](components.md)).
- 🛡 **DDoS Protection & OOM Backpressure Safeguard** — Optional network-level queue capacity watermarks (`max_injector_capacity`) that reject overload traffic with immediate HTTP `503 Service Unavailable` responses (`Retry-After: 5`) before allocation.
- 🗜 **Zlib File Compression** — Optional Gzip / Brotli response compression choices in `send_file()`.
- 🌐 **Compile-Time File Routing** — Build-time CMake directory scanner generating static route headers for static files (`StaticMount`) and C++ handler modules (`FolderMode`).
