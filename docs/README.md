# WaveX Documentation

## Start here

| Page                                  | What it covers                                     |
|:--------------------------------------|:---------------------------------------------------|
| [Getting started](getting-started.md) | Build, create a certificate, run your first server |
| [Building & testing](building.md)     | Toolchains, presets, CMake options, compiler notes |
| [Dev servers & cURL](dev-servers.md)  | Interactive servers for Postman and cURL           |
| [Feature reference](features.md)      | The complete feature list                          |

## Guides

| Guide                                                                | Topics                                                              |
|:---------------------------------------------------------------------|:--------------------------------------------------------------------|
| [Routing, middleware & responses](guides/routing-and-middleware.md)  | Routes, params, middleware, `StaticChain`, 404s, redirects, `QUERY` |
| [HTTP/2 and HTTP/3](guides/http2-and-http3.md)                       | h2c, h2, HTTP/3 over QUIC                                           |
| [WebSocket & WebTransport](guides/websocket-and-webtransport.md)     | RFC 6455, WebSocket over HTTP/3 (RFC 9220), WebTransport sessions   |
| [TLS 1.3](guides/tls.md)                                             | `enable_tls`, `TlsConfig`, dev certificates                         |
| [Keep-alive, shutdown & events](guides/connections-and-shutdown.md)  | Timeouts, quotas, draining, restart, `EventBus`                     |
| [HTTP client](guides/http-client.md)                                 | `HttpClient`, ALPN, h2c, bodies                                     |
| [File uploads & compression](guides/file-uploads-and-compression.md) | Multipart, spooling, Gzip/Deflate                                   |
| [Async offloading](guides/async-offloading.md)                       | `spawn_blocking`, `wavex::fs`                                       |
| [Memory & lifetimes](guides/memory-and-lifetimes.md)                 | Arenas, `FlatMap`, `string_view` contract                           |
| [Logging & CLI](guides/logging-and-cli.md)                           | `wavex::log`, `CliParser`                                           |
| [Custom protocols](guides/custom-protocols.md)                       | Codec, traits and router for your own protocol                      |

## Reference

| Page                                      | What it covers                                    |
|:------------------------------------------|:--------------------------------------------------|
| [Architecture](architecture.md)           | Layers, runtime, component map, request lifecycle |
| [Component status](components.md)         | Per-component maturity                            |
| [Project structure](project-structure.md) | Directory and header map                          |
| [Roadmap](roadmap.md)                     | Planned work                                      |

## For contributors

- [CONTRIBUTING.md](../CONTRIBUTING.md): workflow, standards, PR checklist.
- [`.agents/`](../.agents): coding rules and architecture references used by AI coding agents (conventions, QUIC invariants, test invariants, three-seam architecture).
