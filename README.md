<p align="center">
  <img src="docs/logo_anim.svg" alt="WaveX" width="240" />
</p>

<h1 align="center">WaveX</h1>

<h3 align="center">Coroutine-native HTTP/1.1, HTTP/2 and HTTP/3 for modern C++23</h3>

<p align="center">
  <a href="CHANGELOG.md"><img alt="Version" src="https://img.shields.io/badge/Version-v0.4.0-orange.svg" /></a>
  <a href="LICENSE"><img alt="License: MPL-2.0" src="https://img.shields.io/badge/License-MPL--2.0-blue.svg" /></a>
  <a href="https://en.cppreference.com/w/cpp/23"><img alt="C++23" src="https://img.shields.io/badge/C%2B%2B-23-blue.svg" /></a>
  <a href="https://cmake.org"><img alt="CMake 4.0+" src="https://img.shields.io/badge/CMake-4.0+-064F8C.svg" /></a>
</p>

<p align="center">
  <a href="#hello-wavex">Hello, WaveX</a> ·
  <a href="docs/getting-started.md">Getting started</a> ·
  <a href="docs/README.md">Documentation</a> ·
  <a href="docs/architecture.md">Architecture</a> ·
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

---

WaveX is a C++23 backend framework for building HTTP servers and clients with `co_await` instead of callbacks. It takes its routing from **Actix Web**, its work-stealing runtime from **Tokio**, and its linear middleware pipeline from **Express.js**.

## Hello, WaveX

```c++
#include <wavex/wavex.hpp>

int main() {
    auto &router = wavex::engine::HttpRouter::instance();

    router.get("/", [](auto &, auto &res) -> asio::awaitable<void> {
        res.status(200).send("Hello, World!");
        co_return;
    });

    router.get("/hello/:name", [](auto &req, auto &res) -> asio::awaitable<void> {
        res.status(200).json({{"hello", std::string(req.param("name").value_or("World"))}});
        co_return;
    });

    wavex::server::Server server(router, "127.0.0.1", 8080);
    server.run();   // http://127.0.0.1:8080
}
```

## Why WaveX

- **One router, three protocols.** The same handler style serves HTTP/1.1, HTTP/2 (h2c and TLS) and HTTP/3 over a native QUIC stack.
- **Coroutines all the way down.** Handlers, middleware, the client and file I/O are `asio::awaitable`s on a work-stealing worker pool.
- **No virtuals on the hot path.** Requests, responses and middleware chains use C++23 *deducing this*, so dispatch is static and inlinable.
- **Allocation-aware.** Per-request arenas, contiguous containers and zero-copy parsing keep the request path off the global heap.
- **Extensible.** Plug your own wire protocol into the same runtime, TLS and QUIC transports through a three-seam design.

## Protocols at a glance

| Protocol | Server        | Router        | Transport                |
|:---------|:--------------|:--------------|:-------------------------|
| HTTP/1.1 | `Http1Server` | `Http1Router` | TCP, TLS 1.3             |
| HTTP/2   | `Http2Server` | `Http2Router` | h2c, TLS 1.3 (ALPN `h2`) |
| HTTP/3   | `Http3Server` | `Http3Router` | QUIC (UDP) with TLS 1.3  |

## What's inside

| Area                 | Highlights                                                                                                                                     | Guide                                                  |
|:---------------------|:-----------------------------------------------------------------------------------------------------------------------------------------------|:-------------------------------------------------------|
| Routing & middleware | Radix tree with `:id`, `{id:[0-9]+}` (RE2) and `*catch-all`; `QUERY` method; short-circuiting coroutine middleware; compile-time `StaticChain` | [Routing](docs/guides/routing-and-middleware.md)       |
| Protocols            | HTTP/2 + HPACK, HTTP/3 + QPACK, QUIC (RFC 9000/9001), chunked encoding                                                                         | [HTTP/2 & HTTP/3](docs/guides/http2-and-http3.md)      |
| Security             | TLS 1.3 only, ALPN negotiation, body-size limits with `413`                                                                                    | [TLS](docs/guides/tls.md)                              |
| Connections          | Keep-alive and pipelining, inactivity timeouts, graceful shutdown, restartable servers, event bus                                              | [Connections](docs/guides/connections-and-shutdown.md) |
| Client               | HTTP/1.1 + HTTP/2, ALPN, h2c, JSON/text/binary bodies                                                                                          | [Client](docs/guides/http-client.md)                   |
| Files                | RFC 7578 multipart with disk spooling, Gzip/Deflate, async file I/O                                                                            | [Uploads](docs/guides/file-uploads-and-compression.md) |
| Concurrency          | Work-stealing pool, `spawn_blocking`, elastic blocking pool                                                                                    | [Offloading](docs/guides/async-offloading.md)          |
| Memory               | `RequestArena`, `ConnectionMemoryPool`, `FlatMap`, `string_view` contract                                                                      | [Memory](docs/guides/memory-and-lifetimes.md)          |
| Tooling              | CLI parser, levelled logger, Postman dev servers                                                                                               | [Logging & CLI](docs/guides/logging-and-cli.md)        |

## Get started

```bash
git clone https://github.com/Jyotipm05/WaveX.git
cd WaveX && git checkout dev

cmake --preset test-profile
cmake --build --preset fast-dev
ctest --preset run-tests --output-on-failure
```

Requires **GCC 16+, Clang 18.1+ or MSVC 19.44+**, **CMake 4.0+**, Ninja, and (optionally) vcpkg. Full instructions, MinGW notes and CMake options are in [Building & Testing](docs/building.md). Add WaveX to your own project with:

```cmake
include(FetchContent)
FetchContent_Declare(wavex GIT_REPOSITORY https://github.com/Jyotipm05/WaveX.git GIT_TAG dev)
FetchContent_MakeAvailable(wavex)
target_link_libraries(my_app PRIVATE wavex)
```

## Documentation

| I want to...                             | Read                                           |
|:-----------------------------------------|:-----------------------------------------------|
| Build and run something in five minutes  | [Getting started](docs/getting-started.md)     |
| Learn a feature with copy-paste examples | [Guides](docs/README.md#guides)                |
| Understand how it fits together          | [Architecture](docs/architecture.md)           |
| See what is stable                       | [Component status](docs/components.md)         |
| Try the servers with cURL or Postman     | [Dev servers](docs/dev-servers.md)             |
| Find a file in the tree                  | [Project structure](docs/project-structure.md) |
| See what is planned                      | [Roadmap](docs/roadmap.md)                     |

## Status

WaveX is pre-1.0, so public APIs can still change between minor versions. HTTP/1.1, HTTP/2 and the runtime are the most mature parts; HTTP/3 and QUIC are newer and marked Beta in [Component status](docs/components.md). Release history is in the [Changelog](CHANGELOG.md).

## Contributing

Contributions are welcome and target the **`dev`** branch. Read [CONTRIBUTING.md](CONTRIBUTING.md) first.

## License

[MPL-2.0](LICENSE). Third-party licenses are listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

Copyright © 2026 Jyotipriya Mondal
