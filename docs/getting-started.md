# Getting Started

## 1. Build

```bash
git clone https://github.com/Jyotipm05/WaveX.git
cd WaveX && git checkout dev

cmake --preset test-profile
cmake --build --preset fast-dev
```

Requirements and options: [Building & Testing](building.md).

## 2. Run a dev server

```bash
./build/test-profile/wavex_postman_http1_server        # http://127.0.0.1:8080  (add .exe on Windows)
curl http://127.0.0.1:8080/api/json
```

## 3. Create a development certificate (for TLS, HTTP/2 over TLS and HTTP/3)

```bash
mkdir -p ssl
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 365 \
  -subj "/CN=localhost" -keyout ssl/test.key -out ssl/test.crt
./build/test-profile/wavex_postman_http1_server --tls    # https://127.0.0.1:8443
curl -k https://127.0.0.1:8443/api/json
```

## 4. Write your own server

```c++
#include <wavex/wavex.hpp>

int main() {
    auto &router = wavex::engine::HttpRouter::instance();
    router.get("/api/hello", [](auto &, auto &res) -> wavex::task<void> {
        res.status(200).json({{"message", "Hello, World!"}, {"framework", "WaveX"}});
        co_return;
    });

    wavex::server::Server server(router, "127.0.0.1", 8080);
    server.run();
}
```

Prefer modules? With `WAVEX_USE_MODULE=ON` (the default on MSVC) import the module instead of including the header:

```c++
import wavex;
#include <iostream>

int main() {
    wavex::log::info("WaveX version: {}", wavex::wx_version);
    return 0;
}
```

## 5. Where next

- Add middleware, parameters and 404 handling: [Routing guide](guides/routing-and-middleware.md)
- Serve HTTP/2 or HTTP/3: [HTTP/2 & HTTP/3](guides/http2-and-http3.md)
- Add WebSocket or WebTransport endpoints: [WebSocket & WebTransport](guides/websocket-and-webtransport.md)
- Understand request lifetimes: [Memory & lifetimes](guides/memory-and-lifetimes.md)
