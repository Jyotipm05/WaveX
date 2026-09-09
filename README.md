# WaveX

A modern, high-performance C++23 backend framework built for coroutine-native HTTP servers & clients, Express.js-style pipeline execution, extensible protocol support, and powerful CLI tooling.

WaveX draws inspiration from **Rust's Actix Web** (hybrid radix-tree routing), **Tokio** (hybrid work-stealing dual-queue runtime with hysteresis-based thread scaling), and **Express.js** (linear middleware chain with immediate response dispatching).

[![Version: v0.3.0](https://img.shields.io/badge/Version-v0.3.0-orange.svg)](RELEASE_NOTES.md)
[![License: MPL-2.0](https://img.shields.io/badge/License-MPL--2.0-blue.svg)](LICENSE)
[![C++ Standard](https://img.shields.io/badge/C%2B%2B-23-blue.svg)](https://en.cppreference.com/w/cpp/23)
[![CMake](https://img.shields.io/badge/CMake-4.0+-064F8C.svg)](https://cmake.org)

---

## Features

- **⚡ Coroutine-Native Engine** — Async server handlers and client requests written with asio C++23 coroutines (`co_await`, `asio::awaitable<void>`), zero callback boilerplate.
- **⚡ Native HTTP/2 (RFC 7540) & HPACK (RFC 7541)** — Full binary framing engine (`http2codec`), connection preface validation (`PRI * HTTP/2.0...`), client/server `SETTINGS` negotiation & ACK handshake, server-side ALPN selection (`h2` over TLS 1.3), stream multiplexing, and HPACK static/dynamic table compression.
- **⚡ Dual-Protocol Server Architecture** — Extensible `Server<Codec, Router>` template providing dedicated first-class `Http1Server` and `Http2Server` specializations with zero runtime protocol switching overhead.
- **⚡ C++23 "Deducing This" Static Pipelines** — Zero-overhead static dispatch mixin (`wavex::Chainable`) enabling compile-time tuple pipelines (`wavex::StaticChain`), `make_chain` factory, and semi-static runtime toggles (`ConditionalChainable`), eliminating vtable and dynamic `std::function` heap allocation overhead.
- **⚡ CRTP Zero-Vtable Architecture** — Static compile-time polymorphism (`Request<Derived>`, `Response<Derived>`) eliminating virtual function pointers (`vptr`), saving memory and enabling zero-overhead direct dispatch.
- **🚀 Express.js-Style Linear Pipeline** — Iterative, non-recursive `run_chain()` middleware runner with immediate response dispatch (`res.send()` / `res.json()`) and zero-allocation socket pointer dispatch (`HttpResponse res(&socket)`).
- **🌳 Hybrid Radix-Tree Router** — High-performance radix-tree supporting static segments, dynamic parameters (`:id`), `{id:[0-9]+}` RE2 regex constraints, catch-all wildcards (`*filepath`), and RFC 9110 HTTP methods including `QUERY`.
- **🌐 Async Coroutine HTTP Client** — Modern, coroutine-native HTTP/1.1 client (`HttpClient`) for non-blocking outbound requests (`get`, `post`, `send`) with connection reuse and optional TLS 1.3 encryption *(HTTP/2 client support to be released soon)*.
- **📦 Chunked Transfer-Encoding** — Full streaming support for HTTP/1.1 chunked request and response encoding & decoding.
- **🗂 MIME Type Detection Engine** — Fast, built-in file extension to MIME content-type resolver (`MimeTypes.hpp`) supporting over 50+ common web media types.
- **🛠 Modern CLI Engine** — High-performance CLI argument parser (`wavex::cli::CliParser`) supporting flags (`--verbose`, `-v`), key-value options (`--host`, `-p`), positional arguments, typed getters (`get_int`, `get_bool`), and automatic `--help` generation.
- **🔒 TLS 1.3 OpenSSL Encryption Engine** — Strict, native TLS 1.3 server encryption (`enable_tls()`, `wavex::server::TlsConfig`) supporting custom PEM certificate chains (`cert_file`), private key passphrases (`key_password`), DH parameters (`dh_file`), ALPN protocol negotiation (`http/1.1`, `h2`), and strict legacy SSL/TLS protocol disabling (`force_tls13`).
- **🔄 HTTP Stay-Active & Inactivity Timeout (RFC 7230 / RFC 9112)** — Full persistent connection support over Plain TCP and TLS 1.3 streams. Handles HTTP pipelining without socket re-establishment, manages inactivity timeouts (`set_keep_alive_timeout`) via asio steady timers, enforces maximum request thresholds (`set_max_keep_alive_requests`), and includes zero-cost compile-time policies (`KeepAlivePolicy`) and middlewares (`keep_alive`, `sse_stay_active`).
- **🚫 Configurable 404 Not Found Engine** — Default `"Not Found"` string response with full customization support across Router and Server: custom text, HTML/JSON bodies with automatic MIME types, static error pages loaded from disk (`not_found_page`), or custom coroutine handlers.
- **🧵 Tokio-Style Work-Stealing Dual-Queue Runtime** —
  - **`LocalQueue`**: Bounded 256-slot ring buffer per worker thread for ultra-fast LIFO/FIFO work stealing.
  - **`InjectorQueue`**: Unbounded global MPMC queue with atomic size tracking for external tasks and overflow.
  - **Zero Request Loss on Scale-Down**: Retiring workers safely drain their remaining local ring tasks back into `InjectorQueue` on thread exit.
- **🛡 Pipeline Short-Circuiting** — Middleware rejection (e.g. `401 Unauthorized`) immediately sends the response while skipping downstream middlewares and route handlers.
- **🧪 Interactive Postman Dev Servers** — Pre-configured CLI-driven testing servers for HTTP/1.1 ([tests/postman_demo_http1_server.cpp](tests/postman_demo_http1_server.cpp)) and HTTP/2 ([tests/postman_demo_http2_server.cpp](tests/postman_demo_http2_server.cpp)) supporting plain and TLS 1.3 modes via WaveX's built-in CLI parser.


---

## Quick Start

### 1. Minimal "Hello, World!" Server

The absolute simplest WaveX server in under 15 lines of code:

```cpp
#include <wavex/wavex.hpp>

int main() {
    auto &router = wavex::engine::HttpRouter::instance();

    // Plain text "Hello, World!" endpoint
    router.get("/", [](auto &, auto &res) -> asio::awaitable<void> {
        res.status(200).send("Hello, World!");
        co_return;
    });

    // Bind and run server on http://127.0.0.1:8080
    wavex::server::Server server(router, "127.0.0.1", 8080);
    wavex::log::info("WaveX server running on http://127.0.0.1:8080");
    server.run();

    return 0;
}
```

### 2. "Hello, World!" JSON API & Route Parameters

Returning structured JSON and reading dynamic path parameters (`:name`):

```cpp
#include <wavex/wavex.hpp>

int main() {
    auto &router = wavex::engine::HttpRouter::instance();

    // 1. JSON "Hello, World!" endpoint
    router.get("/api/hello", [](auto &, auto &res) -> asio::awaitable<void> {
        res.status(200).json({
            {"message", "Hello, World!"},
            {"framework", "WaveX"},
            {"status", "success"}
        });
        co_return;
    });

    // 2. Dynamic route parameter: /hello/Alice -> "Hello, Alice!"
    router.get("/hello/:name", [](auto &req, auto &res) -> asio::awaitable<void> {
        auto name = req.param("name").value_or("World");
        res.status(200).send("Hello, " + std::string(name) + "!");
        co_return;
    });

    wavex::server::Server server(router, "127.0.0.1", 8080);
    server.run();

    return 0;
}
```

### 3. HTTP/2 Server (Cleartext h2c & TLS 1.3 h2)

WaveX provides native HTTP/2 server support via `Http2Server` and `Http2Router`, implementing RFC 7540 binary framing and RFC 7541 HPACK header compression:

```cpp
#include <wavex/wavex.hpp>

int main() {
    auto &router = wavex::engine::Http2Router::instance();

    // Stream-aware HTTP/2 JSON endpoint
    router.get("/api/h2", [](auto &req, auto &res) -> asio::awaitable<void> {
        res.status(200).json({
            {"protocol", "HTTP/2"},
            {"stream_id", req.stream_id()},
            {"framework", "WaveX"}
        });
        co_return;
    });

    // Option A: Cleartext HTTP/2 (h2c) on port 8082
    wavex::server::Http2Server server(router, "127.0.0.1", 8082);

    // Option B: HTTP/2 over TLS 1.3 (ALPN 'h2' negotiated automatically on port 8444)
    // wavex::server::Http2Server server(router, "127.0.0.1", 8444);
    // server.enable_tls("ssl/test.crt", "ssl/test.key");

    wavex::log::info("WaveX HTTP/2 server running on http://127.0.0.1:8082");
    server.run();

    return 0;
}
```

### 4. Full HTTP Server & Coroutine Middleware

```cpp
#include <iostream>
#include <wavex/wavex.hpp>

using namespace wavex;

// Auth Guard Middleware
asio::awaitable<void> auth_guard(protos::http::HttpRequest &req, protos::http::HttpResponse &res, base::Next next) {
    auto auth_header = req.header("Authorization");
    if (!auth_header || *auth_header != "Bearer secret123") {
        res.status(401).json({{"error", "Unauthorized"}});
        co_return; // Immediate response sent, short-circuits pipeline!
    }
    co_await next();
}

int main() {
    auto &router = engine::HttpRouter::instance();

    // 1. Plain text endpoint
    router.get("/", [](protos::http::HttpRequest &, protos::http::HttpResponse &res) -> asio::awaitable<void> {
        res.status(200).send("Welcome to WaveX!");
        co_return;
    });

    // 2. JSON endpoint
    router.get("/api/json", [](protos::http::HttpRequest &, protos::http::HttpResponse &res) -> asio::awaitable<void> {
        res.status(200).json({{"status", "success"}, {"framework", "WaveX"}, {"version", wx_version}});
        co_return;
    });

    // 3. Protected endpoint with middleware
    router.get("/api/protected", {auth_guard}, [](protos::http::HttpRequest &, protos::http::HttpResponse &res) -> asio::awaitable<void> {
        res.status(200).json({{"secret", "Access Granted"}});
        co_return;
    });

    // 4. Wildcard catch-all endpoint
    router.get("/files/*filepath", [](protos::http::HttpRequest &req, protos::http::HttpResponse &res) -> asio::awaitable<void> {
        res.status(200).json({{"file", std::string(req.path())}});
        co_return;
    });

    server::Server server(router, "127.0.0.1", 8080);
    wavex::log::info("WaveX server running on http://127.0.0.1:8080");
    server.run();

    return 0;
}
```

### 5. Modern Logging with Source Location & ANSI Colors

Zero-macro, high-performance logging with automatic `std::source_location` call-site capture and ANSI terminal colors:

```cpp
#include <wavex/Base/Logger.hpp>

int main() {
    // Configure minimum log level (TRACE, DEBUG, INFO, WARN, ERROR, FATAL)
    wavex::base::Logger::instance().set_level(wavex::base::LogLevel::DEBUG);

    // Enable or disable ANSI terminal colors (enabled by default)
    wavex::base::Logger::instance().set_colored(true);

    // Modern functional logging API
    wavex::log::trace("Buffer allocated: {} bytes", 1024);
    wavex::log::debug("Route match resolved in {} us", 12.4);
    wavex::log::info("Worker pool online: {} threads", 8);
    wavex::log::warn("Slow database query detected ({}ms)", 235);
    wavex::log::error("Connection reset by peer: fd={}", 14);

    // Optional: direct logs to file or custom stream
    // wavex::base::Logger::instance().set_output("./logs/wavex.log");

    return 0;
}
```

### 6. C++23 "Deducing This" Static Pipelines (`class Chainable`)

Build compile-time static dispatch pipelines without vtables or dynamic heap allocations using `StaticChain` and `make_chain`:

```cpp
#include <wavex/Base/Chainable.hpp>
#include <wavex/Engine/HttpRouter.hpp>
#include <iostream>

// 1. Define Chainable Middlewares using C++23 "Deducing This"
struct AuthGuard : public wavex::Chainable {
    template <typename Self, typename Req, typename Res>
    asio::awaitable<bool> handle_impl(this Self&& self, Req& req, Res& res) {
        if (req.header("Authorization") != "Bearer valid_token") {
            res.status(401).send("Unauthorized");
            co_return false; // Short-circuits remaining pipeline statically!
        }
        co_return true; // Proceed to next handler
    }
};

struct AuditLogger : public wavex::Chainable {
    template <typename Self, typename Req, typename Res>
    asio::awaitable<bool> handle_impl(this Self&& self, Req& req, Res& res) {
        std::cout << "[AuditLog] Request path: " << req.path() << "\n";
        co_return true;
    }
};

struct TargetHandler : public wavex::Chainable {
    template <typename Self, typename Req, typename Res>
    asio::awaitable<bool> handle_impl(this Self&& self, Req& req, Res& res) {
        res.status(200).send("Static Chain Success!");
        co_return true;
    }
};

// 2. Register Static Chain directly in HttpRouter
int main() {
    auto &router = wavex::engine::HttpRouter::instance();

    // Fuses Auth -> Audit -> Handler into 1 statically dispatched, inlined pipeline!
    router.get("/api/static-fast", wavex::make_chain(AuthGuard{}, AuditLogger{}, TargetHandler{}));
}
```

### 7. Async HTTP Client

> [!NOTE]
> `HttpClient` currently supports **HTTP/1.1** (with TLS 1.3). **HTTP/2** client support is planned for release soon.

```cpp
#include <iostream>
#include <asio.hpp>
#include <wavex/Client/HttpClient.hpp>

using namespace wavex::client;

asio::awaitable<void> fetch_data(asio::io_context &ioc) {
    HttpClient client(ioc);
    
    // GET request (HTTP/1.1)
    auto response = co_await client.get("http://httpbin.org/get");
    std::cout << "Status: " << response.status_code() << "\n";
    std::cout << "Body: " << response.body() << "\n";

    // POST request with JSON
    auto post_res = co_await client.post("http://httpbin.org/post", "{\"framework\":\"wavex\"}", "application/json");
    std::cout << "POST Response: " << post_res.body() << "\n";
}
```

### 8. Command-Line Interface (CLI) Engine

```cpp
#include <wavex/Cli/Cli.hpp>
#include <iostream>

int main(int argc, char* argv[]) {
    wavex::cli::CliParser parser("wavex-tool", "WaveX High-Performance HTTP Server Utility");

    parser.add_flag("verbose", 'v', "Enable verbose logging")
          .add_option("host", 'h', "Host address to bind server", "127.0.0.1")
          .add_option("port", 'p', "Server port to listen on", "8080");

    auto result = parser.parse(argc, argv);
    if (!result.ok()) {
        if (result.help_requested) {
            parser.print_help();
            return 0;
        }
        std::cerr << "Error: " << result.error_message << "\n";
        return 1;
    }

    std::string host = parser.get_string("host");
    int port = parser.get_int("port", 8080);
    bool verbose = parser.get_bool("verbose");

    std::cout << "Starting server on http://" << host << ":" << port << " (verbose=" << verbose << ")\n";
    return 0;
}
```

### 9. TLS 1.3 Server Encryption (`TlsConfig`)

Enable strict TLS 1.3 HTTPS server encryption using `server.enable_tls()` with custom certificate/key paths or a `wavex::server::TlsConfig` struct:

```cpp
#include <wavex/wavex.hpp>
#include <wavex/Server/TlsConfig.hpp>

int main() {
    auto &router = wavex::engine::HttpRouter::instance();

    router.get("/secure", [](auto &, auto &res) -> asio::awaitable<void> {
        res.status(200).json({{"encrypted", true}, {"protocol", "TLS 1.3"}});
        co_return;
    });

    wavex::server::Http1Server server(router, "0.0.0.0", 8443);

    // Option A: Enable TLS 1.3 directly with certificate & key paths
    server.enable_tls("ssl/test.crt", "ssl/test.key");

    // Option B: Advanced configuration via TlsConfig struct
    /*
    wavex::server::TlsConfig cfg;
    cfg.cert_file = "ssl/cert.pem";
    cfg.key_file = "ssl/key.pem";
    cfg.key_password = "secret_passphrase";
    cfg.dh_file = "ssl/dh2048.pem";
    cfg.force_tls13 = true; // Exclusively enforce TLS 1.3
    server.enable_tls(cfg);
    */

    server.run();
    return 0;
}
```

### 10. HTTP Stay-Active (Keep-Alive) & Inactivity Timeout

WaveX natively supports RFC 7230 / RFC 9112 persistent connections (`Keep-Alive`) and HTTP pipelining for both Plain TCP and TLS 1.3 servers.

#### Server Inactivity Timeout & Request Quotas

Configure idle timeout thresholds and sequential request limits per persistent connection directly on `Server`:

```cpp
wavex::server::Http1Server server(router, "0.0.0.0", 8080);

// Inactivity timeout: close socket if client is idle for > 10 seconds
server.set_keep_alive_timeout(std::chrono::seconds(10));

// Request quota: allow up to 500 requests per TCP connection before gracefully closing
server.set_max_keep_alive_requests(500);

server.run();
```

#### Granular Response Header Control

Control keep-alive persistence dynamically in route handlers:

```cpp
router.get("/stream", [](auto &, auto &res) -> asio::awaitable<void> {
    // Advertise keep-alive with custom timeout (seconds) and remaining request count
    res.set_keep_alive(true, /*timeout_sec=*/15, /*max_requests=*/200);
    res.status(200).send("Keep-Alive Active");
    co_return;
});

router.get("/logout", [](auto &, auto &res) -> asio::awaitable<void> {
    // Explicitly command connection closure
    res.set_keep_alive(false); // Sends 'Connection: close' and strips 'Keep-Alive'
    res.status(200).send("Logged out. Connection closing.");
    co_return;
});
```

#### Zero-Cost Policies & Middleware

Use compile-time static chain policies or dynamic middlewares:

```cpp
// 1. StaticChain KeepAlivePolicy (zero runtime overhead)
router.get("/api/fast", wavex::make_chain(wavex::KeepAlivePolicy<10, 1000>{}, MyHandler{}));

// 2. Dynamic Middleware for Keep-Alive
router.get("/api/data", {wavex::base::keep_alive(10, 500)}, DataHandler);

// 3. Server-Sent Events (SSE) Stay-Active Middleware
router.get("/events", {wavex::base::sse_stay_active()}, SseHandler);
```

### 11. Configurable 404 Not Found Handling

By default, any unmatched route automatically responds with HTTP status 404 and the plain text `"Not Found"`. Developers can easily customize 404 handling across both `HttpRouter` and `Server`:

#### Option A: Custom String, HTML, or JSON

```cpp
// Custom plain text or HTML on Router
router.not_found("<h1>404 - Page Not Found</h1>", "text/html");

// Or configure directly on Server
server.set_not_found("Custom 404 text", "text/plain");
```

#### Option B: Load Error Page from File (Auto-MIME Detection)

```cpp
// Reads static file from disk and infers Content-Type via wavex::base::mime_type_from_path
router.not_found_page("public/404.html");

// Or configure directly on Server
server.set_not_found_page("public/404.html");
```

#### Option C: Full Dynamic Coroutine Handler

```cpp
router.not_found([](auto &req, auto &res) -> asio::awaitable<void> {
    nlohmann::json j = {
        {"error", "Not Found"},
        {"requested_path", std::string(req.path())},
        {"method", to_string(req.method_type())}
    };
    res.status(404).json(j);
    co_return;
});
```

### 12. C++23 Modules Quick Start

WaveX fully supports C++23 module imports for ultra-fast compilation:

```cpp
import wavex;
#include <iostream>

int main() {
    wavex::log::info("WaveX version: {}", wavex::wx_version);
    return 0;
}
```

---

## Architecture

```mermaid
graph LR
    subgraph "Base (protocol-agnostic)"
        Logger["Logger<br/><small>TRACE..FATAL</small>"]
        Uri["Uri / Url<br/><small>RFC 3986</small>"]
        Mime["MimeTypes<br/><small>file ext -> Content-Type</small>"]
        Chainable["Chainable / StaticChain<br/><small>C++23 static dispatch</small>"]
        Req["Request<br/><small>abstract</small>"]
        Res["Response<br/><small>fluent API</small>"]
        MW["Middleware<br/><small>linear chain + next()</small>"]
    end

    subgraph "Engine"
        Router["Router&lt;Proto&gt;<br/><small>radix tree + RE2</small>"]
        Http1Router["Http1Router<br/><small>HTTP/1.1 routes</small>"]
        Http2Router["Http2Router<br/><small>HTTP/2 routes</small>"]
        Router --> Http1Router
        Router --> Http2Router
    end

    subgraph "Tokio Dual-Queue Runtime"
        LocalQ["LocalQueue<br/><small>256-slot lock-free ring</small>"]
        InjQ["InjectorQueue<br/><small>global MPMC overflow</small>"]
        Pool["ThreadPool<br/><small>hysteresis scaling</small>"]
        Server["Server&lt;Codec, Router&gt;<br/><small>Http1Server / Http2Server</small>"]
        LocalQ --> Pool
        InjQ --> Pool
        Pool --> Server
    end

    subgraph "Protos & Networking"
        H1Codec["http1codec<br/><small>chunked + zero-copy</small>"]
        H2Codec["http2codec<br/><small>RFC 7540 + HPACK RFC 7541</small>"]
        HReq["HttpRequest<br/><small>Http1Request / Http2Request</small>"]
        HRes["HttpResponse<br/><small>Http1Response / Http2Response</small>"]
        Client["HttpClient<br/><small>async coroutine client</small>"]
        HReq --> Server
        HRes --> Server
    end

    subgraph "CLI"
        CLIApp["Cli::CliParser<br/><small>options, flags & positionals</small>"]
    end

    Req --> HReq
    Res --> HRes
    Chainable --> Http1Router
    Chainable --> Http2Router
    Http1Router --> Server
    Http2Router --> Server
    MW --> Server
    H1Codec --> Server
    H2Codec --> Server
    H1Codec --> Client

    style Logger fill:#2d6a4f,color:#fff
    style Uri fill:#2d6a4f,color:#fff
    style Mime fill:#2d6a4f,color:#fff
    style Chainable fill:#2d6a4f,color:#fff
    style Req fill:#2d6a4f,color:#fff
    style Res fill:#2d6a4f,color:#fff
    style MW fill:#2d6a4f,color:#fff
    style Router fill:#1b4332,color:#fff
    style Http1Router fill:#1b4332,color:#fff
    style Http2Router fill:#1b4332,color:#fff
    style H1Codec fill:#40916c,color:#fff
    style H2Codec fill:#40916c,color:#fff
    style HReq fill:#40916c,color:#fff
    style HRes fill:#40916c,color:#fff
    style Client fill:#40916c,color:#fff
    style CLIApp fill:#2d6a4f,color:#fff
    style Server fill:#52b788,color:#000
    style LocalQ fill:#1b4332,color:#fff
    style InjQ fill:#1b4332,color:#fff
    style Pool fill:#52b788,color:#000
```

### Request Lifecycle (UML Activity Diagram)

The following UML activity diagram illustrates the end-to-end lifecycle of an HTTP connection in WaveX — from initial TCP/TLS acceptance, asio coroutine scheduling, and zero-copy `http1codec` parsing, through radix-tree route resolution, middleware chain execution, short-circuit dispatch, configurable 404 fallback, and persistent Keep-Alive evaluation:

```mermaid
flowchart TD
    %% UML Activity Diagram - Request Lifecycle
    Start([● Connection Accepted]) --> InitSession[Initialize Connection Session & Arm Inactivity Timer]
    
    InitSession --> AwaitData[Wait for Incoming Data / async_read_some]
    
    AwaitData --> ReadCheck{"Data Received or Inactivity Timeout?"}
    ReadCheck -- "Inactivity Timeout / Client EOF" --> CloseSocket[Gracefully Close Socket]
    CloseSocket --> Terminate([● End Session])
    
    ReadCheck -- "Data Received" --> ParseCodec[Parse HTTP Request via http1codec]
    ParseCodec --> SyntaxCheck{"Valid HTTP Framing?"}
    SyntaxCheck -- "Malformed Request" --> Send400[Send 400 Bad Request]
    Send400 --> CloseSocket
    
    SyntaxCheck -- "Valid Request" --> ResetTimer[Refresh Inactivity Timer]
    ResetTimer --> RouteLookup[Radix-Tree Route Lookup in HttpRouter]
    
    RouteLookup --> RouteCheck{"Route Matched?"}
    
    %% Unmatched route -> Configurable 404
    RouteCheck -- "No (Unmatched)" --> Exec404[Execute Configured 404 Handler<br/>Custom Coroutine / Static File / Default Text]
    Exec404 --> SendResponse[Serialize & Dispatch HTTP Response]
    
    %% Matched route -> Middleware & Handler
    RouteCheck -- "Yes" --> ExtractParams[Extract Dynamic Params :id & Wildcards]
    ExtractParams --> ExecMW[Execute Middleware Chain / StaticChain]
    
    ExecMW --> ShortCircuitCheck{"Middleware Short-Circuited?<br/>(e.g., Auth Guard, Rate Limit, Cache)"}
    ShortCircuitCheck -- "Yes (Response Already Sent)" --> SendResponse
    ShortCircuitCheck -- "No (next() Called)" --> ExecHandler[Execute Target Route Handler]
    ExecHandler --> SendResponse
    
    SendResponse --> CheckPersistence{"Evaluate Persistence Policy:<br/>- HTTP/1.1 Keep-Alive requested<br/>- requests_served < max_requests<br/>- Inactivity timeout active<br/>- Connection != 'close'"}
    
    CheckPersistence -- "Keep-Alive Active" --> IncRequests[Increment Requests Served Count]
    IncRequests --> AwaitData
    
    CheckPersistence -- "Close / Quota Exceeded" --> CheckTLS{"Is TLS 1.3 Active?"}
    CheckTLS -- "Yes" --> TLSShutdown[Perform TLS Stream Shutdown]
    CheckTLS -- "No" --> CloseSocket
    TLSShutdown --> CloseSocket

    %% Styling
    classDef action fill:#2d6a4f,stroke:#1b4332,stroke-width:2px,color:#fff;
    classDef decision fill:#1b4332,stroke:#40916c,stroke-width:2px,color:#fff;
    classDef terminal fill:#081c15,stroke:#52b788,stroke-width:3px,color:#fff;
    
    class InitSession,AwaitData,ParseCodec,Send400,ResetTimer,RouteLookup,Exec404,ExtractParams,ExecMW,ExecHandler,SendResponse,IncRequests,TLSShutdown,CloseSocket action;
    class ReadCheck,SyntaxCheck,RouteCheck,ShortCircuitCheck,CheckPersistence,CheckTLS decision;
    class Start,Terminate terminal;
```

---

## Component Status

| Component                  | Status     | Description                                                                                                               |
|:---------------------------|:-----------|:--------------------------------------------------------------------------------------------------------------------------|
| `Base/Logger`              | ✅ Complete | Levelled logger (TRACE, DEBUG, INFO, WARN, ERROR, FATAL)                                                                  |
| `Base/Uri` / `Base/Url`    | ✅ Complete | RFC 3986 URI encode/decode & URL query string parser                                                                      |
| `Base/MimeTypes`           | ✅ Complete | Fast file extension to MIME type mappings (`mime_type_from_ext`)                                                          |
| `Base/Chainable`           | ✅ Complete | C++23 "Deducing `this`" static pipeline dispatch (`StaticChain`, `make_chain`, `KeepAlivePolicy`, `ConditionalChainable`) |
| `Base/Request`             | ✅ Complete | Protocol-agnostic CRTP request base (`Request<Derived>`, zero-vtable)                                                     |
| `Base/Response`            | ✅ Complete | Protocol-agnostic CRTP response builder (`Response<Derived>`, zero-vtable, fluent API)                                    |
| `Base/MiddleWare`          | ✅ Complete | Coroutine-aware middleware template (`GenericMiddlewareFn`), linear pipeline, `keep_alive` & `sse_stay_active`            |
| `Engine/Router`            | ✅ Complete | Protocol-agnostic radix tree with RE2 regex, wildcard matching & configurable 404 handler                                 |
| `Engine/HttpRouter`        | ✅ Complete | HTTP/1.1 (`Http1Router`) & HTTP/2 (`Http2Router`) method convenience routing (`get`, `post`, etc.) & 404 customization    |
| `Server/LocalQueue`        | ✅ Complete | Per-worker 256-slot ring buffer for ultra-fast task stealing                                                              |
| `Server/InjectorQueue`     | ✅ Complete | Global unbounded MPMC task overflow queue with atomic size tracking                                                       |
| `Server/ThreadPool`        | ✅ Complete | Adaptive Tokio-style work-stealing thread pool with load hysteresis                                                       |
| `Server/Server`            | ✅ Complete | Coroutine TCP & TLS 1.3 server (`Http1Server`, `Http2Server`) with master acceptor, worker pool, ALPN, Keep-Alive & 404   |
| `Server/TlsConfig`         | ✅ Complete | TLS 1.3 server encryption config (`cert_file`, `key_file`, `key_password`, `dh_file`, `force_tls13`)                      |
| `protos/http/http1codec`   | ✅ Complete | Zero-copy HTTP/1.x parser, encoder, response decoder, chunked framing & stream pipelining                                 |
| `protos/http/http2codec`   | ✅ Complete | Full RFC 7540 binary framing, RFC 7541 HPACK encoder/decoder, stream multiplexing & SETTINGS negotiation                  |
| `protos/http/HttpRequest`  | ✅ Complete | HTTP/1.1 (`Http1Request`) & HTTP/2 (`Http2Request`) with zero-copy stream parsing & keep-alive detection                    |
| `protos/http/HttpResponse` | ✅ Complete | HTTP/1.1 (`Http1Response`) & HTTP/2 (`Http2Response`) with zero-alloc socket writing & fluent builder API                 |
| `Client/HttpClient`        | ✅ Complete | Async coroutine HTTP/1.1 client (`get`, `post`, `send`) — *HTTP/2 client support to be released soon*                     |
| `Cli/Cli`                  | ✅ Complete | Type-safe CLI argument parser (`wavex::cli::CliParser`), flag validator, and option engine                                |

---

## Building & Testing

### Requirements

- **C++ Compiler**: GCC 13+, Clang 16+, or MSVC 19.36+ with C++23 enabled.
- **Build System**: CMake 4.0+, [Ninja](https://ninja-build.org/) generator.
- **Package Manager**: [vcpkg](https://vcpkg.io/) with `VCPKG_ROOT` environment variable configured.

### Build & Run with CMake Presets

WaveX uses standard [CMake Presets](CMakePresets.json) for rapid Ninja-backed configuration, multi-core parallel builds, and automated CTest runs.

#### 1. Configure
```bash
# Clone the repository
git clone https://github.com/Jyotipm05/WaveX.git
cd WaveX

# Configure development build (Debug, tests enabled)
cmake --preset test-profile

# Or configure production release (Release, tests disabled)
cmake --preset release

# Or configure with runtime sanitizers
cmake --preset asan   # Address + UB + Leak Sanitizers
cmake --preset tsan   # Thread Sanitizer
```

#### 2. Build
```bash
# Fast build (10 parallel jobs)
cmake --build --preset fast-dev

# Max build (all available CPU cores)
cmake --build --preset max-dev

# Build production Release binaries
cmake --build --preset fast-release
```

#### 3. Run Tests
```bash
# Run all automated tests via test preset
ctest --preset run-tests --output-on-failure

# Run specific test suites
ctest --preset run-tests -R test_http2_codec --output-on-failure
ctest --preset run-tests -R test_server_keepalive --output-on-failure
ctest --preset run-tests -R test_not_found --output-on-failure

# Run Sanitizer test suites
ctest --preset asan
ctest --preset tsan
```

### Manual Testing with Postman & cURL

WaveX includes two pre-configured, CLI-driven interactive dev servers for manual validation via Postman, cURL, or browsers:

#### Dev Server Executables

| Executable | Protocol Modes | Default Ports | Source |
|:---|:---|:---|:---|
| `wavex_postman_http1_server` | Plain HTTP / HTTPS (TLS 1.3) | `8080` (plain), `8443` (`--tls`) | [tests/postman_demo_http1_server.cpp](tests/postman_demo_http1_server.cpp) |
| `wavex_postman_http2_server` | Cleartext h2c / HTTP/2 over TLS 1.3 (h2) | `8082` (cleartext), `8444` (`--tls`) | [tests/postman_demo_http2_server.cpp](tests/postman_demo_http2_server.cpp) |

#### Command-Line Options (Built-in CLI)

Both servers support the following command-line flags:

| Flag | Short | Default | Description |
|:---|:---|:---|:---|
| `--tls` | `-s` | disabled | Enable TLS 1.3 encryption (ALPN `http/1.1` or `h2`) |
| `--port <num>` | `-p` | 8080/8082 (plain), 8443/8444 (TLS) | Port to listen on |
| `--host <ip>` | `-H` | `127.0.0.1` | Host address to bind |
| `--cert <path>` | `-c` | `ssl/test.crt` | Path to TLS certificate file |
| `--key <path>` | `-k` | `ssl/test.key` | Path to TLS private key file |
| `--help` | `-h` | — | Show CLI help and options |

#### Launching the Servers

```bash
# 1. HTTP/1.1 Server
./build/test-profile/wavex_postman_http1_server.exe                     # Plain HTTP on http://127.0.0.1:8080
./build/test-profile/wavex_postman_http1_server.exe --tls               # HTTPS/TLS 1.3 on https://127.0.0.1:8443
./build/test-profile/wavex_postman_http1_server.exe -p 9000             # Custom port

# 2. HTTP/2 Server
./build/test-profile/wavex_postman_http2_server.exe                     # Cleartext HTTP/2 (h2c) on http://127.0.0.1:8082
./build/test-profile/wavex_postman_http2_server.exe --tls               # HTTP/2 over TLS 1.3 (h2) on https://127.0.0.1:8444
./build/test-profile/wavex_postman_http2_server.exe --tls -p 9444       # Custom port with TLS
```

#### cURL Verification Commands

```bash
# HTTP/1.1 Plain & TLS
curl http://127.0.0.1:8080/api/json
curl -k https://127.0.0.1:8443/api/json

# HTTP/2 Cleartext (h2c prior knowledge) & TLS 1.3 (ALPN h2 negotiation)
curl --http2-prior-knowledge http://127.0.0.1:8082/api/json
curl -k --http2 https://127.0.0.1:8444/api/json

# HTTP/2 Protected Endpoint (Middleware Auth Check)
curl -k --http2 -H "Authorization: Bearer secret123" https://127.0.0.1:8444/api/protected
```

---

## Dependencies

| Library                                           | Purpose                                         | License      |
|:--------------------------------------------------|:------------------------------------------------|:-------------|
| [Asio](https://think-async.com/Asio/)             | Async I/O & C++ coroutines (standalone)         | BSL-1.0      |
| [nlohmann/json](https://github.com/nlohmann/json) | Modern C++ JSON parsing & serialization         | MIT          |
| [Google RE2](https://github.com/google/re2)       | Linear-time regex for route pattern constraints | BSD 3-Clause |
| [OpenSSL](https://www.openssl.org/)               | TLS 1.3 encryption & ALPN negotiation           | Apache-2.0   |

---

## Project Structure

```
include/wavex/
├── wavex.hpp                ← Main framework entry header
├── Base/
│   ├── Chainable.hpp        ← C++23 Deducing-this static dispatch & StaticChain
│   ├── Logger.hpp           ← Levelled logger
│   ├── Request.hpp          ← Abstract request base
│   ├── Response.hpp         ← Abstract response + fluent API
│   ├── MiddleWare.hpp       ← Middleware definition
│   ├── MimeTypes.hpp        ← File extension to MIME type resolver
│   ├── Uri.hpp              ← RFC 3986 URI utilities
│   └── Url.hpp              ← URL & query string parser
├── Engine/
│   ├── Router.hpp           ← Protocol-agnostic radix tree + RE2
│   └── HttpRouter.hpp       ← HTTP route shortcuts (Http1Router & Http2Router)
├── Server/
│   ├── WorkStealingQueue.hpp← LocalQueue (lock-free ring) & InjectorQueue (global MPMC)
│   ├── ThreadPool.hpp       ← Tokio-style adaptive worker pool
│   ├── Server.hpp           ← Coroutine TCP & TLS 1.3 server (Http1Server & Http2Server)
│   └── TlsConfig.hpp        ← TLS 1.3 encryption configuration
├── Client/
│   └── HttpClient.hpp       ← Async coroutine HTTP client
├── Cli/
│   └── Cli.hpp              ← Subcommand and CLI option parser
└── protos/
    └── http/
        ├── Methods.hpp      ← HTTP method enum (GET, POST, PUT, DELETE, QUERY, etc.)
        ├── http1codec.hpp   ← Zero-copy HTTP/1.x parser + chunked encoder/decoder
        ├── http2codec.hpp   ← RFC 7540 binary frame parser & RFC 7541 HPACK codec
        ├── HttpRequest.hpp  ← Concrete HTTP request (Http1Request & Http2Request)
        └── HttpResponse.hpp ← Concrete HTTP response (Http1Response & Http2Response)

src/                         ← Implementation + C++20 module partitions (.ixx)
tests/                       ← Automated unit tests & interactive postman servers
cmake/                       ← CMake installation config
```

## Roadmap & Optional Future Features

- 🛡 **DDoS Protection & OOM Backpressure Safeguard** — Optional network-level queue capacity watermarks (`max_injector_capacity`) that reject overload traffic with immediate HTTP `503 Service Unavailable` responses (`Retry-After: 5`) before allocation.
- 🗜 **Zlib File Compression** — Optional Gzip / Brotli response compression choices in `send_file()`.
- 🌐 **Compile-Time File Routing** — Build-time CMake directory scanner generating static route headers for static files (`StaticMount`) and C++ handler modules (`FolderMode`).

---

## License & Release

- **License**: WaveX is licensed under the [Mozilla Public License Version 2.0 (MPL-2.0)](LICENSE).
- **Third-Party Notices**: See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for dependency copyright statements.
- **Release Notes**: See [RELEASE_NOTES.md](RELEASE_NOTES.md) for version changelog and release history.

Copyright © 2026 Jyotipriya Mondal
