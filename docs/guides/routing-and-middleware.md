# Routing, Middleware & Responses

Everything you need to register routes, read parameters, short-circuit with middleware, fuse static pipelines, customize 404s and redirect.

## Hello, World

The absolute simplest WaveX server in under 15 lines of code:

```c++
#include <wavex/wavex.hpp>

int main() {
    auto &router = wavex::engine::HttpRouter::instance();

    // Plain text "Hello, World!" endpoint
    router.get("/", [](auto &, auto &res) -> wavex::task<void> {
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

## JSON and route parameters

Returning structured JSON and reading dynamic path parameters (`:name`):

```c++
#include <wavex/wavex.hpp>

int main() {
    auto &router = wavex::engine::HttpRouter::instance();

    // 1. JSON "Hello, World!" endpoint
    router.get("/api/hello", [](auto &, auto &res) -> wavex::task<void> {
        res.status(200).json({
            {"message", "Hello, World!"},
            {"framework", "WaveX"},
            {"status", "success"}
        });
        co_return;
    });

    // 2. Dynamic route parameter: /hello/Alice -> "Hello, Alice!"
    router.get("/hello/:name", [](auto &req, auto &res) -> wavex::task<void> {
        auto name = req.param("name").value_or("World");
        res.status(200).send("Hello, " + std::string(name) + "!");
        co_return;
    });

    wavex::server::Server server(router, "127.0.0.1", 8080);
    server.run();

    return 0;
}
```

Route syntax supported by the radix-tree router: static segments, `:id` parameters, `{id:[0-9]+}` RE2 constraints, `*filepath` catch-alls, and every RFC 9110 method including `QUERY`.

## Coroutine middleware

Middleware are coroutines that either call `co_await next()` or answer the request and return (short-circuit).

```c++
#include <iostream>
#include <wavex/wavex.hpp>

using namespace wavex;

// Auth Guard Middleware
wavex::task<void> auth_guard(protos::http::HttpRequest &req, protos::http::HttpResponse &res, base::Next next) {
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
    router.get("/", [](protos::http::HttpRequest &, protos::http::HttpResponse &res) -> wavex::task<void> {
        res.status(200).send("Welcome to WaveX!");
        co_return;
    });

    // 2. JSON endpoint
    router.get("/api/json", [](protos::http::HttpRequest &, protos::http::HttpResponse &res) -> wavex::task<void> {
        res.status(200).json({{"status", "success"}, {"framework", "WaveX"}, {"version", wx_version}});
        co_return;
    });

    // 3. Protected endpoint with middleware
    router.get("/api/protected", {auth_guard}, [](protos::http::HttpRequest &, protos::http::HttpResponse &res) -> wavex::task<void> {
        res.status(200).json({{"secret", "Access Granted"}});
        co_return;
    });

    // 4. Wildcard catch-all endpoint
    router.get("/files/*filepath", [](protos::http::HttpRequest &req, protos::http::HttpResponse &res) -> wavex::task<void> {
        res.status(200).json({{"file", std::string(req.path())}});
        co_return;
    });

    server::Server server(router, "127.0.0.1", 8080);
    wavex::log::info("WaveX server running on http://127.0.0.1:8080");
    server.run();

    return 0;
}
```

## Static pipelines with `Chainable`

Build compile-time static dispatch pipelines without vtables or dynamic heap allocations using `StaticChain` and `make_chain`:

```c++
#include <wavex/Base/Chainable.hpp>
#include <wavex/Engine/HttpRouter.hpp>
#include <iostream>

// 1. Define Chainable Middlewares using C++23 "Deducing This"
struct AuthGuard : public wavex::Chainable {
    template <typename Self, typename Req, typename Res>
    wavex::task<bool> handle_impl(this Self&& self, Req& req, Res& res) {
        if (req.header("Authorization") != "Bearer valid_token") {
            res.status(401).send("Unauthorized");
            co_return false; // Short-circuits remaining pipeline statically!
        }
        co_return true; // Proceed to next handler
    }
};

struct AuditLogger : public wavex::Chainable {
    template <typename Self, typename Req, typename Res>
    wavex::task<bool> handle_impl(this Self&& self, Req& req, Res& res) {
        std::cout << "[AuditLog] Request path: " << req.path() << "\n";
        co_return true;
    }
};

struct TargetHandler : public wavex::Chainable {
    template <typename Self, typename Req, typename Res>
    wavex::task<bool> handle_impl(this Self&& self, Req& req, Res& res) {
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

## Custom 404 handling

By default, any unmatched route automatically responds with HTTP status 404 and the plain text `"Not Found"`. Developers can easily customize 404 handling across both `HttpRouter` and `Server`:

### Option A: Custom String, HTML, or JSON

```c++
// Custom plain text or HTML on Router
router.not_found("<h1>404 - Page Not Found</h1>", "text/html");

// Or configure directly on Server
server.set_not_found("Custom 404 text", "text/plain");
```

### Option B: Load Error Page from File (Auto-MIME Detection)

```c++
// Reads static file from disk and infers Content-Type via wavex::base::mime_type_from_path
router.not_found_page("public/404.html");

// Or configure directly on Server
server.set_not_found_page("public/404.html");
```

### Option C: Full Dynamic Coroutine Handler

```c++
router.not_found([](auto &req, auto &res) -> wavex::task<void> {
    nlohmann::json j = {
        {"error", "Not Found"},
        {"requested_path", std::string(req.path())},
        {"method", to_string(req.method_type())}
    };
    res.status(404).json(j);
    co_return;
});
```

## Redirects

Express- and Fastify-compatible redirections with zero boilerplate:

```c++
#include <wavex/wavex.hpp>

int main() {
    auto &router = wavex::engine::HttpRouter::instance();

    // 1. Default temporary redirect (302 Found)
    router.get("/old-docs", [](auto &, auto &res) -> wavex::task<void> {
        res.redirect("/docs/v2");
        co_return;
    });

    // 2. Custom status redirect (e.g. 307 Temporary Redirect, or 303 See Other)
    router.post("/login", [](auto &, auto &res) -> wavex::task<void> {
        res.redirect("/dashboard", 307);
        // Equivalent: res.redirect(307, "/dashboard");
        co_return;
    });

    // 3. Permanent redirect (301 Moved Permanently; pass true for 308)
    router.get("/legacy-api", [](auto &, auto &res) -> wavex::task<void> {
        res.permanent_redirect("/api/v1");
        co_return;
    });

    // 4. Temporary redirect helper (302 Found; pass true for 307)
    router.get("/profile", [](auto &, auto &res) -> wavex::task<void> {
        res.temporary_redirect("/user/profile");
        co_return;
    });

    wavex::server::Server server(router, "127.0.0.1", 8080);
    server.run();
}
```

## The `QUERY` method

WaveX supports the RFC 9110 `QUERY` method (a safe request that carries a body) next to `GET`, `POST`, `PUT`, `DELETE` and `PATCH`.

An asynchronous coroutine handler querying DNS records without blocking worker threads:

```c++
#include <wavex/wavex.hpp>
#include <nlohmann/json.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/as_tuple.hpp>
#include <asio/use_awaitable.hpp>

auto &router = wavex::engine::Http1Router::instance();

auto dns_handler = [](const auto &req, auto &res) -> wavex::task<void> {
    auto j = nlohmann::json::parse(req.body(), nullptr, false);
    std::string domain = j.value("domain", "");

    if (domain.empty()) {
        res.status(400).json({
            {"status", "error"},
            {"message", "Missing 'domain' in JSON body. Example: {\"domain\": \"google.com\"}"}
        });
        co_return;
    }

    auto executor = co_await asio::this_coro::executor;
    asio::ip::tcp::resolver resolver(executor);

    auto [ec, results] = co_await resolver.async_resolve(domain, "", asio::as_tuple(asio::use_awaitable));
    if (ec) {
        res.status(404).json({
            {"status", "error"},
            {"domain", domain},
            {"message", "Failed to resolve domain: " + ec.message()}
        });
        co_return;
    }

    std::vector<std::string> ips;
    for (const auto &entry : results) {
        ips.push_back(entry.endpoint().address().to_string());
    }

    res.status(200).json({
        {"status", "success"},
        {"domain", domain},
        {"ip", ips.empty() ? "" : ips.front()},
        {"ips", ips}
    });
    co_return;
};

// Route can be called via either standard POST or RFC 9110 QUERY
router.post("/api/query", dns_handler);
router.query("/api/query", dns_handler);
```

---

**See also:** [Connections & shutdown](connections-and-shutdown.md) · [Memory & lifetimes](memory-and-lifetimes.md) · [Architecture](../architecture.md)
