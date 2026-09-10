/**
 * @file test_method_template.cpp
 * @brief Unit tests for the wavex::engine::Router and HttpRouter class template.
 *
 * Covers:
 *  1. Static route registration and resolution across HTTP methods (verifying method & path separation)
 *  2. Singleton instance behaviour (`HttpRouter::instance()`)
 *  3. Dynamic parameter extraction (`:id`, `:name`)
 *  4. RE2 regex constraint matching (`{id:\d+}`)
 *  5. Wildcard catch-all parameter matching (`*`, `*path`)
 *  6. Global, scoped prefix, and per-route middleware chain order
 *  7. Resolution failures for non-existent paths or mismatched methods
 */

#include <wavex/wavex.hpp>

#define ASIO_HAS_CO_AWAIT 1
#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>

#include <iostream>
#include <string>
#include <vector>

// ─── Minimal concrete stubs for testing ──────────────────────────────────────

// ─── Minimal concrete stubs for testing ──────────────────────────────────────

struct [[maybe_unused]] TestRequest final : wavex::base::Request {
    std::string path_val;
    [[nodiscard]] std::string_view path_impl() const { return path_val; }
    [[nodiscard]] std::optional<std::string_view> header_impl(std::string_view) const { return std::nullopt; }
    [[nodiscard]] std::string_view body_impl() const { return {}; }
};

struct [[maybe_unused]] TestResponse final : wavex::base::Response {
    [[nodiscard]] std::string serialize_impl() const {
        return "HTTP/1.1 " + std::to_string(status_code_) + "\r\n\r\n" + body_;
    }
};

using HTTP_Method = wavex::protos::http::method;
using HttpRequest = wavex::protos::http::Http1Request;
using HttpResponse = wavex::protos::http::Http1Response;
using HttpRouter = wavex::engine::Http1Router;

namespace {
    int tests_run = 0;
    int tests_passed = 0;

    void check(const bool condition, const char *name) {
        ++tests_run;
        if (condition) {
            ++tests_passed;
            std::cout << "  [PASS] " << name << "\n";
        } else {
            std::cout << "  [FAIL] " << name << "\n";
        }
    }
}

template<typename Coro>
void run_sync(Coro coro) {
    asio::io_context ioc;
    asio::co_spawn(ioc, std::move(coro), asio::detached);
    ioc.run();
}

/// Helper function to execute a handler and return the resulting response body string
std::string execute_handler(const HttpRouter::Handler &h) {
    HttpRequest req;
    HttpResponse res;
    run_sync(h(req, res));
    return res.get_body();
}

asio::awaitable<void> dummy_handler(HttpRequest &, HttpResponse &res) {
    res.status(200).send("OK");
    co_return;
}

// ─── Test 1: Static Route Matching across HTTP Methods & Paths ───────────────

void test_static_routes() {
    std::cout << "\n[Test 1] Static route separation for different HTTP methods & paths\n";
    HttpRouter router;

    // Register distinct handlers for different HTTP methods on the EXACT SAME PATH
    router.get("/api/v1/resource", [](HttpRequest &, HttpResponse &res) -> asio::awaitable<void> {
        res.status(200).send("GET_RESOURCE_BODY");
        co_return;
    });

    router.post("/api/v1/resource", [](HttpRequest &, HttpResponse &res) -> asio::awaitable<void> {
        res.status(201).send("POST_RESOURCE_BODY");
        co_return;
    });

    router.put("/api/v1/resource", [](HttpRequest &, HttpResponse &res) -> asio::awaitable<void> {
        res.status(200).send("PUT_RESOURCE_BODY");
        co_return;
    });

    router.del("/api/v1/resource", [](HttpRequest &, HttpResponse &res) -> asio::awaitable<void> {
        res.status(204).send("DELETE_RESOURCE_BODY");
        co_return;
    });

    router.patch("/api/v1/resource", [](HttpRequest &, HttpResponse &res) -> asio::awaitable<void> {
        res.status(200).send("PATCH_RESOURCE_BODY");
        co_return;
    });

    router.query("/api/v1/resource", [](HttpRequest &, HttpResponse &res) -> asio::awaitable<void> {
        res.status(200).send("QUERY_RESOURCE_BODY");
        co_return;
    });

    // Register distinct handlers for DIFFERENT PATHS under the same prefix
    router.get("/api/v1/health", [](HttpRequest &, HttpResponse &res) -> asio::awaitable<void> {
        res.status(200).send("HEALTH_OK_BODY");
        co_return;
    });

    router.get("/api/v1/users", [](HttpRequest &, HttpResponse &res) -> asio::awaitable<void> {
        res.status(200).send("USERS_LIST_BODY");
        co_return;
    });

    // 1. Verify method separation on the same path
    auto match_get = router.resolve(HTTP_Method::GET, "/api/v1/resource");
    check(match_get.has_value(), "GET /api/v1/resource resolves successfully");
    if (match_get) {
        check(execute_handler(match_get->handler) == "GET_RESOURCE_BODY",
              "GET handler returns distinct body 'GET_RESOURCE_BODY'");
    }

    auto match_post = router.resolve(HTTP_Method::POST, "/api/v1/resource");
    check(match_post.has_value(), "POST /api/v1/resource resolves successfully");
    if (match_post) {
        check(execute_handler(match_post->handler) == "POST_RESOURCE_BODY",
              "POST handler returns distinct body 'POST_RESOURCE_BODY'");
    }

    auto match_put = router.resolve(HTTP_Method::PUT, "/api/v1/resource");
    check(match_put.has_value(), "PUT /api/v1/resource resolves successfully");
    if (match_put) {
        check(execute_handler(match_put->handler) == "PUT_RESOURCE_BODY",
              "PUT handler returns distinct body 'PUT_RESOURCE_BODY'");
    }

#ifdef DELETE
#undef DELETE
#endif
    auto match_del = router.resolve((HTTP_Method::DELETE), "/api/v1/resource");
    check(match_del.has_value(), "DELETE /api/v1/resource resolves successfully");
    if (match_del) {
        check(execute_handler(match_del->handler) == "DELETE_RESOURCE_BODY",
              "DELETE handler returns distinct body 'DELETE_RESOURCE_BODY'");
    }

    auto match_patch = router.resolve(HTTP_Method::PATCH, "/api/v1/resource");
    check(match_patch.has_value(), "PATCH /api/v1/resource resolves successfully");
    if (match_patch) {
        check(execute_handler(match_patch->handler) == "PATCH_RESOURCE_BODY",
              "PATCH handler returns distinct body 'PATCH_RESOURCE_BODY'");
    }

    auto match_query = router.resolve(HTTP_Method::QUERY, "/api/v1/resource");
    check(match_query.has_value(), "QUERY /api/v1/resource resolves successfully");
    if (match_query) {
        check(execute_handler(match_query->handler) == "QUERY_RESOURCE_BODY",
              "QUERY handler returns distinct body 'QUERY_RESOURCE_BODY'");
    }


    // 2. Verify path separation on the same method (GET)
    auto match_health = router.resolve(HTTP_Method::GET, "/api/v1/health");
    check(match_health.has_value(), "GET /api/v1/health resolves successfully");
    if (match_health) {
        check(execute_handler(match_health->handler) == "HEALTH_OK_BODY",
              "Health handler returns distinct body 'HEALTH_OK_BODY'");
    }

    auto match_users = router.resolve(HTTP_Method::GET, "/api/v1/users");
    check(match_users.has_value(), "GET /api/v1/users resolves successfully");
    if (match_users) {
        check(execute_handler(match_users->handler) == "USERS_LIST_BODY",
              "Users handler returns distinct body 'USERS_LIST_BODY'");
    }

    // 3. Verify non-existent method / path failures
    auto match_wrong_method = router.resolve(HTTP_Method::HEAD, "/api/v1/resource");
    check(!match_wrong_method.has_value(), "HEAD /api/v1/resource fails (unregistered method)");

    auto match_not_found = router.resolve(HTTP_Method::GET, "/api/v1/nonexistent");
    check(!match_not_found.has_value(), "GET /api/v1/nonexistent fails (404 path not found)");
}

// ─── Test 2: Singleton Instance Access ────────────────────────────────────────

void test_singleton_instance() {
    std::cout << "\n[Test 2] Router singleton instance identity & handler execution\n";

    auto &router1 = HttpRouter::instance();
    const auto &router2 = HttpRouter::instance();

    check(&router1 == &router2, "HttpRouter::instance() returns reference to exact same singleton");

    router1.clear();
    router1.get("/singleton/test", [](HttpRequest &, HttpResponse &res) -> asio::awaitable<void> {
        res.status(200).send("SINGLETON_RESPONSE");
        co_return;
    });

    const auto match = router2.resolve(HTTP_Method::GET, "/singleton/test");
    check(match.has_value(), "Route registered via reference 1 resolves via reference 2");
    if (match) {
        check(execute_handler(match->handler) == "SINGLETON_RESPONSE",
              "Singleton handler executes and produces 'SINGLETON_RESPONSE'");
    }

    router1.clear();
}

// ─── Test 3: Dynamic Path Parameters ──────────────────────────────────────────

void test_path_parameters() {
    std::cout << "\n[Test 3] Dynamic path parameters (:id, {name})\n";
    HttpRouter router;

    router.get("/users/:id/profile/:section", [](HttpRequest &, HttpResponse &res) -> asio::awaitable<void> {
        res.status(200).send("PROFILE_SECTION_OK");
        co_return;
    });

    router.get("/posts/{category}/{slug}", [](HttpRequest &, HttpResponse &res) -> asio::awaitable<void> {
        res.status(200).send("POST_CATEGORY_OK");
        co_return;
    });

    auto match = router.resolve(HTTP_Method::GET, "/users/42/profile/settings");
    check(match.has_value(), "Path with multiple :param parameters resolves");

    if (match) {
        check(match->params["id"] == "42", "Extracted parameter 'id' equals '42'");
        check(match->params["section"] == "settings", "Extracted parameter 'section' equals 'settings'");
        check(execute_handler(match->handler) == "PROFILE_SECTION_OK",
              "Param route handler returns 'PROFILE_SECTION_OK'");
    }

    auto match_brace = router.resolve(HTTP_Method::GET, "/posts/tech/cxx20-modules");
    check(match_brace.has_value(), "Path with {name} parameters resolves");
    if (match_brace) {
        check(match_brace->params["category"] == "tech", "Extracted parameter 'category' equals 'tech'");
        check(match_brace->params["slug"] == "cxx20-modules", "Extracted parameter 'slug' equals 'cxx20-modules'");
        check(execute_handler(match_brace->handler) == "POST_CATEGORY_OK",
              "Brace param route handler returns 'POST_CATEGORY_OK'");
    }
}

// ─── Test 4: RE2 Regex Constraints ───────────────────────────────────────────

void test_regex_constraints() {
    std::cout << "\n[Test 4] RE2 regex constraints {id:\\d+}\n";
    HttpRouter router;

    router.get("/items/{id:\\d+}", [](HttpRequest &, HttpResponse &res) -> asio::awaitable<void> {
        res.status(200).send("NUMERIC_ITEM_OK");
        co_return;
    });

    auto match_numeric = router.resolve(HTTP_Method::GET, "/items/12345");
    check(match_numeric.has_value(), "Numeric path matches regex constraint {id:\\d+}");
    if (match_numeric) {
        check(match_numeric->params["id"] == "12345", "Extracted regex parameter 'id' equals '12345'");
        check(execute_handler(match_numeric->handler) == "NUMERIC_ITEM_OK",
              "Regex route handler returns 'NUMERIC_ITEM_OK'");
    }

    const auto match_alpha = router.resolve(HTTP_Method::GET, "/items/abcde");
    check(!match_alpha.has_value(), "Alpha path fails regex constraint {id:\\d+}");
}

// ─── Test 5: Wildcard Catch-All ───────────────────────────────────────────────

void test_wildcards() {
    std::cout << "\n[Test 5] Wildcard parameter matching (*, *filepath)\n";
    HttpRouter router;

    router.get("/static/*filepath", [](HttpRequest &, HttpResponse &res) -> asio::awaitable<void> {
        res.status(200).send("STATIC_FILE_OK");
        co_return;
    });

    auto match = router.resolve(HTTP_Method::GET, "/static/css/themes/dark.css");
    check(match.has_value(), "Wildcard path /static/*filepath resolves multi-segment path");
    if (match) {
        check(match->params["filepath"] == "css/themes/dark.css",
              "Wildcard parameter 'filepath' captured 'css/themes/dark.css'");
        check(execute_handler(match->handler) == "STATIC_FILE_OK", "Wildcard route handler returns 'STATIC_FILE_OK'");
    }
}

// ─── Test 6: Scoped & Global Middleware Chain Order ──────────────────────────

void test_middleware_chain() {
    std::cout << "\n[Test 6] Middleware chain execution (global -> scoped -> per-route)\n";
    HttpRouter router;

    std::vector<std::string> order;

    // Global MW
    router.use([&order](HttpRequest &, HttpResponse &, const wavex::base::Next next) -> asio::awaitable<void> {
        order.push_back("global");
        co_await next();
    });

    // Scoped MW for /api
    router.use("/api", [&order](HttpRequest &, HttpResponse &, const wavex::base::Next next) -> asio::awaitable<void> {
        order.push_back("scoped_api");
        co_await next();
    });

    // Per-route MW
    HttpRouter::MiddlewareFn route_mw = [&order](HttpRequest &, HttpResponse &,
                                                 const wavex::base::Next next) -> asio::awaitable<void> {
        order.push_back("per_route");
        co_await next();
    };

    router.get("/api/v1/test", {route_mw}, [](HttpRequest &, HttpResponse &res) -> asio::awaitable<void> {
        res.status(200).send("MW_TEST_OK");
        co_return;
    });

    const auto match = router.resolve(HTTP_Method::GET, "/api/v1/test");
    check(match.has_value(), "Route with full middleware chain resolved");
    if (match) {
        check(match->middlewares.size() == 3, "Middleware chain contains 3 functions");
        check(execute_handler(match->handler) == "MW_TEST_OK", "Route handler returns 'MW_TEST_OK'");
    }
}

// ─── main ─────────────────────────────────────────────────────────────────────

int main() {
    std::cout << "=== WaveX Router & HttpRouter Unit Tests ===\n";

    test_static_routes();
    test_singleton_instance();
    test_path_parameters();
    test_regex_constraints();
    test_wildcards();
    test_middleware_chain();

    std::cout << "\n" << tests_passed << "/" << tests_run << " tests passed.\n";
    return tests_passed == tests_run ? 0 : 1;
}
