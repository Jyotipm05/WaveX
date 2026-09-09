/**
 * @file postman_demo_server.cpp
 * @brief Interactive WaveX HTTP Server for Postman & Manual Testing.
 *
 * Listens on: http://127.0.0.1:8080
 *
 * Quick Test Endpoints Reference for Postman / cURL:
 * ====================================================================================================
 *  METHOD  | PATH                       | HEADERS / BODY                        | EXPECTED RESPONSE
 * ====================================================================================================
 *  1. GET  | /                          | None                                  | 200 OK - Welcome message
 *  2. GET  | /api/json                  | None                                  | 200 OK - Framework JSON metadata
 *  3. POST | /api/echo                  | Content-Type: application/json        | 200 OK - Echoes request body
 *          |                            | Body: {"name": "WaveX", "test": true} |
 *  4. GET  | /api/protected             | None                                  | 401 Unauthorized (Pipeline short-circuit test)
 *  5. GET  | /api/protected             | Authorization: Bearer secret123       | 200 OK - Secret data (Access Granted)
 *  6. GET  | /users/:id                 | None                                  | 200 OK - Dynamic path parameter matching
 *  7. GET  | /files/ *filepath          | None                                  | 200 OK - Wildcard catch-all match
 *          | (e.g. /files/docs/2026/r.pdf)|                                       |
 * ====================================================================================================
 */

#ifndef ASIO_HAS_CO_AWAIT
#define ASIO_HAS_CO_AWAIT 1
#endif

#include <iostream>
#include <string>
#include <nlohmann/json.hpp>
#include <wavex/wavex.hpp>

using namespace wavex;
using HttpRequest = protos::http::Http1Request;
using HttpResponse = protos::http::Http1Response;
using HttpRouter = engine::Http1Router;

// Global Logger Middleware
asio::awaitable<void> logger_middleware(const HttpRequest &req, const HttpResponse &res, base::Next next) {
    std::cout << "[LOG] Incoming request: " << req.path() << "\n";
    co_await next();
    std::cout << "[LOG] Response status: " << res.status_code() << " for " << req.path() << "\n";
}

// Auth Middleware (Postman header required: Authorization: Bearer secret123)
asio::awaitable<void> auth_middleware(const HttpRequest &req, HttpResponse &res, base::Next next) {
    auto auth_header = req.header("Authorization");
    if (!auth_header || *auth_header != "Bearer secret123") {
        std::cout << "[AUTH] Unauthorized attempt on " << req.path() << "\n";
        res.status(401).json({
            {"error", "Unauthorized"},
            {"message", "Missing or invalid 'Authorization: Bearer secret123' header"}
        });
        co_return; // Immediate response sent, short-circuits remaining pipeline!
    }

    std::cout << "[AUTH] Access granted for " << req.path() << "\n";
    co_await next();
}

int main() {
    std::cout << "=========================================================================\n";
    std::cout << ("               WaveX Interactive Dev v" + std::string(wx_version) +
                  " / Postman Server                    \n");
    std::cout << "=========================================================================\n";
    std::cout << " Endpoints available for testing:\n";
    std::cout << "  1. GET  http://127.0.0.1:8080/\n";
    std::cout << "  2. GET  http://127.0.0.1:8080/api/json\n";
    std::cout << "  3. POST http://127.0.0.1:8080/api/echo  (Body: JSON payload)\n";
    std::cout << "  4. GET  http://127.0.0.1:8080/api/protected  (Header: Authorization: Bearer secret123)\n";
    std::cout << "  5. GET  http://127.0.0.1:8080/users/42\n";
    std::cout << "  6. GET  http://127.0.0.1:8080/files/documents/2026/report.pdf  (Wildcard match)\n";
    std::cout << "=========================================================================\n\n";

    auto &router = HttpRouter::instance();

    // 1. Root route - Plain text
    router.get("/", [](HttpRequest &, HttpResponse &res) -> asio::awaitable<void> {
        res.status(200).send("Welcome to WaveX HTTP Server!");
        co_return;
    });

    // 2. JSON endpoint
    router.get("/api/json", [](HttpRequest &, HttpResponse &res) -> asio::awaitable<void> {
        res.status(200).json({
            {"status", "success"},
            {"framework", "WaveX"},
            {"version", wx_version},
            {"features", {"express-style immediate send", "linear middleware", "zero-alloc coroutines"}}
        });
        co_return;
    });

    // 3. POST Echo endpoint (processes JSON body)
    router.post("/api/echo", [](const HttpRequest &req, HttpResponse &res) -> asio::awaitable<void> {
        std::string raw(req.body());
        nlohmann::json parsed_body;

        if (raw.empty()) {
            parsed_body = nullptr;
        } else {
            auto j = nlohmann::json::parse(raw, nullptr, false);
            if (!j.is_discarded()) {
                parsed_body = std::move(j);
            } else {
                parsed_body = raw;
            }
        }

        res.status(200).json({
            {"message", "Echo received"},
            {"path", std::string(req.path())},
            {"received_body", parsed_body}
        });
        co_return;
    });

    // 4. Protected route with Auth Middleware
    router.get("/api/protected", {auth_middleware}, [](HttpRequest &, HttpResponse &res) -> asio::awaitable<void> {
        res.status(200).json({
            {"status", "granted"},
            {"secret_data", "Super secret information accessible only with valid auth header!"}
        });
        co_return;
    });

    // 5. Dynamic path parameter
    router.get("/users/:id", [](const HttpRequest &req, HttpResponse &res) -> asio::awaitable<void> {
        res.status(200).json({
            {"endpoint", "user_details"},
            {"path", std::string(req.path())}
        });
        co_return;
    });

    // 6. Wildcard endpoint (*filepath matches any nested subpaths under /files/)
    router.get("/files/*filepath", [](const HttpRequest &req, HttpResponse &res) -> asio::awaitable<void> {
        res.status(200).json({
            {"endpoint", "wildcard_file_handler"},
            {"matched_path", std::string(req.path())},
            {"description", "Wildcard route *filepath caught nested subpath under /files/"}
        });
        co_return;
    });

    try {
        server::Http1Server server(router, "127.0.0.1", 8080);
        std::cout << "Server successfully listening on http://127.0.0.1:8080\n";
        std::cout << "Press Ctrl+C to stop.\n\n";
        server.run();
    } catch (const std::exception &e) {
        std::cerr << "[Server Error] " << e.what() << "\n";
        return 1;
    }

    return 0;
}
