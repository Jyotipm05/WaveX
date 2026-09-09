/**
 * @file postman_demo_tls_server.cpp
 * @brief Interactive WaveX HTTPS/TLS 1.3 Server for Postman & Manual SSL Testing.
 *
 * Listens on: https://127.0.0.1:8443
 * Uses certificate keypair from ssl/test.crt and ssl/test.key
 *
 * Quick Test Endpoints Reference for Postman / cURL:
 * ====================================================================================================
 *  METHOD  | PATH                       | HEADERS / BODY                        | EXPECTED RESPONSE
 * ====================================================================================================
 *  1. GET  | /                          | None                                  | 200 OK - Welcome message over TLS 1.3
 *  2. GET  | /api/json                  | None                                  | 200 OK - Framework TLS metadata
 *  3. POST | /api/echo                  | Content-Type: application/json        | 200 OK - Echoes request body over HTTPS
 *          |                            | Body: {"name": "WaveX", "tls": true}  |
 *  4. GET  | /api/protected             | None                                  | 401 Unauthorized
 *  5. GET  | /api/protected             | Authorization: Bearer secret123       | 200 OK - Secret data over HTTPS
 *  6. GET  | /users/:id                 | None                                  | 200 OK - Dynamic path parameter
 *  7. GET  | /files/ *filepath          | None                                  | 200 OK - Wildcard catch-all match
 * ====================================================================================================
 *
 * Example cURL test:
 *   curl -k https://127.0.0.1:8443/api/json
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

// Global Logger Middleware for TLS Server
asio::awaitable<void> tls_logger_middleware(const HttpRequest &req, const HttpResponse &res, base::Next next) {
    std::cout << "[TLS-LOG] Incoming HTTPS request: " << req.path() << "\n";
    co_await next();
    std::cout << "[TLS-LOG] HTTPS Response status: " << res.status_code() << " for " << req.path() << "\n";
}

// Auth Middleware (Postman header required: Authorization: Bearer secret123)
asio::awaitable<void> tls_auth_middleware(const HttpRequest &req, HttpResponse &res, base::Next next) {
    auto auth_header = req.header("Authorization");
    if (!auth_header || *auth_header != "Bearer secret123") {
        std::cout << "[TLS-AUTH] Unauthorized attempt on " << req.path() << "\n";
        res.status(401).json({
            {"error", "Unauthorized"},
            {"message", "Missing or invalid 'Authorization: Bearer secret123' header over TLS"}
        });
        co_return;
    }

    std::cout << "[TLS-AUTH] Access granted for " << req.path() << "\n";
    co_await next();
}

int main(int argc, char *argv[]) {
    std::string cert_file = "ssl/test.crt";
    std::string key_file = "ssl/test.key";

    if (argc >= 3) {
        cert_file = argv[1];
        key_file = argv[2];
    }

    std::cout << "=========================================================================\n";
    std::cout << ("               WaveX TLS 1.3 Dev v" + std::string(wx_version) +
                  " / Postman Server               \n");
    std::cout << "=========================================================================\n";
    std::cout << " Cert File: " << cert_file << "\n";
    std::cout << " Key File : " << key_file << "\n";
    std::cout << "=========================================================================\n";
    std::cout << " Endpoints available for testing over HTTPS:\n";
    std::cout << "  1. GET  https://127.0.0.1:8443/\n";
    std::cout << "  2. GET  https://127.0.0.1:8443/api/json\n";
    std::cout << "  3. POST https://127.0.0.1:8443/api/echo  (Body: JSON payload)\n";
    std::cout << "  4. GET  https://127.0.0.1:8443/api/protected  (Header: Authorization: Bearer secret123)\n";
    std::cout << "  5. GET  https://127.0.0.1:8443/users/42\n";
    std::cout << "  6. GET  https://127.0.0.1:8443/files/documents/2026/report.pdf\n";
    std::cout << "=========================================================================\n\n";

    auto &router = HttpRouter::instance();

    // 1. Root route
    router.get("/", [](HttpRequest &, HttpResponse &res) -> asio::awaitable<void> {
        res.status(200).send("Welcome to WaveX HTTPS (TLS 1.3) Server!");
        co_return;
    });

    // 2. JSON endpoint
    router.get("/api/json", [](HttpRequest &, HttpResponse &res) -> asio::awaitable<void> {
        res.status(200).json({
            {"status", "success"},
            {"framework", "WaveX"},
            {"version", wx_version},
            {"tls_version", "TLS 1.3"},
            {"features", {"TLS 1.3 OpenSSL encryption", "express-style immediate send", "linear middleware"}}
        });
        co_return;
    });

    // 3. POST Echo endpoint
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
            {"message", "TLS Echo received"},
            {"path", std::string(req.path())},
            {"received_body", parsed_body}
        });
        co_return;
    });

    // 4. Protected route
    router.get("/api/protected", {tls_auth_middleware}, [](HttpRequest &, HttpResponse &res) -> asio::awaitable<void> {
        res.status(200).json({
            {"status", "granted"},
            {"secret_data", "Super secret HTTPS data accessible only with valid auth header!"}
        });
        co_return;
    });

    // 5. Dynamic path parameter
    router.get("/users/:id", [](const HttpRequest &req, HttpResponse &res) -> asio::awaitable<void> {
        res.status(200).json({
            {"endpoint", "tls_user_details"},
            {"path", std::string(req.path())}
        });
        co_return;
    });

    // 6. Wildcard endpoint
    router.get("/files/*filepath", [](const HttpRequest &req, HttpResponse &res) -> asio::awaitable<void> {
        res.status(200).json({
            {"endpoint", "tls_wildcard_file_handler"},
            {"matched_path", std::string(req.path())}
        });
        co_return;
    });

    try {
        server::Http1Server server(router, "127.0.0.1", 8443);
        server.enable_tls(cert_file, key_file);

        std::cout << "TLS Server successfully listening on https://127.0.0.1:8443 (TLS 1.3 Active)\n";
        std::cout << "Press Ctrl+C to stop.\n\n";
        server.run();
    } catch (const std::exception &e) {
        std::cerr << "[TLS Server Error] " << e.what() << "\n";
        return 1;
    }

    return 0;
}
