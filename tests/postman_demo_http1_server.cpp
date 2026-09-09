/**
 * @file postman_demo_http1_server.cpp
 * @brief Unified Interactive WaveX HTTP/1.1 Dev Server (Plain & TLS 1.3) for Postman & Manual Testing.
 *
 * Configured via built-in WaveX CLI argument parser (wavex::cli::CliParser).
 *
 * Usage examples:
 *   ./wavex_postman_http1_server                      # Plain HTTP on http://127.0.0.1:8080
 *   ./wavex_postman_http1_server --tls                # HTTPS/TLS 1.3 on https://127.0.0.1:8443
 *   ./wavex_postman_http1_server -p 9000              # Plain HTTP on http://127.0.0.1:9000
 *   ./wavex_postman_http1_server --tls -p 4430 -c ssl/test.crt -k ssl/test.key
 *   ./wavex_postman_http1_server --help               # Show CLI usage and option details
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
    std::cout << "[HTTP1-LOG] Incoming request: " << req.path() << "\n";
    co_await next();
    std::cout << "[HTTP1-LOG] Response status: " << res.status_code() << " for " << req.path() << "\n";
}

// Auth Middleware (Postman header required: Authorization: Bearer secret123)
asio::awaitable<void> auth_middleware(const HttpRequest &req, HttpResponse &res, base::Next next) {
    const auto auth_header = req.header("Authorization");
    if (!auth_header || *auth_header != "Bearer secret123") {
        std::cout << "[HTTP1-AUTH] Unauthorized attempt on " << req.path() << "\n";
        res.status(401).json({
            {"error", "Unauthorized"},
            {"message", "Missing or invalid 'Authorization: Bearer secret123' header"}
        });
        co_return; // Immediate response sent, short-circuits remaining pipeline!
    }

    std::cout << "[HTTP1-AUTH] Access granted for " << req.path() << "\n";
    co_await next();
}

int main(int argc, char *argv[]) {
    cli::CliParser parser("wavex_postman_http1_server",
                          "Unified WaveX HTTP/1.1 Interactive Dev & Postman Testing Server");

    parser.add_flag("tls", 's', "Enable HTTPS / TLS 1.3 encryption (default: disabled)")
            .add_option("port", 'p', "Port number to listen on (default: 8080 plain, 8443 with --tls)")
            .add_option("host", 'H', "Host IP address to bind to", "127.0.0.1")
            .add_option("cert", 'c', "Path to TLS certificate file", "ssl/test.crt")
            .add_option("key", 'k', "Path to TLS private key file", "ssl/test.key");

    const auto parse_res = parser.parse(argc, argv);
    if (!parse_res.ok()) {
        if (parse_res.help_requested) {
            parser.print_help();
            return 0;
        }
        std::cerr << "Error: " << parse_res.error_message << "\n\n";
        parser.print_help();
        return 1;
    }

    const bool is_tls = parser.get_bool("tls");
    const std::string host = parser.get_string("host");
    const std::string cert_file = parser.get_string("cert");
    const std::string key_file = parser.get_string("key");

    // Dynamic default port based on TLS mode
    const int default_port = is_tls ? 8443 : 8080;
    const int port = parser.has("port") ? parser.get_int("port", default_port) : default_port;

    const std::string scheme = is_tls ? "https" : "http";
    const std::string base_url = scheme + "://" + host + ":" + std::to_string(port);

    std::cout << "=========================================================================\n";
    std::cout << "           WaveX Interactive Dev v" << wx_version
            << " / Postman Server (HTTP/1.1)           \n";
    std::cout << "=========================================================================\n";
    std::cout << " Protocol : HTTP/1.1 " << (is_tls ? "[TLS 1.3 Active]" : "[Plain TCP]") << "\n";
    std::cout << " Bound To : " << base_url << "\n";
    if (is_tls) {
        std::cout << " Cert File: " << cert_file << "\n";
        std::cout << " Key File : " << key_file << "\n";
    }
    std::cout << "=========================================================================\n";
    std::cout << " Quick Test Endpoints Reference for Postman / cURL:\n";
    std::cout << "  1. GET  " << base_url << "/\n";
    std::cout << "  2. GET  " << base_url << "/api/json\n";
    std::cout << "  3. POST " << base_url << "/api/echo  (Body: JSON payload)\n";
    std::cout << "  4. GET  " << base_url << "/api/protected  (Header: Authorization: Bearer secret123)\n";
    std::cout << "  5. GET  " << base_url << "/users/42\n";
    std::cout << "  6. GET  " << base_url << "/files/documents/2026/report.pdf  (Wildcard match)\n";
    std::cout << "=========================================================================\n\n";

    auto &router = HttpRouter::instance();

    // 1. Root route - Plain text
    router.get("/", [is_tls](HttpRequest &, HttpResponse &res) -> asio::awaitable<void> {
        res.status(200).send("Welcome to WaveX HTTP/1.1 " + std::string(is_tls ? "(TLS 1.3) " : "") + "Server!");
        co_return;
    });

    // 2. JSON endpoint
    router.get("/api/json", [is_tls](HttpRequest &, HttpResponse &res) -> asio::awaitable<void> {
        res.status(200).json({
            {"status", "success"},
            {"framework", "WaveX"},
            {"version", wx_version},
            {"protocol", "HTTP/1.1"},
            {"tls_enabled", is_tls},
            {
                "features", {
                    is_tls ? "TLS 1.3 OpenSSL encryption" : "Cleartext HTTP/1.1 transport",
                    "express-style immediate send",
                    "linear middleware chaining",
                    "zero-alloc coroutines",
                    "built-in CLI parser"
                }
            }
        });
        co_return;
    });

    // 3. POST Echo endpoint (processes JSON body)
    router.post("/api/echo", [](const HttpRequest &req, HttpResponse &res) -> asio::awaitable<void> {
        const std::string raw(req.body());
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
            {"protocol", "HTTP/1.1"},
            {"path", std::string(req.path())},
            {"received_body", parsed_body}
        });
        co_return;
    });

    // 4. Protected route with Auth Middleware
    router.get("/api/protected", {auth_middleware}, [](HttpRequest &, HttpResponse &res) -> asio::awaitable<void> {
        res.status(200).json({
            {"status", "granted"},
            {"secret_data", "Super secret HTTP/1.1 information accessible only with valid auth header!"}
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
        server::Http1Server server(router, host, static_cast<unsigned short>(port));
        if (is_tls) {
#if WAVEX_HAS_SSL
            server.enable_tls(cert_file, key_file);
            std::cout << "Server successfully listening on " << base_url << " (TLS 1.3 Active)\n";
#else
            std::cerr << "Fatal Error: WaveX was built without SSL support (WAVEX_HAS_SSL=0)!\n";
            return 1;
#endif
        } else {
            std::cout << "Server successfully listening on " << base_url << "\n";
        }

        std::cout << "Press Ctrl+C to stop.\n\n";
        server.run();
    } catch (const std::exception &e) {
        std::cerr << "[HTTP/1 Server Error] " << e.what() << "\n";
        return 1;
    }

    return 0;
}
