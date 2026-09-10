/**
 * @file test_not_found.cpp
 * @brief Unit & integration tests for 404 Not Found handling in WaveX.
 */

#include <wavex/wavex.hpp>

#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <asio.hpp>

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

// ─── Test 1: Router Default 404 Handler ───────────────────────────────────────

void test_router_default_not_found() {
    std::cout << "\n[Test 1] Router default 404 handler returns 'Not Found'\n";

    auto router = wavex::engine::Http1Router::make_instance();
    router.get("/hello", [](auto &, auto &res) -> asio::awaitable<void> {
        res.status(200).send("OK");
        co_return;
    });

    wavex::protos::http::Http1Request req("GET /nonexistent HTTP/1.1\r\nHost: localhost\r\n\r\n");
    check(req.parse(), "Parse request");

    auto match = router.resolve(req.method_type(), req.path());
    check(!match.has_value(), "Route does not match");

    wavex::protos::http::Http1Response res;
    asio::io_context ioc;
    asio::co_spawn(ioc, router.not_found_handler()(req, res), asio::detached);
    ioc.run();

    check(res.status_code() == 404, "Default status code is 404");
    check(res.get_body() == "Not Found", "Default body is 'Not Found'");
}

// ─── Test 2: Router Custom String & Content-Type ──────────────────────────────

void test_router_custom_string_not_found() {
    std::cout << "\n[Test 2] Router custom string & Content-Type\n";

    auto router = wavex::engine::Http1Router::make_instance();
    router.not_found("<h1>Oops! Page Not Found</h1>", "text/html");

    wavex::protos::http::Http1Request req("GET /missing HTTP/1.1\r\nHost: localhost\r\n\r\n");
    check(req.parse(), "Parse request");

    wavex::protos::http::Http1Response res;
    asio::io_context ioc;
    asio::co_spawn(ioc, router.not_found_handler()(req, res), asio::detached);
    ioc.run();

    check(res.status_code() == 404, "Status code is 404");
    check(res.get_body() == "<h1>Oops! Page Not Found</h1>", "Body matches custom HTML");
    auto ct = res.header("Content-Type");
    check(ct.has_value() && *ct == "text/html", "Content-Type is text/html");
}

// ─── Test 3: Router Custom Page from File ─────────────────────────────────────

void test_router_custom_page_file() {
    std::cout << "\n[Test 3] Router custom page from file\n";

    // Create a temporary 404 html file
    std::string temp_file = "test_temp_404.html"; {
        std::ofstream out(temp_file);
        out << "<!DOCTYPE html><html><body><h1>404 Custom Error</h1></body></html>";
    }

    auto router = wavex::engine::Http1Router::make_instance();
    router.not_found_page(temp_file);

    wavex::protos::http::Http1Request req("GET /lost HTTP/1.1\r\nHost: localhost\r\n\r\n");
    check(req.parse(), "Parse request");

    wavex::protos::http::Http1Response res;
    asio::io_context ioc;
    asio::co_spawn(ioc, router.not_found_handler()(req, res), asio::detached);
    ioc.run();

    check(res.status_code() == 404, "Status code is 404");
    check(res.get_body().find("404 Custom Error") != std::string::npos, "File content loaded into body");
    auto ct = res.header("Content-Type");
    check(ct.has_value() && *ct == "text/html; charset=utf-8", "Content-Type inferred as text/html");

    // Clean up temp file
    std::filesystem::remove(temp_file);

    // Test fallback when file does not exist
    router.not_found_page("non_existent_page_12345.html");
    wavex::protos::http::Http1Response res_fallback;
    ioc.restart();
    asio::co_spawn(ioc, router.not_found_handler()(req, res_fallback), asio::detached);
    ioc.run();

    check(res_fallback.status_code() == 404, "Fallback status code is 404");
    check(res_fallback.get_body() == "Not Found", "Fallback body is 'Not Found'");
}

// ─── Test 4: Router Dynamic Coroutine Handler ─────────────────────────────────

void test_router_dynamic_coroutine_handler() {
    std::cout << "\n[Test 4] Router dynamic coroutine handler\n";

    auto router = wavex::engine::Http1Router::make_instance();
    router.not_found([](wavex::protos::http::Http1Request &req,
                        wavex::protos::http::Http1Response &res) -> asio::awaitable<void> {
        nlohmann::json j = {
            {"error", "Route Not Found"},
            {"requested_path", std::string(req.path())}
        };
        res.status(404).json(j);
        co_return;
    });

    wavex::protos::http::Http1Request req("GET /api/unknown/resource HTTP/1.1\r\nHost: localhost\r\n\r\n");
    check(req.parse(), "Parse request");

    wavex::protos::http::Http1Response res;
    asio::io_context ioc;
    asio::co_spawn(ioc, router.not_found_handler()(req, res), asio::detached);
    ioc.run();

    check(res.status_code() == 404, "Status code is 404");
    check(res.get_body().find("\"Route Not Found\"") != std::string::npos, "JSON contains error field");
    check(res.get_body().find("/api/unknown/resource") != std::string::npos, "JSON contains requested path");
    auto ct = res.header("Content-Type");
    check(ct.has_value() && *ct == "application/json", "Content-Type is application/json");
}

// ─── Test 5: Server Integration Test - Default 404 Wire Response ──────────────

void test_server_default_404_integration() {
    std::cout << "\n[Test 5] Server integration: default 404 wire response\n";

    auto router = wavex::engine::Http1Router::make_instance();
    router.get("/valid", [](auto &, auto &res) -> asio::awaitable<void> {
        res.status(200).send("Valid Route");
        co_return;
    });

    const unsigned short port = 19180;
    wavex::server::Http1Server server(router, "127.0.0.1", port);

    std::thread server_thread([&server] {
        server.run();
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    try {
        asio::io_context client_ioc;
        asio::ip::tcp::socket client_socket(client_ioc);
        client_socket.connect(asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), port));

        std::string req = "GET /does_not_exist HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
        asio::write(client_socket, asio::buffer(req));

        char buf[2048];
        std::size_t n = client_socket.read_some(asio::buffer(buf));
        std::string resp(buf, n);

        check(resp.find("HTTP/1.1 404 Not Found") != std::string::npos, "Response wire has HTTP/1.1 404 Not Found");
        check(resp.find("Not Found") != std::string::npos, "Response body has 'Not Found'");

        client_socket.close();
    } catch (const std::exception &e) {
        std::cerr << "Client error: " << e.what() << "\n";
        check(false, "Integration test failed with exception");
    }

    server.stop();
    if (server_thread.joinable()) server_thread.join();
}

// ─── Test 6: Server Integration Test - Custom Server-Level 404 Override ───────

void test_server_custom_404_integration() {
    std::cout << "\n[Test 6] Server integration: custom server-level 404 override\n";

    auto router = wavex::engine::Http1Router::make_instance();
    const unsigned short port = 19181;
    wavex::server::Http1Server server(router, "127.0.0.1", port);
    server.set_not_found("Custom 404: The requested resource does not exist.", "text/plain");

    std::thread server_thread([&server] {
        server.run();
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    try {
        asio::io_context client_ioc;
        asio::ip::tcp::socket client_socket(client_ioc);
        client_socket.connect(asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), port));

        std::string req = "GET /anything HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
        asio::write(client_socket, asio::buffer(req));

        char buf[2048];
        std::size_t n = client_socket.read_some(asio::buffer(buf));
        std::string resp(buf, n);

        check(resp.find("HTTP/1.1 404 Not Found") != std::string::npos, "Response status line is 404 Not Found");
        check(resp.find("Custom 404: The requested resource does not exist.") != std::string::npos,
              "Response body contains custom server text");

        client_socket.close();
    } catch (const std::exception &e) {
        std::cerr << "Client error: " << e.what() << "\n";
        check(false, "Custom server 404 test failed with exception");
    }

    server.stop();
    if (server_thread.joinable()) server_thread.join();
}

// ─── Test 7: Server Integration Test - Keep-Alive Persistence on 404 ──────────

void test_server_keep_alive_on_404() {
    std::cout << "\n[Test 7] Server integration: keep-alive persistence across 404\n";

    auto router = wavex::engine::Http1Router::make_instance();
    router.get("/valid", [](auto &, auto &res) -> asio::awaitable<void> {
        res.status(200).send("Valid");
        co_return;
    });

    const unsigned short port = 19182;
    wavex::server::Http1Server server(router, "127.0.0.1", port);
    server.set_keep_alive_timeout(std::chrono::seconds(5));

    std::thread server_thread([&server] {
        server.run();
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    try {
        asio::io_context client_ioc;
        asio::ip::tcp::socket client_socket(client_ioc);
        client_socket.connect(asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), port));

        // 1. Request 404 with keep-alive
        std::string req1 = "GET /not_real HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        asio::write(client_socket, asio::buffer(req1));

        char buf[2048];
        std::size_t n1 = client_socket.read_some(asio::buffer(buf));
        std::string resp1(buf, n1);

        check(resp1.find("HTTP/1.1 404 Not Found") != std::string::npos, "Request 1 responded 404");
        check(resp1.find("Connection: keep-alive") != std::string::npos, "Request 1 kept alive after 404");

        // 2. Request valid endpoint on same persistent socket
        std::string req2 = "GET /valid HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
        asio::write(client_socket, asio::buffer(req2));

        std::size_t n2 = client_socket.read_some(asio::buffer(buf));
        std::string resp2(buf, n2);

        check(resp2.find("HTTP/1.1 200 OK") != std::string::npos, "Request 2 on same socket responded 200 OK");
        check(resp2.find("Valid") != std::string::npos, "Request 2 returned expected body");

        client_socket.close();
    } catch (const std::exception &e) {
        std::cerr << "Client error: " << e.what() << "\n";
        check(false, "Keep-alive 404 test failed with exception");
    }

    server.stop();
    if (server_thread.joinable()) server_thread.join();
}

int main() {
    std::cout << "========================================\n";
    std::cout << "   WaveX 404 Not Found Handling Tests   \n";
    std::cout << "========================================\n";

    test_router_default_not_found();
    test_router_custom_string_not_found();
    test_router_custom_page_file();
    test_router_dynamic_coroutine_handler();
    test_server_default_404_integration();
    test_server_custom_404_integration();
    test_server_keep_alive_on_404();

    std::cout << "\n========================================\n";
    std::cout << "Results: " << tests_passed << " / " << tests_run << " passed\n";
    std::cout << "========================================\n";

    return (tests_passed == tests_run) ? 0 : 1;
}
