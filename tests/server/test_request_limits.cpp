/**
 * @file test_request_limits.cpp
 * @brief Server::set_max_headers / set_max_query_params must actually reject oversized requests (431).
 */
#include <wavex/wavex.hpp>

#include <array>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>

namespace {
    int tests_run = 0;
    int tests_passed = 0;

    void check(const bool ok, const char *name) {
        ++tests_run;
        if (ok) {
            ++tests_passed;
            std::cout << "  [PASS] " << name << "\n";
        } else {
            std::cout << "  [FAIL] " << name << "\n";
        }
    }

    /// Sends one request on a fresh connection and returns the first line of the response.
    std::string status_line_for(const unsigned short port, const std::string &request) {
        asio::io_context ioc;
        asio::ip::tcp::socket sock(ioc);
        sock.connect({asio::ip::make_address("127.0.0.1"), port});
        asio::write(sock, asio::buffer(request));

        std::string data;
        std::array<char, 1024> buf{};
        asio::error_code ec;
        while (data.find("\r\n") == std::string::npos) {
            const auto n = sock.read_some(asio::buffer(buf), ec);
            if (ec) break;
            data.append(buf.data(), n);
        }
        return data.substr(0, data.find("\r\n"));
    }
} // namespace

int main() {
    std::cout << "=== Request limit enforcement tests ===\n";

    auto router = wavex::engine::Http1Router::make_instance();
    router.get("/ok", [](wavex::protos::http::Http1Request &, wavex::protos::http::Http1Response &res) -> wavex::task<void> {
        res.status(200).send("ok");
        co_return;
    });

    constexpr unsigned short port = 19120;
    wavex::server::Http1Server server(router, "127.0.0.1", port);
    server.enable_signal_handling(false);
    server.set_max_headers(4);
    server.set_max_query_params(3);

    std::thread server_thread([&server] { server.run(); });
    for (int i = 0; i < 200 && !server.is_running(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    const auto within = status_line_for(port, "GET /ok HTTP/1.1\r\nHost: x\r\nA: 1\r\nConnection: close\r\n\r\n");
    check(within.find("200") != std::string::npos, "request within limits is served");

    const auto many_headers = status_line_for(
        port, "GET /ok HTTP/1.1\r\nHost: x\r\nA: 1\r\nB: 2\r\nC: 3\r\nD: 4\r\nE: 5\r\nConnection: close\r\n\r\n");
    check(many_headers.find("431") != std::string::npos, "too many headers -> 431");

    const auto many_query = status_line_for(
        port, "GET /ok?a=1&b=2&c=3&d=4&e=5 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    check(many_query.find("431") != std::string::npos, "too many query params -> 431");

    server.stop();
    server_thread.join();

    std::cout << "\n" << tests_passed << "/" << tests_run << " tests passed.\n";
    return tests_passed == tests_run ? 0 : 1;
}
