/**
 * @file test_server_keepalive.cpp
 * @brief Unit & integration tests for HTTP Persistent Connection (Stay-Active / Keep-Alive).
 */

#ifndef ASIO_HAS_CO_AWAIT
#define ASIO_HAS_CO_AWAIT 1
#endif

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>

#include <wavex/wavex.hpp>

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

// ─── Test 1: HttpRequest should_keep_alive & consumed_bytes ───────────────────

void test_request_keep_alive() {
    std::cout << "\n[Test 1] HttpRequest keep-alive detection and consumed_bytes\n";

    // HTTP/1.1 without Connection header -> should keep alive by default
    std::string req1_str = "GET /test HTTP/1.1\r\nHost: localhost\r\n\r\n";
    wavex::protos::http::Http1Request req1(req1_str);
    check(req1.parse(), "HTTP/1.1 request parsed");
    check(req1.should_keep_alive(), "HTTP/1.1 defaults to keep-alive");
    check(req1.consumed_bytes() == req1_str.size(), "Consumed bytes matches exact request size");

    // HTTP/1.1 with Connection: close -> should NOT keep alive
    std::string req2_str = "GET /test HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    wavex::protos::http::Http1Request req2(req2_str);
    check(req2.parse(), "HTTP/1.1 close request parsed");
    check(!req2.should_keep_alive(), "HTTP/1.1 with Connection: close does not keep alive");

    // HTTP/1.0 without Connection header -> should NOT keep alive by default
    std::string req3_str = "GET /test HTTP/1.0\r\nHost: localhost\r\n\r\n";
    wavex::protos::http::Http1Request req3(req3_str);
    check(req3.parse(), "HTTP/1.0 request parsed");
    check(!req3.should_keep_alive(), "HTTP/1.0 defaults to close");

    // HTTP/1.0 with Connection: keep-alive -> should keep alive
    std::string req4_str = "GET /test HTTP/1.0\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n";
    wavex::protos::http::Http1Request req4(req4_str);
    check(req4.parse(), "HTTP/1.0 keep-alive request parsed");
    check(req4.should_keep_alive(), "HTTP/1.0 with Connection: keep-alive keeps alive");

    // Pipelined buffer test: two requests in one buffer
    std::string pipelined = req1_str + req2_str;
    wavex::protos::http::Http1Request pipe_req;
    auto res = pipe_req.parse_stream(pipelined);
    check(res == wavex::protos::http::http1codec::parser::result::success,
          "First pipelined request parsed from stream");
    check(pipe_req.consumed_bytes() == req1_str.size(), "First pipelined request consumed bytes matches req1");
}

// ─── Test 2: HttpResponse set_keep_alive & should_keep_alive ──────────────────

void test_response_keep_alive() {
    std::cout << "\n[Test 2] HttpResponse set_keep_alive & should_keep_alive\n";

    wavex::protos::http::Http1Response res;
    res.set_keep_alive(true, 10, 500);
    check(res.should_keep_alive(), "Response indicates keep-alive");
    check(res.header("Connection") == "keep-alive", "Connection header is keep-alive");
    check(res.header("Keep-Alive") == "timeout=10, max=500", "Keep-Alive header is set");

    res.set_keep_alive(false);
    check(!res.should_keep_alive(), "Response indicates close");
    check(res.header("Connection") == "close", "Connection header is close");
}

// ─── Test 3: StaticChain & KeepAlivePolicy ───────────────────────────────────

void test_chainable_keep_alive() {
    std::cout << "\n[Test 3] StaticChain KeepAlivePolicy static handler\n";

    auto chain = wavex::make_chain(wavex::KeepAlivePolicy < 15, 200 > {
    }
    )
    ;
    wavex::protos::http::Http1Request req("GET /api HTTP/1.1\r\nHost: localhost\r\n\r\n");
    check(req.parse(), "Parse request for chain");

    wavex::protos::http::Http1Response res;
    bool ok = chain.process_all(req, res);
    check(ok, "StaticChain processed KeepAlivePolicy");
    check(res.should_keep_alive(), "Response configured for keep-alive by StaticChain");
    check(res.header("Connection") == "keep-alive", "Header set to keep-alive");
    check(res.header("Keep-Alive") == "timeout=15, max=200", "Keep-Alive header matches template arguments");
}

// ─── Test 4: Middleware keep_alive & sse_stay_active ─────────────────────────

void test_middleware_keep_alive() {
    std::cout << "\n[Test 4] MiddleWare keep_alive and sse_stay_active\n";

    auto mw = wavex::base::keep_alive<wavex::protos::http::Http1Request, wavex::protos::http::Http1Response>(5, 100);
    wavex::protos::http::Http1Request req("GET /data HTTP/1.1\r\nHost: localhost\r\n\r\n");
    check(req.parse(), "Parse request for middleware");

    wavex::protos::http::Http1Response res;
    bool next_called = false;
    wavex::base::Next next = [&next_called]() -> asio::awaitable<void> {
        next_called = true;
        co_return;
    };

    asio::io_context ioc;
    asio::co_spawn(ioc, mw(req, res, next), asio::detached);
    ioc.run();

    check(next_called, "keep_alive middleware invoked next()");
    check(res.header("Connection") == "keep-alive", "Middleware set Connection: keep-alive");

    auto sse_mw = wavex::base::sse_stay_active<wavex::protos::http::Http1Request, wavex::protos::http::Http1Response>();
    wavex::protos::http::Http1Response sse_res;
    next_called = false;

    asio::io_context ioc2;
    asio::co_spawn(ioc2, sse_mw(req, sse_res, next), asio::detached);
    ioc2.run();

    check(next_called, "sse_stay_active middleware invoked next()");
    check(sse_res.header("Content-Type") == "text/event-stream", "SSE content type set");
    check(sse_res.header("Connection") == "keep-alive", "SSE keep-alive set");
}

// ─── Test 5: Integration Test - Persistent TCP Connection ─────────────────────

void test_server_persistent_connection() {
    std::cout << "\n[Test 5] Integration Test: Sequential requests on single persistent TCP socket\n";

    auto router = wavex::engine::Http1Router::make_instance();
    router.get("/hello", [](wavex::protos::http::Http1Request &,
                            wavex::protos::http::Http1Response &res) -> asio::awaitable<void> {
        res.status(200).send("Hello KeepAlive");
        co_return;
    });

    router.get("/counter", [](wavex::protos::http::Http1Request &,
                              wavex::protos::http::Http1Response &res) -> asio::awaitable<void> {
        static int counter = 0;
        counter++;
        res.status(200).send(std::to_string(counter));
        co_return;
    });

    const unsigned short port = 19095;
    wavex::server::Http1Server server(router, "127.0.0.1", port);
    server.set_keep_alive_timeout(std::chrono::seconds(3));
    server.set_max_keep_alive_requests(10);

    std::thread server_thread([&server] {
        server.run();
    });

    // Allow server to start listening
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    try {
        asio::io_context client_ioc;
        asio::ip::tcp::socket client_socket(client_ioc);
        client_socket.connect(asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), port));

        // 1. Send first request on this socket
        std::string req1 = "GET /hello HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        asio::write(client_socket, asio::buffer(req1));

        char buf[2048];
        std::size_t n1 = client_socket.read_some(asio::buffer(buf));
        std::string resp1(buf, n1);

        check(resp1.find("HTTP/1.1 200 OK") != std::string::npos, "Request 1 responded 200 OK");
        check(resp1.find("Hello KeepAlive") != std::string::npos, "Request 1 returned expected body");
        check(resp1.find("Connection: keep-alive") != std::string::npos, "Request 1 contains Connection: keep-alive");

        // 2. Send second request on the EXACT SAME socket (verifies connection stayed active)
        std::string req2 = "GET /counter HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        asio::write(client_socket, asio::buffer(req2));

        std::size_t n2 = client_socket.read_some(asio::buffer(buf));
        std::string resp2(buf, n2);

        check(resp2.find("HTTP/1.1 200 OK") != std::string::npos, "Request 2 on same socket responded 200 OK");
        check(resp2.find("Connection: keep-alive") != std::string::npos, "Request 2 still kept alive");

        // 3. Send third request with Connection: close to cleanly finish
        std::string req3 = "GET /hello HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
        asio::write(client_socket, asio::buffer(req3));

        std::size_t n3 = client_socket.read_some(asio::buffer(buf));
        std::string resp3(buf, n3);

        check(resp3.find("Connection: close") != std::string::npos, "Request 3 closed connection gracefully");

        // Socket should now be closed by server
        asio::error_code ec;
        client_socket.read_some(asio::buffer(buf), ec);
        check(ec == asio::error::eof || ec == asio::error::connection_reset,
              "Server closed socket after Connection: close");

        client_socket.close();
    } catch (const std::exception &ex) {
        std::cerr << "Client error: " << ex.what() << "\n";
        check(false, "Persistent connection test failed with exception");
    }

    server.stop();
    if (server_thread.joinable()) {
        server_thread.join();
    }
}

int main() {
    std::cout << "==================================================\n";
    std::cout << " WaveX HTTP Stay-Active / Keep-Alive Unit Tests    \n";
    std::cout << "==================================================\n";

    test_request_keep_alive();
    test_response_keep_alive();
    test_chainable_keep_alive();
    test_middleware_keep_alive();
    test_server_persistent_connection();

    std::cout << "\n==================================================\n";
    std::cout << " Results: " << tests_passed << " / " << tests_run << " passed\n";
    std::cout << "==================================================\n";

    return (tests_passed == tests_run) ? 0 : 1;
}
