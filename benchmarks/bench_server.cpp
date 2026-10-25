/**
 * @file bench_server.cpp
 * @brief Minimal HTTP/1.1 server used by the benchmark harness.
 *
 * Routes: GET /hello (13-byte body), GET /blob (64 KiB body), GET /sleep (spawn_blocking, 2 ms).
 * Usage: [BENCH_WORKERS=N] wavex_bench_server [port=18080]
 */
#include <wavex/wavex.hpp>

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>

int main(const int argc, char **argv) {
    const auto port = static_cast<unsigned short>(argc > 1 ? std::atoi(argv[1]) : 18080);

    // BENCH_WORKERS=N pins the worker pool to exactly N threads (disables elastic scaling) for A/B runs.
    if (const char *w = std::getenv("BENCH_WORKERS"); w != nullptr && std::atoi(w) > 0) {
        const auto n = static_cast<std::size_t>(std::atoi(w));
        wavex::server::ThreadPoolConfig::instance().set_limits(n, n);
    }

    auto router = wavex::engine::Http1Router::make_instance();
    router.get("/hello", [](wavex::protos::http::Http1Request &,
                            wavex::protos::http::Http1Response &res) -> asio::awaitable<void> {
        res.status(200).send("Hello, World!");
        co_return;
    });

    static const std::string blob(64 * 1024, 'x');
    router.get("/blob", [](wavex::protos::http::Http1Request &,
                           wavex::protos::http::Http1Response &res) -> asio::awaitable<void> {
        res.status(200).send(blob);
        co_return;
    });

    router.get("/sleep", [](wavex::protos::http::Http1Request &,
                            wavex::protos::http::Http1Response &res) -> asio::awaitable<void> {
        co_await wavex::spawn_blocking([] { std::this_thread::sleep_for(std::chrono::milliseconds(2)); });
        res.status(200).send("done");
        co_return;
    });

    wavex::server::Http1Server server(router, "127.0.0.1", port);
    server.enable_signal_handling(true);
    server.set_max_keep_alive_requests(1'000'000); // measure the request path, not reconnect churn
    server.set_keep_alive_timeout(std::chrono::seconds(120));
    std::cout << "bench server listening on 127.0.0.1:" << port << std::endl;
    server.run();
    return 0;
}
