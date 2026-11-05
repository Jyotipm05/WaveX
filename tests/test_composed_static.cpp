/**
 * @file test_composed_static.cpp
 * @brief ComposedServer<R2, R3> with compile-time routers: HTTP/2 over TCP/TLS and HTTP/3 over QUIC on one port,
 *        typed and regex parameters, middleware post-processing, custom 404, and the same wiring through the
 *        dynamic ComposedHttpServer (which is now a ComposedServer plus owned routers).
 */

#include <wavex/wavex.hpp>
#include <wavex/Engine/StaticHttpRouter.hpp>
#include <wavex/Server/ComposedServer.hpp>

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>

#include <filesystem>
#include <iostream>
#include <source_location>
#include <thread>

using namespace wavex;
namespace hr = wavex::engine::route::http;
using engine::route::static_router;
using engine::route::use;

namespace {
    int tests_run{0};
    int tests_failed{0};

    void check(const bool condition, const char *name) {
        ++tests_run;
        if (!condition) ++tests_failed;
        std::cout << (condition ? "  [PASS] " : "  [FAIL] ") << name << "\n";
    }

    template<typename Proto>
    auto make_routes() {
        using Req = Proto::request;
        using Res = Proto::response;
        return static_router<Proto>(
            use([](Req &, Res &res, auto &next) -> wavex::task<void> {
                co_await next();
                res.set("x-static", "1");
            }),
            hr::get<"/hello/{name:alpha}">([](Req &req, Res &res) -> wavex::task<void> {
                res.status(200).send("hi " + std::string(req.param("name")));
                co_return;
            }),
            hr::get<"/id/{id:[0-9]{3}}">([](Req &req, Res &res) -> wavex::task<void> {
                res.status(200).send("id=" + std::string(req.param("id")));
                co_return;
            }));
    }

    template<typename Fn>
    void run_client(Fn &&fn) {
        asio::io_context io;
        asio::co_spawn(io, std::forward<Fn>(fn), asio::detached);
        io.run();
    }

    wavex::task<void> exercise(const unsigned short port, const char *label) {
        using client::HttpClient;
        using client::ClientRequest;
        const std::string base = "https://127.0.0.1:" + std::to_string(port);
        for (const auto ver: {client::HttpVersion::Http2, client::HttpVersion::Http3}) {
            const bool is3 = ver == client::HttpVersion::Http3;
            client::ClientOptions o;
            o.version = ver;
            const std::string tag = std::string(label) + (is3 ? " HTTP/3: " : " HTTP/2: ");
            auto a = co_await HttpClient::send(ClientRequest(client::method::GET, base + "/hello/world"), o);
            check(a.status_code() == 200 && a.body() == "hi world" && a.http_version() == ver, (tag + "typed parameter").c_str());
            check(a.header("x-static").value_or("") == "1", (tag + "middleware post-processing").c_str());
            auto b = co_await HttpClient::send(ClientRequest(client::method::GET, base + "/id/042"), o);
            check(b.status_code() == 200 && b.body() == "id=042", (tag + "regex parameter").c_str());
            auto c = co_await HttpClient::send(ClientRequest(client::method::GET, base + "/id/42"), o);
            check(c.status_code() == 404, (tag + "regex miss is 404").c_str());
        }
    }
} // namespace

int main() {
    const auto root = std::filesystem::path(std::source_location::current().file_name()).parent_path().parent_path();
    const std::string cert = (root / "ssl" / "test.crt").string();
    const std::string key = (root / "ssl" / "test.key").string();

    std::cout << "ComposedServer with static routers\n";
    auto r2 = make_routes<engine::Http2Proto>();
    auto r3 = make_routes<engine::Http3Proto>();
    server::ComposedServer<decltype(r2), decltype(r3)> srv(r2, r3, "127.0.0.1", 19994);
    srv.tcp_server().enable_signal_handling(false);
    srv.enable_tls(cert, key);
    std::thread t([&] { srv.run(); });
    for (int i = 0; i < 300 && !srv.tcp_server().is_running(); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
    run_client([]() { return exercise(19994, "static"); });
    srv.stop();
    t.join();

    std::cout << "ComposedHttpServer (dynamic routers) still works\n";
    server::ComposedHttpServer dyn("127.0.0.1", 19995);
    dyn.tcp_server().enable_signal_handling(false);
    dyn.enable_tls(cert, key);
    dyn.get("/hello/world", [](auto &, auto &res) { res.status(200).send("hi world"); });
    std::thread t2([&] { dyn.run(); });
    for (int i = 0; i < 300 && !dyn.tcp_server().is_running(); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
    run_client([]() -> wavex::task<void> {
        using client::HttpClient;
        using client::ClientRequest;
        for (const auto ver: {client::HttpVersion::Http2, client::HttpVersion::Http3}) {
            client::ClientOptions o;
            o.version = ver;
            auto a = co_await HttpClient::send(ClientRequest(client::method::GET, "https://127.0.0.1:19995/hello/world"), o);
            check(a.status_code() == 200 && a.body() == "hi world",
                  ver == client::HttpVersion::Http3 ? "dynamic HTTP/3" : "dynamic HTTP/2");
        }
    });
    dyn.stop();
    t2.join();

    std::cout << "\n" << (tests_run - tests_failed) << "/" << tests_run << " passed\n";
    return tests_failed == 0 ? 0 : 1;
}
