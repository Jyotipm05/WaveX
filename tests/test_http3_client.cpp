/**
 * @file test_http3_client.cpp
 * @brief End-to-end tests of the HTTP/3 client against WaveX's own ComposedHttpServer (HTTP/2 over TCP + HTTP/3
 *        over QUIC on one port): single requests, large bodies, concurrent streams, HttpVersion::Http3 through
 *        HttpClient, and Alt-Svc discovery with TCP first and HTTP/3 afterwards.
 */

#include <wavex/wavex.hpp>
#include <wavex/Client/Http3Client.hpp>

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <source_location>
#include <thread>

using namespace wavex;

namespace {
    int tests_run{0};
    int tests_failed{0};

    void check(const bool condition, const char *name) {
        ++tests_run;
        if (!condition) ++tests_failed;
        std::cout << (condition ? "  [PASS] " : "  [FAIL] ") << name << "\n";
    }

    constexpr uint16_t kPort = 19990;

    std::string big_payload(const std::size_t n) {
        std::string s(n, '\0');
        for (std::size_t i = 0; i < n; ++i) s[i] = static_cast<char>('a' + (i * 7 + i / 251) % 26);
        return s;
    }

    template<typename Fn>
    void run_client(Fn &&fn) {
        asio::io_context io;
        asio::co_spawn(io, std::forward<Fn>(fn), asio::detached);
        io.run();
    }
}

int main() {
    const auto root = std::filesystem::path(std::source_location::current().file_name()).parent_path().parent_path();
    const std::string cert = (root / "ssl" / "test.crt").string();
    const std::string key = (root / "ssl" / "test.key").string();

    server::ComposedHttpServer srv("127.0.0.1", kPort);
    srv.tcp_server().enable_signal_handling(false);
    srv.enable_tls(cert, key);

    std::atomic<int> h3_hits{0}, tcp_hits{0};
    const auto routes = [&]<typename R>(R &r, std::atomic<int> &hits) {
        using Req = typename R::RequestType;
        using Res = typename R::ResponseType;
        r.get("/hello", [&hits](const Req &, Res &res) -> wavex::task<void> {
            ++hits;
            res.status(200).set("x-test", "yes").send("hello over quic");
            co_return;
        });
        r.post("/echo", [&hits](const Req &req, Res &res) -> wavex::task<void> {
            ++hits;
            res.status(200).send(std::string(req.body()));
            co_return;
        });
        r.get("/big", [&hits](const Req &, Res &res) -> wavex::task<void> {
            ++hits;
            res.status(200).send(big_payload(300 * 1024));
            co_return;
        });
        r.get("/id/:n", [&hits](const Req &req, Res &res) -> wavex::task<void> {
            ++hits;
            res.status(200).send("id=" + std::string(req.path()));
            co_return;
        });
    };
    routes(srv.h3_router(), h3_hits);
    routes(srv.h2_router(), tcp_hits);

    std::thread server_thread([&] { srv.run(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    const std::string base = "https://127.0.0.1:" + std::to_string(kPort);

    std::cout << "Http3Client\n";
    {
        asio::io_context probe;
        client::Http3Client never(probe.get_executor());
        std::expected<client::ClientResponse, std::error_code> r = std::unexpected(std::error_code{});
        asio::co_spawn(probe, [&]() -> wavex::task<void> {
            r = co_await never.send(client::ClientRequest(client::method::GET, base + "/hello"));
        }, asio::detached);
        probe.run();
        check(!r && r.error() == client::http3_errc::not_connected, "send before connect -> not_connected");
    }

    run_client([&]() -> wavex::task<void> {
        client::Http3Client c(co_await asio::this_coro::executor);
        const auto ec = co_await c.connect("127.0.0.1", kPort);
        check(!ec, "connect: QUIC handshake with ALPN h3");
        check(c.is_open(), "connection is open");

        auto r = co_await c.send(client::ClientRequest(client::method::GET, base + "/hello"));
        if (!r) std::cout << "    error: " << r.error().message() << "\n";
        check(r && r->status_code() == 200 && r->body() == "hello over quic", "GET status and body");
        check(r && r->http_version() == client::HttpVersion::Http3, "response marked HTTP/3");
        check(r && r->header("x-test") == "yes", "response header (lowercase, QPACK-decoded)");

        client::ClientRequest post(client::method::POST, base + "/echo");
        post.set_body("ping", "text/plain");
        auto p = co_await c.send(post);
        check(p && p->status_code() == 200 && p->body() == "ping", "POST body echoed");

        const auto payload = big_payload(400 * 1024);
        client::ClientRequest bigpost(client::method::POST, base + "/echo");
        bigpost.set_body(payload, "application/octet-stream");
        auto bp = co_await c.send(bigpost);
        if (!bp) std::cout << "    error: " << bp.error().message() << "\n";
        else std::cout << "    status " << bp->status_code() << " body " << bp->body().size() << "\n";
        check(bp && bp->status_code() == 200 && bp->body() == payload, "400 KiB request body round-trips");

        auto bg = co_await c.send(client::ClientRequest(client::method::GET, base + "/big"));
        if (!bg) std::cout << "    error: " << bg.error().message() << "\n";
        else std::cout << "    status " << bg->status_code() << " body " << bg->body().size() << "\n";
        check(bg && bg->status_code() == 200 && bg->body() == big_payload(300 * 1024), "300 KiB response body");

        auto nf = co_await c.send(client::ClientRequest(client::method::GET, base + "/missing"));
        if (!nf) std::cout << "    error: " << nf.error().message() << "\n";
        check(nf && nf->status_code() == 404, "404 from router");

        // Concurrent requests share the connection, one QUIC stream each.
        std::atomic<int> done{0}, good{0};
        auto ex = co_await asio::this_coro::executor;
        for (int i = 0; i < 12; ++i) {
            asio::co_spawn(ex, [&, i]() -> wavex::task<void> {
                auto q = co_await c.send(
                    client::ClientRequest(client::method::GET, base + "/id/" + std::to_string(i)));
                if (q && q->status_code() == 200 && q->body() == "id=/id/" + std::to_string(i)) ++good;
                ++done;
            }, asio::detached);
        }
        asio::steady_timer wait(ex);
        for (int i = 0; i < 200 && done < 12; ++i) {
            wait.expires_after(std::chrono::milliseconds(50));
            co_await wait.async_wait(asio::use_awaitable);
        }
        check(good == 12, "12 concurrent requests on one connection");
        c.close();
        check(!c.is_open(), "close()");
    });

    std::cout << "HttpClient integration\n";
    run_client([&]() -> wavex::task<void> {
        client::ClientOptions o;
        o.version = client::HttpVersion::Http3;
        const int before = h3_hits;
        auto r = co_await client::HttpClient::get(base + "/hello", o);
        check(r.status_code() == 200 && r.body() == "hello over quic", "HttpVersion::Http3 via HttpClient::get");
        check(r.http_version() == client::HttpVersion::Http3 && h3_hits == before + 1, "served over HTTP/3");

        // Alt-Svc discovery: first request over TCP, then the advertised h3 endpoint is used.
        client::ClientOptions d;
        d.h3_discovery = true;
        const int tcp_before = tcp_hits;
        auto first = co_await client::HttpClient::get(base + "/hello", d);
        check(first.status_code() == 200 && first.http_version() != client::HttpVersion::Http3 && tcp_hits == tcp_before + 1,
              "first request goes over TCP (no HTTP/3 knowledge yet)");
        check(first.header("alt-svc").has_value(), "server advertised Alt-Svc");
        auto second = co_await client::HttpClient::get(base + "/hello", d);
        check(second.status_code() == 200 && second.http_version() == client::HttpVersion::Http3,
              "second request uses HTTP/3 learned from Alt-Svc");

        // Auto without discovery never touches QUIC.
        const int h3_before = h3_hits;
        auto plain = co_await client::HttpClient::get(base + "/hello");
        check(plain.status_code() == 200 && h3_hits == h3_before, "default Auto stays on TCP");
    });

    srv.stop();
    if (server_thread.joinable()) server_thread.join();

    std::cout << "\n" << (tests_run - tests_failed) << "/" << tests_run << " passed\n";
    return tests_failed == 0 ? 0 : 1;
}
