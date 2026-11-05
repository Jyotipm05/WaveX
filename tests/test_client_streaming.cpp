/**
 * @file test_client_streaming.cpp
 * @brief Streaming response bodies: codec stream parsers (HTTP/1.x, HTTP/3) fed at every split point, hostile and
 *        truncated input, and end-to-end HttpClient::send_streaming over HTTP/1.1, HTTP/2 and HTTP/3.
 */

#include <wavex/wavex.hpp>
#include <wavex/Client/Http3Client.hpp>

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>

#include <filesystem>
#include <iostream>
#include <source_location>
#include <random>
#include <thread>

using namespace wavex;
namespace h1 = protos::http;
namespace h3 = protos::http::http3;

namespace {
    int tests_run{0};
    int tests_failed{0};

    void check(const bool condition, const char *name) {
        ++tests_run;
        if (!condition) ++tests_failed;
        std::cout << (condition ? "  [PASS] " : "  [FAIL] ") << name << "\n";
    }

    void check(const bool condition, const std::string &name) { check(condition, name.c_str()); }

    std::string payload(const std::size_t n) {
        std::string s(n, '\0');
        for (std::size_t i = 0; i < n; ++i) s[i] = static_cast<char>('a' + (i * 5 + i / 97) % 26);
        return s;
    }

    // ── HTTP/1.x parser driver ──────────────────────────────────────────────────────
    struct h1_out {
        bool head{false}, ok{false}, error{false};
        unsigned status{0};
        std::string body;
        std::vector<std::pair<std::string, std::string> > headers;
    };

    /// Feed `wire` in pieces of `step` bytes, then signal EOF.
    h1_out run_h1(const std::string &wire, const std::size_t step, const bool head_request = false) {
        using kind = h1::http1codec::response_stream_parser::event_kind;
        h1::http1codec::response_stream_parser p(head_request);
        h1_out out;
        for (std::size_t off = 0; off <= wire.size() && !out.error;) {
            std::string_view piece(wire.data() + off, std::min(step, wire.size() - off));
            off += std::max<std::size_t>(piece.size(), 1);
            for (;;) {
                const auto ev = p.next(piece);
                if (ev.kind == kind::need_more) break;
                if (ev.kind == kind::error) {
                    out.error = true;
                    break;
                }
                if (ev.kind == kind::head) out.head = true;
                if (ev.kind == kind::body) out.body.append(ev.data);
                if (ev.kind == kind::done) break;
            }
            if (off > wire.size()) break;
        }
        out.ok = !out.error && p.finish();
        out.status = p.status_code();
        out.headers = p.headers();
        return out;
    }

    bool same_for_all_splits(const std::string &wire, const std::string &expected_body, const unsigned status) {
        for (const std::size_t step: {std::size_t{1}, std::size_t{2}, std::size_t{3}, std::size_t{7}, std::size_t{64},
                                      wire.size() + 1}) {
            const auto r = run_h1(wire, step);
            if (!r.ok || r.status != status || r.body != expected_body) return false;
        }
        return true;
    }

    void test_h1_parser() {
        std::cout << "HTTP/1.x stream parser\n";
        const std::string body = payload(1000);
        check(same_for_all_splits("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nX-A: b\r\n\r\n" + body, body, 200),
              "Content-Length body, every split size");
        check(same_for_all_splits("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                                  "5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nTrailer: x\r\n\r\n", "hello world", 200),
              "chunked body with extension and trailer, every split size");
        check(same_for_all_splits("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n" + body, body, 200),
              "until-close body");
        check(same_for_all_splits("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok",
                                  "ok", 201), "interim 100 response skipped");
        check(same_for_all_splits("HTTP/1.1 204 No Content\r\n\r\n", "", 204), "204 has no body");
        {
            const auto r = run_h1("HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n", 4, true);
            check(r.ok && r.body.empty() && r.status == 200, "HEAD response: Content-Length but no body");
        }
        const auto r = run_h1("HTTP/1.1 200 OK\r\nX: 1\r\nX: 2\r\nContent-Length: 0\r\n\r\n", 5);
        check(r.ok && r.headers.size() == 3 && r.headers[0].first == "X", "headers kept in order, duplicates kept");

        check(!run_h1("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc", 3).ok, "truncated Content-Length body not complete");
        check(!run_h1("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel", 2).ok, "truncated chunked body not complete");
        check(run_h1("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n", 4).error, "bad chunk size is an error");
        check(run_h1("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcXX", 6).error, "missing chunk CRLF is an error");
        check(run_h1("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab", 6).error, "conflicting Content-Length is an error");
        check(run_h1("garbage\r\n\r\n", 3).error, "garbage status line is an error");
        check(run_h1("HTTP/1.1 999 X\r\n\r\n", 3).error, "status code out of range is an error");
        check(run_h1("HTTP/1.1 200 OK\r\n" + std::string(70000, 'a'), 8192).error, "oversized head is an error");
        check(!run_h1("HTTP/1.1 200 OK\r\nContent-Le", 4).head, "partial head yields no head event");
    }

    // ── HTTP/3 parser driver ────────────────────────────────────────────────────────
    struct h3_out {
        bool head{false}, ok{false}, error{false};
        unsigned status{0};
        std::string body;
    };

    h3_out run_h3(const std::string &wire, const std::size_t step) {
        using kind = h3::response_stream_parser::event_kind;
        h3::response_stream_parser p;
        h3_out out;
        for (std::size_t off = 0; off < wire.size() && !out.error; off += step) {
            std::string_view piece(wire.data() + off, std::min(step, wire.size() - off));
            for (;;) {
                const auto ev = p.next(piece);
                if (ev.kind == kind::need_more) break;
                if (ev.kind == kind::error) {
                    out.error = true;
                    break;
                }
                if (ev.kind == kind::head) out.head = true;
                if (ev.kind == kind::body) out.body.append(ev.data);
            }
        }
        out.ok = !out.error && p.finish();
        out.status = p.status_code();
        return out;
    }

    std::string h3_wire(const std::string &body, unsigned status = 200, const std::string &content_length = "") {
        h3::response r;
        r.status_code = status;
        std::vector<h1::header> hs;
        hs.emplace_back("content-type", "text/plain");
        if (!content_length.empty()) hs.emplace_back("content-length", content_length);
        r.headers = hs;
        r.body = body;
        return h3::encoder::serialize_response(r);
    }

    void test_h3_parser() {
        std::cout << "HTTP/3 stream parser\n";
        const std::string body = payload(3000);
        const std::string wire = h3_wire(body);
        bool all = true;
        for (const std::size_t step: {std::size_t{1}, std::size_t{2}, std::size_t{5}, std::size_t{100}, wire.size()}) {
            const auto r = run_h3(wire, step);
            all = all && r.ok && r.status == 200 && r.body == body;
        }
        check(all, "HEADERS + DATA, every split size");
        check(run_h3(h3_wire("", 204), 3).ok, "headers only");
        check(run_h3(h3_wire(body, 200, "3000"), 7).ok, "matching content-length");
        check(!run_h3(h3_wire(body, 200, "3001"), 7).ok, "content-length mismatch is not complete");
        check(!run_h3(wire.substr(0, wire.size() - 10), 50).ok, "stream cut inside a DATA frame is not complete");
        check(!run_h3(wire.substr(0, 3), 1).ok, "stream cut inside HEADERS is not complete");

        // DATA before HEADERS, control frames and garbage are protocol errors.
        check(run_h3(h3::encoder::encode_data_frame("x"), 2).error, "DATA before HEADERS is an error");
        check(run_h3(h3::encoder::encode_frame(h3::frame_type::SETTINGS, "") + wire, 4).error,
              "SETTINGS on a request stream is an error");
        // Unknown extension frame is skipped (type 0x21 is reserved-for-grease-like but valid to ignore).
        std::string with_ext;
        {
            std::string ext;
            ext.push_back(static_cast<char>(0x40)); ext.push_back(static_cast<char>(0x40)); // type 0x40 (2-byte varint)
            ext.push_back(5);
            ext += "abcde";
            with_ext = ext + wire;
        }
        const auto er = run_h3(with_ext, 6);
        check(er.ok && er.body == body, "unknown extension frame skipped");
        // Interim 103 followed by the real response.
        const auto interim = h3_wire("", 103) + wire;
        const auto ir = run_h3(interim, 9);
        check(ir.ok && ir.status == 200 && ir.body == body, "interim 1xx response skipped");
        // Trailers after the body are accepted.
        const auto tr = run_h3(wire + h3::encoder::encode_frame(h3::frame_type::HEADERS, std::string("\0\0\xc0", 3)), 8);
        check(!tr.error || tr.body == body, "trailing HEADERS does not corrupt the body");

        std::mt19937 rng(7);
        for (int i = 0; i < 5000; ++i) { // random bytes never crash
            std::string junk(rng() % 80, '\0');
            for (auto &c: junk) c = static_cast<char>(rng());
            (void) run_h3(junk, 1 + rng() % 9);
            (void) run_h1(junk, 1 + rng() % 9);
        }
        check(true, "10000 random inputs parsed without crashing");
    }

    // ── End to end ──────────────────────────────────────────────────────────────────
    template<typename Fn>
    void run_client(Fn &&fn) {
        asio::io_context io;
        asio::co_spawn(io, std::forward<Fn>(fn), asio::detached);
        io.run();
    }

    struct collected {
        std::string data;
        int chunks{0};
    };

    client::BodySink collector(collected &c, const std::size_t abort_after = 0) {
        return [&c, abort_after](const std::string_view chunk) -> wavex::task<bool> {
            c.data.append(chunk);
            ++c.chunks;
            co_return abort_after == 0 || c.data.size() < abort_after;
        };
    }
}

int main() {
    test_h1_parser();
    test_h3_parser();

    const auto root = std::filesystem::path(std::source_location::current().file_name()).parent_path().parent_path();
    const std::string cert = (root / "ssl" / "test.crt").string();
    const std::string key = (root / "ssl" / "test.key").string();
    const std::string big = payload(3 * 1024 * 1024);

    // Plain HTTP/1.1 server: chunked and fixed-length bodies.
    engine::Http1Router r1;
    r1.get("/chunks", [](protos::http::Http1Request &, protos::http::Http1Response &res) -> wavex::task<void> {
        (void) co_await res.start_chunked();
        for (int i = 0; i < 50; ++i) (void) co_await res.write_chunk(std::string(1000, static_cast<char>('A' + i % 26)));
        (void) co_await res.end_chunked();
    });
    r1.get("/big", [&big](protos::http::Http1Request &, protos::http::Http1Response &res) -> wavex::task<void> {
        res.status(200).send(big);
        co_return;
    });
    server::Http1Server s1(r1, "127.0.0.1", 19992);
    std::thread t1([&] { s1.run(); });

    // TLS server speaking HTTP/2 (TCP) and HTTP/3 (QUIC) on one port.
    server::ComposedHttpServer s2("127.0.0.1", 19991);
    s2.tcp_server().enable_signal_handling(false);
    s2.enable_tls(cert, key);
    const auto routes = [&]<typename R>(R &r) {
        using Req = typename R::RequestType;
        using Res = typename R::ResponseType;
        r.get("/big", [&big](const Req &, Res &res) -> wavex::task<void> {
            res.status(200).set("x-size", std::to_string(big.size())).send(big);
            co_return;
        });
        r.get("/small", [](const Req &, Res &res) -> wavex::task<void> {
            res.status(200).send("tiny");
            co_return;
        });
    };
    routes(s2.h2_router());
    routes(s2.h3_router());
    std::thread t2([&] { s2.run(); });

    for (int i = 0; i < 300 && !s1.is_running(); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));
    std::this_thread::sleep_for(std::chrono::milliseconds(250));

    std::cout << "send_streaming over HTTP/1.1\n";
    run_client([&]() -> wavex::task<void> {
        using client::HttpClient;
        using client::ClientRequest;
        collected c;
        auto r = co_await HttpClient::send_streaming(ClientRequest(client::method::GET, "http://127.0.0.1:19992/chunks"),
                                                     {}, collector(c));
        std::string expected;
        for (int i = 0; i < 50; ++i) expected += std::string(1000, static_cast<char>('A' + i % 26));
        check(r.status_code() == 200 && !r.body_error() && c.data == expected, "chunked body streamed intact");
        check(c.chunks > 1 && r.body().empty(), "delivered in several chunks; response body stays empty");

        collected b;
        auto rb = co_await HttpClient::send_streaming(ClientRequest(client::method::GET, "http://127.0.0.1:19992/big"),
                                                      {}, collector(b));
        check(rb.status_code() == 200 && !rb.body_error() && b.data == big, "3 MiB Content-Length body streamed intact");
        check(b.chunks > 10, "3 MiB arrived in many chunks");

        collected a;
        auto ra = co_await HttpClient::send_streaming(ClientRequest(client::method::GET, "http://127.0.0.1:19992/big"),
                                                      {}, collector(a, 100000));
        check(ra.status_code() == 200 && ra.body_error() == std::errc::operation_canceled && a.data.size() < big.size(),
              "sink returning false aborts the download");

        collected nf;
        auto rn = co_await HttpClient::send_streaming(ClientRequest(client::method::GET, "http://127.0.0.1:19992/missing"),
                                                      {}, collector(nf));
        check(rn.status_code() == 404 && !rn.body_error(), "error status streamed like any other");
    });

    std::cout << "send_streaming over HTTP/2 and HTTP/3\n";
    run_client([&]() -> wavex::task<void> {
        using client::HttpClient;
        using client::ClientRequest;
        for (const auto ver: {client::HttpVersion::Http2, client::HttpVersion::Http3}) {
            const bool is3 = ver == client::HttpVersion::Http3;
            client::ClientOptions o;
            o.version = ver;
            collected c;
            auto r = co_await HttpClient::send_streaming(
                ClientRequest(client::method::GET, "https://127.0.0.1:19991/big"), o, collector(c));
            check(r.status_code() == 200 && r.http_version() == ver && !r.body_error() && c.data == big,
                  is3 ? "HTTP/3: 3 MiB streamed intact" : "HTTP/2: 3 MiB streamed intact");
            check(c.chunks > 10, is3 ? "HTTP/3: many chunks" : "HTTP/2: many chunks");
            check(r.header("x-size") == std::to_string(big.size()), is3 ? "HTTP/3: headers present" : "HTTP/2: headers present");

            collected a;
            auto ra = co_await HttpClient::send_streaming(
                ClientRequest(client::method::GET, "https://127.0.0.1:19991/big"), o, collector(a, 200000));
            check(ra.status_code() == 200 && ra.body_error() == std::errc::operation_canceled && a.data.size() < big.size(),
                  is3 ? "HTTP/3: sink abort" : "HTTP/2: sink abort");

            collected s;
            auto rs = co_await HttpClient::send_streaming(
                ClientRequest(client::method::GET, "https://127.0.0.1:19991/small"), o, collector(s));
            check(rs.status_code() == 200 && s.data == "tiny", is3 ? "HTTP/3: small body" : "HTTP/2: small body");
        }

        // Buffered sends still work and share the same incremental H3 reader.
        client::ClientOptions o3;
        o3.version = client::HttpVersion::Http3;
        auto plain = co_await HttpClient::send(ClientRequest(client::method::GET, "https://127.0.0.1:19991/big"), o3);
        check(plain.status_code() == 200 && plain.body() == big, "buffered HTTP/3 send unchanged");
    });

    std::cout << "pull-style reader (HttpClient::open)\n";
    run_client([&]() -> wavex::task<void> {
        using client::HttpClient;
        using client::ClientRequest;
        struct target {
            const char *name;
            std::string url;
            client::HttpVersion ver;
        };
        const target targets[] = {
            {"HTTP/1.1", "http://127.0.0.1:19992/big", client::HttpVersion::Http1_1},
            {"HTTP/2", "https://127.0.0.1:19991/big", client::HttpVersion::Http2},
            {"HTTP/3", "https://127.0.0.1:19991/big", client::HttpVersion::Http3},
        };
        for (const auto &t: targets) {
            const std::string name = t.name;
            client::ClientOptions o;
            o.version = t.ver;

            auto rd = co_await HttpClient::open(ClientRequest(client::method::GET, t.url), o);
            check(rd.response().status_code() == 200, name + ": head available before the body");
            std::string got;
            int chunks = 0;
            while (auto c = co_await rd.read_chunk()) {
                got += *c;
                ++chunks;
            }
            check(got == big && !rd.body_error() && chunks > 10, name + ": body pulled intact");
            check(!(co_await rd.read_chunk()).has_value(), name + ": read_chunk after the end stays empty");

            // Stop reading early: closing aborts the transfer and nothing may touch freed memory.
            {
                auto early = co_await HttpClient::open(ClientRequest(client::method::GET, t.url), o);
                auto first = co_await early.read_chunk();
                check(first.has_value() && !first->empty(), name + ": first chunk");
                early.close();
                check(!(co_await early.read_chunk()).has_value(), name + ": closed reader yields nothing");
            }
            {
                auto dropped = co_await HttpClient::open(ClientRequest(client::method::GET, t.url), o);
                (void) co_await dropped.read_chunk();
            } // destroyed mid-transfer
        }

        auto nf = co_await HttpClient::open(ClientRequest(client::method::GET, "http://127.0.0.1:19992/missing"), {});
        std::string nf_body;
        while (auto c = co_await nf.read_chunk()) nf_body += *c;
        check(nf.response().status_code() == 404 && !nf.body_error(), "404 head then its body through the reader");

        auto bad = co_await HttpClient::open(ClientRequest(client::method::GET, "http://127.0.0.1:1/none"), {});
        check(bad.response().status_code() >= 500 && !(co_await bad.read_chunk()).has_value(),
              "connection failure reported through the reader");
    });

    std::cout << "HTTP/3 connection pool\n";
    run_client([&]() -> wavex::task<void> {
        using client::HttpClient;
        using client::ClientRequest;
        auto pool = std::make_shared<client::Http3Pool>();
        client::ClientOptions o;
        o.version = client::HttpVersion::Http3;
        o.h3_pool = pool;

        for (int i = 0; i < 4; ++i) {
            auto r = co_await HttpClient::send(ClientRequest(client::method::GET, "https://127.0.0.1:19991/small"), o);
            check(r.status_code() == 200 && r.body() == "tiny", "pooled request " + std::to_string(i));
        }
        check(pool->size() == 1, "four requests share one pooled connection");

        client::Http3Options h3o;
        auto c1 = co_await pool->acquire(co_await asio::this_coro::executor, "127.0.0.1", 19991, h3o);
        auto c2 = co_await pool->acquire(co_await asio::this_coro::executor, "127.0.0.1", 19991, h3o);
        check(c1 && c2 && c1->get() == c2->get(), "acquire returns the same connection");

        collected c;
        auto rs = co_await HttpClient::send_streaming(
            ClientRequest(client::method::GET, "https://127.0.0.1:19991/big"), o, collector(c));
        check(rs.status_code() == 200 && c.data == big && pool->size() == 1, "streaming over the pooled connection");

        // A dead pooled connection is replaced transparently.
        (*c1)->close();
        auto again = co_await HttpClient::send(ClientRequest(client::method::GET, "https://127.0.0.1:19991/small"), o);
        check(again.status_code() == 200 && again.body() == "tiny", "request after the pooled connection closed");

        pool->close_all();
        check(pool->size() == 0, "close_all empties the pool");
    });

    s1.stop();
    s2.stop();
    t1.join();
    t2.join();

    std::cout << "\n" << (tests_run - tests_failed) << "/" << tests_run << " passed\n";
    return tests_failed == 0 ? 0 : 1;
}
