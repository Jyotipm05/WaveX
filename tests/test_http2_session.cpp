// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file test_http2_session.cpp
 * @brief Loopback tests for the multiplexed HTTP/2 server session (RFC 9113) and WebSocket over HTTP/2
 *        (RFC 8441), driven by a frame-level client.
 */

#ifndef ASIO_HAS_CO_AWAIT
#define ASIO_HAS_CO_AWAIT 1
#endif

#include <atomic>
#include <chrono>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/steady_timer.hpp>
#include <asio/this_coro.hpp>
#include <asio/write.hpp>

#include <wavex/wavex.hpp>

namespace h2 = wavex::protos::http::http2;
namespace ws = wavex::protos::websocket;
using wavex::protos::http::Http2Request;
using wavex::protos::http::Http2Response;

namespace {
    int tests_run = 0;
    int tests_passed = 0;

    void check(const bool condition, const char *name) {
        ++tests_run;
        if (condition) {
            ++tests_passed;
            std::cout << "  [PASS] " << name << std::endl;
        } else {
            std::cout << "  [FAIL] " << name << std::endl;
        }
    }

    constexpr unsigned short kPort = 19881;

    struct frame {
        h2::frame_header hdr;
        std::string payload;
    };

    /// Literal-only HPACK block for arbitrary (pseudo-)headers.
    std::string header_block(const std::vector<std::pair<std::string, std::string> > &fields) {
        std::string out;
        for (const auto &[n, v]: fields) {
            h2::hpack::encode_integer(out, 0, 4, 0x00);
            h2::hpack::encode_string(out, n);
            h2::hpack::encode_string(out, v);
        }
        return out;
    }

    std::vector<std::pair<std::string, std::string> > get_fields(const std::string &method, const std::string &path) {
        return {{":method", method}, {":scheme", "http"}, {":path", path}, {":authority", "127.0.0.1"}};
    }

    /// Blocking frame-level HTTP/2 client.
    struct client {
        asio::io_context io;
        asio::ip::tcp::socket sock{io};
        std::string buf;
        h2::hpack::dynamic_table table;
        std::map<uint16_t, uint32_t> server_settings;

        bool open(const std::vector<std::pair<h2::settings_parameter, uint32_t> > &settings = {}) {
            asio::error_code ec;
            sock.connect({asio::ip::make_address("127.0.0.1"), kPort}, ec);
            if (ec) return false;
            std::string pre(h2::CONNECTION_PREFACE);
            pre += h2::encoder::serialize_settings(settings);
            send_raw(pre);
            // Server SETTINGS come first.
            frame f;
            if (!read(f) || f.hdr.type != h2::frame_type::SETTINGS) return false;
            for (std::size_t i = 0; i + 6 <= f.payload.size(); i += 6) {
                const auto id = static_cast<uint16_t>((static_cast<uint8_t>(f.payload[i]) << 8) |
                                                      static_cast<uint8_t>(f.payload[i + 1]));
                server_settings[id] = h2::read_u32(std::string_view(f.payload).substr(i + 2, 4));
            }
            send_raw(h2::encoder::serialize_settings_ack());
            return true;
        }

        void send_raw(const std::string &bytes) {
            asio::error_code ec;
            asio::write(sock, asio::buffer(bytes), ec);
        }

        void send_frame(const h2::frame_type t, const uint8_t f, const uint32_t sid, const std::string &payload) {
            send_raw(h2::encode_frame(t, f, sid, payload));
        }

        void send_headers(const uint32_t sid, const std::vector<std::pair<std::string, std::string> > &fields,
                          const bool end_stream) {
            send_frame(h2::frame_type::HEADERS,
                       static_cast<uint8_t>(h2::flags::END_HEADERS | (end_stream ? h2::flags::END_STREAM : 0)),
                       sid, header_block(fields));
        }

        bool read(frame &out, const std::chrono::milliseconds timeout = std::chrono::milliseconds(3000)) {
            const auto deadline = std::chrono::steady_clock::now() + timeout;
            for (;;) {
                if (buf.size() >= 9) {
                    h2::unpack_frame_header(buf, out.hdr);
                    if (buf.size() >= 9 + out.hdr.length) {
                        out.payload = buf.substr(9, out.hdr.length);
                        buf.erase(0, 9 + out.hdr.length);
                        return true;
                    }
                }
                if (std::chrono::steady_clock::now() >= deadline) return false;
                sock.non_blocking(true);
                char tmp[16384];
                asio::error_code ec;
                const auto n = sock.read_some(asio::buffer(tmp), ec);
                if (ec == asio::error::would_block) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(2));
                    continue;
                }
                if (ec) return false;
                buf.append(tmp, n);
            }
        }

        /// Read frames until one matches `pred`, skipping (but recording) everything else.
        template<typename Pred>
        bool read_until(frame &out, Pred pred, std::vector<frame> *others = nullptr,
                        const std::chrono::milliseconds timeout = std::chrono::milliseconds(3000)) {
            const auto deadline = std::chrono::steady_clock::now() + timeout;
            while (std::chrono::steady_clock::now() < deadline) {
                frame f;
                if (!read(f, std::chrono::duration_cast<std::chrono::milliseconds>(
                        deadline - std::chrono::steady_clock::now()))) return false;
                if (pred(f)) {
                    out = std::move(f);
                    return true;
                }
                if (others) others->push_back(std::move(f));
            }
            return false;
        }

        std::vector<std::pair<std::string, std::string> > decode(const std::string &block) {
            std::vector<std::pair<std::string, std::string> > out;
            const h2::hpack::decoder dec(table);
            dec.decode_header_block(block, out);
            return out;
        }

        static std::string status_of(const std::vector<std::pair<std::string, std::string> > &fields) {
            for (const auto &[n, v]: fields) if (n == ":status") return v;
            return {};
        }

        /// Collect a complete response on `sid`: status and body.
        bool response(const uint32_t sid, std::string &status, std::string &body,
                      const std::chrono::milliseconds timeout = std::chrono::milliseconds(3000)) {
            const auto deadline = std::chrono::steady_clock::now() + timeout;
            bool ended = false;
            while (!ended && std::chrono::steady_clock::now() < deadline) {
                frame f;
                if (!read(f, std::chrono::duration_cast<std::chrono::milliseconds>(
                        deadline - std::chrono::steady_clock::now()))) return false;
                if (f.hdr.stream_id != sid) continue;
                if (f.hdr.type == h2::frame_type::HEADERS) {
                    status = status_of(decode(f.payload));
                } else if (f.hdr.type == h2::frame_type::DATA) {
                    body += f.payload;
                } else if (f.hdr.type == h2::frame_type::RST_STREAM) {
                    return false;
                }
                ended = f.hdr.has_flag(h2::flags::END_STREAM);
            }
            return ended;
        }
    };
} // namespace

int main() {
    std::cout << "==================================================" << std::endl;
    std::cout << " WaveX HTTP/2 Session & RFC 8441 Tests" << std::endl;
    std::cout << "==================================================" << std::endl;

    auto router = wavex::engine::Http2Router::make_instance();
    router.get("/fast", [](Http2Request &, Http2Response &res) -> asio::awaitable<void> {
        res.status(200).send("fast");
        co_return;
    });
    router.get("/slow", [](Http2Request &, Http2Response &res) -> asio::awaitable<void> {
        asio::steady_timer t(co_await asio::this_coro::executor, std::chrono::milliseconds(400));
        co_await t.async_wait(asio::use_awaitable);
        res.status(200).send("slow");
    });
    router.get("/big", [](Http2Request &, Http2Response &res) -> asio::awaitable<void> {
        res.status(200).send(std::string(100000, 'b'));
        co_return;
    });
    router.post("/echo", [](Http2Request &req, Http2Response &res) -> asio::awaitable<void> {
        res.status(200).send(std::string(req.body()));
        co_return;
    });
    router.get("/stream", [](Http2Request &, Http2Response &res) -> asio::awaitable<void> {
        res.status(200);
        std::ignore = co_await res.write_chunk("part1-");
        std::ignore = co_await res.write_chunk("part2");
        std::ignore = co_await res.end_chunked();
    });
    router.websocket("/ws", [](Http2Request &, std::shared_ptr<ws::connection> c) -> asio::awaitable<void> {
        while (auto m = co_await c->read()) c->send(*m);
    });

    wavex::server::Http2Server server(router, "127.0.0.1", kPort);
    server.enable_signal_handling(false);
    std::thread server_thread([&server] { server.run(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // 1. Connection setup.
    {
        std::cout << "\n[Test H2] Connection preface & SETTINGS" << std::endl;
        client c;
        check(c.open(), "server SETTINGS received after the preface");
        check(c.server_settings[static_cast<uint16_t>(h2::settings_parameter::ENABLE_CONNECT_PROTOCOL)] == 1,
              "SETTINGS_ENABLE_CONNECT_PROTOCOL = 1 advertised (RFC 8441 §3)");
        check(c.server_settings[static_cast<uint16_t>(h2::settings_parameter::MAX_CONCURRENT_STREAMS)] == 100,
              "SETTINGS_MAX_CONCURRENT_STREAMS advertised");
        frame f;
        check(c.read_until(f, [](const frame &x) {
            return x.hdr.type == h2::frame_type::SETTINGS && x.hdr.has_flag(h2::flags::ACK);
        }), "client SETTINGS acknowledged");
        c.send_frame(h2::frame_type::PING, 0, 0, "12345678");
        check(c.read_until(f, [](const frame &x) {
            return x.hdr.type == h2::frame_type::PING && x.hdr.has_flag(h2::flags::ACK);
        }) && f.payload == "12345678", "PING answered with ACK and the same payload");
    }

    // 2. Real multiplexing: a fast request overtakes a slow one on the same connection.
    {
        std::cout << "\n[Test H2] Concurrent streams" << std::endl;
        client c;
        c.open();
        c.send_headers(1, get_fields("GET", "/slow"), true);
        c.send_headers(3, get_fields("GET", "/fast"), true);
        std::vector<uint32_t> order;
        std::map<uint32_t, std::string> bodies;
        const auto start = std::chrono::steady_clock::now();
        std::chrono::milliseconds fast_at{0};
        while (order.size() < 2) {
            frame f;
            if (!c.read(f)) break;
            if (f.hdr.type == h2::frame_type::DATA) bodies[f.hdr.stream_id] += f.payload;
            if ((f.hdr.type == h2::frame_type::DATA || f.hdr.type == h2::frame_type::HEADERS) &&
                f.hdr.has_flag(h2::flags::END_STREAM)) {
                order.push_back(f.hdr.stream_id);
                if (f.hdr.stream_id == 3) {
                    fast_at = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - start);
                }
            }
        }
        check(order == std::vector<uint32_t>{3, 1}, "stream 3 completes before stream 1 that started earlier");
        check(fast_at < std::chrono::milliseconds(300), "the fast stream is not blocked behind the slow handler");
        check(bodies[1] == "slow" && bodies[3] == "fast", "both responses arrive on their own streams");
    }

    // 3. Flow control: the server stops at the client's window and resumes on WINDOW_UPDATE.
    {
        std::cout << "\n[Test H2] Flow control (RFC 9113 §5.2)" << std::endl;
        client c;
        c.open({{h2::settings_parameter::INITIAL_WINDOW_SIZE, 1000}});
        c.send_headers(1, get_fields("GET", "/big"), true);
        std::size_t received = 0;
        frame f;
        while (c.read(f, std::chrono::milliseconds(400))) {
            if (f.hdr.type == h2::frame_type::DATA && f.hdr.stream_id == 1) received += f.payload.size();
        }
        check(received == 1000, "only the advertised 1000-byte stream window is sent");
        // Both windows bound the sender: raise the stream's and the connection's (still at 65535).
        c.send_frame(h2::frame_type::WINDOW_UPDATE, 0, 1, std::string("\x00\x10\x00\x00", 4)); // +1 MiB
        c.send_frame(h2::frame_type::WINDOW_UPDATE, 0, 0, std::string("\x00\x10\x00\x00", 4)); // +1 MiB
        bool ended = false;
        while (!ended && c.read(f)) {
            if (f.hdr.type == h2::frame_type::DATA && f.hdr.stream_id == 1) {
                received += f.payload.size();
                ended = f.hdr.has_flag(h2::flags::END_STREAM);
            }
        }
        check(ended && received == 100000, "transfer completes after WINDOW_UPDATEs");
    }

    // 4. Request bodies across frames, CONTINUATION, 404, streamed responses.
    {
        std::cout << "\n[Test H2] Frames, CONTINUATION and streaming" << std::endl;
        client c;
        c.open();
        c.send_headers(1, get_fields("POST", "/echo"), false);
        c.send_frame(h2::frame_type::DATA, 0, 1, "hello ");
        c.send_frame(h2::frame_type::DATA, h2::flags::END_STREAM, 1, "world");
        std::string status, body;
        check(c.response(1, status, body) && status == "200" && body == "hello world",
              "request body split over DATA frames");

        const std::string block = header_block(get_fields("GET", "/fast"));
        c.send_frame(h2::frame_type::HEADERS, h2::flags::END_STREAM, 3, block.substr(0, 5));
        c.send_frame(h2::frame_type::CONTINUATION, h2::flags::END_HEADERS, 3, block.substr(5));
        status.clear();
        body.clear();
        check(c.response(3, status, body) && body == "fast", "header block split over CONTINUATION");

        c.send_headers(5, get_fields("GET", "/missing"), true);
        status.clear();
        body.clear();
        check(c.response(5, status, body) && status == "404", "unknown route answered 404 on its stream");

        c.send_headers(7, get_fields("GET", "/stream"), true);
        status.clear();
        body.clear();
        check(c.response(7, status, body) && status == "200" && body == "part1-part2",
              "streamed (write_chunk) response framed on its own stream");
    }

    // 5. A client reset does not disturb other streams.
    {
        std::cout << "\n[Test H2] RST_STREAM" << std::endl;
        client c;
        c.open();
        c.send_headers(1, get_fields("GET", "/slow"), true);
        c.send_frame(h2::frame_type::RST_STREAM, 0, 1, std::string("\x00\x00\x00\x08", 4));
        c.send_headers(3, get_fields("GET", "/fast"), true);
        std::string status, body;
        check(c.response(3, status, body) && body == "fast", "connection keeps serving after a client RST_STREAM");
    }

    // 6. WebSocket over HTTP/2 (RFC 8441).
    {
        std::cout << "\n[Test H2] WebSocket over HTTP/2 (RFC 8441)" << std::endl;
        client c;
        c.open();
        auto fields = get_fields("CONNECT", "/ws");
        fields.insert(fields.begin() + 1, {":protocol", "websocket"});
        fields.emplace_back("sec-websocket-version", "13");
        c.send_headers(1, fields, false);
        frame f;
        const bool got = c.read_until(f, [](const frame &x) {
            return x.hdr.stream_id == 1 && x.hdr.type == h2::frame_type::HEADERS;
        });
        check(got && client::status_of(c.decode(f.payload)) == "200" && !f.hdr.has_flag(h2::flags::END_STREAM),
              "extended CONNECT answered 200 and the stream stays open");

        std::string wsf;
        ws::codec::encode_frame(wsf, ws::opcode::text, "over-h2", true, 0x5a5a5a5au);
        c.send_frame(h2::frame_type::DATA, 0, 1, wsf);

        // Another request on the same connection while the tunnel is open.
        c.send_headers(3, get_fields("GET", "/fast"), true);

        std::string tunnel_bytes;
        bool fast_done = false;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        ws::frame_header wh;
        while (std::chrono::steady_clock::now() < deadline &&
               !(fast_done && ws::codec::parse_header(tunnel_bytes, wh) == ws::parse_result::complete &&
                 tunnel_bytes.size() >= wh.header_size + wh.payload_length)) {
            frame d;
            if (!c.read(d)) break;
            if (d.hdr.stream_id == 1 && d.hdr.type == h2::frame_type::DATA) tunnel_bytes += d.payload;
            if (d.hdr.stream_id == 3 && d.hdr.has_flag(h2::flags::END_STREAM)) fast_done = true;
        }
        const bool parsed = ws::codec::parse_header(tunnel_bytes, wh) == ws::parse_result::complete;
        check(parsed && wh.op == ws::opcode::text && !wh.masked &&
              tunnel_bytes.substr(wh.header_size, static_cast<std::size_t>(wh.payload_length)) == "over-h2",
              "WebSocket message echoed through DATA frames");
        check(fast_done, "regular request served on the same connection while the tunnel is open");

        std::string closef;
        ws::codec::encode_frame(closef, ws::opcode::close, ws::codec::close_payload(1000), true, 0x01020304u);
        c.send_frame(h2::frame_type::DATA, h2::flags::END_STREAM, 1, closef);
        bool closed = false;
        bool got_close = false;
        std::string rest;
        while (!closed && c.read(f)) {
            if (f.hdr.stream_id != 1) continue;
            if (f.hdr.type == h2::frame_type::DATA) rest += f.payload;
            closed = f.hdr.has_flag(h2::flags::END_STREAM) || f.hdr.type == h2::frame_type::RST_STREAM;
        }
        if (ws::codec::parse_header(rest, wh) == ws::parse_result::complete) got_close = wh.op == ws::opcode::close;
        check(got_close && closed, "close handshake answered and the stream ended");

        c.send_headers(5, {{":method", "GET"}, {":protocol", "websocket"}, {":scheme", "http"},
                           {":path", "/ws"}, {":authority", "127.0.0.1"}}, true);
        std::string status, body;
        check(c.response(5, status, body) && status == "400", ":protocol on a non-CONNECT request -> 400");
    }

    // 7. The WaveX client still talks to the server (h2c prior knowledge).
    {
        std::cout << "\n[Test H2] HttpClient interoperability" << std::endl;
        asio::io_context io;
        std::string body;
        asio::co_spawn(io, [&]() -> asio::awaitable<void> {
            const wavex::client::ClientOptions opts{.version = wavex::client::HttpVersion::Http2};
            auto r = co_await wavex::client::HttpClient::get("http://127.0.0.1:" + std::to_string(kPort) + "/big", opts);
            body = std::string(r.get_body());
        }, asio::detached);
        io.run_for(std::chrono::seconds(5));
        check(body.size() == 100000, "HttpClient receives a 100 KB body (opens its windows)");
    }

    // 8. Graceful shutdown: idle connections get GOAWAY, open tunnels are closed at the deadline.
    {
        std::cout << "\n[Test H2] Graceful shutdown" << std::endl;
        client idle;
        idle.open();
        client busy;
        busy.open();
        auto fields = get_fields("CONNECT", "/ws");
        fields.insert(fields.begin() + 1, {":protocol", "websocket"});
        fields.emplace_back("sec-websocket-version", "13");
        busy.send_headers(1, fields, false);
        frame f;
        busy.read_until(f, [](const frame &x) { return x.hdr.type == h2::frame_type::HEADERS; });

        const auto start = std::chrono::steady_clock::now();
        server.exit(std::chrono::milliseconds(1500));
        if (server_thread.joinable()) server_thread.join();
        const auto took = std::chrono::steady_clock::now() - start;

        check(idle.read_until(f, [](const frame &x) { return x.hdr.type == h2::frame_type::GOAWAY; }),
              "idle connection receives GOAWAY");
        check(took < std::chrono::seconds(5), "exit() returns even with an open WebSocket tunnel");
    }

    std::cout << "\n Results: " << tests_passed << " / " << tests_run << " passed" << std::endl;
    return tests_passed == tests_run ? 0 : 1;
}
