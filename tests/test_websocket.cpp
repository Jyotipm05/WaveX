// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file test_websocket.cpp
 * @brief Unit and loopback integration tests for WebSocket (RFC 6455) in WaveX.
 *
 * Covers the frame codec, the opening-handshake helpers, and real sessions on an Http1Server: echo, large and
 * fragmented messages, ping/pong, both close-handshake directions, protocol-violation closes, pipelined
 * frames, subprotocol negotiation, cross-thread sends and middleware that refuses the upgrade.
 */

#ifndef ASIO_HAS_CO_AWAIT
#define ASIO_HAS_CO_AWAIT 1
#endif

#include <atomic>
#include <cassert>
#include <chrono>
#include <future>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/read.hpp>
#include <asio/write.hpp>

#include <wavex/wavex.hpp>
#include <wavex/protos/websocket/WebSocket.hpp>

namespace ws = wavex::protos::websocket;
using wavex::protos::http::Http1Request;
using wavex::protos::http::Http1Response;

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

    constexpr unsigned short kPort = 19871;

    std::string handshake_request(const std::string &path, const std::string &key,
                                  const std::string &extra_headers = {},
                                  const std::string &version = "13") {
        return "GET " + path + " HTTP/1.1\r\n"
               "Host: 127.0.0.1\r\n"
               "Upgrade: websocket\r\n"
               "Connection: keep-alive, Upgrade\r\n"
               "Sec-WebSocket-Key: " + key + "\r\n"
               "Sec-WebSocket-Version: " + version + "\r\n" + extra_headers + "\r\n";
    }

    /// Blocking connect + write + read of the HTTP response head; whatever follows the head is `leftover`.
    struct raw_client {
        asio::io_context io;
        std::shared_ptr<asio::ip::tcp::socket> sock = std::make_shared<asio::ip::tcp::socket>(io);
        std::string head;
        std::string leftover;

        bool open(const std::string &request) {
            asio::error_code ec;
            sock->connect({asio::ip::make_address("127.0.0.1"), kPort}, ec);
            if (ec) return false;
            sock->set_option(asio::ip::tcp::no_delay(true), ec);
            asio::write(*sock, asio::buffer(request), ec);
            if (ec) return false;
            std::string buf;
            char tmp[4096];
            while (buf.find("\r\n\r\n") == std::string::npos) {
                const auto n = sock->read_some(asio::buffer(tmp), ec);
                if (ec) return false;
                buf.append(tmp, n);
            }
            const auto end = buf.find("\r\n\r\n") + 4;
            head = buf.substr(0, end);
            leftover = buf.substr(end);
            return true;
        }

        /// Read one raw frame (blocking), unmasking if needed.
        bool read_frame(ws::frame_header &h, std::string &payload) {
            asio::error_code ec;
            char tmp[4096];
            for (;;) {
                if (ws::codec::parse_header(leftover, h) == ws::parse_result::complete &&
                    leftover.size() >= h.header_size + h.payload_length) {
                    payload = leftover.substr(h.header_size, static_cast<std::size_t>(h.payload_length));
                    if (h.masked) ws::codec::apply_mask(payload.data(), payload.size(), h.masking_key);
                    leftover.erase(0, h.header_size + static_cast<std::size_t>(h.payload_length));
                    return true;
                }
                const auto n = sock->read_some(asio::buffer(tmp), ec);
                if (ec) return false;
                leftover.append(tmp, n);
            }
        }

        void write_frame(const ws::opcode op, const std::string_view payload, const bool fin = true,
                         const bool masked = true) {
            std::string frame;
            ws::codec::encode_frame(frame, op, payload, fin,
                                    masked ? std::optional<uint32_t>(0x37fa213d) : std::nullopt);
            asio::error_code ec;
            asio::write(*sock, asio::buffer(frame), ec);
        }

        /// Run a client-role session over this socket on `io` until `body` finishes (bounded).
        template<typename Body>
        bool run_session(Body body, const std::chrono::seconds limit = std::chrono::seconds(5)) {
            auto conn = std::make_shared<ws::connection>(wavex::network::AnyStream::wrap(sock), leftover,
                                                         ws::options{}, ws::role::client);
            leftover.clear();
            bool done = false;
            asio::co_spawn(io, [conn, body, &done]() -> asio::awaitable<void> {
                co_await body(conn);
                done = true;
            }, asio::detached);
            io.run_for(limit);
            io.restart();
            return done;
        }
    };

    std::string http_get(const std::string &path) {
        asio::io_context io;
        asio::ip::tcp::socket s(io);
        asio::error_code ec;
        s.connect({asio::ip::make_address("127.0.0.1"), kPort}, ec);
        if (ec) return {};
        const std::string req = "GET " + path + " HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
        asio::write(s, asio::buffer(req), ec);
        std::string out;
        char tmp[4096];
        for (;;) {
            const auto n = s.read_some(asio::buffer(tmp), ec);
            out.append(tmp, n);
            if (ec) break;
        }
        return out;
    }

    std::mutex g_bcast_mtx;
    std::shared_ptr<ws::connection> g_bcast_conn;
    std::promise<void> g_bcast_ready;
} // namespace

// ─── Unit Tests ──────────────────────────────────────────────────────────────

void test_handshake_helpers() {
    std::cout << "\n[Test WS] Handshake helpers (RFC 6455 §1.3, §4)" << std::endl;
    // The worked example from RFC 6455 §1.3.
    check(ws::compute_accept_key("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
          "Sec-WebSocket-Accept matches the RFC 6455 example");
    check(ws::detail::base64_encode("foobar") == "Zm9vYmFy" && ws::detail::base64_encode("fo") == "Zm8=",
          "base64 encoding (with padding)");
    check(ws::is_valid_client_key("dGhlIHNhbXBsZSBub25jZQ=="), "16-byte base64 key accepted");
    check(!ws::is_valid_client_key("dGhlIHNhbXBsZQ=="), "short key rejected");
    check(!ws::is_valid_client_key("not base64 at all!!!!!=="), "non-base64 key rejected");
    check(ws::is_valid_client_key(ws::generate_client_key()), "generated client key is valid");
    check(ws::header_contains_token("keep-alive, Upgrade", "upgrade"), "Connection token match is case-insensitive");
    check(!ws::header_contains_token("keep-alive, upgraded", "upgrade"), "token match is exact");
    check(ws::detail::select_subprotocol("chat.v1, chat.v2", {"chat.v2", "chat.v1"}) == "chat.v2",
          "subprotocol chosen by server preference");
    check(ws::detail::select_subprotocol("x", {"chat.v2"}).empty(), "no common subprotocol -> none");
}

void test_utf8_validation() {
    std::cout << "\n[Test WS] UTF-8 validation (RFC 6455 §8.1)" << std::endl;
    check(ws::is_valid_utf8("plain ascii"), "ASCII is valid");
    check(ws::is_valid_utf8("\xce\xba\xe1\xbd\xb9\xcf\x83\xce\xbc\xce\xb5"), "Greek text is valid");
    check(ws::is_valid_utf8("\xf0\x9f\x98\x80"), "4-byte emoji is valid");
    check(!ws::is_valid_utf8("\xc0\xaf"), "overlong encoding rejected");
    check(!ws::is_valid_utf8("\xed\xa0\x80"), "UTF-16 surrogate rejected");
    check(!ws::is_valid_utf8("\xe2\x82"), "truncated sequence rejected");
    check(!ws::is_valid_utf8("\xf4\x90\x80\x80"), "code point above U+10FFFF rejected");
}

void test_frame_codec() {
    std::cout << "\n[Test WS] Frame codec (RFC 6455 §5.2)" << std::endl;
    for (const std::size_t len: {std::size_t{0}, std::size_t{125}, std::size_t{126}, std::size_t{65535},
                                 std::size_t{65536}, std::size_t{70000}}) {
        const std::string payload(len, 'x');
        std::string frame;
        ws::codec::encode_frame(frame, ws::opcode::binary, payload, true, 0xA1B2C3D4u);
        ws::frame_header h;
        const bool ok = ws::codec::parse_header(frame, h) == ws::parse_result::complete &&
                        h.payload_length == len && h.masked && h.fin && h.op == ws::opcode::binary &&
                        frame.size() == h.header_size + len;
        std::string body = frame.substr(h.header_size);
        ws::codec::apply_mask(body.data(), body.size(), h.masking_key);
        check(ok && body == payload, ("masked round trip, payload length " + std::to_string(len)).c_str());
    }

    std::string partial;
    ws::codec::encode_frame(partial, ws::opcode::text, std::string(300, 'a'));
    ws::frame_header h;
    check(ws::codec::parse_header(std::string_view(partial).substr(0, 3), h) == ws::parse_result::incomplete,
          "truncated extended length reports incomplete");
    const std::string reserved("\x83\x00", 2); // FIN + reserved opcode 0x3
    check(ws::codec::parse_header(reserved, h) == ws::parse_result::error, "reserved opcode rejected");

    uint16_t code = 0;
    std::string reason;
    check(ws::codec::parse_close_payload(ws::codec::close_payload(4001, "bye"), code, reason) &&
          code == 4001 && reason == "bye", "close payload round trip");
    check(ws::codec::parse_close_payload("", code, reason) && code == ws::close_code::no_status,
          "empty close payload means 1005");
    check(!ws::codec::parse_close_payload("\x03", code, reason), "1-byte close payload rejected");
    check(!ws::codec::parse_close_payload(ws::codec::close_payload(1000, "") .replace(0, 2, "\x03\xed"), code,
                                          reason), "close code 1005 on the wire rejected");
    check(ws::codec::close_payload(1000, std::string(200, 'r')).size() <= 125, "close reason truncated to fit");
}

template<typename Traits, typename Req, typename Res>
concept has_takeover_hook = requires(Req &q, Res &r) { Traits::wants_takeover(q, r); };

void test_takeover_policy() {
    std::cout << "\n[Test WS] Connection takeover policy hooks" << std::endl;
    using traits1 = wavex::protos::protocol_traits<wavex::protos::http::http1codec>;
    using traits2 = wavex::protos::protocol_traits<wavex::protos::http::http2codec>;
    static_assert(has_takeover_hook<traits2, Http1Request, Http1Response>,
                  "HTTP/2 tunnels extended CONNECT streams (RFC 8441)");
    static_assert(has_takeover_hook<traits1, Http1Request, Http1Response>, "HTTP/1.x defines the takeover hook");

    Http1Request req;
    std::string raw = "GET /x HTTP/1.1\r\nHost: a\r\n\r\n";
    std::ignore = req.parse_stream(raw);
    Http1Response res;
    res.status(200);
    check(!traits1::wants_takeover(req, res), "ordinary response: no takeover");
    res.status(101);
    check(!traits1::wants_takeover(req, res), "101 without an upgrade handler: no takeover");
    res.upgrade([](wavex::network::AnyStream, std::string) -> asio::awaitable<void> { co_return; });
    check(traits1::wants_takeover(req, res), "101 with an upgrade handler: takeover");
    res.status(401);
    check(!traits1::wants_takeover(req, res), "handler left on an error response is ignored");
    res.status(101);
    res.set("Connection", "Upgrade");
    traits1::prepare_response(req, res, true, 5, 10);
    check(res.header("Connection") == std::optional<std::string_view>("Upgrade") && !res.header("Keep-Alive"),
          "prepare_response leaves a 101 alone");
}

// ─── Integration Tests ───────────────────────────────────────────────────────

void run_integration_tests() {
    std::cout << "\n[Test WS] Loopback integration on Http1Server" << std::endl;

    auto router = wavex::engine::Http1Router::make_instance();
    router.get("/plain", [](Http1Request &, Http1Response &res) -> asio::awaitable<void> {
        res.status(200).send("still serving HTTP");
        co_return;
    });

    router.websocket("/echo", [](Http1Request &req, std::shared_ptr<ws::connection> conn) -> asio::awaitable<void> {
        const std::string path(req.path()); // the request stays valid for the whole session
        for (;;) {
            auto msg = co_await conn->read();
            if (!msg) break;
            if (msg->data == "close-me") {
                conn->close(4000, "requested");
                continue;
            }
            if (msg->data == "path?") {
                conn->send_text(path);
                continue;
            }
            conn->send(*msg);
        }
    });

    ws::options chat_opts;
    chat_opts.subprotocols = {"chat.v2", "chat.v1"};
    router.websocket("/chat", [](Http1Request &, std::shared_ptr<ws::connection> conn) -> asio::awaitable<void> {
        conn->send_text("proto=" + conn->subprotocol());
        while (co_await conn->read()) {
        }
    }, chat_opts);

    router.websocket("/bcast", [](Http1Request &, std::shared_ptr<ws::connection> conn) -> asio::awaitable<void> {
        {
            std::lock_guard lock(g_bcast_mtx);
            g_bcast_conn = conn;
        }
        g_bcast_ready.set_value();
        while (co_await conn->read()) {
        }
    });

    const wavex::base::GenericMiddlewareFn<Http1Request, Http1Response> deny =
            [](Http1Request &, Http1Response &res, wavex::base::Next) -> asio::awaitable<void> {
                res.status(401).send("no token");
                co_return;
            };
    router.websocket("/private", {deny}, [](Http1Request &, std::shared_ptr<ws::connection>) -> asio::awaitable<void> {
        co_return;
    });

    wavex::server::Http1Server server(router, "127.0.0.1", kPort);
    server.enable_signal_handling(false);
    std::thread server_thread([&server] { server.run(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(80));

    // 1. Handshake + text/binary echo + client-initiated close handshake.
    {
        raw_client c;
        const std::string key = ws::generate_client_key();
        const bool opened = c.open(handshake_request("/echo", key));
        check(opened && c.head.starts_with("HTTP/1.1 101 Switching Protocols"), "101 Switching Protocols");
        check(c.head.find("Sec-WebSocket-Accept: " + ws::compute_accept_key(key)) != std::string::npos,
              "Sec-WebSocket-Accept is correct");
        check(c.head.find("Keep-Alive") == std::string::npos && c.head.find("Connection: Upgrade") != std::string::npos,
              "101 carries Connection: Upgrade and no keep-alive headers");

        std::string text_echo, bin_echo, path_echo;
        std::error_code close_ec;
        uint16_t close_code = 0;
        const std::string big(70000, '\x5a');
        const bool done = c.run_session([&](std::shared_ptr<ws::connection> conn) -> asio::awaitable<void> {
            conn->send_text("hello");
            if (auto m = co_await conn->read()) text_echo = m->data;
            conn->send_binary(big);
            if (auto m = co_await conn->read(); m && m->is_binary()) bin_echo = m->data;
            conn->send_text("path?");
            if (auto m = co_await conn->read()) path_echo = m->data;
            conn->close(ws::close_code::normal, "bye");
            auto r = co_await conn->read();
            close_ec = r ? std::error_code{} : r.error();
            close_code = conn->close_code();
        });
        check(done, "client session completed");
        check(text_echo == "hello", "text message echoed");
        check(bin_echo == big, "70000-byte binary message echoed (64-bit length)");
        check(path_echo == "/echo", "handler can use the request during the session");
        check(close_ec == ws::error::closed && close_code == ws::close_code::normal,
              "client-initiated close handshake completed (server echoed 1000)");
    }

    // 2. Server-initiated close with a code and reason.
    {
        raw_client c;
        c.open(handshake_request("/echo", ws::generate_client_key()));
        uint16_t code = 0;
        std::string reason;
        c.run_session([&](std::shared_ptr<ws::connection> conn) -> asio::awaitable<void> {
            conn->send_text("close-me");
            auto r = co_await conn->read();
            if (!r && r.error() == ws::error::closed) {
                code = conn->close_code();
                reason = conn->close_reason();
            }
            co_await conn->finish();
        });
        check(code == 4000 && reason == "requested", "server-initiated close delivers code 4000 and reason");
    }

    // 3. Raw protocol checks: ping -> pong, fragmentation with an interleaved ping, pipelined first frame.
    {
        raw_client c;
        std::string req = handshake_request("/echo", ws::generate_client_key());
        std::string first;
        ws::codec::encode_frame(first, ws::opcode::text, "pipelined", true, 0x01020304u);
        c.open(req + first); // the first frame travels in the same segment as the handshake

        ws::frame_header h;
        std::string payload;
        check(c.read_frame(h, payload) && h.op == ws::opcode::text && payload == "pipelined",
              "frame pipelined behind the handshake is processed");

        c.write_frame(ws::opcode::ping, "are-you-there");
        check(c.read_frame(h, payload) && h.op == ws::opcode::pong && payload == "are-you-there" && !h.masked,
              "ping answered with an unmasked pong carrying the same payload");

        c.write_frame(ws::opcode::text, "Hel", false);
        c.write_frame(ws::opcode::ping, "mid");
        c.write_frame(ws::opcode::continuation, "lo", true);
        const bool got_pong = c.read_frame(h, payload) && h.op == ws::opcode::pong && payload == "mid";
        const bool got_msg = c.read_frame(h, payload) && h.op == ws::opcode::text && payload == "Hello";
        check(got_pong && got_msg, "fragmented message reassembled around an interleaved ping");

        c.write_frame(ws::opcode::close, ws::codec::close_payload(1000));
        check(c.read_frame(h, payload) && h.op == ws::opcode::close && payload.substr(0, 2) == "\x03\xe8",
              "raw close answered with close 1000");
    }

    // 4. Protocol violations are closed with the right status code.
    {
        raw_client c;
        c.open(handshake_request("/echo", ws::generate_client_key()));
        c.write_frame(ws::opcode::text, "unmasked", true, false);
        ws::frame_header h;
        std::string payload;
        check(c.read_frame(h, payload) && h.op == ws::opcode::close && payload.substr(0, 2) == "\x03\xea",
              "unmasked client frame -> close 1002");
    }
    {
        raw_client c;
        c.open(handshake_request("/echo", ws::generate_client_key()));
        c.write_frame(ws::opcode::text, "\xc0\xaf");
        ws::frame_header h;
        std::string payload;
        check(c.read_frame(h, payload) && h.op == ws::opcode::close && payload.substr(0, 2) == "\x03\xef",
              "invalid UTF-8 text -> close 1007");
    }

    // 5. Handshake rejections.
    {
        raw_client c;
        c.open(handshake_request("/echo", ws::generate_client_key(), {}, "8"));
        check(c.head.starts_with("HTTP/1.1 426") && c.head.find("Sec-WebSocket-Version: 13") != std::string::npos,
              "unsupported version -> 426 + Sec-WebSocket-Version: 13");
    }
    {
        raw_client c;
        c.open("GET /echo HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        check(c.head.starts_with("HTTP/1.1 426"), "plain GET on a WebSocket route -> 426 Upgrade Required");
    }
    {
        raw_client c;
        c.open(handshake_request("/echo", "short"));
        check(c.head.starts_with("HTTP/1.1 400"), "invalid Sec-WebSocket-Key -> 400");
    }
    {
        raw_client c;
        c.open(handshake_request("/private", ws::generate_client_key()));
        check(c.head.starts_with("HTTP/1.1 401"), "route middleware can refuse the upgrade");
    }

    // 6. Subprotocol negotiation.
    {
        raw_client c;
        c.open(handshake_request("/chat", ws::generate_client_key(), "Sec-WebSocket-Protocol: chat.v1, chat.v2\r\n"));
        check(c.head.find("Sec-WebSocket-Protocol: chat.v2") != std::string::npos, "server selects chat.v2");
        std::string first;
        c.run_session([&](std::shared_ptr<ws::connection> conn) -> asio::awaitable<void> {
            if (auto m = co_await conn->read()) first = m->data;
            conn->close();
            while (co_await conn->read()) {
            }
        });
        check(first == "proto=chat.v2", "session sees the negotiated subprotocol");
    }

    // 7. Sending from another thread (broadcast pattern).
    {
        raw_client c;
        c.open(handshake_request("/bcast", ws::generate_client_key()));
        auto ready = g_bcast_ready.get_future();
        const bool registered = ready.wait_for(std::chrono::seconds(2)) == std::future_status::ready;
        std::thread sender([] {
            std::shared_ptr<ws::connection> conn;
            {
                std::lock_guard lock(g_bcast_mtx);
                conn = g_bcast_conn;
            }
            for (int i = 0; i < 3 && conn; ++i) conn->send_text("broadcast-" + std::to_string(i));
        });
        sender.join();
        std::vector<std::string> got;
        c.run_session([&](std::shared_ptr<ws::connection> conn) -> asio::awaitable<void> {
            for (int i = 0; i < 3; ++i) {
                if (auto m = co_await conn->read()) got.push_back(m->data);
            }
            conn->close();
            while (co_await conn->read()) {
            }
        });
        check(registered && got == std::vector<std::string>{"broadcast-0", "broadcast-1", "broadcast-2"},
              "frames queued from another thread arrive in order");
        std::lock_guard lock(g_bcast_mtx);
        g_bcast_conn.reset();
    }

    // 8. The server keeps serving plain HTTP afterwards.
    check(http_get("/plain").find("still serving HTTP") != std::string::npos, "plain HTTP still served");

    server.stop();
    if (server_thread.joinable()) server_thread.join();
}

int main() {
    std::cout << "==================================================" << std::endl;
    std::cout << " WaveX WebSocket (RFC 6455) Tests" << std::endl;
    std::cout << "==================================================" << std::endl;

    test_handshake_helpers();
    test_utf8_validation();
    test_frame_codec();
    test_takeover_policy();
    run_integration_tests();

    std::cout << "\n Results: " << tests_passed << " / " << tests_run << " passed" << std::endl;
    return tests_passed == tests_run ? 0 : 1;
}
