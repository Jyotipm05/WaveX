// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file test_webtransport.cpp
 * @brief Tests for HTTP/3 extended CONNECT, WebTransport over HTTP/3 and WebSocket over HTTP/3 (RFC 9220).
 *
 * Runs on mock (non-TLS) QUIC connections: capsules, the DATA-frame tunnel, QUIC DATAGRAM frames, stream
 * demultiplexing, the session registry, and full sessions driven through Http3Server's connection loop.
 */

#ifndef ASIO_HAS_CO_AWAIT
#define ASIO_HAS_CO_AWAIT 1
#endif

#include <atomic>
#include <chrono>
#include <deque>
#include <future>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>

#include <wavex/wavex.hpp>
#include <wavex/Network/QUIC.hpp>
#include <wavex/protos/http/http3tunnel.hpp>
#include <wavex/protos/webtransport/WebTransport.hpp>
#include <wavex/protos/websocket/WebSocket.hpp>

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

namespace h3 = wavex::protos::http::http3;
namespace quic = wavex::network::quic;
namespace wt = wavex::protos::webtransport;
namespace ws = wavex::protos::websocket;
using wavex::network::AnyStream;
using wavex::protos::http::method;
using wavex::protos::http::http3codec;

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

    std::string varint(const uint64_t v) {
        std::string out;
        quic::VarInt::encode(v, out);
        return out;
    }

    /// Serialized HTTP/3 extended CONNECT request HEADERS frame.
    std::string extended_connect(const std::string &protocol, const std::string &path,
                                 const std::vector<std::pair<std::string, std::string> > &extra = {},
                                 const bool with_authority = true) {
        h3::request req;
        req.method_type = method::CONNECT;
        req.protocol = protocol;
        req.target = path;
        req.scheme = "https";
        req.authority = with_authority ? std::string_view("localhost") : std::string_view();
        for (const auto &[n, v]: extra) req.headers.emplace_back(n, v);
        return http3codec::serialize_request(req);
    }

    std::shared_ptr<quic::QuicConnection> mock_server_conn(asio::io_context &io, const unsigned short port) {
        const auto ep = asio::ip::udp::endpoint(asio::ip::address_v4::loopback(), port);
        return std::make_shared<quic::QuicConnection>(quic::ConnectionId::random(8), quic::ConnectionId::random(8),
                                                      ep, true, io.get_executor());
    }

    /// In-memory stream: reads come from scripted chunks then EOF, writes are recorded.
    struct scripted_stream {
        std::deque<std::string> chunks;
        std::string written;
    };

    AnyStream make_scripted(const std::shared_ptr<scripted_stream> &s, asio::io_context &io) {
        auto ops = std::make_shared<AnyStream::operations>();
        ops->executor = io.get_executor();
        ops->read_some = [s](const asio::mutable_buffer b) -> wavex::task<AnyStream::read_result> {
            if (s->chunks.empty()) co_return AnyStream::read_result{asio::error::eof, 0};
            std::string &front = s->chunks.front();
            const std::size_t n = (std::min)(b.size(), front.size());
            std::memcpy(b.data(), front.data(), n);
            front.erase(0, n);
            if (front.empty()) s->chunks.pop_front();
            co_return AnyStream::read_result{std::error_code{}, n};
        };
        ops->write = [s](const asio::const_buffer b) -> wavex::task<std::error_code> {
            s->written.append(static_cast<const char *>(b.data()), b.size());
            co_return std::error_code{};
        };
        return AnyStream(std::move(ops));
    }

    template<typename Fn>
    void run_coro(asio::io_context &io, Fn fn) {
        asio::co_spawn(io, std::move(fn), asio::detached);
        io.run_for(std::chrono::milliseconds(500));
        io.restart();
    }
} // namespace

// ─── Unit Tests ──────────────────────────────────────────────────────────────

void test_capsules() {
    std::cout << "\n[Test WT] Capsules (RFC 9297 §3.2)" << std::endl;
    const std::string close = wt::capsule::encode_close_session(0xDEADBEEF, "bye");
    uint64_t type = 0;
    std::string_view payload;
    std::size_t consumed = 0;
    check(wt::capsule::parse(close, type, payload, consumed) == wt::capsule::parse_result::complete &&
          type == wt::kCapsuleCloseSession && consumed == close.size(), "CLOSE_WEBTRANSPORT_SESSION parses");
    uint32_t code = 0;
    std::string reason;
    check(wt::capsule::decode_close_session(payload, code, reason) && code == 0xDEADBEEF && reason == "bye",
          "close code and reason round trip");
    check(wt::capsule::parse(std::string_view(close).substr(0, close.size() - 1), type, payload, consumed) ==
          wt::capsule::parse_result::incomplete, "truncated capsule is incomplete");
    const std::string long_close = wt::capsule::encode_close_session(1, std::string(5000, 'r'));
    std::ignore = wt::capsule::parse(long_close, type, payload, consumed);
    check(payload.size() == 4 + wt::kMaxCloseReasonBytes, "close reason capped at 1024 bytes");
}

void test_extended_connect_parsing() {
    std::cout << "\n[Test WT] HTTP/3 extended CONNECT parsing (RFC 9220 §3)" << std::endl;
    const std::string headers = extended_connect("webtransport", "/wt", {{"origin", "https://example.org"}});
    const std::string tunnel_bytes = h3::encode_tunnel_data_frame("capsule-bytes");
    const std::string wire = headers + tunnel_bytes;

    h3::request req;
    std::size_t consumed = 0;
    h3::qpack::dynamic_table dt;
    const auto r = http3codec::parse_request(wire, req, consumed, dt);
    check(r == http3codec::result::success, "extended CONNECT parses");
    check(req.method_type == method::CONNECT && req.protocol == "webtransport" && req.target == "/wt" &&
          req.authority == "localhost", ":method/:protocol/:path/:authority decoded");
    check(consumed == headers.size() && req.body.empty(), "tunnel DATA after HEADERS is left unconsumed");

    wavex::protos::http::Http3Request wrapped;
    std::size_t c2 = 0;
    check(http3codec::parse_request(wire, wrapped.raw(), c2, dt) == http3codec::result::success &&
          wrapped.connect_protocol() == "webtransport", "HttpRequest::connect_protocol() exposes :protocol");

    h3::request bad;
    bad.method_type = method::GET;
    bad.protocol = "websocket";
    bad.target = "/";
    bad.authority = "localhost";
    h3::request out;
    check(http3codec::parse_request(http3codec::serialize_request(bad), out, consumed, dt) ==
          http3codec::result::error, ":protocol on a non-CONNECT request is malformed");
    check(http3codec::parse_request(extended_connect("webtransport", "/wt", {}, false), out, consumed, dt) ==
          http3codec::result::error, "extended CONNECT without :authority is malformed");
}

void test_quic_datagram_frames() {
    std::cout << "\n[Test WT] QUIC DATAGRAM frames (RFC 9221)" << std::endl;
    quic::DatagramFrame df;
    df.data = "payload";
    std::string wire;
    quic::serialize_frame(df, wire);
    wire.push_back('\x01'); // a PING after it: the length-prefixed form allows more frames
    std::vector<quic::Frame> frames;
    const bool ok = quic::parse_frames(wire, frames);
    check(ok && frames.size() == 2 && std::holds_alternative<quic::DatagramFrame>(frames[0]) &&
          std::get<quic::DatagramFrame>(frames[0]).data == "payload" &&
          std::holds_alternative<quic::PingFrame>(frames[1]), "DATAGRAM (0x31) round trip");

    std::string no_len = "\x30";
    no_len += "rest-of-packet";
    frames.clear();
    check(quic::parse_frames(no_len, frames) && frames.size() == 1 &&
          std::get<quic::DatagramFrame>(frames[0]).data == "rest-of-packet", "DATAGRAM (0x30) extends to packet end");

    asio::io_context io;
    const auto conn = mock_server_conn(io, 9911);
    check(conn->max_datagram_payload() == 0 && !conn->send_datagram("x"),
          "no DATAGRAM sending before the peer advertises max_datagram_frame_size");
    conn->set_peer_max_datagram_frame_size(65535);
    check(conn->max_datagram_payload() > 1000 && conn->max_datagram_payload() < 1200,
          "datagram payload bounded by the path MTU once negotiated");
}

void test_data_tunnel() {
    std::cout << "\n[Test WT] HTTP/3 DATA-frame tunnel (RFC 9297 §3.1)" << std::endl;
    asio::io_context io;
    auto script = std::make_shared<scripted_stream>();
    std::string raw = h3::encode_tunnel_data_frame("hel");
    raw += varint(0x21) + varint(3) + "xyz"; // reserved/GREASE-style unknown frame: skipped
    raw += h3::encode_tunnel_data_frame("lo");
    raw += varint(0x01) + varint(0);          // trailing HEADERS: end of the data stream
    // Deliver it in awkward pieces to exercise partial frame headers.
    for (std::size_t i = 0; i < raw.size(); i += 3) script->chunks.push_back(raw.substr(i, 3));

    auto tunnel = h3::make_data_tunnel(make_scripted(script, io), {});
    std::string got;
    std::error_code end_ec;
    std::error_code write_ec;
    run_coro(io, [&]() -> wavex::task<void> {
        char buf[2];
        for (;;) {
            auto [ec, n] = co_await tunnel.read_some(asio::buffer(buf));
            got.append(buf, n);
            if (ec) {
                end_ec = ec;
                break;
            }
        }
        write_ec = co_await tunnel.write(asio::buffer(std::string_view("abc")));
    });
    check(got == "hello", "DATA payloads concatenated, unknown frames skipped");
    check(end_ec == asio::error::eof, "trailing HEADERS ends the tunnel with EOF");
    check(!write_ec && script->written == h3::encode_tunnel_data_frame("abc"), "writes are framed as DATA");

    auto bad = std::make_shared<scripted_stream>();
    bad->chunks.push_back(varint(0x04) + varint(0)); // SETTINGS on a request stream
    auto bad_tunnel = h3::make_data_tunnel(make_scripted(bad, io), {});
    std::error_code bad_ec;
    run_coro(io, [&]() -> wavex::task<void> {
        char buf[16];
        auto [ec, n] = co_await bad_tunnel.read_some(asio::buffer(buf));
        bad_ec = ec;
    });
    check(bad_ec == std::errc::protocol_error, "control frame inside the tunnel is a protocol error");
}

void test_websocket_over_tunnel() {
    std::cout << "\n[Test WT] WebSocket frames over the HTTP/3 tunnel (RFC 9220)" << std::endl;
    asio::io_context io;
    auto script = std::make_shared<scripted_stream>();
    std::string frame;
    ws::codec::encode_frame(frame, ws::opcode::text, "over-h3", true, 0x11223344u);
    script->chunks.push_back(h3::encode_tunnel_data_frame(frame));

    auto conn = std::make_shared<ws::connection>(h3::make_data_tunnel(make_scripted(script, io), {}), "",
                                                 ws::options{}, ws::role::server);
    std::string got;
    run_coro(io, [&]() -> wavex::task<void> {
        if (auto m = co_await conn->read()) got = m->data;
        conn->send_text("reply");
    });
    std::string expected_reply;
    ws::codec::encode_frame(expected_reply, ws::opcode::text, "reply");
    check(got == "over-h3", "masked WebSocket frame read through DATA frames");
    check(script->written == h3::encode_tunnel_data_frame(expected_reply), "reply wrapped in a DATA frame");
}

void test_stream_demux_and_registry() {
    std::cout << "\n[Test WT] Stream demultiplexing, registry and session plumbing" << std::endl;
    asio::io_context io;
    const auto conn = mock_server_conn(io, 9912);
    const auto ctx = wt::http3_context_for(conn);
    const auto reg = wt::registry_for(*ctx);
    check(wt::http3_context_for(conn) == ctx && wt::registry_for(*ctx) == reg, "context and registry are per connection");

    // A WebTransport bidirectional stream that overtakes its session's CONNECT is parked.
    const auto s4 = conn->get_or_create_stream(4);
    s4->push_inbound(varint(wt::kBidiStreamSignal) + varint(0) + "early", false);
    bool wt_stream = false;
    run_coro(io, [&]() -> wavex::task<void> { wt_stream = co_await wt::dispatch_bidirectional_stream(s4); });
    check(wt_stream && reg->pending_count() == 1, "WT_STREAM (0x41) recognised and buffered until the session exists");

    // A request stream is handed back untouched.
    h3::request get;
    get.method_type = method::GET;
    get.target = "/index";
    get.authority = "localhost";
    const std::string get_wire = http3codec::serialize_request(get);
    const auto s8 = conn->get_or_create_stream(8);
    s8->push_inbound(get_wire, true);
    bool s8_is_wt = true;
    run_coro(io, [&]() -> wavex::task<void> { s8_is_wt = co_await wt::dispatch_bidirectional_stream(s8); });
    char buf[1024];
    std::error_code rec;
    const std::size_t n = s8->read_some(asio::buffer(buf), rec);
    check(!s8_is_wt && std::string(buf, n) == get_wire, "HTTP/3 request stream is put back byte-for-byte");

    // Establish session 0 and receive the parked stream.
    const auto s0 = conn->get_or_create_stream(0);
    auto sess = std::make_shared<wt::session>(0, s0, h3::make_data_tunnel(AnyStream::wrap(s0, io.get_executor()), {}),
                                              conn, reg, wt::options{});
    reg->add(sess);
    std::string early;
    run_coro(io, [&]() -> wavex::task<void> {
        if (auto st = co_await sess->accept_bidirectional_stream()) {
            char b[64];
            auto [ec, k] = co_await st->read_some(asio::buffer(b));
            early.assign(b, k);
        }
    });
    check(early == "early" && reg->pending_count() == 0, "parked stream delivered when the session registers");

    // Unidirectional stream: type 0x54 through the regular HTTP/3 unidirectional handler.
    const auto s2 = conn->get_or_create_stream(2);
    s2->push_inbound(varint(wt::kUniStreamType) + varint(0) + "uni-data", true);
    std::string uni;
    bool uni_is_incoming = false;
    run_coro(io, [&]() -> wavex::task<void> {
        co_await h3::session_handler::handle_unidirectional_stream(s2, ctx);
        if (auto st = co_await sess->accept_unidirectional_stream()) {
            uni_is_incoming = st->is_incoming() && !st->can_write();
            auto [ec, data] = co_await st->read_all();
            if (!ec) uni = data;
        }
    });
    check(uni == "uni-data" && uni_is_incoming, "unidirectional stream (0x54) routed to the session");

    // Datagrams carry the quarter stream ID (RFC 9297 §2.1).
    reg->dispatch_datagram(varint(0) + "dgram");
    reg->dispatch_datagram(varint(25) + "nobody"); // session 100 does not exist: dropped
    std::optional<std::string> dg;
    run_coro(io, [&]() -> wavex::task<void> { dg = co_await sess->receive_datagram(); });
    check(dg && *dg == "dgram", "datagram delivered by quarter stream ID");

    const auto out_bidi = sess->open_bidirectional_stream();
    const auto out_uni = sess->open_unidirectional_stream();
    check(out_bidi && (out_bidi->id() & 0x03) == 0x01 && out_uni && (out_uni->id() & 0x03) == 0x03,
          "server-initiated bidirectional / unidirectional streams");

    // Short-lived streams must not pile up in the session's bookkeeping (a dead weak_ptr still pins its block).
    for (int i = 0; i < 300; ++i) std::ignore = sess->open_unidirectional_stream(); // each handle is dropped at once
    check(sess->tracked_stream_count() <= 70, "dropped streams are swept, the tracking list stays bounded");
    check(out_bidi->id() != 0 && out_uni->id() != 0, "live streams survive the sweeps");

    // Peer closes the session with a CLOSE capsule on the CONNECT stream.
    s0->push_inbound(h3::encode_tunnel_data_frame(wt::capsule::encode_close_session(42, "done")), false);
    std::shared_ptr<wt::stream> after_close = std::make_shared<wt::stream>(nullptr, "", 0, true, true);
    run_coro(io, [&]() -> wavex::task<void> {
        co_await sess->run_capsule_reader();
        after_close = co_await sess->accept_bidirectional_stream();
    });
    check(sess->is_closed() && sess->close_code() == 42 && sess->close_reason() == "done",
          "CLOSE_WEBTRANSPORT_SESSION ends the session with the peer's code and reason");
    check(after_close == nullptr && reg->find(0) == nullptr, "closed session stops accepting and leaves the registry");
    check(!sess->send_datagram("late") && sess->open_bidirectional_stream() == nullptr, "no sends after close");

    // Pending streams for unknown sessions are bounded.
    for (uint64_t i = 0; i < wt::session_registry::kMaxPendingStreams + 4; ++i) {
        reg->dispatch_stream(400, conn->get_or_create_stream(12 + 4 * i), {}, true);
    }
    check(reg->pending_count() == wt::session_registry::kMaxPendingStreams, "parked streams capped per connection");

    // Invalid session IDs (not a client bidirectional stream) are refused.
    reg->dispatch_stream(3, conn->get_or_create_stream(500), {}, true);
    check(reg->pending_count() == wt::session_registry::kMaxPendingStreams, "invalid session ID refused");
    conn->close();
}

// ─── Server Integration (Http3Server connection loop) ────────────────────────

void test_server_integration() {
    std::cout << "\n[Test WT] Sessions through Http3Server (extended CONNECT takeover)" << std::endl;
    wavex::engine::Http3Router router;

    struct wt_seen {
        std::string path, req_path, origin, stream_data;
        uint64_t id = 99;
    };
    auto seen = std::make_shared<wt_seen>();
    auto handler_started = std::make_shared<std::promise<void> >();
    auto stream_read = std::make_shared<std::promise<void> >();
    auto handler_done = std::make_shared<std::promise<void> >();

    router.webtransport("/wt", [seen, handler_started, stream_read, handler_done](
                        wavex::protos::http::Http3Request &req, std::shared_ptr<wt::session> s) -> wavex::task<void> {
                            seen->path = s->path();
                            seen->req_path = std::string(req.path());
                            seen->origin = s->origin();
                            seen->id = s->id();
                            handler_started->set_value();
                            while (auto st = co_await s->accept_bidirectional_stream()) {
                                auto [ec, data] = co_await st->read_all();
                                seen->stream_data = data;
                                stream_read->set_value();
                                std::ignore = co_await st->write("ack");
                                st->finish();
                            }
                            handler_done->set_value();
                        });

    auto ws_message = std::make_shared<std::promise<std::string> >();
    router.websocket("/ws", [ws_message](wavex::protos::http::Http3Request &,
                                         std::shared_ptr<ws::connection> c) -> wavex::task<void> {
        auto m = co_await c->read();
        ws_message->set_value(m ? m->data : std::string("<error>"));
        while (co_await c->read()) {
        }
    });

    constexpr unsigned short port = 19873;
    wavex::server::Http3Server server(router, "127.0.0.1", port);
    server.enable_signal_handling(false);
    server.allow_insecure();
    std::thread server_thread([&server] { server.run(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(80));

    asio::io_context io;
    const auto conn = mock_server_conn(io, 9913);
    std::thread io_thread([&io] {
        auto guard = asio::make_work_guard(io);
        io.run_for(std::chrono::seconds(10));
    });

    // WebTransport session on stream 0.
    const auto s0 = conn->get_or_create_stream(0);
    s0->push_inbound(extended_connect("webtransport", "/wt", {{"origin", "https://example.org"},
                                                              {"sec-webtransport-http3-draft02", "1"}}), false);
    // Hand the stream to the server from its own reactor thread, as the QUIC listener does, so the
    // router (frozen at the start of run()) is published to the connection coroutine.
    asio::post(server.io_context(), [&server, s0] { server.spawn_connection(s0); });
    const bool started = handler_started->get_future().wait_for(std::chrono::seconds(3)) == std::future_status::ready;
    check(started, "router.webtransport() handler runs after the 200 response");
    check(seen->id == 0 && seen->path == "/wt" && seen->req_path == "/wt" && seen->origin == "https://example.org",
          "session exposes its ID, path and Origin; the request is still valid");

    // A WebTransport stream arrives through the listener-side demultiplexer.
    const auto s4 = conn->get_or_create_stream(4);
    s4->push_inbound(varint(wt::kBidiStreamSignal) + varint(0) + "stream-payload", true);
    asio::co_spawn(io, [s4]() -> wavex::task<void> {
        co_await wt::dispatch_bidirectional_stream(s4);
    }, asio::detached);

    const bool read_ok = stream_read->get_future().wait_for(std::chrono::seconds(3)) == std::future_status::ready;
    check(read_ok && seen->stream_data == "stream-payload", "session handler reads a client bidirectional stream");

    // Client closes the session.
    s0->push_inbound(h3::encode_tunnel_data_frame(wt::capsule::encode_close_session(0, "")), true);
    const bool done = handler_done->get_future().wait_for(std::chrono::seconds(3)) == std::future_status::ready;
    check(done, "CLOSE capsule ends the session and the handler returns");
    for (int i = 0; i < 300 && !s0->is_fin_sent(); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));
    check(s0->is_fin_sent(), "server finished the CONNECT stream after the session");

    // WebSocket over HTTP/3 (RFC 9220) on stream 8.
    const auto s8 = conn->get_or_create_stream(8);
    std::string ws_frame;
    ws::codec::encode_frame(ws_frame, ws::opcode::text, "hello-rfc9220", true, 0x0badf00du);
    std::string close_frame;
    ws::codec::encode_frame(close_frame, ws::opcode::close, ws::codec::close_payload(1000), true, 0x0badf00du);
    s8->push_inbound(extended_connect("websocket", "/ws", {{"sec-websocket-version", "13"}}) +
                     h3::encode_tunnel_data_frame(ws_frame), false);
    asio::post(server.io_context(), [&server, s8] { server.spawn_connection(s8); });
    auto ws_future = ws_message->get_future();
    const bool ws_ok = ws_future.wait_for(std::chrono::seconds(3)) == std::future_status::ready;
    check(ws_ok && ws_future.get() == "hello-rfc9220", "WebSocket message received over an HTTP/3 extended CONNECT");
    s8->push_inbound(h3::encode_tunnel_data_frame(close_frame), true);
    for (int i = 0; i < 300 && !s8->is_fin_sent(); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));
    check(s8->is_fin_sent(), "WebSocket-over-HTTP/3 session closed its stream");

    conn->close();
    io.stop();
    if (io_thread.joinable()) io_thread.join();
    server.stop();
    if (server_thread.joinable()) server_thread.join();
}

int main() {
    std::cout << "==================================================" << std::endl;
    std::cout << " WaveX WebTransport / HTTP/3 extended CONNECT Tests" << std::endl;
    std::cout << "==================================================" << std::endl;

    test_capsules();
    test_extended_connect_parsing();
    test_quic_datagram_frames();
    test_data_tunnel();
    test_websocket_over_tunnel();
    test_stream_demux_and_registry();
    test_server_integration();

    std::cout << "\n Results: " << tests_passed << " / " << tests_run << " passed" << std::endl;
    return tests_passed == tests_run ? 0 : 1;
}

#else

int main() {
    std::cout << "WebTransport requires WAVEX_HAS_SSL; skipped." << std::endl;
    return 0;
}

#endif
