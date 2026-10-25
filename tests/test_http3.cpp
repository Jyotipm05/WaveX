// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file test_http3.cpp
 * @brief Comprehensive Unit & Integration Tests for WaveX HTTP/3 Binary Framing and QPACK Engine (RFC 9114 & RFC 9204).
 */

#include <iostream>
#include <cassert>
#include <string>
#include <vector>
#include <thread>
#include <chrono>

#include <wavex/protos/http/http3codec.hpp>
#include <wavex/protos/http/http.hpp>
#include <wavex/Server/Server.hpp>
#include <wavex/Network/QUIC.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/steady_timer.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>

namespace h3 = wavex::protos::http::http3;
namespace h2 = wavex::protos::http::http2;
namespace qpk = wavex::protos::http::http3::qpack;
namespace quic = wavex::network::quic;

using wavex::protos::http::header;
using wavex::protos::http::method;
using wavex::protos::http::http3codec;

using h3::frame_header;
using h3::frame_type;
using h3::settings_parameter;

void test_http3_framing() {
    std::cout << "[Test HTTP/3] HTTP/3 Binary Framing (RFC 9114)...\n";

    // 1. DATA frame
    constexpr std::string_view payload = "HTTP/3 Wire Payload Body Data!";
    std::string data_frame = h3::encoder::encode_data_frame(payload);
    assert(!data_frame.empty());

    frame_header hdr;
    std::string_view frame_payload;
    std::size_t consumed = 0;
    auto parse_res = h3::parser::parse_frame(data_frame, hdr, frame_payload, consumed);
    assert(parse_res == h3::parser::result::success);
    assert(hdr.type == static_cast<uint64_t>(frame_type::DATA));
    assert(frame_payload == payload);
    assert(consumed == data_frame.size());

    // 2. SETTINGS frame
    std::vector<std::pair<settings_parameter, uint64_t> > settings = {
        {settings_parameter::QPACK_MAX_TABLE_CAPACITY, 4096},
        {settings_parameter::MAX_FIELD_SECTION_SIZE, 65536}
    };
    std::string settings_frame = h3::encoder::serialize_settings(settings);
    assert(!settings_frame.empty());

    frame_header s_hdr;
    std::string_view s_payload;
    std::size_t s_consumed = 0;
    auto s_res = h3::parser::parse_frame(settings_frame, s_hdr, s_payload, s_consumed);
    assert(s_res == h3::parser::result::success);
    assert(s_hdr.type == static_cast<uint64_t>(frame_type::SETTINGS));
    assert(s_consumed == settings_frame.size());

    std::cout << "  [PASS] HTTP/3 Binary Framing passed.\n";
}

void test_http3codec_full_message_roundtrip() {
    std::cout << "[Test HTTP/3] http3codec Request and Response roundtrip...\n";

    // 1. Request test
    h3::request req;
    req.method_type = method::POST;
    req.target = "/api/v1/products";
    req.scheme = "https";
    req.authority = "api.wavex.internal";
    req.headers.reserve(2);
    req.headers.emplace_back("content-type", "application/json");
    req.headers.emplace_back("x-client-id", "quic-client-99");
    req.body = "{\"product\":\"quic-nitro\",\"price\":99}";

    std::string wire_req = http3codec::serialize_request(req);
    assert(!wire_req.empty());

    h3::request parsed_req;
    std::size_t req_consumed = 0;
    qpk::dynamic_table req_dt;
    auto r_res = http3codec::parse_request(wire_req, parsed_req, req_consumed, req_dt);
    assert(r_res == http3codec::result::success);
    assert(parsed_req.method_type == method::POST);
    assert(parsed_req.target == "/api/v1/products");
    assert(parsed_req.scheme == "https");
    assert(parsed_req.authority == "api.wavex.internal");
    assert(parsed_req.body == req.body);
    assert(parsed_req.get_header("content-type").value_or("") == "application/json");
    assert(parsed_req.get_header("x-client-id").value_or("") == "quic-client-99");

    // 2. Response test
    h3::response res;
    res.status_code = 201;
    res.status_text = "Created";
    res.headers.reserve(2);
    res.headers.emplace_back("content-type", "application/json");
    res.headers.emplace_back("server", "WaveX-HTTP3");
    res.body = "{\"status\":\"created\",\"id\":\"prod-12345\"}";

    std::string wire_res = http3codec::serialize(res);
    assert(!wire_res.empty());

    h3::response parsed_res;
    std::size_t res_consumed = 0;
    qpk::dynamic_table res_dt;
    auto resp_res = http3codec::parse_response(wire_res, parsed_res, res_consumed, res_dt);
    assert(resp_res == http3codec::result::success);
    assert(parsed_res.status_code == 201);
    assert(parsed_res.body == res.body);
    assert(parsed_res.get_header("content-type").value_or("") == "application/json");
    assert(parsed_res.get_header("server").value_or("") == "WaveX-HTTP3");

    std::cout << "  [PASS] http3codec Request and Response roundtrip passed.\n";
}

void test_http3_over_quic_stream() {
    std::cout << "[Test HTTP/3] HTTP/3 Request/Response exchange over QuicStream...\n";

    asio::io_context io;
    auto ep = asio::ip::udp::endpoint(asio::ip::address_v4::loopback(), 9998);
    auto client_conn = std::make_shared<quic::QuicConnection>(
        quic::ConnectionId::random(8), quic::ConnectionId::random(8), ep, false);
    auto server_conn = std::make_shared<quic::QuicConnection>(
        client_conn->peer_cid(), client_conn->local_cid(), ep, true);

    auto client_stream = client_conn->create_stream(true);
    auto server_stream = server_conn->get_or_create_stream(client_stream->stream_id());

    // 1. Client serializes HTTP/3 request
    h3::request req;
    req.method_type = method::GET;
    req.target = "/healthcheck";
    req.scheme = "https";
    req.authority = "localhost";
    req.body = "";
    std::string wire_req = http3codec::serialize_request(req);

    // Simulate wire transit by pushing data into server_stream
    server_stream->push_inbound(wire_req, true);

    // 2. Server reads and parses HTTP/3 request
    h3::request server_received_req;
    char server_buf[4096];
    std::error_code ec;
    std::size_t n = server_stream->read_some(asio::buffer(server_buf), ec);
    assert(n > 0);

    std::size_t consumed = 0;
    qpk::dynamic_table server_dt;
    auto srv_parse_res = http3codec::parse_request(
        std::string_view(server_buf, n), server_received_req, consumed, server_dt);
    assert(srv_parse_res == http3codec::result::success);
    assert(server_received_req.method_type == method::GET);
    assert(server_received_req.target == "/healthcheck");

    // 3. Server generates HTTP/3 response and pushes to client
    h3::response s_res;
    s_res.status_code = 200;
    s_res.headers.reserve(1);
    s_res.headers.emplace_back("content-type", "text/plain");
    s_res.body = "OK";
    std::string wire_resp = http3codec::serialize(s_res);

    client_stream->push_inbound(wire_resp, true);

    // 4. Client reads and parses HTTP/3 response
    char client_buf[4096];
    std::size_t cn = client_stream->read_some(asio::buffer(client_buf), ec);
    assert(cn > 0);

    h3::response client_received_res;
    std::size_t c_consumed = 0;
    qpk::dynamic_table client_dt;
    auto c_parse_res = http3codec::parse_response(
        std::string_view(client_buf, cn), client_received_res, c_consumed, client_dt);
    assert(c_parse_res == http3codec::result::success);
    assert(client_received_res.status_code == 200);
    assert(client_received_res.body == "OK");

    std::cout << "  [PASS] HTTP/3 over QuicStream exchange passed.\n";
}

void test_http3_rfc9114_stream_rules() {
    std::cout << "[Test HTTP/3] RFC 9114 Request Stream Rules...\n";

    // 1. DATA before HEADERS -> must return error
    std::string bad_data_first = h3::encoder::encode_data_frame("Illegal early body");
    h3::request req1;
    std::size_t consumed1 = 0;
    qpk::dynamic_table dt1;
    auto r1 = http3codec::parse_request(bad_data_first, req1, consumed1, dt1);
    assert(r1 == http3codec::result::error);

    // 2. SETTINGS frame on Request Stream -> must return error
    std::string bad_settings = h3::encoder::serialize_settings({{settings_parameter::MAX_FIELD_SECTION_SIZE, 65536}});
    h3::request req2;
    std::size_t consumed2 = 0;
    qpk::dynamic_table dt2;
    auto r2 = http3codec::parse_request(bad_settings, req2, consumed2, dt2);
    assert(r2 == http3codec::result::error);

    // 3. Unknown frames are ignored/skipped per RFC 9114 §7.2.8
    h3::request valid_req;
    valid_req.method_type = method::GET;
    valid_req.target = "/api/test";
    valid_req.scheme = "https";
    valid_req.authority = "wavex.internal";
    valid_req.body = "body-payload";
    std::string headers_frame = h3::encoder::encode_frame(
        frame_type::HEADERS,
        qpk::encoder::encode_request_headers(valid_req.method_type, valid_req.target, valid_req.scheme,
                                             valid_req.authority, valid_req.headers));

    // Inject unknown frame type 0x3f (decimal 63)
    std::string unknown_frame;
    unknown_frame.reserve(16);
    quic::VarInt::encode(0x3f, unknown_frame);
    quic::VarInt::encode(4, unknown_frame);
    unknown_frame.append("WAVX");

    std::string data_frame = h3::encoder::encode_data_frame(valid_req.body);

    std::string wire_with_unknown;
    wire_with_unknown.reserve(headers_frame.size() + unknown_frame.size() + data_frame.size());
    wire_with_unknown.append(headers_frame).append(unknown_frame).append(data_frame);
    h3::request parsed_req;
    std::size_t consumed3 = 0;
    qpk::dynamic_table dt3;
    auto r3 = http3codec::parse_request(wire_with_unknown, parsed_req, consumed3, dt3);
    assert(r3 == http3codec::result::success);
    assert(parsed_req.method_type == method::GET);
    assert(parsed_req.target == "/api/test");
    assert(parsed_req.body == "body-payload");
    assert(consumed3 == wire_with_unknown.size());

    std::cout << "  [PASS] RFC 9114 Request Stream Rules passed.\n";
}

void test_http3_server_acceptor_guard() {
    std::cout << "[Test HTTP/3] Server TCP Acceptor Guard & Composition...\n";

    // 1. Static compile-time trait assertions
    static_assert(!wavex::protos::protocol_traits<wavex::protos::http::http3codec>::has_tcp_transport,
                  "HTTP/3 must have has_tcp_transport = false");
    static_assert(wavex::protos::protocol_traits<wavex::protos::http::http1codec>::has_tcp_transport,
                  "HTTP/1.1 must have has_tcp_transport = true");
    static_assert(wavex::protos::protocol_traits<wavex::protos::http::http2codec>::has_tcp_transport,
                  "HTTP/2 must have has_tcp_transport = true");

    // 2. Standalone Http3Server: acceptor must never open, port refuses TCP connections
    wavex::engine::Http3Router h3_router;
    wavex::server::Http3Server h3_server(h3_router, "127.0.0.1", 19983);
    h3_server.enable_signal_handling(false);
    assert(!h3_server.is_acceptor_open());
    assert(h3_server.is_http3_enabled());

    h3_server.allow_insecure();
    std::thread h3_thread([&h3_server]() {
        h3_server.run();
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    assert(!h3_server.is_acceptor_open());

    // Attempting a plain-TCP connection to the HTTP/3 port MUST be cleanly rejected
    // by the OS kernel (Connection Refused / TCP RST), NEVER accepted and mis-parsed.
    // We use an async connect with a deadline timer to avoid the OS kernel's
    // 2000ms synchronous SYN retransmit stall on Windows loopback.
    {
        asio::io_context client_io;
        asio::ip::tcp::socket tcp_sock(client_io);
        asio::steady_timer timer(client_io, std::chrono::milliseconds(20));
        bool connected = false;
        asio::error_code connect_ec;

        tcp_sock.async_connect(asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), 19983),
                               [&](const asio::error_code &ec) {
                                   connect_ec = ec;
                                   if (!ec) connected = true;
                                   timer.cancel();
                               });

        timer.async_wait([&](const asio::error_code &) {
            asio::error_code cancel_ec;
            tcp_sock.cancel(cancel_ec);
        });

        client_io.run();
        assert(!connected); // Plain TCP connection must never succeed on HTTP/3 UDP port!
    }

    h3_server.stop();
    if (h3_thread.joinable()) {
        h3_thread.join();
    }

    // 3. ComposedHttpServer: opens TCP acceptor for HTTP/2 + HTTP/1.1 and QUIC for HTTP/3
    wavex::server::ComposedHttpServer comp_server("127.0.0.1", 19984);
    comp_server.tcp_server().enable_signal_handling(false);
    assert(!comp_server.is_acceptor_open()); // Unopened before run()
    assert(comp_server.is_http3_enabled());

    comp_server.allow_insecure();
    std::thread comp_thread([&comp_server]() {
        comp_server.run();
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    assert(comp_server.is_acceptor_open());

    // Composed server must successfully accept plain TCP connections
    {
        asio::io_context client_io2;
        asio::ip::tcp::socket tcp_sock2(client_io2);
        asio::error_code ec2;
        tcp_sock2.connect(asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), 19984), ec2);
        assert(!ec2); // Composed server accepts TCP cleanly!
        tcp_sock2.close(ec2);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    comp_server.stop();
    if (comp_thread.joinable()) {
        comp_thread.join();
    }

    std::cout << "  [PASS] Server TCP Acceptor Guard & Composition tests passed." << std::endl;
}

void test_http3_unidirectional_control_and_qpack_streams() {
    std::cout << "[Test HTTP/3] RFC 9114 §6.2 Unidirectional Control & QPACK Stream Establishment...\n";

    auto ep = asio::ip::udp::endpoint(asio::ip::address_v4::loopback(), 9996);
    auto server_conn = std::make_shared<quic::QuicConnection>(
        quic::ConnectionId::random(8), quic::ConnectionId::random(8), ep, true);

    assert(!server_conn->is_http3_session_initialized());
    server_conn->initialize_http3_session();
    assert(server_conn->is_http3_session_initialized());

    // Outgoing datagrams must contain the 3 streams
    auto datagrams = server_conn->poll_outgoing_datagrams();
    assert(!datagrams.empty());

    // Stream 3 is Control Stream
    auto stream3 = server_conn->get_or_create_stream(3);
    assert(stream3 != nullptr);
    assert(stream3->stream_id() == 3);

    // Stream 7 is QPACK Encoder Stream
    auto stream7 = server_conn->get_or_create_stream(7);
    assert(stream7 != nullptr);
    assert(stream7->stream_id() == 7);

    // Stream 11 is QPACK Decoder Stream
    auto stream11 = server_conn->get_or_create_stream(11);
    assert(stream11 != nullptr);
    assert(stream11->stream_id() == 11);

    std::cout << "  [PASS] RFC 9114 §6.2 Unidirectional Control & QPACK streams verified.\n";
}

void test_http3_body_truncation_prevention_c1() {
    std::cout << "[Test HTTP/3] Body truncation prevention & Content-Length verification (C1)...\n";

    // 1. Construct valid HTTP/3 request
    h3::request req;
    req.method_type = method::POST;
    req.target = "/submit";
    req.scheme = "https";
    req.authority = "127.0.0.1";
    req.headers.emplace_back("content-length", "11");
    req.body = "hello world";

    std::string headers_frame = h3::encoder::encode_frame(
        frame_type::HEADERS,
        qpk::encoder::encode_request_headers(req.method_type, req.target, req.scheme,
                                             req.authority, req.headers));
    std::string data_frame = h3::encoder::encode_data_frame(req.body);
    std::string full_wire = headers_frame + data_frame;

    // 2. Cut wire buffer in half (DATA frame is cut off)
    assert(data_frame.size() > 5);
    std::string partial_wire = headers_frame + data_frame.substr(0, data_frame.size() - 5);

    h3::request parsed_req;
    std::size_t consumed = 0;
    qpk::dynamic_table dec_dt;
    const auto res_incomplete = http3codec::parse_request(partial_wire, parsed_req, consumed, dec_dt);
    // Must return incomplete, NOT success with a truncated body!
    assert(res_incomplete == http3codec::result::incomplete);

    // 3. Provide full wire: must return success with the full body
    const auto res_complete = http3codec::parse_request(full_wire, parsed_req, consumed, dec_dt);
    assert(res_complete == http3codec::result::success);
    assert(parsed_req.body == "hello world");

    std::cout << "  [PASS] C1: Request body truncation properly prevented." << std::endl;
}

void test_http3_malformed_request_rejection_c8() {
    std::cout << "[Test HTTP/3] C8: Malformed request rejection per RFC 9114 §4.3 & §4.2...\n";

    // 1. Valid request
    {
        std::string fields;
        fields.push_back('\0'); // RIC = 0
        fields.push_back('\0'); // Delta base = 0
        qpk::encoder::encode_indexed_static(fields, 17); // :method GET
        qpk::encoder::encode_indexed_static(fields, 1);  // :path /
        qpk::encoder::encode_indexed_static(fields, 23); // :scheme https
        std::string frame = h3::encoder::encode_frame(frame_type::HEADERS, fields);

        h3::request req;
        std::size_t consumed = 0;
        qpk::dynamic_table dt;
        auto res = http3codec::parse_request(frame, req, consumed, dt);
        assert(res == http3codec::result::success);
        assert(req.method_type == method::GET);
        assert(req.target == "/");
    }

    // 2. Missing :path (must fail per RFC 9114 §4.3)
    {
        std::string fields;
        fields.push_back('\0');
        fields.push_back('\0');
        qpk::encoder::encode_indexed_static(fields, 17); // :method GET
        qpk::encoder::encode_indexed_static(fields, 23); // :scheme https
        std::string frame = h3::encoder::encode_frame(frame_type::HEADERS, fields);

        h3::request req;
        std::size_t consumed = 0;
        qpk::dynamic_table dt;
        auto res = http3codec::parse_request(frame, req, consumed, dt);
        assert(res == http3codec::result::error);
    }

    // 3. Duplicate :method (must fail per RFC 9114 §4.3)
    {
        std::string fields;
        fields.push_back('\0');
        fields.push_back('\0');
        qpk::encoder::encode_indexed_static(fields, 17); // :method GET
        qpk::encoder::encode_indexed_static(fields, 20); // :method POST (duplicate!)
        qpk::encoder::encode_indexed_static(fields, 1);  // :path /
        std::string frame = h3::encoder::encode_frame(frame_type::HEADERS, fields);

        h3::request req;
        std::size_t consumed = 0;
        qpk::dynamic_table dt;
        auto res = http3codec::parse_request(frame, req, consumed, dt);
        assert(res == http3codec::result::error);
    }

    // 4. Uppercase header name (must fail per RFC 9114 §4.2)
    {
        std::string fields;
        fields.push_back('\0');
        fields.push_back('\0');
        qpk::encoder::encode_indexed_static(fields, 17); // :method GET
        qpk::encoder::encode_indexed_static(fields, 1);  // :path /
        qpk::encoder::encode_literal_new_name(fields, "X-Custom-Header", "value"); // Uppercase!
        std::string frame = h3::encoder::encode_frame(frame_type::HEADERS, fields);

        h3::request req;
        std::size_t consumed = 0;
        qpk::dynamic_table dt;
        auto res = http3codec::parse_request(frame, req, consumed, dt);
        assert(res == http3codec::result::error);
    }

    // 5. Prohibited connection header (must fail per RFC 9114 §4.2)
    {
        std::string fields;
        fields.push_back('\0');
        fields.push_back('\0');
        qpk::encoder::encode_indexed_static(fields, 17); // :method GET
        qpk::encoder::encode_indexed_static(fields, 1);  // :path /
        qpk::encoder::encode_literal_new_name(fields, "connection", "close"); // Prohibited!
        std::string frame = h3::encoder::encode_frame(frame_type::HEADERS, fields);

        h3::request req;
        std::size_t consumed = 0;
        qpk::dynamic_table dt;
        auto res = http3codec::parse_request(frame, req, consumed, dt);
        assert(res == http3codec::result::error);
    }

    // 6. Pseudo-header after regular header (must fail per RFC 9114 §4.3)
    {
        std::string fields;
        fields.push_back('\0');
        fields.push_back('\0');
        qpk::encoder::encode_indexed_static(fields, 17); // :method GET
        qpk::encoder::encode_literal_new_name(fields, "x-header", "value"); // Regular header
        qpk::encoder::encode_indexed_static(fields, 1);  // :path / (after regular header!)
        std::string frame = h3::encoder::encode_frame(frame_type::HEADERS, fields);

        h3::request req;
        std::size_t consumed = 0;
        qpk::dynamic_table dt;
        auto res = http3codec::parse_request(frame, req, consumed, dt);
        assert(res == http3codec::result::error);
    }

    std::cout << "  [PASS] C8: Malformed request rejection passed." << std::endl;
}

void test_http3_session_unidirectional_routing_c7() {
    std::cout << "[Test HTTP/3] C7: Unidirectional Control, Encoder and Decoder routing & dynamic table session...\n";

    asio::io_context io;
    auto ep = asio::ip::udp::endpoint(asio::ip::address_v4::loopback(), 9999);
    auto server_conn = std::make_shared<quic::QuicConnection>(
        quic::ConnectionId::random(8), quic::ConnectionId::random(8), ep, true, io.get_executor());

    // 1. Connection-level context initially absent, then initialized
    assert(server_conn->user_context() == nullptr);
    auto ctx = std::make_shared<h3::connection_context>();
    server_conn->set_user_context(ctx);
    assert(server_conn->user_context() == ctx);

    // 2. Client-initiated unidirectional Stream 2 (sid & 0x03 == 2) -> Control Stream
    auto ctrl_stream = server_conn->get_or_create_stream(2);
    assert(ctrl_stream != nullptr);

    // Wire data for Control Stream: Type 0x00 followed by SETTINGS frame and GOAWAY frame
    std::string ctrl_wire;
    quic::VarInt::encode(0x00, ctrl_wire); // Type 0x00 = Control Stream

    // SETTINGS payload: QPACK_MAX_TABLE_CAPACITY = 4096 (id=1), MAX_FIELD_SECTION_SIZE = 32768 (id=6)
    std::string settings_payload;
    quic::VarInt::encode(0x01, settings_payload);
    quic::VarInt::encode(4096, settings_payload);
    quic::VarInt::encode(0x06, settings_payload);
    quic::VarInt::encode(32768, settings_payload);
    ctrl_wire.append(h3::encoder::encode_frame(frame_type::SETTINGS, settings_payload));

    // GOAWAY payload: Stream ID = 100
    std::string goaway_payload;
    quic::VarInt::encode(100, goaway_payload);
    ctrl_wire.append(h3::encoder::encode_frame(frame_type::GOAWAY, goaway_payload));

    ctrl_stream->push_inbound(ctrl_wire, false);

    // Spawn unidirectional session handler for Control Stream
    asio::co_spawn(io, [ctrl_stream, ctx]() -> asio::awaitable<void> {
        co_await h3::session_handler::handle_unidirectional_stream(ctrl_stream, ctx);
    }, asio::detached);
    io.poll();

    // Verify Control Stream frames parsed into connection_context
    assert(ctx->settings_received == true);
    assert(ctx->peer_qpack_max_table_capacity == 4096);
    assert(ctx->max_field_section_size == 32768);
    assert(ctx->goaway_received == true);
    assert(ctx->goaway_stream_id == 100);

    // 3. Client-initiated unidirectional Stream 6 (sid & 0x03 == 2) -> QPACK Encoder Stream
    auto enc_stream = server_conn->get_or_create_stream(6);
    assert(enc_stream != nullptr);

    std::string enc_wire;
    quic::VarInt::encode(0x02, enc_wire); // Type 0x02 = QPACK Encoder Stream

    // Encoder instruction: Insert with Literal Name (01Hxxxxx)
    qpk::encoder::encode_insert_with_literal_name(enc_wire, "x-routed-header", "c7-verified");

    enc_stream->push_inbound(enc_wire, false);

    // Spawn handler for Encoder Stream
    asio::co_spawn(io, [enc_stream, ctx]() -> asio::awaitable<void> {
        co_await h3::session_handler::handle_unidirectional_stream(enc_stream, ctx);
    }, asio::detached);
    io.poll();

    // Verify dynamic table in connection_context received the instruction!
    assert(ctx->decode_table.count() == 1);
    const auto *entry = ctx->decode_table.get_by_absolute_index(0);
    assert(entry != nullptr);
    assert(entry->name == "x-routed-header");
    assert(entry->value == "c7-verified");

    // 4. Verify request stream (sid=0 bidi) uses the connection's session_context and parses the dynamic header!
    auto bidi_stream = server_conn->get_or_create_stream(0);
    assert(bidi_stream != nullptr);
    assert(bidi_stream->connection() == server_conn);

    h3::connection_context fallback;
    auto &retrieved_ctx = wavex::protos::protocol_traits<wavex::protos::http::http3codec>::get_connection_context(bidi_stream, fallback);
    assert(&retrieved_ctx == ctx.get());

    // Build HTTP/3 request referencing the dynamic table entry
    std::string req_fields;
    // Prefix: RIC = 1, Delta Base = 0
    h3::qpack::encoder::encode_prefix(req_fields, 1, 1, 4096);
    h3::qpack::encoder::encode_indexed_static(req_fields, 17); // :method GET
    h3::qpack::encoder::encode_indexed_static(req_fields, 1);  // :path /
    h3::qpack::encoder::encode_indexed_static(req_fields, 23); // :scheme https
    // Indexed Field Line - Dynamic Table (Relative Index 0 -> Absolute Index = 1 - 1 - 0 = 0)
    h3::qpack::encoder::encode_indexed_dynamic(req_fields, 0);

    std::string req_frame = h3::encoder::encode_frame(frame_type::HEADERS, req_fields);
    h3::request req;
    std::size_t consumed = 0;
    auto parse_res = http3codec::parse_request(req_frame, req, consumed, retrieved_ctx);
    assert(parse_res == http3codec::result::success);
    assert(req.headers_storage.size() == 1);
    assert(req.headers_storage[0].first == "x-routed-header");
    assert(req.headers_storage[0].second == "c7-verified");

    ctrl_stream->close();
    enc_stream->close();
    bidi_stream->close();
    server_conn->close();
    io.stop();
    io.poll();

    std::cout << "  [PASS] C7: Control, encoder and decoder streams successfully routed and decoded." << std::endl;
}

void test_http3_resumable_parser_c2() {
    std::cout << "[Test HTTP/3] C2: Resumable non-quadratic streaming parser..." << std::endl;

    // 1. Chunked streaming of single DATA frame across small read slices
    {
        h3::request orig_req;
        orig_req.method_type = method::POST;
        orig_req.target = "/upload";
        orig_req.scheme = "https";
        orig_req.authority = "wavex.dev";
        std::string long_body;
        for (int i = 0; i < 50; ++i) {
            long_body += "chunk-payload-" + std::to_string(i) + ";";
        }
        orig_req.body = long_body;
        // header holds string_views: the value must outlive the request, so it cannot be a temporary.
        const std::string long_body_len = std::to_string(long_body.size());
        orig_req.headers.emplace_back("content-length", long_body_len);

        std::string wire = http3codec::serialize_request(orig_req);
        assert(!wire.empty());

        h3::request parsed_req;
        qpk::dynamic_table dt;
        std::size_t consumed = 0;
        std::string stream_buf;

        // Feed wire data in tiny 17-byte chunks to stress resumable parser state
        const std::size_t chunk_size = 17;
        http3codec::result r = http3codec::result::incomplete;
        for (std::size_t offset = 0; offset < wire.size(); offset += chunk_size) {
            const std::size_t slice_len = std::min(chunk_size, wire.size() - offset);
            stream_buf.append(wire.substr(offset, slice_len));
            r = http3codec::parse_request(stream_buf, parsed_req, consumed, dt);
            if (offset + slice_len < wire.size()) {
                assert(r == http3codec::result::incomplete);
            }
        }

        assert(r == http3codec::result::success);
        assert(parsed_req.body == long_body);
        assert(parsed_req.method_type == method::POST);
        assert(parsed_req.target == "/upload");
    }

    // 2. Multiple sequential DATA frames arriving incrementally
    {
        std::string fields;
        fields.push_back('\0'); // RIC = 0
        fields.push_back('\0'); // Delta base = 0
        qpk::encoder::encode_indexed_static(fields, 17); // :method GET
        qpk::encoder::encode_indexed_static(fields, 1);  // :path /
        qpk::encoder::encode_indexed_static(fields, 23); // :scheme https
        qpk::encoder::encode_literal_with_name_ref(fields, 4, true, "15"); // content-length: 15 (index 4 in QPACK static table)
        std::string headers_frame = h3::encoder::encode_frame(frame_type::HEADERS, fields);

        std::string data1 = h3::encoder::encode_frame(frame_type::DATA, "hello");
        std::string data2 = h3::encoder::encode_frame(frame_type::DATA, "world");
        std::string data3 = h3::encoder::encode_frame(frame_type::DATA, "12345");

        h3::request req;
        qpk::dynamic_table dt;
        std::size_t consumed = 0;
        std::string stream_buf = headers_frame;

        // Pass headers frame: incomplete because body (15 bytes) not received
        auto r1 = http3codec::parse_request(stream_buf, req, consumed, dt);
        assert(r1 == http3codec::result::incomplete);
        assert(req.state_.headers_received);

        // Append data1
        stream_buf += data1;
        auto r2 = http3codec::parse_request(stream_buf, req, consumed, dt);
        assert(r2 == http3codec::result::incomplete);
        assert(req.body_storage == "hello");

        // Append data2
        stream_buf += data2;
        auto r3 = http3codec::parse_request(stream_buf, req, consumed, dt);
        assert(r3 == http3codec::result::incomplete);
        assert(req.body_storage == "helloworld");

        // Append data3 (completes 15 bytes)
        stream_buf += data3;
        auto r4 = http3codec::parse_request(stream_buf, req, consumed, dt);
        assert(r4 == http3codec::result::success);
        assert(req.body == "helloworld12345");
    }

    // 3. Resumable response parser with streaming DATA frames
    {
        h3::response orig_res;
        orig_res.status_code = 200;
        orig_res.body = "Streamed HTTP/3 Response Body Payload";
        const std::string orig_res_len = std::to_string(orig_res.body.size());
        orig_res.headers.emplace_back("content-length", orig_res_len);

        std::string wire = http3codec::serialize(orig_res);
        assert(!wire.empty());

        h3::response parsed_res;
        qpk::dynamic_table dt;
        std::size_t consumed = 0;
        std::string stream_buf;

        const std::size_t chunk_size = 11;
        http3codec::result r = http3codec::result::incomplete;
        for (std::size_t offset = 0; offset < wire.size(); offset += chunk_size) {
            const std::size_t slice_len = std::min(chunk_size, wire.size() - offset);
            stream_buf.append(wire.substr(offset, slice_len));
            r = http3codec::parse_response(stream_buf, parsed_res, consumed, dt);
            if (offset + slice_len < wire.size()) {
                assert(r == http3codec::result::incomplete);
            }
        }

        assert(r == http3codec::result::success);
        assert(parsed_res.status_code == 200);
        assert(parsed_res.body == orig_res.body);
    }

    std::cout << "  [PASS] C2: Resumable non-quadratic streaming parser verified." << std::endl;
}

void test_http3_reserved_frame_types_c9() {
    std::cout << "[Test HTTP/3] C9: Rejection of HTTP/2 Reserved Frame Types (RFC 9114 §7.2.8)...\n";

    // Build a valid request headers frame
    h3::request valid_req;
    valid_req.method_type = method::GET;
    valid_req.target = "/api/resource";
    valid_req.scheme = "https";
    valid_req.authority = "wavex.internal";
    valid_req.body = "valid-body";

    const std::string headers_frame = h3::encoder::encode_frame(
        frame_type::HEADERS,
        qpk::encoder::encode_request_headers(valid_req.method_type, valid_req.target, valid_req.scheme,
                                             valid_req.authority, valid_req.headers));

    // HTTP/2 Reserved frame types per RFC 9114 §7.2.8 & §11.2.1:
    // 0x02 (PRIORITY), 0x06 (PING), 0x08 (WINDOW_UPDATE), 0x09 (CONTINUATION)
    const std::vector<uint64_t> reserved_types = {0x02, 0x06, 0x08, 0x09};

    for (const uint64_t reserved_type : reserved_types) {
        assert(wavex::protos::http::http3::is_reserved_frame_type(reserved_type));
        assert(http3codec::is_reserved_frame(reserved_type));
        assert(h3::parser::is_reserved_frame(reserved_type));

        std::string reserved_frame;
        quic::VarInt::encode(reserved_type, reserved_frame);
        quic::VarInt::encode(8, reserved_frame);
        reserved_frame.append("12345678");

        // 1. Standalone reserved frame on request stream -> must return error
        {
            h3::request req;
            std::size_t consumed = 0;
            qpk::dynamic_table dt;
            const auto r = http3codec::parse_request(reserved_frame, req, consumed, dt);
            assert(r == http3codec::result::error);
        }

        // 2. Interleaved reserved frame after HEADERS on request stream -> must return error
        {
            const std::string wire = headers_frame + reserved_frame;
            h3::request req;
            std::size_t consumed = 0;
            qpk::dynamic_table dt;
            const auto r = http3codec::parse_request(wire, req, consumed, dt);
            assert(r == http3codec::result::error);
        }

        // 3. Standalone reserved frame on response stream -> must return error
        {
            h3::response res;
            std::size_t consumed = 0;
            qpk::dynamic_table dt;
            const auto r = http3codec::parse_response(reserved_frame, res, consumed, dt);
            assert(r == http3codec::result::error);
        }

        // 4. Interleaved reserved frame on response stream after HEADERS -> must return error
        {
            h3::response valid_res;
            valid_res.status_code = 200;
            valid_res.body = "ok";
            const std::string res_headers_frame = h3::encoder::encode_frame(
                frame_type::HEADERS,
                qpk::encoder::encode_response_headers(valid_res.status_code, valid_res.headers));
            const std::string wire = res_headers_frame + reserved_frame;
            h3::response res;
            std::size_t consumed = 0;
            qpk::dynamic_table dt;
            const auto r = http3codec::parse_response(wire, res, consumed, dt);
            assert(r == http3codec::result::error);
        }

        // 5. parse_frame directly -> must return error
        {
            h3::frame_header hdr;
            std::string_view payload;
            std::size_t bytes_consumed = 0;
            const auto r = h3::parser::parse_frame(reserved_frame, hdr, payload, bytes_consumed);
            assert(r == h3::parser::result::error);
        }
    }

    // 6. Prohibited control stream frames on request stream (CANCEL_PUSH 0x03, GOAWAY 0x07, MAX_PUSH_ID 0x0d)
    for (const uint64_t ctrl_type : {0x03ULL, 0x07ULL, 0x0dULL}) {
        std::string ctrl_frame;
        quic::VarInt::encode(ctrl_type, ctrl_frame);
        quic::VarInt::encode(4, ctrl_frame);
        ctrl_frame.append("CTRL");

        const std::string wire = headers_frame + ctrl_frame;
        h3::request req;
        std::size_t consumed = 0;
        qpk::dynamic_table dt;
        const auto r = http3codec::parse_request(wire, req, consumed, dt);
        assert(r == http3codec::result::error);
    }

    // 7. Verify non-reserved unknown frames (e.g. 0x3f, 0x21 grease) are still ignored/skipped
    for (const uint64_t unknown_type : {0x3fULL, 0x21ULL}) {
        assert(!wavex::protos::http::http3::is_reserved_frame_type(unknown_type));

        std::string unk_frame;
        quic::VarInt::encode(unknown_type, unk_frame);
        quic::VarInt::encode(4, unk_frame);
        unk_frame.append("GRES");

        std::string data_frame = h3::encoder::encode_data_frame(valid_req.body);
        std::string wire = headers_frame + unk_frame + data_frame;

        h3::request req;
        std::size_t consumed = 0;
        qpk::dynamic_table dt;
        const auto r = http3codec::parse_request(wire, req, consumed, dt);
        assert(r == http3codec::result::success);
        assert(req.target == "/api/resource");
        assert(req.body == "valid-body");
    }

    std::cout << "  [PASS] C9: Rejection of HTTP/2 Reserved Frame Types verified.\n";
}

void test_http3_max_field_section_size_enforcement_c10() {
    std::cout << "[Test HTTP/3] C10: Enforcement & Configuration of MAX_FIELD_SECTION_SIZE (RFC 9114 §7.2.4.1)...\n";

    // 1. Build a valid request headers frame
    // Size calculation per RFC 9114 §7.2.4.1:
    // :method (7) + GET (3) + 32 = 42
    // :path (5) + /test (5) + 32 = 42
    // :scheme (7) + https (5) + 32 = 44
    // :authority (10) + wavex.local (11) + 32 = 53
    // Total section size = 42 + 42 + 44 + 53 = 181 bytes
    h3::request req;
    req.method_type = method::GET;
    req.target = "/test";
    req.scheme = "https";
    req.authority = "wavex.local";

    const std::string headers_payload = qpk::encoder::encode_request_headers(
        req.method_type, req.target, req.scheme, req.authority, req.headers);
    const std::string wire_headers = h3::encoder::encode_frame(frame_type::HEADERS, headers_payload);

    // 2. Direct QPACK decoder enforcement
    {
        qpk::dynamic_table dt;
        const qpk::decoder dec(dt);
        std::vector<std::pair<std::string, std::string>> out;
        bool is_blocked = false;

        // Limit 100 bytes (lower than 181 bytes) -> must fail
        const bool ok_small = dec.decode_header_block(headers_payload, out, is_blocked, 100);
        assert(!ok_small);

        // Limit 250 bytes (greater than 181 bytes) -> must succeed
        out.clear();
        const bool ok_large = dec.decode_header_block(headers_payload, out, is_blocked, 250);
        assert(ok_large);
        assert(out.size() == 4);
    }

    // 3. parse_request with explicit max_field_section_size
    {
        qpk::dynamic_table dt;
        h3::request parsed;
        std::size_t consumed = 0;

        // Limit 100 bytes -> rejected with error
        const auto r1 = http3codec::parse_request(wire_headers, parsed, consumed, dt, 100);
        assert(r1 == http3codec::result::error);

        // Limit 250 bytes -> succeeds
        consumed = 0;
        const auto r2 = http3codec::parse_request(wire_headers, parsed, consumed, dt, 250);
        assert(r2 == http3codec::result::success);
        assert(parsed.method_type == method::GET);
        assert(parsed.target == "/test");
    }

    // 4. parse_request with connection_context configuration
    {
        h3::connection_context ctx;
        ctx.max_field_section_size = 120; // smaller than 181

        h3::request parsed;
        std::size_t consumed = 0;
        const auto r_fail = http3codec::parse_request(wire_headers, parsed, consumed, ctx);
        assert(r_fail == http3codec::result::error);

        // Update context limit to 300
        ctx.max_field_section_size = 300;
        consumed = 0;
        const auto r_pass = http3codec::parse_request(wire_headers, parsed, consumed, ctx);
        assert(r_pass == http3codec::result::success);
    }

    // 5. Response headers enforcement
    {
        h3::response res;
        res.status_code = 200;
        res.headers.emplace_back("x-wavex-framework", "production-speed");
        // :status (7) + 200 (3) + 32 = 42
        // x-wavex-framework (17) + production-speed (16) + 32 = 65
        // Total = 107 bytes

        const std::string res_payload = qpk::encoder::encode_response_headers(res.status_code, res.headers);
        const std::string res_wire = h3::encoder::encode_frame(frame_type::HEADERS, res_payload);

        qpk::dynamic_table dt;
        h3::response parsed_res;
        std::size_t consumed = 0;

        // Limit 80 -> fail
        const auto r_fail = http3codec::parse_response(res_wire, parsed_res, consumed, dt, 80);
        assert(r_fail == http3codec::result::error);

        // Limit 150 -> pass
        consumed = 0;
        const auto r_pass = http3codec::parse_response(res_wire, parsed_res, consumed, dt, 150);
        assert(r_pass == http3codec::result::success);
        assert(parsed_res.status_code == 200);
    }

    // 6. QUIC connection and server instance configuration
    {
        asio::io_context io;
        quic::QuicServer srv(io, 0);
        assert(srv.max_field_section_size() == 65536);

        srv.set_max_field_section_size(32768);
        assert(srv.max_field_section_size() == 32768);

        const auto cid = quic::ConnectionId::random(8);
        const auto peer_cid = quic::ConnectionId::random(8);
        asio::ip::udp::endpoint ep(asio::ip::address_v4::loopback(), 4433);
        quic::QuicConnection conn(cid, peer_cid, ep, true, io.get_executor());

        assert(conn.max_field_section_size() == 65536);
        conn.set_max_field_section_size(16384);
        assert(conn.max_field_section_size() == 16384);
    }

    // 7. Global default configuration
    {
        const uint64_t original = http3codec::default_max_field_section_size();
        http3codec::set_default_max_field_section_size(123456);
        assert(http3codec::default_max_field_section_size() == 123456);
        http3codec::set_default_max_field_section_size(original);
        assert(http3codec::default_max_field_section_size() == original);
    }

    std::cout << "  [PASS] C10: MAX_FIELD_SECTION_SIZE enforcement & multi-layer configuration verified.\n";
}

int main() {
    std::cout << "=== Running WaveX HTTP/3 Codec Tests ===\n";
    try {
        test_http3_framing();
        test_http3codec_full_message_roundtrip();
        test_http3_over_quic_stream();
        test_http3_rfc9114_stream_rules();
        test_http3_unidirectional_control_and_qpack_streams();
        test_http3_server_acceptor_guard();
        test_http3_body_truncation_prevention_c1();
        test_http3_malformed_request_rejection_c8();
        test_http3_session_unidirectional_routing_c7();
        test_http3_resumable_parser_c2();
        test_http3_reserved_frame_types_c9();
        test_http3_max_field_section_size_enforcement_c10();
        std::cout << "=== All HTTP/3 Tests PASSED ===\n";
        return 0;
    } catch (const std::exception &ex) {
        std::cerr << "Exception in test_http3: " << ex.what() << "\n";
        return 1;
    }
}
