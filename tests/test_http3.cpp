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

namespace h3   = wavex::protos::http::http3;
namespace qpk  = wavex::protos::http::http3::qpack;
namespace quic = wavex::network::quic;

using wavex::protos::http::header;
using wavex::protos::http::method;
using wavex::protos::http::http3codec;

using h3::frame_header;
using h3::frame_type;
using h3::settings_parameter;

void test_qpack_static_table() {
    std::cout << "[Test HTTP/3] QPACK Static Table lookup (RFC 9204 Appendix A)...\n";

    // 1. Exact matches for pseudo-headers
    auto [idx_meth, exact_meth] = qpk::find_static(":method", "GET");
    assert(exact_meth);
    assert(idx_meth == 17);

    auto [idx_post, exact_post] = qpk::find_static(":method", "POST");
    assert(exact_post);
    assert(idx_post == 20);

    auto [idx_path, exact_path] = qpk::find_static(":path", "/");
    assert(exact_path);
    assert(idx_path == 1);

    auto [idx_scheme, exact_scheme] = qpk::find_static(":scheme", "https");
    assert(exact_scheme);
    assert(idx_scheme == 23);

    auto [idx_status, exact_status] = qpk::find_static(":status", "200");
    assert(exact_status);
    assert(idx_status == 25);

    // 2. Name-only matches with custom values
    auto [idx_name, exact_name] = qpk::find_static(":path", "/custom/api/v2");
    assert(!exact_name);
    assert(idx_name == 1);

    auto [idx_auth, exact_auth] = qpk::find_static(":authority", "wavex.internal");
    assert(!exact_auth);
    assert(idx_auth == 0);

    std::cout << "  [PASS] QPACK Static Table lookup passed.\n";
}

void test_qpack_dynamic_table() {
    std::cout << "[Test HTTP/3] QPACK Dynamic Table FIFO eviction and indexing...\n";

    qpk::dynamic_table dt(120); // Small capacity (~2 entries)
    assert(dt.count() == 0);
    assert(dt.total_inserts() == 0);

    // 1. First insert
    uint64_t idx1 = dt.insert("x-custom-1", "value-1");
    assert(idx1 == 0);
    assert(dt.count() == 1);
    assert(dt.total_inserts() == 1);
    assert(dt.get_by_absolute_index(0) != nullptr);
    assert(dt.get_by_absolute_index(0)->name == "x-custom-1");
    assert(dt.get_by_absolute_index(0)->value == "value-1");

    // 2. Second insert
    uint64_t idx2 = dt.insert("x-custom-2", "value-2");
    assert(idx2 == 1);
    assert(dt.count() == 2);
    assert(dt.total_inserts() == 2);

    // 3. Third insert triggers eviction of oldest entry (index 0)
    uint64_t idx3 = dt.insert("x-custom-3", "value-3-longer-than-others");
    assert(idx3 == 2);
    assert(dt.total_inserts() == 3);
    assert(dt.get_by_absolute_index(0) == nullptr); // Evicted!
    assert(dt.get_by_absolute_index(2) != nullptr);
    assert(dt.get_by_absolute_index(2)->name == "x-custom-3");

    std::cout << "  [PASS] QPACK Dynamic Table FIFO eviction passed.\n";
}

void test_qpack_dynamic_table_reentrancy_and_ric() {
    std::cout << "[Test HTTP/3] QPACK Dynamic Table Re-entrancy & Required Insert Count (RIC)...\n";

    qpk::dynamic_table dt(4096);

    // Step 1: Insert initial entries into dynamic table
    dt.insert("x-env", "production");   // Absolute index 0
    dt.insert("x-tenant", "tenant-42");  // Absolute index 1
    assert(dt.total_inserts() == 2);

    // Step 2: Encode a header block referencing both entries
    std::vector<header> req1_headers = {
        {"x-env", "production"},
        {"x-tenant", "tenant-42"}
    };

    std::string block1 = qpk::encoder::encode_request_headers(
        method::GET, "/orders", "https", "api.wavex.dev", req1_headers, &dt);

    // Step 3: Mutate the dynamic table with NEW inserts (simulating interleaved request stream reads)
    // In HPACK, this would shift 1-based relative indices and corrupt in-flight reads!
    // In QPACK, block1 uses Base = 2 and relative indices against Base, so future inserts MUST NOT corrupt block1!
    dt.insert("x-trace-id", "trace-999"); // Absolute index 2
    dt.insert("x-user-role", "admin");    // Absolute index 3
    assert(dt.total_inserts() == 4);

    // Step 4: Decode block1 now, AFTER the table has been mutated with 2 more entries
    qpk::decoder dec(dt);
    std::vector<std::pair<std::string, std::string>> decoded1;
    bool is_blocked = false;
    bool ok1 = dec.decode_header_block(block1, decoded1, is_blocked);
    assert(ok1);
    assert(!is_blocked);

    bool has_env = false, has_tenant = false;
    for (const auto &[n, v] : decoded1) {
        if (n == "x-env" && v == "production") has_env = true;
        if (n == "x-tenant" && v == "tenant-42") has_tenant = true;
    }
    assert(has_env);
    assert(has_tenant);

    // Step 5: Test Required Insert Count (RIC) Blocking Behavior
    // Create a new decoder with an empty dynamic table
    qpk::dynamic_table empty_dt(4096);
    qpk::decoder blocked_dec(empty_dt);

    std::vector<std::pair<std::string, std::string>> blocked_headers;
    bool blocked_flag = false;
    bool blocked_res = blocked_dec.decode_header_block(block1, blocked_headers, blocked_flag);

    // Must be blocked because empty_dt.total_inserts() (0) < block1's RIC (2)
    assert(!blocked_res);
    assert(blocked_flag);

    // Now push the required entries into empty_dt
    empty_dt.insert("x-env", "production");
    empty_dt.insert("x-tenant", "tenant-42");
    assert(empty_dt.total_inserts() == 2);

    // Now decoding must succeed without blocking!
    std::vector<std::pair<std::string, std::string>> unblocked_headers;
    bool unblocked_flag = false;
    bool unblocked_res = blocked_dec.decode_header_block(block1, unblocked_headers, unblocked_flag);
    assert(unblocked_res);
    assert(!unblocked_flag);

    std::cout << "  [PASS] QPACK Dynamic Table Re-entrancy & RIC verification passed.\n";
}

void test_qpack_encoder_decoder_streams() {
    std::cout << "[Test HTTP/3] QPACK Encoder and Decoder Sub-stream Instructions (RFC 9204 §4.3 & §4.4)...\n";

    qpk::dynamic_table dt(4096);
    qpk::decoder dec(dt);

    // 1. Encoder Instruction: Set Dynamic Table Capacity (001xxxxx)
    std::string stream_buf;
    qpk::encoder::encode_set_capacity(stream_buf, 2048);

    std::size_t cursor = 0;
    bool ok_cap = dec.apply_encoder_instruction(stream_buf, cursor);
    assert(ok_cap);
    assert(dt.max_capacity() == 2048);
    assert(cursor == stream_buf.size());

    // 2. Encoder Instruction: Insert with Literal Name (01Hxxxxx)
    stream_buf.clear();
    cursor = 0;
    qpk::encoder::encode_insert_with_literal_name(stream_buf, "x-app-name", "WaveX-Http3");
    bool ok_ins_lit = dec.apply_encoder_instruction(stream_buf, cursor);
    assert(ok_ins_lit);
    assert(dt.count() == 1);
    assert(dt.get_by_absolute_index(0)->name == "x-app-name");
    assert(dt.get_by_absolute_index(0)->value == "WaveX-Http3");

    // 3. Encoder Instruction: Insert with Name Reference (1Txxxxxx)
    // Refers to static table index 46 ("content-type")
    stream_buf.clear();
    cursor = 0;
    qpk::encoder::encode_insert_with_name_ref(stream_buf, 46, true, "application/xml");
    bool ok_ins_ref = dec.apply_encoder_instruction(stream_buf, cursor);
    assert(ok_ins_ref);
    assert(dt.count() == 2);
    assert(dt.get_by_absolute_index(1)->name == "content-type");
    assert(dt.get_by_absolute_index(1)->value == "application/xml");

    // 4. Decoder Instructions (RFC 9204 §4.4)
    std::string dec_stream;
    qpk::encoder::encode_section_ack(dec_stream, 4);            // Section Ack for Stream 4
    qpk::encoder::encode_stream_cancel(dec_stream, 8);          // Stream Cancel for Stream 8
    qpk::encoder::encode_insert_count_increment(dec_stream, 2); // Insert Count Increment +2

    assert(!dec_stream.empty());

    std::cout << "  [PASS] QPACK Encoder and Decoder Sub-stream Instructions passed.\n";
}

void test_qpack_encode_decode() {
    std::cout << "[Test HTTP/3] QPACK Header encode and decode roundtrip...\n";

    std::vector<header> headers = {
        {"content-type", "application/json"},
        {"x-wavex-version", "3.0.0"},
        {"accept", "*/*"}
    };

    // 1. Request headers encode
    std::string encoded_req = qpk::encoder::encode_request_headers(
        method::POST,
        "/api/v1/orders",
        "https",
        "wavex.dev",
        headers
    );
    assert(!encoded_req.empty());

    // 2. Request headers decode
    qpk::dynamic_table dt;
    qpk::decoder dec(dt);
    std::vector<std::pair<std::string, std::string>> decoded_headers;
    bool ok = dec.decode_header_block(encoded_req, decoded_headers);
    assert(ok);

    bool has_method = false, has_path = false, has_scheme = false, has_auth = false, has_custom = false;
    for (const auto &[n, v] : decoded_headers) {
        if (n == ":method" && v == "POST") has_method = true;
        if (n == ":path" && v == "/api/v1/orders") has_path = true;
        if (n == ":scheme" && v == "https") has_scheme = true;
        if (n == ":authority" && v == "wavex.dev") has_auth = true;
        if (n == "x-wavex-version" && v == "3.0.0") has_custom = true;
    }

    assert(has_method);
    assert(has_path);
    assert(has_scheme);
    assert(has_auth);
    assert(has_custom);

    // 3. Response headers encode and decode
    std::string encoded_res = qpk::encoder::encode_response_headers(200, headers);
    std::vector<std::pair<std::string, std::string>> decoded_res_headers;
    bool res_ok = dec.decode_header_block(encoded_res, decoded_res_headers);
    assert(res_ok);

    bool has_status = false;
    for (const auto &[n, v] : decoded_res_headers) {
        if (n == ":status" && v == "200") has_status = true;
    }
    assert(has_status);

    std::cout << "  [PASS] QPACK encode and decode roundtrip passed.\n";
}

void test_http3_framing() {
    std::cout << "[Test HTTP/3] HTTP/3 Binary Framing (RFC 9114)...\n";

    // 1. DATA frame
    const std::string payload = "HTTP/3 Wire Payload Body Data!";
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
    std::vector<std::pair<settings_parameter, uint64_t>> settings = {
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
    std::string server_buf;
    server_buf.resize(4096);
    std::error_code ec;
    std::size_t n = server_stream->read_some(asio::buffer(server_buf), ec);
    assert(n > 0);
    server_buf.resize(n);

    std::size_t consumed = 0;
    qpk::dynamic_table server_dt;
    auto srv_parse_res = http3codec::parse_request(server_buf, server_received_req, consumed, server_dt);
    assert(srv_parse_res == http3codec::result::success);
    assert(server_received_req.method_type == method::GET);
    assert(server_received_req.target == "/healthcheck");

    // 3. Server generates HTTP/3 response and pushes to client
    h3::response s_res;
    s_res.status_code = 200;
    s_res.headers.emplace_back("content-type", "text/plain");
    s_res.body = "OK";
    std::string wire_resp = http3codec::serialize(s_res);

    client_stream->push_inbound(wire_resp, true);

    // 4. Client reads and parses HTTP/3 response
    std::string client_buf;
    client_buf.resize(4096);
    std::size_t cn = client_stream->read_some(asio::buffer(client_buf), ec);
    assert(cn > 0);
    client_buf.resize(cn);

    h3::response client_received_res;
    std::size_t c_consumed = 0;
    qpk::dynamic_table client_dt;
    auto c_parse_res = http3codec::parse_response(client_buf, client_received_res, c_consumed, client_dt);
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
        qpk::encoder::encode_request_headers(valid_req.method_type, valid_req.target, valid_req.scheme, valid_req.authority, valid_req.headers));

    // Inject unknown frame type 0x3f (decimal 63)
    std::string unknown_frame;
    quic::VarInt::encode(0x3f, unknown_frame);
    quic::VarInt::encode(4, unknown_frame);
    unknown_frame.append("WAVX");

    std::string data_frame = h3::encoder::encode_data_frame(valid_req.body);

    std::string wire_with_unknown = headers_frame + unknown_frame + data_frame;
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
    assert(!h3_server.is_acceptor_open());
    assert(h3_server.is_http3_enabled());

    h3_server.allow_insecure();
    std::thread h3_thread([&h3_server]() {
        h3_server.run();
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    assert(!h3_server.is_acceptor_open());

    // Attempting a plain-TCP connection to the HTTP/3 port MUST be cleanly rejected
    // by the OS kernel (Connection Refused / TCP RST), NEVER accepted and mis-parsed
    {
        asio::io_context client_io;
        asio::ip::tcp::socket tcp_sock(client_io);
        asio::error_code ec;
        tcp_sock.connect(asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), 19983), ec);
        assert(ec); // TCP connection must fail/be refused!
    }

    h3_server.stop();
    if (h3_thread.joinable()) {
        h3_thread.join();
    }

    // 3. ComposedHttpServer: opens TCP acceptor for HTTP/2 + HTTP/1.1 and QUIC for HTTP/3
    wavex::server::ComposedHttpServer comp_server("127.0.0.1", 19984);
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

    comp_server.stop();
    if (comp_thread.joinable()) {
        comp_thread.join();
    }

    std::cout << "  [PASS] Server TCP Acceptor Guard & Composition tests passed.\n";
}

int main() {
    std::cout << "=== Running WaveX HTTP/3 Codec Tests ===\n";
    try {
        test_qpack_static_table();
        test_qpack_dynamic_table();
        test_qpack_dynamic_table_reentrancy_and_ric();
        test_qpack_encoder_decoder_streams();
        test_qpack_encode_decode();
        test_http3_framing();
        test_http3codec_full_message_roundtrip();
        test_http3_over_quic_stream();
        test_http3_rfc9114_stream_rules();
        test_http3_server_acceptor_guard();
        std::cout << "=== All HTTP/3 Tests PASSED ===\n";
        return 0;
    } catch (const std::exception &ex) {
        std::cerr << "Exception in test_http3: " << ex.what() << "\n";
        return 1;
    }
}
