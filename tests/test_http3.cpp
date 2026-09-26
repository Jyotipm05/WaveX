// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file test_http3.cpp
 * @brief Unit and integration tests for WaveX HTTP/3 Binary Framing and QPACK Codec.
 */

#include <iostream>
#include <cassert>
#include <string>
#include <vector>

#include <wavex/protos/http/http3codec.hpp>
#include <wavex/protos/http/http.hpp>
#include <wavex/Network/QUIC.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>

// DO NOT add `using namespace wavex::protos::http` here: it imports http1codec's
// `encoder` and `parser` which are ambiguous with http3's encoder/parser.
namespace h3   = wavex::protos::http::http3;
namespace qpk  = wavex::protos::http::http3::qpack;
namespace quic = wavex::network::quic;

// Pull in only non-clashing names from the http namespace
using wavex::protos::http::header;
using wavex::protos::http::method;
using wavex::protos::http::http3codec;

// Bring h3 types into scope directly
using h3::frame_header;
using h3::frame_type;
using h3::settings_parameter;

void test_qpack_static_table() {
    std::cout << "[Test HTTP/3] QPACK Static Table lookup...\n";

    // 1. Exact match for :method GET -> index 17
    auto [idx_get, exact_get] = qpk::find_static(":method", "GET");
    assert(exact_get);
    assert(idx_get == 17);

    // 2. Exact match for :path / -> index 1
    auto [idx_path, exact_path] = qpk::find_static(":path", "/");
    assert(exact_path);
    assert(idx_path == 1);

    // 3. Exact match for :scheme https -> index 23
    auto [idx_scheme, exact_scheme] = qpk::find_static(":scheme", "https");
    assert(exact_scheme);
    assert(idx_scheme == 23);

    // 4. Exact match for :status 200 -> index 25
    auto [idx_status, exact_status] = qpk::find_static(":status", "200");
    assert(exact_status);
    assert(idx_status == 25);

    // 5. Name match with custom value
    auto [idx_name, exact_name] = qpk::find_static(":path", "/custom/endpoint");
    assert(!exact_name);
    assert(idx_name == 1);

    std::cout << "  [PASS] QPACK Static Table lookup passed.\n";
}

void test_qpack_dynamic_table() {
    std::cout << "[Test HTTP/3] QPACK Dynamic Table insertion and eviction...\n";

    qpk::dynamic_table dt(120); // Small capacity: ~2 entries
    assert(dt.size() == 0);

    dt.insert("x-custom-1", "value-1");
    assert(dt.size() == 1);
    assert(dt.get(0) != nullptr);
    assert(dt.get(0)->name == "x-custom-1");
    assert(dt.get(0)->value == "value-1");

    dt.insert("x-custom-2", "value-2");
    assert(dt.size() == 2);
    assert(dt.get(0)->name == "x-custom-2"); // Newest at 0
    assert(dt.get(1)->name == "x-custom-1");

    // Insert 3rd entry which triggers eviction of oldest
    dt.insert("x-custom-3", "value-3-longer");
    assert(dt.get(0)->name == "x-custom-3");

    std::cout << "  [PASS] QPACK Dynamic Table insertion and eviction passed.\n";
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
    // get_header() is inherited from message_base; returns std::optional<string_view>
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

int main() {
    std::cout << "=== Running WaveX HTTP/3 Codec Tests ===\n";
    try {
        test_qpack_static_table();
        test_qpack_dynamic_table();
        test_qpack_encode_decode();
        test_http3_framing();
        test_http3codec_full_message_roundtrip();
        test_http3_over_quic_stream();
        test_http3_rfc9114_stream_rules();
        std::cout << "=== All HTTP/3 Tests PASSED ===\n";
        return 0;
    } catch (const std::exception &ex) {
        std::cerr << "Exception in test_http3: " << ex.what() << "\n";
        return 1;
    }
}
