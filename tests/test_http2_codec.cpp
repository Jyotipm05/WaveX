/**
 * @file test_http2_codec.cpp
 * @brief Unit tests for HTTP/2 protocol codec (RFC 7540 / RFC 7541).
 */

#include <wavex/wavex.hpp>
#include <wavex/protos/http/http2codec.hpp>

#if defined(NO_ERROR)
#undef NO_ERROR
#endif

#include <iostream>
#include <string>
#include <string_view>
#include <vector>
#include <array>

namespace {
    int tests_run = 0;
    int tests_passed = 0;

    void check(const bool condition, const char *name) {
        ++tests_run;
        if (condition) {
            ++tests_passed;
            std::cout << "  [PASS] " << name << "\n";
        } else {
            std::cout << "  [FAIL] " << name << "\n";
        }
    }
}

namespace h2 = wavex::protos::http::http2;
using wavex::protos::http::method;
using wavex::protos::http::header;
using wavex::protos::http::Http2Request;
using wavex::protos::http::Http2Response;

// ─── Test 1: Frame Header Packing & Unpacking ─────────────────────────────────

void test_frame_header_codec() {
    std::cout << "\n[Test 1] HTTP/2 Frame Header Packing & Unpacking\n";

    h2::frame_header hdr;
    hdr.length = 16384;
    hdr.type = h2::frame_type::HEADERS;
    hdr.flags = h2::flags::END_HEADERS | h2::flags::END_STREAM;
    hdr.stream_id = 1337;

    std::array<uint8_t, h2::frame_header::HEADER_SIZE> bytes{};
    h2::pack_frame_header(hdr, bytes);

    check(bytes.size() == 9, "Header size is 9 octets");

    // Manual inspection of big-endian 24-bit length 16384 (0x004000)
    check(bytes[0] == 0x00 && bytes[1] == 0x40 && bytes[2] == 0x00, "Length packed big-endian");
    check(bytes[3] == 0x01, "Type is HEADERS (0x01)");
    check(bytes[4] == (h2::flags::END_HEADERS | h2::flags::END_STREAM), "Flags match");

    h2::frame_header unpacked;
    const std::string_view buf(reinterpret_cast<const char *>(bytes.data()), bytes.size());
    check(h2::unpack_frame_header(buf, unpacked), "Unpack succeeds");
    check(unpacked.length == 16384, "Unpacked length matches");
    check(unpacked.type == h2::frame_type::HEADERS, "Unpacked type matches");
    check(unpacked.flags == (h2::flags::END_HEADERS | h2::flags::END_STREAM), "Unpacked flags match");
    check(unpacked.stream_id == 1337, "Unpacked stream ID matches");
    check(unpacked.has_flag(h2::flags::END_HEADERS), "has_flag END_HEADERS");
    check(unpacked.has_flag(h2::flags::END_STREAM), "has_flag END_STREAM");
    check(!unpacked.has_flag(h2::flags::PADDED), "has_flag PADDED is false");
}

// ─── Test 2: HPACK Integer Encoding & Decoding ────────────────────────────────

void test_hpack_integer() {
    std::cout << "\n[Test 2] HPACK Variable-Length Integer Encoding & Decoding\n";

    // Test 1: 10 with 5-bit prefix (fits in prefix, max 31)
    std::string out1;
    h2::hpack::encode_integer(out1, 10, 5, 0x00);
    check(out1.size() == 1, "Small integer fits in 1 byte");

    std::size_t c1 = 0;
    uint64_t val1 = 0;
    check(h2::hpack::decode_integer(out1, c1, 5, val1), "Decode integer 10 succeeds");
    check(val1 == 10, "Decoded integer is 10");

    // Test 2: 1337 with 7-bit prefix
    std::string out2;
    h2::hpack::encode_integer(out2, 1337, 7, 0x80);
    check(out2.size() > 1, "Multi-byte integer spans continuation bytes");

    std::size_t c2 = 0;
    uint64_t val2 = 0;
    check(h2::hpack::decode_integer(out2, c2, 7, val2), "Decode integer 1337 succeeds");
    check(val2 == 1337, "Decoded integer is 1337");

    // Test 3: Large value 65535 with 4-bit prefix
    std::string out3;
    h2::hpack::encode_integer(out3, 65535, 4, 0x00);
    std::size_t c3 = 0;
    uint64_t val3 = 0;
    check(h2::hpack::decode_integer(out3, c3, 4, val3), "Decode large integer succeeds");
    check(val3 == 65535, "Decoded integer is 65535");
}

// ─── Test 3: HPACK String Encoding & Decoding ─────────────────────────────────

void test_hpack_string() {
    std::cout << "\n[Test 3] HPACK String Encoding & Decoding\n";

    // Raw string roundtrip
    std::string original = "application/json; charset=utf-8";
    std::string out;
    h2::hpack::encode_string(out, original);

    std::size_t cursor = 0;
    std::string decoded;
    check(h2::hpack::decode_string(out, cursor, decoded), "Decode raw string succeeds");
    check(decoded == original, "Decoded string matches original");

    // Test Huffman decoding against known RFC 7541 vector:
    // "www.example.com" in RFC 7541 Appendix C.4.1 is Huffman encoded as:
    // f1 e3 c2 e5 f2 3a 6b a0 ab 90 f4 ff
    constexpr std::string_view huff_vec = "\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff";
    std::string huff_decoded;
    check(h2::hpack::huffman::decode(huff_vec, huff_decoded), "Huffman vector decode succeeds");
    check(huff_decoded == "www.example.com", "Decoded Huffman vector is 'www.example.com'");
}

// ─── Test 4: HPACK Static Table Lookups ────────────────────────────────────────

void test_hpack_static_table() {
    std::cout << "\n[Test 4] HPACK Static Table Lookups\n";

    auto [idx_get, exact_get] = h2::hpack::find_static(":method", "GET");
    check(idx_get == 2 && exact_get, ":method: GET is static index 2");

    auto [idx_post, exact_post] = h2::hpack::find_static(":method", "POST");
    check(idx_post == 3 && exact_post, ":method: POST is static index 3");

    auto [idx_root, exact_root] = h2::hpack::find_static(":path", "/");
    check(idx_root == 4 && exact_root, ":path: / is static index 4");

    auto [idx_200, exact_200] = h2::hpack::find_static(":status", "200");
    check(idx_200 == 8 && exact_200, ":status: 200 is static index 8");

    auto [idx_404, exact_404] = h2::hpack::find_static(":status", "404");
    check(idx_404 == 13 && exact_404, ":status: 404 is static index 13");

    auto [idx_cl, exact_cl] = h2::hpack::find_static("content-length", "42");
    check(idx_cl == 28 && !exact_cl, "content-length name match index 28, not exact");
}

// ─── Test 5: Control Frames Serialization ─────────────────────────────────────

void test_control_frames() {
    std::cout << "\n[Test 5] HTTP/2 Control Frames Serialization\n";

    // SETTINGS frame
    std::vector<std::pair<h2::settings_parameter, uint32_t> > settings = {
        {h2::settings_parameter::MAX_CONCURRENT_STREAMS, 100},
        {h2::settings_parameter::INITIAL_WINDOW_SIZE, 65535}
    };
    std::string s_frame = h2::encoder::serialize_settings(settings);
    h2::frame_header s_hdr;
    std::string_view s_payload;
    std::size_t s_consumed = 0;
    check(h2::parser::parse_frame(s_frame, s_hdr, s_payload, s_consumed) == h2::parser::result::success,
          "Parse SETTINGS frame");
    check(s_hdr.type == h2::frame_type::SETTINGS, "Frame is SETTINGS");
    check(s_hdr.length == 12, "SETTINGS payload is 12 bytes (2 * 6)");
    check(s_hdr.stream_id == 0, "SETTINGS stream ID is 0");

    // SETTINGS ACK
    std::string s_ack = h2::encoder::serialize_settings_ack();
    h2::frame_header ack_hdr;
    std::string_view ack_payload;
    std::size_t ack_consumed = 0;
    check(h2::parser::parse_frame(s_ack, ack_hdr, ack_payload, ack_consumed) == h2::parser::result::success,
          "Parse SETTINGS ACK");
    check(ack_hdr.type == h2::frame_type::SETTINGS, "Frame is SETTINGS");
    check(ack_hdr.has_flag(h2::flags::ACK), "ACK flag set");
    check(ack_hdr.length == 0, "ACK payload is 0");

    // PING frame
    std::string ping_frame = h2::encoder::serialize_ping(0x1122334455667788ULL);
    h2::frame_header ping_hdr;
    std::string_view ping_payload;
    std::size_t ping_consumed = 0;
    check(h2::parser::parse_frame(ping_frame, ping_hdr, ping_payload, ping_consumed) == h2::parser::result::success,
          "Parse PING frame");
    check(ping_hdr.type == h2::frame_type::PING, "Frame is PING");
    check(ping_hdr.length == 8, "PING payload is 8 bytes");

    // WINDOW_UPDATE
    std::string wu_frame = h2::encoder::serialize_window_update(1, 32768);
    h2::frame_header wu_hdr;
    std::string_view wu_payload;
    std::size_t wu_consumed = 0;
    check(h2::parser::parse_frame(wu_frame, wu_hdr, wu_payload, wu_consumed) == h2::parser::result::success,
          "Parse WINDOW_UPDATE frame");
    check(wu_hdr.type == h2::frame_type::WINDOW_UPDATE, "Frame is WINDOW_UPDATE");
    check(wu_hdr.stream_id == 1, "Stream ID is 1");

    // GOAWAY
    std::string ga_frame = h2::encoder::serialize_goaway(5, h2::error_code::NO_ERROR, "Graceful Shutdown");
    h2::frame_header ga_hdr;
    std::string_view ga_payload;
    std::size_t ga_consumed = 0;
    check(h2::parser::parse_frame(ga_frame, ga_hdr, ga_payload, ga_consumed) == h2::parser::result::success,
          "Parse GOAWAY frame");
    check(ga_hdr.type == h2::frame_type::GOAWAY, "Frame is GOAWAY");
    check(ga_payload.size() == 8 + std::string("Graceful Shutdown").size(), "GOAWAY payload with debug data");
}

// ─── Test 6: Full Response Serialization & Parsing ────────────────────────────

void test_response_serialization_parsing() {
    std::cout << "\n[Test 6] Full Response Serialization & Parsing\n";

    h2::response res;
    res.status_code = 200;
    res.stream_id = 3;
    res.headers.push_back(header{"content-type", "application/json"});
    res.headers.push_back(header{"x-custom-wavex", "v2"});
    res.body = R"({"status":"ok","engine":"wavex-http2"})";

    std::string wire = h2::encoder::serialize(res);
    check(!wire.empty(), "Serialized response wire is non-empty");

    h2::response parsed_res;
    std::size_t consumed = 0;
    const auto res_result = h2::parser::parse_response(wire, parsed_res, consumed);

    check(res_result == h2::parser::result::success, "parse_response returned success");
    check(consumed == wire.size(), "Consumed all bytes of response wire");
    check(parsed_res.status_code == 200, "Parsed status code is 200");
    check(parsed_res.status_text == "OK", "Parsed status text is 'OK'");
    check(parsed_res.stream_id == 3, "Parsed stream ID is 3");
    check(parsed_res.body == res.body, "Parsed body matches original JSON payload");
    check(parsed_res.get_header("content-type").value_or("") == "application/json", "Header content-type matches");
    check(parsed_res.get_header("x-custom-wavex").value_or("") == "v2", "Header x-custom-wavex matches");
}

// ─── Test 7: Full Request Serialization & Parsing ─────────────────────────────

void test_request_serialization_parsing() {
    std::cout << "\n[Test 7] Full Request Serialization & Parsing\n";

    h2::request req;
    req.method_type = method::POST;
    req.target = "/api/v2/compute";
    req.scheme = "https";
    req.authority = "api.wavex.dev";
    req.stream_id = 1;
    req.headers.push_back(header{"authorization", "Bearer token-abc"});
    req.body = "request-payload-bytes";

    std::string wire = h2::encoder::serialize_request(req);
    check(!wire.empty(), "Serialized request wire is non-empty");

    h2::request parsed_req;
    std::size_t consumed = 0;
    const auto req_result = h2::parser::parse_request(wire, parsed_req, consumed);

    check(req_result == h2::parser::result::success, "parse_request returned success");
    check(consumed == wire.size(), "Consumed all bytes of request wire");
    check(parsed_req.method_type == method::POST, "Parsed method is POST");
    check(parsed_req.target == "/api/v2/compute", "Parsed target is /api/v2/compute");
    check(parsed_req.scheme == "https", "Parsed scheme is https");
    check(parsed_req.authority == "api.wavex.dev", "Parsed authority matches");
    check(parsed_req.stream_id == 1, "Parsed stream ID is 1");
    check(parsed_req.body == "request-payload-bytes", "Parsed body matches");
    check(parsed_req.get_header("authorization").value_or("") == "Bearer token-abc", "Authorization header matches");
}

// ─── Test 8: Client Connection Preface & Multi-Frame Flow ─────────────────────

void test_client_preface_parsing() {
    std::cout << "\n[Test 8] Client Connection Preface & Multi-Frame Stream\n";

    h2::request req;
    req.method_type = method::GET;
    req.target = "/health";
    req.scheme = "https";
    req.authority = "localhost:8443";
    req.stream_id = 1;

    // Simulate real browser/client connection: PREFACE + SETTINGS + HEADERS
    std::string wire;
    wire.append(h2::CONNECTION_PREFACE);
    wire.append(h2::encoder::serialize_settings({{h2::settings_parameter::INITIAL_WINDOW_SIZE, 65535}}));
    wire.append(h2::encoder::serialize_request(req));

    h2::request parsed_req;
    std::size_t consumed = 0;
    const auto r = h2::parser::parse_request(wire, parsed_req, consumed);

    check(r == h2::parser::result::success, "parse_request with connection preface succeeds");
    check(consumed == wire.size(), "Consumed entire client preface and frames");
    check(parsed_req.method_type == method::GET, "Method GET identified");
    check(parsed_req.target == "/health", "Target /health identified");
}

// ─── Test 9: Integration with HttpRequest<http2codec> & HttpResponse<http2codec> ───

void test_http2_request_response_types() {
    std::cout << "\n[Test 9] Integration with HttpRequest<http2codec> & HttpResponse<http2codec>\n";

    // Verify HttpRequest<http2codec> alias
    Http2Request req;
    check(req.raw().version_major == 2, "Http2Request default version is HTTP/2");

    // Verify HttpResponse<http2codec> fluent builder API
    Http2Response res;
    res.status(404).set("Content-Type", "text/plain");
    check(res.status_code() == 404, "Http2Response status code is 404");
    check(res.status_text() == "Not Found", "Http2Response status text is 'Not Found'");

    res.send_impl("Resource Not Found");
    check(res.is_sent(), "Response marked as sent");

    std::string wire = res.serialize_impl();
    check(!wire.empty(), "Serialized wire is valid HTTP/2 binary frame");

    h2::response parsed_res;
    std::size_t consumed = 0;
    const auto r = h2::parser::parse_response(wire, parsed_res, consumed);
    check(r == h2::parser::result::success, "Parse serialized Http2Response wire");
    check(parsed_res.status_code == 404, "Status code preserved as 404");
    check(parsed_res.body == "Resource Not Found", "Body preserved through serialize_impl");
}

// ─── Test 10: Symmetrical Developer-Friendly API Facade (http1codec vs http2codec) ───

void test_symmetrical_codec_api() {
    std::cout << "\n[Test 10] Symmetrical Developer-Friendly API Facade (http1codec & http2codec)\n";

    using wavex::protos::http::http1codec;
    using wavex::protos::http::http2codec;

    // 1. Symmetrical Request Serialization & Parsing via Facade
    http1codec::request req1;
    req1.method_type = method::GET;
    req1.target = "/api/v1/users";
    req1.headers.emplace_back("Accept", "application/json");
    const std::string wire1 = http1codec::serialize_request(req1);
    check(!wire1.empty(), "http1codec::serialize_request produced wire");

    http1codec::request out1;
    std::size_t consumed1 = 0;
    const auto r1 = http1codec::parse_request(wire1, out1, consumed1);
    check(r1 == http1codec::result::success, "http1codec::parse_request succeeded via facade");
    check(out1.target == "/api/v1/users", "http1codec request target preserved");

    http2codec::request req2;
    req2.method_type = method::GET;
    req2.target = "/api/v1/users";
    req2.stream_id = 7;
    req2.headers.emplace_back("accept", "application/json");
    const std::string wire2 = http2codec::serialize_request(req2);
    check(!wire2.empty(), "http2codec::serialize_request produced wire");

    http2codec::request out2;
    std::size_t consumed2 = 0;
    const auto r2 = http2codec::parse_request(wire2, out2, consumed2);
    check(r2 == http2codec::result::success, "http2codec::parse_request succeeded via facade");
    check(out2.target == "/api/v1/users", "http2codec request target preserved");
    check(out2.stream_id == 7, "http2codec stream_id preserved");

    // 2. Symmetrical Response Serialization & Parsing via Facade
    http1codec::response res1;
    res1.status_code = 200;
    res1.body = R"({"status":"ok"})";
    const std::string wire_res1 = http1codec::serialize(res1);
    http1codec::response out_res1;
    std::size_t c_res1 = 0;
    check(http1codec::parse_response(wire_res1, out_res1, c_res1) == http1codec::result::success,
          "http1codec::parse_response succeeded via facade");
    check(out_res1.body == R"({"status":"ok"})", "http1codec response body matches");

    http2codec::response res2;
    res2.status_code = 200;
    res2.stream_id = 5;
    res2.body = R"({"status":"ok"})";
    const std::string wire_res2 = http2codec::serialize(res2);
    http2codec::response out_res2;
    std::size_t c_res2 = 0;
    check(http2codec::parse_response(wire_res2, out_res2, c_res2) == http2codec::result::success,
          "http2codec::parse_response succeeded via facade");
    check(out_res2.body == R"({"status":"ok"})", "http2codec response body matches");
    check(out_res2.stream_id == 5, "http2codec response stream_id matches");

    // 3. Symmetrical Streaming Chunking Helpers
    const std::string chunk1 = http1codec::format_chunk("data-payload");
    const std::string chunk2 = http2codec::format_chunk("data-payload");
    check(!chunk1.empty() && chunk1.find("data-payload") != std::string::npos, "http1codec::format_chunk");
    check(!chunk2.empty() && chunk2.find("data-payload") != std::string::npos, "http2codec::format_chunk");

    constexpr auto term1 = http1codec::format_terminal_chunk();
    constexpr auto term2 = http2codec::format_terminal_chunk();
    check(term1 == "0\r\n\r\n", "http1codec::format_terminal_chunk");
    check(term2.size() == 9, "http2codec::format_terminal_chunk 9-octet frame");
    check(http1codec::format_chunk("") == term1, "http1codec::format_chunk(\"\") delegates to format_terminal_chunk");
    check(http2codec::format_chunk("") == term2, "http2codec::format_chunk(\"\") delegates to format_terminal_chunk");

    std::string buf1;
    http1codec::format_chunk_to(buf1, "data-payload");
    check(buf1 == chunk1, "http1codec::format_chunk_to matches format_chunk");
    std::string buf2;
    http2codec::format_chunk_to(buf2, "data-payload");
    check(buf2 == chunk2, "http2codec::format_chunk_to matches format_chunk");

    // 4. Codec-Templated Generic Functions in wavex::protos::http
    const std::string gen1 = wavex::protos::http::serialize_request<http1codec>(req1);
    const std::string gen2 = wavex::protos::http::serialize_request<http2codec>(req2);
    check(!gen1.empty() && !gen2.empty(), "Generic wavex::protos::http::serialize_request<Codec>");

    // 5. Multiplexed Stream ID support in HttpRequest & HttpResponse
    Http2Request h2_req;
    h2_req.stream_id(42);
    check(h2_req.stream_id() == 42, "Http2Request stream_id getter/setter");

    Http2Response h2_res;
    h2_res.stream_id(42);
    check(h2_res.stream_id() == 42, "Http2Response stream_id getter/setter");
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main() {
    std::cout << "========================================================\n";
    std::cout << " WaveX HTTP/2 Protocol Codec Unit Tests (RFC 7540/7541)\n";
    std::cout << "========================================================\n";

    test_frame_header_codec();
    test_hpack_integer();
    test_hpack_string();
    test_hpack_static_table();
    test_control_frames();
    test_response_serialization_parsing();
    test_request_serialization_parsing();
    test_client_preface_parsing();
    test_http2_request_response_types();
    test_symmetrical_codec_api();

    std::cout << "\n--------------------------------------------------------\n";
    std::cout << "Tests Summary: " << tests_passed << " / " << tests_run << " passed.\n";
    std::cout << "--------------------------------------------------------\n";

    return (tests_passed == tests_run) ? 0 : 1;
}
