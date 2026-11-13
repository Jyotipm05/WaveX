// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file test_qpack.cpp
 * @brief Comprehensive Unit Tests for WaveX QPACK Engine (RFC 9204).
 */

#include <iostream>
#include <cassert>
#include <string>
#include <vector>

#include <wavex/protos/http/http3codec.hpp>
#include <wavex/protos/http/http.hpp>

namespace h3 = wavex::protos::http::http3;
namespace h2 = wavex::protos::http::http2;
namespace qpk = wavex::protos::http::http3::qpack;

using wavex::protos::http::header;
using wavex::protos::http::method;
using wavex::protos::http::http3codec;

void test_qpack_static_table() {
    std::cout << "[Test QPACK] Static Table lookup (RFC 9204 Appendix A)...\n";

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

    std::cout << "  [PASS] Static Table lookup passed.\n";
}

void test_qpack_dynamic_table() {
    std::cout << "[Test QPACK] Dynamic Table FIFO eviction and indexing...\n";

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

    std::cout << "  [PASS] Dynamic Table FIFO eviction passed.\n";
}

void test_qpack_dynamic_table_reentrancy_and_ric() {
    std::cout << "[Test QPACK] Dynamic Table Re-entrancy & Required Insert Count (RIC)...\n";

    qpk::dynamic_table dt(4096);

    // Step 1: Insert initial entries into dynamic table
    dt.insert("x-env", "production"); // Absolute index 0
    dt.insert("x-tenant", "tenant-42"); // Absolute index 1
    assert(dt.total_inserts() == 2);

    // Step 2: Encode a header block referencing both entries
    const std::vector<header> req1_headers = {
        {"x-env", "production"},
        {"x-tenant", "tenant-42"}
    };

    std::string block1 = qpk::encoder::encode_request_headers(
        method::GET, "/orders", "https", "api.wavex.dev", req1_headers, &dt);

    // Step 3: Mutate the dynamic table with NEW inserts (simulating interleaved request stream reads)
    // In HPACK, this would shift 1-based relative indices and corrupt in-flight reads!
    // In QPACK, block1 uses Base = 2 and relative indices against Base, so future inserts MUST NOT corrupt block1!
    dt.insert("x-trace-id", "trace-999"); // Absolute index 2
    dt.insert("x-user-role", "admin"); // Absolute index 3
    assert(dt.total_inserts() == 4);

    // Step 4: Decode block1 now, AFTER the table has been mutated with 2 more entries
    qpk::decoder dec(dt);
    std::vector<std::pair<std::string, std::string> > decoded1;
    decoded1.reserve(4);
    bool is_blocked = false;
    bool ok1 = dec.decode_header_block(block1, decoded1, is_blocked);
    assert(ok1);
    assert(!is_blocked);

    bool has_env = false, has_tenant = false;
    for (const auto &[n, v]: decoded1) {
        if (n == "x-env" && v == "production") has_env = true;
        if (n == "x-tenant" && v == "tenant-42") has_tenant = true;
    }
    assert(has_env);
    assert(has_tenant);

    // Step 5: Test Required Insert Count (RIC) Blocking Behavior
    // Create a new decoder with an empty dynamic table
    qpk::dynamic_table empty_dt(4096);
    qpk::decoder blocked_dec(empty_dt);

    std::vector<std::pair<std::string, std::string> > blocked_headers;
    blocked_headers.reserve(4);
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
    std::vector<std::pair<std::string, std::string> > unblocked_headers;
    unblocked_headers.reserve(4);
    bool unblocked_flag = false;
    bool unblocked_res = blocked_dec.decode_header_block(block1, unblocked_headers, unblocked_flag);
    assert(unblocked_res);
    assert(!unblocked_flag);

    std::cout << "  [PASS] Dynamic Table Re-entrancy & RIC verification passed.\n";
}

void test_qpack_encoder_decoder_streams() {
    std::cout << "[Test QPACK] Encoder and Decoder Sub-stream Instructions (RFC 9204 §4.3 & §4.4)...\n";

    qpk::dynamic_table dt(4096);
    qpk::decoder dec(dt);

    // 1. Encoder Instruction: Set Dynamic Table Capacity (001xxxxx)
    std::string stream_buf;
    stream_buf.reserve(128);
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
    dec_stream.reserve(64);
    qpk::encoder::encode_section_ack(dec_stream, 4); // Section Ack for Stream 4
    qpk::encoder::encode_stream_cancel(dec_stream, 8); // Stream Cancel for Stream 8
    qpk::encoder::encode_insert_count_increment(dec_stream, 2); // Insert Count Increment +2

    assert(!dec_stream.empty());

    std::cout << "  [PASS] Encoder and Decoder Sub-stream Instructions passed.\n";
}

void test_qpack_encode_decode() {
    std::cout << "[Test QPACK] Header encode and decode roundtrip...\n";

    const std::vector<header> headers = {
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
    std::vector<std::pair<std::string, std::string> > decoded_headers;
    decoded_headers.reserve(8);
    bool ok = dec.decode_header_block(encoded_req, decoded_headers);
    assert(ok);

    bool has_method = false, has_path = false, has_scheme = false, has_auth = false, has_custom = false;
    for (const auto &[n, v]: decoded_headers) {
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
    std::vector<std::pair<std::string, std::string> > decoded_res_headers;
    decoded_res_headers.reserve(4);
    bool res_ok = dec.decode_header_block(encoded_res, decoded_res_headers);
    assert(res_ok);

    bool has_status = false;
    for (const auto &[n, v]: decoded_res_headers) {
        if (n == ":status" && v == "200") has_status = true;
    }
    assert(has_status);

    std::cout << "  [PASS] Header encode and decode roundtrip passed.\n";
}

void test_qpack_huffman_literal_names_c5() {
    std::cout << "[Test QPACK] C5: Huffman-encoded literal names decoding...\n";

    // RFC 7541 C.4.1: "custom-key" Huffman-encoded is 8 bytes: 25 a8 49 e9 5b 18 b4 7f
    std::string fields;
    fields.push_back('\0'); // RIC = 0
    fields.push_back('\0'); // Base = 0

    // Add :method GET (static 17), :scheme https (static 23, required by RFC 9114 §4.3.1) and :path / (static 1)
    qpk::encoder::encode_indexed_static(fields, 17);
    qpk::encoder::encode_indexed_static(fields, 23);
    qpk::encoder::encode_indexed_static(fields, 1);

    // Literal Field Line with Literal Name (001 N H Name_Len(3+))
    // RFC 7541 vector: "www.example.com" (12 bytes) -> \xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff
    // N=0, H=1 -> prefix byte = 0x28 | 7 = 0x2f, next byte = 12 - 7 = 5
    fields.push_back(static_cast<char>(0x2f));
    fields.push_back(static_cast<char>(0x05));
    const char huff_name[] = "\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff";
    fields.append(huff_name, 12);

    // Value string: H=0, length 6: "custom"
    fields.push_back(static_cast<char>(6));
    fields.append("custom");

    std::string frame = h3::encoder::encode_frame(h3::frame_type::HEADERS, fields);
    h3::request req;
    std::size_t consumed = 0;
    qpk::dynamic_table dt;
    auto res = http3codec::parse_request(frame, req, consumed, dt);
    assert(res == http3codec::result::success);
    assert(req.target == "/");
    assert(req.method_type == method::GET);
    assert(req.headers_storage.size() == 1);
    assert(req.headers_storage[0].first == "www.example.com");
    assert(req.headers_storage[0].second == "custom");

    std::cout << "  [PASS] C5: Huffman literal names decoded successfully.\n";
}

void test_qpack_required_insert_count_c3() {
    std::cout << "[Test QPACK] C3: RFC 9204 §4.5.1.1 Required Insert Count decoding...\n";

    // 1. Table capacity = 0 with Encoded Insert Count > 0 must return decompression error (not blocked)
    {
        qpk::dynamic_table dt(0); // capacity 0
        qpk::decoder dec(dt);

        std::string block;
        // Encoded Insert Count = 1 (8-bit prefix int)
        h2::hpack::encode_integer(block, 1, 8, 0x00);
        // Sign = 0, Delta Base = 0 (7-bit prefix int)
        h2::hpack::encode_integer(block, 0, 7, 0x00);
        // Field line (:status 200)
        qpk::encoder::encode_indexed_static(block, 25);

        bool is_blocked = false;
        std::vector<std::pair<std::string, std::string>> out_headers;
        const bool ok = dec.decode_header_block(block, out_headers, is_blocked);
        assert(!ok);
        assert(!is_blocked); // Must be decompression error per RFC 9204 §4.5.1.1, NOT blocked!
    }

    // 2. Table capacity = 0 with Encoded Insert Count == 0 succeeds
    {
        qpk::dynamic_table dt(0);
        qpk::decoder dec(dt);

        std::string block;
        // Encoded Insert Count = 0
        h2::hpack::encode_integer(block, 0, 8, 0x00);
        // Delta base = 0
        h2::hpack::encode_integer(block, 0, 7, 0x00);
        // Static table :status 200
        qpk::encoder::encode_indexed_static(block, 25);

        bool is_blocked = false;
        std::vector<std::pair<std::string, std::string>> out_headers;
        const bool ok = dec.decode_header_block(block, out_headers, is_blocked);
        assert(ok);
        assert(!is_blocked);
        assert(out_headers.size() == 1);
        assert(out_headers[0].first == ":status");
        assert(out_headers[0].second == "200");
    }

    // 3. Encoded Insert Count exceeding FullRange is an error
    {
        qpk::dynamic_table dt(4096); // max_entries = 128, FullRange = 256
        qpk::decoder dec(dt);

        std::string block;
        // Encoded Insert Count = 257 (> FullRange 256)
        h2::hpack::encode_integer(block, 257, 8, 0x00);
        h2::hpack::encode_integer(block, 0, 7, 0x00);
        qpk::encoder::encode_indexed_static(block, 25);

        bool is_blocked = false;
        std::vector<std::pair<std::string, std::string>> out_headers;
        const bool ok = dec.decode_header_block(block, out_headers, is_blocked);
        assert(!ok);
        assert(!is_blocked);
    }

    // 4. Modulus unwrapping: TotalNumberOfInserts = 300, FullRange = 256
    {
        qpk::dynamic_table dt(4096);
        for (int i = 0; i < 300; ++i) {
            dt.insert("x-custom-key-" + std::to_string(i), "val-" + std::to_string(i));
        }
        assert(dt.total_inserts() == 300);

        qpk::decoder dec(dt);

        // Part 4a: RIC = 200 unwraps across FullRange (MaxWrapped = 256, 456 > 428 -> 200)
        {
            std::string block;
            h3::qpack::encoder::encode_prefix(block, 200, 300, 4096);
            qpk::encoder::encode_indexed_static(block, 25); // :status 200

            bool is_blocked = false;
            std::vector<std::pair<std::string, std::string>> out_headers;
            const bool ok = dec.decode_header_block(block, out_headers, is_blocked);
            assert(ok);
            assert(!is_blocked);
            assert(out_headers.size() == 1);
            assert(out_headers[0].first == ":status");
            assert(out_headers[0].second == "200");
        }

        // Part 4b: Modulus unwrapping with dynamic entry lookup (target_abs = 280, Base = 300 -> rel_idx = 19)
        {
            std::string block;
            // RIC = 281, Base = 300
            h3::qpack::encoder::encode_prefix(block, 281, 300, 4096);
            qpk::encoder::encode_indexed_dynamic(block, 19);

            bool is_blocked = false;
            std::vector<std::pair<std::string, std::string>> out_headers;
            const bool ok = dec.decode_header_block(block, out_headers, is_blocked);
            assert(ok);
            assert(!is_blocked);
            assert(out_headers.size() == 1);
            assert(out_headers[0].first == "x-custom-key-280");
            assert(out_headers[0].second == "val-280");
        }
    }

    // 5. Blocked stream detection when req_insert_count > dt.total_inserts()
    {
        qpk::dynamic_table dt(4096);
        dt.insert("x-k1", "v1");
        dt.insert("x-k2", "v2");
        assert(dt.total_inserts() == 2);

        qpk::decoder dec(dt);
        std::string block;
        // RIC = 5 (> total_inserts 2), Base = 5
        h3::qpack::encoder::encode_prefix(block, 5, 5, 4096);
        qpk::encoder::encode_indexed_dynamic(block, 0);

        bool is_blocked = false;
        std::vector<std::pair<std::string, std::string>> out_headers;
        const bool ok = dec.decode_header_block(block, out_headers, is_blocked);
        assert(!ok);
        assert(is_blocked); // Must be marked blocked waiting for dynamic table inserts!
    }

    std::cout << "  [PASS] C3: RFC 9204 §4.5.1.1 Required Insert Count decoding verified.\n";
}

void test_qpack_relative_indexing_c4() {
    std::cout << "[Test QPACK] C4: RFC 9204 §4.3.2 & §4.3.4 Relative Indexing in Encoder Instructions...\n";

    qpk::dynamic_table dt(4096);
    qpk::decoder dec(dt);

    // 1. Seed dynamic table with 3 entries:
    // abs_idx 0: "x-key-0", "v0"
    // abs_idx 1: "x-key-1", "v1"
    // abs_idx 2: "x-key-2", "v2"
    dt.insert("x-key-0", "v0");
    dt.insert("x-key-1", "v1");
    dt.insert("x-key-2", "v2");
    assert(dt.total_inserts() == 3);

    // 2. Duplicate with Relative Index 0 (refers to newest entry: 3 - 1 - 0 = abs_idx 2)
    {
        std::string instr;
        qpk::encoder::encode_duplicate(instr, 0); // rel_idx = 0
        std::size_t cursor = 0;
        bool ok = dec.apply_encoder_instruction(instr, cursor);
        assert(ok);
        assert(dt.total_inserts() == 4);
        const auto *e = dt.get_by_absolute_index(3);
        assert(e != nullptr);
        assert(e->name == "x-key-2");
        assert(e->value == "v2");
    }

    // 3. Duplicate with Relative Index 2 (refers to entry: 4 - 1 - 2 = abs_idx 1)
    {
        std::string instr;
        qpk::encoder::encode_duplicate(instr, 2); // rel_idx = 2
        std::size_t cursor = 0;
        bool ok = dec.apply_encoder_instruction(instr, cursor);
        assert(ok);
        assert(dt.total_inserts() == 5);
        const auto *e = dt.get_by_absolute_index(4);
        assert(e != nullptr);
        assert(e->name == "x-key-1");
        assert(e->value == "v1");
    }

    // 4. Duplicate with Out-of-Range Relative Index (rel_idx >= total_inserts 5)
    {
        std::string instr;
        qpk::encoder::encode_duplicate(instr, 5); // rel_idx = 5
        std::size_t cursor = 0;
        bool ok = dec.apply_encoder_instruction(instr, cursor);
        assert(!ok); // Must reject out-of-range index
        assert(dt.total_inserts() == 5);
    }

    // 5. Insert with Name Reference using Dynamic Table (T = 0)
    // Refers to Entry abs_idx 0 ("x-key-0"):
    // Current total_inserts = 5.
    // rel_idx = 5 - 1 - 0 = 4.
    {
        std::string instr;
        qpk::encoder::encode_insert_with_name_ref(instr, 4, false, "new-v0"); // is_static = false, rel_idx = 4
        std::size_t cursor = 0;
        bool ok = dec.apply_encoder_instruction(instr, cursor);
        assert(ok);
        assert(dt.total_inserts() == 6);
        const auto *e = dt.get_by_absolute_index(5);
        assert(e != nullptr);
        assert(e->name == "x-key-0");
        assert(e->value == "new-v0");
    }

    // 6. Insert with Name Reference using Out-of-Range Dynamic Index
    {
        std::string instr;
        qpk::encoder::encode_insert_with_name_ref(instr, 6, false, "bad"); // rel_idx = 6 >= total_inserts 6
        std::size_t cursor = 0;
        bool ok = dec.apply_encoder_instruction(instr, cursor);
        assert(!ok);
        assert(dt.total_inserts() == 6);
    }

    // 7. Eviction handling: entries evicted from front cannot be referenced
    {
        // Set capacity small enough to evict older entries
        dt.set_max_capacity(120); // Each entry ~40 bytes, only ~2 newest entries fit
        assert(dt.get_by_absolute_index(0) == nullptr); // Evicted!

        // Referencing relative index that points to evicted entry fails
        // Current total_inserts = 6. Rel idx 5 points to abs_idx 0 (evicted).
        std::string instr;
        qpk::encoder::encode_duplicate(instr, 5);
        std::size_t cursor = 0;
        bool ok = dec.apply_encoder_instruction(instr, cursor);
        assert(!ok); // Evicted entry lookup returns nullptr -> rejected!

        // Referencing relative index 0 points to newest entry (abs_idx 5) and succeeds
        instr.clear();
        cursor = 0;
        qpk::encoder::encode_duplicate(instr, 0);
        ok = dec.apply_encoder_instruction(instr, cursor);
        assert(ok);
        assert(dt.total_inserts() == 7);
    }

    std::cout << "  [PASS] C4: RFC 9204 Relative Indexing in Encoder Instructions verified.\n";
}

void test_qpack_post_base_and_capacity_limits_c6() {
    std::cout << "[Test QPACK] C6: Dynamic Table Capacity Limits & Post-Base Indexing...\n";

    // 1. Capacity Limit enforcement (RFC 9204 §4.3.1)
    {
        qpk::dynamic_table dt(256, 512); // initial cap = 256, max_capacity_limit = 512
        assert(dt.max_capacity() == 256);
        assert(dt.max_capacity_limit() == 512);

        qpk::decoder dec(dt);

        // Instruction setting capacity to 512 <= max_capacity_limit (succeeds)
        {
            std::string instr;
            qpk::encoder::encode_set_capacity(instr, 512);
            std::size_t cursor = 0;
            bool ok = dec.apply_encoder_instruction(instr, cursor);
            assert(ok);
            assert(dt.max_capacity() == 512);
        }

        // Instruction attempting to set capacity to 513 > max_capacity_limit (fails per §4.3.1)
        {
            std::string instr;
            qpk::encoder::encode_set_capacity(instr, 513);
            std::size_t cursor = 0;
            bool ok = dec.apply_encoder_instruction(instr, cursor);
            assert(!ok);
            assert(dt.max_capacity() == 512); // Unchanged!
        }
    }

    // 2. Connection-scoped dynamic table verification
    {
        h3::connection_context ctx;
        assert(ctx.decode_table.max_capacity_limit() == 4096);
        qpk::decoder dec(ctx.decode_table);

        // Populate table on connection context
        ctx.decode_table.insert("x-conn-token", "tok-12345");
        assert(ctx.decode_table.total_inserts() == 1);
        const auto *e = ctx.decode_table.get_by_absolute_index(0);
        assert(e != nullptr);
        assert(e->name == "x-conn-token");
        assert(e->value == "tok-12345");
    }

    // 3. Post-Base Indexing (RFC 9204 §4.5.3 & §4.5.5)
    {
        qpk::dynamic_table dt(4096);
        // Insert 4 entries: abs_idx 0, 1, 2, 3
        dt.insert("x-hdr-0", "val-0");
        dt.insert("x-hdr-1", "val-1");
        dt.insert("x-hdr-2", "val-2");
        dt.insert("x-hdr-3", "val-3");
        assert(dt.total_inserts() == 4);

        // We choose Base = 2.
        // Entries 0, 1 have absolute index < Base (relative index)
        // Entries 2, 3 have absolute index >= Base (post-base index)
        // Target abs_idx for Entry 2: post-base index = 2 - 2 = 0
        // Target abs_idx for Entry 3: post-base index = 3 - 2 = 1

        // Verify get_post_base helper
        assert(dt.get_post_base(2, 0) != nullptr && dt.get_post_base(2, 0)->name == "x-hdr-2");
        assert(dt.get_post_base(2, 1) != nullptr && dt.get_post_base(2, 1)->name == "x-hdr-3");
        assert(dt.get_post_base(2, 2) == nullptr); // abs 4 does not exist

        // Now construct an encoded field section:
        // Required Insert Count (RIC) = 4 (entry 3 is referenced, so RIC = 4).
        // Base = 2. Since Base (2) < RIC (4):
        // Sign = 1 (bit 0x80)
        // Delta Base = RIC - Base - 1 = 4 - 2 - 1 = 1.
        std::string block;
        qpk::encoder::encode_prefix(block, 4, 2, 4096);

        // Field A: Relative Dynamic Index for Entry 1 (abs 1 < Base 2)
        // rel_idx = Base - 1 - abs = 2 - 1 - 1 = 0
        qpk::encoder::encode_indexed_dynamic(block, 0);

        // Field B: Indexed Post-Base (RFC 9204 §4.5.3) for Entry 2
        // post_base_idx = abs - Base = 2 - 2 = 0
        qpk::encoder::encode_indexed_post_base(block, 0);

        // Field C: Indexed Post-Base (RFC 9204 §4.5.3) for Entry 3
        // post_base_idx = abs - Base = 3 - 2 = 1
        qpk::encoder::encode_indexed_post_base(block, 1);

        // Field D: Literal Post-Base Name Reference (RFC 9204 §4.5.5) for Entry 3's name with new value
        // post_base_name_idx = abs - Base = 3 - 2 = 1
        qpk::encoder::encode_literal_post_base_name_ref(block, 1, "overridden-val-3");

        // Decode field block
        qpk::decoder dec(dt);
        std::vector<std::pair<std::string, std::string>> decoded;
        bool is_blocked = false;
        bool ok = dec.decode_header_block(block, decoded, is_blocked);
        assert(ok);
        assert(!is_blocked);
        assert(decoded.size() == 4);

        assert(decoded[0].first == "x-hdr-1" && decoded[0].second == "val-1");
        assert(decoded[1].first == "x-hdr-2" && decoded[1].second == "val-2");
        assert(decoded[2].first == "x-hdr-3" && decoded[2].second == "val-3");
        assert(decoded[3].first == "x-hdr-3" && decoded[3].second == "overridden-val-3");
    }

    // 4. Out-of-range Post-Base Index rejection
    {
        qpk::dynamic_table dt(4096);
        dt.insert("x-hdr-0", "val-0");
        dt.insert("x-hdr-1", "val-1"); // total_inserts = 2

        // Base = 1. Post-base index 1 refers to abs 1 + 1 = 2 (not yet inserted)
        std::string block;
        qpk::encoder::encode_prefix(block, 2, 1, 4096);
        qpk::encoder::encode_indexed_post_base(block, 1);

        qpk::decoder dec(dt);
        std::vector<std::pair<std::string, std::string>> decoded;
        bool is_blocked = false;
        bool ok = dec.decode_header_block(block, decoded, is_blocked);
        assert(!ok); // Fails cleanly!
    }

    std::cout << "  [PASS] C6: Dynamic Table Limits & Post-Base Indexing verified.\n";
}

int main() {
    std::cout << "=== Running WaveX QPACK Engine Tests (RFC 9204) ===\n";
    try {
        test_qpack_static_table();
        test_qpack_dynamic_table();
        test_qpack_dynamic_table_reentrancy_and_ric();
        test_qpack_encoder_decoder_streams();
        test_qpack_encode_decode();
        test_qpack_huffman_literal_names_c5();
        test_qpack_required_insert_count_c3();
        test_qpack_relative_indexing_c4();
        test_qpack_post_base_and_capacity_limits_c6();
        std::cout << "=== All QPACK Tests PASSED ===\n";
        return 0;
    } catch (const std::exception &ex) {
        std::cerr << "Exception in test_qpack: " << ex.what() << "\n";
        return 1;
    }
}
