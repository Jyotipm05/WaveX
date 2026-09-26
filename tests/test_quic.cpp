// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file test_quic.cpp
 * @brief Unit and integration tests for WaveX RFC 9000 & 9001 QUIC Transport protocol.
 */

#include <iostream>
#include <cassert>
#include <string>
#include <vector>
#include <thread>
#include <chrono>

#include <wavex/Network/QUIC.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/as_tuple.hpp>

using namespace wavex::network::quic;

void test_varint() {
    std::cout << "[Test QUIC] VarInt encoding and decoding...\n";

    const std::vector<uint64_t> test_values = {
        0, 1, 25, 63,                           // 1-byte
        64, 150, 16383,                         // 2-byte
        16384, 100000, 1073741823,               // 4-byte
        1073741824, 12345678901234ULL           // 8-byte
    };

    for (uint64_t val : test_values) {
        std::string encoded;
        VarInt::encode(val, encoded);
        assert(encoded.size() == VarInt::encoded_size(val));

        std::size_t cursor = 0;
        uint64_t decoded = 0;
        bool ok = VarInt::decode(encoded, cursor, decoded);
        assert(ok);
        assert(cursor == encoded.size());
        assert(decoded == val);
    }

    std::cout << "  [PASS] VarInt tests passed.\n";
}

void test_connection_id() {
    std::cout << "[Test QUIC] ConnectionId operations...\n";

    auto cid1 = ConnectionId::random(8);
    assert(cid1.length() == 8);
    assert(!cid1.empty());

    std::string hex = cid1.to_string();
    assert(hex.size() == 16);

    auto cid2 = ConnectionId::from_hex(hex);
    assert(cid1 == cid2);

    auto cid3 = ConnectionId::random(8);
    assert(cid1 != cid3);

    std::hash<ConnectionId> hasher;
    assert(hasher(cid1) == hasher(cid2));

    std::cout << "  [PASS] ConnectionId tests passed.\n";
}

void test_frames() {
    std::cout << "[Test QUIC] Frame serialization and parsing...\n";

    std::string buffer;

    // 1. PingFrame
    PingFrame ping;
    serialize_frame(ping, buffer);

    // 2. AckFrame
    AckFrame ack;
    ack.largest_acknowledged = 105;
    ack.ack_delay = 25;
    ack.ranges.push_back({0, 5});
    ack.ranges.push_back({2, 10});
    serialize_frame(ack, buffer);

    // 3. StreamFrame
    StreamFrame sf;
    sf.stream_id = 4;
    sf.offset = 100;
    sf.fin = true;
    sf.has_offset = true;
    sf.has_length = true;
    sf.data = "WaveX QUIC Stream Payload 🚀";
    serialize_frame(sf, buffer);

    // 4. CryptoFrame
    CryptoFrame cf;
    cf.offset = 0;
    cf.data = "TLS 1.3 ClientHello / ServerHello bytes";
    serialize_frame(cf, buffer);

    // 5. MaxDataFrame
    MaxDataFrame mdf{1048576};
    serialize_frame(mdf, buffer);

    // 6. ResetStreamFrame
    ResetStreamFrame rsf{4, 0x01, 250};
    serialize_frame(rsf, buffer);

    // 7. ConnectionCloseFrame
    ConnectionCloseFrame ccf{"Graceful close", 0, 0, false};
    serialize_frame(ccf, buffer);

    // Parse all frames back
    std::vector<Frame> parsed;
    bool ok = parse_frames(buffer, parsed);
    assert(ok);
    assert(parsed.size() == 7);

    // Verify parsed frame types
    assert(std::holds_alternative<PingFrame>(parsed[0]));
    assert(std::holds_alternative<AckFrame>(parsed[1]));
    assert(std::holds_alternative<StreamFrame>(parsed[2]));
    assert(std::holds_alternative<CryptoFrame>(parsed[3]));
    assert(std::holds_alternative<MaxDataFrame>(parsed[4]));
    assert(std::holds_alternative<ResetStreamFrame>(parsed[5]));
    assert(std::holds_alternative<ConnectionCloseFrame>(parsed[6]));

    const auto &parsed_sf = std::get<StreamFrame>(parsed[2]);
    assert(parsed_sf.stream_id == 4);
    assert(parsed_sf.offset == 100);
    assert(parsed_sf.fin == true);
    assert(parsed_sf.data == "WaveX QUIC Stream Payload 🚀");

    const auto &parsed_cf = std::get<CryptoFrame>(parsed[3]);
    assert(parsed_cf.data == "TLS 1.3 ClientHello / ServerHello bytes");

    std::cout << "  [PASS] Frame serialization and parsing passed.\n";
}

void test_packet_protection() {
    std::cout << "[Test QUIC] RFC 9001 Packet protection and crypto...\n";

    const auto client_dcid = ConnectionId::random(8);
    const auto client_scid = ConnectionId::random(8);

    ProtectionKeys client_keys, server_keys;
    bool derived = CryptoSuite::derive_initial_secrets(client_dcid, client_keys, server_keys);
    assert(derived);
    assert(client_keys.valid);
    assert(server_keys.valid);

    PacketHeader hdr;
    hdr.is_long = true;
    hdr.type = PacketType::Initial;
    hdr.version = QUIC_VERSION_1;
    hdr.dcid = client_dcid;
    hdr.scid = client_scid;
    hdr.packet_number = 1;
    hdr.packet_number_len = 4;

    const std::string plaintext = "PING and CRYPTO handshake payload";
    std::string protected_packet;

    bool prot_ok = CryptoSuite::protect_packet(client_keys, hdr, plaintext, protected_packet);
    assert(prot_ok);
    assert(!protected_packet.empty());

    // Unprotect packet using client keys (as server would)
    PacketHeader dec_hdr;
    std::string decrypted_plaintext;
    bool unprot_ok = CryptoSuite::unprotect_packet(client_keys, dec_hdr, protected_packet, decrypted_plaintext);
    assert(unprot_ok);
    assert(decrypted_plaintext == plaintext);
    assert(dec_hdr.dcid == client_dcid);
    assert(dec_hdr.scid == client_scid);
    assert(dec_hdr.packet_number == 1);

    std::cout << "  [PASS] Packet protection and unprotection passed.\n";
}

void test_quic_stream_async() {
    std::cout << "[Test QUIC] QuicStream async read/write buffering...\n";

    asio::io_context io;
    auto ep = asio::ip::udp::endpoint(asio::ip::address_v4::loopback(), 9999);
    auto conn = std::make_shared<QuicConnection>(ConnectionId::random(8), ConnectionId::random(8), ep, true);

    auto stream = conn->create_stream(true);
    assert(stream != nullptr);
    assert(stream->is_open());

    const std::string test_data = "Hello from async QuicStream!";
    bool read_completed = false;
    std::string received_data;

    // Launch async coroutine reader
    asio::co_spawn(io, [&]() -> asio::awaitable<void> {
        char buf[128];
        auto [ec, n] = co_await stream->async_read_some(
            asio::buffer(buf), asio::as_tuple(asio::use_awaitable));
        assert(!ec);
        assert(n == test_data.size());
        received_data.assign(buf, n);
        read_completed = true;
        co_return;
    }, asio::detached);

    // Push data into the stream
    stream->push_inbound(test_data, false);

    io.run();

    assert(read_completed);
    assert(received_data == test_data);
    std::cout << "  [PASS] QuicStream async read/write buffering passed.\n";
}

void test_quic_server_client_loopback() {
    std::cout << "[Test QUIC] QuicServer and QuicClient UDP integration loopback...\n";

    asio::io_context server_io;
    asio::io_context client_io;

    QuicServer server(server_io, 0); // Bind ephemeral port
    const uint16_t port = server.local_port();
    assert(port > 0);

    bool server_received_stream = false;
    std::string server_received_msg;

    server.set_stream_handler([&](std::shared_ptr<QuicStream> stream) -> asio::awaitable<void> {
        server_received_stream = true;
        char buf[256];
        auto [ec, n] = co_await stream->async_read_some(asio::buffer(buf), asio::as_tuple(asio::use_awaitable));
        if (!ec && n > 0) {
            server_received_msg.assign(buf, n);
            // Echo back
            const std::string echo = "ECHO: " + server_received_msg;
            co_await stream->async_write_some(asio::buffer(echo), asio::use_awaitable);
        }
        co_return;
    });

    server.start();

    // Start server in background thread
    std::thread server_thread([&server_io] {
        server_io.run();
    });

    // Client connects
    QuicClient client(client_io);
    bool connected = false;

    asio::co_spawn(client_io, [&]() -> asio::awaitable<void> {
        connected = co_await client.connect("127.0.0.1", port);
        assert(connected);

        auto stream = client.create_stream(true);
        assert(stream != nullptr);

        const std::string msg = "Ping over QUIC UDP!";
        co_await stream->async_write_some(asio::buffer(msg), asio::use_awaitable);

        client_io.stop();
        co_return;
    }, asio::detached);

    client_io.run();

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    server.stop();
    server_io.stop();
    if (server_thread.joinable()) server_thread.join();

    assert(connected);
    std::cout << "  [PASS] QuicServer and QuicClient UDP integration passed.\n";
}

void test_stream_id_allocation() {
    std::cout << "[Test QUIC] RFC 9000 §2.1 Stream ID allocation...\n";
    auto ep = asio::ip::udp::endpoint(asio::ip::address_v4::loopback(), 9997);

    // Server connection (is_server = true)
    auto server_conn = std::make_shared<QuicConnection>(ConnectionId::random(8), ConnectionId::random(8), ep, true);
    auto s_bidi1 = server_conn->create_stream(true);
    auto s_bidi2 = server_conn->create_stream(true);
    auto s_bidi3 = server_conn->create_stream(true);
    auto s_bidi4 = server_conn->create_stream(true);
    auto s_uni1 = server_conn->create_stream(false);
    auto s_uni2 = server_conn->create_stream(false);
    auto s_uni3 = server_conn->create_stream(false);
    auto s_uni4 = server_conn->create_stream(false);

    assert(s_bidi1->stream_id() == 1);
    assert(s_bidi2->stream_id() == 5);
    assert(s_bidi3->stream_id() == 9);
    assert(s_bidi4->stream_id() == 13);

    assert(s_uni1->stream_id() == 3);
    assert(s_uni2->stream_id() == 7);
    assert(s_uni3->stream_id() == 11);
    assert(s_uni4->stream_id() == 15);

    // Client connection (is_server = false)
    auto client_conn = std::make_shared<QuicConnection>(ConnectionId::random(8), ConnectionId::random(8), ep, false);
    auto c_bidi1 = client_conn->create_stream(true);
    auto c_bidi2 = client_conn->create_stream(true);
    auto c_bidi3 = client_conn->create_stream(true);
    auto c_bidi4 = client_conn->create_stream(true);
    auto c_uni1 = client_conn->create_stream(false);
    auto c_uni2 = client_conn->create_stream(false);
    auto c_uni3 = client_conn->create_stream(false);
    auto c_uni4 = client_conn->create_stream(false);

    assert(c_bidi1->stream_id() == 0);
    assert(c_bidi2->stream_id() == 4);
    assert(c_bidi3->stream_id() == 8);
    assert(c_bidi4->stream_id() == 12);

    assert(c_uni1->stream_id() == 2);
    assert(c_uni2->stream_id() == 6);
    assert(c_uni3->stream_id() == 10);
    assert(c_uni4->stream_id() == 14);

    std::cout << "  [PASS] RFC 9000 §2.1 Stream ID allocation passed.\n";
}

void test_rfc9001_appendix_a() {
    std::cout << "[Test QUIC] RFC 9001 Appendix A known-answer vector...\n";

    // RFC 9001 §A.1: Keys derived from DCID = 0x8394c8f03e515708
    const std::vector<uint8_t> dcid_bytes = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
    ConnectionId dcid(dcid_bytes.data(), dcid_bytes.size());

    ProtectionKeys client_keys, server_keys;
    bool ok = CryptoSuite::derive_initial_secrets(dcid, client_keys, server_keys);
    assert(ok);

    // Expected client initial secret: c00cf151ca5be075ed0ebfb5c80323c42d6b7db6788128913a9ec5438652e139
    const uint8_t exp_client_secret[32] = {
        0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75, 0xed, 0x0e, 0xbf, 0xb5, 0xc8, 0x03, 0x23, 0xc4,
        0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81, 0x28, 0x91, 0x3a, 0x9e, 0xc5, 0x43, 0x86, 0x52, 0xe1, 0x39
    };
    assert(std::memcmp(client_keys.secret.data(), exp_client_secret, 32) == 0);

    // Expected client key: 1f369613dd76d5467730efcbe3b1a22d
    const uint8_t exp_client_key[16] = {
        0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46, 0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d
    };
    assert(std::memcmp(client_keys.key.data(), exp_client_key, 16) == 0);

    // Expected client iv: fa044b2f42a3eed77ab411b497bbcdc6
    const uint8_t exp_client_iv[12] = {
        0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xee, 0xd7, 0x7a, 0xb4, 0x11, 0xb4
    };
    assert(std::memcmp(client_keys.iv.data(), exp_client_iv, 12) == 0);

    // Expected client hp: 9f50449e04a0e810283a1e9933adedd2
    const uint8_t exp_client_hp[16] = {
        0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10, 0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2
    };
    assert(std::memcmp(client_keys.hp.data(), exp_client_hp, 16) == 0);

    // Expected server initial secret: 3c199828fd139ef106fe4b31775bc2f061423138d2377ced95f4005cdd7944f0
    const uint8_t exp_server_secret[32] = {
        0x3c, 0x19, 0x98, 0x28, 0xfd, 0x13, 0x9e, 0xf1, 0x06, 0xfe, 0x4b, 0x31, 0x77, 0x5b, 0xc2, 0xf0,
        0x61, 0x42, 0x31, 0x38, 0xd2, 0x37, 0x7c, 0xed, 0x95, 0xf4, 0x00, 0x5c, 0xdd, 0x79, 0x44, 0xf0
    };
    assert(std::memcmp(server_keys.secret.data(), exp_server_secret, 32) == 0);

    // Expected server key: cf3a5331653c364c88f0f379b6067e37
    const uint8_t exp_server_key[16] = {
        0xcf, 0x3a, 0x53, 0x31, 0x65, 0x3c, 0x36, 0x4c, 0x88, 0xf0, 0xf3, 0x79, 0xb6, 0x06, 0x7e, 0x37
    };
    assert(std::memcmp(server_keys.key.data(), exp_server_key, 16) == 0);

    // Expected server iv: 0ac1493ca1905853b0bba03e36f37cbc
    const uint8_t exp_server_iv[12] = {
        0x0a, 0xc1, 0x49, 0x3c, 0xa1, 0x90, 0x58, 0x53, 0xb0, 0xbb, 0xa0, 0x3e
    };
    assert(std::memcmp(server_keys.iv.data(), exp_server_iv, 12) == 0);

    // Expected server hp: c206b8d9b1f0d8120b08d10224869281
    const uint8_t exp_server_hp[16] = {
        0xc2, 0x06, 0xb8, 0xd9, 0xb1, 0xf0, 0xd8, 0x12, 0x0b, 0x08, 0xd1, 0x02, 0x24, 0x86, 0x92, 0x81
    };
    assert(std::memcmp(server_keys.hp.data(), exp_server_hp, 16) == 0);

    std::cout << "  [PASS] RFC 9001 Appendix A known-answer vector passed.\n";
}

int main() {
    std::cout << "=== Running WaveX QUIC Transport Tests ===\n";
    try {
        test_varint();
        test_connection_id();
        test_stream_id_allocation();
        test_rfc9001_appendix_a();
        test_frames();
        test_packet_protection();
        test_quic_stream_async();
        test_quic_server_client_loopback();
        std::cout << "=== All QUIC Tests PASSED ===\n";
        return 0;
    } catch (const std::exception &ex) {
        std::cerr << "Exception in test_quic: " << ex.what() << "\n";
        return 1;
    }
}
