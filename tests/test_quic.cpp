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

int main() {
    std::cout << "=== Running WaveX QUIC Transport Tests ===\n";
    try {
        test_varint();
        test_connection_id();
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
