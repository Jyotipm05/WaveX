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
#include <iomanip>

#include <wavex/Network/QUIC.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/as_tuple.hpp>
#include <asio/write.hpp>
#include <asio/read.hpp>
#include <asio/ip/address.hpp>

using namespace wavex::network::quic;
namespace quic = wavex::network::quic;

void test_varint() {
    std::cout << "[Test QUIC] VarInt encoding and decoding..." << std::endl;

    constexpr std::array<uint64_t, 12> test_values = {
        0, 1, 25, 63,                           // 1-byte
        64, 150, 16383,                         // 2-byte
        16384, 100000, 1073741823,               // 4-byte
        1073741824, 12345678901234ULL           // 8-byte
    };

    for (const uint64_t val : test_values) {
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

    std::cout << "  [PASS] VarInt tests passed." << std::endl;
}

void test_connection_id() {
    std::cout << "[Test QUIC] ConnectionId operations..." << std::endl;

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

    std::cout << "  [PASS] ConnectionId tests passed." << std::endl;
}

void test_frames() {
    std::cout << "[Test QUIC] Frame serialization and parsing..." << std::endl;

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

    std::cout << "  [PASS] Frame serialization and parsing passed." << std::endl;
}

void test_packet_protection() {
    std::cout << "[Test QUIC] RFC 9001 Packet protection and crypto..." << std::endl;

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

    constexpr std::string_view plaintext = "PING and CRYPTO handshake payload";
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

    std::cout << "  [PASS] Packet protection and unprotection passed." << std::endl;
}

void test_quic_stream_async() {
    std::cout << "[Test QUIC] QuicStream async read/write buffering..." << std::endl;

    asio::io_context io;
    auto ep = asio::ip::udp::endpoint(asio::ip::address_v4::loopback(), 9999);
    auto conn = std::make_shared<QuicConnection>(ConnectionId::random(8), ConnectionId::random(8), ep, true);

    auto stream = conn->create_stream(true);
    assert(stream != nullptr);
    assert(stream->is_open());

    constexpr std::string_view test_data = "Hello from async QuicStream!";
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
    std::cout << "  [PASS] QuicStream async read/write buffering passed." << std::endl;
}

void test_quic_server_client_loopback() {
    std::cout << "[Test QUIC] QuicServer and QuicClient UDP integration loopback..." << std::endl;

    asio::io_context server_io;
    asio::io_context client_io;

    QuicServer server(server_io, 0); // Bind ephemeral port
    const uint16_t port = server.local_port();
    assert(port > 0);

    std::string server_received_msg;

    server.set_stream_handler([&](std::shared_ptr<QuicStream> stream) -> asio::awaitable<void> {
        [[maybe_unused]] bool server_received_stream = true;
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
    std::string client_received_echo;

    asio::co_spawn(client_io, [&]() -> asio::awaitable<void> {
        connected = co_await client.connect("127.0.0.1", port);
        assert(connected);

        auto stream = client.create_stream(true);
        assert(stream != nullptr);

        constexpr std::string_view msg = "Ping over QUIC UDP!";
        co_await stream->async_write_some(asio::buffer(msg), asio::use_awaitable);

        char buf[256];
        auto [rec, rn] = co_await stream->async_read_some(asio::buffer(buf), asio::as_tuple(asio::use_awaitable));
        if (!rec && rn > 0) {
            client_received_echo.assign(buf, rn);
        }

        client.close();
        client_io.stop();
        co_return;
    }, asio::detached);

    client_io.run();

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    server.stop();
    server_io.stop();
    if (server_thread.joinable()) server_thread.join();

    assert(connected);
    assert(server_received_msg == "Ping over QUIC UDP!");
    assert(client_received_echo == "ECHO: Ping over QUIC UDP!");
    std::cout << "  [PASS] QuicServer and QuicClient UDP integration passed." << std::endl;
}

void test_stream_id_allocation() {
    std::cout << "[Test QUIC] RFC 9000 §2.1 Stream ID allocation..." << std::endl;
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

    std::cout << "  [PASS] RFC 9000 §2.1 Stream ID allocation passed." << std::endl;
}

void test_rfc9001_appendix_a() {
    std::cout << "[Test QUIC] RFC 9001 Appendix A known-answer vector...\n";

    // RFC 9001 §A.1: Keys derived from DCID = 0x8394c8f03e515708
    const std::vector<uint8_t> dcid_bytes = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
    ConnectionId dcid(dcid_bytes.data(), dcid_bytes.size());

    ProtectionKeys client_keys, server_keys;
    bool ok = CryptoSuite::derive_initial_secrets(dcid, client_keys, server_keys);
    assert(ok);

    auto print_hex = [](const std::string_view label, const uint8_t *data, std::size_t len) {
        std::cout << "    [LOG] " << label << ": ";
        for (std::size_t i = 0; i < len; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
        }
        std::cout << std::dec << std::endl;
    };

    // Expected client initial secret: c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea
    const uint8_t exp_client_secret[32] = {
        0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75, 0xed, 0x0e, 0xbf, 0xb5, 0xc8, 0x03, 0x23, 0xc4,
        0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81, 0x28, 0x9a, 0xf4, 0x00, 0x8f, 0x1f, 0x6c, 0x35, 0x7a, 0xea
    };
    print_hex("Computed Client Secret", client_keys.secret.data(), 32);
    print_hex("Expected Client Secret", exp_client_secret, 32);
    assert(std::memcmp(client_keys.secret.data(), exp_client_secret, 32) == 0);

    // Expected client key: 1f369613dd76d5467730efcbe3b1a22d
    const uint8_t exp_client_key[16] = {
        0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46, 0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d
    };
    print_hex("Computed Client Key", client_keys.key.data(), 16);
    print_hex("Expected Client Key", exp_client_key, 16);
    assert(std::memcmp(client_keys.key.data(), exp_client_key, 16) == 0);

    // Expected client iv: fa044b2f42a3fd3b46fb255c
    const uint8_t exp_client_iv[12] = {
        0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c
    };
    print_hex("Computed Client IV", client_keys.iv.data(), 12);
    print_hex("Expected Client IV", exp_client_iv, 12);
    assert(std::memcmp(client_keys.iv.data(), exp_client_iv, 12) == 0);

    // Expected client hp: 9f50449e04a0e810283a1e9933adedd2
    const uint8_t exp_client_hp[16] = {
        0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10, 0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2
    };
    print_hex("Computed Client HP", client_keys.hp.data(), 16);
    print_hex("Expected Client HP", exp_client_hp, 16);
    assert(std::memcmp(client_keys.hp.data(), exp_client_hp, 16) == 0);

    // Expected server initial secret: 3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b
    const uint8_t exp_server_secret[32] = {
        0x3c, 0x19, 0x98, 0x28, 0xfd, 0x13, 0x9e, 0xfd, 0x21, 0x6c, 0x15, 0x5a, 0xd8, 0x44, 0xcc, 0x81,
        0xfb, 0x82, 0xfa, 0x8d, 0x74, 0x46, 0xfa, 0x7d, 0x78, 0xbe, 0x80, 0x3a, 0xcd, 0xda, 0x95, 0x1b
    };
    print_hex("Computed Server Secret", server_keys.secret.data(), 32);
    print_hex("Expected Server Secret", exp_server_secret, 32);
    assert(std::memcmp(server_keys.secret.data(), exp_server_secret, 32) == 0);

    // Expected server key: cf3a5331653c364c88f0f379b6067e37
    const uint8_t exp_server_key[16] = {
        0xcf, 0x3a, 0x53, 0x31, 0x65, 0x3c, 0x36, 0x4c, 0x88, 0xf0, 0xf3, 0x79, 0xb6, 0x06, 0x7e, 0x37
    };
    print_hex("Computed Server Key", server_keys.key.data(), 16);
    print_hex("Expected Server Key", exp_server_key, 16);
    assert(std::memcmp(server_keys.key.data(), exp_server_key, 16) == 0);

    // Expected server iv: 0ac1493ca1905853b0bba03e
    const uint8_t exp_server_iv[12] = {
        0x0a, 0xc1, 0x49, 0x3c, 0xa1, 0x90, 0x58, 0x53, 0xb0, 0xbb, 0xa0, 0x3e
    };
    print_hex("Computed Server IV", server_keys.iv.data(), 12);
    print_hex("Expected Server IV", exp_server_iv, 12);
    assert(std::memcmp(server_keys.iv.data(), exp_server_iv, 12) == 0);

    // Expected server hp: c206b8d9b9f0f37644430b490eeaa314
    const uint8_t exp_server_hp[16] = {
        0xc2, 0x06, 0xb8, 0xd9, 0xb9, 0xf0, 0xf3, 0x76, 0x44, 0x43, 0x0b, 0x49, 0x0e, 0xea, 0xa3, 0x14
    };
    print_hex("Computed Server HP", server_keys.hp.data(), 16);
    print_hex("Expected Server HP", exp_server_hp, 16);
    assert(std::memcmp(server_keys.hp.data(), exp_server_hp, 16) == 0);

    std::cout << "  [PASS] RFC 9001 Appendix A known-answer vector passed." << std::endl;
}

void test_quic_protocol() {
    std::cout << "[Test QUIC] Protocol definitions (endpoint, resolver, v4, v6)..." << std::endl;
    const auto p4 = quic::v4();
    const auto p6 = quic::v6();
    assert(p4.type() == SOCK_DGRAM);
    assert(p4.protocol() == IPPROTO_UDP);
    assert(p4.family() == PF_INET);
    assert(p6.family() == PF_INET6);
    assert(p4 == quic::quic_protocol::v4());
    assert(p4 != p6);

    const quic::endpoint ep(p4, 4433);
    assert(ep.port() == 4433);
    std::cout << "  [PASS] Protocol definitions passed." << std::endl;
}

void test_quic_socket_acceptor_tcp_syntax() {
    std::cout << "[Test QUIC] quic::socket and quic::acceptor standard Asio TCP-like syntax..." << std::endl;

    asio::io_context server_io;
    asio::io_context client_io;

    quic::endpoint listen_ep(quic::v4(), 0);
    quic::acceptor acceptor(server_io, listen_ep);
    const uint16_t port = acceptor.local_endpoint().port();
    assert(port > 0);

    bool server_accepted = false;
    std::string server_received_msg;

    auto server_sock = std::make_shared<quic::socket>(server_io);
    acceptor.async_accept(*server_sock, [server_sock, &server_accepted, &server_received_msg](std::error_code ec) {
        assert(!ec);
        server_accepted = true;

        auto buf = std::make_shared<std::array<char, 256>>();
        server_sock->async_read_some(asio::buffer(*buf), [server_sock, buf, &server_received_msg](std::error_code read_ec, std::size_t n) {
            assert(!read_ec);
            server_received_msg.assign(buf->data(), n);

            auto reply = std::make_shared<std::string>("ECHO: " + server_received_msg);
            asio::async_write(*server_sock, asio::buffer(*reply), [reply, server_sock](std::error_code write_ec, std::size_t) {
                assert(!write_ec);
            });
        });
    });

    std::thread server_thread([&server_io] {
        server_io.run();
    });

    quic::socket client_sock(client_io);
    quic::endpoint server_ep(asio::ip::make_address("127.0.0.1"), port);

    bool client_connected = false;
    std::string client_received_reply;

    client_sock.async_connect(server_ep, [&](std::error_code ec) {
        assert(!ec);
        client_connected = true;

        const auto msg = std::make_shared<std::string>("Hello QUIC TCP-like socket!");
        asio::async_write(client_sock, asio::buffer(*msg), [&](std::error_code write_ec, std::size_t) {
            assert(!write_ec);

            auto reply_buf = std::make_shared<std::array<char, 256>>();
            client_sock.async_read_some(asio::buffer(*reply_buf), [&client_sock, reply_buf, &client_received_reply, &client_io](std::error_code read_ec, std::size_t n) {
                assert(!read_ec);
                client_received_reply.assign(reply_buf->data(), n);
                client_sock.close();
                client_io.stop();
            });
        });
    });

    client_io.run();

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    acceptor.close();
    server_io.stop();
    if (server_thread.joinable()) server_thread.join();

    assert(server_accepted);
    assert(client_connected);
    assert(server_received_msg == "Hello QUIC TCP-like socket!");
    assert(client_received_reply == "ECHO: Hello QUIC TCP-like socket!");
    std::cout << "  [PASS] quic::socket and quic::acceptor TCP-like syntax passed." << std::endl;
}

void test_quic_socket_acceptor_coroutine() {
    std::cout << "[Test QUIC] quic::socket and quic::acceptor C++20 coroutine awaitables..." << std::endl;

    asio::io_context server_io;
    asio::io_context client_io;

    quic::endpoint listen_ep(quic::v4(), 0);
    quic::acceptor acceptor(server_io, listen_ep);
    const uint16_t port = acceptor.local_endpoint().port();
    assert(port > 0);

    bool server_finished = false;
    asio::co_spawn(server_io, [&]() -> asio::awaitable<void> {
        quic::socket sock(server_io);
        co_await acceptor.async_accept(sock, asio::use_awaitable);

        char buf[256];
        auto [read_ec, n] = co_await sock.async_read_some(asio::buffer(buf), asio::as_tuple(asio::use_awaitable));
        assert(!read_ec);
        std::string req(buf, n);

        std::string reply = "AWAIT: " + req;
        auto [write_ec, wn] = co_await asio::async_write(sock, asio::buffer(reply), asio::as_tuple(asio::use_awaitable));
        assert(!write_ec);
        assert(wn == reply.size());

        server_finished = true;
        co_return;
    }, asio::detached);

    std::thread server_thread([&server_io] {
        server_io.run();
    });

    bool client_finished = false;
    std::string client_result;

    asio::co_spawn(client_io, [&]() -> asio::awaitable<void> {
        quic::socket client(client_io);
        quic::endpoint server_ep(asio::ip::make_address("127.0.0.1"), port);
        co_await client.async_connect(server_ep, asio::use_awaitable);

        std::string msg = "Ping from C++20 awaitable!";
        co_await asio::async_write(client, asio::buffer(msg), asio::use_awaitable);

        char buf[256];
        auto [read_ec, n] = co_await client.async_read_some(asio::buffer(buf), asio::as_tuple(asio::use_awaitable));
        assert(!read_ec);
        client_result.assign(buf, n);
        client_finished = true;

        client.close();
        client_io.stop();
        co_return;
    }, asio::detached);

    client_io.run();

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    acceptor.close();
    server_io.stop();
    if (server_thread.joinable()) server_thread.join();

    assert(server_finished);
    assert(client_finished);
    assert(client_result == "AWAIT: Ping from C++20 awaitable!");
    std::cout << "  [PASS] quic::socket and quic::acceptor C++20 coroutine awaitables passed." << std::endl;
}

void test_quic_stream_multiplexing() {
    std::cout << "[Test QUIC] quic::socket stream multiplexing (open_stream)..." << std::endl;

    asio::io_context server_io;
    asio::io_context client_io;

    quic::endpoint listen_ep(quic::v4(), 0);
    quic::acceptor acceptor(server_io, listen_ep);
    const uint16_t port = acceptor.local_endpoint().port();

    auto s1 = std::make_shared<quic::socket>(server_io);
    auto s2 = std::make_shared<quic::socket>(server_io);

    bool s1_accepted = false;
    bool s2_accepted = false;

    // Accept stream 0 and then stream 4
    acceptor.async_accept(*s1, [&acceptor, s2, &s1_accepted, &s2_accepted](std::error_code ec) {
        assert(!ec);
        s1_accepted = true;
        acceptor.async_accept(*s2, [&s2_accepted](std::error_code ec2) {
            assert(!ec2);
            s2_accepted = true;
        });
    });

    std::thread server_thread([&server_io] {
        server_io.run();
    });

    quic::socket c1(client_io);
    quic::endpoint server_ep(asio::ip::make_address("127.0.0.1"), port);

    client_io.post([&] {
        c1.async_connect(server_ep, [&](std::error_code ec) {
            assert(!ec);
            assert(c1.stream_id() == 0);

            // Open second stream over the same QUIC connection
            auto c2 = std::make_shared<quic::socket>(c1.open_stream(true));
            assert(c2->stream_id() > 0);

            // Write on c2 so server accepts the stream
            auto msg = std::make_shared<std::string>("c2 ping");
            asio::async_write(*c2, asio::buffer(*msg), [&c1, c2, msg, &client_io](std::error_code wec, std::size_t) {
                assert(!wec);
                c1.close();
                c2->close();
                client_io.stop();
            });
        });
    });

    client_io.run();

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    acceptor.close();
    server_io.stop();
    if (server_thread.joinable()) server_thread.join();

    assert(s1_accepted);
    assert(s2_accepted);
    std::cout << "  [PASS] quic::socket stream multiplexing passed." << std::endl;
}

void test_varint_edge_cases() {
    std::cout << "[Test QUIC] VarInt edge cases and truncation resilience..." << std::endl;

    // 1. Truncated 2-byte VarInt (prefix 0x40 says 2 bytes, but only 1 byte provided)
    {
        const std::string truncated = "\x40";
        std::size_t cursor = 0;
        uint64_t val = 0;
        assert(!VarInt::decode(truncated, cursor, val));
        assert(cursor == 0); // Cursor must not advance on failure
    }

    // 2. Truncated 4-byte VarInt (prefix 0x80 says 4 bytes, only 2 bytes provided)
    {
        const std::string truncated = "\x80\x01";
        std::size_t cursor = 0;
        uint64_t val = 0;
        assert(!VarInt::decode(truncated, cursor, val));
        assert(cursor == 0);
    }

    // 3. Truncated 8-byte VarInt (prefix 0xc0 says 8 bytes, only 5 bytes provided)
    {
        const std::string truncated = "\xc0\x01\x02\x03\x04";
        std::size_t cursor = 0;
        uint64_t val = 0;
        assert(!VarInt::decode(truncated, cursor, val));
        assert(cursor == 0);
    }

    // 4. Empty buffer
    {
        const std::string empty;
        std::size_t cursor = 0;
        uint64_t val = 0;
        assert(!VarInt::decode(empty, cursor, val));
    }

    // 5. Maximum 62-bit VarInt boundary (2^62 - 1 = 0x3fffffffffffffff)
    {
        constexpr uint64_t kMaxVarInt = 0x3fffffffffffffffULL;
        std::string encoded;
        VarInt::encode(kMaxVarInt, encoded);
        assert(encoded.size() == 8);
        assert(static_cast<uint8_t>(encoded[0]) == 0xff); // 0xc0 | 0x3f

        std::size_t cursor = 0;
        uint64_t decoded = 0;
        assert(VarInt::decode(encoded, cursor, decoded));
        assert(decoded == kMaxVarInt);
        assert(cursor == 8);
    }

    // 6. Concatenated sequential VarInts
    {
        std::string buffer;
        VarInt::encode(0, buffer);
        VarInt::encode(63, buffer);
        VarInt::encode(64, buffer);
        VarInt::encode(16383, buffer);
        VarInt::encode(16384, buffer);
        VarInt::encode(1073741823, buffer);
        VarInt::encode(1073741824, buffer);

        std::size_t cursor = 0;
        uint64_t v = 0;
        assert(VarInt::decode(buffer, cursor, v) && v == 0);
        assert(VarInt::decode(buffer, cursor, v) && v == 63);
        assert(VarInt::decode(buffer, cursor, v) && v == 64);
        assert(VarInt::decode(buffer, cursor, v) && v == 16383);
        assert(VarInt::decode(buffer, cursor, v) && v == 16384);
        assert(VarInt::decode(buffer, cursor, v) && v == 1073741823);
        assert(VarInt::decode(buffer, cursor, v) && v == 1073741824);
        assert(cursor == buffer.size());
    }

    std::cout << "  [PASS] VarInt edge cases and truncation resilience passed." << std::endl;
}

void test_connection_id_boundaries() {
    std::cout << "[Test QUIC] ConnectionId boundary limits (0 to 20 bytes)..." << std::endl;

    // 1. Zero-length (empty) CID (RFC 9000 allows empty CID)
    {
        const ConnectionId empty_cid;
        assert(empty_cid.empty());
        assert(empty_cid.length() == 0);
        assert(empty_cid.to_string().empty());

        const ConnectionId parsed_empty = ConnectionId::from_hex("");
        assert(parsed_empty.empty());
        assert(empty_cid == parsed_empty);
    }

    // 2. Minimum length (1 byte)
    {
        const uint8_t one_byte = 0x42;
        const ConnectionId cid1(&one_byte, 1);
        assert(!cid1.empty());
        assert(cid1.length() == 1);
        assert(cid1.data()[0] == 0x42);
        assert(cid1.to_string() == "42");

        const ConnectionId from_h = ConnectionId::from_hex("42");
        assert(from_h == cid1);
    }

    // 3. Maximum length (20 bytes per RFC 9000 §5.1)
    {
        const uint8_t max_bytes[20] = {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14
        };
        const ConnectionId cid20(max_bytes, 20);
        assert(cid20.length() == 20);
        assert(!cid20.empty());
        assert(cid20.to_string() == "0102030405060708090a0b0c0d0e0f1011121314");

        const ConnectionId parsed20 = ConnectionId::from_hex("0102030405060708090a0b0c0d0e0f1011121314");
        assert(parsed20 == cid20);
    }

    // 4. Clamping of over-length CID (> 20 bytes)
    {
        const uint8_t over_bytes[25] = {0};
        const ConnectionId over_cid(over_bytes, 25);
        assert(over_cid.length() == 20); // Clamped to MAX_CONNECTION_ID_LEN
    }

    // 5. Malformed hex inputs
    {
        // Odd length hex
        const ConnectionId odd_hex = ConnectionId::from_hex("123");
        assert(odd_hex.empty());

        // Invalid hex characters
        const ConnectionId invalid_hex = ConnectionId::from_hex("0102030405zz");
        assert(invalid_hex.empty());

        // Hex exceeding 20 bytes (42 hex chars = 21 bytes)
        const ConnectionId too_long_hex = ConnectionId::from_hex("000102030405060708090a0b0c0d0e0f1011121314");
        assert(too_long_hex.empty());
    }

    std::cout << "  [PASS] ConnectionId boundary limits passed." << std::endl;
}

void test_malformed_packets_and_fuzzing() {
    std::cout << "[Test QUIC] Malformed packet parser resilience & fuzzing..." << std::endl;

    // 1. Packet too short for header
    {
        PacketHeader hdr;
        std::size_t hdr_len = 0;
        assert(!unpack_packet_header("", hdr, hdr_len));
        assert(!unpack_packet_header("\xc0", hdr, hdr_len));
        assert(!unpack_packet_header("\xc0\x00\x00", hdr, hdr_len));
    }

    // 2. Long header with DCID length exceeding 20 bytes (RFC 9000 §17.2 violation)
    {
        std::string malformed_long_pkt;
        malformed_long_pkt.push_back(static_cast<char>(0xc0)); // Long header
        malformed_long_pkt.push_back(0); malformed_long_pkt.push_back(0); malformed_long_pkt.push_back(0); malformed_long_pkt.push_back(1); // Version 1
        malformed_long_pkt.push_back(21); // DCID length 21 (ILLEGAL: must be <= 20)
        malformed_long_pkt.append(21, 'A');
        malformed_long_pkt.push_back(0); // SCID length 0

        PacketHeader hdr;
        std::size_t hdr_len = 0;
        assert(!unpack_packet_header(malformed_long_pkt, hdr, hdr_len));
    }

    // 3. Long header with truncated Initial token
    {
        std::string malformed_token_pkt;
        malformed_token_pkt.push_back(static_cast<char>(0xc0)); // Long Initial
        malformed_token_pkt.push_back(0); malformed_token_pkt.push_back(0); malformed_token_pkt.push_back(0); malformed_token_pkt.push_back(1);
        malformed_token_pkt.push_back(4); malformed_token_pkt.append("1234"); // DCID
        malformed_token_pkt.push_back(4); malformed_token_pkt.append("5678"); // SCID
        VarInt::encode(100, malformed_token_pkt); // Claims token is 100 bytes, but buffer ends

        PacketHeader hdr;
        std::size_t hdr_len = 0;
        assert(!unpack_packet_header(malformed_token_pkt, hdr, hdr_len));
    }

    // 4. Truncated Frame Payloads in parse_frames
    {
        std::vector<Frame> frames;

        // Truncated STREAM frame (flags say has length, but VarInt truncated)
        const std::string trunc_stream = "\x0a\x04"; // Type 0x0a (has length), stream_id=4, truncated length
        frames.clear();
        assert(!parse_frames(trunc_stream, frames));

        // Truncated CRYPTO frame (offset 0, length says 50, but buffer ends)
        std::string trunc_crypto;
        trunc_crypto.push_back(0x06); // Crypto frame
        VarInt::encode(0, trunc_crypto);
        VarInt::encode(50, trunc_crypto);
        trunc_crypto.append("only 10 bytes");
        frames.clear();
        assert(!parse_frames(trunc_crypto, frames));

        // Truncated ACK frame (claims 5 ranges, but provides 0)
        std::string trunc_ack;
        trunc_ack.push_back(0x02); // Ack frame
        VarInt::encode(10, trunc_ack); // largest ack
        VarInt::encode(0, trunc_ack);  // ack delay
        VarInt::encode(5, trunc_ack);  // 5 ranges claimed
        VarInt::encode(0, trunc_ack);  // first ack range
        // Missing range pairs!
        frames.clear();
        assert(!parse_frames(trunc_ack, frames));

        // Unknown frame type (e.g. 0x2f) - must safely stop/skip without crash
        const std::string unknown_frame = "\x2f\x00\x00";
        frames.clear();
        assert(parse_frames(unknown_frame, frames));
    }

    // 5. Crypto Tamper Detection (AEAD auth tag mismatch)
    {
        const auto cid = ConnectionId::random(8);
        ProtectionKeys client_keys, server_keys;
        CryptoSuite::derive_initial_secrets(cid, client_keys, server_keys);

        PacketHeader hdr;
        hdr.is_long = true;
        hdr.type = PacketType::Initial;
        hdr.version = QUIC_VERSION_1;
        hdr.dcid = cid;
        hdr.scid = ConnectionId::random(8);
        hdr.packet_number = 42;
        hdr.packet_number_len = 4;

        std::string valid_packet;
        CryptoSuite::protect_packet(client_keys, hdr, "Top Secret Handshake Payload", valid_packet);
        assert(!valid_packet.empty());

        // Corrupt a byte in the payload ciphertext (tampering attack)
        std::string tampered_packet = valid_packet;
        tampered_packet[tampered_packet.size() - 5] ^= 0x55;

        PacketHeader dec_hdr;
        std::string decrypted;
        const bool ok = CryptoSuite::unprotect_packet(client_keys, dec_hdr, tampered_packet, decrypted);
        assert(!ok); // AEAD tag verification must reject tampered packet!
    }

    std::cout << "  [PASS] Malformed packet parser resilience & fuzzing passed." << std::endl;
}

void test_rfc9002_loss_and_recovery() {
    std::cout << "[Test QUIC] RFC 9002 Loss detection and ACK range processing..." << std::endl;

    // Emulate packet sequence with multiple lost packet intervals:
    // Received: packets 0, 1, 2, 5, 6, 9
    // Lost: packets 3, 4, 7, 8
    AckFrame ack;
    ack.largest_acknowledged = 9;
    ack.ack_delay = 5;
    ack.ranges.push_back(AckRange{0, 0}); // acknowledges packet 9 (first range: gap 0, len 0)
    ack.ranges.push_back(AckRange{1, 1}); // packets 6, 5
    ack.ranges.push_back(AckRange{1, 2}); // packets 2, 1, 0

    std::string serialized;
    serialize_frame(ack, serialized);
    assert(!serialized.empty());

    std::vector<Frame> parsed_frames;
    const bool ok = parse_frames(serialized, parsed_frames);
    assert(ok);
    assert(parsed_frames.size() == 1);
    assert(std::holds_alternative<AckFrame>(parsed_frames[0]));

    const auto &parsed_ack = std::get<AckFrame>(parsed_frames[0]);
    assert(parsed_ack.largest_acknowledged == 9);
    assert(parsed_ack.ack_delay == 5);
    assert(parsed_ack.ranges.size() == 3);
    assert(parsed_ack.ranges[0].ack_range_len == 0);
    assert(parsed_ack.ranges[1].gap == 1);
    assert(parsed_ack.ranges[1].ack_range_len == 1);
    assert(parsed_ack.ranges[2].gap == 1);
    assert(parsed_ack.ranges[2].ack_range_len == 2);

    // Test ReceivedPacketTracker interval coalescence and ACK range production
    QuicConnection::ReceivedPacketTracker tracker;
    assert(!tracker.needs_ack());
    tracker.add_packet(0, true);
    tracker.add_packet(1, true);
    tracker.add_packet(2, true);
    tracker.add_packet(5, true);
    tracker.add_packet(6, true);
    tracker.add_packet(9, true);
    assert(tracker.needs_ack());

    AckFrame generated_ack = tracker.build_ack_frame(5);
    assert(generated_ack.largest_acknowledged == 9);
    assert(generated_ack.ack_delay == 5);
    assert(generated_ack.ranges.size() == 3);
    assert(generated_ack.ranges[0].ack_range_len == 0);
    assert(generated_ack.ranges[1].gap == 1);
    assert(generated_ack.ranges[1].ack_range_len == 1);
    assert(generated_ack.ranges[2].gap == 1);
    assert(generated_ack.ranges[2].ack_range_len == 2);

    tracker.mark_ack_sent();
    assert(!tracker.needs_ack());

    // Out-of-order and duplicate packet insertion
    tracker.add_packet(4, true); // Inserts between {0..2} and {5,6}
    tracker.add_packet(1, false); // Duplicate, ignored
    assert(tracker.needs_ack());

    // Flow control frame roundtrips
    MaxDataFrame mdf{2097152}; // 2 MB connection limit
    std::string mdf_bytes;
    serialize_frame(mdf, mdf_bytes);
    parsed_frames.clear();
    assert(parse_frames(mdf_bytes, parsed_frames));
    assert(std::get<MaxDataFrame>(parsed_frames[0]).max_data == 2097152);

    MaxStreamDataFrame msdf{4, 524288}; // 512 KB stream limit
    std::string msdf_bytes;
    serialize_frame(msdf, msdf_bytes);
    parsed_frames.clear();
    assert(parse_frames(msdf_bytes, parsed_frames));
    assert(std::get<MaxStreamDataFrame>(parsed_frames[0]).stream_id == 4);
    assert(std::get<MaxStreamDataFrame>(parsed_frames[0]).max_stream_data == 524288);

    std::cout << "  [PASS] RFC 9002 Loss detection and ACK range processing passed." << std::endl;
}

void test_congestion_controller() {
    std::cout << "[Test QUIC] RFC 9002 Congestion Control & RTT estimator..." << std::endl;

    CongestionController cc;
    assert(cc.bytes_in_flight() == 0);
    assert(cc.congestion_window() == CongestionController::kInitialWindow);
    assert(cc.can_send());
    assert(!cc.in_recovery());

    // 1. Packet sending tracks bytes in flight
    cc.on_packet_sent(1200);
    assert(cc.bytes_in_flight() == 1200);
    assert(cc.can_send());

    // Fill up the initial window (14720 bytes)
    for (int i = 0; i < 11; ++i) {
        cc.on_packet_sent(1200);
    }
    assert(cc.bytes_in_flight() == 14400);
    assert(cc.can_send());

    cc.on_packet_sent(1000);
    assert(cc.bytes_in_flight() == 15400);
    assert(!cc.can_send()); // 15400 >= 14720 -> cannot send!

    // 2. Slow Start expansion upon ACK
    cc.on_packet_acked(1200);
    assert(cc.bytes_in_flight() == 14200);
    // cwnd grows by 1200 in Slow Start: 14720 + 1200 = 15920
    assert(cc.congestion_window() == 15920);
    assert(cc.can_send()); // 14200 < 15920 -> can send again!

    // 3. Congestion Event / Loss
    const auto now = std::chrono::steady_clock::now();
    cc.on_congestion_event(now - std::chrono::milliseconds(50), now);
    assert(cc.in_recovery());
    // ssthresh = max(15920 / 2, 2400) = 7960
    assert(cc.ssthresh() == 7960);
    assert(cc.congestion_window() == 7960);

    // 4. Exit Recovery and enter Congestion Avoidance
    cc.exit_recovery();
    assert(!cc.in_recovery());

    // In Congestion Avoidance (cwnd >= ssthresh):
    // cwnd increases by (kMaxDatagramSize * bytes) / cwnd = (1200 * 1200) / 7960 = 180 bytes
    const uint64_t prev_cwnd = cc.congestion_window();
    cc.on_packet_acked(1200);
    assert(cc.congestion_window() == prev_cwnd + (1200 * 1200) / prev_cwnd);

    // 5. RTT Estimator (RFC 9002 §5)
    RttStats rtt;
    assert(rtt.first_rtt_sample);
    // First sample: 100ms
    rtt.update_rtt(std::chrono::microseconds(100000));
    assert(!rtt.first_rtt_sample);
    assert(rtt.latest_rtt.count() == 100000);
    assert(rtt.min_rtt.count() == 100000);
    assert(rtt.smoothed_rtt.count() == 100000);
    assert(rtt.rttvar.count() == 50000);

    // Second sample: 120ms with 10ms ack_delay -> adjusted_rtt = 110ms
    // diff = |100ms - 110ms| = 10ms
    // rttvar = (3 * 50ms + 10ms) / 4 = 40ms = 40000us
    // smoothed_rtt = (7 * 100ms + 110ms) / 8 = 810ms / 8 = 101250us
    rtt.update_rtt(std::chrono::microseconds(120000), std::chrono::microseconds(10000));
    assert(rtt.min_rtt.count() == 100000);
    assert(rtt.latest_rtt.count() == 120000);
    assert(rtt.rttvar.count() == 40000);
    assert(rtt.smoothed_rtt.count() == 101250);

    std::cout << "  [PASS] RFC 9002 Congestion Control & RTT estimator passed." << std::endl;
}

void test_quic_packet_fuzzer() {
    std::cout << "[Test QUIC] Pre-authentication packet parser fuzz harness..." << std::endl;

    // Deterministic pseudo-random sequence for repeatability
    uint32_t state = 0x12345678;
    auto next_rand = [&state]() -> uint8_t {
        state = state * 1103515245 + 12345;
        return static_cast<uint8_t>((state >> 16) & 0xFF);
    };

    // 1. Fuzz unpack_packet_header on 1000 randomized buffers
    for (int i = 0; i < 1000; ++i) {
        const std::size_t len = (next_rand() % 128);
        std::string garbage(len, '\0');
        for (std::size_t j = 0; j < len; ++j) {
            garbage[j] = static_cast<char>(next_rand());
        }

        PacketHeader hdr;
        std::size_t hdr_len = 0;
        // MUST NEVER crash or throw
        unpack_packet_header(garbage, hdr, hdr_len);
    }

    // 2. Fuzz parse_frames on 1000 randomized frame sequences
    for (int i = 0; i < 1000; ++i) {
        const std::size_t len = (next_rand() % 256);
        std::string garbage(len, '\0');
        for (std::size_t j = 0; j < len; ++j) {
            garbage[j] = static_cast<char>(next_rand());
        }

        std::vector<Frame> frames;
        // MUST NEVER crash, hang, or throw
        parse_frames(garbage, frames);
    }

    // 3. Fuzz mutation of valid Initial packet
    const auto cid = ConnectionId::random(8);
    ProtectionKeys client_keys, server_keys;
    CryptoSuite::derive_initial_secrets(cid, client_keys, server_keys);

    PacketHeader hdr;
    hdr.is_long = true;
    hdr.type = PacketType::Initial;
    hdr.version = QUIC_VERSION_1;
    hdr.dcid = cid;
    hdr.scid = ConnectionId::random(8);
    hdr.packet_number = 1;
    hdr.packet_number_len = 4;

    std::string valid_pkt;
    CryptoSuite::protect_packet(client_keys, hdr, "Fuzz target sample payload 1234567890", valid_pkt);
    assert(!valid_pkt.empty());

    for (int i = 0; i < 500; ++i) {
        std::string mutated = valid_pkt;
        // Mutate random bytes
        const int num_mutations = (next_rand() % 5) + 1;
        for (int m = 0; m < num_mutations; ++m) {
            const std::size_t pos = next_rand() % mutated.size();
            mutated[pos] ^= static_cast<char>(next_rand() | 0x01);
        }

        PacketHeader dec_hdr;
        std::string dec_payload;
        // MUST cleanly reject invalid packets with false, never crash
        CryptoSuite::unprotect_packet(client_keys, dec_hdr, mutated, dec_payload);
    }

    std::cout << "  [PASS] Pre-authentication packet parser fuzz harness passed (2500 mutations)." << std::endl;
}

int main() {
    std::cout << "=== Running WaveX QUIC Transport Tests ===\n";
    try {
        test_varint();
        test_varint_edge_cases();
        test_connection_id();
        test_connection_id_boundaries();
        test_stream_id_allocation();
        test_rfc9001_appendix_a();
        test_frames();
        test_malformed_packets_and_fuzzing();
        test_quic_packet_fuzzer();
        test_packet_protection();
        test_rfc9002_loss_and_recovery();
        test_congestion_controller();
        test_quic_stream_async();
        test_quic_server_client_loopback();
        test_quic_protocol();
        test_quic_socket_acceptor_tcp_syntax();
        test_quic_socket_acceptor_coroutine();
        test_quic_stream_multiplexing();
        std::cout << "=== All QUIC Tests PASSED ===\n";
        return 0;
    } catch (const std::exception &ex) {
        std::cerr << "Exception in test_quic: " << ex.what() << "\n";
        return 1;
    }
}


