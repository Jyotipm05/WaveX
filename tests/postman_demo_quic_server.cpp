/**
 * @file postman_demo_quic_server.cpp
 * @brief Interactive WaveX RFC 9000 & 9001 QUIC Dev Server for curl --http3, Wireshark, & Interop Testing.
 *
 * Configured via built-in WaveX CLI argument parser (wavex::cli::CliParser).
 *
 * Usage examples:
 *   ./wavex_postman_quic_server                       # QUIC server on udp://127.0.0.1:8443
 *   ./wavex_postman_quic_server --lan                 # QUIC server on LAN (0.0.0.0:8443)
 *   ./wavex_postman_quic_server -p 9443               # Custom UDP port
 *   ./wavex_postman_quic_server -c ssl/test.crt -k ssl/test.key
 *   ./wavex_postman_quic_server --help                # Show CLI options
 *
 * Ground-truth verification tooling:
 *   1. SSLKEYLOGFILE for Wireshark Decryption:
 *      $env:SSLKEYLOGFILE = "$PWD\sslkeylog.log"       (PowerShell)
 *      export SSLKEYLOGFILE="./sslkeylog.log"         (Bash)
 *
 *   2. Independent Client Interop:
 *      curl --http3 -v -k https://127.0.0.1:8443/
 *      curl --http3-only -v -k https://127.0.0.1:8443/
 */

#ifndef ASIO_HAS_CO_AWAIT
#define ASIO_HAS_CO_AWAIT 1
#endif

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <filesystem>
#include <csignal>

#include <wavex/wavex.hpp>
#include <wavex/Network/QUIC.hpp>
#include <asio/io_context.hpp>
#include <asio/signal_set.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/as_tuple.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/read.hpp>
#include <asio/write.hpp>
#include <asio/ip/address.hpp>

using namespace wavex;
namespace quic = wavex::network::quic;

// Helper to detect LAN IP address of current machine
inline std::string get_lan_ip() {
    try {
        asio::io_context ctx;
        asio::ip::udp::socket sock(ctx);
        sock.connect(asio::ip::udp::endpoint(asio::ip::make_address("8.8.8.8"), 53));
        const auto addr = sock.local_endpoint().address();
        if (addr.is_v4() && !addr.is_loopback()) {
            return addr.to_string();
        }
    } catch (...) {
    }
    return "";
}

asio::awaitable<void> handle_quic_stream(std::shared_ptr<quic::basic_quic_socket> sock) {
    try {
        std::array<char, 4096> buffer{};
        while (sock->is_open()) {
            std::error_code read_ec;
            auto [ec, n] = co_await sock->async_read_some(asio::buffer(buffer), asio::as_tuple(asio::use_awaitable));
            if (ec) {
                if (ec != asio::error::eof && ec != asio::error::operation_aborted) {
                    std::cout << "[QUIC-STREAM] Read ended: " << ec.message() << std::endl;
                }
                break;
            }

            const std::string_view req(buffer.data(), n);
            std::cout << "[QUIC-STREAM] Received " << n << " bytes: " << req.substr(0, std::min(n, std::size_t{80})) << std::endl;

            // Send back greeting / echo response
            const std::string resp = "HTTP/3 200 OK\r\nserver: WaveX-QUIC\r\ncontent-type: text/plain\r\ncontent-length: 33\r\n\r\nHello from WaveX QUIC Transport! 🚀";
            auto [write_ec, written] = co_await asio::async_write(*sock, asio::buffer(resp), asio::as_tuple(asio::use_awaitable));
            if (write_ec) {
                std::cout << "[QUIC-STREAM] Write error: " << write_ec.message() << std::endl;
                break;
            }

            std::error_code close_ec;
            sock->close(close_ec);
            break;
        }
    } catch (const std::exception &ex) {
        std::cerr << "[QUIC-STREAM] Exception: " << ex.what() << std::endl;
    }
    co_return;
}

int main(int argc, char *argv[]) {
    cli::CliParser parser("wavex_postman_quic_server", "Interactive WaveX RFC 9000 / 9001 QUIC Echo Server for Interop & Testing");

    parser.add_flag("lan", 'l', "Bind to all interfaces (0.0.0.0) instead of localhost only (127.0.0.1)")
          .add_option("port", 'p', "UDP Port number to listen on", "8443")
          .add_option("cert", 'c', "Path to TLS 1.3 certificate file (PEM format)", "ssl/test.crt")
          .add_option("key", 'k', "Path to TLS 1.3 private key file (PEM format)", "ssl/test.key");

    const auto parse_res = parser.parse(argc, argv);
    if (!parse_res.ok()) {
        if (parse_res.help_requested) {
            parser.print_help();
            return 0;
        }
        std::cerr << "Error: " << parse_res.error_message << "\n\n";
        parser.print_help();
        return 1;
    }

    const uint16_t port = static_cast<uint16_t>(parser.get_int("port", 8443));
    const bool is_lan = parser.get_bool("lan");
    const std::string cert_file = parser.get_string("cert");
    const std::string key_file = parser.get_string("key");

    std::string bind_ip = is_lan ? "0.0.0.0" : "127.0.0.1";
    const std::string lan_ip = get_lan_ip();

    std::cout << "\n======================================================================\n";
    std::cout << "  WaveX RFC 9000 & 9001 QUIC Dev Server (Interop & Verification)\n";
    std::cout << "======================================================================\n";
    std::cout << "  Listening Address : udp://" << bind_ip << ":" << port << "\n";
    if (is_lan && !lan_ip.empty()) {
        std::cout << "  LAN Access        : udp://" << lan_ip << ":" << port << "\n";
    }
    std::cout << "  TLS Certificate   : " << cert_file << "\n";
    std::cout << "  TLS Private Key   : " << key_file << "\n";
    std::cout << "  ALPN Supported    : h3, h3-29\n";

    if (const char *keylog = std::getenv("SSLKEYLOGFILE")) {
        std::cout << "  SSLKEYLOGFILE     : " << keylog << " (Wireshark keylog ACTIVE)\n";
    } else {
        std::cout << "  SSLKEYLOGFILE     : (Not set. Set SSLKEYLOGFILE for Wireshark decryption!)\n";
    }

    std::cout << "----------------------------------------------------------------------\n";
    std::cout << "  Verification Commands:\n";
    std::cout << "    1. Test via curl (HTTP/3):\n";
    std::cout << "       curl --http3 -v -k https://127.0.0.1:" << port << "/\n\n";
    std::cout << "    2. Test via ngtcp2 client (or quiche-client):\n";
    std::cout << "       ngtcp2-client 127.0.0.1 " << port << "\n\n";
    std::cout << "    3. Wireshark Decryption:\n";
    std::cout << "       Preferences -> Protocols -> TLS -> (Pre)-Master-Secret log filename\n";
    std::cout << "======================================================================\n" << std::endl;

    try {
        asio::io_context io;

        // Graceful shutdown on Ctrl+C / SIGINT / SIGTERM
        asio::signal_set signals(io, SIGINT, SIGTERM);
        signals.async_wait([&](std::error_code, int) {
            std::cout << "\n[QUIC-SERVER] Shutting down gracefully..." << std::endl;
            io.stop();
        });

        quic::endpoint ep(asio::ip::make_address(bind_ip), port);
        quic::acceptor acceptor(io, ep, cert_file, key_file);
        acceptor.listen();

        // Connection accept loop
        std::function<void()> do_accept;
        do_accept = [&]() {
            auto sock = std::make_shared<quic::basic_quic_socket>(io);
            acceptor.async_accept(*sock, [&, sock](std::error_code ec) {
                if (!ec) {
                    std::cout << "[QUIC-SERVER] Accepted connection/stream from " 
                              << sock->remote_endpoint().address().to_string() << ":" 
                              << sock->remote_endpoint().port() << std::endl;
                    asio::co_spawn(io, handle_quic_stream(sock), asio::detached);
                }
                if (acceptor.is_open()) {
                    do_accept();
                }
            });
        };

        do_accept();
        std::cout << "[QUIC-SERVER] Ready for incoming QUIC datagrams. Press Ctrl+C to stop.\n" << std::endl;
        io.run();

    } catch (const std::exception &ex) {
        std::cerr << "[QUIC-SERVER] Fatal error: " << ex.what() << std::endl;
        return 1;
    }

    std::cout << "[QUIC-SERVER] Stopped cleanly." << std::endl;
    return 0;
}
