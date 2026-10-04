/**
 * @file QuicClient.hpp
 * @brief Asynchronous QUIC client establishing connections over UDP.
 */

#pragma once

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

#include <array>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string_view>

#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>

#include <wavex/Network/QUIC/QuicConnection.hpp>
#include <wavex/Network/QUIC/QuicStream.hpp>

namespace wavex::network::quic {

    /**
     * @class QuicClient
     * @brief Asynchronous QUIC client establishing connections over UDP.
     */
    class QuicClient {
    private:
        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        asio::io_context &io_;
        asio::ip::udp::socket socket_;
        asio::ip::udp::endpoint server_endpoint_{};
        std::shared_ptr<QuicConnection> connection_{};
        mutable std::mutex mtx_{};
        std::array<uint8_t, 65536> recv_buf_{};
        bool connected_{false};

    public:
        // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
        explicit QuicClient(asio::io_context &io);
        ~QuicClient();

        // ─── 4. Member Functions & Friend Declarations (LAST) ──────────────
        asio::awaitable<bool> connect(std::string_view host, uint16_t port);
        std::shared_ptr<QuicStream> create_stream(bool bidirectional = true);
        void close();

    private:
        void do_receive();
        void flush_outbound();
    };

} // namespace wavex::network::quic

#endif // WAVEX_HAS_SSL
