/**
 * @file QuicClient.hpp
 * @brief Asynchronous QUIC client establishing connections over UDP.
 */

#pragma once

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

#include <array>
#include <memory>
#include <mutex>
#include <string_view>

#include <asio/awaitable.hpp>
#include <wavex/Base/Task.hpp>
#include <asio/ip/udp.hpp>

#include <wavex/Base/Executor.hpp>
#include <wavex/Network/QUIC/QuicConnection.hpp>
#include <wavex/Network/QUIC/QuicStream.hpp>

namespace wavex::network::quic {
    /**
     * @class QuicClient
     * @brief Asynchronous QUIC client establishing connections over UDP.
     */
    class QuicClient {
        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        wavex::executor ex_;
        asio::ip::udp::socket socket_;
        asio::ip::udp::endpoint server_endpoint_{};
        asio::ip::udp::endpoint recv_endpoint_{}; // sender of the last datagram; never used for sending
        std::shared_ptr<QuicConnection> connection_{};
        mutable std::mutex mtx_{};
        std::array<uint8_t, 65536> recv_buf_{};
        bool connected_{false};
        bool verify_peer_{true};

    public:
        // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
        explicit QuicClient(const wavex::executor &ex);

        explicit QuicClient(asio::io_context &io) : QuicClient(wavex::executor_of(io)) {}

        ~QuicClient();

        // ─── 4. Member Functions & Friend Declarations (LAST) ──────────────
        auto connect(std::string_view host, uint16_t port) -> wavex::task<bool>;

        auto create_stream(bool bidirectional = true) -> std::shared_ptr<QuicStream>;

        void close();

        /// Verify the server certificate (default). Only disable for local testing with self-signed certs.
        void set_verify_peer(const bool verify) noexcept { verify_peer_ = verify; }

    private:
        void do_receive();

        void flush_outbound();
    };
} // namespace wavex::network::quic

#endif // WAVEX_HAS_SSL
