/**
 * @file QuicClient.hpp
 * @brief Asynchronous QUIC client establishing connections over UDP.
 */

#pragma once

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

#include <array>
#include <functional>
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
        std::function<void(std::shared_ptr<QuicStream>)> peer_uni_handler_{};
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

        /// Connect to `address`:`port`, using `server_name` for SNI and certificate verification.
        auto connect(std::string_view server_name, const asio::ip::address &address, uint16_t port)
            -> wavex::task<bool>;

        auto create_stream(bool bidirectional = true) -> std::shared_ptr<QuicStream>;

        void close();

        /// True while the QUIC handshake is complete and the connection has not been closed or lost.
        [[nodiscard]] bool is_connected() const noexcept { return connected_ && connection_ && connection_->is_connected(); }

        /**
         * @brief Take over server-initiated unidirectional streams (HTTP/3 control and QPACK streams).
         *
         * Without a handler such streams are read and discarded. The handler runs on the client's executor and
         * owns the stream; set it before `connect()`.
         */
        void set_peer_uni_stream_handler(std::function<void(std::shared_ptr<QuicStream>)> handler) {
            peer_uni_handler_ = std::move(handler);
        }

        /// Verify the server certificate (default). Only disable for local testing with self-signed certs.
        void set_verify_peer(const bool verify) noexcept { verify_peer_ = verify; }

    private:
        void do_receive();

        void flush_outbound();
    };
} // namespace wavex::network::quic

#endif // WAVEX_HAS_SSL
