/**
 * @file QuicServer.hpp
 * @brief Asynchronous UDP server hosting QUIC connections and dispatching streams.
 */

#pragma once

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>

#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>

#include <wavex/Network/QUIC/ConnectionId.hpp>
#include <wavex/Network/QUIC/QuicConnection.hpp>
#include <wavex/Network/QUIC/QuicStream.hpp>

namespace wavex::network::quic {

    /**
     * @class QuicServer
     * @brief Asynchronous UDP server hosting QUIC connections and dispatching streams.
     */
    class QuicServer {
    public:
        // ─── 1. Nested Types & Definitions (TOP) ───────────────────────────
        using StreamHandler = std::function<asio::awaitable<void>(std::shared_ptr<QuicStream>)>;
        using UniStreamHandler = std::function<asio::awaitable<void>(std::shared_ptr<QuicStream>)>;

    private:
        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        asio::io_context &io_;
        asio::ip::udp::socket socket_;
        asio::ip::udp::endpoint sender_endpoint_{};
        std::unordered_map<ConnectionId, std::shared_ptr<QuicConnection>> connections_{};
        mutable std::mutex mtx_{};
        std::array<uint8_t, 65536> recv_buf_{};
        StreamHandler stream_handler_{};
        UniStreamHandler uni_stream_handler_{};
        std::string tls_cert_file_{};
        std::string tls_key_file_{};
        std::atomic<bool> stopped_{false};
        bool running_{false};

    public:
        // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
        QuicServer(asio::io_context &io, uint16_t port);
        QuicServer(asio::io_context &io, std::string_view host, uint16_t port);
        ~QuicServer();

        // ─── 4. Member Functions & Friend Declarations (LAST) ──────────────
        void set_stream_handler(StreamHandler handler) {
            std::lock_guard lock(mtx_);
            stream_handler_ = std::move(handler);
        }

        void set_uni_stream_handler(UniStreamHandler handler) {
            std::lock_guard lock(mtx_);
            uni_stream_handler_ = std::move(handler);
        }

        void set_tls_credentials(std::string cert_file, std::string key_file) {
            std::lock_guard lock(mtx_);
            tls_cert_file_ = std::move(cert_file);
            tls_key_file_ = std::move(key_file);
        }

        void start();
        void stop();

        [[nodiscard]] bool is_open() const noexcept { return socket_.is_open(); }

        [[nodiscard]] std::size_t connection_count() const noexcept {
            std::lock_guard lock(mtx_);
            return connections_.size();
        }

        [[nodiscard]] uint16_t local_port() const noexcept {
            asio::error_code ec;
            auto ep = socket_.local_endpoint(ec);
            return ec ? 0 : ep.port();
        }

    private:
        void do_receive();
        void flush_outbound(const std::shared_ptr<QuicConnection> &conn);
    };

} // namespace wavex::network::quic

#endif // WAVEX_HAS_SSL
