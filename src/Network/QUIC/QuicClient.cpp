#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

#include <wavex/Network/QUIC/QuicClient.hpp>
#include <wavex/Network/QUIC/QuicCrypto.hpp>

#if defined(min)
#undef min
#endif
#if defined(max)
#undef max
#endif

#include <asio/as_tuple.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/steady_timer.hpp>
#include <asio/async_result.hpp>
#include <asio/post.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <utility>

namespace wavex::network::quic {

    QuicClient::QuicClient(asio::io_context &io)
        : io_(io), socket_(io) {
        asio::error_code ec;
        socket_.open(asio::ip::udp::v4(), ec);
        socket_.bind(asio::ip::udp::endpoint(asio::ip::udp::v4(), 0), ec);
    }

    QuicClient::~QuicClient() {
        close();
    }

    asio::awaitable<bool> QuicClient::connect(const std::string_view host, const uint16_t port) {
        wavex::log::info("[QuicClient] connect() called to {}:{}", host, port);
        asio::error_code ec;
        auto addr = asio::ip::make_address(host, ec);
        if (ec) co_return false;

        server_endpoint_ = asio::ip::udp::endpoint(addr, port);
        const ConnectionId client_cid = ConnectionId::random(8);
        const ConnectionId initial_peer_cid = ConnectionId::random(8);

        connection_ = std::make_shared<QuicConnection>(client_cid, initial_peer_cid, server_endpoint_, false,
                                                       io_.get_executor(), initial_peer_cid);
        connection_->set_sni_hostname(std::string(host));
        connection_->set_outbound_callback([this] {
            flush_outbound();
        });
        wavex::log::info("[QuicClient] connection created, initializing TLS...");

        connection_->set_stream_created_callback([this](std::shared_ptr<QuicStream> stream) {
            if (!stream) return;
            const uint64_t sid = stream->stream_id();
            // Server-initiated unidirectional stream (sid & 0x03 == 3) per RFC 9000 / RFC 9114
            if ((sid & 0x03) == 0x03) {
                asio::co_spawn(io_, [stream]() -> asio::awaitable<void> {
                    char buf[1024];
                    while (stream->is_open()) {
                        auto [ec, n] = co_await stream->async_read_some(
                            asio::buffer(buf), asio::as_tuple(asio::use_awaitable));
                        if (ec || n == 0) break;
                    }
                    co_return;
                }, asio::detached);
            }
        });

        // Initialize TLS handshake engine for client (ALPN h3, SNI, ClientHello)
        if (!connection_->init_tls_handshake_engine()) {
            wavex::log::error("[QuicClient] Failed to init TLS engine");
            co_return false;
        }
        wavex::log::info("[QuicClient] TLS engine initialized, starting handshake...");

        // Start the TLS handshake - this generates ClientHello and queues it
        connection_->run_tls_engine();
        wavex::log::info("[QuicClient] TLS engine started, flushing outbound...");

        // CRITICAL: Flush outbound to actually SEND the Initial packet via UDP
        flush_outbound();
        wavex::log::info("[QuicClient] Initial packet flushed, starting receive loop...");

        // Start receiving responses
        do_receive();

        if (connection_->is_connected()) {
            connected_ = true;
            co_return true;
        }

        asio::steady_timer timer(io_);
        timer.expires_after(std::chrono::seconds(5));

        connection_->set_connected_callback([&timer] {
            asio::error_code cancel_err;
            timer.cancel(cancel_err);
        });

        // Suspends until either the 5-second timer fires, or handshake completes and cancels the timer
        auto [wait_result] = co_await timer.async_wait(asio::as_tuple(asio::use_awaitable));
        (void)wait_result;

        connection_->set_connected_callback(nullptr);

        if (connection_->is_connected()) {
            connected_ = true;
            co_return true;
        }

        wavex::log::error("[QuicClient] Connection timeout waiting for handshake completion");
        co_return false;
    }

    std::shared_ptr<QuicStream> QuicClient::create_stream(const bool bidirectional) {
        if (!connection_) return nullptr;
        auto stream = connection_->create_stream(bidirectional);
        flush_outbound();
        return stream;
    }

    void QuicClient::close() {
        if (connection_) {
            connection_->close();
            flush_outbound();
        }
        asio::error_code ec;
        socket_.close(ec);
    }

    void QuicClient::do_receive() {
        socket_.async_receive_from(
            asio::buffer(recv_buf_), server_endpoint_,
            [this](const std::error_code ec, const std::size_t bytes_recvd) {
                if (ec || bytes_recvd == 0) return;
                wavex::log::debug("[QuicClient] Received {} bytes from server", bytes_recvd);
                const std::string_view datagram(reinterpret_cast<const char *>(recv_buf_.data()), bytes_recvd);
                if (connection_) {
                    connection_->handle_datagram(datagram);
                    flush_outbound();
                }
                do_receive();
            }
        );
    }

    void QuicClient::flush_outbound() {
        if (io_.get_executor().running_in_this_thread()) {
            if (!connection_ || !socket_.is_open()) return;
            auto datagrams = connection_->poll_outgoing_datagrams();
            for (auto &dgram: datagrams) {
                if (dgram.empty()) continue;
                auto buf = std::make_shared<std::string>(std::move(dgram));
                socket_.async_send_to(
                    asio::buffer(*buf), server_endpoint_,
                    [buf](std::error_code ec, std::size_t bytes_sent) {
                        if (ec && ec != asio::error::operation_aborted) {
                            wavex::log::warn("[QuicClient] send error: {}", ec.message());
                        } else {
                            wavex::log::debug("[QuicClient] Sent {} bytes to server", bytes_sent);
                        }
                    }
                );
            }
        } else {
            asio::post(io_, [this] {
                flush_outbound();
            });
        }
    }

} // namespace wavex::network::quic

#endif // WAVEX_HAS_SSL

