/**
 * @file QuicListener.hpp
 * @brief QUIC/UDP transport listener driven by a generic server host.
 *
 * `Host` is any server exposing: address(), port(), io_context(), is_tls_enabled(), tls_config(),
 * allow_insecure_transports() and spawn_connection(stream). The host never names QUIC; it holds this
 * object through network::TransportListener.
 */

#pragma once

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

#include <memory>
#include <mutex>
#include <stdexcept>
#include <utility>
#include <asio/awaitable.hpp>
#include <wavex/Base/Logger.hpp>
#include <wavex/Network/QUIC/QuicServer.hpp>
#include <wavex/Network/TransportListener.hpp>

namespace wavex::network::quic {
    template<typename Host>
    class QuicTransportListener final : public TransportListener {
    public:
        explicit QuicTransportListener(Host &host) : host_(host) {
        }

        ~QuicTransportListener() override {
            stop();
        }

        QuicTransportListener(const QuicTransportListener &) = delete;
        QuicTransportListener &operator=(const QuicTransportListener &) = delete;

        void start() override {
            if (!host_.is_tls_enabled() && !host_.allow_insecure_transports()) {
                throw std::runtime_error(
                    "QUIC transport requires TLS 1.3. "
                    "Call server.enable_tls(cert, key) before server.run().");
            }
            auto quic = std::make_unique<QuicServer>(host_.io_context(), host_.address(), host_.port());
            if (host_.is_tls_enabled()) {
                quic->set_tls_credentials(host_.tls_config().cert_file, host_.tls_config().key_file);
            }
            quic->set_stream_handler(
                [this](std::shared_ptr<QuicStream> stream) -> asio::awaitable<void> {
                    if (!stream) co_return;
                    // Client-initiated bidirectional streams carry requests.
                    if ((stream->stream_id() & 0x03) == 0x00) {
                        host_.spawn_connection(std::move(stream));
                    }
                    co_return;
                });
            quic->start();
            {
                std::lock_guard lock(mtx_);
                quic_ = std::move(quic);
            }
            wavex::log::info("[WaveX] QUIC/UDP listener active on {}:{}", host_.address(), host_.port());
        }

        void stop() noexcept override {
            std::unique_ptr<QuicServer> quic; {
                std::lock_guard lock(mtx_);
                quic = std::move(quic_);
            }
            if (quic) quic->stop();
        }

    private:
        Host &host_;
        std::mutex mtx_;
        std::unique_ptr<QuicServer> quic_;
    };
} // namespace wavex::network::quic

#endif // WAVEX_HAS_SSL
