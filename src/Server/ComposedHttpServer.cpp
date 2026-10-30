// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file ComposedHttpServer.cpp
 * @brief Out-of-line ComposedHttpServer::run() (keeps the HTTP/2 + HTTP/3 handler instantiations out of every includer).
 */

#include <wavex/Server/ComposedHttpServer.hpp>

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
#include <wavex/Server/Server.hpp>

namespace wavex::server {

    void ComposedHttpServer::run() {
        h2_router_->freeze();
        h3_router_->freeze();

        if (!tls_enabled_ && !allow_insecure_) {
            throw std::runtime_error(
                "QUIC transport requires TLS 1.3. "
                "Call server.enable_tls(cert, key) before server.run().");
        }

        auto quic = std::make_unique<network::quic::QuicServer>(
            server_.io_context(), address_, port_);
        quic->set_max_field_section_size(max_field_section_size_);

        if (tls_enabled_) {
            quic->set_tls_credentials(tls_config_.cert_file, tls_config_.key_file);
        }

        quic->set_uni_stream_handler(
            [](std::shared_ptr<network::quic::QuicStream> stream)
        -> asio::awaitable<void> {
                if (!stream) co_return;
                const auto conn = stream->connection();
                if (!conn) co_return;
                auto session_ctx = std::static_pointer_cast<protos::http::http3::connection_context>(conn->user_context());
                if (!session_ctx) {
                    session_ctx = std::make_shared<protos::http::http3::connection_context>();
                    conn->set_user_context(session_ctx);
                }
                co_await protos::http::http3codec::session_handler::handle_unidirectional_stream(
                    std::move(stream), session_ctx);
            });

        quic->set_stream_handler(
            [this](std::shared_ptr<network::quic::QuicStream> stream)
        -> asio::awaitable<void> {
                if (!stream) co_return;
                if ((stream->stream_id() & 0x03) == 0x00) {
                    // WebTransport streams (WT_STREAM signal) go to their session, not to the router.
                    if (co_await protos::webtransport::dispatch_bidirectional_stream(stream)) co_return;
                    if (server_.pool().worker_count() == 0) {
                        server_.pool().start_pool();
                    }
                    server_.pool().spawn_coroutine(
                        server_.handle_connection_impl<protos::http::http3codec, engine::Http3Router>(
                            std::move(stream), *h3_router_));
                }
                co_return;
            });

        quic->start(); {
            std::lock_guard quic_lock(quic_mtx_);
            quic_server_ = std::move(quic);
        }
        log::info("[WaveX] ComposedHttpServer QUIC/UDP listener active on {}:{}", address_, port_);

        server_.run();

        stop_quic();
    }

} // namespace wavex::server
#endif // WAVEX_HAS_SSL
