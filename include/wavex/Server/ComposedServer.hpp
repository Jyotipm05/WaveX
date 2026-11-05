// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file ComposedServer.hpp
 * @brief HTTP/1.1 + HTTP/2 over TCP/TLS and HTTP/3 over QUIC/UDP on one port, for any pair of routers.
 *
 * `ComposedServer<R2, R3>` is router-agnostic: R2 serves the TCP side (HTTP/2) and R3 the QUIC side (HTTP/3);
 * both only need to satisfy `engine::route::router_type`. That makes it usable with the compile-time router:
 *
 * ```cpp
 * auto r2 = static_router<engine::Http2Proto>(get<"/hi">(hello));
 * auto r3 = static_router<engine::Http3Proto>(get<"/hi">(hello));
 * server::ComposedServer<decltype(r2), decltype(r3)> srv(r2, r3, "0.0.0.0", 8443);
 * srv.enable_tls("ssl/test.crt", "ssl/test.key");
 * srv.run();
 * ```
 *
 * The routers are borrowed and must outlive the server. `ComposedHttpServer` is this class plus owned
 * `HttpRouter`s and the `get/post/...` conveniences that register on both.
 */

#pragma once
#undef ERROR

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

#include <chrono>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <utility>

#include <wavex/Base/Executor.hpp>
#include <wavex/Base/Logger.hpp>
#include <wavex/Base/Task.hpp>
#include <wavex/Engine/HttpRouter.hpp>
#include <wavex/Network/QUIC.hpp>
#include <wavex/protos/http/http2codec.hpp>
#include <wavex/protos/http/http3codec.hpp>
#include <wavex/protos/webtransport/WebTransport.hpp>
#include <wavex/Server/ServerCore.hpp>
#include <wavex/Server/TlsConfig.hpp>

namespace wavex::server {

    template<typename R2, typename R3>
    class ComposedServer {
    public:
        using Http2Router = R2;
        using Http3Router = R3;
        using TcpServer = Server<protos::http::http2codec, R2>;

    private:
        R2 *h2_router_{nullptr};
        R3 *h3_router_{nullptr};
        std::unique_ptr<network::quic::QuicServer> quic_server_{nullptr}; // guarded by quic_mtx_
        std::mutex quic_mtx_;                                             // run() installs it, stop()/exit() take it
        std::string address_{"0.0.0.0"};
        TlsConfig tls_config_{};
        TcpServer server_;
        uint64_t max_field_section_size_{65536};
        unsigned short port_{0};
        bool tls_enabled_{false};
        bool allow_insecure_{false};

    public:
        ComposedServer(R2 &h2_router, R3 &h3_router, std::string address, const unsigned short port)
            : h2_router_(&h2_router),
              h3_router_(&h3_router),
              address_(address),
              server_(*h2_router_, std::move(address), port),
              port_(port) {
            server_.set_alt_svc_port(port_);
        }

        ~ComposedServer() = default;

        ComposedServer(const ComposedServer &) = delete;
        ComposedServer &operator=(const ComposedServer &) = delete;
        ComposedServer(ComposedServer &&) = delete;
        ComposedServer &operator=(ComposedServer &&) = delete;

        [[nodiscard]] R2 &h2_router() noexcept { return *h2_router_; }
        [[nodiscard]] const R2 &h2_router() const noexcept { return *h2_router_; }
        [[nodiscard]] R3 &h3_router() noexcept { return *h3_router_; }
        [[nodiscard]] const R3 &h3_router() const noexcept { return *h3_router_; }
        [[nodiscard]] TcpServer &tcp_server() noexcept { return server_; }
        [[nodiscard]] const TcpServer &tcp_server() const noexcept { return server_; }

        void enable_tls(std::string cert_file = "ssl/test.crt",
                        std::string key_file = "ssl/test.key") {
            TlsConfig cfg;
            cfg.cert_file = std::move(cert_file);
            cfg.key_file = std::move(key_file);
            enable_tls(std::move(cfg));
        }

        void enable_tls(TlsConfig config) {
            tls_config_ = std::move(config);
            tls_enabled_ = true;
            server_.enable_tls(tls_config_);
            tls_config_ = server_.tls_config();
            std::lock_guard quic_lock(quic_mtx_);
            if (quic_server_) {
                quic_server_->set_tls_credentials(tls_config_.cert_file, tls_config_.key_file);
            }
        }

        [[nodiscard]] bool is_tls_enabled() const noexcept { return tls_enabled_ || server_.is_tls_enabled(); }
        [[nodiscard]] bool is_acceptor_open() const noexcept { return server_.is_acceptor_open(); }
        [[nodiscard]] static bool is_http3_enabled() noexcept { return true; }

        void allow_insecure(const bool allow = true) noexcept {
            allow_insecure_ = allow;
            server_.allow_insecure(allow);
        }

        void set_max_field_section_size(const uint64_t max_size) noexcept {
            max_field_section_size_ = max_size;
            std::lock_guard quic_lock(quic_mtx_);
            if (quic_server_) {
                quic_server_->set_max_field_section_size(max_size);
            }
            protos::http::http3codec::set_default_max_field_section_size(max_size);
        }

        [[nodiscard]] auto max_field_section_size() const noexcept -> uint64_t {
            return max_field_section_size_;
        }

        /// Runs the TCP/TLS server and the QUIC listener until stopped.
        void run() {
            h2_router_->freeze();
            h3_router_->freeze();

            if (!tls_enabled_ && !allow_insecure_) {
                throw std::runtime_error(
                    "QUIC transport requires TLS 1.3. "
                    "Call server.enable_tls(cert, key) before server.run().");
            }

            auto quic = std::make_unique<network::quic::QuicServer>(server_.executor(), address_, port_);
            quic->set_max_field_section_size(max_field_section_size_);

            if (tls_enabled_) {
                quic->set_tls_credentials(tls_config_.cert_file, tls_config_.key_file);
            }

            quic->set_uni_stream_handler(
                [](std::shared_ptr<network::quic::QuicStream> stream) -> wavex::task<void> {
                    if (!stream) co_return;
                    const auto conn = stream->connection();
                    if (!conn) co_return;
                    // The control/QPACK uni streams of one connection arrive concurrently; the connection creates
                    // the shared context exactly once under its own lock.
                    const auto session_ctx = std::static_pointer_cast<protos::http::http3::connection_context>(
                        conn->user_context_or_create([] {
                            return std::make_shared<protos::http::http3::connection_context>();
                        }));
                    co_await protos::http::http3codec::session_handler::handle_unidirectional_stream(
                        std::move(stream), session_ctx);
                });

            quic->set_stream_handler(
                [this](std::shared_ptr<network::quic::QuicStream> stream) -> wavex::task<void> {
                    if (!stream) co_return;
                    if ((stream->stream_id() & 0x03) == 0x00) {
                        // WebTransport streams (WT_STREAM signal) go to their session, not to the router.
                        if (co_await protos::webtransport::dispatch_bidirectional_stream(stream)) co_return;
                        if (server_.pool().worker_count() == 0) {
                            server_.pool().start_pool();
                        }
                        server_.pool().spawn_coroutine(
                            server_.template handle_connection_impl<protos::http::http3codec, R3>(
                                std::move(stream), *h3_router_));
                    }
                    co_return;
                });

            quic->start();
            {
                std::lock_guard quic_lock(quic_mtx_);
                quic_server_ = std::move(quic);
            }
            log::info("[WaveX] ComposedServer QUIC/UDP listener active on {}:{}", address_, port_);

            server_.run();

            stop_quic();
        }

        void stop_quic() {
            std::unique_ptr<network::quic::QuicServer> quic; {
                std::lock_guard quic_lock(quic_mtx_);
                quic = std::move(quic_server_);
            }
            if (quic) quic->stop();
        }

        void stop() {
            stop_quic();
            server_.stop();
        }

        void exit(const std::chrono::milliseconds timeout = std::chrono::seconds(10)) {
            stop_quic();
            server_.exit(timeout);
        }

        void shutdown(const std::chrono::milliseconds timeout = std::chrono::seconds(10)) {
            exit(timeout);
        }

        [[nodiscard]] asio::io_context &io_context() noexcept { return server_.io_context(); }
        [[nodiscard]] wavex::executor executor() noexcept { return server_.executor(); }

    };

    // The default router pair is instantiated once in ComposedHttpServer.cpp (its run() pulls in the HTTP/2 and
    // HTTP/3 connection handlers, ~10k symbols), not in every includer.
    extern template class ComposedServer<engine::Http2Router, engine::Http3Router>;

} // namespace wavex::server

#endif // WAVEX_HAS_SSL
