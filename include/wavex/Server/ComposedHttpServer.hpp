// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file ComposedHttpServer.hpp
 * @brief High-level composed server running HTTP/1.1 & HTTP/2 over TCP/TLS and HTTP/3 over QUIC/UDP concurrently.
 */

#pragma once

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

#include <chrono>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

#include <wavex/Base/Logger.hpp>
#include <wavex/Network/QUIC.hpp>
#include <wavex/protos/http/http3codec.hpp>
#include <wavex/protos/webtransport/WebTransport.hpp>
#include <wavex/Engine/HttpRouter.hpp>
#include <wavex/Server/ServerAliases.hpp>
#include <wavex/Server/TlsConfig.hpp>

namespace wavex::server {
    /**
     * @class ComposedHttpServer
     * @brief High-level composed server running HTTP/1.1 & HTTP/2 over TCP/TLS and HTTP/3 over QUIC/UDP concurrently on the same port.
     */
    class ComposedHttpServer {
    public:
        // ─── 1. Nested Types & Definitions ───────────────────────────────────
        using Http2Router = engine::Http2Router;
        using Http3Router = engine::Http3Router;

    private:
        // ─── 2. Member Variables (Arranged for minimum padding) ──────────────
        Http2Router owned_h2_router_{};
        Http3Router owned_h3_router_{};
        Http2Router *h2_router_{nullptr}; // 8 bytes
        Http3Router *h3_router_{nullptr}; // 8 bytes
        std::unique_ptr<network::quic::QuicServer> quic_server_{nullptr}; // 8 bytes; guarded by quic_mtx_
        std::mutex quic_mtx_;                                             // run() installs it, stop()/exit() take it
        std::string address_{"0.0.0.0"}; // complex (32 bytes)
        TlsConfig tls_config_{}; // complex
        Http2Server server_; // complex
        uint64_t max_field_section_size_{65536}; // 8 bytes
        unsigned short port_{0}; // 2 bytes
        bool tls_enabled_{false}; // 1 byte
        bool allow_insecure_{false}; // 1 byte

    public:
        // ─── 3. Constructors & Destructor ────────────────────────────────────
        ComposedHttpServer(std::string address, const unsigned short port)
            : owned_h2_router_(),
              owned_h3_router_(),
              h2_router_(&owned_h2_router_),
              h3_router_(&owned_h3_router_),
              quic_server_(nullptr),
              address_(address),
              tls_config_(),
              server_(*h2_router_, std::move(address), port),
              port_(port),
              tls_enabled_(false),
              allow_insecure_(false) {
            server_.set_alt_svc_port(port_);
        }

        ComposedHttpServer(Http2Router &h2_router, Http3Router &h3_router,
                           std::string address, const unsigned short port)
            : owned_h2_router_(),
              owned_h3_router_(),
              h2_router_(&h2_router),
              h3_router_(&h3_router),
              quic_server_(nullptr),
              address_(address),
              tls_config_(),
              server_(*h2_router_, std::move(address), port),
              port_(port),
              tls_enabled_(false),
              allow_insecure_(false) {
            server_.set_alt_svc_port(port_);
        }

        ~ComposedHttpServer() = default;

        ComposedHttpServer(const ComposedHttpServer &) = delete;

        ComposedHttpServer &operator=(const ComposedHttpServer &) = delete;

        ComposedHttpServer(ComposedHttpServer &&) = delete;

        ComposedHttpServer &operator=(ComposedHttpServer &&) = delete;

        // ─── 4. Member Functions ─────────────────────────────────────────────
        [[nodiscard]] Http2Router &h2_router() noexcept { return *h2_router_; }
        [[nodiscard]] const Http2Router &h2_router() const noexcept { return *h2_router_; }
        [[nodiscard]] Http3Router &h3_router() noexcept { return *h3_router_; }
        [[nodiscard]] const Http3Router &h3_router() const noexcept { return *h3_router_; }
        [[nodiscard]] Http2Server &tcp_server() noexcept { return server_; }
        [[nodiscard]] const Http2Server &tcp_server() const noexcept { return server_; }

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

        void run() {
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

        // ─── Templated Router Convenience Methods ────────────────────────────
        template<typename Handler>
        ComposedHttpServer &get(const std::string_view pattern, Handler &&h) {
            auto h_copy = h;
            h2_router_->get(pattern, [h_copy](Http2Router::RequestType &req,
                                              Http2Router::ResponseType &res) -> asio::awaitable<void> {
                if constexpr (std::is_invocable_r_v<asio::awaitable<void>, decltype(h_copy), Http2Router::RequestType &,
                    Http2Router::ResponseType &>) {
                    co_await h_copy(req, res);
                } else {
                    h_copy(req, res);
                    co_return;
                }
            });
            h3_router_->get(pattern, [h = std::forward<Handler>(h)](Http3Router::RequestType &req,
                                                                    Http3Router::ResponseType &res) -> asio::awaitable<
                        void> {
                                if constexpr (std::is_invocable_r_v<asio::awaitable<void>, decltype(h),
                                    Http3Router::RequestType &, Http3Router::ResponseType &>) {
                                    co_await h(req, res);
                                } else {
                                    h(req, res);
                                    co_return;
                                }
                            });
            return *this;
        }

        template<typename Handler>
        ComposedHttpServer &post(const std::string_view pattern, Handler &&h) {
            auto h_copy = h;
            h2_router_->post(pattern, [h_copy](Http2Router::RequestType &req,
                                               Http2Router::ResponseType &res) -> asio::awaitable<void> {
                if constexpr (std::is_invocable_r_v<asio::awaitable<void>, decltype(h_copy), Http2Router::RequestType &,
                    Http2Router::ResponseType &>) {
                    co_await h_copy(req, res);
                } else {
                    h_copy(req, res);
                    co_return;
                }
            });
            h3_router_->post(
                pattern, [h = std::forward<Handler>(h)](Http3Router::RequestType &req,
                                                        Http3Router::ResponseType &res) -> asio::awaitable<void> {
                    if constexpr (std::is_invocable_r_v<asio::awaitable<void>, decltype(h), Http3Router::RequestType &,
                        Http3Router::ResponseType &>) {
                        co_await h(req, res);
                    } else {
                        h(req, res);
                        co_return;
                    }
                });
            return *this;
        }

        template<typename Handler>
        ComposedHttpServer &put(const std::string_view pattern, Handler &&h) {
            auto h_copy = h;
            h2_router_->put(pattern, [h_copy](Http2Router::RequestType &req,
                                              Http2Router::ResponseType &res) -> asio::awaitable<void> {
                if constexpr (std::is_invocable_r_v<asio::awaitable<void>, decltype(h_copy), Http2Router::RequestType &,
                    Http2Router::ResponseType &>) {
                    co_await h_copy(req, res);
                } else {
                    h_copy(req, res);
                    co_return;
                }
            });
            h3_router_->put(pattern, [h = std::forward<Handler>(h)](Http3Router::RequestType &req,
                                                                    Http3Router::ResponseType &res) -> asio::awaitable<
                        void> {
                                if constexpr (std::is_invocable_r_v<asio::awaitable<void>, decltype(h),
                                    Http3Router::RequestType &, Http3Router::ResponseType &>) {
                                    co_await h(req, res);
                                } else {
                                    h(req, res);
                                    co_return;
                                }
                            });
            return *this;
        }

        template<typename Handler>
        ComposedHttpServer &del(const std::string_view pattern, Handler &&h) {
            auto h_copy = h;
            h2_router_->del(pattern, [h_copy](Http2Router::RequestType &req,
                                              Http2Router::ResponseType &res) -> asio::awaitable<void> {
                if constexpr (std::is_invocable_r_v<asio::awaitable<void>, decltype(h_copy), Http2Router::RequestType &,
                    Http2Router::ResponseType &>) {
                    co_await h_copy(req, res);
                } else {
                    h_copy(req, res);
                    co_return;
                }
            });
            h3_router_->del(pattern, [h = std::forward<Handler>(h)](Http3Router::RequestType &req,
                                                                    Http3Router::ResponseType &res) -> asio::awaitable<
                        void> {
                                if constexpr (std::is_invocable_r_v<asio::awaitable<void>, decltype(h),
                                    Http3Router::RequestType &, Http3Router::ResponseType &>) {
                                    co_await h(req, res);
                                } else {
                                    h(req, res);
                                    co_return;
                                }
                            });
            return *this;
        }

        template<typename Handler>
        ComposedHttpServer &patch(const std::string_view pattern, Handler &&h) {
            auto h_copy = h;
            h2_router_->patch(pattern, [h_copy](Http2Router::RequestType &req,
                                                Http2Router::ResponseType &res) -> asio::awaitable<void> {
                if constexpr (std::is_invocable_r_v<asio::awaitable<void>, decltype(h_copy), Http2Router::RequestType &,
                    Http2Router::ResponseType &>) {
                    co_await h_copy(req, res);
                } else {
                    h_copy(req, res);
                    co_return;
                }
            });
            h3_router_->patch(
                pattern, [h = std::forward<Handler>(h)](Http3Router::RequestType &req,
                                                        Http3Router::ResponseType &res) -> asio::awaitable<void> {
                    if constexpr (std::is_invocable_r_v<asio::awaitable<void>, decltype(h), Http3Router::RequestType &,
                        Http3Router::ResponseType &>) {
                        co_await h(req, res);
                    } else {
                        h(req, res);
                        co_return;
                    }
                });
            return *this;
        }

        /**
         * @brief WebSocket endpoint on both routers: extended CONNECT over HTTP/2 (RFC 8441) and HTTP/3
         *        (RFC 9220). `h` receives the protocol-neutral session; use `h2`/`h3` overloads for the request.
         */
        ComposedHttpServer &websocket(const std::string_view pattern,
                                      std::function<asio::awaitable<void>(std::shared_ptr<protos::websocket::connection>)> h,
                                      const protos::websocket::options &opts = {}) {
            auto shared = std::make_shared<decltype(h)>(std::move(h));
            h2_router_->websocket(pattern, [shared](Http2Router::RequestType &,
                                                    std::shared_ptr<protos::websocket::connection> c)
                              -> asio::awaitable<void> { co_await (*shared)(std::move(c)); }, opts);
            h3_router_->websocket(pattern, [shared](Http3Router::RequestType &,
                                                    std::shared_ptr<protos::websocket::connection> c)
                              -> asio::awaitable<void> { co_await (*shared)(std::move(c)); }, opts);
            return *this;
        }

        /// WebTransport endpoint (HTTP/3 extended CONNECT with `:protocol = webtransport`).
        ComposedHttpServer &webtransport(const std::string_view pattern, Http3Router::WebTransportHandler h,
                                         protos::webtransport::options opts = {}) {
            h3_router_->webtransport(pattern, std::move(h), opts);
            return *this;
        }

        template<typename Handler>
        ComposedHttpServer &query(const std::string_view pattern, Handler &&h) {
            auto h_copy = h;
            h2_router_->query(pattern, [h_copy](Http2Router::RequestType &req,
                                                Http2Router::ResponseType &res) -> asio::awaitable<void> {
                if constexpr (std::is_invocable_r_v<asio::awaitable<void>, decltype(h_copy), Http2Router::RequestType &,
                    Http2Router::ResponseType &>) {
                    co_await h_copy(req, res);
                } else {
                    h_copy(req, res);
                    co_return;
                }
            });
            h3_router_->query(
                pattern, [h = std::forward<Handler>(h)](Http3Router::RequestType &req,
                                                        Http3Router::ResponseType &res) -> asio::awaitable<void> {
                    if constexpr (std::is_invocable_r_v<asio::awaitable<void>, decltype(h), Http3Router::RequestType &,
                        Http3Router::ResponseType &>) {
                        co_await h(req, res);
                    } else {
                        h(req, res);
                        co_return;
                    }
                });
            return *this;
        }
    };

    using composed_http_server = ComposedHttpServer;
} // namespace wavex::server

#endif // WAVEX_HAS_SSL
