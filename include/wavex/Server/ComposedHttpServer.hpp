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
#include <wavex/Utils/FsUtils.hpp>
#include <wavex/Network/QUIC.hpp>
#include <wavex/protos/http/http3codec.hpp>
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
        Http2Router *h2_router_{nullptr};                     // 8 bytes
        Http3Router *h3_router_{nullptr};                     // 8 bytes
        std::unique_ptr<network::quic::QuicServer> quic_server_{nullptr}; // 8 bytes
        std::string address_{"0.0.0.0"};                      // complex (32 bytes)
        TlsConfig tls_config_{};                              // complex
        Http2Server server_;                                  // complex
        unsigned short port_{0};                              // 2 bytes
        bool tls_enabled_{false};                             // 1 byte
        bool allow_insecure_{false};                          // 1 byte

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
            tls_config_.cert_file = std::move(cert_file);
            tls_config_.key_file = std::move(key_file);
            tls_enabled_ = true;
            server_.enable_tls(tls_config_);
        }

        void enable_tls(TlsConfig config) {
            tls_config_ = std::move(config);
            tls_enabled_ = true;
            server_.enable_tls(tls_config_);
        }

        [[nodiscard]] bool is_tls_enabled() const noexcept { return tls_enabled_ || server_.is_tls_enabled(); }
        [[nodiscard]] bool is_acceptor_open() const noexcept { return server_.is_acceptor_open(); }
        [[nodiscard]] bool is_http3_enabled() const noexcept { return true; }

        void allow_insecure(bool allow = true) noexcept {
            allow_insecure_ = allow;
            server_.allow_insecure(allow);
        }

        void run() {
            h2_router_->freeze();
            h3_router_->freeze();

            if (!tls_enabled_ && !allow_insecure_) {
                throw std::runtime_error(
                    "QUIC transport requires TLS 1.3. "
                    "Call server.enable_tls(cert, key) before server.run().");
            }

            quic_server_ = std::make_unique<network::quic::QuicServer>(
                server_.io_context(), address_, port_);

            if (tls_enabled_) {
                std::string cert_path = tls_config_.cert_file;
                std::string key_path = tls_config_.key_file;
                std::error_code ec;
                if (!wavex::utils::fs_utils::exists(cert_path, ec)) {
#ifdef PROJECT_DIR
                    std::string alt = std::string(PROJECT_DIR) + "/" + cert_path;
                    if (wavex::utils::fs_utils::exists(alt, ec)) cert_path = alt;
#endif
                    if (!wavex::utils::fs_utils::exists(cert_path, ec) &&
                        wavex::utils::fs_utils::exists("../" + tls_config_.cert_file, ec)) {
                        cert_path = "../" + tls_config_.cert_file;
                    }
                }
                if (!wavex::utils::fs_utils::exists(key_path, ec)) {
#ifdef PROJECT_DIR
                    std::string alt = std::string(PROJECT_DIR) + "/" + key_path;
                    if (wavex::utils::fs_utils::exists(alt, ec)) key_path = alt;
#endif
                    if (!wavex::utils::fs_utils::exists(key_path, ec) &&
                        wavex::utils::fs_utils::exists("../" + tls_config_.key_file, ec)) {
                        key_path = "../" + tls_config_.key_file;
                    }
                }
                quic_server_->set_tls_credentials(std::move(cert_path), std::move(key_path));
            }

            quic_server_->set_stream_handler(
                [this](std::shared_ptr<network::quic::QuicStream> stream)
                    -> asio::awaitable<void> {
                    if (!stream) co_return;
                    if ((stream->stream_id() & 0x03) == 0x00) {
                        if (server_.pool().worker_count() == 0) {
                            server_.pool().start_pool();
                        }
                        server_.pool().spawn_coroutine(
                            server_.handle_connection_impl<protos::http::http3codec, engine::Http3Router>(
                                std::move(stream), *h3_router_));
                    }
                    co_return;
                });

            quic_server_->start();
            wavex::log::info("[WaveX] ComposedHttpServer QUIC/UDP listener active on {}:{}", address_, port_);

            server_.run();

            if (quic_server_) {
                quic_server_->stop();
                quic_server_.reset();
            }
        }

        void stop() {
            if (quic_server_) {
                quic_server_->stop();
                quic_server_.reset();
            }
            server_.stop();
        }

        void exit(std::chrono::milliseconds timeout = std::chrono::seconds(10)) {
            if (quic_server_) {
                quic_server_->stop();
                quic_server_.reset();
            }
            server_.exit(timeout);
        }

        void shutdown(std::chrono::milliseconds timeout = std::chrono::seconds(10)) {
            exit(timeout);
        }

        [[nodiscard]] asio::io_context &io_context() noexcept { return server_.io_context(); }

        // ─── Templated Router Convenience Methods ────────────────────────────
        template<typename Handler>
        ComposedHttpServer &get(const std::string_view pattern, Handler &&h) {
            auto h_copy = h;
            h2_router_->get(pattern, [h_copy](Http2Router::RequestType &req, Http2Router::ResponseType &res) -> asio::awaitable<void> {
                if constexpr (std::is_invocable_r_v<asio::awaitable<void>, decltype(h_copy), Http2Router::RequestType &, Http2Router::ResponseType &>) {
                    co_await h_copy(req, res);
                } else {
                    h_copy(req, res);
                    co_return;
                }
            });
            h3_router_->get(pattern, [h = std::forward<Handler>(h)](Http3Router::RequestType &req, Http3Router::ResponseType &res) -> asio::awaitable<void> {
                if constexpr (std::is_invocable_r_v<asio::awaitable<void>, decltype(h), Http3Router::RequestType &, Http3Router::ResponseType &>) {
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
            h2_router_->post(pattern, [h_copy](Http2Router::RequestType &req, Http2Router::ResponseType &res) -> asio::awaitable<void> {
                if constexpr (std::is_invocable_r_v<asio::awaitable<void>, decltype(h_copy), Http2Router::RequestType &, Http2Router::ResponseType &>) {
                    co_await h_copy(req, res);
                } else {
                    h_copy(req, res);
                    co_return;
                }
            });
            h3_router_->post(pattern, [h = std::forward<Handler>(h)](Http3Router::RequestType &req, Http3Router::ResponseType &res) -> asio::awaitable<void> {
                if constexpr (std::is_invocable_r_v<asio::awaitable<void>, decltype(h), Http3Router::RequestType &, Http3Router::ResponseType &>) {
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
            h2_router_->put(pattern, [h_copy](Http2Router::RequestType &req, Http2Router::ResponseType &res) -> asio::awaitable<void> {
                if constexpr (std::is_invocable_r_v<asio::awaitable<void>, decltype(h_copy), Http2Router::RequestType &, Http2Router::ResponseType &>) {
                    co_await h_copy(req, res);
                } else {
                    h_copy(req, res);
                    co_return;
                }
            });
            h3_router_->put(pattern, [h = std::forward<Handler>(h)](Http3Router::RequestType &req, Http3Router::ResponseType &res) -> asio::awaitable<void> {
                if constexpr (std::is_invocable_r_v<asio::awaitable<void>, decltype(h), Http3Router::RequestType &, Http3Router::ResponseType &>) {
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
            h2_router_->del(pattern, [h_copy](Http2Router::RequestType &req, Http2Router::ResponseType &res) -> asio::awaitable<void> {
                if constexpr (std::is_invocable_r_v<asio::awaitable<void>, decltype(h_copy), Http2Router::RequestType &, Http2Router::ResponseType &>) {
                    co_await h_copy(req, res);
                } else {
                    h_copy(req, res);
                    co_return;
                }
            });
            h3_router_->del(pattern, [h = std::forward<Handler>(h)](Http3Router::RequestType &req, Http3Router::ResponseType &res) -> asio::awaitable<void> {
                if constexpr (std::is_invocable_r_v<asio::awaitable<void>, decltype(h), Http3Router::RequestType &, Http3Router::ResponseType &>) {
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
            h2_router_->patch(pattern, [h_copy](Http2Router::RequestType &req, Http2Router::ResponseType &res) -> asio::awaitable<void> {
                if constexpr (std::is_invocable_r_v<asio::awaitable<void>, decltype(h_copy), Http2Router::RequestType &, Http2Router::ResponseType &>) {
                    co_await h_copy(req, res);
                } else {
                    h_copy(req, res);
                    co_return;
                }
            });
            h3_router_->patch(pattern, [h = std::forward<Handler>(h)](Http3Router::RequestType &req, Http3Router::ResponseType &res) -> asio::awaitable<void> {
                if constexpr (std::is_invocable_r_v<asio::awaitable<void>, decltype(h), Http3Router::RequestType &, Http3Router::ResponseType &>) {
                    co_await h(req, res);
                } else {
                    h(req, res);
                    co_return;
                }
            });
            return *this;
        }

        template<typename Handler>
        ComposedHttpServer &query(const std::string_view pattern, Handler &&h) {
            auto h_copy = h;
            h2_router_->query(pattern, [h_copy](Http2Router::RequestType &req, Http2Router::ResponseType &res) -> asio::awaitable<void> {
                if constexpr (std::is_invocable_r_v<asio::awaitable<void>, decltype(h_copy), Http2Router::RequestType &, Http2Router::ResponseType &>) {
                    co_await h_copy(req, res);
                } else {
                    h_copy(req, res);
                    co_return;
                }
            });
            h3_router_->query(pattern, [h = std::forward<Handler>(h)](Http3Router::RequestType &req, Http3Router::ResponseType &res) -> asio::awaitable<void> {
                if constexpr (std::is_invocable_r_v<asio::awaitable<void>, decltype(h), Http3Router::RequestType &, Http3Router::ResponseType &>) {
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
