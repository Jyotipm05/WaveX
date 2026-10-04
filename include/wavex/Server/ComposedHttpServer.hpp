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

#include <chrono>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

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
        Http2Router *h2_router_{nullptr};
        Http3Router *h3_router_{nullptr};
        Http2Server server_;

    public:
        // ─── 3. Constructors & Destructor ────────────────────────────────────
        ComposedHttpServer(std::string address, const unsigned short port)
            : owned_h2_router_(),
              owned_h3_router_(),
              h2_router_(&owned_h2_router_),
              h3_router_(&owned_h3_router_),
              server_(*h2_router_, std::move(address), port) {
            server_.enable_http3(*h3_router_);
        }

        ComposedHttpServer(Http2Router &h2_router, Http3Router &h3_router,
                           std::string address, const unsigned short port)
            : owned_h2_router_(),
              owned_h3_router_(),
              h2_router_(&h2_router),
              h3_router_(&h3_router),
              server_(*h2_router_, std::move(address), port) {
            server_.enable_http3(*h3_router_);
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
            server_.enable_tls(std::move(cert_file), std::move(key_file));
        }

        void enable_tls(TlsConfig config) {
            server_.enable_tls(std::move(config));
        }

        [[nodiscard]] bool is_tls_enabled() const noexcept { return server_.is_tls_enabled(); }
        [[nodiscard]] bool is_acceptor_open() const noexcept { return server_.is_acceptor_open(); }
        [[nodiscard]] bool is_http3_enabled() const noexcept { return server_.is_http3_enabled(); }

        void allow_insecure(bool allow = true) noexcept {
            server_.allow_insecure(allow);
        }

        void run() {
            server_.run();
        }

        void stop() {
            server_.stop();
        }

        void exit(std::chrono::milliseconds timeout = std::chrono::seconds(10)) {
            server_.exit(timeout);
        }

        void shutdown(std::chrono::milliseconds timeout = std::chrono::seconds(10)) {
            server_.shutdown(timeout);
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
