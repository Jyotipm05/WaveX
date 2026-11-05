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
#undef ERROR

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

#include <chrono>
#include <memory>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

#include <wavex/Network/QUIC.hpp>
#include <wavex/protos/http/http3codec.hpp>
#include <wavex/protos/webtransport/WebTransport.hpp>
#include <wavex/Engine/HttpRouter.hpp>
#include <wavex/Server/ComposedServer.hpp>

namespace wavex::server {

    namespace detail {
        /// Declared as the first base so the routers exist before ComposedServer takes references to them.
        struct OwnedHttpRouters {
            engine::Http2Router h2{};
            engine::Http3Router h3{};
        };
    } // namespace detail

    /**
     * @class ComposedHttpServer
     * @brief High-level composed server running HTTP/1.1 & HTTP/2 over TCP/TLS and HTTP/3 over QUIC/UDP concurrently on the same port.
     *
     * A `ComposedServer<Http2Router, Http3Router>` that owns its (dynamic) routers by default and registers
     * `get/post/...` on both. For compile-time or custom routers use `ComposedServer` directly.
     */
    class ComposedHttpServer : private detail::OwnedHttpRouters,
                               public ComposedServer<engine::Http2Router, engine::Http3Router> {
    public:
        using Base = ComposedServer<engine::Http2Router, engine::Http3Router>;
        using Http2Router = engine::Http2Router;
        using Http3Router = engine::Http3Router;

        ComposedHttpServer(std::string address, const unsigned short port)
            : OwnedHttpRouters(), Base(h2, h3, std::move(address), port) {
        }

        ComposedHttpServer(Http2Router &h2_router, Http3Router &h3_router, std::string address,
                           const unsigned short port)
            : OwnedHttpRouters(), Base(h2_router, h3_router, std::move(address), port) {
        }

        // ─── Templated Router Convenience Methods ────────────────────────────
        template<typename Handler>
        ComposedHttpServer &get(const std::string_view pattern, Handler &&h) {
            auto h_copy = h;
            h2_router().get(pattern, [h_copy](Http2Router::RequestType &req,
                                              Http2Router::ResponseType &res) -> wavex::task<void> {
                if constexpr (std::is_invocable_r_v<wavex::task<void>, decltype(h_copy), Http2Router::RequestType &,
                    Http2Router::ResponseType &>) {
                    co_await h_copy(req, res);
                } else {
                    h_copy(req, res);
                    co_return;
                }
            });
            h3_router().get(pattern, [h = std::forward<Handler>(h)](Http3Router::RequestType &req,
                                                                    Http3Router::ResponseType &res) -> wavex::task<
                        void> {
                                if constexpr (std::is_invocable_r_v<wavex::task<void>, decltype(h),
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
            h2_router().post(pattern, [h_copy](Http2Router::RequestType &req,
                                               Http2Router::ResponseType &res) -> wavex::task<void> {
                if constexpr (std::is_invocable_r_v<wavex::task<void>, decltype(h_copy), Http2Router::RequestType &,
                    Http2Router::ResponseType &>) {
                    co_await h_copy(req, res);
                } else {
                    h_copy(req, res);
                    co_return;
                }
            });
            h3_router().post(
                pattern, [h = std::forward<Handler>(h)](Http3Router::RequestType &req,
                                                        Http3Router::ResponseType &res) -> wavex::task<void> {
                    if constexpr (std::is_invocable_r_v<wavex::task<void>, decltype(h), Http3Router::RequestType &,
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
            h2_router().put(pattern, [h_copy](Http2Router::RequestType &req,
                                              Http2Router::ResponseType &res) -> wavex::task<void> {
                if constexpr (std::is_invocable_r_v<wavex::task<void>, decltype(h_copy), Http2Router::RequestType &,
                    Http2Router::ResponseType &>) {
                    co_await h_copy(req, res);
                } else {
                    h_copy(req, res);
                    co_return;
                }
            });
            h3_router().put(pattern, [h = std::forward<Handler>(h)](Http3Router::RequestType &req,
                                                                    Http3Router::ResponseType &res) -> wavex::task<
                        void> {
                                if constexpr (std::is_invocable_r_v<wavex::task<void>, decltype(h),
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
            h2_router().del(pattern, [h_copy](Http2Router::RequestType &req,
                                              Http2Router::ResponseType &res) -> wavex::task<void> {
                if constexpr (std::is_invocable_r_v<wavex::task<void>, decltype(h_copy), Http2Router::RequestType &,
                    Http2Router::ResponseType &>) {
                    co_await h_copy(req, res);
                } else {
                    h_copy(req, res);
                    co_return;
                }
            });
            h3_router().del(pattern, [h = std::forward<Handler>(h)](Http3Router::RequestType &req,
                                                                    Http3Router::ResponseType &res) -> wavex::task<
                        void> {
                                if constexpr (std::is_invocable_r_v<wavex::task<void>, decltype(h),
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
            h2_router().patch(pattern, [h_copy](Http2Router::RequestType &req,
                                                Http2Router::ResponseType &res) -> wavex::task<void> {
                if constexpr (std::is_invocable_r_v<wavex::task<void>, decltype(h_copy), Http2Router::RequestType &,
                    Http2Router::ResponseType &>) {
                    co_await h_copy(req, res);
                } else {
                    h_copy(req, res);
                    co_return;
                }
            });
            h3_router().patch(
                pattern, [h = std::forward<Handler>(h)](Http3Router::RequestType &req,
                                                        Http3Router::ResponseType &res) -> wavex::task<void> {
                    if constexpr (std::is_invocable_r_v<wavex::task<void>, decltype(h), Http3Router::RequestType &,
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
                                      std::function<wavex::task<void>(std::shared_ptr<protos::websocket::connection>)> h,
                                      const protos::websocket::options &opts = {}) {
            auto shared = std::make_shared<decltype(h)>(std::move(h));
            h2_router().websocket(pattern, [shared](Http2Router::RequestType &,
                                                    std::shared_ptr<protos::websocket::connection> c)
                              -> wavex::task<void> { co_await (*shared)(std::move(c)); }, opts);
            h3_router().websocket(pattern, [shared](Http3Router::RequestType &,
                                                    std::shared_ptr<protos::websocket::connection> c)
                              -> wavex::task<void> { co_await (*shared)(std::move(c)); }, opts);
            return *this;
        }

        /// WebTransport endpoint (HTTP/3 extended CONNECT with `:protocol = webtransport`).
        ComposedHttpServer &webtransport(const std::string_view pattern, Http3Router::WebTransportHandler h,
                                         const protos::webtransport::options opts = {}) {
            h3_router().webtransport(pattern, std::move(h), opts);
            return *this;
        }

        template<typename Handler>
        ComposedHttpServer &query(const std::string_view pattern, Handler &&h) {
            auto h_copy = h;
            h2_router().query(pattern, [h_copy](Http2Router::RequestType &req,
                                                Http2Router::ResponseType &res) -> wavex::task<void> {
                if constexpr (std::is_invocable_r_v<wavex::task<void>, decltype(h_copy), Http2Router::RequestType &,
                    Http2Router::ResponseType &>) {
                    co_await h_copy(req, res);
                } else {
                    h_copy(req, res);
                    co_return;
                }
            });
            h3_router().query(
                pattern, [h = std::forward<Handler>(h)](Http3Router::RequestType &req,
                                                        Http3Router::ResponseType &res) -> wavex::task<void> {
                    if constexpr (std::is_invocable_r_v<wavex::task<void>, decltype(h), Http3Router::RequestType &,
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
