// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file HttpRouter.hpp
 * @brief HTTP-specific router with GET/POST/PUT/DEL convenience methods.
 *
 * Derives from Router<HttpProto> to add HTTP method shortcuts and static chain integration
 * while keeping the base router protocol-agnostic.
 */

#pragma once

#include <wavex/Engine/Router.hpp>
#include <wavex/protos/http/Methods.hpp>
#include <wavex/protos/http/HttpRequest.hpp>
#include <wavex/protos/http/HttpResponse.hpp>
#include <wavex/protos/http/http2codec.hpp>
#include <wavex/protos/http/http3codec.hpp>
#include <wavex/protos/websocket/WebSocket.hpp>
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
#include <wavex/protos/webtransport/WebTransport.hpp>
#endif

#undef DELETE

namespace wavex::engine {
    /**
     * @struct HttpProto
     * @brief Protocol adapter for HTTP — provides the method, request, and response types for a specific Codec.
     * @tparam Codec HTTP protocol codec type (defaults to http1codec).
     */
    template<typename Codec = protos::http::http1codec>
    struct HttpProto {
        using method = protos::http::method;
        using request = protos::http::HttpRequest<Codec>;
        using response = protos::http::HttpResponse<Codec>;
    };

    /// Concrete default HTTP/1.x protocol adapter aliases
    using Http1Proto = HttpProto<protos::http::http1codec>;
    using http1proto = Http1Proto;

    /// Concrete HTTP/2 protocol adapter aliases
    using Http2Proto = HttpProto<protos::http::http2codec>;
    using http2proto = Http2Proto;

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
    /// Concrete HTTP/3 protocol adapter aliases
    using Http3Proto = HttpProto<protos::http::http3codec>;
    using http3proto = Http3Proto;
#endif

    /**
     * @class HttpRouter
     * @brief HTTP-specific convenience wrapper around Router<HttpProto<Codec>>.
     * @tparam Codec HTTP protocol codec type (defaults to http1codec).
     */
    template<typename Codec = protos::http::http1codec>
    class HttpRouter : public Router<HttpProto<Codec> > {
    public:
        using Base = Router<HttpProto<Codec> >;
        using typename Base::Handler;
        using typename Base::NotFoundHandler;
        using typename Base::MiddlewareFn;
        using Base::route;
        using Base::use;
        using Base::resolve;
        using Base::not_found;
        using Base::not_found_page;
        using Base::not_found_handler;

        HttpRouter() = default;

        HttpRouter(const HttpRouter &) = delete;

        HttpRouter &operator=(const HttpRouter &) = delete;

        HttpRouter(HttpRouter &&) noexcept = default;

        HttpRouter &operator=(HttpRouter &&) noexcept = default;

        /**
         * @brief Singleton instance getter for HttpRouter.
         * @return Reference to the process-wide HttpRouter instance.
         */
        static HttpRouter &instance() {
            static HttpRouter s_instance;
            return s_instance;
        }

        /**
         * @brief Creates a distinct, local HttpRouter instance.
         * @return A new local HttpRouter instance independent of the process-wide singleton.
         */
        static auto make_instance() -> HttpRouter {
            return HttpRouter{};
        }

        // ---------------------------------------------------------------
        //  Simple registration (method + pattern + handler)
        // ---------------------------------------------------------------

        /**
         * @brief Registers a GET handler for a given route pattern.
         * @param pattern Route pattern.
         * @param h Coroutine handler.
         */
        void get(const std::string_view pattern, Handler h) {
            route(protos::http::method::GET, pattern, std::move(h));
        }

        /**
         * @brief Registers a POST handler for a given route pattern.
         * @param pattern Route pattern.
         * @param h Coroutine handler.
         */
        void post(const std::string_view pattern, Handler h) {
            route(protos::http::method::POST, pattern, std::move(h));
        }

        /**
         * @brief Registers a PUT handler for a given route pattern.
         * @param pattern Route pattern.
         * @param h Coroutine handler.
         */
        void put(const std::string_view pattern, Handler h) {
            route(protos::http::method::PUT, pattern, std::move(h));
        }

        /**
         * @brief Registers a DELETE handler for a given route pattern.
         * @param pattern Route pattern.
         * @param h Coroutine handler.
         */
        void del(const std::string_view pattern, Handler h) {
            route(protos::http::method::DELETE, pattern, std::move(h));
        }

        /**
         * @brief Registers a HEAD handler for a given route pattern.
         * @param pattern Route pattern.
         * @param h Coroutine handler.
         */
        void head(const std::string_view pattern, Handler h) {
            route(protos::http::method::HEAD, pattern, std::move(h));
        }

        /**
         * @brief Registers an OPTIONS handler for a given route pattern.
         * @param pattern Route pattern.
         * @param h Coroutine handler.
         */
        void options(const std::string_view pattern, Handler h) {
            route(protos::http::method::OPTIONS, pattern, std::move(h));
        }

        /**
         * @brief Registers a PATCH handler for a given route pattern.
         * @param pattern Route pattern.
         * @param h Coroutine handler.
         */
        void patch(const std::string_view pattern, Handler h) {
            route(protos::http::method::PATCH, pattern, std::move(h));
        }

        /**
         * @brief Registers a QUERY handler for a given route pattern.
         * @param pattern Route pattern.
         * @param h Coroutine handler.
         */
        void query(const std::string_view pattern, Handler h) {
            route(protos::http::method::QUERY, pattern, std::move(h));
        }

        // ---------------------------------------------------------------
        //  Registration with per-route middlewares
        // ---------------------------------------------------------------

        /**
         * @brief Registers a GET handler with per-route middlewares.
         * @param pattern Route pattern.
         * @param mws Vector of per-route middleware functions.
         * @param h Coroutine handler.
         */
        void get(const std::string_view pattern, std::vector<MiddlewareFn> mws, Handler h) {
            route(protos::http::method::GET, pattern, std::move(mws), std::move(h));
        }

        /**
         * @brief Registers a POST handler with per-route middlewares.
         * @param pattern Route pattern.
         * @param mws Vector of per-route middleware functions.
         * @param h Coroutine handler.
         */
        void post(const std::string_view pattern, std::vector<MiddlewareFn> mws, Handler h) {
            route(protos::http::method::POST, pattern, std::move(mws), std::move(h));
        }

        /**
         * @brief Registers a PUT handler with per-route middlewares.
         * @param pattern Route pattern.
         * @param mws Vector of per-route middleware functions.
         * @param h Coroutine handler.
         */
        void put(const std::string_view pattern, std::vector<MiddlewareFn> mws, Handler h) {
            route(protos::http::method::PUT, pattern, std::move(mws), std::move(h));
        }

        /**
         * @brief Registers a DELETE handler with per-route middlewares.
         * @param pattern Route pattern.
         * @param mws Vector of per-route middleware functions.
         * @param h Coroutine handler.
         */
        void del(const std::string_view pattern, std::vector<MiddlewareFn> mws, Handler h) {
            route(protos::http::method::DELETE, pattern, std::move(mws), std::move(h));
        }

        /**
         * @brief Registers a HEAD handler with per-route middlewares.
         * @param pattern Route pattern.
         * @param mws Vector of per-route middleware functions.
         * @param h Coroutine handler.
         */
        void head(const std::string_view pattern, std::vector<MiddlewareFn> mws, Handler h) {
            route(protos::http::method::HEAD, pattern, std::move(mws), std::move(h));
        }

        /**
         * @brief Registers an OPTIONS handler with per-route middlewares.
         * @param pattern Route pattern.
         * @param mws Vector of per-route middleware functions.
         * @param h Coroutine handler.
         */
        void options(const std::string_view pattern, std::vector<MiddlewareFn> mws, Handler h) {
            route(protos::http::method::OPTIONS, pattern, std::move(mws), std::move(h));
        }

        /**
         * @brief Registers a PATCH handler with per-route middlewares.
         * @param pattern Route pattern.
         * @param mws Vector of per-route middleware functions.
         * @param h Coroutine handler.
         */
        void patch(const std::string_view pattern, std::vector<MiddlewareFn> mws, Handler h) {
            route(protos::http::method::PATCH, pattern, std::move(mws), std::move(h));
        }

        /**
         * @brief Registers a QUERY handler with per-route middlewares.
         * @param pattern Route pattern.
         * @param mws Vector of per-route middleware functions.
         * @param h Coroutine handler.
         */
        void query(const std::string_view pattern, std::vector<MiddlewareFn> mws, Handler h) {
            route(protos::http::method::QUERY, pattern, std::move(mws), std::move(h));
        }

        // ---------------------------------------------------------------
        //  Registration with StaticChain
        // ---------------------------------------------------------------

        /**
         * @brief Registers a GET route using a StaticChain pipeline.
         * @tparam Handlers Types of handlers in the static chain.
         * @param pattern Route pattern.
         * @param chain StaticChain instance.
         */
        template<typename... Handlers>
        void get(const std::string_view pattern, StaticChain<Handlers...> chain) {
            route(protos::http::method::GET, pattern, std::move(chain));
        }

        /**
         * @brief Registers a POST route using a StaticChain pipeline.
         * @tparam Handlers Types of handlers in the static chain.
         * @param pattern Route pattern.
         * @param chain StaticChain instance.
         */
        template<typename... Handlers>
        void post(const std::string_view pattern, StaticChain<Handlers...> chain) {
            route(protos::http::method::POST, pattern, std::move(chain));
        }

        /**
         * @brief Registers a PUT route using a StaticChain pipeline.
         * @tparam Handlers Types of handlers in the static chain.
         * @param pattern Route pattern.
         * @param chain StaticChain instance.
         */
        template<typename... Handlers>
        void put(const std::string_view pattern, StaticChain<Handlers...> chain) {
            route(protos::http::method::PUT, pattern, std::move(chain));
        }

        /**
         * @brief Registers a DELETE route using a StaticChain pipeline.
         * @tparam Handlers Types of handlers in the static chain.
         * @param pattern Route pattern.
         * @param chain StaticChain instance.
         */
        template<typename... Handlers>
        void del(const std::string_view pattern, StaticChain<Handlers...> chain) {
            route(protos::http::method::DELETE, pattern, std::move(chain));
        }

        /**
         * @brief Registers a HEAD route using a StaticChain pipeline.
         * @tparam Handlers Types of handlers in the static chain.
         * @param pattern Route pattern.
         * @param chain StaticChain instance.
         */
        template<typename... Handlers>
        void head(const std::string_view pattern, StaticChain<Handlers...> chain) {
            route(protos::http::method::HEAD, pattern, std::move(chain));
        }

        /**
         * @brief Registers an OPTIONS route using a StaticChain pipeline.
         * @tparam Handlers Types of handlers in the static chain.
         * @param pattern Route pattern.
         * @param chain StaticChain instance.
         */
        template<typename... Handlers>
        void options(const std::string_view pattern, StaticChain<Handlers...> chain) {
            route(protos::http::method::OPTIONS, pattern, std::move(chain));
        }

        /**
         * @brief Registers a PATCH route using a StaticChain pipeline.
         * @tparam Handlers Types of handlers in the static chain.
         * @param pattern Route pattern.
         * @param chain StaticChain instance.
         */
        template<typename... Handlers>
        void patch(const std::string_view pattern, StaticChain<Handlers...> chain) {
            route(protos::http::method::PATCH, pattern, std::move(chain));
        }

        /**
         * @brief Registers a QUERY route using a StaticChain pipeline.
         * @tparam Handlers Types of handlers in the static chain.
         * @param pattern Route pattern.
         * @param chain StaticChain instance.
         */
        template<typename... Handlers>
        void query(const std::string_view pattern, StaticChain<Handlers...> chain) {
            route(protos::http::method::QUERY, pattern, std::move(chain));
        }

        // ---------------------------------------------------------------
        //  WebSocket endpoints (RFC 6455 / RFC 9220)
        // ---------------------------------------------------------------

        /// Session handler: runs after the handshake; `req` stays valid until it returns.
        using WebSocketHandler = std::function<asio::awaitable<void>(
            typename Base::RequestType &, std::shared_ptr<protos::websocket::connection>)>;

        /**
         * @brief Register a WebSocket endpoint.
         *
         * On HTTP/1.x routers this answers `GET` + `Upgrade: websocket` with `101 Switching Protocols`; on the
         * HTTP/2 and HTTP/3 routers it answers an extended CONNECT with `:protocol = websocket` (RFC 8441,
         * RFC 9220). Requests that
         * are not a valid handshake get 400 / 426. Route middlewares run before the handshake, so they can
         * authenticate and refuse the upgrade.
         */
        void websocket(const std::string_view pattern, WebSocketHandler h, protos::websocket::options opts = {}) {
            websocket(pattern, {}, std::move(h), std::move(opts));
        }

        void websocket(const std::string_view pattern, std::vector<MiddlewareFn> mws, WebSocketHandler h,
                       protos::websocket::options opts = {}) {
            auto session = std::make_shared<WebSocketHandler>(std::move(h));
            route(websocket_method(), pattern, std::move(mws),
                  [session, opts = std::move(opts)](typename Base::RequestType &req,
                                                    typename Base::ResponseType &res) -> asio::awaitable<void> {
                      protos::websocket::accept(
                          req, res,
                          [session, &req](std::shared_ptr<protos::websocket::connection> ws)
                      -> asio::awaitable<void> {
                              co_await (*session)(req, std::move(ws));
                          },
                          opts);
                      co_return;
                  });
        }

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        // ---------------------------------------------------------------
        //  WebTransport endpoints (HTTP/3 only)
        // ---------------------------------------------------------------

        /// Session handler: runs once the CONNECT is accepted; `req` stays valid until it returns.
        using WebTransportHandler = std::function<asio::awaitable<void>(
            typename Base::RequestType &, std::shared_ptr<protos::webtransport::session>)>;

        /**
         * @brief Register a WebTransport endpoint: an extended CONNECT with `:protocol = webtransport` on
         *        `pattern` is answered 200 and handed to `h` as a session. HTTP/3 routers only.
         */
        void webtransport(const std::string_view pattern, WebTransportHandler h,
                          protos::webtransport::options opts = {})
            requires std::is_same_v<Codec, protos::http::http3codec> {
            webtransport(pattern, {}, std::move(h), std::move(opts));
        }

        void webtransport(const std::string_view pattern, std::vector<MiddlewareFn> mws, WebTransportHandler h,
                          protos::webtransport::options opts = {})
            requires std::is_same_v<Codec, protos::http::http3codec> {
            auto session = std::make_shared<WebTransportHandler>(std::move(h));
            route(protos::http::method::CONNECT, pattern, std::move(mws),
                  [session, opts](typename Base::RequestType &req,
                                  typename Base::ResponseType &res) -> asio::awaitable<void> {
                      protos::webtransport::accept(
                          req, res,
                          [session, &req](std::shared_ptr<protos::webtransport::session> wt)
                      -> asio::awaitable<void> {
                              co_await (*session)(req, std::move(wt));
                          },
                          opts);
                      co_return;
                  });
        }
#endif

        /// The request method a WebSocket handshake arrives with on this router's protocol.
        [[nodiscard]] static constexpr protos::http::method websocket_method() noexcept {
            if constexpr (std::is_same_v<Codec, protos::http::http2codec>) {
                return protos::http::method::CONNECT;
            }
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
            if constexpr (std::is_same_v<Codec, protos::http::http3codec>) {
                return protos::http::method::CONNECT;
            }
#endif
            return protos::http::method::GET;
        }
    };

    /// Concrete default HTTP/1.x router type aliases
    using Http1Router = HttpRouter<protos::http::http1codec>;
    using http1router = Http1Router;

    /// Concrete HTTP/2 router type aliases
    using Http2Router = HttpRouter<protos::http::http2codec>;
    using http2router = Http2Router;

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
    /// Concrete HTTP/3 router type aliases
    using Http3Router = HttpRouter<protos::http::http3codec>;
    using http3router = Http3Router;
#endif
} // namespace wavex::engine
