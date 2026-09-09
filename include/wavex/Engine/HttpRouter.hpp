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
        static HttpRouter make_instance() {
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
    };

    /// Concrete default HTTP/1.x router type aliases
    using Http1Router = HttpRouter<protos::http::http1codec>;
    using http1router = Http1Router;

    /// Concrete HTTP/2 router type aliases
    using Http2Router = HttpRouter<protos::http::http2codec>;
    using http2router = Http2Router;
} // namespace wavex::engine
