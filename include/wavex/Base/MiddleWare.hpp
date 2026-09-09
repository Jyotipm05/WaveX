// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file MiddleWare.hpp
 * @brief Defines the middleware function type for the WaveX pipeline.
 *
 * A middleware is a coroutine-aware function that receives a Request, Response,
 * and a Next callable. Calling co_await next() passes control to the next
 * middleware in the chain (or the final route handler). Not calling next()
 * short-circuits the pipeline (e.g., for auth rejection).
 */

#pragma once

#include <functional>
#include <string>

#ifndef ASIO_HAS_CO_AWAIT
#define ASIO_HAS_CO_AWAIT 1
#endif

#include <asio/awaitable.hpp>

// Forward declarations of Request and Response base classes
namespace wavex::base {
    class Request;
    class Response;

    /// Callable that invokes the next middleware or the final handler
    using Next = std::function<asio::awaitable<void>()>;

    /**
     * @brief Generic middleware function signature for Request and Response types.
     *
     * Usage:
     *   auto logger = [](ReqT &req, ResT &res, Next next) -> asio::awaitable<void> {
     *       WX_LOG_INFO("-> {}", req.path());
     *       co_await next();
     *       WX_LOG_INFO("<- {} {}", res.status_code(), req.path());
     *   };
     */
    template<typename ReqT, typename ResT>
    using GenericMiddlewareFn = std::function<asio::awaitable<void>(ReqT &, ResT &, Next)>;

    /**
     * @brief Factory for keep-alive middleware enforcing persistent connection headers.
     * @param timeout_sec Keep-Alive idle timeout in seconds.
     * @param max_requests Max requests per connection before closing.
     */
    template<typename ReqT, typename ResT>
    GenericMiddlewareFn<ReqT, ResT> keep_alive(unsigned timeout_sec = 5, unsigned max_requests = 1000) {
        return [timeout_sec, max_requests](ReqT &req, ResT &res, Next next) -> asio::awaitable<void> {
            if (req.should_keep_alive()) {
                res.set("Connection", "keep-alive");
                res.set("Keep-Alive",
                        "timeout=" + std::to_string(timeout_sec) + ", max=" + std::to_string(max_requests));
            } else {
                res.set("Connection", "close");
            }
            co_await next();
        };
    }

    /**
     * @brief Middleware preparing headers for Server-Sent Events (SSE) stay-active streams.
     */
    template<typename ReqT, typename ResT>
    GenericMiddlewareFn<ReqT, ResT> sse_stay_active() {
        return [](const ReqT &req, ResT &res, const Next next) -> asio::awaitable<void> {
            (void) req;
            res.set("Content-Type", "text/event-stream");
            res.set("Cache-Control", "no-cache");
            res.set("Connection", "keep-alive");
            co_await next();
        };
    }
} // namespace wavex::base
