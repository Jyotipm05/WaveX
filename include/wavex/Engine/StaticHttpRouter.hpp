// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file StaticHttpRouter.hpp
 * @brief HTTP method helpers for StaticRouter: `get<"/p">(handler)` instead of `on<method::GET, "/p">(handler)`.
 *
 * ```cpp
 * using namespace wavex::engine::route::http;
 * auto router = wavex::engine::route::static_router<wavex::engine::Http1Proto>(
 *     get<"/users/{id:int}">(show), post<"/users">(create));
 * ```
 */

#ifndef WAVEX_ENGINE_STATICHTTPROUTER_HPP
#define WAVEX_ENGINE_STATICHTTPROUTER_HPP

#include <wavex/Engine/HttpRouter.hpp>
#include <wavex/Engine/StaticRouter.hpp>

namespace wavex::engine::route::http {

#define WAVEX_STATIC_HTTP_ROUTE(fn, verb)                                                                      \
    template<fixed_string P, typename H, typename... Mw>                                                       \
    [[nodiscard]] constexpr auto fn(H handler, Mw... mw) {                                                     \
        return on<protos::http::method::verb, P>(std::move(handler), std::move(mw)...);                        \
    }

    WAVEX_STATIC_HTTP_ROUTE(get, GET)
    WAVEX_STATIC_HTTP_ROUTE(post, POST)
    WAVEX_STATIC_HTTP_ROUTE(put, PUT)
    WAVEX_STATIC_HTTP_ROUTE(del, DELETE)
    WAVEX_STATIC_HTTP_ROUTE(patch, PATCH)
    WAVEX_STATIC_HTTP_ROUTE(head, HEAD)
    WAVEX_STATIC_HTTP_ROUTE(options, OPTIONS)
    WAVEX_STATIC_HTTP_ROUTE(query, QUERY)

#undef WAVEX_STATIC_HTTP_ROUTE

} // namespace wavex::engine::route::http

#endif // WAVEX_ENGINE_STATICHTTPROUTER_HPP
