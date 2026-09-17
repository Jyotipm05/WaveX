// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file Request.hpp
 * @brief Defines the Request base class for handling incoming network requests using C++23 deducing this.
 *
 * Provides base abstractions for HTTP/WS request parsing and state management.
 * Protocol-specific implementations (HttpRequest, etc.) derive from this cleanly:
 * `class HttpRequest final : public base::Request`.
 *
 * Memory model:
 *   `params` and `query` are backed by FlatMap<std::string_view, std::string_view>.
 *   All string_view keys and values point into the connection stream buffer or the
 *   request arena — they are valid for the lifetime of the current request only.
 *
 * string_view safety contract:
 *   - Safe (ephemeral, in-turn use): Passing a view to a filter, validator, format
 *     conversion, or a DB query executed within the same coroutine turn.
 *   - Unsafe (escaping use): Capturing a view into spawn_blocking, a global cache,
 *     or a struct that outlives the request. Convert to std::string at that boundary:
 *       std::string(req.param("id"))
 */

#pragma once

#include <string>
#include <string_view>
#include <utility>

#include <wavex/Base/FlatMap.hpp>

namespace wavex::base {
    /**
     * @class Request
     * @brief Protocol-agnostic C++23 "deducing this" request base class (zero-vtable overhead).
     *
     * Concrete protocol implementations (HttpRequest, etc.) inherit via:
     * `class HttpRequest final : public base::Request`.
     */
    class Request {
    protected:
        ~Request() = default;

    public:
        /// The request path/target, e.g. "/user/123"
        template<typename Self>
        [[nodiscard]] decltype(auto) path(this Self &&self) {
            return std::forward<Self>(self).path_impl();
        }

        /// Retrieve a header by name (case-insensitive for HTTP)
        template<typename Self>
        [[nodiscard]] decltype(auto) header(this Self &&self, const std::string_view name) {
            return std::forward<Self>(self).header_impl(name);
        }

        /// The request body
        template<typename Self>
        [[nodiscard]] decltype(auto) body(this Self &&self) {
            return std::forward<Self>(self).body_impl();
        }

        /// Check if request payload is multipart/form-data
        template<typename Self>
        [[nodiscard]] decltype(auto) is_multipart(this Self &&self) {
            if constexpr (requires { std::forward<Self>(self).is_multipart_impl(); }) {
                return std::forward<Self>(self).is_multipart_impl();
            } else {
                return false;
            }
        }

        /**
         * @brief Zero-copy path parameter accessor.
         *
         * Returns a string_view into the request stream buffer or arena.
         * Valid only for the duration of the current request coroutine turn.
         * For escaping use, convert: std::string(req.param("id"))
         *
         * @param name  Parameter name as registered in the route (e.g. "id" for :id).
         * @return      View of the matched parameter value, or empty view if absent.
         */
        [[nodiscard]] std::string_view param(const std::string_view name) const noexcept {
            return params.get(name);
        }

        /**
         * @brief Zero-copy query string parameter accessor.
         *
         * Returns a string_view into the request stream buffer or arena.
         * Valid only for the duration of the current request coroutine turn.
         * For escaping use, convert: std::string(req.query_param("page"))
         *
         * @param name  Query parameter key (e.g. "page" for ?page=2).
         * @return      View of the decoded query value, or empty view if absent.
         */
        [[nodiscard]] std::string_view query_param(const std::string_view name) const noexcept {
            return query.get(name);
        }

        /// Path parameters populated by the router (e.g. :id -> "123")
        /// Keys and values are string_view slices into the request stream buffer.
        FlatMap<std::string_view, std::string_view> params;

        /// Query string parameters (e.g. ?key=val -> {"key": "val"})
        /// Keys and values are string_view slices into arena-backed decoded strings.
        FlatMap<std::string_view, std::string_view> query;
    };
} // namespace wavex::base
