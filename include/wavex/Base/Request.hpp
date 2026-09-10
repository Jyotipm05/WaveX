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
 */

#pragma once

#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

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

        /// Path parameters populated by the router (e.g. :id -> "123")
        std::unordered_map<std::string, std::string> params;

        /// Query string parameters (e.g. ?key=val -> {"key": "val"})
        std::unordered_map<std::string, std::string> query;
    };
} // namespace wavex::base
