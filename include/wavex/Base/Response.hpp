// Copyright (c) 2026 Jyotipriary Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file Response.hpp
 * @brief Defines the Response base class for representing outgoing network responses using C++23 deducing this.
 *
 * Provides base abstractions for HTTP/WS response generation and header/body management.
 * Features a fluent API for method chaining: res.status(200).set("X-Foo", "bar").send("body").
 *
 * Memory model:
 *   `headers_` is backed by FlatMap<std::string_view, std::string_view>. All header
 *   name and value views must remain valid for the lifetime of the Response object.
 *   In WaveX's arena model, this is guaranteed by the request arena which outlives
 *   the Response and is released only after the response is sent.
 */

#pragma once

#include <string>
#include <string_view>
#include <ranges>
#include <utility>
#include <nlohmann/json.hpp>

#include <wavex/Base/FlatMap.hpp>

namespace wavex::base {
    /**
     * @class Response
     * @brief Protocol-agnostic C++23 "deducing this" response builder with fluent API (zero-vtable overhead).
     *
     * Concrete protocol implementations inherit cleanly:
     * `class HttpResponse final : public base::Response`.
     */
    class Response {
    protected:
        ~Response() = default;

    public:
        /// Set the response status code
        template<typename Self>
        decltype(auto) status(this Self &&self, const unsigned int code) {
            self.status_code_ = code;
            return std::forward<Self>(self);
        }

        /**
         * @brief Set a response header (updates existing if present, otherwise appends).
         *
         * Uses case-insensitive search to conform to RFC 7230 §3.2 header field rules.
         * Header name and value views are stored directly in headers_ FlatMap.
         * The backing storage for the string_view data must outlive the Response object.
         * In practice, HttpResponse stores owned std::string copies for set headers and
         * passes views into those owned strings.
         */
        template<typename Self>
        decltype(auto) set(this Self &&self, const std::string_view name, const std::string_view value) {
            if constexpr (requires { std::forward<Self>(self).set_impl(name, value); }) {
                return std::forward<Self>(self).set_impl(name, value);
            } else {
                self.headers_.insert_or_assign_ci(name, value);
                return std::forward<Self>(self);
            }
        }

        /// Remove a header by name (case-insensitive)
        template<typename Self>
        decltype(auto) remove_header(this Self &&self, const std::string_view name) {
            if constexpr (requires { std::forward<Self>(self).remove_header_impl(name); }) {
                return std::forward<Self>(self).remove_header_impl(name);
            } else {
                self.headers_.erase_ci(name);
                return std::forward<Self>(self);
            }
        }

        /// Returns true if the response has already been sent
        [[nodiscard]] bool is_sent() const { return is_sent_; }

        /// Set the response body as plain text and mark as sent
        template<typename Self>
        decltype(auto) send(this Self &&self, const std::string_view body = "") {
            return std::forward<Self>(self).send_impl(body);
        }

        /// Set the response body as JSON — sets Content-Type automatically
        template<typename Self>
        decltype(auto) json(this Self &&self, const nlohmann::json &j) {
            self.set("Content-Type", "application/json");
            return std::forward<Self>(self).send(j.dump());
        }

        /// Issue a redirect response with target location and optional status code (default: 302 Found)
        template<typename Self>
        decltype(auto) redirect(this Self &&self,
                                const std::string_view location,
                                const unsigned int code = 302) {
            self.status(code);
            self.set("Location", location);
            return std::forward<Self>(self).send();
        }

        /// Express/Fastify-style overload: res.redirect(code, url)
        template<typename Self>
        decltype(auto) redirect(this Self &&self,
                                const unsigned int code,
                                const std::string_view location) {
            return std::forward<Self>(self).redirect(location, code);
        }

        /// Permanent redirect (default: 301 Moved Permanently; 308 Permanent Redirect if preserve_method = true)
        template<typename Self>
        decltype(auto) permanent_redirect(this Self &&self,
                                          const std::string_view location,
                                          const bool preserve_method = false) {
            return std::forward<Self>(self).redirect(location, preserve_method ? 308 : 301);
        }

        /// Temporary redirect (default: 302 Found; 307 Temporary Redirect if preserve_method = true)
        template<typename Self>
        decltype(auto) temporary_redirect(this Self &&self,
                                          const std::string_view location,
                                          const bool preserve_method = false) {
            return std::forward<Self>(self).redirect(location, preserve_method ? 307 : 302);
        }

        /// Serialize the response into the wire format (protocol-specific)
        template<typename Self>
        [[nodiscard]] decltype(auto) serialize(this Self &&self) {
            return std::forward<Self>(self).serialize_impl();
        }

        /// Access the current status code
        [[nodiscard]] unsigned int status_code() const { return status_code_; }

        /// Access the current body
        [[nodiscard]] const std::string &get_body() const { return body_; }

        /**
         * @brief Check if a header exists (case-insensitive for HTTP)
         */
        [[nodiscard]] bool has_header(const std::string_view name) const {
            return headers_.find_ci(name) != headers_.end();
        }

    protected:
        unsigned int status_code_ = 200;

        /// Response headers — contiguous FlatMap for zero-node allocation.
        /// Concrete subclasses (HttpResponse) own the backing string storage and
        /// store string_views into those owned strings inside this map.
        FlatMap<std::string_view, std::string_view> headers_;

        std::string body_;
        bool is_sent_ = false;
    };
} // namespace wavex::base
