// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file Url.hpp
 * @brief RFC 3986 structured URL parser and query-string utilities.
 *
 * Provides:
 *  - struct Url       — parsed representation of a URL
 *  - Url::parse()     — decompose a raw URL string into its components
 *  - parse_query()    — decode a query string into a key-value map
 *
 * For low-level percent-encoding/decoding only, see:
 *   <wavex/Base/Uri.hpp>
 */

#pragma once

#include <string>
#include <string_view>
#include <unordered_map>
#include <cstdint>

namespace wavex::url {
    /**
     * @struct Url
     * @brief Structured representation of a parsed URL.
     *
     * Conforms to RFC 3986 generic URI syntax:
     *   scheme "://" [userinfo "@"] host [":" port] path ["?" query] ["#" fragment]
     */
    struct Url {
        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        std::string scheme; ///< e.g. "http", "https"
        std::string userinfo; ///< e.g. "user:pass" (the part before '@')
        std::string host; ///< hostname or IP address (IPv6 without brackets)
        std::string path; ///< e.g. "/foo/bar"
        std::string query; ///< query string without leading '?'
        std::string fragment; ///< fragment without leading '#'
        uint16_t port = 0; ///< 0 means "infer from scheme" (80 / 443)

        // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
        Url() = default;
        ~Url() = default;
        Url(const Url &) = default;
        Url &operator=(const Url &) = default;
        Url(Url &&) noexcept = default;
        Url &operator=(Url &&) noexcept = default;

        // ─── 4. Member Functions & Friend Declarations (LAST) ──────────────
        /**
         * @brief Parse a raw URL string into its components.
         * @param raw  Full URL, e.g. "https://user@example.com:8080/path?q=1#sec"
         * @return     Populated Url struct (empty fields for absent components)
         */
        static Url parse(std::string_view raw);

        /**
         * @brief Reconstruct the URL string from its components.
         * @return Canonical URL string
         */
        [[nodiscard]] std::string to_string() const;

        /**
         * @brief Resolve the effective port number.
         *
         * Returns the explicit port if set, otherwise falls back to the
         * well-known port for the scheme (80 for http, 443 for https).
         */
        [[nodiscard]] uint16_t effective_port() const;
    };

    /**
     * @brief Parse a query string into decoded key-value pairs.
     *
     * Splits on '&', then on '=' within each pair. Both keys and values are
     * percent-decoded. Keys with no '=' get an empty-string value.
     *
     * @param qs  Query string without the leading '?', e.g. "key=val&k2=v2"
     * @return    Map of decoded key -> decoded value pairs
     */
    std::unordered_map<std::string, std::string> parse_query(std::string_view qs);
} // namespace wavex::url
