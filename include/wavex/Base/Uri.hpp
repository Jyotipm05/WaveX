// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file Uri.hpp
 * @brief RFC 3986 URI percent-encoding and decoding utilities.
 *
 * Provides uri_encode() and uri_decode() for escaping/unescaping strings
 * according to RFC 3986 §2.1 and §2.3 (unreserved characters pass through
 * without modification).
 *
 * For full URL parsing (scheme, host, port, path, query, fragment) see:
 *   <wavex/Base/Url/Url.hpp>
 */

#pragma once

#include <string>
#include <string_view>

namespace wavex::uri {
    /**
     * @brief Percent-encode a raw string per RFC 3986.
     *
     * Every byte that is not an RFC 3986 unreserved character
     * (A-Z a-z 0-9 - _ . ~) is replaced with its %XX hex escape.
     *
     * @param raw  Input string (may contain arbitrary bytes)
     * @return     Percent-encoded string safe for use in a URI component
     */
    std::string encode(std::string_view raw);

    /**
     * @brief Decode a percent-encoded string directly into caller-provided storage.
     *
     * Converts %XX sequences back to their byte values and '+' to space.
     * The destination buffer @p out_buf must be at least encoded.size() bytes.
     *
     * @param encoded  Percent-encoded input
     * @param out_buf  Output buffer of at least encoded.size() bytes
     * @return         Number of bytes written to out_buf
     */
    std::size_t decode_to(std::string_view encoded, char *out_buf);

    /**
     * @brief Decode a percent-encoded string.
     *
     * Converts %XX sequences back to their byte values. Also converts
     * '+' to space (application/x-www-form-urlencoded compatibility).
     * Invalid or truncated %XX sequences are passed through unchanged.
     *
     * @param encoded  Percent-encoded input
     * @return         Decoded string
     */
    std::string decode(std::string_view encoded);
} // namespace wavex::uri
