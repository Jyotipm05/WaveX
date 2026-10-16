// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file Uri.cpp
 * @brief Implementation of RFC 3986 percent-encoding and decoding.
 */

#include <wavex/Base/Uri.hpp>
#include <cctype>
#include <cstring>

namespace wavex::uri {
    // -----------------------------------------------------------------------
    //  Internal helpers
    // -----------------------------------------------------------------------

    /// RFC 3986 §2.3 — unreserved characters pass through unescaped.
    static bool is_unreserved(const char c) {
        return std::isalnum(static_cast<unsigned char>(c))
               || c == '-' || c == '_' || c == '.' || c == '~';
    }

    static char hex_digit(const unsigned int nibble) {
        return "0123456789ABCDEF"[nibble & 0xF];
    }

    static int hex_value(const char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return -1;
    }

    // -----------------------------------------------------------------------
    //  Public API
    // -----------------------------------------------------------------------

    std::string encode(const std::string_view raw) {
        std::string out;
        if (raw.empty()) return out;

        // Maximum possible size is 3x the original (every char becomes %XX)
        // Pre-allocating this means NO capacity checks in the hot loop.
        out.resize(raw.size() * 3);

        const char *src = raw.data();
        const char *src_end = src + raw.size();
        char *dst = out.data();

        while (src < src_end) {
            if (const char c = *src; is_unreserved(c)) [[likely]] {
                // Fast-forward through contiguous unreserved characters
                const char *run_start = src;
                ++src;
                while (src < src_end && is_unreserved(*src)) {
                    ++src;
                }

                // Bulk copy the safe characters using memcpy
                const auto run_len = static_cast<size_t>(src - run_start);
                std::memcpy(dst, run_start, run_len);
                dst += run_len;
            } else [[unlikely]] {
                // Write '%' and the two hex digits directly to memory
                *dst++ = '%';
                const auto uc = static_cast<unsigned char>(c);
                *dst++ = hex_digit(uc >> 4);
                *dst++ = hex_digit(uc & 0xF);
                ++src;
            }
        }

        // Shrink the string to the actual encoded size
        out.resize(static_cast<size_t>(dst - out.data()));
        return out;
    }

    std::size_t decode_to(const std::string_view encoded, char *dst) {
        if (encoded.empty() || !dst) return 0;

        char *start = dst;
        const char *src = encoded.data();
        const char *src_end = src + encoded.size();

        while (src < src_end) {
            if (const char c = *src; c == '%') [[unlikely]] {
                if (src + 2 < src_end) [[likely]] {
                    if (const int hi = hex_value(src[1]), lo = hex_value(src[2]); hi >= 0 && lo >= 0) {
                        *dst++ = static_cast<char>((hi << 4) | lo);
                        src += 3;
                        continue;
                    }
                }
                // Invalid or truncated sequence — pass through verbatim.
                *dst++ = '%';
                ++src;
            } else if (c == '+') [[unlikely]] {
                // application/x-www-form-urlencoded: '+' -> space
                *dst++ = ' ';
                ++src;
            } else [[likely]] {
                // Fast bulk copy of plain-text runs.
                const char *run_start = src;
                ++src;
                while (src < src_end && *src != '%' && *src != '+') {
                    ++src;
                }
                const auto run_len = static_cast<size_t>(src - run_start);
                std::memcpy(dst, run_start, run_len);
                dst += run_len;
            }
        }

        return static_cast<std::size_t>(dst - start);
    }

    std::string decode(const std::string_view encoded) {
        std::string out;
        if (encoded.empty()) return out;

        // Allocate maximum possible size upfront — no reallocation will occur.
        out.resize(encoded.size());
        const size_t written = decode_to(encoded, out.data());
        out.resize(written);
        return out;
    }
}
