// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file VarInt.hpp
 * @brief RFC 9000 §16 Variable-Length Integer encoding/decoding.
 *
 * QUIC uses a variable-length integer encoding with 2-bit length prefix.
 * Supports 6-bit, 14-bit, 30-bit, and 62-bit unsigned integers.
 */

#pragma once

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>

namespace wavex::network::quic {

    struct VarInt {
        // ─── 4. Member Functions (LAST) ────────────────────────────────────
        [[nodiscard]] static std::size_t encoded_size(uint64_t val) noexcept;
        static void encode(uint64_t val, std::string &out);
        static std::size_t encode(uint64_t val, uint8_t *out, std::size_t max_len) noexcept;
        static bool decode(std::string_view buf, std::size_t &cursor, uint64_t &val) noexcept;
    };

} // namespace wavex::network::quic

#endif // WAVEX_HAS_SSL

