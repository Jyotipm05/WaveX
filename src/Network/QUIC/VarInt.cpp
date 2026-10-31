// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file VarInt.cpp
 * @brief Implementation of RFC 9000 §16 Variable-Length Integer.
 */

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

#include <wavex/Network/QUIC/VarInt.hpp>

namespace wavex::network::quic {

    std::size_t VarInt::encoded_size(const uint64_t val) noexcept {
        if (val <= 0x3f) return 1;
        if (val <= 0x3fff) return 2;
        if (val <= 0x3fffffff) return 4;
        return 8;
    }

    void VarInt::encode(const uint64_t val, std::string &out) {
        if (val <= 0x3f) {
            out.push_back(static_cast<char>(val & 0x3f));
        } else if (val <= 0x3fff) {
            out.push_back(static_cast<char>(0x40 | ((val >> 8) & 0x3f)));
            out.push_back(static_cast<char>(val & 0xff));
        } else if (val <= 0x3fffffff) {
            out.push_back(static_cast<char>(0x80 | ((val >> 24) & 0x3f)));
            out.push_back(static_cast<char>((val >> 16) & 0xff));
            out.push_back(static_cast<char>((val >> 8) & 0xff));
            out.push_back(static_cast<char>(val & 0xff));
        } else {
            out.push_back(static_cast<char>(0xc0 | ((val >> 56) & 0x3f)));
            out.push_back(static_cast<char>((val >> 48) & 0xff));
            out.push_back(static_cast<char>((val >> 40) & 0xff));
            out.push_back(static_cast<char>((val >> 32) & 0xff));
            out.push_back(static_cast<char>((val >> 24) & 0xff));
            out.push_back(static_cast<char>((val >> 16) & 0xff));
            out.push_back(static_cast<char>((val >> 8) & 0xff));
            out.push_back(static_cast<char>(val & 0xff));
        }
    }

    std::size_t VarInt::encode(const uint64_t val, uint8_t *out, const std::size_t max_len) noexcept {
        const std::size_t len = encoded_size(val);
        if (max_len < len) return 0;
        if (len == 1) {
            out[0] = static_cast<uint8_t>(val & 0x3f);
        } else if (len == 2) {
            out[0] = static_cast<uint8_t>(0x40 | ((val >> 8) & 0x3f));
            out[1] = static_cast<uint8_t>(val & 0xff);
        } else if (len == 4) {
            out[0] = static_cast<uint8_t>(0x80 | ((val >> 24) & 0x3f));
            out[1] = static_cast<uint8_t>((val >> 16) & 0xff);
            out[2] = static_cast<uint8_t>((val >> 8) & 0xff);
            out[3] = static_cast<uint8_t>(val & 0xff);
        } else {
            out[0] = static_cast<uint8_t>(0xc0 | ((val >> 56) & 0x3f));
            out[1] = static_cast<uint8_t>((val >> 48) & 0xff);
            out[2] = static_cast<uint8_t>((val >> 40) & 0xff);
            out[3] = static_cast<uint8_t>((val >> 32) & 0xff);
            out[4] = static_cast<uint8_t>((val >> 24) & 0xff);
            out[5] = static_cast<uint8_t>((val >> 16) & 0xff);
            out[6] = static_cast<uint8_t>((val >> 8) & 0xff);
            out[7] = static_cast<uint8_t>(val & 0xff);
        }
        return len;
    }

    bool VarInt::decode(const std::string_view buf, std::size_t &cursor, uint64_t &val) noexcept {
        if (cursor >= buf.size()) return false;
        const auto first = static_cast<uint8_t>(buf[cursor]);
        const uint8_t prefix = (first >> 6) & 0x03;
        const std::size_t len = 1ULL << prefix;
        if (cursor + len > buf.size()) return false;

        val = first & 0x3f;
        for (std::size_t i = 1; i < len; ++i) {
            val = (val << 8) | static_cast<uint8_t>(buf[cursor + i]);
        }
        cursor += len;
        return true;
    }

} // namespace wavex::network::quic

#endif // WAVEX_HAS_SSL
