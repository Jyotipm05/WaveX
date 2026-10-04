// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file ConnectionId.cpp
 * @brief Implementation of RFC 9000 §5 Connection ID representation.
 */

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

#include <wavex/Network/QUIC/ConnectionId.hpp>

#if defined(min)
#undef min
#endif
#if defined(max)
#undef max
#endif

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <random>
#include <sstream>

namespace wavex::network::quic {

    ConnectionId::ConnectionId(const uint8_t *src, const std::size_t len) noexcept {
        length_ = static_cast<uint8_t>((std::min)(len, MAX_CONNECTION_ID_LEN));
        if (src && length_ > 0) {
            std::memcpy(data_.data(), src, length_);
        }
    }

    ConnectionId::ConnectionId(const std::string_view sv) noexcept {
        length_ = static_cast<uint8_t>((std::min)(sv.size(), MAX_CONNECTION_ID_LEN));
        if (length_ > 0) {
            std::memcpy(data_.data(), sv.data(), length_);
        }
    }

    std::string ConnectionId::to_string() const {
        std::ostringstream oss;
        for (std::size_t i = 0; i < length_; ++i) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data_[i]);
        }
        return oss.str();
    }

    ConnectionId ConnectionId::from_hex(const std::string_view hex) {
        if (hex.empty() || hex.size() % 2 != 0 || hex.size() / 2 > MAX_CONNECTION_ID_LEN) {
            return ConnectionId{};
        }
        ConnectionId cid;
        for (std::size_t i = 0; i < hex.size() / 2; ++i) {
            const char c1 = hex[i * 2];
            const char c2 = hex[i * 2 + 1];
            auto hex_val = [](char c) noexcept -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            const int v1 = hex_val(c1);
            const int v2 = hex_val(c2);
            if (v1 < 0 || v2 < 0) {
                return ConnectionId{};
            }
            cid.data_[i] = static_cast<uint8_t>((v1 << 4) | v2);
        }
        cid.length_ = static_cast<uint8_t>(hex.size() / 2);
        return cid;
    }

    ConnectionId ConnectionId::random(const std::size_t len) {
        ConnectionId cid;
        cid.length_ = static_cast<uint8_t>((std::min)(len, MAX_CONNECTION_ID_LEN));
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int> dist(0, 255);
        for (std::size_t i = 0; i < cid.length_; ++i) {
            cid.data_[i] = static_cast<uint8_t>(dist(gen));
        }
        return cid;
    }

    bool ConnectionId::operator==(const ConnectionId &other) const noexcept {
        if (length_ != other.length_) return false;
        if (length_ == 0) return true;
        return std::memcmp(data_.data(), other.data_.data(), length_) == 0;
    }

} // namespace wavex::network::quic

namespace std {
    std::size_t hash<wavex::network::quic::ConnectionId>::operator()(
        const wavex::network::quic::ConnectionId &cid) const noexcept {
        std::size_t h = 14695981039346656037ULL;
        for (std::size_t i = 0; i < cid.length(); ++i) {
            h ^= cid.data()[i];
            h *= 1099511628211ULL;
        }
        return h;
    }
} // namespace std

#endif // WAVEX_HAS_SSL

