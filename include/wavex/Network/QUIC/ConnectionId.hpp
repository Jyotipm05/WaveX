// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file ConnectionId.hpp
 * @brief RFC 9000 §5 Connection ID representation and operations.
 */

#pragma once

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <functional>

#include <wavex/Network/QUIC/QuicConstants.hpp>

namespace wavex::network::quic {
    struct ConnectionId {
        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        std::array<uint8_t, MAX_CONNECTION_ID_LEN> data_{};
        uint8_t length_{0};

        // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
        constexpr ConnectionId() noexcept = default;

        ConnectionId(const uint8_t *src, std::size_t len) noexcept;

        explicit ConnectionId(std::string_view sv) noexcept;

        ~ConnectionId() = default;

        ConnectionId(const ConnectionId &) = default;

        ConnectionId &operator=(const ConnectionId &) = default;

        ConnectionId(ConnectionId &&) noexcept = default;

        ConnectionId &operator=(ConnectionId &&) noexcept = default;

        // ─── 4. Member Functions & Friend Declarations (LAST) ──────────────
        [[nodiscard]] auto length() const noexcept -> uint8_t { return length_; }
        [[nodiscard]] auto data() const noexcept -> const uint8_t * { return data_.data(); }
        [[nodiscard]] auto data() noexcept -> uint8_t * { return data_.data(); }
        [[nodiscard]] auto empty() const noexcept -> bool { return length_ == 0; }

        [[nodiscard]] std::string to_string() const;

        [[nodiscard]] auto as_string_view() const noexcept -> std::string_view {
            return {reinterpret_cast<const char *>(data_.data()), length_};
        }

        static auto from_hex(std::string_view hex) -> ConnectionId;

        static auto random(std::size_t len = 8) -> ConnectionId;

        auto operator==(const ConnectionId &other) const noexcept -> bool;

        auto operator!=(const ConnectionId &other) const noexcept -> bool { return !(*this == other); }
    };
} // namespace wavex::network::quic

// Hash specialization
template<>
struct std::hash<wavex::network::quic::ConnectionId> {
    auto operator()(const wavex::network::quic::ConnectionId &cid) const noexcept -> std::size_t;
}; // namespace std

#endif // WAVEX_HAS_SSL
