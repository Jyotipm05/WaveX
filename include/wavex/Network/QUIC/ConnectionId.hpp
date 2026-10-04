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
#include <cstddef>
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
        [[nodiscard]] uint8_t length() const noexcept { return length_; }
        [[nodiscard]] const uint8_t *data() const noexcept { return data_.data(); }
        [[nodiscard]] uint8_t *data() noexcept { return data_.data(); }
        [[nodiscard]] bool empty() const noexcept { return length_ == 0; }
        [[nodiscard]] std::string to_string() const;
        [[nodiscard]] std::string_view as_string_view() const noexcept {
            return {reinterpret_cast<const char*>(data_.data()), length_};
        }

        static ConnectionId from_hex(std::string_view hex);
        static ConnectionId random(std::size_t len = 8);

        bool operator==(const ConnectionId &other) const noexcept;
        bool operator!=(const ConnectionId &other) const noexcept { return !(*this == other); }
    };

} // namespace wavex::network::quic

// Hash specialization
namespace std {
    template<>
    struct hash<wavex::network::quic::ConnectionId> {
        std::size_t operator()(const wavex::network::quic::ConnectionId &cid) const noexcept;
    };
} // namespace std

#endif // WAVEX_HAS_SSL

