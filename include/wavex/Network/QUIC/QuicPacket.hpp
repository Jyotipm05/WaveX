// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file QuicPacket.hpp
 * @brief RFC 9000 §17 QUIC packet header structure and packing/unpacking.
 */

#pragma once

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

#include <string>
#include <string_view>
#include <cstdint>
#include <cstddef>

#include <wavex/Network/QUIC/QuicConstants.hpp>
#include <wavex/Network/QUIC/ConnectionId.hpp>
#include <wavex/Network/QUIC/VarInt.hpp>

namespace wavex::network::quic {

    struct PacketHeader {
        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        std::string token{};
        uint64_t length{0};
        uint64_t packet_number{0};
        uint32_t version{QUIC_VERSION_1};
        uint32_t pn_offset{0};
        ConnectionId dcid{};
        ConnectionId scid{};
        PacketType type{PacketType::OneRTT};
        uint8_t flags{0};
        uint8_t packet_number_len{4};
        bool is_long{false};
    };

    void pack_packet_header(const PacketHeader &hdr, std::string &out);
    bool unpack_packet_header(std::string_view raw, PacketHeader &hdr, std::size_t &hdr_len, std::size_t expected_dcid_len = 8) noexcept;

} // namespace wavex::network::quic

#endif // WAVEX_HAS_SSL

