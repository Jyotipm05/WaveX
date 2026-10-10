// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file QuicPacket.cpp
 * @brief Implementation of RFC 9000 §17 QUIC packet header packing and unpacking.
 */

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

#include <wavex/Network/QUIC/QuicPacket.hpp>

#include "wavex/Network/QUIC/VarInt.hpp"

namespace wavex::network::quic {
    void pack_packet_header(const PacketHeader &hdr, std::string &out) {
        if (hdr.is_long) {
            uint8_t first = 0xc0; // Long packet (form bit = 1, fixed bit = 1)
            first |= (static_cast<uint8_t>(hdr.type) & 0x03) << 4;
            first |= (hdr.packet_number_len - 1) & 0x03;
            out.push_back(static_cast<char>(first));

            // Version (4 bytes big-endian)
            out.push_back(static_cast<char>((hdr.version >> 24) & 0xff));
            out.push_back(static_cast<char>((hdr.version >> 16) & 0xff));
            out.push_back(static_cast<char>((hdr.version >> 8) & 0xff));
            out.push_back(static_cast<char>(hdr.version & 0xff));

            // DCID
            out.push_back(static_cast<char>(hdr.dcid.length()));
            out.append(reinterpret_cast<const char *>(hdr.dcid.data()), hdr.dcid.length());

            // SCID
            out.push_back(static_cast<char>(hdr.scid.length()));
            out.append(reinterpret_cast<const char *>(hdr.scid.data()), hdr.scid.length());

            if (hdr.type == PacketType::Initial) {
                VarInt::encode(hdr.token.size(), out);
                out.append(hdr.token);
            }

            VarInt::encode(hdr.length, out);

            // Packet number
            for (int i = static_cast<int>(hdr.packet_number_len) - 1; i >= 0; --i) {
                out.push_back(static_cast<char>((hdr.packet_number >> (i * 8)) & 0xff));
            }
        } else {
            // Short header (1-RTT)
            uint8_t first = 0x40; // Short packet (form bit = 0, fixed bit = 1)
            first |= (hdr.packet_number_len - 1) & 0x03;
            out.push_back(static_cast<char>(first));

            // DCID
            out.append(reinterpret_cast<const char *>(hdr.dcid.data()), hdr.dcid.length());

            // Packet number
            for (int i = static_cast<int>(hdr.packet_number_len) - 1; i >= 0; --i) {
                out.push_back(static_cast<char>((hdr.packet_number >> (i * 8)) & 0xff));
            }
        }
    }

    bool unpack_packet_header(const std::string_view raw, PacketHeader &hdr, std::size_t &hdr_len,
                              const std::size_t expected_dcid_len) noexcept {
        if (raw.empty()) return false;
        std::size_t cursor = 0;

        const auto first = static_cast<uint8_t>(raw[cursor++]);
        hdr.is_long = (first & 0x80) != 0;

        if (hdr.is_long) {
            hdr.type = static_cast<PacketType>((first >> 4) & 0x03);
            hdr.packet_number_len = static_cast<uint8_t>((first & 0x03) + 1);

            if (cursor + 4 > raw.size()) return false;
            hdr.version = (static_cast<uint32_t>(static_cast<uint8_t>(raw[cursor])) << 24) |
                          (static_cast<uint32_t>(static_cast<uint8_t>(raw[cursor + 1])) << 16) |
                          (static_cast<uint32_t>(static_cast<uint8_t>(raw[cursor + 2])) << 8) |
                          static_cast<uint32_t>(static_cast<uint8_t>(raw[cursor + 3]));
            cursor += 4;

            // DCID
            if (cursor >= raw.size()) return false;
            const auto dcid_len = static_cast<uint8_t>(raw[cursor++]);
            if (dcid_len > MAX_CONNECTION_ID_LEN || cursor + dcid_len > raw.size()) return false;
            hdr.dcid = ConnectionId(reinterpret_cast<const uint8_t *>(raw.data() + cursor), dcid_len);
            cursor += dcid_len;

            // SCID
            if (cursor >= raw.size()) return false;
            const auto scid_len = static_cast<uint8_t>(raw[cursor++]);
            if (scid_len > MAX_CONNECTION_ID_LEN || cursor + scid_len > raw.size()) return false;
            hdr.scid = ConnectionId(reinterpret_cast<const uint8_t *>(raw.data() + cursor), scid_len);
            cursor += scid_len;

            if (hdr.type == PacketType::Initial) {
                uint64_t token_len = 0;
                if (!VarInt::decode(raw, cursor, token_len)) return false;
                if (cursor + token_len > raw.size()) return false;
                hdr.token = std::string(raw.substr(cursor, token_len));
                cursor += token_len;
            }

            if (!VarInt::decode(raw, cursor, hdr.length)) return false;

            hdr.pn_offset = static_cast<uint32_t>(cursor);
            if (cursor + hdr.packet_number_len <= raw.size()) {
                hdr.packet_number = 0;
                for (std::size_t i = 0; i < hdr.packet_number_len; ++i) {
                    hdr.packet_number = (hdr.packet_number << 8) | static_cast<uint8_t>(raw[cursor + i]);
                }
            }
        } else {
            // Short header (1-RTT)
            hdr.type = PacketType::OneRTT;
            hdr.packet_number_len = static_cast<uint8_t>((first & 0x03) + 1);

            const std::size_t dcid_len = expected_dcid_len > 0 ? expected_dcid_len : 8;
            if (cursor + dcid_len > raw.size()) return false;
            hdr.dcid = ConnectionId(reinterpret_cast<const uint8_t *>(raw.data() + cursor), dcid_len);
            cursor += dcid_len;

            hdr.pn_offset = static_cast<uint32_t>(cursor);
            if (cursor + hdr.packet_number_len <= raw.size()) {
                hdr.packet_number = 0;
                for (std::size_t i = 0; i < hdr.packet_number_len; ++i) {
                    hdr.packet_number = (hdr.packet_number << 8) | static_cast<uint8_t>(raw[cursor + i]);
                }
            }
        }

        hdr_len = cursor;
        return true;
    }
} // namespace wavex::network::quic

#endif // WAVEX_HAS_SSL
