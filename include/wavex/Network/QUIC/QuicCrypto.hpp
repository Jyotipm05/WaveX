// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file QuicCrypto.hpp
 * @brief RFC 9001 QUIC-TLS key derivation and packet protection.
 *
 * Handles Initial Secret derivation, HKDF key expansion,
 * AEAD encryption/decryption, and header protection.
 */

#pragma once

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

#include <wavex/Network/QUIC/ConnectionId.hpp>
#include <wavex/Network/QUIC/QuicPacket.hpp>

namespace wavex::network::quic {
    struct ProtectionKeys {
        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        std::array<uint8_t, 32> secret{};
        std::array<uint8_t, 16> key{};
        std::array<uint8_t, 12> iv{};
        std::array<uint8_t, 16> hp{};
        bool valid{false};
    };

    struct CryptoSuite {
        static auto derive_initial_secrets(
            const ConnectionId &client_dcid,
            ProtectionKeys &client_keys,
            ProtectionKeys &server_keys) noexcept -> bool;

        static auto expand_quic_keys(
            const uint8_t *secret, std::size_t secret_len,
            ProtectionKeys &keys) noexcept -> bool;

        static auto protect_packet(
            const ProtectionKeys &keys,
            PacketHeader &hdr,
            std::string_view plaintext,
            std::string &ciphertext_out) noexcept -> bool;

        static auto unprotect_packet(
            const ProtectionKeys &keys,
            PacketHeader &hdr,
            std::string_view packet_bytes,
            std::string &plaintext_out,
            uint64_t largest_pn = 0,
            std::size_t expected_dcid_len = 8) noexcept -> bool;
    };
} // namespace wavex::network::quic

#endif // WAVEX_HAS_SSL
