// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file QuicConstants.hpp
 * @brief QUIC protocol constants, version identifiers, and enumerations.
 * @reference RFC 9000 (QUIC Transport), RFC 9001 (QUIC-TLS), RFC 9002 (Loss Detection)
 */

#pragma once

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

#include <cstdint>
#include <cstddef>

namespace wavex::network::quic {
    // ─── Version Constants ────────────────────────────────────────────────
    inline constexpr uint32_t QUIC_VERSION_1 = 0x00000001;
    inline constexpr uint32_t QUIC_VERSION_NEGOTIATION = 0x00000000;

    // ─── Size Constants ───────────────────────────────────────────────────
    inline constexpr std::size_t MAX_CONNECTION_ID_LEN = 20;
    inline constexpr std::size_t DEFAULT_MAX_PACKET_SIZE = 1280;

    // ─── Packet Types (RFC 9000 §17) ──────────────────────────────────────
    enum class PacketType : uint8_t {
        Initial = 0x00,
        ZeroRTT = 0x01,
        Handshake = 0x02,
        Retry = 0x03,
        OneRTT = 0x04,
        VersionNegotiation = 0x05
    };

    // ─── Transport Error Codes (RFC 9000 §20.1) ───────────────────────────
    enum class TransportError : uint64_t {
        NoError = 0x00,
        InternalError = 0x01,
        ConnectionRefused = 0x02,
        FlowControlError = 0x03,
        StreamLimitError = 0x04,
        StreamStateError = 0x05,
        FinalSizeError = 0x06,
        FrameEncodingError = 0x07,
        TransportParameterError = 0x08,
        ConnectionIdLimitError = 0x09,
        ProtocolViolation = 0x0a,
        InvalidToken = 0x0b,
        ApplicationError = 0x0c,
        CryptoBufferExceeded = 0x0d,
        KeyUpdateError = 0x0e,
        AeadLimitReached = 0x0f,
        NoViablePath = 0x10
    };

    // ─── Frame Types (RFC 9000 §12.4) ─────────────────────────────────────
    enum class FrameType : uint64_t {
        Padding = 0x00,
        Ping = 0x01,
        Ack = 0x02,
        AckEcn = 0x03,
        ResetStream = 0x04,
        StopSending = 0x05,
        Crypto = 0x06,
        NewToken = 0x07,
        Stream = 0x08,
        StreamOff = 0x0c,
        StreamLen = 0x0a,
        StreamOffLen = 0x0e,
        StreamFin = 0x09,
        StreamOffFin = 0x0d,
        StreamLenFin = 0x0b,
        StreamOffLenFin = 0x0f,
        MaxData = 0x10,
        MaxStreamData = 0x11,
        MaxStreamsBidi = 0x12,
        MaxStreamsUni = 0x13,
        DataBlocked = 0x14,
        StreamDataBlocked = 0x15,
        StreamsBlockedBidi = 0x16,
        StreamsBlockedUni = 0x17,
        NewConnectionId = 0x18,
        RetireConnectionId = 0x19,
        PathChallenge = 0x1a,
        PathResponse = 0x1b,
        ConnectionCloseQuic = 0x1c,
        ConnectionCloseApp = 0x1d,
        HandshakeDone = 0x1e
    };

    // ─── Connection States ────────────────────────────────────────────────
    enum class ConnectionState : uint8_t {
        Initial,
        Handshaking,
        Connected,
        Draining,
        Closed
    };

    // ─── Packet Number Space Helper (RFC 9002 §A.1) ───────────────────────
    inline constexpr std::size_t space_index(const PacketType type) noexcept {
        switch (type) {
            case PacketType::Initial: return 0;
            case PacketType::Handshake: return 1;
            case PacketType::ZeroRTT:
            case PacketType::OneRTT:
            default: return 2;
        }
    }
} // namespace wavex::network::quic

#endif // WAVEX_HAS_SSL
