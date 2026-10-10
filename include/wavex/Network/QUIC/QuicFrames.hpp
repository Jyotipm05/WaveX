// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file QuicFrames.hpp
 * @brief RFC 9000 §12 QUIC frame structures, serialization, and parsing.
 */

#pragma once

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

#include <cstdint>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace wavex::network::quic {
    // ─── Individual Frame Structures ──────────────────────────────────────

    struct PaddingFrame {
        uint32_t length{1};
    };

    struct PingFrame {
    };

    struct AckRange {
        uint64_t gap{0};
        uint64_t ack_range_len{0};
    };

    struct AckFrame {
        std::vector<AckRange> ranges{};
        uint64_t largest_acknowledged{0};
        uint64_t ack_delay{0};
        bool ecn{false};
    };

    struct ResetStreamFrame {
        uint64_t stream_id{0};
        uint64_t error_code{0};
        uint64_t final_size{0};
    };

    struct StopSendingFrame {
        uint64_t stream_id{0};
        uint64_t error_code{0};
    };

    struct CryptoFrame {
        uint64_t offset{0};
        std::string data{};
    };

    struct NewTokenFrame {
        std::string token{};
    };

    struct StreamFrame {
        std::string data{};
        uint64_t stream_id{0};
        uint64_t offset{0};
        bool fin{false};
        bool has_offset{false};
        bool has_length{true};
    };

    struct MaxDataFrame {
        uint64_t max_data{0};
    };

    struct MaxStreamDataFrame {
        uint64_t stream_id{0};
        uint64_t max_stream_data{0};
    };

    struct MaxStreamsFrame {
        uint64_t max_streams{0};
        bool bidirectional{true};
    };

    struct DataBlockedFrame {
        uint64_t data_limit{0};
    };

    struct StreamDataBlockedFrame {
        uint64_t stream_id{0};
        uint64_t stream_data_limit{0};
    };

    struct StreamsBlockedFrame {
        uint64_t stream_limit{0};
        bool bidirectional{true};
    };

    struct ConnectionCloseFrame {
        std::string reason_phrase{};
        uint64_t error_code{0};
        uint64_t frame_type{0};
        bool is_application{false};
    };

    struct HandshakeDoneFrame {
    };

    // ─── Frame Variant ────────────────────────────────────────────────────
    using Frame = std::variant<
        PaddingFrame,
        PingFrame,
        AckFrame,
        ResetStreamFrame,
        StopSendingFrame,
        CryptoFrame,
        NewTokenFrame,
        StreamFrame,
        MaxDataFrame,
        MaxStreamDataFrame,
        MaxStreamsFrame,
        DataBlockedFrame,
        StreamDataBlockedFrame,
        StreamsBlockedFrame,
        ConnectionCloseFrame,
        HandshakeDoneFrame
    >;

    // ─── Serialization/Parsing Interface ──────────────────────────────────
    void serialize_frame(const Frame &frame, std::string &out);

    auto parse_frames(std::string_view payload, std::vector<Frame> &out_frames) -> bool;
} // namespace wavex::network::quic

#endif // WAVEX_HAS_SSL
