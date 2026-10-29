// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file http2session.cpp
 * @brief Non-template helpers of the multiplexed HTTP/2 server session.
 */

#include <wavex/protos/http/http2session.hpp>

namespace wavex::protos::http::http2 {
    std::string session_preamble() {
        std::string out = encoder::serialize_settings({
            {settings_parameter::MAX_CONCURRENT_STREAMS, session_limits::kMaxConcurrentStreams},
            {settings_parameter::INITIAL_WINDOW_SIZE, session_limits::kInitialStreamWindow},
            {settings_parameter::ENABLE_PUSH, 0},
            {settings_parameter::MAX_HEADER_LIST_SIZE, static_cast<uint32_t>(kDefaultMaxHeaderListSize)},
            {settings_parameter::ENABLE_CONNECT_PROTOCOL, 1},
        });
        out += encoder::serialize_window_update(0, session_limits::kConnectionWindow - 65535);
        return out;
    }

    std::string encode_frame(const frame_type type, const uint8_t flags, const uint32_t stream_id,
                             const std::string_view payload) {
        frame_header hdr;
        hdr.length = static_cast<uint32_t>(payload.size());
        hdr.type = type;
        hdr.flags = flags;
        hdr.stream_id = stream_id;
        std::array<uint8_t, frame_header::HEADER_SIZE> bytes{};
        pack_frame_header(hdr, bytes);
        std::string out;
        out.reserve(bytes.size() + payload.size());
        out.append(reinterpret_cast<const char *>(bytes.data()), bytes.size());
        out.append(payload);
        return out;
    }

    std::string encode_header_frames(const uint32_t stream_id, const std::string_view block, const bool end_stream,
                                     const uint32_t max_frame_size) {
        const uint8_t es = end_stream ? flags::END_STREAM : flags::NONE;
        if (block.size() <= max_frame_size) {
            return encode_frame(frame_type::HEADERS, static_cast<uint8_t>(es | flags::END_HEADERS), stream_id, block);
        }
        std::string out = encode_frame(frame_type::HEADERS, es, stream_id, block.substr(0, max_frame_size));
        for (std::size_t offset = max_frame_size; offset < block.size(); offset += max_frame_size) {
            const auto piece = block.substr(offset, max_frame_size);
            const bool last = offset + piece.size() == block.size();
            out += encode_frame(frame_type::CONTINUATION, last ? flags::END_HEADERS : flags::NONE, stream_id, piece);
        }
        return out;
    }

    bool headers_fragment(const frame_header &hdr, const std::string_view payload, std::string_view &fragment) {
        std::size_t cursor = 0;
        std::size_t pad = 0;
        if (hdr.has_flag(flags::PADDED)) {
            if (payload.empty()) return false;
            pad = static_cast<uint8_t>(payload[0]);
            cursor = 1;
        }
        if (hdr.has_flag(flags::PRIORITY)) cursor += 5;
        if (payload.size() < cursor + pad) return false;
        fragment = payload.substr(cursor, payload.size() - cursor - pad);
        return true;
    }

    bool data_payload(const frame_header &hdr, const std::string_view payload, std::string_view &data) {
        if (!hdr.has_flag(flags::PADDED)) {
            data = payload;
            return true;
        }
        if (payload.empty()) return false;
        const std::size_t pad = static_cast<uint8_t>(payload[0]);
        if (payload.size() < 1 + pad) return false;
        data = payload.substr(1, payload.size() - 1 - pad);
        return true;
    }

    uint32_t read_u32(const std::string_view p) noexcept {
        if (p.size() < 4) return 0;
        return (static_cast<uint32_t>(static_cast<uint8_t>(p[0])) << 24) |
               (static_cast<uint32_t>(static_cast<uint8_t>(p[1])) << 16) |
               (static_cast<uint32_t>(static_cast<uint8_t>(p[2])) << 8) |
               static_cast<uint32_t>(static_cast<uint8_t>(p[3]));
    }

    std::string build_request_wire(const uint32_t stream_id,
                                   const std::vector<std::pair<std::string, std::string> > &headers,
                                   const std::string_view body, const bool end_stream) {
        std::string block;
        for (const auto &[name, value]: headers) {
            // Literal Header Field without Indexing, new name (RFC 7541 §6.2.2): no dynamic table effect.
            hpack::encode_integer(block, 0, 4, 0x00);
            hpack::encode_string(block, name);
            hpack::encode_string(block, value);
        }
        const bool body_follows = !body.empty();
        uint8_t hflags = flags::END_HEADERS;
        if (end_stream && !body_follows) hflags |= flags::END_STREAM;
        // The parser takes the block in one frame; its frame header length field is 24 bits.
        std::string wire = encode_frame(frame_type::HEADERS, hflags, stream_id, block);
        for (std::size_t offset = 0; offset < body.size(); offset += 16384) {
            const auto piece = body.substr(offset, 16384);
            const bool last = offset + piece.size() == body.size();
            wire += encode_frame(frame_type::DATA, (last && end_stream) ? flags::END_STREAM : flags::NONE,
                                 stream_id, piece);
        }
        return wire;
    }
} // namespace wavex::protos::http::http2
