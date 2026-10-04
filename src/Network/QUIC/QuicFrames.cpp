// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file QuicFrames.cpp
 * @brief Implementation of RFC 9000 §12 frame serialization and parsing.
 */

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

#include <wavex/Network/QUIC/QuicFrames.hpp>
#include <wavex/Network/QUIC/VarInt.hpp>
#include <wavex/Base/Logger.hpp>

namespace wavex::network::quic {

    void serialize_frame(const Frame &frame, std::string &out) {
        std::visit([&out]<typename T0>(const T0 &f) {
            using T = std::decay_t<T0>;
            if constexpr (std::is_same_v<T, PaddingFrame>) {
                out.append(f.length, '\0');
            } else if constexpr (std::is_same_v<T, PingFrame>) {
                VarInt::encode(static_cast<uint64_t>(FrameType::Ping), out);
            } else if constexpr (std::is_same_v<T, AckFrame>) {
                VarInt::encode(static_cast<uint64_t>(FrameType::Ack), out);
                VarInt::encode(f.largest_acknowledged, out);
                VarInt::encode(f.ack_delay, out);
                const uint64_t additional_ranges = f.ranges.empty() ? 0 : (f.ranges.size() - 1);
                VarInt::encode(additional_ranges, out);
                const uint64_t first_range = f.ranges.empty() ? 0 : f.ranges[0].ack_range_len;
                VarInt::encode(first_range, out);
                for (std::size_t i = 1; i < f.ranges.size(); ++i) {
                    VarInt::encode(f.ranges[i].gap, out);
                    VarInt::encode(f.ranges[i].ack_range_len, out);
                }
            } else if constexpr (std::is_same_v<T, ResetStreamFrame>) {
                VarInt::encode(static_cast<uint64_t>(FrameType::ResetStream), out);
                VarInt::encode(f.stream_id, out);
                VarInt::encode(f.error_code, out);
                VarInt::encode(f.final_size, out);
            } else if constexpr (std::is_same_v<T, StopSendingFrame>) {
                VarInt::encode(static_cast<uint64_t>(FrameType::StopSending), out);
                VarInt::encode(f.stream_id, out);
                VarInt::encode(f.error_code, out);
            } else if constexpr (std::is_same_v<T, CryptoFrame>) {
                VarInt::encode(static_cast<uint64_t>(FrameType::Crypto), out);
                VarInt::encode(f.offset, out);
                VarInt::encode(f.data.size(), out);
                out.append(f.data);
            } else if constexpr (std::is_same_v<T, NewTokenFrame>) {
                VarInt::encode(static_cast<uint64_t>(FrameType::NewToken), out);
                VarInt::encode(f.token.size(), out);
                out.append(f.token);
            } else if constexpr (std::is_same_v<T, StreamFrame>) {
                uint8_t type = 0x08;
                if (f.has_offset) type |= 0x04;
                if (f.has_length) type |= 0x02;
                if (f.fin) type |= 0x01;
                out.push_back(static_cast<char>(type));
                VarInt::encode(f.stream_id, out);
                if (f.has_offset) VarInt::encode(f.offset, out);
                if (f.has_length) VarInt::encode(f.data.size(), out);
                out.append(f.data);
            } else if constexpr (std::is_same_v<T, MaxDataFrame>) {
                VarInt::encode(static_cast<uint64_t>(FrameType::MaxData), out);
                VarInt::encode(f.max_data, out);
            } else if constexpr (std::is_same_v<T, MaxStreamDataFrame>) {
                VarInt::encode(static_cast<uint64_t>(FrameType::MaxStreamData), out);
                VarInt::encode(f.stream_id, out);
                VarInt::encode(f.max_stream_data, out);
            } else if constexpr (std::is_same_v<T, MaxStreamsFrame>) {
                const auto ft = f.bidirectional ? FrameType::MaxStreamsBidi : FrameType::MaxStreamsUni;
                VarInt::encode(static_cast<uint64_t>(ft), out);
                VarInt::encode(f.max_streams, out);
            } else if constexpr (std::is_same_v<T, DataBlockedFrame>) {
                VarInt::encode(static_cast<uint64_t>(FrameType::DataBlocked), out);
                VarInt::encode(f.data_limit, out);
            } else if constexpr (std::is_same_v<T, StreamDataBlockedFrame>) {
                VarInt::encode(static_cast<uint64_t>(FrameType::StreamDataBlocked), out);
                VarInt::encode(f.stream_id, out);
                VarInt::encode(f.stream_data_limit, out);
            } else if constexpr (std::is_same_v<T, StreamsBlockedFrame>) {
                const auto ft = f.bidirectional ? FrameType::StreamsBlockedBidi : FrameType::StreamsBlockedUni;
                VarInt::encode(static_cast<uint64_t>(ft), out);
                VarInt::encode(f.stream_limit, out);
            } else if constexpr (std::is_same_v<T, ConnectionCloseFrame>) {
                const auto ft = f.is_application ? FrameType::ConnectionCloseApp : FrameType::ConnectionCloseQuic;
                VarInt::encode(static_cast<uint64_t>(ft), out);
                VarInt::encode(f.error_code, out);
                if (!f.is_application) VarInt::encode(f.frame_type, out);
                VarInt::encode(f.reason_phrase.size(), out);
                out.append(f.reason_phrase);
            } else if constexpr (std::is_same_v<T, HandshakeDoneFrame>) {
                VarInt::encode(static_cast<uint64_t>(FrameType::HandshakeDone), out);
            }
        }, frame);
    }

    bool parse_frames(const std::string_view payload, std::vector<Frame> &out_frames) {
        std::size_t cursor = 0;
#define PARSE_FAIL(reason) do { \
            wavex::log::warn("[QUIC] parse_frames: decode failed at offset {} in {} bytes: {}", cursor, payload.size(), (reason)); \
            return false; \
        } while(0)

        while (cursor < payload.size()) {
            const std::size_t frame_start_cursor = cursor;
            const auto peek = static_cast<uint8_t>(payload[cursor]);

            // RFC 9000 §19.8 STREAM frame (0x08 - 0x0f)
            if (peek >= 0x08 && peek <= 0x0f) {
                ++cursor;
                StreamFrame sf;
                sf.has_offset = (peek & 0x04) != 0;
                sf.has_length = (peek & 0x02) != 0;
                sf.fin = (peek & 0x01) != 0;

                if (!VarInt::decode(payload, cursor, sf.stream_id)) PARSE_FAIL("STREAM decode stream_id");
                if (sf.has_offset) {
                    if (!VarInt::decode(payload, cursor, sf.offset)) PARSE_FAIL("STREAM decode offset");
                }
                uint64_t len = 0;
                if (sf.has_length) {
                    if (!VarInt::decode(payload, cursor, len)) PARSE_FAIL("STREAM decode len");
                } else {
                    len = payload.size() - cursor;
                }
                if (cursor + len > payload.size()) PARSE_FAIL("STREAM len exceeds payload bounds");
                sf.data = std::string(payload.substr(cursor, len));
                cursor += len;
                out_frames.emplace_back(std::move(sf));
                continue;
            }

            uint64_t raw_type = 0;
            if (!VarInt::decode(payload, cursor, raw_type)) PARSE_FAIL("decode raw_type");
            wavex::log::info("[QUIC] parse_frames: decoded frame type=0x{:02x} at offset {} (payload_size={})",
                              raw_type, frame_start_cursor, payload.size());

            if (raw_type == 0x00) {
                // PADDING
                uint32_t pad_len = 1;
                while (cursor < payload.size() && payload[cursor] == '\0') {
                    ++pad_len;
                    ++cursor;
                }
                out_frames.emplace_back(PaddingFrame{pad_len});
            } else if (raw_type == 0x01) {
                out_frames.emplace_back(PingFrame{});
            } else if (raw_type == 0x02 || raw_type == 0x03) {
                AckFrame ack;
                ack.ecn = (raw_type == 0x03);
                uint64_t range_count = 0, first_range = 0;
                if (!VarInt::decode(payload, cursor, ack.largest_acknowledged)) PARSE_FAIL("ACK decode largest_acknowledged");
                if (!VarInt::decode(payload, cursor, ack.ack_delay)) PARSE_FAIL("ACK decode ack_delay");
                if (!VarInt::decode(payload, cursor, range_count)) PARSE_FAIL("ACK decode range_count");
                if (!VarInt::decode(payload, cursor, first_range)) PARSE_FAIL("ACK decode first_range");
                ack.ranges.push_back(AckRange{0, first_range});
                for (std::size_t i = 0; i < range_count; ++i) {
                    uint64_t gap = 0, len = 0;
                    if (!VarInt::decode(payload, cursor, gap)) PARSE_FAIL("ACK decode range gap");
                    if (!VarInt::decode(payload, cursor, len)) PARSE_FAIL("ACK decode range len");
                    ack.ranges.push_back(AckRange{gap, len});
                }
                out_frames.emplace_back(std::move(ack));
            } else if (raw_type == 0x04) {
                ResetStreamFrame rsf;
                if (!VarInt::decode(payload, cursor, rsf.stream_id)) PARSE_FAIL("RESET_STREAM decode stream_id");
                if (!VarInt::decode(payload, cursor, rsf.error_code)) PARSE_FAIL("RESET_STREAM decode error_code");
                if (!VarInt::decode(payload, cursor, rsf.final_size)) PARSE_FAIL("RESET_STREAM decode final_size");
                out_frames.emplace_back(rsf);
            } else if (raw_type == 0x05) {
                StopSendingFrame ssf;
                if (!VarInt::decode(payload, cursor, ssf.stream_id)) PARSE_FAIL("STOP_SENDING decode stream_id");
                if (!VarInt::decode(payload, cursor, ssf.error_code)) PARSE_FAIL("STOP_SENDING decode error_code");
                out_frames.emplace_back(ssf);
            } else if (raw_type == 0x06) {
                CryptoFrame cf;
                uint64_t len = 0;
                if (!VarInt::decode(payload, cursor, cf.offset)) PARSE_FAIL("CRYPTO decode offset");
                if (!VarInt::decode(payload, cursor, len)) PARSE_FAIL("CRYPTO decode len");
                if (cursor + len > payload.size()) PARSE_FAIL("CRYPTO len exceeds payload bounds");
                cf.data = std::string(payload.substr(cursor, len));
                cursor += len;
                out_frames.emplace_back(std::move(cf));
            } else if (raw_type == 0x07) {
                NewTokenFrame ntf;
                uint64_t len = 0;
                if (!VarInt::decode(payload, cursor, len)) PARSE_FAIL("NEW_TOKEN decode len");
                if (cursor + len > payload.size()) PARSE_FAIL("NEW_TOKEN token exceeds payload bounds");
                ntf.token = std::string(payload.substr(cursor, len));
                cursor += len;
                out_frames.emplace_back(std::move(ntf));
            } else if (raw_type == 0x10) {
                MaxDataFrame mdf;
                if (!VarInt::decode(payload, cursor, mdf.max_data)) PARSE_FAIL("MAX_DATA decode max_data");
                out_frames.emplace_back(mdf);
            } else if (raw_type == 0x11) {
                MaxStreamDataFrame msdf;
                if (!VarInt::decode(payload, cursor, msdf.stream_id)) PARSE_FAIL("MAX_STREAM_DATA decode stream_id");
                if (!VarInt::decode(payload, cursor, msdf.max_stream_data)) PARSE_FAIL("MAX_STREAM_DATA decode max_stream_data");
                out_frames.emplace_back(msdf);
            } else if (raw_type == 0x12 || raw_type == 0x13) {
                MaxStreamsFrame msf;
                msf.bidirectional = (raw_type == 0x12);
                if (!VarInt::decode(payload, cursor, msf.max_streams)) PARSE_FAIL("MAX_STREAMS decode max_streams");
                out_frames.emplace_back(msf);
            } else if (raw_type == 0x14) {
                DataBlockedFrame dbf;
                if (!VarInt::decode(payload, cursor, dbf.data_limit)) PARSE_FAIL("DATA_BLOCKED decode data_limit");
                out_frames.emplace_back(dbf);
            } else if (raw_type == 0x15) {
                StreamDataBlockedFrame sdbf;
                if (!VarInt::decode(payload, cursor, sdbf.stream_id)) PARSE_FAIL("STREAM_DATA_BLOCKED decode stream_id");
                if (!VarInt::decode(payload, cursor, sdbf.stream_data_limit)) PARSE_FAIL("STREAM_DATA_BLOCKED decode stream_data_limit");
                out_frames.emplace_back(sdbf);
            } else if (raw_type == 0x16 || raw_type == 0x17) {
                StreamsBlockedFrame sbf;
                sbf.bidirectional = (raw_type == 0x16);
                if (!VarInt::decode(payload, cursor, sbf.stream_limit)) PARSE_FAIL("STREAMS_BLOCKED decode stream_limit");
                out_frames.emplace_back(sbf);
            } else if (raw_type == 0x1c || raw_type == 0x1d) {
                ConnectionCloseFrame ccf;
                ccf.is_application = (raw_type == 0x1d);
                if (!VarInt::decode(payload, cursor, ccf.error_code)) PARSE_FAIL("CONNECTION_CLOSE decode error_code");
                if (!ccf.is_application && !VarInt::decode(payload, cursor, ccf.frame_type)) PARSE_FAIL("CONNECTION_CLOSE decode frame_type");
                uint64_t r_len = 0;
                if (!VarInt::decode(payload, cursor, r_len)) PARSE_FAIL("CONNECTION_CLOSE decode reason_phrase len");
                if (cursor + r_len > payload.size()) PARSE_FAIL("CONNECTION_CLOSE reason exceeds payload bounds");
                ccf.reason_phrase = std::string(payload.substr(cursor, r_len));
                cursor += r_len;
                out_frames.emplace_back(std::move(ccf));
            } else if (raw_type == 0x18) {
                // NEW_CONNECTION_ID (RFC 9000 §19.15)
                uint64_t seq_num = 0, retire_prior_to = 0;
                if (!VarInt::decode(payload, cursor, seq_num)) PARSE_FAIL("NEW_CONNECTION_ID decode seq_num");
                if (!VarInt::decode(payload, cursor, retire_prior_to)) PARSE_FAIL("NEW_CONNECTION_ID decode retire_prior_to");
                if (cursor >= payload.size()) PARSE_FAIL("NEW_CONNECTION_ID missing cid_len");
                const auto cid_len = static_cast<uint8_t>(payload[cursor++]);
                if (cid_len < 1 || cid_len > MAX_CONNECTION_ID_LEN || cursor + cid_len + 16 > payload.size()) {
                    PARSE_FAIL("NEW_CONNECTION_ID invalid cid_len or exceeds payload bounds");
                }
                cursor += cid_len + 16; // Skip Connection ID + 16-byte Stateless Reset Token
            } else if (raw_type == 0x19) {
                // RETIRE_CONNECTION_ID (RFC 9000 §19.16)
                uint64_t seq_num = 0;
                if (!VarInt::decode(payload, cursor, seq_num)) PARSE_FAIL("RETIRE_CONNECTION_ID decode seq_num");
            } else if (raw_type == 0x1a || raw_type == 0x1b) {
                // PATH_CHALLENGE (0x1a) / PATH_RESPONSE (0x1b) (RFC 9000 §19.17-18)
                if (cursor + 8 > payload.size()) PARSE_FAIL("PATH_CHALLENGE/RESPONSE data exceeds payload bounds");
                cursor += 8;
            } else if (raw_type == 0x1e) {
                out_frames.emplace_back(HandshakeDoneFrame{});
            } else if (raw_type == 0x30) {
                // DATAGRAM without length (RFC 9221)
                cursor = payload.size();
            } else if (raw_type == 0x31) {
                // DATAGRAM with length (RFC 9221)
                uint64_t dlen = 0;
                if (!VarInt::decode(payload, cursor, dlen)) PARSE_FAIL("DATAGRAM decode dlen");
                if (cursor + dlen > payload.size()) PARSE_FAIL("DATAGRAM dlen exceeds payload bounds");
                cursor += dlen;
            } else {
                wavex::log::warn("[QUIC] parse_frames: unrecognized frame type 0x{:02x} at offset {} in {} bytes payload, stopping packet frame parsing",
                                 raw_type, cursor, payload.size());
                break;
            }
        }
        return true;
#undef PARSE_FAIL
    }

} // namespace wavex::network::quic

#endif // WAVEX_HAS_SSL
