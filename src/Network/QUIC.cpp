// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file QUIC.cpp
 * @brief Implementation of RFC 9000 & RFC 9001 QUIC Transport protocol for WaveX.
 */

#include <wavex/Network/QUIC.hpp>
#include <wavex/Base/Logger.hpp>

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <future>

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <random>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <cassert>

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
#include <openssl/hmac.h>
#endif

namespace wavex::network::quic {
    // RFC 9001 §5.2 Initial Salt for QUIC Version 1
    static constexpr uint8_t INITIAL_SALT_V1[20] = {
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
        0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
    };

    // RFC 9000 §A.3 Packet Number Reconstruction
    static uint64_t full_pn(const uint64_t truncated, const uint8_t pn_len, const uint64_t largest_pn) noexcept {
        const uint64_t pn_nbits = static_cast<uint64_t>(pn_len) * 8;
        const uint64_t win = 1ULL << pn_nbits;
        const uint64_t half = win / 2;
        const uint64_t expected = largest_pn + 1;
        uint64_t candidate = (expected & ~(win - 1)) | truncated;
        if (candidate + half <= expected) {
            candidate += win;
        } else if (candidate > expected + half && candidate >= win) {
            candidate -= win;
        }
        return candidate;
    }

    // ─── 1. VarInt Implementation ──────────────────────────────────────────────

    std::size_t VarInt::encoded_size(const uint64_t val) noexcept {
        if (val <= 0x3f) return 1;
        if (val <= 0x3fff) return 2;
        if (val <= 0x3fffffff) return 4;
        return 8;
    }

    void VarInt::encode(const uint64_t val, std::string &out) {
        if (val <= 0x3f) {
            out.push_back(static_cast<char>(val));
        } else if (val <= 0x3fff) {
            out.push_back(static_cast<char>(0x40 | (val >> 8)));
            out.push_back(static_cast<char>(val & 0xff));
        } else if (val <= 0x3fffffff) {
            out.push_back(static_cast<char>(0x80 | (val >> 24)));
            out.push_back(static_cast<char>((val >> 16) & 0xff));
            out.push_back(static_cast<char>((val >> 8) & 0xff));
            out.push_back(static_cast<char>(val & 0xff));
        } else {
            out.push_back(static_cast<char>(0xc0 | (val >> 56)));
            out.push_back(static_cast<char>((val >> 48) & 0xff));
            out.push_back(static_cast<char>((val >> 40) & 0xff));
            out.push_back(static_cast<char>((val >> 32) & 0xff));
            out.push_back(static_cast<char>((val >> 24) & 0xff));
            out.push_back(static_cast<char>((val >> 16) & 0xff));
            out.push_back(static_cast<char>((val >> 8) & 0xff));
            out.push_back(static_cast<char>(val & 0xff));
        }
    }

    std::size_t VarInt::encode(const uint64_t val, uint8_t *out, const std::size_t max_len) noexcept {
        const std::size_t needed = encoded_size(val);
        if (max_len < needed) return 0;

        if (needed == 1) {
            out[0] = static_cast<uint8_t>(val);
        } else if (needed == 2) {
            out[0] = static_cast<uint8_t>(0x40 | (val >> 8));
            out[1] = static_cast<uint8_t>(val & 0xff);
        } else if (needed == 4) {
            out[0] = static_cast<uint8_t>(0x80 | (val >> 24));
            out[1] = static_cast<uint8_t>((val >> 16) & 0xff);
            out[2] = static_cast<uint8_t>((val >> 8) & 0xff);
            out[3] = static_cast<uint8_t>(val & 0xff);
        } else {
            out[0] = static_cast<uint8_t>(0xc0 | (val >> 56));
            out[1] = static_cast<uint8_t>((val >> 48) & 0xff);
            out[2] = static_cast<uint8_t>((val >> 40) & 0xff);
            out[3] = static_cast<uint8_t>((val >> 32) & 0xff);
            out[4] = static_cast<uint8_t>((val >> 24) & 0xff);
            out[5] = static_cast<uint8_t>((val >> 16) & 0xff);
            out[6] = static_cast<uint8_t>((val >> 8) & 0xff);
            out[7] = static_cast<uint8_t>(val & 0xff);
        }
        return needed;
    }

    bool VarInt::decode(const std::string_view buf, std::size_t &cursor, uint64_t &val) noexcept {
        if (cursor >= buf.size()) return false;

        const auto first = static_cast<uint8_t>(buf[cursor]);
        const uint8_t prefix = first >> 6;
        const std::size_t length = 1ULL << prefix;

        if (cursor + length > buf.size()) return false;

        val = first & 0x3f;
        for (std::size_t i = 1; i < length; ++i) {
            val = (val << 8) | static_cast<uint8_t>(buf[cursor + i]);
        }

        cursor += length;
        return true;
    }

    // ─── 2. ConnectionId Implementation ────────────────────────────────────────

    ConnectionId::ConnectionId(const uint8_t *src, const std::size_t len) noexcept {
        length_ = static_cast<uint8_t>(std::min(len, MAX_CONNECTION_ID_LEN));
        if (src && length_ > 0) {
            std::memcpy(data_.data(), src, length_);
        }
    }

    ConnectionId::ConnectionId(const std::string_view sv) noexcept {
        length_ = static_cast<uint8_t>(std::min(sv.size(), MAX_CONNECTION_ID_LEN));
        if (!sv.empty() && length_ > 0) {
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
        ConnectionId cid;
        if (hex.size() % 2 != 0 || hex.size() / 2 > MAX_CONNECTION_ID_LEN) return cid;

        auto hex_val = [](const char c) noexcept -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };

        cid.length_ = static_cast<uint8_t>(hex.size() / 2);
        for (std::size_t i = 0; i < cid.length_; ++i) {
            const int hi = hex_val(hex[i * 2]);
            const int lo = hex_val(hex[i * 2 + 1]);
            if (hi < 0 || lo < 0) {
                return ConnectionId{}; // Malformed hex
            }
            cid.data_[i] = static_cast<uint8_t>((hi << 4) | lo);
        }
        return cid;
    }

    ConnectionId ConnectionId::random(const std::size_t len) {
        ConnectionId cid;
        cid.length_ = static_cast<uint8_t>(std::min(len, MAX_CONNECTION_ID_LEN));

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        if (RAND_bytes(cid.data_.data(), cid.length_) == 1) {
            return cid;
        }
#endif
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

    // ─── 3. Frame Serialization & Parsing ──────────────────────────────────────

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
                VarInt::encode(
                    static_cast<uint64_t>(f.bidirectional ? FrameType::MaxStreamsBidi : FrameType::MaxStreamsUni), out);
                VarInt::encode(f.max_streams, out);
            } else if constexpr (std::is_same_v<T, DataBlockedFrame>) {
                VarInt::encode(static_cast<uint64_t>(FrameType::DataBlocked), out);
                VarInt::encode(f.data_limit, out);
            } else if constexpr (std::is_same_v<T, StreamDataBlockedFrame>) {
                VarInt::encode(static_cast<uint64_t>(FrameType::StreamDataBlocked), out);
                VarInt::encode(f.stream_id, out);
                VarInt::encode(f.stream_data_limit, out);
            } else if constexpr (std::is_same_v<T, StreamsBlockedFrame>) {
                VarInt::encode(
                    static_cast<uint64_t>(
                        f.bidirectional ? FrameType::StreamsBlockedBidi : FrameType::StreamsBlockedUni), out);
                VarInt::encode(f.stream_limit, out);
            } else if constexpr (std::is_same_v<T, ConnectionCloseFrame>) {
                VarInt::encode(
                    static_cast<uint64_t>(f.is_application
                                              ? FrameType::ConnectionCloseApp
                                              : FrameType::ConnectionCloseQuic), out);
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
        while (cursor < payload.size()) {
            uint64_t raw_type = 0;
            if (!VarInt::decode(payload, cursor, raw_type)) return false;

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
                if (!VarInt::decode(payload, cursor, ack.largest_acknowledged)) return false;
                if (!VarInt::decode(payload, cursor, ack.ack_delay)) return false;
                if (!VarInt::decode(payload, cursor, range_count)) return false;
                if (!VarInt::decode(payload, cursor, first_range)) return false;
                ack.ranges.push_back(AckRange{0, first_range});
                for (std::size_t i = 0; i < range_count; ++i) {
                    uint64_t gap = 0, len = 0;
                    if (!VarInt::decode(payload, cursor, gap)) return false;
                    if (!VarInt::decode(payload, cursor, len)) return false;
                    ack.ranges.push_back(AckRange{gap, len});
                }
                out_frames.emplace_back(std::move(ack));
            } else if (raw_type == 0x04) {
                ResetStreamFrame rsf;
                if (!VarInt::decode(payload, cursor, rsf.stream_id)) return false;
                if (!VarInt::decode(payload, cursor, rsf.error_code)) return false;
                if (!VarInt::decode(payload, cursor, rsf.final_size)) return false;
                out_frames.emplace_back(rsf);
            } else if (raw_type == 0x05) {
                StopSendingFrame ssf;
                if (!VarInt::decode(payload, cursor, ssf.stream_id)) return false;
                if (!VarInt::decode(payload, cursor, ssf.error_code)) return false;
                out_frames.emplace_back(ssf);
            } else if (raw_type == 0x06) {
                CryptoFrame cf;
                uint64_t len = 0;
                if (!VarInt::decode(payload, cursor, cf.offset)) return false;
                if (!VarInt::decode(payload, cursor, len)) return false;
                if (cursor + len > payload.size()) return false;
                cf.data = std::string(payload.substr(cursor, len));
                cursor += len;
                out_frames.emplace_back(std::move(cf));
            } else if (raw_type == 0x07) {
                NewTokenFrame ntf;
                uint64_t t_len = 0;
                if (!VarInt::decode(payload, cursor, t_len)) return false;
                if (cursor + t_len > payload.size()) return false;
                ntf.token = std::string(payload.substr(cursor, t_len));
                cursor += t_len;
                out_frames.emplace_back(std::move(ntf));
            } else if (raw_type >= 0x08 && raw_type <= 0x0f) {
                StreamFrame sf;
                sf.has_offset = (raw_type & 0x04) != 0;
                sf.has_length = (raw_type & 0x02) != 0;
                sf.fin = (raw_type & 0x01) != 0;
                if (!VarInt::decode(payload, cursor, sf.stream_id)) return false;
                if (sf.has_offset && !VarInt::decode(payload, cursor, sf.offset)) return false;
                uint64_t data_len = payload.size() - cursor;
                if (sf.has_length) {
                    if (!VarInt::decode(payload, cursor, data_len)) return false;
                }
                if (cursor + data_len > payload.size()) return false;
                sf.data = std::string(payload.substr(cursor, data_len));
                cursor += data_len;
                out_frames.emplace_back(std::move(sf));
            } else if (raw_type == 0x10) {
                MaxDataFrame mdf;
                if (!VarInt::decode(payload, cursor, mdf.max_data)) return false;
                out_frames.emplace_back(mdf);
            } else if (raw_type == 0x11) {
                MaxStreamDataFrame msdf;
                if (!VarInt::decode(payload, cursor, msdf.stream_id)) return false;
                if (!VarInt::decode(payload, cursor, msdf.max_stream_data)) return false;
                out_frames.emplace_back(msdf);
            } else if (raw_type == 0x12 || raw_type == 0x13) {
                MaxStreamsFrame msf;
                msf.bidirectional = (raw_type == 0x12);
                if (!VarInt::decode(payload, cursor, msf.max_streams)) return false;
                out_frames.emplace_back(msf);
            } else if (raw_type == 0x14) {
                DataBlockedFrame dbf;
                if (!VarInt::decode(payload, cursor, dbf.data_limit)) return false;
                out_frames.emplace_back(dbf);
            } else if (raw_type == 0x15) {
                StreamDataBlockedFrame sdbf;
                if (!VarInt::decode(payload, cursor, sdbf.stream_id)) return false;
                if (!VarInt::decode(payload, cursor, sdbf.stream_data_limit)) return false;
                out_frames.emplace_back(sdbf);
            } else if (raw_type == 0x16 || raw_type == 0x17) {
                StreamsBlockedFrame sbf;
                sbf.bidirectional = (raw_type == 0x16);
                if (!VarInt::decode(payload, cursor, sbf.stream_limit)) return false;
                out_frames.emplace_back(sbf);
            } else if (raw_type == 0x1c || raw_type == 0x1d) {
                ConnectionCloseFrame ccf;
                ccf.is_application = (raw_type == 0x1d);
                if (!VarInt::decode(payload, cursor, ccf.error_code)) return false;
                if (!ccf.is_application && !VarInt::decode(payload, cursor, ccf.frame_type)) return false;
                uint64_t r_len = 0;
                if (!VarInt::decode(payload, cursor, r_len)) return false;
                if (cursor + r_len > payload.size()) return false;
                ccf.reason_phrase = std::string(payload.substr(cursor, r_len));
                cursor += r_len;
                out_frames.emplace_back(std::move(ccf));
            } else if (raw_type == 0x1e) {
                out_frames.emplace_back(HandshakeDoneFrame{});
            } else {
                // Unknown or unhandled frame, skip payload remainder
                break;
            }
        }
        return true;
    }

    // ─── 4. Packet Packing & Unpacking ─────────────────────────────────────────

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

    // ─── 5. Crypto Suite (RFC 9001) ────────────────────────────────────────────

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
    static bool hkdf_expand_label(
        const uint8_t *secret, std::size_t secret_len,
        const std::string_view label,
        uint8_t *out, std::size_t out_len) noexcept {
        // Construct HkdfLabel: Length (2 bytes), "tls13 " + Label (1 byte len + chars), Context (0 len)
        std::string hkdf_label;
        hkdf_label.push_back(static_cast<char>((out_len >> 8) & 0xff));
        hkdf_label.push_back(static_cast<char>(out_len & 0xff));

        const std::string full_label = "tls13 " + std::string(label);
        hkdf_label.push_back(static_cast<char>(full_label.size()));
        hkdf_label.append(full_label);
        hkdf_label.push_back(0); // empty context

        // Multi-block RFC 5869 HKDF-Expand loop
        std::size_t pos = 0;
        uint8_t counter = 1;
        std::string prev_t;

        while (pos < out_len) {
            std::string info;
            info.reserve(prev_t.size() + hkdf_label.size() + 1);
            info.append(prev_t);
            info.append(hkdf_label);
            info.push_back(static_cast<char>(counter++));

            unsigned int len = 0;
            uint8_t hmac_out[32];
            if (!HMAC(EVP_sha256(), secret, static_cast<int>(secret_len),
                      reinterpret_cast<const unsigned char *>(info.data()), info.size(),
                      hmac_out, &len)) {
                return false;
            }

            const std::size_t to_copy = std::min(out_len - pos, static_cast<std::size_t>(len));
            std::memcpy(out + pos, hmac_out, to_copy);
            pos += to_copy;
            prev_t.assign(reinterpret_cast<const char *>(hmac_out), len);
        }

        return true;
    }
#endif

    bool CryptoSuite::derive_initial_secrets(
        const ConnectionId &client_dcid,
        ProtectionKeys &client_keys,
        ProtectionKeys &server_keys) noexcept {
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        // 1. Initial Secret = HKDF-Extract(salt, client_dcid)
        unsigned int initial_secret_len = 0;
        uint8_t initial_secret[32];
        if (!HMAC(EVP_sha256(), INITIAL_SALT_V1, sizeof(INITIAL_SALT_V1),
                  client_dcid.data(), client_dcid.length(),
                  initial_secret, &initial_secret_len)) {
            return false;
        }

        // 2. Client & Server Initial Secrets
        hkdf_expand_label(initial_secret, 32, "client in", client_keys.secret.data(), 32);
        hkdf_expand_label(initial_secret, 32, "server in", server_keys.secret.data(), 32);

        // 3. Client Key, IV, HP Key
        hkdf_expand_label(client_keys.secret.data(), 32, "quic key", client_keys.key.data(), 16);
        hkdf_expand_label(client_keys.secret.data(), 32, "quic iv", client_keys.iv.data(), 12);
        hkdf_expand_label(client_keys.secret.data(), 32, "quic hp", client_keys.hp.data(), 16);
        client_keys.valid = true;

        // 4. Server Key, IV, HP Key
        hkdf_expand_label(server_keys.secret.data(), 32, "quic key", server_keys.key.data(), 16);
        hkdf_expand_label(server_keys.secret.data(), 32, "quic iv", server_keys.iv.data(), 12);
        hkdf_expand_label(server_keys.secret.data(), 32, "quic hp", server_keys.hp.data(), 16);
        server_keys.valid = true;
        return true;
#else
        // Fallback mock keys
        std::fill(client_keys.key.begin(), client_keys.key.end(), 0xaa);
        std::fill(client_keys.iv.begin(), client_keys.iv.end(), 0xbb);
        std::fill(client_keys.hp.begin(), client_keys.hp.end(), 0xcc);
        client_keys.valid = true;

        std::fill(server_keys.key.begin(), server_keys.key.end(), 0xdd);
        std::fill(server_keys.iv.begin(), server_keys.iv.end(), 0xee);
        std::fill(server_keys.hp.begin(), server_keys.hp.end(), 0xff);
        server_keys.valid = true;
        return true;
#endif
    }

    bool CryptoSuite::expand_quic_keys(
        const uint8_t *secret, const std::size_t secret_len,
        ProtectionKeys &keys) noexcept {
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        if (!secret || secret_len == 0) return false;
        std::memcpy(keys.secret.data(), secret, std::min(secret_len, keys.secret.size()));
        hkdf_expand_label(secret, secret_len, "quic key", keys.key.data(), 16);
        hkdf_expand_label(secret, secret_len, "quic iv", keys.iv.data(), 12);
        hkdf_expand_label(secret, secret_len, "quic hp", keys.hp.data(), 16);
        keys.valid = true;
        return true;
#else
        (void) secret;
        (void) secret_len;
        std::fill(keys.key.begin(), keys.key.end(), 0x11);
        std::fill(keys.iv.begin(), keys.iv.end(), 0x22);
        std::fill(keys.hp.begin(), keys.hp.end(), 0x33);
        keys.valid = true;
        return true;
#endif
    }

    bool CryptoSuite::protect_packet(
        const ProtectionKeys &keys,
        PacketHeader &hdr,
        const std::string_view plaintext,
        std::string &ciphertext_out) noexcept {
        if (!keys.valid) return false;
        if (hdr.packet_number_len == 0) {
            hdr.packet_number_len = 4;
        }
        if (hdr.is_long) {
            hdr.length = plaintext.size() + 16 + hdr.packet_number_len; // + 16 auth tag
        }
        std::string header_bytes;
        pack_packet_header(hdr, header_bytes);
        const std::size_t pn_offset = header_bytes.size() - hdr.packet_number_len;

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        // Calculate Nonce = IV ^ PacketNumber
        std::array<uint8_t, 12> nonce = keys.iv;
        for (int i = 0; i < 8; ++i) {
            nonce[11 - i] ^= static_cast<uint8_t>((hdr.packet_number >> (i * 8)) & 0xff);
        }

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;

        bool ok = true;
        int out_len = 0;
        std::vector<uint8_t> encrypted(plaintext.size() + 16);

        if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, keys.key.data(), nonce.data()) != 1) ok = false;
        if (ok && EVP_EncryptUpdate(ctx, nullptr, &out_len, reinterpret_cast<const uint8_t *>(header_bytes.data()),
                                    static_cast<int>(header_bytes.size())) != 1) ok = false;
        if (ok && EVP_EncryptUpdate(ctx, encrypted.data(), &out_len,
                                    reinterpret_cast<const uint8_t *>(plaintext.data()),
                                    static_cast<int>(plaintext.size())) != 1) ok = false;
        if (ok && EVP_EncryptFinal_ex(ctx, encrypted.data() + out_len, &out_len) != 1) ok = false;
        if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, encrypted.data() + plaintext.size()) != 1)
            ok = false;

        EVP_CIPHER_CTX_free(ctx);
        if (!ok) return false;

        ciphertext_out = header_bytes;
        ciphertext_out.append(reinterpret_cast<const char *>(encrypted.data()), encrypted.size());

        // Apply RFC 9001 §5.4 Header Protection
        const std::size_t sample_offset = pn_offset + 4;
        if (ciphertext_out.size() >= sample_offset + 16) {
            const auto *sample = reinterpret_cast<const uint8_t *>(ciphertext_out.data() + sample_offset);
            uint8_t mask[16] = {0};

            if (EVP_CIPHER_CTX *hp_ctx = EVP_CIPHER_CTX_new()) {
                int hp_len = 0;
                if (EVP_EncryptInit_ex(hp_ctx, EVP_aes_128_ecb(), nullptr, keys.hp.data(), nullptr) == 1 &&
                    EVP_CIPHER_CTX_set_padding(hp_ctx, 0) == 1 &&
                    EVP_EncryptUpdate(hp_ctx, mask, &hp_len, sample, 16) == 1) {
                    // Mask first byte
                    if (hdr.is_long) {
                        ciphertext_out[0] ^= static_cast<char>(mask[0] & 0x0f);
                    } else {
                        ciphertext_out[0] ^= static_cast<char>(mask[0] & 0x1f);
                    }

                    // Mask packet number bytes
                    for (std::size_t i = 0; i < hdr.packet_number_len; ++i) {
                        ciphertext_out[pn_offset + i] ^= static_cast<char>(mask[1 + i]);
                    }
                }
                EVP_CIPHER_CTX_free(hp_ctx);
            }
        }
        return true;
#else
        // Passthrough with 16 zero tag bytes for non-SSL mock builds
        ciphertext_out = header_bytes;
        ciphertext_out.append(plaintext);
        ciphertext_out.append(16, '\0');
        return true;
#endif
    }

    bool CryptoSuite::unprotect_packet(
        const ProtectionKeys &keys,
        PacketHeader &hdr,
        const std::string_view packet_bytes,
        std::string &plaintext_out,
        const uint64_t largest_pn,
        const std::size_t expected_dcid_len) noexcept {
        if (packet_bytes.empty()) return false;

        std::size_t hdr_len = 0;
        if (!unpack_packet_header(packet_bytes, hdr, hdr_len, expected_dcid_len)) return false;

        const std::size_t pn_offset = hdr.pn_offset;

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        // Step 1: Remove Header Protection (RFC 9001 §5.4)
        const std::size_t sample_offset = pn_offset + 4;
        if (packet_bytes.size() < sample_offset + 16) return false;

        const auto *sample = reinterpret_cast<const uint8_t *>(packet_bytes.data() + sample_offset);
        uint8_t mask[16] = {0};

        EVP_CIPHER_CTX *hp_ctx = EVP_CIPHER_CTX_new();
        if (!hp_ctx) return false;

        int hp_len = 0;
        bool hp_ok = (EVP_EncryptInit_ex(hp_ctx, EVP_aes_128_ecb(), nullptr, keys.hp.data(), nullptr) == 1 &&
                      EVP_CIPHER_CTX_set_padding(hp_ctx, 0) == 1 &&
                      EVP_EncryptUpdate(hp_ctx, mask, &hp_len, sample, 16) == 1);
        EVP_CIPHER_CTX_free(hp_ctx);
        if (!hp_ok) return false;

        // Unmask first byte
        uint8_t first_byte = static_cast<uint8_t>(packet_bytes[0]);
        if (hdr.is_long) {
            first_byte ^= (mask[0] & 0x0f);
        } else {
            first_byte ^= (mask[0] & 0x1f);
        }
        const auto pn_len = static_cast<uint8_t>((first_byte & 0x03) + 1);
        hdr.packet_number_len = pn_len;

        if (packet_bytes.size() < pn_offset + pn_len + 16) return false;

        // Unmask packet number
        uint64_t truncated_pn = 0;
        for (std::size_t i = 0; i < pn_len; ++i) {
            const uint8_t b = static_cast<uint8_t>(packet_bytes[pn_offset + i]) ^ mask[1 + i];
            truncated_pn = (truncated_pn << 8) | b;
        }

        // Reconstruct full 64-bit packet number (RFC 9000 §A.3)
        const uint64_t full_packet_num = full_pn(truncated_pn, pn_len, largest_pn);
        hdr.packet_number = full_packet_num;

        // Step 2: Reconstruct the UNMASKED header for AAD
        const std::size_t real_hdr_len = pn_offset + pn_len;
        std::string unmasked_hdr(packet_bytes.substr(0, real_hdr_len));
        unmasked_hdr[0] = static_cast<char>(first_byte);
        for (std::size_t i = 0; i < pn_len; ++i) {
            unmasked_hdr[pn_offset + i] = static_cast<char>(
                static_cast<uint8_t>(packet_bytes[pn_offset + i]) ^ mask[1 + i]);
        }

        // Step 3: Payload starts at real_hdr_len
        std::size_t total_packet_len = packet_bytes.size();
        if (hdr.is_long && hdr.length > 0) {
            const std::size_t expected_long_len = pn_offset + static_cast<std::size_t>(hdr.length);
            if (expected_long_len <= packet_bytes.size()) {
                total_packet_len = expected_long_len;
            }
        }

        if (total_packet_len < real_hdr_len + 16) return false;
        const std::string_view payload = packet_bytes.substr(real_hdr_len, total_packet_len - real_hdr_len);

        // Step 4: Calculate Nonce = IV ^ FullPacketNumber (RFC 9001 §5.3)
        std::array<uint8_t, 12> nonce = keys.iv;
        for (int i = 0; i < 8; ++i) {
            nonce[11 - i] ^= static_cast<uint8_t>((full_packet_num >> (i * 8)) & 0xff);
        }

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;

        const std::size_t cipher_len = payload.size() - 16;
        const auto *cipher_data = reinterpret_cast<const uint8_t *>(payload.data());
        const auto *tag_data = cipher_data + cipher_len;

        std::vector<uint8_t> decrypted(cipher_len);
        int out_len = 0;
        bool ok = true;

        if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, keys.key.data(), nonce.data()) != 1) ok = false;
        if (ok && EVP_DecryptUpdate(ctx, nullptr, &out_len, reinterpret_cast<const uint8_t *>(unmasked_hdr.data()),
                                    static_cast<int>(unmasked_hdr.size())) != 1) ok = false;
        if (ok && EVP_DecryptUpdate(ctx, decrypted.data(), &out_len, cipher_data, static_cast<int>(cipher_len)) != 1)
            ok = false;
        if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t *>(tag_data)) != 1) ok = false;
        if (ok && EVP_DecryptFinal_ex(ctx, decrypted.data() + out_len, &out_len) <= 0) ok = false;

        EVP_CIPHER_CTX_free(ctx);
        if (!ok) return false;

        plaintext_out.assign(reinterpret_cast<const char *>(decrypted.data()), cipher_len);
        return true;
#else
        // Mock decode: strip 16 byte trailing tag
        if (hdr_len >= packet_bytes.size()) return false;
        const std::string_view payload = packet_bytes.substr(hdr_len);
        if (payload.size() < 16) return false;
        plaintext_out.assign(payload.data(), payload.size() - 16);
        return true;
#endif
    }

    // ─── 6. QuicStream Implementation ──────────────────────────────────────────

    QuicStream::QuicStream(const std::shared_ptr<QuicConnection> &conn, const uint64_t stream_id,
                           asio::any_io_executor executor) noexcept
        : conn_(conn), executor_(std::move(executor)), stream_id_(stream_id) {
    }

    QuicStream::~QuicStream() {
        close();
    }

    asio::any_io_executor QuicStream::get_executor() const noexcept {
        if (executor_) return executor_;
        if (auto c = conn_.lock()) {
            if (auto conn_ex = c->get_executor()) return conn_ex;
        }
        return asio::any_io_executor(asio::system_executor{});
    }

    bool QuicStream::is_open() const noexcept {
        std::lock_guard lock(mtx_);
        return is_open_;
    }

    bool QuicStream::is_fin_received() const noexcept {
        std::lock_guard lock(mtx_);
        return fin_received_;
    }

    bool QuicStream::is_fin_sent() const noexcept {
        std::lock_guard lock(mtx_);
        return fin_sent_;
    }

    std::error_code QuicStream::cancel(std::error_code &ec) noexcept {
        ec.clear();
        std::lock_guard lock(mtx_);
        if (pending_read_) {
            auto cb = std::move(*pending_read_);
            pending_read_.reset();
            cb(asio::error::operation_aborted, 0);
        }
        return ec;
    }

    std::error_code QuicStream::shutdown(const asio::ip::tcp::socket::shutdown_type type,
                                         std::error_code &ec) noexcept {
        ec.clear();
        bool need_fin = false; {
            std::lock_guard lock(mtx_);
            if (type == asio::ip::tcp::socket::shutdown_send || type == asio::ip::tcp::socket::shutdown_both) {
                if (!fin_sent_) {
                    fin_sent_ = true;
                    need_fin = true;
                }
            }
            if (type == asio::ip::tcp::socket::shutdown_receive || type == asio::ip::tcp::socket::shutdown_both) {
                fin_received_ = true;
            }
        }
        if (need_fin) {
            if (auto conn = conn_.lock()) {
                conn->queue_stream_data(stream_id_, "", true);
            }
        }
        return ec;
    }

    std::error_code QuicStream::close(std::error_code &ec) noexcept {
        ec.clear();
        close();
        return ec;
    }

    void QuicStream::close() noexcept {
        ReadCallback cb;
        bool need_fin = false; {
            std::lock_guard lock(mtx_);
            if (!is_open_) return;
            is_open_ = false;
            if (!fin_sent_) {
                fin_sent_ = true;
                need_fin = true;
            }
            if (pending_read_) {
                cb = std::move(*pending_read_);
                pending_read_.reset();
            }
        }
        if (need_fin) {
            if (auto conn = conn_.lock()) {
                conn->queue_stream_data(stream_id_, "", true);
            }
        }
        if (cb) {
            cb(asio::error::connection_reset, 0);
        }
    }

    std::size_t QuicStream::available(std::error_code &ec) const noexcept {
        ec.clear();
        std::lock_guard lock(mtx_);
        return in_buffer_.size();
    }

    std::size_t QuicStream::read_some(const asio::mutable_buffer &buffer, std::error_code &ec) noexcept {
        ec.clear();
        std::lock_guard lock(mtx_);
        if (in_buffer_.empty()) {
            if (fin_received_ || !is_open_) {
                ec = asio::error::eof;
            }
            return 0;
        }

        const std::size_t to_read = std::min(buffer.size(), in_buffer_.size());
        auto *dest = static_cast<uint8_t *>(buffer.data());
        for (std::size_t i = 0; i < to_read; ++i) {
            dest[i] = in_buffer_.front();
            in_buffer_.pop_front();
        }
        return to_read;
    }

    void QuicStream::push_inbound(const std::string_view data, const bool fin) {
        ReadCallback cb;
        std::size_t bytes_transferred = 0;
        std::error_code ec; {
            std::lock_guard lock(mtx_);
            if (fin) fin_received_ = true;

            if (pending_read_ && pending_buf_ && pending_buf_size_ > 0) {
                // Fulfill pending read immediately
                const std::size_t to_copy = std::min(data.size(), pending_buf_size_);
                std::memcpy(pending_buf_, data.data(), to_copy);
                bytes_transferred = to_copy;

                // Any leftover bytes go into in_buffer_
                for (std::size_t i = to_copy; i < data.size(); ++i) {
                    in_buffer_.push_back(static_cast<uint8_t>(data[i]));
                }

                cb = std::move(*pending_read_);
                pending_read_.reset();
                pending_buf_ = nullptr;
                pending_buf_size_ = 0;
            } else {
                for (const char c: data) {
                    in_buffer_.push_back(static_cast<uint8_t>(c));
                }
                if (fin && pending_read_) {
                    cb = std::move(*pending_read_);
                    pending_read_.reset();
                    ec = asio::error::eof;
                }
            }
        }

        if (cb) {
            cb(ec, bytes_transferred);
        }
    }

    std::error_code QuicStream::write_outbound(const std::string_view data, const bool fin) {
        if (auto conn = conn_.lock()) {
            if (fin) {
                std::lock_guard lock(mtx_);
                fin_sent_ = true;
            }
            conn->queue_stream_data(stream_id_, data, fin);
            return {};
        }
        return asio::error::not_connected;
    }

    // ─── 7. QuicConnection Implementation ──────────────────────────────────────

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
    QuicConnection::TlsCtx::~TlsCtx() {
        if (ssl) {
            SSL_free(ssl);
            ssl = nullptr;
        }
        if (ctx) {
            SSL_CTX_free(ctx);
            ctx = nullptr;
        }
    }

    extern "C" {
    static int quic_tls_crypto_send(
        SSL * /*s*/, const unsigned char *buf, size_t buf_len,
        size_t *consumed, void *arg) {
        if (!arg || !buf || buf_len == 0) return 0;
        auto *conn = static_cast<QuicConnection *>(arg);
        wavex::log::info("[QUIC] crypto_send_fn: {} bytes at write_level={}", buf_len, conn->current_write_level());
        conn->queue_crypto_frame(std::string_view(reinterpret_cast<const char *>(buf), buf_len));
        if (consumed) *consumed = buf_len;
        return 1;
    }

    static int quic_tls_crypto_recv_rcd(
        SSL * /*s*/, const unsigned char **buf, size_t *bytes_read,
        void *arg) {
        if (!arg || !buf || !bytes_read) return 0;
        auto *conn = static_cast<QuicConnection *>(arg);
        const int res = conn->on_tls_crypto_recv(buf, bytes_read);
        if (*bytes_read > 0) {
            wavex::log::info("[QUIC] crypto_recv_rcd: supplied {} bytes to TLS engine", *bytes_read);
        }
        return res;
    }

    static int quic_tls_crypto_release_rcd(
        SSL * /*s*/, size_t bytes_read, void *arg) {
        if (!arg) return 0;
        auto *conn = static_cast<QuicConnection *>(arg);
        wavex::log::info("[QUIC] crypto_release_rcd: released {} bytes", bytes_read);
        return conn->on_tls_crypto_release(bytes_read);
    }

    static int quic_tls_yield_secret(
        SSL * /*s*/, uint32_t prot_level, int direction,
        const unsigned char *secret, size_t secret_len, void *arg) {
        if (!arg || !secret) return 0;
        auto *conn = static_cast<QuicConnection *>(arg);
        wavex::log::info("[QUIC] yield_secret: prot_level={} direction={} (0=read,1=write) len={}",
                         prot_level, direction, secret_len);
        return conn->on_tls_secret(prot_level, direction, secret, secret_len);
    }

    static int quic_tls_got_transport_params(
        SSL * /*s*/, const unsigned char *params, size_t params_len,
        void *arg) {
        if (!arg) return 0;
        auto *conn = static_cast<QuicConnection *>(arg);
        wavex::log::info("[QUIC] got_transport_params: len={}", params_len);
        return conn->on_tls_transport_params(params, params_len);
    }

    static int quic_tls_alert(
        SSL * /*s*/, unsigned char alert_code, void * /*arg*/) {
        wavex::log::warn("[QUIC] tls_alert: alert_code={}", alert_code);
        return 1;
    }
    } // extern "C"
#else
    QuicConnection::TlsCtx::~TlsCtx() = default;
#endif

    void QuicConnection::CryptoStreamReassembler::insert(const uint64_t offset, const std::string_view data) {
        if (data.empty()) return;
        if (offset + data.size() <= next_offset) return;
        pending.emplace(offset, std::string(data));
        while (!pending.empty()) {
            const auto it = pending.begin();
            if (it->first > next_offset) break;
            const uint64_t end = it->first + it->second.size();
            if (end > next_offset) {
                const std::size_t overlap = static_cast<std::size_t>(next_offset - it->first);
                ready.append(it->second.data() + overlap, it->second.size() - overlap);
                next_offset = end;
            }
            pending.erase(it);
        }
    }

    std::string_view QuicConnection::CryptoStreamReassembler::available() const noexcept {
        if (ready_consumed >= ready.size()) return {};
        return std::string_view(ready.data() + ready_consumed, ready.size() - ready_consumed);
    }

    void QuicConnection::CryptoStreamReassembler::consume(const std::size_t bytes) {
        ready_consumed += bytes;
        if (ready_consumed >= ready.size()) {
            ready.clear();
            ready_consumed = 0;
        } else if (ready_consumed > 65536) {
            ready.erase(0, ready_consumed);
            ready_consumed = 0;
        }
    }

    bool QuicConnection::CryptoStreamReassembler::has_available() const noexcept {
        return ready_consumed < ready.size();
    }

    QuicConnection::CryptoStreamReassembler &QuicConnection::reassembler_for_level(uint32_t level) noexcept {
        if (level >= crypto_reassemblers_.size()) level = 0;
        return crypto_reassemblers_[level];
    }

    QuicConnection::CryptoStreamReassembler &QuicConnection::reassembler_for_pkt_type(const PacketType type) noexcept {
        switch (type) {
            case PacketType::Initial: return crypto_reassemblers_[0];
            case PacketType::ZeroRTT: return crypto_reassemblers_[1];
            case PacketType::Handshake: return crypto_reassemblers_[2];
            case PacketType::OneRTT:
            default: return crypto_reassemblers_[3];
        }
    }

    QuicConnection::~QuicConnection() = default;

    QuicConnection::QuicConnection(
        ConnectionId local_cid,
        ConnectionId peer_cid,
        asio::ip::udp::endpoint peer_ep,
        const bool is_server,
        asio::any_io_executor executor,
        ConnectionId initial_dcid) noexcept
        : peer_endpoint_(std::move(peer_ep)),
          executor_(std::move(executor)),
          local_cid_(std::move(local_cid)),
          peer_cid_(std::move(peer_cid)),
          original_dcid_(std::move(initial_dcid)),
          is_server_(is_server) {
        const ConnectionId &secret_cid = (!original_dcid_.empty()) ? original_dcid_ : peer_cid_;
        if (is_server_) {
            CryptoSuite::derive_initial_secrets(secret_cid, initial_keys_peer_, initial_keys_local_);
        } else {
            CryptoSuite::derive_initial_secrets(secret_cid, initial_keys_local_, initial_keys_peer_);
        }
    }

    bool QuicConnection::init_tls_handshake_engine() {
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        if (tls_ && tls_->initialized) return true;
        if (!tls_) tls_ = std::make_unique<TlsCtx>();

        tls_->ctx = SSL_CTX_new(is_server_ ? TLS_server_method() : TLS_client_method());
        if (!tls_->ctx) {
            wavex::log::error("[QUIC] init_tls_handshake_engine: SSL_CTX_new failed");
            return false;
        }

        SSL_CTX_set_min_proto_version(tls_->ctx, TLS1_3_VERSION);
        SSL_CTX_set_max_proto_version(tls_->ctx, TLS1_3_VERSION);

        // Standard TLS 1.3 cipher suite preferred for QUIC
        SSL_CTX_set_ciphersuites(tls_->ctx, "TLS_AES_128_GCM_SHA256");

        // Ground-truth tooling: support SSLKEYLOGFILE for Wireshark / diagnostic interop
        if (const char *keylog_path = std::getenv("SSLKEYLOGFILE")) {
            SSL_CTX_set_keylog_callback(
                tls_->ctx,
                [](const SSL *, const char *line) {
                    if (const char *path = std::getenv("SSLKEYLOGFILE")) {
                        if (std::ofstream ofs(path, std::ios::app); ofs.is_open()) {
                            ofs << line << "\n";
                        }
                    }
                });
        }

        if (is_server_) {
            if (!tls_cert_file_.empty() && !tls_key_file_.empty()) {
                std::string cert_file = tls_cert_file_;
                std::string key_file = tls_key_file_;
                std::error_code ec;
                if (!std::filesystem::exists(cert_file, ec)) {
#ifdef PROJECT_DIR
                    std::string alt = std::string(PROJECT_DIR) + "/" + cert_file;
                    if (std::filesystem::exists(alt, ec)) cert_file = alt;
#endif
                    if (!std::filesystem::exists(cert_file, ec) && std::filesystem::exists("../" + tls_cert_file_, ec)) {
                        cert_file = "../" + tls_cert_file_;
                    }
                }
                if (!std::filesystem::exists(key_file, ec)) {
#ifdef PROJECT_DIR
                    std::string alt = std::string(PROJECT_DIR) + "/" + key_file;
                    if (std::filesystem::exists(alt, ec)) key_file = alt;
#endif
                    if (!std::filesystem::exists(key_file, ec) && std::filesystem::exists("../" + tls_key_file_, ec)) {
                        key_file = "../" + tls_key_file_;
                    }
                }

                if (SSL_CTX_use_certificate_file(tls_->ctx, cert_file.c_str(), SSL_FILETYPE_PEM) != 1) {
                    wavex::log::error("[QUIC] init_tls_handshake_engine: SSL_CTX_use_certificate_file failed for '{}'", cert_file);
                    return false;
                }
                if (SSL_CTX_use_PrivateKey_file(tls_->ctx, key_file.c_str(), SSL_FILETYPE_PEM) != 1) {
                    wavex::log::error("[QUIC] init_tls_handshake_engine: SSL_CTX_use_PrivateKey_file failed for '{}'", key_file);
                    return false;
                }
                wavex::log::info("[QUIC] init_tls_handshake_engine: loaded cert '{}' and key '{}'", cert_file, key_file);
            } else {
                wavex::log::warn("[QUIC] init_tls_handshake_engine: is_server=true but cert ('{}') or key ('{}') is empty!",
                                 tls_cert_file_, tls_key_file_);
            }

            // ALPN selection callback for server (mandated by RFC 9001 §8.1)
            SSL_CTX_set_alpn_select_cb(
                tls_->ctx,
                [](SSL * /*ssl*/,
                   const unsigned char **out,
                   unsigned char *outlen,
                   const unsigned char *in,
                   unsigned int inlen,
                   void * /*arg*/) -> int {
                    unsigned int i = 0;
                    while (i < inlen) {
                        const unsigned char proto_len = in[i++];
                        if (i + proto_len > inlen) break;
                        const std::string_view proto(reinterpret_cast<const char *>(in + i), proto_len);
                        if (proto == "h3" || proto == "h3-29") {
                            *out = in + i;
                            *outlen = proto_len;
                            return SSL_TLSEXT_ERR_OK;
                        }
                        i += proto_len;
                    }
                    return SSL_TLSEXT_ERR_NOACK;
                },
                nullptr);
        }

        tls_->ssl = SSL_new(tls_->ctx);
        if (!tls_->ssl) {
            wavex::log::error("[QUIC] init_tls_handshake_engine: SSL_new failed");
            return false;
        }

        if (is_server_) {
            SSL_set_accept_state(tls_->ssl);
        } else {
            SSL_set_connect_state(tls_->ssl);
            static const unsigned char kAlpnProtos[] = "\x02h3\x05h3-29";
            SSL_set_alpn_protos(tls_->ssl, kAlpnProtos, sizeof(kAlpnProtos) - 1);
        }

        static const OSSL_DISPATCH kDispatchTable[] = {
            {
                OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND,
                reinterpret_cast<void(*)()>(quic_tls_crypto_send)
            },
            {
                OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD,
                reinterpret_cast<void(*)()>(quic_tls_crypto_recv_rcd)
            },
            {
                OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD,
                reinterpret_cast<void(*)()>(quic_tls_crypto_release_rcd)
            },
            {
                OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET,
                reinterpret_cast<void(*)()>(quic_tls_yield_secret)
            },
            {
                OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS,
                reinterpret_cast<void(*)()>(quic_tls_got_transport_params)
            },
            {
                OSSL_FUNC_SSL_QUIC_TLS_ALERT,
                reinterpret_cast<void(*)()>(quic_tls_alert)
            },
            OSSL_DISPATCH_END
        };

        if (SSL_set_quic_tls_cbs(tls_->ssl, kDispatchTable, this) != 1) {
            wavex::log::error("[QUIC] init_tls_handshake_engine: SSL_set_quic_tls_cbs failed");
            return false;
        }

        const std::string transport_params = build_quic_transport_params();
        if (SSL_set_quic_tls_transport_params(
                tls_->ssl,
                reinterpret_cast<const unsigned char *>(transport_params.data()),
                transport_params.size()) != 1) {
            wavex::log::error("[QUIC] init_tls_handshake_engine: SSL_set_quic_tls_transport_params failed");
            return false;
        }

        tls_->initialized = true;
        wavex::log::info("[QUIC] init_tls_handshake_engine: TLS engine initialized successfully (is_server={})", is_server_);
        if (!is_server_) {
            run_tls_engine();
        }
        return true;
#else
        return false;
#endif
    }

    std::string QuicConnection::build_quic_transport_params() const {
        std::string out;
        auto add_varint_param = [&out](uint64_t id, uint64_t val) {
            VarInt::encode(id, out);
            const std::size_t val_len = VarInt::encoded_size(val);
            VarInt::encode(val_len, out);
            VarInt::encode(val, out);
        };

        const ConnectionId &orig_cid = (!original_dcid_.empty()) ? original_dcid_ : local_cid_;
        if (!orig_cid.empty()) {
            VarInt::encode(0x00, out); // original_destination_connection_id
            VarInt::encode(orig_cid.length(), out);
            out.append(reinterpret_cast<const char *>(orig_cid.data()), orig_cid.length());
        }

        if (!local_cid_.empty()) {
            VarInt::encode(0x0f, out); // initial_source_connection_id (RFC 9000 §18.2)
            VarInt::encode(local_cid_.length(), out);
            out.append(reinterpret_cast<const char *>(local_cid_.data()), local_cid_.length());
        }

        add_varint_param(0x01, 30000); // max_idle_timeout (30s)
        add_varint_param(0x04, max_data_); // initial_max_data (1MB)
        add_varint_param(0x05, max_stream_data_); // initial_max_stream_data_bidi_local (256KB)
        add_varint_param(0x06, max_stream_data_); // initial_max_stream_data_bidi_remote (256KB)
        add_varint_param(0x07, max_stream_data_); // initial_max_stream_data_uni (256KB)
        add_varint_param(0x08, 100); // initial_max_streams_bidi
        add_varint_param(0x09, 100); // initial_max_streams_uni
        add_varint_param(0x0e, 2); // active_connection_id_limit (RFC 9000 §18.2)

        return out;
    }

    int QuicConnection::on_tls_crypto_recv(const unsigned char **buf, size_t *bytes_read) {
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        static constexpr unsigned char kEmptyBuf[1] = {0};
        auto &r = reassembler_for_level(current_read_level_);
        last_read_crypto_level_ = current_read_level_;

        if (!r.has_available()) {
            *buf = kEmptyBuf;
            *bytes_read = 0;
            return 1;
        }

        const auto avail = r.available();
        *buf = reinterpret_cast<const unsigned char *>(avail.data());
        *bytes_read = avail.size();
        return 1;
#else
        static const unsigned char kEmptyBuf[1] = {0};
        *buf = kEmptyBuf;
        *bytes_read = 0;
        return 1;
#endif
    }

    int QuicConnection::on_tls_crypto_release(const size_t bytes_read) {
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        auto &r = reassembler_for_level(last_read_crypto_level_);
        r.consume(bytes_read);
        return 1;
#else
        (void) bytes_read;
        return 1;
#endif
    }

    int QuicConnection::on_tls_secret(
        uint32_t prot_level, int direction,
        const unsigned char *secret, size_t secret_len) {
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        ProtectionKeys keys;
        if (!CryptoSuite::expand_quic_keys(secret, secret_len, keys)) {
            return 0;
        }

        if (direction == 1) {
            // 1 = write (local/sender)
            current_write_level_ = prot_level;
            if (prot_level == 2) {
                // OSSL_RECORD_PROTECTION_LEVEL_HANDSHAKE
                handshake_keys_local_ = keys;
            } else if (prot_level == 3) {
                // OSSL_RECORD_PROTECTION_LEVEL_APPLICATION
                one_rtt_keys_local_ = keys;
                one_rtt_keys_ = keys;
            }
        } else {
            // 0 = read (peer/receiver)
            current_read_level_ = prot_level;
            if (prot_level == 2) {
                // OSSL_RECORD_PROTECTION_LEVEL_HANDSHAKE
                handshake_keys_peer_ = keys;
            } else if (prot_level == 3) {
                // OSSL_RECORD_PROTECTION_LEVEL_APPLICATION
                one_rtt_keys_peer_ = keys;
            }
        }
        return 1;
#else
        (void) prot_level;
        (void) direction;
        (void) secret;
        (void) secret_len;
        return 1;
#endif
    }

    int QuicConnection::on_tls_transport_params(
        const unsigned char * /*params*/, size_t /*params_len*/) {
        return 1;
    }

    void QuicConnection::queue_crypto_frame(std::string_view data) {
        std::size_t offset = 0;

        while (offset < data.size() || data.empty()) {
            constexpr std::size_t kMaxChunk = 1150;
            std::size_t chunk_len = std::min(data.size() - offset, kMaxChunk);
            std::string_view chunk = data.substr(offset, chunk_len);

            CryptoFrame cf;
            std::string payload;

            PacketHeader hdr;
            hdr.is_long = true;
            hdr.version = version_;
            hdr.dcid = peer_cid_;
            hdr.scid = local_cid_;
            hdr.packet_number = next_packet_number_++;

            const ProtectionKeys *keys = nullptr;

            if (current_write_level_ == 0) {
                // OSSL_RECORD_PROTECTION_LEVEL_NONE (Initial)
                hdr.type = PacketType::Initial;
                cf.offset = crypto_send_offset_initial_;
                crypto_send_offset_initial_ += chunk.size();
                cf.data = std::string(chunk);

                if (has_received_initial_) {
                    AckFrame ack;
                    ack.largest_acknowledged = largest_received_initial_pn_;
                    ack.ranges.push_back({0, 0});
                    serialize_frame(ack, payload);
                }
                serialize_frame(cf, payload);

                // Server ack-eliciting Initial packets MUST be expanded to at least 1200 bytes (RFC 9000 §14.1)
                const std::size_t est_overhead =
                        1 + 4 + (1 + hdr.dcid.length()) + (1 + hdr.scid.length()) + 1 + 2 + 4 + 16;
                if (payload.size() + est_overhead < 1200) {
                    payload.resize(1200 - est_overhead, '\0');
                }

                keys = &initial_keys_local_;
            } else if (current_write_level_ == 2) {
                // OSSL_RECORD_PROTECTION_LEVEL_HANDSHAKE
                hdr.type = PacketType::Handshake;
                cf.offset = crypto_send_offset_handshake_;
                crypto_send_offset_handshake_ += chunk.size();
                cf.data = std::string(chunk);

                if (has_received_handshake_) {
                    AckFrame ack;
                    ack.largest_acknowledged = largest_received_handshake_pn_;
                    ack.ranges.push_back({0, 0});
                    serialize_frame(ack, payload);
                }
                serialize_frame(cf, payload);
                keys = handshake_keys_local_.valid ? &handshake_keys_local_ : &initial_keys_local_;
            } else {
                // OSSL_RECORD_PROTECTION_LEVEL_APPLICATION (1-RTT)
                hdr.is_long = false;
                hdr.type = PacketType::OneRTT;
                cf.offset = crypto_send_offset_app_;
                crypto_send_offset_app_ += chunk.size();
                cf.data = std::string(chunk);
                serialize_frame(cf, payload);
                keys = one_rtt_keys_local_.valid ? &one_rtt_keys_local_ : &initial_keys_local_;
            }

            std::string packet;
            if (!keys || !keys->valid) {
                wavex::log::error("[QUIC] queue_crypto_frame: No valid keys for write_level={}! Dropping crypto packet.",
                                  current_write_level_);
            } else if (!CryptoSuite::protect_packet(*keys, hdr, payload, packet)) {
                wavex::log::error("[QUIC] queue_crypto_frame: CryptoSuite::protect_packet failed for write_level={}!",
                                  current_write_level_);
            } else {
                wavex::log::info("[QUIC] queue_crypto_frame: successfully protected packet ({} bytes, type={:02x}, pn={}), enqueuing to pending_outbound_datagrams_ (total={})",
                                 packet.size(), static_cast<uint8_t>(hdr.type), hdr.packet_number, pending_outbound_datagrams_.size() + 1);
                pending_outbound_datagrams_.push_back(std::move(packet));
            }

            offset += chunk_len;
            if (data.empty()) break;
        }

        if (on_outbound_) on_outbound_();
    }

    void QuicConnection::run_tls_engine() {
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        if (!tls_ || !tls_->ssl || !tls_->initialized) {
            wavex::log::warn("[QUIC] run_tls_engine: TLS engine not initialized! tls_={} initialized={}",
                             (tls_ != nullptr), (tls_ ? tls_->initialized : false));
            return;
        }

        const int ret = SSL_do_handshake(tls_->ssl);
        if (ret != 1) {
            const int err = SSL_get_error(tls_->ssl, ret);
            wavex::log::error("[QUIC] SSL_do_handshake rc={} SSL_get_error={}", ret, err);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                if (on_outbound_) on_outbound_();
                return;
            }
            // Fatal TLS error
            state_ = ConnectionState::Closed;
            return;
        }

        // ret == 1: Handshake completed successfully
        wavex::log::info("[QUIC] SSL_do_handshake succeeded (rc=1)! Handshake complete.");
        handshake_done_ = true;
        state_ = ConnectionState::Connected;

        if (is_server_) {
            // Send HANDSHAKE_DONE in a 1-RTT short packet (RFC 9000 §19.20)
            PacketHeader one_rtt_hdr;
            one_rtt_hdr.is_long = false;
            one_rtt_hdr.type = PacketType::OneRTT;
            one_rtt_hdr.dcid = peer_cid_;
            one_rtt_hdr.packet_number = next_packet_number_++;

            HandshakeDoneFrame hdf;
            std::string one_rtt_payload;
            serialize_frame(hdf, one_rtt_payload);

            const auto &keys = one_rtt_keys_local_.valid ? one_rtt_keys_local_ : initial_keys_local_;
            std::string one_rtt_packet;
            if (CryptoSuite::protect_packet(keys, one_rtt_hdr, one_rtt_payload, one_rtt_packet)) {
                pending_outbound_datagrams_.push_back(std::move(one_rtt_packet));
            }
        }

        if (on_outbound_) on_outbound_();
#endif
    }

    void QuicConnection::send_ack(const uint64_t pn, const PacketType type) {
        PacketHeader hdr;
        const ProtectionKeys *keys = nullptr;
        if (type == PacketType::OneRTT) {
            hdr.is_long = false;
            hdr.type = PacketType::OneRTT;
            hdr.dcid = peer_cid_;
            hdr.packet_number = next_packet_number_++;
            keys = one_rtt_keys_local_.valid
                       ? &one_rtt_keys_local_
                       : (one_rtt_keys_.valid ? &one_rtt_keys_ : &initial_keys_local_);
        } else if (type == PacketType::Handshake) {
            hdr.is_long = true;
            hdr.type = PacketType::Handshake;
            hdr.version = version_;
            hdr.dcid = peer_cid_;
            hdr.scid = local_cid_;
            hdr.packet_number = next_packet_number_++;
            keys = handshake_keys_local_.valid ? &handshake_keys_local_ : nullptr;
        } else {
            hdr.is_long = true;
            hdr.type = PacketType::Initial;
            hdr.version = version_;
            hdr.dcid = peer_cid_;
            hdr.scid = local_cid_;
            hdr.packet_number = next_packet_number_++;
            keys = &initial_keys_local_;
        }
        if (!keys || !keys->valid) return;

        AckFrame ack;
        ack.largest_acknowledged = pn;
        ack.ranges.push_back({0, 0});
        std::string payload;
        serialize_frame(ack, payload);

        std::string packet;
        if (CryptoSuite::protect_packet(*keys, hdr, payload, packet)) {
            pending_outbound_datagrams_.push_back(std::move(packet));
        }
        if (on_outbound_) on_outbound_();
    }

    void QuicConnection::handle_datagram(const std::string_view datagram) {
        std::vector<std::shared_ptr<QuicStream> > created_streams;
        OutboundCallback outbound_cb;
        StreamCreatedCallback stream_created_cb; {
            std::lock_guard lock(mtx_);
            std::string_view remaining = datagram;

            while (!remaining.empty()) {
                PacketHeader hdr;
                std::size_t hdr_len = 0;
                if (!unpack_packet_header(remaining, hdr, hdr_len, local_cid_.length())) {
                    break;
                }

                std::size_t packet_size = remaining.size();
                if (hdr.is_long && hdr.length > 0) {
                    const std::size_t expected_size = hdr.pn_offset + static_cast<std::size_t>(hdr.length);
                    if (expected_size <= remaining.size()) {
                        packet_size = expected_size;
                    }
                }

                const std::string_view packet_bytes = remaining.substr(0, packet_size);
                remaining.remove_prefix(packet_size);

                const ProtectionKeys *keys = nullptr;
                if (hdr.is_long) {
                    if (hdr.type == PacketType::Initial) {
                        keys = &initial_keys_peer_;
                    } else if (hdr.type == PacketType::Handshake) {
                        keys = handshake_keys_peer_.valid ? &handshake_keys_peer_ : &initial_keys_peer_;
                    }
                } else {
                    // 1-RTT: prefer derived peer keys, then negotiated symmetric keys, then initial peer keys (test/mock)
                    keys = (one_rtt_keys_peer_.valid)
                               ? &one_rtt_keys_peer_
                               : (one_rtt_keys_.valid ? &one_rtt_keys_ : &initial_keys_peer_);
                }

                // Drop packet if we don't have the right keys for this level yet
                if (!keys || !keys->valid) continue;

                std::string plaintext;
                if (!CryptoSuite::unprotect_packet(*keys, hdr, packet_bytes, plaintext, largest_received_pn_,
                                                   local_cid_.length())) {
                    continue;
                }

                largest_received_pn_ = std::max(largest_received_pn_, hdr.packet_number);
                if (hdr.is_long) {
                    if (hdr.type == PacketType::Initial) {
                        largest_received_initial_pn_ = std::max(largest_received_initial_pn_, hdr.packet_number);
                        has_received_initial_ = true;
                    } else if (hdr.type == PacketType::Handshake) {
                        largest_received_handshake_pn_ = std::max(largest_received_handshake_pn_, hdr.packet_number);
                        has_received_handshake_ = true;
                    }
                }

                std::vector<Frame> frames;
                if (parse_frames(plaintext, frames)) {
                    bool has_crypto_frame = false;
                    for (const auto &f: frames) {
                        if (const auto *cf = std::get_if<CryptoFrame>(&f)) {
                            wavex::log::info("[QUIC] Received CryptoFrame: {} bytes at offset {} (pkt_type={})",
                                             cf->data.size(), cf->offset, static_cast<int>(hdr.type));
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
                            if (tls_ && tls_->initialized) {
                                auto &reassembler = reassembler_for_pkt_type(hdr.type);
                                reassembler.insert(cf->offset, cf->data);
                                wavex::log::info("[QUIC] Crypto reassembler for pkt_type={}: ready={} unconsumed={} next_offset={} pending_fragments={}",
                                                 static_cast<int>(hdr.type),
                                                 reassembler.ready.size(),
                                                 reassembler.ready.size() - reassembler.ready_consumed,
                                                 reassembler.next_offset,
                                                 reassembler.pending.size());
                                has_crypto_frame = true;
                            } else {
                                wavex::log::warn("[QUIC] Received CryptoFrame ({} bytes) but TLS engine not initialized! tls_={} initialized={}",
                                                 cf->data.size(), (tls_ != nullptr), (tls_ ? tls_->initialized : false));
                            }
#endif
                        }
                    }

                    if (has_crypto_frame) {
                        wavex::log::info("[QUIC] invoking run_tls_engine() due to incoming CRYPTO frame");
                        run_tls_engine();
                    }

                    // Pass the packet type so process_frames can ACK at the correct level
                    process_frames(frames, hdr.packet_number, hdr.type, created_streams);
                }
            }

            if (is_server_ && state_ == ConnectionState::Initial) {
                // For mock or non-TLS connections (e.g. unit tests without certs), auto-complete handshake
                if (!tls_ || !tls_->initialized) {
                    wavex::log::info("[QUIC] Non-TLS or uninitialized fallback: calling send_initial_handshake_response()");
                    send_initial_handshake_response();
                    state_ = ConnectionState::Connected;
                }
            }

            outbound_cb = on_outbound_;
            stream_created_cb = on_stream_created_;
        }

        if (stream_created_cb) {
            for (const auto &s: created_streams) {
                stream_created_cb(s);
            }
        }
        if (outbound_cb) outbound_cb();
    }

    void QuicConnection::process_frames(const std::vector<Frame> &frames, const uint64_t pn, const PacketType pkt_type,
                                        std::vector<std::shared_ptr<QuicStream> > &new_streams) {
        for (const auto &f: frames) {
            std::visit([this, pn, pkt_type, &new_streams]<typename T0>(const T0 &frame) {
                using T = std::decay_t<T0>;
                if constexpr (std::is_same_v<T, PingFrame>) {
                    // ACK at the same level the PING arrived on (RFC 9000 §13.2)
                    send_ack(pn, pkt_type);
                } else if constexpr (std::is_same_v<T, AckFrame>) {
                    // RFC 9002 §7 Congestion Control ACK processing
                    congestion_controller_.on_packet_acked(CongestionController::kMaxDatagramSize);
                    if (frame.ack_delay > 0) {
                        congestion_controller_.update_rtt(
                            std::chrono::microseconds(frame.ack_delay * 1000),
                            std::chrono::microseconds(frame.ack_delay * 1000)
                        );
                    }
                } else if constexpr (std::is_same_v<T, StreamFrame>) {
                    send_ack(pn, PacketType::OneRTT); // STREAM frames are always 1-RTT

                    auto it = streams_.find(frame.stream_id);
                    if (it == streams_.end()) {
                        auto stream = std::make_shared<QuicStream>(shared_from_this(), frame.stream_id, executor_);
                        streams_[frame.stream_id] = stream;
                        accepted_streams_.push_back(stream);
                        if (stream_acceptor_) {
                            auto cb = std::move(*stream_acceptor_);
                            stream_acceptor_.reset();
                            cb(stream);
                        }
                        new_streams.push_back(stream);
                        it = streams_.find(frame.stream_id);
                    }
                    it->second->push_inbound(frame.data, frame.fin);
                } else if constexpr (std::is_same_v<T, MaxDataFrame>) {
                    if (frame.max_data > max_data_) {
                        max_data_ = frame.max_data;
                    }
                } else if constexpr (std::is_same_v<T, MaxStreamDataFrame>) {
                    if (frame.max_stream_data > max_stream_data_) {
                        max_stream_data_ = frame.max_stream_data;
                    }
                } else if constexpr (std::is_same_v<T, ResetStreamFrame>) {
                    auto it = streams_.find(frame.stream_id);
                    if (it != streams_.end()) {
                        it->second->close();
                    }
                } else if constexpr (std::is_same_v<T, StopSendingFrame>) {
                    auto it = streams_.find(frame.stream_id);
                    if (it != streams_.end()) {
                        it->second->close();
                    }
                } else if constexpr (std::is_same_v<T, ConnectionCloseFrame>) {
                    state_ = ConnectionState::Closed;
                }
            }, f);
        }
    }

    void QuicConnection::send_initial_handshake_response() {
        // Build Initial Server Packet with Ack only (RFC 9000 §19.20 forbids HANDSHAKE_DONE in Initial packet)
        PacketHeader hdr;
        hdr.is_long = true;
        hdr.type = PacketType::Initial;
        hdr.version = version_;
        hdr.dcid = peer_cid_;
        hdr.scid = local_cid_;
        hdr.packet_number = next_packet_number_++;

        AckFrame ack;
        ack.largest_acknowledged = largest_received_pn_;
        ack.ranges.push_back({0, 0});

        std::string payload;
        serialize_frame(ack, payload);

        std::string packet;
        const auto &keys = initial_keys_local_;
        if (CryptoSuite::protect_packet(keys, hdr, payload, packet)) {
            pending_outbound_datagrams_.push_back(std::move(packet));
        }

        // Send HANDSHAKE_DONE in a 1-RTT packet (RFC 9000 §19.20)
        PacketHeader one_rtt_hdr;
        one_rtt_hdr.is_long = false;
        one_rtt_hdr.type = PacketType::OneRTT;
        one_rtt_hdr.dcid = peer_cid_;
        one_rtt_hdr.packet_number = next_packet_number_++;

        HandshakeDoneFrame hdf;
        std::string one_rtt_payload;
        serialize_frame(hdf, one_rtt_payload);

        const auto &one_rtt_keys = (one_rtt_keys_local_.valid)
                                       ? one_rtt_keys_local_
                                       : (one_rtt_keys_.valid ? one_rtt_keys_ : initial_keys_local_);
        std::string one_rtt_packet;
        if (CryptoSuite::protect_packet(one_rtt_keys, one_rtt_hdr, one_rtt_payload, one_rtt_packet)) {
            pending_outbound_datagrams_.push_back(std::move(one_rtt_packet));
        }
    }

    std::shared_ptr<QuicStream> QuicConnection::create_stream(const bool bidirectional) {
        std::lock_guard lock(mtx_);
        uint64_t sid = 0;
        if (bidirectional) {
            sid = (next_bidi_stream_id_++) << 2;
            if (is_server_) sid |= 0x01;
        } else {
            sid = (next_uni_stream_id_++) << 2 | 0x02;
            if (is_server_) sid |= 0x01;
        }

        auto stream = std::make_shared<QuicStream>(shared_from_this(), sid, executor_);
        streams_[sid] = stream;
        return stream;
    }

    std::shared_ptr<QuicStream> QuicConnection::get_or_create_stream(const uint64_t stream_id) {
        std::lock_guard lock(mtx_);
        auto it = streams_.find(stream_id);
        if (it != streams_.end()) return it->second;

        auto stream = std::make_shared<QuicStream>(shared_from_this(), stream_id, executor_);
        streams_[stream_id] = stream;
        return stream;
    }

    void QuicConnection::close_stream(const uint64_t stream_id) {
        std::lock_guard lock(mtx_);
        auto it = streams_.find(stream_id);
        if (it != streams_.end()) {
            it->second->close();
            streams_.erase(it);
        }
    }

    asio::awaitable<std::shared_ptr<QuicStream> > QuicConnection::accept_stream() {
        std::unique_lock lock(mtx_);
        if (!accepted_streams_.empty()) {
            auto stream = accepted_streams_.front();
            accepted_streams_.pop_front();
            co_return stream;
        }

        co_return co_await asio::async_initiate<const asio::use_awaitable_t<> &, void(std::shared_ptr<QuicStream>)>(
            [this]<typename T0>(T0 handler) {
                using HandlerType = std::decay_t<T0>;
                auto shared_h = std::make_shared<HandlerType>(std::move(handler));
                auto executor = asio::get_associated_executor(*shared_h);

                std::lock_guard inner_lock(mtx_);
                if (!accepted_streams_.empty()) {
                    auto stream = accepted_streams_.front();
                    accepted_streams_.pop_front();
                    asio::post(executor, [shared_h, stream] {
                        (*shared_h)(stream);
                    });
                    return;
                }
                stream_acceptor_ = [shared_h, executor](std::shared_ptr<QuicStream> s) {
                    asio::post(executor, [shared_h, s] {
                        (*shared_h)(s);
                    });
                };
            },
            asio::use_awaitable
        );
    }

    void QuicConnection::queue_stream_data(const uint64_t stream_id, const std::string_view data, const bool fin) {
        OutboundCallback cb; {
            std::lock_guard lock(mtx_);
            StreamFrame sf;
            sf.stream_id = stream_id;
            sf.data = std::string(data);
            sf.fin = fin;
            sf.has_length = true;

            uint64_t &cur_offset = stream_send_offsets_[stream_id];
            sf.offset = cur_offset;
            sf.has_offset = (cur_offset > 0);
            cur_offset += data.size();

            std::string payload;
            serialize_frame(sf, payload);

            PacketHeader hdr;
            hdr.is_long = false;
            hdr.type = PacketType::OneRTT;
            hdr.dcid = peer_cid_;
            hdr.packet_number = next_packet_number_++;

            std::string packet;
            const auto &keys = (one_rtt_keys_local_.valid)
                                   ? one_rtt_keys_local_
                                   : (one_rtt_keys_.valid ? one_rtt_keys_ : initial_keys_local_);
            if (CryptoSuite::protect_packet(keys, hdr, payload, packet)) {
                congestion_controller_.on_packet_sent(packet.size(), true);
                pending_outbound_datagrams_.push_back(std::move(packet));
            }
            cb = on_outbound_;
        }
        if (cb) cb();
    }

    std::vector<std::string> QuicConnection::poll_outgoing_datagrams() {
        std::lock_guard lock(mtx_);
        std::vector<std::string> pkts;
        pkts.reserve(pending_outbound_datagrams_.size());
        while (!pending_outbound_datagrams_.empty()) {
            pkts.push_back(std::move(pending_outbound_datagrams_.front()));
            pending_outbound_datagrams_.pop_front();
        }
        if (!pkts.empty()) {
            wavex::log::info("[QUIC] poll_outgoing_datagrams: drained {} datagram(s)", pkts.size());
        }
        return pkts;
    }

    void QuicConnection::close(const TransportError err, const std::string_view reason) {
        OutboundCallback cb; {
            std::lock_guard lock(mtx_);
            if (state_ == ConnectionState::Closed) return;
            state_ = ConnectionState::Closed;

            ConnectionCloseFrame ccf;
            ccf.error_code = static_cast<uint64_t>(err);
            ccf.reason_phrase = std::string(reason);

            std::string payload;
            serialize_frame(ccf, payload);

            PacketHeader hdr;
            hdr.is_long = false;
            hdr.type = PacketType::OneRTT;
            hdr.dcid = peer_cid_;
            hdr.packet_number = next_packet_number_++;

            std::string packet;
            const auto &keys = (one_rtt_keys_local_.valid)
                                   ? one_rtt_keys_local_
                                   : (one_rtt_keys_.valid ? one_rtt_keys_ : initial_keys_local_);
            if (CryptoSuite::protect_packet(keys, hdr, payload, packet)) {
                pending_outbound_datagrams_.push_back(std::move(packet));
            }
            cb = on_outbound_;
        }
        if (cb) cb();
    }

    // ─── 8. QuicServer Implementation ──────────────────────────────────────────

    QuicServer::QuicServer(asio::io_context &io, const uint16_t port)
        : io_(io), socket_(io) {
        asio::error_code ec;
        socket_.open(asio::ip::udp::v4(), ec);
        socket_.set_option(asio::socket_base::reuse_address(true), ec);
        socket_.bind(asio::ip::udp::endpoint(asio::ip::udp::v4(), port), ec);
    }

    QuicServer::QuicServer(asio::io_context &io, const std::string_view host, const uint16_t port)
        : io_(io), socket_(io) {
        asio::error_code ec;
        auto addr = asio::ip::make_address(host, ec);
        if (!ec) {
            socket_.open(addr.is_v6() ? asio::ip::udp::v6() : asio::ip::udp::v4(), ec);
            socket_.set_option(asio::socket_base::reuse_address(true), ec);
            socket_.bind(asio::ip::udp::endpoint(addr, port), ec);
        }
    }

    QuicServer::~QuicServer() {
        stop();
    }

    void QuicServer::start() {
        if (!socket_.is_open()) return;
        running_ = true;
        do_receive();
    }

    void QuicServer::stop() {
        running_ = false;
        asio::error_code ec;
        socket_.close(ec);
    }

    void QuicServer::do_receive() {
        if (!running_) return;

        socket_.async_receive_from(
            asio::buffer(recv_buf_), sender_endpoint_,
            [this](const std::error_code ec, const std::size_t bytes_recvd) {
                // Only abort the receive loop on intentional cancellation (shutdown).
                // Transient UDP errors (e.g. ECONNRESET on Windows) must not halt the loop.
                if (ec == asio::error::operation_aborted) return;
                if (ec || bytes_recvd == 0) {
                    do_receive();
                    return;
                }

                const std::string_view datagram(reinterpret_cast<const char *>(recv_buf_.data()), bytes_recvd);
                PacketHeader hdr;
                std::size_t hdr_len = 0;

                if (unpack_packet_header(datagram, hdr, hdr_len)) {
                    if (hdr.is_long && hdr.version != QUIC_VERSION_1 && hdr.version != 0) {
                        // RFC 9000 §6: Version Negotiation packet
                        std::string vn_packet;
                        vn_packet.push_back(static_cast<char>(0x80 | 0x40));
                        vn_packet.push_back(0);
                        vn_packet.push_back(0);
                        vn_packet.push_back(0);
                        vn_packet.push_back(0); // Version 0
                        vn_packet.push_back(static_cast<char>(hdr.scid.length()));
                        vn_packet.append(reinterpret_cast<const char *>(hdr.scid.data()), hdr.scid.length());
                        vn_packet.push_back(static_cast<char>(hdr.dcid.length()));
                        vn_packet.append(reinterpret_cast<const char *>(hdr.dcid.data()), hdr.dcid.length());
                        // Supported version: QUIC_VERSION_1 (0x00000001)
                        vn_packet.push_back(0);
                        vn_packet.push_back(0);
                        vn_packet.push_back(0);
                        vn_packet.push_back(1);

                        auto buf = std::make_shared<std::string>(std::move(vn_packet));
                        socket_.async_send_to(asio::buffer(*buf), sender_endpoint_, [buf](auto, auto) {
                        });
                        do_receive();
                        return;
                    }

                    std::shared_ptr<QuicConnection> conn; {
                        std::lock_guard lock(mtx_);
                        auto it = connections_.find(hdr.dcid);
                        if (it != connections_.end()) {
                            conn = it->second;
                        } else if (hdr.is_long && hdr.type == PacketType::Initial) {
                            // New incoming connection (Initial)
                            const ConnectionId server_cid = ConnectionId::random(8);
                            conn = std::make_shared<QuicConnection>(server_cid, hdr.scid, sender_endpoint_, true,
                                                                    io_.get_executor(), hdr.dcid);
                            std::string cert = tls_cert_file_;
                            std::string key = tls_key_file_;
                            if (!cert.empty() && !key.empty()) {
                                conn->set_tls_credentials(std::move(cert), std::move(key));
                                if (!conn->init_tls_handshake_engine()) {
                                    wavex::log::error("[QUIC] Failed to init_tls_handshake_engine for new incoming connection!");
                                }
                            } else {
                                wavex::log::warn("[QUIC] New incoming connection without TLS credentials: cert='{}' key='{}'", cert, key);
                            }
                            connections_[server_cid] = conn;
                            connections_[hdr.dcid] = conn;

                            conn->set_outbound_callback([this, weak_conn = std::weak_ptr<QuicConnection>(conn)] {
                                asio::post(io_, [this, weak_conn] {
                                    if (auto c = weak_conn.lock()) {
                                        flush_outbound(c);
                                    }
                                });
                            });

                            if (stream_handler_) {
                                conn->set_stream_created_callback([this](std::shared_ptr<QuicStream> stream) {
                                    if (stream_handler_) {
                                        asio::co_spawn(io_, stream_handler_(stream), asio::detached);
                                    }
                                });
                            }
                        }
                    }

                    if (conn) {
                        conn->handle_datagram(datagram);
                        flush_outbound(conn);
                    }
                }

                do_receive();
            }
        );
    }

    void QuicServer::flush_outbound(const std::shared_ptr<QuicConnection> &conn) {
        auto datagrams = conn->poll_outgoing_datagrams();
        if (!datagrams.empty()) {
            wavex::log::info("[QUIC] flush_outbound: sending {} datagram(s) via UDP to {}", datagrams.size(), conn->peer_endpoint().port());
        }
        for (auto &dgram: datagrams) {
            auto buf = std::make_shared<std::string>(std::move(dgram));
            socket_.async_send_to(
                asio::buffer(*buf), conn->peer_endpoint(),
                [buf](std::error_code ec, std::size_t) {
                    if (ec) {
                        wavex::log::error("[QUIC] async_send_to failed: {}", ec.message());
                    }
                }
            );
        }
    }

    // ─── 9. QuicClient Implementation ──────────────────────────────────────────

    QuicClient::QuicClient(asio::io_context &io)
        : io_(io), socket_(io) {
        asio::error_code ec;
        socket_.open(asio::ip::udp::v4(), ec);
        socket_.bind(asio::ip::udp::endpoint(asio::ip::udp::v4(), 0), ec);
    }

    QuicClient::~QuicClient() {
        close();
    }

    asio::awaitable<bool> QuicClient::connect(const std::string_view host, const uint16_t port) {
        asio::error_code ec;
        auto addr = asio::ip::make_address(host, ec);
        if (ec) co_return false;

        server_endpoint_ = asio::ip::udp::endpoint(addr, port);
        const ConnectionId client_cid = ConnectionId::random(8);
        const ConnectionId initial_peer_cid = ConnectionId::random(8);

        connection_ = std::make_shared<QuicConnection>(client_cid, initial_peer_cid, server_endpoint_, false,
                                                       io_.get_executor(), initial_peer_cid);
        connection_->set_outbound_callback([this] {
            flush_outbound();
        });

        // Send Initial Ping packet to initiate connection
        PacketHeader hdr;
        hdr.is_long = true;
        hdr.type = PacketType::Initial;
        hdr.version = QUIC_VERSION_1;
        hdr.dcid = initial_peer_cid;
        hdr.scid = client_cid;
        hdr.packet_number = 0;

        PingFrame pf;
        std::string payload;
        serialize_frame(pf, payload);

        std::string packet;
        ProtectionKeys client_keys, server_keys;
        CryptoSuite::derive_initial_secrets(initial_peer_cid, client_keys, server_keys);
        CryptoSuite::protect_packet(client_keys, hdr, payload, packet);

        co_await socket_.async_send_to(asio::buffer(packet), server_endpoint_, asio::use_awaitable);

        do_receive();
        connected_ = true;
        co_return true;
    }

    std::shared_ptr<QuicStream> QuicClient::create_stream(const bool bidirectional) {
        if (!connection_) return nullptr;
        auto stream = connection_->create_stream(bidirectional);
        flush_outbound();
        return stream;
    }

    void QuicClient::close() {
        if (connection_) {
            connection_->close();
            flush_outbound();
        }
        asio::error_code ec;
        socket_.close(ec);
    }

    void QuicClient::do_receive() {
        socket_.async_receive_from(
            asio::buffer(recv_buf_), server_endpoint_,
            [this](const std::error_code ec, const std::size_t bytes_recvd) {
                if (ec || bytes_recvd == 0) return;
                const std::string_view datagram(reinterpret_cast<const char *>(recv_buf_.data()), bytes_recvd);
                if (connection_) {
                    connection_->handle_datagram(datagram);
                    flush_outbound();
                }
                do_receive();
            }
        );
    }

    void QuicClient::flush_outbound() {
        if (!connection_) return;
        auto datagrams = connection_->poll_outgoing_datagrams();
        for (auto &dgram: datagrams) {
            auto buf = std::make_shared<std::string>(std::move(dgram));
            socket_.async_send_to(
                asio::buffer(*buf), server_endpoint_,
                [buf](std::error_code, std::size_t) {
                }
            );
        }
    }

    // ─── 10. Client Outbound Driver ────────────────────────────────────────────

    class ClientOutboundDriver : public basic_quic_socket::OutboundDriver,
                                 public std::enable_shared_from_this<ClientOutboundDriver> {
    public:
        asio::any_io_executor executor_{};
        asio::ip::udp::socket udp_socket_;
        std::weak_ptr<QuicConnection> conn_{};
        basic_quic_socket::endpoint_type server_endpoint_{};
        basic_quic_socket::endpoint_type sender_endpoint_{};
        std::array<uint8_t, 65536> recv_buf_{};
        bool running_{true};

        explicit ClientOutboundDriver(const asio::any_io_executor &ex)
            : executor_(ex), udp_socket_(ex) {
        }

        ~ClientOutboundDriver() override {
            ClientOutboundDriver::close_driver();
        }

        void send_datagram(std::string dgram, const basic_quic_socket::endpoint_type &dest) override {
            if (!udp_socket_.is_open() || !running_) return;
            auto buf = std::make_shared<std::string>(std::move(dgram));
            udp_socket_.async_send_to(
                asio::buffer(*buf), dest,
                [buf](std::error_code, std::size_t) {
                }
            );
        }

        void close_driver() override {
            if (!running_) return;
            running_ = false;
            asio::error_code ec;
            if (udp_socket_.is_open()) {
                udp_socket_.close(ec);
            }
        }

        void start_receive() {
            if (!running_ || !udp_socket_.is_open()) return;
            auto weak_self = std::weak_ptr<ClientOutboundDriver>(shared_from_this());
            udp_socket_.async_receive_from(
                asio::buffer(recv_buf_), sender_endpoint_,
                [this, weak_self](const std::error_code ec, const std::size_t bytes_recvd) {
                    auto self = weak_self.lock();
                    if (!self || ec == asio::error::operation_aborted || !running_) return;
                    if (!ec && bytes_recvd > 0) {
                        if (auto c = conn_.lock()) {
                            const std::string_view dgram(reinterpret_cast<const char *>(recv_buf_.data()), bytes_recvd);
                            c->handle_datagram(dgram);
                            flush_outbound();
                        }
                    }
                    self->start_receive();
                }
            );
        }

        void flush_outbound() {
            if (auto c = conn_.lock()) {
                auto dgrams = c->poll_outgoing_datagrams();
                for (auto &d: dgrams) {
                    send_datagram(std::move(d), server_endpoint_);
                }
            }
        }
    };

    // ─── 11. basic_quic_socket Implementation ──────────────────────────────────

    basic_quic_socket::basic_quic_socket(const executor_type &ex)
        : stream_(nullptr), conn_(nullptr), outbound_driver_(nullptr),
          executor_(ex), remote_endpoint_{}, local_endpoint_{},
          is_open_(false), is_connected_(false) {
    }

    basic_quic_socket::basic_quic_socket(asio::io_context &io)
        : basic_quic_socket(io.get_executor()) {
    }

    basic_quic_socket::basic_quic_socket(const executor_type &ex, const endpoint_type &ep)
        : basic_quic_socket(ex) {
        open(quic_protocol(ep.protocol().family()));
    }

    basic_quic_socket::basic_quic_socket(asio::io_context &io, const endpoint_type &ep)
        : basic_quic_socket(io.get_executor(), ep) {
    }

    basic_quic_socket::~basic_quic_socket() {
        std::error_code ec;
        close(ec);
    }

    basic_quic_socket::basic_quic_socket(basic_quic_socket &&other) noexcept
        : stream_(std::move(other.stream_)),
          conn_(std::move(other.conn_)),
          outbound_driver_(std::move(other.outbound_driver_)),
          executor_(std::move(other.executor_)),
          remote_endpoint_(std::move(other.remote_endpoint_)),
          local_endpoint_(std::move(other.local_endpoint_)),
          is_open_(other.is_open_),
          is_connected_(other.is_connected_) {
        other.is_open_ = false;
        other.is_connected_ = false;
    }

    basic_quic_socket &basic_quic_socket::operator=(basic_quic_socket &&other) noexcept {
        if (this != &other) {
            std::error_code ec;
            close(ec);
            stream_ = std::move(other.stream_);
            conn_ = std::move(other.conn_);
            outbound_driver_ = std::move(other.outbound_driver_);
            executor_ = std::move(other.executor_);
            remote_endpoint_ = std::move(other.remote_endpoint_);
            local_endpoint_ = std::move(other.local_endpoint_);
            is_open_ = other.is_open_;
            is_connected_ = other.is_connected_;
            other.is_open_ = false;
            other.is_connected_ = false;
        }
        return *this;
    }

    uint64_t basic_quic_socket::stream_id() const noexcept {
        return stream_ ? stream_->stream_id() : 0;
    }

    basic_quic_socket::endpoint_type basic_quic_socket::remote_endpoint() const {
        if (!is_connected_) throw std::system_error(asio::error::not_connected);
        return remote_endpoint_;
    }

    basic_quic_socket::endpoint_type basic_quic_socket::remote_endpoint(std::error_code &ec) const noexcept {
        if (!is_connected_) {
            ec = asio::error::not_connected;
            return {};
        }
        ec.clear();
        return remote_endpoint_;
    }

    basic_quic_socket::endpoint_type basic_quic_socket::local_endpoint() const {
        return local_endpoint_;
    }

    basic_quic_socket::endpoint_type basic_quic_socket::local_endpoint(std::error_code &ec) const noexcept {
        ec.clear();
        return local_endpoint_;
    }

    void basic_quic_socket::open(const protocol_type &proto) {
        std::error_code ec;
        open(proto, ec);
        if (ec) throw std::system_error(ec);
    }

    void basic_quic_socket::open(const protocol_type &, std::error_code &ec) noexcept {
        ec.clear();
        is_open_ = true;
    }

    void basic_quic_socket::close() {
        std::error_code ec;
        close(ec);
        if (ec) throw std::system_error(ec);
    }

    void basic_quic_socket::close(std::error_code &ec) noexcept {
        ec.clear();
        if (stream_) {
            stream_->close(ec);
            stream_.reset();
        }
        outbound_driver_.reset();
        conn_.reset();
        is_open_ = false;
        is_connected_ = false;
    }

    void basic_quic_socket::cancel() {
        std::error_code ec;
        cancel(ec);
        if (ec) throw std::system_error(ec);
    }

    void basic_quic_socket::cancel(std::error_code &ec) const noexcept {
        ec.clear();
        if (stream_) {
            stream_->cancel(ec);
        }
    }

    void basic_quic_socket::shutdown(asio::ip::tcp::socket::shutdown_type what, std::error_code &ec) const noexcept {
        if (stream_) {
            stream_->shutdown(what, ec);
        } else {
            ec = asio::error::not_connected;
        }
    }

    void basic_quic_socket::connect(const endpoint_type &peer_ep) {
        std::error_code ec;
        connect(peer_ep, ec);
        if (ec) throw std::system_error(ec);
    }

    void basic_quic_socket::connect(const endpoint_type &peer_ep, std::error_code &ec) noexcept {
        auto driver = std::make_shared<ClientOutboundDriver>(executor_);
        driver->udp_socket_.open(peer_ep.protocol(), ec);
        if (ec) return;
        driver->udp_socket_.bind(endpoint_type(peer_ep.protocol(), 0), ec);
        if (ec) return;

        driver->server_endpoint_ = peer_ep;
        remote_endpoint_ = peer_ep;
        local_endpoint_ = driver->udp_socket_.local_endpoint(ec);
        if (ec) return;

        const ConnectionId client_cid = ConnectionId::random(8);
        const ConnectionId initial_peer_cid = ConnectionId::random(8);

        conn_ = std::make_shared<QuicConnection>(
            client_cid, initial_peer_cid, peer_ep, false, executor_, initial_peer_cid
        );
        driver->conn_ = conn_;

        conn_->set_outbound_callback([w = std::weak_ptr<ClientOutboundDriver>(driver)] {
            if (auto d = w.lock()) {
                d->flush_outbound();
            }
        });

        PacketHeader hdr;
        hdr.is_long = true;
        hdr.type = PacketType::Initial;
        hdr.version = QUIC_VERSION_1;
        hdr.dcid = initial_peer_cid;
        hdr.scid = client_cid;
        hdr.packet_number = 0;

        PingFrame pf;
        std::string payload;
        serialize_frame(pf, payload);

        std::string packet;
        ProtectionKeys client_keys, server_keys;
        CryptoSuite::derive_initial_secrets(initial_peer_cid, client_keys, server_keys);
        CryptoSuite::protect_packet(client_keys, hdr, payload, packet);

        driver->udp_socket_.send_to(asio::buffer(packet), peer_ep, 0, ec);
        if (ec) return;

        driver->start_receive();
        outbound_driver_ = driver;
        stream_ = conn_->create_stream(true);
        is_open_ = true;
        is_connected_ = true;
    }

    void basic_quic_socket::async_connect_impl(const endpoint_type &peer_ep,
                                               std::function<void(std::error_code)> handler) {
        auto driver = std::make_shared<ClientOutboundDriver>(executor_);
        asio::error_code ec;
        driver->udp_socket_.open(peer_ep.protocol(), ec);
        if (ec) {
            handler(ec);
            return;
        }
        driver->udp_socket_.bind(endpoint_type(peer_ep.protocol(), 0), ec);
        if (ec) {
            handler(ec);
            return;
        }

        driver->server_endpoint_ = peer_ep;
        remote_endpoint_ = peer_ep;
        local_endpoint_ = driver->udp_socket_.local_endpoint(ec);

        const ConnectionId client_cid = ConnectionId::random(8);
        const ConnectionId initial_peer_cid = ConnectionId::random(8);

        conn_ = std::make_shared<QuicConnection>(
            client_cid, initial_peer_cid, peer_ep, false, executor_, initial_peer_cid
        );
        driver->conn_ = conn_;

        conn_->set_outbound_callback([w = std::weak_ptr<ClientOutboundDriver>(driver)] {
            if (auto d = w.lock()) {
                d->flush_outbound();
            }
        });

        PacketHeader hdr;
        hdr.is_long = true;
        hdr.type = PacketType::Initial;
        hdr.version = QUIC_VERSION_1;
        hdr.dcid = initial_peer_cid;
        hdr.scid = client_cid;
        hdr.packet_number = 0;

        PingFrame pf;
        std::string payload;
        serialize_frame(pf, payload);

        std::string packet;
        ProtectionKeys client_keys, server_keys;
        CryptoSuite::derive_initial_secrets(initial_peer_cid, client_keys, server_keys);
        CryptoSuite::protect_packet(client_keys, hdr, payload, packet);

        auto pkt_buf = std::make_shared<std::string>(std::move(packet));
        driver->udp_socket_.async_send_to(
            asio::buffer(*pkt_buf), peer_ep,
            [this, driver, pkt_buf, h = std::move(handler)](std::error_code send_ec, std::size_t) mutable {
                if (send_ec) {
                    h(send_ec);
                    return;
                }
                driver->start_receive();
                outbound_driver_ = driver;
                stream_ = conn_->create_stream(true);
                is_open_ = true;
                is_connected_ = true;
                h(std::error_code{});
            }
        );
    }

    basic_quic_socket basic_quic_socket::open_stream(const bool bidirectional) const {
        if (!conn_ || !is_connected_) {
            throw std::system_error(asio::error::not_connected);
        }
        basic_quic_socket new_sock(executor_);
        auto new_stream = conn_->create_stream(bidirectional);
        new_sock.assign_stream(new_stream, conn_, outbound_driver_, remote_endpoint_, local_endpoint_);
        conn_->queue_stream_data(new_stream->stream_id(), "", false);
        return new_sock;
    }

    void basic_quic_socket::assign_stream(
        std::shared_ptr<QuicStream> stream,
        std::shared_ptr<QuicConnection> conn,
        std::shared_ptr<OutboundDriver> driver,
        endpoint_type remote_ep,
        endpoint_type local_ep) {
        stream_ = std::move(stream);
        conn_ = std::move(conn);
        outbound_driver_ = std::move(driver);
        remote_endpoint_ = remote_ep;
        local_endpoint_ = local_ep;
        is_open_ = (stream_ != nullptr);
        is_connected_ = (stream_ != nullptr);
    }

    // ─── 12. basic_quic_acceptor::AcceptorDriver ───────────────────────────────

    class basic_quic_acceptor::AcceptorDriver : public basic_quic_socket::OutboundDriver {
    public:
        asio::ip::udp::socket &socket_;
        bool active_{true};

        explicit AcceptorDriver(asio::ip::udp::socket &sock) : socket_(sock) {
        }

        ~AcceptorDriver() override = default;

        void send_datagram(std::string dgram, const basic_quic_socket::endpoint_type &dest) override {
            if (!active_ || !socket_.is_open()) return;
            auto buf = std::make_shared<std::string>(std::move(dgram));
            socket_.async_send_to(
                asio::buffer(*buf), dest,
                [buf](std::error_code, std::size_t) {
                }
            );
        }

        void close_driver() override {
            active_ = false;
        }
    };

    // ─── 13. basic_quic_acceptor Implementation ────────────────────────────────

    basic_quic_acceptor::basic_quic_acceptor(const executor_type &ex)
        : executor_(ex), mtx_{}, udp_socket_(ex),
          driver_(nullptr),
          sender_endpoint_{}, connections_{}, accept_queue_{}, pending_accepts_{},
          tls_cert_file_{}, tls_key_file_{}, recv_buf_{},
          is_listening_(false), is_open_(false) {
        driver_ = std::make_shared<AcceptorDriver>(udp_socket_);
    }

    basic_quic_acceptor::basic_quic_acceptor(asio::io_context &io)
        : basic_quic_acceptor(io.get_executor()) {
    }

    basic_quic_acceptor::basic_quic_acceptor(const executor_type &ex, const endpoint_type &ep, const bool reuse_addr)
        : basic_quic_acceptor(ex) {
        asio::error_code ec;
        open(quic_protocol(ep.protocol().family()), ec);
        if (reuse_addr) {
            udp_socket_.set_option(asio::socket_base::reuse_address(true), ec);
        }
        bind(ep, ec);
        listen();
    }

    basic_quic_acceptor::basic_quic_acceptor(asio::io_context &io, const endpoint_type &ep, const bool reuse_addr)
        : basic_quic_acceptor(io.get_executor(), ep, reuse_addr) {
    }

    basic_quic_acceptor::basic_quic_acceptor(asio::io_context &io, const endpoint_type &ep, std::string cert_file,
                                             std::string key_file)
        : basic_quic_acceptor(io.get_executor(), ep, true) {
        set_tls_credentials(std::move(cert_file), std::move(key_file));
    }

    basic_quic_acceptor::~basic_quic_acceptor() {
        std::error_code ec;
        close(ec);
    }

    basic_quic_acceptor::basic_quic_acceptor(basic_quic_acceptor &&other) noexcept
        : executor_(std::move(other.executor_)),
          mtx_{},
          udp_socket_(std::move(other.udp_socket_)),
          driver_(std::move(other.driver_)),
          sender_endpoint_(std::move(other.sender_endpoint_)),
          connections_(std::move(other.connections_)),
          accept_queue_(std::move(other.accept_queue_)),
          pending_accepts_(std::move(other.pending_accepts_)),
          tls_cert_file_(std::move(other.tls_cert_file_)),
          tls_key_file_(std::move(other.tls_key_file_)),
          recv_buf_(other.recv_buf_),
          is_listening_(other.is_listening_),
          is_open_(other.is_open_) {
        other.is_listening_ = false;
        other.is_open_ = false;
    }

    basic_quic_acceptor &basic_quic_acceptor::operator=(basic_quic_acceptor &&other) noexcept {
        if (this != &other) {
            std::error_code ec;
            close(ec);
            executor_ = std::move(other.executor_);
            udp_socket_ = std::move(other.udp_socket_);
            driver_ = std::move(other.driver_);
            sender_endpoint_ = std::move(other.sender_endpoint_);
            connections_ = std::move(other.connections_);
            accept_queue_ = std::move(other.accept_queue_);
            pending_accepts_ = std::move(other.pending_accepts_);
            tls_cert_file_ = std::move(other.tls_cert_file_);
            tls_key_file_ = std::move(other.tls_key_file_);
            recv_buf_ = other.recv_buf_;
            is_listening_ = other.is_listening_;
            is_open_ = other.is_open_;
            other.is_listening_ = false;
            other.is_open_ = false;
        }
        return *this;
    }

    void basic_quic_acceptor::open(const protocol_type &proto) {
        std::error_code ec;
        open(proto, ec);
        if (ec) throw std::system_error(ec);
    }

    void basic_quic_acceptor::open(const protocol_type &proto, std::error_code &ec) noexcept {
        udp_socket_.open(proto.family() == PF_INET6 ? asio::ip::udp::v6() : asio::ip::udp::v4(), ec);
        if (!ec) is_open_ = true;
    }

    void basic_quic_acceptor::bind(const endpoint_type &ep) {
        std::error_code ec;
        bind(ep, ec);
        if (ec) throw std::system_error(ec);
    }

    void basic_quic_acceptor::bind(const endpoint_type &ep, std::error_code &ec) noexcept {
        if (!udp_socket_.is_open()) {
            open(quic_protocol(ep.protocol().family()), ec);
            if (ec) return;
        }
        udp_socket_.bind(ep, ec);
        if (!ec) is_open_ = true;
    }

    void basic_quic_acceptor::listen(int /*backlog*/) {
        std::error_code ec;
        listen(0, ec);
        if (ec) throw std::system_error(ec);
    }

    void basic_quic_acceptor::listen(int /*backlog*/, std::error_code &ec) noexcept {
        ec.clear();
        if (!is_listening_) {
            is_listening_ = true;
            do_receive();
        }
    }

    void basic_quic_acceptor::close() {
        std::error_code ec;
        close(ec);
        if (ec) throw std::system_error(ec);
    }

    void basic_quic_acceptor::close(std::error_code &ec) noexcept {
        is_listening_ = false;
        is_open_ = false;
        cancel(ec);
        if (udp_socket_.is_open()) {
            udp_socket_.close(ec);
        }
    }

    void basic_quic_acceptor::cancel() {
        std::error_code ec;
        cancel(ec);
        if (ec) throw std::system_error(ec);
    }

    void basic_quic_acceptor::cancel(std::error_code &ec) noexcept {
        ec.clear();
        if (udp_socket_.is_open()) {
            udp_socket_.cancel(ec);
        }
        std::deque<AcceptHandlerFn> pending; {
            std::lock_guard lock(mtx_);
            pending = std::move(pending_accepts_);
            pending_accepts_.clear();
        }
        for (auto &h: pending) {
            h(asio::error::operation_aborted, AcceptedStreamInfo{});
        }
    }

    basic_quic_acceptor::endpoint_type basic_quic_acceptor::local_endpoint() const {
        std::error_code ec;
        auto ep = local_endpoint(ec);
        if (ec) throw std::system_error(ec);
        return ep;
    }

    basic_quic_acceptor::endpoint_type basic_quic_acceptor::local_endpoint(std::error_code &ec) const noexcept {
        return udp_socket_.local_endpoint(ec);
    }

    void basic_quic_acceptor::set_tls_credentials(std::string cert_file, std::string key_file) {
        std::lock_guard lock(mtx_);
        tls_cert_file_ = std::move(cert_file);
        tls_key_file_ = std::move(key_file);
    }

    std::shared_ptr<basic_quic_socket::OutboundDriver> basic_quic_acceptor::driver() const noexcept {
        return driver_;
    }

    void basic_quic_acceptor::accept(basic_quic_socket &peer_socket) {
        std::error_code ec;
        accept(peer_socket, ec);
        if (ec) throw std::system_error(ec);
    }

    void basic_quic_acceptor::accept(basic_quic_socket &peer_socket, std::error_code &ec) noexcept {
        ec.clear();
        std::unique_lock lock(mtx_);
        if (!accept_queue_.empty()) {
            auto info = std::move(accept_queue_.front());
            accept_queue_.pop_front();
            lock.unlock();
            peer_socket.assign_stream(info.stream, info.conn, driver(), info.peer_ep, local_endpoint());
            return;
        }

        std::promise<AcceptedStreamInfo> prom;
        auto fut = prom.get_future();
        pending_accepts_.push_back([&prom, &ec](std::error_code err, const AcceptedStreamInfo &info) {
            if (err) ec = err;
            prom.set_value(info);
        });
        lock.unlock();

        auto info = fut.get();
        if (!ec) {
            peer_socket.assign_stream(info.stream, info.conn, driver(), info.peer_ep, local_endpoint());
        }
    }

    void basic_quic_acceptor::async_accept_impl(AcceptHandlerFn handler) {
        std::lock_guard lock(mtx_);
        if (!accept_queue_.empty()) {
            auto info = std::move(accept_queue_.front());
            accept_queue_.pop_front();
            handler(std::error_code{}, std::move(info));
            return;
        }
        pending_accepts_.push_back(std::move(handler));
    }

    void basic_quic_acceptor::do_receive() {
        if (!is_listening_ || !udp_socket_.is_open()) return;

        udp_socket_.async_receive_from(
            asio::buffer(recv_buf_), sender_endpoint_,
            [this](const std::error_code ec, const std::size_t bytes_recvd) {
                if (ec == asio::error::operation_aborted || !is_listening_) return;
                if (ec || bytes_recvd == 0) {
                    do_receive();
                    return;
                }

                const std::string_view datagram(reinterpret_cast<const char *>(recv_buf_.data()), bytes_recvd);
                PacketHeader hdr;
                std::size_t hdr_len = 0;

                if (unpack_packet_header(datagram, hdr, hdr_len)) {
                    if (hdr.is_long && hdr.version != QUIC_VERSION_1 && hdr.version != 0) {
                        std::string vn_packet;
                        vn_packet.push_back(static_cast<char>(0x80 | 0x40));
                        vn_packet.push_back(0);
                        vn_packet.push_back(0);
                        vn_packet.push_back(0);
                        vn_packet.push_back(0);
                        vn_packet.push_back(static_cast<char>(hdr.scid.length()));
                        vn_packet.append(reinterpret_cast<const char *>(hdr.scid.data()), hdr.scid.length());
                        vn_packet.push_back(static_cast<char>(hdr.dcid.length()));
                        vn_packet.append(reinterpret_cast<const char *>(hdr.dcid.data()), hdr.dcid.length());
                        vn_packet.push_back(0);
                        vn_packet.push_back(0);
                        vn_packet.push_back(0);
                        vn_packet.push_back(1);

                        auto buf = std::make_shared<std::string>(std::move(vn_packet));
                        udp_socket_.async_send_to(asio::buffer(*buf), sender_endpoint_, [buf](auto, auto) {
                        });
                        do_receive();
                        return;
                    }

                    std::shared_ptr<QuicConnection> conn;
                    bool is_new = false; {
                        std::lock_guard lock(mtx_);
                        auto it = connections_.find(hdr.dcid);
                        if (it != connections_.end()) {
                            conn = it->second;
                        } else if (hdr.is_long && hdr.type == PacketType::Initial) {
                            is_new = true;
                            const ConnectionId server_cid = ConnectionId::random(8);
                            conn = std::make_shared<QuicConnection>(
                                server_cid, hdr.scid, sender_endpoint_, true, executor_, hdr.dcid
                            );
                            if (!tls_cert_file_.empty() && !tls_key_file_.empty()) {
                                conn->set_tls_credentials(tls_cert_file_, tls_key_file_);
                                if (!conn->init_tls_handshake_engine()) {
                                    wavex::log::error("[QUIC] [acceptor] Failed to init_tls_handshake_engine!");
                                }
                            } else {
                                wavex::log::warn("[QUIC] [acceptor] New incoming connection without TLS credentials: cert='{}' key='{}'", tls_cert_file_, tls_key_file_);
                            }
                            connections_[server_cid] = conn;
                            connections_[hdr.dcid] = conn;

                            conn->set_outbound_callback([this, weak_conn = std::weak_ptr<QuicConnection>(conn)] {
                                asio::post(executor_, [this, weak_conn] {
                                    if (auto c = weak_conn.lock()) {
                                        flush_outbound(c);
                                    }
                                });
                            });

                            conn->set_stream_created_callback(
                                [this, conn, sender_ep = sender_endpoint_](std::shared_ptr<QuicStream> stream) {
                                    on_stream_ready(std::move(stream), conn, sender_ep);
                                });
                        }
                    }

                    if (conn) {
                        conn->handle_datagram(datagram);
                        flush_outbound(conn);
                        if (is_new) {
                            auto stream0 = conn->get_or_create_stream(0);
                            on_stream_ready(stream0, conn, sender_endpoint_);
                        }
                    }
                }

                do_receive();
            }
        );
    }

    void basic_quic_acceptor::flush_outbound(const std::shared_ptr<QuicConnection> &conn) {
        auto datagrams = conn->poll_outgoing_datagrams();
        for (auto &dgram: datagrams) {
            auto buf = std::make_shared<std::string>(std::move(dgram));
            udp_socket_.async_send_to(
                asio::buffer(*buf), conn->peer_endpoint(),
                [buf](std::error_code, std::size_t) {
                }
            );
        }
    }

    void basic_quic_acceptor::on_stream_ready(
        std::shared_ptr<QuicStream> stream,
        std::shared_ptr<QuicConnection> conn,
        endpoint_type peer_ep) {
        AcceptHandlerFn handler; {
            std::lock_guard lock(mtx_);
            if (!pending_accepts_.empty()) {
                handler = std::move(pending_accepts_.front());
                pending_accepts_.pop_front();
            } else {
                accept_queue_.push_back(AcceptedStreamInfo{std::move(stream), std::move(conn), peer_ep});
                return;
            }
        }
        if (handler) {
            handler(std::error_code{}, AcceptedStreamInfo{std::move(stream), std::move(conn), peer_ep});
        }
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
