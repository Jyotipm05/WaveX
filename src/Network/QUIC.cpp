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

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>

#include <algorithm>
#include <cstring>
#include <random>
#include <sstream>
#include <iomanip>
#include <cassert>

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
#include <openssl/hmac.h>
#endif

namespace wavex::network::quic {

    // RFC 9001 §5.2 Initial Salt for QUIC Version 1
    static constexpr uint8_t INITIAL_SALT_V1[20] = {
        0x38, 0x7b, 0x23, 0x23, 0x12, 0x64, 0x71, 0xf5, 0x5a, 0xac,
        0x41, 0xd1, 0x61, 0x66, 0xe2, 0xd9, 0x1f, 0x80, 0x57, 0xb6
    };

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
        if (hex.size() % 2 != 0) return cid;

        cid.length_ = static_cast<uint8_t>(std::min(hex.size() / 2, MAX_CONNECTION_ID_LEN));
        for (std::size_t i = 0; i < cid.length_; ++i) {
            unsigned int byte_val = 0;
            std::stringstream ss;
            ss << std::hex << hex.substr(i * 2, 2);
            ss >> byte_val;
            cid.data_[i] = static_cast<uint8_t>(byte_val);
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
        std::visit([&out](const auto &f) {
            using T = std::decay_t<decltype(f)>;
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
                VarInt::encode(static_cast<uint64_t>(f.bidirectional ? FrameType::MaxStreamsBidi : FrameType::MaxStreamsUni), out);
                VarInt::encode(f.max_streams, out);
            } else if constexpr (std::is_same_v<T, DataBlockedFrame>) {
                VarInt::encode(static_cast<uint64_t>(FrameType::DataBlocked), out);
                VarInt::encode(f.data_limit, out);
            } else if constexpr (std::is_same_v<T, StreamDataBlockedFrame>) {
                VarInt::encode(static_cast<uint64_t>(FrameType::StreamDataBlocked), out);
                VarInt::encode(f.stream_id, out);
                VarInt::encode(f.stream_data_limit, out);
            } else if constexpr (std::is_same_v<T, StreamsBlockedFrame>) {
                VarInt::encode(static_cast<uint64_t>(f.bidirectional ? FrameType::StreamsBlockedBidi : FrameType::StreamsBlockedUni), out);
                VarInt::encode(f.stream_limit, out);
            } else if constexpr (std::is_same_v<T, ConnectionCloseFrame>) {
                VarInt::encode(static_cast<uint64_t>(f.is_application ? FrameType::ConnectionCloseApp : FrameType::ConnectionCloseQuic), out);
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
            out.append(reinterpret_cast<const char*>(hdr.dcid.data()), hdr.dcid.length());

            // SCID
            out.push_back(static_cast<char>(hdr.scid.length()));
            out.append(reinterpret_cast<const char*>(hdr.scid.data()), hdr.scid.length());

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
            out.append(reinterpret_cast<const char*>(hdr.dcid.data()), hdr.dcid.length());

            // Packet number
            for (int i = static_cast<int>(hdr.packet_number_len) - 1; i >= 0; --i) {
                out.push_back(static_cast<char>((hdr.packet_number >> (i * 8)) & 0xff));
            }
        }
    }

    bool unpack_packet_header(const std::string_view raw, PacketHeader &hdr, std::size_t &hdr_len) noexcept {
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
            const uint8_t dcid_len = static_cast<uint8_t>(raw[cursor++]);
            if (cursor + dcid_len > raw.size()) return false;
            hdr.dcid = ConnectionId(reinterpret_cast<const uint8_t*>(raw.data() + cursor), dcid_len);
            cursor += dcid_len;

            // SCID
            if (cursor >= raw.size()) return false;
            const uint8_t scid_len = static_cast<uint8_t>(raw[cursor++]);
            if (cursor + scid_len > raw.size()) return false;
            hdr.scid = ConnectionId(reinterpret_cast<const uint8_t*>(raw.data() + cursor), scid_len);
            cursor += scid_len;

            if (hdr.type == PacketType::Initial) {
                uint64_t token_len = 0;
                if (!VarInt::decode(raw, cursor, token_len)) return false;
                if (cursor + token_len > raw.size()) return false;
                hdr.token = std::string(raw.substr(cursor, token_len));
                cursor += token_len;
            }

            if (!VarInt::decode(raw, cursor, hdr.length)) return false;

            if (cursor + hdr.packet_number_len > raw.size()) return false;
            hdr.packet_number = 0;
            for (std::size_t i = 0; i < hdr.packet_number_len; ++i) {
                hdr.packet_number = (hdr.packet_number << 8) | static_cast<uint8_t>(raw[cursor++]);
            }
        } else {
            // Short header (1-RTT)
            hdr.type = PacketType::OneRTT;
            hdr.packet_number_len = static_cast<uint8_t>((first & 0x03) + 1);

            // DCID length heuristic (usually 8 bytes if omitted from packet)
            constexpr std::size_t kDefaultShortCidLen = 8;
            if (cursor + kDefaultShortCidLen > raw.size()) return false;
            hdr.dcid = ConnectionId(reinterpret_cast<const uint8_t*>(raw.data() + cursor), kDefaultShortCidLen);
            cursor += kDefaultShortCidLen;

            if (cursor + hdr.packet_number_len > raw.size()) return false;
            hdr.packet_number = 0;
            for (std::size_t i = 0; i < hdr.packet_number_len; ++i) {
                hdr.packet_number = (hdr.packet_number << 8) | static_cast<uint8_t>(raw[cursor++]);
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

        // HMAC-SHA256 expand
        std::string info = hkdf_label;
        info.push_back(0x01); // Counter

        unsigned int len = 0;
        uint8_t hmac_out[32];
        if (!HMAC(EVP_sha256(), secret, static_cast<int>(secret_len),
                  reinterpret_cast<const unsigned char*>(info.data()), info.size(),
                  hmac_out, &len)) {
            return false;
        }

        std::memcpy(out, hmac_out, std::min(out_len, static_cast<std::size_t>(len)));
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

    bool CryptoSuite::protect_packet(
        const ProtectionKeys &keys,
        PacketHeader &hdr,
        const std::string_view plaintext,
        std::string &ciphertext_out) noexcept {
        hdr.length = plaintext.size() + 16 + hdr.packet_number_len; // + 16 auth tag
        std::string header_bytes;
        pack_packet_header(hdr, header_bytes);

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
        if (ok && EVP_EncryptUpdate(ctx, nullptr, &out_len, reinterpret_cast<const uint8_t*>(header_bytes.data()), static_cast<int>(header_bytes.size())) != 1) ok = false;
        if (ok && EVP_EncryptUpdate(ctx, encrypted.data(), &out_len, reinterpret_cast<const uint8_t*>(plaintext.data()), static_cast<int>(plaintext.size())) != 1) ok = false;
        if (ok && EVP_EncryptFinal_ex(ctx, encrypted.data() + out_len, &out_len) != 1) ok = false;
        if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, encrypted.data() + plaintext.size()) != 1) ok = false;

        EVP_CIPHER_CTX_free(ctx);
        if (!ok) return false;

        ciphertext_out = header_bytes;
        ciphertext_out.append(reinterpret_cast<const char*>(encrypted.data()), encrypted.size());
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
        std::string &plaintext_out) noexcept {
        std::size_t hdr_len = 0;
        if (!unpack_packet_header(packet_bytes, hdr, hdr_len)) return false;

        if (hdr_len >= packet_bytes.size()) return false;
        const std::string_view payload = packet_bytes.substr(hdr_len);
        if (payload.size() < 16) return false;

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        std::array<uint8_t, 12> nonce = keys.iv;
        for (int i = 0; i < 8; ++i) {
            nonce[11 - i] ^= static_cast<uint8_t>((hdr.packet_number >> (i * 8)) & 0xff);
        }

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;

        const std::size_t cipher_len = payload.size() - 16;
        const auto *cipher_data = reinterpret_cast<const uint8_t*>(payload.data());
        const auto *tag_data = cipher_data + cipher_len;

        std::vector<uint8_t> decrypted(cipher_len);
        int out_len = 0;
        bool ok = true;

        if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, keys.key.data(), nonce.data()) != 1) ok = false;
        if (ok && EVP_DecryptUpdate(ctx, nullptr, &out_len, reinterpret_cast<const uint8_t*>(packet_bytes.data()), static_cast<int>(hdr_len)) != 1) ok = false;
        if (ok && EVP_DecryptUpdate(ctx, decrypted.data(), &out_len, cipher_data, static_cast<int>(cipher_len)) != 1) ok = false;
        if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t*>(tag_data)) != 1) ok = false;
        if (ok && EVP_DecryptFinal_ex(ctx, decrypted.data() + out_len, &out_len) <= 0) ok = false;

        EVP_CIPHER_CTX_free(ctx);
        if (!ok) return false;

        plaintext_out.assign(reinterpret_cast<const char*>(decrypted.data()), cipher_len);
        return true;
#else
        // Mock decode: strip 16 byte trailing tag
        plaintext_out.assign(payload.data(), payload.size() - 16);
        return true;
#endif
    }

    // ─── 6. QuicStream Implementation ──────────────────────────────────────────

    QuicStream::QuicStream(std::shared_ptr<QuicConnection> conn, const uint64_t stream_id, asio::any_io_executor executor) noexcept
        : conn_(conn), executor_(std::move(executor)), stream_id_(stream_id) {}

    QuicStream::~QuicStream() {
        close();
    }

    asio::any_io_executor QuicStream::get_executor() const noexcept {
        if (executor_) return executor_;
        if (auto c = conn_.lock()) {
            auto conn_ex = c->get_executor();
            if (conn_ex) return conn_ex;
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

    std::error_code QuicStream::shutdown(const asio::ip::tcp::socket::shutdown_type type, std::error_code &ec) noexcept {
        ec.clear();
        std::lock_guard lock(mtx_);
        if (type == asio::ip::tcp::socket::shutdown_send || type == asio::ip::tcp::socket::shutdown_both) {
            fin_sent_ = true;
            if (auto conn = conn_.lock()) {
                conn->queue_stream_data(stream_id_, "", true);
            }
        }
        if (type == asio::ip::tcp::socket::shutdown_receive || type == asio::ip::tcp::socket::shutdown_both) {
            fin_received_ = true;
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
        {
            std::lock_guard lock(mtx_);
            if (!is_open_) return;
            is_open_ = false;
            if (pending_read_) {
                cb = std::move(*pending_read_);
                pending_read_.reset();
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
        auto *dest = static_cast<uint8_t*>(buffer.data());
        for (std::size_t i = 0; i < to_read; ++i) {
            dest[i] = in_buffer_.front();
            in_buffer_.pop_front();
        }
        return to_read;
    }

    void QuicStream::push_inbound(const std::string_view data, const bool fin) {
        ReadCallback cb;
        std::size_t bytes_transferred = 0;
        std::error_code ec;

        {
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
                for (const char c : data) {
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
            conn->queue_stream_data(stream_id_, data, fin);
            return {};
        }
        return asio::error::not_connected;
    }

    // ─── 7. QuicConnection Implementation ──────────────────────────────────────

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
          is_server_(is_server) {
        const ConnectionId &secret_cid = (!initial_dcid.empty()) ? initial_dcid : peer_cid_;
        CryptoSuite::derive_initial_secrets(secret_cid, initial_keys_peer_, initial_keys_local_);
    }

    void QuicConnection::handle_datagram(const std::string_view datagram) {
        std::lock_guard lock(mtx_);
        PacketHeader hdr;
        std::string plaintext;

        const auto &keys = is_server_ ? initial_keys_peer_ : initial_keys_local_;
        if (!CryptoSuite::unprotect_packet(keys, hdr, datagram, plaintext)) {
            return;
        }

        largest_received_pn_ = std::max(largest_received_pn_, hdr.packet_number);

        std::vector<Frame> frames;
        if (parse_frames(plaintext, frames)) {
            bool has_crypto_frame = false;
            for (const auto &f : frames) {
                if (std::holds_alternative<CryptoFrame>(f)) {
                    has_crypto_frame = true;
                    break;
                }
            }

            if (is_server_ && has_crypto_frame) {
                // If a client (such as Chrome or cURL) initiates a TLS 1.3 ClientHello
                // in an Initial packet that cannot be completed by this transport,
                // signal RFC 9114 H3_VERSION_FALLBACK (0x0110).
                // Chromium handles H3_VERSION_FALLBACK by cleanly falling back to TCP
                // (HTTP/1.1 or HTTP/2) without triggering net::ERR_QUIC_PROTOCOL_ERROR.
                ConnectionCloseFrame ccf;
                ccf.is_application = true;
                ccf.error_code = 0x0110; // H3_VERSION_FALLBACK (RFC 9114 §8.1)
                ccf.reason_phrase = "H3_VERSION_FALLBACK";

                std::string payload;
                serialize_frame(ccf, payload);

                PacketHeader close_hdr;
                close_hdr.is_long = true;
                close_hdr.type = PacketType::Initial;
                close_hdr.version = version_;
                close_hdr.dcid = peer_cid_;
                close_hdr.scid = local_cid_;
                close_hdr.packet_number = next_packet_number_++;

                std::string packet;
                if (CryptoSuite::protect_packet(initial_keys_local_, close_hdr, payload, packet)) {
                    pending_outbound_datagrams_.push_back(std::move(packet));
                }
                state_ = ConnectionState::Closed;
                return;
            }

            process_frames(frames, hdr.packet_number);
        }

        if (is_server_ && state_ == ConnectionState::Initial) {
            send_initial_handshake_response();
            state_ = ConnectionState::Connected;
        }
    }

    void QuicConnection::process_frames(const std::vector<Frame> &frames, const uint64_t pn) {
        for (const auto &f : frames) {
            std::visit([this, pn](const auto &frame) {
                using T = std::decay_t<decltype(frame)>;
                if constexpr (std::is_same_v<T, PingFrame>) {
                    // Queue ACK response
                    AckFrame ack;
                    ack.largest_acknowledged = pn;
                    ack.ranges.push_back({0, 0});
                    std::string payload;
                    serialize_frame(ack, payload);
                } else if constexpr (std::is_same_v<T, StreamFrame>) {
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
                        if (on_stream_created_) {
                            on_stream_created_(stream);
                        }
                        it = streams_.find(frame.stream_id);
                    }
                    it->second->push_inbound(frame.data, frame.fin);
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
        const auto &keys = is_server_ ? initial_keys_local_ : initial_keys_peer_;
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

        std::string one_rtt_packet;
        if (CryptoSuite::protect_packet(keys, one_rtt_hdr, one_rtt_payload, one_rtt_packet)) {
            pending_outbound_datagrams_.push_back(std::move(one_rtt_packet));
        }
    }

    std::shared_ptr<QuicStream> QuicConnection::create_stream(const bool bidirectional) {
        std::lock_guard lock(mtx_);
        uint64_t sid = next_bidi_stream_id_;
        next_bidi_stream_id_ += 4;
        if (!bidirectional) sid |= 0x02;
        if (!is_server_) sid &= ~0x01ULL;
        else sid |= 0x01ULL;

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

    asio::awaitable<std::shared_ptr<QuicStream>> QuicConnection::accept_stream() {
        std::unique_lock lock(mtx_);
        if (!accepted_streams_.empty()) {
            auto stream = accepted_streams_.front();
            accepted_streams_.pop_front();
            co_return stream;
        }

        co_return co_await asio::async_initiate<const asio::use_awaitable_t<>&, void(std::shared_ptr<QuicStream>)>(
            [this](auto handler) {
                using HandlerType = std::decay_t<decltype(handler)>;
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
        OutboundCallback cb;
        {
            std::lock_guard lock(mtx_);
            StreamFrame sf;
            sf.stream_id = stream_id;
            sf.data = std::string(data);
            sf.fin = fin;
            sf.has_length = true;

            std::string payload;
            serialize_frame(sf, payload);

            PacketHeader hdr;
            hdr.is_long = false;
            hdr.type = PacketType::OneRTT;
            hdr.dcid = peer_cid_;
            hdr.packet_number = next_packet_number_++;

            std::string packet;
            const auto &keys = is_server_ ? initial_keys_local_ : initial_keys_peer_;
            if (CryptoSuite::protect_packet(keys, hdr, payload, packet)) {
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
        return pkts;
    }

    void QuicConnection::close(const TransportError err, const std::string_view reason) {
        OutboundCallback cb;
        {
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
            const auto &keys = is_server_ ? initial_keys_local_ : initial_keys_peer_;
            if (CryptoSuite::protect_packet(keys, hdr, payload, packet)) {
                pending_outbound_datagrams_.push_back(std::move(packet));
            }
            cb = on_outbound_;
        }
        if (cb) cb();
    }

    // ─── 8. QuicServer Implementation ──────────────────────────────────────────

    QuicServer::QuicServer(asio::io_context &io, const uint16_t port)
        : io_(io), socket_(io, asio::ip::udp::endpoint(asio::ip::udp::v4(), port)) {}

    QuicServer::QuicServer(asio::io_context &io, const std::string_view host, const uint16_t port)
        : io_(io), socket_(io, asio::ip::udp::endpoint(asio::ip::make_address(host), port)) {}

    QuicServer::~QuicServer() {
        stop();
    }

    void QuicServer::start() {
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
                if (ec || bytes_recvd == 0) return;

                const std::string_view datagram(reinterpret_cast<const char*>(recv_buf_.data()), bytes_recvd);
                PacketHeader hdr;
                std::size_t hdr_len = 0;

                if (unpack_packet_header(datagram, hdr, hdr_len)) {
                    std::shared_ptr<QuicConnection> conn;
                    {
                        std::lock_guard lock(mtx_);
                        auto it = connections_.find(hdr.dcid);
                        if (it != connections_.end()) {
                            conn = it->second;
                        } else {
                            // New incoming connection (Initial)
                            const ConnectionId server_cid = ConnectionId::random(8);
                            conn = std::make_shared<QuicConnection>(server_cid, hdr.scid, sender_endpoint_, true, io_.get_executor(), hdr.dcid);
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
        for (auto &dgram : datagrams) {
            auto buf = std::make_shared<std::string>(std::move(dgram));
            socket_.async_send_to(
                asio::buffer(*buf), conn->peer_endpoint(),
                [buf](std::error_code, std::size_t) {}
            );
        }
    }

    // ─── 9. QuicClient Implementation ──────────────────────────────────────────

    QuicClient::QuicClient(asio::io_context &io)
        : io_(io), socket_(io, asio::ip::udp::endpoint(asio::ip::udp::v4(), 0)) {}

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

        connection_ = std::make_shared<QuicConnection>(client_cid, initial_peer_cid, server_endpoint_, false, io_.get_executor(), initial_peer_cid);
        connection_->set_outbound_callback([this] {
            asio::post(io_, [this] {
                flush_outbound();
            });
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
                const std::string_view datagram(reinterpret_cast<const char*>(recv_buf_.data()), bytes_recvd);
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
        for (auto &dgram : datagrams) {
            auto buf = std::make_shared<std::string>(std::move(dgram));
            socket_.async_send_to(
                asio::buffer(*buf), server_endpoint_,
                [buf](std::error_code, std::size_t) {}
            );
        }
    }

} // namespace wavex::network::quic

namespace std {
    std::size_t hash<wavex::network::quic::ConnectionId>::operator()(const wavex::network::quic::ConnectionId &cid) const noexcept {
        std::size_t h = 14695981039346656037ULL;
        for (std::size_t i = 0; i < cid.length(); ++i) {
            h ^= cid.data()[i];
            h *= 1099511628211ULL;
        }
        return h;
    }
} // namespace std
