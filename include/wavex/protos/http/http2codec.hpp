// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file http2codec.hpp
 * @brief HTTP/2 Protocol Codec — Binary Framing and HPACK Header Compression
 *
 * Implements RFC 7540 (HTTP/2 Binary Framing Layer) and RFC 7541 (HPACK Header Compression)
 * matching the WaveX Codec concept for seamless integration with HttpRequest and HttpResponse.
 */

#pragma once

#if defined(NO_ERROR)
#undef NO_ERROR
#endif

#include <string_view>
#include <vector>
#include <array>
#include <string>
#include <charconv>
#include <cstdint>
#include <utility>
#include <wavex/protos/http/Methods.hpp>
#include <wavex/protos/http/http1codec.hpp> // for header, message_base, detail helpers

namespace wavex::protos::http {
    namespace http2 {
        // ─── Connection Preface ───────────────────────────────────────────────────
        inline constexpr std::string_view CONNECTION_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

        // ─── Frame Types (RFC 7540 §11.2) ─────────────────────────────────────────
        enum class frame_type : uint8_t {
            DATA = 0x0,
            HEADERS = 0x1,
            PRIORITY = 0x2,
            RST_STREAM = 0x3,
            SETTINGS = 0x4,
            PUSH_PROMISE = 0x5,
            PING = 0x6,
            GOAWAY = 0x7,
            WINDOW_UPDATE = 0x8,
            CONTINUATION = 0x9
        };

        // ─── Frame Flags (RFC 7540 §6) ────────────────────────────────────────────
        namespace flags {
            inline constexpr uint8_t NONE = 0x00;
            inline constexpr uint8_t END_STREAM = 0x01; // DATA, HEADERS
            inline constexpr uint8_t ACK = 0x01; // SETTINGS, PING
            inline constexpr uint8_t END_HEADERS = 0x04; // HEADERS, PUSH_PROMISE, CONTINUATION
            inline constexpr uint8_t PADDED = 0x08; // DATA, HEADERS, PUSH_PROMISE
            inline constexpr uint8_t PRIORITY = 0x20; // HEADERS
        }

        // ─── Error Codes (RFC 7540 §7) ────────────────────────────────────────────
#if defined(NO_ERROR)
#undef NO_ERROR
#endif
        enum class error_code : uint32_t {
            NO_ERROR = 0x0,
            NO_ERR = 0x0,
            PROTOCOL_ERROR = 0x1,
            INTERNAL_ERROR = 0x2,
            FLOW_CONTROL_ERROR = 0x3,
            SETTINGS_TIMEOUT = 0x4,
            STREAM_CLOSED = 0x5,
            FRAME_SIZE_ERROR = 0x6,
            REFUSED_STREAM = 0x7,
            CANCEL = 0x8,
            COMPRESSION_ERROR = 0x9,
            CONNECT_ERROR = 0xa,
            ENHANCE_YOUR_CALM = 0xb,
            INADEQUATE_SECURITY = 0xc,
            HTTP_1_1_REQUIRED = 0xd
        };

        // ─── Settings Identifiers (RFC 7540 §6.5.2) ───────────────────────────────
        enum class settings_parameter : uint16_t {
            HEADER_TABLE_SIZE = 0x1,
            ENABLE_PUSH = 0x2,
            MAX_CONCURRENT_STREAMS = 0x3,
            INITIAL_WINDOW_SIZE = 0x4,
            MAX_FRAME_SIZE = 0x5,
            MAX_HEADER_LIST_SIZE = 0x6
        };

        // ─── Frame Header (9 octets, RFC 7540 §4.1) ───────────────────────────────
        struct frame_header {
            uint32_t length = 0; // 24 bits: payload length
            frame_type type = frame_type::DATA; // 8 bits
            uint8_t flags = flags::NONE; // 8 bits
            uint32_t stream_id = 0; // 31 bits: MSB reserved bit masked out

            static constexpr std::size_t HEADER_SIZE = 9;

            [[nodiscard]] bool has_flag(const uint8_t f) const noexcept {
                return (flags & f) == f;
            }
        };

        /**
         * @brief Pack a 9-octet HTTP/2 frame header into a buffer.
         */
        inline void pack_frame_header(
            const frame_header &hdr,
            std::array<uint8_t, frame_header::HEADER_SIZE> &out) noexcept {
            // 24-bit Length (big-endian)
            out[0] = static_cast<uint8_t>((hdr.length >> 16) & 0xFF);
            out[1] = static_cast<uint8_t>((hdr.length >> 8) & 0xFF);
            out[2] = static_cast<uint8_t>(hdr.length & 0xFF);

            // Type and Flags
            out[3] = static_cast<uint8_t>(hdr.type);
            out[4] = hdr.flags;

            // 31-bit Stream ID (MSB is reserved R bit, must be 0)
            const uint32_t sid = hdr.stream_id & 0x7FFFFFFF;
            out[5] = static_cast<uint8_t>((sid >> 24) & 0xFF);
            out[6] = static_cast<uint8_t>((sid >> 16) & 0xFF);
            out[7] = static_cast<uint8_t>((sid >> 8) & 0xFF);
            out[8] = static_cast<uint8_t>(sid & 0xFF);
        }

        /**
         * @brief Unpack a 9-octet HTTP/2 frame header from a buffer.
         */
        inline bool unpack_frame_header(
            const std::string_view buf,
            frame_header &hdr) noexcept {
            if (buf.size() < frame_header::HEADER_SIZE) return false;

            const auto *p = reinterpret_cast<const uint8_t *>(buf.data());
            hdr.length = (static_cast<uint32_t>(p[0]) << 16) |
                         (static_cast<uint32_t>(p[1]) << 8) |
                         static_cast<uint32_t>(p[2]);

            hdr.type = static_cast<frame_type>(p[3]);
            hdr.flags = p[4];

            hdr.stream_id = ((static_cast<uint32_t>(p[5]) & 0x7F) << 24) |
                            (static_cast<uint32_t>(p[6]) << 16) |
                            (static_cast<uint32_t>(p[7]) << 8) |
                            static_cast<uint32_t>(p[8]);
            return true;
        }

        // ─── HPACK (RFC 7541) Header Compression Engine ───────────────────────────
        namespace hpack {
            struct static_entry {
                std::string_view name;
                std::string_view value;
            };

            // RFC 7541 Appendix A — Static Table (1-indexed, entries 1..61)
            inline constexpr std::array<static_entry, 62> STATIC_TABLE = {
                {
                    {"", ""}, // 0 index unused
                    {":authority", ""},
                    {":method", "GET"},
                    {":method", "POST"},
                    {":path", "/"},
                    {":path", "/index.html"},
                    {":scheme", "http"},
                    {":scheme", "https"},
                    {":status", "200"},
                    {":status", "204"},
                    {":status", "206"},
                    {":status", "304"},
                    {":status", "400"},
                    {":status", "404"},
                    {":status", "500"},
                    {"accept-charset", ""},
                    {"accept-encoding", "gzip, deflate"},
                    {"accept-language", ""},
                    {"accept-ranges", ""},
                    {"accept", ""},
                    {"access-control-allow-origin", ""},
                    {"age", ""},
                    {"allow", ""},
                    {"authorization", ""},
                    {"cache-control", ""},
                    {"content-disposition", ""},
                    {"content-encoding", ""},
                    {"content-language", ""},
                    {"content-length", ""},
                    {"content-location", ""},
                    {"content-range", ""},
                    {"content-type", ""},
                    {"cookie", ""},
                    {"date", ""},
                    {"etag", ""},
                    {"expect", ""},
                    {"expires", ""},
                    {"from", ""},
                    {"host", ""},
                    {"if-match", ""},
                    {"if-modified-since", ""},
                    {"if-none-match", ""},
                    {"if-range", ""},
                    {"if-unmodified-since", ""},
                    {"last-modified", ""},
                    {"link", ""},
                    {"location", ""},
                    {"max-forwards", ""},
                    {"proxy-authenticate", ""},
                    {"proxy-authorization", ""},
                    {"range", ""},
                    {"referer", ""},
                    {"refresh", ""},
                    {"retry-after", ""},
                    {"server", ""},
                    {"set-cookie", ""},
                    {"strict-transport-security", ""},
                    {"transfer-encoding", ""},
                    {"user-agent", ""},
                    {"vary", ""},
                    {"via", ""},
                    {"www-authenticate", ""}
                }
            };

            /**
             * @brief Find static table index for a header name and optional value.
             * Returns pair {index, exact_match}.
             */
            inline std::pair<std::size_t, bool> find_static(
                const std::string_view name,
                const std::string_view value = "") noexcept {
                std::size_t name_match = 0;
                for (std::size_t i = 1; i < STATIC_TABLE.size(); ++i) {
                    if (detail::is_equal(STATIC_TABLE[i].name, name)) {
                        if (STATIC_TABLE[i].value == value) {
                            return {i, true}; // Name + Value exact match
                        }
                        if (name_match == 0) {
                            name_match = i;
                        }
                    }
                }
                return {name_match, false};
            }

            /**
             * @brief Encode variable-length HPACK integer (RFC 7541 §5.1).
             */
            inline void encode_integer(
                std::string &out,
                uint64_t value,
                const uint8_t prefix_bits,
                const uint8_t prefix_mask = 0x00) {
                const auto max_prefix = static_cast<uint8_t>((1U << prefix_bits) - 1U);
                if (value < max_prefix) {
                    out.push_back(static_cast<char>(prefix_mask | static_cast<uint8_t>(value)));
                    return;
                }

                out.push_back(static_cast<char>(prefix_mask | max_prefix));
                value -= max_prefix;
                while (value >= 128) {
                    out.push_back(static_cast<char>((value % 128) | 0x80));
                    value /= 128;
                }
                out.push_back(static_cast<char>(value));
            }

            /**
             * @brief Decode variable-length HPACK integer (RFC 7541 §5.1).
             */
            inline bool decode_integer(
                const std::string_view in,
                std::size_t &cursor,
                const uint8_t prefix_bits,
                uint64_t &result) noexcept {
                if (cursor >= in.size()) return false;

                const auto max_prefix = static_cast<uint8_t>((1U << prefix_bits) - 1U);
                const auto first = static_cast<uint8_t>(in[cursor++]);
                result = first & max_prefix;

                if (result < max_prefix) return true;

                uint64_t m = 0;
                while (cursor < in.size()) {
                    const auto b = static_cast<uint8_t>(in[cursor++]);
                    result += static_cast<uint64_t>(b & 0x7F) << m;
                    m += 7;
                    if ((b & 0x80) == 0) return true;
                    if (m > 63) return false; // Overflow protection
                }
                return false;
            }

            /**
             * @brief Encode literal string (RFC 7541 §5.2).
             * Emits uncompressed literal string (Huffman = 0) with 7-bit prefix integer length.
             */
            inline void encode_string(std::string &out, const std::string_view str) {
                encode_integer(out, str.size(), 7, 0x00); // H = 0
                out.append(str);
            }

            // ─── RFC 7541 Huffman Decoding Tree / Tables ──────────────────────────
            // Fast Huffman decoding for standard HPACK static table codes
            namespace huffman {
                // Huffman code definition: {bits, bit_length}
                struct huff_code {
                    uint32_t code;
                    uint8_t bits;
                };

                // RFC 7541 Appendix B Huffman Code Table (256 octets + EOS)
                inline constexpr huff_code TABLE[257] = {
                    {0x1ff8, 13}, {0x7fffd8, 23}, {0xfffffe2, 28}, {0xfffffe3, 28}, {0xfffffe4, 28}, {0xfffffe5, 28},
                    {0xfffffe6, 28}, {0xfffffe7, 28}, {0xfffffe8, 28}, {0xffffea, 24}, {0x3ffffffc, 30},
                    {0xfffffe9, 28},
                    {0xfffffea, 28}, {0x3ffffffd, 30}, {0xfffffeb, 28}, {0xfffffec, 28}, {0xfffffed, 28},
                    {0xfffffee, 28},
                    {0xfffffef, 28}, {0xffffff0, 28}, {0xffffff1, 28}, {0xffffff2, 28}, {0x3ffffffe, 30},
                    {0xffffff3, 28},
                    {0xffffff4, 28}, {0xffffff5, 28}, {0xffffff6, 28}, {0xffffff7, 28}, {0xffffff8, 28},
                    {0xffffff9, 28},
                    {0xffffffa, 28}, {0xffffffb, 28}, {0x14, 6}, {0x3f8, 10}, {0x3f9, 10}, {0xffa, 12}, {0x1ff9, 13},
                    {0x15, 6}, {0xf8, 8}, {0x7fa, 11}, {0x3fa, 10}, {0x3fb, 10}, {0xf9, 8}, {0x7fb, 11}, {0xfa, 8},
                    {0x16, 6}, {0x17, 6}, {0x18, 6}, {0x0, 5}, {0x1, 5}, {0x2, 5}, {0x19, 6}, {0x1a, 6}, {0x1b, 6},
                    {0x1c, 6}, {0x1d, 6}, {0x1e, 6}, {0x1f, 6}, {0x5c, 7}, {0xfb, 8}, {0x7ffc, 15}, {0x20, 6},
                    {0xffb, 12}, {0x3fc, 10}, {0x1ffa, 13}, {0x21, 6}, {0x5d, 7}, {0x5e, 7}, {0x5f, 7}, {0x60, 7},
                    {0x61, 7}, {0x62, 7}, {0x63, 7}, {0x64, 7}, {0x65, 7}, {0x66, 7}, {0x67, 7}, {0x68, 7}, {0x69, 7},
                    {0x6a, 7}, {0x6b, 7}, {0x6c, 7}, {0x6d, 7}, {0x6e, 7}, {0x6f, 7}, {0x70, 7}, {0x71, 7}, {0x72, 7},
                    {0xfc, 8}, {0x73, 7}, {0xfd, 8}, {0x1ffb, 13}, {0x7fff0, 19}, {0x1ffc, 13}, {0x3ffc, 14}, {0x22, 6},
                    {0x7ffd, 15}, {0x3, 5}, {0x23, 6}, {0x4, 5}, {0x24, 6}, {0x5, 5}, {0x25, 6}, {0x26, 6}, {0x27, 6},
                    {0x6, 5}, {0x74, 7}, {0x75, 7}, {0x28, 6}, {0x29, 6}, {0x2a, 6}, {0x7, 5}, {0x2b, 6}, {0x76, 7},
                    {0x2c, 6}, {0x8, 5}, {0x9, 5}, {0x2d, 6}, {0x77, 7}, {0x78, 7}, {0x79, 7}, {0x7a, 7}, {0x7b, 7},
                    {0x7ffe, 15}, {0x7fc, 11}, {0x3ffd, 14}, {0x1ffd, 13}, {0xffffffc, 28}, {0xfffe6, 20},
                    {0x3fffd2, 22},
                    {0xfffe7, 20}, {0xfffe8, 20}, {0x3fffd3, 22}, {0x3fffd4, 22}, {0xffffffd, 28}, {0x7fffd9, 23},
                    {0x3fffd5, 22}, {0x7fffda, 23}, {0x7fffdb, 23}, {0x7fffdc, 23}, {0x7fffdd, 23}, {0x7fffde, 23},
                    {0xffffeb, 24}, {0x7fffdf, 23}, {0xffffec, 24}, {0xffffed, 24}, {0x3fffd6, 22}, {0x7fffe0, 23},
                    {0x1fffdc, 21}, {0x3fffd7, 22}, {0x7fffe1, 23}, {0x7fffe2, 23}, {0x7fffe3, 23}, {0x7fffe4, 23},
                    {0x1fffdd, 21}, {0x7fffe5, 23}, {0x7fffe6, 23}, {0x7fffe7, 23}, {0x7fffe8, 23}, {0x7ffffff, 30},
                    {0x3fffe, 18}, {0x7fffe9, 23}, {0xfffe9, 20}, {0x3fffd8, 22}, {0x7fffea, 23}, {0x3fffd9, 22},
                    {0x3fffda, 22}, {0x7fffeb, 23}, {0x7fffec, 23}, {0x7fffed, 23}, {0x7fffee, 23}, {0x7fffef, 23},
                    {0x7ffff0, 23}, {0x3fffdb, 22}, {0x3fffdc, 22}, {0x7ffff1, 23}, {0x7ffff2, 23}, {0x1fffde, 21},
                    {0x7ffff3, 23}, {0x7ffff4, 23}, {0x7ffff5, 23}, {0x7ffff6, 23}, {0x7ffff7, 23}, {0x7ffff8, 23},
                    {0x7ffff9, 23}, {0x7ffffa, 23}, {0x7ffffb, 23}, {0x1fffdf, 21}, {0x7ffffc, 23}, {0xfffea, 20},
                    {0x3fffdd, 22}, {0x1fffe0, 21}, {0x1fffe1, 21}, {0x3fffde, 22}, {0x7ffffd, 23}, {0x3fffdf, 22},
                    {0x7ffffe, 23}, {0xffffff0, 24}, {0xffffff1, 24}, {0x3fffe0, 22}, {0x1fffe2, 21}, {0x1fffe3, 21},
                    {0x3fffe1, 22}, {0x1fffe4, 21}, {0x7ffea, 19}, {0x3fffe2, 22}, {0x3fffe3, 22}, {0x3fffe4, 22},
                    {0x7ffeb, 19}, {0x7ffec, 19}, {0x3fffe5, 22}, {0x3fffe6, 22}, {0x3fffe7, 22}, {0x3fffe8, 22},
                    {0x3fffe9, 22}, {0x3fffea, 22}, {0x3fffeb, 22}, {0x1fffe5, 21}, {0x3fffec, 22}, {0x3fffed, 22},
                    {0x3fffee, 22}, {0x3fffef, 22}, {0x3ffff0, 22}, {0x3ffff1, 22}, {0x3ffff2, 22}, {0x3ffff3, 22},
                    {0x1fffe6, 21}, {0x3ffff4, 22}, {0x3ffff5, 22}, {0x3ffff6, 22}, {0x3ffff7, 22}, {0x3ffff8, 22},
                    {0x3ffff9, 22}, {0x3ffffa, 22}, {0x3ffffb, 22}, {0x1fffe7, 21}, {0x1fffe8, 21}, {0x3ffffc, 22},
                    {0x3ffffd, 22}, {0x1fffe9, 21}, {0x1fffea, 21}, {0x1fffeb, 21}, {0x1fffec, 21}, {0x1fffed, 21},
                    {0x1fffee, 21}, {0x1fffef, 21}, {0xfffeeb, 24}, {0xfffeec, 24}, {0xfffeed, 24}, {0xfffeee, 24},
                    {0x7fffec, 24}, {0x7fffed, 24}, {0x7fffee, 24}, {0x7ffff0, 24}, {0x7ffff1, 24}, {0x3fffffe, 30}
                };

                /**
                 * @brief Decode an RFC 7541 Huffman encoded string.
                 */
                inline bool decode(const std::string_view in, std::string &out) {
                    uint32_t current = 0;
                    uint8_t bits = 0;

                    for (const char c: in) {
                        current = (current << 8) | static_cast<uint8_t>(c);
                        bits += 8;

                        while (bits >= 5) {
                            bool matched = false;
                            // Search symbol in TABLE
                            for (uint32_t sym = 0; sym < 256; ++sym) {
                                const auto &e = TABLE[sym];
                                if (e.bits <= bits) {
                                    const uint32_t code_part = (current >> (bits - e.bits)) & ((1U << e.bits) - 1U);
                                    if (code_part == e.code) {
                                        out.push_back(static_cast<char>(sym));
                                        bits -= e.bits;
                                        matched = true;
                                        break;
                                    }
                                }
                            }
                            if (!matched) break;
                        }
                    }

                    // Padding check: must be less than 8 bits and all 1s
                    if (bits > 0) {
                        if (bits > 7) return false;
                        const uint32_t mask = (1U << bits) - 1U;
                        if ((current & mask) != mask) return false;
                    }
                    return true;
                }
            } // namespace huffman

            /**
             * @brief Decode literal string (RFC 7541 §5.2). Supports both raw and Huffman decoding.
             */
            inline bool decode_string(
                const std::string_view in,
                std::size_t &cursor,
                std::string &out) {
                if (cursor >= in.size()) return false;

                const bool is_huffman = (static_cast<uint8_t>(in[cursor]) & 0x80) != 0;
                uint64_t str_len = 0;
                if (!decode_integer(in, cursor, 7, str_len)) return false;

                if (cursor + str_len > in.size()) return false;
                const std::string_view raw_str = in.substr(cursor, str_len);
                cursor += str_len;

                if (is_huffman) {
                    return huffman::decode(raw_str, out);
                }
                out.append(raw_str);
                return true;
            }

            // ─── HPACK Dynamic Table ──────────────────────────────────────────────
            class dynamic_table {
            public:
                struct entry {
                    std::string name;
                    std::string value;

                    [[nodiscard]] std::size_t size() const noexcept {
                        return name.size() + value.size() + 32;
                    }
                };

                explicit dynamic_table(const std::size_t max_capacity = 4096)
                    : max_capacity_(max_capacity) {
                }

                void set_max_capacity(const std::size_t new_cap) {
                    max_capacity_ = new_cap;
                    evict_to_fit();
                }

                void insert(std::string name, std::string value) {
                    const entry e{std::move(name), std::move(value)};
                    const std::size_t entry_sz = e.size();
                    if (entry_sz > max_capacity_) {
                        entries_.clear();
                        current_size_ = 0;
                        return;
                    }
                    entries_.insert(entries_.begin(), e);
                    current_size_ += entry_sz;
                    evict_to_fit();
                }

                [[nodiscard]] std::size_t size() const noexcept { return entries_.size(); }

                [[nodiscard]] const entry *get(const std::size_t dynamic_index) const noexcept {
                    if (dynamic_index < entries_.size()) return &entries_[dynamic_index];
                    return nullptr;
                }

            private:
                void evict_to_fit() {
                    while (current_size_ > max_capacity_ && !entries_.empty()) {
                        current_size_ -= entries_.back().size();
                        entries_.pop_back();
                    }
                }

                std::vector<entry> entries_;
                std::size_t current_size_ = 0;
                std::size_t max_capacity_ = 4096;
            };

            /**
             * @brief HPACK Encoder: serializes headers into binary header blocks.
             */
            class encoder {
            public:
                /**
                 * @brief Encode request pseudo-headers and headers list into a header block fragment.
                 */
                static std::string encode_request_headers(
                    const http::method m,
                    const std::string_view target,
                    const std::string_view scheme,
                    const std::string_view authority,
                    const std::vector<header> &headers) {
                    std::string out;
                    out.reserve(256);

                    // 1. :method
                    const std::string_view method_str = to_string(m);
                    const auto [m_idx, m_exact] = find_static(":method", method_str);
                    if (m_exact) {
                        encode_integer(out, m_idx, 7, 0x80); // Indexed Header Field (1xxxxxxx)
                    } else if (m_idx > 0) {
                        encode_integer(out, m_idx, 4, 0x00); // Literal without indexing, indexed name (0000xxxx)
                        encode_string(out, method_str);
                    } else {
                        encode_integer(out, 0, 4, 0x00);
                        encode_string(out, ":method");
                        encode_string(out, method_str);
                    }

                    // 2. :scheme
                    const auto [s_idx, s_exact] = find_static(":scheme", scheme.empty() ? "https" : scheme);
                    if (s_exact) {
                        encode_integer(out, s_idx, 7, 0x80);
                    } else {
                        encode_integer(out, 6, 4, 0x00); // static 6 = :scheme: http
                        encode_string(out, scheme.empty() ? "https" : scheme);
                    }

                    // 3. :path
                    const std::string_view path = target.empty() ? "/" : target;
                    if (path == "/") {
                        encode_integer(out, 4, 7, 0x80); // static 4 = :path: /
                    } else if (path == "/index.html") {
                        encode_integer(out, 5, 7, 0x80); // static 5 = :path: /index.html
                    } else {
                        encode_integer(out, 4, 4, 0x00); // indexed name :path
                        encode_string(out, path);
                    }

                    // 4. authority (if present)
                    if (!authority.empty()) {
                        encode_integer(out, 1, 4, 0x00); // indexed name :authority
                        encode_string(out, authority);
                    }

                    // 5. General Headers
                    for (const auto &[name, value]: headers) {
                        if (name.starts_with(':')) continue; // Skip pseudo-headers already handled
                        const auto [idx, exact] = find_static(name, value);
                        if (exact) {
                            encode_integer(out, idx, 7, 0x80);
                        } else if (idx > 0) {
                            encode_integer(out, idx, 4, 0x00);
                            encode_string(out, value);
                        } else {
                            encode_integer(out, 0, 4, 0x00);
                            encode_string(out, name);
                            encode_string(out, value);
                        }
                    }

                    return out;
                }

                /**
                 * @brief Encode response pseudo-headers and headers list into a header block fragment.
                 */
                static std::string encode_response_headers(
                    const unsigned int status_code,
                    const std::vector<header> &headers) {
                    std::string out;
                    out.reserve(256);

                    // 1. :status
                    char status_buf[16];
                    const auto [ptr, ec] = std::to_chars(status_buf, status_buf + sizeof(status_buf), status_code);
                    const std::string_view status_str(status_buf, ptr);

                    const auto [s_idx, s_exact] = find_static(":status", status_str);
                    if (s_exact) {
                        encode_integer(out, s_idx, 7, 0x80);
                    } else {
                        encode_integer(out, 8, 4, 0x00); // static 8 = :status: 200
                        encode_string(out, status_str);
                    }

                    // 2. Regular headers
                    for (const auto &[name, value]: headers) {
                        if (name.starts_with(':')) continue;
                        const auto [idx, exact] = find_static(name, value);
                        if (exact) {
                            encode_integer(out, idx, 7, 0x80);
                        } else if (idx > 0) {
                            encode_integer(out, idx, 4, 0x00);
                            encode_string(out, value);
                        } else {
                            encode_integer(out, 0, 4, 0x00);
                            encode_string(out, name);
                            encode_string(out, value);
                        }
                    }

                    return out;
                }
            };

            /**
             * @brief HPACK Decoder: parses binary header blocks into header pairs.
             */
            class decoder {
            public:
                explicit decoder(dynamic_table &dt) : dt_(dt) {
                }

                bool decode_header_block(
                    const std::string_view block,
                    std::vector<std::pair<std::string, std::string> > &out_headers) const {
                    std::size_t cursor = 0;
                    while (cursor < block.size()) {
                        const auto b = static_cast<uint8_t>(block[cursor]);

                        // Case 1: Indexed Header Field (starts with 1xxxxxxx)
                        if ((b & 0x80) != 0) {
                            uint64_t index = 0;
                            if (!decode_integer(block, cursor, 7, index)) return false;
                            auto [n, v] = lookup_index(index);
                            if (n.empty()) return false;
                            out_headers.emplace_back(std::string(n), std::string(v));
                        }
                        // Case 2: Literal Header with Incremental Indexing (starts with 01xxxxxx)
                        else if ((b & 0x40) != 0) {
                            uint64_t name_idx = 0;
                            if (!decode_integer(block, cursor, 6, name_idx)) return false;
                            std::string name, val;
                            if (name_idx == 0) {
                                if (!decode_string(block, cursor, name)) return false;
                            } else {
                                auto [n, _] = lookup_index(name_idx);
                                if (n.empty()) return false;
                                name = std::string(n);
                            }
                            if (!decode_string(block, cursor, val)) return false;
                            dt_.insert(name, val);
                            out_headers.emplace_back(std::move(name), std::move(val));
                        }
                        // Case 3: Dynamic Table Size Update (starts with 001xxxxx)
                        else if ((b & 0x20) != 0) {
                            uint64_t new_max_size = 0;
                            if (!decode_integer(block, cursor, 5, new_max_size)) return false;
                            dt_.set_max_capacity(new_max_size);
                        }
                        // Case 4: Literal Header without Indexing (0000xxxx or 0001xxxx)
                        else {
                            uint64_t name_idx = 0;
                            if (!decode_integer(block, cursor, 4, name_idx)) return false;
                            std::string name, val;
                            if (name_idx == 0) {
                                if (!decode_string(block, cursor, name)) return false;
                            } else {
                                auto [n, _] = lookup_index(name_idx);
                                if (n.empty()) return false;
                                name = std::string(n);
                            }
                            if (!decode_string(block, cursor, val)) return false;
                            out_headers.emplace_back(std::move(name), std::move(val));
                        }
                    }
                    return true;
                }

            private:
                [[nodiscard]] std::pair<std::string_view, std::string_view> lookup_index(const uint64_t idx) const {
                    if (idx == 0) return {};
                    if (idx < STATIC_TABLE.size()) {
                        return {STATIC_TABLE[idx].name, STATIC_TABLE[idx].value};
                    }
                    const std::size_t dyn_idx = idx - STATIC_TABLE.size();
                    if (const auto *entry = dt_.get(dyn_idx)) {
                        return {entry->name, entry->value};
                    }
                    return {};
                }

                dynamic_table &dt_;
            };
        } // namespace hpack

        // ─── HTTP/2 Messages ───────────────────────────────────────────────────────

        /**
         * @brief HTTP/2 Request Message (inherits protocol-agnostic message_base).
         */
        struct request : public message_base {
            http::method method_type = method::UNKNOWN;
            std::string_view target; ///< Extracted from :path
            uint32_t stream_id = 1; ///< HTTP/2 Stream Identifier
            std::string_view scheme = "https"; ///< :scheme
            std::string_view authority; ///< :authority

            // Internal backing storage for decoded strings
            std::string target_storage;
            std::string scheme_storage;
            std::string authority_storage;
            std::string body_storage;
            std::vector<std::pair<std::string, std::string> > headers_storage;

            request() {
                version_major = 2;
                version_minor = 0;
            }

            request(const request &other)
                : message_base(other),
                  method_type(other.method_type),
                  stream_id(other.stream_id),
                  target_storage(other.target_storage),
                  scheme_storage(other.scheme_storage),
                  authority_storage(other.authority_storage),
                  body_storage(other.body_storage),
                  headers_storage(other.headers_storage) {
                rebase(other);
            }

            request(request &&other) noexcept
                : message_base(std::move(other)),
                  method_type(other.method_type),
                  stream_id(other.stream_id),
                  target_storage(std::move(other.target_storage)),
                  scheme_storage(std::move(other.scheme_storage)),
                  authority_storage(std::move(other.authority_storage)),
                  body_storage(std::move(other.body_storage)),
                  headers_storage(std::move(other.headers_storage)) {
                rebase(other);
            }

            request &operator=(const request &other) {
                if (this != &other) {
                    message_base::operator=(other);
                    method_type = other.method_type;
                    stream_id = other.stream_id;
                    target_storage = other.target_storage;
                    scheme_storage = other.scheme_storage;
                    authority_storage = other.authority_storage;
                    body_storage = other.body_storage;
                    headers_storage = other.headers_storage;
                    rebase(other);
                }
                return *this;
            }

            request &operator=(request &&other) noexcept {
                if (this != &other) {
                    message_base::operator=(std::move(other));
                    method_type = other.method_type;
                    stream_id = other.stream_id;
                    target_storage = std::move(other.target_storage);
                    scheme_storage = std::move(other.scheme_storage);
                    authority_storage = std::move(other.authority_storage);
                    body_storage = std::move(other.body_storage);
                    headers_storage = std::move(other.headers_storage);
                    rebase(other);
                }
                return *this;
            }

            void rebase(const request &fallback) {
                target = !target_storage.empty() ? std::string_view(target_storage) : fallback.target;
                scheme = !scheme_storage.empty() ? std::string_view(scheme_storage) : fallback.scheme;
                authority = !authority_storage.empty() ? std::string_view(authority_storage) : fallback.authority;
                body = !body_storage.empty() ? std::string_view(body_storage) : fallback.body;

                if (!headers_storage.empty()) {
                    headers.clear();
                    headers.reserve(headers_storage.size());
                    for (const auto &[n, v]: headers_storage) {
                        headers.emplace_back(n, v);
                    }
                }
            }
        };

        /**
         * @brief HTTP/2 Response Message (inherits protocol-agnostic message_base).
         */
        struct response : public message_base {
            unsigned int status_code = 200;
            std::string_view status_text = "OK";
            uint32_t stream_id = 1; ///< Target HTTP/2 Stream Identifier

            // Internal backing storage for decoded strings
            std::string body_storage;
            std::vector<std::pair<std::string, std::string> > headers_storage;

            response() {
                version_major = 2;
                version_minor = 0;
            }

            response(const response &other)
                : message_base(other),
                  status_code(other.status_code),
                  status_text(other.status_text),
                  stream_id(other.stream_id),
                  body_storage(other.body_storage),
                  headers_storage(other.headers_storage) {
                rebase(other);
            }

            response(response &&other) noexcept
                : message_base(std::move(other)),
                  status_code(other.status_code),
                  status_text(other.status_text),
                  stream_id(other.stream_id),
                  body_storage(std::move(other.body_storage)),
                  headers_storage(std::move(other.headers_storage)) {
                rebase(other);
            }

            response &operator=(const response &other) {
                if (this != &other) {
                    message_base::operator=(other);
                    status_code = other.status_code;
                    status_text = other.status_text;
                    stream_id = other.stream_id;
                    body_storage = other.body_storage;
                    headers_storage = other.headers_storage;
                    rebase(other);
                }
                return *this;
            }

            response &operator=(response &&other) noexcept {
                if (this != &other) {
                    message_base::operator=(std::move(other));
                    status_code = other.status_code;
                    status_text = other.status_text;
                    stream_id = other.stream_id;
                    body_storage = std::move(other.body_storage);
                    headers_storage = std::move(other.headers_storage);
                    rebase(other);
                }
                return *this;
            }

            void rebase(const response &fallback) {
                body = !body_storage.empty() ? std::string_view(body_storage) : fallback.body;

                if (!headers_storage.empty()) {
                    headers.clear();
                    headers.reserve(headers_storage.size());
                    for (const auto &[n, v]: headers_storage) {
                        headers.emplace_back(n, v);
                    }
                }
            }
        };

        // ─── HTTP/2 Parser ─────────────────────────────────────────────────────────

        /**
         * @brief HTTP/2 Binary Message Parser.
         */
        class parser {
        public:
            enum class result { success, incomplete, error };

            /**
             * @brief Parse a single HTTP/2 frame from a buffer.
             * @param buffer Raw network buffer.
             * @param hdr Output frame header.
             * @param payload Output view of the frame's payload.
             * @param bytes_consumed Output bytes consumed (9 + payload size).
             */
            [[nodiscard]]
            static result parse_frame(
                const std::string_view buffer,
                frame_header &hdr,
                std::string_view &payload,
                std::size_t &bytes_consumed) {
                bytes_consumed = 0;
                if (buffer.size() < frame_header::HEADER_SIZE) return result::incomplete;

                if (!unpack_frame_header(buffer, hdr)) return result::error;

                const std::size_t total_frame_len = frame_header::HEADER_SIZE + hdr.length;
                if (buffer.size() < total_frame_len) return result::incomplete;

                payload = buffer.substr(frame_header::HEADER_SIZE, hdr.length);
                bytes_consumed = total_frame_len;
                return result::success;
            }

            /**
             * @brief Parse an incoming HTTP/2 client request from a network buffer.
             * Handles connection preface, initial SETTINGS, HEADERS, and DATA frames.
             */
            [[nodiscard]]
            static result parse_request(
                const std::string_view buffer,
                request &req,
                std::size_t &bytes_consumed) {
                bytes_consumed = 0;
                std::size_t cursor = 0;

                // 1. Consume connection preface if present
                if (buffer.starts_with(CONNECTION_PREFACE)) {
                    cursor += CONNECTION_PREFACE.size();
                }

                hpack::dynamic_table dt;
                hpack::decoder dec(dt);

                std::vector<std::pair<std::string, std::string> > decoded_headers;
                bool headers_received = false;
                std::string body_accumulator;

                while (cursor < buffer.size()) {
                    const std::string_view remaining = buffer.substr(cursor);
                    frame_header hdr;
                    std::string_view payload;
                    std::size_t frame_bytes = 0;

                    const auto r = parse_frame(remaining, hdr, payload, frame_bytes);
                    if (r != result::success) {
                        if (r == result::incomplete && headers_received) {
                            // If headers already parsed and we're waiting for DATA
                            return result::incomplete;
                        }
                        return r;
                    }

                    cursor += frame_bytes;

                    if (hdr.type == frame_type::SETTINGS) {
                        // Acknowledge or process SETTINGS frame, proceed to next frame
                        continue;
                    }

                    if (hdr.type == frame_type::HEADERS) {
                        req.stream_id = hdr.stream_id;
                        std::size_t pad_len = 0;
                        std::size_t header_cursor = 0;

                        if (hdr.has_flag(flags::PADDED)) {
                            if (payload.empty()) return result::error;
                            pad_len = static_cast<uint8_t>(payload[0]);
                            header_cursor += 1;
                        }

                        if (hdr.has_flag(flags::PRIORITY)) {
                            if (payload.size() < header_cursor + 5) return result::error;
                            header_cursor += 5; // Stream dependency (4) + weight (1)
                        }

                        if (payload.size() < header_cursor + pad_len) return result::error;
                        const std::string_view header_block = payload.substr(
                            header_cursor, payload.size() - header_cursor - pad_len);

                        if (!dec.decode_header_block(header_block, decoded_headers)) {
                            return result::error;
                        }

                        headers_received = true;
                        if (hdr.has_flag(flags::END_STREAM)) {
                            break;
                        }
                    } else if (hdr.type == frame_type::DATA) {
                        if (hdr.stream_id == req.stream_id) {
                            std::size_t pad_len = 0;
                            std::size_t data_offset = 0;
                            if (hdr.has_flag(flags::PADDED)) {
                                if (payload.empty()) return result::error;
                                pad_len = static_cast<uint8_t>(payload[0]);
                                data_offset += 1;
                            }
                            if (payload.size() < data_offset + pad_len) return result::error;
                            body_accumulator.append(
                                payload.substr(data_offset, payload.size() - data_offset - pad_len));

                            if (hdr.has_flag(flags::END_STREAM)) {
                                break;
                            }
                        }
                    }
                }

                if (!headers_received) return result::incomplete;

                // Transfer decoded headers and extract pseudo-headers
                req.headers.clear();
                req.headers_storage.clear();
                req.target_storage.clear();
                req.scheme_storage.clear();
                req.authority_storage.clear();

                for (auto &[name, value]: decoded_headers) {
                    if (name == ":method") {
                        req.method_type = from_string(value);
                    } else if (name == ":path") {
                        req.target_storage = std::move(value);
                    } else if (name == ":scheme") {
                        req.scheme_storage = std::move(value);
                    } else if (name == ":authority") {
                        req.authority_storage = std::move(value);
                    } else {
                        req.headers_storage.emplace_back(std::move(name), std::move(value));
                    }
                }

                req.target = req.target_storage;
                req.scheme = req.scheme_storage.empty()
                                 ? std::string_view("https")
                                 : std::string_view(req.scheme_storage);
                req.authority = req.authority_storage;

                req.headers.reserve(req.headers_storage.size());
                for (const auto &[n, v]: req.headers_storage) {
                    req.headers.emplace_back(n, v);
                }

                req.body_storage = std::move(body_accumulator);
                req.body = req.body_storage;

                bytes_consumed = cursor;
                return result::success;
            }

            /**
             * @brief Parse an incoming HTTP/2 server response from a network buffer.
             */
            [[nodiscard]]
            static result parse_response(
                const std::string_view buffer,
                response &res,
                std::size_t &bytes_consumed) {
                bytes_consumed = 0;
                std::size_t cursor = 0;

                hpack::dynamic_table dt;
                hpack::decoder dec(dt);

                std::vector<std::pair<std::string, std::string> > decoded_headers;
                bool headers_received = false;
                std::string body_accumulator;

                while (cursor < buffer.size()) {
                    const std::string_view remaining = buffer.substr(cursor);
                    frame_header hdr;
                    std::string_view payload;
                    std::size_t frame_bytes = 0;

                    const auto r = parse_frame(remaining, hdr, payload, frame_bytes);
                    if (r != result::success) {
                        return headers_received ? result::incomplete : r;
                    }

                    cursor += frame_bytes;

                    if (hdr.type == frame_type::SETTINGS) {
                        continue;
                    }

                    if (hdr.type == frame_type::HEADERS) {
                        res.stream_id = hdr.stream_id;
                        std::size_t pad_len = 0;
                        std::size_t header_cursor = 0;

                        if (hdr.has_flag(flags::PADDED)) {
                            if (payload.empty()) return result::error;
                            pad_len = static_cast<uint8_t>(payload[0]);
                            header_cursor += 1;
                        }

                        if (hdr.has_flag(flags::PRIORITY)) {
                            if (payload.size() < header_cursor + 5) return result::error;
                            header_cursor += 5;
                        }

                        if (payload.size() < header_cursor + pad_len) return result::error;
                        const std::string_view header_block = payload.substr(
                            header_cursor, payload.size() - header_cursor - pad_len);

                        if (!dec.decode_header_block(header_block, decoded_headers)) {
                            return result::error;
                        }

                        headers_received = true;
                        if (hdr.has_flag(flags::END_STREAM)) break;
                    } else if (hdr.type == frame_type::DATA) {
                        if (hdr.stream_id == res.stream_id) {
                            std::size_t pad_len = 0;
                            std::size_t data_offset = 0;
                            if (hdr.has_flag(flags::PADDED)) {
                                if (payload.empty()) return result::error;
                                pad_len = static_cast<uint8_t>(payload[0]);
                                data_offset += 1;
                            }
                            if (payload.size() < data_offset + pad_len) return result::error;
                            body_accumulator.append(
                                payload.substr(data_offset, payload.size() - data_offset - pad_len));

                            if (hdr.has_flag(flags::END_STREAM)) break;
                        }
                    }
                }

                if (!headers_received) return result::incomplete;

                res.headers.clear();
                res.headers_storage.clear();

                for (auto &[name, value]: decoded_headers) {
                    if (name == ":status") {
                        std::size_t parsed_code = 200;
                        std::from_chars(value.data(), value.data() + value.size(), parsed_code);
                        res.status_code = static_cast<unsigned int>(parsed_code);
                        res.status_text = status_text_for(res.status_code);
                    } else {
                        res.headers_storage.emplace_back(std::move(name), std::move(value));
                    }
                }

                res.headers.reserve(res.headers_storage.size());
                for (const auto &[n, v]: res.headers_storage) {
                    res.headers.emplace_back(n, v);
                }

                res.body_storage = std::move(body_accumulator);
                res.body = res.body_storage;

                bytes_consumed = cursor;
                return result::success;
            }
        };

        // ─── HTTP/2 Encoder ─────────────────────────────────────────────────────────

        /**
         * @brief HTTP/2 Binary Message Serializer.
         */
        class encoder {
        public:
            /**
             * @brief Serialize an HTTP/2 response into wire-format frames (HEADERS [+ DATA]).
             */
            static std::string serialize(const response &res) {
                std::string wire;

                // 1. HPACK encode headers
                const std::string header_block = hpack::encoder::encode_response_headers(
                    res.status_code, res.headers);

                // 2. Build HEADERS frame
                frame_header h_hdr;
                h_hdr.length = static_cast<uint32_t>(header_block.size());
                h_hdr.type = frame_type::HEADERS;
                h_hdr.flags = flags::END_HEADERS;
                if (res.body.empty()) {
                    h_hdr.flags |= flags::END_STREAM;
                }
                h_hdr.stream_id = res.stream_id;

                std::array<uint8_t, frame_header::HEADER_SIZE> h_bytes{};
                pack_frame_header(h_hdr, h_bytes);

                wire.append(reinterpret_cast<const char *>(h_bytes.data()), h_bytes.size());
                wire.append(header_block);

                // 3. Build DATA frame(s) if body present
                if (!res.body.empty()) {
                    std::size_t offset = 0;
                    while (offset < res.body.size()) {
                        constexpr uint32_t MAX_FRAME_SIZE = 16384;
                        const auto chunk_len = static_cast<uint32_t>(
                            std::min<std::size_t>(res.body.size() - offset, MAX_FRAME_SIZE));
                        const bool is_last = (offset + chunk_len == res.body.size());

                        frame_header d_hdr;
                        d_hdr.length = chunk_len;
                        d_hdr.type = frame_type::DATA;
                        d_hdr.flags = is_last ? flags::END_STREAM : flags::NONE;
                        d_hdr.stream_id = res.stream_id;

                        std::array<uint8_t, frame_header::HEADER_SIZE> d_bytes{};
                        pack_frame_header(d_hdr, d_bytes);

                        wire.append(reinterpret_cast<const char *>(d_bytes.data()), d_bytes.size());
                        wire.append(res.body.substr(offset, chunk_len));

                        offset += chunk_len;
                    }
                }

                return wire;
            }

            /**
             * @brief Serialize an HTTP/2 request into wire-format frames (HEADERS [+ DATA]).
             */
            static std::string serialize_request(const request &req) {
                std::string wire;

                // 1. HPACK encode request headers
                std::string header_block = hpack::encoder::encode_request_headers(
                    req.method_type, req.target, req.scheme, req.authority, req.headers);

                // 2. Build HEADERS frame
                frame_header h_hdr;
                h_hdr.length = static_cast<uint32_t>(header_block.size());
                h_hdr.type = frame_type::HEADERS;
                h_hdr.flags = flags::END_HEADERS;
                if (req.body.empty()) {
                    h_hdr.flags |= flags::END_STREAM;
                }
                h_hdr.stream_id = req.stream_id;

                std::array<uint8_t, frame_header::HEADER_SIZE> h_bytes{};
                pack_frame_header(h_hdr, h_bytes);

                wire.append(reinterpret_cast<const char *>(h_bytes.data()), h_bytes.size());
                wire.append(header_block);

                // 3. Build DATA frame(s) if body present
                if (!req.body.empty()) {
                    std::size_t offset = 0;
                    while (offset < req.body.size()) {
                        constexpr uint32_t MAX_FRAME_SIZE = 16384;
                        const auto chunk_len = static_cast<uint32_t>(
                            std::min<std::size_t>(req.body.size() - offset, MAX_FRAME_SIZE));
                        const bool is_last = (offset + chunk_len == req.body.size());

                        frame_header d_hdr;
                        d_hdr.length = chunk_len;
                        d_hdr.type = frame_type::DATA;
                        d_hdr.flags = is_last ? flags::END_STREAM : flags::NONE;
                        d_hdr.stream_id = req.stream_id;

                        std::array<uint8_t, frame_header::HEADER_SIZE> d_bytes{};
                        pack_frame_header(d_hdr, d_bytes);

                        wire.append(reinterpret_cast<const char *>(d_bytes.data()), d_bytes.size());
                        wire.append(req.body.substr(offset, chunk_len));

                        offset += chunk_len;
                    }
                }

                return wire;
            }

            // ─── Control Frame Serialization Helpers ──────────────────────────────

            /**
             * @brief Serialize a SETTINGS frame (RFC 7540 §6.5).
             */
            static std::string serialize_settings(
                const std::vector<std::pair<settings_parameter, uint32_t> > &settings) {
                frame_header hdr;
                hdr.length = static_cast<uint32_t>(settings.size() * 6);
                hdr.type = frame_type::SETTINGS;
                hdr.flags = flags::NONE;
                hdr.stream_id = 0; // Connection-level stream

                std::array<uint8_t, frame_header::HEADER_SIZE> hdr_bytes{};
                pack_frame_header(hdr, hdr_bytes);

                std::string wire(reinterpret_cast<const char *>(hdr_bytes.data()), hdr_bytes.size());
                for (const auto &[param, val]: settings) {
                    const auto p_val = static_cast<uint16_t>(param);
                    wire.push_back(static_cast<char>((p_val >> 8) & 0xFF));
                    wire.push_back(static_cast<char>(p_val & 0xFF));
                    wire.push_back(static_cast<char>((val >> 24) & 0xFF));
                    wire.push_back(static_cast<char>((val >> 16) & 0xFF));
                    wire.push_back(static_cast<char>((val >> 8) & 0xFF));
                    wire.push_back(static_cast<char>(val & 0xFF));
                }
                return wire;
            }

            /**
             * @brief Serialize a SETTINGS ACK frame (RFC 7540 §6.5.3).
             */
            static std::string serialize_settings_ack() {
                frame_header hdr;
                hdr.length = 0;
                hdr.type = frame_type::SETTINGS;
                hdr.flags = flags::ACK;
                hdr.stream_id = 0;

                std::array<uint8_t, frame_header::HEADER_SIZE> bytes{};
                pack_frame_header(hdr, bytes);
                return {reinterpret_cast<const char *>(bytes.data()), bytes.size()};
            }

            /**
             * @brief Serialize a PING frame (RFC 7540 §6.7).
             */
            static std::string serialize_ping(const uint64_t opaque_data, const bool ack = false) {
                frame_header hdr;
                hdr.length = 8;
                hdr.type = frame_type::PING;
                hdr.flags = ack ? flags::ACK : flags::NONE;
                hdr.stream_id = 0;

                std::array<uint8_t, frame_header::HEADER_SIZE> bytes{};
                pack_frame_header(hdr, bytes);

                std::string wire(reinterpret_cast<const char *>(bytes.data()), bytes.size());
                for (int i = 7; i >= 0; --i) {
                    wire.push_back(static_cast<char>((opaque_data >> (i * 8)) & 0xFF));
                }
                return wire;
            }

            /**
             * @brief Serialize a WINDOW_UPDATE frame (RFC 7540 §6.9).
             */
            static std::string serialize_window_update(
                const uint32_t stream_id,
                const uint32_t window_size_increment) {
                frame_header hdr;
                hdr.length = 4;
                hdr.type = frame_type::WINDOW_UPDATE;
                hdr.flags = flags::NONE;
                hdr.stream_id = stream_id;

                std::array<uint8_t, frame_header::HEADER_SIZE> bytes{};
                pack_frame_header(hdr, bytes);

                std::string wire(reinterpret_cast<const char *>(bytes.data()), bytes.size());
                const uint32_t win = window_size_increment & 0x7FFFFFFF;
                wire.push_back(static_cast<char>((win >> 24) & 0xFF));
                wire.push_back(static_cast<char>((win >> 16) & 0xFF));
                wire.push_back(static_cast<char>((win >> 8) & 0xFF));
                wire.push_back(static_cast<char>(win & 0xFF));
                return wire;
            }

            /**
             * @brief Serialize a GOAWAY frame (RFC 7540 §6.8).
             */
            static std::string serialize_goaway(
                const uint32_t last_stream_id,
                const error_code err,
                const std::string_view debug_data = "") {
                frame_header hdr;
                hdr.length = static_cast<uint32_t>(8 + debug_data.size());
                hdr.type = frame_type::GOAWAY;
                hdr.flags = flags::NONE;
                hdr.stream_id = 0;

                std::array<uint8_t, frame_header::HEADER_SIZE> bytes{};
                pack_frame_header(hdr, bytes);

                std::string wire(reinterpret_cast<const char *>(bytes.data()), bytes.size());
                const uint32_t lsid = last_stream_id & 0x7FFFFFFF;
                wire.push_back(static_cast<char>((lsid >> 24) & 0xFF));
                wire.push_back(static_cast<char>((lsid >> 16) & 0xFF));
                wire.push_back(static_cast<char>((lsid >> 8) & 0xFF));
                wire.push_back(static_cast<char>(lsid & 0xFF));

                const auto err_val = static_cast<uint32_t>(err);
                wire.push_back(static_cast<char>((err_val >> 24) & 0xFF));
                wire.push_back(static_cast<char>((err_val >> 16) & 0xFF));
                wire.push_back(static_cast<char>((err_val >> 8) & 0xFF));
                wire.push_back(static_cast<char>(err_val & 0xFF));

                wire.append(debug_data);
                return wire;
            }

            /**
             * @brief Serialize an RST_STREAM frame (RFC 7540 §6.4).
             */
            static std::string serialize_rst_stream(const uint32_t stream_id, const error_code err) {
                frame_header hdr;
                hdr.length = 4;
                hdr.type = frame_type::RST_STREAM;
                hdr.flags = flags::NONE;
                hdr.stream_id = stream_id;

                std::array<uint8_t, frame_header::HEADER_SIZE> bytes{};
                pack_frame_header(hdr, bytes);

                std::string wire(reinterpret_cast<const char *>(bytes.data()), bytes.size());
                const auto err_val = static_cast<uint32_t>(err);
                wire.push_back(static_cast<char>((err_val >> 24) & 0xFF));
                wire.push_back(static_cast<char>((err_val >> 16) & 0xFF));
                wire.push_back(static_cast<char>((err_val >> 8) & 0xFF));
                wire.push_back(static_cast<char>(err_val & 0xFF));
                return wire;
            }

            /**
             * @brief Serialize a DATA frame (RFC 7540 §6.1).
             * @param stream_id Stream identifier.
             * @param data Payload view.
             * @param end_stream True if this is the terminal frame of the stream.
             */
            static std::string serialize_data_frame(
                const uint32_t stream_id,
                const std::string_view data,
                const bool end_stream = false) {
                frame_header d_hdr;
                d_hdr.length = static_cast<uint32_t>(data.size());
                d_hdr.type = frame_type::DATA;
                d_hdr.flags = end_stream ? flags::END_STREAM : flags::NONE;
                d_hdr.stream_id = stream_id;

                std::array<uint8_t, frame_header::HEADER_SIZE> d_bytes{};
                pack_frame_header(d_hdr, d_bytes);

                std::string wire;
                wire.reserve(frame_header::HEADER_SIZE + data.size());
                wire.append(reinterpret_cast<const char *>(d_bytes.data()), d_bytes.size());
                wire.append(data);
                return wire;
            }

            /**
             * @brief Format a single stream chunk into an existing buffer without redundant reallocations.
             */
            static void format_chunk_to(std::string &out, const std::string_view data) {
                if (data.empty()) {
                    out.append(format_terminal_chunk());
                    return;
                }
                frame_header d_hdr;
                d_hdr.length = static_cast<uint32_t>(data.size());
                d_hdr.type = frame_type::DATA;
                d_hdr.flags = flags::NONE;
                d_hdr.stream_id = 1;

                std::array<uint8_t, frame_header::HEADER_SIZE> d_bytes{};
                pack_frame_header(d_hdr, d_bytes);

                out.reserve(out.size() + frame_header::HEADER_SIZE + data.size());
                out.append(reinterpret_cast<const char *>(d_bytes.data()), d_bytes.size());
                out.append(data);
            }

            /**
             * @brief Format a single stream chunk using an HTTP/2 DATA frame on stream 1.
             */
            static std::string format_chunk(const std::string_view data) {
                if (data.empty()) return std::string(format_terminal_chunk());
                return serialize_data_frame(1, data, false);
            }

            /**
             * @brief Format the terminal stream chunk: 9-octet empty DATA frame with END_STREAM on stream 1.
             */
            [[nodiscard]] static constexpr std::string_view format_terminal_chunk() noexcept {
                return {"\x00\x00\x00\x00\x01\x00\x00\x00\x01", 9};
            }
        };

        // ─── HTTP/2 Decoder ─────────────────────────────────────────────────────────

        /**
         * @brief HTTP/2 Response Decoder.
         */
        class decoder {
        public:
            [[nodiscard]]
            static parser::result decode_response(
                const std::string_view buffer,
                response &res,
                std::size_t &bytes_consumed) {
                return parser::parse_response(buffer, res, bytes_consumed);
            }

            /**
             * @brief For HTTP/2, chunks are carried in DATA frames, so dechunking returns raw payload.
             */
            static std::string dechunk(const std::string_view chunked_raw) {
                return std::string(chunked_raw);
            }
        };
    } // namespace http2

    // ─── Unified http2codec Concept ───────────────────────────────────────────────

    /**
     * @struct http2codec
     * @brief HTTP/2 Protocol Codec combining binary frame parser, encoder, decoder, and developer-friendly facade.
     */
    struct http2codec {
        using parser = wavex::protos::http::http2::parser;
        using encoder = wavex::protos::http::http2::encoder;
        using decoder = wavex::protos::http::http2::decoder;
        using request = wavex::protos::http::http2::request;
        using response = wavex::protos::http::http2::response;
        using result = parser::result;

        static std::string_view status_text_for(const unsigned int code) noexcept {
            return wavex::protos::http::status_text_for(code);
        }

        // ─── Developer-Friendly Codec Facade (Symmetrical with http1codec) ───

        /** @brief Serialize an HTTP/2 response into wire-format binary frames. */
        static std::string serialize(const response &res) {
            return encoder::serialize(res);
        }

        /** @brief Serialize an HTTP/2 request into wire-format binary frames. */
        static std::string serialize_request(const request &req) {
            return encoder::serialize_request(req);
        }

        /** @brief Parse raw buffer into an HTTP/2 request. */
        static result parse_request(const std::string_view buffer, request &req, std::size_t &bytes_consumed) {
            return parser::parse_request(buffer, req, bytes_consumed);
        }

        /** @brief Parse raw buffer into an HTTP/2 response. */
        static result parse_response(const std::string_view buffer, response &res, std::size_t &bytes_consumed) {
            return parser::parse_response(buffer, res, bytes_consumed);
        }

        /** @brief Decode a raw HTTP/2 response buffer. */
        static result decode_response(const std::string_view buffer, response &res, std::size_t &bytes_consumed) {
            return decoder::decode_response(buffer, res, bytes_consumed);
        }

        /** @brief Serialize a single HTTP/2 DATA frame for streaming. */
        static std::string serialize_data_frame(const uint32_t stream_id, const std::string_view data,
                                                const bool end_stream = false) {
            return encoder::serialize_data_frame(stream_id, data, end_stream);
        }

        /** @brief Format a single stream chunk (DATA frame on stream 1). */
        static std::string format_chunk(const std::string_view data) {
            return encoder::format_chunk(data);
        }

        /** @brief Format a single stream chunk directly into a provided buffer. */
        static void format_chunk_to(std::string &out, const std::string_view data) {
            encoder::format_chunk_to(out, data);
        }

        /** @brief Terminal stream chunk signaling end of stream. */
        [[nodiscard]] static constexpr std::string_view format_terminal_chunk() noexcept {
            return encoder::format_terminal_chunk();
        }

        /** @brief De-chunk payload (for HTTP/2, returns the payload). */
        static std::string dechunk(const std::string_view chunked_raw) {
            return decoder::dechunk(chunked_raw);
        }
    };
} // namespace wavex::protos::http
