// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file http3codec.hpp
 * @brief HTTP/3 Protocol Codec — Binary Framing (RFC 9114) and QPACK Header Compression (RFC 9204).
 *
 * Implements:
 *  - RFC 9114: HTTP/3 Binary Framing Layer (DATA, HEADERS, SETTINGS, CANCEL_PUSH, GOAWAY)
 *  - RFC 9204: QPACK Header Compression Engine (99-entry Static Table, Dynamic Table, Literal & Indexed Field lines)
 *  - WaveX Codec Concept integration: seamless compatibility with HttpRequest, HttpResponse, and Server.
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
#include <algorithm>
#include <wavex/protos/http/Methods.hpp>
#include <wavex/protos/http/http1codec.hpp>
#include <wavex/protos/http/http2codec.hpp>
#include <wavex/Network/QUIC.hpp>

namespace wavex::protos::http {
    namespace http3 {
        using network::quic::VarInt;

        // ─── Frame Types (RFC 9114 §7.2) ──────────────────────────────────────────
        enum class frame_type : uint64_t {
            DATA = 0x00,
            HEADERS = 0x01,
            CANCEL_PUSH = 0x03,
            SETTINGS = 0x04,
            PUSH_PROMISE = 0x05,
            GOAWAY = 0x07,
            MAX_PUSH_ID = 0x0d
        };

        // ─── Stream Types (RFC 9114 §6.2) ─────────────────────────────────────────
        enum class stream_type : uint64_t {
            CONTROL = 0x00,
            PUSH = 0x01,
            QPACK_ENCODER = 0x02,
            QPACK_DECODER = 0x03
        };

        // ─── Settings Parameters (RFC 9114 §7.2.4.1) ──────────────────────────────
        enum class settings_parameter : uint64_t {
            QPACK_MAX_TABLE_CAPACITY = 0x01,
            MAX_FIELD_SECTION_SIZE = 0x06,
            QPACK_BLOCKED_STREAMS = 0x07
        };

        // ─── HTTP/3 Error Codes (RFC 9114 §8.1) ───────────────────────────────────
        enum class error_code : uint64_t {
            H3_NO_ERROR = 0x0100,
            H3_GENERAL_PROTOCOL_ERROR = 0x0101,
            H3_INTERNAL_ERROR = 0x0102,
            H3_STREAM_CREATION_ERROR = 0x0103,
            H3_CLOSED_CRITICAL_STREAM = 0x0104,
            H3_FRAME_UNEXPECTED = 0x0105,
            H3_FRAME_ERROR = 0x0106,
            H3_EXCESSIVE_LOAD = 0x0107,
            H3_ID_ERROR = 0x0108,
            H3_SETTINGS_ERROR = 0x0109,
            H3_MISSING_SETTINGS = 0x010a,
            H3_REQUEST_REJECTED = 0x010b,
            H3_REQUEST_CANCELLED = 0x010c,
            H3_REQUEST_INCOMPLETE = 0x010d,
            H3_MESSAGE_ERROR = 0x010e,
            H3_CONNECT_ERROR = 0x010f,
            H3_VERSION_FALLBACK = 0x0110
        };

        // ─── Frame Header (RFC 9114 §7.1) ─────────────────────────────────────────
        struct frame_header {
            // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
            uint64_t type{0};
            uint64_t length{0};

            // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
            frame_header() = default;
            constexpr frame_header(const uint64_t t, const uint64_t l) noexcept : type(t), length(l) {}
            ~frame_header() = default;
        };

        // ─── QPACK (RFC 9204) Header Compression Engine ───────────────────────────
        namespace qpack {
            struct static_entry {
                std::string_view name;
                std::string_view value;
            };

            // RFC 9204 Appendix A — QPACK Static Table (0-indexed, entries 0..98)
            inline constexpr std::array<static_entry, 99> STATIC_TABLE = {{
                {":authority", ""},                                             // 0
                {":path", "/"},                                                 // 1
                {"age", "0"},                                                   // 2
                {"content-disposition", ""},                                    // 3
                {"content-length", "0"},                                        // 4
                {"cookie", ""},                                                 // 5
                {"date", ""},                                                   // 6
                {"etag", ""},                                                   // 7
                {"if-modified-since", ""},                                      // 8
                {"if-none-match", ""},                                          // 9
                {"last-modified", ""},                                          // 10
                {"link", ""},                                                   // 11
                {"location", ""},                                               // 12
                {"referer", ""},                                                // 13
                {"set-cookie", ""},                                             // 14
                {":method", "CONNECT"},                                         // 15
                {":method", "DELETE"},                                          // 16
                {":method", "GET"},                                             // 17
                {":method", "HEAD"},                                            // 18
                {":method", "OPTIONS"},                                         // 19
                {":method", "POST"},                                            // 20
                {":method", "PUT"},                                             // 21
                {":scheme", "http"},                                            // 22
                {":scheme", "https"},                                           // 23
                {":status", "103"},                                             // 24
                {":status", "200"},                                             // 25
                {":status", "304"},                                             // 26
                {":status", "404"},                                             // 27
                {":status", "503"},                                             // 28
                {"accept", "*/*"},                                              // 29
                {"accept", "application/dns-message"},                          // 30
                {"accept-encoding", "gzip, deflate, br"},                       // 31
                {"accept-ranges", "bytes"},                                     // 32
                {"access-control-allow-headers", "cache-control"},               // 33
                {"access-control-allow-headers", "content-type"},                // 34
                {"access-control-allow-origin", "*"},                           // 35
                {"cache-control", "max-age=0"},                                 // 36
                {"cache-control", "max-age=2592000"},                           // 37
                {"cache-control", "max-age=604800"},                            // 38
                {"cache-control", "no-cache"},                                  // 39
                {"cache-control", "no-store"},                                  // 40
                {"cache-control", "public, max-age=31536000"},                  // 41
                {"content-encoding", "br"},                                     // 42
                {"content-encoding", "gzip"},                                   // 43
                {"content-type", "application/dns-message"},                    // 44
                {"content-type", "application/javascript"},                     // 45
                {"content-type", "application/json"},                           // 46
                {"content-type", "application/x-www-form-urlencoded"},          // 47
                {"content-type", "image/gif"},                                  // 48
                {"content-type", "image/jpeg"},                                 // 49
                {"content-type", "image/png"},                                  // 50
                {"content-type", "text/css"},                                   // 51
                {"content-type", "text/html; charset=utf-8"},                   // 52
                {"content-type", "text/plain"},                                 // 53
                {"content-type", "text/plain;charset=utf-8"},                   // 54
                {"range", "bytes=0-"},                                          // 55
                {"strict-transport-security", "max-age=31536000"},              // 56
                {"strict-transport-security", "max-age=31536000; includesubdomains"}, // 57
                {"strict-transport-security", "max-age=31536000; includesubdomains; preload"}, // 58
                {"vary", "accept-encoding"},                                    // 59
                {"vary", "origin"},                                             // 60
                {"x-content-type-options", "nosniff"},                          // 61
                {"x-xss-protection", "1; mode=block"},                          // 62
                {":status", "100"},                                             // 63
                {":status", "204"},                                             // 64
                {":status", "206"},                                             // 65
                {":status", "302"},                                             // 66
                {":status", "400"},                                             // 67
                {":status", "403"},                                             // 68
                {":status", "421"},                                             // 69
                {":status", "425"},                                             // 70
                {":status", "500"},                                             // 71
                {"accept-language", ""},                                        // 72
                {"access-control-allow-credentials", "FALSE"},                  // 73
                {"access-control-allow-credentials", "TRUE"},                   // 74
                {"access-control-allow-headers", "*"},                          // 75
                {"access-control-allow-methods", "get"},                        // 76
                {"access-control-allow-methods", "get, post, options"},         // 77
                {"access-control-allow-methods", "options"},                    // 78
                {"access-control-expose-headers", "content-length"},            // 79
                {"access-control-request-headers", "content-type"},             // 80
                {"access-control-request-method", "get"},                       // 81
                {"access-control-request-method", "post"},                      // 82
                {"alt-svc", "clear"},                                           // 83
                {"authorization", ""},                                          // 84
                {"content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none';"}, // 85
                {"early-data", "1"},                                            // 86
                {"expect-ct", ""},                                              // 87
                {"forwarded", ""},                                              // 88
                {"if-range", ""},                                               // 89
                {"origin", ""},                                                 // 90
                {"purpose", "prefetch"},                                        // 91
                {"server", ""},                                                 // 92
                {"timing-allow-origin", "*"},                                   // 93
                {"upgrade-insecure-requests", "1"},                             // 94
                {"user-agent", ""},                                             // 95
                {"x-forwarded-for", ""},                                        // 96
                {"x-frame-options", "deny"},                                    // 97
                {"x-frame-options", "sameorigin"}                               // 98
            }};

            /**
             * @brief Locate static table entry matching a header name and optional value.
             */
            inline std::pair<std::size_t, bool> find_static(
                const std::string_view name,
                const std::string_view value = "") noexcept {
                std::size_t name_match = STATIC_TABLE.size();
                for (std::size_t i = 0; i < STATIC_TABLE.size(); ++i) {
                    if (detail::is_equal(STATIC_TABLE[i].name, name)) {
                        if (STATIC_TABLE[i].value == value) {
                            return {i, true}; // Exact match
                        }
                        if (name_match == STATIC_TABLE.size()) {
                            name_match = i;
                        }
                    }
                }
                return {name_match, false};
            }

            /**
             * @brief QPACK Dynamic Table.
             */
            class dynamic_table {
            public:
                struct entry {
                    std::string name{};
                    std::string value{};
                    [[nodiscard]] std::size_t size() const noexcept {
                        return name.size() + value.size() + 32;
                    }
                };

            private:
                std::vector<entry> entries_{};
                std::size_t current_size_{0};
                std::size_t max_capacity_{4096};

            public:
                explicit dynamic_table(const std::size_t max_cap = 4096) noexcept
                    : max_capacity_(max_cap) {}

                void set_max_capacity(const std::size_t cap) noexcept {
                    max_capacity_ = cap;
                    evict();
                }

                void insert(std::string name, std::string value) {
                    const entry e{std::move(name), std::move(value)};
                    const std::size_t esz = e.size();
                    if (esz > max_capacity_) {
                        entries_.clear();
                        current_size_ = 0;
                        return;
                    }
                    entries_.insert(entries_.begin(), e);
                    current_size_ += esz;
                    evict();
                }

                [[nodiscard]] std::size_t size() const noexcept { return entries_.size(); }
                [[nodiscard]] const entry *get(const std::size_t idx) const noexcept {
                    if (idx < entries_.size()) return &entries_[idx];
                    return nullptr;
                }

            private:
                void evict() noexcept {
                    while (current_size_ > max_capacity_ && !entries_.empty()) {
                        current_size_ -= entries_.back().size();
                        entries_.pop_back();
                    }
                }
            };

            /**
             * @brief QPACK Encoder: Serializes headers into QPACK wire blocks.
             */
            class encoder {
            public:
                static std::string encode_request_headers(
                    const http::method m,
                    const std::string_view target,
                    const std::string_view scheme,
                    const std::string_view authority,
                    const std::vector<header> &headers) {
                    std::string out;
                    out.reserve(256);

                    // 1. QPACK Prefix (RFC 9204 §4.5.1):
                    // Required Insert Count = 0 (1 byte 0x00), Delta Base = 0 (1 byte 0x00)
                    out.push_back('\0');
                    out.push_back('\0');

                    // 2. :method
                    const std::string_view method_str = to_string(m);
                    const auto [m_idx, m_exact] = find_static(":method", method_str);
                    if (m_exact) {
                        encode_indexed_static(out, m_idx);
                    } else if (m_idx < STATIC_TABLE.size()) {
                        encode_literal_with_name_ref(out, m_idx, method_str);
                    } else {
                        encode_literal_new_name(out, ":method", method_str);
                    }

                    // 3. :scheme
                    const std::string_view sc = scheme.empty() ? "https" : scheme;
                    const auto [s_idx, s_exact] = find_static(":scheme", sc);
                    if (s_exact) {
                        encode_indexed_static(out, s_idx);
                    } else {
                        encode_literal_with_name_ref(out, 23, sc); // 23 = :scheme https
                    }

                    // 4. :path
                    const std::string_view p = target.empty() ? "/" : target;
                    if (p == "/") {
                        encode_indexed_static(out, 1); // 1 = :path: /
                    } else {
                        encode_literal_with_name_ref(out, 1, p);
                    }

                    // 5. :authority
                    if (!authority.empty()) {
                        encode_literal_with_name_ref(out, 0, authority); // 0 = :authority
                    }

                    // 6. General Headers
                    for (const auto &[name, value] : headers) {
                        if (name.starts_with(':')) continue;
                        const auto [idx, exact] = find_static(name, value);
                        if (exact) {
                            encode_indexed_static(out, idx);
                        } else if (idx < STATIC_TABLE.size()) {
                            encode_literal_with_name_ref(out, idx, value);
                        } else {
                            encode_literal_new_name(out, name, value);
                        }
                    }

                    return out;
                }

                static std::string encode_response_headers(
                    const unsigned int status_code,
                    const std::vector<header> &headers) {
                    std::string out;
                    out.reserve(256);

                    // QPACK Prefix: Required Insert Count = 0, Delta Base = 0
                    out.push_back('\0');
                    out.push_back('\0');

                    // :status
                    char sbuf[16];
                    const auto [ptr, ec] = std::to_chars(sbuf, sbuf + sizeof(sbuf), status_code);
                    const std::string_view status_str(sbuf, ptr);

                    const auto [idx, exact] = find_static(":status", status_str);
                    if (exact) {
                        encode_indexed_static(out, idx);
                    } else {
                        encode_literal_with_name_ref(out, 25, status_str); // 25 = :status: 200
                    }

                    // General Headers
                    for (const auto &[name, value] : headers) {
                        if (name.starts_with(':')) continue;
                        const auto [h_idx, h_exact] = find_static(name, value);
                        if (h_exact) {
                            encode_indexed_static(out, h_idx);
                        } else if (h_idx < STATIC_TABLE.size()) {
                            encode_literal_with_name_ref(out, h_idx, value);
                        } else {
                            encode_literal_new_name(out, name, value);
                        }
                    }

                    return out;
                }

            private:
                // Indexed Header Field Line (RFC 9204 §4.5.2): 1 T=1 Index (6-bit prefix)
                static void encode_indexed_static(std::string &out, const std::size_t idx) {
                    http2::hpack::encode_integer(out, idx, 6, 0xc0);
                }

                // Literal Header Field With Name Reference (RFC 9204 §4.5.4): 0 1 N=0 T=1 Index (4-bit prefix) + Value
                static void encode_literal_with_name_ref(std::string &out, const std::size_t idx, const std::string_view val) {
                    http2::hpack::encode_integer(out, idx, 4, 0x50);
                    http2::hpack::encode_string(out, val);
                }

                // Literal Header Field With Literal Name (RFC 9204 §4.5.6): 0 0 1 N=0 H=0 (3-bit prefix 0x20)
                static void encode_literal_new_name(std::string &out, const std::string_view name, const std::string_view val) {
                    http2::hpack::encode_integer(out, name.size(), 3, 0x20);
                    out.append(name);
                    http2::hpack::encode_string(out, val);
                }
            };

            /**
             * @brief QPACK Decoder: Parses QPACK binary header blocks into header pairs.
             */
            class decoder {
            public:
                explicit decoder(dynamic_table &dt) noexcept : dt_(dt) {}

                bool decode_header_block(
                    const std::string_view block,
                    std::vector<std::pair<std::string, std::string>> &out_headers) const {
                    if (block.empty()) return false;
                    std::size_t cursor = 0;

                    // RFC 9204 §4.5.1: Encoded Field Section Prefix
                    // 1. Required Insert Count (8-bit prefix integer)
                    uint64_t req_insert_count = 0;
                    if (!http2::hpack::decode_integer(block, cursor, 8, req_insert_count)) return false;

                    // 2. Sign bit + Delta Base (7-bit prefix integer)
                    if (cursor >= block.size()) return false;
                    uint64_t delta_base = 0;
                    if (!http2::hpack::decode_integer(block, cursor, 7, delta_base)) return false;

                    while (cursor < block.size()) {
                        const auto b = static_cast<uint8_t>(block[cursor]);

                        // Case 1: Indexed Header Field (starts with 1Txxxxxx)
                        if ((b & 0x80) != 0) {
                            const bool is_static = (b & 0x40) != 0;
                            uint64_t index = 0;
                            if (!http2::hpack::decode_integer(block, cursor, 6, index)) return false;

                            if (is_static) {
                                if (index >= STATIC_TABLE.size()) return false;
                                out_headers.emplace_back(
                                    std::string(STATIC_TABLE[index].name),
                                    std::string(STATIC_TABLE[index].value)
                                );
                            } else {
                                const auto *e = dt_.get(index);
                                if (!e) return false;
                                out_headers.emplace_back(e->name, e->value);
                            }
                        }
                        // Case 2: Literal Header with Name Reference (starts with 01NTxxxx)
                        else if ((b & 0x40) != 0) {
                            const bool is_static = (b & 0x10) != 0;
                            uint64_t name_idx = 0;
                            if (!http2::hpack::decode_integer(block, cursor, 4, name_idx)) return false;

                            std::string name;
                            if (is_static) {
                                if (name_idx >= STATIC_TABLE.size()) return false;
                                name = std::string(STATIC_TABLE[name_idx].name);
                            } else {
                                const auto *e = dt_.get(name_idx);
                                if (!e) return false;
                                name = e->name;
                            }

                            std::string value;
                            if (!http2::hpack::decode_string(block, cursor, value)) return false;
                            out_headers.emplace_back(std::move(name), std::move(value));
                        }
                        // Case 3: Literal Header with Literal Name (starts with 001xxxxx)
                        else if ((b & 0x20) != 0) {
                            uint64_t name_len = 0;
                            if (!http2::hpack::decode_integer(block, cursor, 3, name_len)) return false;
                            if (cursor + name_len > block.size()) return false;
                            std::string name(block.substr(cursor, name_len));
                            cursor += name_len;

                            std::string value;
                            if (!http2::hpack::decode_string(block, cursor, value)) return false;
                            out_headers.emplace_back(std::move(name), std::move(value));
                        } else {
                            // Skip unrecognized or dynamic post-base prefix
                            ++cursor;
                        }
                    }
                    return true;
                }

            private:
                dynamic_table &dt_;
            };
        } // namespace qpack

        /**
         * @brief Connection context for HTTP/3 sessions (scoped to QUIC connection lifetime).
         */
        struct connection_context {
            // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
            qpack::dynamic_table decode_table{};
            uint64_t max_field_section_size{65536};
            bool settings_sent{false};
            bool settings_received{false};
        };

        // ─── HTTP/3 Messages ───────────────────────────────────────────────────────

        /**
         * @brief HTTP/3 Request Message (inherits protocol-agnostic message_base).
         */
        struct request : public message_base {
            // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
            std::string_view target{};
            std::string_view scheme{"https"};
            std::string_view authority{};
            std::string target_storage{};
            std::string scheme_storage{};
            std::string authority_storage{};
            std::string body_storage{};
            std::vector<std::pair<std::string, std::string>> headers_storage{};
            uint64_t stream_id{0};
            http::method method_type{method::UNKNOWN};

            // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
            request() {
                version_major = 3;
                version_minor = 0;
            }

            ~request() = default;

            request(const request &other)
                : message_base(other),
                  target(other.target),
                  scheme(other.scheme),
                  authority(other.authority),
                  target_storage(other.target_storage),
                  scheme_storage(other.scheme_storage),
                  authority_storage(other.authority_storage),
                  body_storage(other.body_storage),
                  headers_storage(other.headers_storage),
                  stream_id(other.stream_id),
                  method_type(other.method_type) {
                rebase(other);
            }

            request(request &&other) noexcept
                : message_base(std::move(other)),
                  target(other.target),
                  scheme(other.scheme),
                  authority(other.authority),
                  target_storage(std::move(other.target_storage)),
                  scheme_storage(std::move(other.scheme_storage)),
                  authority_storage(std::move(other.authority_storage)),
                  body_storage(std::move(other.body_storage)),
                  headers_storage(std::move(other.headers_storage)),
                  stream_id(other.stream_id),
                  method_type(other.method_type) {
                rebase(other);
            }

            request &operator=(const request &other) {
                if (this != &other) {
                    message_base::operator=(other);
                    target = other.target;
                    scheme = other.scheme;
                    authority = other.authority;
                    target_storage = other.target_storage;
                    scheme_storage = other.scheme_storage;
                    authority_storage = other.authority_storage;
                    body_storage = other.body_storage;
                    headers_storage = other.headers_storage;
                    stream_id = other.stream_id;
                    method_type = other.method_type;
                    rebase(other);
                }
                return *this;
            }

            request &operator=(request &&other) noexcept {
                if (this != &other) {
                    message_base::operator=(std::move(other));
                    target = other.target;
                    scheme = other.scheme;
                    authority = other.authority;
                    target_storage = std::move(other.target_storage);
                    scheme_storage = std::move(other.scheme_storage);
                    authority_storage = std::move(other.authority_storage);
                    body_storage = std::move(other.body_storage);
                    headers_storage = std::move(other.headers_storage);
                    stream_id = other.stream_id;
                    method_type = other.method_type;
                    rebase(other);
                }
                return *this;
            }

            // ─── 4. Member Functions & Friend Declarations (LAST) ──────────────
            void rebase(const request &fallback) {
                target = !target_storage.empty() ? std::string_view(target_storage) : fallback.target;
                scheme = !scheme_storage.empty() ? std::string_view(scheme_storage) : fallback.scheme;
                authority = !authority_storage.empty() ? std::string_view(authority_storage) : fallback.authority;
                body = !body_storage.empty() ? std::string_view(body_storage) : fallback.body;

                if (!headers_storage.empty()) {
                    headers.clear();
                    headers.reserve(headers_storage.size());
                    for (const auto &[n, v] : headers_storage) {
                        headers.emplace_back(n, v);
                    }
                }
            }
        };

        /**
         * @brief HTTP/3 Response Message (inherits protocol-agnostic message_base).
         */
        struct response : public message_base {
            // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
            std::string_view status_text{"OK"};
            std::string body_storage{};
            std::vector<std::pair<std::string, std::string>> headers_storage{};
            uint64_t stream_id{0};
            unsigned int status_code{200};

            // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
            response() {
                version_major = 3;
                version_minor = 0;
            }

            ~response() = default;

            response(const response &other)
                : message_base(other),
                  status_text(other.status_text),
                  body_storage(other.body_storage),
                  headers_storage(other.headers_storage),
                  stream_id(other.stream_id),
                  status_code(other.status_code) {
                rebase(other);
            }

            response(response &&other) noexcept
                : message_base(std::move(other)),
                  status_text(other.status_text),
                  body_storage(std::move(other.body_storage)),
                  headers_storage(std::move(other.headers_storage)),
                  stream_id(other.stream_id),
                  status_code(other.status_code) {
                rebase(other);
            }

            response &operator=(const response &other) {
                if (this != &other) {
                    message_base::operator=(other);
                    status_text = other.status_text;
                    body_storage = other.body_storage;
                    headers_storage = other.headers_storage;
                    stream_id = other.stream_id;
                    status_code = other.status_code;
                    rebase(other);
                }
                return *this;
            }

            response &operator=(response &&other) noexcept {
                if (this != &other) {
                    message_base::operator=(std::move(other));
                    status_text = other.status_text;
                    body_storage = std::move(other.body_storage);
                    headers_storage = std::move(other.headers_storage);
                    stream_id = other.stream_id;
                    status_code = other.status_code;
                    rebase(other);
                }
                return *this;
            }

            // ─── 4. Member Functions & Friend Declarations (LAST) ──────────────
            void rebase(const response &fallback) {
                body = !body_storage.empty() ? std::string_view(body_storage) : fallback.body;
                if (!headers_storage.empty()) {
                    headers.clear();
                    headers.reserve(headers_storage.size());
                    for (const auto &[n, v] : headers_storage) {
                        headers.emplace_back(n, v);
                    }
                }
            }
        };

        // ─── HTTP/3 Parser & Encoder ───────────────────────────────────────────────

        class parser {
        public:
            enum class result { success, incomplete, error };

            [[nodiscard]] static result parse_frame(
                const std::string_view buffer,
                frame_header &hdr,
                std::string_view &payload,
                std::size_t &bytes_consumed) {
                bytes_consumed = 0;
                std::size_t cursor = 0;

                if (!VarInt::decode(buffer, cursor, hdr.type)) return result::incomplete;
                if (!VarInt::decode(buffer, cursor, hdr.length)) return result::incomplete;

                if (cursor + hdr.length > buffer.size()) return result::incomplete;

                payload = buffer.substr(cursor, hdr.length);
                bytes_consumed = cursor + hdr.length;
                return result::success;
            }

            [[nodiscard]] static result parse_request(
                const std::string_view buffer,
                request &req,
                std::size_t &bytes_consumed,
                qpack::dynamic_table &dt) {
                bytes_consumed = 0;
                if (buffer.empty()) return result::incomplete;

                std::size_t cursor = 0;

                req.headers.clear();
                req.headers_storage.clear();
                req.target_storage.clear();
                req.scheme_storage.clear();
                req.authority_storage.clear();
                req.body_storage.clear();
                req.body = {};

                qpack::dynamic_table working_dt = dt;
                qpack::decoder dec(working_dt);

                std::vector<std::pair<std::string, std::string>> decoded_headers;
                bool headers_received = false;
                std::string body_accumulator;

                while (cursor < buffer.size()) {
                    const std::string_view remaining = buffer.substr(cursor);
                    frame_header hdr;
                    std::string_view payload;
                    std::size_t frame_bytes = 0;

                    const auto r = parse_frame(remaining, hdr, payload, frame_bytes);
                    if (r == result::incomplete) {
                        return headers_received ? result::success : result::incomplete;
                    }
                    if (r == result::error) return result::error;

                    if (hdr.type == static_cast<uint64_t>(frame_type::HEADERS)) {
                        if (!dec.decode_header_block(payload, decoded_headers)) {
                            return result::error;
                        }
                        headers_received = true;
                    } else if (hdr.type == static_cast<uint64_t>(frame_type::DATA)) {
                        if (!headers_received) {
                            // RFC 9114 §4.1: DATA frame before HEADERS is a stream error
                            return result::error;
                        }
                        body_accumulator.append(payload);
                    } else if (hdr.type == static_cast<uint64_t>(frame_type::SETTINGS)) {
                        // RFC 9114 §7.2.4: SETTINGS frame MUST NOT be sent on any stream other than control stream
                        return result::error;
                    }
                    // RFC 9114 §7.2.8: Unknown frames are ignored

                    cursor += frame_bytes;
                }

                if (!headers_received) return result::incomplete;

                dt = working_dt;
                bytes_consumed = cursor;

                // Process decoded pseudo-headers & standard headers
                for (auto &[name, val] : decoded_headers) {
                    if (name == ":method") {
                        req.method_type = from_string(val);
                    } else if (name == ":path") {
                        req.target_storage = std::move(val);
                    } else if (name == ":scheme") {
                        req.scheme_storage = std::move(val);
                    } else if (name == ":authority") {
                        req.authority_storage = std::move(val);
                    } else {
                        req.headers_storage.emplace_back(std::move(name), std::move(val));
                    }
                }

                req.body_storage = std::move(body_accumulator);
                req.rebase(req);
                return result::success;
            }

            [[nodiscard]] static result parse_request(
                const std::string_view buffer,
                request &req,
                std::size_t &bytes_consumed) {
                qpack::dynamic_table local_dt;
                return parse_request(buffer, req, bytes_consumed, local_dt);
            }

            [[nodiscard]] static result parse_request(
                const std::string_view buffer,
                request &req,
                std::size_t &bytes_consumed,
                connection_context &ctx) {
                return parse_request(buffer, req, bytes_consumed, ctx.decode_table);
            }

            [[nodiscard]] static result parse_response(
                const std::string_view buffer,
                response &res,
                std::size_t &bytes_consumed,
                qpack::dynamic_table &dt) {
                bytes_consumed = 0;
                std::size_t cursor = 0;

                res.headers.clear();
                res.headers_storage.clear();
                res.body_storage.clear();
                res.body = {};

                qpack::dynamic_table working_dt = dt;
                qpack::decoder dec(working_dt);

                std::vector<std::pair<std::string, std::string>> decoded_headers;
                bool headers_received = false;
                std::string body_accumulator;

                while (cursor < buffer.size()) {
                    const std::string_view remaining = buffer.substr(cursor);
                    frame_header hdr;
                    std::string_view payload;
                    std::size_t frame_bytes = 0;

                    const auto r = parse_frame(remaining, hdr, payload, frame_bytes);
                    if (r == result::incomplete) {
                        return headers_received ? result::success : result::incomplete;
                    }
                    if (r == result::error) return result::error;

                    if (hdr.type == static_cast<uint64_t>(frame_type::HEADERS)) {
                        if (!dec.decode_header_block(payload, decoded_headers)) {
                            return result::error;
                        }
                        headers_received = true;
                    } else if (hdr.type == static_cast<uint64_t>(frame_type::DATA)) {
                        if (!headers_received) {
                            return result::error;
                        }
                        body_accumulator.append(payload);
                    } else if (hdr.type == static_cast<uint64_t>(frame_type::SETTINGS)) {
                        return result::error;
                    }
                    // RFC 9114 §7.2.8: Unknown frames are ignored

                    cursor += frame_bytes;
                }

                if (!headers_received) return result::incomplete;

                dt = working_dt;
                bytes_consumed = cursor;

                for (auto &[name, val] : decoded_headers) {
                    if (name == ":status") {
                        unsigned int code = 200;
                        std::from_chars(val.data(), val.data() + val.size(), code);
                        res.status_code = code;
                    } else {
                        res.headers_storage.emplace_back(std::move(name), std::move(val));
                    }
                }

                res.body_storage = std::move(body_accumulator);
                res.rebase(res);
                return result::success;
            }

            [[nodiscard]] static result parse_response(
                const std::string_view buffer,
                response &res,
                std::size_t &bytes_consumed) {
                qpack::dynamic_table local_dt;
                return parse_response(buffer, res, bytes_consumed, local_dt);
            }

            [[nodiscard]] static result parse_response(
                const std::string_view buffer,
                response &res,
                std::size_t &bytes_consumed,
                connection_context &ctx) {
                return parse_response(buffer, res, bytes_consumed, ctx.decode_table);
            }
        };

        class encoder {
        public:
            static std::string encode_frame(const frame_type type, const std::string_view payload) {
                std::string out;
                VarInt::encode(static_cast<uint64_t>(type), out);
                VarInt::encode(payload.size(), out);
                out.append(payload);
                return out;
            }

            static std::string encode_data_frame(const std::string_view payload) {
                return encode_frame(frame_type::DATA, payload);
            }

            static std::string serialize_request(const request &req) {
                std::string header_block = qpack::encoder::encode_request_headers(
                    req.method_type,
                    req.target,
                    req.scheme,
                    req.authority,
                    req.headers
                );

                std::string out = encode_frame(frame_type::HEADERS, header_block);
                if (!req.body.empty()) {
                    out += encode_data_frame(req.body);
                }
                return out;
            }

            static std::string serialize_response(const response &res) {
                std::string header_block = qpack::encoder::encode_response_headers(
                    res.status_code,
                    res.headers
                );

                std::string out = encode_frame(frame_type::HEADERS, header_block);
                if (!res.body.empty()) {
                    out += encode_data_frame(res.body);
                }
                return out;
            }

            static std::string serialize(const response &res) {
                return serialize_response(res);
            }

            static std::string serialize(const request &req) {
                return serialize_request(req);
            }

            static std::string serialize_settings(const std::vector<std::pair<settings_parameter, uint64_t>> &settings) {
                std::string payload;
                for (const auto &[param, val] : settings) {
                    VarInt::encode(static_cast<uint64_t>(param), payload);
                    VarInt::encode(val, payload);
                }
                return encode_frame(frame_type::SETTINGS, payload);
            }

            static std::string format_chunk(const std::string_view data) {
                return encode_data_frame(data);
            }

            [[nodiscard]] static constexpr std::string_view format_terminal_chunk() noexcept {
                return {};
            }
        };

        class decoder {
        public:
            static parser::result decode_response(
                const std::string_view buffer,
                response &res,
                std::size_t &bytes_consumed,
                qpack::dynamic_table &dt) {
                return parser::parse_response(buffer, res, bytes_consumed, dt);
            }

            static parser::result decode_response(
                const std::string_view buffer,
                response &res,
                std::size_t &bytes_consumed) {
                return parser::parse_response(buffer, res, bytes_consumed);
            }

            static parser::result decode_response(
                const std::string_view buffer,
                response &res,
                std::size_t &bytes_consumed,
                connection_context &ctx) {
                return parser::parse_response(buffer, res, bytes_consumed, ctx.decode_table);
            }

            static std::string dechunk(const std::string_view chunked_raw) {
                return std::string(chunked_raw);
            }
        };

    } // namespace http3

    // ─── http3codec (WaveX Codec Concept Implementation) ──────────────────────

    struct http3codec {
        using request = http3::request;
        using response = http3::response;
        using request_type = http3::request;
        using response_type = http3::response;
        using connection_context = http3::connection_context;
        using dynamic_table = http3::qpack::dynamic_table;
        using parser = http3::parser;
        using encoder = http3::encoder;
        using decoder = http3::decoder;
        using result = http3::parser::result;

        static std::string serialize(const response &res) {
            return encoder::serialize_response(res);
        }

        static std::string serialize_request(const request &req) {
            return encoder::serialize_request(req);
        }

        [[nodiscard]] static std::string_view status_text_for(const unsigned int code) noexcept {
            return http1codec::status_text_for(code);
        }

        static result parse_stream(const std::string_view buffer, request &req, std::size_t &bytes_consumed, dynamic_table &dt) {
            return parser::parse_request(buffer, req, bytes_consumed, dt);
        }

        static result parse_stream(const std::string_view buffer, request &req, std::size_t &bytes_consumed, connection_context &ctx) {
            return parser::parse_request(buffer, req, bytes_consumed, ctx.decode_table);
        }

        static result parse_stream(const std::string_view buffer, request &req, std::size_t &bytes_consumed) {
            return parser::parse_request(buffer, req, bytes_consumed);
        }

        static result parse_request(const std::string_view buffer, request &req, std::size_t &bytes_consumed, dynamic_table &dt) {
            return parser::parse_request(buffer, req, bytes_consumed, dt);
        }

        static result parse_request(const std::string_view buffer, request &req, std::size_t &bytes_consumed) {
            return parser::parse_request(buffer, req, bytes_consumed);
        }

        static result parse_request(const std::string_view buffer, request &req, std::size_t &bytes_consumed, connection_context &ctx) {
            return parser::parse_request(buffer, req, bytes_consumed, ctx.decode_table);
        }

        static result parse_response(const std::string_view buffer, response &res, std::size_t &bytes_consumed, dynamic_table &dt) {
            return parser::parse_response(buffer, res, bytes_consumed, dt);
        }

        static result parse_response(const std::string_view buffer, response &res, std::size_t &bytes_consumed, connection_context &ctx) {
            return parser::parse_response(buffer, res, bytes_consumed, ctx.decode_table);
        }

        static result parse_response(const std::string_view buffer, response &res, std::size_t &bytes_consumed) {
            return parser::parse_response(buffer, res, bytes_consumed);
        }

        static result decode_response(const std::string_view buffer, response &res, std::size_t &bytes_consumed, dynamic_table &dt) {
            return decoder::decode_response(buffer, res, bytes_consumed, dt);
        }

        static result decode_response(const std::string_view buffer, response &res, std::size_t &bytes_consumed, connection_context &ctx) {
            return decoder::decode_response(buffer, res, bytes_consumed, ctx.decode_table);
        }

        static result decode_response(const std::string_view buffer, response &res, std::size_t &bytes_consumed) {
            return decoder::decode_response(buffer, res, bytes_consumed);
        }

        static std::string format_chunk(const std::string_view data) {
            return encoder::format_chunk(data);
        }

        [[nodiscard]] static constexpr std::string_view format_terminal_chunk() noexcept {
            return encoder::format_terminal_chunk();
        }

        static std::string dechunk(const std::string_view chunked_raw) {
            return decoder::dechunk(chunked_raw);
        }
    };

} // namespace wavex::protos::http
