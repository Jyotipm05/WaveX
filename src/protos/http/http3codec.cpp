// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file http3codec.cpp
 * @brief Out-of-line implementation of HTTP/3 binary framing and QPACK compression engine.
 */

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

#include <wavex/protos/http/http3codec.hpp>
#include <charconv>
#include <limits>
#include <algorithm>
#include <atomic>

#include "wavex/protos/http/http2codec.hpp"

namespace wavex::protos::http::http3 {
    namespace {
        std::atomic<uint64_t> s_default_max_field_section_size{65536};

        /// Strict content-length: 1*DIGIT only (RFC 9110 §8.6). strtoull accepted "+5", " 5", "5abc"
        /// and wrapped "-1" to ~2^64, which left the request permanently incomplete.
        bool parse_content_length(const std::string_view v, uint64_t &out) noexcept {
            if (v.empty()) return false;
            const auto [ptr, ec] = std::from_chars(v.data(), v.data() + v.size(), out);
            return ec == std::errc{} && ptr == v.data() + v.size();
        }

        /// Field values must not contain CR, LF or NUL (RFC 9114 §4.2, RFC 9110 §5.5). These would
        /// otherwise survive into logs, HTTP/1.1 upstreams or response headers echoed back.
        bool is_valid_field_value(const std::string_view v) noexcept {
            return std::ranges::none_of(v, [](const char c) { return c == '\r' || c == '\n' || c == '\0'; });
        }

        /// Lowercase token characters only; ':' is allowed solely as the pseudo-header prefix.
        bool is_valid_field_name(const std::string_view n) noexcept {
            if (n.empty() || n == ":") return false;
            for (std::size_t i = 0; i < n.size(); ++i) {
                const auto u = static_cast<unsigned char>(n[i]);
                if (n[i] == ':' && i == 0) continue;
                if (u <= 0x20 || u >= 0x7f || n[i] == ':' || (u >= 'A' && u <= 'Z')) return false;
            }
            return true;
        }
    }

    uint64_t parser::default_max_field_section_size() noexcept {
        return s_default_max_field_section_size.load(std::memory_order_relaxed);
    }

    void parser::set_default_max_field_section_size(const uint64_t size) noexcept {
        s_default_max_field_section_size.store(size, std::memory_order_relaxed);
    }

    namespace qpack {
        // RFC 9204 Appendix A — QPACK Static Table (0-indexed, entries 0..98)
        const std::array<static_entry, 99> STATIC_TABLE = {
            {
                {":authority", ""}, // 0
                {":path", "/"}, // 1
                {"age", "0"}, // 2
                {"content-disposition", ""}, // 3
                {"content-length", "0"}, // 4
                {"cookie", ""}, // 5
                {"date", ""}, // 6
                {"etag", ""}, // 7
                {"if-modified-since", ""}, // 8
                {"if-none-match", ""}, // 9
                {"last-modified", ""}, // 10
                {"link", ""}, // 11
                {"location", ""}, // 12
                {"referer", ""}, // 13
                {"set-cookie", ""}, // 14
                {":method", "CONNECT"}, // 15
                {":method", "DELETE"}, // 16
                {":method", "GET"}, // 17
                {":method", "HEAD"}, // 18
                {":method", "OPTIONS"}, // 19
                {":method", "POST"}, // 20
                {":method", "PUT"}, // 21
                {":scheme", "http"}, // 22
                {":scheme", "https"}, // 23
                {":status", "103"}, // 24
                {":status", "200"}, // 25
                {":status", "304"}, // 26
                {":status", "404"}, // 27
                {":status", "503"}, // 28
                {"accept", "*/*"}, // 29
                {"accept", "application/dns-message"}, // 30
                {"accept-encoding", "gzip, deflate, br"}, // 31
                {"accept-ranges", "bytes"}, // 32
                {"access-control-allow-headers", "cache-control"}, // 33
                {"access-control-allow-headers", "content-type"}, // 34
                {"access-control-allow-origin", "*"}, // 35
                {"cache-control", "max-age=0"}, // 36
                {"cache-control", "max-age=2592000"}, // 37
                {"cache-control", "max-age=604800"}, // 38
                {"cache-control", "no-cache"}, // 39
                {"cache-control", "no-store"}, // 40
                {"cache-control", "public, max-age=31536000"}, // 41
                {"content-encoding", "br"}, // 42
                {"content-encoding", "gzip"}, // 43
                {"content-type", "application/dns-message"}, // 44
                {"content-type", "application/javascript"}, // 45
                {"content-type", "application/json"}, // 46
                {"content-type", "application/x-www-form-urlencoded"}, // 47
                {"content-type", "image/gif"}, // 48
                {"content-type", "image/jpeg"}, // 49
                {"content-type", "image/png"}, // 50
                {"content-type", "text/css"}, // 51
                {"content-type", "text/html; charset=utf-8"}, // 52
                {"content-type", "text/plain"}, // 53
                {"content-type", "text/plain;charset=utf-8"}, // 54
                {"range", "bytes=0-"}, // 55
                {"strict-transport-security", "max-age=31536000"}, // 56
                {"strict-transport-security", "max-age=31536000; includesubdomains"}, // 57
                {"strict-transport-security", "max-age=31536000; includesubdomains; preload"}, // 58
                {"vary", "accept-encoding"}, // 59
                {"vary", "origin"}, // 60
                {"x-content-type-options", "nosniff"}, // 61
                {"x-xss-protection", "1; mode=block"}, // 62
                {":status", "100"}, // 63
                {":status", "204"}, // 64
                {":status", "206"}, // 65
                {":status", "302"}, // 66
                {":status", "400"}, // 67
                {":status", "403"}, // 68
                {":status", "421"}, // 69
                {":status", "425"}, // 70
                {":status", "500"}, // 71
                {"accept-language", ""}, // 72
                {"access-control-allow-credentials", "FALSE"}, // 73
                {"access-control-allow-credentials", "TRUE"}, // 74
                {"access-control-allow-headers", "*"}, // 75
                {"access-control-allow-methods", "get"}, // 76
                {"access-control-allow-methods", "get, post, options"}, // 77
                {"access-control-allow-methods", "options"}, // 78
                {"access-control-expose-headers", "content-length"}, // 79
                {"access-control-request-headers", "content-type"}, // 80
                {"access-control-request-method", "get"}, // 81
                {"access-control-request-method", "post"}, // 82
                {"alt-svc", "clear"}, // 83
                {"authorization", ""}, // 84
                {"content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none';"}, // 85
                {"early-data", "1"}, // 86
                {"expect-ct", ""}, // 87
                {"forwarded", ""}, // 88
                {"if-range", ""}, // 89
                {"origin", ""}, // 90
                {"purpose", "prefetch"}, // 91
                {"server", ""}, // 92
                {"timing-allow-origin", "*"}, // 93
                {"upgrade-insecure-requests", "1"}, // 94
                {"user-agent", ""}, // 95
                {"x-forwarded-for", ""}, // 96
                {"x-frame-options", "deny"}, // 97
                {"x-frame-options", "sameorigin"} // 98
            }
        };

        std::pair<std::size_t, bool> find_static(
            const std::string_view name,
            const std::string_view value) noexcept {
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

        // ─── dynamic_table ─────────────────────────────────────────────────────────

        bool dynamic_table::set_max_capacity(const std::size_t cap) noexcept {
            if (cap > max_capacity_limit_) return false;
            max_capacity_ = cap;
            evict();
            return true;
        }

        void dynamic_table::set_max_capacity_limit(const std::size_t limit) noexcept {
            max_capacity_limit_ = limit;
            if (max_capacity_ > max_capacity_limit_) {
                max_capacity_ = max_capacity_limit_;
                evict();
            }
        }

        uint64_t dynamic_table::insert(std::string name, std::string value) {
            const uint64_t abs_idx = total_inserts_++;
            entry e{std::move(name), std::move(value), abs_idx};
            const std::size_t esz = e.size();

            if (esz > max_capacity_) {
                entries_.clear();
                current_size_ = 0;
                return abs_idx;
            }

            entries_.push_back(std::move(e));
            current_size_ += esz;
            evict();
            return abs_idx;
        }

        const dynamic_table::entry *dynamic_table::get_by_absolute_index(const uint64_t abs_idx) const noexcept {
            if (entries_.empty()) return nullptr;
            const uint64_t oldest_idx = entries_.front().absolute_index;
            if (const uint64_t newest_idx = entries_.back().absolute_index;
                abs_idx < oldest_idx || abs_idx > newest_idx) return nullptr;
            const std::size_t offset = static_cast<std::size_t>(abs_idx - oldest_idx);
            return &entries_[offset];
        }

        const dynamic_table::entry *dynamic_table::get_relative(const uint64_t base,
                                                                const uint64_t relative_idx) const noexcept {
            if (base == 0 || relative_idx >= base) return nullptr;
            const uint64_t target_abs = base - 1 - relative_idx;
            return get_by_absolute_index(target_abs);
        }

        const dynamic_table::entry *dynamic_table::get_post_base(const uint64_t base,
                                                                 const uint64_t post_base_idx) const noexcept {
            if (post_base_idx > std::numeric_limits<uint64_t>::max() - base) return nullptr;
            const uint64_t target_abs = base + post_base_idx;
            return get_by_absolute_index(target_abs);
        }

        std::tuple<uint64_t, bool, bool> dynamic_table::find(
            const std::string_view name,
            const std::string_view value) const noexcept {
            bool name_found = false;
            uint64_t name_abs = 0;
            for (auto it = entries_.rbegin(); it != entries_.rend(); ++it) {
                if (detail::is_equal(it->name, name)) {
                    if (it->value == value) {
                        return {it->absolute_index, true, true};
                    }
                    if (!name_found) {
                        name_abs = it->absolute_index;
                        name_found = true;
                    }
                }
            }
            if (name_found) return {name_abs, false, true};
            return {0, false, false};
        }

        void dynamic_table::evict() noexcept {
            while (current_size_ > max_capacity_ && !entries_.empty()) {
                current_size_ -= entries_.front().size();
                entries_.erase(entries_.begin());
            }
        }

        // ─── qpack::encoder ────────────────────────────────────────────────────────

        void encoder::encode_set_capacity(std::string &out, const uint64_t capacity) {
            http2::hpack::encode_integer(out, capacity, 5, 0x20);
        }

        void encoder::encode_insert_with_name_ref(
            std::string &out,
            const uint64_t name_idx,
            const bool is_static,
            const std::string_view val) {
            const uint8_t mask = is_static ? 0xc0 : 0x80;
            http2::hpack::encode_integer(out, name_idx, 6, mask);
            http2::hpack::encode_string(out, val);
        }

        void encoder::encode_insert_with_literal_name(
            std::string &out,
            const std::string_view name,
            const std::string_view val) {
            http2::hpack::encode_integer(out, name.size(), 5, 0x40);
            out.append(name);
            http2::hpack::encode_string(out, val);
        }

        void encoder::encode_duplicate(std::string &out, const uint64_t index) {
            http2::hpack::encode_integer(out, index, 5, 0x00);
        }

        void encoder::encode_section_ack(std::string &out, const uint64_t stream_id) {
            http2::hpack::encode_integer(out, stream_id, 7, 0x80);
        }

        void encoder::encode_stream_cancel(std::string &out, const uint64_t stream_id) {
            http2::hpack::encode_integer(out, stream_id, 6, 0x40);
        }

        void encoder::encode_insert_count_increment(std::string &out, const uint64_t increment) {
            http2::hpack::encode_integer(out, increment, 6, 0x00);
        }

        std::string encoder::encode_request_headers(
            const http::method m,
            const std::string_view target,
            const std::string_view scheme,
            const std::string_view authority,
            const std::vector<header> &headers,
            const dynamic_table *dt) {
            std::string out;
            out.reserve(256);

            uint64_t max_used_abs = 0;
            bool used_dynamic = false;

            std::string fields;
            fields.reserve(256);

            // 1. :method
            const std::string_view method_str = to_string(m);
            if (const auto [m_idx, m_exact] = find_static(":method", method_str); m_exact) {
                encode_indexed_static(fields, m_idx);
            } else if (m_idx < STATIC_TABLE.size()) {
                encode_literal_with_name_ref(fields, m_idx, true, method_str);
            } else {
                encode_literal_new_name(fields, ":method", method_str);
            }

            // 2. :scheme
            const std::string_view sc = scheme.empty() ? "https" : scheme;
            if (const auto [s_idx, s_exact] = find_static(":scheme", sc); s_exact) {
                encode_indexed_static(fields, s_idx);
            } else {
                encode_literal_with_name_ref(fields, 23, true, sc); // 23 = :scheme https
            }

            // 3. :path
            if (const std::string_view p = target.empty() ? "/" : target; p == "/") {
                encode_indexed_static(fields, 1); // 1 = :path: /
            } else {
                encode_literal_with_name_ref(fields, 1, true, p);
            }

            // 4. :authority
            if (!authority.empty()) {
                encode_literal_with_name_ref(fields, 0, true, authority); // 0 = :authority
            }

            // 4b. Extension pseudo-headers (e.g. `:protocol` of an extended CONNECT, RFC 9220) must precede
            //     the regular fields (RFC 9114 §4.3).
            for (const auto &[pseudo_name, pseudo_value]: headers) {
                if (pseudo_name.starts_with(':') && pseudo_name != ":method" && pseudo_name != ":scheme" &&
                    pseudo_name != ":path" && pseudo_name != ":authority") {
                    encode_literal_new_name(fields, pseudo_name, pseudo_value);
                }
            }

            // 5. General Headers
            for (const auto &[raw_name, value]: headers) {
                if (raw_name.starts_with(':')) continue;
                std::string name;
                name.reserve(raw_name.size());
                for (const char c: raw_name) {
                    name.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
                }

                // Check static table first
                const auto [idx, exact] = find_static(name, value);
                if (exact) {
                    encode_indexed_static(fields, idx);
                    continue;
                }

                // Check dynamic table if provided
                if (dt && !dt->empty()) {
                    const auto [dyn_abs, dyn_exact, dyn_found] = dt->find(name, value);
                    if (dyn_exact) {
                        const uint64_t base = dt->total_inserts();
                        const uint64_t rel_idx = base - 1 - dyn_abs;
                        encode_indexed_dynamic(fields, rel_idx);
                        if (!used_dynamic || dyn_abs > max_used_abs) max_used_abs = dyn_abs;
                        used_dynamic = true;
                        continue;
                    }
                    if (dyn_found && idx >= STATIC_TABLE.size()) {
                        const uint64_t base = dt->total_inserts();
                        const uint64_t rel_idx = base - 1 - dyn_abs;
                        encode_literal_with_name_ref(fields, rel_idx, false, value);
                        if (!used_dynamic || dyn_abs > max_used_abs) max_used_abs = dyn_abs;
                        used_dynamic = true;
                        continue;
                    }
                }

                if (idx < STATIC_TABLE.size()) {
                    encode_literal_with_name_ref(fields, idx, true, value);
                } else {
                    encode_literal_new_name(fields, name, value);
                }
            }

            // Prepend Encoded Field Section Prefix (RFC 9204 §4.5.1)
            if (used_dynamic) {
                const uint64_t ric = max_used_abs + 1;
                const uint64_t base = dt ? dt->total_inserts() : ric;
                encode_prefix(out, ric, base, dt ? dt->max_capacity() : 4096);
            } else {
                encode_prefix(out, 0, 0);
            }

            out.append(fields);
            return out;
        }

        std::string encoder::encode_response_headers(
            const unsigned int status_code,
            const std::vector<header> &headers,
            dynamic_table *dt) {
            std::string out;
            out.reserve(256);

            // Response prefix: Required Insert Count = 0, Delta Base = 0
            out.push_back('\0');
            out.push_back('\0');

            // :status
            char sbuf[16];
            const auto [ptr, ec] = std::to_chars(sbuf, sbuf + sizeof(sbuf), status_code);
            const std::string_view status_str(sbuf, ptr);

            if (const auto [idx, exact] = find_static(":status", status_str); exact) {
                encode_indexed_static(out, idx);
            } else {
                encode_literal_with_name_ref(out, 25, true, status_str); // 25 = :status: 200
            }

            // General Headers
            for (const auto &[raw_name, value]: headers) {
                if (raw_name.starts_with(':')) continue;
                std::string name;
                name.reserve(raw_name.size());
                for (const char c: raw_name) {
                    name.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
                }
                if (const auto [h_idx, h_exact] = find_static(name, value); h_exact) {
                    encode_indexed_static(out, h_idx);
                } else if (h_idx < STATIC_TABLE.size()) {
                    encode_literal_with_name_ref(out, h_idx, true, value);
                } else {
                    encode_literal_new_name(out, name, value);
                }
            }

            return out;
        }

        void encoder::encode_prefix(
            std::string &out,
            const uint64_t ric,
            const uint64_t base,
            const uint64_t max_table_capacity) {
            uint64_t enc_insert_count = 0;
            if (ric > 0) {
                if (const uint64_t max_entries = max_table_capacity / 32; max_entries > 0) {
                    enc_insert_count = (ric % (2 * max_entries)) + 1;
                }
            }
            http2::hpack::encode_integer(out, enc_insert_count, 8, 0x00);
            if (base >= ric) {
                const uint64_t delta_base = base - ric;
                http2::hpack::encode_integer(out, delta_base, 7, 0x00); // Sign = 0
            } else {
                const uint64_t delta_base = ric - base - 1;
                http2::hpack::encode_integer(out, delta_base, 7, 0x80); // Sign = 1
            }
        }

        void encoder::encode_indexed_static(std::string &out, const std::size_t idx) {
            http2::hpack::encode_integer(out, idx, 6, 0xc0);
        }

        void encoder::encode_indexed_dynamic(std::string &out, const uint64_t rel_idx) {
            http2::hpack::encode_integer(out, rel_idx, 6, 0x80);
        }

        void encoder::encode_literal_with_name_ref(
            std::string &out,
            const uint64_t idx,
            const bool is_static,
            const std::string_view val) {
            const uint8_t mask = is_static ? 0x50 : 0x40;
            http2::hpack::encode_integer(out, idx, 4, mask);
            http2::hpack::encode_string(out, val);
        }

        void encoder::encode_literal_new_name(
            std::string &out,
            const std::string_view name,
            const std::string_view val) {
            http2::hpack::encode_integer(out, name.size(), 3, 0x20);
            out.append(name);
            http2::hpack::encode_string(out, val);
        }

        void encoder::encode_indexed_post_base(std::string &out, const uint64_t post_base_idx) {
            http2::hpack::encode_integer(out, post_base_idx, 4, 0x10);
        }

        void encoder::encode_literal_post_base_name_ref(
            std::string &out,
            const uint64_t post_base_name_idx,
            const std::string_view val) {
            http2::hpack::encode_integer(out, post_base_name_idx, 3, 0x00);
            http2::hpack::encode_string(out, val);
        }

        // ─── qpack::decoder ────────────────────────────────────────────────────────

        bool decoder::apply_encoder_instruction(const std::string_view in, std::size_t &cursor) const {
            if (cursor >= in.size()) return false;
            const auto b = static_cast<uint8_t>(in[cursor]);

            // Set Dynamic Table Capacity: 001xxxxx (5-bit prefix, 0x20)
            if ((b & 0xe0) == 0x20) {
                uint64_t capacity = 0;
                if (!http2::hpack::decode_integer(in, cursor, 5, capacity)) return false;
                if (!dt_.set_max_capacity(static_cast<std::size_t>(capacity))) return false;
                return true;
            }

            // Insert with Name Reference: 1Txxxxxx (6-bit prefix)
            if ((b & 0x80) != 0) {
                const bool is_static = (b & 0x40) != 0;
                uint64_t name_idx = 0;
                if (!http2::hpack::decode_integer(in, cursor, 6, name_idx)) return false;

                std::string name;
                if (is_static) {
                    if (name_idx >= STATIC_TABLE.size()) return false;
                    name = std::string(STATIC_TABLE[name_idx].name);
                } else {
                    const auto *e = dt_.get_relative(dt_.total_inserts(), name_idx);
                    if (!e) return false;
                    name = e->name;
                }

                std::string val;
                if (!http2::hpack::decode_string(in, cursor, val)) return false;
                dt_.insert(std::move(name), std::move(val));
                return true;
            }

            // Insert with Literal Name: 01Hxxxxx (5-bit prefix, 0x40)
            if ((b & 0xc0) == 0x40) {
                const bool is_huffman = (b & 0x20) != 0;
                uint64_t name_len = 0;
                if (!http2::hpack::decode_integer(in, cursor, 5, name_len)) return false;
                if (cursor + name_len > in.size()) return false;

                std::string name;
                if (is_huffman) {
                    if (!http2::hpack::huffman::decode(in.substr(cursor, name_len), name)) return false;
                } else {
                    name = std::string(in.substr(cursor, name_len));
                }
                cursor += name_len;

                std::string val;
                if (!http2::hpack::decode_string(in, cursor, val)) return false;
                dt_.insert(std::move(name), std::move(val));
                return true;
            }

            // Duplicate: 000xxxxx (5-bit prefix, 0x00)
            if ((b & 0xe0) == 0x00) {
                uint64_t index = 0;
                if (!http2::hpack::decode_integer(in, cursor, 5, index)) return false;
                const auto *e = dt_.get_relative(dt_.total_inserts(), index);
                if (!e) return false;
                std::string d_name = e->name;
                std::string d_val = e->value;
                dt_.insert(std::move(d_name), std::move(d_val));
                return true;
            }

            return false;
        }

        bool decoder::decode_header_block(
            const std::string_view block,
            std::vector<std::pair<std::string, std::string> > &out_headers,
            bool &is_blocked,
            const uint64_t max_field_section_size) const {
            is_blocked = false;
            if (block.empty()) return false;
            std::size_t cursor = 0;

            // RFC 9204 §4.5.1: Encoded Field Section Prefix
            uint64_t enc_insert_count = 0;
            if (!http2::hpack::decode_integer(block, cursor, 8, enc_insert_count)) return false;

            uint64_t req_insert_count = 0;
            const uint64_t max_entries = dt_.max_capacity() / 32;
            if (enc_insert_count == 0) {
                req_insert_count = 0;
            } else {
                if (max_entries == 0) {
                    return false;
                }
                const uint64_t full_range = 2 * max_entries;
                if (enc_insert_count > full_range) {
                    return false;
                }
                const uint64_t total_number_of_inserts = dt_.total_inserts();
                const uint64_t max_value = total_number_of_inserts + max_entries;
                const uint64_t max_wrapped = (max_value / full_range) * full_range;
                req_insert_count = max_wrapped + enc_insert_count - 1;
                if (req_insert_count > max_value) {
                    if (req_insert_count <= full_range) return false;
                    req_insert_count -= full_range;
                }
                if (req_insert_count == 0) return false;
            }

            if (cursor >= block.size()) return false;
            const bool sign = (static_cast<uint8_t>(block[cursor]) & 0x80) != 0;
            uint64_t delta_base = 0;
            if (!http2::hpack::decode_integer(block, cursor, 7, delta_base)) return false;

            if (dt_.is_blocked(req_insert_count)) {
                is_blocked = true;
                return false;
            }

            uint64_t base = 0;
            if (!sign) {
                base = req_insert_count + delta_base;
            } else {
                if (delta_base >= req_insert_count) return false;
                base = req_insert_count - delta_base - 1;
            }

            uint64_t accumulated_section_size = 0;
            auto add_header = [&](std::string name, std::string value) -> bool {
                accumulated_section_size += name.size() + value.size() + 32;
                if (max_field_section_size > 0 && accumulated_section_size > max_field_section_size) {
                    return false;
                }
                out_headers.emplace_back(std::move(name), std::move(value));
                return true;
            };

            while (cursor < block.size()) {
                // Case 1: Indexed Header Field (starts with 1xxxxxxx)
                if (const auto b = static_cast<uint8_t>(block[cursor]); (b & 0x80) != 0) {
                    const bool is_static = (b & 0x40) != 0;
                    uint64_t index = 0;
                    if (!http2::hpack::decode_integer(block, cursor, 6, index)) return false;

                    if (is_static) {
                        if (index >= STATIC_TABLE.size()) return false;
                        if (!add_header(
                            std::string(STATIC_TABLE[index].name),
                            std::string(STATIC_TABLE[index].value))) return false;
                    } else {
                        const auto *e = dt_.get_relative(base, index);
                        if (!e) return false;
                        if (!add_header(e->name, e->value)) return false;
                    }
                }
                // Case 2: Literal Header with Name Reference (starts with 01xxxxxx)
                else if ((b & 0x40) != 0) {
                    const bool is_static = (b & 0x10) != 0;
                    uint64_t name_idx = 0;
                    if (!http2::hpack::decode_integer(block, cursor, 4, name_idx)) return false;

                    std::string name;
                    if (is_static) {
                        if (name_idx >= STATIC_TABLE.size()) return false;
                        name = std::string(STATIC_TABLE[name_idx].name);
                    } else {
                        const auto *e = dt_.get_relative(base, name_idx);
                        if (!e) return false;
                        name = e->name;
                    }

                    std::string value;
                    if (!http2::hpack::decode_string(block, cursor, value)) return false;
                    if (!add_header(std::move(name), std::move(value))) return false;
                }
                // Case 3: Literal Header with Literal Name (starts with 001xxxxx)
                else if ((b & 0x20) != 0) {
                    const bool is_huffman = (b & 0x08) != 0;
                    uint64_t name_len = 0;
                    if (!http2::hpack::decode_integer(block, cursor, 3, name_len)) return false;
                    if (cursor + name_len > block.size()) return false;
                    std::string name;
                    if (is_huffman) {
                        if (!http2::hpack::huffman::decode(block.substr(cursor, name_len), name)) return false;
                    } else {
                        name = std::string(block.substr(cursor, name_len));
                    }
                    cursor += name_len;

                    std::string value;
                    if (!http2::hpack::decode_string(block, cursor, value)) return false;
                    if (!add_header(std::move(name), std::move(value))) return false;
                }
                // Case 4: Indexed Header Field with Post-Base Index (RFC 9204 §4.5.3: 0001xxxx, 4-bit prefix 0x10)
                else if ((b & 0xf0) == 0x10) {
                    uint64_t post_base_idx = 0;
                    if (!http2::hpack::decode_integer(block, cursor, 4, post_base_idx)) return false;
                    const auto *e = dt_.get_post_base(base, post_base_idx);
                    if (!e) return false;
                    if (!add_header(e->name, e->value)) return false;
                }
                // Case 5: Literal Header with Post-Base Name Reference (RFC 9204 §4.5.5: 0000xxxx, 3-bit prefix 0x00)
                else if ((b & 0xf0) == 0x00) {
                    uint64_t name_idx = 0;
                    if (!http2::hpack::decode_integer(block, cursor, 3, name_idx)) return false;
                    const auto *e = dt_.get_post_base(base, name_idx);
                    if (!e) return false;

                    std::string value;
                    if (!http2::hpack::decode_string(block, cursor, value)) return false;
                    if (!add_header(e->name, std::move(value))) return false;
                } else {
                    return false;
                }
            }
            return true;
        }

        bool decoder::decode_header_block(
            const std::string_view block,
            std::vector<std::pair<std::string, std::string> > &out_headers,
            const uint64_t max_field_section_size) const {
            bool is_blocked = false;
            return decode_header_block(block, out_headers, is_blocked, max_field_section_size);
        }
    } // namespace qpack

    // ─── http3::parser ─────────────────────────────────────────────────────────────

    bool parser::parse_frame_header(
        const std::string_view buffer,
        frame_header &hdr,
        std::size_t &bytes_consumed) {
        bytes_consumed = 0;
        std::size_t cursor = 0;
        if (!VarInt::decode(buffer, cursor, hdr.type)) return false;
        if (!VarInt::decode(buffer, cursor, hdr.length)) return false;
        bytes_consumed = cursor;
        return true;
    }

    parser::result parser::parse_frame(
        const std::string_view buffer,
        frame_header &hdr,
        std::string_view &payload,
        std::size_t &bytes_consumed) {
        bytes_consumed = 0;
        std::size_t hdr_bytes = 0;
        if (!parse_frame_header(buffer, hdr, hdr_bytes)) return result::incomplete;
        if (hdr_bytes + hdr.length > buffer.size()) return result::incomplete;

        if (is_reserved_frame_type(hdr.type)) {
            return result::error;
        }

        payload = buffer.substr(hdr_bytes, hdr.length);
        bytes_consumed = hdr_bytes + hdr.length;
        return result::success;
    }

    parser::result parser::parse_request(
        const std::string_view buffer,
        request &req,
        std::size_t &bytes_consumed,
        qpack::dynamic_table &dt,
        const uint64_t max_field_section_size) {
        bytes_consumed = 0;
        if (buffer.empty()) return result::incomplete;

        if (req.state_.cursor == 0 && !req.state_.headers_received && !req.state_.in_data_frame) {
            req.headers.clear();
            req.headers_storage.clear();
            req.target_storage.clear();
            req.scheme_storage.clear();
            req.authority_storage.clear();
            req.body_storage.clear();
            req.protocol.clear();
            req.body = {};
            req.state_.reset();
        }

        const qpack::decoder dec(dt);
        std::size_t cursor = req.state_.cursor;

        while (cursor < buffer.size()) {
            if (req.state_.in_data_frame) {
                const std::size_t available = buffer.size() - cursor;
                const auto to_consume = static_cast<std::size_t>(
                    std::min(static_cast<uint64_t>(available), req.state_.remaining_data_frame_bytes));
                req.body_storage.append(buffer.substr(cursor, to_consume));
                cursor += to_consume;
                req.state_.cursor = cursor;
                req.state_.remaining_data_frame_bytes -= to_consume;
                if (req.state_.remaining_data_frame_bytes == 0) {
                    req.state_.in_data_frame = false;
                }
                continue;
            }

            const std::string_view remaining = buffer.substr(cursor);
            frame_header hdr;
            std::size_t hdr_bytes = 0;
            if (!parse_frame_header(remaining, hdr, hdr_bytes)) {
                break;
            }

            if (is_reserved_frame_type(hdr.type)) {
                req.state_.reset();
                return result::error;
            }

            if (hdr.type == static_cast<uint64_t>(frame_type::DATA)) {
                if (!req.state_.headers_received) {
                    req.state_.reset();
                    return result::error;
                }
                cursor += hdr_bytes;
                req.state_.cursor = cursor;
                req.state_.in_data_frame = true;
                req.state_.remaining_data_frame_bytes = hdr.length;

                const std::size_t available = buffer.size() - cursor;
                const auto to_consume = static_cast<std::size_t>(
                    std::min(static_cast<uint64_t>(available), req.state_.remaining_data_frame_bytes));
                req.body_storage.append(buffer.substr(cursor, to_consume));
                cursor += to_consume;
                req.state_.cursor = cursor;
                req.state_.remaining_data_frame_bytes -= to_consume;
                if (req.state_.remaining_data_frame_bytes == 0) {
                    req.state_.in_data_frame = false;
                }
            } else if (hdr.type == static_cast<uint64_t>(frame_type::HEADERS)) {
                if (req.state_.headers_received) {
                    // Trailing HEADERS: skip only once the whole frame is buffered. Advancing past the end
                    // of the buffer left cursor > buffer.size() and reported bytes that were never read.
                    if (hdr_bytes + hdr.length > remaining.size()) {
                        break;
                    }
                    cursor += hdr_bytes + hdr.length;
                    req.state_.cursor = cursor;
                    continue;
                }

                if (hdr_bytes + hdr.length > remaining.size()) {
                    break;
                }

                const std::string_view block = remaining.substr(hdr_bytes, hdr.length);
                std::vector<std::pair<std::string, std::string> > decoded;
                if (bool is_blocked = false; !dec.decode_header_block(block, decoded, is_blocked, max_field_section_size)) {
                    if (is_blocked) {
                        return result::incomplete;
                    }
                    req.state_.reset();
                    return result::error;
                }

                uint64_t section_size = 0;
                for (const auto &[name, val] : decoded) {
                    section_size += name.size() + val.size() + 32;
                    if (max_field_section_size > 0 && section_size > max_field_section_size) {
                        req.state_.reset();
                        return result::error;
                    }
                }

                bool has_method = false;
                bool has_path = false;
                bool has_scheme = false;
                bool has_authority = false;
                bool has_protocol = false;
                bool seen_regular_header = false;

                for (auto &[name, val]: decoded) {
                    // RFC 9114 §4.2 / §10.3: malformed names (uppercase, controls, spaces) and values carrying
                    // CR, LF or NUL make the whole request malformed.
                    if (!is_valid_field_name(name) || !is_valid_field_value(val)) {
                        req.state_.reset();
                        return result::error;
                    }

                    if (name.starts_with(':')) {
                        if (seen_regular_header) {
                            req.state_.reset();
                            return result::error;
                        }
                        if (name == ":method") {
                            if (has_method) {
                                req.state_.reset();
                                return result::error;
                            }
                            has_method = true;
                            req.method_type = http::from_string(val);
                        } else if (name == ":path") {
                            if (has_path) {
                                req.state_.reset();
                                return result::error;
                            }
                            has_path = true;
                            req.target_storage = std::move(val);
                        } else if (name == ":scheme") {
                            if (has_scheme) {
                                req.state_.reset();
                                return result::error;
                            }
                            has_scheme = true;
                            req.scheme_storage = std::move(val);
                        } else if (name == ":authority") {
                            if (has_authority) {
                                req.state_.reset();
                                return result::error;
                            }
                            has_authority = true;
                            req.authority_storage = std::move(val);
                        } else if (name == ":protocol") {
                            // Extended CONNECT (RFC 8441 §4, RFC 9220 §3): validated against :method below.
                            if (has_protocol || val.empty()) {
                                req.state_.reset();
                                return result::error;
                            }
                            has_protocol = true;
                            req.protocol = std::move(val);
                        } else {
                            req.state_.reset();
                            return result::error;
                        }
                    } else {
                        seen_regular_header = true;

                        if (name == "connection" || name == "keep-alive" ||
                            name == "proxy-connection" || name == "transfer-encoding" ||
                            name == "upgrade") {
                            req.state_.reset();
                            return result::error;
                        }
                        if (name == "te" && val != "trailers") {
                            req.state_.reset();
                            return result::error;
                        }

                        if (name == "content-length") {
                            uint64_t cl = 0;
                            // Reject non-numeric values and conflicting duplicates (RFC 9110 §8.6).
                            if (!parse_content_length(val, cl) ||
                                (req.state_.has_content_length && req.state_.content_length != cl)) {
                                req.state_.reset();
                                return result::error;
                            }
                            req.state_.has_content_length = true;
                            req.state_.content_length = cl;
                        }
                        req.headers_storage.emplace_back(std::move(name), std::move(val));
                    }
                }

                // RFC 9114 §4.3.1: non-CONNECT requests need :method, :scheme and :path.
                if (!has_method || (req.method_type != method::CONNECT && (!has_path || !has_scheme))) {
                    req.state_.reset();
                    return result::error;
                }
                // RFC 8441 §4 / RFC 9220 §3: `:protocol` only on CONNECT, and an extended CONNECT carries the
                // full set of :scheme, :path and :authority.
                if (has_protocol && (req.method_type != method::CONNECT || !has_scheme || !has_path ||
                                     !has_authority)) {
                    req.state_.reset();
                    return result::error;
                }
                if (has_path && req.target_storage.empty() && req.method_type != method::CONNECT) {
                    req.state_.reset();
                    return result::error;
                }

                req.state_.headers_received = true;
                cursor += hdr_bytes + hdr.length;
                req.state_.cursor = cursor;
                // RFC 9114 §4.4: after a CONNECT the stream is a tunnel. Its DATA frames are not a request
                // body; leave them unconsumed for whoever takes the stream over (WebSocket, WebTransport).
                if (req.method_type == method::CONNECT) {
                    break;
                }
            } else if (hdr.type == static_cast<uint64_t>(frame_type::SETTINGS) ||
                       hdr.type == static_cast<uint64_t>(frame_type::CANCEL_PUSH) ||
                       hdr.type == static_cast<uint64_t>(frame_type::GOAWAY) ||
                       hdr.type == static_cast<uint64_t>(frame_type::MAX_PUSH_ID)) {
                req.state_.reset();
                return result::error;
            } else {
                if (hdr_bytes + hdr.length > remaining.size()) {
                    break;
                }
                cursor += hdr_bytes + hdr.length;
                req.state_.cursor = cursor;
            }
        }

        if (!req.state_.headers_received) return result::incomplete;
        if (req.state_.in_data_frame) return result::incomplete;

        if (req.state_.has_content_length) {
            if (req.body_storage.size() < req.state_.content_length) {
                return result::incomplete;
            }
            if (req.body_storage.size() > req.state_.content_length) {
                req.state_.reset();
                return result::error;
            }
        }

        bytes_consumed = req.state_.cursor;
        req.rebase(req);
        req.state_.reset();
        return result::success;
    }

    parser::result parser::parse_request(
        const std::string_view buffer,
        request &req,
        std::size_t &bytes_consumed,
        qpack::dynamic_table &dt) {
        return parse_request(buffer, req, bytes_consumed, dt, default_max_field_section_size());
    }

    parser::result parser::parse_request(
        const std::string_view buffer,
        request &req,
        std::size_t &bytes_consumed) {
        qpack::dynamic_table local_dt;
        return parse_request(buffer, req, bytes_consumed, local_dt, default_max_field_section_size());
    }

    parser::result parser::parse_request(
        const std::string_view buffer,
        request &req,
        std::size_t &bytes_consumed,
        connection_context &ctx) {
        return parse_request(buffer, req, bytes_consumed, ctx.decode_table, ctx.max_field_section_size);
    }

    parser::result parser::parse_response(
        const std::string_view buffer,
        response &res,
        std::size_t &bytes_consumed,
        qpack::dynamic_table &dt,
        const uint64_t max_field_section_size) {
        bytes_consumed = 0;
        if (buffer.empty()) return result::incomplete;

        if (res.state_.cursor == 0 && !res.state_.headers_received && !res.state_.in_data_frame) {
            res.headers.clear();
            res.headers_storage.clear();
            res.body_storage.clear();
            res.body = {};
            res.state_.reset();
        }

        const qpack::decoder dec(dt);
        std::size_t cursor = res.state_.cursor;

        while (cursor < buffer.size()) {
            if (res.state_.in_data_frame) {
                const std::size_t available = buffer.size() - cursor;
                const auto to_consume = static_cast<std::size_t>(
                    std::min(static_cast<uint64_t>(available), res.state_.remaining_data_frame_bytes));
                res.body_storage.append(buffer.substr(cursor, to_consume));
                cursor += to_consume;
                res.state_.cursor = cursor;
                res.state_.remaining_data_frame_bytes -= to_consume;
                if (res.state_.remaining_data_frame_bytes == 0) {
                    res.state_.in_data_frame = false;
                }
                continue;
            }

            const std::string_view remaining = buffer.substr(cursor);
            frame_header hdr;
            std::size_t hdr_bytes = 0;
            if (!parse_frame_header(remaining, hdr, hdr_bytes)) {
                break;
            }

            if (is_reserved_frame_type(hdr.type)) {
                res.state_.reset();
                return result::error;
            }

            if (hdr.type == static_cast<uint64_t>(frame_type::DATA)) {
                if (!res.state_.headers_received) {
                    res.state_.reset();
                    return result::error;
                }
                cursor += hdr_bytes;
                res.state_.cursor = cursor;
                res.state_.in_data_frame = true;
                res.state_.remaining_data_frame_bytes = hdr.length;

                const std::size_t available = buffer.size() - cursor;
                const auto to_consume = static_cast<std::size_t>(
                    std::min(static_cast<uint64_t>(available), res.state_.remaining_data_frame_bytes));
                res.body_storage.append(buffer.substr(cursor, to_consume));
                cursor += to_consume;
                res.state_.cursor = cursor;
                res.state_.remaining_data_frame_bytes -= to_consume;
                if (res.state_.remaining_data_frame_bytes == 0) {
                    res.state_.in_data_frame = false;
                }
            } else if (hdr.type == static_cast<uint64_t>(frame_type::HEADERS)) {
                if (res.state_.headers_received) {
                    if (hdr_bytes + hdr.length > remaining.size()) {
                        break; // wait for the whole trailing HEADERS frame
                    }
                    cursor += hdr_bytes + hdr.length;
                    res.state_.cursor = cursor;
                    continue;
                }

                if (hdr_bytes + hdr.length > remaining.size()) {
                    break;
                }

                const std::string_view block = remaining.substr(hdr_bytes, hdr.length);
                std::vector<std::pair<std::string, std::string> > decoded;
                if (bool is_blocked = false; !dec.decode_header_block(block, decoded, is_blocked, max_field_section_size)) {
                    if (is_blocked) {
                        return result::incomplete;
                    }
                    res.state_.reset();
                    return result::error;
                }

                uint64_t section_size = 0;
                for (const auto &[name, val] : decoded) {
                    section_size += name.size() + val.size() + 32;
                    if (max_field_section_size > 0 && section_size > max_field_section_size) {
                        res.state_.reset();
                        return result::error;
                    }
                }

                bool has_status = false;
                bool seen_regular_header = false;

                for (auto &[name, val]: decoded) {
                    for (const char c: name) {
                        if (std::isupper(static_cast<unsigned char>(c))) {
                            res.state_.reset();
                            return result::error;
                        }
                    }

                    if (name.starts_with(':')) {
                        if (seen_regular_header) {
                            res.state_.reset();
                            return result::error;
                        }
                        if (name == ":status") {
                            if (has_status) {
                                res.state_.reset();
                                return result::error;
                            }
                            has_status = true;
                            if (const auto sc = std::strtoul(val.c_str(), nullptr, 10); sc != 0) {
                                res.status_code = static_cast<unsigned int>(sc);
                            }
                        } else {
                            res.state_.reset();
                            return result::error;
                        }
                    } else {
                        seen_regular_header = true;
                        if (name == "connection" || name == "keep-alive" ||
                            name == "proxy-connection" || name == "transfer-encoding" ||
                            name == "upgrade") {
                            res.state_.reset();
                            return result::error;
                        }
                        if (name == "content-length") {
                            uint64_t cl = 0;
                            if (!parse_content_length(val, cl) ||
                                (res.state_.has_content_length && res.state_.content_length != cl)) {
                                res.state_.reset();
                                return result::error;
                            }
                            res.state_.has_content_length = true;
                            res.state_.content_length = cl;
                        }
                        res.headers_storage.emplace_back(std::move(name), std::move(val));
                    }
                }

                if (!has_status) {
                    res.state_.reset();
                    return result::error;
                }

                res.state_.headers_received = true;
                cursor += hdr_bytes + hdr.length;
                res.state_.cursor = cursor;
            } else if (hdr.type == static_cast<uint64_t>(frame_type::SETTINGS) ||
                       hdr.type == static_cast<uint64_t>(frame_type::CANCEL_PUSH) ||
                       hdr.type == static_cast<uint64_t>(frame_type::GOAWAY) ||
                       hdr.type == static_cast<uint64_t>(frame_type::MAX_PUSH_ID)) {
                res.state_.reset();
                return result::error;
            } else {
                if (hdr_bytes + hdr.length > remaining.size()) {
                    break;
                }
                cursor += hdr_bytes + hdr.length;
                res.state_.cursor = cursor;
            }
        }

        if (!res.state_.headers_received) return result::incomplete;
        if (res.state_.in_data_frame) return result::incomplete;

        if (res.state_.has_content_length) {
            if (res.body_storage.size() < res.state_.content_length) {
                return result::incomplete;
            }
            if (res.body_storage.size() > res.state_.content_length) {
                res.state_.reset();
                return result::error;
            }
        }

        bytes_consumed = res.state_.cursor;
        res.status_text = http1codec::status_text_for(res.status_code);
        res.rebase(res);
        res.state_.reset();
        return result::success;
    }

    parser::result parser::parse_response(
        const std::string_view buffer,
        response &res,
        std::size_t &bytes_consumed,
        qpack::dynamic_table &dt) {
        return parse_response(buffer, res, bytes_consumed, dt, default_max_field_section_size());
    }

    parser::result parser::parse_response(
        const std::string_view buffer,
        response &res,
        std::size_t &bytes_consumed) {
        qpack::dynamic_table local_dt;
        return parse_response(buffer, res, bytes_consumed, local_dt, default_max_field_section_size());
    }

    parser::result parser::parse_response(
        const std::string_view buffer,
        response &res,
        std::size_t &bytes_consumed,
        connection_context &ctx) {
        return parse_response(buffer, res, bytes_consumed, ctx.decode_table, ctx.max_field_section_size);
    }

    // ─── http3::encoder ─────────────────────────────────────────────────────────────

    std::string encoder::encode_frame(const frame_type type, const std::string_view payload) {
        std::string out;
        VarInt::encode(static_cast<uint64_t>(type), out);
        VarInt::encode(payload.size(), out);
        out.append(payload);
        return out;
    }

    std::string encoder::encode_data_frame(const std::string_view payload) {
        return encode_frame(frame_type::DATA, payload);
    }

    std::string encoder::serialize_request(const request &req, const qpack::dynamic_table *dt) {
        std::vector<header> extended;
        if (!req.protocol.empty()) {
            extended.reserve(req.headers.size() + 1);
            extended.emplace_back(":protocol", req.protocol);
            extended.insert(extended.end(), req.headers.begin(), req.headers.end());
        }
        const std::string header_block = qpack::encoder::encode_request_headers(
            req.method_type,
            req.target,
            req.scheme,
            req.authority,
            req.protocol.empty() ? req.headers : extended,
            dt
        );

        std::string out = encode_frame(frame_type::HEADERS, header_block);
        if (!req.body.empty()) {
            out += encode_data_frame(req.body);
        }
        return out;
    }

    std::string encoder::serialize_response(const response &res, qpack::dynamic_table *dt) {
        std::string out;
        serialize_into(res, out, dt);
        return out;
    }

    std::string encoder::serialize(const response &res) {
        return serialize_response(res);
    }

    std::string encoder::serialize(const request &req) {
        return serialize_request(req);
    }

    std::string encoder::serialize_settings(
        const std::vector<std::pair<settings_parameter, uint64_t> > &settings) {
        std::string payload;
        for (const auto &[param, val]: settings) {
            VarInt::encode(static_cast<uint64_t>(param), payload);
            VarInt::encode(val, payload);
        }
        return encode_frame(frame_type::SETTINGS, payload);
    }

    std::string encoder::format_chunk(const std::string_view data) {
        return encode_data_frame(data);
    }

    // ─── http3::decoder ─────────────────────────────────────────────────────────────

    parser::result decoder::decode_response(
        const std::string_view buffer,
        response &res,
        std::size_t &bytes_consumed,
        qpack::dynamic_table &dt) {
        return parser::parse_response(buffer, res, bytes_consumed, dt);
    }

    parser::result decoder::decode_response(
        const std::string_view buffer,
        response &res,
        std::size_t &bytes_consumed) {
        return parser::parse_response(buffer, res, bytes_consumed);
    }

    parser::result decoder::decode_response(
        const std::string_view buffer,
        response &res,
        std::size_t &bytes_consumed,
        connection_context &ctx) {
        return parser::parse_response(buffer, res, bytes_consumed, ctx.decode_table);
    }

    std::string decoder::dechunk(const std::string_view chunked_raw) {
        return std::string(chunked_raw);
    }
} // namespace wavex::protos::http::http3

#endif // WAVEX_HAS_SSL
