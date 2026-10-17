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
 *  - RFC 9114: HTTP/3 Binary Framing Layer (DATA, HEADERS, SETTINGS, CANCEL_PUSH, GOAWAY, MAX_PUSH_ID)
 *  - RFC 9204: QPACK Header Compression Engine (99-entry Static Table, Dynamic Table with
 *              Required Insert Count & Base indexing, Encoder/Decoder Sub-stream Instructions)
 *  - WaveX Codec Concept integration: seamless compatibility with HttpRequest, HttpResponse, and Server.
 */

#pragma once

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

#if defined(NO_ERROR)
#undef NO_ERROR
#endif

#include <string_view>
#include <vector>
#include <deque>
#include <array>
#include <string>
#include <utility>
#include <algorithm>
#include <asio/as_tuple.hpp>
#include <asio/buffer.hpp>
#include <asio/use_awaitable.hpp>
#include <wavex/protos/http/Methods.hpp>
#include <wavex/protos/http/http1codec.hpp>
#include <wavex/Network/QUIC/VarInt.hpp>

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

        // ─── Reserved HTTP/2 Frame Types (RFC 9114 §7.2.8 & §11.2.1) ──────────────
        enum class reserved_frame_type : uint64_t {
            H2_PRIORITY = 0x02,
            H2_PING = 0x06,
            H2_WINDOW_UPDATE = 0x08,
            H2_CONTINUATION = 0x09
        };

        [[nodiscard]] constexpr bool is_reserved_frame_type(const uint64_t type) noexcept {
            return type == static_cast<uint64_t>(reserved_frame_type::H2_PRIORITY) ||
                   type == static_cast<uint64_t>(reserved_frame_type::H2_PING) ||
                   type == static_cast<uint64_t>(reserved_frame_type::H2_WINDOW_UPDATE) ||
                   type == static_cast<uint64_t>(reserved_frame_type::H2_CONTINUATION);
        }

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

            constexpr frame_header(const uint64_t t, const uint64_t l) noexcept : type(t), length(l) {
            }

            ~frame_header() = default;
        };

        // ─── QPACK (RFC 9204) Header Compression Engine ───────────────────────────
        namespace qpack {
            struct static_entry {
                std::string_view name;
                std::string_view value;
            };

            // RFC 9204 Appendix A — QPACK Static Table (0-indexed, entries 0..98)
            extern const std::array<static_entry, 99> STATIC_TABLE;

            /**
             * @brief Locate static table entry matching a header name and optional value.
             */
            [[nodiscard]] std::pair<std::size_t, bool> find_static(
                std::string_view name,
                std::string_view value = "") noexcept;

            /**
             * @brief QPACK Dynamic Table (RFC 9204 §3.2).
             *
             * Implements FIFO dynamic entry storage with:
             *  - Tracking of total cumulative insertions (insert_count / total_inserts).
             *  - Absolute index mapping: entry at absolute index A is retained until evicted.
             *  - Relative index calculation: relative index R against Base refers to absolute index (Base - 1 - R).
             *  - Required Insert Count (RIC) blocking validation: guarantees out-of-order stream safety.
             */
            class dynamic_table {
            public:
                // ─── 1. Nested Types & Definitions (TOP) ───────────────────────────
                struct entry {
                    // ─── 2. Member Variables (SECOND - Minimal Padding) ────────────
                    std::string name{};
                    std::string value{};
                    uint64_t absolute_index{0};

                    // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────
                    entry() = default;

                    entry(std::string n, std::string v, const uint64_t abs_idx)
                        : name(std::move(n)), value(std::move(v)), absolute_index(abs_idx) {
                    }

                    ~entry() = default;

                    entry(const entry &) = default;

                    entry &operator=(const entry &) = default;

                    entry(entry &&) noexcept = default;

                    entry &operator=(entry &&) noexcept = default;

                    // ─── 4. Member Functions (LAST) ────────────────────────────────
                    [[nodiscard]] std::size_t size() const noexcept {
                        return name.size() + value.size() + 32;
                    }
                };

            private:
                // ─── 2. Member Variables (SECOND - Minimal Padding) ────────────────
                std::vector<entry> entries_{};
                uint64_t total_inserts_{0};
                std::size_t current_size_{0};
                std::size_t max_capacity_{4096};
                std::size_t max_capacity_limit_{4096};

            public:
                // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
                explicit dynamic_table(const std::size_t max_cap = 4096,
                                       const std::size_t max_cap_limit = 4096) noexcept
                    : max_capacity_(max_cap),
                      max_capacity_limit_(std::max(max_cap, max_cap_limit)) {
                }

                ~dynamic_table() = default;

                dynamic_table(const dynamic_table &) = default;

                dynamic_table &operator=(const dynamic_table &) = default;

                dynamic_table(dynamic_table &&) noexcept = default;

                dynamic_table &operator=(dynamic_table &&) noexcept = default;

                // ─── 4. Member Functions (LAST) ────────────────────────────────────
                bool set_max_capacity(std::size_t cap) noexcept;

                void set_max_capacity_limit(std::size_t limit) noexcept;

                [[nodiscard]] std::size_t max_capacity_limit() const noexcept { return max_capacity_limit_; }
                [[nodiscard]] std::size_t max_capacity() const noexcept { return max_capacity_; }
                [[nodiscard]] std::size_t current_size() const noexcept { return current_size_; }
                [[nodiscard]] uint64_t total_inserts() const noexcept { return total_inserts_; }
                [[nodiscard]] std::size_t count() const noexcept { return entries_.size(); }
                [[nodiscard]] bool empty() const noexcept { return entries_.empty(); }

                uint64_t insert(std::string name, std::string value);

                [[nodiscard]] bool is_blocked(const uint64_t required_insert_count) const noexcept {
                    return total_inserts_ < required_insert_count;
                }

                [[nodiscard]] const entry *get_by_absolute_index(uint64_t abs_idx) const noexcept;

                [[nodiscard]] const entry *get_relative(uint64_t base, uint64_t relative_idx) const noexcept;

                [[nodiscard]] const entry *get_post_base(uint64_t base, uint64_t post_base_idx) const noexcept;

                [[nodiscard]] std::tuple<uint64_t, bool, bool> find(
                    std::string_view name,
                    std::string_view value = "") const noexcept;

            private:
                void evict() noexcept;
            };

            /**
             * @brief QPACK Encoder: Serializes headers into QPACK wire blocks & encoder stream instructions.
             */
            class encoder {
            public:
                // ─── Encoder Stream Instructions (RFC 9204 §4.3) ───────────────────
                static void encode_set_capacity(std::string &out, uint64_t capacity);

                static void encode_insert_with_name_ref(
                    std::string &out,
                    uint64_t name_idx,
                    bool is_static,
                    std::string_view val);

                static void encode_insert_with_literal_name(
                    std::string &out,
                    std::string_view name,
                    std::string_view val);

                static void encode_duplicate(std::string &out, uint64_t index);

                // ─── Decoder Stream Instructions (RFC 9204 §4.4) ───────────────────
                static void encode_section_ack(std::string &out, uint64_t stream_id);

                static void encode_stream_cancel(std::string &out, uint64_t stream_id);

                static void encode_insert_count_increment(std::string &out, uint64_t increment);

                // ─── Header Field Section (Field Block) Encoding (RFC 9204 §4.5) ───

                /**
                 * @brief Encode Request Header block with optional Dynamic Table reference.
                 */
                static std::string encode_request_headers(
                    http::method m,
                    std::string_view target,
                    std::string_view scheme,
                    std::string_view authority,
                    const std::vector<header> &headers,
                    const dynamic_table *dt = nullptr);

                /**
                 * @brief Encode Response Header block.
                 */
                static std::string encode_response_headers(
                    unsigned int status_code,
                    const std::vector<header> &headers,
                    dynamic_table *dt = nullptr);

                // Encoded Field Section Prefix (RFC 9204 §4.5.1)
                static void encode_prefix(std::string &out, uint64_t ric, uint64_t base,
                                          uint64_t max_table_capacity = 4096);

                // Indexed Field Line — Static Table (RFC 9204 §4.5.2): 1 1 Index (6-bit prefix)
                static void encode_indexed_static(std::string &out, std::size_t idx);

                // Indexed Field Line — Dynamic Table (RFC 9204 §4.5.2): 1 0 Relative_Index (6-bit prefix)
                static void encode_indexed_dynamic(std::string &out, uint64_t rel_idx);

                // Literal Field Line With Name Reference (RFC 9204 §4.5.4):
                // 0 1 N T Index (4-bit prefix) + Value
                static void encode_literal_with_name_ref(
                    std::string &out,
                    uint64_t idx,
                    bool is_static,
                    std::string_view val);

                // Literal Field Line With Literal Name (RFC 9204 §4.5.6):
                // 0 0 1 N H (3-bit prefix 0x20) + Name + Value
                static void encode_literal_new_name(
                    std::string &out,
                    std::string_view name,
                    std::string_view val);

                // Indexed Field Line with Post-Base Index (RFC 9204 §4.5.3):
                // 0 0 0 1 Index (4-bit prefix, 0x10)
                static void encode_indexed_post_base(std::string &out, uint64_t post_base_idx);

                // Literal Field Line with Post-Base Name Reference (RFC 9204 §4.5.5):
                // 0 0 0 0 N Name_Index (3-bit prefix, 0x00) + Value String
                static void encode_literal_post_base_name_ref(
                    std::string &out,
                    uint64_t post_base_name_idx,
                    std::string_view val);
            };

            /**
             * @brief QPACK Decoder: Parses QPACK binary header blocks into header pairs,
             * and processes encoder sub-stream instructions.
             */
            class decoder {
            private:
                // ─── 2. Member Variables (SECOND - Minimal Padding) ────────────────
                dynamic_table &dt_;

            public:
                // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
                explicit decoder(dynamic_table &dt) noexcept : dt_(dt) {
                }

                // ─── 4. Member Functions (LAST) ────────────────────────────────────
                /**
                 * @brief Apply a single instruction received from the QPACK encoder sub-stream (RFC 9204 §4.3).
                 */
                bool apply_encoder_instruction(std::string_view in, std::size_t &cursor) const;

                /**
                 * @brief Decode Encoded Field Section (Header Block) into header pairs.
                 * If the block references dynamic table entries beyond current insert count,
                 * is_blocked is set to true and false is returned.
                 */
                bool decode_header_block(
                    std::string_view block,
                    std::vector<std::pair<std::string, std::string> > &out_headers,
                    bool &is_blocked,
                    uint64_t max_field_section_size = 0) const;

                bool decode_header_block(
                    std::string_view block,
                    std::vector<std::pair<std::string, std::string> > &out_headers,
                    uint64_t max_field_section_size = 0) const;
            };
        } // namespace qpack

        /**
         * @brief Connection context for HTTP/3 sessions (scoped to QUIC connection lifetime).
         */
        struct connection_context {
            // ─── 2. Member Variables (SECOND - Minimal Padding) ────────────────
            qpack::dynamic_table decode_table{};
            uint64_t max_field_section_size{65536};
            uint64_t peer_max_field_section_size{(std::numeric_limits<uint64_t>::max)()};
            uint64_t peer_qpack_max_table_capacity{0};
            uint64_t peer_qpack_blocked_streams{0};
            uint64_t goaway_stream_id{0};
            bool settings_sent{false};
            bool settings_received{false};
            bool goaway_received{false};
        };

        // ─── HTTP/3 Messages ───────────────────────────────────────────────────────

        /**
         * @brief HTTP/3 Request Message (inherits protocol-agnostic message_base).
         */
        struct request : public message_base {
            // ─── 1. Nested Types (TOP) ─────────────────────────────────────────
            struct parser_state {
                // ─── 2. Member Variables (SECOND - Minimal Padding) ────
                uint64_t content_length{0};
                uint64_t remaining_data_frame_bytes{0};
                std::size_t cursor{0};
                bool headers_received{false};
                bool has_content_length{false};
                bool in_data_frame{false};

                // ─── 4. Member Functions (LAST) ────────────────────────
                void reset() noexcept {
                    content_length = 0;
                    remaining_data_frame_bytes = 0;
                    cursor = 0;
                    headers_received = false;
                    has_content_length = false;
                    in_data_frame = false;
                }
            };

            // ─── 2. Member Variables (SECOND - Minimal Padding) ────────────────
            std::string_view target{};
            std::string_view scheme{"https"};
            std::string_view authority{};
            std::string target_storage{};
            std::string scheme_storage{};
            std::string authority_storage{};
            std::string body_storage{};
            std::vector<std::pair<std::string, std::string> > headers_storage{};
            parser_state state_{};
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
                  state_(other.state_),
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
                  state_(other.state_),
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
                    state_ = other.state_;
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
                    state_ = other.state_;
                    stream_id = other.stream_id;
                    method_type = other.method_type;
                    rebase(other);
                }
                return *this;
            }

            // ─── 4. Member Functions (LAST) ────────────────────────────────────
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
         * @brief HTTP/3 Response Message (inherits protocol-agnostic message_base).
         */
        struct response : public message_base {
            // ─── 1. Nested Types (TOP) ─────────────────────────────────────────
            using parser_state = request::parser_state;

            // ─── 2. Member Variables (SECOND - Minimal Padding) ────────────────
            std::string_view status_text{"OK"};
            std::string body_storage{};
            std::vector<std::pair<std::string, std::string> > headers_storage{};
            parser_state state_{};
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
                  state_(other.state_),
                  stream_id(other.stream_id),
                  status_code(other.status_code) {
                rebase(other);
            }

            response(response &&other) noexcept
                : message_base(std::move(other)),
                  status_text(other.status_text),
                  body_storage(std::move(other.body_storage)),
                  headers_storage(std::move(other.headers_storage)),
                  state_(other.state_),
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
                    state_ = other.state_;
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
                    state_ = other.state_;
                    stream_id = other.stream_id;
                    status_code = other.status_code;
                    rebase(other);
                }
                return *this;
            }

            // ─── 4. Member Functions (LAST) ────────────────────────────────────
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

        // ─── HTTP/3 Parser & Encoder ───────────────────────────────────────────────

        class parser {
        public:
            // ─── 1. Nested Types (TOP) ─────────────────────────────────────────
            enum class result { success, incomplete, error };

            // ─── 4. Member Functions (LAST) ────────────────────────────────────
            [[nodiscard]] static uint64_t default_max_field_section_size() noexcept;
            static void set_default_max_field_section_size(uint64_t size) noexcept;

            [[nodiscard]] static constexpr bool is_reserved_frame(const uint64_t type) noexcept {
                return is_reserved_frame_type(type);
            }

            [[nodiscard]] static bool parse_frame_header(
                std::string_view buffer,
                frame_header &hdr,
                std::size_t &bytes_consumed);

            [[nodiscard]] static result parse_frame(
                std::string_view buffer,
                frame_header &hdr,
                std::string_view &payload,
                std::size_t &bytes_consumed);

            [[nodiscard]] static result parse_request(
                std::string_view buffer,
                request &req,
                std::size_t &bytes_consumed,
                qpack::dynamic_table &dt,
                uint64_t max_field_section_size);

            [[nodiscard]] static result parse_request(
                std::string_view buffer,
                request &req,
                std::size_t &bytes_consumed,
                qpack::dynamic_table &dt);

            [[nodiscard]] static result parse_request(
                std::string_view buffer,
                request &req,
                std::size_t &bytes_consumed);

            [[nodiscard]] static result parse_request(
                std::string_view buffer,
                request &req,
                std::size_t &bytes_consumed,
                connection_context &ctx);

            [[nodiscard]] static result parse_response(
                std::string_view buffer,
                response &res,
                std::size_t &bytes_consumed,
                qpack::dynamic_table &dt,
                uint64_t max_field_section_size);

            [[nodiscard]] static result parse_response(
                std::string_view buffer,
                response &res,
                std::size_t &bytes_consumed,
                qpack::dynamic_table &dt);

            [[nodiscard]] static result parse_response(
                std::string_view buffer,
                response &res,
                std::size_t &bytes_consumed);

            [[nodiscard]] static result parse_response(
                std::string_view buffer,
                response &res,
                std::size_t &bytes_consumed,
                connection_context &ctx);
        };

        class encoder {
        public:
            // ─── 4. Member Functions (LAST) ────────────────────────────────────
            static std::string encode_frame(frame_type type, std::string_view payload);

            static std::string encode_data_frame(std::string_view payload);

            static std::string serialize_request(const request &req, const qpack::dynamic_table *dt = nullptr);

            template<typename Out>
            static void serialize_into(const response &res, Out &out, qpack::dynamic_table *dt = nullptr) {
                const std::string header_block = qpack::encoder::encode_response_headers(
                    res.status_code,
                    res.headers,
                    dt
                );

                const std::size_t est = 16 + header_block.size() + (!res.body.empty() ? 16 + res.body.size() : 0);
                if (out.capacity() < out.size() + est) {
                    out.reserve(out.size() + est);
                }

                uint8_t vi[8];
                std::size_t n = VarInt::encode(static_cast<uint64_t>(frame_type::HEADERS), vi, sizeof(vi));
                out.append(reinterpret_cast<const char *>(vi), n);
                n = VarInt::encode(header_block.size(), vi, sizeof(vi));
                out.append(reinterpret_cast<const char *>(vi), n);
                out.append(header_block);

                if (!res.body.empty()) {
                    n = VarInt::encode(static_cast<uint64_t>(frame_type::DATA), vi, sizeof(vi));
                    out.append(reinterpret_cast<const char *>(vi), n);
                    n = VarInt::encode(res.body.size(), vi, sizeof(vi));
                    out.append(reinterpret_cast<const char *>(vi), n);
                    out.append(res.body);
                }
            }

            static std::string serialize_response(const response &res, qpack::dynamic_table *dt = nullptr);

            static std::string serialize(const response &res);

            static std::string serialize(const request &req);

            static std::string
            serialize_settings(const std::vector<std::pair<settings_parameter, uint64_t> > &settings);

            static std::string format_chunk(std::string_view data);

            [[nodiscard]] static constexpr std::string_view format_terminal_chunk() noexcept {
                return {};
            }
        };

        class decoder {
        public:
            // ─── 4. Member Functions (LAST) ────────────────────────────────────
            static parser::result decode_response(
                std::string_view buffer,
                response &res,
                std::size_t &bytes_consumed,
                qpack::dynamic_table &dt);

            static parser::result decode_response(
                std::string_view buffer,
                response &res,
                std::size_t &bytes_consumed);

            static parser::result decode_response(
                std::string_view buffer,
                response &res,
                std::size_t &bytes_consumed,
                connection_context &ctx);

            static std::string dechunk(std::string_view chunked_raw);
        };

        /**
         * @class session_handler
         * @brief Handles HTTP/3 unidirectional streams (Control, QPACK Encoder, QPACK Decoder per RFC 9114/9204).
         */
        class session_handler {
        public:
            template<typename Stream>
            static asio::awaitable<void> handle_unidirectional_stream(
                std::shared_ptr<Stream> stream,
                const std::shared_ptr<connection_context> ctx) {
                if (!stream || !ctx) co_return;

                std::string stream_buf;
                char buf[1024];

                // 1. Read unidirectional stream type (RFC 9114 §6.2)
                uint64_t stream_type = 0;
                while (stream->is_open()) {
                    if (std::size_t offset = 0; VarInt::decode(stream_buf, offset, stream_type)) {
                        stream_buf.erase(0, offset);
                        break;
                    }
                    auto [ec, n] = co_await stream->async_read_some(
                        asio::buffer(buf), asio::as_tuple(asio::use_awaitable));
                    if (ec || n == 0) co_return;
                    stream_buf.append(buf, n);
                }

                if (stream_type == 0x00) {
                    // Control Stream (RFC 9114 §6.2.1)
                    while (stream->is_open()) {
                        frame_header hdr;
                        std::string_view payload;
                        std::size_t frame_bytes = 0;
                        const auto res = parser::parse_frame(stream_buf, hdr, payload, frame_bytes);
                        if (res == parser::result::incomplete) {
                            auto [ec, n] = co_await stream->async_read_some(
                                asio::buffer(buf), asio::as_tuple(asio::use_awaitable));
                            if (ec || n == 0) break;
                            stream_buf.append(buf, n);
                            continue;
                        }
                        if (res == parser::result::error) {
                            break;
                        }

                        if (is_reserved_frame_type(hdr.type) ||
                            hdr.type == static_cast<uint64_t>(frame_type::DATA) ||
                            hdr.type == static_cast<uint64_t>(frame_type::HEADERS)) {
                            // Connection error H3_FRAME_UNEXPECTED (RFC 9114 §7.2.1, §7.2.2, §7.2.8)
                            break;
                        }

                        if (hdr.type == static_cast<uint64_t>(frame_type::SETTINGS)) {
                            // Parse SETTINGS frame payload (pairs of VarInt: identifier and value)
                            std::size_t s_cursor = 0;
                            while (s_cursor < payload.size()) {
                                uint64_t id = 0, val = 0;
                                if (!VarInt::decode(payload, s_cursor, id)) break;
                                if (!VarInt::decode(payload, s_cursor, val)) break;

                                if (id == 0x01) {
                                    // SETTINGS_QPACK_MAX_TABLE_CAPACITY (peer's advertised capacity limit)
                                    ctx->peer_qpack_max_table_capacity = val;
                                } else if (id == 0x06) {
                                    // SETTINGS_MAX_FIELD_SECTION_SIZE
                                    ctx->max_field_section_size = val;
                                } else if (id == 0x07) {
                                    // SETTINGS_QPACK_BLOCKED_STREAMS
                                    ctx->peer_qpack_blocked_streams = val;
                                }
                            }
                            ctx->settings_received = true;
                        } else if (hdr.type == static_cast<uint64_t>(frame_type::GOAWAY)) {
                            std::size_t g_cursor = 0;
                            if (uint64_t goaway_sid = 0; VarInt::decode(payload, g_cursor, goaway_sid)) {
                                ctx->goaway_stream_id = goaway_sid;
                            }
                            ctx->goaway_received = true;
                        }

                        stream_buf.erase(0, frame_bytes);
                    }
                } else if (stream_type == 0x02) {
                    // QPACK Encoder Stream (RFC 9204 §4.2)
                    const qpack::decoder dec(ctx->decode_table);
                    while (stream->is_open()) {
                        std::size_t cursor = 0;
                        while (cursor < stream_buf.size()) {
                            const std::size_t prev_cursor = cursor;
                            if (!dec.apply_encoder_instruction(stream_buf, cursor)) {
                                cursor = prev_cursor;
                                break;
                            }
                        }
                        if (cursor > 0) {
                            stream_buf.erase(0, cursor);
                        }

                        auto [ec, n] = co_await stream->async_read_some(
                            asio::buffer(buf), asio::as_tuple(asio::use_awaitable));
                        if (ec || n == 0) break;
                        stream_buf.append(buf, n);
                    }
                } else if (stream_type == 0x03) {
                    // QPACK Decoder Stream (RFC 9204 §4.2)
                    while (stream->is_open()) {
                        auto [ec, n] = co_await stream->async_read_some(
                            asio::buffer(buf), asio::as_tuple(asio::use_awaitable));
                        if (ec || n == 0) break;
                    }
                }
                co_return;
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
        using session_handler = http3::session_handler;
        using dynamic_table = http3::qpack::dynamic_table;
        using parser = http3::parser;
        using encoder = http3::encoder;
        using decoder = http3::decoder;
        using result = http3::parser::result;
        using reserved_frame_type = http3::reserved_frame_type;

        static void set_default_max_field_section_size(const uint64_t size) noexcept {
            parser::set_default_max_field_section_size(size);
        }

        [[nodiscard]] static uint64_t default_max_field_section_size() noexcept {
            return parser::default_max_field_section_size();
        }

        [[nodiscard]] static constexpr bool is_reserved_frame(const uint64_t type) noexcept {
            return http3::is_reserved_frame_type(type);
        }

        static std::string serialize(const response &res) {
            return encoder::serialize_response(res);
        }

        static std::string serialize_request(const request &req) {
            return encoder::serialize_request(req);
        }

        [[nodiscard]] static std::string_view status_text_for(const unsigned int code) noexcept {
            return http1codec::status_text_for(code);
        }

        static result parse_stream(const std::string_view buffer, request &req, std::size_t &bytes_consumed,
                                   dynamic_table &dt, const uint64_t max_field_section_size) {
            return parser::parse_request(buffer, req, bytes_consumed, dt, max_field_section_size);
        }

        static result parse_stream(const std::string_view buffer, request &req, std::size_t &bytes_consumed,
                                   dynamic_table &dt) {
            return parser::parse_request(buffer, req, bytes_consumed, dt);
        }

        static result parse_stream(const std::string_view buffer, request &req, std::size_t &bytes_consumed,
                                   connection_context &ctx) {
            return parser::parse_request(buffer, req, bytes_consumed, ctx);
        }

        static result parse_stream(const std::string_view buffer, request &req, std::size_t &bytes_consumed) {
            return parser::parse_request(buffer, req, bytes_consumed);
        }

        static result parse_request(const std::string_view buffer, request &req, std::size_t &bytes_consumed,
                                    dynamic_table &dt, const uint64_t max_field_section_size) {
            return parser::parse_request(buffer, req, bytes_consumed, dt, max_field_section_size);
        }

        static result parse_request(const std::string_view buffer, request &req, std::size_t &bytes_consumed,
                                    dynamic_table &dt) {
            return parser::parse_request(buffer, req, bytes_consumed, dt);
        }

        static result parse_request(const std::string_view buffer, request &req, std::size_t &bytes_consumed) {
            return parser::parse_request(buffer, req, bytes_consumed);
        }

        static result parse_request(const std::string_view buffer, request &req, std::size_t &bytes_consumed,
                                    connection_context &ctx) {
            return parser::parse_request(buffer, req, bytes_consumed, ctx);
        }

        static result parse_response(const std::string_view buffer, response &res, std::size_t &bytes_consumed,
                                     dynamic_table &dt, const uint64_t max_field_section_size) {
            return parser::parse_response(buffer, res, bytes_consumed, dt, max_field_section_size);
        }

        static result parse_response(const std::string_view buffer, response &res, std::size_t &bytes_consumed,
                                     dynamic_table &dt) {
            return parser::parse_response(buffer, res, bytes_consumed, dt);
        }

        static result parse_response(const std::string_view buffer, response &res, std::size_t &bytes_consumed,
                                     connection_context &ctx) {
            return parser::parse_response(buffer, res, bytes_consumed, ctx);
        }

        static result parse_response(const std::string_view buffer, response &res, std::size_t &bytes_consumed) {
            return parser::parse_response(buffer, res, bytes_consumed);
        }

        static result decode_response(const std::string_view buffer, response &res, std::size_t &bytes_consumed,
                                      dynamic_table &dt) {
            return decoder::decode_response(buffer, res, bytes_consumed, dt);
        }

        static result decode_response(const std::string_view buffer, response &res, std::size_t &bytes_consumed,
                                      connection_context &ctx) {
            return decoder::decode_response(buffer, res, bytes_consumed, ctx.decode_table);
        }

        static result decode_response(const std::string_view buffer, response &res, std::size_t &bytes_consumed) {
            return decoder::decode_response(buffer, res, bytes_consumed);
        }

        static std::string format_chunk(const std::string_view data) {
            return encoder::format_chunk(data);
        }

        template<typename Out>
        static void serialize_into(const response &res, Out &out) {
            encoder::serialize_into(res, out);
        }

        [[nodiscard]] static constexpr std::string_view format_terminal_chunk() noexcept {
            return encoder::format_terminal_chunk();
        }

        static std::string dechunk(const std::string_view chunked_raw) {
            return decoder::dechunk(chunked_raw);
        }
    };
} // namespace wavex::protos::http

#endif // WAVEX_HAS_SSL
