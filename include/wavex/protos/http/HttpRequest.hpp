// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file HttpRequest.hpp
 * @brief Concrete HTTP/1.x implementation of base::Request.
 *
 * Supports both server-side request parsing (from network buffer) and
 * client-side request construction & serialization (for sending to 3rd-party services).
 */

#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <utility>
#include <optional>
#include <type_traits>

#ifndef ASIO_HAS_CO_AWAIT
#define ASIO_HAS_CO_AWAIT 1
#endif
#include <asio/awaitable.hpp>

#include <wavex/Base/Request.hpp>
#include <wavex/Base/Url.hpp>
#include <wavex/Base/Uri.hpp>

#include <wavex/protos/http/http1codec.hpp>
#include <wavex/Utils/BinaryFile.hpp>
#include <wavex/Utils/Multipart.hpp>
#include <wavex/Utils/Compression.hpp>

namespace wavex::protos::http {
    /**
     * @class HttpRequest
     * @brief HTTP request parameterized on Codec — supports both server-side parsing and client-side creation.
     * @tparam Codec Protocol codec defining parser, encoder, decoder, request, and response types.
     */
    template<typename Codec = http1codec>
    class HttpRequest final : public base::Request {
    public:
        // ─── 1. Nested Types & Definitions (TOP) ───────────────────────────
        using codec_type = Codec;
        using parser_type = Codec::parser;
        using encoder_type = Codec::encoder;
        using request_type = Codec::request;

        using Request::query;
        using Request::params;
        using Request::param;
        using Request::query_param;

        /// Maximum query parameters accepted per request (hard cap).
        /// Requests exceeding this are rejected with 431 in Server::handle_connection.
        static constexpr std::size_t kMaxQueryParams = 64;

    private:
        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        std::string buffer_{}; ///< owned receive buffer (server)
        request_type parsed_{}; ///< zero-copy views
        std::string path_{}; ///< extracted path
        std::string raw_target_owned_{}; ///< owned full target string (client)
        std::string path_target_owned_{}; ///< owned path + query string
        std::string body_owned_{}; ///< owned body string (client)
        /// Contiguous linear buffer owning all decoded query key-value characters.
        /// FlatMap `query` holds string_views slicing directly into this buffer.
        std::string query_decoded_buf_{};
        std::vector<std::pair<std::string, std::string> > headers_owned_{}; ///< owned headers (client)
        size_t consumed_{0}; ///< byte count consumed by parser
        bool query_param_overflow_{false}; ///< set when >kMaxQueryParams were present

    public:
        // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
        HttpRequest() = default;

        ~HttpRequest() = default;

        /// Construct from a raw buffer (server side).
        explicit HttpRequest(std::string buffer)
            : buffer_(std::move(buffer)) {
        }

        /// Construct with method and target URL/path (client side).
        HttpRequest(const http::method m, const std::string_view target) {
            parsed_.method_type = m;
            raw_target_owned_ = std::string(target);
            extract_path_query(raw_target_owned_);
        }

        HttpRequest(const HttpRequest &other)
            : Request(other),
              buffer_(other.buffer_),
              parsed_(other.parsed_),
              path_(other.path_),
              raw_target_owned_(other.raw_target_owned_),
              path_target_owned_(other.path_target_owned_),
              body_owned_(other.body_owned_),
              query_decoded_buf_(other.query_decoded_buf_),
              headers_owned_(other.headers_owned_),
              consumed_(other.consumed_),
              query_param_overflow_(other.query_param_overflow_) {
            rebase_query_views(other.query_decoded_buf_.data(), other.query_decoded_buf_.size());
        }

        HttpRequest &operator=(const HttpRequest &other) {
            if (this != &other) {
                Request::operator=(other);
                buffer_ = other.buffer_;
                parsed_ = other.parsed_;
                path_ = other.path_;
                raw_target_owned_ = other.raw_target_owned_;
                path_target_owned_ = other.path_target_owned_;
                body_owned_ = other.body_owned_;
                query_decoded_buf_ = other.query_decoded_buf_;
                headers_owned_ = other.headers_owned_;
                consumed_ = other.consumed_;
                query_param_overflow_ = other.query_param_overflow_;
                rebase_query_views(other.query_decoded_buf_.data(), other.query_decoded_buf_.size());
            }
            return *this;
        }

        HttpRequest(HttpRequest &&other) noexcept
            : Request(std::move(other)),
              buffer_(std::move(other.buffer_)),
              parsed_(std::move(other.parsed_)),
              path_(std::move(other.path_)),
              raw_target_owned_(std::move(other.raw_target_owned_)),
              path_target_owned_(std::move(other.path_target_owned_)),
              body_owned_(std::move(other.body_owned_)),
              query_decoded_buf_(std::move(other.query_decoded_buf_)),
              headers_owned_(std::move(other.headers_owned_)),
              consumed_(other.consumed_),
              query_param_overflow_(other.query_param_overflow_) {
            rebase_query_views(other.query_decoded_buf_.data(), query_decoded_buf_.size());
        }

        HttpRequest &operator=(HttpRequest &&other) noexcept {
            if (this != &other) {
                const char *old_base = other.query_decoded_buf_.data();
                const size_t old_len = other.query_decoded_buf_.size();
                Request::operator=(std::move(other));
                buffer_ = std::move(other.buffer_);
                parsed_ = std::move(other.parsed_);
                path_ = std::move(other.path_);
                raw_target_owned_ = std::move(other.raw_target_owned_);
                path_target_owned_ = std::move(other.path_target_owned_);
                body_owned_ = std::move(other.body_owned_);
                query_decoded_buf_ = std::move(other.query_decoded_buf_);
                headers_owned_ = std::move(other.headers_owned_);
                consumed_ = other.consumed_;
                query_param_overflow_ = other.query_param_overflow_;
                rebase_query_views(old_base, old_len);
            }
            return *this;
        }

        // ─── 4. Member Functions & Friend Declarations (LAST) ──────────────

        /// Parse the owned buffer (server side). Returns true on success.
        bool parse() {
            consumed_ = 0;
            if (const auto result = parser_type::parse_request(buffer_, parsed_, consumed_);
                result != parser_type::result::success)
                return false;

            extract_path_query(parsed_.target);
            return true;
        }

        /**
         * @brief Parse directly from an external stream buffer view using a connection-scoped context.
         * @param stream_buf Stream buffer view containing wire data.
         * @param ctx Connection context (e.g. holding persistent HPACK dynamic table for HTTP/2).
         * @return parser_type::result (success, incomplete, error).
         */
        template<typename Context>
        parser_type::result parse_stream(const std::string_view stream_buf, Context &ctx) {
            consumed_ = 0;
            typename parser_type::result result = parser_type::result::error;
            if constexpr (requires { parser_type::parse_request(stream_buf, parsed_, consumed_, ctx); }) {
                result = parser_type::parse_request(stream_buf, parsed_, consumed_, ctx);
            } else {
                result = parser_type::parse_request(stream_buf, parsed_, consumed_);
            }
            if (result == parser_type::result::success) {
                extract_path_query(parsed_.target);
            }
            return result;
        }

        /**
         * @brief Parse directly from an external stream buffer view without copying.
         * @param stream_buf Stream buffer view containing wire data.
         * @return parser_type::result (success, incomplete, error).
         */
        parser_type::result parse_stream(const std::string_view stream_buf) {
            consumed_ = 0;
            const auto result = parser_type::parse_request(stream_buf, parsed_, consumed_);
            if (result == parser_type::result::success) {
                extract_path_query(parsed_.target);
            }
            return result;
        }

        /// Returns number of bytes consumed by the parser for this request
        [[nodiscard]] size_t consumed_bytes() const noexcept { return consumed_; }

        /**
         * @brief Returns true if the request's query string exceeded the hard cap (kMaxQueryParams).
         * Server::handle_connection checks this to emit a 431 response before routing.
         */
        [[nodiscard]] bool has_query_param_overflow() const noexcept { return query_param_overflow_; }

        /// Checks if this HTTP request indicates the connection should stay active (Keep-Alive)
        [[nodiscard]] bool should_keep_alive() const noexcept {
            const auto conn = parsed_.get_header("Connection");
            if (parsed_.version_major == 1 && parsed_.version_minor == 1) {
                // In HTTP/1.1, connections are persistent by default unless "close" is specified.
                if (conn && detail::is_equal(*conn, "close")) {
                    return false;
                }
                return true;
            } else if (parsed_.version_major == 1 && parsed_.version_minor == 0) {
                // In HTTP/1.0, connections close by default unless "keep-alive" is specified.
                if (conn && detail::is_equal(*conn, "keep-alive")) {
                    return true;
                }
                return false;
            }
            return true;
        }

        // ── Client-side Fluent Setters ──────────────────────────────────────

        HttpRequest &method(const http::method m) {
            parsed_.method_type = m;
            return *this;
        }

        HttpRequest &target(const std::string_view target) {
            raw_target_owned_ = std::string(target);
            extract_path_query(raw_target_owned_);
            return *this;
        }

        HttpRequest &set_header(const std::string_view name, const std::string_view value) {
            headers_owned_.emplace_back(std::string(name), std::string(value));
            rebuild_headers_views();
            return *this;
        }

        HttpRequest &set_body(const std::string_view body) {
            body_owned_ = std::string(body);
            parsed_.body = body_owned_;
            return *this;
        }

        // ── Stream ID for HTTP/2 & Multiplexed Protocols ────────────────────
        [[nodiscard]] uint32_t stream_id() const noexcept {
            if constexpr (requires { parsed_.stream_id; }) {
                return parsed_.stream_id;
            } else {
                return 0;
            }
        }

        HttpRequest &stream_id(const uint32_t id) noexcept {
            if constexpr (requires { parsed_.stream_id; }) {
                parsed_.stream_id = id;
            }
            return *this;
        }

        HttpRequest &set_stream_id(const uint32_t id) noexcept {
            return stream_id(id);
        }

        // ── Accessors (CRTP Implementations) ────────────────────────────────

        [[nodiscard]] http::method method_type() const { return parsed_.method_type; }

        [[nodiscard]] std::string_view target() const {
            return raw_target_owned_.empty() ? parsed_.target : std::string_view(raw_target_owned_);
        }

        [[nodiscard]] std::string_view path_impl() const { return path_; }

        [[nodiscard]] std::optional<std::string_view> header_impl(const std::string_view name) const {
            return parsed_.get_header(name);
        }

        [[nodiscard]] std::string_view body_impl() const { return parsed_.body; }

        // ── Multipart & File Upload Accessors ──────────────────────────────

        /**
         * @brief Checks if request Content-Type is multipart/form-data.
         */
        [[nodiscard]] bool is_multipart_impl() const {
            const auto ct = header_impl("Content-Type");
            return ct.has_value() && ct->find("multipart/form-data") != std::string_view::npos;
        }

        [[nodiscard]] bool is_multipart() const {
            return is_multipart_impl();
        }

        /**
         * @brief Parses the multipart/form-data body according to RFC 7578.
         * @param limits Size and count thresholds for memory buffering and spooling.
         * @return Parsed MultipartFormData containing fields and uploaded files.
         */
        [[nodiscard]] utils::MultipartFormData multipart(const utils::MultipartLimits &limits = {}) const {
            const auto ct = header_impl("Content-Type");
            return utils::MultipartFormData::parse(body_impl(), ct.value_or(""), limits);
        }

        /**
         * @brief Asynchronously parses the multipart/form-data body according to RFC 7578.
         * Offloads disk spooling for files > max_memory_buffer to the background blocking pool.
         * @param limits Size and count thresholds for memory buffering and spooling.
         * @return Awaitable yielding parsed MultipartFormData containing fields and uploaded files.
         */
        [[nodiscard]] asio::awaitable<utils::MultipartFormData> multipart_async(
            const utils::MultipartLimits &limits = {}) const {
            const auto ct = header_impl("Content-Type");
            co_return co_await utils::MultipartFormData::parse_async(body_impl(), ct.value_or(""), limits);
        }

        /**
         * @brief Convenience helper to retrieve an uploaded file by form field name.
         * @param name Name of the form file field.
         */
        [[nodiscard]] std::optional<utils::UploadedFile> file(const std::string_view name) const {
            return multipart().file(name);
        }

        /**
         * @brief Convenience helper to retrieve all uploaded files in the request.
         */
        [[nodiscard]] std::vector<utils::UploadedFile> files() const {
            return multipart().files();
        }

        /**
         * @brief Decompresses request body using Content-Encoding header or fallback format.
         * @param format Default compression algorithm if Content-Encoding is unspecified.
         */
        [[nodiscard]] std::optional<std::string> decompressed_body(
            const utils::CompressionFormat format = utils::CompressionFormat::Gzip) const {
            auto decompress_helper = [](const std::string_view d,
                                        const utils::CompressionFormat fmt) -> std::optional<std::string> {
                if (auto res = utils::Compressor::decompress(d, fmt)) return *res;
                return std::nullopt;
            };
            const auto enc = header_impl("Content-Encoding");
            if (enc.has_value()) {
                if (enc->find("gzip") != std::string_view::npos) {
                    return decompress_helper(body_impl(), utils::CompressionFormat::Gzip);
                }
                if (enc->find("deflate") != std::string_view::npos) {
                    return decompress_helper(body_impl(), utils::CompressionFormat::Deflate);
                }
            }
            return decompress_helper(body_impl(), format);
        }

        /**
         * @brief Saves the raw request body to the specified file on disk.
         * @param dest_path Target file path.
         * @return True if saved successfully, false otherwise.
         */
        bool save_body_to_file(const std::string &dest_path) const {
            return utils::BinaryFile::write_all(dest_path, body_impl());
        }

        template<typename PathLike>
            requires (!std::is_convertible_v<PathLike, const std::string &>)
        bool save_body_to_file(const PathLike &dest_path) const {
            if constexpr (requires { dest_path.string(); }) {
                return save_body_to_file(dest_path.string());
            } else {
                return save_body_to_file(std::string(dest_path));
            }
        }

        /**
         * @brief Serialize this HTTP request into wire format via Codec::encoder.
         * @return Serialized HTTP request string ready for network transmission.
         */
        [[nodiscard]] std::string serialize() const {
            return encoder_type::serialize_request(parsed_);
        }

        /// Access the raw parsed codec request
        [[nodiscard]] const request_type &raw() const { return parsed_; }

        [[nodiscard]] request_type &raw() { return parsed_; }

    private:
        /**
         * @brief Extract path and query parameters from the full request target.
         *
         * Strips any scheme+authority prefix (for absolute-form targets), then
         * splits at the first '?' to separate path from query. The path is stored
         * as an owned string (path_) and also sets parsed_.target. Query string
         * parameters are percent-decoded and inserted into the FlatMap `query`.
         *
         * Hard cap: if the query string contains more than kMaxQueryParams pairs,
         * the overflow is silently discarded. The Server enforces a 431 rejection
         * before routing when this flag is set.
         *
         * @param full_target  The raw request target (e.g. "/user/123?page=2").
         */
        void extract_path_query(const std::string_view full_target) {
            std::string_view path_and_query = full_target;
            if (const size_t scheme_pos = full_target.find("://"); scheme_pos != std::string_view::npos) {
                const size_t path_start = full_target.find('/', scheme_pos + 3);
                if (path_start != std::string_view::npos) {
                    path_and_query = full_target.substr(path_start);
                } else {
                    path_and_query = "/";
                }
            }

            if (const size_t q = path_and_query.find('?'); q != std::string_view::npos) {
                // Path: store as owned string, then point path_ at it
                path_target_owned_ = std::string(path_and_query);
                parsed_.target = path_target_owned_;
                path_ = std::string(path_and_query.substr(0, q));

                // Query: parse key=value pairs into FlatMap via contiguous linear buffer
                std::string_view qs = path_and_query.substr(q + 1);
                query.clear();
                query_decoded_buf_.clear();
                query_decoded_buf_.reserve(qs.size() + 16);

                struct QuerySlice {
                    size_t k_start{0}, k_len{0};
                    size_t v_start{0}, v_len{0};
                    bool has_val{false};
                };
                std::array<QuerySlice, kMaxQueryParams> slices{};
                std::size_t param_count = 0;

                while (!qs.empty() && param_count < kMaxQueryParams) {
                    const size_t amp = qs.find('&');
                    const std::string_view pair = (amp != std::string_view::npos)
                                                      ? qs.substr(0, amp)
                                                      : qs;

                    if (!pair.empty()) {
                        const size_t eq = pair.find('=');
                        const size_t k_start = query_decoded_buf_.size();
                        query_decoded_buf_ += wavex::uri::decode(pair.substr(0, eq));
                        const size_t k_len = query_decoded_buf_.size() - k_start;

                        size_t v_start = query_decoded_buf_.size();
                        size_t v_len = 0;
                        const bool has_val = (eq != std::string_view::npos);
                        if (has_val) {
                            query_decoded_buf_ += wavex::uri::decode(pair.substr(eq + 1));
                            v_len = query_decoded_buf_.size() - v_start;
                        }

                        slices[param_count] = QuerySlice{k_start, k_len, v_start, v_len, has_val};
                        ++param_count;
                    }

                    if (amp == std::string_view::npos) break;
                    qs = qs.substr(amp + 1);
                }

                for (size_t i = 0; i < param_count; ++i) {
                    const auto &sl = slices[i];
                    const std::string_view k(query_decoded_buf_.data() + sl.k_start, sl.k_len);
                    const std::string_view v = sl.has_val
                                                   ? std::string_view(query_decoded_buf_.data() + sl.v_start, sl.v_len)
                                                   : std::string_view{};
                    query.insert_or_assign(k, v);
                }
                query_param_overflow_ = (param_count >= kMaxQueryParams && !qs.empty());
            } else {
                // No query string — path only
                path_target_owned_ = std::string(path_and_query);
                parsed_.target = path_target_owned_;
                path_ = std::string(path_and_query);
                query.clear();
                query_decoded_buf_.clear();
                query_param_overflow_ = false;
            }
        }

        void rebase_query_views(const char *src_base, const size_t src_len) {
            if (src_base == nullptr || src_len == 0 || query_decoded_buf_.empty()) {
                if (query_decoded_buf_.empty()) query.clear();
                return;
            }
            const char *dst_base = query_decoded_buf_.data();
            if (src_base == dst_base) {
                return;
            }
            base::FlatMap<std::string_view, std::string_view> updated;
            for (const auto &[k, v]: query) {
                std::string_view new_k = k;
                std::string_view new_v = v;
                if (k.data() >= src_base && k.data() < src_base + src_len) {
                    new_k = std::string_view(dst_base + (k.data() - src_base), k.size());
                }
                if (v.data() >= src_base && v.data() < src_base + src_len) {
                    new_v = std::string_view(dst_base + (v.data() - src_base), v.size());
                }
                updated.insert_or_assign(new_k, new_v);
            }
            query = std::move(updated);
        }

        void rebuild_headers_views() {
            parsed_.headers.clear();
            parsed_.headers.reserve(headers_owned_.size());
            for (const auto &[k, v]: headers_owned_) {
                parsed_.headers.emplace_back(k, v);
            }
        }
    };

    /// Concrete default HTTP/1.x request type aliases
    using Http1Request = HttpRequest<wavex::protos::http::http1codec>;
    using http1request = Http1Request;
} // namespace wavex::protos::http
