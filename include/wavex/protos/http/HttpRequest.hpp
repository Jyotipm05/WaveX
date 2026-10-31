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
#include <wavex/Utils/FsUtils.hpp>
#include <wavex/Base/StringSink.hpp>

namespace wavex::protos::http {
    namespace detail {
        template<typename String, typename Op>
        inline void resize_and_overwrite_compat(String &str, const std::size_t count, Op &&op) {
            wavex::base::resize_and_overwrite_compat(str, count, std::forward<Op>(op));
        }
    } // namespace detail

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
        std::pmr::string query_decoded_buf_;
        /// Contiguous linear buffer owning all decoded route parameter characters.
        /// FlatMap `params` holds string_views slicing directly into this buffer.
        std::pmr::string params_decoded_buf_;
        std::vector<std::pair<std::string, std::string> > headers_owned_{}; ///< owned headers (client)
        size_t consumed_{0}; ///< byte count consumed by parser
        bool query_param_overflow_{false}; ///< set when >kMaxQueryParams were present

    public:
        // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
        HttpRequest()
            : Request(std::pmr::get_default_resource()),
              query_decoded_buf_(arena_mr_),
              params_decoded_buf_(arena_mr_) {
        }

        explicit HttpRequest(std::pmr::memory_resource *mr) noexcept
            : Request(mr),
              query_decoded_buf_(arena_mr_),
              params_decoded_buf_(arena_mr_) {
        }

        ~HttpRequest() = default;

        /// Construct from a raw buffer (server side).
        explicit HttpRequest(std::string buffer, std::pmr::memory_resource *mr = nullptr)
            : Request(mr),
              buffer_(std::move(buffer)),
              query_decoded_buf_(arena_mr_),
              params_decoded_buf_(arena_mr_) {
        }

        /// Construct with method and target URL/path (client side).
        HttpRequest(const http::method m, const std::string_view target, std::pmr::memory_resource *mr = nullptr)
            : Request(mr),
              query_decoded_buf_(arena_mr_),
              params_decoded_buf_(arena_mr_) {
            parsed_.method_type = m;
            raw_target_owned_ = std::string(target);
            extract_path_query(raw_target_owned_);
        }

        HttpRequest(const HttpRequest &other, std::pmr::memory_resource *mr)
            : Request(other, mr),
              buffer_(other.buffer_),
              parsed_(other.parsed_),
              path_(other.path_),
              raw_target_owned_(other.raw_target_owned_),
              path_target_owned_(other.path_target_owned_),
              body_owned_(other.body_owned_),
              query_decoded_buf_(other.query_decoded_buf_, arena_mr_),
              params_decoded_buf_(other.params_decoded_buf_, arena_mr_),
              headers_owned_(other.headers_owned_),
              consumed_(other.consumed_),
              query_param_overflow_(other.query_param_overflow_) {
            if (!path_target_owned_.empty()) {
                parsed_.target = path_target_owned_;
            }
            rebase_query_views(other.query_decoded_buf_.data(), other.query_decoded_buf_.size());
            rebase_params_views(other.params_decoded_buf_.data(), other.params_decoded_buf_.size());
        }

        HttpRequest(const HttpRequest &other)
            : HttpRequest(other, other.arena_mr_) {}

        HttpRequest &operator=(const HttpRequest &other) {
            if (this != &other) {
                auto *saved_mr = arena_mr_;
                Request::operator=(other);
                arena_mr_ = saved_mr; // Preserve allocator non-propagation per std::pmr
                buffer_ = other.buffer_;
                parsed_ = other.parsed_;
                path_ = other.path_;
                raw_target_owned_ = other.raw_target_owned_;
                path_target_owned_ = other.path_target_owned_;
                if (!path_target_owned_.empty()) {
                    parsed_.target = path_target_owned_;
                }
                body_owned_ = other.body_owned_;
                query_decoded_buf_ = other.query_decoded_buf_;
                params_decoded_buf_ = other.params_decoded_buf_;
                headers_owned_ = other.headers_owned_;
                consumed_ = other.consumed_;
                query_param_overflow_ = other.query_param_overflow_;
                rebase_query_views(other.query_decoded_buf_.data(), other.query_decoded_buf_.size());
                rebase_params_views(other.params_decoded_buf_.data(), other.params_decoded_buf_.size());
            }
            return *this;
        }

        HttpRequest(HttpRequest &&other, std::pmr::memory_resource *mr)
            : Request(std::move(other), mr),
              buffer_(std::move(other.buffer_)),
              parsed_(std::move(other.parsed_)),
              path_(std::move(other.path_)),
              raw_target_owned_(std::move(other.raw_target_owned_)),
              path_target_owned_(std::move(other.path_target_owned_)),
              body_owned_(std::move(other.body_owned_)),
              query_decoded_buf_(arena_mr_),
              params_decoded_buf_(arena_mr_),
              headers_owned_(std::move(other.headers_owned_)),
              consumed_(other.consumed_),
              query_param_overflow_(other.query_param_overflow_) {
            if (!path_target_owned_.empty()) {
                parsed_.target = path_target_owned_;
            }
            const char *old_q_base = other.query_decoded_buf_.data();
            const size_t old_q_len = other.query_decoded_buf_.size();
            const char *old_p_base = other.params_decoded_buf_.data();
            const size_t old_p_len = other.params_decoded_buf_.size();

            query_decoded_buf_ = std::move(other.query_decoded_buf_);
            params_decoded_buf_ = std::move(other.params_decoded_buf_);

            rebase_query_views(old_q_base, old_q_len);
            rebase_params_views(old_p_base, old_p_len);
        }

        HttpRequest(HttpRequest &&other) noexcept
            : HttpRequest(std::move(other), other.arena_mr_) {}

        HttpRequest &operator=(HttpRequest &&other) noexcept {
            if (this != &other) {
                const char *old_q_base = other.query_decoded_buf_.data();
                const size_t old_q_len = other.query_decoded_buf_.size();
                const char *old_p_base = other.params_decoded_buf_.data();
                const size_t old_p_len = other.params_decoded_buf_.size();

                auto *saved_mr = arena_mr_;
                Request::operator=(std::move(other));
                arena_mr_ = saved_mr; // Preserve allocator non-propagation per std::pmr

                buffer_ = std::move(other.buffer_);
                parsed_ = std::move(other.parsed_);
                path_ = std::move(other.path_);
                raw_target_owned_ = std::move(other.raw_target_owned_);
                path_target_owned_ = std::move(other.path_target_owned_);
                if (!path_target_owned_.empty()) {
                    parsed_.target = path_target_owned_;
                }
                body_owned_ = std::move(other.body_owned_);
                query_decoded_buf_ = std::move(other.query_decoded_buf_);
                params_decoded_buf_ = std::move(other.params_decoded_buf_);
                headers_owned_ = std::move(other.headers_owned_);
                consumed_ = other.consumed_;
                query_param_overflow_ = other.query_param_overflow_;
                rebase_query_views(old_q_base, old_q_len);
                rebase_params_views(old_p_base, old_p_len);
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

        /**
         * @brief Number of request header fields, or 0 for codecs that do not expose a flat header list.
         * @details Used by the server to enforce `set_max_headers()`. HTTP/2 and HTTP/3 bound header
         *          size through HPACK/QPACK limits instead.
         */
        [[nodiscard]] std::size_t header_count() const noexcept {
            if constexpr (requires { parsed_.headers.size(); }) {
                return parsed_.headers.size();
            } else {
                return 0;
            }
        }

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

        /**
         * @brief Populate route parameters with automatic percent-decoding.
         *
         * If a parameter value contains '%', it is decoded into `params_decoded_buf_`
         * and a string_view slicing into that buffer is stored in `params`.
         * If no '%' is present, zero allocation occurs and a zero-copy string_view
         * referencing the original route slice is stored.
         */
        template<typename ParamContainer>
        void set_params(const ParamContainer &route_params) {
            params.clear();

            bool any_encoded = false;
            size_t total_est_len = 0;
            for (const auto &[k, v]: route_params) {
                if (v.find('%') != std::string_view::npos) {
                    any_encoded = true;
                }
                total_est_len += v.size();
            }

            if (!any_encoded) {
                for (const auto &[k, v]: route_params) {
                    params.insert_or_assign(k, v);
                }
                return;
            }

            params_decoded_buf_.clear();

            struct ParamSlice {
                std::string_view key;
                size_t val_start{0};
                size_t val_len{0};
                bool is_decoded{false};
                std::string_view raw_val{};
            };

            const size_t num_params = route_params.size();
            std::array<ParamSlice, 32> inline_slices{};
            // heap_slices must outlive `slices`; declaring it inside the else-block left a dangling pointer.
            // ReSharper disable once CppTooWideScope
            std::vector<ParamSlice> heap_slices;
            ParamSlice *slices = nullptr;
            if (num_params <= inline_slices.size()) {
                slices = inline_slices.data();
            } else {
                heap_slices.resize(num_params);
                slices = heap_slices.data();
            }

            size_t count = 0;
            size_t buf_offset = 0;

            detail::resize_and_overwrite_compat(params_decoded_buf_, total_est_len, [&](char *buf, size_t) noexcept {
                for (const auto &[k, v]: route_params) {
                    if (v.find('%') != std::string_view::npos) {
                        const size_t v_start = buf_offset;
                        const size_t v_len = wavex::uri::decode_to(v, buf + buf_offset);
                        buf_offset += v_len;
                        slices[count++] = ParamSlice{k, v_start, v_len, true, {}};
                    } else {
                        slices[count++] = ParamSlice{k, 0, 0, false, v};
                    }
                }
                return buf_offset;
            });

            const char *base = params_decoded_buf_.data();
            for (size_t i = 0; i < count; ++i) {
                if (const auto &sl = slices[i]; sl.is_decoded) {
                    params.insert_or_assign(
                        sl.key,
                        std::string_view(base + sl.val_start, sl.val_len));
                } else {
                    params.insert_or_assign(sl.key, sl.raw_val);
                }
            }
        }

        /**
         * @brief Insert or assign a route parameter with automatic percent-decoding.
         *
         * If the value contains '%', it is decoded into `params_decoded_buf_`.
         * Reallocations are detected and existing views in `params` are rebased automatically.
         */
        void set_param(const std::string_view key, const std::string_view val) {
            if (val.find('%') != std::string_view::npos) {
                const size_t old_len = params_decoded_buf_.size();
                const size_t est_len = val.size();
                const char *old_base = params_decoded_buf_.data();

                detail::resize_and_overwrite_compat(params_decoded_buf_, old_len + est_len,
                    [&](char *buf, size_t) {
                        const size_t written = wavex::uri::decode_to(val, buf + old_len);
                        return old_len + written;
                    });

                if (params_decoded_buf_.data() != old_base && old_base != nullptr) {
                    rebase_params_views(old_base, old_len);
                }
                const size_t decoded_len = params_decoded_buf_.size() - old_len;
                params.insert_or_assign(key, std::string_view(params_decoded_buf_.data() + old_len, decoded_len));
            } else {
                params.insert_or_assign(key, val);
            }
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

        [[nodiscard]] uint8_t version_major() const noexcept {
            if constexpr (requires { parsed_.version_major; }) {
                return static_cast<uint8_t>(parsed_.version_major);
            } else {
                return 1;
            }
        }

        [[nodiscard]] uint8_t version_minor() const noexcept {
            if constexpr (requires { parsed_.version_minor; }) {
                return static_cast<uint8_t>(parsed_.version_minor);
            } else {
                return 1;
            }
        }

        // ── Accessors (Deducing-This Implementations) ──────────────────────────

        [[nodiscard]] http::method method_type() const { return parsed_.method_type; }

        /**
         * @brief The `:protocol` pseudo-header of an extended CONNECT (RFC 8441 §4 / RFC 9220), e.g.
         *        "websocket" or "webtransport". Empty for every other request and for protocols without it.
         */
        [[nodiscard]] std::string_view connect_protocol() const noexcept {
            if constexpr (requires { parsed_.protocol; }) {
                return parsed_.protocol;
            } else {
                return {};
            }
        }

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
            if (const auto enc = header_impl("Content-Encoding"); enc.has_value()) {
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
        [[nodiscard]] bool save_body_to_file(const std::string &dest_path) const {
            return utils::BinaryFile::write_all(dest_path, body_impl());
        }

        template<typename PathLike>
            requires (!std::is_convertible_v<PathLike, const std::string &>)
        bool save_body_to_file(const PathLike &dest_path) const {
            return save_body_to_file(utils::fs_utils::to_u8_path_string(dest_path));
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
                if (const size_t path_start = full_target.find('/', scheme_pos + 3);
                    path_start != std::string_view::npos) [[likely]] {
                    path_and_query = full_target.substr(path_start);
                } else [[unlikely]] {
                    path_and_query = "/";
                }
            }

            if (const size_t q = path_and_query.find('?'); q != std::string_view::npos) {
                // Path: store as owned string, then point path_ at it
                path_target_owned_ = std::string(path_and_query);
                parsed_.target = path_target_owned_;
                path_ = std::string(path_and_query.substr(0, q));

                // Query: parse key=value pairs into FlatMap via contiguous linear buffer
                const std::string_view qs = path_and_query.substr(q + 1);
                query.clear();
                query_decoded_buf_.clear();

                struct QuerySlice {
                    size_t k_start{0}, k_len{0};
                    size_t v_start{0}, v_len{0};
                    bool has_val{false};
                };
                std::array<QuerySlice, kMaxQueryParams> slices{};
                std::size_t param_count = 0;
                size_t buf_offset = 0;

                detail::resize_and_overwrite_compat(query_decoded_buf_, qs.size(), [&](char *buf, size_t) {
                    std::string_view remaining_qs = qs;
                    while (!remaining_qs.empty() && param_count < kMaxQueryParams) {
                        const size_t amp = remaining_qs.find('&');
                        const std::string_view pair = (amp != std::string_view::npos)
                                                          ? remaining_qs.substr(0, amp)
                                                          : remaining_qs;

                        if (!pair.empty()) {
                            const size_t eq = pair.find('=');
                            const std::string_view raw_k = pair.substr(0, eq);
                            const bool has_val = (eq != std::string_view::npos);

                            const size_t k_start = buf_offset;
                            const size_t k_len = wavex::uri::decode_to(raw_k, buf + buf_offset);
                            buf_offset += k_len;

                            size_t v_start = buf_offset;
                            size_t v_len = 0;
                            if (has_val) {
                                const std::string_view raw_v = pair.substr(eq + 1);
                                v_len = wavex::uri::decode_to(raw_v, buf + buf_offset);
                                buf_offset += v_len;
                            }

                            slices[param_count] = QuerySlice{k_start, k_len, v_start, v_len, has_val};
                            ++param_count;
                        }

                        if (amp == std::string_view::npos) break;
                        remaining_qs = remaining_qs.substr(amp + 1);
                    }
                    return buf_offset;
                });

                const char *base = query_decoded_buf_.data();
                for (size_t i = 0; i < param_count; ++i) {
                    const auto &sl = slices[i];
                    const std::string_view k(base + sl.k_start, sl.k_len);
                    const std::string_view v = sl.has_val
                                                   ? std::string_view(base + sl.v_start, sl.v_len)
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

        void rebase_params_views(const char *src_base, const size_t src_len) {
            if (src_base == nullptr || src_len == 0 || params_decoded_buf_.empty()) {
                return;
            }
            const char *dst_base = params_decoded_buf_.data();
            if (src_base == dst_base) {
                return;
            }
            base::FlatMap<std::string_view, std::string_view> updated;
            for (const auto &[k, v]: params) {
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
            params = std::move(updated);
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
