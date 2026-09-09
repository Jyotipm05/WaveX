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
#include <utility>
#include <optional>

#include <wavex/Base/Request.hpp>
#include <wavex/Base/Url.hpp>
#include <wavex/protos/http/http1codec.hpp>

namespace wavex::protos::http {
    /**
     * @class HttpRequest
     * @brief HTTP request parameterized on Codec — supports both server-side parsing and client-side creation.
     * @tparam Codec Protocol codec defining parser, encoder, decoder, request, and response types.
     */
    template<typename Codec = http1codec>
    class HttpRequest final : public base::Request {
    public:
        using codec_type = Codec;
        using parser_type = Codec::parser;
        using encoder_type = Codec::encoder;
        using request_type = Codec::request;

        using base::Request::query;
        using base::Request::params;

        HttpRequest() = default;

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

            std::string local_path;
            std::unordered_map<std::string, std::string> local_query;

            if (const size_t q = path_and_query.find('?'); q != std::string_view::npos) {
                local_path = std::string(path_and_query.substr(0, q));
                local_query = url::parse_query(path_and_query.substr(q + 1));
            } else {
                local_path = std::string(path_and_query);
            }

            path_target_owned_ = std::string(path_and_query);
            parsed_.target = path_target_owned_;
            path_ = std::move(local_path);
            query = std::move(local_query);
        }

        void rebuild_headers_views() {
            parsed_.headers.clear();
            parsed_.headers.reserve(headers_owned_.size());
            for (const auto &[k, v]: headers_owned_) {
                parsed_.headers.emplace_back(k, v);
            }
        }

        std::string buffer_; ///< owned receive buffer (server)
        size_t consumed_{0}; ///< byte count consumed by parser
        request_type parsed_; ///< zero-copy views
        std::string path_; ///< extracted path
        std::string raw_target_owned_; ///< owned full target string (client)
        std::string path_target_owned_; ///< owned path + query string (client)
        std::string body_owned_; ///< owned body string (client)
        std::vector<std::pair<std::string, std::string> > headers_owned_; ///< owned headers (client)
    };

    /// Concrete default HTTP/1.x request type aliases
    using Http1Request = HttpRequest<wavex::protos::http::http1codec>;
    using http1request = Http1Request;
} // namespace wavex::protos::http
