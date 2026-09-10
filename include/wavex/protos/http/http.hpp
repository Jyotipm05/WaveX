// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file http.hpp
 * @brief Primary HTTP protocol header for WaveX.
 *
 * Exposes all HTTP components and codec-templated helper functions (parser, encoder, decoder)
 * parameterized on Codec (defaulting to http1codec) to support multiple HTTP versions (HTTP/1.x, HTTP/2, HTTP/3).
 */

#pragma once

#include <string>
#include <string_view>

#include <wavex/protos/http/http1codec.hpp>
#include <wavex/protos/http/http2codec.hpp>
#include <wavex/protos/http/HttpResponse.hpp>

#include "HttpRequest.hpp"

namespace wavex::protos::http {
    // ─── Codec-Templated Parser Methods ──────────────────────────────────────────

    /**
     * @brief Parse a raw HTTP request buffer using the specified Codec's parser.
     * @tparam Codec Protocol codec (default `http1codec`).
     * @param buffer Network request buffer.
     * @param req Output request structure.
     * @param bytes_consumed Output number of bytes parsed.
     * @return Codec parser result (success, incomplete, error).
     */
    template<typename Codec = http1codec>
    [[nodiscard]] inline auto parse_request(
        const std::string_view buffer,
        typename Codec::request &req,
        std::size_t &bytes_consumed) {
        return Codec::parser::parse_request(buffer, req, bytes_consumed);
    }

    /**
     * @brief Parse a raw HTTP response buffer using the specified Codec's parser.
     * @tparam Codec Protocol codec (default `http1codec`).
     * @param buffer Network response buffer.
     * @param res Output response structure.
     * @param bytes_consumed Output number of bytes parsed.
     * @return Codec parser result (success, incomplete, error).
     */
    template<typename Codec = http1codec>
    [[nodiscard]] inline auto parse_response(
        const std::string_view buffer,
        typename Codec::response &res,
        std::size_t &bytes_consumed) {
        return Codec::parser::parse_response(buffer, res, bytes_consumed);
    }

    // ─── Codec-Templated Encoder Methods ──────────────────────────────────────────

    /**
     * @brief Serialize an HTTP request structure into wire format using the specified Codec's encoder.
     * @tparam Codec Protocol codec (default `http1codec`).
     * @param req Request structure to serialize.
     * @return Serialized wire representation string.
     */
    template<typename Codec = http1codec>
    [[nodiscard]] inline std::string serialize_request(const typename Codec::request &req) {
        return Codec::encoder::serialize_request(req);
    }

    /**
     * @brief Serialize an HTTP response structure into wire format using the specified Codec's encoder.
     * @tparam Codec Protocol codec (default `http1codec`).
     * @param res Response structure to serialize.
     * @return Serialized wire representation string.
     */
    template<typename Codec = http1codec>
    [[nodiscard]] inline std::string serialize_response(const typename Codec::response &res) {
        return Codec::encoder::serialize(res);
    }

    /**
     * @brief Format a single stream chunk using the specified Codec's encoder.
     * @tparam Codec Protocol codec (default `http1codec`).
     * @param data Payload bytes.
     * @return Wire formatted chunk.
     */
    template<typename Codec = http1codec>
    [[nodiscard]] inline std::string format_chunk(const std::string_view data) {
        return Codec::encoder::format_chunk(data);
    }

    /**
     * @brief Format the terminal stream chunk using the specified Codec's encoder.
     * @tparam Codec Protocol codec (default `http1codec`).
     * @return Terminal chunk view (e.g. "0\r\n\r\n").
     */
    template<typename Codec = http1codec>
    [[nodiscard]] inline constexpr std::string_view format_terminal_chunk() noexcept {
        return Codec::encoder::format_terminal_chunk();
    }

    // ─── Codec-Templated Decoder Methods ──────────────────────────────────────────

    /**
     * @brief Decode a raw response buffer using the specified Codec's decoder.
     * @tparam Codec Protocol codec (default `http1codec`).
     * @param buffer Raw network buffer.
     * @param res Output response structure.
     * @param bytes_consumed Output consumed bytes.
     * @return Decode result.
     */
    template<typename Codec = http1codec>
    [[nodiscard]] inline auto decode_response(
        const std::string_view buffer,
        typename Codec::response &res,
        std::size_t &bytes_consumed) {
        return Codec::decoder::decode_response(buffer, res, bytes_consumed);
    }

    /**
     * @brief De-chunk a chunked body payload using the specified Codec's decoder.
     * @tparam Codec Protocol codec (default `http1codec`).
     * @param chunked_raw Raw chunked payload.
     * @return Decoded unchunked body string.
     */
    template<typename Codec = http1codec>
    [[nodiscard]] inline std::string dechunk(const std::string_view chunked_raw) {
        return Codec::decoder::dechunk(chunked_raw);
    }

    // ─── HTTP/2 Type Aliases ──────────────────────────────────────────────────────
    using Http2Request = HttpRequest<wavex::protos::http::http2codec>;
    using http2request = Http2Request;
    using Http2Response = HttpResponse<wavex::protos::http::http2codec>;
    using http2response = Http2Response;
} // namespace wavex::protos::http
