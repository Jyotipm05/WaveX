// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file HttpClient.hpp
 * @brief Async coroutine-based HTTP client supporting both HTTP/1.1 and HTTP/2,
 *        plain TCP and TLS 1.3, multi-payload formatting, URL query parameters,
 *        and domainless IPv4/IPv6 client endpoints.
 */

#pragma once

#ifndef ASIO_HAS_CO_AWAIT
#define ASIO_HAS_CO_AWAIT 1
#endif

#include <string>
#include <string_view>
#include <vector>
#include <utility>
#include <optional>
#include <chrono>
#include <cctype>
#include <type_traits>

#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <nlohmann/json.hpp>

#include <wavex/Base/Response.hpp>
#include <wavex/Base/Uri.hpp>
#include <wavex/Base/Url.hpp>
#include <wavex/protos/http/HttpRequest.hpp>
#include <wavex/protos/http/HttpResponse.hpp>
#include <wavex/protos/http/http.hpp>

namespace wavex::client {
    using protos::http::method;
    using protos::http::Http1Request;
    using protos::http::Http1Response;
    using protos::http::Http2Request;
    using protos::http::Http2Response;

    /**
     * @enum HttpVersion
     * @brief Target HTTP protocol version for client requests.
     */
    enum class HttpVersion {
        Auto,     ///< Auto-negotiate via ALPN on TLS (h2/http1.1); default to HTTP/1.1 on plain TCP
        Http1_1,  ///< Enforce HTTP/1.1 (skip HTTP/2 framing overhead)
        Http2     ///< Enforce HTTP/2 (ALPN "h2" on TLS; prior-knowledge h2c on plain TCP)
    };

    /**
     * @struct ClientOptions
     * @brief Configuration options for HttpClient requests.
     */
    struct ClientOptions {
        HttpVersion version = HttpVersion::Auto; ///< Protocol version strategy
        std::chrono::milliseconds timeout{30000}; ///< Request timeout (default: 30s)
        bool verify_peer = false; ///< Verify TLS server certificates (default: false for development/self-signed)
        std::string ca_file; ///< Optional path to CA bundle
        std::string cert_file; ///< Optional client certificate for mTLS
        std::string key_file; ///< Optional client private key for mTLS
    };

    /// Key-value query parameters alias
    using QueryParams = std::vector<std::pair<std::string, std::string>>;

    /**
     * @class ClientRequest
     * @brief Fluent, protocol-agnostic HTTP request builder.
     */
    class ClientRequest {
    public:
        ClientRequest() = default;

        ClientRequest(const method m, const std::string_view target_url)
            : method_(m), target_(target_url) {
        }

        explicit ClientRequest(const std::string_view target_url)
            : method_(method::GET), target_(target_url) {
        }

        /// Construct from concrete Http1Request
        explicit ClientRequest(const Http1Request &req) {
            method_ = req.raw().method_type;
            target_ = req.target();
            for (const auto &[k, v]: req.raw().headers) {
                headers_.emplace_back(std::string(k), std::string(v));
            }
            body_ = req.body();
        }

        /// Construct from concrete Http2Request
        explicit ClientRequest(const Http2Request &req) {
            method_ = req.raw().method_type;
            target_ = req.target();
            for (const auto &[k, v]: req.raw().headers) {
                headers_.emplace_back(std::string(k), std::string(v));
            }
            body_ = req.body();
        }

        ClientRequest &method(const protos::http::method m) noexcept {
            method_ = m;
            return *this;
        }

        [[nodiscard]] protos::http::method method() const noexcept { return method_; }
        [[nodiscard]] protos::http::method get_method() const noexcept { return method_; }

        ClientRequest &target(const std::string_view t) {
            target_ = std::string(t);
            return *this;
        }

        ClientRequest &url(const std::string_view u) {
            target_ = std::string(u);
            return *this;
        }

        [[nodiscard]] const std::string &target() const noexcept { return target_; }
        [[nodiscard]] const std::string &url() const noexcept { return target_; }

        /// Add a query parameter
        ClientRequest &query(const std::string_view key, const std::string_view value) {
            queries_.emplace_back(std::string(key), std::string(value));
            return *this;
        }

        template<typename T>
        requires (!std::is_convertible_v<T, std::string_view>)
        ClientRequest &query(const std::string_view key, const T &value) {
            queries_.emplace_back(std::string(key), std::to_string(value));
            return *this;
        }

        ClientRequest &queries(const QueryParams &params) {
            for (const auto &[k, v]: params) {
                queries_.emplace_back(k, v);
            }
            return *this;
        }

        [[nodiscard]] const QueryParams &queries() const noexcept { return queries_; }

        /// Set a header (overwrites if exists, case-insensitively)
        ClientRequest &set_header(const std::string_view key, const std::string_view value) {
            for (auto &[k, v]: headers_) {
                if (detail_case_equal(k, key)) {
                    v = std::string(value);
                    return *this;
                }
            }
            headers_.emplace_back(std::string(key), std::string(value));
            return *this;
        }

        [[nodiscard]] std::optional<std::string_view> header(const std::string_view key) const noexcept {
            for (const auto &[k, v]: headers_) {
                if (detail_case_equal(k, key)) return v;
            }
            return std::nullopt;
        }

        [[nodiscard]] const std::vector<std::pair<std::string, std::string> > &headers() const noexcept {
            return headers_;
        }

        /// Set body with optional Content-Type
        ClientRequest &set_body(const std::string_view body, const std::string_view content_type = "") {
            body_ = std::string(body);
            if (!content_type.empty()) {
                set_header("Content-Type", content_type);
            }
            return *this;
        }

        /// Set JSON body (sets Content-Type to application/json automatically)
        ClientRequest &json(const nlohmann::json &j) {
            body_ = j.dump();
            set_header("Content-Type", "application/json");
            return *this;
        }

        [[nodiscard]] const std::string &body() const noexcept { return body_; }

    private:
        static bool detail_case_equal(const std::string_view a, const std::string_view b) noexcept {
            if (a.size() != b.size()) return false;
            for (size_t i = 0; i < a.size(); ++i) {
                if (std::tolower(static_cast<unsigned char>(a[i])) !=
                    std::tolower(static_cast<unsigned char>(b[i]))) {
                    return false;
                }
            }
            return true;
        }

        protos::http::method method_{protos::http::method::GET};
        std::string target_;
        QueryParams queries_;
        std::vector<std::pair<std::string, std::string> > headers_;
        std::string body_;
    };

    /**
     * @class ClientResponse
     * @brief Unified, protocol-agnostic response object returned by HttpClient.
     *
     * Inherits from base::Response (zero-vtable) and provides implicit conversion
     * to Http1Response and Http2Response for 100% backward compatibility.
     */
    class ClientResponse final : public base::Response {
    public:
        ClientResponse() = default;

        // Internal setters used by HttpClient engine
        ClientResponse &status_code(const unsigned int code) noexcept {
            status_code_ = code;
            return *this;
        }

        ClientResponse &status_text(const std::string_view text) {
            status_text_ = std::string(text);
            return *this;
        }

        ClientResponse &body(const std::string_view b) {
            body_ = std::string(b);
            return *this;
        }

        ClientResponse &set_raw_response(const std::string_view raw) {
            raw_buffer_ = std::string(raw);
            return *this;
        }

        ClientResponse &header(const std::string_view k, const std::string_view v) {
            headers_storage_.emplace_back(std::string(k), std::string(v));
            return *this;
        }

        ClientResponse &http_version(const HttpVersion ver) noexcept {
            version_ = ver;
            return *this;
        }

        // Getters
        [[nodiscard]] unsigned int status_code() const noexcept { return status_code_; }
        [[nodiscard]] std::string_view status_text() const noexcept { return status_text_; }
        [[nodiscard]] std::string_view body() const noexcept { return body_; }
        [[nodiscard]] const std::string &get_body() const noexcept { return body_; }
        [[nodiscard]] HttpVersion http_version() const noexcept { return version_; }

        [[nodiscard]] std::optional<std::string_view> header(const std::string_view name) const noexcept {
            for (const auto &[k, v]: headers_storage_) {
                if (k.size() == name.size()) {
                    bool match = true;
                    for (size_t i = 0; i < k.size(); ++i) {
                        if (std::tolower(static_cast<unsigned char>(k[i])) !=
                            std::tolower(static_cast<unsigned char>(name[i]))) {
                            match = false;
                            break;
                        }
                    }
                    if (match) return v;
                }
            }
            return std::nullopt;
        }

        [[nodiscard]] std::optional<std::string_view> get_header(const std::string_view name) const noexcept {
            return header(name);
        }

        [[nodiscard]] const std::vector<std::pair<std::string, std::string> > &headers() const noexcept {
            return headers_storage_;
        }

        [[nodiscard]] const std::vector<std::pair<std::string, std::string> > &header_views() const noexcept {
            return headers_storage_;
        }

        [[nodiscard]] std::string_view raw_body() const noexcept {
            return body_;
        }

        /// Access the raw unparsed response wire buffer (mirrors Http1Response::raw_response())
        [[nodiscard]] std::string_view raw_response() const noexcept {
            return raw_buffer_;
        }

        [[nodiscard]] nlohmann::json json() const {
            return nlohmann::json::parse(body_);
        }

        // Implicit conversions for backward compatibility
        operator wavex::protos::http::Http1Response() const {
            wavex::protos::http::Http1Response res;
            res.status(status_code_);
            for (const auto &[k, v]: headers_storage_) {
                res.set(k, v);
            }
            res.send(body_);
            return res;
        }

        operator wavex::protos::http::Http2Response() const {
            wavex::protos::http::Http2Response res;
            res.status(status_code_);
            for (const auto &[k, v]: headers_storage_) {
                res.set(k, v);
            }
            res.send(body_);
            return res;
        }

    private:
        unsigned int status_code_{0};
        std::string status_text_;
        std::string body_;
        std::string raw_buffer_;          ///< Stores full HTTP/1.1 wire bytes for raw_response()
        std::vector<std::pair<std::string, std::string> > headers_storage_;
        HttpVersion version_{HttpVersion::Auto};
    };

    /**
     * @class HttpClient
     * @brief Coroutine-native HTTP client supporting HTTP/1.1 & HTTP/2, plain TCP & TLS 1.3,
     *        domainless IPv4/IPv6 endpoints, query parameter builder, and multi-payload posting.
     */
    class HttpClient {
    public:
        HttpClient() = default;

        /**
         * @brief Core asynchronous send method for ClientRequest.
         * @param req The protocol-agnostic client request.
         * @param options Connection & protocol options.
         * @return Coroutine awaitable producing ClientResponse.
         */
        static asio::awaitable<ClientResponse> send(const ClientRequest &req, const ClientOptions &options = {});

        /**
         * @brief Backward-compatible send overload for Http1Request.
         */
        static asio::awaitable<Http1Response> send(Http1Request req, const ClientOptions &options = {}) {
            ClientRequest creq(req);
            ClientResponse c_res = co_await send(creq, options);
            co_return static_cast<Http1Response>(c_res);
        }

        /**
         * @brief Send overload for Http2Request.
         */
        static asio::awaitable<Http2Response> send(Http2Request req, const ClientOptions &options = {}) {
            ClientRequest creq(req);
            ClientOptions opts = options;
            if (opts.version == HttpVersion::Auto) {
                opts.version = HttpVersion::Http2;
            }
            ClientResponse c_res = co_await send(creq, opts);
            co_return static_cast<Http2Response>(c_res);
        }

        // ─── GET ─────────────────────────────────────────────────────────────
        template<typename ResponseType = ClientResponse>
        static asio::awaitable<ResponseType> get(const std::string_view url, const ClientOptions &options = {}) {
            ClientRequest req(method::GET, url);
            ClientResponse c_res = co_await send(req, options);
            if constexpr (std::is_same_v<ResponseType, ClientResponse>) {
                co_return c_res;
            } else {
                co_return static_cast<ResponseType>(c_res);
            }
        }

        template<typename ResponseType = ClientResponse>
        static asio::awaitable<ResponseType> get(const std::string_view url, const QueryParams &params,
                                                 const ClientOptions &options = {}) {
            ClientRequest req(method::GET, url);
            req.queries(params);
            ClientResponse c_res = co_await send(req, options);
            if constexpr (std::is_same_v<ResponseType, ClientResponse>) {
                co_return c_res;
            } else {
                co_return static_cast<ResponseType>(c_res);
            }
        }

        // ─── POST ────────────────────────────────────────────────────────────
        template<typename ResponseType = ClientResponse>
        static asio::awaitable<ResponseType> post(const std::string_view url, const std::string_view body,
                                                  const std::string_view content_type = "text/plain",
                                                  const ClientOptions &options = {}) {
            ClientRequest req(method::POST, url);
            req.set_body(body, content_type);
            ClientResponse c_res = co_await send(req, options);
            if constexpr (std::is_same_v<ResponseType, ClientResponse>) {
                co_return c_res;
            } else {
                co_return static_cast<ResponseType>(c_res);
            }
        }


        template<typename ResponseType = ClientResponse, typename JsonBody>
        requires (std::is_same_v<std::remove_cvref_t<JsonBody>, nlohmann::json>)
        static asio::awaitable<ResponseType> post(const std::string_view url, JsonBody &&json_body,
                                                  const ClientOptions &options = {}) {
            ClientRequest req(method::POST, url);
            req.json(std::forward<JsonBody>(json_body));
            ClientResponse c_res = co_await send(req, options);
            if constexpr (std::is_same_v<ResponseType, ClientResponse>) {
                co_return c_res;
            } else {
                co_return static_cast<ResponseType>(c_res);
            }
        }

        // ─── PUT ─────────────────────────────────────────────────────────────
        template<typename ResponseType = ClientResponse>
        static asio::awaitable<ResponseType> put(const std::string_view url, const std::string_view body,
                                                 const std::string_view content_type = "text/plain",
                                                 const ClientOptions &options = {}) {
            ClientRequest req(method::PUT, url);
            req.set_body(body, content_type);
            ClientResponse c_res = co_await send(req, options);
            if constexpr (std::is_same_v<ResponseType, ClientResponse>) {
                co_return c_res;
            } else {
                co_return static_cast<ResponseType>(c_res);
            }
        }


        template<typename ResponseType = ClientResponse, typename JsonBody>
        requires (std::is_same_v<std::remove_cvref_t<JsonBody>, nlohmann::json>)
        static asio::awaitable<ResponseType> put(const std::string_view url, JsonBody &&json_body,
                                                 const ClientOptions &options = {}) {
            ClientRequest req(method::PUT, url);
            req.json(std::forward<JsonBody>(json_body));
            ClientResponse c_res = co_await send(req, options);
            if constexpr (std::is_same_v<ResponseType, ClientResponse>) {
                co_return c_res;
            } else {
                co_return static_cast<ResponseType>(c_res);
            }
        }

        // ─── DELETE ──────────────────────────────────────────────────────────
        template<typename ResponseType = ClientResponse>
        static asio::awaitable<ResponseType> del(const std::string_view url, const ClientOptions &options = {}) {
            ClientRequest req(method::DELETE, url);
            ClientResponse c_res = co_await send(req, options);
            if constexpr (std::is_same_v<ResponseType, ClientResponse>) {
                co_return c_res;
            } else {
                co_return static_cast<ResponseType>(c_res);
            }
        }

        // ─── PATCH ───────────────────────────────────────────────────────────
        template<typename ResponseType = ClientResponse>
        static asio::awaitable<ResponseType> patch(const std::string_view url, const std::string_view body,
                                                   const std::string_view content_type = "text/plain",
                                                   const ClientOptions &options = {}) {
            ClientRequest req(method::PATCH, url);
            req.set_body(body, content_type);
            ClientResponse c_res = co_await send(req, options);
            if constexpr (std::is_same_v<ResponseType, ClientResponse>) {
                co_return c_res;
            } else {
                co_return static_cast<ResponseType>(c_res);
            }
        }

        // ─── GENERIC REQUEST ─────────────────────────────────────────────────
        template<typename ResponseType = ClientResponse>
        static asio::awaitable<ResponseType> request(
            const method m,
            const std::string_view url,
            const std::string_view body = "",
            const std::vector<std::pair<std::string, std::string> > &headers = {},
            const ClientOptions &options = {}) {
            ClientRequest req(m, url);
            for (const auto &[k, v]: headers) {
                req.set_header(k, v);
            }
            if (!body.empty()) {
                req.set_body(body);
            }
            ClientResponse c_res = co_await send(req, options);
            if constexpr (std::is_same_v<ResponseType, ClientResponse>) {
                co_return c_res;
            } else {
                co_return static_cast<ResponseType>(c_res);
            }
        }
    };
} // namespace wavex::client
