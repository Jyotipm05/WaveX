// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file HttpResponse.hpp
 * @brief Concrete HTTP/1.x implementation of base::Response.
 *
 * Supports both server-side response creation & immediate socket writing,
 * and zero-copy client-side response parsing & inspection (for 3rd-party services).
 */

#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <utility>
#include <expected>
#include <chrono>
#include <fstream>
#include <filesystem>
#include <system_error>
#include <asio/ip/tcp.hpp>
#include <asio/as_tuple.hpp>
#include <asio/write.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>
#include <wavex/Base/Response.hpp>
#include <wavex/Base/MimeTypes.hpp>
#include <wavex/protos/http/http1codec.hpp>

namespace wavex::protos::http {
    enum class CompressionMode {
        None,
        Gzip, // Planned for future zlib update
        Deflate // Planned for future zlib update
    };

    /**
     * @class HttpResponse
     * @brief HTTP response parameterized on Codec — supports both server-side creation & client parsing.
     * @tparam Codec Protocol codec defining parser, encoder, decoder, request, and response types.
     */
    template<typename Codec = wavex::protos::http::http1codec>
    class HttpResponse final : public base::Response {
    public:
        using codec_type = Codec;
        using parser_type = Codec::parser;
        using encoder_type = Codec::encoder;
        using decoder_type = Codec::decoder;
        using response_type = Codec::response;

        using Response::status_code_;
        using Response::body_;
        using Response::headers_;
        using Response::is_sent_;
        using Response::set;
        using Response::remove_header;
        using Response::send;

        /// Set the response status code and automatically update status text from Codec
        HttpResponse &status(const unsigned int code) {
            status_code_ = code;
            status_text_ = Codec::status_text_for(code);
            return *this;
        }

        /// Set the response status code with custom status text
        HttpResponse &status(const unsigned int code, const std::string_view text) {
            status_code_ = code;
            status_text_ = text;
            return *this;
        }

        // ── Stream ID for HTTP/2 & Multiplexed Protocols ────────────────────
        [[nodiscard]] uint32_t stream_id() const noexcept {
            return stream_id_;
        }

        HttpResponse &stream_id(const uint32_t id) noexcept {
            stream_id_ = id;
            if constexpr (requires { parsed_.stream_id; }) {
                parsed_.stream_id = id;
            }
            return *this;
        }

        HttpResponse &set_stream_id(const uint32_t id) noexcept {
            return stream_id(id);
        }

        HttpResponse() = default;

        explicit HttpResponse(asio::ip::tcp::socket *socket) : socket_(socket) {
        }

        ~HttpResponse() = default;

        /**
         * @brief Copy constructor — deep-copies backing stores and rebases all
         *        string_view members so they point into THIS object's buffers.
         */
        HttpResponse(const HttpResponse &other)
            : base::Response(other),
              socket_(other.socket_),
              stream_id_(other.stream_id_),
              buffer_owner_(other.buffer_owner_),
              dechunked_body_storage_(other.dechunked_body_storage_),
              parsed_(other.parsed_) {
            const auto buf_base = other.buffer_owner_.data();
            const auto buf_len = other.buffer_owner_.size();
            const auto my_base = buffer_owner_.data();

            auto rebase_buf = [buf_base, buf_len, my_base](
                const std::string_view sv) -> std::string_view {
                if (sv.data() == nullptr) return {};
                const auto off = static_cast<std::size_t>(sv.data() - buf_base);
                if (off < buf_len && off + sv.size() <= buf_len)
                    return {my_base + off, sv.size()};
                // False positive disabled
                // ReSharper disable once CppDFALocalValueEscapesFunction
                return sv;
            };

            // Rebase status_text_ and parsed_ views (all from buffer_owner_)
            if (buf_len > 0) {
                status_text_ = rebase_buf(other.status_text_);
                if constexpr (std::is_same_v<Codec, wavex::protos::http::http1codec>) {
                    parsed_.status_text = rebase_buf(other.parsed_.status_text);
                    parsed_.body = rebase_buf(other.parsed_.body);
                    for (auto &h: parsed_.headers) {
                        h.name = rebase_buf(h.name);
                        h.value = rebase_buf(h.value);
                    }
                }
            }

            // Rebase body_view_ — may point into dechunked_body_storage_ or body_
            if (!other.dechunked_body_storage_.empty()) {
                const auto dk_base = other.dechunked_body_storage_.data();
                const auto dk_len = other.dechunked_body_storage_.size();
                const auto off = static_cast<std::size_t>(
                    other.body_view_.data() - dk_base);
                if (off < dk_len && off + other.body_view_.size() <= dk_len)
                    body_view_ = {
                        dechunked_body_storage_.data() + off,
                        other.body_view_.size()
                    };
            } else if (!body_.empty() && (body_view_.data() == nullptr || body_view_ == other.body_)) {
                body_view_ = body_;
            }

            // Rebase headers_views_ (all from buffer_owner_ if http1)
            headers_views_.reserve(other.headers_views_.size());
            if (buf_len > 0 && std::is_same_v<Codec, wavex::protos::http::http1codec>) {
                for (const auto &[k, v]: other.headers_views_)
                    headers_views_.emplace_back(rebase_buf(k), rebase_buf(v));
            } else {
                if (!parsed_.headers.empty()) {
                    for (const auto &h : parsed_.headers) {
                        headers_views_.emplace_back(h.name, h.value);
                    }
                } else {
                    headers_views_ = other.headers_views_;
                }
            }
        }

        /// Attach or update the target socket for immediate response writing
        void set_socket(asio::ip::tcp::socket *socket) { socket_ = socket; }

        /// Get stored socket pointer
        [[nodiscard]] asio::ip::tcp::socket *socket() const { return socket_; }

        /**
         * @brief Zero-copy parse a raw HTTP response buffer into this object (used by HttpClient).
         * Storage is safely owned by buffer_owner_; string_views point into owned storage.
         * @param buffer Raw network response string.
         * @return true on successful parsing.
         */
        bool parse(const std::string_view buffer) {
            buffer_owner_ = std::string(buffer);
            parsed_ = {};
            headers_views_.clear();

            std::size_t consumed = 0;
            if (parser_type::parse_response(buffer_owner_, parsed_, consumed) != parser_type::result::success) {
                headers_views_.clear();
                return false;
            }

            status_code_ = parsed_.status_code;
            status_text_ = parsed_.status_text;

            // Handle chunked response un-chunking
            if (const auto te = parsed_.get_header("Transfer-Encoding");
                te && te->find("chunked") != std::string_view::npos) {
                dechunked_body_storage_ = decoder_type::dechunk(parsed_.body);
                body_view_ = dechunked_body_storage_;
            } else {
                body_view_ = parsed_.body;
            }
            body_ = std::string(body_view_);

            headers_views_.clear();
            headers_views_.reserve(parsed_.headers.size());
            for (const auto &[name, value]: parsed_.headers) {
                headers_views_.emplace_back(name, value);
            }
            if constexpr (requires { stream_id_ = parsed_.stream_id; }) {
                stream_id_ = parsed_.stream_id;
            }
            return true;
        }

        /// Immediate write serialized HTTP response to the socket if bound
        HttpResponse &send_impl(const std::string_view body) {
            if (is_sent_) return *this;
            body_ = std::string(body);
            body_view_ = body_;
            is_sent_ = true;
            if (socket_) {
                std::string serialized = serialize_impl();
                asio::write(*socket_, asio::buffer(serialized));
            }
            return *this;
        }

        /**
         * @brief Serialize the HTTP response into wire format via Codec::encoder.
         * @return Serialized HTTP response string ready to be transmitted over the socket.
         */
        [[nodiscard]] std::string serialize_impl() const {
            response_type res;
            if constexpr (requires { res.stream_id = stream_id_; }) {
                res.stream_id = stream_id_;
            }
            res.status_code = status_code_;
            res.status_text = (status_text_.empty() || (status_text_ == "OK" && status_code_ != 200))
                                  ? Codec::status_text_for(status_code_)
                                  : status_text_;
            res.body = body_view_.empty() ? std::string_view(body_) : body_view_;

            if (!headers_views_.empty()) {
                res.headers.reserve(headers_views_.size());
                for (const auto &[name, value]: headers_views_) {
                    res.headers.emplace_back(name, value);
                }
            } else {
                res.headers.reserve(headers_.size());
                for (const auto &[name, value]: headers_) {
                    res.headers.emplace_back(name, value);
                }
            }

            return encoder_type::serialize(res);
        }

        /// Access status text as zero-copy std::string_view
        [[nodiscard]] std::string_view status_text() const { return status_text_; }

        /// Retrieve a header value by name (zero-copy std::string_view)
        [[nodiscard]] std::optional<std::string_view> header(const std::string_view name) const {
            if (!headers_views_.empty()) {
                for (const auto &[k, v]: headers_views_) {
                    if (detail::is_equal(k, name)) return v;
                }
            } else {
                for (const auto &[k, v]: headers_) {
                    if (detail::is_equal(k, name)) return v;
                }
            }
            return std::nullopt;
        }

        /// Access zero-copy headers views
        [[nodiscard]] const std::vector<std::pair<std::string_view, std::string_view> > &header_views() const {
            return headers_views_;
        }

        /// Access the raw unparsed HTTP response wire buffer
        [[nodiscard]] std::string_view raw_response() const { return buffer_owner_; }

        /**
         * @brief Configure HTTP Keep-Alive persistent connection headers on this response.
         * @param enable True to request keep-alive, false to request connection closure.
         * @param timeout_sec Idle timeout in seconds (default: 5).
         * @param max_requests Remaining maximum requests on this connection (default: 1000).
         */
        HttpResponse &set_keep_alive(bool enable, unsigned timeout_sec = 5, unsigned max_requests = 1000) {
            if (enable) {
                this->set("Connection", "keep-alive");
                this->set("Keep-Alive",
                          "timeout=" + std::to_string(timeout_sec) + ", max=" + std::to_string(max_requests));
            } else {
                this->set("Connection", "close");
                this->remove_header("Keep-Alive");
            }
            return *this;
        }

        /// Checks if this HTTP response allows the connection to stay active
        [[nodiscard]] bool should_keep_alive() const noexcept {
            const auto conn = header("Connection");
            if (conn && detail::is_equal(*conn, "close")) {
                return false;
            }
            return true;
        }

        /**
         * @brief Starts chunked response streaming over the bound socket.
         * Transmits HTTP status line and Transfer-Encoding: chunked headers immediately.
         */
        asio::awaitable<std::expected<void, std::error_code> > start_chunked(
            const std::chrono::milliseconds timeout = std::chrono::milliseconds(15000)) {
            if (is_headers_sent_) co_return std::expected<void, std::error_code>{};

            this->set("Transfer-Encoding", "chunked");
            this->set("Connection", "keep-alive");

            std::string head = serialize_headers_only();
            is_headers_sent_ = true;

            co_return co_await async_write_with_timeout(head, timeout);
        }

        /**
         * @brief Writes a single chunk of data to the chunked HTTP stream.
         */
        asio::awaitable<std::expected<void, std::error_code> > write_chunk(
            const std::string_view data,
            const std::chrono::milliseconds timeout = std::chrono::milliseconds(15000)) {
            if (!is_headers_sent_) {
                if (auto res = co_await start_chunked(timeout); !res) {
                    co_return res;
                }
            }

            if (data.empty()) co_return std::expected<void, std::error_code>{};

            std::string chunk_bytes = encoder_type::format_chunk(data);
            co_return co_await async_write_with_timeout(chunk_bytes, timeout);
        }

        /**
         * @brief Sends terminal chunk 0\r\n\r\n and finishes the chunked HTTP response.
         */
        asio::awaitable<std::expected<void, std::error_code> > end_chunked(
            const std::chrono::milliseconds timeout = std::chrono::milliseconds(15000)) {
            if (is_sent_) co_return std::expected<void, std::error_code>{};

            if (!is_headers_sent_) {
                if (auto res = co_await start_chunked(timeout); !res) {
                    co_return res;
                }
            }

            std::string_view term = encoder_type::format_terminal_chunk();
            auto res = co_await async_write_with_timeout(term, timeout);
            is_sent_ = true;
            co_return res;
        }

        /**
         * @brief Streams a file from disk with automatic MIME detection and default/custom timeouts.
         */
        asio::awaitable<std::expected<void, std::error_code> > send_file(
            const std::string_view filepath,
            const std::chrono::milliseconds timeout = std::chrono::milliseconds(30000),
            const std::size_t buffer_size = 65536,
            const CompressionMode compression = CompressionMode::None) {
            const std::string_view mime = base::mime_type_from_path(filepath);
            co_return co_await send_file(filepath, mime, timeout, buffer_size, compression);
        }

        /**
         * @brief Streams a file from disk with custom MIME override and default/custom timeouts.
         */
        asio::awaitable<std::expected<void, std::error_code> > send_file(
            const std::string_view filepath,
            const std::string_view custom_mime,
            const std::chrono::milliseconds timeout = std::chrono::milliseconds(30000),
            const std::size_t buffer_size = 65536,
            const CompressionMode compression = CompressionMode::None) {
            (void) compression; // Reserved for future zlib update

            std::filesystem::path path(filepath);
            std::error_code ec;
            const uintmax_t file_size = std::filesystem::file_size(path, ec);
            if (ec) {
                co_return std::unexpected(std::make_error_code(std::errc::no_such_file_or_directory));
            }

            std::ifstream file(path, std::ios::binary);
            if (!file.is_open()) {
                co_return std::unexpected(std::make_error_code(std::errc::no_such_file_or_directory));
            }

            this->set("Content-Type", custom_mime);

            if (file_size < 100 * 1024 * 1024) {
                // < 100 MB: use Content-Length
                this->set("Content-Length", std::to_string(file_size));
                std::string headers = serialize_headers_only();
                is_headers_sent_ = true;
                if (auto res = co_await async_write_with_timeout(headers, timeout); !res) {
                    co_return res;
                }

                std::vector<char> buf(buffer_size);
                while (file.read(buf.data(), static_cast<std::streamsize>(buf.size())) || file.gcount() > 0) {
                    const auto bytes_read = static_cast<std::size_t>(file.gcount());
                    if (bytes_read == 0) break;
                    if (auto res = co_await async_write_with_timeout(std::string_view(buf.data(), bytes_read), timeout);
                        !res) {
                        co_return res;
                    }
                }
                is_sent_ = true;
                co_return std::expected<void, std::error_code>{};
            }

            // Chunked streaming for large files
            std::vector<char> buf(buffer_size);
            while (file.read(buf.data(), static_cast<std::streamsize>(buf.size())) || file.gcount() > 0) {
                const auto bytes_read = static_cast<std::size_t>(file.gcount());
                if (bytes_read == 0) break;
                if (auto res = co_await write_chunk(std::string_view(buf.data(), bytes_read), timeout); !res) {
                    co_return res;
                }
            }
            co_return co_await end_chunked(timeout);
        }

    private:
        [[nodiscard]] asio::awaitable<std::expected<void, std::error_code> > async_write_with_timeout(
            const std::string_view data,
            const std::chrono::milliseconds timeout) const {
            if (!socket_ || !socket_->is_open()) {
                co_return std::unexpected(std::make_error_code(std::errc::not_connected));
            }

            auto executor = co_await asio::this_coro::executor;
            asio::steady_timer timer(executor, timeout);
            bool timed_out = false;

            timer.async_wait([&](const std::error_code ec) {
                if (!ec && socket_) {
                    timed_out = true;
                    std::error_code cancel_ec;
                    std::ignore = socket_->cancel(cancel_ec);
                }
            });

            auto [write_ec, bytes_written] = co_await asio::async_write(
                *socket_,
                asio::buffer(data),
                asio::as_tuple(asio::use_awaitable));

            (void) timer.cancel();

            if (timed_out || write_ec == asio::error::operation_aborted) {
                std::error_code close_ec;
                std::ignore = socket_->close(close_ec);
                co_return std::unexpected(std::make_error_code(std::errc::timed_out));
            }

            if (write_ec) {
                co_return std::unexpected(write_ec);
            }

            co_return std::expected<void, std::error_code>{};
        }

        [[nodiscard]] std::string serialize_headers_only() const {
            response_type res;
            if constexpr (requires { res.stream_id = stream_id_; }) {
                res.stream_id = stream_id_;
            }
            res.status_code = status_code_;
            res.status_text = (status_text_.empty() || (status_text_ == "OK" && status_code_ != 200))
                                  ? Codec::status_text_for(status_code_)
                                  : status_text_;
            res.body = "";

            if (!headers_views_.empty()) {
                res.headers.reserve(headers_views_.size());
                for (const auto &[name, value]: headers_views_) {
                    res.headers.emplace_back(name, value);
                }
            } else {
                res.headers.reserve(headers_.size());
                for (const auto &[name, value]: headers_) {
                    res.headers.emplace_back(name, value);
                }
            }

            return encoder_type::serialize(res);
        }

        asio::ip::tcp::socket *socket_ = nullptr;
        uint32_t stream_id_{1};
        std::string_view status_text_{"OK"};
        std::string buffer_owner_;
        std::string dechunked_body_storage_;
        std::string_view body_view_;
        response_type parsed_;
        std::vector<std::pair<std::string_view, std::string_view> > headers_views_;
        bool is_headers_sent_{false};
    };

    /// Concrete default HTTP/1.x response type aliases
    using Http1Response = HttpResponse<wavex::protos::http::http1codec>;
    using http1response = Http1Response;
} // namespace wavex::protos::http
