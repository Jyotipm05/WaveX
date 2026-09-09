// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file Server.hpp
 * @brief Templated coroutine-based TCP/TLS Server with master acceptor and dynamic slave thread pool.
 *
 * Parametric on `Codec` (default `http1codec`) and `RouterType` (default `HttpRouter`)
 * to easily support HTTP/1.x, HTTP/2, HTTP/3, and protocol upgrades.
 */

#pragma once

#ifndef ASIO_HAS_CO_AWAIT
#define ASIO_HAS_CO_AWAIT 1
#endif

#include <iostream>
#include <string>
#include <utility>
#include <memory>
#include <optional>
#include <filesystem>
#include <fstream>
#include <chrono>
#include <atomic>

#include <wavex/Base/MimeTypes.hpp>

#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/write.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/as_tuple.hpp>
#include <asio/steady_timer.hpp>
#include <asio/redirect_error.hpp>

#if WAVEX_HAS_SSL
#include <asio/ssl.hpp>
#include <openssl/ssl.h>  // For SSL_CTX_set_alpn_protos (ALPN negotiation)
#endif

#include <wavex/Engine/HttpRouter.hpp>
#include <wavex/protos/http/http1codec.hpp>
#include <wavex/protos/http/http2codec.hpp>
#include <wavex/protos/http/HttpRequest.hpp>
#include <wavex/protos/http/HttpResponse.hpp>
#include <wavex/Server/ThreadPool.hpp>
#include <wavex/Server/TlsConfig.hpp>

namespace wavex::server {
    /**
     * @class Server
     * @brief Coroutine TCP/TLS Server dispatching accepted streams across a dynamic work-stealing thread pool.
     *
     * @tparam Codec Protocol codec (default `protos::http::http1codec`).
     * @tparam RouterType Router specialization (default `engine::HttpRouter`).
     */
    template<typename Codec = wavex::protos::http::http1codec, typename RouterType = wavex::engine::HttpRouter<Codec> >
    class Server {
    public:
        using codec_type = Codec;
        using RequestType = wavex::protos::http::HttpRequest<Codec>;
        using ResponseType = wavex::protos::http::HttpResponse<Codec>;

        /**
         * @brief Constructs a Server listening on the specified address and port.
         * @param router Reference to the protocol router.
         * @param address IP address or host string.
         * @param port Network port number.
         */
        Server(RouterType &router, std::string address, const unsigned short port)
            : router_(router),
              address_(std::move(address)),
              acceptor_(master_io_, asio::ip::tcp::endpoint(asio::ip::make_address(address_), port)),
              port_(port) {
        }

        ~Server() {
            stop();
        }

        Server(const Server &) = delete;

        Server &operator=(const Server &) = delete;

        /**
         * @brief Enables TLS 1.3 encryption on this server instance using a TlsConfig struct.
         * @param config TlsConfig struct containing certificate and key file paths.
         */
        void enable_tls(TlsConfig config) {
#if WAVEX_HAS_SSL
            tls_config_ = std::move(config);
            init_ssl();
            tls_enabled_ = true;
#else
            (void) config;
            throw std::runtime_error(
                "Server::enable_tls failed: WaveX was built without OpenSSL TLS support (WAVEX_HAS_SSL=0)");
#endif
        }

        /**
         * @brief Convenience overload to enable TLS 1.3 directly with certificate and key file paths.
         * @param cert_file Path to PEM certificate chain file (defaults to ssl/test.crt).
         * @param key_file Path to PEM private key file (defaults to ssl/test.key).
         */
        void enable_tls(std::string cert_file = "ssl/test.crt", std::string key_file = "ssl/test.key") {
            TlsConfig cfg;
            cfg.cert_file = std::move(cert_file);
            cfg.key_file = std::move(key_file);
            enable_tls(std::move(cfg));
        }

        /**
         * @brief Checks if TLS encryption is enabled on this server instance.
         * @return True if TLS is enabled, false otherwise.
         */
        [[nodiscard]] bool is_tls_enabled() const { return tls_enabled_; }

        /// Start master acceptor loop and run event loop
        void run() {
            if (is_running_) [[unlikely]] {
                std::cerr << "Critical: Duplicate run() invocation detected!\n";
                return;
            }
            is_running_ = true;
            asio::co_spawn(master_io_, accept_loop(), asio::detached);
            master_io_.run();
        }

        /// Stop the server and thread pool
        void stop() {
            if (!is_running_) [[unlikely]] return;
            is_running_ = false;
            master_io_.stop();
        }

        /// Access the underlying thread pool
        ThreadPool &pool() { return pool_; }

        /// Configure HTTP Keep-Alive idle timeout
        void set_keep_alive_timeout(std::chrono::seconds timeout) noexcept {
            keep_alive_timeout_ = timeout;
        }

        /// Get current HTTP Keep-Alive idle timeout
        [[nodiscard]] std::chrono::seconds keep_alive_timeout() const noexcept {
            return keep_alive_timeout_;
        }

        /// Configure max sequential requests allowed on a single persistent connection
        void set_max_keep_alive_requests(unsigned max_requests) noexcept {
            max_keep_alive_requests_ = max_requests;
        }

        /// Get max sequential requests allowed on a single persistent connection
        [[nodiscard]] unsigned max_keep_alive_requests() const noexcept {
            return max_keep_alive_requests_;
        }

        using NotFoundHandler = std::function<asio::awaitable<void>(RequestType &, ResponseType &)>;

        /**
         * @brief Configures a custom coroutine handler for 404 Not Found responses on this server.
         * @param h Custom handler lambda or function.
         */
        void set_not_found_handler(NotFoundHandler h) {
            server_not_found_handler_ = std::move(h);
        }

        /**
         * @brief Configures a custom static body and Content-Type for 404 Not Found responses on this server.
         * @param body Custom response payload string (e.g. custom text, JSON string, or HTML).
         * @param content_type Optional Content-Type header (defaults to "text/plain").
         */
        void set_not_found(std::string body, std::string content_type = "text/plain") {
            server_not_found_handler_ = [b = std::move(body), ct = std::move(content_type)](
                RequestType &, ResponseType &res) -> asio::awaitable<void> {
                        res.status(404);
                        if (!ct.empty()) {
                            res.set("Content-Type", ct);
                        }
                        res.send(b);
                        co_return;
                    };
        }

        /**
         * @brief Configures a static file or HTML page from disk for 404 Not Found responses on this server.
         *
         * Automatically infers Content-Type via wavex::base::mime_type_from_path.
         * If the file is not found or unreadable, falls back to default "Not Found".
         *
         * @param file_path Path to the error page file.
         */
        void set_not_found_page(const std::filesystem::path &file_path) {
            if (std::filesystem::exists(file_path)) {
                std::ifstream file(file_path, std::ios::binary);
                if (file) {
                    std::string content((std::istreambuf_iterator<char>(file)),
                                        std::istreambuf_iterator<char>());
                    std::string mime = std::string(base::mime_type_from_path(file_path.string()));
                    set_not_found(std::move(content), std::move(mime));
                    return;
                }
            }
            set_not_found("Not Found", "text/plain");
        }

    private:
        RouterType &router_;
        std::string address_;
        asio::io_context master_io_;
        asio::ip::tcp::acceptor acceptor_;
        ThreadPool pool_;
        unsigned short port_;
        std::atomic<bool> is_running_{false};
        bool tls_enabled_{false};
        TlsConfig tls_config_;
        std::chrono::seconds keep_alive_timeout_{5};
        unsigned max_keep_alive_requests_{1000};
        std::optional<NotFoundHandler> server_not_found_handler_{std::nullopt};

#if WAVEX_HAS_SSL
        std::unique_ptr<asio::ssl::context> ssl_ctx_;

        /**
         * @brief Configures OpenSSL context for strict TLS 1.3 server operation.
         */
        void init_ssl() {
            ssl_ctx_ = std::make_unique<asio::ssl::context>(asio::ssl::context::tlsv13_server);
            ssl_ctx_->set_options(
                asio::ssl::context::default_workarounds |
                asio::ssl::context::no_sslv2 |
                asio::ssl::context::no_sslv3 |
                asio::ssl::context::no_tlsv1 |
                asio::ssl::context::no_tlsv1_1 |
                asio::ssl::context::no_tlsv1_2
            );

            if (!tls_config_.key_password.empty()) {
                ssl_ctx_->set_password_callback(
                    [pwd = tls_config_.key_password](std::size_t, asio::ssl::context::password_purpose) {
                        return pwd;
                    });
            }

            std::string cert_path = tls_config_.cert_file;
            std::string key_path = tls_config_.key_file;

            if (!std::filesystem::exists(cert_path)) {
#ifdef PROJECT_DIR
                std::string alt = std::string(PROJECT_DIR) + "/" + cert_path;
                if (std::filesystem::exists(alt)) cert_path = alt;
#endif
                if (!std::filesystem::exists(cert_path) && std::filesystem::exists("../" + tls_config_.cert_file)) {
                    cert_path = "../" + tls_config_.cert_file;
                }
            }

            if (!std::filesystem::exists(key_path)) {
#ifdef PROJECT_DIR
                std::string alt = std::string(PROJECT_DIR) + "/" + key_path;
                if (std::filesystem::exists(alt)) key_path = alt;
#endif
                if (!std::filesystem::exists(key_path) && std::filesystem::exists("../" + tls_config_.key_file)) {
                    key_path = "../" + tls_config_.key_file;
                }
            }

            ssl_ctx_->use_certificate_chain_file(cert_path);
            ssl_ctx_->use_private_key_file(key_path, asio::ssl::context::pem);

            if (!tls_config_.dh_file.empty()) {
                ssl_ctx_->use_tmp_dh_file(tls_config_.dh_file);
            }

            // ── ALPN (Application-Layer Protocol Negotiation) ──────────────────────
            // RFC 7301: ALPN is mandatory for HTTP/2 over TLS (RFC 7540 §3.3).
            // IMPORTANT: SSL_CTX_set_alpn_protos() is CLIENT-SIDE only.
            // Servers MUST use SSL_CTX_set_alpn_select_cb() to register a selection
            // callback. Without it Chrome/Firefox see no negotiated protocol and refuse
            // to upgrade to HTTP/2, causing immediate ERR_EMPTY_RESPONSE.
            if constexpr (std::is_same_v<Codec, wavex::protos::http::http2codec>) {
                // HTTP/2 server: prefer "h2", fall back to "http/1.1"
                SSL_CTX_set_alpn_select_cb(
                    ssl_ctx_->native_handle(),
                    [](SSL *, const unsigned char **out, unsigned char *outlen,
                       const unsigned char *in, unsigned int inlen, void *) -> int {
                        // Walk the client's protocol list (each entry: 1-byte length + name)
                        const unsigned char *p = in;
                        const unsigned char *http11_start = nullptr;
                        while (p < in + inlen) {
                            const unsigned char len = *p++;
                            if (len == 2 && p[0] == 'h' && p[1] == '2') {
                                *out = p;
                                *outlen = 2;
                                return SSL_TLSEXT_ERR_OK;
                            }
                            if (len == 8 && std::memcmp(p, "http/1.1", 8) == 0) {
                                http11_start = p; // Remember as fallback
                            }
                            p += len;
                        }
                        if (http11_start) {
                            *out = http11_start;
                            *outlen = 8;
                            return SSL_TLSEXT_ERR_OK;
                        }
                        return SSL_TLSEXT_ERR_ALERT_FATAL;
                    },
                    nullptr);
            } else {
                // HTTP/1.1 TLS server: select "http/1.1"
                SSL_CTX_set_alpn_select_cb(
                    ssl_ctx_->native_handle(),
                    [](SSL *, const unsigned char **out, unsigned char *outlen,
                       const unsigned char *in, unsigned int inlen, void *) -> int {
                        const unsigned char *p = in;
                        while (p < in + inlen) {
                            const unsigned char len = *p++;
                            if (len == 8 && std::memcmp(p, "http/1.1", 8) == 0) {
                                *out = p;
                                *outlen = 8;
                                return SSL_TLSEXT_ERR_OK;
                            }
                            p += len;
                        }
                        // No match — don't abort, just proceed without ALPN
                        return SSL_TLSEXT_ERR_NOACK;
                    },
                    nullptr);
            }
        }
#endif

        /// Master thread acceptor loop
        asio::awaitable<void> accept_loop() {
            while (is_running_) {
                try {
                    asio::ip::tcp::socket socket = co_await acceptor_.async_accept();
#if WAVEX_HAS_SSL
                    if (tls_enabled_ && ssl_ctx_) {
                        auto ssl_socket = std::make_unique<asio::ssl::stream<asio::ip::tcp::socket> >(
                            std::move(socket), *ssl_ctx_);
                        pool_.spawn_coroutine(handle_tls_client(std::move(ssl_socket)));
                        continue;
                    }
#endif
                    pool_.spawn_coroutine(handle_client(std::move(socket)));
                } catch (const std::exception &e) {
                    std::cerr << "[Server] Accept error: " << e.what() << "\n";
                    break;
                }
            }
        }

        /// Plain TCP client connection processing coroutine with persistent stay-active loop
        asio::awaitable<void> handle_client(asio::ip::tcp::socket socket) {
            std::string stream_buf;
            stream_buf.reserve(8192);
            auto executor = co_await asio::this_coro::executor;

            // ── HTTP/2 Connection Preface (RFC 7540 §3.5) ─────────────────────────────
            // For HTTP/2 (h2c), we must:
            //   1. Read the 24-byte client connection preface (PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n).
            //   2. Send our own server SETTINGS frame.
            //   3. Send a SETTINGS ACK for the client's initial SETTINGS frame.
            // Browsers will stall indefinitely if the server skips this exchange.
            constexpr bool is_http2 = std::is_same_v<Codec, wavex::protos::http::http2codec>;
            if constexpr (is_http2) {
                // Read until we have at least the connection preface + one SETTINGS frame header
                while (stream_buf.size() < wavex::protos::http::http2::CONNECTION_PREFACE.size() + 9) {
                    char buf[4096];
                    auto [ec, n] = co_await socket.async_read_some(
                        asio::buffer(buf), asio::as_tuple(asio::use_awaitable));
                    if (ec || n == 0) co_return;
                    stream_buf.append(buf, n);
                }

                // Validate client connection preface
                if (!stream_buf.starts_with(wavex::protos::http::http2::CONNECTION_PREFACE)) {
                    co_return; // Not an HTTP/2 client
                }

                // Send server SETTINGS (empty — accept all defaults) + SETTINGS ACK
                const std::string server_settings = wavex::protos::http::http2::encoder::serialize_settings({});
                const std::string settings_ack = wavex::protos::http::http2::encoder::serialize_settings_ack();
                std::string preface_response;
                preface_response.reserve(server_settings.size() + settings_ack.size());
                preface_response += server_settings;
                preface_response += settings_ack;

                asio::error_code write_ec;
                co_await asio::async_write(
                    socket, asio::buffer(preface_response),
                    asio::redirect_error(asio::use_awaitable, write_ec));
                if (write_ec) co_return;

                // Strip the 24-byte preface from the buffer.
                // The parser only expects raw HTTP/2 frames from here on.
                // Remaining bytes (client SETTINGS, SETTINGS ACK, WINDOW_UPDATE, etc.)
                // are handled by parse_request's frame-skipping logic.
                stream_buf.erase(0, wavex::protos::http::http2::CONNECTION_PREFACE.size());
            }

            try {
                unsigned request_count = 0;
                while (is_running_) {
                    RequestType req;
                    auto p_res = req.parse_stream(stream_buf);

                    while (p_res == Codec::parser::result::incomplete && is_running_) {
                        asio::steady_timer timer(executor, keep_alive_timeout_);
                        bool timed_out = false;

                        timer.async_wait([&](const std::error_code ec) {
                            if (!ec) {
                                timed_out = true;
                                std::error_code cancel_ec;
                                std::ignore = socket.cancel(cancel_ec);
                            }
                        });

                        char buffer[4096];
                        auto [read_ec, bytes_read] = co_await socket.async_read_some(
                            asio::buffer(buffer), asio::as_tuple(asio::use_awaitable));

                        std::error_code timer_ec;
                        std::ignore = timer.cancel(timer_ec);

                        if (timed_out || read_ec == asio::error::operation_aborted) {
                            // Inactivity timeout expired
                            co_return;
                        }
                        if (read_ec || bytes_read == 0) {
                            // Client closed connection or read error
                            co_return;
                        }

                        stream_buf.append(buffer, bytes_read);
                        p_res = req.parse_stream(stream_buf);
                    }

                    if (p_res != Codec::parser::result::success) {
                        if constexpr (!is_http2) {
                            ResponseType err_res(&socket);
                            err_res.set_keep_alive(false);
                            err_res.status(400).send("Bad Request");
                            std::string out = err_res.serialize();
                            co_await asio::async_write(socket, asio::buffer(out), asio::use_awaitable);
                        }
                        co_return;
                    }

                    ++request_count;

                    // HTTP/2 connections are always persistent and multiplexed.
                    // HTTP/1-style Connection/Keep-Alive headers are forbidden in HTTP/2 (RFC 7540 §8.1.2.2).
                    const bool keep_alive = is_http2
                                                ? true
                                                : (req.should_keep_alive() && (
                                                       request_count < max_keep_alive_requests_));

                    auto match = router_.resolve(req.method_type(), req.path());
                    if (!match) {
                        ResponseType not_found_res(&socket);
                        if constexpr (requires { not_found_res.stream_id(req.stream_id()); }) {
                            not_found_res.stream_id(req.stream_id());
                        }
                        if constexpr (!is_http2) {
                            not_found_res.set_keep_alive(keep_alive,
                                                         static_cast<unsigned>(keep_alive_timeout_.count()),
                                                         max_keep_alive_requests_ - request_count);
                        }
                        not_found_res.status(404);

                        if (server_not_found_handler_) {
                            co_await (*server_not_found_handler_)(req, not_found_res);
                        } else {
                            co_await router_.not_found_handler()(req, not_found_res);
                        }

                        if (!not_found_res.is_sent()) {
                            std::string out = not_found_res.serialize();
                            co_await asio::async_write(socket, asio::buffer(out), asio::use_awaitable);
                        }
                        if constexpr (!is_http2) {
                            if (!keep_alive || !not_found_res.should_keep_alive()) co_return;
                        }
                        stream_buf.erase(0, req.consumed_bytes());
                        continue;
                    }

                    ResponseType res(&socket);
                    if constexpr (requires { res.stream_id(req.stream_id()); }) {
                        res.stream_id(req.stream_id());
                    }
                    if constexpr (!is_http2) {
                        res.set_keep_alive(keep_alive,
                                           static_cast<unsigned>(keep_alive_timeout_.count()),
                                           max_keep_alive_requests_ - request_count);
                    }

                    if (match->middlewares.empty()) {
                        co_await match->handler(req, res);
                    } else {
                        co_await run_chain(req, res, match->middlewares, match->handler);
                    }

                    if (!res.is_sent()) {
                        std::string response_bytes = res.serialize();
                        co_await asio::async_write(socket, asio::buffer(response_bytes), asio::use_awaitable);
                    }

                    stream_buf.erase(0, req.consumed_bytes());

                    if constexpr (!is_http2) {
                        if (!keep_alive || !res.should_keep_alive()) {
                            break;
                        }
                    }
                }
            } catch (const std::exception &) {
                // Connection closed or socket error
            }

            asio::error_code ignore_ec;
            std::ignore = socket.shutdown(asio::ip::tcp::socket::shutdown_both, ignore_ec);
            std::ignore = socket.close(ignore_ec);
            co_return;
        }

#if WAVEX_HAS_SSL
        /// TLS client connection processing coroutine with persistent stay-active loop
        asio::awaitable<void> handle_tls_client(
            std::unique_ptr<asio::ssl::stream<asio::ip::tcp::socket> > ssl_socket_ptr) {
            auto &ssl_socket = *ssl_socket_ptr;
            std::string stream_buf;
            stream_buf.reserve(8192);
            auto executor = co_await asio::this_coro::executor;

            try {
                unsigned request_count = 0;
                co_await ssl_socket.async_handshake(asio::ssl::stream_base::server, asio::use_awaitable);

                // ── HTTP/2 Connection Preface over TLS (RFC 7540 §3.5) ────────────────
                // After TLS handshake, the client sends the 24-byte PRI preface + SETTINGS.
                // We must reply with server SETTINGS + SETTINGS ACK before any responses.
                constexpr bool is_http2 = std::is_same_v<Codec, wavex::protos::http::http2codec>;
                if constexpr (is_http2) {
                    while (stream_buf.size() < wavex::protos::http::http2::CONNECTION_PREFACE.size() + 9) {
                        char buf[4096];
                        auto [ec, n] = co_await ssl_socket.async_read_some(
                            asio::buffer(buf), asio::as_tuple(asio::use_awaitable));
                        if (ec || n == 0) co_return;
                        stream_buf.append(buf, n);
                    }

                    if (!stream_buf.starts_with(wavex::protos::http::http2::CONNECTION_PREFACE)) {
                        co_return;
                    }

                    const std::string server_settings = wavex::protos::http::http2::encoder::serialize_settings({});
                    const std::string settings_ack = wavex::protos::http::http2::encoder::serialize_settings_ack();
                    std::string preface_response;
                    preface_response.reserve(server_settings.size() + settings_ack.size());
                    preface_response += server_settings;
                    preface_response += settings_ack;

                    asio::error_code write_ec;
                    co_await asio::async_write(
                        ssl_socket, asio::buffer(preface_response),
                        asio::redirect_error(asio::use_awaitable, write_ec));
                    if (write_ec) co_return;

                    // Strip the 24-byte preface — parser only expects raw HTTP/2 frames.
                    stream_buf.erase(0, wavex::protos::http::http2::CONNECTION_PREFACE.size());
                }

                while (is_running_) {
                    RequestType req;
                    auto p_res = req.parse_stream(stream_buf);

                    while (p_res == Codec::parser::result::incomplete && is_running_) {
                        asio::steady_timer timer(executor, keep_alive_timeout_);
                        bool timed_out = false;

                        timer.async_wait([&](const std::error_code ec) {
                            if (!ec) {
                                timed_out = true;
                                std::error_code cancel_ec;
                                std::ignore = ssl_socket.lowest_layer().cancel(cancel_ec);
                            }
                        });

                        char buffer[4096];
                        auto [read_ec, bytes_read] = co_await ssl_socket.async_read_some(
                            asio::buffer(buffer), asio::as_tuple(asio::use_awaitable));

                        std::error_code timer_ec;
                        std::ignore = timer.cancel(timer_ec);

                        if (timed_out || read_ec == asio::error::operation_aborted) {
                            // Inactivity timeout expired
                            co_return;
                        }
                        if (read_ec || bytes_read == 0) {
                            // Client closed connection or read error
                            co_return;
                        }

                        stream_buf.append(buffer, bytes_read);
                        p_res = req.parse_stream(stream_buf);
                    }

                    if (p_res != Codec::parser::result::success) {
                        if constexpr (!is_http2) {
                            ResponseType err_res;
                            err_res.set_keep_alive(false);
                            err_res.status(400).send("Bad Request");
                            std::string out = err_res.serialize();
                            co_await asio::async_write(ssl_socket, asio::buffer(out), asio::use_awaitable);
                        }
                        co_return;
                    }

                    ++request_count;

                    // HTTP/2 connections are always persistent and multiplexed.
                    // HTTP/1-style Connection/Keep-Alive headers are forbidden in HTTP/2 (RFC 7540 §8.1.2.2).
                    const bool keep_alive = is_http2
                                                ? true
                                                : (req.should_keep_alive() && (
                                                       request_count < max_keep_alive_requests_));

                    auto match = router_.resolve(req.method_type(), req.path());
                    if (!match) {
                        ResponseType not_found_res;
                        if constexpr (requires { not_found_res.stream_id(req.stream_id()); }) {
                            not_found_res.stream_id(req.stream_id());
                        }
                        if constexpr (!is_http2) {
                            not_found_res.set_keep_alive(keep_alive,
                                                         static_cast<unsigned>(keep_alive_timeout_.count()),
                                                         max_keep_alive_requests_ - request_count);
                        }
                        not_found_res.status(404);

                        if (server_not_found_handler_) {
                            co_await (*server_not_found_handler_)(req, not_found_res);
                        } else {
                            co_await router_.not_found_handler()(req, not_found_res);
                        }

                        // Always write via ssl_socket — TLS ResponseType has no socket ptr,
                        // so send_impl() never actually sends even when is_sent_ becomes true.
                        {
                            std::string out = not_found_res.serialize();
                            co_await asio::async_write(ssl_socket, asio::buffer(out), asio::use_awaitable);
                        }
                        if constexpr (!is_http2) {
                            if (!keep_alive || !not_found_res.should_keep_alive()) co_return;
                        }
                        stream_buf.erase(0, req.consumed_bytes());
                        continue;
                    }

                    ResponseType res;
                    if constexpr (requires { res.stream_id(req.stream_id()); }) {
                        res.stream_id(req.stream_id());
                    }
                    if constexpr (!is_http2) {
                        res.set_keep_alive(keep_alive,
                                           static_cast<unsigned>(keep_alive_timeout_.count()),
                                           max_keep_alive_requests_ - request_count);
                    }

                    if (match->middlewares.empty()) {
                        co_await match->handler(req, res);
                    } else {
                        co_await run_chain(req, res, match->middlewares, match->handler);
                    }

                    // In the TLS handler, ResponseType is constructed without a socket pointer.
                    // This means send()/json() → send_impl() sets is_sent_=true but cannot write to
                    // the ssl_socket. We must always serialize and write here via ssl_socket.
                    {
                        std::string response_bytes = res.serialize();
                        co_await asio::async_write(ssl_socket, asio::buffer(response_bytes), asio::use_awaitable);
                    }

                    stream_buf.erase(0, req.consumed_bytes());

                    if constexpr (!is_http2) {
                        if (!keep_alive || !res.should_keep_alive()) {
                            break;
                        }
                    }
                }
            } catch (const std::exception &) {
                // Connection closed or SSL error
            }

            asio::error_code ignore_ec;
            co_await ssl_socket.async_shutdown(asio::redirect_error(asio::use_awaitable, ignore_ec));
            std::ignore = ssl_socket.lowest_layer().close(ignore_ec);
            co_return;
        }
#endif

        /// Generic middleware chain runner helper for arbitrary CRTP Request/Response types
        template<typename ReqT, typename ResT, typename MwVec, typename H>
        static asio::awaitable<void> run_chain(
            ReqT &req,
            ResT &res,
            const MwVec &mws,
            const H &handler) {
            std::size_t idx = 0;
            while (idx < mws.size() && !res.is_sent()) {
                bool next_called = false;
                wavex::base::Next next = [&next_called]() -> asio::awaitable<void> {
                    next_called = true;
                    co_return;
                };

                co_await mws[idx](req, res, std::move(next));
                idx++;

                if (!next_called || res.is_sent()) {
                    break;
                }
            }

            if (!res.is_sent()) {
                co_await handler(req, res);
            }
            co_return;
        }
    };

    /// Concrete default HTTP/1.x server type aliases
    using Http1Server = Server<wavex::protos::http::http1codec, wavex::engine::Http1Router>;
    using http1server = Http1Server;

    /// Concrete HTTP/2 server type aliases
    using Http2Server = Server<wavex::protos::http::http2codec, wavex::engine::Http2Router>;
    using http2server = Http2Server;
} // namespace wavex::server
