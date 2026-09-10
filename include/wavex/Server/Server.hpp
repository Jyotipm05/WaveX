// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file Server.hpp
 * @brief Protocol-agnostic coroutine TCP/TLS server dispatching accepted streams
 *        across an adaptive Tokio-style work-stealing thread pool.
 *
 * Employs the 3-Seam Architecture:
 *  - Seam 1 (Transport): handle_connection<Stream> is written once for any AsyncStream.
 *  - Seam 2 (Codec): Communicates strictly through parse_stream, serialize, and result.
 *  - Seam 3 (Protocol Traits): All protocol-specific connection behavior (opening preface,
 *    persistence, response preparation, and ALPN registration) is delegated to
 *    wavex::protos::protocol_traits<Codec>. Server contains zero codec-specific branching.
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
#include <functional>

#include <wavex/Base/MimeTypes.hpp>
#include <wavex/protos/ProtocolTraits.hpp>

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

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
#include <asio/ssl.hpp>
#include <openssl/ssl.h>
#endif

#include <wavex/Engine/HttpRouter.hpp>
#include <wavex/Server/ThreadPool.hpp>
#include <wavex/Server/TlsConfig.hpp>

namespace wavex::server {
    /**
     * @class Server
     * @brief Completely protocol-agnostic coroutine TCP/TLS server.
     *
     * @tparam Codec Protocol codec (default `protos::http::http1codec`).
     * @tparam RouterType Router specialization (default `engine::HttpRouter<Codec>`).
     */
    template<typename Codec = wavex::protos::http::http1codec,
             typename RouterType = wavex::engine::HttpRouter<Codec> >
    class Server {
    public:
        using codec_type = Codec;
        using traits = wavex::protos::protocol_traits<Codec>;
        using RequestType = typename RouterType::RequestType;
        using ResponseType = typename RouterType::ResponseType;

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
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
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

        /// Configure connection idle timeout
        void set_keep_alive_timeout(std::chrono::seconds timeout) noexcept {
            keep_alive_timeout_ = timeout;
        }

        /// Get current connection idle timeout
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
         * @param body Custom response payload string.
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
         * @brief Configures a static file from disk for 404 Not Found responses on this server.
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

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        std::unique_ptr<asio::ssl::context> ssl_ctx_;

        /**
         * @brief Configures OpenSSL context for strict TLS 1.3 server operation.
         */
        void init_ssl() {
            ssl_ctx_ = std::make_unique<asio::ssl::context>(asio::ssl::context::tlsv13_server);
            ssl_ctx_->set_options(
                asio::ssl::context::default_workarounds |
                asio::ssl::context::no_sslv2 | asio::ssl::context::no_sslv3 |
                asio::ssl::context::no_tlsv1 | asio::ssl::context::no_tlsv1_1 |
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

            // Protocol-driven ALPN selection callback registration
            traits::configure_alpn(ssl_ctx_->native_handle());
        }
#endif

        /// Master acceptor loop — accepts incoming sockets and spawns connection handlers
        asio::awaitable<void> accept_loop() {
            while (is_running_) {
                try {
                    asio::ip::tcp::socket socket = co_await acceptor_.async_accept();
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
                    if (tls_enabled_ && ssl_ctx_) {
                        auto stream = std::make_unique<asio::ssl::stream<asio::ip::tcp::socket> >(
                            std::move(socket), *ssl_ctx_);
                        pool_.spawn_coroutine(handle_connection(std::move(stream)));
                        continue;
                    }
#endif
                    pool_.spawn_coroutine(
                        handle_connection(std::make_unique<asio::ip::tcp::socket>(std::move(socket))));
                } catch (const std::exception &e) {
                    std::cerr << "[Server] Accept error: " << e.what() << "\n";
                    break;
                }
            }
        }

        /**
         * @brief Unified connection handler — written once for every protocol and transport.
         */
        template<typename Stream>
        asio::awaitable<void> handle_connection(std::unique_ptr<Stream> stream_ptr) {
            auto &stream = *stream_ptr;
            std::string stream_buf;
            stream_buf.reserve(8192);
            auto executor = co_await asio::this_coro::executor;

            try {
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
                // Asynchronously perform TLS handshake on worker thread if SSL stream
                if constexpr (requires { stream.async_handshake(asio::ssl::stream_base::server, asio::use_awaitable); }) {
                    asio::error_code hec;
                    co_await stream.async_handshake(
                        asio::ssl::stream_base::server,
                        asio::redirect_error(asio::use_awaitable, hec));
                    if (hec) co_return;
                }
#endif

                // Protocol opening exchange (e.g. HTTP/2 PRI preface and SETTINGS handshake)
                if constexpr (traits::has_connection_preface) {
                    if (!co_await traits::on_connection_start(stream, stream_buf)) co_return;
                }

                unsigned request_count = 0;
                while (is_running_) {
                    RequestType req;
                    auto p_res = req.parse_stream(stream_buf);

                    while (p_res == Codec::result::incomplete && is_running_) {
                        asio::steady_timer timer(executor, keep_alive_timeout_);
                        bool timed_out = false;
                        timer.async_wait([&](const std::error_code ec) {
                            if (!ec) {
                                timed_out = true;
                                std::error_code cancel_ec;
                                std::ignore = stream.lowest_layer().cancel(cancel_ec);
                            }
                        });

                        char buffer[4096];
                        auto [read_ec, bytes_read] = co_await stream.async_read_some(
                            asio::buffer(buffer), asio::as_tuple(asio::use_awaitable));

                        std::error_code timer_ec;
                        std::ignore = timer.cancel(timer_ec);

                        if (timed_out || read_ec == asio::error::operation_aborted) co_return;
                        if (read_ec || bytes_read == 0) co_return;

                        stream_buf.append(buffer, bytes_read);
                        p_res = req.parse_stream(stream_buf);
                    }

                    if (p_res != Codec::result::success) {
                        ResponseType err_res;
                        err_res.status(400).send("Bad Request");
                        co_await asio::async_write(stream, asio::buffer(err_res.serialize()),
                                                   asio::use_awaitable);
                        co_return;
                    }

                    ++request_count;
                    const bool keep = traits::keep_alive(req, request_count, max_keep_alive_requests_);
                    const unsigned remaining =
                        request_count < max_keep_alive_requests_ ? max_keep_alive_requests_ - request_count : 0;

                    auto match = router_.resolve(req.method_type(), req.path());

                    ResponseType res;
                    if constexpr (requires { res.stream_id(req.stream_id()); }) {
                        res.stream_id(req.stream_id());
                    }

                    // Inject per-connection write sink for streaming transfers (chunked, send_file)
                    if constexpr (requires { res.set_write_sink({}); }) {
                        res.set_write_sink([&stream](const std::string_view data,
                                                     const std::chrono::milliseconds timeout)
                            -> asio::awaitable<std::expected<void, std::error_code> > {
                            auto ex = co_await asio::this_coro::executor;
                            asio::steady_timer timer(ex, timeout);
                            bool timed_out = false;
                            timer.async_wait([&](const std::error_code ec) {
                                if (!ec) {
                                    timed_out = true;
                                    std::error_code cancel_ec;
                                    std::ignore = stream.lowest_layer().cancel(cancel_ec);
                                }
                            });

                            auto [write_ec, bytes_written] = co_await asio::async_write(
                                stream, asio::buffer(data), asio::as_tuple(asio::use_awaitable));
                            (void) timer.cancel();

                            if (timed_out || write_ec == asio::error::operation_aborted) {
                                std::error_code close_ec;
                                std::ignore = stream.lowest_layer().close(close_ec);
                                co_return std::unexpected(std::make_error_code(std::errc::timed_out));
                            }
                            if (write_ec) {
                                co_return std::unexpected(write_ec);
                            }
                            co_return std::expected<void, std::error_code>{};
                        });
                    }

                    traits::prepare_response(req, res, keep,
                                             static_cast<unsigned>(keep_alive_timeout_.count()), remaining);
                    res.status(match ? 200 : 404);

                    if (!match) {
                        if (server_not_found_handler_) {
                            co_await (*server_not_found_handler_)(req, res);
                        } else {
                            co_await router_.not_found_handler()(req, res);
                        }
                    } else if (match->middlewares.empty()) {
                        co_await match->handler(req, res);
                    } else {
                        co_await run_chain(req, res, match->middlewares, match->handler);
                    }

                    // Server writes serialized response if headers were not already flushed by streaming
                    if (!res.is_headers_sent()) {
                        co_await asio::async_write(stream, asio::buffer(res.serialize()),
                                                   asio::use_awaitable);
                    }

                    stream_buf.erase(0, req.consumed_bytes());
                    if (!keep) break;
                }
            } catch (const std::exception &) {
                // Connection closed or stream error
            }

            // Graceful transport shutdown
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
            if constexpr (requires { stream.async_shutdown(asio::use_awaitable); }) {
                asio::error_code ignore_ec;
                co_await stream.async_shutdown(asio::redirect_error(asio::use_awaitable, ignore_ec));
            } else
#endif
            {
                asio::error_code ignore_ec;
                std::ignore = stream.shutdown(asio::ip::tcp::socket::shutdown_both, ignore_ec);
            }
            asio::error_code ignore_ec;
            std::ignore = stream.lowest_layer().close(ignore_ec);
            co_return;
        }

        /// Generic middleware chain runner helper for arbitrary CRTP Request/Response types
        template<typename ReqT, typename ResT, typename MwVec, typename H>
        static asio::awaitable<void> run_chain(ReqT &req, ResT &res, const MwVec &mws, const H &handler) {
            std::size_t idx = 0;
            while (idx < mws.size() && !res.is_sent()) {
                bool next_called = false;
                wavex::base::Next next = [&next_called]() -> asio::awaitable<void> {
                    next_called = true;
                    co_return;
                };
                co_await mws[idx](req, res, std::move(next));
                idx++;
                if (!next_called || res.is_sent()) break;
            }
            if (!res.is_sent()) co_await handler(req, res);
            co_return;
        }
    };

    /// Protocol-specialized server type aliases
    using Http1Server = Server<wavex::protos::http::http1codec, wavex::engine::Http1Router>;
    using http1server = Http1Server;
    using Http2Server = Server<wavex::protos::http::http2codec, wavex::engine::Http2Router>;
    using http2server = Http2Server;
    using HttpServer = Http1Server;
    using httpserver = HttpServer;
} // namespace wavex::server
