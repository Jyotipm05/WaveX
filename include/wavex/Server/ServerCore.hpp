// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file ServerCore.hpp
 * @brief Protocol-agnostic coroutine TCP/TLS/QUIC server class declaration.
 *
 * This file contains ONLY the class declaration with member variables and
 * method signatures. Implementations are located in .ipp files.
 *
 * @note This file should NOT be included directly. Include Server.hpp instead.
 */

#pragma once

#ifndef ASIO_HAS_CO_AWAIT
#define ASIO_HAS_CO_AWAIT 1
#endif

#include <wavex/Server/ServerState.hpp>
#include <wavex/Server/ConnectionTracker.hpp>
#include <wavex/Server/ThreadPool.hpp>
#include <wavex/Server/TlsConfig.hpp>
#include <wavex/Engine/HttpRouter.hpp>
#include <wavex/protos/ProtocolTraits.hpp>
#include <wavex/protos/http/http.hpp>
#include <wavex/Network/QUIC.hpp>
#include <wavex/Base/Event.hpp>

#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/awaitable.hpp>
#include <asio/signal_set.hpp>
#include <asio/steady_timer.hpp>

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
#include <asio/ssl.hpp>
#endif

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace wavex::server {

    template<typename C>
    inline constexpr bool is_http3_codec_v =
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        std::is_same_v<C, protos::http::http3codec>;
#else
        false;
#endif

    /**
     * @class Server
     * @brief Completely protocol-agnostic coroutine TCP/TLS/QUIC server.
     *
     * @tparam Codec Protocol codec (default `protos::http::http1codec`).
     * @tparam RouterType Router specialization (default `engine::HttpRouter<Codec>`).
     */
    template<typename Codec = wavex::protos::http::http1codec,
             typename RouterType = wavex::engine::HttpRouter<Codec>>
    class Server {
    public:
        // ─── 1. Nested Types & Definitions ───────────────────────────────────
        using codec_type = Codec;
        using traits = protos::protocol_traits<Codec>;
        using RequestType = RouterType::RequestType;
        using ResponseType = RouterType::ResponseType;
        using NotFoundHandler = std::function<asio::awaitable<void>(RequestType &, ResponseType &)>;

        static constexpr bool has_quic_transport = requires {
            { traits::has_quic_transport } -> std::convertible_to<bool>;
        } && traits::has_quic_transport;

        static constexpr bool has_tcp_transport = requires {
            { traits::has_tcp_transport } -> std::convertible_to<bool>;
        } ? traits::has_tcp_transport : true;

    private:
        // ─── 2. Member Variables (Arranged for minimum padding) ──────────────
        RouterType &router_;                                  // 8 bytes (reference)
        std::string address_;                                 // complex (32 bytes)
        asio::io_context master_io_;                          // complex
        asio::ip::tcp::acceptor acceptor_;                    // complex
        ThreadPool pool_;                                     // complex
        ConnectionTracker conn_tracker_;                      // complex
        TlsConfig tls_config_;                                // complex
        std::optional<NotFoundHandler> server_not_found_handler_{std::nullopt}; // complex
        std::optional<asio::signal_set> signals_;             // complex
        std::optional<asio::steady_timer> shutdown_timer_;    // complex

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        std::unique_ptr<asio::ssl::context> ssl_ctx_;         // 8 bytes (pointer)
        std::unique_ptr<network::quic::QuicServer> quic_server_; // 8 bytes (pointer)
        engine::Http3Router *h3_router_{nullptr};             // 8 bytes (pointer)
#endif

        std::chrono::milliseconds shutdown_timeout_{10000};   // 8 bytes
        std::chrono::seconds keep_alive_timeout_{5};           // 8 bytes
        std::size_t max_request_size_{100 * 1024 * 1024};     // 8 bytes
        std::size_t max_memory_buffer_{10 * 1024 * 1024};     // 8 bytes
        std::size_t max_query_params_{64};                    // 8 bytes
        std::size_t max_headers_{100};                        // 8 bytes
        std::atomic<std::size_t> active_connections_{0};      // 8 bytes
        unsigned max_keep_alive_requests_{1000};              // 4 bytes
        unsigned short port_{0};                              // 2 bytes
        std::atomic<ServerState> state_{ServerState::Stopped}; // 1 byte
        std::atomic<bool> is_stopped_{false};                 // 1 byte
        std::atomic<bool> is_signal_shutdown_{false};         // 1 byte
        bool enable_signals_{true};                           // 1 byte
        bool exit_on_signal_{true};                           // 1 byte
        bool tls_enabled_{false};                             // 1 byte
        bool allow_insecure_quic_{false};                     // 1 byte
        bool http3_enabled_{false};                           // 1 byte

    public:
        // ─── 3. Constructors & Destructor ────────────────────────────────────
        Server(RouterType &router, std::string address, const unsigned short port);
        ~Server();

        Server(const Server &) = delete;
        Server &operator=(const Server &) = delete;
        Server(Server &&) = delete;
        Server &operator=(Server &&) = delete;

        // ─── 4. Member Functions ─────────────────────────────────────────────

        // Lifecycle (ServerLifecycle.ipp)
        void run();
        void exit(std::chrono::milliseconds timeout = std::chrono::seconds(10));
        void shutdown(std::chrono::milliseconds timeout = std::chrono::seconds(10));
        void attach_shutdown_event(base::ShutdownEvent &event);
        void attach_event_bus(base::EventBus &bus);
        void stop();

        // TLS (ServerTls.ipp)
        void enable_tls(TlsConfig config);
        void enable_tls(std::string cert_file = "ssl/test.crt",
                       std::string key_file = "ssl/test.key");
        [[nodiscard]] bool is_tls_enabled() const noexcept;

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        // HTTP/3 & QUIC (ServerQuic.ipp)
        [[nodiscard]] bool is_http3_enabled() const noexcept;
        void enable_http3(engine::Http3Router &h3_router) noexcept;
        void attach_http3(engine::Http3Router &h3_router) noexcept;
        void allow_insecure(bool allow = true) noexcept;

        // Connection handling (ServerConnection.ipp)
        template<typename Stream>
        asio::awaitable<void> handle_connection(std::shared_ptr<Stream> stream_ptr);

        asio::awaitable<void> handle_http3_connection(
            std::shared_ptr<network::quic::QuicStream> stream_ptr);

        template<typename Stream>
        void spawn_connection(std::shared_ptr<Stream> stream_ptr);

        void spawn_http3_stream(std::shared_ptr<network::quic::QuicStream> stream_ptr);
#else
        template<typename Stream>
        asio::awaitable<void> handle_connection(std::shared_ptr<Stream> stream_ptr);

        template<typename Stream>
        void spawn_connection(std::shared_ptr<Stream> stream_ptr);
#endif

        // Configuration (ServerConfig.ipp)
        void enable_signal_handling(bool enable = true) noexcept;
        void set_exit_on_signal(bool exit_proc) noexcept;
        void set_shutdown_timeout(std::chrono::milliseconds timeout) noexcept;
        [[nodiscard]] std::chrono::milliseconds shutdown_timeout() const noexcept;
        void set_keep_alive_timeout(std::chrono::seconds timeout) noexcept;
        [[nodiscard]] std::chrono::seconds keep_alive_timeout() const noexcept;
        void set_max_keep_alive_requests(unsigned max_requests) noexcept;
        [[nodiscard]] unsigned max_keep_alive_requests() const noexcept;
        void set_max_request_size(size_t size) noexcept;
        [[nodiscard]] size_t max_request_size() const noexcept;
        void set_max_memory_buffer(size_t size) noexcept;
        [[nodiscard]] size_t max_memory_buffer() const noexcept;
        void set_max_query_params(std::size_t max) noexcept;
        [[nodiscard]] std::size_t max_query_params() const noexcept;
        void set_max_headers(std::size_t max) noexcept;
        [[nodiscard]] std::size_t max_headers() const noexcept;
        void set_not_found_handler(NotFoundHandler h);
        void set_not_found(std::string body, std::string content_type = "text/plain");
        void set_not_found_page(const std::string &file_path);

        // State queries (ServerConfig.ipp)
        [[nodiscard]] bool is_running() const noexcept;
        [[nodiscard]] bool is_shutting_down() const noexcept;
        [[nodiscard]] bool is_stopped() const noexcept;
        [[nodiscard]] std::size_t active_connections() const noexcept;
        [[nodiscard]] ThreadPool &pool() noexcept;
        [[nodiscard]] asio::io_context &io_context() noexcept;
        [[nodiscard]] bool is_acceptor_open() const noexcept;

        // Memory management (ServerConfig.ipp)
        void trim_memory();

    private:
        void start_graceful_shutdown(std::chrono::milliseconds timeout);
        void finish_shutdown();

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        void init_ssl();
#endif

        asio::awaitable<void> accept_loop();

        template<typename Stream>
        static decltype(auto) get_stream_socket(Stream &s) noexcept;

        template<typename Stream>
        static asio::awaitable<void> drain_and_abort(Stream &s);

        template<typename CustomCodec, typename CustomRouter, typename Stream>
        asio::awaitable<void> handle_connection_impl(std::shared_ptr<Stream> stream_ptr,
                                                     CustomRouter &router);

        template<typename ReqT, typename ResT, typename MwVec, typename H>
        static asio::awaitable<void> run_chain(ReqT &req, ResT &res, const MwVec &mws,
                                               const H &handler);
    };

} // namespace wavex::server
