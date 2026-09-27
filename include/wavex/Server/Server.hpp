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
#include <wavex/Utils/FsUtils.hpp>
#include <wavex/Utils/BinaryFile.hpp>

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
#endif

#include <asio/signal_set.hpp>
#include <csignal>
#include <unordered_set>
#include <mutex>

#include <wavex/Base/Event.hpp>
#include <wavex/Engine/HttpRouter.hpp>
#include <wavex/protos/http/http.hpp>
#include <wavex/Server/ThreadPool.hpp>
#include <wavex/Server/TlsConfig.hpp>
#include <wavex/Base/Memory.hpp>
#include <wavex/Base/Logger.hpp>
#include <wavex/Network/QUIC.hpp>

namespace wavex::server {
    /**
     * @enum ServerState
     * @brief Lifecycle states of the Server instance.
     */
    enum class ServerState : uint8_t {
        Stopped,
        Running,
        ShuttingDown
    };

    /**
     * @struct ConnectionTracker
     * @brief Thread-safe registry of active and idle socket connections for graceful drain.
     */
    struct ConnectionTracker {
        // ─── 1. Nested Types & Definitions ───────────────────────────────────
        struct Entry {
            std::function<void()> cancel;
            std::function<void()> close;

            Entry() = default;

            Entry(std::function<void()> c, std::function<void()> cl)
                : cancel(std::move(c)), close(std::move(cl)) {
            }
        };

        // ─── 2. Member Variables (Arranged for minimum padding) ──────────────
        mutable std::mutex mtx;
        std::unordered_map<uint64_t, Entry> all_sockets;
        std::unordered_set<uint64_t> idle_sockets;
        uint64_t next_id{1};

        // ─── 3. Constructors & Destructor ────────────────────────────────────
        ConnectionTracker() = default;

        ~ConnectionTracker() = default;

        // ─── 4. Member Functions ─────────────────────────────────────────────
        uint64_t register_socket(std::function<void()> cancel_fn, std::function<void()> close_fn) {
            std::lock_guard lock(mtx);
            uint64_t id = next_id++;
            all_sockets.emplace(id, Entry{std::move(cancel_fn), std::move(close_fn)});
            return id;
        }

        void unregister_socket(uint64_t id) {
            std::lock_guard lock(mtx);
            all_sockets.erase(id);
            idle_sockets.erase(id);
        }

        void mark_idle(uint64_t id) {
            std::lock_guard lock(mtx);
            if (all_sockets.contains(id)) {
                idle_sockets.insert(id);
            }
        }

        void mark_active(const uint64_t id) {
            std::lock_guard lock(mtx);
            idle_sockets.erase(id);
        }

        void cancel_all_idle() {
            std::vector<std::function<void()> > to_cancel; {
                std::lock_guard lock(mtx);
                to_cancel.reserve(idle_sockets.size());
                for (uint64_t id: idle_sockets) {
                    if (auto it = all_sockets.find(id); it != all_sockets.end()) {
                        to_cancel.push_back(it->second.cancel);
                    }
                }
                idle_sockets.clear();
            }
            for (auto &fn: to_cancel) {
                if (fn) fn();
            }
        }

        void force_close_all() {
            std::vector<std::function<void()> > to_close; {
                std::lock_guard lock(mtx);
                to_close.reserve(all_sockets.size());
                for (auto &entry: all_sockets | std::views::values) {
                    to_close.push_back(entry.close);
                }
                all_sockets.clear();
                idle_sockets.clear();
            }
            for (auto &fn: to_close) {
                if (fn) fn();
            }
        }

        [[nodiscard]] std::size_t count() const {
            std::lock_guard lock(mtx);
            return all_sockets.size();
        }
    };

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
        RouterType &router_;
        std::string address_;
        asio::io_context master_io_;
        asio::ip::tcp::acceptor acceptor_;
        ThreadPool pool_;
        ConnectionTracker conn_tracker_;
        TlsConfig tls_config_;
        std::optional<NotFoundHandler> server_not_found_handler_{std::nullopt};
        std::optional<asio::signal_set> signals_;
        std::optional<asio::steady_timer> shutdown_timer_;
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        std::unique_ptr<asio::ssl::context> ssl_ctx_;
#endif
        std::unique_ptr<network::quic::QuicServer> quic_server_;
        engine::Http3Router *h3_router_{nullptr};
        std::chrono::milliseconds shutdown_timeout_{10000};
        std::chrono::seconds keep_alive_timeout_{5};
        std::size_t max_request_size_{100 * 1024 * 1024}; ///< Default 100MB limit
        std::size_t max_memory_buffer_{10 * 1024 * 1024}; ///< Default 10MB memory threshold
        std::size_t max_query_params_{64}; ///< Max query params per request (hard cap → 431)
        std::size_t max_headers_{100}; ///< Max headers per request (hard cap → 431)
        std::atomic<std::size_t> active_connections_{0};
        unsigned max_keep_alive_requests_{1000};
        unsigned short port_;
        std::atomic<ServerState> state_{ServerState::Stopped};
        std::atomic<bool> is_stopped_{false};
        std::atomic<bool> is_signal_shutdown_{false};
        bool enable_signals_{true};
        bool exit_on_signal_{true};
        bool tls_enabled_{false};
        bool allow_insecure_quic_{false};
        bool http3_enabled_{false};

    public:
        // ─── 3. Constructors & Destructor ────────────────────────────────────
        /**
         * @brief Constructs a Server listening on the specified address and port.
         * @param router Reference to the protocol router.
         * @param address IP address or host string.
         * @param port Network port number.
         */
        Server(RouterType &router, std::string address, const unsigned short port)
            : router_(router),
              address_(std::move(address)),
              master_io_(),
              acceptor_(master_io_),
              pool_(),
              port_(port) {
            if constexpr (std::is_same_v<Codec, protos::http::http3codec>) {
                h3_router_ = reinterpret_cast<engine::Http3Router *>(&router_);
                http3_enabled_ = true;
            }
        }

        ~Server() {
            stop();
        }

        Server(const Server &) = delete;

        Server &operator=(const Server &) = delete;

        Server(Server &&) = delete;

        Server &operator=(Server &&) = delete;

        // ─── 4. Member Functions ─────────────────────────────────────────────

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

        /**
         * @brief Checks if the TCP acceptor is currently bound and listening.
         * @return True if the TCP acceptor is open, false otherwise.
         */
        [[nodiscard]] bool is_acceptor_open() const noexcept { return acceptor_.is_open(); }

        /**
         * @brief Checks if HTTP/3 (QUIC) transport is enabled on this server instance.
         * @return True if QUIC/HTTP-3 listener is active or scheduled to run, false otherwise.
         */
        [[nodiscard]] bool is_http3_enabled() const noexcept { return has_quic_transport || http3_enabled_; }

        /**
         * @brief Orthogonally enables HTTP/3 (QUIC) transport on this server instance using the given router.
         * @param h3_router Reference to an Http3Router handling HTTP/3 stream requests.
         */
        void enable_http3(engine::Http3Router &h3_router) noexcept {
            h3_router_ = &h3_router;
            http3_enabled_ = true;
        }

        /**
         * @brief Synonym for enable_http3(). Attaches an HTTP/3 router and activates QUIC listener.
         */
        void attach_http3(engine::Http3Router &h3_router) noexcept {
            enable_http3(h3_router);
        }

        /**
         * @brief Allows QUIC transport to run without TLS 1.3 encryption (dev/testing mode only).
         * @param allow True to allow cleartext QUIC, false to require TLS 1.3 (default: false).
         */
        void allow_insecure(bool allow = true) noexcept {
            allow_insecure_quic_ = allow;
        }

        /// Start master acceptor loop and run event loop
        void run() {
            ServerState expected = ServerState::Stopped;
            if (!state_.compare_exchange_strong(expected, ServerState::Running, std::memory_order_acq_rel)) [[unlikely]
            ] {
                std::cerr << "Critical: Duplicate run() invocation detected!\n";
                return;
            }
            is_stopped_.store(false, std::memory_order_release);
            is_signal_shutdown_.store(false, std::memory_order_release);

            if (master_io_.stopped()) {
                master_io_.restart();
            }

            if (pool_.worker_count() == 0) {
                pool_.start_pool();
            }

            if constexpr (has_tcp_transport) {
                if (!acceptor_.is_open()) {
                    asio::error_code ec;
                    auto ep = asio::ip::tcp::endpoint(asio::ip::make_address(address_), port_);
                    std::ignore = acceptor_.open(ep.protocol(), ec);
                    std::ignore = acceptor_.set_option(asio::ip::tcp::acceptor::reuse_address(true), ec);
                    std::ignore = acceptor_.bind(ep, ec);
                    std::ignore = acceptor_.listen(asio::socket_base::max_listen_connections, ec);
                }
            }

            // Pre-compile all middleware chains for zero-allocation resolve() hot path
            router_.freeze();
            if (h3_router_) {
                h3_router_->freeze();
            }

            if (enable_signals_) {
                signals_.emplace(master_io_, SIGINT, SIGTERM);
#if defined(SIGQUIT)
                signals_->add(SIGQUIT);
#endif
                signals_->async_wait([this](const asio::error_code &ec, int sig) {
                    if (!ec) {
                        is_signal_shutdown_.store(true, std::memory_order_release);
                        wavex::log::info("[WaveX] Signal {} received, initiating graceful shutdown...", sig);
                        exit(shutdown_timeout_);
                    }
                });
            }

            // Conditionally start the QUIC/UDP listener on the same port
            if (has_quic_transport || http3_enabled_) {
                if (!tls_enabled_ && !allow_insecure_quic_) {
                    throw std::runtime_error(
                        "QUIC transport requires TLS 1.3. Call server.enable_tls(cert, key) before server.run().");
                }
                quic_server_ = std::make_unique<network::quic::QuicServer>(
                    master_io_, address_, port_);
                if (tls_enabled_) {
                    std::string cert_path = tls_config_.cert_file;
                    std::string key_path = tls_config_.key_file;
                    std::error_code ec;
                    if (!wavex::utils::fs_utils::exists(cert_path, ec)) {
#ifdef PROJECT_DIR
                        std::string alt = std::string(PROJECT_DIR) + "/" + cert_path;
                        if (wavex::utils::fs_utils::exists(alt, ec)) cert_path = alt;
#endif
                        if (!wavex::utils::fs_utils::exists(cert_path, ec) && wavex::utils::fs_utils::exists("../" + tls_config_.cert_file, ec)) {
                            cert_path = "../" + tls_config_.cert_file;
                        }
                    }
                    if (!wavex::utils::fs_utils::exists(key_path, ec)) {
#ifdef PROJECT_DIR
                        std::string alt = std::string(PROJECT_DIR) + "/" + key_path;
                        if (wavex::utils::fs_utils::exists(alt, ec)) key_path = alt;
#endif
                        if (!wavex::utils::fs_utils::exists(key_path, ec) && wavex::utils::fs_utils::exists("../" + tls_config_.key_file, ec)) {
                            key_path = "../" + tls_config_.key_file;
                        }
                    }
                    quic_server_->set_tls_credentials(std::move(cert_path), std::move(key_path));
                }
                quic_server_->set_stream_handler(
                    [this](std::shared_ptr<network::quic::QuicStream> stream)
                        -> asio::awaitable<void> {
                        spawn_http3_stream(std::move(stream));
                        co_return;
                    });
                quic_server_->start();
                wavex::log::info("[WaveX] QUIC/UDP listener active on {}:{}", address_, port_);
            }

            if constexpr (has_tcp_transport) {
                asio::co_spawn(master_io_, accept_loop(), asio::detached);
            }
            master_io_.run();

            state_.store(ServerState::Stopped, std::memory_order_release);
            if (master_io_.stopped()) {
                master_io_.restart();
            }
        }

        /**
         * @brief Initiates graceful drain and shutdown of the server.
         *
         * Can be called from ANY thread, including route handlers on worker threads.
         * Stops accepting new connections, cancels idle keep-alive sockets, allows in-flight
         * requests to finish their responses with Connection: close, and unblocks server.run()
         * without terminating the process (never calls std::exit).
         *
         * @param timeout Maximum grace period before force-closing remaining active sockets.
         */
        void exit(std::chrono::milliseconds timeout = std::chrono::seconds(10)) {
            ServerState expected = ServerState::Running;
            if (!state_.compare_exchange_strong(expected, ServerState::ShuttingDown, std::memory_order_acq_rel)) {
                return; // Not running or already shutting down
            }
            asio::post(master_io_, [this, timeout] {
                start_graceful_shutdown(timeout);
            });
        }

        /**
         * @brief Synonym for exit(). Initiates graceful drain and shutdown.
         */
        void shutdown(std::chrono::milliseconds timeout = std::chrono::seconds(10)) {
            exit(timeout);
        }

        /**
         * @brief Attaches an external generic ShutdownEvent to trigger server exit.
         * @param event The generic base::ShutdownEvent instance.
         */
        void attach_shutdown_event(base::ShutdownEvent &event) {
            event.subscribe([this](std::chrono::milliseconds timeout) {
                exit(timeout);
            }).detach();
        }

        /**
         * @brief Attaches an external generic EventBus to trigger server exit on ServerShutdownEvent.
         * @param bus The generic base::EventBus instance.
         */
        void attach_event_bus(base::EventBus &bus) {
            bus.subscribe<base::ServerShutdownEvent>([this](const base::ServerShutdownEvent &ev) {
                exit(ev.timeout);
            }).detach();
        }

        /// Immediately stop the server, force-close sockets, and stop thread pool
        void stop() {
            if (is_stopped_.exchange(true, std::memory_order_acq_rel)) {
                return;
            }
            state_.store(ServerState::Stopped, std::memory_order_release);
            asio::error_code ec;
            std::ignore = acceptor_.close(ec);
            if (quic_server_) {
                quic_server_->stop();
                quic_server_.reset();
            }
            conn_tracker_.force_close_all();
            if (shutdown_timer_) {
                shutdown_timer_->cancel(ec);
            }
            pool_.stop_pool();
            if (signals_) {
                std::ignore = signals_->cancel(ec);
                signals_.reset();
            }
            std::signal(SIGINT, SIG_DFL);
            std::signal(SIGTERM, SIG_DFL);
            master_io_.stop();
        }

        /// Enable or disable OS signal interception (SIGINT, SIGTERM)
        void enable_signal_handling(bool enable = true) noexcept {
            enable_signals_ = enable;
        }

        /// Configure whether OS signals should invoke std::exit(0) upon drain completion
        void set_exit_on_signal(bool exit_proc) noexcept {
            exit_on_signal_ = exit_proc;
        }

        /// Configure default graceful shutdown timeout
        void set_shutdown_timeout(std::chrono::milliseconds timeout) noexcept {
            shutdown_timeout_ = timeout;
        }

        /// Get configured graceful shutdown timeout
        [[nodiscard]] std::chrono::milliseconds shutdown_timeout() const noexcept {
            return shutdown_timeout_;
        }

        /// Checks if the server is currently actively running
        [[nodiscard]] bool is_running() const noexcept {
            return state_.load(std::memory_order_acquire) == ServerState::Running;
        }

        /// Checks if the server is in the graceful drain / shutdown sequence
        [[nodiscard]] bool is_shutting_down() const noexcept {
            return state_.load(std::memory_order_acquire) == ServerState::ShuttingDown;
        }

        /// Checks if the server is fully stopped
        [[nodiscard]] bool is_stopped() const noexcept {
            return state_.load(std::memory_order_acquire) == ServerState::Stopped;
        }

        /// Returns the number of currently active connection coroutines
        [[nodiscard]] std::size_t active_connections() const noexcept {
            return active_connections_.load(std::memory_order_acquire);
        }

        /// Access the underlying thread pool
        [[nodiscard]] ThreadPool &pool() noexcept { return pool_; }

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

        /// Configure maximum incoming request payload size in bytes (0 for unlimited, default 100MB)
        void set_max_request_size(size_t size) noexcept {
            max_request_size_ = size;
        }

        /// Get maximum incoming request payload size in bytes
        [[nodiscard]] size_t max_request_size() const noexcept {
            return max_request_size_;
        }

        /// Configure threshold above which uploaded files are spooled to temporary files on disk (default 10MB)
        void set_max_memory_buffer(size_t size) noexcept {
            max_memory_buffer_ = size;
        }

        /// Get threshold above which uploaded files are spooled to temporary files on disk
        [[nodiscard]] size_t max_memory_buffer() const noexcept {
            return max_memory_buffer_;
        }

        /// Configure maximum number of query parameters per request (default: 64, hard cap → 431)
        void set_max_query_params(std::size_t max) noexcept {
            max_query_params_ = max;
        }

        /// Get configured maximum query parameters per request
        [[nodiscard]] std::size_t max_query_params() const noexcept {
            return max_query_params_;
        }

        /// Configure maximum number of HTTP headers per request (default: 100, hard cap → 431)
        void set_max_headers(std::size_t max) noexcept {
            max_headers_ = max;
        }

        /// Get configured maximum number of HTTP headers per request
        [[nodiscard]] std::size_t max_headers() const noexcept {
            return max_headers_;
        }

        /**
         * @brief Post pool.release() to all worker threads to trim idle slab memory.
         *
         * Each worker thread's thread_local pool retains slab memory after burst traffic.
         * Calling trim_memory() reclaims that memory back to the OS on the next idle cycle.
         * Useful in container deployments where RSS is visible, and you want predictable
         * memory footprint after traffic subsides.
         */
        void trim_memory() {
            pool_.post_all([] { wavex::memory::get_thread_local_pool().release(); });
        }

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
        void set_not_found_page(const std::string &file_path) {
            if (auto res = utils::BinaryFile::read_all(file_path)) {
                auto mime = std::string(base::mime_type_from_path(file_path));
                set_not_found(std::move(*res), std::move(mime));
                return;
            }
            set_not_found("Not Found", "text/plain");
        }

        /// Get reference to the server's master io_context
        [[nodiscard]] asio::io_context &io_context() noexcept { return master_io_; }

    private:
        void start_graceful_shutdown(std::chrono::milliseconds timeout) {
            asio::error_code ec;
            std::ignore = acceptor_.close(ec);

            // Cancel all idle sockets waiting for keep-alive requests immediately
            conn_tracker_.cancel_all_idle();

            // If no active in-flight requests, finalize shutdown immediately
            if (active_connections_.load(std::memory_order_acquire) == 0) {
                finish_shutdown();
                return;
            }

            // Arm a deadline timer for remaining in-flight requests
            shutdown_timer_.emplace(master_io_, timeout);
            shutdown_timer_->async_wait([this](const asio::error_code &timer_ec) {
                if (!timer_ec) {
                    wavex::log::warn("[WaveX] Graceful shutdown timeout reached. Force-closing remaining sockets.");
                    conn_tracker_.force_close_all();
                    finish_shutdown();
                }
            });
        }

        void finish_shutdown() {
            if (is_stopped_.exchange(true, std::memory_order_acq_rel)) return;

            asio::error_code ec;
            if (shutdown_timer_) {
                shutdown_timer_->cancel(ec);
            }
            if (quic_server_) {
                quic_server_->stop();
                quic_server_.reset();
            }
            if (signals_) {
                std::ignore = signals_->cancel(ec);
                signals_.reset();
            }
            std::signal(SIGINT, SIG_DFL);
            std::signal(SIGTERM, SIG_DFL);

            pool_.stop_pool();
            master_io_.stop();
            state_.store(ServerState::Stopped, std::memory_order_release);

            if (is_signal_shutdown_.load(std::memory_order_acquire) && exit_on_signal_) {
                std::exit(0);
            }
        }

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
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

            std::error_code ec;
            if (!wavex::utils::fs_utils::exists(cert_path, ec)) {
#ifdef PROJECT_DIR
                std::string alt = std::string(PROJECT_DIR) + "/" + cert_path;
                if (wavex::utils::fs_utils::exists(alt, ec)) cert_path = alt;
#endif
                if (!wavex::utils::fs_utils::exists(cert_path, ec) && wavex::utils::fs_utils::exists(
                        "../" + tls_config_.cert_file, ec)) {
                    cert_path = "../" + tls_config_.cert_file;
                }
            }

            if (!wavex::utils::fs_utils::exists(key_path, ec)) {
#ifdef PROJECT_DIR
                std::string alt = std::string(PROJECT_DIR) + "/" + key_path;
                if (wavex::utils::fs_utils::exists(alt, ec)) key_path = alt;
#endif
                if (!wavex::utils::fs_utils::exists(key_path, ec) && wavex::utils::fs_utils::exists(
                        "../" + tls_config_.key_file, ec)) {
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
            while (state_.load(std::memory_order_acquire) == ServerState::Running) {
                try {
                    asio::ip::tcp::socket socket = co_await acceptor_.async_accept();
                    asio::error_code nd_ec;
                    std::ignore = socket.set_option(asio::ip::tcp::no_delay(true), nd_ec);
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
                    if (tls_enabled_ && ssl_ctx_) {
                        auto stream = std::make_shared<asio::ssl::stream<asio::ip::tcp::socket> >(
                            std::move(socket), *ssl_ctx_);
                        pool_.spawn_coroutine(handle_connection(std::move(stream)));
                        continue;
                    }
#endif
                    pool_.spawn_coroutine(
                        handle_connection(std::make_shared<asio::ip::tcp::socket>(std::move(socket))));
                } catch (const std::exception &e) {
                    if (state_.load(std::memory_order_acquire) == ServerState::Running) {
                        std::cerr << "[Server] Accept error: " << e.what() << "\n";
                    }
                    break;
                }
            }
        }

        template<typename Stream>
        static decltype(auto) get_stream_socket(Stream &s) noexcept {
            if constexpr (requires { s.next_layer(); }) {
                return s.next_layer();
            } else {
                return s;
            }
        }

        /**
         * @brief Half-close socket for sending and drain lingering inbound data before closing.
         * Prevents TCP RST / ECONNRESET on client when closing with unread data in kernel receive buffer.
         *
         * Trade-off: Uses a synchronous wall-clock deadline (std::chrono::steady_clock) rather than
         * an asio::steady_timer to ensure zero pending async operations on the executor, eliminating
         * Windows IOCP timer-thread deadlocks on shutdown. In the rare case of an active adversarial
         * stream, this may occupy the worker thread for up to 200ms before hard-closing.
         */
        template<typename Stream>
        static asio::awaitable<void> drain_and_abort(Stream &s) {
            // QUIC streams handle their own graceful teardown — drain is TCP-only
            if constexpr (requires {
                { get_stream_socket(s).available(std::declval<asio::error_code&>()) } -> std::integral;
            }) {
                auto &sock = get_stream_socket(s);
                asio::error_code ec;
                std::ignore = sock.shutdown(asio::ip::tcp::socket::shutdown_send, ec);
                if (ec || !sock.is_open()) co_return;

                constexpr auto kDrainLimit = std::chrono::milliseconds(200);
                constexpr std::size_t kMaxDrainBytes = 64 * 1024; // 64 KB cap
                const auto deadline = std::chrono::steady_clock::now() + kDrainLimit;

                char discard_buf[4096];
                std::size_t total_drained = 0;

                while (sock.is_open()) {
                    if (std::chrono::steady_clock::now() >= deadline) break;

                    std::size_t avail = sock.available(ec);
                    if (ec || avail == 0) break;

                    std::size_t to_read = std::min({avail, sizeof(discard_buf), kMaxDrainBytes - total_drained});
                    std::size_t n = sock.read_some(asio::buffer(discard_buf, to_read), ec);
                    if (ec || n == 0) break;

                    total_drained += n;
                    if (total_drained >= kMaxDrainBytes) break;
                }
            }
            co_return;
        }

    public:
        /**
         * @brief Unified connection handler — delegates to handle_connection_impl for this server's primary codec.
         */
        template<typename Stream>
        asio::awaitable<void> handle_connection(std::shared_ptr<Stream> stream_ptr) {
            co_await handle_connection_impl<Codec, RouterType>(std::move(stream_ptr), router_);
            co_return;
        }

        /**
         * @brief HTTP/3 connection handler — processes incoming QUIC streams using http3codec and the attached Http3Router.
         */
        asio::awaitable<void> handle_http3_connection(std::shared_ptr<network::quic::QuicStream> stream_ptr) {
            if (h3_router_) {
                co_await handle_connection_impl<protos::http::http3codec, engine::Http3Router>(std::move(stream_ptr), *h3_router_);
            }
            co_return;
        }

    private:
        template<typename CustomCodec, typename CustomRouter, typename Stream>
        asio::awaitable<void> handle_connection_impl(std::shared_ptr<Stream> stream_ptr, CustomRouter &router) {
            using CustTraits = protos::protocol_traits<CustomCodec>;
            using CustReq = typename CustomRouter::RequestType;
            using CustRes = typename CustomRouter::ResponseType;

            auto &stream = *stream_ptr;
            auto weak_stream = std::weak_ptr<Stream>(stream_ptr);

            const uint64_t conn_id = conn_tracker_.register_socket(
                [weak_stream] {
                    if (auto s = weak_stream.lock()) {
                        asio::error_code ec;
                        s->lowest_layer().cancel(ec);
                    }
                },
                [weak_stream] {
                    if (auto s = weak_stream.lock()) {
                        asio::error_code ec;
                        s->lowest_layer().cancel(ec);
                        s->lowest_layer().close(ec);
                    }
                }
            );
            active_connections_.fetch_add(1, std::memory_order_acq_rel);

            struct ConnectionGuard {
                Server &srv;
                uint64_t id;

                ~ConnectionGuard() {
                    srv.conn_tracker_.unregister_socket(id);
                    if (srv.active_connections_.fetch_sub(1, std::memory_order_acq_rel) == 1) {
                        if (srv.state_.load(std::memory_order_acquire) == ServerState::ShuttingDown) {
                            asio::post(srv.master_io_, [&srv = srv] {
                                srv.finish_shutdown();
                            });
                        }
                    }
                }
            } conn_guard{*this, conn_id};

            struct TransportGuard {
                // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
                Stream &s;
                bool closed{false};

                // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
                explicit TransportGuard(Stream &stream) : s(stream) {
                }

                ~TransportGuard() {
                    close();
                }

                // ─── 4. Member Functions (LAST) ────────────────────────────────────
                void close() noexcept {
                    if (closed) return;
                    closed = true;
                    if constexpr (requires { s.lowest_layer().remote_endpoint(); }) {
                        auto &sock = get_stream_socket(s);
                        asio::error_code ec;
                        std::ignore = sock.shutdown(asio::ip::tcp::socket::shutdown_send, ec);
                        std::ignore = sock.close(ec);
                    } else {
                        s.close();
                    }
                }
            } transport_guard{stream};

            std::string stream_buf;
            stream_buf.reserve(8192);
            std::size_t stream_buf_consumed = 0;
            typename CustTraits::connection_context conn_ctx{};
            auto executor = co_await asio::this_coro::executor;

            try {
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
                // Asynchronously perform TLS handshake on worker thread if SSL stream
                if constexpr (requires
                {
                    stream.async_handshake(asio::ssl::stream_base::server, asio::use_awaitable);
                }) {
                    asio::error_code hec;
                    co_await stream.async_handshake(
                        asio::ssl::stream_base::server,
                        asio::redirect_error(asio::use_awaitable, hec));
                    if (hec) co_return;
                }
#endif

                // Protocol opening exchange (e.g. HTTP/2 PRI preface and SETTINGS handshake)
                if constexpr (CustTraits::has_connection_preface) {
                    if (!co_await CustTraits::on_connection_start(stream, stream_buf)) co_return;
                }

                unsigned request_count = 0;
                while (state_.load(std::memory_order_acquire) != ServerState::Stopped) {
                    if (state_.load(std::memory_order_acquire) == ServerState::ShuttingDown && stream_buf.empty()) [[
                        unlikely]] {
                        break;
                    }

                    std::string_view unconsumed(stream_buf.data() + stream_buf_consumed,
                                                stream_buf.size() - stream_buf_consumed);
                    CustReq req;
                    auto p_res = req.parse_stream(unconsumed, conn_ctx);

                    while (p_res == CustomCodec::result::incomplete && state_.load(std::memory_order_acquire) !=
                           ServerState::Stopped) {
                        if (state_.load(std::memory_order_acquire) == ServerState::ShuttingDown && stream_buf.empty()) [
                            [unlikely]] {
                            co_return;
                        }

                        // Compact stream_buf before reading if there are consumed bytes
                        if (stream_buf_consumed > 0) {
                            stream_buf.erase(0, stream_buf_consumed);
                            stream_buf_consumed = 0;
                        }

                        if (stream_buf.empty()) {
                            conn_tracker_.mark_idle(conn_id);
                        }

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

                        conn_tracker_.mark_active(conn_id);

                        if (timed_out || read_ec || bytes_read == 0) [[unlikely]] {
                            co_return;
                        }

                        stream_buf.append(buffer, bytes_read);

                        if (max_request_size_ > 0 && stream_buf.size() > max_request_size_) [[unlikely]] {
                            CustRes err_res;
                            err_res.status(413).send("Payload Too Large");
                            std::string err_wire = err_res.serialize();
                            co_await asio::async_write(stream, asio::buffer(err_wire),
                                                       asio::use_awaitable);
                            co_await drain_and_abort(stream);
                            co_return;
                        }

                        unconsumed = std::string_view(stream_buf.data() + stream_buf_consumed,
                                                      stream_buf.size() - stream_buf_consumed);
                        p_res = req.parse_stream(unconsumed, conn_ctx);
                    }

                    if (p_res != CustomCodec::result::success) [[unlikely]] {
                        CustRes err_res;
                        err_res.status(400).send("Bad Request");
                        std::string err_wire = err_res.serialize();
                        co_await asio::async_write(stream, asio::buffer(err_wire),
                                                   asio::use_awaitable);
                        co_await drain_and_abort(stream);
                        co_return;
                    }

                    ++request_count;
                    const bool keep = CustTraits::keep_alive(req, request_count, max_keep_alive_requests_);
                    const unsigned remaining =
                            request_count < max_keep_alive_requests_ ? max_keep_alive_requests_ - request_count : 0;

                    // Hard cap: reject requests that overflow query param or header limits
                    if (req.has_query_param_overflow()) [[unlikely]] {
                        CustRes err_res;
                        CustTraits::prepare_response(req, err_res, false, 0, 0);
                        err_res.status(431).send("Request Header Fields Too Large");
                        std::string err_wire = err_res.serialize();
                        co_await asio::async_write(stream, asio::buffer(err_wire),
                                                   asio::use_awaitable);
                        stream_buf_consumed += req.consumed_bytes();
                        if (stream_buf_consumed >= 4096 || stream_buf_consumed == stream_buf.size()) {
                            stream_buf.erase(0, stream_buf_consumed);
                            stream_buf_consumed = 0;
                        }
                        if (!keep) {
                            co_await drain_and_abort(stream);
                            break;
                        }
                        continue;
                    }

                    if constexpr (requires { stream.stream_id(); }) {
                        req.stream_id(static_cast<uint32_t>(stream.stream_id()));
                    }

                    auto match = router.resolve(req.method_type(), req.path());

                    CustRes res;
                    if constexpr (requires { res.stream_id(req.stream_id()); }) {
                        res.stream_id(req.stream_id());
                    }
                    if constexpr (requires { res.set_version(req.version_major(), req.version_minor()); }) {
                        res.set_version(req.version_major(), req.version_minor());
                    }

                    // Copy route params from RouteMatch into the request (with automatic percent-decoding)
                    if (match) [[likely]] {
                        if constexpr (requires { req.set_params(match->params); }) {
                            req.set_params(match->params);
                        } else {
                            for (const auto &[k, v]: match->params) {
                                req.params.insert_or_assign(k, v);
                            }
                        }
                    }

                    // Inject per-connection write sink for streaming transfers (chunked, send_file)
                    if constexpr (requires { res.set_write_sink({}); }) {
                        res.set_write_sink([weak_stream](const std::string_view data,
                                                         const std::chrono::milliseconds timeout)
                        -> asio::awaitable<std::expected<void, std::error_code> > {
                                auto s = weak_stream.lock();
                                if (!s) [[unlikely]] {
                                    co_return std::unexpected(std::make_error_code(std::errc::broken_pipe));
                                }
                                auto ex = co_await asio::this_coro::executor;
                                asio::steady_timer timer(ex, timeout);
                                bool timed_out = false;
                                timer.async_wait([&](const std::error_code ec) {
                                    if (!ec) {
                                        timed_out = true;
                                        std::error_code cancel_ec;
                                        std::ignore = s->lowest_layer().cancel(cancel_ec);
                                    }
                                });

                                auto [write_ec, bytes_written] = co_await asio::async_write(
                                    *s, asio::buffer(data), asio::as_tuple(asio::use_awaitable));
                                (void) timer.cancel();

                                if (timed_out || write_ec == asio::error::operation_aborted) [[unlikely]] {
                                    std::error_code close_ec;
                                    std::ignore = s->lowest_layer().close(close_ec);
                                    co_return std::unexpected(std::make_error_code(std::errc::timed_out));
                                }

                                if (write_ec) [[unlikely]] {
                                    co_return std::unexpected(write_ec);
                                }
                                co_return std::expected<void, std::error_code>{};
                            });
                    }

                    res.status(match ? 200 : 404);

                    try {
                        if (!match) [[unlikely]] {
                            if constexpr (std::is_same_v<CustReq, RequestType> && std::is_same_v<CustRes, ResponseType>) {
                                if (server_not_found_handler_) {
                                    co_await (*server_not_found_handler_)(req, res);
                                } else {
                                    co_await router.not_found_handler()(req, res);
                                }
                            } else {
                                co_await router.not_found_handler()(req, res);
                            }
                        } else if (match->middlewares.empty()) [[likely]] {
                            co_await match->handler(req, res);
                        } else {
                            co_await run_chain(req, res, match->middlewares, match->handler);
                        }
                    } catch (const std::exception &ex) {
                        wavex::log::error("[Server] Unhandled exception in request handler for {}: {}", req.path(),
                                          ex.what());
                        if (!res.is_headers_sent()) {
                            res.status(500);
                            if constexpr (requires { res.set("Content-Type", "text/plain"); }) {
                                res.set("Content-Type", "text/plain");
                            }
                            res.send("Internal Server Error");
                        }
                    } catch (...) {
                        wavex::log::error("[Server] Unknown exception in request handler for {}", req.path());
                        if (!res.is_headers_sent()) {
                            res.status(500);
                            if constexpr (requires { res.set("Content-Type", "text/plain"); }) {
                                res.set("Content-Type", "text/plain");
                            }
                            res.send("Internal Server Error");
                        }
                    }

                    // Check shutdown state after handler execution
                    // (in case the handler itself invoked server.exit() or external shutdown event)
                    const bool is_shutting_down = state_.load(std::memory_order_acquire) == ServerState::ShuttingDown;
                    const bool effective_keep = keep && !is_shutting_down;

                    CustTraits::prepare_response(req, res, effective_keep,
                                                 static_cast<unsigned>(keep_alive_timeout_.count()), remaining);

                    // Dynamic Alt-Svc injection for HTTP/3 servers on HTTP/1.x and HTTP/2 fallback connections
                    if (has_quic_transport || http3_enabled_) {
                        if constexpr (requires { req.version_major(); }) {
                            if ((req.version_major() == 1 || req.version_major() == 2) && !res.header("Alt-Svc")) {
                                const auto port_str = std::to_string(port_);
                                res.set("Alt-Svc", "h3=\":" + port_str + "\"; ma=2592000,h3-29=\":" + port_str + "\"; ma=2592000");
                            }
                        }
                    }

                    // Server writes serialized response if headers were not already flushed by streaming
                    if (!res.is_headers_sent()) [[likely]] {
                        std::string wire_resp = res.serialize();
                        co_await asio::async_write(stream, asio::buffer(wire_resp),
                                                   asio::use_awaitable);
                    }

                    stream_buf_consumed += req.consumed_bytes();
                    if (stream_buf_consumed >= 4096) [[unlikely]] {
                        stream_buf.erase(0, stream_buf_consumed);
                        stream_buf_consumed = 0;
                    } else if (stream_buf_consumed == stream_buf.size()) {
                        stream_buf.clear();
                        stream_buf_consumed = 0;
                    }

                    // Trim stream_buf RSS if it has grown large and is now empty
                    if (stream_buf.capacity() > 64 * 1024 && stream_buf.empty()) [[unlikely]] {
                        stream_buf.shrink_to_fit();
                        stream_buf.reserve(8192); // restore working reservation
                    }

                    if (!effective_keep) break;
                }
            } catch (const std::exception &e) {
                wavex::log::trace("[Server] Connection closed or stream error: {}", e.what());
            }

            // Graceful transport shutdown — drain any pipelined bytes the client sent
            // while we were processing so the OS sends FIN not RST.
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
            if constexpr (requires { stream.async_shutdown(asio::use_awaitable); }) {
                asio::error_code ignore_ec;
                co_await stream.async_shutdown(asio::redirect_error(asio::use_awaitable, ignore_ec));
            } else
#endif
            {
                if constexpr (requires { stream.lowest_layer().remote_endpoint(); }) {
                    co_await drain_and_abort(stream);
                }
            }
            transport_guard.close();
            co_return;
        }

    public:
        /**
         * @brief Spawns connection processing coroutine on the server's thread pool.
         */
        template<typename Stream>
        void spawn_connection(std::shared_ptr<Stream> stream_ptr) {
            if (pool_.worker_count() == 0) {
                pool_.start_pool();
            }
            pool_.spawn_coroutine(handle_connection(std::move(stream_ptr)));
        }

        /**
         * @brief Spawns HTTP/3 QUIC stream processing coroutine on the server's thread pool.
         */
        void spawn_http3_stream(std::shared_ptr<network::quic::QuicStream> stream_ptr) {
            if (pool_.worker_count() == 0) {
                pool_.start_pool();
            }
            if constexpr (std::is_same_v<Codec, protos::http::http3codec>) {
                pool_.spawn_coroutine(handle_connection(std::move(stream_ptr)));
            } else {
                pool_.spawn_coroutine(handle_http3_connection(std::move(stream_ptr)));
            }
        }

    private:
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
    using Http3Server = Server<wavex::protos::http::http3codec, wavex::engine::Http3Router>;
    using http3server = Http3Server;
    using HttpServer = Http1Server;
    using httpserver = HttpServer;

    /**
     * @class ComposedHttpServer
     * @brief High-level composed server running HTTP/1.1 & HTTP/2 over TCP/TLS and HTTP/3 over QUIC/UDP concurrently on the same port.
     */
    class ComposedHttpServer {
    public:
        // ─── 1. Nested Types & Definitions ───────────────────────────────────
        using Http2Router = engine::Http2Router;
        using Http3Router = engine::Http3Router;

    private:
        // ─── 2. Member Variables (Arranged for minimum padding) ──────────────
        Http2Router owned_h2_router_{};
        Http3Router owned_h3_router_{};
        Http2Router *h2_router_{nullptr};
        Http3Router *h3_router_{nullptr};
        Http2Server server_;

    public:
        // ─── 3. Constructors & Destructor ────────────────────────────────────
        ComposedHttpServer(std::string address, const unsigned short port)
            : owned_h2_router_(),
              owned_h3_router_(),
              h2_router_(&owned_h2_router_),
              h3_router_(&owned_h3_router_),
              server_(*h2_router_, std::move(address), port) {
            server_.enable_http3(*h3_router_);
        }

        ComposedHttpServer(Http2Router &h2_router, Http3Router &h3_router,
                           std::string address, const unsigned short port)
            : owned_h2_router_(),
              owned_h3_router_(),
              h2_router_(&h2_router),
              h3_router_(&h3_router),
              server_(*h2_router_, std::move(address), port) {
            server_.enable_http3(*h3_router_);
        }

        ~ComposedHttpServer() = default;

        ComposedHttpServer(const ComposedHttpServer &) = delete;
        ComposedHttpServer &operator=(const ComposedHttpServer &) = delete;
        ComposedHttpServer(ComposedHttpServer &&) = delete;
        ComposedHttpServer &operator=(ComposedHttpServer &&) = delete;

        // ─── 4. Member Functions ─────────────────────────────────────────────
        [[nodiscard]] Http2Router &h2_router() noexcept { return *h2_router_; }
        [[nodiscard]] const Http2Router &h2_router() const noexcept { return *h2_router_; }
        [[nodiscard]] Http3Router &h3_router() noexcept { return *h3_router_; }
        [[nodiscard]] const Http3Router &h3_router() const noexcept { return *h3_router_; }
        [[nodiscard]] Http2Server &tcp_server() noexcept { return server_; }
        [[nodiscard]] const Http2Server &tcp_server() const noexcept { return server_; }

        void enable_tls(std::string cert_file = "ssl/test.crt", std::string key_file = "ssl/test.key") {
            server_.enable_tls(std::move(cert_file), std::move(key_file));
        }

        void enable_tls(TlsConfig config) {
            server_.enable_tls(std::move(config));
        }

        [[nodiscard]] bool is_tls_enabled() const noexcept { return server_.is_tls_enabled(); }
        [[nodiscard]] bool is_acceptor_open() const noexcept { return server_.is_acceptor_open(); }
        [[nodiscard]] bool is_http3_enabled() const noexcept { return server_.is_http3_enabled(); }

        void allow_insecure(bool allow = true) noexcept {
            server_.allow_insecure(allow);
        }

        void run() {
            server_.run();
        }

        void stop() {
            server_.stop();
        }

        void exit(std::chrono::milliseconds timeout = std::chrono::seconds(10)) {
            server_.exit(timeout);
        }

        void shutdown(std::chrono::milliseconds timeout = std::chrono::seconds(10)) {
            server_.shutdown(timeout);
        }

        [[nodiscard]] asio::io_context &io_context() noexcept { return server_.io_context(); }

        template<typename Handler>
        ComposedHttpServer &get(const std::string_view pattern, Handler &&h) {
            auto h_copy = h;
            h2_router_->get(pattern, [h_copy](Http2Router::RequestType &req, Http2Router::ResponseType &res) -> asio::awaitable<void> {
                if constexpr (std::is_invocable_r_v<asio::awaitable<void>, decltype(h_copy), Http2Router::RequestType &, Http2Router::ResponseType &>) {
                    co_await h_copy(req, res);
                } else {
                    h_copy(req, res);
                    co_return;
                }
            });
            h3_router_->get(pattern, [h = std::forward<Handler>(h)](Http3Router::RequestType &req, Http3Router::ResponseType &res) -> asio::awaitable<void> {
                if constexpr (std::is_invocable_r_v<asio::awaitable<void>, decltype(h), Http3Router::RequestType &, Http3Router::ResponseType &>) {
                    co_await h(req, res);
                } else {
                    h(req, res);
                    co_return;
                }
            });
            return *this;
        }

        template<typename Handler>
        ComposedHttpServer &post(const std::string_view pattern, Handler &&h) {
            auto h_copy = h;
            h2_router_->post(pattern, [h_copy](Http2Router::RequestType &req, Http2Router::ResponseType &res) -> asio::awaitable<void> {
                if constexpr (std::is_invocable_r_v<asio::awaitable<void>, decltype(h_copy), Http2Router::RequestType &, Http2Router::ResponseType &>) {
                    co_await h_copy(req, res);
                } else {
                    h_copy(req, res);
                    co_return;
                }
            });
            h3_router_->post(pattern, [h = std::forward<Handler>(h)](Http3Router::RequestType &req, Http3Router::ResponseType &res) -> asio::awaitable<void> {
                if constexpr (std::is_invocable_r_v<asio::awaitable<void>, decltype(h), Http3Router::RequestType &, Http3Router::ResponseType &>) {
                    co_await h(req, res);
                } else {
                    h(req, res);
                    co_return;
                }
            });
            return *this;
        }

        template<typename Handler>
        ComposedHttpServer &put(const std::string_view pattern, Handler &&h) {
            auto h_copy = h;
            h2_router_->put(pattern, [h_copy](Http2Router::RequestType &req, Http2Router::ResponseType &res) -> asio::awaitable<void> {
                if constexpr (std::is_invocable_r_v<asio::awaitable<void>, decltype(h_copy), Http2Router::RequestType &, Http2Router::ResponseType &>) {
                    co_await h_copy(req, res);
                } else {
                    h_copy(req, res);
                    co_return;
                }
            });
            h3_router_->put(pattern, [h = std::forward<Handler>(h)](Http3Router::RequestType &req, Http3Router::ResponseType &res) -> asio::awaitable<void> {
                if constexpr (std::is_invocable_r_v<asio::awaitable<void>, decltype(h), Http3Router::RequestType &, Http3Router::ResponseType &>) {
                    co_await h(req, res);
                } else {
                    h(req, res);
                    co_return;
                }
            });
            return *this;
        }

        template<typename Handler>
        ComposedHttpServer &del(const std::string_view pattern, Handler &&h) {
            auto h_copy = h;
            h2_router_->del(pattern, [h_copy](Http2Router::RequestType &req, Http2Router::ResponseType &res) -> asio::awaitable<void> {
                if constexpr (std::is_invocable_r_v<asio::awaitable<void>, decltype(h_copy), Http2Router::RequestType &, Http2Router::ResponseType &>) {
                    co_await h_copy(req, res);
                } else {
                    h_copy(req, res);
                    co_return;
                }
            });
            h3_router_->del(pattern, [h = std::forward<Handler>(h)](Http3Router::RequestType &req, Http3Router::ResponseType &res) -> asio::awaitable<void> {
                if constexpr (std::is_invocable_r_v<asio::awaitable<void>, decltype(h), Http3Router::RequestType &, Http3Router::ResponseType &>) {
                    co_await h(req, res);
                } else {
                    h(req, res);
                    co_return;
                }
            });
            return *this;
        }

        template<typename Handler>
        ComposedHttpServer &patch(const std::string_view pattern, Handler &&h) {
            auto h_copy = h;
            h2_router_->patch(pattern, [h_copy](Http2Router::RequestType &req, Http2Router::ResponseType &res) -> asio::awaitable<void> {
                if constexpr (std::is_invocable_r_v<asio::awaitable<void>, decltype(h_copy), Http2Router::RequestType &, Http2Router::ResponseType &>) {
                    co_await h_copy(req, res);
                } else {
                    h_copy(req, res);
                    co_return;
                }
            });
            h3_router_->patch(pattern, [h = std::forward<Handler>(h)](Http3Router::RequestType &req, Http3Router::ResponseType &res) -> asio::awaitable<void> {
                if constexpr (std::is_invocable_r_v<asio::awaitable<void>, decltype(h), Http3Router::RequestType &, Http3Router::ResponseType &>) {
                    co_await h(req, res);
                } else {
                    h(req, res);
                    co_return;
                }
            });
            return *this;
        }

        template<typename Handler>
        ComposedHttpServer &query(const std::string_view pattern, Handler &&h) {
            auto h_copy = h;
            h2_router_->query(pattern, [h_copy](Http2Router::RequestType &req, Http2Router::ResponseType &res) -> asio::awaitable<void> {
                if constexpr (std::is_invocable_r_v<asio::awaitable<void>, decltype(h_copy), Http2Router::RequestType &, Http2Router::ResponseType &>) {
                    co_await h_copy(req, res);
                } else {
                    h_copy(req, res);
                    co_return;
                }
            });
            h3_router_->query(pattern, [h = std::forward<Handler>(h)](Http3Router::RequestType &req, Http3Router::ResponseType &res) -> asio::awaitable<void> {
                if constexpr (std::is_invocable_r_v<asio::awaitable<void>, decltype(h), Http3Router::RequestType &, Http3Router::ResponseType &>) {
                    co_await h(req, res);
                } else {
                    h(req, res);
                    co_return;
                }
            });
            return *this;
        }
    };

    using composed_http_server = ComposedHttpServer;
} // namespace wavex::server

