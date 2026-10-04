// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file ServerLifecycle.ipp
 * @brief Server lifecycle method implementations (run, stop, shutdown).
 *
 * @note This file is included by Server.hpp and should NOT be included directly.
 */

#pragma once

#include <csignal>
#include <iostream>
#include <wavex/Base/Logger.hpp>
#include <wavex/Utils/FsUtils.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/post.hpp>

namespace wavex::server {

    template<typename Codec, typename RouterType>
    Server<Codec, RouterType>::Server(RouterType &router, std::string address,
                                      const unsigned short port)
        : router_(router),
          address_(std::move(address)),
          master_io_(),
          acceptor_(master_io_),
          pool_(),
          port_(port) {
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        if constexpr (is_http3_codec_v<Codec>) {
            h3_router_ = reinterpret_cast<engine::Http3Router *>(&router_);
            http3_enabled_ = true;
        }
#endif
    }

    template<typename Codec, typename RouterType>
    Server<Codec, RouterType>::~Server() {
        stop();
    }

    template<typename Codec, typename RouterType>
    void Server<Codec, RouterType>::run() {
        ServerState expected = ServerState::Stopped;
        if (!state_.compare_exchange_strong(expected, ServerState::Running,
                                            std::memory_order_acq_rel)) [[unlikely]] {
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
                const auto ep = asio::ip::tcp::endpoint(
                    asio::ip::make_address(address_), port_);
                std::ignore = acceptor_.open(ep.protocol(), ec);
                std::ignore = acceptor_.set_option(
                    asio::ip::tcp::acceptor::reuse_address(true), ec);
                std::ignore = acceptor_.bind(ep, ec);
                std::ignore = acceptor_.listen(
                    asio::socket_base::max_listen_connections, ec);
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

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        // Conditionally start the QUIC/UDP listener on the same port
        if (has_quic_transport || http3_enabled_) {
            if (!tls_enabled_ && !allow_insecure_quic_) {
                throw std::runtime_error(
                    "QUIC transport requires TLS 1.3. "
                    "Call server.enable_tls(cert, key) before server.run().");
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
                    if (!wavex::utils::fs_utils::exists(cert_path, ec) &&
                        wavex::utils::fs_utils::exists("../" + tls_config_.cert_file, ec)) {
                        cert_path = "../" + tls_config_.cert_file;
                    }
                }
                if (!wavex::utils::fs_utils::exists(key_path, ec)) {
#ifdef PROJECT_DIR
                    std::string alt = std::string(PROJECT_DIR) + "/" + key_path;
                    if (wavex::utils::fs_utils::exists(alt, ec)) key_path = alt;
#endif
                    if (!wavex::utils::fs_utils::exists(key_path, ec) &&
                        wavex::utils::fs_utils::exists("../" + tls_config_.key_file, ec)) {
                        key_path = "../" + tls_config_.key_file;
                    }
                }
                quic_server_->set_tls_credentials(std::move(cert_path), std::move(key_path));
            }
            quic_server_->set_stream_handler(
                [this](std::shared_ptr<network::quic::QuicStream> stream)
                    -> asio::awaitable<void> {
                    if (!stream) co_return;
                    wavex::log::info("[Server] quic_server_ stream_handler invoked for stream_id={}",
                                     stream->stream_id());
                    if ((stream->stream_id() & 0x03) == 0x00) {
                        spawn_http3_stream(std::move(stream));
                    }
                    co_return;
                });
            quic_server_->start();
            wavex::log::info("[WaveX] QUIC/UDP listener active on {}:{}", address_, port_);
        }
#endif

        if constexpr (has_tcp_transport) {
            asio::co_spawn(master_io_, accept_loop(), asio::detached);
        }
        master_io_.run();

        state_.store(ServerState::Stopped, std::memory_order_release);
        if (master_io_.stopped()) {
            master_io_.restart();
        }
    }

    template<typename Codec, typename RouterType>
    void Server<Codec, RouterType>::exit(std::chrono::milliseconds timeout) {
        if (auto expected = ServerState::Running;
            !state_.compare_exchange_strong(expected, ServerState::ShuttingDown,
                                            std::memory_order_acq_rel)) {
            return; // Not running or already shutting down
        }
        asio::post(master_io_, [this, timeout] {
            start_graceful_shutdown(timeout);
        });
    }

    template<typename Codec, typename RouterType>
    void Server<Codec, RouterType>::shutdown(std::chrono::milliseconds timeout) {
        exit(timeout);
    }

    template<typename Codec, typename RouterType>
    void Server<Codec, RouterType>::attach_shutdown_event(base::ShutdownEvent &event) {
        event.subscribe([this](std::chrono::milliseconds timeout) {
            exit(timeout);
        }).detach();
    }

    template<typename Codec, typename RouterType>
    void Server<Codec, RouterType>::attach_event_bus(base::EventBus &bus) {
        bus.subscribe<base::ServerShutdownEvent>([this](const base::ServerShutdownEvent &ev) {
            exit(ev.timeout);
        }).detach();
    }

    template<typename Codec, typename RouterType>
    void Server<Codec, RouterType>::stop() {
        if (is_stopped_.exchange(true, std::memory_order_acq_rel)) {
            return;
        }
        state_.store(ServerState::Stopped, std::memory_order_release);
        asio::error_code ec;
        std::ignore = acceptor_.close(ec);
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        if (quic_server_) {
            quic_server_->stop();
            quic_server_.reset();
        }
#endif
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

    template<typename Codec, typename RouterType>
    void Server<Codec, RouterType>::start_graceful_shutdown(std::chrono::milliseconds timeout) {
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

    template<typename Codec, typename RouterType>
    void Server<Codec, RouterType>::finish_shutdown() {
        if (is_stopped_.exchange(true, std::memory_order_acq_rel)) return;

        asio::error_code ec;
        if (shutdown_timer_) {
            shutdown_timer_->cancel(ec);
        }
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        if (quic_server_) {
            quic_server_->stop();
            quic_server_.reset();
        }
#endif
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

} // namespace wavex::server
