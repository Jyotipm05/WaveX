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
          port_(port) {}

    template<typename Codec, typename RouterType>
    Server<Codec, RouterType>::~Server() {
        stop();
    }

    template<typename Codec, typename RouterType>
    void Server<Codec, RouterType>::run() {
        if (auto expected = ServerState::Stopped; !state_.compare_exchange_strong(expected, ServerState::Running,
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
        if constexpr (has_quic_transport) {
            if (!tls_enabled_ && !allow_insecure_quic_) {
                throw std::runtime_error(
                    "QUIC transport requires TLS 1.3. "
                    "Call server.enable_tls(cert, key) before server.run().");
            }
            quic_server_ = std::make_unique<network::quic::QuicServer>(
                master_io_, address_, port_);
            if (tls_enabled_) {
                quic_server_->set_tls_credentials(tls_config_.cert_file, tls_config_.key_file);
            }
            quic_server_->set_stream_handler(
                [this](std::shared_ptr<network::quic::QuicStream> stream)
                    -> asio::awaitable<void> {
                    if (!stream) co_return;
                    if ((stream->stream_id() & 0x03) == 0x00) {
                        spawn_connection(std::move(stream));
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
        // Keep the reactor alive until stop()/finish_shutdown() call master_io_.stop(). Without a guard,
        // run() returns as soon as the acceptor is closed and every connection is momentarily between I/O
        // operations (their coroutines are executing on workers); the next read a connection starts would
        // then never be serviced and the connection could never drain.
        auto reactor_guard = asio::make_work_guard(master_io_);
        reactor_running_.store(true, std::memory_order_release);
        master_io_.run();
        reactor_running_.store(false, std::memory_order_release);

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
    void Server<Codec, RouterType>::shutdown(const std::chrono::milliseconds timeout) {
        exit(timeout);
    }

    template<typename Codec, typename RouterType>
    void Server<Codec, RouterType>::attach_shutdown_event(base::ShutdownEvent &event) {
        event.subscribe([this](const std::chrono::milliseconds timeout) {
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
        // The closes above run on the workers that own each connection. Let them finish before the pool is
        // torn down, otherwise their sockets and coroutine frames would be stranded in worker io_contexts
        // and the next run() of this same Server would start with leftovers. Bounded, so a handler that
        // calls stop() on itself (it is one of the connections being drained) cannot hang forever.
        {
            const auto deadline = std::chrono::steady_clock::now() + kStopDrainTimeout;
            while (active_connections_.load(std::memory_order_acquire) != 0 &&
                   std::chrono::steady_clock::now() < deadline) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            if (const auto left = active_connections_.load(std::memory_order_acquire); left != 0) {
                wavex::log::warn("[WaveX] stop(): {} connection(s) still draining after {} ms", left,
                                 std::chrono::duration_cast<std::chrono::milliseconds>(kStopDrainTimeout).count());
            }
        }
        if (signals_) {
            std::ignore = signals_->cancel(ec);
            signals_.reset();
        }
        std::signal(SIGINT, SIG_DFL);
        std::signal(SIGTERM, SIG_DFL);

        // Order matters for an in-process restart. Sockets live on the master reactor but their coroutines
        // (and the completion handlers that resume them) target the worker io_contexts. Tearing the workers
        // down while run() is still delivering completions is a use-after-free, so: stop the reactor, wait
        // for run() to return, and only then destroy the workers.
        master_io_.stop();
        {
            const auto deadline = std::chrono::steady_clock::now() + kStopDrainTimeout;
            while (reactor_running_.load(std::memory_order_acquire) &&
                   std::chrono::steady_clock::now() < deadline) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }
        pool_.stop_pool();
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
                // The closes run on the workers and their completions need this (reactor) thread, so wait
                // for them by polling from a timer instead of blocking, then finish.
                finish_after_forced_close(std::chrono::steady_clock::now() + kStopDrainTimeout);
            }
        });
    }

    template<typename Codec, typename RouterType>
    void Server<Codec, RouterType>::finish_after_forced_close(const std::chrono::steady_clock::time_point deadline) {
        if (active_connections_.load(std::memory_order_acquire) == 0 ||
            std::chrono::steady_clock::now() >= deadline || !shutdown_timer_) {
            finish_shutdown();
            return;
        }
        shutdown_timer_->expires_after(std::chrono::milliseconds(2));
        shutdown_timer_->async_wait([this, deadline](const asio::error_code &ec) {
            if (!ec) finish_after_forced_close(deadline);
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
