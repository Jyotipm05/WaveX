// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file ServerConfig.ipp
 * @brief Server configuration getters, setters, state queries, and memory management.
 *
 * @note This file is included by Server.hpp and should NOT be included directly.
 */

#pragma once

namespace wavex::server {
    template<typename Codec, typename RouterType>
    void Server<Codec, RouterType>::enable_signal_handling(const bool enable) noexcept {
        enable_signals_ = enable;
    }

    template<typename Codec, typename RouterType>
    void Server<Codec, RouterType>::set_exit_on_signal(const bool exit_proc) noexcept {
        exit_on_signal_ = exit_proc;
    }

    template<typename Codec, typename RouterType>
    void Server<Codec, RouterType>::set_shutdown_timeout(
        const std::chrono::milliseconds timeout) noexcept {
        shutdown_timeout_ = timeout;
    }

    template<typename Codec, typename RouterType>
    std::chrono::milliseconds Server<Codec, RouterType>::shutdown_timeout() const noexcept {
        return shutdown_timeout_;
    }

    template<typename Codec, typename RouterType>
    bool Server<Codec, RouterType>::is_running() const noexcept {
        return state_.load(std::memory_order_acquire) == ServerState::Running;
    }

    template<typename Codec, typename RouterType>
    bool Server<Codec, RouterType>::is_shutting_down() const noexcept {
        return state_.load(std::memory_order_acquire) == ServerState::ShuttingDown;
    }

    template<typename Codec, typename RouterType>
    bool Server<Codec, RouterType>::is_stopped() const noexcept {
        return state_.load(std::memory_order_acquire) == ServerState::Stopped;
    }

    template<typename Codec, typename RouterType>
    std::size_t Server<Codec, RouterType>::active_connections() const noexcept {
        return active_connections_.load(std::memory_order_acquire);
    }

    template<typename Codec, typename RouterType>
    ThreadPool &Server<Codec, RouterType>::pool() noexcept {
        return pool_;
    }

    template<typename Codec, typename RouterType>
    void Server<Codec, RouterType>::set_keep_alive_timeout(
        const std::chrono::seconds timeout) noexcept {
        keep_alive_timeout_ = timeout;
    }

    template<typename Codec, typename RouterType>
    std::chrono::seconds Server<Codec, RouterType>::keep_alive_timeout() const noexcept {
        return keep_alive_timeout_;
    }

    template<typename Codec, typename RouterType>
    void Server<Codec, RouterType>::set_max_keep_alive_requests(
        const unsigned max_requests) noexcept {
        max_keep_alive_requests_ = max_requests;
    }

    template<typename Codec, typename RouterType>
    unsigned Server<Codec, RouterType>::max_keep_alive_requests() const noexcept {
        return max_keep_alive_requests_;
    }

    template<typename Codec, typename RouterType>
    void Server<Codec, RouterType>::set_max_request_size(const size_t size) noexcept {
        max_request_size_ = size;
    }

    template<typename Codec, typename RouterType>
    size_t Server<Codec, RouterType>::max_request_size() const noexcept {
        return max_request_size_;
    }

    template<typename Codec, typename RouterType>
    void Server<Codec, RouterType>::set_max_memory_buffer(const size_t size) noexcept {
        max_memory_buffer_ = size;
    }

    template<typename Codec, typename RouterType>
    size_t Server<Codec, RouterType>::max_memory_buffer() const noexcept {
        return max_memory_buffer_;
    }

    template<typename Codec, typename RouterType>
    void Server<Codec, RouterType>::set_max_query_params(const std::size_t max) noexcept {
        max_query_params_ = max;
    }

    template<typename Codec, typename RouterType>
    std::size_t Server<Codec, RouterType>::max_query_params() const noexcept {
        return max_query_params_;
    }

    template<typename Codec, typename RouterType>
    void Server<Codec, RouterType>::set_max_headers(const std::size_t max) noexcept {
        max_headers_ = max;
    }

    template<typename Codec, typename RouterType>
    std::size_t Server<Codec, RouterType>::max_headers() const noexcept {
        return max_headers_;
    }

    template<typename Codec, typename RouterType>
    void Server<Codec, RouterType>::set_alt_svc_port(const unsigned short port) noexcept {
        alt_svc_port_ = port;
    }

    template<typename Codec, typename RouterType>
    unsigned short Server<Codec, RouterType>::alt_svc_port() const noexcept {
        return alt_svc_port_;
    }

    template<typename Codec, typename RouterType>
    std::string_view Server<Codec, RouterType>::address() const noexcept {
        return address_;
    }

    template<typename Codec, typename RouterType>
    unsigned short Server<Codec, RouterType>::port() const noexcept {
        return port_;
    }

    template<typename Codec, typename RouterType>
    void Server<Codec, RouterType>::trim_memory() {
        pool_.post_all(&detail::release_thread_local_pool);
    }

    template<typename Codec, typename RouterType>
    void Server<Codec, RouterType>::set_not_found_handler(NotFoundHandler h) {
        server_not_found_handler_ = std::move(h);
    }

    template<typename Codec, typename RouterType>
    void Server<Codec, RouterType>::set_not_found(std::string body,
                                                  std::string content_type) {
        server_not_found_handler_ =
                [b = std::move(body), ct = std::move(content_type)](
            RequestType &, ResponseType &res) -> asio::awaitable<void> {
                    traits::write_not_found(res, b, ct);
                    co_return;
                };
    }

    template<typename Codec, typename RouterType>
    void Server<Codec, RouterType>::set_not_found_page(const std::string &file_path) {
        if (std::string body, mime; detail::load_not_found_page_file(file_path, body, mime)) {
            set_not_found(std::move(body), std::move(mime));
            return;
        }
        set_not_found("Not Found", "text/plain");
    }

    template<typename Codec, typename RouterType>
    asio::io_context &Server<Codec, RouterType>::io_context() noexcept {
        return master_io_;
    }

    template<typename Codec, typename RouterType>
    bool Server<Codec, RouterType>::is_acceptor_open() const noexcept {
        return acceptor_open_.load(std::memory_order_acquire);
    }

    template<typename Codec, typename RouterType>
    bool Server<Codec, RouterType>::is_http3_enabled() noexcept {
        return has_quic_transport;
    }

    template<typename Codec, typename RouterType>
    void Server<Codec, RouterType>::allow_insecure(const bool allow) noexcept {
        allow_insecure_ = allow;
    }

    template<typename Codec, typename RouterType>
    bool Server<Codec, RouterType>::allow_insecure_transports() const noexcept {
        return allow_insecure_;
    }
} // namespace wavex::server
