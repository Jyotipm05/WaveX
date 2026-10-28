// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file ServerConnection.ipp
 * @brief Server stream and connection handling implementations.
 *
 * @note This file is included by Server.hpp and should NOT be included directly.
 */

#pragma once

#include <algorithm>
#include <chrono>
#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>

#if !defined(_WIN32)
#include <unistd.h>
#endif
#include <wavex/Base/Logger.hpp>
#include <wavex/Base/Memory.hpp>
#include <wavex/Base/MiddleWare.hpp>
#include <wavex/Base/StringSink.hpp>

#include <asio/as_tuple.hpp>
#include <asio/buffer.hpp>
#include <asio/redirect_error.hpp>
#include <asio/steady_timer.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/write.hpp>

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
#include <asio/ssl.hpp>
#endif

namespace wavex::server {
    template<typename Codec, typename RouterType>
    asio::awaitable<void> Server<Codec, RouterType>::accept_loop() {
        while (state_.load(std::memory_order_acquire) == ServerState::Running) {
            try {
                asio::ip::tcp::socket accepted = co_await acceptor_.async_accept();
                asio::error_code nd_ec;
                std::ignore = accepted.set_option(asio::ip::tcp::no_delay(true), nd_ec);

                // One worker serves this connection for its whole life: lease it now (it cannot be retired
                // meanwhile) and register the socket with that worker's own reactor, so readiness for the
                // connection is handled on the worker instead of funnelling through the master io_context.
                auto lease = pool_.lease_worker();
                if (!lease) [[unlikely]] continue; // no workers (shutting down): drop the connection
                asio::ip::tcp::socket socket = adopt_on_worker(std::move(accepted), lease.context());
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
                if (tls_enabled_ && ssl_ctx_) {
                    auto stream = std::make_shared<asio::ssl::stream<asio::ip::tcp::socket> >(
                        std::move(socket), *ssl_ctx_);
                    pool_.spawn_leased(std::move(lease), handle_connection(std::move(stream)));
                    continue;
                }
#endif
                pool_.spawn_leased(std::move(lease),
                                   handle_connection(std::make_shared<asio::ip::tcp::socket>(std::move(socket))));
            } catch (const std::exception &e) {
                if (state_.load(std::memory_order_acquire) == ServerState::Running) {
                    std::cerr << "[Server] Accept error: " << e.what() << "\n";
                }
                break;
            }
        }
    }

    template<typename Codec, typename RouterType>
    asio::ip::tcp::socket Server<Codec, RouterType>::adopt_on_worker(asio::ip::tcp::socket &&accepted,
                                                                     asio::io_context &worker_io) {
#if !defined(ASIO_HAS_IOCP)
        // Re-register the connected socket with the worker's reactor. If anything fails the original socket is
        // returned untouched (it keeps working through the master reactor), so this is purely an optimisation.
        asio::error_code ec;
        const auto protocol = accepted.local_endpoint(ec).protocol();
        if (!ec) {
            const auto fd = accepted.release(ec);
            if (!ec) {
                asio::ip::tcp::socket moved(worker_io);
                if (!moved.assign(protocol, fd, ec)) {
                    return moved;
                }
                // assign() failed after release(): the descriptor is ours to close. The returned socket is
                // closed, so the connection coroutine ends on its first read.
                ::close(fd);
                return asio::ip::tcp::socket(worker_io);
            }
        }
#else
        (void) worker_io; // IOCP cannot hand a socket to another completion port
#endif
        return std::move(accepted);
    }

    template<typename Codec, typename RouterType>
    template<typename Stream>
    decltype(auto) Server<Codec, RouterType>::get_stream_socket(Stream &s) noexcept {
        if constexpr (requires { s.next_layer(); }) {
            return s.next_layer();
        } else {
            return s;
        }
    }

    template<typename Codec, typename RouterType>
    template<typename Stream>
    asio::awaitable<void> Server<Codec, RouterType>::drain_and_abort(Stream &s) {
        // QUIC streams handle their own graceful teardown — drain is TCP-only
        if constexpr (std::is_convertible_v<decltype(get_stream_socket(s)) &, asio::ip::tcp::socket &>) {
            detail::drain_and_abort_tcp(get_stream_socket(s));
        }
        co_return;
    }

    template<typename Codec, typename RouterType>
    template<typename Stream>
    asio::awaitable<void> Server<Codec, RouterType>::handle_connection(
        std::shared_ptr<Stream> stream_ptr) {
        co_await handle_connection_impl<Codec, RouterType>(std::move(stream_ptr), router_);
        co_return;
    }


    template<typename T>
    concept ArenaAware = std::constructible_from<T, std::pmr::memory_resource *>;

    template<typename Codec, typename RouterType>
    template<typename CustomCodec, typename CustomRouter, typename Stream>
    asio::awaitable<void> Server<Codec, RouterType>::handle_connection_impl(
        std::shared_ptr<Stream> stream_ptr, CustomRouter &router) {
        using CustTraits = protos::protocol_traits<CustomCodec>;
        using CustReq = CustomRouter::RequestType;
        using CustRes = CustomRouter::ResponseType;

        static_assert(ArenaAware<CustReq> && ArenaAware<CustRes>,
                      "CustReq and CustRes must be constructible with std::pmr::memory_resource*");
        static_assert(requires(CustRes &r, std::pmr::string &s) { r.serialize_to(s); },
                      "CustRes must provide serialize_to(std::pmr::string&)");
        // The request/response contract of the generic loop (codec + router seams). Anything protocol-flavoured
        // beyond this goes through protocol_traits.
        static_assert(requires(CustReq &q) { q.consumed_bytes(); q.method_type(); q.path(); },
                      "CustReq must provide consumed_bytes(), method_type() and path() (codec/router contract)");
        static_assert(requires(CustRes &r) { r.is_sent(); r.is_headers_sent(); },
                      "CustRes must provide is_sent() and is_headers_sent()");

        auto &stream = *stream_ptr;
        auto weak_stream = std::weak_ptr<Stream>(stream_ptr);

        // Sockets are not thread-safe. The tracker is driven from other threads (stop(), graceful drain), so
        // its callbacks never touch the socket themselves: they post to this connection's own executor,
        // where the coroutine runs, and the cancel/close happens serialized with the coroutine's I/O.
        auto executor = co_await asio::this_coro::executor;

        const uint64_t conn_id = conn_tracker_.register_socket(
            [weak_stream, executor] {
                asio::post(executor, [weak_stream] {
                    if (auto s = weak_stream.lock()) {
                        asio::error_code ec;
                        s->lowest_layer().cancel(ec);
                    }
                });
            },
            [weak_stream, executor] {
                asio::post(executor, [weak_stream] {
                    if (auto s = weak_stream.lock()) {
                        asio::error_code ec;
                        s->lowest_layer().cancel(ec);
                        s->lowest_layer().close(ec);
                    }
                });
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
            Stream &s;
            bool closed{false};

            explicit TransportGuard(Stream &stream) : s(stream) {
            }

            ~TransportGuard() {
                close();
            }

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
        typename CustTraits::connection_context default_conn_ctx{};
        auto &conn_ctx = CustTraits::get_connection_context(stream, default_conn_ctx);
        // Per-connection memory pool: outlives individual requests and travels safely across worker hops

        try {
            wavex::memory::ConnectionMemoryPool conn_pool;
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

                // Compact stream_buf if there are consumed bytes from a previous request
                if (stream_buf_consumed > 0) {
                    stream_buf.erase(0, stream_buf_consumed);
                    stream_buf_consumed = 0;
                }

                // When stream_buf is empty, the connection is in an idle keep-alive wait
                if (stream_buf.empty()) {
                    if (state_.load(std::memory_order_acquire) == ServerState::ShuttingDown) [[unlikely]] {
                        break;
                    }
                    conn_tracker_.mark_idle(conn_id);
                    conn_pool.release();
                    if (stream_buf.capacity() > 8192) {
                        stream_buf.shrink_to_fit();
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

                    const std::size_t prev_size = stream_buf.size();
                    stream_buf.reserve(prev_size + 4096);
                    auto [read_ec, bytes_read] = co_await stream.async_read_some(
                        asio::buffer(stream_buf.data() + prev_size, 4096),
                        asio::as_tuple(asio::use_awaitable));
                    wavex::base::resize_and_overwrite_compat(stream_buf, prev_size + bytes_read,
                        [prev_size, bytes_read](char *, std::size_t) noexcept {
                            return prev_size + bytes_read;
                        });

                    std::error_code timer_ec;
                    std::ignore = timer.cancel(timer_ec);

                    conn_tracker_.mark_active(conn_id);

                    if (timed_out || read_ec || bytes_read == 0) [[unlikely]] {
                        co_return;
                    }
                }

                // Request-scoped monotonic arena with per-connection fallback pool
                wavex::memory::RequestArena arena(conn_pool.resource());

                std::string_view unconsumed(stream_buf.data() + stream_buf_consumed,
                                            stream_buf.size() - stream_buf_consumed);
                CustReq req(arena.resource());
                auto p_res = req.parse_stream(unconsumed, conn_ctx);

                while (p_res == CustomCodec::result::incomplete &&
                       state_.load(std::memory_order_acquire) != ServerState::Stopped) {
                    if (state_.load(std::memory_order_acquire) == ServerState::ShuttingDown && stream_buf.empty()) [[
                        unlikely]] {
                        co_return;
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

                    const std::size_t prev_size = stream_buf.size();
                    stream_buf.reserve(prev_size + 4096);
                    auto [read_ec, bytes_read] = co_await stream.async_read_some(
                        asio::buffer(stream_buf.data() + prev_size, 4096),
                        asio::as_tuple(asio::use_awaitable));
                    wavex::base::resize_and_overwrite_compat(stream_buf, prev_size + bytes_read,
                        [prev_size, bytes_read](char *, std::size_t) noexcept {
                            return prev_size + bytes_read;
                        });

                    std::error_code timer_ec;
                    std::ignore = timer.cancel(timer_ec);

                    if (timed_out || read_ec || bytes_read == 0) [[unlikely]] {
                        co_return;
                    }

                    if (max_request_size_ > 0 && stream_buf.size() > max_request_size_) [[unlikely]] {
                        CustRes err_res(arena.resource());
                        CustTraits::write_error(err_res, protos::protocol_error::payload_too_large);
                        std::pmr::string err_wire(arena.resource());
                        err_res.serialize_to(err_wire);
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
                    CustRes err_res(arena.resource());
                    if constexpr (requires { err_res.stream_id(req.stream_id()); }) {
                        err_res.stream_id(req.stream_id()); // multiplexed protocols answer on the failing stream
                    }
                    auto failure = protos::protocol_error::bad_request;
                    if constexpr (requires { CustTraits::classify_parse_error(p_res); }) {
                        failure = CustTraits::classify_parse_error(p_res);
                    }
                    CustTraits::write_error(err_res, failure);
                    std::pmr::string err_wire(arena.resource());
                    err_res.serialize_to(err_wire);
                    co_await asio::async_write(stream, asio::buffer(err_wire),
                                               asio::use_awaitable);
                    co_await drain_and_abort(stream);
                    co_return;
                }

                ++request_count;
                const bool keep = CustTraits::keep_alive(req, request_count, max_keep_alive_requests_);
                const unsigned remaining =
                        request_count < max_keep_alive_requests_ ? max_keep_alive_requests_ - request_count : 0;

                // Hard cap: the protocol policy decides what its structural limits are and how to refuse.
                if (CustTraits::exceeds_limits(req, protos::request_limits{max_headers_, max_query_params_}))
                    [[unlikely]] {
                    CustRes err_res(arena.resource());
                    CustTraits::prepare_response(req, err_res, false, 0, 0);
                    CustTraits::write_error(err_res, protos::protocol_error::limits_exceeded);
                    std::pmr::string err_wire(arena.resource());
                    err_res.serialize_to(err_wire);
                    co_await asio::async_write(stream, asio::buffer(err_wire),
                                               asio::use_awaitable);
                    stream_buf_consumed += req.consumed_bytes();
                    if (stream_buf_consumed >= 4096 || stream_buf_consumed == stream_buf.size()) {
                        stream_buf.erase(0, stream_buf_consumed);
                        stream_buf_consumed = 0;
                    }
                    // No explicit arena.release(): req, err_res and err_wire still hold arena
                    // memory here. Leaving the scope destroys them first and then the arena
                    // (declared before them), which is the only safe order.
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

                CustRes res(arena.resource());
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

                CustTraits::set_default_status(res, static_cast<bool>(match));

                try {
                    if (!match) [[unlikely]] {
                        if constexpr (std::is_same_v<CustReq, RequestType> &&
                                      std::is_same_v<CustRes, ResponseType>) {
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
                    wavex::log::error("[Server] Unhandled exception in request handler for {}: {}",
                                      CustTraits::request_label(req), ex.what());
                    if (!res.is_headers_sent()) {
                        CustTraits::write_error(res, protos::protocol_error::internal_error);
                    }
                } catch (...) {
                    wavex::log::error("[Server] Unknown exception in request handler for {}", CustTraits::request_label(req));
                    if (!res.is_headers_sent()) {
                        CustTraits::write_error(res, protos::protocol_error::internal_error);
                    }
                }

                // Check shutdown state after handler execution
                // (in case the handler itself invoked server.exit() or external shutdown event)
                const bool is_shutting_down =
                        state_.load(std::memory_order_acquire) == ServerState::ShuttingDown;
                const bool effective_keep = keep && !is_shutting_down;

                // Alt-Svc advertisement is a policy decision; the kernel only forwards the port.
                constexpr bool advertise_by_default = [] {
                    if constexpr (requires { CustTraits::advertises_alt_svc_by_default; }) {
                        return static_cast<bool>(CustTraits::advertises_alt_svc_by_default);
                    } else {
                        return false;
                    }
                }();
                const unsigned short alt_svc_port = (advertise_by_default || alt_svc_port_ > 0)
                                                        ? (alt_svc_port_ > 0 ? alt_svc_port_ : port_)
                                                        : 0;
                CustTraits::prepare_response(req, res, effective_keep,
                                             static_cast<unsigned>(keep_alive_timeout_.count()),
                                             remaining, alt_svc_port);

                // Server writes serialized response if headers were not already flushed by streaming
                if (!res.is_headers_sent()) [[likely]] {
                    std::pmr::string wire_resp(arena.resource());
                    res.serialize_to(wire_resp);
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

    template<typename Codec, typename RouterType>
    template<typename Stream>
    void Server<Codec, RouterType>::spawn_connection(std::shared_ptr<Stream> stream_ptr) {
        if (pool_.worker_count() == 0) {
            pool_.start_pool();
        }
        pool_.spawn_coroutine(handle_connection(std::move(stream_ptr)));
    }


    template<typename Codec, typename RouterType>
    template<typename ReqT, typename ResT, typename MwVec, typename H>
    asio::awaitable<void> Server<Codec, RouterType>::run_chain(
        ReqT &req, ResT &res, const MwVec &mws, const H &handler) {
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
} // namespace wavex::server
