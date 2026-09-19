// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file SpawnBlocking.hpp
 * @brief Tokio-like spawn_blocking awaitable for offloading synchronous work
 *        from C++23 coroutines to the dedicated BlockingThreadPool.
 *
 * Automatically captures the calling coroutine's Asio executor, executes the
 * callable on a background blocking thread, and posts the resumption (along with
 * the return value or any thrown exception) back to the calling executor.
 */

#pragma once

#ifndef ASIO_HAS_CO_AWAIT
#define ASIO_HAS_CO_AWAIT 1
#endif

#include <asio/awaitable.hpp>
#include <asio/async_result.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/associated_executor.hpp>
#include <asio/post.hpp>

#include <exception>
#include <memory>
#include <optional>
#include <type_traits>
#include <utility>

#include <wavex/Server/BlockingPool.hpp>

namespace wavex {

    namespace detail {

        template <typename Fn, typename R>
        asio::awaitable<R> spawn_blocking_impl(Fn fn, server::BlockingThreadPool &pool) {
            struct State {
                Fn func;
                std::optional<R> result;
                std::exception_ptr error{nullptr};
            };

            auto state = std::make_shared<State>(std::move(fn), std::nullopt, nullptr);

            co_await asio::async_initiate<const asio::use_awaitable_t<>&, void(std::exception_ptr)>(
                [&pool, state]<typename T0>(T0 handler) {
                    auto executor = asio::get_associated_executor(handler);
                    auto shared_handler = std::make_shared<T0>(std::move(handler));

                    pool.dispatch([state, executor, shared_handler]() mutable {
                        try {
                            state->result.emplace(state->func());
                        } catch (...) {
                            state->error = std::current_exception();
                        }

                        asio::post(executor, [state, shared_handler]() mutable {
                            auto h = std::move(*shared_handler);
                            h(state->error);
                        });
                    });
                },
                asio::use_awaitable
            );

            if (state->error) {
                std::rethrow_exception(state->error);
            }

            co_return std::move(*state->result);
        }

        template <typename Fn>
        asio::awaitable<void> spawn_blocking_void_impl(Fn fn, server::BlockingThreadPool &pool) {
            struct State {
                Fn func;
                std::exception_ptr error{nullptr};
            };

            auto state = std::make_shared<State>(std::move(fn), nullptr);

            co_await asio::async_initiate<const asio::use_awaitable_t<>&, void(std::exception_ptr)>(
                [&pool, state]<typename T0>(T0 handler) {
                    auto executor = asio::get_associated_executor(handler);
                    auto shared_handler = std::make_shared<T0>(std::move(handler));

                    pool.dispatch([state, executor, shared_handler]() mutable {
                        try {
                            state->func();
                        } catch (...) {
                            state->error = std::current_exception();
                        }

                        asio::post(executor, [state, shared_handler]() mutable {
                            auto h = std::move(*shared_handler);
                            h(state->error);
                        });
                    });
                },
                asio::use_awaitable
            );

            if (state->error) {
                std::rethrow_exception(state->error);
            }

            co_return;
        }

    } // namespace detail

    /**
     * @brief Offloads a synchronous, CPU-intensive, or blocking function to a dedicated
     *        blocking thread pool, suspending the calling coroutine without blocking the
     *        network I/O reactor threads.
     *
     * @tparam Fn Callable type.
     * @param fn The blocking callable to execute.
     * @param pool The blocking thread pool to execute on (defaults to the global instance).
     * @return asio::awaitable yielding the return value of fn() or re-throwing any exception thrown by fn().
     *
     * @example
     * asio::awaitable<void> handler(Request& req, Response& res) {
     *     auto hash = co_await wavex::spawn_blocking([&] {
     *         return compute_heavy_hash(req.body());
     *     });
     *     res.send(hash);
     * }
     */
    template <typename Fn>
    auto spawn_blocking(Fn &&fn, server::BlockingThreadPool &pool = server::BlockingThreadPool::instance()) {
        using R = std::remove_cvref_t<std::invoke_result_t<std::decay_t<Fn>>>;
        if constexpr (std::is_void_v<R>) {
            return detail::spawn_blocking_void_impl(std::forward<Fn>(fn), pool);
        } else {
            return detail::spawn_blocking_impl<std::decay_t<Fn>, R>(std::forward<Fn>(fn), pool);
        }
    }

} // namespace wavex
