// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file Executor.hpp
 * @brief The one executor type WaveX's transports and servers are written against.
 *
 * Everything above the thread pool (QUIC server/client, WebSocket, WebTransport, `AnyStream`, HTTP/2 sessions)
 * already runs on `asio::any_io_executor`. This header names it once (`wavex::executor`) so a component never
 * depends on `asio::io_context` itself, and so an embedding application can hand WaveX its own `io_context`
 * executor, a strand or any other `any_io_executor`-convertible executor.
 *
 * The helpers below are best-effort optimisations only: a type-erased executor cannot always tell whether the
 * caller is already on it, and "unknown" always means "post it", which is correct, only slower.
 */
#pragma once

#include <asio/any_io_executor.hpp>
#include <asio/io_context.hpp>
#include <asio/strand.hpp>

namespace wavex {

    /// The executor type used across WaveX.
    using executor = asio::any_io_executor;

    /// Executor of an `io_context` (the common case; `io_context::get_executor()` converts implicitly).
    [[nodiscard]] inline executor executor_of(asio::io_context &io) noexcept {
        return io.get_executor();
    }

    /**
     * @brief True when the calling thread is currently running handlers of `ex`.
     *
     * Exact for `io_context` executors and strands of them. For any other executor the answer is `false`
     * ("unknown"), so callers fall back to `asio::post`, which is always safe. Never use a `true` result for
     * anything but skipping a redundant post.
     */
    [[nodiscard]] inline bool running_in_this_thread(const executor &ex) noexcept {
        if (const auto *io = ex.target<asio::io_context::executor_type>()) {
            return io->running_in_this_thread();
        }
        if (const auto *strand = ex.target<asio::strand<asio::io_context::executor_type> >()) {
            return strand->running_in_this_thread();
        }
        return false;
    }

    /**
     * @brief True when `ex` is known to belong to an `io_context` that has stopped.
     *
     * Best-effort: `false` for executors whose context is not an `io_context`.
     */
    [[nodiscard]] inline bool context_stopped(const executor &ex) noexcept {
        if (const auto *io = ex.target<asio::io_context::executor_type>()) {
            return io->context().stopped();
        }
        if (const auto *strand = ex.target<asio::strand<asio::io_context::executor_type> >()) {
            return strand->get_inner_executor().context().stopped();
        }
        return false;
    }

} // namespace wavex
