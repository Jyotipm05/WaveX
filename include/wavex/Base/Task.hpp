// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file Task.hpp
 * @brief `wavex::task<T>`: the coroutine return type of every asynchronous WaveX function.
 *
 * `wavex::task<T>` is another name for `asio::awaitable<T>` (running on `wavex::executor`), exactly the same
 * type, so nothing converts and nothing is copied. Handlers, middleware and library signatures spell it
 * `wavex::task<...>` so application code reads as WaveX code, and code that still says `asio::awaitable<...>`
 * keeps compiling and interoperates freely.
 *
 * @code
 * wavex::task<void> handler(Request &req, Response &res) {
 *     co_await res.send("hello");
 * }
 * wavex::task<int> answer() { co_return 42; }
 * @endcode
 */
#pragma once

#include <asio/awaitable.hpp>

namespace wavex {

    /// Coroutine type returned by asynchronous WaveX functions; identical to `asio::awaitable<T>`.
    template<typename T = void>
    using task = asio::awaitable<T>;

} // namespace wavex
