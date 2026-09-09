// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file MiddleWare.ixx
 * @brief C++ module interface for the WaveX middleware pipeline types.
 *
 * Exports wavex::base::Next and wavex::base::MiddlewareFn from the
 * wavex:middleware partition so they can be consumed via:
 *
 *   import wavex;           // transitively re-exports :middleware
 *   import wavex:middleware; // direct partition import
 */

module;

// Global module fragment — legacy headers included here are invisible
// outside this translation unit but their declarations are available
// to the module body below.
#define ASIO_HAS_CO_AWAIT 1
#include <functional>
#include <asio/awaitable.hpp>
#include <wavex/Base/MimeTypes.hpp>
#include <wavex/Base/Request.hpp>
#include <wavex/Base/Response.hpp>
#include <wavex/Base/MiddleWare.hpp>

export module wavex:middleware;

export namespace wavex::base {
    using base::Request;
    using base::Response;
    using base::mime_type_from_ext;
    using base::mime_type_from_path;

    /// Callable that invokes the next middleware or the final handler.
    using Next = std::function<asio::awaitable<void>()>;

    /**
     * @brief Generic middleware function signature for CRTP Request and Response types.
     */
    template<typename ReqT, typename ResT>
    using GenericMiddlewareFn = std::function<asio::awaitable<void>(ReqT &, ResT &, Next)>;

    using base::keep_alive;
    using base::sse_stay_active;
} // export namespace wavex::base
