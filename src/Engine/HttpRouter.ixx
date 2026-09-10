// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file HttpRouter.ixx
 * @brief C++ module interface for the HttpRouter component in WaveX.
 *
 * Exports wavex::engine::HttpProto and wavex::engine::HttpRouter from the
 * wavex:http_router partition so they can be consumed via:
 *
 *   import wavex;              // transitively re-exports :http_router
 *   import wavex:http_router;  // direct partition import
 */

module;

// Global module fragment
#include <wavex/Engine/HttpRouter.hpp>

export module wavex:http_router;

export namespace wavex::engine {
    using engine::Http1Proto;
    using engine::http1proto;
    using engine::HttpRouter;
    using engine::HttpProto;
    using engine::Http1Router;
    using engine::http1router;
    using engine::Http2Router;
    using engine::http2router;
}
