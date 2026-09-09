// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file Router.ixx
 * @brief C++ module interface file for the Router component in WaveX.
 *
 * Exports wavex::engine::Handler, RouteMatch, ScopedMiddleware, and Router
 * from the wavex:router partition.
 */

module;

// Global module fragment
#include <wavex/Engine/Router.hpp>

export module wavex:router;

export namespace wavex::engine {
    using engine::Router;
}
