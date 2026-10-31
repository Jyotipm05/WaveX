// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file ServerState.hpp
 * @brief Lifecycle states and simple type definitions for WaveX servers.
 */

#pragma once

#include <cstdint>

namespace wavex::server {

    /**
     * @enum ServerState
     * @brief Lifecycle states of the Server instance.
     */
    enum class ServerState : uint8_t {
        Stopped,       ///< Server is fully stopped
        Running,       ///< Server is accepting and processing connections
        ShuttingDown   ///< Server is draining active connections
    };

} // namespace wavex::server
