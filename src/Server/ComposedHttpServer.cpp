// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file ComposedHttpServer.cpp
 * @brief Translation unit anchor for ComposedHttpServer.
 */

#include <wavex/Server/ComposedHttpServer.hpp>

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
#include <wavex/Server/Server.hpp>

namespace wavex::server {

    // Anchor translation unit for ComposedHttpServer

} // namespace wavex::server
#endif // WAVEX_HAS_SSL
