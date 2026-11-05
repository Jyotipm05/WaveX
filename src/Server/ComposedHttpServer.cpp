// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file ComposedHttpServer.cpp
 * @brief Explicit instantiation of the default ComposedServer (keeps the HTTP/2 + HTTP/3 handler instantiations out of every includer).
 */

#include <wavex/Server/ComposedHttpServer.hpp>

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
#include <wavex/Server/Server.hpp>

namespace wavex::server {

    // The one instantiation of the default pair (ComposedServer.hpp declares it extern).
    template class ComposedServer<engine::Http2Router, engine::Http3Router>;

} // namespace wavex::server
#endif // WAVEX_HAS_SSL
