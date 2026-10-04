// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file ServerAliases.hpp
 * @brief Protocol-specialized server type aliases.
 */

#pragma once

#include <wavex/protos/http/http1codec.hpp>
#include <wavex/protos/http/http2codec.hpp>
#include <wavex/protos/http/http3codec.hpp>
#include <wavex/Engine/HttpRouter.hpp>
#include <wavex/Server/ServerCore.hpp>

namespace wavex::server {

    using Http1Server  = Server<wavex::protos::http::http1codec, wavex::engine::Http1Router>;
    using http1server  = Http1Server;
    using Http2Server  = Server<wavex::protos::http::http2codec, wavex::engine::Http2Router>;
    using http2server  = Http2Server;
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
    using Http3Server  = Server<wavex::protos::http::http3codec, wavex::engine::Http3Router>;
    using http3server  = Http3Server;
#endif
    using HttpServer   = Http1Server;
    using httpserver   = HttpServer;

} // namespace wavex::server
