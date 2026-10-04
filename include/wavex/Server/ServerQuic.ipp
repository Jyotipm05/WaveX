// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file ServerQuic.ipp
 * @brief Server HTTP/3 and QUIC transport configuration implementations.
 *
 * @note This file is included by Server.hpp and should NOT be included directly.
 */

#pragma once

namespace wavex::server {

    template<typename Codec, typename RouterType>
    bool Server<Codec, RouterType>::is_http3_enabled() const noexcept {
        return has_quic_transport || http3_enabled_;
    }

    template<typename Codec, typename RouterType>
    void Server<Codec, RouterType>::enable_http3(engine::Http3Router &h3_router) noexcept {
        h3_router_ = &h3_router;
        http3_enabled_ = true;
    }

    template<typename Codec, typename RouterType>
    void Server<Codec, RouterType>::attach_http3(engine::Http3Router &h3_router) noexcept {
        enable_http3(h3_router);
    }

    template<typename Codec, typename RouterType>
    void Server<Codec, RouterType>::allow_insecure(bool allow) noexcept {
        allow_insecure_quic_ = allow;
    }

} // namespace wavex::server
