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

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

namespace wavex::server {

    template<typename Codec, typename RouterType>
    bool Server<Codec, RouterType>::is_http3_enabled() const noexcept {
        return has_quic_transport;
    }

    template<typename Codec, typename RouterType>
    void Server<Codec, RouterType>::allow_insecure(bool allow) noexcept {
        allow_insecure_quic_ = allow;
    }

} // namespace wavex::server

#endif // WAVEX_HAS_SSL

