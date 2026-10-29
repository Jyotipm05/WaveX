// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file protos.hpp
 * @brief Defines supported communication protocols within WaveX.
 */

#pragma once

namespace wavex {
    /**
     * @enum protocol
     * @brief Supported network protocols in the WaveX framework.
     */
    enum class protocol {
        http,        /**< Hypertext Transfer Protocol (HTTP/1.1, HTTP/2, HTTP/3) */
        websocket,   /**< WebSocket (RFC 6455; over HTTP/3 per RFC 9220) */
        webtransport /**< WebTransport over HTTP/3 */
    };
}
