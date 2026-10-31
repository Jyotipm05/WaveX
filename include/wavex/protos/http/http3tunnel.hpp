// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file http3tunnel.hpp
 * @brief The "data stream" of an HTTP/3 extended CONNECT (RFC 9220 §3, RFC 9297 §3.1).
 *
 * After the CONNECT exchange the request stream keeps carrying HTTP/3 frames: the tunnelled bytes travel in
 * DATA frames. `make_data_tunnel` turns such a stream into a plain byte stream so that byte-oriented protocols
 * (WebSocket frames, HTTP capsules) can run on it unchanged.
 */

#pragma once

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

#if defined(__MINGW32__) || defined(__clang__) || defined(__GNUC__)
#include <cstddef>
#endif
#include <string>

#include <wavex/Network/AnyStream.hpp>

namespace wavex::protos::http::http3 {
    /**
     * @brief Wrap the request stream of an accepted extended CONNECT.
     *
     * Reads yield the concatenated payloads of the DATA frames; unknown or extension frame types are skipped
     * (RFC 9114 §9); a trailing HEADERS frame ends the stream (EOF); control-stream-only frames (SETTINGS,
     * GOAWAY, ...) and the reserved HTTP/2 types are a protocol error. Writes are sent as one DATA frame each.
     * Half-close, cancel and close are forwarded to the inner stream, and `native<T>()` still exposes it.
     *
     * @param inner    The request stream (after the response HEADERS were written).
     * @param leftover Bytes already read from the stream past the request HEADERS.
     */
    [[nodiscard]] network::AnyStream make_data_tunnel(network::AnyStream inner, std::string leftover);

    /// Encode one DATA frame carrying `payload` (helper shared with the tunnel and tests).
    [[nodiscard]] std::string encode_tunnel_data_frame(std::string_view payload);
} // namespace wavex::protos::http::http3

#endif // WAVEX_HAS_SSL
