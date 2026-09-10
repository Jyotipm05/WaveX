// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file http2codec.ixx
 * @brief C++ module interface for the HTTP/2 codec in WaveX.
 */

module;

#include <wavex/protos/http/http2codec.hpp>

export module wavex:protos_http_http2codec;

export namespace wavex::protos::http {
    using http::http2codec;

    namespace http2 {
        using http2::frame_type;
        using http2::frame_header;
        using http2::error_code;
        using http2::settings_parameter;
        using http2::request;
        using http2::response;
        using http2::parser;
        using http2::encoder;
        using http2::decoder;
    }
}
