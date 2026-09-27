// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file http3codec.ixx
 * @brief C++ module interface for the HTTP/3 codec in WaveX.
 */

module;

#include <wavex/protos/http/http3codec.hpp>

export module wavex:protos_http_http3codec;

export namespace wavex::protos::http {
    using http::http3codec;

    namespace http3 {
        using http3::frame_type;
        using http3::stream_type;
        using http3::settings_parameter;
        using http3::error_code;
        using http3::frame_header;
        using http3::request;
        using http3::response;
        using http3::connection_context;
        using http3::parser;
        using http3::encoder;
        using http3::decoder;

        namespace qpack {
            using qpack::dynamic_table;
            using qpack::encoder;
            using qpack::decoder;
        }
    }
}
