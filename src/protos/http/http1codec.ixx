// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file http1codec.ixx
 * @brief C++ module interface for the HTTP/1.x codec in WaveX.
 */

module;

#include <wavex/protos/http/http1codec.hpp>

export module wavex:protos_http_codec;

export namespace wavex::protos::http {
    using http::header;
    using http::message_base;
    using http::request;
    using http::response;
    using http::to_string;
    using http::from_string;
    using http::status_text_for;
    using http::parser;
    using http::encoder;
    using http::decoder;
    using http::http1codec;

    namespace http1 {
        using http1::request;
        using http1::response;
        using http1::parser;
        using http1::encoder;
        using http1::decoder;
    }
}
