// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file http.ixx
 * @brief Primary C++ module interface partition for HTTP protocol support in WaveX.
 */

module;

#include <wavex/protos/http/Methods.hpp>
#include <wavex/protos/http/http1codec.hpp>
#include <wavex/protos/http/http2codec.hpp>
#include <wavex/protos/http/HttpRequest.hpp>
#include <wavex/protos/http/HttpResponse.hpp>
#include <wavex/protos/http/http.hpp>

export module wavex:protos_http;

export import :protos_http_methods;
export import :protos_http_codec;
export import :protos_http_http2codec;
export import :protos_http_request;
export import :protos_http_response;

export namespace wavex::protos::http {
    using http::method;
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
    using http::http2codec;
    using http::HttpRequest;
    using http::Http1Request;
    using http::http1request;
    using http::Http2Request;
    using http::http2request;
    using http::HttpResponse;
    using http::Http1Response;
    using http::http1response;
    using http::Http2Response;
    using http::http2response;

    // Templated codec helpers
    using http::parse_request;
    using http::parse_response;
    using http::serialize_request;
    using http::serialize_response;
    using http::format_chunk;
    using http::format_terminal_chunk;
    using http::decode_response;
    using http::dechunk;
}
