// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file HttpRequest.ixx
 * @brief C++ module interface for HttpRequest in WaveX.
 */

module;

#include <wavex/protos/http/HttpRequest.hpp>

export module wavex:protos_http_request;

export namespace wavex::protos::http {
    using http::HttpRequest;
    using http::Http1Request;
    using http::http1request;
}
