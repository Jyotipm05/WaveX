// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file HttpResponse.ixx
 * @brief C++ module interface partition for HttpResponse in WaveX.
 */

module;

#include <wavex/protos/http/HttpResponse.hpp>

export module wavex:protos_http_response;

export namespace wavex::protos::http {
    using http::HttpResponse;
    using http::Http1Response;
    using http::http1response;
}
