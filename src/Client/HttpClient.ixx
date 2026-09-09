// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file HttpClient.ixx
 * @brief C++ module interface partition for HttpClient in WaveX.
 */

module;

#include <wavex/Client/HttpClient.hpp>

export module wavex:client;

export namespace wavex::client {
    using client::HttpClient;
    using protos::http::method;
    using enum wavex::protos::http::method;
}
