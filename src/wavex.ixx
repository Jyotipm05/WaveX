// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file wavex.ixx
 * @brief Primary C++ module interface file for the WaveX library.
 * 
 * Exports the main WaveX namespace symbols, functions, and submodule partitions.
 */

module;

#include <wavex/wavex.hpp>

export module wavex;
export import :chainable;
export import :logger;
export import :protos;
export import :protos_http;
export import :middleware;
export import :router;
export import :http_router;
export import :server;
export import :client;
export import :cli;


export namespace wavex {
    using wavex::_version;
    std::string_view wx_version = ::wx_version;
}
