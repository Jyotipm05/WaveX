// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file TlsConfig.ixx
 * @brief C++ module interface partition for TlsConfig in WaveX.
 */

module;

#include <wavex/Server/TlsConfig.hpp>

export module wavex:server_tls_config;

export namespace wavex::server {
    using server::TlsConfig;
}
