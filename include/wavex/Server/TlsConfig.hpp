// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file TlsConfig.hpp
 * @brief Configuration parameters for TLS 1.3 encrypted server and client endpoints.
 */

#pragma once

#include <string>

namespace wavex::server {
    /**
     * @struct TlsConfig
     * @brief Configuration struct for TLS 1.3 server encryption settings.
     */
    struct TlsConfig {
        std::string cert_file = "ssl/test.crt"; ///< Path to PEM certificate chain file
        std::string key_file = "ssl/test.key"; ///< Path to PEM private key file
        std::string dh_file; ///< Optional path to Diffie-Hellman parameters file
        std::string key_password; ///< Optional password for encrypted private key
        bool force_tls13 = true; ///< Enforce TLS 1.3 exclusively (disables legacy SSL/TLS)
    };
} // namespace wavex::server
