// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file ServerTls.ipp
 * @brief Server TLS configuration and initialization implementations.
 *
 * @note This file is included by Server.hpp and should NOT be included directly.
 */

#pragma once

#include <stdexcept>
#include <string>
#include <utility>
#include <wavex/Utils/FsUtils.hpp>

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
#include <asio/ssl.hpp>
#endif

namespace wavex::server {

    template<typename Codec, typename RouterType>
    void Server<Codec, RouterType>::enable_tls(TlsConfig config) {
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        tls_config_ = std::move(config);
        init_ssl();
        tls_enabled_ = true;
#else
        (void) config;
        throw std::runtime_error(
            "Server::enable_tls failed: WaveX was built without OpenSSL TLS support (WAVEX_HAS_SSL=0)");
#endif
    }

    template<typename Codec, typename RouterType>
    void Server<Codec, RouterType>::enable_tls(std::string cert_file, std::string key_file) {
        TlsConfig cfg;
        cfg.cert_file = std::move(cert_file);
        cfg.key_file = std::move(key_file);
        enable_tls(std::move(cfg));
    }

    template<typename Codec, typename RouterType>
    bool Server<Codec, RouterType>::is_tls_enabled() const noexcept {
        return tls_enabled_;
    }

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
    template<typename Codec, typename RouterType>
    void Server<Codec, RouterType>::init_ssl() {
        ssl_ctx_ = std::make_unique<asio::ssl::context>(asio::ssl::context::tlsv13_server);
        ssl_ctx_->set_options(
            asio::ssl::context::default_workarounds |
            asio::ssl::context::no_sslv2 | asio::ssl::context::no_sslv3 |
            asio::ssl::context::no_tlsv1 | asio::ssl::context::no_tlsv1_1 |
            asio::ssl::context::no_tlsv1_2
        );

        if (!tls_config_.key_password.empty()) {
            ssl_ctx_->set_password_callback(
                [pwd = tls_config_.key_password](std::size_t, asio::ssl::context::password_purpose) {
                    return pwd;
                });
        }

        std::string cert_path = tls_config_.cert_file;
        std::string key_path = tls_config_.key_file;

        std::error_code ec;
        if (!wavex::utils::fs_utils::exists(cert_path, ec)) {
#ifdef PROJECT_DIR
            std::string alt = std::string(PROJECT_DIR) + "/" + cert_path;
            if (wavex::utils::fs_utils::exists(alt, ec)) cert_path = alt;
#endif
            if (!wavex::utils::fs_utils::exists(cert_path, ec) &&
                wavex::utils::fs_utils::exists("../" + tls_config_.cert_file, ec)) {
                cert_path = "../" + tls_config_.cert_file;
            }
        }

        if (!wavex::utils::fs_utils::exists(key_path, ec)) {
#ifdef PROJECT_DIR
            std::string alt = std::string(PROJECT_DIR) + "/" + key_path;
            if (wavex::utils::fs_utils::exists(alt, ec)) key_path = alt;
#endif
            if (!wavex::utils::fs_utils::exists(key_path, ec) &&
                wavex::utils::fs_utils::exists("../" + tls_config_.key_file, ec)) {
                key_path = "../" + tls_config_.key_file;
            }
        }

        ssl_ctx_->use_certificate_chain_file(cert_path);
        ssl_ctx_->use_private_key_file(key_path, asio::ssl::context::pem);

        if (!tls_config_.dh_file.empty()) {
            ssl_ctx_->use_tmp_dh_file(tls_config_.dh_file);
        }

        // Protocol-driven ALPN selection callback registration
        traits::configure_alpn(ssl_ctx_->native_handle());
    }
#endif

} // namespace wavex::server
