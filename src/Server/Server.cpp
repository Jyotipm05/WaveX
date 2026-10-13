// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file Server.cpp
 * @brief Out-of-line non-template implementations and translation unit anchor for Server.
 */

#include <wavex/Server/Server.hpp>
#include <wavex/Utils/FsUtils.hpp>
#include <wavex/Utils/BinaryFile.hpp>
#include <wavex/Base/MimeTypes.hpp>
#include <wavex/Base/Memory.hpp>

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/buffer.hpp>
#include <chrono>
#include <algorithm>
#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>

namespace wavex::server::detail {

    auto resolve_cert_path(const std::string_view base_dir, const std::string &cert_file) -> std::string {
        if (cert_file.empty()) {
            throw std::runtime_error("Server::enable_tls: Certificate file path cannot be empty");
        }
        std::filesystem::path p(cert_file);
        if (!base_dir.empty() && p.is_relative()) {
            p = std::filesystem::path(base_dir) / p;
        }
        std::error_code ec;
        if (!wavex::utils::fs_utils::exists(p.string(), ec)) {
            throw std::runtime_error("Server::enable_tls: Certificate file not found: '" + p.string() + "'");
        }
        return p.string();
    }

    auto resolve_key_path(const std::string_view base_dir, const std::string &key_file) -> std::string {
        if (key_file.empty()) {
            throw std::runtime_error("Server::enable_tls: Private key file path cannot be empty");
        }
        std::filesystem::path p(key_file);
        if (!base_dir.empty() && p.is_relative()) {
            p = std::filesystem::path(base_dir) / p;
        }
        std::error_code ec;
        if (!wavex::utils::fs_utils::exists(p.string(), ec)) {
            throw std::runtime_error("Server::enable_tls: Private key file not found: '" + p.string() + "'");
        }
        return p.string();
    }

    auto load_not_found_page_file(const std::string &file_path, std::string &out_body, std::string &out_mime) -> bool {
        if (auto res = utils::BinaryFile::read_all(file_path)) {
            out_body = std::move(*res);
            out_mime = std::string(base::mime_type_from_path(file_path));
            return true;
        }
        return false;
    }

    void release_thread_local_pool() {
        wavex::memory::get_thread_local_pool().release();
    }

    void drain_and_abort_tcp(asio::ip::tcp::socket &sock) {
        asio::error_code ec;
        std::ignore = sock.shutdown(asio::ip::tcp::socket::shutdown_send, ec);
        if (ec || !sock.is_open()) return;

        constexpr auto kDrainLimit = std::chrono::milliseconds(200);
        constexpr std::size_t kMaxDrainBytes = 64 * 1024; // 64 KB cap
        const auto deadline = std::chrono::steady_clock::now() + kDrainLimit;

        char discard_buf[4096];
        std::size_t total_drained = 0;

        while (sock.is_open()) {
            if (std::chrono::steady_clock::now() >= deadline) break;

            const std::size_t avail = sock.available(ec);
            if (ec || avail == 0) break;

            const std::size_t to_read = std::min({avail, sizeof(discard_buf), kMaxDrainBytes - total_drained});
            const std::size_t n = sock.read_some(asio::buffer(discard_buf, to_read), ec);
            if (ec || n == 0) break;

            total_drained += n;
            if (total_drained >= kMaxDrainBytes) break;
        }
    }

} // namespace wavex::server::detail

// ─── Explicit Template Instantiations for Asio Coroutines ──────────────────
template class asio::awaitable<void, asio::any_io_executor>;
template class asio::detail::awaitable_frame<void, asio::any_io_executor>;
template class asio::detail::awaitable_thread<asio::any_io_executor>;

namespace wavex::server {

    // ─── Explicit Template Instantiations for Concrete Server Types ────────────
    template class Server<protos::http::http1codec, engine::Http1Router>;
    template class Server<protos::http::http2codec, engine::Http2Router>;
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
    template class Server<protos::http::http3codec, engine::Http3Router>;
#endif

} // namespace wavex::server