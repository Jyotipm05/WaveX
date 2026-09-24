// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file AsyncFs.cpp
 * @brief Implementation of Tokio-like async file system operations.
 */

#ifndef ASIO_HAS_CO_AWAIT
#define ASIO_HAS_CO_AWAIT 1
#endif

#include <wavex/Utils/AsyncFs.hpp>
#include <wavex/Async/SpawnBlocking.hpp>
#include <wavex/Utils/FsUtils.hpp>
#include <wavex/Utils/BinaryFile.hpp>
#include <asio/awaitable.hpp>
#include <string>
#include <vector>
#include <expected>
#include <system_error>
#include <utility>

namespace wavex::fs {
    asio::awaitable<std::expected<std::string, std::error_code> > read_file(std::string path) {
        auto res = co_await spawn_blocking(
            [p = std::move(path)]() -> std::expected<std::string, std::error_code> {
                std::error_code ec;
                if (!utils::fs_utils::exists(p, ec) || ec) {
                    return std::unexpected(ec ? ec : std::make_error_code(std::errc::no_such_file_or_directory));
                }

                auto result = utils::BinaryFile::read_all(p);
                if (!result) {
                    return std::unexpected(result.error());
                }
                return result.value();
            });
        co_return res;
    }

    asio::awaitable<std::expected<std::vector<char>, std::error_code> > read_bytes(std::string path) {
        auto res = co_await spawn_blocking(
            [p = std::move(path)]() -> std::expected<std::vector<char>, std::error_code> {
                std::error_code ec;
                if (!utils::fs_utils::exists(p, ec) || ec) {
                    return std::unexpected(ec ? ec : std::make_error_code(std::errc::no_such_file_or_directory));
                }

                auto result = utils::BinaryFile::read_all(p);
                if (!result) {
                    return std::unexpected(result.error());
                }
                const std::string &s = result.value();
                return std::vector<char>(s.begin(), s.end());
            });
        co_return res;
    }

    asio::awaitable<std::expected<void, std::error_code> > write_file(std::string path, std::string content) {
        auto res = co_await spawn_blocking(
            [p = std::move(path), data = std::move(content)]() -> std::expected<void, std::error_code> {
                if (!utils::BinaryFile::write_all(p, data, false)) {
                    return std::unexpected(std::make_error_code(std::errc::io_error));
                }
                return {};
            });
        co_return res;
    }

    asio::awaitable<std::expected<void, std::error_code> > append_file(std::string path, std::string content) {
        auto res = co_await spawn_blocking(
            [p = std::move(path), data = std::move(content)]() -> std::expected<void, std::error_code> {
                if (!utils::BinaryFile::write_all(p, data, true)) {
                    return std::unexpected(std::make_error_code(std::errc::io_error));
                }
                return {};
            });
        co_return res;
    }

    asio::awaitable<std::expected<void, std::error_code> > copy_file(std::string from, std::string to, bool overwrite) {
        auto res = co_await spawn_blocking(
            [f = std::move(from), t = std::move(to), overwrite]() -> std::expected<void, std::error_code> {
                std::error_code ec;
                utils::fs_utils::copy_file(f, t, overwrite, ec);
                if (ec) {
                    return std::unexpected(ec);
                }
                return {};
            });
        co_return res;
    }

    asio::awaitable<std::expected<bool, std::error_code> > remove(std::string path) {
        auto res = co_await spawn_blocking([p = std::move(path)]() -> std::expected<bool, std::error_code> {
            std::error_code ec;
            const bool removed = utils::fs_utils::remove(p, ec);
            if (ec) {
                return std::unexpected(ec);
            }
            return removed;
        });
        co_return res;
    }
} // namespace wavex::fs
