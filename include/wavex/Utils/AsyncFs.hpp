// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file AsyncFs.hpp
 * @brief Tokio-like async file system operations built on wavex::spawn_blocking.
 *
 * Provides non-blocking file read, write, append, copy, and remove utilities
 * that execute standard C++ std::ifstream/ofstream/std::filesystem calls on
 * the dedicated blocking thread pool, returning results via std::expected.
 */

#pragma once

#include <expected>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <vector>

#include <asio/awaitable.hpp>
#include <wavex/Async/SpawnBlocking.hpp>

namespace wavex::fs {
    /**
     * @brief Asynchronously reads the entire contents of a file into a std::string.
     * @param path The file path to read.
     * @return asio::awaitable yielding std::expected<std::string, std::error_code>.
     */
    inline asio::awaitable<std::expected<std::string, std::error_code> > read_file(
        std::filesystem::path path) {
        auto res = co_await wavex::spawn_blocking(
            [p = std::move(path)]() -> std::expected<std::string, std::error_code> {
                std::error_code ec;
                if (!std::filesystem::exists(p, ec) || ec) {
                    return std::unexpected(ec ? ec : std::make_error_code(std::errc::no_such_file_or_directory));
                }

                std::ifstream file(p, std::ios::binary | std::ios::ate);
                if (!file.is_open()) {
                    return std::unexpected(std::make_error_code(std::errc::permission_denied));
                }

                const auto size = file.tellg();
                if (size < 0) {
                    return std::unexpected(std::make_error_code(std::errc::io_error));
                }

                std::string content;
                content.resize(static_cast<std::size_t>(size));
                file.seekg(0, std::ios::beg);
                if (!file.read(content.data(), static_cast<std::streamsize>(size))) {
                    if (size > 0) {
                        return std::unexpected(std::make_error_code(std::errc::io_error));
                    }
                }
                return content;
            });
        co_return res;
    }

    /**
     * @brief Asynchronously reads the entire contents of a file into a binary std::vector<char>.
     * @param path The file path to read.
     * @return asio::awaitable yielding std::expected<std::vector<char>, std::error_code>.
     */
    inline asio::awaitable<std::expected<std::vector<char>, std::error_code> > read_bytes(
        std::filesystem::path path) {
        auto res = co_await wavex::spawn_blocking(
            [p = std::move(path)]() -> std::expected<std::vector<char>, std::error_code> {
                std::error_code ec;
                if (!std::filesystem::exists(p, ec) || ec) {
                    return std::unexpected(ec ? ec : std::make_error_code(std::errc::no_such_file_or_directory));
                }

                std::ifstream file(p, std::ios::binary | std::ios::ate);
                if (!file.is_open()) {
                    return std::unexpected(std::make_error_code(std::errc::permission_denied));
                }

                const auto size = file.tellg();
                if (size < 0) {
                    return std::unexpected(std::make_error_code(std::errc::io_error));
                }

                std::vector<char> content(static_cast<std::size_t>(size));
                file.seekg(0, std::ios::beg);
                if (!file.read(content.data(), static_cast<std::streamsize>(size))) {
                    if (size > 0) {
                        return std::unexpected(std::make_error_code(std::errc::io_error));
                    }
                }
                return content;
            });
        co_return res;
    }

    /**
     * @brief Asynchronously writes string content to a file, replacing existing content.
     * @param path The file path to write to.
     * @param content The string contents to write.
     * @return asio::awaitable yielding std::expected<void, std::error_code>.
     */
    inline asio::awaitable<std::expected<void, std::error_code> > write_file(
        std::filesystem::path path, std::string content) {
        auto res = co_await wavex::spawn_blocking(
            [p = std::move(path), data = std::move(content)]() -> std::expected<void, std::error_code> {
                std::ofstream file(p, std::ios::binary | std::ios::trunc);
                if (!file.is_open()) {
                    return std::unexpected(std::make_error_code(std::errc::permission_denied));
                }

                if (!file.write(data.data(), static_cast<std::streamsize>(data.size()))) {
                    return std::unexpected(std::make_error_code(std::errc::io_error));
                }
                return {};
            });
        co_return res;
    }

    /**
     * @brief Asynchronously appends string content to a file.
     * @param path The file path to append to.
     * @param content The string contents to append.
     * @return asio::awaitable yielding std::expected<void, std::error_code>.
     */
    inline asio::awaitable<std::expected<void, std::error_code> > append_file(
        std::filesystem::path path, std::string content) {
        auto res = co_await wavex::spawn_blocking(
            [p = std::move(path), data = std::move(content)]() -> std::expected<void, std::error_code> {
                std::ofstream file(p, std::ios::binary | std::ios::app);
                if (!file.is_open()) {
                    return std::unexpected(std::make_error_code(std::errc::permission_denied));
                }

                if (!file.write(data.data(), static_cast<std::streamsize>(data.size()))) {
                    return std::unexpected(std::make_error_code(std::errc::io_error));
                }
                return {};
            });
        co_return res;
    }

    /**
     * @brief Asynchronously copies a file.
     * @param from Source path.
     * @param to Destination path.
     * @param options Filesystem copy options.
     * @return asio::awaitable yielding std::expected<void, std::error_code>.
     */
    inline asio::awaitable<std::expected<void, std::error_code> > copy_file(
        std::filesystem::path from, std::filesystem::path to,
        std::filesystem::copy_options options = std::filesystem::copy_options::overwrite_existing) {
        auto res = co_await wavex::spawn_blocking(
            [f = std::move(from), t = std::move(to), options]() -> std::expected<void, std::error_code> {
                std::error_code ec;
                std::filesystem::copy_file(f, t, options, ec);
                if (ec) {
                    return std::unexpected(ec);
                }
                return {};
            });
        co_return res;
    }

    /**
     * @brief Asynchronously removes a file or directory.
     * @param path Path to remove.
     * @return asio::awaitable yielding std::expected<bool, std::error_code> (true if file existed and was removed).
     */
    inline asio::awaitable<std::expected<bool, std::error_code> > remove(
        std::filesystem::path path) {
        auto res = co_await wavex::spawn_blocking([p = std::move(path)]() -> std::expected<bool, std::error_code> {
            std::error_code ec;
            const bool removed = std::filesystem::remove(p, ec);
            if (ec) {
                return std::unexpected(ec);
            }
            return removed;
        });
        co_return res;
    }
} // namespace wavex::fs
