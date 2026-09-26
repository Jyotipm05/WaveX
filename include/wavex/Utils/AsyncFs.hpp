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
#include <string>
#include <system_error>
#include <vector>
#include <type_traits>

#include <asio/awaitable.hpp>
#include <wavex/Utils/FsUtils.hpp>

namespace wavex::fs {
    namespace detail {
        template<typename T>
        std::string to_string_path(const T &p) {
            return utils::fs_utils::to_u8_path_string(p);
        }
    } // namespace detail

    /**
     * @brief Asynchronously reads the entire contents of a file into a std::string.
     * @param path The file path to read.
     * @return asio::awaitable yielding std::expected<std::string, std::error_code>.
     */
    asio::awaitable<std::expected<std::string, std::error_code> > read_file(std::string path);

    template<typename PathLike>
        requires (!std::is_convertible_v<PathLike, std::string>)
    asio::awaitable<std::expected<std::string, std::error_code> > read_file(
        const PathLike &path) {
        return read_file(detail::to_string_path(path));
    }

    /**
     * @brief Asynchronously reads the entire contents of a file into a binary std::vector<char>.
     * @param path The file path to read.
     * @return asio::awaitable yielding std::expected<std::vector<char>, std::error_code>.
     */
    asio::awaitable<std::expected<std::vector<char>, std::error_code> > read_bytes(std::string path);

    template<typename PathLike>
        requires (!std::is_convertible_v<PathLike, std::string>)
    asio::awaitable<std::expected<std::vector<char>, std::error_code> > read_bytes(
        const PathLike &path) {
        return read_bytes(detail::to_string_path(path));
    }

    /**
     * @brief Asynchronously writes string content to a file, replacing existing content.
     * @param path The file path to write to.
     * @param content The string contents to write.
     * @return asio::awaitable yielding std::expected<void, std::error_code>.
     */
    asio::awaitable<std::expected<void, std::error_code> > write_file(std::string path, std::string content);

    template<typename PathLike>
        requires (!std::is_convertible_v<PathLike, std::string>)
    asio::awaitable<std::expected<void, std::error_code> > write_file(
        const PathLike &path, std::string content) {
        return write_file(detail::to_string_path(path), std::move(content));
    }

    /**
     * @brief Asynchronously appends string content to a file.
     * @param path The file path to append to.
     * @param content The string contents to append.
     * @return asio::awaitable yielding std::expected<void, std::error_code>.
     */
    asio::awaitable<std::expected<void, std::error_code> > append_file(std::string path, std::string content);

    template<typename PathLike>
        requires (!std::is_convertible_v<PathLike, std::string>)
    asio::awaitable<std::expected<void, std::error_code> > append_file(
        const PathLike &path, std::string content) {
        return append_file(detail::to_string_path(path), std::move(content));
    }

    /**
     * @brief Asynchronously copies a file.
     * @param from Source path.
     * @param to Destination path.
     * @param overwrite True to overwrite existing file.
     * @return asio::awaitable yielding std::expected<void, std::error_code>.
     */
    asio::awaitable<std::expected<void, std::error_code> > copy_file(
        std::string from, std::string to, bool overwrite = true);

    template<typename PathLike1, typename PathLike2>
        requires (!std::is_convertible_v<PathLike1, std::string> || !std::is_convertible_v<PathLike2, std::string>)
    asio::awaitable<std::expected<void, std::error_code> > copy_file(
        const PathLike1 &from, const PathLike2 &to, bool overwrite = true) {
        return copy_file(detail::to_string_path(from), detail::to_string_path(to), overwrite);
    }

    /**
     * @brief Asynchronously removes a file or directory.
     * @param path Path to remove.
     * @return asio::awaitable yielding std::expected<bool, std::error_code> (true if file existed and was removed).
     */
    asio::awaitable<std::expected<bool, std::error_code> > remove(std::string path);

    template<typename PathLike>
        requires (!std::is_convertible_v<PathLike, std::string>)
    asio::awaitable<std::expected<bool, std::error_code> > remove(
        const PathLike &path) {
        return remove(detail::to_string_path(path));
    }
} // namespace wavex::fs
