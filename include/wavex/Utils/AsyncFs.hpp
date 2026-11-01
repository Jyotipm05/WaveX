// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file AsyncFs.hpp
 * @brief Tokio-like async file system operations.
 *
 * Provides non-blocking file read, write, append, copy, and remove utilities returning results via
 * std::expected. By default every call runs its blocking file code (open, stat, read, write, close) on the
 * dedicated blocking thread pool (wavex::spawn_blocking), so a slow disk or network file system can never stall
 * the worker that serves your connections.
 *
 * Optionally (`set_io_mode(io_mode::native)`), reads of small files use Asio's native file I/O
 * (asio::stream_file: IOCP on Windows, io_uring on Linux when built with -DWAVEX_IO_URING=ON), which skips the
 * thread hop. Asio opens the file with a synchronous open() on the calling worker, so that mode trades the
 * "never blocks a worker" guarantee for lower latency on local disks; it is off by default. See the
 * "Async file I/O" section of docs/architecture.md for measurements.
 */

#pragma once

#include <cstddef>
#include <expected>
#include <string>
#include <system_error>
#include <vector>
#include <type_traits>

#include <asio/awaitable.hpp>
#include <wavex/Base/Task.hpp>
#include <wavex/Utils/FsUtils.hpp>

namespace wavex::fs {
    /// How read_file()/read_bytes() reach the file system.
    enum class io_mode {
        blocking_pool, ///< default: all file code runs on the blocking thread pool (never blocks a worker)
        native ///< small files via Asio's native file I/O when the build has it; larger files use the pool
    };

    /// Largest file (bytes) that `io_mode::native` reads natively; bigger files go to the blocking pool, which wins
    /// on large files under concurrency (measured crossover between 64 KiB and 256 KiB).
    inline constexpr std::size_t native_read_max_bytes = 64 * 1024;

    /// True when this build of WaveX has native async file I/O (Windows IOCP, or Linux with WAVEX_IO_URING=ON) and
    /// the kernel has not refused it at run time.
    [[nodiscard]] bool native_io_available() noexcept;

    /// Select the I/O mode (process-wide, thread-safe). Returns the mode now in effect: asking for `native` where
    /// `native_io_available()` is false leaves `blocking_pool` in effect.
    io_mode set_io_mode(io_mode mode) noexcept;

    /// The mode currently in effect.
    [[nodiscard]] io_mode get_io_mode() noexcept;

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
    wavex::task<std::expected<std::string, std::error_code> > read_file(std::string path);

    template<typename PathLike>
        requires (!std::is_convertible_v<PathLike, std::string>)
    wavex::task<std::expected<std::string, std::error_code> > read_file(
        const PathLike &path) {
        return read_file(detail::to_string_path(path));
    }

    /**
     * @brief Asynchronously reads the entire contents of a file into a binary std::vector<char>.
     * @param path The file path to read.
     * @return asio::awaitable yielding std::expected<std::vector<char>, std::error_code>.
     */
    wavex::task<std::expected<std::vector<char>, std::error_code> > read_bytes(std::string path);

    template<typename PathLike>
        requires (!std::is_convertible_v<PathLike, std::string>)
    wavex::task<std::expected<std::vector<char>, std::error_code> > read_bytes(
        const PathLike &path) {
        return read_bytes(detail::to_string_path(path));
    }

    /**
     * @brief Asynchronously writes string content to a file, replacing existing content.
     * @param path The file path to write to.
     * @param content The string contents to write.
     * @return asio::awaitable yielding std::expected<void, std::error_code>.
     */
    wavex::task<std::expected<void, std::error_code> > write_file(std::string path, std::string content);

    template<typename PathLike>
        requires (!std::is_convertible_v<PathLike, std::string>)
    wavex::task<std::expected<void, std::error_code> > write_file(
        const PathLike &path, std::string content) {
        return write_file(detail::to_string_path(path), std::move(content));
    }

    /**
     * @brief Asynchronously appends string content to a file.
     * @param path The file path to append to.
     * @param content The string contents to append.
     * @return asio::awaitable yielding std::expected<void, std::error_code>.
     */
    wavex::task<std::expected<void, std::error_code> > append_file(std::string path, std::string content);

    template<typename PathLike>
        requires (!std::is_convertible_v<PathLike, std::string>)
    wavex::task<std::expected<void, std::error_code> > append_file(
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
    wavex::task<std::expected<void, std::error_code> > copy_file(
        std::string from, std::string to, bool overwrite = true);

    template<typename PathLike1, typename PathLike2>
        requires (!std::is_convertible_v<PathLike1, std::string> || !std::is_convertible_v<PathLike2, std::string>)
    wavex::task<std::expected<void, std::error_code> > copy_file(
        const PathLike1 &from, const PathLike2 &to, const bool overwrite = true) {
        return copy_file(detail::to_string_path(from), detail::to_string_path(to), overwrite);
    }

    /**
     * @brief Asynchronously removes a file or directory.
     * @param path Path to remove.
     * @return asio::awaitable yielding std::expected<bool, std::error_code> (true if file existed and was removed).
     */
    wavex::task<std::expected<bool, std::error_code> > remove(std::string path);

    template<typename PathLike>
        requires (!std::is_convertible_v<PathLike, std::string>)
    wavex::task<std::expected<bool, std::error_code> > remove(
        const PathLike &path) {
        return remove(detail::to_string_path(path));
    }
} // namespace wavex::fs
