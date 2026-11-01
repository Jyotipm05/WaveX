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
#include <wavex/Base/Task.hpp>

#if defined(ASIO_HAS_FILE)
#include <asio/buffer.hpp>
#include <asio/read.hpp>
#include <asio/stream_file.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/as_tuple.hpp>
#endif

#include <atomic>
#include <cerrno>
#include <optional>
#include <tuple>
#include <string>
#include <vector>
#include <expected>
#include <system_error>
#include <utility>

namespace wavex::fs {
    namespace {
        std::atomic<io_mode> g_mode{io_mode::blocking_pool};
        std::atomic<bool> g_native_broken{false}; // set when the kernel refuses native file I/O (e.g. io_uring blocked)

        constexpr bool kNativeCompiled =
#if defined(ASIO_HAS_FILE)
            true;
#else
            false;
#endif

        std::error_code errno_code(const std::errc fallback) noexcept {
            const int e = errno;
            return e != 0 ? std::error_code(e, std::generic_category()) : std::make_error_code(fallback);
        }

        // ── Blocking-pool implementations (run inside spawn_blocking) ─────────────────────────────────────────────

        /// Read a whole file into `Out` (std::string or std::vector<char>) with one allocation and no copy.
        template<typename Out>
        std::expected<Out, std::error_code> read_whole(const std::string &path) {
            utils::BinaryFile file(path, utils::FileMode::Read);
            if (!file.is_open()) {
                return std::unexpected(errno_code(std::errc::no_such_file_or_directory)); // real reason, e.g. EACCES
            }
            const auto size = file.file_size();
            Out data;
            data.resize(size);
            if (size > 0) {
                const auto got = file.read(data.data(), size);
                if (got != size) data.resize(got); // file shrank while reading
            }
            return data;
        }

        std::expected<void, std::error_code> write_whole(const std::string &path, const std::string &data,
                                                         const bool append) {
            // BinaryFile::write_all creates missing parent directories and now also reports flush failures.
            if (!utils::BinaryFile::write_all(path, data, append)) {
                return std::unexpected(errno_code(std::errc::io_error));
            }
            return {};
        }

        // ── Native implementation (Asio file I/O) ─────────────────────────────────────────────────────────────────

        bool native_enabled() noexcept {
            return kNativeCompiled && g_mode.load(std::memory_order_relaxed) == io_mode::native &&
                   !g_native_broken.load(std::memory_order_relaxed);
        }

#if defined(ASIO_HAS_FILE)
        /// Asio reports OS errors in its own "asio.system" category, which does not compare equal to std::errc.
        /// std::system_category() holds the same value (errno / Win32 code) and maps to std::errc on both platforms.
        std::error_code to_std(const std::error_code &ec) noexcept {
            return ec.category() == asio::system_category()
                       ? std::error_code(ec.value(), std::system_category())
                       : ec;
        }

        /**
         * Try to read `path` natively. Result:
         *  - a value or error  -> final answer (including "no such file", "permission denied");
         *  - std::nullopt      -> not handled here (file too large for the native path, or the kernel refuses native
         *                         file I/O); the caller falls back to the blocking pool.
         */
        template<typename Out>
        wavex::task<std::optional<std::expected<Out, std::error_code> > > native_try_read(const std::string &path) {
            try {
                auto ex = co_await asio::this_coro::executor;
                asio::stream_file file(ex);
                std::error_code ec;
                std::ignore = file.open(path, asio::stream_file::read_only, ec);
                if (ec) co_return std::optional<std::expected<Out, std::error_code> >(std::unexpected(to_std(ec)));

                const auto size = file.size(ec);
                if (ec || size > native_read_max_bytes) co_return std::nullopt; // let the pool handle it

                Out data;
                data.resize(static_cast<std::size_t>(size));
                if (size > 0) {
                    auto [read_ec, got] = co_await asio::async_read(
                        file, asio::buffer(data.data(), data.size()), asio::as_tuple(asio::use_awaitable));
                    if (read_ec && read_ec != asio::error::eof) {
                        co_return std::optional<std::expected<Out, std::error_code> >(std::unexpected(to_std(read_ec)));
                    }
                    data.resize(got);
                }
                co_return std::optional<std::expected<Out, std::error_code> >(std::move(data));
            } catch (const std::system_error &) {
                // Creating the file service failed (e.g. io_uring_setup() blocked by seccomp): stop trying.
                g_native_broken.store(true, std::memory_order_relaxed);
                co_return std::nullopt;
            }
        }
#endif

        template<typename Out>
        wavex::task<std::expected<Out, std::error_code> > read_any(std::string path) {
#if defined(ASIO_HAS_FILE)
            if (native_enabled()) {
                if (auto native = co_await native_try_read<Out>(path)) co_return std::move(*native);
            }
#endif
            auto res = co_await spawn_blocking(
                [p = std::move(path)]() -> std::expected<Out, std::error_code> { return read_whole<Out>(p); });
            co_return res;
        }
    } // namespace

    bool native_io_available() noexcept {
        return kNativeCompiled && !g_native_broken.load(std::memory_order_relaxed);
    }

    io_mode set_io_mode(const io_mode mode) noexcept {
        const io_mode effective = (mode == io_mode::native && !native_io_available()) ? io_mode::blocking_pool : mode;
        g_mode.store(effective, std::memory_order_relaxed);
        return effective;
    }

    io_mode get_io_mode() noexcept {
        return native_enabled() ? io_mode::native : io_mode::blocking_pool;
    }

    wavex::task<std::expected<std::string, std::error_code> > read_file(std::string path) {
        co_return co_await read_any<std::string>(std::move(path));
    }

    wavex::task<std::expected<std::vector<char>, std::error_code> > read_bytes(std::string path) {
        co_return co_await read_any<std::vector<char> >(std::move(path));
    }

    wavex::task<std::expected<void, std::error_code> > write_file(std::string path, std::string content) {
        auto res = co_await spawn_blocking(
            [p = std::move(path), data = std::move(content)]() -> std::expected<void, std::error_code> {
                return write_whole(p, data, false);
            });
        co_return res;
    }

    wavex::task<std::expected<void, std::error_code> > append_file(std::string path, std::string content) {
        auto res = co_await spawn_blocking(
            [p = std::move(path), data = std::move(content)]() -> std::expected<void, std::error_code> {
                return write_whole(p, data, true);
            });
        co_return res;
    }

    wavex::task<std::expected<void, std::error_code> > copy_file(std::string from, std::string to, bool overwrite) {
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

    wavex::task<std::expected<bool, std::error_code> > remove(std::string path) {
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
