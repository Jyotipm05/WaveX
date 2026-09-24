// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file BinaryFile.hpp
 * @brief High-performance, zero-vtable RAII wrapper for native binary file I/O.
 */

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>
#include <expected>
#include <utility>
#include <type_traits>

namespace wavex::utils {
    /**
     * @enum FileMode
     * @brief File open mode for BinaryFile.
     */
    enum class FileMode : uint8_t {
        Read,
        Write,
        Append,
        ReadWrite
    };

    /**
     * @class BinaryFile
     * @brief Lightweight, zero-vtable RAII wrapper around C standard binary file I/O.
     *
     * Provides an 8-to-16 byte footprint (zero padding) suitable for capturing in
     * coroutine frames without virtual method/base table overhead or C++20 module
     * stream serialization issues.
     */
    class BinaryFile {
    public:
        // ─── 1. Nested Types & Definitions (TOP) ───────────────────────────
        using Mode = FileMode;

    private:
        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        std::FILE *handle_{nullptr}; // 8 bytes (align 8)
        std::size_t last_read_{0}; // 8 bytes (align 8)
        // Total: 16 bytes (0 bytes padding)

    public:
        // ─── 3. Constructors, Destructor & Special Member Functions (MIDDLE) ─
        BinaryFile() noexcept = default;

        explicit BinaryFile(std::string_view path, FileMode mode = FileMode::Read) noexcept;

        template<typename PathLike>
            requires (!std::is_convertible_v<PathLike, std::string_view>)
        explicit BinaryFile(const PathLike &path, FileMode mode = FileMode::Read) noexcept {
            open(path, mode);
        }

        ~BinaryFile() noexcept;

        BinaryFile(const BinaryFile &) = delete;

        BinaryFile &operator=(const BinaryFile &) = delete;

        BinaryFile(BinaryFile &&other) noexcept
            : handle_(std::exchange(other.handle_, nullptr)),
              last_read_(std::exchange(other.last_read_, 0)) {
        }

        BinaryFile &operator=(BinaryFile &&other) noexcept {
            if (this != &other) {
                close();
                handle_ = std::exchange(other.handle_, nullptr);
                last_read_ = std::exchange(other.last_read_, 0);
            }
            return *this;
        }

        // ─── 4. Member Functions & Friend Declarations (LAST) ──────────────
        [[nodiscard]] bool is_open() const noexcept {
            return handle_ != nullptr;
        }

        explicit operator bool() const noexcept {
            return is_open();
        }

        [[nodiscard]] std::size_t gCount() const noexcept {
            return last_read_;
        }

        bool open(std::string_view path, FileMode mode = FileMode::Read) noexcept;

        template<typename PathLike>
            requires (!std::is_convertible_v<PathLike, std::string_view>)
        bool open(const PathLike &path, const FileMode mode = FileMode::Read) noexcept {
            if constexpr (requires { path.string(); }) {
                std::string s = path.string();
                return open(std::string_view(s), mode);
            } else {
                std::string s(path);
                return open(std::string_view(s), mode);
            }
        }

        void close() noexcept;

        std::size_t read(char *dest, std::size_t count) noexcept;

        bool write(const char *src, std::size_t count) const noexcept;

        bool write(std::string_view data) const noexcept;

        bool flush() const noexcept;

        [[nodiscard]] std::size_t file_size() const noexcept;

        // Static convenience utilities:
        static std::expected<std::string, std::error_code> read_all(std::string_view path);

        template<typename PathLike>
            requires (!std::is_convertible_v<PathLike, std::string_view>)
        static std::expected<std::string, std::error_code> read_all(const PathLike &path) {
            if constexpr (requires { path.string(); }) {
                const std::string s = path.string();
                return read_all(std::string_view(s));
            } else {
                const std::string s(path);
                return read_all(std::string_view(s));
            }
        }

        static bool write_all(std::string_view path, std::string_view content, bool append = false);

        template<typename PathLike>
            requires (!std::is_convertible_v<PathLike, std::string_view>)
        static bool write_all(const PathLike &path, const std::string_view content, const bool append = false) {
            if constexpr (requires { path.string(); }) {
                const std::string s = path.string();
                return write_all(std::string_view(s), content, append);
            } else {
                const std::string s(path);
                return write_all(std::string_view(s), content, append);
            }
        }
    };
} // namespace wavex::utils
