// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file TempFile.hpp
 * @brief RAII temporary file management with automatic cleanup on disconnection/destruction.
 */

#pragma once

#include <string>
#include <cstdint>
#include <utility>
#include <type_traits>

namespace wavex::utils {
    /**
     * @class TempFileGuard
     * @brief RAII guard for temporary disk files.
     *
     * Invariant: The temporary file on disk is deleted automatically upon destruction
     * UNLESS commit() or move_to() is called. This guarantees zero orphaned temporary
     * files if a connection disconnects or an error occurs during upload.
     */
    class TempFileGuard {
    private:
        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        std::string path_{};
        bool committed_{false};

    public:
        // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
        TempFileGuard() = default;

        explicit TempFileGuard(std::string path)
            : path_(std::move(path)) {
        }

        ~TempFileGuard();

        TempFileGuard(TempFileGuard &&other) noexcept
            : path_(std::move(other.path_)), committed_(other.committed_) {
            other.committed_ = true; // Prevent moved-from object from deleting the file
        }

        TempFileGuard &operator=(TempFileGuard &&other) noexcept {
            if (this != &other) {
                purge();
                path_ = std::move(other.path_);
                committed_ = other.committed_;
                other.committed_ = true;
            }
            return *this;
        }

        TempFileGuard(const TempFileGuard &) = delete;

        TempFileGuard &operator=(const TempFileGuard &) = delete;

        // ─── 4. Member Functions & Friend Declarations (LAST) ──────────────
        [[nodiscard]] const std::string &path() const noexcept { return path_; }
        [[nodiscard]] bool empty() const noexcept { return path_.empty(); }
        explicit operator bool() const noexcept { return !path_.empty(); }

        /// Returns file size in bytes, or 0 if empty/non-existent
        [[nodiscard]] std::uintmax_t size() const noexcept;

        /// Moves the temporary file to destination and commits (will not be purged on destruct)
        bool move_to(const std::string &destination, bool overwrite = true);

        template<typename PathLike>
            requires (!std::is_convertible_v<PathLike, const std::string &>)
        bool move_to(const PathLike &destination, bool overwrite = true) {
            if constexpr (requires { destination.string(); }) {
                return move_to(destination.string(), overwrite);
            } else {
                return move_to(std::string(destination), overwrite);
            }
        }

        /// Disarms the guard so the temporary file is NOT deleted on destruction
        void commit() noexcept { committed_ = true; }

        /// Releases ownership of the path without deleting, disarming the guard
        std::string release() noexcept;

        /**
         * @brief Creates a new unique temporary file.
         * @param dir Target directory. If empty, uses system temp directory.
         * @param prefix Filename prefix (defaults to "wx_upload_").
         * @return TempFileGuard managing the newly created empty file.
         */
        static TempFileGuard create(const std::string &dir = "", const std::string &prefix = "wx_upload_");

        template<typename DirPath>
            requires (!std::is_convertible_v<DirPath, const std::string &>)
        static TempFileGuard create(const DirPath &dir, const std::string &prefix = "wx_upload_") {
            if constexpr (requires { dir.string(); }) {
                return create(dir.string(), prefix);
            } else {
                return create(std::string(dir), prefix);
            }
        }

        /**
         * @brief Convenience helper to create a temporary file with a custom prefix.
         * @param prefix Filename prefix.
         * @param dir Target directory (empty for system temp).
         */
        static TempFileGuard create_with_prefix(const std::string &prefix, const std::string &dir = "");

        template<typename DirPath>
            requires (!std::is_convertible_v<DirPath, const std::string &>)
        static TempFileGuard create_with_prefix(const std::string &prefix, const DirPath &dir) {
            if constexpr (requires { dir.string(); }) {
                return create_with_prefix(prefix, dir.string());
            } else {
                return create_with_prefix(prefix, std::string(dir));
            }
        }

    private:
        void purge() const noexcept;
    };
} // namespace wavex::utils
