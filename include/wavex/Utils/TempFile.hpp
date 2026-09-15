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

#include <filesystem>
#include <string>
#include <fstream>
#include <random>
#include <chrono>
#include <system_error>

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
    public:
        TempFileGuard() = default;

        explicit TempFileGuard(std::filesystem::path path)
            : path_(std::move(path)) {
        }

        ~TempFileGuard() {
            purge();
        }

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

        [[nodiscard]] const std::filesystem::path &path() const noexcept { return path_; }
        [[nodiscard]] bool empty() const noexcept { return path_.empty(); }
        explicit operator bool() const noexcept { return !path_.empty(); }

        /// Returns file size in bytes, or 0 if empty/non-existent
        [[nodiscard]] std::uintmax_t size() const noexcept {
            if (path_.empty()) return 0;
            std::error_code ec;
            const auto sz = std::filesystem::file_size(path_, ec);
            return ec ? 0 : sz;
        }

        /// Moves the temporary file to destination and commits (will not be purged on destruct)
        bool move_to(const std::filesystem::path &destination, const bool overwrite = true) {
            if (path_.empty()) return false;
            std::error_code ec;

            // Ensure parent directory exists
            if (destination.has_parent_path()) {
                std::filesystem::create_directories(destination.parent_path(), ec);
                if (ec) return false;
            }

            if (overwrite && std::filesystem::exists(destination, ec)) {
                std::filesystem::remove(destination, ec);
            }

            std::filesystem::rename(path_, destination, ec);
            if (ec) {
                // Rename across filesystem boundaries may fail; fallback to copy + remove
                ec.clear();
                std::filesystem::copy_file(path_, destination,
                    overwrite ? std::filesystem::copy_options::overwrite_existing
                              : std::filesystem::copy_options::none, ec);
                if (ec) return false;
                std::filesystem::remove(path_, ec);
            }

            committed_ = true;
            return true;
        }

        /// Disarms the guard so the temporary file is NOT deleted on destruction
        void commit() noexcept { committed_ = true; }

        /// Releases ownership of the path without deleting, disarming the guard
        std::filesystem::path release() noexcept {
            committed_ = true;
            return std::move(path_);
        }

        /**
         * @brief Creates a new unique temporary file.
         * @param dir Target directory. If empty, uses std::filesystem::temp_directory_path().
         * @param prefix Filename prefix (defaults to "wx_upload_").
         * @return TempFileGuard managing the newly created empty file.
         */
        static TempFileGuard create(const std::filesystem::path &dir = "", const std::string &prefix = "wx_upload_") {
            std::error_code ec;
            std::filesystem::path target_dir = dir.empty() ? std::filesystem::temp_directory_path(ec) : dir;
            if (ec) {
                target_dir = std::filesystem::current_path();
            }

            std::filesystem::create_directories(target_dir, ec);

            // Generate unique name
            static std::mt19937_64 rng(static_cast<unsigned long long>(
                std::chrono::high_resolution_clock::now().time_since_epoch().count()));
            std::uniform_int_distribution<uint64_t> dist;

            std::filesystem::path temp_path;
            for (int attempt = 0; attempt < 50; ++attempt) {
                auto candidate = target_dir / (prefix + std::to_string(dist(rng)) + ".tmp");
                if (!std::filesystem::exists(candidate, ec)) {
                    // Create empty file
                    std::ofstream ofs(candidate, std::ios::binary);
                    if (ofs.is_open()) {
                        temp_path = std::move(candidate);
                        break;
                    }
                }
            }

            return TempFileGuard(std::move(temp_path));
        }

        /**
         * @brief Convenience helper to create a temporary file with a custom prefix.
         * @param prefix Filename prefix.
         * @param dir Target directory (empty for system temp).
         */
        static TempFileGuard create_with_prefix(const std::string &prefix, const std::filesystem::path &dir = "") {
            return create(dir, prefix);
        }

    private:
        void purge() noexcept {
            if (!committed_ && !path_.empty()) {
                std::error_code ec;
                std::filesystem::remove(path_, ec);
            }
        }

        std::filesystem::path path_;
        bool committed_{false};
    };

} // namespace wavex::utils
