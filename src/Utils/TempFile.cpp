// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file TempFile.cpp
 * @brief Implementation of TempFileGuard methods.
 */

#include <wavex/Utils/TempFile.hpp>
#include <wavex/Utils/FsUtils.hpp>
#include <wavex/Utils/BinaryFile.hpp>
#include <random>
#include <chrono>
#include <string>
#include <system_error>
#include <utility>

namespace wavex::utils {
    TempFileGuard::~TempFileGuard() {
        purge();
    }

    std::uintmax_t TempFileGuard::size() const noexcept {
        if (path_.empty()) return 0;
        std::error_code ec;
        const auto sz = fs_utils::file_size(path_, ec);
        return ec ? 0 : sz;
    }

    bool TempFileGuard::move_to(const std::string &destination, const bool overwrite) {
        if (path_.empty()) return false;
        std::error_code ec;

        // Ensure parent directory exists
        if (fs_utils::has_parent_path(destination)) {
            fs_utils::create_directories(fs_utils::parent_path(destination), ec);
            if (ec) return false;
        }

        if (overwrite && fs_utils::exists(destination, ec)) {
            fs_utils::remove(destination, ec);
        }

        fs_utils::rename(path_, destination, ec);
        if (ec) {
            // Rename across filesystem boundaries may fail; fallback to copy + remove
            ec.clear();
            fs_utils::copy_file(path_, destination, overwrite, ec);
            if (ec) return false;
            fs_utils::remove(path_, ec);
        }

        committed_ = true;
        return true;
    }

    std::string TempFileGuard::release() noexcept {
        committed_ = true;
        return std::move(path_);
    }

    TempFileGuard TempFileGuard::create(const std::string &dir, const std::string &prefix) {
        std::error_code ec;
        std::string target_dir = dir.empty() ? fs_utils::temp_directory_path(ec) : dir;
        if (ec || target_dir.empty()) {
            ec.clear();
            target_dir = fs_utils::current_path(ec);
        }

        fs_utils::create_directories(target_dir, ec);

        // Generate unique name
        static std::mt19937_64 rng(static_cast<unsigned long long>(
            std::chrono::high_resolution_clock::now().time_since_epoch().count()));
        std::uniform_int_distribution<uint64_t> dist;

        std::string temp_path;
        for (int attempt = 0; attempt < 50; ++attempt) {
            std::string sep = (!target_dir.empty() && target_dir.back() != '/' && target_dir.back() != '\\') ? "/" : "";
            auto candidate = target_dir + sep + prefix + std::to_string(dist(rng)) + ".tmp";
            if (!fs_utils::exists(candidate, ec)) {
                // Create empty file
                BinaryFile ofs(candidate, FileMode::Write);
                if (ofs.is_open()) {
                    temp_path = std::move(candidate);
                    break;
                }
            }
        }

        return TempFileGuard(std::move(temp_path));
    }

    TempFileGuard TempFileGuard::create_with_prefix(const std::string &prefix, const std::string &dir) {
        return create(dir, prefix);
    }

    void TempFileGuard::purge() const noexcept {
        if (!committed_ && !path_.empty()) {
            std::error_code ec;
            fs_utils::remove(path_, ec);
        }
    }
} // namespace wavex::utils
