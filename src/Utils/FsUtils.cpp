// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include <wavex/Utils/FsUtils.hpp>
#include <filesystem>

namespace wavex::utils::fs_utils {
    std::uintmax_t file_size(const std::string &path, std::error_code &ec) noexcept {
        return std::filesystem::file_size(std::filesystem::path(path), ec);
    }

    bool create_directories(const std::string &path, std::error_code &ec) noexcept {
        return std::filesystem::create_directories(std::filesystem::path(path), ec);
    }

    bool exists(const std::string &path, std::error_code &ec) noexcept {
        return std::filesystem::exists(std::filesystem::path(path), ec);
    }

    bool remove(const std::string &path, std::error_code &ec) noexcept {
        return std::filesystem::remove(std::filesystem::path(path), ec);
    }

    void rename(const std::string &old_p, const std::string &new_p, std::error_code &ec) noexcept {
        std::filesystem::rename(std::filesystem::path(old_p), std::filesystem::path(new_p), ec);
    }

    void copy_file(const std::string &from, const std::string &to, bool overwrite, std::error_code &ec) noexcept {
        std::filesystem::copy_file(
            std::filesystem::path(from),
            std::filesystem::path(to),
            overwrite ? std::filesystem::copy_options::overwrite_existing : std::filesystem::copy_options::none,
            ec
        );
    }

    std::string temp_directory_path(std::error_code &ec) noexcept {
        auto p = std::filesystem::temp_directory_path(ec);
        return ec ? "" : p.string();
    }

    std::string current_path(std::error_code &ec) noexcept {
        auto p = std::filesystem::current_path(ec);
        return ec ? "" : p.string();
    }

    std::string parent_path(const std::string &path) noexcept {
        return std::filesystem::path(path).parent_path().string();
    }

    std::string filename(const std::string &path) noexcept {
        return std::filesystem::path(path).filename().string();
    }

    bool has_parent_path(const std::string &path) noexcept {
        return std::filesystem::path(path).has_parent_path();
    }
} // namespace wavex::utils::fs_utils
