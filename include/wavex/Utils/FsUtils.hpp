// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once

#include <string>
#include <system_error>
#include <cstdint>

namespace wavex::utils::fs_utils {

    std::uintmax_t file_size(const std::string& path, std::error_code& ec) noexcept;
    bool create_directories(const std::string& path, std::error_code& ec) noexcept;
    bool exists(const std::string& path, std::error_code& ec) noexcept;
    bool remove(const std::string& path, std::error_code& ec) noexcept;
    void rename(const std::string& old_p, const std::string& new_p, std::error_code& ec) noexcept;
    void copy_file(const std::string& from, const std::string& to, bool overwrite, std::error_code& ec) noexcept;
    std::string temp_directory_path(std::error_code& ec) noexcept;
    std::string current_path(std::error_code& ec) noexcept;
    
    std::string parent_path(const std::string& path) noexcept;
    std::string filename(const std::string& path) noexcept;
    bool has_parent_path(const std::string& path) noexcept;

} // namespace wavex::utils::fs_utils
