// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once

#include <string>
#include <string_view>
#include <system_error>
#include <cstdint>
#include <filesystem>
#include <type_traits>

namespace wavex::utils::fs_utils {

    /// Converts a UTF-8 encoded string view into a std::filesystem::path without ANSI code page loss
    std::filesystem::path to_path(std::string_view u8_path) noexcept;

    /// Converts a std::filesystem::path into a UTF-8 encoded std::string without ANSI code page loss
    std::string to_u8_string(const std::filesystem::path &p) noexcept;

    /// Generic helper to convert any PathLike (std::filesystem::path, std::string, string_view, const char*) into UTF-8 std::string
    template<typename PathLike>
    std::string to_u8_path_string(const PathLike &p) {
        if constexpr (std::is_same_v<std::decay_t<PathLike>, std::filesystem::path>) {
            return to_u8_string(p);
        } else if constexpr (requires { p.u8string(); }) {
            auto u8 = p.u8string();
            return std::string(reinterpret_cast<const char*>(u8.data()), u8.size());
        } else if constexpr (requires { p.native(); }) {
            return to_u8_string(std::filesystem::path(p));
        } else if constexpr (requires { p.string(); }) {
            return to_u8_string(std::filesystem::path(p));
        } else {
            return std::string(p);
        }
    }

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
