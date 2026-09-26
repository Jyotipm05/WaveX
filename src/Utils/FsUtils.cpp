// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include <wavex/Utils/FsUtils.hpp>
#include <filesystem>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace wavex::utils::fs_utils {
    std::filesystem::path to_path(const std::string_view u8_path) noexcept {
        if (u8_path.empty()) return {};
#if defined(_WIN32)
        try {
            const int wlen = ::MultiByteToWideChar(CP_UTF8, 0, u8_path.data(), static_cast<int>(u8_path.size()), nullptr, 0);
            if (wlen > 0) {
                std::wstring wpath(static_cast<std::size_t>(wlen), L'\0');
                ::MultiByteToWideChar(CP_UTF8, 0, u8_path.data(), static_cast<int>(u8_path.size()), wpath.data(), wlen);
                return std::filesystem::path(wpath);
            }
            return std::filesystem::path(
                reinterpret_cast<const char8_t*>(u8_path.data()),
                reinterpret_cast<const char8_t*>(u8_path.data() + u8_path.size())
            );
        } catch (...) {
            return {};
        }
#else
        try {
            return std::filesystem::path(u8_path);
        } catch (...) {
            return {};
        }
#endif
    }

    std::string to_u8_string(const std::filesystem::path &p) noexcept {
#if defined(_WIN32)
        try {
            const std::wstring &wpath = p.native();
            if (wpath.empty()) return {};
            const int u8len = ::WideCharToMultiByte(CP_UTF8, 0, wpath.data(), static_cast<int>(wpath.size()), nullptr, 0, nullptr, nullptr);
            if (u8len > 0) {
                std::string u8path(static_cast<std::size_t>(u8len), '\0');
                ::WideCharToMultiByte(CP_UTF8, 0, wpath.data(), static_cast<int>(wpath.size()), u8path.data(), u8len, nullptr, nullptr);
                return u8path;
            }
            auto u8 = p.u8string();
            return std::string(reinterpret_cast<const char*>(u8.data()), u8.size());
        } catch (...) {
            return {};
        }
#else
        try {
            return p.string();
        } catch (...) {
            return {};
        }
#endif
    }

    std::uintmax_t file_size(const std::string &path, std::error_code &ec) noexcept {
        return std::filesystem::file_size(to_path(path), ec);
    }

    bool create_directories(const std::string &path, std::error_code &ec) noexcept {
        return std::filesystem::create_directories(to_path(path), ec);
    }

    bool exists(const std::string &path, std::error_code &ec) noexcept {
        return std::filesystem::exists(to_path(path), ec);
    }

    bool remove(const std::string &path, std::error_code &ec) noexcept {
        return std::filesystem::remove(to_path(path), ec);
    }

    void rename(const std::string &old_p, const std::string &new_p, std::error_code &ec) noexcept {
        std::filesystem::rename(to_path(old_p), to_path(new_p), ec);
    }

    void copy_file(const std::string &from, const std::string &to, const bool overwrite, std::error_code &ec) noexcept {
        std::filesystem::copy_file(
            to_path(from),
            to_path(to),
            overwrite ? std::filesystem::copy_options::overwrite_existing : std::filesystem::copy_options::none,
            ec
        );
    }

    std::string temp_directory_path(std::error_code &ec) noexcept {
        auto p = std::filesystem::temp_directory_path(ec);
        return ec ? "" : to_u8_string(p);
    }

    std::string current_path(std::error_code &ec) noexcept {
        auto p = std::filesystem::current_path(ec);
        return ec ? "" : to_u8_string(p);
    }

    std::string parent_path(const std::string &path) noexcept {
        return to_u8_string(to_path(path).parent_path());
    }

    std::string filename(const std::string &path) noexcept {
        return to_u8_string(to_path(path).filename());
    }

    bool has_parent_path(const std::string &path) noexcept {
        return to_path(path).has_parent_path();
    }
} // namespace wavex::utils::fs_utils
