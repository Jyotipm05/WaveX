// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file BinaryFile.cpp
 * @brief Implementation of the BinaryFile RAII wrapper.
 */

#include <wavex/Utils/BinaryFile.hpp>
#include <wavex/Utils/FsUtils.hpp>
#include <cstddef>
#include <cstdio>
#include <string>
#include <string_view>
#include <system_error>
#include <expected>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace wavex::utils {
    BinaryFile::BinaryFile(const std::string_view path, const FileMode mode) noexcept {
        open(path, mode);
    }

    BinaryFile::~BinaryFile() noexcept {
        close();
    }

    bool BinaryFile::open(const std::string_view path, const FileMode mode) noexcept {
        close();
        if (path.empty()) return false;

#if defined(_WIN32)
        auto wmode = L"rb";
        switch (mode) {
            case FileMode::Read: wmode = L"rb";
                break;
            case FileMode::Write: wmode = L"wb";
                break;
            case FileMode::Append: wmode = L"ab";
                break;
            case FileMode::ReadWrite: wmode = L"r+b";
                break;
        }
        if (const int wLen = MultiByteToWideChar(CP_UTF8, 0, path.data(), static_cast<int>(path.size()), nullptr, 0); wLen > 0) {
            std::wstring wpath(static_cast<std::size_t>(wLen), L'\0');
            MultiByteToWideChar(CP_UTF8, 0, path.data(), static_cast<int>(path.size()), wpath.data(), wLen);
            handle_ = _wfopen(wpath.c_str(), wmode);
            if (handle_) return true;
        }
        const std::string cpath(path);
        auto cMode = "rb";
        switch (mode) {
            case FileMode::Read: cMode = "rb";
                break;
            case FileMode::Write: cMode = "wb";
                break;
            case FileMode::Append: cMode = "ab";
                break;
            case FileMode::ReadWrite: cMode = "r+b";
                break;
        }
        handle_ = std::fopen(cpath.c_str(), cMode);
#else
        const char *cMode = "rb";
        switch (mode) {
            case FileMode::Read: cMode = "rb";
                break;
            case FileMode::Write: cMode = "wb";
                break;
            case FileMode::Append: cMode = "ab";
                break;
            case FileMode::ReadWrite: cMode = "r+b";
                break;
        }
        std::string cpath(path);
        handle_ = std::fopen(cpath.c_str(), cMode);
#endif
        return is_open();
    }

    void BinaryFile::close() noexcept {
        if (handle_) {
            std::fclose(handle_);
            handle_ = nullptr;
            last_read_ = 0;
        }
    }

    std::size_t BinaryFile::read(char *dest, const std::size_t count) noexcept {
        if (!handle_ || !dest || count == 0) {
            last_read_ = 0;
            return 0;
        }
        last_read_ = std::fread(dest, 1, count, handle_);
        return last_read_;
    }

    bool BinaryFile::write(const char *src, const std::size_t count) const noexcept {
        if (!handle_) return false;
        if (count == 0) return true;
        if (!src) return false;
        return std::fwrite(src, 1, count, handle_) == count;
    }

    bool BinaryFile::write(const std::string_view data) const noexcept {
        return write(data.data(), data.size());
    }

    bool BinaryFile::flush() const noexcept {
        return handle_ ? (std::fflush(handle_) == 0) : false;
    }

    std::size_t BinaryFile::file_size() const noexcept {
        if (!handle_) return 0;
        const auto cur = std::ftell(handle_);
        if (cur < 0) return 0;
        if (std::fseek(handle_, 0, SEEK_END) != 0) return 0;
        const auto end = std::ftell(handle_);
        std::fseek(handle_, cur, SEEK_SET);
        return end > 0 ? static_cast<std::size_t>(end) : 0;
    }

    std::expected<std::string, std::error_code> BinaryFile::read_all(const std::string_view path) {
        BinaryFile file(path, FileMode::Read);
        if (!file.is_open()) {
            return std::unexpected(std::make_error_code(std::errc::no_such_file_or_directory));
        }
        const auto sz = file.file_size();
        std::string content;
        content.resize(sz);
        if (sz > 0) {
            const auto read_bytes = file.read(content.data(), sz);
            if (read_bytes != sz) {
                content.resize(read_bytes);
            }
        }
        return content;
    }

    bool BinaryFile::write_all(const std::string_view path, const std::string_view content, const bool append) {
        BinaryFile file(path, append ? FileMode::Append : FileMode::Write);
        if (!file.is_open()) {
            const auto last_slash = path.find_last_of("/\\");
            if (last_slash != std::string_view::npos && last_slash > 0) {
                std::error_code ec;
                fs_utils::create_directories(std::string(path.substr(0, last_slash)), ec);
                if (!file.open(path, append ? FileMode::Append : FileMode::Write)) {
                    return false;
                }
            } else {
                return false;
            }
        }
        return file.write(content);
    }
} // namespace wavex::utils
