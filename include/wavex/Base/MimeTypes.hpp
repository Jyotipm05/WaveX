// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file MimeTypes.hpp
 * @brief Dedicated MIME type resolution system for WaveX.
 *
 * Provides fast extension-to-MIME lookup (mime_type_from_ext, mime_type_from_path)
 * under the wavex::base namespace.
 */

#pragma once

#include <string_view>
#include <array>
#include <algorithm>
#include <cctype>

namespace wavex::base {
    struct MimePair {
        std::string_view ext;
        std::string_view mime;
    };

    // Strictly sorted alphabetically by extension for std::lower_bound.
    inline constexpr std::array<MimePair, 32> mime_map = {
        {
            {"avif", "image/avif"},
            {"cs", "text/plain; charset=utf-8"},
            {"css", "text/css; charset=utf-8"},
            {"gif", "image/gif"},
            {"glb", "model/gltf-binary"},
            {"gltf", "model/gltf+json"},
            {"gz", "application/gzip"},
            {"gzip", "application/gzip"},
            {"htm", "text/html; charset=utf-8"},
            {"html", "text/html; charset=utf-8"},
            {"jpeg", "image/jpeg"},
            {"jpg", "image/jpeg"},
            {"js", "text/javascript; charset=utf-8"},
            {"json", "application/json"},
            {"mjs", "text/javascript; charset=utf-8"},
            {"mp3", "audio/mpeg"},
            {"mp4", "video/mp4"},
            {"obj", "model/obj"},
            {"otf", "font/otf"},
            {"pdf", "application/pdf"},
            {"png", "image/png"},
            {"rs", "text/rust; charset=utf-8"},
            {"svg", "image/svg+xml"},
            {"ttf", "font/ttf"},
            {"txt", "text/plain; charset=utf-8"},
            {"wasm", "application/wasm"},
            {"webm", "video/webm"},
            {"webp", "image/webp"},
            {"woff", "font/woff"},
            {"woff2", "font/woff2"},
            {"xml", "application/xml"},
            {"zip", "application/zip"}
        }
    };

    /**
     * @brief Resolves a file extension to its standard MIME Content-Type string.
     * @param ext File extension (with or without leading dot, e.g., "html" or ".html").
     * @return Standard MIME Content-Type string view, defaulting to "application/octet-stream".
     */
    [[nodiscard]] inline std::string_view mime_type_from_ext(std::string_view ext) {
        if (!ext.empty() && ext.front() == '.') {
            ext.remove_prefix(1);
        }

        // Convert extension to lowercase for case-insensitive lookup
        char clean_ext[16];
        const std::size_t len = std::min(ext.size(), sizeof(clean_ext));
        for (std::size_t i = 0; i < len; ++i) {
            clean_ext[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(ext[i])));
        }
        const std::string_view e(clean_ext, len);

        // O(log N) binary search
        const auto it = std::lower_bound(mime_map.begin(), mime_map.end(), e,
                                         [](const MimePair &pair, const std::string_view target) {
                                             return pair.ext < target;
                                         });

        if (it != mime_map.end() && it->ext == e) {
            return it->mime;
        }

        return "application/octet-stream";
    }

    /**
     * @brief Resolves a file path to its standard MIME Content-Type string.
     * @param path Full or relative file path (e.g. "public/index.html").
     * @return Standard MIME Content-Type string view, defaulting to "application/octet-stream".
     */
    [[nodiscard]] inline std::string_view mime_type_from_path(const std::string_view path) {
        const std::size_t dot_pos = path.rfind('.');
        if (dot_pos == std::string_view::npos) {
            return "application/octet-stream";
        }
        // Ensure dot is part of the filename segment (after last slash)
        if (const std::size_t slash_pos = path.find_last_of("/\\");
            slash_pos != std::string_view::npos && dot_pos < slash_pos) {
            return "application/octet-stream";
        }
        return mime_type_from_ext(path.substr(dot_pos));
    }
} // namespace wavex::base
