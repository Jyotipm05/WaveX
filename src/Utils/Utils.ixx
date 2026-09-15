// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file Utils.ixx
 * @brief Primary C++ module interface partition for wavex:utils bundling submodules.
 */

module;

#include <wavex/Utils/Utils.hpp>

export module wavex:utils;

export import :utils_temp_file;
export import :utils_compression;
export import :utils_multipart;

export namespace wavex::utils {
    using wavex::utils::TempFileGuard;
    using wavex::utils::CompressionFormat;
    using wavex::utils::Compressor;
    using wavex::utils::UploadedFile;
    using wavex::utils::FormField;
    using wavex::utils::MultipartLimits;
    using wavex::utils::MultipartFormData;
}
