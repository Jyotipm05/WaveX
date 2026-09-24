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
#include <wavex/Utils/AsyncFs.hpp>

export module wavex:utils;

export namespace wavex::utils {
    using utils::FileMode;
    using utils::BinaryFile;
    using utils::TempFileGuard;
    using utils::CompressionFormat;
    using utils::Compressor;
    using utils::UploadedFile;
    using utils::FormField;
    using utils::MultipartLimits;
    using utils::MultipartFormData;
}

export namespace wavex::fs {
    using fs::read_file;
    using fs::read_bytes;
    using fs::write_file;
    using fs::append_file;
    using fs::remove;
    using fs::copy_file;
}
