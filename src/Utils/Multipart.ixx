// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file Multipart.ixx
 * @brief C++20 module partition for wavex::utils Multipart and UploadedFile.
 */

module;

#include <wavex/Utils/Multipart.hpp>

export module wavex:utils_multipart;

export namespace wavex::utils {
    using wavex::utils::UploadedFile;
    using wavex::utils::FormField;
    using wavex::utils::MultipartLimits;
    using wavex::utils::MultipartFormData;
}
