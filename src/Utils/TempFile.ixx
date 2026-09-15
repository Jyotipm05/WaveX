// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file TempFile.ixx
 * @brief C++20 module partition for wavex::utils::TempFileGuard.
 */

module;

#include <wavex/Utils/TempFile.hpp>

export module wavex:utils_temp_file;

export namespace wavex::utils {
    using wavex::utils::TempFileGuard;
}
