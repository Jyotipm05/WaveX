// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file Version.hpp
 * @brief Dynamic version definitions for the WaveX framework (reference header).
 */

#pragma once

#include <string_view>

inline std::string_view wx_version = "@PROJECT_VERSION@";

namespace wavex {
    /**
     * @brief Prints the current version of the WaveX library/framework to standard output.
     */
    void _version();
}
