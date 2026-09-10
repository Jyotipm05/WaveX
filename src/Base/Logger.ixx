// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file Logger.ixx
 * @brief C++ module interface for WaveX Logger and modern wavex::log API.
 */

module;

#include <wavex/Base/Logger.hpp>

export module wavex:logger;

export namespace wavex::base {
    using base::LogLevel;
    using base::log_level_tag;
    using base::log_level_color;
    using base::Logger;
}

export namespace wavex::log {
    using log::format_with_loc;
    using log::msg_with_loc;
    using log::trace;
    using log::debug;
    using log::info;
    using log::warn;
    using log::error;
    using log::fatal;
}

export namespace wxlog = wavex::log;