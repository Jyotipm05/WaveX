// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file StringSink.hpp
 * @brief String sink concept and string allocation helpers.
 */

#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <utility>

namespace wavex::base {
    /**
     * @brief Concept for any string container or sink that supports append and reserve.
     */
    template<typename S>
    concept StringSink = requires(S &s, std::string_view v) {
        s.append(v.data(), v.size());
        s.reserve(std::size_t{});
    };

    /**
     * @brief Portable wrapper for std::string::resize_and_overwrite (C++23) with fallback.
     *
     * In C++23, resize_and_overwrite avoids the default initialization zero-fill penalty
     * when writing into contiguous string buffers.
     */
    template<typename String, typename Op>
    inline void resize_and_overwrite_compat(String &str, const std::size_t count, Op &&op) {
#if defined(__cpp_lib_string_resize_and_overwrite) && __cpp_lib_string_resize_and_overwrite >= 202110L
        str.resize_and_overwrite(count, std::forward<Op>(op));
#else
        str.resize(count);
        const std::size_t actual = op(str.data(), count);
        str.resize(actual);
#endif
    }
} // namespace wavex::base
