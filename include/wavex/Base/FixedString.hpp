// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file FixedString.hpp
 * @brief A string literal usable as a template argument (`template<fixed_string S>`).
 */

#ifndef WAVEX_BASE_FIXEDSTRING_HPP
#define WAVEX_BASE_FIXEDSTRING_HPP

#include <cstddef>
#include <string_view>

namespace wavex::base {

    template<std::size_t N>
    struct fixed_string {
        char data[N + 1]{};

        constexpr fixed_string() = default;

        constexpr fixed_string(const char (&s)[N + 1]) noexcept {
            for (std::size_t i = 0; i < N; ++i) data[i] = s[i];
        }

        [[nodiscard]] constexpr std::string_view view() const noexcept { return {data, N}; }
        [[nodiscard]] static constexpr std::size_t size() noexcept { return N; }
    };

    template<std::size_t N>
    fixed_string(const char (&)[N]) -> fixed_string<N - 1>;

    /// `a` followed by `b`, as a new fixed_string.
    template<std::size_t N, std::size_t M>
    [[nodiscard]] constexpr fixed_string<N + M> concat(const fixed_string<N> &a, const fixed_string<M> &b) noexcept {
        fixed_string<N + M> out;
        for (std::size_t i = 0; i < N; ++i) out.data[i] = a.data[i];
        for (std::size_t i = 0; i < M; ++i) out.data[N + i] = b.data[i];
        return out;
    }

} // namespace wavex::base

#endif // WAVEX_BASE_FIXEDSTRING_HPP
