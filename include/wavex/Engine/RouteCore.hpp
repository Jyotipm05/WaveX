// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file RouteCore.hpp
 * @brief Pieces shared by every router: the router concept, segment comparison policies and the
 *        constexpr route-pattern parser.
 *
 * Nothing here depends on a protocol, an allocator or the registration time, so the compile-time
 * `StaticRouter` uses it from `consteval` code and a runtime router can use the very same parser.
 *
 * Pattern syntax (identical to DynamicRouter, minus regex):
 *   - `users`            literal segment
 *   - `:id` / `{id}`     parameter, any non-empty segment
 *   - `{id:int}`         parameter with a built-in constraint: any, int, uint, alpha, alnum, hex
 *   - `{id:[0-9]{4}}`    parameter whose segment must fully match a regular expression (wavex::rx, see CtRegex.hpp)
 *   - `*` / `*name`      wildcard, must be the last segment, captures the rest of the path
 */

#ifndef WAVEX_ENGINE_ROUTECORE_HPP
#define WAVEX_ENGINE_ROUTECORE_HPP

#include <array>
#include <concepts>
#if defined(__MINGW64__) || defined(__clang__) || defined(__GNUC__)
#include <cstddef>
#endif
#include <cstdint>
#include <functional>
#include <string_view>

#include <wavex/Base/FixedString.hpp>

namespace wavex::engine::route {

    // ─── Router concept ─────────────────────────────────────────────────────

    /// What `Server<Codec, Router>` needs from a router. DynamicRouter and StaticRouter both satisfy it.
    template<typename R>
    concept router_type = requires(R &r, typename R::MethodType m, std::string_view path) {
        typename R::RequestType;
        typename R::ResponseType;
        r.freeze();
        r.resolve(m, path);
        r.not_found_handler();
    };

    using base::concat;
    using base::fixed_string;

    // ─── Segment comparison policies ────────────────────────────────────────
    //
    // `prepare(segment)` is evaluated once per literal segment (in consteval code for registered routes,
    // once per request segment while matching); `equals(key, segment)` is the comparison in the hot loop.
    // A policy may reject cheaply but must confirm with the full string, so a collision never misroutes.

    struct string_compare {
        using key_type = std::string_view;

        [[nodiscard]] static constexpr key_type prepare(const std::string_view s) noexcept { return s; }

        [[nodiscard]] static constexpr bool equals(const key_type &k, const std::string_view s) noexcept {
            return k == s;
        }
    };

    struct fnv1a64 {
        [[nodiscard]] constexpr std::uint64_t operator()(const std::string_view s) const noexcept {
            std::uint64_t h = 0xcbf29ce484222325ULL;
            for (const char c: s) {
                h ^= static_cast<unsigned char>(c);
                h *= 0x100000001b3ULL;
            }
            return h;
        }
    };

    /// Opt-in: compare a 64-bit hash first, then the string. Mismatches (the common case while scanning
    /// siblings) are rejected with one integer compare.
    template<typename Hash = fnv1a64>
    struct hash_compare {
        struct key_type {
            std::uint64_t hash{};
            std::string_view text{};
        };

        [[nodiscard]] static constexpr key_type prepare(const std::string_view s) noexcept {
            return {Hash{}(s), s};
        }

        [[nodiscard]] static constexpr bool equals(const key_type &k, const std::string_view s) noexcept {
            return k.text.size() == s.size() && k.text == s;
        }

        /// Hash of a segment, used by DynamicRouter as the hasher of its child index.
        [[nodiscard]] static constexpr std::uint64_t hash(const std::string_view s) noexcept { return Hash{}(s); }

        /// Request-side overload: both keys are prepared, so the hash filters before the string compare.
        [[nodiscard]] static constexpr bool equals(const key_type &a, const key_type &b) noexcept {
            return a.hash == b.hash && a.text == b.text;
        }
    };

    /// Hasher for tables keyed by segment text: the policy's own `hash` when it has one, `std::hash` otherwise.
    template<typename Cmp>
    struct segment_hasher {
        [[nodiscard]] std::size_t operator()(const std::string_view s) const noexcept {
            if constexpr (requires { { Cmp::hash(s) } -> std::convertible_to<std::uint64_t>; }) {
                return static_cast<std::size_t>(Cmp::hash(s));
            } else {
                return std::hash<std::string_view>{}(s);
            }
        }
    };

    // ─── Pattern parsing ────────────────────────────────────────────────────

    enum class segment_kind : std::uint8_t { literal, param, wildcard };

    enum class param_class : std::uint8_t { any, int_, uint_, alpha, alnum, hex, regex };

    struct pattern_segment {
        std::string_view text{}; ///< literal text, or the parameter / wildcard name
        segment_kind kind{segment_kind::literal};
        param_class cls{param_class::any};
        std::string_view pattern{}; ///< regular expression (cls == regex), else empty
    };

    inline constexpr std::size_t max_pattern_segments = 16;

    enum class pattern_error : std::uint8_t {
        none,
        too_many_segments, ///< more than max_pattern_segments
        wildcard_not_last,
        unknown_constraint, ///< `{name:}` with nothing after the colon
        bad_literal, ///< a literal segment contains '{', '}' or '*'
        empty_param_name,
        duplicate_param ///< the same parameter name used twice in one pattern
    };

    struct parsed_pattern {
        std::array<pattern_segment, max_pattern_segments> segs{};
        std::size_t count{0};
        pattern_error error{pattern_error::none};
    };

    /// True when `s` is acceptable for the constraint `c` (an empty segment never matches).
    [[nodiscard]] constexpr bool matches_class(const param_class c, const std::string_view s) noexcept {
        if (s.empty()) return false;
        const auto digit = [](const char ch) { return ch >= '0' && ch <= '9'; };
        const auto alpha = [](const char ch) { return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z'); };
        const auto hex = [&](const char ch) {
            return digit(ch) || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
        };
        switch (c) {
            case param_class::any:
                return true;
            case param_class::int_: {
                const std::size_t start = (s[0] == '-' || s[0] == '+') ? 1 : 0;
                if (start == s.size()) return false;
                for (std::size_t i = start; i < s.size(); ++i) if (!digit(s[i])) return false;
                return true;
            }
            case param_class::uint_:
                for (const char ch: s) if (!digit(ch)) return false;
                return true;
            case param_class::alpha:
                for (const char ch: s) if (!alpha(ch)) return false;
                return true;
            case param_class::alnum:
                for (const char ch: s) if (!alpha(ch) && !digit(ch)) return false;
                return true;
            case param_class::hex:
                for (const char ch: s) if (!hex(ch)) return false;
                return true;
            case param_class::regex: // evaluated by the router with the compiled program, never here
                return false;
        }
        return false;
    }

    [[nodiscard]] constexpr bool parse_class(const std::string_view name, param_class &out) noexcept {
        if (name == "any") out = param_class::any;
        else if (name == "int") out = param_class::int_;
        else if (name == "uint") out = param_class::uint_;
        else if (name == "alpha") out = param_class::alpha;
        else if (name == "alnum") out = param_class::alnum;
        else if (name == "hex") out = param_class::hex;
        else return false;
        return true;
    }

    /// `s.find(c, from)` written as a plain loop: GCC's sanitizer builds cannot constant-evaluate the pointer null
    /// check inside std::string_view::find when the view points into a static constexpr object.
    [[nodiscard]] constexpr std::size_t find_char(const std::string_view s, const char c, std::size_t from) noexcept {
        for (; from < s.size(); ++from) {
            if (s[from] == c) return from;
        }
        return std::string_view::npos;
    }

    /// Parses `pattern` into at most `max_pattern_segments` segments. Never throws; check `error` (the StaticRouter turns it into a static_assert).
    [[nodiscard]] constexpr parsed_pattern parse_pattern(const std::string_view pattern) noexcept {
        parsed_pattern out;
        std::size_t pos = 0;
        while (pos <= pattern.size()) {
            std::size_t end = find_char(pattern, '/', pos);
            if (end == std::string_view::npos) end = pattern.size();
            const std::string_view seg = pattern.substr(pos, end - pos);
            pos = end + 1;
            if (seg.empty()) continue; // leading, trailing and doubled slashes are ignored

            if (out.count == max_pattern_segments) {
                out.error = pattern_error::too_many_segments;
                return out;
            }
            if (out.count > 0 && out.segs[out.count - 1].kind == segment_kind::wildcard) {
                out.error = pattern_error::wildcard_not_last;
                return out;
            }

            pattern_segment ps;
            if (seg[0] == ':') {
                ps.kind = segment_kind::param;
                ps.text = seg.substr(1);
            } else if (seg.size() >= 2 && seg.front() == '{' && seg.back() == '}') {
                const std::string_view inner = seg.substr(1, seg.size() - 2);
                const std::size_t colon = find_char(inner, ':', 0);
                ps.kind = segment_kind::param;
                ps.text = inner.substr(0, colon);
                if (colon != std::string_view::npos) {
                    const std::string_view c = inner.substr(colon + 1);
                    if (c.empty()) {
                        out.error = pattern_error::unknown_constraint;
                        return out;
                    }
                    // A built-in class name, otherwise a regular expression (same `{name:regex}` form as DynamicRouter).
                    if (!parse_class(c, ps.cls)) {
                        ps.cls = param_class::regex;
                        ps.pattern = c;
                    }
                }
            } else if (seg[0] == '*') {
                ps.kind = segment_kind::wildcard;
                ps.text = seg.size() > 1 ? seg.substr(1) : std::string_view{"*"};
            } else {
                ps.kind = segment_kind::literal;
                ps.text = seg;
                for (const char ch: seg) {
                    if (ch == '{' || ch == '}' || ch == '*') {
                        out.error = pattern_error::bad_literal;
                        return out;
                    }
                }
            }
            if (ps.kind == segment_kind::param && ps.text.empty()) {
                out.error = pattern_error::empty_param_name;
                return out;
            }
            for (std::size_t i = 0; i < out.count; ++i) {
                if (out.segs[i].kind != segment_kind::literal && ps.kind != segment_kind::literal &&
                    out.segs[i].text == ps.text) {
                    out.error = pattern_error::duplicate_param;
                    return out;
                }
            }
            out.segs[out.count++] = ps;
        }
        return out;
    }

    /// Next path segment of `rest` (skipping empty ones); advances `rest` past it. False when none is left.
    [[nodiscard]] constexpr bool next_segment(std::string_view &rest, std::string_view &seg) noexcept {
        while (!rest.empty() && rest.front() == '/') rest.remove_prefix(1);
        if (rest.empty()) return false;
        if (const std::size_t end = rest.find('/'); end == std::string_view::npos) {
            seg = rest;
            rest.remove_prefix(rest.size()); // keeps rest.data() at the end of the buffer (wildcard slicing)
        } else {
            seg = rest.substr(0, end);
            rest.remove_prefix(end);
        }
        return true;
    }

} // namespace wavex::engine::route

#endif // WAVEX_ENGINE_ROUTECORE_HPP
