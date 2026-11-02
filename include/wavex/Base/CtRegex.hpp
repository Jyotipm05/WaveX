// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file CtRegex.hpp
 * @brief A small regular-expression engine compiled at compile time (`wavex::rx`).
 *
 * `compile(pattern)` is `constexpr`: it turns the pattern into an NFA program held in fixed-size arrays, so the
 * result can live in a `constexpr` variable or a template argument and a bad pattern is a compile error. Matching
 * (`program::match`) simulates the NFA with a bit-set of states (epsilon closures are precomputed at compile time),
 * one pass over the input: O(input x program size) time, no backtracking (so no catastrophic patterns), no allocation, and it is `constexpr` too.
 *
 * Semantics: the whole input must match (like `std::regex_match`), byte-wise (a multi-byte UTF-8 character is
 * several bytes), ECMAScript flavour for what is supported.
 *
 * Supported:
 *   - literals, `.` (any byte except \n and \r), escapes `\\ \. \/ ...` (any punctuation), `\t \n \r \f \v \0 \xHH`
 *   - classes `[abc] [a-z0-9_-] [^...]` with `\d \w \s` inside; shorthands `\d \D \w \W \s \S`
 *   - groups `( )` and `(?: )` (groups never capture), alternation `|`
 *   - quantifiers `* + ? {n} {n,} {n,m}`; a trailing `?` (lazy form) is accepted and ignored since only a full
 *     match is asked for
 *   - `^` at the very start and `$` at the very end (no-ops under full-match semantics), `(?i)` at the start
 * Not supported (compile error `unsupported`/`bad_escape`): lookaround, backreferences, `\b`, named groups,
 * captures, anchors elsewhere.
 *
 * Limits (error `too_complex`): 128 instructions and 16 distinct character sets per program, 32 nesting levels,
 * 16 alternatives per group, repeat counts up to 1000 (each copy counts towards the instruction limit).
 *
 * ```cpp
 * static_assert(wavex::rx::matches<"[0-9]{4}-[0-9]{2}">("2026-11"));
 * constexpr auto uuid = wavex::rx::compile("[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}");
 * static_assert(uuid.ok() && uuid.match("123e4567-e89b-12d3-a456-426614174000"));
 * ```
 */

#ifndef WAVEX_BASE_CTREGEX_HPP
#define WAVEX_BASE_CTREGEX_HPP

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include <wavex/Base/FixedString.hpp>

namespace wavex::rx {

    enum class error : std::uint8_t {
        none,
        unbalanced_paren,   ///< '(' without ')' or a stray ')'
        bad_escape,         ///< unknown or unsupported escape (\b, \1, ...)
        trailing_backslash, ///< pattern ends with '\'
        bad_class,          ///< unterminated or reversed range in [...]
        nothing_to_repeat,  ///< quantifier without an atom, or two quantifiers in a row
        bad_repeat,         ///< {n,m} with n > m or a count above 1000
        too_complex,        ///< program, set, nesting or alternative limit exceeded
        unsupported         ///< lookaround, named group, anchor in the middle, ...
    };

    enum class opcode : std::uint8_t { chr, any, set, split, jmp, match };

    template<std::size_t MaxInsn = 128, std::size_t MaxSets = 16>
    struct basic_program {
        struct insn {
            opcode op{opcode::match};
            unsigned char ch{0};  ///< chr
            std::uint16_t x{0};   ///< set: set index; split/jmp: target
            std::uint16_t y{0};   ///< split: second target
        };

        using bitset256 = std::array<std::uint64_t, 4>;
        static constexpr std::size_t words = (MaxInsn + 63) / 64;

        std::array<insn, MaxInsn> code{};
        std::array<bitset256, MaxSets> sets{};
        std::uint16_t size{0};
        std::uint16_t set_count{0};
        error err{error::none};

        [[nodiscard]] constexpr bool ok() const noexcept { return err == error::none; }

        using state_set = std::array<std::uint64_t, words>;

        state_set start{};                        ///< states reachable before any input (consuming states and match)
        std::array<state_set, MaxInsn> follow{};  ///< follow[pc]: states reachable after pc consumes a byte

        /// Precomputes the epsilon closures so matching never walks split/jmp chains. Called by compile().
        constexpr void finalize() noexcept {
            start = closure(0);
            for (std::size_t pc = 0; pc < size; ++pc) {
                const opcode op = code[pc].op;
                if (op == opcode::chr || op == opcode::any || op == opcode::set) follow[pc] = closure(pc + 1);
            }
        }

        /// True when all of `s` matches. A program that failed to compile matches nothing.
        [[nodiscard]] constexpr bool match(const std::string_view s) const noexcept {
            if (err != error::none || size == 0) return false;
            state_set cur = start;
            for (const char raw: s) {
                const auto c = static_cast<unsigned char>(raw);
                state_set nxt{};
                std::uint64_t any_bits = 0;
                for (std::size_t w = 0; w < words; ++w) {
                    std::uint64_t bits = cur[w];
                    while (bits != 0) {
                        const auto b = static_cast<std::size_t>(lowest_bit(bits));
                        bits &= bits - 1;
                        const std::size_t pc = w * 64 + b;
                        const insn &in = code[pc];
                        bool hit = false;
                        switch (in.op) {
                            case opcode::chr: hit = in.ch == c; break;
                            case opcode::any: hit = c != '\n' && c != '\r'; break;
                            case opcode::set: hit = ((sets[in.x][c >> 6] >> (c & 63)) & 1U) != 0; break;
                            default: break; // the match state consumes nothing
                        }
                        if (hit) {
                            const state_set &f = follow[pc];
                            for (std::size_t k = 0; k < words; ++k) {
                                nxt[k] |= f[k];
                                any_bits |= f[k];
                            }
                        }
                    }
                }
                if (any_bits == 0) return false;
                cur = nxt;
            }
            const std::size_t last = size - 1; // the single `match` instruction is always last
            return ((cur[last >> 6] >> (last & 63)) & 1U) != 0;
        }

    private:
        [[nodiscard]] static constexpr int lowest_bit(const std::uint64_t v) noexcept { return std::countr_zero(v); }

        /// Consuming states (and match) reachable from `start` through split/jmp.
        [[nodiscard]] constexpr state_set closure(const std::size_t from) const noexcept {
            state_set visited{};
            state_set out{};
            std::array<std::uint16_t, MaxInsn + 1> stack{};
            std::size_t sp = 0;
            stack[sp++] = static_cast<std::uint16_t>(from);
            while (sp != 0) {
                const std::size_t pc = stack[--sp];
                const std::uint64_t bit = std::uint64_t{1} << (pc & 63);
                if ((visited[pc >> 6] & bit) != 0) continue;
                visited[pc >> 6] |= bit;
                const insn &in = code[pc];
                if (in.op == opcode::split) {
                    stack[sp++] = in.y;
                    stack[sp++] = in.x;
                } else if (in.op == opcode::jmp) {
                    stack[sp++] = in.x;
                } else {
                    out[pc >> 6] |= bit;
                }
            }
            return out;
        }
    };

    using program = basic_program<>;

    namespace detail {

        template<typename P>
        struct compiler {
            using insn = typename P::insn;
            using bitset256 = typename P::bitset256;

            static constexpr std::size_t max_insn = P{}.code.size();
            static constexpr std::size_t max_sets = P{}.sets.size();
            static constexpr int max_depth = 32;
            static constexpr std::size_t max_alternatives = 16;
            static constexpr unsigned max_repeat = 1000;

            P prog{};
            std::string_view src{};
            std::size_t pos{0};
            bool icase{false};

            constexpr bool fail(const error e) noexcept {
                if (prog.err == error::none) prog.err = e;
                return false;
            }

            // ── character sets ──────────────────────────────────────────────────
            static constexpr void set_bit(bitset256 &b, const unsigned c) noexcept {
                b[c >> 6] |= std::uint64_t{1} << (c & 63);
            }

            static constexpr bool test_bit(const bitset256 &b, const unsigned c) noexcept {
                return ((b[c >> 6] >> (c & 63)) & 1U) != 0;
            }

            static constexpr void add_range(bitset256 &b, unsigned lo, const unsigned hi) noexcept {
                for (; lo <= hi; ++lo) set_bit(b, lo);
            }

            static constexpr void negate(bitset256 &b) noexcept {
                for (auto &w: b) w = ~w;
            }

            static constexpr void add_class(bitset256 &b, const char kind) noexcept {
                bitset256 t{};
                switch (kind) {
                    case 'd': case 'D': add_range(t, '0', '9'); break;
                    case 'w': case 'W':
                        add_range(t, '0', '9');
                        add_range(t, 'a', 'z');
                        add_range(t, 'A', 'Z');
                        set_bit(t, '_');
                        break;
                    default: // s, S
                        set_bit(t, ' ');
                        add_range(t, '\t', '\r'); // \t \n \v \f \r
                        break;
                }
                if (kind == 'D' || kind == 'W' || kind == 'S') negate(t);
                for (std::size_t i = 0; i < 4; ++i) b[i] |= t[i];
            }

            static constexpr void fold_case(bitset256 &b) noexcept {
                for (unsigned c = 'a'; c <= 'z'; ++c) {
                    const unsigned u = c - 'a' + 'A';
                    if (test_bit(b, c) || test_bit(b, u)) {
                        set_bit(b, c);
                        set_bit(b, u);
                    }
                }
            }

            constexpr bool add_set(const bitset256 &b, std::size_t &index) noexcept {
                for (std::size_t i = 0; i < prog.set_count; ++i) {
                    if (prog.sets[i] == b) {
                        index = i;
                        return true;
                    }
                }
                if (prog.set_count == max_sets) return fail(error::too_complex);
                prog.sets[prog.set_count] = b;
                index = prog.set_count++;
                return true;
            }

            // ── code emission ───────────────────────────────────────────────────
            constexpr bool emit(const opcode op, const unsigned ch = 0, const std::size_t x = 0,
                                const std::size_t y = 0) noexcept {
                if (prog.size >= max_insn) return fail(error::too_complex);
                insn &in = prog.code[prog.size++];
                in.op = op;
                in.ch = static_cast<unsigned char>(ch);
                in.x = static_cast<std::uint16_t>(x);
                in.y = static_cast<std::uint16_t>(y);
                return true;
            }

            /// Inserts `in` at `at`; jump targets of the moved instructions that pointed at or past `at` follow them.
            constexpr bool insert(const std::size_t at, const insn in) noexcept {
                if (prog.size >= max_insn) return fail(error::too_complex);
                for (std::size_t i = prog.size; i > at; --i) prog.code[i] = prog.code[i - 1];
                prog.code[at] = in;
                ++prog.size;
                for (std::size_t i = at + 1; i < prog.size; ++i) {
                    insn &m = prog.code[i];
                    if (m.op == opcode::split) {
                        if (m.x >= at) ++m.x;
                        if (m.y >= at) ++m.y;
                    } else if (m.op == opcode::jmp) {
                        if (m.x >= at) ++m.x;
                    }
                }
                return true;
            }

            /// Appends a copy of [s, e), retargeting its internal jumps.
            constexpr bool copy_range(const std::size_t s, const std::size_t e) noexcept {
                const std::size_t delta = prog.size - s;
                for (std::size_t i = s; i < e; ++i) {
                    insn in = prog.code[i];
                    if (in.op == opcode::split) {
                        in.x = static_cast<std::uint16_t>(in.x + delta);
                        in.y = static_cast<std::uint16_t>(in.y + delta);
                    } else if (in.op == opcode::jmp) {
                        in.x = static_cast<std::uint16_t>(in.x + delta);
                    }
                    if (prog.size >= max_insn) return fail(error::too_complex);
                    prog.code[prog.size++] = in;
                }
                return true;
            }

            constexpr bool emit_literal(const unsigned c) noexcept {
                const bool letter = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
                if (icase && letter) {
                    bitset256 b{};
                    set_bit(b, c);
                    fold_case(b);
                    std::size_t idx = 0;
                    return add_set(b, idx) && emit(opcode::set, 0, idx);
                }
                return emit(opcode::chr, c);
            }

            // ── parsing ─────────────────────────────────────────────────────────
            [[nodiscard]] constexpr bool at_end() const noexcept { return pos >= src.size(); }

            static constexpr int hex_value(const char c) noexcept {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            }

            static constexpr bool is_alnum(const char c) noexcept {
                return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
            }

            /// Parses the escape after a '\' (pos is just past it). Single byte -> `ch`, `\d`-style -> `cls` (not 0).
            constexpr bool parse_escape(unsigned &ch, char &cls) noexcept {
                if (at_end()) return fail(error::trailing_backslash);
                const char c = src[pos++];
                cls = 0;
                switch (c) {
                    case 'd': case 'D': case 'w': case 'W': case 's': case 'S':
                        cls = c;
                        return true;
                    case 't': ch = '\t'; return true;
                    case 'n': ch = '\n'; return true;
                    case 'r': ch = '\r'; return true;
                    case 'f': ch = '\f'; return true;
                    case 'v': ch = '\v'; return true;
                    case '0': ch = 0; return true;
                    case 'x': {
                        if (pos + 2 > src.size()) return fail(error::bad_escape);
                        const int h = hex_value(src[pos]);
                        const int l = hex_value(src[pos + 1]);
                        if (h < 0 || l < 0) return fail(error::bad_escape);
                        pos += 2;
                        ch = static_cast<unsigned>(h * 16 + l);
                        return true;
                    }
                    default:
                        if (is_alnum(c)) return fail(error::bad_escape); // \b \B \1 \A ...
                        ch = static_cast<unsigned char>(c);
                        return true;
                }
            }

            constexpr bool parse_bracket() noexcept {
                // pos is just past '['
                bool neg = false;
                if (!at_end() && src[pos] == '^') {
                    neg = true;
                    ++pos;
                }
                bitset256 b{};
                for (;;) {
                    if (at_end()) return fail(error::bad_class);
                    if (src[pos] == ']') {
                        ++pos;
                        break;
                    }
                    unsigned lo = 0;
                    char cls = 0;
                    if (src[pos] == '\\') {
                        ++pos;
                        if (!parse_escape(lo, cls)) return false;
                    } else {
                        lo = static_cast<unsigned char>(src[pos++]);
                    }
                    if (cls != 0) {
                        add_class(b, cls);
                        continue; // a following '-' is a literal
                    }
                    if (pos + 1 < src.size() && src[pos] == '-' && src[pos + 1] != ']') {
                        ++pos;
                        unsigned hi = 0;
                        char hcls = 0;
                        if (src[pos] == '\\') {
                            ++pos;
                            if (!parse_escape(hi, hcls)) return false;
                            if (hcls != 0) return fail(error::bad_class);
                        } else {
                            hi = static_cast<unsigned char>(src[pos++]);
                        }
                        if (lo > hi) return fail(error::bad_class);
                        add_range(b, lo, hi);
                    } else {
                        set_bit(b, lo);
                    }
                }
                if (icase) fold_case(b); // before negating: [^a] under (?i) excludes both 'a' and 'A'
                if (neg) negate(b);
                std::size_t idx = 0;
                return add_set(b, idx) && emit(opcode::set, 0, idx);
            }

            constexpr bool parse_atom(const int depth) noexcept {
                const char c = src[pos];
                switch (c) {
                    case '(': {
                        ++pos;
                        if (!at_end() && src[pos] == '?') {
                            if (pos + 1 < src.size() && src[pos + 1] == ':') pos += 2;
                            else return fail(error::unsupported); // lookaround, named group, flags in the middle
                        }
                        if (!parse_alt(depth + 1)) return false;
                        if (at_end() || src[pos] != ')') return fail(error::unbalanced_paren);
                        ++pos;
                        return true;
                    }
                    case '[':
                        ++pos;
                        return parse_bracket();
                    case '.':
                        ++pos;
                        return emit(opcode::any);
                    case '\\': {
                        ++pos;
                        unsigned ch = 0;
                        char cls = 0;
                        if (!parse_escape(ch, cls)) return false;
                        if (cls != 0) {
                            bitset256 b{};
                            add_class(b, cls);
                            std::size_t idx = 0;
                            return add_set(b, idx) && emit(opcode::set, 0, idx);
                        }
                        return emit_literal(ch);
                    }
                    case '*': case '+': case '?':
                        return fail(error::nothing_to_repeat);
                    default:
                        ++pos;
                        return emit_literal(static_cast<unsigned char>(c));
                }
            }

            /// Recognizes `{n}`, `{n,}` and `{n,m}` at pos. Anything else leaves pos alone and returns false
            /// (the '{' is then an ordinary character).
            constexpr bool parse_braces(unsigned &lo, long &hi) noexcept {
                std::size_t p = pos + 1;
                const auto number = [&](unsigned &out) {
                    if (p >= src.size() || src[p] < '0' || src[p] > '9') return false;
                    unsigned v = 0;
                    while (p < src.size() && src[p] >= '0' && src[p] <= '9') {
                        if (v <= 100000) v = v * 10 + static_cast<unsigned>(src[p] - '0');
                        ++p;
                    }
                    out = v;
                    return true;
                };
                if (!number(lo)) return false;
                hi = lo;
                if (p < src.size() && src[p] == ',') {
                    ++p;
                    unsigned h = 0;
                    if (number(h)) hi = h;
                    else hi = -1;
                }
                if (p >= src.size() || src[p] != '}') return false;
                pos = p + 1;
                return true;
            }

            /// `atom{lo,hi}` for the atom occupying [s, prog.size); hi < 0 means unbounded.
            constexpr bool apply_repeat(const std::size_t s, const unsigned lo, const long hi) noexcept {
                if (lo > max_repeat || hi > static_cast<long>(max_repeat) || (hi >= 0 && static_cast<long>(lo) > hi)) {
                    return fail(error::bad_repeat);
                }
                std::size_t e = prog.size;
                if (hi == 0) { // x{0}: the atom never matches anything, drop it
                    prog.size = static_cast<std::uint16_t>(s);
                    return true;
                }
                if (lo == 0) {
                    // Make the first copy optional (x?) or a loop (x*).
                    if (!insert(s, insn{opcode::split, 0, static_cast<std::uint16_t>(s + 1), 0})) return false;
                    ++e;
                    if (hi < 0) {
                        if (!emit(opcode::jmp, 0, s)) return false;
                        prog.code[s].y = prog.size;
                        return true;
                    }
                    prog.code[s].y = prog.size;
                    return optional_copies(s + 1, e, static_cast<unsigned>(hi) - 1);
                }
                // lo >= 1: the atom already is the first required copy.
                std::size_t last_start = s;
                for (unsigned i = 1; i < lo; ++i) {
                    last_start = prog.size;
                    if (!copy_range(s, e)) return false;
                }
                if (hi < 0) { // x{n,} = x^(n-1) x+
                    return emit(opcode::split, 0, last_start, prog.size + 1);
                }
                return optional_copies(s, e, static_cast<unsigned>(hi) - lo);
            }

            constexpr bool optional_copies(const std::size_t s, const std::size_t e, const unsigned count) noexcept {
                for (unsigned i = 0; i < count; ++i) {
                    const std::size_t p = prog.size;
                    if (!emit(opcode::split, 0, p + 1, 0)) return false;
                    if (!copy_range(s, e)) return false;
                    prog.code[p].y = prog.size;
                }
                return true;
            }

            constexpr bool parse_seq(const int depth) noexcept {
                while (!at_end() && src[pos] != '|' && src[pos] != ')') {
                    if (src[pos] == '^' && pos == anchor_start) {
                        ++pos;
                        continue;
                    }
                    if (src[pos] == '$' && pos + 1 == src.size() && depth == 0) {
                        ++pos;
                        continue;
                    }
                    if (src[pos] == '^' || src[pos] == '$') return fail(error::unsupported);

                    const std::size_t s = prog.size;
                    if (!parse_atom(depth)) return false;

                    if (at_end()) break;
                    bool quantified = true;
                    switch (src[pos]) {
                        case '*': ++pos; if (!apply_repeat(s, 0, -1)) return false; break;
                        case '+': ++pos; if (!apply_repeat(s, 1, -1)) return false; break;
                        case '?': ++pos; if (!apply_repeat(s, 0, 1)) return false; break;
                        case '{': {
                            unsigned lo = 0;
                            long hi = 0;
                            if (parse_braces(lo, hi)) {
                                if (!apply_repeat(s, lo, hi)) return false;
                            } else {
                                quantified = false;
                            }
                            break;
                        }
                        default: quantified = false; break;
                    }
                    if (quantified && !at_end()) {
                        if (src[pos] == '?') ++pos; // lazy form: irrelevant for a full match
                        if (!at_end() && (src[pos] == '*' || src[pos] == '+' || src[pos] == '?')) {
                            return fail(error::nothing_to_repeat);
                        }
                    }
                }
                return true;
            }

            constexpr bool parse_alt(const int depth) noexcept {
                if (depth > max_depth) return fail(error::too_complex);
                std::size_t branch_start = prog.size;
                std::array<std::uint16_t, max_alternatives> jumps{};
                std::size_t njumps = 0;
                if (!parse_seq(depth)) return false;
                while (!at_end() && src[pos] == '|') {
                    ++pos;
                    if (njumps == max_alternatives) return fail(error::too_complex);
                    if (!insert(branch_start, insn{opcode::split, 0, static_cast<std::uint16_t>(branch_start + 1), 0})) {
                        return false;
                    }
                    jumps[njumps++] = prog.size;
                    if (!emit(opcode::jmp)) return false;
                    prog.code[branch_start].y = prog.size;
                    branch_start = prog.size;
                    if (!parse_seq(depth)) return false;
                }
                for (std::size_t i = 0; i < njumps; ++i) prog.code[jumps[i]].x = prog.size;
                return true;
            }

            std::size_t anchor_start{0};

            constexpr P run(const std::string_view pattern) noexcept {
                src = pattern;
                if (src.starts_with("(?i)")) {
                    icase = true;
                    pos = 4;
                }
                anchor_start = pos;
                if (parse_alt(0) && pos != src.size()) fail(error::unbalanced_paren); // stray ')'
                if (prog.err == error::none && !emit(opcode::match)) return prog;
                return prog;
            }
        };

    } // namespace detail

    /// Compiles `pattern`. Check `ok()` / `err` on the result (a failed program matches nothing).
    template<std::size_t MaxInsn = 128, std::size_t MaxSets = 16>
    [[nodiscard]] constexpr basic_program<MaxInsn, MaxSets> compile_with(const std::string_view pattern) noexcept {
        detail::compiler<basic_program<MaxInsn, MaxSets> > c;
        auto prog = c.run(pattern);
        if (prog.ok()) prog.finalize();
        return prog;
    }

    [[nodiscard]] constexpr program compile(const std::string_view pattern) noexcept {
        return compile_with<>(pattern);
    }

    /// `matches<"[0-9]+">(s)`: pattern checked at compile time, program built once.
    template<base::fixed_string Pattern>
    [[nodiscard]] constexpr bool matches(const std::string_view s) noexcept {
        constexpr program prog = compile(Pattern.view());
        static_assert(prog.ok(), "wavex::rx: invalid regular expression");
        return prog.match(s);
    }

} // namespace wavex::rx

#endif // WAVEX_BASE_CTREGEX_HPP
