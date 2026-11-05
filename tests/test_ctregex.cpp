/**
 * @file test_ctregex.cpp
 * @brief wavex::rx: compile-time evaluation, a table of pattern/input expectations, error reporting, and a
 *        differential test against std::regex (ECMAScript) on thousands of generated patterns.
 */

#include <wavex/Base/CtRegex.hpp>

#include <iostream>
#include <random>
#include <regex>
#include <string>
#include <vector>

using namespace wavex;

namespace {
    int tests_run{0};
    int tests_failed{0};

    void check(const bool condition, const std::string &name) {
        ++tests_run;
        if (!condition) {
            ++tests_failed;
            std::cout << "  [FAIL] " << name << "\n";
        }
    }

    // ── evaluated by the compiler ───────────────────────────────────────────────────
    static_assert(rx::matches<"abc">("abc") && !rx::matches<"abc">("abcd") && !rx::matches<"abc">("ab"));
    static_assert(rx::matches<"[0-9]{4}-[0-9]{2}">("2026-11") && !rx::matches<"[0-9]{4}-[0-9]{2}">("2026-1"));
    static_assert(rx::matches<"a|bc|d">("bc") && !rx::matches<"a|bc|d">("b") && rx::matches<"a|bc|d">("d"));
    static_assert(rx::matches<"(ab)+c?">("ababc") && rx::matches<"(ab)+c?">("ab") && !rx::matches<"(ab)+c?">("aba"));
    static_assert(rx::matches<"x*">("") && rx::matches<"x*">("xxx") && !rx::matches<"x+">(""));
    static_assert(rx::matches<"a{2,3}">("aa") && rx::matches<"a{2,3}">("aaa") && !rx::matches<"a{2,3}">("aaaa") &&
                  !rx::matches<"a{2,3}">("a"));
    static_assert(rx::matches<"[^a-c]+">("xyz") && !rx::matches<"[^a-c]+">("xbz"));
    static_assert(rx::matches<"\\d+\\.\\d+">("3.14") && !rx::matches<"\\d+\\.\\d+">("3x14"));
    static_assert(rx::matches<"(?i)hello">("HeLLo") && !rx::matches<"hello">("HeLLo"));
    static_assert(rx::matches<"^ab$">("ab"));
    static_assert(rx::matches<"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}">("123e4567-e89b-12d3-a456-426614174000"));
    static_assert(rx::compile("(ab").err == rx::error::unbalanced_paren);
    static_assert(rx::compile("ab)").err == rx::error::unbalanced_paren);
    static_assert(rx::compile("\\").err == rx::error::trailing_backslash);
    static_assert(rx::compile("\\b").err == rx::error::bad_escape);
    static_assert(rx::compile("\\x4").err == rx::error::bad_escape);
    static_assert(rx::compile("[a-").err == rx::error::bad_class);
    static_assert(rx::compile("[z-a]").err == rx::error::bad_class);
    static_assert(rx::compile("*a").err == rx::error::nothing_to_repeat);
    static_assert(rx::compile("a**").err == rx::error::nothing_to_repeat);
    static_assert(rx::compile("a{3,2}").err == rx::error::bad_repeat);
    static_assert(rx::compile("a{2000}").err == rx::error::bad_repeat);
    static_assert(rx::compile("(?=a)").err == rx::error::unsupported);
    static_assert(rx::compile("a^b").err == rx::error::unsupported);
    static_assert(rx::compile("(a{100}){100}").err == rx::error::too_complex);
    static_assert(!rx::compile("(ab").match("ab"), "a failed program matches nothing");

    struct row {
        const char *pattern;
        const char *input;
        bool expect;
    };

    const row table[] = {
        {"", "", true}, {"", "a", false}, {"a", "a", true}, {"a", "", false}, {"a.c", "abc", true},
        {"a.c", "a\nc", false}, {"a.c", "ac", false}, {"ab*c", "ac", true}, {"ab*c", "abbbc", true},
        {"ab+c", "ac", false}, {"ab?c", "abc", true}, {"ab?c", "abbc", false},
        {"(a|b)*c", "ababc", true}, {"(a|b)*c", "abxc", false}, {"a|", "", true}, {"|a", "", true},
        {"(a|ab)(c|bcd)(d*)", "abcd", true}, {"(a*)*", "aaaa", true}, {"(a*)+", "", true},
        {"(a|b)*abb", "babaabb", true}, {"(a|b)*abb", "babaab", false},
        {"x{0}", "", true}, {"x{0}", "x", false}, {"ax{0}b", "ab", true}, {"x{3}", "xxx", true},
        {"x{3}", "xx", false}, {"x{2,}", "xxxxx", true}, {"x{2,}", "x", false}, {"(xy){2}", "xyxy", true},
        {"(xy){2}", "xyx", false}, {"(xy){1,3}z", "xyxyz", true}, {"(xy){1,3}z", "z", false},
        {"(xy){0,2}z", "z", true}, {"(xy){0,2}z", "xyxyxyz", false},
        {"[abc]", "b", true}, {"[abc]", "d", false}, {"[a-c-]", "-", true}, {"[-a]", "-", true},
        {"[^abc]", "d", true}, {"[^abc]", "a", false}, {"[a-z0-9_]+", "ab_09", true},
        {"[a-z0-9_]+", "ab-09", false}, {"[\\d]+", "123", true}, {"[\\d-]+", "1-2", true},
        {"[\\w.]+", "a.b_c", true}, {"[\\]]", "]", true}, {"[\\\\]", "\\", true}, {"[]", "a", false},
        {"\\d{3}", "123", true}, {"\\D+", "abc", true}, {"\\D+", "a1c", false}, {"\\w+", "a_9", true},
        {"\\W", "-", true}, {"\\s+", " \t", true}, {"\\S+", "ab", true}, {"\\S+", "a b", false},
        {"\\.", ".", true}, {"\\.", "x", false}, {"\\/", "/", true}, {"\\x41", "A", true},
        {"a\\tb", "a\tb", true}, {"(?:ab)+", "abab", true}, {"(?i)abc", "aBC", true},
        {"(?i)[a-c]+", "AbC", true}, {"(?i)[^a]", "A", false}, {"a{,2}", "a{,2}", true},
        {"a{x}", "a{x}", true}, {"a{", "a{", true}, {"a+?", "aaa", true}, {"a*?b", "aab", true},
        {"^abc$", "abc", true}, {"^$", "", true}, {"(^a)", "a", false},
    };

    void table_tests() {
        for (const auto &[pattern, input, expect]: table) {
            const auto prog = rx::compile_runtime(pattern);
            // rows marked as compile errors above are exercised by the static_asserts; the ones here must compile
            // except the intentionally unsupported "(^a)" which must report an error and match nothing.
            if (std::string_view(pattern) == "(^a)") {
                check(!prog.ok() && !prog.match(input), "unsupported inner anchor");
                continue;
            }
            check(prog.ok(), std::string("compiles: ") + pattern);
            check(prog.match(input) == expect,
                  std::string("/") + pattern + "/ vs \"" + input + "\" expected " + (expect ? "match" : "no match"));
        }
    }

    // ── differential test ───────────────────────────────────────────────────────────
    struct generator {
        std::mt19937 rng;
        explicit generator(const unsigned seed) : rng(seed) {}

        unsigned pick(const unsigned n) { return std::uniform_int_distribution<unsigned>(0, n - 1)(rng); }

        std::string atom(const int depth) {
            switch (pick(depth > 2 ? 6 : 8)) {
                case 0: case 1: return std::string(1, static_cast<char>('a' + pick(3)));
                case 2: return ".";
                case 3: return "[a-c]";
                case 4: return "[^ab]";
                case 5: return pick(2) ? "\\d" : "\\w";
                case 6: return "(" + alt(depth + 1) + ")";
                default: return "(?:" + alt(depth + 1) + ")";
            }
        }

        std::string quantified(const int depth) {
            std::string a = atom(depth);
            if (a[0] == '(') { // std::regex backtracks exponentially on nested repeats; keep the reference tractable
                return pick(3) == 0 ? a + "?" : a;
            }
            switch (pick(8)) {
                case 0: return a + "*";
                case 1: return a + "+";
                case 2: return a + "?";
                case 3: return a + "{2}";
                case 4: return a + "{1,3}";
                case 5: return a + "{0,2}";
                default: return a;
            }
        }

        std::string seq(const int depth) {
            std::string out;
            const unsigned n = 1 + pick(4);
            for (unsigned i = 0; i < n; ++i) out += quantified(depth);
            return out;
        }

        std::string alt(const int depth) {
            std::string out = seq(depth);
            while (pick(4) == 0) out += "|" + seq(depth);
            return out;
        }

        std::string input() {
            static constexpr char alphabet[] = "abcd019_ -";
            std::string s;
            const unsigned n = pick(9);
            for (unsigned i = 0; i < n; ++i) s += alphabet[pick(sizeof(alphabet) - 1)];
            return s;
        }
    };

    void differential_tests() {
        generator gen(20261102);
        int patterns = 0, comparisons = 0, mismatches = 0;
        for (int i = 0; i < 6000; ++i) {
            const std::string pat = gen.alt(0);
            const auto prog = rx::compile_runtime(pat);
            if (!prog.ok()) {
                check(prog.err == rx::error::too_complex, "only the size limit may reject a generated pattern: " + pat);
                continue;
            }
            std::regex ref;
            try {
                ref = std::regex(pat, std::regex::ECMAScript);
            } catch (const std::regex_error &) {
                check(false, "std::regex rejected a pattern we accepted: " + pat);
                continue;
            }
            ++patterns;
            for (int k = 0; k < 24; ++k) {
                const std::string in = gen.input();
                const bool want = std::regex_match(in, ref);
                const bool got = prog.match(in);
                ++comparisons;
                if (want != got) {
                    if (++mismatches <= 5) std::cout << "  mismatch /" << pat << "/ on \"" << in << "\": std=" << want << " rx=" << got << "\n";
                }
            }
        }
        check(mismatches == 0, "no disagreement with std::regex (" + std::to_string(comparisons) + " comparisons over " +
                                   std::to_string(patterns) + " patterns)");
        check(patterns > 4000, "most generated patterns compiled");
    }

    void robustness_tests() {
        // Patterns that make backtracking engines explode finish immediately here.
        const auto evil = rx::compile("(a+)+$");
        check(evil.ok(), "(a+)+ compiles");
        check(!evil.match(std::string(100000, 'a') + "!"), "catastrophic pattern on 100 KB input is rejected quickly");
        const auto evil2 = rx::compile("(a|a)*b");
        check(!evil2.match(std::string(100000, 'a')), "ambiguous alternation on 100 KB input is rejected quickly");
        const auto big = rx::compile("a{1000}");
        check(big.err == rx::error::too_complex, "repeat that exceeds the program size reports too_complex");
        std::mt19937 rng(7);
        int errors = 0;
        for (int i = 0; i < 20000; ++i) {
            std::string pat;
            const unsigned n = rng() % 14;
            for (unsigned k = 0; k < n; ++k) pat += "ab()[]{}|*+?^$\\.-,0129dxi:"[rng() % 28];
            const auto p = rx::compile_runtime(pat);
            if (!p.ok()) ++errors;
            (void) p.match("ab01"); // must never crash on garbage patterns
        }
        check(errors > 0, "random garbage patterns are rejected without crashing");
    }
} // namespace

int main() {
    std::cout << "=== wavex::rx tests ===\n";
    table_tests();
    differential_tests();
    robustness_tests();
    std::cout << "\n" << (tests_run - tests_failed) << "/" << tests_run << " passed\n";
    return tests_failed == 0 ? 0 : 1;
}
