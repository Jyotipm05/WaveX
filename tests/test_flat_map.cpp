/**
 * @file test_flat_map.cpp
 * @brief Unit tests for wavex::base::FlatMap.
 *
 * Covers: insert_or_assign, operator[], at(), find(), find_ci(), contains(),
 * iteration, clear(), hard-cap overflow, and case-insensitive operations.
 */

#include <wavex/Base/FlatMap.hpp>

#include <iostream>
#include <string>
#include <string_view>

namespace {
    int tests_run{0};
    int tests_passed{0};

    void check(const bool condition, const char *name) {
        ++tests_run;
        if (condition) {
            ++tests_passed;
            std::cout << "  [PASS] " << name << "\n";
        } else {
            std::cout << "  [FAIL] " << name << "\n";
        }
    }
}

// ─── Test: Basic insert + get ─────────────────────────────────────────────────

void test_basic_insert_get() {
    wavex::base::FlatMap<std::string_view, std::string_view> m;

    std::string k = "host";
    std::string v = "example.com";
    m.insert_or_assign(std::string_view(k), std::string_view(v));

    check(m.size() == 1, "size after insert is 1");
    check(!m.empty(), "not empty after insert");
    check(m.contains("host"), "contains 'host'");
    check(m.get("host") == "example.com", "get returns correct value");
    check(m.get("missing") == std::string_view{}, "get on absent key returns empty view");
}

// ─── Test: Update existing key ────────────────────────────────────────────────

void test_update_existing() {
    wavex::base::FlatMap<std::string_view, std::string_view> m;

    std::string k = "key";
    std::string v1 = "val1";
    std::string v2 = "val2";
    m.insert_or_assign(std::string_view(k), std::string_view(v1));
    m.insert_or_assign(std::string_view(k), std::string_view(v2));

    check(m.size() == 1, "size remains 1 after update");
    check(m.get("key") == "val2", "value updated correctly");
}

// ─── Test: at() throws on missing key ────────────────────────────────────────

void test_at_throws() {
    wavex::base::FlatMap<std::string_view, std::string_view> m;
    bool threw = false;
    try {
        auto _ = m.at("nonexistent");
    } catch (const std::out_of_range &) {
        threw = true;
    }
    check(threw, "at() throws out_of_range for missing key");
}

// ─── Test: find() case-sensitive ─────────────────────────────────────────────

void test_find_case_sensitive() {
    wavex::base::FlatMap<std::string_view, std::string_view> m;

    std::string k = "Content-Type";
    std::string v = "application/json";
    m.insert_or_assign(std::string_view(k), std::string_view(v));

    check(m.find("Content-Type") != m.end(), "find() matches exact case");
    check(m.find("content-type") == m.end(), "find() does not match wrong case");
}

// ─── Test: find_ci() case-insensitive ────────────────────────────────────────

void test_find_ci_case_insensitive() {
    wavex::base::FlatMap<std::string_view, std::string_view> m;

    std::string k = "Content-Type";
    std::string v = "application/json";
    m.insert_or_assign(std::string_view(k), std::string_view(v));

    check(m.find_ci("content-type") != m.end(), "find_ci() matches lowercase");
    check(m.find_ci("CONTENT-TYPE") != m.end(), "find_ci() matches uppercase");
    check(m.find_ci("Content-Type") != m.end(), "find_ci() matches original");
    check(m.find_ci("accept") == m.end(), "find_ci() returns end for absent key");
}

// ─── Test: insert_or_assign_ci updates case-insensitively ────────────────────

void test_insert_or_assign_ci() {
    wavex::base::FlatMap<std::string_view, std::string_view> m;

    std::string k1 = "Content-Type";
    std::string v1 = "text/plain";
    std::string k2 = "content-type";
    std::string v2 = "application/json";

    m.insert_or_assign_ci(std::string_view(k1), std::string_view(v1));
    m.insert_or_assign_ci(std::string_view(k2), std::string_view(v2));

    check(m.size() == 1, "size remains 1 after CI update");
    check(m.find_ci("content-type")->second == "application/json",
          "CI update sets new value");
}

// ─── Test: Iteration ──────────────────────────────────────────────────────────

void test_iteration() {
    wavex::base::FlatMap<std::string_view, std::string_view> m;

    std::string k1 = "a";
    std::string v1 = "1";
    std::string k2 = "b";
    std::string v2 = "2";
    std::string k3 = "c";
    std::string v3 = "3";

    m.insert_or_assign(std::string_view(k1), std::string_view(v1));
    m.insert_or_assign(std::string_view(k2), std::string_view(v2));
    m.insert_or_assign(std::string_view(k3), std::string_view(v3));

    std::size_t count = 0;
    for (const auto &[k, v]: m) { ++count; }
    check(count == 3, "iterates over exactly 3 elements");
}

// ─── Test: clear() ────────────────────────────────────────────────────────────

void test_clear() {
    wavex::base::FlatMap<std::string_view, std::string_view> m;

    std::string k = "x";
    std::string v = "y";
    m.insert_or_assign(std::string_view(k), std::string_view(v));
    m.clear();

    check(m.empty(), "empty() after clear()");
    check(m.size() == 0, "size() == 0 after clear()");
    check(!m.contains("x"), "key absent after clear()");
}

// ─── Test: Inline cap overflow goes to overflow_ vector ──────────────────────

void test_inline_overflow() {
    // InlineCap=4 to trigger overflow quickly
    wavex::base::FlatMap<std::string_view, std::string_view, 4> m;

    // These owned strings live for the duration of the test
    std::string keys[6] = {"a", "b", "c", "d", "e", "f"};
    std::string vals[6] = {"1", "2", "3", "4", "5", "6"};

    for (int i = 0; i < 6; ++i)
        m.insert_or_assign(std::string_view(keys[i]), std::string_view(vals[i]));

    check(m.size() == 6, "size == 6 after 6 inserts (overflow)");
    check(m.get("e") == "5", "get() works for overflow item 'e'");
    check(m.get("f") == "6", "get() works for overflow item 'f'");
    check(m.get("a") == "1", "get() still works for inline item 'a'");
}

// ─── Test: erase and erase_ci ──────────────────────────────────────────────────

void test_erase() {
    wavex::base::FlatMap<std::string_view, std::string_view> m;
    std::string k1 = "Content-Type", v1 = "application/json";
    std::string k2 = "Accept", v2 = "*/*";
    m.insert_or_assign(std::string_view(k1), std::string_view(v1));
    m.insert_or_assign(std::string_view(k2), std::string_view(v2));

    check(m.size() == 2, "size before erase is 2");
    check(m.erase_ci("content-type"), "erase_ci removes Content-Type");
    check(m.size() == 1, "size after erase is 1");
    check(!m.contains("Content-Type"), "Content-Type is gone");
    check(m.contains("Accept"), "Accept is still present");
    check(!m.erase("nonexistent"), "erase nonexistent returns false");
}

// ─────────────────────────────────────────────────────────────────────────────

int main() {
    std::cout << "\n=== FlatMap Unit Tests ===\n\n";

    test_basic_insert_get();
    test_update_existing();
    test_at_throws();
    test_find_case_sensitive();
    test_find_ci_case_insensitive();
    test_insert_or_assign_ci();
    test_iteration();
    test_erase();
    test_clear();
    test_inline_overflow();

    std::cout << "\n" << tests_passed << "/" << tests_run << " tests passed.\n";
    return tests_passed == tests_run ? 0 : 1;
}
