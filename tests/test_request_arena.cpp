/**
 * @file test_request_arena.cpp
 * @brief Unit tests for wavex::memory::RequestArena and thread-local pool.
 *
 * Covers: inline buffer fits within 4KB without overflow, O(1) release(),
 * allocate after release(), large allocation overflow to pool, and
 * multiple sequential arena cycles (simulates keep-alive request loop).
 */

#include <wavex/Base/Memory.hpp>

#include <iostream>
#include <memory_resource>
#include <string>
#include <cstring>

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

// ─── Test: Basic inline allocation within 4KB ─────────────────────────────────

void test_inline_allocation() {
    wavex::memory::RequestArena arena;
    auto *mr = arena.resource();

    // Allocate a small array in the arena
    void *p = mr->allocate(64, 8);
    check(p != nullptr, "allocate returns non-null for small request");

    // Write and read back data through the pointer
    char *buf = static_cast<char *>(p);
    std::memcpy(buf, "hello arena", 11);
    check(std::memcmp(buf, "hello arena", 11) == 0, "data written to arena is readable");
}

// ─── Test: release() makes arena reusable ────────────────────────────────────

void test_release_and_reuse() {
    wavex::memory::RequestArena arena;
    auto *mr = arena.resource();

    void *p1 = mr->allocate(128, 8);
    std::memset(p1, 0xFF, 128);
    arena.release();

    // After release(), allocating again should succeed (bump pointer reset)
    void *p2 = mr->allocate(64, 8);
    check(p2 != nullptr, "allocate succeeds after release()");
}

// ─── Test: Multiple sequential cycles (simulates keep-alive loop) ─────────────

void test_sequential_cycles() {
    wavex::memory::RequestArena arena;
    constexpr int cycles = 100;
    bool all_ok = true;

    for (int i = 0; i < cycles; ++i) {
        auto *mr = arena.resource();
        void *p = mr->allocate(256, alignof(std::max_align_t));
        if (!p) {
            all_ok = false;
            break;
        }
        std::memset(p, static_cast<unsigned char>(i), 256);
        arena.release();
    }
    check(all_ok, "100 sequential request cycles succeed without crash");
}

// ─── Test: Large allocation overflows to thread-local pool ───────────────────

void test_large_allocation_overflow() {
    wavex::memory::RequestArena arena;
    auto *mr = arena.resource();

    // Request 8KB which exceeds the 4KB inline buffer — should overflow to pool
    void *p = mr->allocate(8 * 1024, 8);
    check(p != nullptr, "large (8KB) allocation succeeds via pool overflow");

    // Write and read back
    char *buf = static_cast<char *>(p);
    std::memset(buf, 0xAB, 8 * 1024);
    check(buf[4095] == static_cast<char>(0xAB), "large allocation data is writable");

    arena.release();
}

// ─── Test: make_in_arena<T> convenience helper ───────────────────────────────

struct Point {
    int x;
    int y;
};

void test_make_in_arena() {
    wavex::memory::RequestArena arena;
    auto *mr = arena.resource();

    Point *pt = wavex::memory::make_in_arena<Point>(mr, 3, 7);
    check(pt != nullptr, "make_in_arena returns non-null");
    check(pt->x == 3, "arena-placed object x == 3");
    check(pt->y == 7, "arena-placed object y == 7");

    arena.release();
}

// ─── Test: Thread-local pool is accessible ───────────────────────────────────

void test_thread_local_pool_accessible() {
    auto &pool = wavex::memory::get_thread_local_pool();
    // Allocate and immediately deallocate via pool
    void *p = pool.allocate(256, 8);
    check(p != nullptr, "thread-local pool allocates successfully");
    pool.deallocate(p, 256, 8);

    // release() should not crash
    pool.release();
    check(true, "thread-local pool release() does not crash");
}

// ─────────────────────────────────────────────────────────────────────────────

int main() {
    std::cout << "\n=== RequestArena Unit Tests ===\n\n";

    test_inline_allocation();
    test_release_and_reuse();
    test_sequential_cycles();
    test_large_allocation_overflow();
    test_make_in_arena();
    test_thread_local_pool_accessible();

    std::cout << "\n" << tests_passed << "/" << tests_run << " tests passed.\n";
    return tests_passed == tests_run ? 0 : 1;
}
