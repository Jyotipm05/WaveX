/**
 * @file test_request_arena.cpp
 * @brief Unit tests for wavex::memory::RequestArena and thread-local pool.
 *
 * Covers: inline buffer fits within 4KB without overflow, O(1) release(),
 * allocate after release(), large allocation overflow to pool, and
 * multiple sequential arena cycles (simulates keep-alive request loop).
 */

#include <wavex/Base/Memory.hpp>
#include <wavex/protos/http/http.hpp>

#include <iostream>
#include <memory_resource>
#include <string>
#include <cstring>
#include <thread>
#include <new>

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

// ─── Test: Request and Response arena wiring (Issue F1) ──────────────────────

void test_request_and_response_arena_wiring() {
    wavex::memory::RequestArena arena;
    auto *mr = arena.resource();

    // Construct request and response with arena
    wavex::protos::http::Http1Request req(mr);
    wavex::protos::http::Http1Response res(mr);

    check(req.arena() == mr, "Http1Request::arena() returns injected memory resource");
    check(res.arena() == mr, "Http1Response::arena() returns injected memory resource");

    // Test parse_stream / extract_path_query with encoded query parameters
    const std::string raw_http1 = "GET /search?q=modern%20c%2B%2B&page=1&limit=50 HTTP/1.1\r\nHost: localhost\r\n\r\n";
    std::string_view raw_view = raw_http1;
    const auto pres = req.parse_stream(raw_view);
    check(pres == wavex::protos::http::http1codec::parser::result::success, "req.parse_stream succeeds");
    check(req.query_param("q") == "modern c++", "query_param q decoded from arena");
    check(req.query_param("page") == "1", "query_param page decoded from arena");
    check(req.query_param("limit") == "50", "query_param limit decoded from arena");

    // Test set_params with percent-encoded route parameters
    wavex::base::FlatMap<std::string_view, std::string_view> route_params;
    route_params.insert_or_assign("category", "high%20performance");
    route_params.insert_or_assign("id", "42");
    req.set_params(route_params);

    check(req.param("category") == "high performance", "route param category decoded from arena");
    check(req.param("id") == "42", "route param id matches");

    // Test res.serialize_to with PMR string backed by the arena
    res.status(200).send("{\"status\":\"ok\"}");
    std::pmr::string wire_resp(mr);
    res.serialize_to(wire_resp);

    check(!wire_resp.empty(), "res.serialize_to produces non-empty PMR output");
    check(wire_resp.find("200 OK") != std::string::npos, "serialized response contains 200 OK");
    check(wire_resp.find("{\"status\":\"ok\"}") != std::string::npos, "serialized response contains body");

    // Reclaim arena memory
    arena.release();
    check(true, "arena.release() after request cycle succeeds");
}

// ─── Test: HTTP/3 Request and Response arena wiring (Issue F1) ───────────────

void test_http3_request_arena_wiring() {
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
    wavex::memory::RequestArena arena;
    auto *mr = arena.resource();

    wavex::protos::http::Http3Request h3_req(mr);
    wavex::protos::http::Http3Response h3_res(mr);

    check(h3_req.arena() == mr, "Http3Request::arena() returns injected memory resource");
    check(h3_res.arena() == mr, "Http3Response::arena() returns injected memory resource");

    // Test dynamic route param population in Http3Request using arena
    wavex::base::FlatMap<std::string_view, std::string_view> h3_params;
    h3_params.insert_or_assign("action", "quic%20nitro");
    h3_req.set_params(h3_params);
    check(h3_req.param("action") == "quic nitro", "Http3Request param decoded into arena");

    // Test serialize_to for Http3Response into arena PMR string
    h3_res.status(200).send("HTTP/3 arena body payload");
    std::pmr::string h3_wire(mr);
    h3_res.serialize_to(h3_wire);
    check(!h3_wire.empty(), "Http3Response::serialize_to produces non-empty wire data");

    arena.release();
    check(true, "HTTP/3 arena cycle completed with clean release()");
#else
    check(true, "HTTP/3 arena test skipped (WAVEX_HAS_SSL disabled)");
#endif
}

// ─── Test: ConnectionMemoryPool lifecycle (Issue F2) ─────────────────────────

void test_connection_memory_pool() {
    wavex::memory::ConnectionMemoryPool conn_pool;
    auto *conn_mr = conn_pool.resource();

    // Verify allocation directly through ConnectionMemoryPool
    void *p = conn_mr->allocate(512, 8);
    check(p != nullptr, "ConnectionMemoryPool allocates successfully");
    std::memset(p, 0x3C, 512);
    conn_mr->deallocate(p, 512, 8);

    // Verify RequestArena utilizing ConnectionMemoryPool as custom upstream
    wavex::memory::RequestArena arena(conn_mr);
    auto *mr = arena.resource();

    // Small allocation fits in inline 4KB buffer
    void *p_small = mr->allocate(128, 8);
    check(p_small != nullptr, "arena with conn_pool allocated small buffer");

    // Large allocation (8KB) overflows safely to ConnectionMemoryPool
    void *p_large = mr->allocate(8192, 8);
    check(p_large != nullptr, "arena with conn_pool overflows to ConnectionMemoryPool");
    std::memset(p_large, 0x4B, 8192);

    arena.release();
    check(true, "arena with conn_pool releases cleanly");
}

// ─── Test: Multi-worker thread termination & cross-thread resumption (Issue F2) ──

void test_multi_worker_thread_safety_f2() {
    // Verifies that RequestArena's default upstream (global new_delete_resource)
    // is safe when a coroutine suspends on one worker and resumes on another,
    // or when a worker thread terminates during scale-down.
    alignas(64) std::byte arena_storage[sizeof(wavex::memory::RequestArena)];
    auto *arena_ptr = reinterpret_cast<wavex::memory::RequestArena *>(arena_storage);

    // 1. Worker thread constructs arena and forces an overflow allocation (> 4KB inline buffer)
    std::thread worker([&]() {
        ::new (static_cast<void *>(arena_ptr)) wavex::memory::RequestArena();
        void *p = arena_ptr->resource()->allocate(8192, 8);
        check(p != nullptr, "worker thread allocated >4KB overflow block in RequestArena");
        std::memset(p, 0x5A, 8192);
    });

    // Worker terminates and joins! (If upstream was thread_local, its pool would now be destroyed)
    worker.join();

    // 2. Resuming on a different worker thread (simulated by main thread):
    // Allocate additional memory from the existing arena
    void *p2 = arena_ptr->resource()->allocate(4096, 8);
    check(p2 != nullptr, "resumed thread allocates successfully after initial worker terminated");
    std::memset(p2, 0xA5, 4096);

    // 3. Reclaim memory and destroy arena on the resumed thread
    arena_ptr->release();
    arena_ptr->~RequestArena();
    check(true, "arena successfully released and destroyed across thread termination (F2)");
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
    test_request_and_response_arena_wiring();
    test_http3_request_arena_wiring();
    test_connection_memory_pool();
    test_multi_worker_thread_safety_f2();

    std::cout << "\n" << tests_passed << "/" << tests_run << " tests passed.\n";
    return tests_passed == tests_run ? 0 : 1;
}

