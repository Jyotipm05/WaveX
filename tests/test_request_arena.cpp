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

    std::cout << "\n" << tests_passed << "/" << tests_run << " tests passed.\n";
    return tests_passed == tests_run ? 0 : 1;
}
