/**
 * @file test_request_arena.cpp
 * @brief Unit tests for wavex::memory::RequestArena and thread-local pool.
 *
 * Covers: inline buffer fits within 4KB without overflow, O(1) release(),
 * allocate after release(), large allocation overflow to pool, and
 * multiple sequential arena cycles (simulates keep-alive request loop).
 */

#include <wavex/Base/Memory.hpp>
#include <wavex/Base/Uri.hpp>
#include <wavex/protos/http/http.hpp>

#include <iostream>
#include <memory_resource>
#include <vector>
#include <optional>
#include <type_traits>
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
            std::cout << "  [PASS] " << name << std::endl;
        } else {
            std::cout << "  [FAIL] " << name << std::endl;
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

    {
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
    }

    // Reclaim arena memory
    arena.release();
    check(true, "arena.release() after request cycle succeeds");
}

// ─── Test: HTTP/3 Request and Response arena wiring (Issue F1) ───────────────

void test_http3_request_arena_wiring() {
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
    wavex::memory::RequestArena arena;
    auto *mr = arena.resource();

    {
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
    }

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

// release() returns the pool's blocks to the heap and the pool stays usable (the idle-connection path).
void test_connection_memory_pool_release_and_reuse() {
    wavex::memory::ConnectionMemoryPool conn_pool;

    for (int round = 0; round < 3; ++round) {
        std::pmr::string a(512, 'x', conn_pool.resource());
        std::pmr::vector<int> v(1000, round, conn_pool.resource());
        check(a.size() == 512 && v.back() == round, "allocations succeed from the pool");
        // Everything allocated from the pool is destroyed before release(), as the contract requires.
    }
    conn_pool.release();
    std::pmr::string after(2048, 'y', conn_pool.resource());
    check(after.size() == 2048 && after.front() == 'y', "the pool is usable again after release()");
    // `after` must die before the pool releases at destruction; that is handled by scope order.
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

// ─── Test: Comprehensive uri::decode_to edge cases (Review I-03) ──────────────

void test_decode_to_comprehensive_i03() {
    char out_buf[128];

    // 1. Truncated percent sequences
    std::size_t written = wavex::uri::decode_to("hello%", out_buf);
    check(std::string_view(out_buf, written) == "hello%", "truncated % decoded as literal %");

    written = wavex::uri::decode_to("hello%2", out_buf);
    check(std::string_view(out_buf, written) == "hello%2", "truncated %2 decoded as literal %2");

    // 2. Invalid hex characters
    written = wavex::uri::decode_to("bad%2G", out_buf);
    check(std::string_view(out_buf, written) == "bad%2G", "invalid hex digit decoded literally");

    written = wavex::uri::decode_to("bad%ZZ", out_buf);
    check(std::string_view(out_buf, written) == "bad%ZZ", "invalid hex digits decoded literally");

    // 3. Plus converted to space
    written = wavex::uri::decode_to("hello+world", out_buf);
    check(std::string_view(out_buf, written) == "hello world", "plus decoded to space");

    // 4. Null pointer and empty input protection
    check(wavex::uri::decode_to("", out_buf) == 0, "empty input returns 0 bytes written");
    check(wavex::uri::decode_to("test", nullptr) == 0, "null destination returns 0 without crash");

    // 5. Standard percent encoding
    written = wavex::uri::decode_to("Hello%20World%21", out_buf);
    check(std::string_view(out_buf, written) == "Hello World!", "Hello%20World%21 decoded correctly");
}

// ─── Test: Cross-arena HttpRequest move preserves view validity (Review I-02) ─

void test_cross_arena_request_move_i02() {
    wavex::memory::RequestArena arena_src;
    wavex::memory::RequestArena arena_dst;

    // Construct request backed by arena_src. It lives in an optional so it can be
    // destroyed BEFORE arena_src.release(): objects holding pmr containers must never
    // outlive the memory they allocated from (MSVC debug iterators touch it in dtors).
    std::optional<wavex::protos::http::Http1Request> req_src;
    req_src.emplace(arena_src.resource());
    const std::string raw = "GET /items?category=books%20and%20magazines&page=3 HTTP/1.1\r\nHost: localhost\r\n\r\n";
    std::string_view raw_view = raw;
    const auto res = req_src->parse_stream(raw_view);
    check(res == wavex::protos::http::http1codec::parser::result::success, "req_src parsed successfully");

    wavex::base::FlatMap<std::string_view, std::string_view> r_params;
    r_params.insert_or_assign("author", "bjarne%20stroustrup");
    req_src->set_params(r_params);

    // Verify initial values in req_src
    check(req_src->query_param("category") == "books and magazines", "src query param matches");
    check(req_src->param("author") == "bjarne stroustrup", "src route param matches");

    // Move construct req_dst backed by arena_dst using allocator-extended constructor
    // (Simulates moving a request across different memory resources)
    {
        wavex::protos::http::Http1Request req_dst(std::move(*req_src), arena_dst.resource());

        // Destroy the moved-from source, then release arena_src — if req_dst views
        // dangled into arena_src they would now be invalid!
        req_src.reset();
        arena_src.release();

        // Verify req_dst views remain intact and rebased into new buffer
        check(req_dst.query_param("category") == "books and magazines", "moved query param valid after src arena release");
        check(req_dst.query_param("page") == "3", "moved query param page valid");
        check(req_dst.param("author") == "bjarne stroustrup", "moved route param valid after src arena release");
    }

    arena_dst.release();
}

// ─── Test: Strict Lifetime Separation between Connection and Request (Issue F3) ─

void test_lifetime_separation_f3() {
    // Connection-scoped structures: ConnectionMemoryPool and persistent dynamic table
    wavex::memory::ConnectionMemoryPool conn_pool;
    wavex::protos::http::http2::hpack::dynamic_table h2_dynamic_table;

    // Insert persistent entries into connection-level dynamic table
    h2_dynamic_table.insert("custom-key", "connection-persistent-value");
    check(h2_dynamic_table.size() == 1, "dynamic table initialized at connection scope");

    // Run 5 sequential request cycles with per-request arena wired to conn_pool
    for (int req_idx = 0; req_idx < 5; ++req_idx) {
        wavex::memory::RequestArena req_arena(conn_pool.resource());
        {
            wavex::protos::http::Http1Request req(req_arena.resource());
            wavex::protos::http::Http1Response res(req_arena.resource());

            // Allocate request-scoped data
            res.status(200).send("Ephemeral request body");
            std::pmr::string wire(req_arena.resource());
            res.serialize_to(wire);
            check(!wire.empty(), "request serialized to arena PMR string");
        }

        // Reclaim request arena memory in O(1)
        req_arena.release();
    }

    // Connection-level state must strictly survive all request arena cycles!
    check(h2_dynamic_table.size() == 1, "connection dynamic table survived all request arena releases");
    const auto *entry = h2_dynamic_table.get(0);
    check(entry != nullptr, "connection entry retrieved from dynamic table");
    if (entry) {
        check(entry->name == "custom-key", "connection state name uncorrupted");
        check(entry->value == "connection-persistent-value", "connection state value uncorrupted");
    }
}

// ─── Test: Zero-copy direct sink emission via serialize_into (Review Issue 1) ─

void test_serialize_into_direct_sink() {
    wavex::memory::RequestArena arena;

    {
        // HTTP/1.x response direct emission
        wavex::protos::http::Http1Response res1(arena.resource());
        res1.status(200);
        res1.set("Content-Type", "text/plain");
        res1.send("Zero-copy response payload");

        std::pmr::string sink1(arena.resource());
        res1.serialize_to(sink1);
        check(sink1.starts_with("HTTP/1.1 200 OK\r\n"), "HTTP/1.1 serialize_into emitted status line");
        check(sink1.find("Content-Length: 26\r\n") != std::string::npos, "Content-Length emitted");
        check(sink1.ends_with("Zero-copy response payload"), "Body emitted to sink");

        // HTTP/2 response direct emission
        wavex::protos::http::Http2Response res2(arena.resource());
        res2.status(200);
        res2.send("H2 payload");
        std::pmr::string sink2(arena.resource());
        res2.serialize_to(sink2);
        check(!sink2.empty(), "HTTP/2 serialize_into emitted wire frames");
    }

    arena.release();
}

// ─── Test: Lazy RequestArena and ConnectionMemoryPool::release() (Review Issue 2) ─

void test_lazy_arena_and_pool_release() {
    wavex::memory::ConnectionMemoryPool conn_pool;

    {
        // Construct RequestArena backed by conn_pool
        wavex::memory::RequestArena req_arena(conn_pool.resource());
        check(req_arena.resource() != nullptr, "arena resource is non-null");

        // Allocate from arena
        void *p1 = req_arena.resource()->allocate(128);
        check(p1 != nullptr, "allocated 128 bytes from arena");

        // Allocate >4KB to trigger slab overflow
        void *p2 = req_arena.resource()->allocate(8192);
        check(p2 != nullptr, "allocated 8KB slab from pool");

        req_arena.release();
    }

    // Call conn_pool.release() simulating connection idle state
    conn_pool.release();
    check(true, "conn_pool.release() executed without error");
}

// ─── Test: set_param percent-decoding with decode_to (Review Issue 5 & 6) ─────

void test_set_param_percent_decoding() {
    wavex::memory::RequestArena arena;
    {
        wavex::protos::http::Http1Request req(arena.resource());

        // Single param with percent-encoding
        req.set_param("action", "delete%20user");
        check(req.param("action") == "delete user", "set_param decoded percent sequence");

        // Additional param triggering buffer growth and rebase
        req.set_param("filter", "name%3Dadmin%26active%3Dtrue");
        check(req.param("action") == "delete user", "prior param remained valid after rebase");
        check(req.param("filter") == "name=admin&active=true", "second param decoded correctly");

        // Non-encoded param
        req.set_param("plain", "simple_value");
        check(req.param("plain") == "simple_value", "plain param stored correctly");
    }

    arena.release();
}

// ─── Test: Allocator Non-Propagation in Move Assignment (Review Issue 7) ──────

void test_move_assignment_pmr_allocator_consistency() {
    wavex::memory::RequestArena arena_src;
    wavex::memory::RequestArena arena_dst;

    {
        wavex::protos::http::Http1Request req_src(arena_src.resource());
        req_src.set_param("title", "Modern%20C%2B%2B23");
        check(req_src.param("title") == "Modern C++23", "src param set");

        wavex::protos::http::Http1Request req_dst(arena_dst.resource());
        // Move-assign req_dst = std::move(req_src)
        req_dst = std::move(req_src);

        // Verify req_dst remains consistent and views valid
        check(req_dst.param("title") == "Modern C++23", "moved param remains valid in dst");
    }

    arena_src.release();
    arena_dst.release();
}

// ─── Test: set_params with >32 route params (Issue 4 non-throwing callback) ──

void test_set_params_large_route_params() {
    wavex::memory::RequestArena arena;
    {
        wavex::protos::http::Http1Request req(arena.resource());

        wavex::base::FlatMap<std::string_view, std::string_view> route_params;
        // Insert 40 parameters (exceeds 32-entry threshold)
        std::string keys[40];
        std::string vals[40];
        for (int i = 0; i < 40; ++i) {
            keys[i] = "param_" + std::to_string(i);
            vals[i] = (i % 2 == 0) ? ("val%20" + std::to_string(i)) : ("raw_" + std::to_string(i));
            route_params.insert_or_assign(keys[i], vals[i]);
        }

        req.set_params(route_params);

        check(req.param("param_0") == "val 0", "param_0 decoded with percent encoding");
        check(req.param("param_1") == "raw_1", "param_1 raw preserved");
        check(req.param("param_35") == "raw_35", "param_35 beyond 32 slices inserted successfully");
        check(req.param("param_38") == "val 38", "param_38 beyond 32 slices decoded successfully");
    }

    arena.release();
}

// ─────────────────────────────────────────────────────────────────────────────

// ─── Test: RequestArena is a movable handle with a stable resource ───────────

void test_request_arena_move_semantics() {
    static_assert(std::is_nothrow_move_constructible_v<wavex::memory::RequestArena>);
    static_assert(std::is_nothrow_move_assignable_v<wavex::memory::RequestArena>);
    static_assert(!std::is_copy_constructible_v<wavex::memory::RequestArena>);
    static_assert(!std::is_copy_assignable_v<wavex::memory::RequestArena>);

    wavex::memory::ConnectionMemoryPool conn_pool;

    // Move construction: resource() address is unchanged, earlier allocations stay valid.
    {
        wavex::memory::RequestArena a(conn_pool.resource());
        std::pmr::memory_resource *const mr = a.resource();
        auto *bytes = static_cast<unsigned char *>(mr->allocate(256, 8));
        std::memset(bytes, 0x5A, 256);

        wavex::memory::RequestArena b(std::move(a));
        check(b.resource() == mr, "move-constructed arena keeps the same resource address");
        check(a.resource() == nullptr, "moved-from arena has no resource");
        a.release(); // must be a harmless no-op
        check(bytes[0] == 0x5A && bytes[255] == 0x5A, "allocation made before the move stays valid");

        // Objects created after the move must be destroyed before b (declared after b).
        std::pmr::string s("a string long enough to bypass the small string optimisation", b.resource());
        check(s.size() > 32, "pmr::string allocates from the moved arena");
    }

    // Move assignment: previous resource is destroyed, the source's resource is adopted.
    {
        wavex::memory::RequestArena x(conn_pool.resource());
        (void) x.resource()->allocate(128, 8);
        wavex::memory::RequestArena y(conn_pool.resource());
        std::pmr::memory_resource *const ry = y.resource();

        x = std::move(y);
        check(x.resource() == ry, "move-assigned arena adopts the source resource");
        check(y.resource() == nullptr, "move-assignment source is left empty");
    }

    // Moved arena travels with a request and is released by its destructor.
    {
        auto make_arena = [&] { return wavex::memory::RequestArena(conn_pool.resource()); };
        wavex::memory::RequestArena arena = make_arena();
        wavex::protos::http::Http1Request req(arena.resource());
        req.set_param("k", "a%20b");
        check(req.param("k") == "a b", "request on a returned (moved) arena works");
    }

    conn_pool.release();
    check(true, "arena control blocks returned to the connection pool");
}

int main() {
    std::cout << "\n=== RequestArena Unit Tests ===\n" << std::endl;

    std::cout << "[START] test_inline_allocation" << std::endl;
    test_inline_allocation();
    std::cout << "[START] test_release_and_reuse" << std::endl;
    test_release_and_reuse();
    std::cout << "[START] test_sequential_cycles" << std::endl;
    test_sequential_cycles();
    std::cout << "[START] test_large_allocation_overflow" << std::endl;
    test_large_allocation_overflow();
    std::cout << "[START] test_make_in_arena" << std::endl;
    test_make_in_arena();
    std::cout << "[START] test_thread_local_pool_accessible" << std::endl;
    test_thread_local_pool_accessible();
    std::cout << "[START] test_request_and_response_arena_wiring" << std::endl;
    test_request_and_response_arena_wiring();
    std::cout << "[START] test_http3_request_arena_wiring" << std::endl;
    test_http3_request_arena_wiring();
    std::cout << "[START] test_connection_memory_pool" << std::endl;
    test_connection_memory_pool();
    test_connection_memory_pool_release_and_reuse();
    std::cout << "[START] test_multi_worker_thread_safety_f2" << std::endl;
    test_multi_worker_thread_safety_f2();
    std::cout << "[START] test_decode_to_comprehensive_i03" << std::endl;
    test_decode_to_comprehensive_i03();
    std::cout << "[START] test_cross_arena_request_move_i02" << std::endl;
    test_cross_arena_request_move_i02();
    std::cout << "[START] test_lifetime_separation_f3" << std::endl;
    test_lifetime_separation_f3();
    std::cout << "[START] test_serialize_into_direct_sink" << std::endl;
    test_serialize_into_direct_sink();
    std::cout << "[START] test_lazy_arena_and_pool_release" << std::endl;
    test_lazy_arena_and_pool_release();
    std::cout << "[START] test_set_param_percent_decoding" << std::endl;
    test_set_param_percent_decoding();
    std::cout << "[START] test_move_assignment_pmr_allocator_consistency" << std::endl;
    test_move_assignment_pmr_allocator_consistency();
    std::cout << "[START] test_set_params_large_route_params" << std::endl;
    test_set_params_large_route_params();
    std::cout << "[START] test_request_arena_move_semantics" << std::endl;
    test_request_arena_move_semantics();

    std::cout << "\n" << tests_passed << "/" << tests_run << " tests passed." << std::endl;
    return tests_passed == tests_run ? 0 : 1;
}

