#include <cassert>
#include <chrono>
#include <exception>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>

#include <wavex/Async/SpawnBlocking.hpp>
#include <wavex/Server/BlockingPool.hpp>

void test_blocking_thread_pool_basic() {
    std::cout << "[Test 1] BlockingThreadPool basic dispatch & execution...\n";
    wavex::server::BlockingThreadPool pool(2, 4);

    std::atomic<int> counter{0};
    const int total_tasks = 20;

    for (int i = 0; i < total_tasks; ++i) {
        pool.dispatch([&counter] {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            counter.fetch_add(1, std::memory_order_relaxed);
        });
    }

    // Wait for tasks to complete
    auto start = std::chrono::steady_clock::now();
    while (counter.load(std::memory_order_relaxed) < total_tasks) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        if (std::chrono::steady_clock::now() - start > std::chrono::seconds(5)) {
            assert(false && "Timeout waiting for BlockingThreadPool tasks");
        }
    }

    assert(counter.load() == total_tasks);
    assert(pool.thread_count() >= 2);
    std::cout << "  [PASS] All " << total_tasks << " tasks executed successfully.\n";
}

void test_spawn_blocking_coroutine() {
    std::cout << "[Test 2] wavex::spawn_blocking coroutine offload & resumption...\n";

    asio::io_context io;
    std::thread::id io_thread_id;
    std::thread::id blocking_thread_id;
    int computed_result = 0;
    bool exception_caught = false;

    auto test_coro = [&]() -> asio::awaitable<void> {
        io_thread_id = std::this_thread::get_id();

        // 1. Offload heavy computation
        int val = co_await wavex::spawn_blocking([&]() -> int {
            blocking_thread_id = std::this_thread::get_id();
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            return 42 * 2;
        });

        // Coroutine must resume on the io_context thread!
        assert(std::this_thread::get_id() == io_thread_id);
        assert(blocking_thread_id != io_thread_id);
        computed_result = val;

        // 2. Test void-returning callable
        co_await wavex::spawn_blocking([]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        });
        assert(std::this_thread::get_id() == io_thread_id);

        // 3. Test exception propagation back to coroutine
        try {
            co_await wavex::spawn_blocking([]() -> int {
                throw std::runtime_error("Simulated crypto failure");
            });
        } catch (const std::runtime_error &e) {
            if (std::string(e.what()) == "Simulated crypto failure") {
                exception_caught = true;
            }
        }
        assert(std::this_thread::get_id() == io_thread_id);

        co_return;
    };

    asio::co_spawn(io, test_coro(), asio::detached);
    io.run();

    assert(computed_result == 84);
    assert(exception_caught);
    std::cout << "  [PASS] spawn_blocking returned " << computed_result 
              << " and resumed caller thread correctly. Exceptions propagated safely.\n";
}

int main() {
    std::cout << "=== Running WaveX spawn_blocking Tests ===\n";
    try {
        test_blocking_thread_pool_basic();
        test_spawn_blocking_coroutine();
        std::cout << "=== All spawn_blocking Tests PASSED ===\n";
        return 0;
    } catch (const std::exception &ex) {
        std::cerr << "[FAIL] Unexpected exception: " << ex.what() << "\n";
        return 1;
    }
}
