/**
 * @file test_executor.cpp
 * @brief Tests for the executor seam: wavex::executor helpers and the server/worker executor accessors.
 */

#include <wavex/Base/Executor.hpp>
#include <wavex/Base/Task.hpp>
#include <wavex/Server/ThreadPool.hpp>

#include <asio/post.hpp>
#include <asio/thread_pool.hpp>

#include <atomic>
#include <chrono>
#include <iostream>
#include <thread>
#include <type_traits>

// wavex::task<T> is the same type as asio::awaitable<T> (no conversion, full interoperability).
static_assert(std::is_same_v<wavex::task<int>, asio::awaitable<int> >);
static_assert(std::is_same_v<wavex::task<>, asio::awaitable<void> >);

namespace {
    int tests_run{0};
    int tests_failed{0};

    void check(const bool condition, const char *name) {
        ++tests_run;
        if (!condition) ++tests_failed;
        std::cout << (condition ? "  [PASS] " : "  [FAIL] ") << name << "\n";
    }

    void test_running_in_this_thread() {
        asio::io_context io;
        const wavex::executor ex = wavex::executor_of(io);
        const wavex::executor sx = asio::make_strand(io);

        check(!wavex::running_in_this_thread(ex), "io_context executor: false outside run()");
        check(!wavex::running_in_this_thread(sx), "strand executor: false outside run()");

        bool in_ex = false, in_sx = false;
        asio::post(sx, [&] {
            in_ex = wavex::running_in_this_thread(ex);
            in_sx = wavex::running_in_this_thread(sx);
        });
        io.run();
        check(in_ex, "io_context executor: true inside a handler");
        check(in_sx, "strand executor: true inside a strand handler");
    }

    void test_foreign_executor_is_unknown() {
        asio::thread_pool pool(1);
        const wavex::executor ex = pool.get_executor();
        std::atomic<bool> inside{true};
        std::atomic<bool> done{false};
        asio::post(ex, [&] {
            inside = wavex::running_in_this_thread(ex);
            done = true;
        });
        for (int i = 0; i < 200 && !done; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));
        check(done, "thread_pool executor runs the handler");
        check(!inside, "thread_pool executor: unknown reports false (callers fall back to post)");
        check(!wavex::context_stopped(ex), "thread_pool executor: context_stopped is false (unknown)");
        pool.join();
    }

    void test_context_stopped() {
        asio::io_context io;
        const wavex::executor ex = wavex::executor_of(io);
        check(!wavex::context_stopped(ex), "fresh io_context is not stopped");
        io.stop();
        check(wavex::context_stopped(ex), "stopped io_context reports stopped");
        io.restart();
        check(!wavex::context_stopped(ex), "restarted io_context is not stopped");
    }

    void test_worker_lease_executor() {
        wavex::server::ThreadPool pool;
        auto lease = pool.lease_worker();
        check(static_cast<bool>(lease), "pool hands out a worker lease");
        if (!lease) return;
        const wavex::executor ex = lease.executor();
        check(ex == wavex::executor(lease.context().get_executor()), "lease.executor() is the worker's io_context");

        std::atomic<bool> ran{false};
        asio::post(ex, [&] { ran = true; });
        for (int i = 0; i < 200 && !ran; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));
        check(ran, "a handler posted to lease.executor() runs on the worker");
    }
}

int main() {
    std::cout << "[Test executor]\n";
    test_running_in_this_thread();
    test_foreign_executor_is_unknown();
    test_context_stopped();
    test_worker_lease_executor();
    std::cout << tests_run - tests_failed << "/" << tests_run << " passed\n";
    return tests_failed == 0 ? 0 : 1;
}
