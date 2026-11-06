// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Prototype: can an own task type get its child-coroutine frames elided (HALO)?
//
// `etask<T>` is a minimal lazy task (symmetric transfer, no executor) marked [[clang::coro_await_elidable]].
// The benchmark counts heap allocations while a coroutine awaits a chain of small child coroutines.
// Build (Clang 20+ for the attribute; GCC and older Clang just build it without elision):
//     clang++ -std=c++23 -O2 benchmarks/task_elision.cpp -o task_elision && ./task_elision
// See docs/task-elision.md for the numbers.

#include <chrono>
#include <coroutine>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <new>
#include <utility>

#if defined(__clang__) && __has_cpp_attribute(clang::coro_await_elidable)
#define WAVEX_CORO_ELIDABLE [[clang::coro_await_elidable]]
#define WAVEX_CORO_ELIDABLE_ARG [[clang::coro_await_elidable_argument]]
#define HAVE_ELIDE 1
#else
#define WAVEX_CORO_ELIDABLE
#define WAVEX_CORO_ELIDABLE_ARG
#define HAVE_ELIDE 0
#endif

static unsigned long g_allocs = 0;
void *operator new(const std::size_t n) {
    ++g_allocs;
    if (void *p = std::malloc(n)) return p;
    throw std::bad_alloc{};
}
void operator delete(void *p) noexcept { std::free(p); }
void operator delete(void *p, std::size_t) noexcept { std::free(p); }

template<typename T>
class WAVEX_CORO_ELIDABLE etask {
public:
    struct promise_type {
        T value{};
        std::coroutine_handle<> cont{std::noop_coroutine()};
        etask get_return_object() noexcept { return etask{std::coroutine_handle<promise_type>::from_promise(*this)}; }
        std::suspend_always initial_suspend() const noexcept { return {}; }
        struct fin {
            bool await_ready() const noexcept { return false; }
            std::coroutine_handle<> await_suspend(std::coroutine_handle<promise_type> h) const noexcept { return h.promise().cont; }
            void await_resume() const noexcept {}
        };
        fin final_suspend() const noexcept { return {}; }
        void return_value(T v) noexcept { value = std::move(v); }
        void unhandled_exception() { std::terminate(); }
    };

    etask(etask &&o) noexcept : h_(std::exchange(o.h_, {})) {}
    ~etask() { if (h_) h_.destroy(); }

    bool await_ready() const noexcept { return false; }
    std::coroutine_handle<> await_suspend(std::coroutine_handle<> c) noexcept {
        h_.promise().cont = c;
        return h_;
    }
    T await_resume() { return std::move(h_.promise().value); }

    /// Runs the task to completion (it never really suspends in this benchmark).
    T sync() {
        h_.resume();
        return std::move(h_.promise().value);
    }

private:
    explicit etask(std::coroutine_handle<promise_type> h) noexcept : h_(h) {}
    std::coroutine_handle<promise_type> h_;
};

// A leaf like many handler helpers: small, never suspends.
etask<int> leaf(WAVEX_CORO_ELIDABLE_ARG int x) { co_return x + 1; }
etask<int> middle(WAVEX_CORO_ELIDABLE_ARG int x) {
    int a = co_await leaf(x);
    int b = co_await leaf(a);
    co_return a + b;
}
etask<int> top(int n) {
    int sum = 0;
    for (int i = 0; i < n; ++i) sum += co_await middle(i);
    co_return sum;
}

int main() {
    constexpr int N = 1'000'000;
    const auto t0 = std::chrono::steady_clock::now();
    const unsigned long before = g_allocs;
    const int r = top(N).sync();
    const auto t1 = std::chrono::steady_clock::now();
    const double ns = std::chrono::duration<double, std::nano>(t1 - t0).count() / N;
    std::printf("elision attribute: %s | result %d | %.2f heap allocations per outer iteration (3 child coroutines) | %.1f ns per iteration\n",
                HAVE_ELIDE ? "yes" : "no", r, static_cast<double>(g_allocs - before) / N, ns);
    return 0;
}
