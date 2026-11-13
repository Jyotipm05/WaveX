/**
 * @file test_connection_tracker.cpp
 * @brief ConnectionTracker semantics and lock-striping correctness under concurrency.
 */
#include <wavex/Server/ConnectionTracker.hpp>

#include <atomic>
#include <iostream>
#include <thread>
#include <vector>

using wavex::server::ConnectionTracker;

namespace {
    int run = 0, passed = 0;

    void check(const bool ok, const char *name) {
        ++run;
        if (ok) ++passed;
        std::cout << (ok ? "  [PASS] " : "  [FAIL] ") << name << "\n";
    }
}

int main() {
    std::cout << "=== ConnectionTracker tests ===\n";

    {
        ConnectionTracker t;
        std::atomic<int> cancelled{0}, closed{0};
        const auto a = t.register_socket([&] { ++cancelled; }, [&] { ++closed; });
        const auto b = t.register_socket([&] { ++cancelled; }, [&] { ++closed; });
        const auto c = t.register_socket([&] { ++cancelled; }, [&] { ++closed; });
        check(a != b && b != c && a != c, "ids are unique");
        check(t.count() == 3, "count after register");

        t.mark_idle(a);
        t.mark_idle(b);
        t.mark_active(b);
        t.cancel_all_idle();
        check(cancelled == 1, "only idle sockets are cancelled");
        check(t.count() == 3, "cancel does not unregister");

        t.mark_idle(999999); // unknown id must be ignored
        t.cancel_all_idle();
        check(cancelled == 1, "unknown id is not tracked as idle");

        t.unregister_socket(c);
        check(t.count() == 2, "unregister removes");

        t.force_close_all();
        check(closed == 2 && t.count() == 0, "force_close_all closes everything and empties the tracker");
    }

    {
        // Callbacks run outside the stripe locks, so re-entering the tracker must not deadlock.
        ConnectionTracker t;
        uint64_t id = 0;
        id = t.register_socket([&] { t.unregister_socket(id); }, [&] { t.unregister_socket(id); });
        t.mark_idle(id);
        t.cancel_all_idle();
        check(t.count() == 0, "re-entrant callback does not deadlock");
    }

    {
        ConnectionTracker t;
        constexpr int kThreads = 8, kIters = 20000;
        std::atomic<long> cancels{0};
        std::vector<std::thread> ts;
        for (int i = 0; i < kThreads; ++i) {
            ts.emplace_back([&] {
                for (int n = 0; n < kIters; ++n) {
                    const auto id = t.register_socket([&] { ++cancels; }, [] {});
                    t.mark_idle(id);
                    t.mark_active(id);
                    t.mark_idle(id);
                    t.unregister_socket(id);
                }
            });
        }
        std::thread sweeper([&] {
            for (int n = 0; n < 200; ++n) {
                t.cancel_all_idle();
                (void) t.count();
            }
        });
        for (auto &th : ts) th.join();
        sweeper.join();
        check(t.count() == 0, "concurrent register/unregister leaves no residue");
    }

    std::cout << "\n" << passed << "/" << run << " tests passed.\n";
    return passed == run ? 0 : 1;
}
