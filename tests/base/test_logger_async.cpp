#include <wavex/wavex.hpp>
#include <iostream>
#include <sstream>
#include <cassert>
#include <string>
#include <thread>
#include <vector>

void test_async_basic_and_flush() {
    std::cout << "[Test] Running test_async_basic_and_flush...\n";
    std::ostringstream oss;
    auto &logger = wavex::base::Logger::instance();
    
    wavex::base::LoggerConfig cfg{
        .pool_capacity = 512,
        .max_pool_capacity = 1024,
        .flush_interval = std::chrono::milliseconds(20),
        .overflow_policy = wavex::base::OverflowPolicy::Drop,
        .async_mode = true
    };
    logger.configure(cfg);
    logger.set_output(oss);
    logger.set_colored(false);
    logger.set_level(wavex::base::LogLevel::TRACE);
    logger.set_async(true);

    for (int i = 0; i < 50; ++i) {
        wxlog::info("Async message #{}: status={}", i, 200 + i);
    }

    wxlog::flush();

    std::string out = oss.str();
    assert(out.find("Async message #0: status=200") != std::string::npos);
    assert(out.find("Async message #49: status=249") != std::string::npos);

    // Restore sink before local oss is destructed
    logger.set_output(std::cerr);
    std::cout << "  -> test_async_basic_and_flush PASSED\n";
}

void test_async_multithreaded_stress() {
    std::cout << "[Test] Running test_async_multithreaded_stress (16 threads)...\n";
    std::ostringstream oss;
    auto &logger = wavex::base::Logger::instance();
    
    wavex::base::LoggerConfig cfg{
        .pool_capacity = 4096,
        .max_pool_capacity = 8192,
        .flush_interval = std::chrono::milliseconds(10),
        .overflow_policy = wavex::base::OverflowPolicy::Block,
        .async_mode = true
    };
    logger.configure(cfg);
    logger.set_output(oss);
    logger.set_colored(false);
    logger.set_level(wavex::base::LogLevel::INFO);
    logger.set_async(true);

    constexpr int kThreads = 16;
    constexpr int kLogsPerThread = 200;
    std::vector<std::thread> workers;
    workers.reserve(kThreads);

    for (int t = 0; t < kThreads; ++t) {
        workers.emplace_back([t] {
            for (int i = 0; i < kLogsPerThread; ++i) {
                if (i % 3 == 0) {
                    wxlog::info("Worker {} log {}", t, i);
                } else if (i % 3 == 1) {
                    wxlog::warn("Worker {} warning {}", t, i);
                } else {
                    wxlog::error("Worker {} error {}", t, i);
                }
            }
        });
    }

    for (auto &t : workers) {
        t.join();
    }

    wxlog::flush();

    std::string out = oss.str();
    assert(!out.empty());
    assert(logger.dropped_count() == 0);

    // Restore sink before local oss is destructed
    logger.set_output(std::cerr);
    std::cout << "  -> test_async_multithreaded_stress PASSED\n";
}

namespace {
// Stringbuf whose writes are slow, so the async worker reliably lags the producer.
// Without it the worker drains faster than the test can fill the queue and the
// overflow assertions become timing-dependent.
class SlowStringBuf : public std::stringbuf {
protected:
    std::streamsize xsputn(const char *s, std::streamsize n) override {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        return std::stringbuf::xsputn(s, n);
    }
};

struct SlowStream {
    SlowStringBuf buf;
    std::ostream os{&buf};
    [[nodiscard]] std::string str() const { return buf.str(); }
};
} // namespace

void test_priority_headroom_reservation() {
    std::cout << "[Test] Running test_priority_headroom_reservation...\n";
    SlowStream oss;
    auto &logger = wavex::base::Logger::instance();

    // Small pool capacity of 30 items:
    // Soft cap (90%) = 27 items.
    // Capacity = 30 items.
    // Reserve headroom = 3 items (WARN, ERR, FATAL only).
    wavex::base::LoggerConfig cfg{
        .pool_capacity = 30,
        .max_pool_capacity = 30,
        .flush_interval = std::chrono::milliseconds(500),
        .overflow_policy = wavex::base::OverflowPolicy::Drop,
        .async_mode = true
    };
    logger.configure(cfg);
    logger.set_output(oss.os);
    logger.set_colored(false);
    logger.set_level(wavex::base::LogLevel::INFO);
    logger.set_async(true);

    // Rapid burst of 40 INFO logs to saturate queue past soft cap and capacity
    for (int i = 0; i < 40; ++i) {
        wxlog::info("Burst info message {}", i);
    }

    // Now emit priority records
    wxlog::warn("Priority alert: critical disk temperature");
    wxlog::error("Priority error: upstream service unavailable");

    wxlog::flush();

    std::string out = oss.str();
    // Verify that priority messages made it through the reserved headroom
    assert(out.find("Priority alert: critical disk temperature") != std::string::npos);
    assert(out.find("Priority error: upstream service unavailable") != std::string::npos);
    // Verify that at least some non-priority burst messages were dropped
    assert(logger.dropped_count() > 0);

    // Restore sink before local oss is destructed
    logger.set_output(std::cerr);
    std::cout << "  -> test_priority_headroom_reservation PASSED (dropped " 
              << logger.dropped_count() << " items)\n";
}

void test_drop_notification() {
    std::cout << "[Test] Running test_drop_notification...\n";
    SlowStream oss;
    auto &logger = wavex::base::Logger::instance();

    wavex::base::LoggerConfig cfg{
        .pool_capacity = 20,
        .max_pool_capacity = 20,
        .flush_interval = std::chrono::milliseconds(20),
        .overflow_policy = wavex::base::OverflowPolicy::Drop,
        .async_mode = true
    };
    logger.configure(cfg);
    logger.set_output(oss.os);
    logger.set_colored(false);
    logger.set_level(wavex::base::LogLevel::INFO);
    logger.set_async(true);

    // Induce substantial drops
    for (int i = 0; i < 100; ++i) {
        wxlog::info("Flood log payload to trigger drop notice {}", i);
    }

    // Give worker thread time to process and notice drops
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    wxlog::flush();

    std::string out = oss.str();
    assert(out.find("Dropped ") != std::string::npos);
    assert(out.find("messages due to queue overflow") != std::string::npos);

    // Restore sink before local oss is destructed
    logger.set_output(std::cerr);
    std::cout << "  -> test_drop_notification PASSED\n";
}

int main() {
    std::cout << "=== Running Async Logger Unit Tests ===\n";
    test_async_basic_and_flush();
    test_async_multithreaded_stress();
    test_priority_headroom_reservation();
    test_drop_notification();

    // Restore logger to default clean state
    auto &logger = wavex::base::Logger::instance();
    logger.set_output(std::cerr);
    logger.set_colored(true);
    logger.set_level(wavex::base::LogLevel::INFO);

    std::cout << "=== All Async Logger Unit Tests PASSED Successfully! ===\n";
    return 0;
}
