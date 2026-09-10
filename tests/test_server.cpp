/**
 * @file test_server.cpp
 * @brief Unit & integration tests for HttpResponse, WorkStealingQueue, ThreadPool, and Server.
 */

#include <wavex/wavex.hpp>

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>

namespace {
    int tests_run = 0;
    int tests_passed = 0;

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

// ─── Test 1: HttpResponse Serialization ───────────────────────────────────────

void test_http_response_serialization() {
    std::cout << "\n[Test 1] HttpResponse serialization & fluent API\n";

    wavex::protos::http::Http1Response res;
    res.status(200).set("X-Custom-Header", "WaveXValue").send("Hello Server");

    check(res.status_code() == 200, "Status code is 200");
    check(res.get_body() == "Hello Server", "Body equals 'Hello Server'");
    check(res.has_header("X-Custom-Header"), "Has header 'X-Custom-Header'");

    std::string wire = res.serialize();
    check(wire.starts_with("HTTP/1.1 200 OK\r\n"), "Serialized status line matches HTTP/1.1 200 OK");
    check(wire.find("X-Custom-Header: WaveXValue\r\n") != std::string::npos, "Serialized output contains header");
    check(wire.find("Content-Length: 12\r\n") != std::string::npos, "Serialized output contains Content-Length: 12");
    check(wire.ends_with("Hello Server"), "Serialized wire ends with body 'Hello Server'");

    wavex::protos::http::Http1Response json_res;
    nlohmann::json j = {{"status", "ok"}, {"count", 42}};
    json_res.status(201).json(j);

    std::string json_wire = json_res.serialize();
    check(json_res.status_code() == 201, "JSON response status is 201");
    check(json_wire.find("Content-Type: application/json\r\n") != std::string::npos, "JSON header set automatically");
}

// ─── Test 2: LocalQueue & InjectorQueue Operations ───────────────────────────

void test_work_stealing_queue() {
    std::cout << "\n[Test 2] LocalQueue (ring buffer) push, pop, steal, drain_all\n";

    wavex::server::LocalQueue lq;
    int counter = 0;

    check(lq.push([&counter] { counter += 10; }), "Push task 1 (10)");
    check(lq.push([&counter] { counter += 20; }), "Push task 2 (20)");
    check(lq.push([&counter] { counter += 30; }), "Push task 3 (30)");

    check(lq.size() == 3, "LocalQueue size is 3");

    // Pop (LIFO order — owner thread takes from back)
    auto task1 = lq.pop();
    check(task1.has_value(), "Task popped by owner (LIFO)");
    if (task1) (*task1)();
    check(counter == 30, "LIFO task 3 executed (+30)");

    // Steal (FIFO order — thief takes from front)
    auto stolen_task = lq.steal();
    check(stolen_task.has_value(), "Task stolen by thief (FIFO)");
    if (stolen_task) (*stolen_task)();
    check(counter == 40, "FIFO stolen task 1 executed (+10)");

    // Drain remaining
    check(lq.push([&counter] { counter += 100; }), "Push extra task for drain");
    auto drained = lq.drain_all();
    check(lq.empty(), "LocalQueue empty after drain_all()");
    check(drained.size() == 2, "Drained 2 remaining tasks (task2 + extra)");
    for (auto &t: drained) t();
    check(counter == 160, "Executed drained tasks (+20 +100 -> 160 total)");

    std::cout << "\n[Test 2b] InjectorQueue push / pop (global MPMC)\n";

    wavex::server::InjectorQueue inj;
    check(inj.empty(), "InjectorQueue starts empty");

    int inj_counter = 0;
    inj.push([&inj_counter] { inj_counter += 1; });
    inj.push([&inj_counter] { inj_counter += 2; });
    inj.push([&inj_counter] { inj_counter += 3; });

    check(inj.size() == 3, "InjectorQueue size is 3");

    // FIFO order
    if (auto t = inj.pop()) (*t)();
    check(inj_counter == 1, "InjectorQueue FIFO: first task (+1)");
    if (auto t = inj.pop()) (*t)();
    check(inj_counter == 3, "InjectorQueue FIFO: second task (+2)");
    if (auto t = inj.pop()) (*t)();
    check(inj_counter == 6, "InjectorQueue FIFO: third task (+3)");

    std::cout << "\n[Test 2c] LocalQueue steal_half (half-batch work stealing)\n";
    wavex::server::LocalQueue victim_lq;
    wavex::server::LocalQueue thief_lq;

    int batch_sum = 0;
    for (int i = 1; i <= 10; ++i) {
        (void) victim_lq.push([&batch_sum, i] { batch_sum += i; });
    }
    check(victim_lq.size() == 10, "Victim LocalQueue initialized with 10 tasks");
    check(thief_lq.empty(), "Thief LocalQueue starts empty");

    // Thief steals half from victim (steal_count = (10 + 1) / 2 = 5)
    auto immediate_stolen = victim_lq.steal_half(thief_lq);
    check(immediate_stolen.has_value(), "steal_half returned 1 task for immediate execution");
    if (immediate_stolen) (*immediate_stolen)();
    check(batch_sum == 1, "Immediate stolen task 1 executed (+1)");

    check(victim_lq.size() == 5, "Victim LocalQueue size reduced from 10 to 5");
    check(thief_lq.size() == 4, "Thief LocalQueue populated with 4 stolen batch tasks");

    // Thief pops remaining 4 batch tasks from its own queue
    while (auto t = thief_lq.pop()) {
        (*t)();
    }
    check(thief_lq.empty(), "Thief LocalQueue drained");

    // Victim pops its remaining 5 tasks
    while (auto t = victim_lq.pop()) {
        (*t)();
    }
    check(victim_lq.empty(), "Victim LocalQueue drained");

    check(batch_sum == 55, "All 10 tasks executed correctly across victim and thief (sum == 55)");
    check(inj.empty(), "InjectorQueue empty after all pops");
}

// ─── Test 3: ThreadPoolConfig Singleton Customization ───────────────────────

void test_thread_pool_config_singleton() {
    std::cout << "\n[Test 3] ThreadPoolConfig singleton customization\n";

    auto &config = wavex::server::ThreadPoolConfig::instance();
    config.set_limits(2, 6);

    check(config.min_workers == 2, "Config min_workers set to 2");
    check(config.max_workers == 6, "Config max_workers set to 6");
    check(config.upper_thresholds.size() >= 5, "Upper threshold table sized appropriately for max 6 threads");
    check(config.lower_thresholds.size() >= 5, "Lower threshold table sized appropriately for max 6 threads");
}

// ─── Test 4: ThreadPool Execution & Dynamic Scaling ───────────────────────────

void test_thread_pool_execution_and_scaling() {
    std::cout << "\n[Test 4] ThreadPool execution, work-stealing & scaling\n";

    auto &config = wavex::server::ThreadPoolConfig::instance();
    config.set_limits(2, 4);
    config.upper_thresholds = {2, 5, 10};
    config.lower_thresholds = {1, 2, 4};

    wavex::server::ThreadPool pool(config);

    check(pool.worker_count() >= 2, "Initial worker count is at least min_workers (2)");

    std::atomic<int> executed_count{0};
    constexpr int total_tasks = 20;

    for (int i = 0; i < total_tasks; ++i) {
        pool.dispatch([&executed_count] {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            executed_count.fetch_add(1);
        });
    }

    // Give pool time to execute tasks and run scaling evaluation
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    check(executed_count.load() == total_tasks, "All 20 dispatched tasks executed cleanly");

    // Force scale evaluation after workload drops
    pool.evaluate_scaling();
    std::this_thread::sleep_for(std::chrono::milliseconds(90));

    check(pool.worker_count() <= 4, "Worker count is bounded within max_workers limit (<= 4)");
}

// ─── Test 5: Cache Line Alignment Verification ────────────────────────────────

void test_cache_line_alignment() {
    std::cout << "\n[Test 5] LocalQueue & InjectorQueue cache-line (64-byte) alignment verification\n";

    check(alignof(wavex::server::LocalQueue) >= 64, "LocalQueue alignment is at least 64 bytes");
    check(alignof(wavex::server::InjectorQueue) >= 64, "InjectorQueue alignment is at least 64 bytes");
}

// ─── Test 6: Proportional Hysteresis Scaling ─────────────────────────────────

void test_proportional_hysteresis_scaling() {
    std::cout << "\n[Test 6] Proportional Hysteresis Step Scaling & Cooldown Buffer\n";

    auto &config = wavex::server::ThreadPoolConfig::instance();
    config.set_limits(1, 16);
    config.scale_up_divider = 2;
    config.scale_down_cooldown_cycles = 3;
    config.check_interval = std::chrono::seconds(10); // Pause background monitor auto-ticks during manual testing
    config.upper_thresholds = {5, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140};
    config.lower_thresholds = {2, 4, 8, 15, 25, 35, 45, 55, 65, 75, 85, 95, 105, 115, 125};

    wavex::server::ThreadPool pool(config);
    check(pool.worker_count() == 1, "Initial worker count is 1 (min_workers)");

    // Dispatch tasks to create load and trigger proportional scale-up
    std::atomic<int> completed{0};
    for (int i = 0; i < 25; ++i) {
        pool.dispatch([&completed] {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            completed.fetch_add(1);
        });
    }

    // Force scale evaluation while load is active
    pool.evaluate_scaling();
    check(pool.worker_count() > 1, "Proportional scale-up increased worker count above min_workers");

    const std::size_t scaled_workers = pool.worker_count();

    // Wait for all tasks to complete
    while (completed.load() < 25) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    // Test Scale-Down Cooldown Hysteresis
    check(pool.cooldown_counter() == 0, "Cooldown counter starts at 0 before low-load evaluation");

    // Evaluation 1 under zero load: counter increments to 1, worker count unchanged
    pool.evaluate_scaling();
    check(pool.cooldown_counter() == 1, "Cooldown counter incremented to 1 on low load check");
    check(pool.worker_count() == scaled_workers, "Worker count retained during cooldown cycle 1");

    // Evaluation 2 under zero load: counter increments to 2, worker count unchanged
    pool.evaluate_scaling();
    check(pool.cooldown_counter() == 2, "Cooldown counter incremented to 2 on second low load check");
    check(pool.worker_count() == scaled_workers, "Worker count retained during cooldown cycle 2");

    // Evaluation 3 under zero load: cooldown reached (3/3), resets counter & decommissions 1 worker
    pool.evaluate_scaling();
    check(pool.cooldown_counter() == 0, "Cooldown counter reset to 0 after triggering scale-down");
    check(pool.worker_count() == scaled_workers - 1, "Worker count reduced by 1 after 3 consecutive low load checks");

    // Reset check_interval for subsequent tests
    config.check_interval = std::chrono::milliseconds(100);
}

// ─── main ─────────────────────────────────────────────────────────────────────

int main() {
    std::cout << "=== WaveX Server, HttpResponse & ThreadPool Unit Tests ===\n";

    test_http_response_serialization();
    test_work_stealing_queue();
    test_thread_pool_config_singleton();
    test_thread_pool_execution_and_scaling();
    test_cache_line_alignment();
    test_proportional_hysteresis_scaling();

    std::cout << "\n" << tests_passed << "/" << tests_run << " tests passed.\n";
    return tests_passed == tests_run ? 0 : 1;
}
