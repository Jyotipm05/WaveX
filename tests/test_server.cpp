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
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/steady_timer.hpp>

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

// ─── Test 1b: HttpResponse Redirect API ───────────────────────────────────────

void test_http_response_redirect() {
    std::cout << "\n[Test 1b] HttpResponse redirect & fluent API\n";

    // 1. Default redirect (302 Found)
    wavex::protos::http::Http1Response res_default;
    res_default.redirect("/dashboard");
    check(res_default.status_code() == 302, "Default redirect status is 302");
    check(res_default.is_sent(), "Default redirect marks response as sent");
    check(res_default.get_body().empty(), "Default redirect has empty body");
    std::string wire_default = res_default.serialize();
    check(wire_default.starts_with("HTTP/1.1 302 Found\r\n"), "Serialized status line matches 302 Found");
    check(wire_default.find("Location: /dashboard\r\n") != std::string::npos, "Location header present for /dashboard");

    // 2. Custom status redirect (307 Temporary Redirect)
    wavex::protos::http::Http1Response res_307;
    res_307.redirect("/login", 307);
    check(res_307.status_code() == 307, "Custom redirect status is 307");
    std::string wire_307 = res_307.serialize();
    check(wire_307.starts_with("HTTP/1.1 307 Temporary Redirect\r\n"), "Serialized status line matches 307 Temporary Redirect");
    check(wire_307.find("Location: /login\r\n") != std::string::npos, "Location header present for /login");

    // 3. Express/Fastify-style overload: redirect(code, url)
    wavex::protos::http::Http1Response res_overload;
    res_overload.redirect(303, "/other");
    check(res_overload.status_code() == 303, "Reversed argument redirect status is 303");
    std::string wire_303 = res_overload.serialize();
    check(wire_303.starts_with("HTTP/1.1 303 See Other\r\n"), "Serialized status line matches 303 See Other");
    check(wire_303.find("Location: /other\r\n") != std::string::npos, "Location header present for /other");

    // 4. Permanent redirect (default: 301 Moved Permanently)
    wavex::protos::http::Http1Response res_perm;
    res_perm.permanent_redirect("/new-home");
    check(res_perm.status_code() == 301, "permanent_redirect default status is 301");
    std::string wire_perm = res_perm.serialize();
    check(wire_perm.starts_with("HTTP/1.1 301 Moved Permanently\r\n"), "Serialized status line matches 301 Moved Permanently");
    check(wire_perm.find("Location: /new-home\r\n") != std::string::npos, "Location header present for /new-home");

    // 5. Permanent redirect with preserve_method = true (308 Permanent Redirect)
    wavex::protos::http::Http1Response res_perm_preserve;
    res_perm_preserve.permanent_redirect("/new-api", true);
    check(res_perm_preserve.status_code() == 308, "permanent_redirect(true) status is 308");
    std::string wire_308 = res_perm_preserve.serialize();
    check(wire_308.starts_with("HTTP/1.1 308 Permanent Redirect\r\n"), "Serialized status line matches 308 Permanent Redirect");
    check(wire_308.find("Location: /new-api\r\n") != std::string::npos, "Location header present for /new-api");

    // 6. Temporary redirect (default: 302 Found)
    wavex::protos::http::Http1Response res_temp;
    res_temp.temporary_redirect("/temp-page");
    check(res_temp.status_code() == 302, "temporary_redirect default status is 302");
    std::string wire_temp = res_temp.serialize();
    check(wire_temp.starts_with("HTTP/1.1 302 Found\r\n"), "Serialized status line matches 302 Found");
    check(wire_temp.find("Location: /temp-page\r\n") != std::string::npos, "Location header present for /temp-page");

    // 7. Temporary redirect with preserve_method = true (307 Temporary Redirect)
    wavex::protos::http::Http1Response res_temp_preserve;
    res_temp_preserve.temporary_redirect("/temp-post", true);
    check(res_temp_preserve.status_code() == 307, "temporary_redirect(true) status is 307");
    std::string wire_temp_307 = res_temp_preserve.serialize();
    check(wire_temp_307.starts_with("HTTP/1.1 307 Temporary Redirect\r\n"), "Serialized status line matches 307 Temporary Redirect");
    check(wire_temp_307.find("Location: /temp-post\r\n") != std::string::npos, "Location header present for /temp-post");
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

// ─── Test 7: Generic Event Pub-Sub & Subscription ────────────────────────────

void test_generic_event_system() {
    std::cout << "\n[Test 7] Generic Event<Args...> pub-sub & RAII Subscription\n";
    wavex::base::Event<int, std::string> ev;
    check(ev.subscriber_count() == 0, "Initial subscriber count is 0");

    int received_int = 0;
    std::string received_msg;

    auto sub1 = ev.subscribe([&](int i, std::string s) {
        received_int = i;
        received_msg = std::move(s);
    });

    check(ev.subscriber_count() == 1, "Subscriber count is 1 after subscription");

    ev.publish(42, "hello event");
    check(received_int == 42, "Received int 42");
    check(received_msg == "hello event", "Received msg 'hello event'");

    int sub2_calls = 0;
    {
        auto sub2 = ev.subscribe([&](int, const std::string &) {
            sub2_calls++;
        });
        check(ev.subscriber_count() == 2, "Subscriber count is 2 with second listener");
        ev.publish(1, "test");
        check(sub2_calls == 1, "Second subscriber called");
    }
    // sub2 went out of scope and unsubscribed automatically via RAII
    check(ev.subscriber_count() == 1, "Subscriber count back to 1 after RAII unsubscribe");

    sub1.unsubscribe();
    check(ev.subscriber_count() == 0, "Subscriber count 0 after explicit unsubscribe");
}

// ─── Test 8: Generic EventBus ────────────────────────────────────────────────

struct UserLoginEvent {
    std::string username;
    int user_id;
};

void test_generic_event_bus() {
    std::cout << "\n[Test 8] Generic EventBus type-safe pub-sub\n";
    wavex::base::EventBus bus;

    std::string logged_in_user;
    int logged_in_id = 0;

    auto sub = bus.subscribe<UserLoginEvent>([&](const UserLoginEvent &e) {
        logged_in_user = e.username;
        logged_in_id = e.user_id;
    });

    check(bus.subscriber_count<UserLoginEvent>() == 1, "Bus subscriber count is 1");

    bus.publish(UserLoginEvent{.username = "alice", .user_id = 101});
    check(logged_in_user == "alice", "Received username alice");
    check(logged_in_id == 101, "Received user_id 101");

    sub.unsubscribe();
    check(bus.subscriber_count<UserLoginEvent>() == 0, "Bus subscriber count is 0 after unsubscribe");
}

// ─── Test 9: Server Graceful Remote Shutdown ──────────────────────────────────

void test_server_graceful_remote_shutdown() {
    std::cout << "\n[Test 9] Server programmatic graceful exit via HTTP route handler\n";

    wavex::engine::Http1Router router;
    wavex::server::Http1Server server(router, "127.0.0.1", 18091);
    server.enable_signal_handling(false);

    router.post("/api/admin/shutdown", [&](wavex::protos::http::Http1Request &, wavex::protos::http::Http1Response &res) -> asio::awaitable<void> {
        res.status(200).send("Shutdown initiated");
        server.exit(std::chrono::seconds(2));
        co_return;
    });

    std::thread srv_th([&server] {
        server.run();
    });

    while (!server.is_running()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    check(server.is_running(), "Server is running on 18091");

    asio::io_context client_ioc;
    bool request_ok = false;
    bool conn_close_found = false;

    asio::co_spawn(client_ioc, [&]() -> asio::awaitable<void> {
        auto res = co_await wavex::client::HttpClient::post("http://127.0.0.1:18091/api/admin/shutdown", "");
        if (res.status_code() == 200 && res.get_body() == "Shutdown initiated") {
            request_ok = true;
        }
        auto opt_conn = res.header("Connection");
        if (opt_conn && (*opt_conn == "close" || opt_conn->find("close") != std::string_view::npos)) {
            conn_close_found = true;
        }
        co_return;
    }, asio::detached);

    client_ioc.run();

    check(request_ok, "Shutdown route responded 200 OK with body");
    check(conn_close_found, "Shutdown response included Connection: close");

    if (srv_th.joinable()) {
        srv_th.join();
    }

    check(server.is_stopped(), "Server run() loop terminated cleanly and state is Stopped");
}

// ─── Test 10: External ShutdownEvent ──────────────────────────────────────────

void test_server_external_shutdown_event() {
    std::cout << "\n[Test 10] Server graceful shutdown triggered via external ShutdownEvent\n";

    wavex::engine::Http1Router router;
    wavex::server::Http1Server server(router, "127.0.0.1", 18092);
    server.enable_signal_handling(false);

    wavex::base::ShutdownEvent shutdown_ev;
    server.attach_shutdown_event(shutdown_ev);

    std::thread srv_th([&server] {
        server.run();
    });

    while (!server.is_running()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    check(server.is_running(), "Server running on 18092");

    shutdown_ev.publish(std::chrono::seconds(2));

    if (srv_th.joinable()) {
        srv_th.join();
    }

    check(server.is_stopped(), "Server stopped cleanly after external ShutdownEvent");
}

// ─── Test 11: In-Flight Request Drain ─────────────────────────────────────────

void test_server_inflight_drain() {
    std::cout << "\n[Test 11] Server in-flight request drain before shutdown\n";

    wavex::engine::Http1Router router;
    wavex::server::Http1Server server(router, "127.0.0.1", 18093);
    server.enable_signal_handling(false);

    router.get("/slow", [](wavex::protos::http::Http1Request &, wavex::protos::http::Http1Response &res) -> asio::awaitable<void> {
        auto ex = co_await asio::this_coro::executor;
        asio::steady_timer timer(ex, std::chrono::milliseconds(100));
        co_await timer.async_wait(asio::use_awaitable);
        res.status(200).send("Slow response done");
        co_return;
    });

    std::thread srv_th([&server] {
        server.run();
    });

    while (!server.is_running()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    bool slow_finished = false;
    std::thread client_th([&]() {
        asio::io_context client_ioc;
        asio::co_spawn(client_ioc, [&]() -> asio::awaitable<void> {
            auto res = co_await wavex::client::HttpClient::get("http://127.0.0.1:18093/slow");
            if (res.status_code() == 200 && res.get_body() == "Slow response done") {
                slow_finished = true;
            }
            co_return;
        }, asio::detached);
        client_ioc.run();
    });

    // Give client request time to reach the server and begin executing the slow handler
    std::this_thread::sleep_for(std::chrono::milliseconds(30));

    // Trigger shutdown while the /slow request is in-flight
    server.exit(std::chrono::seconds(3));

    if (client_th.joinable()) client_th.join();
    if (srv_th.joinable()) srv_th.join();

    check(slow_finished, "In-flight request completed successfully before server stopped");
    check(server.is_stopped(), "Server stopped after draining in-flight connection");
}

// ─── Test 12: Server Restartability ───────────────────────────────────────────

void test_server_restartability() {
    std::cout << "\n[Test 12] Server restartability across multiple run() / exit() lifecycles\n";

    wavex::engine::Http1Router router;
    router.get("/ping", [](wavex::protos::http::Http1Request &, wavex::protos::http::Http1Response &res) -> asio::awaitable<void> {
        res.status(200).send("pong");
        co_return;
    });

    wavex::server::Http1Server server(router, "127.0.0.1", 18094);
    server.enable_signal_handling(false);

    // Lifecycle 1
    std::thread srv_th1([&server] { server.run(); });
    while (!server.is_running()) std::this_thread::sleep_for(std::chrono::milliseconds(10));
    check(server.is_running(), "Server running (cycle 1)");

    server.exit(std::chrono::seconds(2));
    if (srv_th1.joinable()) srv_th1.join();
    check(server.is_stopped(), "Server stopped (cycle 1)");

    // Lifecycle 2 — restart the same server instance
    std::thread srv_th2([&server] { server.run(); });
    while (!server.is_running()) std::this_thread::sleep_for(std::chrono::milliseconds(10));
    check(server.is_running(), "Server running again (cycle 2)");

    bool ping_ok = false;
    {
        asio::io_context client_ioc;
        asio::co_spawn(client_ioc, [&]() -> asio::awaitable<void> {
            auto res = co_await wavex::client::HttpClient::get("http://127.0.0.1:18094/ping");
            if (res.status_code() == 200 && res.get_body() == "pong") {
                ping_ok = true;
            }
            co_return;
        }, asio::detached);
        client_ioc.run();
    }
    check(ping_ok, "Server responded to /ping during cycle 2");

    server.exit(std::chrono::seconds(2));
    if (srv_th2.joinable()) srv_th2.join();
    check(server.is_stopped(), "Server stopped (cycle 2)");
}

// ─── main ─────────────────────────────────────────────────────────────────────

int main() {
    std::cout << "=== WaveX Server, HttpResponse & ThreadPool Unit Tests ===\n";

    test_http_response_serialization();
    test_http_response_redirect();
    test_work_stealing_queue();
    test_thread_pool_config_singleton();
    test_thread_pool_execution_and_scaling();
    test_cache_line_alignment();
    test_proportional_hysteresis_scaling();
    test_generic_event_system();
    test_generic_event_bus();
    test_server_graceful_remote_shutdown();
    test_server_external_shutdown_event();
    test_server_inflight_drain();
    test_server_restartability();

    std::cout << "\n" << tests_passed << "/" << tests_run << " tests passed.\n";
    return tests_passed == tests_run ? 0 : 1;
}
