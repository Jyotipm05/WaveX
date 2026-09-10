/**
 * @file test_MW.cpp
 * @brief Tests for the wavex:middleware module partition.
 *
 * Tests covered:
 *  1. Type aliases exist and are default-constructible (empty std::function)
 *  2. A middleware that calls next() — chain executes in linear order
 *  3. A middleware that does NOT call next() — short-circuits the pipeline
 *  4. Middleware can post-process the Response after next() returns
 */

// Pull Request/Response base classes via their headers.
// These are NOT exported by the wavex module — only Next and MiddlewareFn are.
#include <wavex/Base/Request.hpp>
#include <wavex/Base/Response.hpp>

// wavex module provides: wavex::base::Next, wavex::base::MiddlewareFn
// import wavex;

#include <wavex/wavex.hpp>

#define ASIO_HAS_CO_AWAIT 1
#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>

#include <cassert>
#include <iostream>
#include <string>
#include <vector>

// ─── Minimal concrete stubs ───────────────────────────────────────────────────

// ─── Minimal concrete stubs ───────────────────────────────────────────────────

struct StubRequest final : wavex::base::Request {
    std::string path_val;
    [[nodiscard]] std::string_view path_impl() const { return path_val; }
    [[nodiscard]] std::optional<std::string_view> header_impl(std::string_view) const { return std::nullopt; }
    [[nodiscard]] std::string_view body_impl() const { return {}; }
};

struct StubResponse final : wavex::base::Response {
    std::vector<std::string> *sent_log = nullptr;

    StubResponse &send_impl(const std::string_view body) {
        if (is_sent_) return *this;
        body_ = std::string(body);
        is_sent_ = true;
        if (sent_log) {
            sent_log->push_back(serialize_impl());
        }
        return *this;
    }

    [[nodiscard]] std::string serialize_impl() const {
        return "HTTP/1.1 " + std::to_string(status_code_) + "\r\n\r\n" + body_;
    }
};

// ─── Test runner helpers ──────────────────────────────────────────────────────

namespace {
    int tests_run = 0;
    int tests_passed = 0;

    void check(bool condition, const char *name) {
        ++tests_run;
        if (condition) {
            ++tests_passed;
            std::cout << "  [PASS] " << name << "\n";
        } else { std::cout << "  [FAIL] " << name << "\n"; }
    }
}

template<typename Coro>
void run_sync(Coro coro) {
    asio::io_context ioc;
    asio::co_spawn(ioc, std::move(coro), asio::detached);
    ioc.run();
}

// ─── Middleware pipeline runner ───────────────────────────────────────────────

/// Linear coroutine runner that iterates over MiddlewareFn vector.
template<typename ReqT, typename ResT>
asio::awaitable<void> run_chain(
    ReqT &req,
    ResT &res,
    std::vector<wavex::base::GenericMiddlewareFn<ReqT, ResT> > mws) {
    std::size_t idx = 0;
    while (idx < mws.size() && !res.is_sent()) {
        bool next_called = false;
        wavex::base::Next next = [&next_called]() -> asio::awaitable<void> {
            next_called = true;
            co_return;
        };

        co_await mws[idx](req, res, std::move(next));
        idx++;

        if (!next_called || res.is_sent()) {
            break;
        }
    }
    co_return;
}

// ─── Test 1 ───────────────────────────────────────────────────────────────────

void test_type_aliases_exist() {
    std::cout << "\n[Test 1] Type aliases are constructible\n";

    wavex::base::Next next; // default-constructs to empty callable
    wavex::base::GenericMiddlewareFn<StubRequest, StubResponse> mw;

    check(!next, "Next default-constructs as empty");
    check(!mw, "MiddlewareFn default-constructs as empty");
}

// ─── Test 2 ───────────────────────────────────────────────────────────────────

void test_chain_executes_in_order() {
    std::cout << "\n[Test 2] Chain executes in linear order\n";

    StubRequest req;
    StubResponse res;
    std::vector<std::string> log;

    std::vector<wavex::base::GenericMiddlewareFn<StubRequest, StubResponse> > mws = {
        [&log](StubRequest &, StubResponse &, wavex::base::Next next)
    -> asio::awaitable<void> {
            log.emplace_back("A:before");
            co_await next();
            log.emplace_back("A:after");
        },
        [&log](StubRequest &, StubResponse &, wavex::base::Next next)
    -> asio::awaitable<void> {
            log.emplace_back("B:before");
            co_await next();
            log.emplace_back("B:after");
        },
    };

    run_sync(run_chain(req, res, mws));

    check(log.size() == 4, "4 log entries recorded");
    check(log[0] == "A:before", "A executes first (before)");
    check(log[1] == "A:after", "A executes second (after)");
    check(log[2] == "B:before", "B executes third (before)");
    check(log[3] == "B:after", "B executes last (after)");
}

// ─── Test 3 ───────────────────────────────────────────────────────────────────

void test_short_circuit() {
    std::cout << "\n[Test 3] Short-circuit — next not called\n";

    StubRequest req;
    StubResponse res;
    bool reached_second = false;

    std::vector<wavex::base::GenericMiddlewareFn<StubRequest, StubResponse> > mws = {
        // Auth guard — rejects without forwarding
        [](StubRequest &, StubResponse &r, wavex::base::Next)
    -> asio::awaitable<void> {
            r.status(401).send("Unauthorized");
            co_return;
        },
        // Must never run
        [&reached_second](StubRequest &, StubResponse &, wavex::base::Next next)
    -> asio::awaitable<void> {
            reached_second = true;
            co_await next();
        },
    };

    run_sync(run_chain(req, res, mws));

    check(!reached_second, "Second middleware was not reached");
    check(res.status_code() == 401, "Status code is 401");
    check(res.get_body() == "Unauthorized", "Body is 'Unauthorized'");
}

// ─── Test 4 ───────────────────────────────────────────────────────────────────

void test_middleware_post_processes_response() {
    std::cout << "\n[Test 4] Middleware post-processes response\n";

    StubRequest req;
    StubResponse res;

    std::vector<wavex::base::GenericMiddlewareFn<StubRequest, StubResponse> > mws = {
        // Outer: adds a header AFTER the inner middleware sets the body
        [](StubRequest &, StubResponse &r, wavex::base::Next next)
    -> asio::awaitable<void> {
            co_await next();
            r.set("X-Powered-By", "WaveX");
        },
        // Inner: sets status + body
        [](StubRequest &, StubResponse &r, wavex::base::Next)
    -> asio::awaitable<void> {
            r.status(200).send("Hello");
            co_return;
        },
    };

    run_sync(run_chain(req, res, mws));

    check(res.status_code() == 200, "Status code is 200");
    check(res.get_body() == "Hello", "Body is 'Hello'");
    check(res.has_header("X-Powered-By"), "X-Powered-By header was set by outer MW");
}

// ─── Test 5 ───────────────────────────────────────────────────────────────────

void test_express_style_send_and_linear_chain() {
    std::cout << "\n[Test 5] Express-style res.send() / res.json() immediate dispatch and linear continuation\n";

    StubRequest req;
    std::vector<std::string> sent_outputs;
    StubResponse res;
    res.sent_log = &sent_outputs;

    bool post_send_executed = false;
    bool second_mw_executed = false;

    std::vector<wavex::base::GenericMiddlewareFn<StubRequest, StubResponse> > mws = {
        [&post_send_executed](StubRequest &, StubResponse &r, wavex::base::Next)
    -> asio::awaitable<void> {
            r.status(200).json({{"message", "immediate"}});
            // Code after send() inside current lambda executes normally
            post_send_executed = true;
            co_return;
        },
        [&second_mw_executed](StubRequest &, StubResponse &, wavex::base::Next next)
    -> asio::awaitable<void> {
            second_mw_executed = true;
            co_await next();
        }
    };

    run_sync(run_chain(req, res, mws));

    check(res.is_sent(), "Response marked as sent");
    check(sent_outputs.size() == 1, "Immediate socket send was triggered exactly once");
    check(post_send_executed, "Post-send code in current lambda executed");
    check(!second_mw_executed, "Subsequent middleware was NOT executed after send()");
}

// ─── main ─────────────────────────────────────────────────────────────────────

int main() {
    std::cout << "=== WaveX Middleware Tests ===\n";

    test_type_aliases_exist();
    test_chain_executes_in_order();
    test_short_circuit();
    test_middleware_post_processes_response();
    test_express_style_send_and_linear_chain();

    std::cout << "\n" << tests_passed << "/" << tests_run << " tests passed.\n";
    return tests_passed == tests_run ? 0 : 1;
}
