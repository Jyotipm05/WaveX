# WaveX Testing, Concurrency & Asio Debugging Gotchas

This document catalogs non-obvious failure modes, debugging patterns, and concurrency invariants in Asio and coroutines across the WaveX codebase.

---

## 1. Asio Timer Indefinite Execution in Unit Tests

### The Bug
Calling unbounded `io.run()` in unit tests hangs indefinitely or hits CTest timeout when background timers (such as RFC 9002 loss detection, keep-alive, or idle timeout timers) are active.
Asio considers any active `asio::steady_timer` to be active work. If a timer callback rearms itself on timeout, `io.run()` will never return.

### The Invariants
1. **Explicit Stop in Coroutines**: Test completion callbacks or coroutines driving unit assertions must call `io.stop()` as soon as the expected assertion succeeds.
2. **Bounded Execution**: Prefer bounded calls like `io.run_for(100ms)`, `io.poll()`, or `io.run_one()`.
3. **Explicit Cancellation on Teardown**: Components owning background timers (`QuicConnection`, `QuicServer`) must cancel all timers (`timer.cancel(ec)`) on `close()`.

---

## 2. Mutex Deadlocks Across Coroutine Suspension Points (`co_await`)

### The Bug
Holding a `std::mutex` or `std::recursive_mutex` lock while executing `co_await` leads to two fatal failure modes:
1. **Thread Transfer UB**: A coroutine suspending on thread A may resume on thread B. Unlocking a mutex from a thread other than the one that acquired it is undefined behavior (and crashes on Windows/MSVC).
2. **Acceptor Deadlock**: Holding the lock prevents incoming packets or stream events from being processed concurrently.

### The Invariant
Always release mutex locks before suspension points:
```cpp
// CORRECT:
std::unique_lock lock(mtx_);
if (!accepted_streams_.empty()) {
    auto s = accepted_streams_.front();
    accepted_streams_.pop_front();
    return s;
}
// Release lock before suspending:
lock.unlock();
auto stream = co_await suspend_and_await_handoff();
```

---

## 3. Reference Cycles Between Connections and Acceptors

### The Bug
Registering a stream-created callback that captures a `std::shared_ptr<QuicConnection>` inside `QuicConnection` itself:
```cpp
// ANTI-PATTERN:
conn->set_stream_created_callback([conn](auto stream) { ... });
```
This forms a circular reference graph:
`QuicConnection` -> `std::function` callback -> `std::shared_ptr<QuicConnection>`.
The connection is never destroyed even after being erased from connection maps.

### The Invariant
Callbacks registered on connection trackers, streams, or listeners must capture `std::weak_ptr`:
```cpp
// CORRECT:
auto weak_conn = std::weak_ptr<QuicConnection>(conn);
conn->set_stream_created_callback([weak_conn](auto stream) {
    if (auto c = weak_conn.lock()) {
        // Safe to access connection
    }
});
```

---

## 4. Test Assertion Integrity

### The Invariant
**NEVER** modify test assertions, expected output, or fixtures when debugging test failures without explicit user consent.
When an assertion fails (such as `assert(pkts.size() == 4)`):
- The test was written with specific RFC or architectural intent.
- Modifying `4` to `6` masks framework bugs.
- Always debug the implementation to understand why unexpected state or packets were generated.
