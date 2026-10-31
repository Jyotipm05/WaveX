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

---

## 5. Mock Stream Coroutine Lifecycle & Test Teardown

### The Bug
When unit testing coroutines that loop over stream reads (such as `handle_unidirectional_stream` or `handle_connection`), feeding partial data via `stream->push_inbound(wire, false)` without FIN leaves the coroutine suspended on `async_read_some()` waiting for further data.
If the test completes its assertions and exits without closing the streams, the coroutine remains suspended with active `pending_read_` callbacks and armed background timers. When `io_context` leaves scope or is destroyed with pending work, Asio hangs or times out in automated test runners.

### The Invariants
1. **Lambda Closure for `co_spawn`**: Never pass an invoked awaitable expression directly from a temporary or local callable to `asio::co_spawn`. Wrap it in an explicit lambda:
   ```cpp
   asio::co_spawn(io, [stream, ctx]() -> asio::awaitable<void> {
       co_await h3::session_handler::handle_unidirectional_stream(stream, ctx);
   }, asio::detached);
   ```
2. **Explicit Stream & Connection Close**: Always explicitly invoke `stream->close()` on all mock streams and `conn->close()` on test connections.
3. **Explicit IO Stop and Drain**: Call `io.stop()` and drain remaining handlers with `io.poll()` before test function exit:
   ```cpp
   ctrl_stream->close();
   enc_stream->close();
   server_conn->close();
   io.stop();
   io.poll();
   ```

---

## 6. Automated Test Runner Output Flushing (`std::endl` vs. `\n`)

### The Bug
CTest and CI test runners redirect stdout to pipes, causing the C runtime to block-buffer standard output (typically 4096 bytes). Terminating test milestone logs and `[PASS]` messages with `\n` without flushing leaves them in the OS buffer. If a subsequent test stalls or times out, all preceding un-flushed logs remain hidden, creating the misleading impression that an earlier test stalled.

### The Invariant
All test section announcements and `[PASS]` assertions must terminate with `std::endl` (or explicit `std::flush`) to ensure immediate delivery to automated test runners:
```cpp
std::cout << "  [PASS] Feature verification passed." << std::endl;
```
