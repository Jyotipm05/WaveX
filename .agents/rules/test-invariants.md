# WaveX Unit Test, Runner & Stream Invariants

This rule governs test assertions, mock stream lifetimes, Asio `io_context` isolation, and automated test runner execution across WaveX test suites.

---

## 1. Test Assertion & Fixture Integrity
- **NEVER** modify test assertions, expected output, or fixtures when debugging test failures without explicit user consent.
- When an assertion fails, the test was designed around specific RFC or framework contracts. Altering assertion values masks framework defects. Root causes must be diagnosed and resolved in framework implementations.

---

## 2. Automated Test Runner Output Flushing (`std::endl` vs. `\n`)
- When test suites run under CTest or CI pipelines with standard output redirected to a pipe, stdout is block-buffered (typically 4096 bytes) rather than line-buffered.
- Ending test banner logs and `[PASS]` messages with `\n` without flushing leaves them in the OS buffer. If a subsequent test stalls or times out, all preceding un-flushed logs are withheld, giving the false appearance that an earlier test stalled.
- **Mandatory Pattern**: All test milestone markers and `[PASS]` assertion lines MUST terminate with `std::endl` (or explicit `std::flush`) to guarantee immediate delivery to test runners:
  ```cpp
  std::cout << "  [PASS] Feature verification passed." << std::endl;
  ```

---

## 3. Unit Test `io_context` Run Termination & Background Timer Isolation
- Asio's `io_context::run()` blocks as long as there is active work. Active `asio::steady_timer` instances (e.g. RFC 9002 loss detection/PTO timers, keep-alive pingers, or idle timeouts) constitute active work.
- If a tested component schedules a background timer that rearms on expiration (e.g. PTO exponential backoff retransmission), calling unbounded `io.run()` in unit tests causes the test runner to hang indefinitely until CTest timeout.
- **Mandatory Pattern in Unit Tests**:
  1. Coroutines or completion callbacks driving tests must explicitly invoke `io.stop()` (or `io2.stop()`) as soon as the test assertion or coroutine step succeeds.
  2. Prefer bounded execution methods (`io.run_for(100ms)`, `io.poll()`, or `io.run_one()`) when verifying asynchronous state transitions in tests.
  3. Close connection and transport objects (`conn->close()`) to ensure all background timers are canceled (`loss_timer_.cancel(ec)`) before `io_context` teardown.

---

## 4. Mock Stream Coroutine Lifecycle & Test Teardown Invariant
- When testing asynchronous coroutine loops processing streams (such as `handle_unidirectional_stream` or `handle_connection`), feeding partial data via `stream->push_inbound(data, false)` without FIN causes the coroutine to suspend indefinitely on `stream->async_read_some(...)` waiting for more data.
- If the test function exits without explicitly closing the stream (`stream->close()`) and connection (`conn->close()`), the coroutine frame remains suspended, holding `pending_read_` callbacks and background timers (e.g. PTO and idle timers on `QuicConnection`).
- When `asio::io_context` leaves scope or is destroyed with pending work, Asio cannot terminate cleanly, causing test runner timeouts.
- **Mandatory Pattern in Stream Tests**:
  1. Always wrap coroutines passed to `asio::co_spawn` in an explicit capturing lambda closure:
     ```cpp
     asio::co_spawn(io, [stream, ctx]() -> wavex::task<void> {
         co_await h3::session_handler::handle_unidirectional_stream(stream, ctx);
     }, asio::detached);
     ```
  2. Before the test function returns, explicitly close all mock streams (`stream->close()`) and connections (`conn->close()`).
  3. Invoke `io.stop()` and drain any remaining posted callbacks with `io.poll()` prior to function exit:
     ```cpp
     ctrl_stream->close();
     enc_stream->close();
     server_conn->close();
     io.stop();
     io.poll();
     ```

---

## 5. Test Signal Isolation
- Automated unit tests utilizing loopback test servers must configure `server.enable_signal_handling(false)`.
- This prevents background signal registration from interfering with the test runner's global signal table or terminating the runner on SIGINT/SIGTERM handlers.
