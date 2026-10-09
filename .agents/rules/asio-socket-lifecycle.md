---
trigger: always_on
---

# WaveX Asio Async & Socket Lifecycle Invariants

This rule governs all Asio networking, socket options, coroutine frame lifetimes, and connection registry implementations across WaveX.

---

## 1. Asio Async Operation Buffer Lifetime (Temporary vs. Coro-Frame Lvalue)

- **NEVER** pass temporary `std::string` expressions directly into `asio::buffer()` inside asynchronous calls:
  ```cpp
  // PROHIBITED: res.serialize() creates a temporary that may be freed during async suspension
  co_await asio::async_write(stream, asio::buffer(res.serialize()), asio::use_awaitable);
  ```
- `asio::buffer()` stores only a non-owning raw memory pointer and length. When an asynchronous operation suspends, temporary strings in the expression are destroyed while the OS kernel (Windows IOCP / `WSASend` or Linux epoll) is actively transmitting the buffer, leading to heap corruption or intermittent `0xC0000005` SegFaults.
- **Mandatory Pattern**: Always pin serialized output or response buffers to a named lvalue on the coroutine frame:
  ```cpp
  std::string wire_resp = res.serialize();
  co_await asio::async_write(stream, asio::buffer(wire_resp), asio::use_awaitable);
  ```

---

## 2. Connection Lifetime & Thread-Safe Socket Registry (`std::weak_ptr` vs. Raw Reference)

- In socket tracking and graceful shutdown registries (`ConnectionTracker`), **NEVER** capture raw socket references (`[&lowest_sock]`) or raw pointers in cancellation or closure callbacks.
- If a connection coroutine finishes and tears down while a server stop or force-close sequence executes concurrently on another thread, invoking `lowest_sock.close()` on a deallocated socket causes a fatal use-after-free SegFault.
- **Mandatory Pattern**: Connection streams must be managed via `std::shared_ptr<Stream>` in `handle_connection` and captured via `std::weak_ptr<Stream>` by value in tracker callbacks:
  ```cpp
  auto weak_stream = std::weak_ptr<Stream>(stream_ptr);
  conn_tracker_.register_socket(
      [weak_stream] {
          if (auto s = weak_stream.lock()) {
              asio::error_code ec;
              s->lowest_layer().cancel(ec);
          }
      },
      [weak_stream] {
          if (auto s = weak_stream.lock()) {
              asio::error_code ec;
              s->lowest_layer().cancel(ec);
              s->lowest_layer().close(ec);
          }
      }
  );
  ```
  Checking `if (auto s = weak_stream.lock())` guarantees the socket remains alive for the duration of the cancellation/close call, or safely no-ops if already closed.

---

## 3. Asio `io_context` Lifecycle in Custom Worker Loops

- When embedding an `asio::io_context` alongside custom task queues (e.g. work-stealing rings in `ThreadPool`), **NEVER** call `run()`, `run_one()`, or `run_one_for()` without an active `asio::executor_work_guard`.
- Without a work guard, running out of ready handlers immediately transitions `io_context` into the `stopped()` state, permanently dropping subsequent `asio::co_spawn` tasks and causing server deadlocks.
- Use `io_ctx->poll()` to drain ready handlers with 0μs latency, and `io_ctx->run_one_for(100us)` with an active `work_guard` to sleep inside the OS kernel (IOCP/epoll) when idle.
- Always call `work_guard.reset()` before `io_ctx->stop()` during pool shutdown or thread decommissioning.

---

## 4. Graceful TCP Teardown vs. Connection Abort

- Server-side connection termination must use `asio::ip::tcp::socket::shutdown_send` (`SD_SEND` / `SHUT_WR`), not `shutdown_both`.
- Calling `shutdown_both` immediately followed by `close()` instructs Winsock / BSD sockets to reject subsequent incoming packets (including client ACKs or FINs), causing Winsock to issue a TCP RST packet and abort in-flight response transmission.

---

## 5. Domainless IP Resolution & TCP Socket Options

- When connecting to an IP literal (e.g. `127.0.0.1`, `::1`), never invoke `resolver.async_resolve()`. Directly construct endpoint sequences via `asio::ip::tcp::resolver::results_type::create(endpoint, host, port_str)`. Calling `getaddrinfo` on IP literals introduces thread scheduling latency and NetBIOS/LLMNR stalls on Windows.
- Both server-accepted and client-initiated TCP sockets must enable `TCP_NODELAY` (`no_delay(true)`) to prevent Nagle's algorithm and 40–200ms delayed-ACK penalties from deadlocking ping-pong localhost exchanges.

---

## 6. Server Graceful Drain, Deadlock Immunity & Test Signal Isolation

- **Idle Keep-Alive Cancellation**: When initiating shutdown (`server.exit()`, `ShutdownEvent`), the server must proactively cancel idle sockets waiting on empty buffers (`cancel_all_idle()`) to prevent draining hangs.
- **Worker Thread Deadlock Immunity**: During programmatic shutdown, the final shutdown step (`finish_shutdown()`) must be posted to `master_io_` rather than calling `pool_.stop_pool()` directly from inside a worker thread, ensuring worker threads never attempt to join themselves.
- **Response Stamping**: In-flight requests finishing during shutdown must have their responses stamped with `Connection: close`.
- **Test Signal Isolation**: Automated unit tests using loopback test servers must configure `server.enable_signal_handling(false)` to prevent background signal registration from interfering with the test runner's global signal table.

---

## 7. Windows Sockets & Completion Executor Macro Invariants

- **Winsock Linking**: On Windows platforms, all CMake networking targets must explicitly link `ws2_32` and `mswsock` (`PUBLIC`). GNU `ld` on MinGW does not process `#pragma comment(lib, ...)`, which causes link-time failures (`undefined reference to '__imp_WSAStartup'`, etc.) if omitted.
- **TS Executor Prohibited**: Never define `ASIO_USE_TS_EXECUTOR_AS_DEFAULT` in any codebase header or build flag. It alters the fundamental type of `asio::any_completion_executor`, conflicting with modern C++20 awaitable signatures and triggering MSVC `C2371` type redefinition errors.

---

## 8. Unit Test `io_context` Run Termination & Background Timer Isolation

- Asio's `io_context::run()` blocks as long as there is active work. An active `asio::steady_timer` (such as RFC 9002 loss detection/PTO timers, keep-alive pingers, or idle timeouts) counts as pending work.
- If a tested component schedules a background timer that rearms on expiration (e.g. PTO exponential backoff retransmission), calling unbounded `io.run()` in unit tests causes the test runner to hang indefinitely until CTest timeout.
- **Mandatory Pattern in Unit Tests**:
  1. Coroutines or completion callbacks driving tests must explicitly invoke `io.stop()` (or `io2.stop()`) as soon as the test assertion or coroutine step succeeds.
  2. Prefer bounded execution methods (`io.run_for(100ms)`, `io.poll()`, or `io.run_one()`) when verifying asynchronous state transitions in tests.
  3. Close connection and transport objects (`conn->close()`) to ensure all background timers are canceled (`loss_timer_.cancel(ec)`) before `io_context` teardown.

---

## 9. Completion Handler & Coroutine Resumption Mutex Deadlock Invariant

- **NEVER** invoke asynchronous completion callbacks (`shared_h`, completion tokens, or `fire(...)`) while holding a non-recursive `std::mutex` (`mtx_`).
- In Asio, invoking a completion handler frequently resumes the awaiting coroutine inline on the current thread. Resumed coroutines routinely execute cleanup or subsequent stream operations (such as `stream->close()`, `stream->is_open()`, or another `async_read_some()`), each of which attempts to acquire `mtx_`.
- Because `std::mutex` is non-recursive, invoking completion handlers under lock results in an immediate, silent self-deadlock on the thread.
- **Mandatory Pattern**: Evaluate status codes, perform buffer copies, and update container state strictly inside a scoped lock block. Ensure the lock is unlocked/destroyed BEFORE invoking the completion handler:
  ```cpp
  const char *site = "pending-success";
  std::error_code result_ec;
  std::size_t copied = 0;
  {
      std::lock_guard lock(s->mtx_);
      if (ec) {
          site = "pending-ec";
          result_ec = ec;
      } else if (s->in_buffer_.empty()) {
          site = "pending-empty";
          result_ec = s->fin_received_ ? asio::error::eof : std::error_code{};
      } else {
          // copy data from in_buffer_ ...
      }
  } // Lock released here
  fire(site, result_ec, copied); // Safe inline resumption
  ```

---

## 10. `asio::co_spawn` Closure Lifetime & Local Callable Invariant

- **NEVER** pass an already-invoked awaitable expression from a local callable to `asio::co_spawn`:
  ```cpp
  // PROHIBITED: Frame closure pointer dangles when local `handler` goes out of scope!
  StreamHandler handler;
  { std::lock_guard lock(mtx_); handler = stream_handler_; }
  if (handler) asio::co_spawn(io_, handler(stream), asio::detached);
  ```
- `asio::awaitable<T>` is lazily evaluated (`suspend_always` on initial suspend). Invoking `handler(stream)` immediately builds the coroutine frame, holding an implicit pointer back to the closure inside the local `handler` variable. When `handler` leaves scope, its closure is destroyed, leaving dangling references (observed as `this=0x0` or SegFaults on resume).
- **Mandatory Pattern**: Always pass the callable itself to `asio::co_spawn` so Asio owns a copy for the entire duration of the coroutine:
  ```cpp
  // MANDATORY: co_spawn owns the lambda and keeps the handler closure alive
  asio::co_spawn(io_, [handler, stream]() -> asio::awaitable<void> {
      co_await handler(stream);
  }, asio::detached);
  ```

---

## 11. Timed Asynchronous Post Stack Capture Lifetime

- **NEVER** capture local stack variables by reference (`[&stack_var]`) inside lambdas posted to an executor via `asio::post`, especially when followed by a bounded wait (`wait_for` / `wait_until`) or detached execution.
- If the wait times out or the function exits early, the stack frame is unwound and destroyed. When the executor thread subsequently runs the posted task, it dereferences invalid stack memory.
- **Mandatory Pattern**: State passed to `asio::post` that may outlive the caller's stack frame must be captured by value or via heap-allocated `std::shared_ptr`:
  ```cpp
  auto conns_ptr = std::make_shared<std::unordered_map<ConnectionId, std::shared_ptr<QuicConnection>>>(std::move(conns));
  auto drained = std::make_shared<std::promise<void>>();
  auto fut = drained->get_future();
  asio::post(io_, [conns_ptr, drained] {
      for (auto &[cid, conn] : *conns_ptr) {
          if (conn) conn->close();
      }
      drained->set_value();
  });
  fut.wait_for(std::chrono::milliseconds(500));
  ```


