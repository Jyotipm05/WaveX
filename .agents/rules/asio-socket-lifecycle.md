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
