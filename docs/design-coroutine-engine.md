# Design note: an own coroutine engine

Status: proposal, with the first measurements. Nothing here is implemented yet except the two benchmarks it cites.

## Why look at this

WaveX runs on asio. That is a good I/O layer, but three properties of `asio::awaitable` and `io_context` limit how far
the request path can be tuned:

1. **Every `co_await child()` heap-allocates the child's frame.** Frame elision (HALO) is not applied to
   `asio::awaitable` (GCC 14, Clang 20). An own task type with `[[clang::coro_await_elidable]]` removes the
   allocations on Clang 20 (`benchmarks/task_elision.cpp`: 0 instead of 3 per iteration, 12 ns instead of 48 ns).
2. **Executors are type-erased** (`any_io_executor`), so each post/dispatch is an indirect call.
3. **Threading is `io_context` plus strands**, i.e. shared queues and locks. Thread-per-core frameworks (actix) avoid
   that by giving each worker its own connections and queue.

## First measurements

`wavex_bench_server`, an axum server and an actix-web server (same three routes, written outside this repository) were
driven by the same `wavex_loadgen`, alternating servers per round. 2 shared vCPUs, 32 keep-alive connections, loopback, median of 3
rounds, run-to-run spread 2 to 8 %. **Use the ratios, not the absolute numbers.**

| Route (what it does)       | WaveX   | axum    | actix   |
|:---------------------------|--------:|--------:|--------:|
| `/hello` (13 B), req/s     | 113,509 | 133,379 | 120,726 |
| `/blob` (64 KiB), req/s    |  27,786 |  54,097 |  42,823 |
| `/sleep` (2 ms), req/s [^1]|  13,052 |   9,152 |   9,653 |

[^1]: Not comparable. WaveX sleeps a pool thread (`spawn_blocking`), the Rust servers use a timer.

What this says:

* On small responses WaveX is within 6 to 15 % of the Rust frameworks. The per-request coroutine overhead that HALO would
  remove is therefore at most a fraction of that gap, not a 2x.
* The large gap is `/blob`: about 2x behind axum. `strace` per response: WaveX made two `sendto` (asio caps one
  `write_some` at 64 KiB, so 65,639 bytes went out as 65,536 + 103); lifting the cap (`detail::write_whole`) removed the
  second syscall and **did not change throughput**. WaveX also did about 0.55 `futex` and 0.38 `epoll_wait` per request
  against 0.1 and 0.16 for axum, which points at cross-thread wakeups, and the response body is copied twice (into the
  response, then into the wire buffer) where axum issues one `writev` of the existing buffer. Both are hypotheses until
  profiled (`perf` is not available in the sandbox).

## What an own engine would contain

1. `wavex::task<T>`: lazy, symmetric transfer, elidable where the compiler supports it, a per-thread frame pool where
   it does not.
2. A per-thread scheduler: run queue and timer wheel owned by one thread, no locks on the hot path; connections stay on
   the worker that accepted them (the pool already leases a worker per connection).
3. An I/O backend interface: epoll first, io_uring second. TCP, TLS (OpenSSL BIO) and QUIC (UDP) on top.
4. Cancellation and structured concurrency: stop tokens and a scope type that owns spawned children.

## Costs and risks

* TLS, UDP for QUIC, timers and DNS currently ride on asio; each needs a replacement or a bridge.
* HALO only helps coroutines awaited directly inside another coroutine, and only on Clang 20+.
* The measurements above say the biggest visible gap is not frame allocation. Replacing asio first would spend months
  before touching it.

## Staged plan with decision gates

0. **Done:** benchmark against axum/actix; elision prototype.
1. **Close the `/blob` gap on asio:** gather-write header and body without the extra copy; find the source of the extra
   `futex`/`epoll_wait` wakeups. Gate: if `/blob` reaches within 15 % of axum, the remaining gap is small enough that
   the engine work is justified by `/hello` and tail latency alone, not by throughput.
2. **`wavex::task` over asio:** own task type with elision and a `co_spawn` bridge, handlers and routers first. Gate:
   measurable `/hello` gain on Clang 20 and no loss on GCC.
3. **Per-thread scheduler on asio's reactor**, one `io_context` per worker with no cross-thread handoff on the request
   path. Gate: `futex` per request near zero, p99 improvement.
4. **Own epoll/io_uring backend**, one protocol at a time, asio behind the same interface until parity.

Run a stage's benchmark before starting the next; stop when the gap to the Rust frameworks is closed or the remaining
cost is I/O that asio is not causing.
