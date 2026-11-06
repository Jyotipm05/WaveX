# Coroutine frame elision (prototype)

Every `co_await child()` allocates the child's coroutine frame on the heap unless the compiler proves the child cannot
outlive the await and elides the allocation (HALO). Measured on `asio::awaitable` (which `wavex::task` aliases):
**no elision** on GCC 14 or Clang 20.

`benchmarks/task_elision.cpp` is a prototype of the alternative, a minimal task type marked
`[[clang::coro_await_elidable]]` (Clang 20+), awaiting a chain of three small child coroutines per iteration:

| Compiler         | Heap allocations per iteration | Time per iteration |
|:-----------------|-------------------------------:|-------------------:|
| Clang 20, `-O2`  | 0                              | 12 ns              |
| GCC 14, `-O2`    | 3                              | 48 ns              |

(`WAVEX_BENCH=ON` builds it as `wavex_task_elision`.)

## What it would take to adopt

The saving is real but it only applies to a task type that is not `asio::awaitable`. Replacing it means:

* a `wavex::task` of our own with the elidable attribute, plus `co_spawn`/`use_awaitable` interop, because asio's
  async operations and `co_spawn` are written against `asio::awaitable`;
* an executor-aware promise (the prototype has none), cancellation and exception propagation;
* a benefit only on Clang 20+, since GCC has no such attribute.

Until a measured handler path shows these allocations matter, `wavex::task` stays an alias of `asio::awaitable`.
