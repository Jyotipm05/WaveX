# Offloading Blocking Work & Async File I/O

Keep network threads responsive: run CPU-heavy or blocking calls on the elastic blocking pool with `spawn_blocking`, and use `wavex::fs` for non-blocking file access.

To keep low-latency network I/O threads from starving when handling CPU-intensive operations (cryptography, image manipulation, heavy math) or blocking legacy libraries (synchronous SQLite, `<fstream>`), WaveX provides Tokio-equivalent asynchronous offloading:

```c++
#include <wavex/wavex.hpp>

// 1. Offload heavy computation or blocking legacy libraries to the dedicated thread pool
router.post("/api/hash", [](auto &req, auto &res) -> wavex::task<void> {
    // Calling coroutine yields immediately; executes on background blocking pool
    std::string hash = co_await wavex::spawn_blocking([body = req.body()] {
        return compute_heavy_argon2_hash(body);
    });

    res.status(200).send(hash);
    co_return;
});

// 2. Tokio-equivalent non-blocking file system operations
router.get("/api/file", [](auto &, auto &res) -> wavex::task<void> {
    auto file_content = co_await wavex::fs::read_file("./data/document.txt");
    if (!file_content) {
        res.status(404).send("File not found");
        co_return;
    }

    res.status(200).send(*file_content);
    co_return;
});
```

> [!IMPORTANT]
> Anything you pass into `spawn_blocking` crosses a thread boundary. Copy request views into owning `std::string`s first; see [Memory & lifetimes](memory-and-lifetimes.md#the-string_view-safety-contract).

---

**See also:** [Memory & lifetimes](memory-and-lifetimes.md) · [Architecture](../architecture.md)
