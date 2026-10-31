# Logging & Command-Line Parsing

Two small utilities used by the dev servers and available to your own applications.

## Logging

Zero-macro, high-performance asynchronous logging with pre-allocated buffer pooling, automatic `std::source_location` call-site capture, ANSI terminal colors, and non-blocking worker thread dispatch:

```cpp
#include <wavex/Base/Logger.hpp>

int main() {
    // 1. Configure async logger & buffer pool
    wavex::base::LoggerConfig cfg{
        .pool_capacity = 4096,                           // Pre-allocated LogBuffer slots
        .max_pool_capacity = 16384,                      // Upper limit for dynamic growth
        .flush_interval = std::chrono::milliseconds(50), // Periodic background flush
        .overflow_policy = wavex::base::OverflowPolicy::Drop, // Drop newest on queue full
        .async_mode = true                               // Non-blocking background worker
    };
    wavex::base::Logger::instance().configure(cfg);

    // 2. Configure minimum log level (TRACE, DEBUG, INFO, WARN, ERROR, FATAL)
    wavex::base::Logger::instance().set_level(wavex::base::LogLevel::DEBUG);

    // 3. Enable or disable ANSI terminal colors (enabled by default)
    wavex::base::Logger::instance().set_colored(true);

    // 4. Modern functional logging API (namespace wxlog = wavex::log)
    wxlog::trace("Buffer allocated: {} bytes", 1024);
    wxlog::debug("Route match resolved in {} us", 12.4);
    wxlog::info("Worker pool online: {} threads", 8);
    wxlog::warn("Slow database query detected ({}ms)", 235);
    wxlog::error("Connection reset by peer: fd={}", 14);

    // Synchronously flush pending logs before exiting
    wxlog::flush();

    // Optional: direct logs to file or custom stream
    // wavex::base::Logger::instance().set_output("./logs/wavex.log");

    return 0;
}
```

### Asynchronous Architecture & Buffer Pooling

To prevent logging I/O from stalling worker coroutines and degrading p99 tail latency, WaveX employs a dedicated background writer thread and a pre-allocated pool of `LogBuffer` slots:

- **Hot Path Zero-Allocation**: When formatting log messages under 512 bytes, the caller thread formats directly into pre-allocated buffer memory (`LogBuffer::inline_storage`). No heap allocation occurs on the calling thread.
- **Batch Processing**: The background writer thread drains up to 256 records per batch, writing them in a single lock acquisition to minimize sink contention.
- **Deterministic Flush**: `wxlog::flush()` provides a synchronization barrier that waits until all previously enqueued records have been processed and flushed to disk or stream.

### Overflow Policies

When traffic spikes exhaust queue capacity, `OverflowPolicy` dictates how incoming logs are handled:

| Policy | Behavior | Best Used For |
|---|---|---|
| `OverflowPolicy::Drop` *(Default)* | Non-blocking. Drops newest records and increments an atomic counter (`dropped_count`). Never blocks caller coroutines. | Production high-throughput servers |
| `OverflowPolicy::Block` | Blocking. Caller thread waits on condition variable until buffer slots become available. | Unit testing & deterministic diagnostics |
| `OverflowPolicy::Grow` | Dynamic growth. Expands the buffer pool dynamically up to `max_pool_capacity`. Drops once cap is reached. | Variable load environments with bursting |

### Priority Headroom & Non-Silent Loss

1. **Priority Headroom (Top 10% Reservation)**:
   The queue reserves its top 10% capacity exclusively for `WARN`, `ERROR`, and `FATAL` records. If high-frequency `DEBUG` or `INFO` logs fill 90% of the queue, low-priority logs are dropped immediately, guaranteeing headroom for critical diagnostic alerts.
2. **Non-Silent Loss Notification**:
   When messages are dropped due to overflow, the background logger automatically emits a summary notification upon queue draining:
   ```
   [WARN ] [Logger] Dropped 150 messages due to queue overflow in the last 1s
   ```
3. **Crash Safety**:
   `wxlog::fatal(...)` synchronously flushes and drains the queue before calling `std::abort()`, ensuring crash diagnostics are reliably written to disk.

## CLI parser

`-h` / `--help` is reserved by the parser, so use another short letter for host options.

```cpp
#include <wavex/CLI/CLI.hpp>
#include <iostream>

int main(int argc, char* argv[]) {
    wavex::cli::CliParser parser("wavex-tool", "WaveX High-Performance HTTP Server Utility");

    parser.add_flag("verbose", 'v', "Enable verbose logging")
          .add_option("host", 'H', "Host address to bind server", "127.0.0.1")
          .add_option("port", 'p', "Server port to listen on", "8080");

    auto result = parser.parse(argc, argv);
    if (!result.ok()) {
        if (result.help_requested) {
            parser.print_help();
            return 0;
        }
        std::cerr << "Error: " << result.error_message << "\n";
        return 1;
    }

    std::string host = parser.get_string("host");
    int port = parser.get_int("port", 8080);
    bool verbose = parser.get_bool("verbose");

    std::cout << "Starting server on http://" << host << ":" << port << " (verbose=" << verbose << ")\n";
    return 0;
}
```

---

**See also:** [Dev servers](../dev-servers.md)
