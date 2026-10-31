# Keep-Alive, Graceful Shutdown & Events

Persistent connections, inactivity timeouts, zero-loss draining on `SIGTERM`, programmatic shutdown, restartability and the generic event bus.

## Keep-Alive & inactivity timeout

WaveX natively supports RFC 7230 / RFC 9112 persistent connections (`Keep-Alive`) and HTTP pipelining for both Plain TCP and TLS 1.3 servers.

### Server Inactivity Timeout & Request Quotas

Configure idle timeout thresholds and sequential request limits per persistent connection directly on `Server`:

```c++
wavex::server::Http1Server server(router, "0.0.0.0", 8080);

// Inactivity timeout: close socket if client is idle for > 10 seconds
server.set_keep_alive_timeout(std::chrono::seconds(10));

// Request quota: allow up to 500 requests per TCP connection before gracefully closing
server.set_max_keep_alive_requests(500);

server.run();
```

### Granular Response Header Control

Control keep-alive persistence dynamically in route handlers:

```c++
router.get("/stream", [](auto &, auto &res) -> wavex::task<void> {
    // Advertise keep-alive with custom timeout (seconds) and remaining request count
    res.set_keep_alive(true, /*timeout_sec=*/15, /*max_requests=*/200);
    res.status(200).send("Keep-Alive Active");
    co_return;
});

router.get("/logout", [](auto &, auto &res) -> wavex::task<void> {
    // Explicitly command connection closure
    res.set_keep_alive(false); // Sends 'Connection: close' and strips 'Keep-Alive'
    res.status(200).send("Logged out. Connection closing.");
    co_return;
});
```

### Zero-Cost Policies & Middleware

Use compile-time static chain policies or dynamic middlewares:

```c++
// 1. StaticChain KeepAlivePolicy (zero runtime overhead)
router.get("/api/fast", wavex::make_chain(wavex::KeepAlivePolicy<10, 1000>{}, MyHandler{}));

// 2. Dynamic Middleware for Keep-Alive
router.get("/api/data", {wavex::base::keep_alive(10, 500)}, DataHandler);

// 3. Server-Sent Events (SSE) Stay-Active Middleware
router.get("/events", {wavex::base::sse_stay_active()}, SseHandler);
```

## Graceful shutdown & events

WaveX provides enterprise-grade graceful termination that ensures zero dropped in-flight requests during server updates, container lifecycle events (Kubernetes `SIGTERM`), or developer-triggered remote maintenance.

### OS Signal Interception (`Ctrl+C` / `SIGTERM`)

By default, `Server` intercepts `SIGINT` and `SIGTERM` via `asio::signal_set`. When a signal arrives:

1. **Acceptor Closes**: The TCP listener immediately stops accepting new incoming connections.
2. **Idle Keep-Alive Sockets Canceled**: Persistent connections idling between requests are proactively aborted to avoid hanging the drain sequence.
3. **In-Flight Requests Complete**: Active requests continue processing. Their outgoing responses are automatically stamped with `Connection: close`.
4. **Deadline Guard**: If in-flight requests exceed the configurable grace period (default 10s via `server.set_shutdown_timeout()`), remaining sockets are force-closed.
5. **OS Default Signals Restored**: Signal handlers are restored to `SIG_DFL` and the process exits cleanly via `std::exit(0)`.

```c++
server.set_shutdown_timeout(std::chrono::seconds(5));
server.enable_signal_handling(true); // Default true
server.run();
```

### Programmatic Remote Shutdown (`server.exit()` / Route Handlers)

Developers can trigger graceful shutdown directly inside any custom route handler or background worker without deadlocking worker threads:

```c++
// Remote shutdown endpoint (authentication omitted for brevity)
router.post("/api/admin/exit", [&](auto &, auto &res) -> wavex::task<void> {
    res.status(200).send("Server draining. Goodbye!");
    
    // Initiates graceful drain with 5s timeout.
    // Unblocks server.run() without invoking std::exit().
    server.exit(std::chrono::seconds(5));
    co_return;
});

server.run();

// Post-run cleanup runs normally!
wavex::log::info("Server stopped. Performing database backups...");
```

### Generic C++23 Pub-Sub Event Architecture

WaveX includes a high-performance, thread-safe publish-subscribe event system in `wavex/Base/Event.hpp`:

- **`Event<Args...>`**: Multicast typed event with snapshot-isolated dispatch (no deadlocks or iterator invalidation). Supports RAII `Subscription` handles (`sub.unsubscribe()`).
- **`EventBus`**: Heterogeneous event broker dispatching events based on the C++ struct/class type (`bus.publish(MyEvent{})`, `bus.subscribe<MyEvent>(...)`).
- **`ShutdownEvent` / `ServerShutdownEvent`**: Decouple shutdown triggers from the server instance.

```c++
#include <wavex/Base/Event.hpp>

// 1. Standalone multicast event
wavex::base::Event<std::string, int> on_user_action;
auto sub = on_user_action.subscribe([](std::string name, int score) {
    wavex::log::info("User {} action, score: {}", name, score);
});
on_user_action.publish("Alice", 100);

// 2. Type-safe EventBus
wavex::base::EventBus bus;
struct OrderPlacedEvent { std::string order_id; double amount; };

auto order_sub = bus.subscribe<OrderPlacedEvent>([](const OrderPlacedEvent &e) {
    wavex::log::info("Processing order {} for ${:.2f}", e.order_id, e.amount);
});
bus.publish(OrderPlacedEvent{.order_id = "ORD-42", .amount = 99.95});

// 3. Attaching external shutdown events to Server
wavex::base::ShutdownEvent shutdown_event;
server.attach_shutdown_event(shutdown_event);

// Trigger shutdown from any independent service or thread
shutdown_event.publish(std::chrono::seconds(3));
```

### Server Restartability

Calling `server.exit()` unblocks `server.run()` while leaving the process running. The same `Server` instance can be re-run cleanly (`server.run()`), automatically re-initializing worker thread pools and network listeners:

```c++
server.run();  // Cycle 1: runs until exit()
// Perform updates, reloads, or migrations...
server.run();  // Cycle 2: re-opens acceptor and thread pool cleanly
```

---

**See also:** [Routing & middleware](routing-and-middleware.md) · [Architecture](../architecture.md)
