# Memory & Lifetimes

WaveX keeps the request hot path off the global heap with per-request arenas and contiguous containers. This page explains the model and the one rule you must follow when handlers keep data beyond a request.

## The three tiers

| Tier | Type                                                            | Scope          | Role                                                            |
|:-----|:----------------------------------------------------------------|:---------------|:----------------------------------------------------------------|
| 0    | `RequestArena` (`std::pmr::monotonic_buffer_resource`)          | one request    | Bump allocation, 4 KB first block, everything freed at once     |
| 1    | `ConnectionMemoryPool` (`std::pmr::synchronized_pool_resource`) | one connection | Supplies arena blocks; recycles them across keep-alive requests |
| 2    | `std::pmr::new_delete_resource()`                               | process        | Fallback for allocations the pools cannot serve                 |

The connection loop creates the pool once per connection and an arena per request:

```cpp
wavex::memory::RequestArena arena(conn_pool.resource()); // declared first ...
CustReq req(arena.resource());                           // ... so it is destroyed last
CustRes res(arena.resource());
```

`Request` and `Response` take a `std::pmr::memory_resource*` (a null pointer means the default resource). Query and route-parameter text lives in `std::pmr::string` buffers owned by the request, and the lookup tables are `FlatMap`s of `std::string_view` into those buffers.

## `RequestArena` is a movable handle

`monotonic_buffer_resource` cannot be moved, and every object allocated from it stores a pointer to it. `RequestArena` therefore keeps the resource at a **stable heap address** and is itself a two-pointer handle:

- Moving a `RequestArena` never changes `resource()`, so existing allocations stay valid.
- Copying is deleted.
- A moved-from arena returns `nullptr` from `resource()` and `release()` is a no-op.
- The destructor releases all blocks and returns the control block to the upstream it came from.

```c++
wavex::memory::RequestArena a(pool.resource());
wavex::memory::RequestArena b = std::move(a);   // ok: b.resource() == old a.resource()
```

## Lifetime rule

> [!IMPORTANT]
> Every object that allocated from an arena (`pmr::string`, `Request`, `Response`, ...) must be **destroyed before** `arena.release()` or the arena's own destruction.

Some standard libraries (for example MSVC STL with iterator debugging) touch allocator memory inside container destructors, so destroying such an object after `release()` is a use-after-free even though pmr deallocation is a no-op.

- Declare the arena **before** the objects that use it; reverse-order destruction is then correct automatically.
- Prefer scope exit over an explicit `release()`.
- Moving a request into another arena is supported with the allocator-extended constructor `HttpRequest(HttpRequest&&, memory_resource*)`, which re-seats the views onto the destination arena. Destroy the source request before releasing the source arena.

## `FlatMap`

`FlatMap<K, V, N>` replaces node-based maps for `req.params`, `req.query` and `res.headers_`:

- Inline storage for up to 16 entries, so typical routes allocate nothing for lookups.
- Linear scans beat hashing at this size thanks to cache locality.
- Header lookups are case-insensitive (`find_ci()`, `insert_or_assign_ci()`).

## Resource caps (DoS protection)

| Limit                 | Value                                           | Behaviour when exceeded                              |
|:----------------------|:------------------------------------------------|:-----------------------------------------------------|
| Query parameters      | 64 (fixed, `kMaxQueryParams`)                   | `431 Request Header Fields Too Large` before routing |
| Headers               | 100 (fixed)                                     | request rejected                                     |
| Request body          | 100 MB default, `server.set_max_request_size()` | `413 Payload Too Large`                              |
| In-memory body buffer | 10 MB default, `server.set_max_memory_buffer()` | multipart parts spool to disk                        |

The per-connection read buffer (`stream_buf`) is shrunk with `shrink_to_fit()` when it is empty and its capacity exceeds 64 KB.

## The `string_view` safety contract

> [!IMPORTANT]
> Views returned by `req.param()`, `req.params`, `req.query`, `req.query_param()` and `res.header()` point into the current request's storage. They are valid **only during the current request coroutine turn**.

| Operation Type             | Context / Examples                                                                                                                                  | Developer Action                                                                      |
|:---------------------------|:----------------------------------------------------------------------------------------------------------------------------------------------------|:--------------------------------------------------------------------------------------|
| **In-Turn (Zero-Copy)**    | Path/query filtering, validation, numeric conversion (`std::from_chars`), JSON parsing, direct DB queries executed within the current handler turn  | **Use `std::string_view` directly.** Zero copies, zero heap overhead.                 |
| **Escaping (Owning Copy)** | Offloading to worker threads via `wavex::spawn_blocking`, caching across requests, inserting into global state, storing in async background structs | **Explicitly copy to `std::string`**: `std::string(req.param("id"))` at the boundary. |

```c++
// Example: In-turn zero-copy vs escaping
router.get("/users/:id", [](auto &req, auto &res) -> asio::awaitable<void> {
    // 1. In-turn: zero-copy validation
    std::string_view id_view = req.param("id").value_or("");
    int user_id = 0;
    std::from_chars(id_view.data(), id_view.data() + id_view.size(), user_id);

    // 2. Escaping: copy to owning std::string across background thread boundary
    auto user_data = co_await wavex::spawn_blocking([id = std::string(id_view)] {
        return fetch_user_from_db(id); // Safe across thread boundary
    });

    res.status(200).json(user_data);
    co_return;
});
```

---

**See also:** [Async offloading](async-offloading.md) · [Architecture](../architecture.md)
