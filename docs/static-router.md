# StaticRouter (compile-time routes)

`StaticRouter` is a second router next to `DynamicRouter`. Its routes, route tree and middleware chains are fixed
at compile time: patterns are parsed and validated by `constexpr` code, the lookup tree is a constexpr array, and
each route's middleware list (global, groups, route) is concatenated into a type. Nothing is allocated while
routing, and handlers stay concrete types the compiler can inline.

Both routers satisfy `wavex::engine::route::router_type`, the concept `Server<Codec, Router>` relies on, so the
server code is unchanged.

```cpp
#include <wavex/Engine/StaticHttpRouter.hpp>
using namespace wavex::engine::route;
using namespace wavex::engine::route::http;       // get / post / put / del / patch / head / options / query

auto router = static_router<wavex::engine::Http1Proto>(      // Proto first, segment compare second (default string_compare)
    use(logging),                                              // global middleware
    get<"/">(home),
    group<"/api">(
        use(auth),                                             // all routes of the group
        get <"/users/{id:int}">(show_user, rate_limit),        // per-route middleware after the handler argument
        post<"/users">(create_user)),
    get<"/files/*path">(serve));

wavex::server::Server<wavex::protos::http::http1codec, decltype(router)> server(router, "0.0.0.0", 8080);
```

`on<Method, "/path">(handler, middleware...)` is the protocol-neutral form; the HTTP helpers just fix the method.
Handlers have the same signature as everywhere else: `task<void>(Req&, Res&)`.

## Patterns

Same syntax as `DynamicRouter`; constraints are built-in classes or a regular expression run by the in-tree
engine (see [ctregex.md](ctregex.md)):

| Pattern | Meaning |
|---------|---------|
| `users` | literal segment |
| `:id`, `{id}` | parameter, any non-empty segment |
| `{id:int}` | parameter constrained to `any`, `int`, `uint`, `alpha`, `alnum` or `hex` |
| `{id:[0-9]{4}}` | anything else after the colon is a regular expression the whole segment must match |
| `*`, `*name` | wildcard, last segment only, captures the rest of the path (key `*` when unnamed) |

Matching order at each position: literal children, then parameters (in registration order, backtracking when a
branch fails), then the wildcard. Repeated, leading and trailing slashes are ignored. An unknown path, or a
known path with an unregistered method, is a miss (404), as in `DynamicRouter`. Parameters appear in
`req.param("id")` exactly like before.

A regular expression is compiled to an NFA program at compile time and run without backtracking, so a hostile
segment cannot make matching slow; it cannot contain `/` (use `\x2f`). Typical cost is a few ns per byte.

Mistakes are compile errors with a readable message: malformed pattern, bad regex, empty constraint, wildcard not last,
the same parameter name twice, more than 16 segments, or the same method and path registered twice.

## Middleware

A middleware is a callable `(Req&, Res&, Next next) -> task<void>`. Awaiting `next()` runs the rest of the chain
and the handler, so code after it is post-processing; not calling it short-circuits.

```cpp
auto timing = [](auto &req, auto &res, auto &next) -> wavex::task<void> {
    const auto t0 = std::chrono::steady_clock::now();
    co_await next();
    res.set("x-elapsed-us", std::to_string(micros_since(t0)));
};
```

`before(fn)` (`bool(Req&, Res&)`, false stops the chain) and `after(fn)` (`void(Req&, Res&)`) adapt plain
functions. Order for every route: global `use`, enclosing groups outer to inner, the route's own list, the
handler. A `use` applies to its whole scope wherever it appears in the list.

Each middleware layer that awaits `next()` is a coroutine frame (the compilers do not elide `asio::awaitable`
frames), so keep hot-path hooks to `before`/`after` or few layers.

## Segment comparison policy

The second template parameter of `static_router<Proto, Cmp>` is how literal segments are compared:

* `string_compare` (default): `string_view` equality.
* `hash_compare<Hash = fnv1a64>`: compares a 64-bit hash first and always confirms with the string, so a
  collision can never misroute. Hashes of registered segments are computed at compile time.

On a micro-benchmark (18 routes, 16 siblings at the widest level, GCC 14 `-O2`) `hash_compare` was slower than
`string_compare` (about 160-185 ns vs 125-135 ns per lookup): hashing each request segment costs more than
comparing short strings that differ early. It is opt-in for trees with many siblings sharing long prefixes; measure
before using it. A custom policy needs `key_type`, `prepare(string_view)` and `equals(key_type, key_type)`, all
`constexpr`.

## Limits

* The route set cannot change after construction (use `DynamicRouter` for runtime registration).
* Regex constraints use the `wavex::rx` subset (no lookaround, backreferences or captures), not RE2; no `HttpRouter` conveniences (`websocket`, `use(prefix, ...)`); `not_found(...)`
  is available.
* `DynamicRouter` does not take the `SegmentCompare` parameter yet.
