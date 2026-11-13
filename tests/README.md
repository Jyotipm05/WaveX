# Tests

One executable per test file, grouped by area. The CMake target name (`wavex_<name>_tests`) is also the ctest name and does not depend on the directory.

| Directory     | What it covers                                                                                           |
|:--------------|:---------------------------------------------------------------------------------------------------------|
| `base/`       | Utilities: `FlatMap`, `RequestArena`, executors, `spawn_blocking`, async file I/O, temp files, CLI, logger, DNS |
| `routing/`    | `DynamicRouter`, `StaticRouter`, compile-time regex (`wavex::rx`), `Chainable`/middleware, 404 handling    |
| `protocols/`  | HTTP/2 codec and session, QPACK, QUIC, HTTP/3, WebSocket, WebTransport, `protocol_traits`                |
| `server/`     | Request handling, chunked bodies, keep-alive, request limits, connection tracking, composed h2 + h3 server |
| `client/`     | `HttpClient`, file upload, response streaming and the pull reader, HTTP/3 client and pool                |
| `content/`    | Compression and multipart                                                                                |
| `checks/`     | Checks about the build itself: public include cost, C++ module smoke test                                |
| `support/`    | Shared test helpers (`project_root.hpp` finds `ssl/` from any depth); not a test group                    |

The Postman dev servers are not tests; they live in [`tools/dev-servers/`](../tools/dev-servers).

## Running

```bash
ctest --test-dir build --output-on-failure            # everything
ctest --test-dir build -L routing                     # one group (labels = directory names)
ctest --test-dir build -R static_router               # by name
ctest --test-dir build -L routing -L asan             # a group under a sanitizer preset (label asan/tsan is added too)
```

Most server and client tests bind fixed loopback ports, so ctest runs them under one resource lock and `-j N` is safe. TLS and HTTP/3 tests need `ssl/test.crt` and `ssl/test.key` (see `CONTRIBUTING.md`).

## Adding a test

1. Put `test_<thing>.cpp` in the directory that matches what it exercises (a test that needs a running server and a client goes in `server/` or `client/`, whichever is under test).
2. Register it in [`WaveXTests.cmake`](WaveXTests.cmake) under that group: `wavex_add_test(wavex_<thing>_tests <dir>/test_<thing>.cpp)`. Put it inside `if (WAVEX_HAS_SSL)` when it needs TLS or QUIC.
3. Tests are plain `assert()`/`check()` programs that exit non-zero on failure. `NDEBUG` is undone for them, so asserts may wrap the call under test.

`wavex_add_test` links `wavex`, reuses the precompiled `<wavex/wavex.hpp>`, and adds the group label. Pass `DEFINES ...` for per-test macros (this opts the test out of the shared precompiled header).
