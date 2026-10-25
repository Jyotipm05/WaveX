# Benchmarks

Two small programs and a runner, no external tools required.

| Target | Purpose |
|:---|:---|
| `wavex_bench_server` | HTTP/1.1 server with `/hello` (13 B), `/blob` (64 KiB) and `/sleep` (2 ms via `spawn_blocking`) |
| `wavex_loadgen` | Closed-loop keep-alive client; prints one JSON line with rps, p50/p90/p99/p99.9/max and error counts. `--idle N` also holds N silent connections |
| `run.sh` | Runs four scenarios (hello, blob, offload, hello-with-idle) for a tier |

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DWAVEX_BENCH=ON
cmake --build build --target wavex_bench_server wavex_loadgen
benchmarks/run.sh build ci      # 32 active + 1,000 idle   (2 vCPU hosted runner)
benchmarks/run.sh build full    # 256 active + 10,000 idle (dedicated machine)
```

## Reading the numbers

- The load generator and the server share the machine. On the 2 vCPU `ci` tier that means they share two cores, so compare a run with another run **on the same job or machine**, never with a number from elsewhere.
- The loop is closed (the next request is sent after the previous reply), which hides stalls: a server that freezes for 200 ms shows up as one slow request, not as the hundreds an open-loop generator would record. Use p99 as a relative signal.
- Hosted runners are noisy. A single run proves nothing; look for differences well beyond the spread of repeated runs.
- `hello-with-idle` should report `idle_connected == idle_requested`; a smaller number means the server (or the file-descriptor limit) refused connections.
