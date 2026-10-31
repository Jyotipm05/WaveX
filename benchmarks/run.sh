#!/usr/bin/env bash
# Runs the WaveX benchmark scenarios and writes one JSON line per scenario to $OUT (default: bench-results.jsonl).
#
#   benchmarks/run.sh <build-dir> [tier]
#
# tier "ci"   : 2 vCPU GitHub-hosted runner. Loadgen and server share the two cores, so absolute numbers are
#               only meaningful when compared with another run on the same job. 1,000 idle connections
#               stand in for the 10k scenario (the runner's CPU/memory budget cannot host 10k).
# tier "full" : a dedicated machine. 10,000 idle connections.
set -euo pipefail

BUILD="${1:?usage: run.sh <build-dir> [ci|full]}"
TIER="${2:-ci}"
PORT="${PORT:-18080}"
OUT="${OUT:-bench-results.jsonl}"
DURATION="${DURATION:-8}"

case "$TIER" in
    ci)   ACTIVE=32;  IDLE=1000 ;;
    full) ACTIVE=256; IDLE=10000 ;;
    *) echo "unknown tier $TIER" >&2; exit 2 ;;
esac

ulimit -n "$((IDLE + ACTIVE + 256))" 2>/dev/null || echo "warning: could not raise ulimit -n" >&2

SERVER_PID=""
stop_server() { [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null && wait "$SERVER_PID" 2>/dev/null || true; SERVER_PID=""; }
trap stop_server EXIT

# A fresh server per scenario: no state carries over, and a crash only fails its own scenario.
start_server() {
    "$BUILD/wavex_bench_server" "$PORT" >/dev/null 2>&1 &
    SERVER_PID=$!
    for _ in $(seq 1 50); do
        (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

: > "$OUT"
FAILED=0
run() { # name path conns idle
    echo "== $1" >&2
    start_server || { echo "server did not start" >&2; FAILED=1; return; }
    local line
    if line=$("$BUILD/wavex_loadgen" --port "$PORT" --path "$2" --conns "$3" --idle "$4" --duration "$DURATION" --warmup 2); then
        :
    else
        echo "scenario $1: loadgen reported errors" >&2; FAILED=1
    fi
    if [ -n "$line" ]; then
        printf '%s\n' "$line" | sed "s/^{/{\"scenario\":\"$1\",\"tier\":\"$TIER\",/" | tee -a "$OUT"
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "scenario $1: SERVER CRASHED" >&2; FAILED=1
    fi
    stop_server
}

run hello           /hello "$ACTIVE" 0
run blob-64k        /blob  "$ACTIVE" 0
run offload-sleep   /sleep "$ACTIVE" 0
run hello-with-idle /hello "$ACTIVE" "$IDLE"

exit "$FAILED"
