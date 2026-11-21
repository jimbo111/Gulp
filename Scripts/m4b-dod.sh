#!/usr/bin/env bash
# M4b Definition of Done (docs/03-roadmap.md), the parts that run headless on Linux:
#   "`curl -N` through Gulp to VulnLab `/sse` receives every event as it is sent and the history row
#    goes from 'streaming' to complete (F01 test 8); WebSocket messages show up in WS history."
# The pending → complete row transition is covered by the PRX-050/HIS-007 unit tests (the project is
# locked while the proxy runs); here the row is checked once the proxy has stopped. The Gulp Browser
# part of the DoD (F16 test 1) needs macOS and is checked by hand (docs/PROGRESS.md).
# Usage: Scripts/m4b-dod.sh   (SWIFTPM_FLAGS may carry extra swift-build flags, e.g. on Linux CI)
set -euo pipefail
cd "$(dirname "$0")/.."
PKG=Packages/GulpKit
PROXY_PORT=${PROXY_PORT:-18084}
# shellcheck disable=SC2086
swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --product gulp-vulnlab
# shellcheck disable=SC2086
swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --product gulp-cli
# shellcheck disable=SC2086
BIN=$(swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --show-bin-path)
WORK=$(mktemp -d)
PROJECT="$WORK/m4b-dod.gulp"

wait_port() {
  for _ in $(seq 1 300); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then return 0; fi
    sleep 0.1
  done
  echo "port $1 never opened" >&2
  return 1
}

now_ms() { perl -MTime::HiRes=time -e 'printf "%d\n", time * 1000'; }  # portable (BSD date has no %N)

"$BIN/gulp-vulnlab" > "$WORK/vulnlab.log" 2>&1 &
VULNLAB=$!
"$BIN/gulp-cli" proxy --project "$PROJECT" --port "$PROXY_PORT" > "$WORK/proxy.log" 2>&1 &
PROXY=$!
trap 'kill $VULNLAB $PROXY 2>/dev/null || true; rm -rf "$WORK"' EXIT
wait_port 8088
wait_port "$PROXY_PORT"

# 1. SSE: each of 5 events (200 ms apart) reaches curl as it is sent, not all at the end.
START=$(now_ms)
curl -sS -N --fail -x "http://127.0.0.1:$PROXY_PORT" "http://127.0.0.1:8088/sse?n=5" |
  while IFS= read -r line; do
    case "$line" in data:*) echo "$(( $(now_ms) - START )) $line" ;; esac
  done > "$WORK/sse.log"
cat "$WORK/sse.log"
[ "$(wc -l < "$WORK/sse.log")" -eq 5 ]
FIRST=$(head -n1 "$WORK/sse.log" | cut -d' ' -f1)
LAST=$(tail -n1 "$WORK/sse.log" | cut -d' ' -f1)
# Buffered whole, every event would arrive at the same moment (≈1 s); streamed, they are ≈800 ms apart.
[ $((LAST - FIRST)) -ge 500 ]
echo "PASS 1: curl -N received each SSE event as it was sent (first at ${FIRST} ms, last at ${LAST} ms)"

# 2. WebSocket through the proxy: VulnLab's greeting (sent with the 101) and two echoes.
"$BIN/gulp-cli" ws --url ws://127.0.0.1:8088/ws --via "http://127.0.0.1:$PROXY_PORT" \
  --send hello --send bye | tee "$WORK/ws.log"
grep -q "^connected: HTTP/1.1 101" "$WORK/ws.log"
grep -q "hello from VulnLab" "$WORK/ws.log"
grep -q "echo: hello" "$WORK/ws.log"
grep -q "echo: bye" "$WORK/ws.log"
echo "PASS 2: a WebSocket conversation went through the proxy in both directions"

kill -TERM "$PROXY"
wait "$PROXY"
"$BIN/gulp-cli" history --project "$PROJECT" --last 5 --websockets | tee "$WORK/history.log"
grep -E $'\tGET\t200\t.*/sse\\?n=5' "$WORK/history.log" > /dev/null
echo "PASS 3: the SSE exchange is in history, complete with status 200"
grep -E $'^ws [0-9]+\tws://127.0.0.1:8088/ws\tupgrade #[0-9]+\tclosed 1000\t' "$WORK/history.log" > /dev/null
grep -qE $'^  -> text\thello$' "$WORK/history.log"
grep -qE $'^  <- text\techo: hello$' "$WORK/history.log"
grep -qE $'^  <- text\thello from VulnLab$' "$WORK/history.log"
grep -qE $'^  -> close\tcode 1000$' "$WORK/history.log"
echo "PASS 4: WebSockets history has the connection (closed 1000) and its messages both ways"
echo "M4b DoD (headless part): PASS"
