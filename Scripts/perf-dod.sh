#!/usr/bin/env bash
# Proxy performance budgets of doc 01 §9 (daily-driver beta gate, docs/03-roadmap.md), as an
# executable check (doc 06 §5):
#   "Proxy added latency (median, keep-alive, small responses) < 5 ms"
#   "Proxy throughput ≥ 2,000 req/s locally against VulnLab"
# plus: every request that went through is recorded, complete, once the proxy has stopped.
# Release build: these budgets are about the product, and a debug client cannot drive the proxy
# hard enough to measure it. The other §9 budgets are checked elsewhere: History at 1M rows in
# m9-dod.sh, Comparer in m7-dod.sh, Fuzzer in m8-dod.sh, the 5 MB message in
# GulpFeaturesTests/MessageFirstPaintTests (see docs/PROGRESS.md for the latest numbers).
# Usage: Scripts/perf-dod.sh   (SWIFTPM_FLAGS may carry extra swift-build flags, e.g. on Linux CI;
#        LAB_PORT / PROXY_PORT move VulnLab and the proxy off their default ports)
set -euo pipefail
cd "$(dirname "$0")/.."
PKG=Packages/GulpKit
# shellcheck disable=SC2086
swift build -c release --package-path "$PKG" ${SWIFTPM_FLAGS:-} --product gulp-vulnlab
# shellcheck disable=SC2086
swift build -c release --package-path "$PKG" ${SWIFTPM_FLAGS:-} --product gulp-cli
# shellcheck disable=SC2086
BIN=$(swift build -c release --package-path "$PKG" ${SWIFTPM_FLAGS:-} --show-bin-path)
WORK=$(mktemp -d)
export GULP_SUPPORT_DIR="$WORK/support"
LAB_PORT=${LAB_PORT:-8088}
PROXY_PORT=${PROXY_PORT:-18091}
LAB=http://127.0.0.1:$LAB_PORT
VIA=http://127.0.0.1:$PROXY_PORT
GULP="$BIN/gulp-cli"
PROJECT="$WORK/perf.gulp"

wait_port() {
  for _ in $(seq 1 300); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then return 0; fi
    sleep 0.1
  done
  echo "port $1 never opened" >&2
  return 1
}

"$BIN/gulp-vulnlab" --port "$LAB_PORT" --raw-port $((LAB_PORT + 1)) --tls-port $((LAB_PORT + 2)) \
  > "$WORK/vulnlab.log" 2>&1 &
VULNLAB=$!
PROXY=""
trap 'kill $VULNLAB $PROXY 2>/dev/null || true; rm -rf "$WORK"' EXIT
wait_port "$LAB_PORT"
"$GULP" proxy --project "$PROJECT" --port "$PROXY_PORT" > "$WORK/proxy.log" 2>&1 &
PROXY=$!
wait_port "$PROXY_PORT"
printf 'GET /echo?n={n} HTTP/1.1\r\nHost: 127.0.0.1:%s\r\n\r\n' "$LAB_PORT" > "$WORK/req.txt"

# `gulp-cli send --repeat` prints "latency p50 X ms, p99 Y ms; R req/s over S s" after the count.
send() { "$GULP" send --raw "$WORK/req.txt" --target "$LAB" "$@" | tail -1; }
p50() { sed -n 's/^latency p50 \([0-9.]*\) ms.*/\1/p'; }
rate() { sed -n 's/.*; \([0-9]*\) req\/s over.*/\1/p'; }

# 1. Added latency: the median of 2,000 sequential keep-alive requests through the proxy, minus
#    the median of the same requests sent directly (both after a warm-up).
send --repeat 200 > /dev/null
send --repeat 200 --via "$VIA" > /dev/null
DIRECT=$(send --repeat 2000 | p50)
PROXIED=$(send --repeat 2000 --via "$VIA" | p50)
ADDED=$(awk -v p="$PROXIED" -v d="$DIRECT" 'BEGIN { printf "%.3f", p - d }')
awk -v a="$ADDED" 'BEGIN { exit !(a < 5) }'
echo "PASS 1: proxy added latency ${ADDED} ms at the median (${PROXIED} ms proxied vs ${DIRECT} ms direct; budget < 5 ms)"

# 2. Throughput: 20,000 requests through the proxy, 32 at a time.
RATE=$(send --repeat 20000 --concurrency 32 --via "$VIA" | rate)
[ "$RATE" -ge 2000 ]
echo "PASS 2: proxy throughput ${RATE} req/s with 32 keep-alive clients (budget ≥ 2,000 req/s)"

# 3. Nothing is lost: stopping the proxy right after the load still records every exchange, complete.
kill -TERM "$PROXY"
wait "$PROXY" || true
PROXY=""
TOTAL=$((200 + 2000 + 20000))
"$GULP" history --project "$PROJECT" | grep -q "^exchanges: $TOTAL$"
"$GULP" query --project "$PROJECT" 'resp.status in 200..299' | grep -qE "^matched $TOTAL in "
echo "PASS 3: all $TOTAL proxied exchanges are recorded with their 200 response"

echo "Proxy performance budgets: PASS"
