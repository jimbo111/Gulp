#!/usr/bin/env bash
# M2 Definition of Done (docs/03-roadmap.md), as an executable check:
#   "Browse http://localhost:8088 through Gulp; 10k requests are recorded and scroll smoothly;
#    quitting and reopening the project shows the same history."
# Headless here: a real client (curl) browses VulnLab through `gulp-cli proxy`, 10,000 more requests
# go through the proxy, the proxy quits (flushing the write coalescer), and the reopened project
# must hold every exchange. Smooth scrolling is the GUI's paging (HIS-002 tests + UI smoke test).
# Usage: Scripts/m2-dod.sh   (SWIFTPM_FLAGS may carry extra swift-build flags, e.g. on Linux CI)
set -euo pipefail
cd "$(dirname "$0")/.."
PKG=Packages/GulpKit
REQUESTS=${REQUESTS:-10000}
PROXY_PORT=${PROXY_PORT:-18080}
# shellcheck disable=SC2086
swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --product gulp-vulnlab
# shellcheck disable=SC2086
swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --product gulp-cli
# shellcheck disable=SC2086
BIN=$(swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --show-bin-path)
WORK=$(mktemp -d)
# Isolated CA and secrets: never the user's Keychain (on macOS that blocks on an access prompt).
export GULP_SUPPORT_DIR="$WORK/support"
PROJECT="$WORK/m2-dod.gulp"

wait_port() {
  for _ in $(seq 1 200); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then return 0; fi
    sleep 0.1
  done
  echo "port $1 never opened" >&2
  return 1
}

"$BIN/gulp-vulnlab" > "$WORK/vulnlab.log" 2>&1 &
VULNLAB=$!
"$BIN/gulp-cli" proxy --project "$PROJECT" --port "$PROXY_PORT" > "$WORK/proxy.log" 2>&1 &
PROXY=$!
trap 'kill $VULNLAB $PROXY 2>/dev/null || true; rm -rf "$WORK"' EXIT
wait_port 8088
wait_port "$PROXY_PORT"

# 1. A real client browses VulnLab through Gulp.
BODY=$(curl -sS --fail -x "http://127.0.0.1:$PROXY_PORT" http://127.0.0.1:8088/echo)
grep -q "GET /echo HTTP/1.1" <<< "$BODY"
echo "PASS 1: curl browsed http://127.0.0.1:8088/echo through the Gulp proxy"

# 2. 10,000 more requests through the proxy.
printf 'GET /echo?n=1 HTTP/1.1\r\nHost: 127.0.0.1:8088\r\n\r\n' > "$WORK/req.txt"
"$BIN/gulp-cli" send --raw "$WORK/req.txt" --target http://127.0.0.1:8088 \
  --via "http://127.0.0.1:$PROXY_PORT" --repeat "$REQUESTS" --concurrency 8 | tee "$WORK/send.log"
grep -q "^$REQUESTS/$REQUESTS succeeded$" "$WORK/send.log"
echo "PASS 2: $REQUESTS requests went through the proxy"

# 3. Quit the proxy (graceful: flushes the write coalescer), then reopen the project.
kill -TERM "$PROXY"
wait "$PROXY"
EXPECTED=$((REQUESTS + 1))
"$BIN/gulp-cli" history --project "$PROJECT" --last 3 | tee "$WORK/history.log"
grep -q "^exchanges: $EXPECTED$" "$WORK/history.log"
grep -q "http://127.0.0.1:8088/echo?n=1" "$WORK/history.log"
echo "PASS 3: the reopened project holds all $EXPECTED exchanges"
echo "M2 DoD: PASS"
