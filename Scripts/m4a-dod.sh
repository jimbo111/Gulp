#!/usr/bin/env bash
# M4a Definition of Done (docs/03-roadmap.md), as an executable check:
#   "Intercept a login POST, change a parameter, and forward it; a match-replace rule adds a header
#    to every request; 'Copy as cURL' on a history row reproduces the request against /echo."
# Headless: `gulp-cli proxy --intercept-replace` is a scripted intercept user (the request is held in
# the real Intercept queue, edited and forwarded), `--add-header` is a Match & Replace rule, and the
# recorded row is exported with `gulp-cli copy-as` and run against VulnLab directly.
# Usage: Scripts/m4a-dod.sh   (SWIFTPM_FLAGS may carry extra swift-build flags, e.g. on Linux CI)
set -euo pipefail
cd "$(dirname "$0")/.."
PKG=Packages/GulpKit
PROXY_PORT=${PROXY_PORT:-18083}
# shellcheck disable=SC2086
swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --product gulp-vulnlab
# shellcheck disable=SC2086
swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --product gulp-cli
# shellcheck disable=SC2086
BIN=$(swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --show-bin-path)
WORK=$(mktemp -d)
# Isolated CA and secrets: never the user's Keychain (on macOS that blocks on an access prompt).
export GULP_SUPPORT_DIR="$WORK/support"
PROJECT="$WORK/m4a-dod.gulp"

wait_port() {
  for _ in $(seq 1 300); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then return 0; fi
    sleep 0.1
  done
  echo "port $1 never opened" >&2
  return 1
}

"$BIN/gulp-vulnlab" > "$WORK/vulnlab.log" 2>&1 &
VULNLAB=$!
"$BIN/gulp-cli" proxy --project "$PROJECT" --port "$PROXY_PORT" \
  --add-header "X-Gulp-DoD: m4a" --intercept-replace "user=alice=>user=admin" > "$WORK/proxy.log" 2>&1 &
PROXY=$!
trap 'kill $VULNLAB $PROXY 2>/dev/null || true; rm -rf "$WORK"' EXIT
wait_port 8088
wait_port "$PROXY_PORT"

# 1 + 2. A login POST through the proxy: intercepted and edited, with the Match & Replace header.
BODY=$(curl -sS --fail -x "http://127.0.0.1:$PROXY_PORT" --data 'user=alice&pw=hunter2' \
  http://127.0.0.1:8088/echo)
grep -q "user=admin&pw=hunter2" <<< "$BODY"
grep -q "^Content-Length: 21" <<< "$(tr -d '\r' <<< "$BODY")"
echo "PASS 1: the intercepted POST was edited (user=alice → user=admin) and forwarded"
grep -q "^X-Gulp-DoD: m4a" <<< "$(tr -d '\r' <<< "$BODY")"
echo "PASS 2: the Match & Replace rule added X-Gulp-DoD: m4a"

# 3. Copy as cURL reproduces the recorded request against /echo (without the proxy).
kill -TERM "$PROXY"
wait "$PROXY"
"$BIN/gulp-cli" history --project "$PROJECT" --last 5 | tee "$WORK/history.log"
ID=$(grep -E $'\tPOST\t' "$WORK/history.log" | head -n1 | cut -f1)
"$BIN/gulp-cli" history --project "$PROJECT" --show "$ID" > "$WORK/show.log"
grep -q "user=alice&pw=hunter2" "$WORK/show.log"  # the original is kept (PRX-012)
"$BIN/gulp-cli" copy-as --project "$PROJECT" --id "$ID" --format curl | tee "$WORK/copy.sh"
REPLAY=$(bash "$WORK/copy.sh")
grep -q "POST /echo HTTP/1.1" <<< "$REPLAY"
grep -q "user=admin&pw=hunter2" <<< "$REPLAY"
grep -q "X-Gulp-DoD: m4a" <<< "$REPLAY"
echo "PASS 3: Copy as cURL replayed the recorded request against /echo"
echo "M4a DoD: PASS"
