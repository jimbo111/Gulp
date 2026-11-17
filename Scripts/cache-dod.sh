#!/usr/bin/env bash
# F28 (M24) Web cache poisoning & deception Definition of Done, as an executable check (F08 §3.5):
#   Active scanning the vulnerable CacheLab routes raises `active.cache-poisoning` (confirmed by a clean
#   follow-up served the cached canary — WCP-002) and `active.cache-deception` (private content cacheable
#   at a static-looking path — WCP-003); the /safe/ twins raise neither.
# Usage: Scripts/cache-dod.sh   (SWIFTPM_FLAGS may carry extra swift-build flags, e.g. on Linux CI)
set -euo pipefail
cd "$(dirname "$0")/.."
PKG=Packages/GulpKit
# shellcheck disable=SC2086
swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --product gulp-vulnlab
# shellcheck disable=SC2086
swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --product gulp-cli
# shellcheck disable=SC2086
BIN=$(swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --show-bin-path)
WORK=$(mktemp -d)
export GULP_SUPPORT_DIR="$WORK/support"
LAB=http://127.0.0.1:8088
GULP="$BIN/gulp-cli"
PROJECT="$WORK/cache.gulp"

fail() { echo "FAIL: $*" >&2; exit 1; }
wait_port() {
  for _ in $(seq 1 300); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then return 0; fi
    sleep 0.1
  done
  echo "port $1 never opened" >&2
  return 1
}
# Active-scan a single GET route; echo the finding lines.
scan() {
  printf 'GET %s HTTP/1.1\r\nHost: 127.0.0.1:8088\r\n\r\n' "$1" > "$WORK/req.txt"
  "$GULP" scan active --project "$PROJECT" --raw "$WORK/req.txt" --target "$LAB" --config thorough >/dev/null
}

"$BIN/gulp-vulnlab" > "$WORK/vulnlab.log" 2>&1 &
VULNLAB=$!
trap 'kill $VULNLAB 2>/dev/null || true; rm -rf "$WORK"' EXIT
wait_port 8088
"$GULP" scope --project "$PROJECT" --add "$LAB/" > /dev/null

# 1. WCP-002: cache poisoning on the vulnerable route, confirmed by a cached clean follow-up.
scan "/cache/poison"
"$GULP" issues --project "$PROJECT" | tee "$WORK/issues.txt"
grep -qE "active.cache-poisoning\s+http://127.0.0.1:8088/cache/poison" "$WORK/issues.txt" \
  || fail "no cache-poisoning issue on /cache/poison"
echo "PASS 1: cache poisoning found and cache-confirmed on /cache/poison (WCP-002)"

# 2. WCP-003: cache deception on the private account route (cacheable at a static suffix).
scan "/cache/acct"
"$GULP" issues --project "$PROJECT" | tee "$WORK/issues2.txt"
grep -qE "active.cache-deception\s+http://127.0.0.1:8088/cache/acct" "$WORK/issues2.txt" \
  || fail "no cache-deception issue on /cache/acct"
echo "PASS 2: cache deception found on /cache/acct (private content cacheable at a static path, WCP-003)"

# 3. The /safe/ twins raise neither.
scan "/safe/cache/poison"
scan "/safe/cache/acct"
"$GULP" issues --project "$PROJECT" | tee "$WORK/issues3.txt"
if grep -qE "active.cache-(poisoning|deception)\s+http://127.0.0.1:8088/safe/"; then
  fail "a cache issue fired on a /safe/ twin"
fi < "$WORK/issues3.txt"
echo "PASS 3: neither cache check fires on the /safe/ twins"

echo "Cache DoD: PASS"
