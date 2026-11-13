#!/usr/bin/env bash
# WebSocket Fuzzer Definition of Done (F07 §2.6, WSX-002): `gulp-cli ws-fuzz` sends several payloads
# into one `§…§` position over a single persistent socket (VulnLab /ws/fuzz echoes `echo: <payload>`),
# and the Fuzzer's grep/extract run on each reply — only the payload matching the grep is flagged, and
# the echoed value is extracted.
set -euo pipefail
cd "$(dirname "$0")/.."
PKG=Packages/GulpKit
# shellcheck disable=SC2086
swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --product gulp-vulnlab
# shellcheck disable=SC2086
swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --product gulp-cli
# shellcheck disable=SC2086
BIN=$(swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --show-bin-path)
WORK=$(mktemp -d); export GULP_SUPPORT_DIR="$WORK/support"
LAB=http://127.0.0.1:8088; GULP="$BIN/gulp-cli"
fail() { echo "FAIL: $*" >&2; exit 1; }

"$BIN/gulp-vulnlab" > "$WORK/vl.log" 2>&1 & VL=$!
trap 'kill $VL 2>/dev/null || true; rm -rf "$WORK"' EXIT
for _ in $(seq 1 300); do (exec 3<>"/dev/tcp/127.0.0.1/8088") 2>/dev/null && break; sleep 0.1; done

echo "== ws-fuzz /ws/fuzz =="
out=$("$GULP" ws-fuzz --target "$LAB" --path /ws/fuzz --template 'cmd=§x§' \
  --payloads alpha,bravo,INJECT --grep 'INJECT' --extract 'echo: cmd=(\w+)'); echo "$out"

echo "$out" | grep -q "3 message(s) over one socket" || fail "should send 3 messages over one socket"
echo "$out" | grep -q "1 match(es)" || fail "exactly one reply should match the grep"
echo "$out" | grep -q "\[MATCH\] #3 payload=INJECT" || fail "the INJECT payload should be the match"
echo "$out" | grep -q "extract=alpha" || fail "the echoed value should be extracted"
echo "PASS: ws-fuzz drives one socket, greps and extracts each reply"

echo "WS Fuzzer DoD: PASS"
