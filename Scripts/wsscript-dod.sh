#!/usr/bin/env bash
# Scripted WebSocket sequence Definition of Done (F15 §2.3, WSX-008): `gulp-cli ws-script` drives a
# send/expect sequence over one connection. Against VulnLab's /ws echo (which greets with "hello from
# VulnLab" then echoes `echo: <msg>`), the script waits for the greeting, sends two messages and
# matches each echo in order; a deliberately wrong expectation is reported as a miss.
set -euo pipefail
cd "$(dirname "$0")/.."
PKG=Packages/GulpKit
# shellcheck disable=SC2086
swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --product gulp-vulnlab
# shellcheck disable=SC2086
swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --product gulp-cli
# shellcheck disable=SC2086
BIN=$(swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --show-bin-path)
WORK=$(mktemp -d); GULP="$BIN/gulp-cli"; LAB=http://127.0.0.1:8088
fail() { echo "FAIL: $*" >&2; exit 1; }

"$BIN/gulp-vulnlab" > "$WORK/vl.log" 2>&1 & VL=$!
trap 'kill $VL 2>/dev/null || true; rm -rf "$WORK"' EXIT
for _ in $(seq 1 300); do (exec 3<>"/dev/tcp/127.0.0.1/8088") 2>/dev/null && break; sleep 0.1; done

cat > "$WORK/seq.txt" <<'SCRIPT'
# wait for the greeting, then two echoes in order
expect hello from VulnLab
send ping
expect echo: ping
send pong
expect-regex ^echo: pong$
SCRIPT

echo "== ws-script (happy path) =="
out=$("$GULP" ws-script --target "$LAB" --path /ws --script "$WORK/seq.txt"); echo "$out"
echo "$out" | grep -q "all steps matched" || fail "the full sequence should match in order"
echo "PASS 1: a stateful send/expect sequence runs over one socket, matching each frame in order"

cat > "$WORK/bad.txt" <<'SCRIPT'
expect hello from VulnLab
send ping
expect echo: THIS_IS_WRONG @1000
SCRIPT

echo "== ws-script (mismatch stops the run) =="
bad=$("$GULP" ws-script --target "$LAB" --path /ws --script "$WORK/bad.txt" || true); echo "$bad"
echo "$bad" | grep -q "did not match; stopping" || fail "a wrong expectation should stop the run"
echo "PASS 2: a mismatching expectation is reported and stops the sequence"

echo "WS script DoD: PASS"
