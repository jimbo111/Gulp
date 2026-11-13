#!/usr/bin/env bash
# OAST-over-WebSocket Definition of Done (F07 §2.6, WSX-005): a WebSocket message carrying an OAST
# payload URL to VulnLab's /ws/ssrf makes the lab fetch it out of band, and `gulp-cli ws-oast`
# correlates the resulting DNS + HTTP interactions to that payload — a blind SSRF reachable only over
# the socket.
set -euo pipefail
cd "$(dirname "$0")/.."
PKG=Packages/GulpKit
# shellcheck disable=SC2086
swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --product gulp-vulnlab
# shellcheck disable=SC2086
swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --product gulp-cli
# shellcheck disable=SC2086
swift build --package-path Beacon ${SWIFTPM_FLAGS:-} --product gulp-beacon
# shellcheck disable=SC2086
BIN=$(swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --show-bin-path)
# shellcheck disable=SC2086
BEACON_BIN=$(swift build --package-path Beacon ${SWIFTPM_FLAGS:-} --show-bin-path)
WORK=$(mktemp -d); GULP="$BIN/gulp-cli"
LAB=http://127.0.0.1:8088
fail() { echo "FAIL: $*" >&2; exit 1; }
wait_port() { for _ in $(seq 1 300); do (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0; sleep 0.1; done; return 1; }

"$BIN/gulp-vulnlab" > "$WORK/vl.log" 2>&1 & VL=$!
"$BEACON_BIN/gulp-beacon" --dev > "$WORK/beacon.log" 2>&1 & BC=$!
trap 'kill $VL $BC 2>/dev/null || true; rm -rf "$WORK"' EXIT
wait_port 8088 || fail "VulnLab never came up"
wait_port 8090 || fail "Beacon never came up"

echo "== ws-oast /ws/ssrf =="
out=$("$GULP" ws-oast --target "$LAB" --path /ws/ssrf \
  --oast-server http://127.0.0.1:8090 --oast-domain oast.test --wait 10); echo "$out"
echo "$out" | grep -q "VULNERABLE" || fail "/ws/ssrf should trigger an OAST interaction"
echo "$out" | grep -q "http" || fail "an HTTP interaction should be correlated"
echo "PASS: a WebSocket message triggered a correlated blind-SSRF interaction"

echo "WS OAST DoD: PASS"
