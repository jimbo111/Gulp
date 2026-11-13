#!/usr/bin/env bash
# CSWSH Definition of Done (F23 WSX-004): the probe flags VulnLab's /ws (which upgrades regardless of
# Origin) as cross-site-WebSocket-hijackable from an attacker Origin, and /safe/ws (which checks Origin)
# as not.
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

echo "== /ws (vulnerable) =="
vuln=$("$GULP" cswsh --target "$LAB" --path /ws --origin https://evil.example); echo "$vuln"
echo "$vuln" | grep -q "VULNERABLE" || fail "/ws should accept the cross-site handshake"
echo "PASS 1: /ws accepts a cross-site handshake (CSWSH)"

echo "== /safe/ws (origin-checked) =="
safe=$("$GULP" cswsh --target "$LAB" --path /safe/ws --origin https://evil.example); echo "$safe"
echo "$safe" | grep -q "VULNERABLE" && fail "/safe/ws must reject the cross-site handshake"
echo "PASS 2: /safe/ws rejects the cross-site handshake"

echo "CSWSH DoD: PASS"
