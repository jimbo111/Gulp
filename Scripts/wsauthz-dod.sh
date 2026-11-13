#!/usr/bin/env bash
# WebSocket per-message authorization Definition of Done (F23 WSX-004, acceptance test 8): VulnLab's
# /ws/authz authorizes only at the handshake, so a privileged message replayed under a stripped
# (non-admin) identity still succeeds — the probe flags it. The per-message-authz twin /safe/ws/authz
# re-checks each message, so the stripped identity is refused — the probe reports it enforced.
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
MSG='{"action":"secret"}'
fail() { echo "FAIL: $*" >&2; exit 1; }

"$BIN/gulp-vulnlab" > "$WORK/vl.log" 2>&1 & VL=$!
trap 'kill $VL 2>/dev/null || true; rm -rf "$WORK"' EXIT
for _ in $(seq 1 300); do (exec 3<>"/dev/tcp/127.0.0.1/8088") 2>/dev/null && break; sleep 0.1; done

echo "== /ws/authz (handshake-only) =="
vuln=$("$GULP" ws-authz --target "$LAB" --path /ws/authz --message "$MSG" \
  --privileged-cookie sid=admin --stripped-cookie sid=guest --success-marker TOP-SECRET); echo "$vuln"
echo "$vuln" | grep -q "VULNERABLE" || fail "/ws/authz should let the stripped identity read the secret"
echo "PASS 1: /ws/authz authorizes only at the handshake (per-message authz missing)"

echo "== /safe/ws/authz (per-message) =="
safe=$("$GULP" ws-authz --target "$LAB" --path /safe/ws/authz --message "$MSG" \
  --privileged-cookie sid=admin --stripped-cookie sid=guest --success-marker TOP-SECRET); echo "$safe"
echo "$safe" | grep -q "VULNERABLE" && fail "/safe/ws/authz must refuse the stripped identity"
echo "$safe" | grep -q "enforced" || fail "/safe/ws/authz should report enforced"
echo "PASS 2: /safe/ws/authz re-authorizes each message"

echo "WS per-message authz DoD: PASS"
