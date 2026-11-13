#!/usr/bin/env bash
# Parameter-pollution Definition of Done (F23 ADV-022): on VulnLab /pollute the duplicated parameter is
# resolved last-wins (a pollution quirk that can bypass a first-value WAF check); /safe/pollute is
# first-wins.
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

run() {  # <path>
  printf 'GET %s?name=original HTTP/1.1\r\nHost: 127.0.0.1:8088\r\n\r\n' "$1" > "$WORK/req.txt"
  "$GULP" pollute --raw "$WORK/req.txt" --target "$LAB"
}

echo "== /pollute =="
out=$(run /pollute); echo "$out"
echo "$out" | grep -q "last-wins" || fail "/pollute should be last-wins"
echo "PASS 1: /pollute resolves the duplicate last-wins (pollution quirk)"

echo "== /safe/pollute =="
safe=$(run /safe/pollute); echo "$safe"
echo "$safe" | grep -q "first-wins" || fail "/safe/pollute should be first-wins"
echo "PASS 2: /safe/pollute resolves the duplicate first-wins"

echo "Parameter pollution DoD: PASS"
