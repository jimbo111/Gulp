#!/usr/bin/env bash
# Parameter Discovery Definition of Done (F23 ADV-020): on VulnLab /params the miner finds the hidden
# `debug` (behaviour) and `trace` (reflected) parameters and nothing advertised; on /safe/params it
# finds nothing.
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

mine() {  # <path>
  printf 'GET %s HTTP/1.1\r\nHost: 127.0.0.1:8088\r\n\r\n' "$1" > "$WORK/req.txt"
  "$GULP" discover-params --raw "$WORK/req.txt" --target "$LAB"
}

echo "== /params =="
out=$(mine /params); echo "$out"
echo "$out" | grep -q "debug" || fail "debug not discovered on /params"
echo "$out" | grep -q "trace" || fail "trace not discovered on /params"
echo "PASS 1: hidden debug (behaviour) and trace (reflected) found on /params"

echo "== /safe/params =="
safe=$(mine /safe/params); echo "$safe"
echo "$safe" | grep -qE "^\s+(debug|trace|admin)" && fail "a param was wrongly discovered on /safe/params"
echo "PASS 2: nothing discovered on /safe/params"

echo "Parameter Discovery DoD: PASS"
