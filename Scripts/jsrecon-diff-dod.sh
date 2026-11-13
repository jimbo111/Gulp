#!/usr/bin/env bash
# JS Recon asset-diff Definition of Done (F27 JSR-009): diffing VulnLab's /recon/app.v2.js against the
# earlier /recon/app.js surfaces the newly-added `adminPanel` parameter and the new internal host, and
# the new `ssoToken` parameter recovered from the v2 source map — with nothing falsely removed.
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

echo "== js-recon --baseline =="
out=$("$GULP" js-recon --target "$LAB" --path /recon/app.v2.js --baseline /recon/app.js); echo "$out"

echo "$out" | grep -q "+ param adminPanel" || fail "the new adminPanel param should be added"
echo "$out" | grep -q "+ param ssoToken" || fail "the new ssoToken param (from the v2 map) should be added"
echo "$out" | grep -Eq "\+ literal .*admin\.corp" || fail "the new internal host should be added"
echo "$out" | grep -q "^  - param" && fail "nothing should be reported as removed (v2 is a superset)"
echo "PASS: the asset diff surfaces the new attack surface, nothing falsely removed"

echo "JS Recon asset-diff DoD: PASS"
