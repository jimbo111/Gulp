#!/usr/bin/env bash
# JavaScript Recon Definition of Done (F27 JSR-003/006/008): on VulnLab /recon/app.js the tool recovers
# the original source from the exposed .map (src/secret.js), mines the hidden parameters (debug,
# featureFlag, trace, admin) and flags the interesting literals (an S3 bucket and an internal host).
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

out=$("$GULP" js-recon --target "$LAB" --path /recon/app.js); echo "$out"
echo "$out" | grep -q "src/secret.js" || fail "the source map was not reconstructed"
echo "$out" | grep -q "debug" || fail "hidden parameter 'debug' not mined"
echo "$out" | grep -q "betaFeature" || fail "parameter 'betaFeature' from the recovered source not mined"
echo "$out" | grep -q "resetToken" || fail "parameter 'resetToken' from the recovered source not mined"
echo "$out" | grep -qi "s3.amazonaws.com" || fail "the cloud-storage literal was not flagged"
echo "$out" | grep -qi "api.internal" || fail "the internal-host literal was not flagged"
echo "JS Recon DoD: PASS"
