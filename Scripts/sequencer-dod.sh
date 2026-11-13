#!/usr/bin/env bash
# Sequencer Definition of Done (F11 acceptance 1–2): capture tokens from VulnLab and check the verdict.
#   - /token/weak  (8 constant hex + an incrementing counter) → Poor / Extremely poor.
#   - /token/strong (16 CSPRNG hex) → Excellent.
# Usage: Scripts/sequencer-dod.sh   (SWIFTPM_FLAGS may carry extra swift-build flags)
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

fail() { echo "FAIL: $*" >&2; exit 1; }

"$BIN/gulp-vulnlab" > "$WORK/vulnlab.log" 2>&1 &
VULNLAB=$!
trap 'kill $VULNLAB 2>/dev/null || true; rm -rf "$WORK"' EXIT
for _ in $(seq 1 300); do (exec 3<>"/dev/tcp/127.0.0.1/8088") 2>/dev/null && break; sleep 0.1; done

analyze() {  # <path> <count> → prints the report, returns the verdict line
  local path="$1" count="$2"
  printf 'GET %s HTTP/1.1\r\nHost: 127.0.0.1:8088\r\n\r\n' "$path" > "$WORK/req.txt"
  "$GULP" sequencer --raw "$WORK/req.txt" --target "$LAB" --cookie SID --count "$count" --concurrency 20
}

echo "== weak token =="
weak=$(analyze /token/weak 1500)
echo "$weak"
echo "$weak" | grep -Eq 'verdict: (Poor|Extremely poor)' \
  || fail "/token/weak should be rated Poor/Extremely poor"
echo "PASS 1: the predictable counter token is rated Poor/Extremely poor"

echo "== strong token =="
strong=$(analyze /token/strong 1500)
echo "$strong"
echo "$strong" | grep -q 'verdict: Excellent' || fail "/token/strong should be rated Excellent"
echo "PASS 2: the CSPRNG token is rated Excellent"

echo "Sequencer DoD: PASS"
