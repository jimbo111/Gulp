#!/usr/bin/env bash
# F30 (M25) Issue retest Definition of Done, as an executable check (F08 §2.4 / F21 §2.4):
#   An active issue's proof re-run flips Still-Vulnerable → Fixed after the route is patched, and
#   `gulp retest --fail-on-regression` exits non-zero when a previously-fixed issue is vulnerable again.
# Uses VulnLab's /lab/patch and /lab/unpatch to toggle a route between vulnerable and patched.
# Usage: Scripts/retest-dod.sh   (SWIFTPM_FLAGS may carry extra swift-build flags, e.g. on Linux CI)
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
PROJECT="$WORK/retest.gulp"

fail() { echo "FAIL: $*" >&2; exit 1; }
wait_port() {
  for _ in $(seq 1 300); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then return 0; fi
    sleep 0.1
  done
  echo "port $1 never opened" >&2
  return 1
}
# GET a VulnLab route over a raw TCP exchange (no curl dependency).
labget() {
  printf 'GET %s HTTP/1.1\r\nHost: 127.0.0.1:8088\r\nConnection: close\r\n\r\n' "$1" > "$WORK/req.txt"
  "$GULP" send --raw "$WORK/req.txt" --target "$LAB" > /dev/null
}

"$BIN/gulp-vulnlab" > "$WORK/vulnlab.log" 2>&1 &
VULNLAB=$!
trap 'kill $VULNLAB 2>/dev/null || true; rm -rf "$WORK"' EXIT
wait_port 8088

"$GULP" scope --project "$PROJECT" --add "$LAB/" > /dev/null

# 1. Scan the vulnerable /ssti route → an active issue with a replayable proof.
printf 'GET /ssti?name=gulp HTTP/1.1\r\nHost: 127.0.0.1:8088\r\n\r\n' > "$WORK/ssti.txt"
"$GULP" scan active --project "$PROJECT" --raw "$WORK/ssti.txt" --target "$LAB" --config thorough \
  | tee "$WORK/scan.txt"
"$GULP" issues --project "$PROJECT" | tee "$WORK/issues.txt"
grep -q "active.ssti" "$WORK/issues.txt" || fail "the scan did not find active.ssti on /ssti"
echo "PASS 1: active.ssti found on the vulnerable /ssti route"

# 2. Retest while still vulnerable → Still-Vulnerable.
"$GULP" retest --project "$PROJECT" | tee "$WORK/r1.txt"
grep -qE "still-vulnerable|REGRESSION" "$WORK/r1.txt" || fail "retest did not report the issue still-vulnerable"
grep -q "0 regression" "$WORK/r1.txt" || fail "a regression was reported before any fix"
echo "PASS 2: retest on the unpatched route reports still-vulnerable, no regression"

# 3. Patch the route, retest → Fixed.
labget "/lab/patch?route=/ssti"
"$GULP" retest --project "$PROJECT" | tee "$WORK/r2.txt"
grep -qE "FIXED|: [1-9][0-9]* fixed" "$WORK/r2.txt" || fail "retest did not flip the issue to Fixed after the patch"
"$GULP" issues --project "$PROJECT" --status fixed | tee "$WORK/fixed.txt"
grep -q "active.ssti" "$WORK/fixed.txt" || fail "the issue status was not updated to fixed"
echo "PASS 3: after patching, retest flips the issue Still-Vulnerable → Fixed"

# 4. Un-patch (regression), retest --fail-on-regression → non-zero exit.
labget "/lab/unpatch?route=/ssti"
set +e
"$GULP" retest --project "$PROJECT" --fail-on-regression | tee "$WORK/r3.txt"
RC=$?
set -e
grep -q "REGRESSION" "$WORK/r3.txt" || fail "the reintroduced vulnerability was not flagged as a regression"
[ "$RC" -ne 0 ] || fail "--fail-on-regression exited 0 despite a regression"
echo "PASS 4: a reintroduced vulnerability is a regression; --fail-on-regression exits non-zero (rc=$RC)"

echo "Retest DoD: PASS"
