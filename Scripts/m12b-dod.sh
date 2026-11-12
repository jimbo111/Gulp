#!/usr/bin/env bash
# M12b Definition of Done (docs/03-roadmap.md), as an executable check:
#   "Authz Matrix flags the VulnLab IDOR (/api/orders/{id}) ... with the /safe/* twins 'Enforced'."
# `gulp-cli authz orders` logs in bob (owns order 2) and alice, then replays /api/orders/2 and
# /safe/api/orders/2 as bob (authorized), alice and unauthenticated. The matrix must mark alice's
# cell on /api/orders/2 "bypassed" (she sees bob's order) and "enforced" on the /safe twin (403),
# and raise an access-control issue.
# Usage: Scripts/m12b-dod.sh   (SWIFTPM_FLAGS may carry extra swift-build flags, e.g. on Linux CI)
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

fail() {
  echo "FAIL: $*" >&2
  exit 1
}
wait_port() {
  for _ in $(seq 1 300); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then return 0; fi
    sleep 0.1
  done
  echo "port $1 never opened" >&2
  return 1
}

"$BIN/gulp-vulnlab" > "$WORK/vulnlab.log" 2>&1 &
VULNLAB=$!
trap 'kill $VULNLAB 2>/dev/null || true; rm -rf "$WORK"' EXIT
wait_port 8088

"$GULP" scope --project "$WORK/authz.gulp" --add "$LAB/" > /dev/null
"$GULP" authz orders --project "$WORK/authz.gulp" --base "$LAB" | tee "$WORK/authz.txt"

# Column order: bob (authorized), alice, unauth.
grep -qE '^authz: request\s+bob\s+alice\s+unauth' "$WORK/authz.txt" || fail "unexpected matrix header"
# The IDOR: alice (column 2) sees bob's order → bypassed; the unauth column is public (ignores auth).
grep -qE '^GET /api/orders/2\s+authorized\s+bypassed\s+same-as-authorized' "$WORK/authz.txt" || fail "IDOR not flagged as a bypass"
# The enforcing twin: alice is denied (403) → enforced; unauth also enforced.
grep -qE '^GET /safe/api/orders/2\s+authorized\s+enforced\s+enforced' "$WORK/authz.txt" || fail "the safe twin wasn't Enforced"
grep -qE '^authz: 1 access-control issue' "$WORK/authz.txt" || fail "no access-control issue raised"
# The raised issue is the broken-access-control type on the IDOR path.
"$GULP" issues --project "$WORK/authz.gulp" | tee "$WORK/issues.txt"
grep -q "authz.broken-access-control" "$WORK/issues.txt" || fail "the issue wasn't recorded"
grep -qE "/api/orders/(2|\{id\})" "$WORK/issues.txt" || fail "the issue isnt on the IDOR path"
if grep -q "/safe/" "$WORK/issues.txt"; then fail "an issue was raised on the safe twin"; fi
echo "PASS: the Authz Matrix flags the IDOR as a bypass, the /safe twin is Enforced, one issue raised"
echo "M12b DoD: PASS"
