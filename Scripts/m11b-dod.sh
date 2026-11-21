#!/usr/bin/env bash
# M11b Definition of Done (docs/03-roadmap.md), as an executable check:
#   "An active audit of VulnLab's vulnerable endpoints finds every P0 vulnerability planted there
#    (including the three OAST checks via the dev Beacon), with zero false positives on the 'safe
#    twin' endpoints (doc 06 §3)."
# `gulp-cli scan active` audits every request of Tests/Fixtures/vulnlab-active.json (vulnerable
# routes and their /safe/ twins) with the Balanced config plus the unsafe gate (stored XSS writes
# data, F08 §6) and the dev Beacon configured for OAST;
# `gulp-cli scan verify-active` requires exactly the manifest's issue types per route.
# Usage: Scripts/m11b-dod.sh   (SWIFTPM_FLAGS may carry extra swift-build flags, e.g. on Linux CI)
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
WORK=$(mktemp -d)
export GULP_SUPPORT_DIR="$WORK/support"
LAB=http://127.0.0.1:8088
GULP="$BIN/gulp-cli"
PROJECT="$WORK/m11b.gulp"
MANIFEST="$PKG/Tests/Fixtures/vulnlab-active.json"

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
"$BEACON_BIN/gulp-beacon" --dev > "$WORK/beacon.log" 2>&1 &
BEACON=$!
trap 'kill $VULNLAB $BEACON 2>/dev/null || true; rm -rf "$WORK"' EXIT
wait_port 8088
wait_port 8090
"$GULP" scope --project "$PROJECT" --add "$LAB/" > /dev/null
"$GULP" oast configure --project "$PROJECT" --server http://127.0.0.1:8090 --domain oast.test --poll 1 > /dev/null

"$GULP" scan active --project "$PROJECT" --manifest "$MANIFEST" --base "$LAB" --config balanced --unsafe | tee "$WORK/scan.txt"
grep -qE '^scan: [0-9]+ findings, [0-9]+ probes, 0 out of scope in [0-9.]+ s \(done\)$' "$WORK/scan.txt" || fail "the scan didn't finish"
"$GULP" scan verify-active --project "$PROJECT" --manifest "$MANIFEST" | tee "$WORK/verify.txt" || fail "issues differ from the manifest"
routes=$(grep -c '"method"' "$MANIFEST")
grep -qE "^verify-active: $routes routes, [0-9]+ expected issue\(s\), 0 missing, 0 unexpected$" "$WORK/verify.txt" || fail "verification summary"
for oast in active.cmd.oast active.xxe.oast active.ssrf.oast; do
  grep -q "  $oast: 1" "$WORK/scan.txt" || fail "no $oast finding"
done
if "$GULP" issues --project "$PROJECT" | grep -q "/safe/"; then fail "an issue on a /safe/ twin"; fi
echo "PASS: every planted P0 vulnerability found (incl. the 3 OAST checks via the dev Beacon); nothing on the safe twins"
echo "M11b DoD: PASS"
