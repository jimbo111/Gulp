#!/usr/bin/env bash
# M11c Definition of Done (docs/03-roadmap.md), as an executable check:
#   "A 'Crawl and audit' of VulnLab finds every planted vulnerability (the doc 06 §3 fixture
#    manifest, including the M11c fixtures and the gRPC SQLi) with zero false positives on the safe
#    twins — the scanner-accuracy test (doc 06 §3); a scan of the imported /openapi.json covers
#    every operation."
# 1. Accuracy: `scan active` over the whole manifest (Tests/Fixtures/vulnlab-active.json: every
#    vulnerable route, its /safe/ twin, the M11c fixtures and the gRPC-Web Orders/SafeOrders pair)
#    with the dev Beacon for OAST; `verify-active` requires exactly the manifest's issues.
# 2. Crawl and audit: a new project crawls from /scanlab/ and audits what it found; every route the
#    manifest marks `crawl` yields exactly its issues, nothing on the safe twins.
# 3. API: `scan api` imports /openapi.json and scans one request per operation.
# 4. Re-test (SCN-037): an SSTI issue re-tests as still present; after /lab/patch it re-tests fixed.
# Usage: Scripts/m11c-dod.sh   (SWIFTPM_FLAGS may carry extra swift-build flags, e.g. on Linux CI)
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

project() {
  "$GULP" scope --project "$1" --add "$LAB/" > /dev/null
  "$GULP" oast configure --project "$1" --server http://127.0.0.1:8090 --domain oast.test --poll 1 > /dev/null
}

"$BIN/gulp-vulnlab" > "$WORK/vulnlab.log" 2>&1 &
VULNLAB=$!
"$BEACON_BIN/gulp-beacon" --dev > "$WORK/beacon.log" 2>&1 &
BEACON=$!
trap 'kill $VULNLAB $BEACON 2>/dev/null || true; rm -rf "$WORK"' EXIT
wait_port 8088
wait_port 8090

routes=$(grep -c '"method"' "$MANIFEST")

# 1. Accuracy over the whole manifest.
ACC="$WORK/accuracy.gulp"
project "$ACC"
"$GULP" scan active --project "$ACC" --manifest "$MANIFEST" --base "$LAB" --config balanced | tee "$WORK/scan.txt"
grep -qE '^scan: [0-9]+ findings, [0-9]+ probes, 0 out of scope in [0-9.]+ s \(done\)$' "$WORK/scan.txt" || fail "the accuracy scan didn't finish"
"$GULP" scan verify-active --project "$ACC" --manifest "$MANIFEST" | tee "$WORK/verify.txt" || fail "issues differ from the manifest"
grep -qE "^verify-active: $routes routes, [0-9]+ expected issue\(s\), 0 missing, 0 unexpected$" "$WORK/verify.txt" || fail "verification summary"
pairs=$(sed -nE 's/^verify-active: [0-9]+ routes, ([0-9]+) expected.*/\1/p' "$WORK/verify.txt")
grep -q "/vulnlab.Orders/Get" <("$GULP" issues --project "$ACC") || fail "no gRPC SQLi issue"
if "$GULP" issues --project "$ACC" | grep -qE "/safe/|SafeOrders"; then fail "an issue on a safe twin"; fi
echo "PASS: accuracy — $routes routes, $pairs expected issues, 0 missing, 0 unexpected (incl. gRPC SQLi)"

# 2. Crawl and audit from the scan lab's index.
CRAWL="$WORK/crawl.gulp"
project "$CRAWL"
"$GULP" scan crawl-audit --project "$CRAWL" --seed "$LAB/scanlab/" --config balanced | tee "$WORK/crawl.txt"
grep -qE '^audit: [0-9]+ distinct requests$' "$WORK/crawl.txt" || fail "the crawl didn't hand requests to the audit"
grep -qE '^scan: [0-9]+ findings, [0-9]+ probes, [0-9]+ out of scope in [0-9.]+ s \(done\)$' "$WORK/crawl.txt" || fail "the audit didn't finish"
"$GULP" scan verify-active --project "$CRAWL" --manifest "$MANIFEST" --crawled | tee "$WORK/verify-crawl.txt" || fail "crawl-and-audit issues differ"
grep -qE '0 missing, 0 unexpected$' "$WORK/verify-crawl.txt" || fail "crawl-and-audit verification"
if "$GULP" issues --project "$CRAWL" | grep -q "/safe/"; then fail "crawl-and-audit: an issue on a /safe/ twin"; fi
echo "PASS: crawl and audit found every crawlable planted vulnerability, nothing on the safe twins"

# 3. Scan every operation of the OpenAPI document.
API="$WORK/api.gulp"
project "$API"
"$GULP" scan api --project "$API" --spec "$LAB/openapi.json" --config light | tee "$WORK/api.txt"
operations=$(curl -s "$LAB/openapi.json" | grep -o '"operationId"' | wc -l | tr -d ' ')
grep -qE "^api: $operations operations" "$WORK/api.txt" || fail "the API scan didn't build one request per operation ($operations)"
grep -qE '^scan: [0-9]+ findings, [0-9]+ probes, 0 out of scope in [0-9.]+ s \(done\)$' "$WORK/api.txt" || fail "the API scan didn't finish"
echo "PASS: API scan covered all $operations operations of /openapi.json"

# 4. Re-test: still present, then fixed after the lab patches the route.
ssti=$("$GULP" issues --project "$ACC" | awk '/active.ssti/ && !/safe/ {print $1; exit}' | tr -d '#')
[ -n "$ssti" ] || fail "no SSTI issue to re-test"
"$GULP" scan retest --project "$ACC" --ids "$ssti" | tee "$WORK/retest1.txt"
grep -q "still present" "$WORK/retest1.txt" || fail "re-test before the patch"
curl -s "$LAB/lab/patch?route=/ssti" > /dev/null
"$GULP" scan retest --project "$ACC" --ids "$ssti" | tee "$WORK/retest2.txt"
grep -q ": fixed" "$WORK/retest2.txt" || fail "re-test after the patch"
echo "PASS: re-test reports still present, then fixed after the patch"
echo "M11c DoD: PASS"
