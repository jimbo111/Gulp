#!/usr/bin/env bash
# Reporting (F19, M16) Definition of Done, as an executable check:
#   After scanning, `gulp-cli report` produces a self-contained HTML report and a Markdown report
#   with a severity summary and a section per issue.
# Browse a couple of VulnLab routes with issues (the recon fixtures), run the passive recon scan to
# record issues, then generate both reports and assert their structure.
# Usage: Scripts/report-dod.sh   (SWIFTPM_FLAGS may carry extra swift-build flags)
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
PROJECT="$WORK/report.gulp"

fail() {
  echo "FAIL: $*" >&2
  echo "--- vulnlab.log" >&2 && cat "$WORK/vulnlab.log" >&2
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
"$GULP" scope --project "$PROJECT" --add "$LAB/" > /dev/null

for route in /recon/config /recon/app.js; do
  printf 'GET %s HTTP/1.1\r\nHost: 127.0.0.1:8088\r\n\r\n' "$route" > "$WORK/req.txt"
  "$GULP" repeater --project "$PROJECT" --raw "$WORK/req.txt" --target "$LAB" > /dev/null
done
"$GULP" scan passive --project "$PROJECT" --all --recon --tools repeater
issues=$("$GULP" issues --project "$PROJECT" | sed -n '1p')
echo "$issues"

# HTML report.
"$GULP" report --project "$PROJECT" --format html --out "$WORK/report.html" --title "Acme engagement"
grep -qE "report: wrote [0-9]+ bytes" <("$GULP" report --project "$PROJECT" --format html --out "$WORK/report2.html" 2>&1) || true
head -c 20 "$WORK/report.html" | grep -q "<!doctype html>" || fail "HTML report has no doctype"
grep -q "Acme engagement" "$WORK/report.html" || fail "HTML report missing the title"
grep -q "recon.secret" <("$GULP" issues --project "$PROJECT") || fail "no issue to report"
grep -qE "class=\"pill\"" "$WORK/report.html" || fail "HTML report missing the severity summary"
grep -q "Secret or credential in a response" "$WORK/report.html" || fail "HTML report missing the issue"
grep -q "Remediation" "$WORK/report.html" || fail "HTML report missing remediation"
echo "PASS 1: HTML report generated with a severity summary and per-issue detail"

# Markdown report.
"$GULP" report --project "$PROJECT" --format markdown --out "$WORK/report.md" --title "Acme engagement"
grep -q "^# Acme engagement — security report" "$WORK/report.md" || fail "Markdown report missing the title"
grep -q "| Severity | Count |" "$WORK/report.md" || fail "Markdown report missing the summary table"
grep -qE "^## Secret or credential in a response" "$WORK/report.md" || fail "Markdown report missing the issue section"
grep -q "Remediation" "$WORK/report.md" || fail "Markdown report missing remediation"
echo "PASS 2: Markdown report generated with a severity table and per-issue sections"
echo "Report DoD: PASS"
