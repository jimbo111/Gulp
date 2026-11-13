#!/usr/bin/env bash
# Recon (F27, M19 first increment) Definition of Done, as an executable check:
#   The passive secret & JS-endpoint recon finds the planted AWS key and the JS-file secret/endpoints,
#   and nothing on the /safe/ twins.
# `gulp-cli send` fetches the recon fixtures into the project's history, then `gulp-cli scan passive
#   --recon` runs the recon checks; `gulp-cli issues` must show recon.secret on the config/JS routes
#   and recon.endpoint on the JS file, with none on /safe/*.
# Usage: Scripts/recon-dod.sh   (SWIFTPM_FLAGS may carry extra swift-build flags)
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
PROJECT="$WORK/recon.gulp"

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
"$GULP" scope --project "$PROJECT" --add "$LAB/" > /dev/null

# Fetch the fixtures (vulnerable + safe) through the Repeater so they land in history.
for route in /recon/config /recon/app.js /safe/recon/config /safe/recon/app.js; do
  printf 'GET %s HTTP/1.1\r\nHost: 127.0.0.1:8088\r\n\r\n' "$route" > "$WORK/req.txt"
  "$GULP" repeater --project "$PROJECT" --raw "$WORK/req.txt" --target "$LAB" > /dev/null
done

# Run the recon checks over the recorded traffic.
"$GULP" scan passive --project "$PROJECT" --all --recon --tools repeater | tee "$WORK/scan.txt"
grep -qE "passive: scanned [0-9]+ exchange" "$WORK/scan.txt" || fail "passive scan didn't run"

"$GULP" issues --project "$PROJECT" | tee "$WORK/issues.txt"
grep -q "recon.secret" "$WORK/issues.txt" || fail "the planted secret wasn't flagged"
grep -q "recon.endpoint" "$WORK/issues.txt" || fail "JS endpoints weren't flagged"
# The AWS-key config and the JS secret both flagged; the JS endpoints flagged.
grep -qE "recon.secret\s+http://127.0.0.1:8088/recon/config" "$WORK/issues.txt" || fail "no secret issue on /recon/config"
grep -qE "recon.endpoint\s+http://127.0.0.1:8088/recon/app.js" "$WORK/issues.txt" || fail "no endpoint issue on /recon/app.js"
if grep -qE "recon\.(secret|endpoint)\s+http://127.0.0.1:8088/safe/" "$WORK/issues.txt"; then
  fail "a recon issue fired on a /safe/ twin"
fi
echo "PASS: recon flagged the secret and JS endpoints on the vulnerable routes, nothing on the safe twins"
echo "Recon DoD: PASS"
