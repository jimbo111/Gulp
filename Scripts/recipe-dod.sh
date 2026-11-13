#!/usr/bin/env bash
# Check Recipes (F08 §3.3, SCN-060/061/064) Definition of Done, as an executable check:
#   A user-authored Check Recipe for a custom header leak detects it on a crafted VulnLab route and
#   renders the templated issue with the captured value; the /safe/ twin is clean.
# A JSON recipe matching `X-Powered-By` is loaded via `gulp-cli scan passive --recipes`; the issue it
# raises carries the header value templated into the detail.
# Usage: Scripts/recipe-dod.sh   (SWIFTPM_FLAGS may carry extra swift-build flags)
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
PROJECT="$WORK/recipe.gulp"

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

# A no-code Check Recipe: flag the X-Powered-By stack header, templating its value into the detail.
cat > "$WORK/x-powered-by.json" <<'JSON'
{
  "id": "recipe.x-powered-by",
  "name": "Stack disclosed via X-Powered-By",
  "severity": "low",
  "confidence": "firm",
  "match": { "headerPresent": "X-Powered-By" },
  "detail": "The response advertises its stack via `X-Powered-By: {{header:X-Powered-By}}`.",
  "remediation": "Remove the X-Powered-By header."
}
JSON

for route in /recipe/leak /safe/recipe/leak; do
  printf 'GET %s HTTP/1.1\r\nHost: 127.0.0.1:8088\r\n\r\n' "$route" > "$WORK/req.txt"
  "$GULP" repeater --project "$PROJECT" --raw "$WORK/req.txt" --target "$LAB" > /dev/null
done

"$GULP" scan passive --project "$PROJECT" --all --recipes "$WORK/x-powered-by.json" --tools repeater | tee "$WORK/scan.txt"
"$GULP" issues --project "$PROJECT" | tee "$WORK/issues.txt"
grep -q "recipe.x-powered-by" "$WORK/issues.txt" || fail "the recipe didn't fire on /recipe/leak"
grep -qE "recipe.x-powered-by\s+http://127.0.0.1:8088/recipe/leak" "$WORK/issues.txt" || fail "the issue isn't on the leaky route"
if grep -qE "recipe.x-powered-by\s+http://127.0.0.1:8088/safe/recipe/leak" "$WORK/issues.txt"; then
  fail "the recipe fired on the /safe/ twin"
fi
# The templated detail carries the captured header value.
ID=$(awk "/recipe.x-powered-by/{print \$1; exit}" "$WORK/issues.txt"); "$GULP" issues show --project "$PROJECT" "$ID" | tee "$WORK/detail.txt"
grep -q "Express/4.17.1" "$WORK/detail.txt" || fail "the header value wasn't templated into the issue detail"
echo "PASS: the Check Recipe fired on the leaky route, templated the header value, and stayed off the safe twin"
echo "Recipe DoD: PASS"
