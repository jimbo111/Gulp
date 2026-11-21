#!/usr/bin/env bash
# M10a Definition of Done (docs/03-roadmap.md), as an executable check:
#   "Browsing VulnLab produces the expected passive issues (fixture list in doc 06 §3) and no
#    duplicates."
# Headless: curl browses every route of Tests/Fixtures/vulnlab-issues.json (HTTP on :8088, HTTPS on
# :8443 through TLS interception) via `gulp-cli proxy`, whose live passive scanner records the
# issues; `gulp-cli issues verify` checks that each route yields exactly its expected issue types and
# nothing else (so none on /safe/*); a second browse must add no issue.
# Usage: Scripts/m10a-dod.sh   (SWIFTPM_FLAGS may carry extra swift-build flags, e.g. on Linux CI)
set -euo pipefail
TAB=$'\t'  # portable: BSD grep has no -P
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
HTTP_BASE=http://127.0.0.1:8088
HTTPS_BASE=https://localhost:8443
PROXY_PORT=${PROXY_PORT:-18100}
GULP="$BIN/gulp-cli"
PROJECT="$WORK/m10a.gulp"
MANIFEST="$PKG/Tests/Fixtures/vulnlab-issues.json"

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
PROXY=""
trap 'kill $VULNLAB $PROXY 2>/dev/null || true; rm -rf "$WORK"' EXIT
wait_port 8088
wait_port 8443
"$GULP" scope --project "$PROJECT" --add "$HTTP_BASE/" > /dev/null
"$GULP" scope --project "$PROJECT" --add "$HTTPS_BASE/" > /dev/null
"$GULP" ca export --out "$WORK/gulp-ca.pem" > /dev/null

browse() {  # every manifest route once, through the proxy; the proxy's passive scanner does the rest
  "$GULP" proxy --project "$PROJECT" --port "$PROXY_PORT" > "$WORK/proxy.log" 2>&1 &
  PROXY=$!
  wait_port "$PROXY_PORT"
  local count=0
  while IFS= read -r line; do
    scheme=$(sed -n 's/.*"scheme": "\([a-z]*\)".*/\1/p' <<< "$line")
    [ -n "$scheme" ] || continue
    path=$(sed -n 's/.*"path": "\([^"]*\)".*/\1/p' <<< "$line")
    origin=$(sed -n 's/.*"origin": "\([^"]*\)".*/\1/p' <<< "$line")
    base=$HTTP_BASE
    [ "$scheme" = https ] && base=$HTTPS_BASE
    args=(-sS -o /dev/null -x "http://127.0.0.1:$PROXY_PORT" --cacert "$WORK/gulp-ca.pem")
    [ -n "$origin" ] && args+=(-H "Origin: $origin")
    curl "${args[@]}" "$base$path"
    count=$((count + 1))
  done < "$MANIFEST"
  kill -TERM "$PROXY"
  wait "$PROXY" || true  # closing the project drains the passive scanner
  PROXY=""
  echo "browsed $count routes"
}

# 1. One browse of every planted route and its /safe/ twin: exactly the expected issues.
browse
"$GULP" issues verify --project "$PROJECT" --manifest "$MANIFEST" | tee "$WORK/verify.txt"
grep -qE "^verify: [0-9]+ routes, [0-9]+ expected issue\(s\), 0 missing, 0 unexpected$" "$WORK/verify.txt"
"$GULP" issues --project "$PROJECT" > "$WORK/issues1.txt"
FIRST=$(sed -n 's/^issues: \([0-9]*\)$/\1/p' "$WORK/issues1.txt")
if grep -q "/safe/" "$WORK/issues1.txt"; then echo "issue on a /safe/ route" >&2; exit 1; fi
echo "PASS 1: browsing VulnLab produced exactly the manifest's passive issues ($FIRST issues; none on /safe/*)"

# 2. Browsing again adds no issue (findings merge by dedup key; evidence accumulates).
browse
"$GULP" issues --project "$PROJECT" > "$WORK/issues2.txt"
SECOND=$(sed -n 's/^issues: \([0-9]*\)$/\1/p' "$WORK/issues2.txt")
[ "$FIRST" = "$SECOND" ]
"$GULP" issues verify --project "$PROJECT" --manifest "$MANIFEST" > /dev/null
grep -qE "${TAB}passive\.csp\.missing${TAB}http://127\.0\.0\.1:8088/headers/no-csp${TAB}×2$" "$WORK/issues2.txt"
echo "PASS 2: a second browse added no issue ($SECOND), only evidence (×2)"

# 3. Evidence markers point at the proof; SARIF export carries every issue.
CORS=$(awk -F'\t' '$5 == "passive.cors.credentials-reflected" {print $1}' "$WORK/issues2.txt")
"$GULP" issues show --project "$PROJECT" "$CORS" | tee "$WORK/cors.txt"
grep -q "response\[[0-9]*\.\.<[0-9]*\]: Access-Control-Allow-Origin: https://evil.example" "$WORK/cors.txt"
grep -q "request\[[0-9]*\.\.<[0-9]*\]: https://evil.example" "$WORK/cors.txt"
"$GULP" issues export --project "$PROJECT" --format sarif --out "$WORK/issues.sarif"
[ "$(grep -c '"ruleId"' "$WORK/issues.sarif")" -eq "$SECOND" ]
grep -q '"version" : "2.1.0"' "$WORK/issues.sarif"
echo "PASS 3: evidence markers highlight the reflected Origin; SARIF export has all $SECOND issues"

echo "M10a DoD: PASS"
