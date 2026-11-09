#!/usr/bin/env bash
# M6a Definition of Done (docs/03-roadmap.md), as an executable check:
#   "The site map tree fills from proxy traffic; scope rules hide out-of-scope items; ScopeGuard
#    blocks out-of-scope Repeater sends (with a confirmation dialog)."
# Headless: curl browses VulnLab through `gulp-cli proxy`; `gulp-cli target` prints the site map the
# app's Target tool shows; `gulp-cli scope` edits the rules; `gulp-cli repeater` refuses an
# out-of-scope send unless given `--allow-out-of-scope` (the app's "Send anyway?").
# Usage: Scripts/m6a-dod.sh   (SWIFTPM_FLAGS may carry extra swift-build flags, e.g. on Linux CI)
set -euo pipefail
cd "$(dirname "$0")/.."
PKG=Packages/GulpKit
PROXY_PORT=${PROXY_PORT:-18080}
# shellcheck disable=SC2086
swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --product gulp-vulnlab
# shellcheck disable=SC2086
swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --product gulp-cli
# shellcheck disable=SC2086
BIN=$(swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --show-bin-path)
WORK=$(mktemp -d)
export GULP_SUPPORT_DIR="$WORK/support"
PROJECT="$WORK/m6a.gulp"
LAB=http://127.0.0.1:8088

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

start_proxy() {  # extra flags
  # shellcheck disable=SC2068
  "$BIN/gulp-cli" proxy --project "$PROJECT" --port "$PROXY_PORT" $@ > "$WORK/proxy.log" 2>&1 &
  PROXY=$!
  wait_port "$PROXY_PORT"
}
stop_proxy() {
  kill -TERM "$PROXY"
  wait "$PROXY" || true
  PROXY=""
}
# `! grep` can't be used for "must not appear": bash's `set -e` ignores a command negated with `!`.
absent() {  # pattern, file
  if grep -qE "$1" "$2"; then echo "unexpected match for '$1' in $2" >&2; exit 1; fi
}
browse() {
  for path in "$@"; do curl -sS -o /dev/null -x "http://127.0.0.1:$PROXY_PORT" "$LAB$path"; done
}

# 1. The site map fills from proxy traffic: visited nodes, plus inferred ones from the home page's links.
start_proxy
browse / /echo "/redirect?to=/echo" "/race/status?code=GULP10" "/status/404"
stop_proxy
"$BIN/gulp-cli" target --project "$PROJECT" | tee "$WORK/map.txt"
grep -q "^http://127.0.0.1:8088" "$WORK/map.txt"
grep -qE "^  echo	×1" "$WORK/map.txt"
grep -qE "^  redirect	×1" "$WORK/map.txt"
grep -qE "^  login	\(inferred\)" "$WORK/map.txt"
grep -qE "^      1	\(inferred\)" "$WORK/map.txt"      # /api/orders/1, linked but never requested
grep -qE "^  race$" "$WORK/map.txt"
echo "PASS 1: the site map holds the browsed host and paths, with linked-but-unvisited URLs inferred"
"$BIN/gulp-cli" target --project "$PROJECT" --hide-404 --visited-only > "$WORK/visited.txt"
absent "\(inferred\)" "$WORK/visited.txt"
absent "^  status" "$WORK/visited.txt"
grep -qE "^  echo" "$WORK/visited.txt"
"$BIN/gulp-cli" target --project "$PROJECT" --grouped > "$WORK/grouped.txt"
grep -qE "^    \{id\}" "$WORK/grouped.txt"
echo "PASS 1b: filters hide inferred and 404-only nodes; numeric segments fold into {id}"

# 2. Scope rules hide out-of-scope items.
"$BIN/gulp-cli" scope --project "$PROJECT" --add "$LAB/race" --exclude "$LAB/race/reset" \
  --test "$LAB/race/status?code=X" --test "$LAB/race/reset" --test "$LAB/echo" | tee "$WORK/scope.txt"
grep -q "^IN	$LAB/race/status?code=X	rule 1 (include)" "$WORK/scope.txt"
grep -q "^OUT	$LAB/race/reset	rule 2 (exclude)" "$WORK/scope.txt"
grep -q "^OUT	$LAB/echo	no rule matches" "$WORK/scope.txt"
"$BIN/gulp-cli" target --project "$PROJECT" --in-scope-only | tee "$WORK/in-scope.txt"
grep -q "race" "$WORK/in-scope.txt"
absent "^  (echo|login|status|redirect)" "$WORK/in-scope.txt"
echo "PASS 2: with a scope set, the in-scope view shows only /race; rule tests name the deciding rule"
# ... and with "Use scope for the proxy", out-of-scope traffic isn't recorded at all (TGT-024).
BEFORE=$("$BIN/gulp-cli" history --project "$PROJECT" | sed -n 's/^exchanges: //p')
start_proxy --use-scope
browse "/race/status?code=SCOPED" /echo /gzip
stop_proxy
AFTER=$("$BIN/gulp-cli" history --project "$PROJECT" --last 1 | tee "$WORK/after.txt" | sed -n 's/^exchanges: //p')
[ "$AFTER" -eq $((BEFORE + 1)) ]
grep -q "race/status?code=SCOPED" "$WORK/after.txt"
echo "PASS 2b: with the proxy using scope, only the in-scope request of three was recorded"
# Scope moves as JSON (TGT-025).
"$BIN/gulp-cli" scope --project "$PROJECT" --export "$WORK/scope.json" > /dev/null
"$BIN/gulp-cli" scope --project "$WORK/other.gulp" --import "$WORK/scope.json" > "$WORK/imported.txt"
grep -q "^imported 2 rule" "$WORK/imported.txt"
echo "PASS 2c: the scope exported as JSON imports into another project"

# 3. ScopeGuard: an out-of-scope Repeater send asks first; "Send anyway" sends it.
printf 'GET /echo HTTP/1.1\r\nHost: 127.0.0.1:8088\r\n\r\n' > "$WORK/echo.txt"
set +e
"$BIN/gulp-cli" repeater --project "$PROJECT" --raw "$WORK/echo.txt" --target "$LAB" 2> "$WORK/refused.txt"
STATUS=$?
set -e
[ "$STATUS" -eq 3 ]
grep -q "Target is out of scope. Send anyway?" "$WORK/refused.txt"
"$BIN/gulp-cli" repeater --project "$PROJECT" --raw "$WORK/echo.txt" --target "$LAB" --allow-out-of-scope \
  > "$WORK/anyway.txt"
grep -q "HTTP/1.1 200" "$WORK/anyway.txt"
printf 'GET /race/status?code=R HTTP/1.1\r\nHost: 127.0.0.1:8088\r\n\r\n' > "$WORK/race.txt"
"$BIN/gulp-cli" repeater --project "$PROJECT" --raw "$WORK/race.txt" --target "$LAB" > "$WORK/in.txt"
grep -q "HTTP/1.1 200" "$WORK/in.txt"
echo "PASS 3: an out-of-scope Repeater send was held for confirmation, then sent when confirmed;"
echo "        an in-scope send went straight out"

# 4. "Analyze target" on the host lists parameters and observations.
"$BIN/gulp-cli" target --project "$PROJECT" --analyze "$LAB" | tee "$WORK/analyze.txt"
grep -qE "^  code	query	" "$WORK/analyze.txt"
grep -qE "^  redirectParameter	to	GET /redirect" "$WORK/analyze.txt"
echo "PASS 4: Analyze target lists the host's parameters and flags the redirect parameter"

echo "M6a DoD: PASS"
