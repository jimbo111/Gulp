#!/usr/bin/env bash
# M9 Definition of Done (docs/03-roadmap.md), as an executable check:
#   "`resp.status >= 500 and req.host ~ "api"` filters 1M rows in < 2 s (index-assisted where
#    possible); the coverage index reflects which tools touched each endpoint."
# Plus F05 acceptance 2 (reflected("q") flags VulnLab's /xss/html?q= row) and 3 (search finds a
# planted token in a request and a response in < 200 ms on a 100k-row project), and F14 acceptance
# 1–2 (Notebook snapshot, status and filter, persisted).
# Headless: `gulp-cli seed|query|search|coverage|notebook`; traffic through `gulp-cli proxy`,
# `gulp-cli repeater` and `gulp-cli fuzz` against VulnLab.
# Usage: Scripts/m9-dod.sh   (SWIFTPM_FLAGS may carry extra swift-build flags, e.g. on Linux CI)
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
LAB=http://127.0.0.1:8088
PROXY_PORT=${PROXY_PORT:-18090}
GULP="$BIN/gulp-cli"
PROJECT="$WORK/m9.gulp"

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

# 1. GulpQL over 1M rows: the DoD filter, index-assisted, in < 2 s; an equivalent spelling agrees.
"$GULP" seed --project "$WORK/big.gulp" --rows 1000000 | tee "$WORK/seed.txt"
"$GULP" query --project "$WORK/big.gulp" 'resp.status >= 500 and req.host ~ "api"' --plan | tee "$WORK/q1.txt"
grep -qE '^matched 50000 in [0-9]+ ms \(push-down: full\)$' "$WORK/q1.txt"
MS=$(sed -n 's/^matched 50000 in \([0-9]*\) ms.*/\1/p' "$WORK/q1.txt")
[ "$MS" -lt 2000 ]
grep -q "USING INDEX ix_ex_status\|USING COVERING INDEX ix_ex_status" "$WORK/q1.txt"
"$GULP" query --project "$WORK/big.gulp" 'resp.status in 500..599 and req.host contains "api"' > "$WORK/q1b.txt"
grep -qE '^matched 50000 in ' "$WORK/q1b.txt"
echo "PASS 1: resp.status >= 500 and req.host ~ \"api\" matched 50,000 of 1,000,000 rows in ${MS} ms via ix_ex_status"

# 2. Proxy traffic; reflected("q") flags the reflected-XSS row (F05 acceptance 2).
"$GULP" scope --project "$PROJECT" --add "$LAB/" > /dev/null
"$GULP" proxy --project "$PROJECT" --port "$PROXY_PORT" > "$WORK/proxy.log" 2>&1 &
PROXY=$!
wait_port "$PROXY_PORT"
for path in "/xss/html?q=gulpprobe42" "/echo?token=plantedneedle77" "/" "/login"; do
  curl -sS -o /dev/null -x "http://127.0.0.1:$PROXY_PORT" "$LAB$path"
done
kill -TERM "$PROXY"
wait "$PROXY" || true
PROXY=""
"$GULP" query --project "$PROJECT" 'reflected("q")' --rows 5 | tee "$WORK/q2.txt"
grep -qE '^matched 1 in ' "$WORK/q2.txt"
grep -q "/xss/html?q=gulpprobe42" "$WORK/q2.txt"
XSS=$(awk -F'\t' '/xss\/html/ {print $1; exit}' "$WORK/q2.txt")
echo "PASS 2: reflected(\"q\") flags exactly the /xss/html?q=gulpprobe42 row (#$XSS)"

# 3. Coverage: proxy traffic only observes; Repeater and the Fuzzer test; a Notebook item counts.
printf 'GET /account HTTP/1.1\r\nHost: 127.0.0.1:8088\r\n\r\n' > "$WORK/account.txt"
"$GULP" repeater --project "$PROJECT" --raw "$WORK/account.txt" --target "$LAB" > /dev/null
printf 'GET /echo?token=%sx%s HTTP/1.1\r\nHost: 127.0.0.1:8088\r\n\r\n' '§' '§' > "$WORK/echo.txt"
"$GULP" fuzz --project "$PROJECT" --raw "$WORK/echo.txt" --target "$LAB" --set list:a,b,c > /dev/null
"$GULP" coverage --project "$PROJECT" | tee "$WORK/coverage.txt"
grep -qE "^observed${TAB}in${TAB}GET${TAB}http://127\.0\.0\.1:8088/xss/html${TAB}proxy×1$" "$WORK/coverage.txt"
grep -qE "^tested${TAB}in${TAB}GET${TAB}http://127\.0\.0\.1:8088/echo${TAB}fuzzer×3 proxy×1$" "$WORK/coverage.txt"
grep -qE "^tested${TAB}in${TAB}GET${TAB}http://127\.0\.0\.1:8088/account${TAB}repeater×1$" "$WORK/coverage.txt"
"$GULP" coverage --project "$PROJECT" --untested > "$WORK/untested.txt"
grep -q "/xss/html" "$WORK/untested.txt"
if grep -q "/echo\|/account" "$WORK/untested.txt"; then echo "tested endpoints listed as untested" >&2; exit 1; fi
echo "PASS 3: coverage shows /xss/html observed (proxy), /echo tested (fuzzer×3), /account tested (repeater)"

# 4. Notebook: a snapshot with status and tags; the filter finds it after reopening; it marks coverage.
"$GULP" notebook add --project "$PROJECT" --exchange "$XSS" --status confirmed --tags xss,p1 \
  --note "Reflected without encoding" | tee "$WORK/nb.txt"
ITEM=$(sed -n 's/^item \([0-9]*\):.*/\1/p' "$WORK/nb.txt")
"$GULP" notebook note --project "$PROJECT" --title "Rate limits" --note "None on /login" > /dev/null
"$GULP" notebook list --project "$PROJECT" --filter "status:confirmed tag:xss" > "$WORK/nblist.txt"
grep -qE "^$ITEM${TAB}confirmed${TAB}exchange${TAB}127\.0\.0\.1/xss/html\?q=gulpprobe42${TAB}GET 127\.0\.0\.1/xss/html${TAB}\[xss,p1\]$" \
  "$WORK/nblist.txt"
[ "$(wc -l < "$WORK/nblist.txt")" -eq 1 ]
"$GULP" coverage --project "$PROJECT" | grep -qE "^tested${TAB}in${TAB}GET${TAB}http://127\.0\.0\.1:8088/xss/html${TAB}proxy×1 notebook×1$"
echo "PASS 4: Notebook item #$ITEM saved (confirmed, xss,p1), found by its filter, and counted in coverage"

# 5. Search: a planted token in a request and its response, on a 100k-row project, in < 200 ms.
"$GULP" seed --project "$PROJECT" --rows 100000 > /dev/null
"$GULP" search --project "$PROJECT" --reindex plantedneedle77 | tee "$WORK/search.txt"
grep -qE '^hits 1 \(index, examined 1\) in [0-9]+ ms$' "$WORK/search.txt"
SMS=$(sed -n 's/^hits 1 (index, examined 1) in \([0-9]*\) ms$/\1/p' "$WORK/search.txt")
[ "$SMS" -lt 200 ]
grep -qE "${TAB}proxy${TAB}200${TAB}QS${TAB}127\.0\.0\.1/echo\?token=plantedneedle77${TAB}" "$WORK/search.txt"
echo "PASS 5: search found the planted token in the request and the response among 100k rows in ${SMS} ms"

echo "M9 DoD: PASS"
