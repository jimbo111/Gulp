#!/usr/bin/env bash
# Daily-driver beta gate (docs/03-roadmap.md, "Release gate — Daily-driver beta"), as an executable
# check: "browse via the Gulp Browser, intercept and edit, Repeater single-packet race, Fuzzer content
# discovery, JWT forgery, import of /openapi.json, global search, and a Notebook entry — then quit and
# reopen the project with everything intact."
# Unlike the per-milestone scripts, every step works on ONE project, in that order. Each `gulp-cli`
# call is a separate session that opens the project, works and quits (closing flushes and
# checkpoints), so the project is reopened many times on the way. At the end the project file alone
# (no -wal/-shm) is copied elsewhere, reopened, and every artifact is checked against the values
# recorded when it was made; a summary of the whole project must also match the one taken before
# quitting.
# Headless: `gulp-cli browser` is the app's Open Browser launcher (headless Chrome, as in
# m4b-browser.sh), `proxy --intercept-replace` the scripted Intercept user (m4a), `group --project`
# the Repeater's "Send group" (REP-010), `discover` the Fuzzer's content discovery (m8), `jwt forge`
# + `repeater --var` the JWT Workbench and a Transform Tag (m7), `project import` the API import
# (m6b), `search` global search and `notebook` the Notebook (m9).
# Usage: Scripts/beta-dod.sh   (needs a Chromium-family browser for step 1; without one that step is
# skipped, except in CI. SWIFTPM_FLAGS may carry extra swift-build flags.)
set -euo pipefail
TAB=$'\t'  # portable: BSD grep has no -P
cd "$(dirname "$0")/.."
PKG=Packages/GulpKit
PROXY_PORT=${PROXY_PORT:-18120}
# shellcheck disable=SC2086
swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --product gulp-vulnlab
# shellcheck disable=SC2086
swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --product gulp-cli
# shellcheck disable=SC2086
BIN=$(swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --show-bin-path)
WORK=$(mktemp -d)
# Isolated CA and secrets: never the user's Keychain (on macOS that blocks on an access prompt).
export GULP_SUPPORT_DIR="$WORK/support"
LAB=http://127.0.0.1:8088
LABS=https://localhost:8443
GULP="$BIN/gulp-cli"
PROJECT="$WORK/beta.gulp"
MARK=gulpbeta7  # planted in the browsed URL and the intercepted body; global search looks for it

wait_port() {
  for _ in $(seq 1 300); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then return 0; fi
    sleep 0.1
  done
  echo "port $1 never opened" >&2
  return 1
}
fail() { echo "FAIL: $*" >&2; exit 1; }
# `query` prints "matched N in …"; this is N.
matched() { "$GULP" query --project "$1" "$2" | sed -n 's/^matched \([0-9]*\) in .*/\1/p'; }

"$BIN/gulp-vulnlab" > "$WORK/vulnlab.log" 2>&1 &
VULNLAB=$!
PROXY=""
trap 'kill $VULNLAB $PROXY 2>/dev/null || true; rm -rf "$WORK"' EXIT
wait_port 8088
wait_port 8443

# 0. Scope: both VulnLab listeners (the active tools refuse anything else).
"$GULP" scope --project "$PROJECT" --add "$LAB/" > /dev/null
"$GULP" scope --project "$PROJECT" --add "$LABS/" > /dev/null
echo "PASS 0: project created with VulnLab ($LAB, $LABS) in scope"

# 1 + 2. One proxy session: the Gulp Browser browses VulnLab, and a POST is intercepted and edited.
"$GULP" proxy --project "$PROJECT" --port "$PROXY_PORT" --intercept-replace "role=guest=>role=admin" \
  > "$WORK/proxy.log" 2>&1 &
PROXY=$!
wait_port "$PROXY_PORT"

BROWSED=no
"$GULP" browser --proxy-port "$PROXY_PORT" --headless --dump-dom \
  --url "$LABS/echo?from=gulp-browser&m=$MARK" > "$WORK/dom.html" 2> "$WORK/browser.err" &
BROWSER=$!
for _ in $(seq 1 900); do
  kill -0 "$BROWSER" 2>/dev/null || break
  sleep 0.1
done
if kill -0 "$BROWSER" 2>/dev/null; then
  kill "$BROWSER"
  echo "browser did not finish in 90 s" >&2
fi
wait "$BROWSER" || true
if grep -q "No Chromium-family browser found" "$WORK/browser.err"; then
  # In CI the macOS runner ships Chrome: a missing browser there is a failure, not a skip.
  [ "${CI:-}" = "true" ] && fail "no Chromium-family browser on the CI runner"
  echo "SKIP 1: no Chromium-family browser on this machine; the Gulp Browser step is not checked"
else
  if grep -qiE "ERR_CERT|not private|NET::ERR" "$WORK/dom.html"; then fail "Chrome showed a certificate warning"; fi
  grep -q "GET /echo?from=gulp-browser&amp;m=$MARK HTTP/2" "$WORK/dom.html" || fail "the page did not load"
  BROWSED=yes
  echo "PASS 1: the Gulp Browser (headless Chrome) loaded $LABS/echo through Gulp over HTTP/2, no certificate warning"
fi

EDITED=$(curl -sS --fail -x "http://127.0.0.1:$PROXY_PORT" --data "user=alice&role=guest&m=$MARK" "$LAB/echo")
grep -q "^user=alice&role=admin&m=$MARK$" <<< "$EDITED" || fail "the intercepted POST was not edited"
echo "PASS 2: the intercepted POST was edited in flight (role=guest → role=admin) and forwarded"
kill -TERM "$PROXY"
wait "$PROXY" || true
PROXY=""

EDIT_ID=$("$GULP" query --project "$PROJECT" 'edited and req.method == "POST"' --rows 5 | awk -F"$TAB" '/\/echo/ {print $1}')
[ "$(wc -w <<< "$EDIT_ID")" -eq 1 ] || fail "expected one edited POST, got '$EDIT_ID'"
"$GULP" history --project "$PROJECT" --show "$EDIT_ID" > "$WORK/edit.txt"
grep -q "^user=alice&role=guest&m=$MARK$" "$WORK/edit.txt"  # the original is kept (PRX-012)
if [ "$BROWSED" = yes ]; then
  BROWSER_ID=$("$GULP" query --project "$PROJECT" "req.path == \"/echo\" and req.param(\"from\") == \"gulp-browser\"" --rows 5 \
    | awk -F"$TAB" 'NR > 1 {print $1}')
  [ "$(wc -w <<< "$BROWSER_ID")" -eq 1 ] || fail "expected one browser /echo row, got '$BROWSER_ID'"
  # BRW-003: the background pings the launch flags switch off must not reach the history.
  NOISE=$(matched "$PROJECT" 'req.host == "clients2.google.com" or req.host == "www.gstatic.com" or req.path == "/async/folae"')
  [ "$NOISE" -eq 0 ] || fail "the Gulp Browser's background pings were recorded ($NOISE rows)"
  echo "        history: browser row #$BROWSER_ID, edited row #$EDIT_ID (original body kept), no time/Safe Browsing/AI-mode pings"
fi

# 3. Repeater single-packet race: 20 tabs in a group, one coupon, released together over HTTP/2.
curl -sS --fail "$LAB/race/reset?code=BETA" > /dev/null
printf 'POST /race/redeem?code=BETA HTTP/1.1\r\nHost: localhost\r\nContent-Length: 6\r\n\r\nredeem' > "$WORK/redeem.txt"
"$GULP" group --project "$PROJECT" --title race --raw "$WORK/redeem.txt" --target "$LABS" --count 20 \
  --mode single-packet > "$WORK/race.txt"
grep -q "^group [0-9]* 'race' (singlePacket): 20 tab(s) sent$" "$WORK/race.txt"
[ "$(grep -c "${TAB}HTTP/2${TAB}" "$WORK/race.txt")" -eq 20 ]
WINS=$(curl -sS "$LAB/race/status?code=BETA" | sed -n 's/.*redemptions=\([0-9]*\).*/\1/p')
[ "$WINS" -gt 1 ] || fail "the race was not won (redemptions=$WINS)"
RACE_200=$(matched "$PROJECT" 'source == repeater and req.path == "/race/redeem" and resp.status == 200')
RACE_409=$(matched "$PROJECT" 'source == repeater and req.path == "/race/redeem" and resp.status == 409')
[ "$RACE_200" -eq "$WINS" ] && [ $((RACE_200 + RACE_409)) -eq 20 ] \
  || fail "recorded race responses (200×$RACE_200, 409×$RACE_409) disagree with VulnLab ($WINS)"
echo "PASS 3: a 20-tab Repeater group sent single-packet over HTTP/2 redeemed the coupon $WINS times (recorded 200×$RACE_200, 409×$RACE_409)"

# 4. Fuzzer content discovery: the hidden /admin and the backup files.
"$GULP" discover --project "$PROJECT" --url "$LAB/" --depth 2 --concurrency 32 > "$WORK/discover.txt"
grep -qE "^admin${TAB}403${TAB}" "$WORK/discover.txt"
grep -qE "^index.html.bak${TAB}200${TAB}" "$WORK/discover.txt"
grep -qE "^backup.zip${TAB}200${TAB}" "$WORK/discover.txt"
grep -qE "^  config.php~${TAB}200${TAB}" "$WORK/discover.txt"
FOUND=$(sed -n 's/^discover: .* \([0-9]*\) found, .*/\1/p' "$WORK/discover.txt")
DISCOVERED=$(matched "$PROJECT" 'tag contains "discovered"')
[ "$DISCOVERED" -eq "$FOUND" ] || fail "discover found $FOUND paths but $DISCOVERED rows are tagged discovered"
echo "PASS 4: content discovery found $FOUND paths incl. /admin, /index.html.bak, /backup.zip, /.old/config.php~ (all recorded)"

# 5. JWT forgery: log in from a Repeater tab, forge alg:none with role=admin, send it via «var(token)».
printf 'GET /api/login?user=alice HTTP/1.1\r\nHost: 127.0.0.1:8088\r\n\r\n' > "$WORK/login.txt"
"$GULP" repeater --project "$PROJECT" --raw "$WORK/login.txt" --target "$LAB" --title login > "$WORK/login.out"
RS=$(sed -n 's/.*"token":"\([^"]*\)".*/\1/p' "$WORK/login.out")
[ -n "$RS" ] || fail "no token from /api/login"
FORGED=$("$GULP" jwt forge --attack none --claims '{"role":"admin"}' "$RS" | head -1 | cut -f2)
grep -q '"alg" *: *"none"' <<< "$("$GULP" jwt decode "$FORGED")"
printf 'GET /api/me HTTP/1.1\r\nHost: 127.0.0.1:8088\r\nAuthorization: Bearer «var(token)»\r\n\r\n' > "$WORK/me.txt"
"$GULP" repeater --project "$PROJECT" --raw "$WORK/me.txt" --target "$LAB" --title jwt --var "token=$FORGED" \
  > "$WORK/me.out"
grep -q "^HTTP/1.1 200" "$WORK/me.out" && grep -q '"role":"admin"' "$WORK/me.out" || fail "/api/me refused the forged token"
JWT_ID=$(sed -n "s/^tab [0-9]* 'jwt': 1 send(s); last exchange #\([0-9]*\)$/\1/p" "$WORK/me.out")
printf 'GET /safe/api/me HTTP/1.1\r\nHost: 127.0.0.1:8088\r\nAuthorization: Bearer «var(token)»\r\n\r\n' > "$WORK/safe.txt"
"$GULP" repeater --project "$PROJECT" --raw "$WORK/safe.txt" --target "$LAB" --title jwt-safe > "$WORK/safe.out"
grep -q "^HTTP/1.1 401" "$WORK/safe.out" || fail "/safe/api/me accepted the forged token"
SAFE_ID=$(sed -n "s/^tab [0-9]* 'jwt-safe': 1 send(s); last exchange #\([0-9]*\)$/\1/p" "$WORK/safe.out")
echo "PASS 5: an alg:none role=admin token forged from alice's RS256 token was accepted by /api/me (#$JWT_ID) and refused by /safe/api/me (#$SAFE_ID)"

# 6. API import: every /api/* operation of /openapi.json becomes a request in the project.
curl -sS --fail "$LAB/openapi.json" -o "$WORK/openapi.json"
"$GULP" project import --project "$PROJECT" --base-url "$LAB/openapi.json" "$WORK/openapi.json" > "$WORK/import.txt"
grep -q "^OpenAPI / Swagger: imported 4, duplicates 0, skipped 0$" "$WORK/import.txt" || fail "$(cat "$WORK/import.txt")"
"$GULP" query --project "$PROJECT" 'tag contains "imported"' --rows 10 | cut -f2- > "$WORK/imported.txt"
cat > "$WORK/imported.expected" <<EOF
matched 4
proxy${TAB}GET${TAB}-${TAB}http://127.0.0.1:8088/api/items?q=string&limit=3
proxy${TAB}GET${TAB}-${TAB}http://127.0.0.1:8088/api/me
proxy${TAB}POST${TAB}-${TAB}http://127.0.0.1:8088/api/orders
proxy${TAB}GET${TAB}-${TAB}http://127.0.0.1:8088/api/orders/1
EOF
sed -i.bak '1s/ in .*//' "$WORK/imported.txt"
diff "$WORK/imported.expected" "$WORK/imported.txt" || fail "imported operations differ"
echo "PASS 6: /openapi.json imported as 4 unsent requests (GET /api/items, GET /api/me, POST /api/orders, GET /api/orders/1)"

# 7. Global search: the planted marker and the forged token, across tools.
"$GULP" search --project "$PROJECT" "$MARK" > "$WORK/search-mark.txt"
grep -qE "^$EDIT_ID${TAB}proxy${TAB}200${TAB}QS${TAB}127\.0\.0\.1/echo${TAB}" "$WORK/search-mark.txt" \
  || fail "search missed the intercepted row"
if [ "$BROWSED" = yes ]; then
  grep -qE "^$BROWSER_ID${TAB}proxy${TAB}200${TAB}QS${TAB}localhost/echo\?from=gulp-browser&m=$MARK${TAB}" "$WORK/search-mark.txt" \
    || fail "search missed the browser row"
fi
MARK_HITS=$(sed -n 's/^hits \([0-9]*\) (index.*/\1/p' "$WORK/search-mark.txt")
"$GULP" search --project "$PROJECT" "$FORGED" > "$WORK/search-token.txt"
grep -q "^hits 2 (index" "$WORK/search-token.txt" || fail "the forged token is not in exactly the two JWT sends"
grep -qE "^$JWT_ID${TAB}repeater${TAB}200${TAB}" "$WORK/search-token.txt"
grep -qE "^$SAFE_ID${TAB}repeater${TAB}401${TAB}" "$WORK/search-token.txt"
echo "PASS 7: search found '$MARK' in $MARK_HITS rows (browser and intercepted rows among them) and the forged token in both JWT sends"

# 8. Notebook: the accepted forged request as a confirmed finding, and a free note about the race.
"$GULP" notebook add --project "$PROJECT" --exchange "$JWT_ID" --status confirmed --tags jwt,beta \
  --note "alg:none admin token accepted by /api/me" > /dev/null
"$GULP" notebook note --project "$PROJECT" --title "Race on /race/redeem" --note "coupon redeemed $WINS times" \
  --tags race,beta > /dev/null
"$GULP" notebook list --project "$PROJECT" --filter "tag:beta" --notes > "$WORK/notebook.txt"
cat > "$WORK/notebook.expected" <<EOF
1${TAB}confirmed${TAB}exchange${TAB}127.0.0.1/api/me${TAB}GET 127.0.0.1/api/me${TAB}[jwt,beta]
    snapshot of #$JWT_ID: GET /api/me HTTP/1.1
    note: alg:none admin token accepted by /api/me
2${TAB}todo${TAB}note${TAB}-${TAB}Race on /race/redeem${TAB}[race,beta]
    note: coupon redeemed $WINS times
EOF
diff "$WORK/notebook.expected" "$WORK/notebook.txt" || fail "Notebook items differ"
echo "PASS 8: Notebook holds the confirmed JWT finding (snapshot of #$JWT_ID) and the race note"

# 9. Quit and reopen. Every session above has quit; the project file alone must now hold everything.
summary() {  # the whole project, as the tools show it
  "$GULP" project info --project "$1" | grep -v '^project: '
  "$GULP" history --project "$1" --last 100000 | cut -f1-5
  "$GULP" target --project "$1"
  "$GULP" notebook list --project "$1" --notes
  "$GULP" search --project "$1" "$MARK" | sed '1s/ in [0-9]* ms$//'
  "$GULP" coverage --project "$1"
}
TOTAL=$("$GULP" history --project "$PROJECT" | sed -n 's/^exchanges: //p')
summary "$PROJECT" > "$WORK/before.txt"
[ ! -s "$PROJECT-wal" ] || fail "the write-ahead log still holds data after every session quit"
mkdir "$WORK/reopened"
REOPENED="$WORK/reopened/beta.gulp"
cp "$PROJECT" "$REOPENED"
summary "$REOPENED" > "$WORK/after.txt"
diff "$WORK/before.txt" "$WORK/after.txt" || fail "the reopened copy differs from the project before quitting"

"$GULP" project info --project "$REOPENED" | tee "$WORK/info.txt"
grep -q "^exchanges: $TOTAL$" "$WORK/info.txt"
grep -q "^scope rules: 2$" "$WORK/info.txt"
grep -q "^repeater tabs: 23$" "$WORK/info.txt"  # 20 race + login + jwt + jwt-safe
grep -qE "^repeater group [0-9]+ 'race' \(singlePacket\): 20 tab\(s\)$" "$WORK/info.txt"
grep -q "^notebook items: 2$" "$WORK/info.txt"
"$GULP" history --project "$REOPENED" --show "$EDIT_ID" > "$WORK/edit-after.txt"
diff <(tail -n +2 "$WORK/edit.txt") <(tail -n +2 "$WORK/edit-after.txt")  # line 1 is the exchange count
grep -q "^user=alice&role=guest&m=$MARK$" "$WORK/edit-after.txt"
grep -q "^user=alice&role=admin&m=$MARK$" "$WORK/edit-after.txt"
[ "$(grep -c "^user=alice&role=admin&m=$MARK$" "$WORK/edit-after.txt")" -eq 2 ]  # sent request + echoed response
if [ "$BROWSED" = yes ]; then
  grep -q "^GET /echo?from=gulp-browser&m=$MARK HTTP/2" <<< "$("$GULP" history --project "$REOPENED" --show "$BROWSER_ID")"
fi
[ "$(matched "$REOPENED" 'source == repeater and req.path == "/race/redeem" and resp.status == 200')" -eq "$WINS" ]
[ "$(matched "$REOPENED" 'source == repeater and req.path == "/race/redeem" and resp.status == 409')" -eq "$RACE_409" ]
[ "$(matched "$REOPENED" 'tag contains "discovered"')" -eq "$FOUND" ]
"$GULP" target --project "$REOPENED" > "$WORK/target.txt"
for node in "  admin${TAB}" "  backup.zip${TAB}" "  index.html.bak${TAB}" "    config.php~${TAB}"; do
  grep -q "^$node" "$WORK/target.txt" || fail "site map lost '$node'"
done
"$GULP" history --project "$REOPENED" --show "$JWT_ID" > "$WORK/jwt-after.txt"
grep -q "^Authorization: Bearer «var(token)»" "$WORK/jwt-after.txt"   # what the tab held
grep -q "^Authorization: Bearer $FORGED" "$WORK/jwt-after.txt"         # what was sent
grep -q '"role":"admin"' "$WORK/jwt-after.txt"
"$GULP" query --project "$REOPENED" 'tag contains "imported"' --rows 10 | cut -f2- > "$WORK/imported-after.txt"
sed -i.bak '1s/ in .*//' "$WORK/imported-after.txt"
diff "$WORK/imported.expected" "$WORK/imported-after.txt"
"$GULP" search --project "$REOPENED" "$MARK" | tail -n +2 > "$WORK/search-after.txt"
diff <(tail -n +2 "$WORK/search-mark.txt") "$WORK/search-after.txt"
"$GULP" search --project "$REOPENED" "$FORGED" | tail -n +2 > "$WORK/token-after.txt"
diff <(tail -n +2 "$WORK/search-token.txt") "$WORK/token-after.txt"
"$GULP" notebook list --project "$REOPENED" --filter "tag:beta" --notes > "$WORK/notebook-after.txt"
diff "$WORK/notebook.expected" "$WORK/notebook-after.txt"
echo "PASS 9: the project file alone, reopened, holds all $TOTAL exchanges and every artifact: the edited bytes"
echo "        (#$EDIT_ID), race 200×$WINS/409×$RACE_409 in a 20-tab group, $FOUND discovered paths, the forged token"
echo "        (#$JWT_ID), 4 imported operations, $MARK_HITS search hits and both Notebook items"

echo "Daily-driver beta check: PASS"
