#!/usr/bin/env bash
# M11a Definition of Done (docs/03-roadmap.md), as an executable check:
#   1. A static crawl of VulnLab discovers every linked route within scope and none outside it
#      (F09 test 1; the routes are Tests/Fixtures/vulnlab-crawl.txt).
#   2. The dev-Beacon and interactsh loops correlate an interaction to its request (F10 tests 1, 3, 4):
#      "Test Beacon"; a Repeater request carrying «beacon(url)» to VulnLab's blind SSRF yields DNS and
#      HTTP interactions tied to that exchange; a token-protected server (the interactsh
#      Authorization flow); the Fuzzer's OAST column flags exactly the rows that carried a payload.
#   3. Global/per-host caps bound aggregate throughput (F03 test 6) and backoff reacts to 503 bursts
#      (F03 test 7).
#   4. The panic stop halts a running crawl + fuzz with zero in-flight requests (F20 test 5).
# Usage: Scripts/m11a-dod.sh   (SWIFTPM_FLAGS may carry extra swift-build flags, e.g. on Linux CI)
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
PROJECT="$WORK/m11a.gulp"
FIXTURE="$PKG/Tests/Fixtures/vulnlab-crawl.txt"

# Every check fails the script by itself (`a && b` hides a failing `a` from `set -e`).
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
"$BEACON_BIN/gulp-beacon" --dev --http-port 8091 --dns-port 8054 --token s3cret > "$WORK/beacon2.log" 2>&1 &
BEACON2=$!
trap 'kill $VULNLAB $BEACON $BEACON2 2>/dev/null || true; rm -rf "$WORK"' EXIT
wait_port 8088
wait_port 8090
wait_port 8091
"$GULP" scope --project "$PROJECT" --add "$LAB/" > /dev/null

# 1. Crawl: every linked in-scope route, nothing out of scope, the logout link never fetched.
"$GULP" crawl --project "$PROJECT" --seed "$LAB/" --pages > "$WORK/crawl.txt"; grep "^crawl:" "$WORK/crawl.txt"
while IFS= read -r path; do
  grep -qE $'^[0-9]{3}\tGET\t'"$(sed 's/[.?]/\\&/g' <<< "$LAB$path")"$'\t' "$WORK/crawl.txt" \
    || { echo "crawl missed $path" >&2; exit 1; }
done < "$FIXTURE"
grep -q '^out of scope: http://localhost:8088/crawl/elsewhere$' "$WORK/crawl.txt"
grep -q '^out of scope: http://example.invalid/$' "$WORK/crawl.txt"
grep -q '^excluded: http://127.0.0.1:8088/crawl/logout$' "$WORK/crawl.txt"
grep -q '^form: GET http://127.0.0.1:8088/crawl/search \[q\]$' "$WORK/crawl.txt"
"$GULP" history --project "$PROJECT" --last 500 > "$WORK/history.txt"
if grep -qE 'localhost:8088|example\.invalid|/crawl/logout' "$WORK/history.txt"; then
  echo "an out-of-scope or excluded URL was fetched" >&2
  exit 1
fi
"$GULP" target --project "$PROJECT" | grep -q "from-sitemap"
echo "PASS 1: the crawl reached all $(wc -l < "$FIXTURE") linked routes, fetched nothing out of scope, never the logout link; the site map filled"

# 2. OAST: Test Beacon, the blind SSRF via Repeater, a token-protected server, the Fuzzer's OAST column.
"$GULP" oast configure --project "$PROJECT" --server http://127.0.0.1:8090 --domain oast.test \
  --connect-to 127.0.0.1:8090 --poll 1 | tee "$WORK/oast.txt"
"$GULP" oast test --project "$PROJECT" | tee "$WORK/oast-test.txt"
grep -qE '^oast test: ok in [0-9.]+ s \(http\) via [0-9a-v]{20}[ybndrfg8ejkmcpqxot1uwisza345h769]{13}\.oast\.test$' "$WORK/oast-test.txt"
printf 'GET /fetch?url=«beacon(url)»blind HTTP/1.1\r\nHost: 127.0.0.1:8088\r\n\r\n' > "$WORK/ssrf.txt"
"$GULP" repeater --project "$PROJECT" --raw "$WORK/ssrf.txt" --target "$LAB" --oast-wait 8 | tee "$WORK/ssrf.out"
EXCHANGE=$(sed -n 's/^oast: [0-9]* interaction(s) for exchange #\([0-9]*\)$/\1/p' "$WORK/ssrf.out")
grep -qE $'^  dns\t' "$WORK/ssrf.out"
grep -qE $'^  http\t.*\tGET /blind HTTP/1.1$' "$WORK/ssrf.out"
"$GULP" oast list --project "$PROJECT" | grep -qE $'\thttp\t.*\trepeater exchange #'"$EXCHANGE"$'\t'
echo "PASS 2a: Test Beacon ok; the blind SSRF's DNS and HTTP interactions are tied to exchange #$EXCHANGE"
TOKENED="$WORK/token.gulp"
"$GULP" scope --project "$TOKENED" --add "$LAB/" > /dev/null
if "$GULP" oast configure --project "$TOKENED" --server http://127.0.0.1:8091 --domain oast.test > /dev/null 2>&1; then
  echo "registration without the token should fail" >&2
  exit 1
fi
"$GULP" oast configure --project "$TOKENED" --server http://127.0.0.1:8091 --domain oast.test \
  --connect-to 127.0.0.1:8091 --token s3cret > /dev/null
GULP_OAST_TOKEN=s3cret "$GULP" oast test --project "$TOKENED" | grep -q '^oast test: ok'
echo "PASS 2b: a token-protected server refuses registration without the token and works with it"
printf 'GET /fetch?url=§x§ HTTP/1.1\r\nHost: 127.0.0.1:8088\r\n\r\n' > "$WORK/fuzz.txt"
"$GULP" fuzz --project "$PROJECT" --raw "$WORK/fuzz.txt" --target "$LAB" \
  --tags --set 'list:«beacon(url)»one,http://example.com/two,«beacon(url)»three,http://example.com/four' \
  --oast-wait 8 | tee "$WORK/fuzz.out"
grep -q '^oast: 2 row(s) caused interactions$' "$WORK/fuzz.out"
grep -qE $'^  #1\tdns,http\t' "$WORK/fuzz.out"
grep -qE $'^  #3\tdns,http\t' "$WORK/fuzz.out"
echo "PASS 2c: the Fuzzer's OAST column flags exactly the two rows that carried a Beacon payload"

# 3. The shared limiter: a 2,000 req/s fuzz + a crawl under a 1,000 req/s global cap and a 50
#    per-host concurrency budget; then backoff on a 503 burst.
"$GULP" governor caps-drill --project "$PROJECT" --target "$LAB" | tee "$WORK/caps.txt"
RATE=$(sed -n 's/^caps: max \([0-9]*\) requests in any 1 s.*/\1/p' "$WORK/caps.txt")
PEAK=$(sed -n 's/^caps: peak in flight to [^:]*: \([0-9]*\) .*/\1/p' "$WORK/caps.txt")
PAGES=$(sed -n 's/^caps: rate phase: fuzz [0-9]* requests, crawl \([0-9]*\) pages$/\1/p' "$WORK/caps.txt")
[ "$RATE" -le 1010 ] || fail "aggregate rate $RATE exceeds the 1,000 req/s cap"
[ "$RATE" -ge 900 ] || fail "aggregate rate $RATE: the cap, not something else, should be the limit"
[ "${PAGES:-0}" -gt 0 ] || fail "the crawl didn't run alongside the fuzz"
[ "$PEAK" -le 50 ] || fail "peak in flight $PEAK exceeds the per-host budget of 50"
[ "$PEAK" -ge 45 ] || fail "peak in flight $PEAK: 130 wanted, the budget should have been reached"
grep -q 'both in flight at once: true$' "$WORK/caps.txt" || fail "fuzz and crawl never overlapped"
echo "PASS 3a: fuzz + crawl together peaked at $RATE req/s (cap 1,000) and $PEAK in flight to one host (budget 50, 130 wanted)"
"$GULP" governor backoff-drill --project "$PROJECT" --target "$LAB" | tee "$WORK/backoff.txt"
read -r BEFORE LOWEST AFTER < <(sed -n 's/^backoff: before \([0-9]*\)\/s, lowest \([0-9]*\)\/s, at the end \([0-9]*\)\/s$/\1 \2 \3/p' "$WORK/backoff.txt")
grep -q '^backoff: throttled badge seen true, throttled at the end false$' "$WORK/backoff.txt" \
  || fail "the throttled badge should flip on, then off"
[ "$LOWEST" -le $((BEFORE / 2)) ] || fail "the rate only fell from $BEFORE to $LOWEST"
[ "$AFTER" -ge $((BEFORE * 2 / 3)) ] || fail "the rate recovered only to $AFTER (from $BEFORE)"
echo "PASS 3b: the 503 burst drove the rate from $BEFORE/s down to $LOWEST/s with the throttled badge; it recovered to $AFTER/s"

# 4. The panic stop during a crawl + fuzz.
"$GULP" governor panic-drill --project "$PROJECT" --target "$LAB" | tee "$WORK/panic.txt"
grep -qE '^panic: [1-9][0-9]* in flight before; cut [1-9][0-9]*; 0 in flight after one tick; 0 a second later$' "$WORK/panic.txt"
grep -qE '^panic: paused [2-9] task\(s\): .*fuzzer: drill.*crawler: ' "$WORK/panic.txt"
read -r SENT_A SENT_B < <(sed -n 's/^panic: fuzz sent \([0-9]*\) then \([0-9]*\) while paused; crawler paused true$/\1 \2/p' "$WORK/panic.txt")
[ -n "$SENT_A" ] && [ "$SENT_A" = "$SENT_B" ] || fail "the fuzz kept sending while paused ($SENT_A → $SENT_B)"
grep -qE '^panic: resumed; fuzz 300 of 300 results \(0 errors\), crawl [1-9][0-9]* pages$' "$WORK/panic.txt"
echo "PASS 4: the panic stop left 0 requests in flight within one tick and paused both tasks; resume finished them"
echo "M11a DoD: PASS"
