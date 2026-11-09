#!/usr/bin/env bash
# M5 Definition of Done (docs/03-roadmap.md), as an executable check:
#   "The VulnLab race-condition endpoint (doc 06 §3) can be exploited with a group send in
#    single-packet mode; a pasted cURL command reproduces its request (F06 test 8); /sse streams in a
#    Repeater tab (F06 test 7)."
# Headless: `gulp-cli group` is the group send the Repeater's "Send group" uses, `gulp-cli paste` the
# paste-to-request parser, and `gulp-cli repeater` sends through a Repeater tab stored in a project.
# Usage: Scripts/m5-dod.sh   (SWIFTPM_FLAGS may carry extra swift-build flags, e.g. on Linux CI)
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
wait_port 8443

redemptions() {
  curl -sS "http://127.0.0.1:8088/race/status?code=$1" | sed -n 's/.*redemptions=\([0-9]*\).*/\1/p'
}

# 1. The race: one coupon, 20 requests released together.
race() {  # $1 code, $2 target, $3 mode, $4 extra flags
  curl -sS "http://127.0.0.1:8088/race/reset?code=$1" > /dev/null
  printf 'POST /race/redeem?code=%s HTTP/1.1\r\nHost: localhost\r\nContent-Length: 6\r\n\r\nredeem' "$1" \
    > "$WORK/redeem-$1.txt"
  # shellcheck disable=SC2086
  "$BIN/gulp-cli" group --raw "$WORK/redeem-$1.txt" --target "$2" --count 20 --mode "$3" $4 \
    | tee "$WORK/group-$1.log" | tail -n 2
}
race SEQ http://127.0.0.1:8088 sequential ""
[ "$(redemptions SEQ)" -eq 1 ]
echo "PASS 1a: sent one after another, the coupon is redeemed exactly once (the check works)"
race H2 https://localhost:8443 single-packet ""
grep -q $'\tHTTP/2\t' "$WORK/group-H2.log"
H2_WINS=$(redemptions H2)
[ "$H2_WINS" -gt 1 ]
echo "PASS 1b: single-packet over HTTP/2 redeemed the coupon $H2_WINS times (race exploited)"
race H1 http://127.0.0.1:8088 single-packet "--http1"
H1_WINS=$(redemptions H1)
[ "$H1_WINS" -gt 1 ]
echo "PASS 1c: last-byte sync over HTTP/1 redeemed the coupon $H1_WINS times"

# 2. Paste to request: a cURL command line becomes the same request.
cat > "$WORK/paste.txt" <<'CURL'
curl 'http://127.0.0.1:8088/echo?from=paste' \
  -H 'X-Pasted: yes' \
  -b 'session=abc123' \
  --data-raw '{"amount":"it'\''s 10"}'
CURL
"$BIN/gulp-cli" paste --file "$WORK/paste.txt" --send | tee "$WORK/paste.log"
grep -q "^POST /echo?from=paste HTTP/1.1" "$WORK/paste.log"
grep -q "X-Pasted: yes" "$WORK/paste.log"
grep -q "Cookie: session=abc123" "$WORK/paste.log"
grep -q "{\"amount\":\"it's 10\"}" "$WORK/paste.log"
grep -q "HTTP/1.1 200" "$WORK/paste.log"
echo "PASS 2: a pasted cURL command reproduced its request against /echo"

# 3. /sse streams in a Repeater tab: events print as they arrive, ~200 ms apart.
printf 'GET /sse?n=3 HTTP/1.1\r\nHost: 127.0.0.1:8088\r\n\r\n' > "$WORK/sse.txt"
"$BIN/gulp-cli" repeater --project "$WORK/m5.gulp" --raw "$WORK/sse.txt" --target http://127.0.0.1:8088 \
  --title sse --stream | tee "$WORK/repeater.log"
[ "$(grep -c 'data: event' "$WORK/repeater.log")" -eq 3 ]
FIRST=$(grep 'data: event 1' "$WORK/repeater.log" | sed -n 's/^\[+\([0-9]*\) ms\].*/\1/p')
THIRD=$(grep 'data: event 3' "$WORK/repeater.log" | sed -n 's/^\[+\([0-9]*\) ms\].*/\1/p')
[ $((THIRD - FIRST)) -ge 250 ]
grep -q "tab .* 'sse': 1 send(s)" "$WORK/repeater.log"
echo "PASS 3: /sse streamed in a Repeater tab (event 1 at ${FIRST} ms, event 3 at ${THIRD} ms)"
echo "M5 DoD: PASS"
