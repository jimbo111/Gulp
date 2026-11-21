#!/usr/bin/env bash
# M3b Definition of Done (docs/03-roadmap.md), as an executable check:
#   "curl --http2 through Gulp to an h2 site and to VulnLab's h2 endpoint; the history shows the
#    decrypted traffic with HTTP/2 flagged, and gRPC-style trailers are kept."
# curl speaks HTTP/2 to the proxy (ALPN mirrored from the h2 server) and trusts ONLY the Gulp CA.
# Usage: Scripts/m3b-dod.sh   (SWIFTPM_FLAGS may carry extra swift-build flags, e.g. on Linux CI)
set -euo pipefail
cd "$(dirname "$0")/.."
PKG=Packages/GulpKit
PROXY_PORT=${PROXY_PORT:-18082}
# shellcheck disable=SC2086
swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --product gulp-vulnlab
# shellcheck disable=SC2086
swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --product gulp-cli
# shellcheck disable=SC2086
BIN=$(swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --show-bin-path)
WORK=$(mktemp -d)
# Isolated CA and secrets: never the user's Keychain (on macOS that blocks on an access prompt).
export GULP_SUPPORT_DIR="$WORK/support"
PROJECT="$WORK/m3b-dod.gulp"

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
"$BIN/gulp-cli" proxy --project "$PROJECT" --port "$PROXY_PORT" > "$WORK/proxy.log" 2>&1 &
PROXY=$!
trap 'kill $VULNLAB $PROXY 2>/dev/null || true; rm -rf "$WORK"' EXIT
wait_port 8443
wait_port "$PROXY_PORT"
"$BIN/gulp-cli" ca export --out "$WORK/gulp-ca.pem"
CURL=(curl -sS --fail --http2 --cacert "$WORK/gulp-ca.pem" -x "http://127.0.0.1:$PROXY_PORT")

# 1. VulnLab over h2 on both legs: curl reports HTTP/2 to the proxy, and VulnLab's echo shows the
#    request it received was HTTP/2 (so the proxy spoke h2 upstream too).
OUT=$("${CURL[@]}" -w '\n%{http_version}' https://localhost:8443/echo)
tail -n1 <<< "$OUT" | grep -qx "2"
grep -q "GET /echo HTTP/2" <<< "$OUT"
echo "PASS 1: curl ↔ Gulp ↔ VulnLab all HTTP/2 (https://localhost:8443/echo)"

# 2. Trailers: VulnLab's /chunked sends a trailer section; over h2 it is a trailing HEADERS frame.
"${CURL[@]}" -D "$WORK/headers.txt" -o /dev/null https://localhost:8443/chunked
grep -qi "^x-trailer: done" "$WORK/headers.txt"
echo "PASS 2: the h2 trailer reached the client (x-trailer: done)"

# 3. A real h2 site (skipped, not failed, without internet access).
if curl -sS --fail -o /dev/null --max-time 10 https://example.com/ 2>/dev/null; then
  OUT=$("${CURL[@]}" --max-time 20 -w '\n%{http_version}' https://example.com/)
  grep -qi "example domain" <<< "$OUT"
  echo "PASS 3: https://example.com through Gulp (client protocol: HTTP/$(tail -n1 <<< "$OUT"))"
else
  echo "SKIP 3: no direct internet access to example.com from this machine"
fi

# 4. History: the exchanges are flagged HTTP/2 and the stored response keeps the trailer.
kill -TERM "$PROXY"
wait "$PROXY"
"$BIN/gulp-cli" history --project "$PROJECT" --last 10 | tee "$WORK/history.log"
grep -E $'\tHTTP/2\thttps://localhost:8443/echo' "$WORK/history.log" > /dev/null
ID=$(grep -E $'\thttps://localhost:8443/chunked$' "$WORK/history.log" | head -n1 | cut -f1)
"$BIN/gulp-cli" history --project "$PROJECT" --show "$ID" | tee "$WORK/show.log"
grep -q "^HTTP/2 200" "$WORK/show.log"
grep -qi "^x-trailer: done" "$WORK/show.log"
echo "PASS 4: the history flags HTTP/2 and keeps the trailer"
echo "M3b DoD: PASS"
