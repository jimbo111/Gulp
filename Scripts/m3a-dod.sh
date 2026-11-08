#!/usr/bin/env bash
# M3a Definition of Done (docs/03-roadmap.md), as an executable check:
#   "Browse https://example.com and VulnLab's https://localhost:8443 through Gulp with the CA
#    trusted; the history shows the decrypted traffic."
# curl trusts ONLY the exported Gulp CA (--cacert), so a successful request proves the proxy
# intercepted TLS with a leaf it minted; the reopened project must hold the decrypted exchanges.
# Usage: Scripts/m3a-dod.sh   (SWIFTPM_FLAGS may carry extra swift-build flags, e.g. on Linux CI)
set -euo pipefail
cd "$(dirname "$0")/.."
PKG=Packages/GulpKit
PROXY_PORT=${PROXY_PORT:-18081}
# shellcheck disable=SC2086
swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --product gulp-vulnlab
# shellcheck disable=SC2086
swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --product gulp-cli
# shellcheck disable=SC2086
BIN=$(swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --show-bin-path)
WORK=$(mktemp -d)
PROJECT="$WORK/m3a-dod.gulp"

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

# 1. VulnLab over TLS: its own certificate is untrusted, so only interception can satisfy curl.
BODY=$(curl -sS --fail --cacert "$WORK/gulp-ca.pem" -x "http://127.0.0.1:$PROXY_PORT" \
  https://localhost:8443/echo)
# (Since M3b the proxy may speak HTTP/2 to VulnLab, so the echoed request line ends HTTP/1.1 or HTTP/2.)
grep -Eq "GET /echo HTTP/(1\.1|2)" <<< "$BODY"
echo "PASS 1: https://localhost:8443/echo through Gulp, trusting only the Gulp CA"

# 2. A real site (skipped, not failed, when this machine has no internet access at all).
if curl -sS --fail -o /dev/null --max-time 10 https://example.com/ 2>/dev/null; then
  BODY=$(curl -sS --fail --cacert "$WORK/gulp-ca.pem" -x "http://127.0.0.1:$PROXY_PORT" \
    --max-time 20 https://example.com/)
  grep -qi "example domain" <<< "$BODY"
  echo "PASS 2: https://example.com through Gulp"
  EXPECT_EXAMPLE=1
else
  echo "SKIP 2: no direct internet access to example.com from this machine"
  EXPECT_EXAMPLE=0
fi

# 3. The decrypted exchanges are in the project after a clean shutdown.
kill -TERM "$PROXY"
wait "$PROXY"
"$BIN/gulp-cli" history --project "$PROJECT" --last 5 | tee "$WORK/history.log"
grep -q "https://localhost:8443/echo" "$WORK/history.log"
if [ "$EXPECT_EXAMPLE" = 1 ]; then grep -q "https://example.com/" "$WORK/history.log"; fi
echo "PASS 3: the history holds the decrypted HTTPS exchanges"
echo "M3a DoD: PASS"
