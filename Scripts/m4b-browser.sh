#!/usr/bin/env bash
# M4b Definition of Done, the Gulp Browser part (F16 acceptance 1), headless on macOS CI:
#   "one click launches Chromium proxied through Gulp with no certificate warning on
#    https://localhost:8443, its traffic is recorded, and quitting Gulp closes it."
# `gulp-cli browser` is the same launcher the app's Open Browser button uses (same flags, SPKI pin of
# the Gulp CA). Headless `--dump-dom` prints the page: VulnLab /echo reflects the request, and a
# certificate warning would print Chrome's interstitial instead. Quitting is covered by the
# BRW-004 unit test (BrowserLauncher.terminateAll).
# Usage: Scripts/m4b-browser.sh   (needs a Chromium-family browser; skips without one, except in CI)
set -euo pipefail
cd "$(dirname "$0")/.."
PKG=Packages/GulpKit
PROXY_PORT=${PROXY_PORT:-18085}
swift build --package-path "$PKG" --product gulp-vulnlab
swift build --package-path "$PKG" --product gulp-cli
BIN=$(swift build --package-path "$PKG" --show-bin-path)
WORK=$(mktemp -d)
export GULP_SUPPORT_DIR="$WORK/support"  # file CA store; no Keychain on the runner

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
"$BIN/gulp-cli" proxy --project "$WORK/browser.gulp" --port "$PROXY_PORT" > "$WORK/proxy.log" 2>&1 &
PROXY=$!
trap 'kill $VULNLAB $PROXY 2>/dev/null || true; rm -rf "$WORK"' EXIT
wait_port 8443
wait_port "$PROXY_PORT"

# Headless Chrome through the proxy; give it 90 s.
"$BIN/gulp-cli" browser --proxy-port "$PROXY_PORT" --headless --dump-dom \
  --url "https://localhost:8443/echo?from=gulp-browser" > "$WORK/dom.html" 2> "$WORK/browser.err" &
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
  # In CI the runner image ships Chrome: a missing browser there is a failure, not a skip.
  if [ "${CI:-}" = "true" ]; then
    echo "FAIL: no Chromium-family browser on the CI runner" >&2
    exit 1
  fi
  echo "SKIP: no Chromium-family browser on this machine"
  exit 0
fi
head -c 2000 "$WORK/dom.html"; echo
if grep -qiE "ERR_CERT|not private|NET::ERR" "$WORK/dom.html"; then
  echo "FAIL: Chrome showed a certificate warning" >&2
  exit 1
fi
grep -q "from=gulp-browser" "$WORK/dom.html"
echo "PASS 1: headless Chrome loaded https://localhost:8443 through Gulp with no certificate warning"

kill -TERM "$PROXY"
wait "$PROXY"
"$BIN/gulp-cli" history --project "$WORK/browser.gulp" --last 20 | tee "$WORK/history.log"
grep -q "https://localhost:8443/echo?from=gulp-browser" "$WORK/history.log"
echo "PASS 2: the browser's request is in the project history"
echo "M4b browser check: PASS"
