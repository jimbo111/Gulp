#!/usr/bin/env bash
# M13a/M13b DOM Probe Definition of Done (F16 test 2): the embedded instrumentation reports the planted
# DOM XSS on a vulnerable SPA (location.hash -> innerHTML) and nothing on the safe twin, in a REAL
# headless Chromium. Runs on a host with Node + Playwright + Chromium; skips cleanly otherwise so CI on
# a browser-less runner stays green. The Swift CDP client and launch helper are covered by unit tests;
# this proves the JavaScript that ships (the same dom-probe.js) actually catches the bug in a browser.
set -euo pipefail
cd "$(dirname "$0")/.."
NODE=${NODE:-/opt/node22/bin/node}
export PLAYWRIGHT_BROWSERS_PATH=${PLAYWRIGHT_BROWSERS_PATH:-/opt/pw-browsers}
export NODE_PATH=${NODE_PATH:-/opt/node-tools/node_modules}

if ! "$NODE" --version >/dev/null 2>&1; then
  echo "SKIP: Node not found (set NODE=/path/to/node); DOM Probe real-browser check not run."
  exit 0
fi
if [ ! -e "$PLAYWRIGHT_BROWSERS_PATH" ]; then
  echo "SKIP: no Chromium at PLAYWRIGHT_BROWSERS_PATH=$PLAYWRIGHT_BROWSERS_PATH; check not run."
  exit 0
fi
if ! "$NODE" -e "require('$NODE_PATH/playwright')" >/dev/null 2>&1; then
  echo "SKIP: Playwright not resolvable at NODE_PATH=$NODE_PATH; check not run."
  exit 0
fi

"$NODE" Scripts/dom-probe-check.mjs
echo "M13a/M13b DOM Probe DoD: PASS"
