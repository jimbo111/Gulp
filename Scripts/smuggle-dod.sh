#!/usr/bin/env bash
# Smuggling Probe Definition of Done (F23 ADV-030/031): the probe classifies VulnLab's CL.TE/TE.CL
# emulation (/smuggle, which hangs 5 s on conflicting Content-Length + Transfer-Encoding framing) as
# vulnerable via the timing differential, and /safe/smuggle (which rejects the conflict promptly) as
# not. This exercises the byte-exact engine: the probes carry framing a normalizing client can't send.
set -euo pipefail
cd "$(dirname "$0")/.."
PKG=Packages/GulpKit
# shellcheck disable=SC2086
swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --product gulp-vulnlab
# shellcheck disable=SC2086
swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --product gulp-cli
# shellcheck disable=SC2086
BIN=$(swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --show-bin-path)
WORK=$(mktemp -d); export GULP_SUPPORT_DIR="$WORK/support"
LAB=http://127.0.0.1:8088; GULP="$BIN/gulp-cli"
fail() { echo "FAIL: $*" >&2; exit 1; }

"$BIN/gulp-vulnlab" > "$WORK/vl.log" 2>&1 & VL=$!
trap 'kill $VL 2>/dev/null || true; rm -rf "$WORK"' EXIT
for _ in $(seq 1 300); do (exec 3<>"/dev/tcp/127.0.0.1/8088") 2>/dev/null && break; sleep 0.1; done

probe() {  # <path>
  printf 'GET %s HTTP/1.1\r\nHost: 127.0.0.1:8088\r\n\r\n' "$1" > "$WORK/req.txt"
  "$GULP" smuggle --raw "$WORK/req.txt" --target "$LAB"
}

echo "== /smuggle =="
vuln=$(probe /smuggle); echo "$vuln"
echo "$vuln" | grep -q "VULNERABLE" || fail "no smuggling differential detected on /smuggle"
echo "PASS 1: the CL.TE/TE.CL timing differential is detected on /smuggle"

echo "== /safe/smuggle =="
safe=$(probe /safe/smuggle); echo "$safe"
echo "$safe" | grep -q "VULNERABLE" && fail "a differential was wrongly reported on /safe/smuggle"
echo "PASS 2: no differential on /safe/smuggle"

echo "Smuggling Probe DoD: PASS"
