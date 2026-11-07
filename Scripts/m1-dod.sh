#!/usr/bin/env bash
# M1 Definition of Done (docs/03-roadmap.md), as an executable check:
#   1. `gulp-cli send --raw request.txt --target http://127.0.0.1:8088/echo` prints the exact response
#      bytes — compared byte-for-byte with what a raw TCP socket receives for the same request.
#   2. `--target http://127.0.0.1:8089/echo-raw` round-trips a malformed request byte-for-byte.
# Usage: Scripts/m1-dod.sh   (SWIFTPM_FLAGS may carry extra swift-build flags, e.g. on Linux CI)
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

"$BIN/gulp-vulnlab" > "$WORK/vulnlab.log" 2>&1 &
VULNLAB=$!
trap 'kill $VULNLAB 2>/dev/null || true; rm -rf "$WORK"' EXIT
for _ in $(seq 1 100); do
  if (exec 3<>/dev/tcp/127.0.0.1/8088) 2>/dev/null; then break; fi
  sleep 0.1
done

# 1. /echo: gulp-cli output == raw socket capture of the same request.
printf 'GET /echo HTTP/1.1\r\nHost: 127.0.0.1:8088\r\nX-Gulp: m1-dod\r\nConnection: close\r\n\r\n' > "$WORK/echo.txt"
"$BIN/gulp-cli" send --raw "$WORK/echo.txt" --target http://127.0.0.1:8088/echo > "$WORK/echo.gulp"
exec 3<>/dev/tcp/127.0.0.1/8088
cat "$WORK/echo.txt" >&3
cat <&3 > "$WORK/echo.socket"
exec 3<&-
cmp "$WORK/echo.gulp" "$WORK/echo.socket"
# ...and /echo reflects the request bytes exactly as its body.
tail -c "$(wc -c < "$WORK/echo.txt")" "$WORK/echo.gulp" | cmp - "$WORK/echo.txt"
echo "PASS 1: /echo — gulp-cli printed the exact response bytes ($(wc -c < "$WORK/echo.gulp") bytes)"

# 2. /echo-raw: a malformed request (bare LF, duplicate mixed-case headers, obs-fold, no CRLF) survives.
printf 'GET /echo-raw HTTP/1.1\nhOsT: x\nX-Dup: 1\nx-DUP: 2\nX-Fold: a\n  folded\n\n' > "$WORK/malformed.txt"
"$BIN/gulp-cli" send --raw "$WORK/malformed.txt" --target http://127.0.0.1:8089/echo-raw > "$WORK/malformed.out"
cmp "$WORK/malformed.txt" "$WORK/malformed.out"
echo "PASS 2: /echo-raw — malformed request round-tripped byte-for-byte"
echo "M1 DoD: PASS"
