#!/usr/bin/env bash
# M12a Definition of Done (docs/03-roadmap.md), as an executable check:
#   "A scan of VulnLab's authenticated area stays logged in by re-running the login macro when the
#    session expires; Repeater sends to the /signed/* fixtures succeed with the matching signing
#    action and fail without it (F15 test 5)."
# 1. Signing: `gulp-cli session sign` signs a request to /signed/dpop, /signed/http-sig and
#    /signed/sigv4 and gets 200; sending the same request without the signing action gets 401.
#    VulnLab verifies each signature with an INDEPENDENT implementation, so a 200 proves interop.
# 2. Re-auth: a login macro + validity rule keeps /account returning 200 across a forced session
#    expiry (/session/expire).
# Usage: Scripts/m12a-dod.sh   (SWIFTPM_FLAGS may carry extra swift-build flags, e.g. on Linux CI)
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
LAB=http://127.0.0.1:8088
GULP="$BIN/gulp-cli"

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
trap 'kill $VULNLAB 2>/dev/null || true; rm -rf "$WORK"' EXIT
wait_port 8088

# 1. Request signing: with the action → 200; without it → 401.
printf 'GET /signed/dpop HTTP/1.1\r\nHost: 127.0.0.1:8088\r\n\r\n' > "$WORK/dpop.txt"
printf 'POST /signed/http-sig HTTP/1.1\r\nHost: 127.0.0.1:8088\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\n{"a":1}' > "$WORK/sig.txt"
printf 'GET /signed/sigv4?b=2&a=1 HTTP/1.1\r\nHost: 127.0.0.1:8088\r\n\r\n' > "$WORK/sigv4.txt"

for scheme in dpop http-sig sigv4; do
  case $scheme in
    dpop) req="$WORK/dpop.txt" ;;
    http-sig) req="$WORK/sig.txt" ;;
    sigv4) req="$WORK/sigv4.txt" ;;
  esac
  out=$("$GULP" session sign --project "$WORK/sign-$scheme.gulp" --raw "$req" --target "$LAB" --scheme "$scheme")
  echo "$out"
  echo "$out" | grep -qE "session sign \($scheme\): 200" || fail "$scheme signing didn't get 200"
  # Without the signing action the fixture must reject the request (401).
  "$GULP" session sign --project "$WORK/nosign-$scheme.gulp" --raw "$req" --target "$LAB" --scheme "$scheme" --no-sign > "$WORK/nosign.txt" 2>&1 || true
  cat "$WORK/nosign.txt"
  grep -qE "session sign \(no signature\): 401" "$WORK/nosign.txt" || fail "$scheme unsigned wasn't rejected with 401"
done
echo "PASS: DPoP, HTTP Message Signatures and SigV4 each verified by VulnLab; unsigned requests rejected"

# 2. Re-auth across session expiry.
out=$("$GULP" session reauth --project "$WORK/reauth.gulp" --base "$LAB" --path /account --expire /session/expire)
echo "$out"
echo "$out" | grep -qE "first fetch of /account → 200" || fail "login macro didn't authenticate"
echo "$out" | grep -qE "after expiry, fetch of /account → 200" || fail "re-auth after expiry failed"
echo "PASS: the login macro keeps /account logged in across a forced session expiry"
echo "M12a DoD: PASS"
