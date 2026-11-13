#!/usr/bin/env bash
# M11c check-catalog Definition of Done (the P1/A6 active checks that need server state or the
# unsafe gate, so they aren't in the balanced m11b manifest):
#   - Server-side prototype pollution (SCN-070) on /pp/merge, clean on /safe/pp/merge.
#   - Mass assignment (SCN-072) on /profile/update, clean on /safe/profile/update.
# Both run `gulp-cli scan active --raw` with --unsafe; the safe twins must stay clean.
# Usage: Scripts/m11c-checks-dod.sh   (SWIFTPM_FLAGS may carry extra swift-build flags)
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

# scan a raw POST and return whether the given issue type was raised.
scan_expect() {  # <path> <body> <issue-type> <should-fire:yes|no>
  local path="$1" body="$2" want="$3" fire="$4"
  # NB: compute proj on its own line — a command substitution that reads $path must come after
  # $path is assigned, or `set -u` sees it unbound and every call collapses onto one shared project.
  local proj="$WORK/$(echo "$path" | tr '/' '_').gulp"
  printf 'POST %s HTTP/1.1\r\nHost: 127.0.0.1:8088\r\nContent-Type: application/json\r\nContent-Length: %s\r\n\r\n%s' \
    "$path" "${#body}" "$body" > "$WORK/req.txt"
  "$GULP" scope --project "$proj" --add "$LAB/" > /dev/null
  "$GULP" scan active --project "$proj" --raw "$WORK/req.txt" --target "$LAB" --config balanced --unsafe > "$WORK/scan.txt"
  local issues
  issues=$("$GULP" issues --project "$proj")
  echo "$issues" | grep -E "$want" || true
  if [ "$fire" = "yes" ]; then
    echo "$issues" | grep -q "$want" || fail "$want not raised on $path"
  else
    if echo "$issues" | grep -q "$want"; then fail "$want wrongly raised on $path"; fi
  fi
}

# 1. Prototype pollution.
scan_expect "/pp/merge" '{}' "active.prototype-pollution" yes
scan_expect "/safe/pp/merge" '{}' "active.prototype-pollution" no
echo "PASS 1: server-side prototype pollution flagged on /pp/merge, clean on the safe twin"

# 2. Mass assignment.
scan_expect "/profile/update" '{"name":"bob"}' "active.mass-assignment" yes
scan_expect "/safe/profile/update" '{"name":"bob"}' "active.mass-assignment" no
echo "PASS 2: mass assignment flagged on /profile/update, clean on the safe twin"

# scan a raw GET of <path-with-query> and assert the issue type fires (or not).
scan_get_expect() {  # <path?query> <issue-type> <should-fire:yes|no>
  local path="$1" want="$2" fire="$3"
  local proj="$WORK/$(echo "$path" | tr -c 'a-zA-Z0-9' '_').gulp"
  printf 'GET %s HTTP/1.1\r\nHost: 127.0.0.1:8088\r\n\r\n' "$path" > "$WORK/req.txt"
  "$GULP" scope --project "$proj" --add "$LAB/" > /dev/null
  "$GULP" scan active --project "$proj" --raw "$WORK/req.txt" --target "$LAB" --config balanced --unsafe > "$WORK/scan.txt"
  local issues
  issues=$("$GULP" issues --project "$proj")
  echo "$issues" | grep -E "$want" || true
  if [ "$fire" = "yes" ]; then
    echo "$issues" | grep -q "$want" || fail "$want not raised on $path"
  else
    if echo "$issues" | grep -q "$want"; then fail "$want wrongly raised on $path"; fi
  fi
}

# 3. NoSQL ($where) injection.
scan_get_expect "/nosql/find?user=alice" "active.nosqli" yes
scan_get_expect "/safe/nosql/find?user=alice" "active.nosqli" no
echo "PASS 3: NoSQL injection flagged on /nosql/find, clean on the safe twin"

# 4. XPath injection.
scan_get_expect "/xpath/user?name=alice" "active.xpathi" yes
scan_get_expect "/safe/xpath/user?name=alice" "active.xpathi" no
echo "PASS 4: XPath injection flagged on /xpath/user, clean on the safe twin"

# 5. LDAP injection.
scan_get_expect "/ldap/login?uid=alice" "active.ldapi" yes
scan_get_expect "/safe/ldap/login?uid=alice" "active.ldapi" no
echo "PASS 5: LDAP injection flagged on /ldap/login, clean on the safe twin"

# scan a raw multipart upload of <path> and assert the issue type fires (or not).
scan_upload_expect() {  # <path> <issue-type> <should-fire:yes|no>
  local path="$1" want="$2" fire="$3"
  local proj="$WORK/$(echo "$path" | tr -c 'a-zA-Z0-9' '_').gulp"
  local b="GulpBoundary123"
  # A benign image upload (file part + a form field), with CRLF line endings.
  { printf -- '--%s\r\n' "$b"
    printf 'Content-Disposition: form-data; name="file"; filename="photo.jpg"\r\n'
    printf 'Content-Type: image/jpeg\r\n\r\n'
    printf 'JPEGDATA\r\n'
    printf -- '--%s--\r\n' "$b"; } > "$WORK/mp.bin"
  local len; len=$(wc -c < "$WORK/mp.bin")
  { printf 'POST %s HTTP/1.1\r\nHost: 127.0.0.1:8088\r\nContent-Type: multipart/form-data; boundary=%s\r\nContent-Length: %s\r\n\r\n' "$path" "$b" "$len"
    cat "$WORK/mp.bin"; } > "$WORK/req.txt"
  "$GULP" scope --project "$proj" --add "$LAB/" > /dev/null
  "$GULP" scan active --project "$proj" --raw "$WORK/req.txt" --target "$LAB" --config balanced --unsafe > "$WORK/scan.txt"
  local issues
  issues=$("$GULP" issues --project "$proj")
  echo "$issues" | grep -E "$want" || true
  if [ "$fire" = "yes" ]; then
    echo "$issues" | grep -q "$want" || fail "$want not raised on $path"
  else
    if echo "$issues" | grep -q "$want"; then fail "$want wrongly raised on $path"; fi
  fi
}

# 6. Unrestricted file upload.
scan_upload_expect "/upload" "active.upload" yes
scan_upload_expect "/safe/upload" "active.upload" no
echo "PASS 6: file-upload bypass flagged on /upload, clean on the safe twin"

echo "M11c checks DoD: PASS"
