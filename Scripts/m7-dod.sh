#!/usr/bin/env bash
# M7 Definition of Done (docs/03-roadmap.md), as an executable check:
#   "A Base64 → URL → Gzip chain decodes correctly; Smart Decode solves the fixture set; Comparer
#    word-diffs two 1 MB responses in < 1 s; forged alg:none and RS→HS tokens are accepted by VulnLab
#    /api/me and rejected by /safe/api/me, and a weak HMAC secret is brute-forced (F12 test 5)."
# Plus F12 test 3: Transform Tags in a Repeater send (and the literal text when tags are off).
# Headless: `gulp-cli decode`, `diff` and `jwt` run the same GulpCodec/GulpDiff code as the app's
# Decoder, Comparer and JWT Workbench; `gulp-cli repeater` evaluates tags in the send pipeline.
# Usage: Scripts/m7-dod.sh   (SWIFTPM_FLAGS may carry extra swift-build flags, e.g. on Linux CI)
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

# 1. A gzip → Base64 → URL-encoded value decodes back through URL → Base64 → gunzip.
printf '{"user":"alice","admin":false}' > "$WORK/plain.json"
"$GULP" decode --chain gzip,base64,url-encode "@$WORK/plain.json" > "$WORK/encoded.txt"
grep -q '%' "$WORK/encoded.txt"
"$GULP" decode --levels --chain url-decode,base64-decode,gunzip "@$WORK/encoded.txt" | tee "$WORK/levels.txt"
grep -q '^\[3\] gunzip (30 bytes): {"user":"alice","admin":false}$' "$WORK/levels.txt"
[ "$("$GULP" decode --reverse --chain url-decode,base64-decode,gunzip "@$WORK/plain.json")" = "$(cat "$WORK/encoded.txt")" ]
echo "PASS 1: URL → Base64 → gunzip decodes the value, and the reversed chain re-encodes it identically"

# 2. Smart Decode solves the fixture set.
"$GULP" decode --check-fixtures "$PKG/Tests/Fixtures/decoder/smart-decode.json" | tee "$WORK/smart.txt"
grep -q "^8/8 solved" "$WORK/smart.txt"
echo "PASS 2: Smart Decode solved every fixture and reported the right chain"

# 3. Comparer: two ~1 MB responses that differ in three bytes, word mode, in under a second.
curl -sS "$LAB/echo" -o /dev/null   # warm VulnLab
# `yes` is killed by SIGPIPE when `head` has enough; under pipefail that must not fail the script.
(yes 'HTTP/1.1 200 OK alpha beta gamma <div class="row">delta</div> token=abc123' || true) | head -c 1048576 \
  > "$WORK/a.txt"
cp "$WORK/a.txt" "$WORK/b.txt"
for offset in 100000 500000 900000; do printf 'X' | dd of="$WORK/b.txt" bs=1 seek="$offset" conv=notrunc status=none; done
set +e
"$GULP" diff "$WORK/a.txt" "$WORK/b.txt" | tee "$WORK/diff.txt"
STATUS=$?
set -e
[ "$STATUS" -eq 1 ]   # 1 = different
grep -qE "^different: 3 modified, 0 added, 0 deleted \(1048576 vs 1048576 bytes, [0-9]+ ms\)" "$WORK/diff.txt"
MS=$(sed -n 's/.*bytes, \([0-9]*\) ms).*/\1/p' "$WORK/diff.txt")
[ "$MS" -lt 1000 ]
echo "PASS 3: word diff of two 1 MB responses found exactly the 3 changes in ${MS} ms"

# 4. JWT Workbench against VulnLab.
token() { sed 's/.*"token":"\([^"]*\)".*/\1/'; }
status() { curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $2" "$LAB$1"; }
RS=$(curl -sS "$LAB/api/login?user=alice" | token)
[ "$(status /api/me "$RS")" = 200 ] && [ "$(status /safe/api/me "$RS")" = 200 ]
# alg:none, sent through a Repeater tab whose Authorization header is a Transform Tag.
NONE=$("$GULP" jwt forge --attack none --claims '{"role":"admin"}' "$RS" | head -1 | cut -f2)
printf 'GET /api/me HTTP/1.1\r\nHost: 127.0.0.1:8088\r\nAuthorization: Bearer «var(token)»\r\n\r\n' > "$WORK/me.txt"
"$GULP" repeater --project "$WORK/m7.gulp" --raw "$WORK/me.txt" --target "$LAB" --var "token=$NONE" > "$WORK/none.txt"
grep -q "HTTP/1.1 200" "$WORK/none.txt" && grep -q '"role":"admin"' "$WORK/none.txt"
[ "$(status /safe/api/me "$NONE")" = 401 ]
echo "PASS 4a: an alg:none admin token was accepted by /api/me (sent via a Repeater «var(token)» tag) and rejected by /safe/api/me"
# RS→HS confusion with the server's public key.
curl -sS "$LAB/api/key.pem" -o "$WORK/key.pem"
"$GULP" jwt forge --attack confusion --pubkey "$WORK/key.pem" --claims '{"role":"admin"}' "$RS" > "$WORK/confusion.txt"
ACCEPTED=0
while IFS=$'\t' read -r label forged; do
  if [ "$(status /api/me "$forged")" = 200 ]; then ACCEPTED=$((ACCEPTED + 1)); echo "  accepted: $label"; fi
  [ "$(status /safe/api/me "$forged")" = 401 ]
done < "$WORK/confusion.txt"
[ "$ACCEPTED" -ge 1 ]
echo "PASS 4b: an RS→HS256 confusion token signed with the public key was accepted by /api/me and rejected by /safe/api/me"
# kid → /dev/null.
KID=$("$GULP" jwt forge --attack kid --claims '{"role":"admin"}' "$RS" | cut -f2)
[ "$(status /api/me "$KID")" = 200 ] && [ "$(status /safe/api/me "$KID")" = 401 ]
# Weak HMAC secret: crack it, then sign an admin token with it.
HS=$(curl -sS "$LAB/api/login?user=bob&alg=HS256" | token)
"$GULP" jwt crack --wordlist Wordlists/jwt-secrets.txt "$HS" | tee "$WORK/crack.txt"
grep -q "^secret: secret123$" "$WORK/crack.txt"
ADMIN=$("$GULP" jwt sign --alg HS256 --secret secret123 --claims '{"role":"admin"}' "$HS")
"$GULP" jwt verify --secret secret123 "$ADMIN" > /dev/null
[ "$(status /api/me "$ADMIN")" = 200 ] && [ "$(status /safe/api/me "$ADMIN")" = 401 ]
curl -sS "$LAB/.well-known/jwks.json" -o "$WORK/jwks.json"
"$GULP" jwt verify --jwks "$WORK/jwks.json" "$RS" | grep -q "^valid (RS256)"
echo "PASS 4c: the weak HMAC secret was brute-forced (secret123) and an admin token signed with it; kid→/dev/null works; JWKS verification works"

# 5. F12 test 3: Basic auth built by tags; with tags off the literal text is sent.
printf 'GET /echo HTTP/1.1\r\nHost: 127.0.0.1:8088\r\nAuthorization: Basic «base64{ «var(user)»:«var(pass)» }»\r\n\r\n' > "$WORK/basic.txt"
"$GULP" repeater --project "$WORK/m7.gulp" --raw "$WORK/basic.txt" --target "$LAB" --var user=alice --var pass=s3cret \
  > "$WORK/basic-out.txt"
grep -q "Authorization: Basic YWxpY2U6czNjcmV0" "$WORK/basic-out.txt"
"$GULP" repeater --project "$WORK/m7.gulp" --raw "$WORK/basic.txt" --target "$LAB" --no-tags > "$WORK/literal.txt"
grep -q "Authorization: Basic «base64{ «var(user)»:«var(pass)» }»" "$WORK/literal.txt"
echo "PASS 5: Transform Tags built the Basic header in a Repeater send; with tags off the literal text went out"

echo "M7 DoD: PASS"
