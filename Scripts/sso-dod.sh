#!/usr/bin/env bash
# F25 (M21) SSO Workbench Definition of Done, as an executable check (acceptance tests 1 & 4):
#   Against a VulnLab OIDC app, `gulp sso probe` reconstructs the auth-code flow and flags a
#   redirect_uri that accepts a /callback/../evil path and a PKCE downgrade to plain; the /safe/
#   authorization server rejects every redirect_uri variant and enforces S256.
# Usage: Scripts/sso-dod.sh   (SWIFTPM_FLAGS may carry extra swift-build flags, e.g. on Linux CI)
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
LAB=http://127.0.0.1:8088
GULP="$BIN/gulp-cli"

fail() { echo "FAIL: $*" >&2; exit 1; }
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

CB="http://127.0.0.1:8088/callback"
BASE="response_type=code&client_id=app&redirect_uri=$CB&state=s&code_challenge=abc&code_challenge_method=S256"

# 1. Offline reconstruction + weakness analysis (SSO-001/004).
"$GULP" sso analyze --authorize "$LAB/authorize?response_type=code&client_id=app&redirect_uri=$CB&code_challenge=abc&code_challenge_method=plain" \
  | tee "$WORK/analyze.txt"
grep -q "grant: authorization_code+pkce" "$WORK/analyze.txt" || fail "grant type not reconstructed"
grep -q "weakness state-missing" "$WORK/analyze.txt" || fail "missing state not flagged"
grep -q "weakness pkce-plain" "$WORK/analyze.txt" || fail "plain PKCE not flagged"
echo "PASS 1: flow reconstructed (auth-code+PKCE); missing state and plain PKCE flagged"

# 2. Live probe against the VULNERABLE authorization server (SSO-003/004).
"$GULP" sso probe --authorize "$LAB/authorize?$BASE" --target "$LAB" | tee "$WORK/vuln.txt"
grep -q "redirect_uri: OVER-ACCEPTS" "$WORK/vuln.txt" || fail "vulnerable AS did not over-accept redirect_uri"
grep -qE "\[path-suffix\].*ACCEPTED" "$WORK/vuln.txt" || fail "the /callback/../evil variant was not accepted"
grep -q "pkce: DOWNGRADEABLE" "$WORK/vuln.txt" || fail "vulnerable AS did not accept a PKCE downgrade"
echo "PASS 2: vulnerable AS over-accepts redirect_uri (incl. path traversal) and accepts PKCE downgrade"

# 3. Live probe against the SAFE twin — strict redirect_uri, enforced PKCE.
"$GULP" sso probe --authorize "$LAB/safe/authorize?$BASE" --target "$LAB" | tee "$WORK/safe.txt"
grep -q "redirect_uri: strict" "$WORK/safe.txt" || fail "safe AS accepted a redirect_uri variant"
grep -q "pkce: enforced" "$WORK/safe.txt" || fail "safe AS did not enforce S256 PKCE"
if grep -qE "\[(path-suffix|subdomain|sibling-host|@-confusion|path-traversal)\].*ACCEPTED" "$WORK/safe.txt"; then
  fail "safe AS accepted a redirect_uri mutation"
fi
echo "PASS 3: safe AS rejects every redirect_uri variant and enforces S256 PKCE"

echo "SSO DoD: PASS"
