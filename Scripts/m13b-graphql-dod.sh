#!/usr/bin/env bash
# M13b (GraphQL half) Definition of Done (docs/03-roadmap.md):
#   "the GraphQL Workbench introspects /graphql, renders the schema and flags the field-level authz bug."
# (The DOM Probe half needs the managed browser/CDP and is verified on macOS CI, not here.)
# 1. `gulp-cli graphql introspect` introspects VulnLab's /graphql and renders User.email etc.
# 2. `gulp-cli graphql scan` raises the introspection-enabled issue and, with a probe that reads
#    another user's email without auth, the broken-object-authz issue. The /safe/graphql twin has
#    introspection disabled.
# Usage: Scripts/m13b-graphql-dod.sh   (SWIFTPM_FLAGS may carry extra swift-build flags)
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
"$GULP" scope --project "$WORK/gql.gulp" --add "$LAB/" > /dev/null

# 1. Introspect and render the schema.
"$GULP" graphql introspect --project "$WORK/gql.gulp" --url "$LAB/graphql" | tee "$WORK/schema.txt"
grep -q "graphql: introspection ENABLED" "$WORK/schema.txt" || fail "introspection wasn't detected"
grep -qE "user\(id: Int!\): User" "$WORK/schema.txt" || fail "the query field wasn't rendered"
grep -qE "email: String" "$WORK/schema.txt" || fail "the User.email field wasn't rendered"
# The safe twin disables introspection.
"$GULP" graphql introspect --project "$WORK/gql-safe.gulp" --url "$LAB/safe/graphql" | tee "$WORK/safe.txt"
grep -q "introspection disabled" "$WORK/safe.txt" || fail "/safe/graphql should disable introspection"
echo "PASS 1: introspected /graphql and rendered the schema; /safe/graphql is disabled"

# 2. Scan: introspection-enabled issue + the broken-object-authz probe (read bob's email without auth).
"$GULP" graphql scan --project "$WORK/gql.gulp" --url "$LAB/graphql" \
  --probe '{ user(id: 2) { name email } }' --marker 'bob@secret.test' | tee "$WORK/scan.txt"
grep -q "graphql.introspection-enabled" "$WORK/scan.txt" || fail "introspection-enabled issue not raised"
grep -q "graphql.broken-object-authz" "$WORK/scan.txt" || fail "the field-level authz bug wasn't flagged"
# The safe twin leaks nothing: the same probe must raise no object-authz issue.
"$GULP" graphql scan --project "$WORK/gql-safe.gulp" --url "$LAB/safe/graphql" \
  --probe '{ user(id: 2) { name email } }' --marker 'bob@secret.test' | tee "$WORK/scan-safe.txt"
if grep -q "graphql.broken-object-authz" "$WORK/scan-safe.txt"; then fail "/safe/graphql wrongly flagged"; fi
echo "PASS 2: flagged introspection-enabled and the field-level authz bug; the safe twin is clean"
echo "M13b (GraphQL) DoD: PASS"
