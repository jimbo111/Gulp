#!/usr/bin/env bash
# Smuggling confirmation workbench Definition of Done (F23 ADV-032): the workbench CONSTRUCTS a
# self-poisoning desync confirmation (attack + innocuous follow-up) with warnings and scope gating, and
# NEVER sends automatically. By default it is a dry run (nothing sent); it refuses to send an
# out-of-scope target even when authorized. No live VulnLab send: confirmation is never auto-run.
set -euo pipefail
cd "$(dirname "$0")/.."
PKG=Packages/GulpKit
# shellcheck disable=SC2086
swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --product gulp-cli
# shellcheck disable=SC2086
BIN=$(swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --show-bin-path)
WORK=$(mktemp -d); GULP="$BIN/gulp-cli"
fail() { echo "FAIL: $*" >&2; exit 1; }
trap 'rm -rf "$WORK"' EXIT

printf 'GET /search HTTP/1.1\r\nHost: shop.example\r\n\r\n' > "$WORK/req.txt"

echo "== dry run (default: nothing sent) =="
dry=$("$GULP" smuggle-confirm --raw "$WORK/req.txt" --target http://shop.example --vector CL.TE); echo "$dry"
echo "$dry" | grep -q "WARNING" || fail "the workbench must print a prominent warning"
echo "$dry" | grep -q "GPOST /search HTTP/1.1" || fail "the attack must smuggle a GPOST request-start"
echo "$dry" | grep -q "DRY RUN: nothing was sent" || fail "the default must not send"
echo "PASS 1: constructs the confirmation and does not send by default"

echo "== authorized but out of scope → refused =="
oos=$("$GULP" smuggle-confirm --raw "$WORK/req.txt" --target http://shop.example --vector CL.TE \
  --scope-host other.example --i-am-authorized); echo "$oos"
echo "$oos" | grep -q "REFUSED" || fail "an out-of-scope target must be refused even when authorized"
echo "$oos" | grep -q "follow-up status" && fail "nothing should be sent to an out-of-scope target"
echo "PASS 2: refuses to send an out-of-scope target even when authorized"

echo "Smuggling confirmation workbench DoD: PASS"
