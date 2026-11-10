#!/usr/bin/env bash
# M8 Definition of Done (docs/03-roadmap.md), as an executable check:
#   "A Cartesian attack with 2 positions × 100 payloads runs at ≥ 1,000 req/s against VulnLab;
#    grep-extract pulls the CSRF token from every response; 'Discover content' finds VulnLab's hidden
#    /admin and backup files (F07 test 6)."
# Headless: `gulp-cli fuzz` and `gulp-cli discover` run the Fuzzer and content discovery through a
# project session (scope-gated, recorded, saved), exactly as the app's Fuzzer does.
# Usage: Scripts/m8-dod.sh   (SWIFTPM_FLAGS may carry extra swift-build flags, e.g. on Linux CI)
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
PROJECT="$WORK/m8.gulp"

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

# 0. ScopeGuard: with no scope the Fuzzer sends nothing.
printf 'GET /echo?a=§x§&b=§y§ HTTP/1.1\r\nHost: 127.0.0.1:8088\r\n\r\n' > "$WORK/echo.txt"
"$GULP" fuzz --project "$PROJECT" --raw "$WORK/echo.txt" --target "$LAB" --attack cluster-bomb \
  --set numbers:1-3 --set numbers:1-3 | tee "$WORK/noscope.txt"
grep -q "^out of scope (not sent): 9$" "$WORK/noscope.txt"
"$GULP" scope --project "$PROJECT" --add "$LAB/" > /dev/null
echo "PASS 0: with no scope the attack sent nothing (9 rows out of scope); scope set to $LAB/"

# 1. Cluster bomb, 2 positions × 100 payloads = 10,000 requests, at ≥ 1,000 req/s.
"$GULP" fuzz --project "$PROJECT" --raw "$WORK/echo.txt" --target "$LAB" --attack cluster-bomb \
  --set numbers:1-100 --set numbers:1-100 --concurrency 32 --match "a=100&b=100" | tee "$WORK/bomb.txt"
grep -qE "^attack #2: sent 10000 of 10000 in [0-9.]+ s \([0-9]+ req/s\), errors 0$" "$WORK/bomb.txt"
RATE=$(sed -n 's/.*s (\([0-9]*\) req\/s).*/\1/p' "$WORK/bomb.txt")
[ "$RATE" -ge 1000 ]
grep -q '^match "a=100&b=100": 1 rows$' "$WORK/bomb.txt"
grep -q "^statuses: 200×10000$" "$WORK/bomb.txt"
"$GULP" history --project "$PROJECT" | grep -q "^exchanges: 10000$"
echo "PASS 1: 10,000-request cluster bomb at ${RATE} req/s (≥ 1,000), every request recorded, the grep column found the one pair"

# 2. Grep-extract pulls the CSRF token from every /login response.
printf 'GET /login?n=§n§ HTTP/1.1\r\nHost: 127.0.0.1:8088\r\n\r\n' > "$WORK/login.txt"
"$GULP" fuzz --project "$PROJECT" --raw "$WORK/login.txt" --target "$LAB" --set numbers:1-50 \
  --extract 'between:name="csrf" value="|"' --print-extracts | tee "$WORK/csrf.txt"
grep -q "^extract 1: 50 values (50 unique)$" "$WORK/csrf.txt"
grep -qE "^  [a-z0-9]{24}$" "$WORK/csrf.txt"
echo "PASS 2: grep-extract pulled a (fresh) CSRF token from all 50 /login responses"

# 3. Discover content: the hidden /admin and the backup files.
"$GULP" discover --project "$PROJECT" --url "$LAB/" --depth 2 --concurrency 32 | tee "$WORK/discover.txt"
grep -qE "^admin	403	" "$WORK/discover.txt"
grep -qE "^index.html.bak	200	" "$WORK/discover.txt"
grep -qE "^backup.zip	200	" "$WORK/discover.txt"
grep -qE "^.old/	403	" "$WORK/discover.txt"
grep -qE "^  config.php~	200	" "$WORK/discover.txt"
"$GULP" target --project "$PROJECT" | grep -q "config.php~"
echo "PASS 3: Discover content found /admin, /index.html.bak, /backup.zip and /.old/config.php~ (recorded in the site map)"

echo "M8 DoD: PASS"
