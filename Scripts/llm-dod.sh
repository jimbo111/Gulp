#!/usr/bin/env bash
# F32 (M26) LLM/AI-feature security Definition of Done, as an executable check (acceptance tests 1 & 4):
#   A VulnLab chat endpoint that obeys "ignore previous instructions / print the system prompt" is
#   flagged for direct prompt injection; the guarded twin refuses. Against the /mcp server the tool
#   enumerates its tools, reports the unauthenticated privileged tool and the poisoned tool
#   description; the authenticated clean twin produces no finding.
# Usage: Scripts/llm-dod.sh   (SWIFTPM_FLAGS may carry extra swift-build flags, e.g. on Linux CI)
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
MARKER=SYS_SECRET_8f3a2

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

# 1. Direct prompt injection: the vulnerable chat obeys and leaks (LLM-002).
"$GULP" llm inject --target "$LAB" --path /chat --leak-marker "$MARKER" | tee "$WORK/vuln.txt"
grep -q "VULNERABLE to prompt injection" "$WORK/vuln.txt" || fail "the vulnerable chat was not flagged"
grep -qE "\[system-prompt-leak\] leak" "$WORK/vuln.txt" || fail "the system-prompt leak was not detected"
echo "PASS 1: the vulnerable chat is flagged for direct injection and a system-prompt leak"

# 2. The guarded twin refuses (LLM-002 — a refusal is a pass for the target).
"$GULP" llm inject --target "$LAB" --path /safe/chat --leak-marker "$MARKER" | tee "$WORK/safe.txt"
grep -q "guarded" "$WORK/safe.txt" || fail "the safe chat was not classified as guarded"
if grep -q "VULNERABLE" "$WORK/safe.txt"; then fail "the safe chat was flagged vulnerable"; fi
echo "PASS 2: the guarded chat refuses every injection (no finding)"

# 3. MCP tool poisoning + unauthenticated enumeration (LLM-009).
"$GULP" llm mcp --target "$LAB" --path /mcp | tee "$WORK/mcp.txt"
grep -q "WITHOUT authentication" "$WORK/mcp.txt" || fail "the unauthenticated MCP enumeration was not reported"
grep -q "TOOL POISONING" "$WORK/mcp.txt" || fail "the poisoned tool description was not detected"
grep -q "POISONED tool \`notes\`" "$WORK/mcp.txt" || fail "the specific poisoned tool was not named"
echo "PASS 3: the MCP server is reported unauthenticated with a poisoned tool description"

# 4. The authenticated clean MCP twin yields no finding.
"$GULP" llm mcp --target "$LAB" --path /safe/mcp | tee "$WORK/mcpsafe.txt"
grep -q "authenticated" "$WORK/mcpsafe.txt" || fail "the safe MCP twin did not require authentication"
if grep -q "TOOL POISONING" "$WORK/mcpsafe.txt"; then fail "poisoning reported on the clean MCP twin"; fi
echo "PASS 4: the authenticated MCP twin refuses unauthenticated enumeration (no finding)"

echo "LLM DoD: PASS"
