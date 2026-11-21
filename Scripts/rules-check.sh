#!/usr/bin/env bash
# AGENTS.md hard rules, enforced as an executable check (the companion to arch-check.sh, which covers
# the dependency direction). Each rule below is a prose rule that was broken at least once; the check
# turns "remember to" into "the gate fails". Pure grep, no build, so it runs everywhere in seconds.
#
# When a rule fires, fix the code. An exception must be explicit and greppable: say so with the
# marker comment the rule names, on the line above, with a reason.
set -euo pipefail
cd "$(dirname "$0")/.."
SRC=Packages/GulpKit/Sources
TESTS=Packages/GulpKit/Tests
fail=0
problem() { echo "RULE VIOLATION: $*" >&2; fail=1; }

# 1. Scope safety (AGENTS.md §4): active CLI tools send through ScopedSender, which refuses
#    out-of-scope targets before sending. In gulp-cli, constructing an NIOHTTPEngine (any arguments)
#    or sending on a session's unguarded engine (`….http.send(`) bypasses that, unless it is a manual
#    send the operator typed (Repeater-like), marked `// rules-check: manual send` on the line above.
while IFS=: read -r file line _; do
  [ -z "$file" ] && continue
  if ! sed -n "$((line - 1))p" "$file" | grep -q "rules-check: manual send"; then
    problem "$file:$line sends without ScopeGuard — use ScopedSender(scope: .pinned(destination)) (AGENTS.md scope safety)"
  fi
done < <(grep -rnE "NIOHTTPEngine\(|\.http\.send\(" "$SRC/gulp-cli" || true)

# 2. Reproducible tests: randomness in Tests/ comes from a seeded generator (GulpTestSupport's
#    SplitMix64), so a failure reproduces. Bans the system generator and generator-less draws.
while IFS= read -r hit; do
  [ -z "$hit" ] && continue
  problem "$hit — unseeded randomness in a test; pass \`using: &generator\` with SplitMix64(seed:)"
done < <(grep -rnE "SystemRandomNumberGenerator|\.random\(in:[^)]*\)|\.randomElement\(\)|\.shuffled\(\)|\.shuffle\(\)" \
  "$TESTS" --include='*.swift' | grep -v "using:" | grep -vE "^[^:]+:[0-9]+:[[:space:]]*//" || true)

# 3. Store writes never fail silently in the orchestration layer: a dropped `store.record(finding)`
#    loses an issue, a dropped `appendAudit` loses an agent action. In GulpWorkspace wrap the write in
#    `persisting(_:events:_:)`, which reports failures to the Event Log; in GulpAutomation/GulpAI let
#    the error propagate (the APIGate fails the call); in GulpFeatures show it to the user (the view
#    model's message). Matches any receiver ending in `store` or `Store()` (`session.store.`,
#    `currentStore().`).
while IFS= read -r hit; do
  [ -z "$hit" ] && continue
  problem "$hit — a store write behind try? fails silently; propagate it, or use persisting(\"…\", events: events) { try await … }"
done < <(grep -rnE "try\? await [A-Za-z_.]*[Ss]tore(\(\))?\.(record|append|set|add|attach|save|insert|update|delete|write|put|upsert|open|close)" \
  "$SRC/GulpWorkspace" "$SRC/GulpAutomation" "$SRC/GulpAI" "$SRC/GulpFeatures" --include='*.swift' || true)

# 4. Registry lookups go through the checked `require`, which names what is missing, never a
#    force-unwrapped named(…)! — issue definitions (IssueIDCoverageTests checks the ids themselves) and
#    Decoder transforms (names can come from user config, e.g. a Fuzzer processor).
while IFS= read -r hit; do
  [ -z "$hit" ] && continue
  problem "$hit — use require(name) instead of force-unwrapping named(name)"
done < <(grep -rnE "(IssueDefinitions|Transforms)\.named\([^)]*\)!" "$SRC" --include='*.swift' || true)

# 5. AGENTS.md §4: no `@unchecked Sendable` without a comment that justifies it (on the line or within
#    the three lines above).
while IFS=: read -r file line _; do
  [ -z "$file" ] && continue
  start=$((line > 3 ? line - 3 : 1))
  if ! sed -n "${start},${line}p" "$file" | grep -q "//"; then
    problem "$file:$line uses @unchecked Sendable without a justifying comment (AGENTS.md §4)"
  fi
done < <(grep -rnE "@unchecked Sendable" "$SRC" --include='*.swift' || true)

# 6. No secrets in the repo (AGENTS.md §4): no private-key blocks in sources, scripts or config.
#    (VulnLab's own throwaway lab keys are generated at runtime, never committed.)
while IFS= read -r hit; do
  [ -z "$hit" ] && continue
  problem "$hit — a private key is committed; CA keys go to the Keychain or a 0600 file"
done < <(grep -rlE -- "-----BEGIN ([A-Z]+ )?PRIVATE KEY-----" Packages App Beacon Scripts .github 2>/dev/null \
  | grep -vE "/\.build/" || true)

# 7. Tool screens split with GulpUI's HSplit/VSplit: SwiftUI's HSplitView/VSplitView size to their
#    panes' ideal size, so a List or empty-state pane leaves the screen a band in the middle of the
#    window (docs/07 small decisions, 2026-11-20). Only GulpUI's Layouts.swift wraps them.
while IFS= read -r hit; do
  [ -z "$hit" ] && continue
  problem "$hit — use GulpUI's HSplit/VSplit, whose panes fill the split's cross axis"
done < <(grep -rnE "\b[HV]SplitView[[:space:]]*\{" "$SRC" App --include='*.swift' \
  | grep -v "^$SRC/GulpUI/Layouts.swift:" | grep -vE "^[^:]+:[0-9]+:[[:space:]]*//" || true)

if [ "$fail" -ne 0 ]; then
  echo "rules-check: FAILED (see AGENTS.md §4 and the comment above each rule in Scripts/rules-check.sh)" >&2
  exit 1
fi
echo "rules-check: OK (scope-safe CLI sends, seeded test randomness, no silent store writes, checked registry lookups, justified @unchecked Sendable, no committed private keys, filling split views)"
