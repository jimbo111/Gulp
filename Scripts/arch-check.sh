#!/usr/bin/env bash
# Architecture invariants (docs/01-architecture.md), enforced as an executable check. Gulp's layering
# is only as good as its enforcement, so this runs in the gate/CI: it parses every module's imports
# and fails on a violation of the dependency direction or the platform rules. No Swift build needed
# (pure grep/sed), so it is fast and runs everywhere.
#
# Layers (a module may import its own or a LOWER layer, plus the explicit rules below):
#   0 foundation : GulpCore
#   1 services   : GulpHTTP GulpTLS GulpStore GulpQuery GulpCodec GulpDiff
#   2 engines    : GulpProxy GulpRepeater GulpFuzzer GulpScanner GulpCrawler GulpSession GulpOAST
#                  GulpSequencer GulpReport GulpExtensions GulpBrowser GulpScript
#   3 orchestr.  : GulpWorkspace (owns the agent tool surface / APIGate, rule 6)
#   4 agent API  : GulpAutomation GulpAI (consumers of GulpWorkspace; neither imports the other)
#   5 ui         : GulpUI GulpFeatures
# Every import form counts: `import X`, `@testable import X`, `public import X`, `@_exported import X`,
# `import struct X.Y`. A Gulp module missing from the table is itself a violation (add it here).
# Apps (gulp-cli, gulp-vulnlab) may import anything and are not checked as importers.
set -euo pipefail
cd "$(dirname "$0")/.."
SRC=Packages/GulpKit/Sources
fail=0
problem() { echo "ARCH VIOLATION: $*" >&2; fail=1; }

layer() {
  case "$1" in
    GulpCore) echo 0 ;;
    GulpHTTP|GulpTLS|GulpStore|GulpQuery|GulpCodec|GulpDiff) echo 1 ;;
    GulpProxy|GulpRepeater|GulpFuzzer|GulpScanner|GulpCrawler|GulpSession|GulpOAST|GulpSequencer|GulpReport|GulpExtensions|GulpBrowser|GulpScript) echo 2 ;;
    GulpWorkspace) echo 3 ;;
    GulpAutomation|GulpAI) echo 4 ;;
    GulpUI|GulpFeatures) echo 5 ;;
    *) echo -1 ;;
  esac
}

# The modules a source directory imports, one per line, whatever attributes, access level or
# declaration kind precede the module name.
imports() {
  grep -rhE '^[[:space:]]*(@[A-Za-z_]+[[:space:]]+)*((public|package|internal|fileprivate|private)[[:space:]]+)?import[[:space:]]' \
    "$1" --include='*.swift' 2>/dev/null \
    | sed -E 's/^[[:space:]]*(@[A-Za-z_]+[[:space:]]+)*((public|package|internal|fileprivate|private)[[:space:]]+)?import[[:space:]]+((typealias|struct|class|enum|protocol|let|var|func)[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*).*/\6/' \
    | sort -u
}

# Modules allowed to import AppKit/SwiftUI/JavaScriptCore/WebKit (platform-capability + UI only).
platform_ok() { case "$1" in GulpUI|GulpFeatures|GulpBrowser|GulpScript) return 0 ;; *) return 1 ;; esac; }

for dir in "$SRC"/*/; do
  module=$(basename "$dir")
  # Apps are allowed to import anything.
  case "$module" in gulp-cli|gulp-vulnlab|CZlib) continue ;; esac
  mrank=$(layer "$module")
  if [ "$mrank" -lt 0 ]; then
    problem "$module is not in the layer table of Scripts/arch-check.sh (docs/01-architecture.md §3)"
    continue
  fi
  mods=$(imports "$dir")

  for imp in $mods; do
    [ "$imp" = "$module" ] && continue
    case "$imp" in
      Gulp*)
        irank=$(layer "$imp")
        if [ "$irank" -lt 0 ]; then
          problem "$module imports $imp, which is not in the layer table (add it to Scripts/arch-check.sh)"
        elif [ "$irank" -gt "$mrank" ]; then
          problem "$module (layer $mrank) imports $imp (layer $irank) — that inverts the dependency direction"
        fi
        ;;
      AppKit|SwiftUI|JavaScriptCore|WebKit)
        # Rule 2: only UI / platform-capability modules may import the Apple UI frameworks.
        platform_ok "$module" || problem "$module imports $imp — engines and services must not (rule 2)"
        ;;
    esac
  done

  # Rule 6: the two agent-API consumers build on GulpWorkspace's APIGate and never on each other.
  case "$module" in
    GulpAI) echo "$mods" | grep -qx GulpAutomation && problem "GulpAI imports GulpAutomation — both use GulpWorkspace's APIGate (rule 6)" ;;
    GulpAutomation) echo "$mods" | grep -qx GulpAI && problem "GulpAutomation imports GulpAI — both use GulpWorkspace's APIGate (rule 6)" ;;
  esac

  # ADR-010: the crawler must not import the browser (keeps the Linux build and the layering intact).
  if [ "$module" = "GulpCrawler" ] && echo "$mods" | grep -qx GulpBrowser; then
    problem "GulpCrawler imports GulpBrowser — browser-backed crawling must go through the injected BrowserDriver (ADR-010)"
  fi
done

if [ "$fail" -eq 0 ]; then
  echo "arch-check: PASS — the dependency direction (rule 6 included) and platform rules hold across all modules"
else
  echo "arch-check: FAIL"
  exit 1
fi
