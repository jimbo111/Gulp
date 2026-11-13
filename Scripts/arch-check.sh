#!/usr/bin/env bash
# Architecture invariants (docs/01-architecture.md), enforced as an executable check. Gulp's layering
# is only as good as its enforcement, so this runs in the gate/CI: it parses every module's imports
# and fails on a violation of the dependency direction or the platform rules. No Swift build needed
# (pure grep/awk), so it is fast and runs everywhere.
#
# Layers (a module may import its own or a LOWER layer, plus the explicit exceptions below):
#   0 foundation : GulpCore
#   1 services   : GulpHTTP GulpTLS GulpStore GulpQuery GulpCodec GulpDiff
#   2 engines    : GulpProxy GulpRepeater GulpFuzzer GulpScanner GulpCrawler GulpSession GulpOAST
#                  GulpSequencer GulpReport GulpExtensions GulpBrowser GulpScript
#   3 orchestr.  : GulpWorkspace GulpAutomation GulpAI
#   4 ui         : GulpUI GulpFeatures
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
    GulpWorkspace|GulpAutomation|GulpAI) echo 3 ;;
    GulpUI|GulpFeatures) echo 4 ;;
    *) echo -1 ;;
  esac
}

# Modules allowed to import AppKit/SwiftUI/JavaScriptCore/WebKit (platform-capability + UI only).
platform_ok() { case "$1" in GulpUI|GulpFeatures|GulpBrowser|GulpScript) return 0 ;; *) return 1 ;; esac; }

for dir in "$SRC"/*/; do
  module=$(basename "$dir")
  # Apps are allowed to import anything.
  case "$module" in gulp-cli|gulp-vulnlab|CZlib) continue ;; esac
  mrank=$(layer "$module")

  # Gulp-module imports must be same or lower layer.
  for imp in $(grep -rhoE "^import Gulp[A-Za-z]+" "$dir" 2>/dev/null | sed 's/import //' | sort -u); do
    [ "$imp" = "$module" ] && continue
    irank=$(layer "$imp")
    if [ "$irank" -gt "$mrank" ]; then
      problem "$module (layer $mrank) imports $imp (layer $irank) — that inverts the dependency direction"
    fi
  done

  # GulpCore imports nothing from the project.
  if [ "$module" = "GulpCore" ] && grep -rqE "^import Gulp" "$dir" 2>/dev/null; then
    problem "GulpCore imports another Gulp module (it must depend on nothing above it)"
  fi

  # ADR-010: the crawler must not import the browser (keeps the Linux build and the layering intact).
  if [ "$module" = "GulpCrawler" ] && grep -rqE "^import GulpBrowser" "$dir" 2>/dev/null; then
    problem "GulpCrawler imports GulpBrowser — browser-backed crawling must go through the injected BrowserDriver (ADR-010)"
  fi

  # Only UI / platform-capability modules may import the Apple UI frameworks.
  if ! platform_ok "$module" && grep -rqE "^import (AppKit|SwiftUI|JavaScriptCore|WebKit)" "$dir" 2>/dev/null; then
    problem "$module imports an Apple UI/JS framework — engines and services must not (rule 2)"
  fi

  # Engines and services must not import the orchestration or UI layers.
  if [ "$mrank" -ge 1 ] && [ "$mrank" -le 2 ]; then
    if grep -rqE "^import (GulpWorkspace|GulpFeatures|GulpUI|GulpAutomation)" "$dir" 2>/dev/null; then
      problem "$module (layer $mrank) imports an orchestration/UI module — those sit above it"
    fi
  fi
done

if [ "$fail" -eq 0 ]; then
  echo "arch-check: PASS — the dependency direction and platform rules hold across all modules"
else
  echo "arch-check: FAIL"
  exit 1
fi
