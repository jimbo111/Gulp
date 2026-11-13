#!/usr/bin/env bash
# Type-check the macOS-only in-process JavaScriptCore extension host (GulpScript/JSExtensionHost.swift)
# on a platform without JavaScriptCore (e.g. Linux CI). JavaScriptCore is an Apple framework, so the
# host is behind `#if canImport(JavaScriptCore)` and normally compiles to empty here — meaning a wrong
# method signature, enum case or cross-module access would only surface on the macOS build. This script
# closes that gap: it type-checks the host body against a faithful shim of the JavaScriptCore subset it
# uses, linked against the REAL GulpExtensions module, so most framework-usage and type errors are
# caught on every platform. (It is not a substitute for the macOS build — the shim must track Apple's
# SDK — but it catches the class of error a Linux `#if canImport` guard otherwise hides.)
set -euo pipefail
cd "$(dirname "$0")/.."
PKG=Packages/GulpKit
HOST="$PKG/Sources/GulpScript/JSExtensionHost.swift"
# shellcheck disable=SC2086
swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --target GulpExtensions >/dev/null
# shellcheck disable=SC2086
BIN=$(swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --show-bin-path)
MOD="$BIN/Modules"
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/harness.swift" <<'SHIM'
// A faithful shim of the JavaScriptCore subset the host uses, with Apple's real signatures.
import Foundation
final class JSValue {
    func call(withArguments arguments: [Any]!) -> JSValue! { nil }
    func toDictionary() -> [AnyHashable: Any]! { nil }
    func toString() -> String! { nil }
    var isUndefined: Bool { false }
}
final class JSContext {
    init!() {}
    @discardableResult func evaluateScript(_ script: String!) -> JSValue! { nil }
    func setObject(_ object: Any!, forKeyedSubscript key: (NSCopying & NSObjectProtocol)!) {}
    func objectForKeyedSubscript(_ key: Any!) -> JSValue! { nil }
    var exceptionHandler: ((JSContext?, JSValue?) -> Void)?
}
import GulpExtensions
SHIM

# Append the host body with its guards and framework import stripped (the shim stands in for them).
sed -n '/#if canImport(JavaScriptCore)/,/#endif/p' "$HOST" \
  | sed '/#if canImport/d; /#endif/d; /import JavaScriptCore/d; /import GulpExtensions/d; /^import Foundation/d' \
  >> "$WORK/harness.swift"

echo "== type-check JSExtensionHost against a JavaScriptCore shim + real GulpExtensions =="
if swiftc -typecheck "$WORK/harness.swift" -I "$MOD"; then
  echo "JSExtensionHost type-check: PASS"
else
  echo "JSExtensionHost type-check: FAIL" >&2
  exit 1
fi
