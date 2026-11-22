#!/usr/bin/env bash
# Gulp beta build (doc 07, 2026-11-21): a Release Gulp.app signed ad hoc with Hardened Runtime and
# zipped for a few testers. There is no Developer ID yet, so it is not notarized: a tester allows the
# first launch in System Settings > Privacy & Security > Open Anyway (macOS 15 dropped right-click > Open).
# Scripts/release.sh is the Developer ID path (signed, notarized, DMG, appcast) for when there is one.
# Usage: Scripts/beta-build.sh   (macOS, Xcode) -> .build/beta/Gulp-<version>-beta.zip
set -euo pipefail
cd "$(dirname "$0")/.."
[[ "$(uname -s)" == Darwin ]] || { echo "beta-build.sh runs on macOS only." >&2; exit 1; }

DERIVED=.build/xcode-release
APP="$DERIVED/Build/Products/Release/Gulp.app"
OUT=.build/beta

make generate
xcodebuild -project Gulp.xcodeproj -scheme Gulp -configuration Release \
  -destination 'generic/platform=macOS' -derivedDataPath "$DERIVED" \
  CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual DEVELOPMENT_TEAM= build

# Inside-out: the embedded CLI first, then the app, so the outer signature covers the inner one.
codesign --force --options runtime --sign - "$APP/Contents/Helpers/gulp"
codesign --force --options runtime --entitlements App/Gulp.entitlements --sign - "$APP"
codesign --verify --deep --strict --verbose=2 "$APP"

VERSION=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP/Contents/Info.plist")
rm -rf "$OUT" && mkdir -p "$OUT"
ditto -c -k --keepParent "$APP" "$OUT/Gulp-$VERSION-beta.zip"
(cd "$OUT" && shasum -a 256 "Gulp-$VERSION-beta.zip" | tee "Gulp-$VERSION-beta.zip.sha256")
for binary in "$APP/Contents/MacOS/Gulp" "$APP/Contents/Helpers/gulp"; do
  archs=$(lipo -archs "$binary")
  [[ "$archs" == *arm64* && "$archs" == *x86_64* ]] || { echo "not universal: $binary ($archs)" >&2; exit 1; }
done
echo "beta-build: $OUT/Gulp-$VERSION-beta.zip (ad hoc signed, not notarized)"
