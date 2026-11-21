#!/usr/bin/env bash
# Gulp release: archive → sign (Hardened Runtime, inside-out) → notarize → staple → DMG → Sparkle
# appcast (doc 02 §8, M20/F24). macOS + Xcode only, and it needs the release secrets as environment
# variables (never committed). It does not run in CI on Linux; `bash -n` keeps it syntactically honest.
#
# Required environment:
#   DEVELOPER_ID            e.g. "Developer ID Application: Acme, Inc. (TEAMID)"
#   NOTARY_KEY              path to the App Store Connect API key (.p8)
#   NOTARY_KEY_ID           the key id
#   NOTARY_ISSUER           the issuer id
#   SPARKLE_PRIVATE_KEY     path to the Sparkle EdDSA private key (for generate_appcast)
# Optional:
#   VERSION                 marketing version (default: from the built app's Info.plist)
#   APPCAST_URL_BASE        base URL where the zip/appcast are hosted
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "release.sh runs on macOS only (needs Xcode, codesign, notarytool, stapler)." >&2
  exit 1
fi
command -v xcodebuild >/dev/null || { echo "xcodebuild not found (install Xcode)." >&2; exit 1; }

: "${DEVELOPER_ID:?set DEVELOPER_ID to the Developer ID Application identity}"
: "${NOTARY_KEY:?set NOTARY_KEY to the App Store Connect API key path}"
: "${NOTARY_KEY_ID:?set NOTARY_KEY_ID}"
: "${NOTARY_ISSUER:?set NOTARY_ISSUER}"

BUILD=.build
ARCHIVE="$BUILD/Gulp.xcarchive"
EXPORT="$BUILD/export"
APP="$EXPORT/Gulp.app"

echo "==> Generating the Xcode project"
make generate

echo "==> 1/7 Archiving (Release)"
xcodebuild archive -scheme Gulp -configuration Release -archivePath "$ARCHIVE" \
  CODE_SIGN_STYLE=Manual CODE_SIGN_IDENTITY="$DEVELOPER_ID"

echo "==> 2/7 Exporting a developer-id build"
rm -rf "$EXPORT"
xcodebuild -exportArchive -archivePath "$ARCHIVE" -exportPath "$EXPORT" \
  -exportOptionsPlist ExportOptions.plist

echo "==> 3/7 Signing helpers inside-out (Hardened Runtime + timestamp)"
# Sign embedded helpers/frameworks first, then the app bundle, so the outer signature is valid.
while IFS= read -r -d '' helper; do
  codesign --force --options runtime --timestamp --sign "$DEVELOPER_ID" "$helper"
done < <(find "$APP/Contents" \( -path '*/Helpers/gulp' -o -name '*.dylib' -o -name '*.framework' \) -print0)
codesign --force --options runtime --timestamp --sign "$DEVELOPER_ID" "$APP"
codesign --verify --deep --strict --verbose=2 "$APP"

echo "==> 4/7 Notarizing the app"
ditto -c -k --keepParent "$APP" "$BUILD/Gulp.zip"
xcrun notarytool submit "$BUILD/Gulp.zip" \
  --key "$NOTARY_KEY" --key-id "$NOTARY_KEY_ID" --issuer "$NOTARY_ISSUER" --wait

echo "==> 5/7 Stapling the ticket to the app"
xcrun stapler staple "$APP"

echo "==> 6/7 Building, notarizing and stapling the DMG"
DMG="$BUILD/Gulp.dmg"
rm -f "$DMG"
hdiutil create -volname Gulp -srcfolder "$APP" -ov -format UDZO "$DMG"
codesign --force --timestamp --sign "$DEVELOPER_ID" "$DMG"
xcrun notarytool submit "$DMG" \
  --key "$NOTARY_KEY" --key-id "$NOTARY_KEY_ID" --issuer "$NOTARY_ISSUER" --wait
xcrun stapler staple "$DMG"

echo "==> 7/7 Sparkle appcast"
if [[ -n "${SPARKLE_PRIVATE_KEY:-}" ]] && command -v generate_appcast >/dev/null; then
  generate_appcast --ed-key-file "$SPARKLE_PRIVATE_KEY" "$BUILD"
  echo "appcast.xml written to $BUILD (host it under ${APPCAST_URL_BASE:-<your URL>})"
else
  echo "SKIP appcast: set SPARKLE_PRIVATE_KEY and install Sparkle's generate_appcast." >&2
fi

echo "release: done — $DMG is signed, notarized and stapled."
