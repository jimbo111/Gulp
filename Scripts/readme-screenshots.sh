#!/usr/bin/env bash
# Regenerates the README screenshots (docs/assets/screens/*.png and tour.gif) from the real app:
#   1. seeds a project with gulp-cli against VulnLab (proxied traffic, a crawl-and-audit, a Repeater
#      tab, a Notebook note);
#   2. runs the opt-in UI test UITests/ReadmeTour.swift, which opens that project and attaches a
#      window screenshot per tool;
#   3. exports the attachments and stitches the tour GIF (needs ffmpeg).
# Usage: Scripts/readme-screenshots.sh   (macOS, Xcode)
set -euo pipefail
cd "$(dirname "$0")/.."
PKG=Packages/GulpKit
OUT=docs/assets/screens
swift build --package-path "$PKG" --product gulp-vulnlab
swift build --package-path "$PKG" --product gulp-cli
BIN=$(swift build --package-path "$PKG" --show-bin-path)
WORK=$(mktemp -d)
export GULP_SUPPORT_DIR="$WORK/support"
LAB=http://127.0.0.1:8088
PROJECT="$WORK/acme-shop.gulp"
GULP="$BIN/gulp-cli"

"$BIN/gulp-vulnlab" > "$WORK/vulnlab.log" 2>&1 &
VULNLAB=$!
trap 'kill $VULNLAB ${PROXY:-} 2>/dev/null || true; [ -n "${KEEP_WORK:-}" ] && echo "work: $WORK" || rm -rf "$WORK"' EXIT
for _ in $(seq 1 100); do curl -s -o /dev/null "$LAB/" && break; sleep 0.1; done

# 1. Scope, then a crawl-and-audit so the site map and the issue list have real content.
"$GULP" scope --project "$PROJECT" --add "$LAB/" > /dev/null
"$GULP" scan crawl-audit --project "$PROJECT" --seed "$LAB/scanlab/" --config balanced > /dev/null

# 2. Proxied browsing, last, so it is what History shows first.
"$GULP" proxy --project "$PROJECT" --port 18187 > "$WORK/proxy.log" 2>&1 &
PROXY=$!
for _ in $(seq 1 100); do (exec 3<>/dev/tcp/127.0.0.1/18187) 2>/dev/null && break; sleep 0.1; done
P=(-s -o /dev/null -x http://127.0.0.1:18187 -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0)")
for path in / /static/app.js /login /api/orders/1 /api/orders/2 "/xss/html?q=hello" \
  "/file?name=readme.txt" "/go?next=/" "/race/status?code=GULP10" /crawl/ /echo "/redirect?to=/echo"; do
  curl "${P[@]}" -b "session=7f3c9a21e0" "$LAB$path"
done
curl "${P[@]}" -X POST -d "user=alice&password=wonderland" "$LAB/login"
curl "${P[@]}" -X POST -d "message=hello+from+gulp" "$LAB/guestbook"
kill "$PROXY"; wait "$PROXY" 2>/dev/null || true; PROXY=

# 3. A Repeater tab and a Notebook note.
printf 'GET /api/orders/2 HTTP/1.1\r\nHost: 127.0.0.1:8088\r\nCookie: session=7f3c9a21e0\r\nAccept: application/json\r\n\r\n' \
  > "$WORK/order.txt"
"$GULP" repeater --project "$PROJECT" --raw "$WORK/order.txt" --target "$LAB" > /dev/null
"$GULP" notebook note --project "$PROJECT" --title "Orders IDOR" \
  --note "Order 2 belongs to bob but alice's session reads it. Check the Authz Matrix." > /dev/null

# 4. The tour. VulnLab stays up so Repeater can send.
xcodegen generate > /dev/null
rm -rf "$WORK/tour.xcresult"
TEST_RUNNER_GULP_README_PROJECT="$PROJECT" xcodebuild -project Gulp.xcodeproj -scheme Gulp \
  -destination 'platform=macOS' -derivedDataPath .build/xcode -resultBundlePath "$WORK/tour.xcresult" \
  -only-testing:GulpAppUITests/ReadmeTour test > "$WORK/xcodebuild.log" 2>&1 \
  || { tail -30 "$WORK/xcodebuild.log"; exit 1; }

# 5. Export, then the GIF.
mkdir -p "$OUT" "$WORK/shots"
xcrun xcresulttool export attachments --path "$WORK/tour.xcresult" --output-path "$WORK/shots" > /dev/null
python3 - "$WORK/shots" "$OUT" <<'PY'
import json, os, shutil, sys
src, out = sys.argv[1], sys.argv[2]
for test in json.load(open(os.path.join(src, "manifest.json"))):
    for a in test.get("attachments", []):
        name = a.get("suggestedHumanReadableName", "").split("_")[0]
        shutil.copy(os.path.join(src, a["exportedFileName"]), os.path.join(out, f"{name}.png"))
PY
ls "$OUT"
LIST="$WORK/tour.txt"
: > "$LIST"
for name in proxy-history target-site-map dashboard-issues repeater scanner; do
  printf "file '%s'\nduration 2.4\n" "$PWD/$OUT/$name.png" >> "$LIST"
done
printf "file '%s'\n" "$PWD/$OUT/scanner.png" >> "$LIST"  # the concat demuxer drops the last duration
ffmpeg -y -loglevel error -f concat -safe 0 -i "$LIST" \
  -vf "scale=1100:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=160[p];[b][p]paletteuse=dither=none" \
  -loop 0 "$OUT/tour.gif"
echo "readme-screenshots: done ($OUT)"
