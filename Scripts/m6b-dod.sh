#!/usr/bin/env bash
# M6b Definition of Done (docs/03-roadmap.md), as an executable check:
#   "Importing VulnLab's /openapi.json creates requests for every /api/* operation in the site map; a
#    HAR export → import round-trips byte-for-byte (F20 test 6) and the other-proxy fixtures import
#    (F20 test 7); Claude Code connected over MCP (stdio) lists history and sends a request, and an
#    out-of-scope send_request is refused with a structured error and audit-logged."
# Headless: `gulp-cli project import/export` is the import/export service every UI entry point uses;
# the MCP client is scripted here as JSON-RPC lines on stdin (exactly what Claude Code writes to
# `gulp-cli mcp`), so CI can check it without an AI client.
# Usage: Scripts/m6b-dod.sh   (SWIFTPM_FLAGS may carry extra swift-build flags, e.g. on Linux CI)
set -euo pipefail
cd "$(dirname "$0")/.."
PKG=Packages/GulpKit
PROXY_PORT=${PROXY_PORT:-18080}
# shellcheck disable=SC2086
swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --product gulp-vulnlab
# shellcheck disable=SC2086
swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --product gulp-cli
# shellcheck disable=SC2086
BIN=$(swift build --package-path "$PKG" ${SWIFTPM_FLAGS:-} --show-bin-path)
WORK=$(mktemp -d)
export GULP_SUPPORT_DIR="$WORK/support"
LAB=http://127.0.0.1:8088
FIXTURES="$PKG/Tests/Fixtures/import"
GULP="$BIN/gulp-cli"

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
PROXY=""
trap 'kill $VULNLAB $PROXY 2>/dev/null || true; rm -rf "$WORK"' EXIT
wait_port 8088

# 1. OpenAPI: every /api/* operation becomes a request in the site map.
curl -sS --fail "$LAB/openapi.json" -o "$WORK/openapi.json"
"$GULP" project import --project "$WORK/api.gulp" --base-url "$LAB/openapi.json" "$WORK/openapi.json" \
  | tee "$WORK/api-import.txt"
grep -q "^OpenAPI / Swagger: imported 4, duplicates 0, skipped 0" "$WORK/api-import.txt"
"$GULP" target --project "$WORK/api.gulp" | tee "$WORK/api-map.txt"
grep -qE "^  api	\(inferred\)" "$WORK/api-map.txt"
grep -qE "^    items	×1	\(inferred\)" "$WORK/api-map.txt"
grep -qE "^    me	×1	\(inferred\)" "$WORK/api-map.txt"
grep -qE "^    orders	×1	\(inferred\)" "$WORK/api-map.txt"
grep -qE "^      1	×1	\(inferred\)" "$WORK/api-map.txt"
"$GULP" project export --project "$WORK/api.gulp" --format har --out "$WORK/api.har" > /dev/null
grep -q '"url" : "http://127.0.0.1:8088/api/orders"' "$WORK/api.har"
grep -q '"value" : "Bearer REPLACE_ME"' "$WORK/api.har"
echo "PASS 1: /openapi.json → 4 requests (GET /api/items, POST /api/orders, GET /api/orders/1, GET /api/me with a bearer placeholder), shown in the site map as not yet sent"

# 2. HAR round trip (F20 test 6): 1,000 proxied exchanges → HAR → a new project, byte-for-byte.
"$GULP" proxy --project "$WORK/source.gulp" --port "$PROXY_PORT" > "$WORK/proxy.log" 2>&1 &
PROXY=$!
wait_port "$PROXY_PORT"
printf 'GET /echo?n={n} HTTP/1.1\r\nHost: 127.0.0.1:8088\r\n\r\n' > "$WORK/echo.txt"
"$GULP" send --raw "$WORK/echo.txt" --target "$LAB" --via "http://127.0.0.1:$PROXY_PORT" --repeat 1000 --concurrency 8 \
  > /dev/null
kill -TERM "$PROXY"
wait "$PROXY" || true
PROXY=""
"$GULP" project export --project "$WORK/source.gulp" --format har --out "$WORK/history.har" | tee "$WORK/export.txt"
"$GULP" project import --project "$WORK/copy.gulp" "$WORK/history.har" | tee "$WORK/import1.txt"
grep -q "^HAR: imported 1000, duplicates 0, skipped 0" "$WORK/import1.txt"
"$GULP" project import --project "$WORK/copy.gulp" "$WORK/history.har" | tee "$WORK/import2.txt"
grep -q "^HAR: imported 0, duplicates 1000, skipped 0" "$WORK/import2.txt"
"$GULP" project export --project "$WORK/copy.gulp" --format har --out "$WORK/again.har" > /dev/null
# The exact bytes are the `_gulp` request/response fields; compare them across both exports.
raw_fields() { grep -oE '"(request|response)" : "[A-Za-z0-9+/=]+"' "$1"; }
[ "$(raw_fields "$WORK/history.har" | wc -l)" -eq 2000 ]
diff <(raw_fields "$WORK/history.har") <(raw_fields "$WORK/again.har")
echo "PASS 2: 1,000 exchanges exported as HAR and imported into a new project byte-for-byte; a second import added nothing"

# 3. Other-proxy imports (F20 test 7): bytes, comments and highlights carried over.
for file in vulnlab-history.xml vulnlab-caido.json vulnlab-mitmproxy.har; do
  "$GULP" project import --project "$WORK/others.gulp" "$FIXTURES/$file" | tee -a "$WORK/others.txt"
done
grep -q "^XML proxy-history export: imported 3," "$WORK/others.txt"
grep -q "^Caido export: imported 2," "$WORK/others.txt"
grep -q "^HAR: imported 2," "$WORK/others.txt"
"$GULP" project export --project "$WORK/others.gulp" --format csv --out "$WORK/others.csv" > /dev/null
grep -q "http://127.0.0.1:8088/echo?from=xml,200,.*,yellow,login & echo check" "$WORK/others.csv"
grep -q "https://localhost:8443/api/orders/2,200,.*,red,IDOR: bob's order" "$WORK/others.csv"
grep -q ",blue,from Caido" "$WORK/others.csv"
"$GULP" history --project "$WORK/others.gulp" --show 1 | grep -q "User-Agent: Mozilla/5.0"
echo "PASS 3: the XML proxy-history, Caido and mitmproxy fixtures imported with their bytes, comments and highlights"

# 4. MCP over stdio: list history, send in scope, refuse out of scope (structured), audit-logged.
"$GULP" scope --project "$WORK/source.gulp" --add "$LAB/api" > /dev/null
cat > "$WORK/mcp-in.jsonl" <<'JSON'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"claude-code","version":"2.0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_exchanges","arguments":{"limit":2}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"send_request","arguments":{"raw":"GET /api/orders/2 HTTP/1.1\r\nHost: 127.0.0.1:8088\r\n\r\n","target":"http://127.0.0.1:8088"}}}
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"send_request","arguments":{"raw":"GET /echo HTTP/1.1\r\nHost: 127.0.0.1:8088\r\n\r\n","target":"http://127.0.0.1:8088"}}}
{"jsonrpc":"2.0","id":6,"method":"resources/read","params":{"uri":"gulp://sitemap"}}
JSON
"$GULP" mcp --project "$WORK/source.gulp" --approval in-scope < "$WORK/mcp-in.jsonl" > "$WORK/mcp-out.jsonl" 2> "$WORK/mcp-err.txt"
cat "$WORK/mcp-out.jsonl" | cut -c1-240
[ "$(wc -l < "$WORK/mcp-out.jsonl")" -eq 6 ]   # one reply per request; none for the notification
grep -q '"id":1,.*"protocolVersion":"2025-06-18"' "$WORK/mcp-out.jsonl"
grep -q '"id":2,.*"name":"send_request"' "$WORK/mcp-out.jsonl"
grep -q '"id":3,.*"total":1000' "$WORK/mcp-out.jsonl"
grep -q '"id":4,.*"isError":false.*"status":200' "$WORK/mcp-out.jsonl"
grep -q '"id":4,.*\\"owner\\":\\"bob\\"' "$WORK/mcp-out.jsonl"
grep -q '"id":5,.*"isError":true.*"code":"out_of_scope"' "$WORK/mcp-out.jsonl"
grep -q '"id":6,.*orders' "$WORK/mcp-out.jsonl"
"$GULP" project audit --project "$WORK/source.gulp" | tee "$WORK/audit.txt"
grep -qE "mcp:claude-code	send_request	allowed	http://127.0.0.1:8088/api/orders/2	#1001" "$WORK/audit.txt"
grep -qE "mcp:claude-code	send_request	refused	http://127.0.0.1:8088/echo	out of scope" "$WORK/audit.txt"
"$GULP" history --project "$WORK/source.gulp" --last 1 | grep -q "api/orders/2"
echo "PASS 4: over MCP stdio the client listed history and sent an in-scope request (recorded as #1001);"
echo "        the out-of-scope send was refused with a structured out_of_scope error; both are in the audit log"

echo "M6b DoD: PASS"
