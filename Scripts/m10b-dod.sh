#!/usr/bin/env bash
# M10b Definition of Done (docs/03-roadmap.md), F33 acceptance tests 1–4, as an executable check:
#   1. A gRPC unary call through the proxy to VulnLab's vulnlab.Echo/Say (HTTP/2 on :8443) shows a
#      schema-less field tree for the request and response, and grpc-status 0 from the HTTP/2 trailers.
#   2. Fetching the schema via reflection (and, separately, importing the fixture's .proto) names the
#      fields; editing `message` and re-sending from Repeater returns the edited echo, with a correct
#      length prefix and the trailers shown.
#   3. A gRPC-Web text-mode call over HTTP/1.1 decodes the same way (base64 stream and in-body trailer
#      message), and so does a Connect unary call.
#   4. A Fuzzer position inside a protobuf string field sends correctly re-encoded payloads: VulnLab
#      parses every one (it answers INVALID_ARGUMENT to a body it can't parse) and echoes it back.
# curl is the client (it trusts only the Gulp CA); everything else is `gulp-cli`.
# Usage: Scripts/m10b-dod.sh   (SWIFTPM_FLAGS may carry extra swift-build flags, e.g. on Linux CI)
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
LAB=https://localhost:8443
PROXY_PORT=${PROXY_PORT:-18110}
GULP="$BIN/gulp-cli"
PROJECT="$WORK/m10b.gulp"
PROTO="$PKG/Tests/Fixtures/grpc/vulnlab.proto"

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
wait_port 8443
"$GULP" scope --project "$PROJECT" --add "$LAB/" > /dev/null
"$GULP" ca export --out "$WORK/gulp-ca.pem" > /dev/null

# EchoRequest { message: "hello" } = 0a 05 "hello" (7 bytes), in a gRPC envelope: flag 0, length 7.
printf '\x00\x00\x00\x00\x07\x0a\x05hello' > "$WORK/say.bin"

"$GULP" proxy --project "$PROJECT" --port "$PROXY_PORT" > "$WORK/proxy.log" 2>&1 &
PROXY=$!
wait_port "$PROXY_PORT"
CURL=(curl -sS --fail --cacert "$WORK/gulp-ca.pem" -x "http://127.0.0.1:$PROXY_PORT")
# gRPC over HTTP/2 on both legs.
"${CURL[@]}" --http2 -o "$WORK/say.out" -w '%{http_version}\n' -H 'Content-Type: application/grpc' \
  -H 'TE: trailers' --data-binary @"$WORK/say.bin" "$LAB/vulnlab.Echo/Say" > "$WORK/say.version"
grep -qx 2 "$WORK/say.version"
# gRPC-Web text over HTTP/1.1: the body is the base64 of the same envelope.
base64 < "$WORK/say.bin" | tr -d '\n' > "$WORK/say.b64"
"${CURL[@]}" --http1.1 -o /dev/null -H 'Content-Type: application/grpc-web-text' -H 'X-Grpc-Web: 1' \
  --data-binary @"$WORK/say.b64" "$LAB/vulnlab.Echo/Say"
# Connect unary with JSON over HTTP/1.1.
"${CURL[@]}" --http1.1 -o /dev/null -H 'Content-Type: application/json' -H 'Connect-Protocol-Version: 1' \
  --data-binary '{"message":"connect me","times":2}' "$LAB/vulnlab.Echo/Say"
kill -TERM "$PROXY"
wait "$PROXY" || true
PROXY=""
"$GULP" history --project "$PROJECT" --last 10 > "$WORK/history.log"
IDS=()  # bash 3.2 (macOS) has no mapfile
while read -r id; do IDS+=("$id"); done < <(grep -E $'\thttps://localhost:8443/vulnlab.Echo/Say$' "$WORK/history.log" | cut -f1 | sort -n)
[ "${#IDS[@]}" -eq 3 ] || { cat "$WORK/history.log"; echo "expected 3 recorded calls" >&2; exit 1; }
GRPC_ID=${IDS[0]}
WEB_ID=${IDS[1]}
CONNECT_ID=${IDS[2]}

# 1. Schema-less: the field tree by number, status 0 from the HTTP/2 trailers.
"$GULP" grpc show --project "$PROJECT" "$GRPC_ID" | tee "$WORK/show1.txt"
grep -q '^gRPC \[grpc\] /vulnlab.Echo/Say  status 0 OK$' "$WORK/show1.txt"
grep -q '^request 1 (envelope flags 0x00, length 7):$' "$WORK/show1.txt"
grep -q '^  1: "hello"$' "$WORK/show1.txt"
grep -qE '^response 1 \(envelope flags 0x00, length [0-9]+\):$' "$WORK/show1.txt"
grep -q '^  2: 5  (sint -3)$' "$WORK/show1.txt"
grep -q '^  grpc-status: 0$' "$WORK/show1.txt"
echo "PASS 1: the gRPC call through the proxy decodes schema-less; grpc-status 0 from the HTTP/2 trailers"

# 2a. Reflection names the fields.
"$GULP" grpc schemas fetch --project "$PROJECT" --target "$LAB" | tee "$WORK/fetch.txt"
grep -q '^fetched reflection https://localhost:8443: vulnlab.Echo, vulnlab.Orders, vulnlab.SafeOrders$' "$WORK/fetch.txt"
"$GULP" grpc show --project "$PROJECT" "$GRPC_ID" --json > "$WORK/show2.txt"
grep -q '^request 1 (envelope flags 0x00, length 7, vulnlab.EchoRequest):$' "$WORK/show2.txt"
grep -q '^  message: "hello"$' "$WORK/show2.txt"
grep -q '^  length: 5$' "$WORK/show2.txt"
grep -q '^  json   "message" : "hello"$' "$WORK/show2.txt"
# 2b. Separately, the fixture's .proto names them too.
SCHEMA_ID=$("$GULP" grpc schemas list --project "$PROJECT" | sed -n 's/^\([0-9A-F-]*\)\treflection .*/\1/p')
"$GULP" grpc schemas remove --project "$PROJECT" "$SCHEMA_ID"
"$GULP" grpc show --project "$PROJECT" "$GRPC_ID" | grep -q '^  1: "hello"$'
"$GULP" grpc schemas import --project "$PROJECT" --proto "$PROTO" | grep -q '^imported vulnlab.proto: '
"$GULP" grpc show --project "$PROJECT" "$GRPC_ID" | grep -q '^  message: "hello"$'
# 2c. Edit `message` and re-send from Repeater (HTTP/2): the edited echo, the new length prefix
#     (0a 0e "edited-in-gulp" + 10 02 for times = 18 bytes), and the trailers.
"$GULP" grpc call --project "$PROJECT" --exchange "$GRPC_ID" --set message=edited-in-gulp --set times=2 \
  | tee "$WORK/call.txt"
grep -qE '^tab [0-9]+, exchange #[0-9]+$' "$WORK/call.txt"
grep -q '^request 1 (envelope flags 0x00, length 18, vulnlab.EchoRequest):$' "$WORK/call.txt"
grep -q '^  message: "edited-in-gulp edited-in-gulp"$' "$WORK/call.txt"
grep -q '^  grpc-status: 0$' "$WORK/call.txt"
echo "PASS 2: reflection and the .proto both name the fields; the edited call echoes back with a correct length prefix"

# 3. gRPC-Web text (base64 stream, in-body trailer message) and Connect unary decode the same way.
"$GULP" grpc show --project "$PROJECT" "$WEB_ID" | tee "$WORK/web.txt"
grep -q '^gRPC-Web \[grpc-web-text\] /vulnlab.Echo/Say  status 0 OK$' "$WORK/web.txt"
grep -q '^  message: "hello"$' "$WORK/web.txt"
grep -q '^  grpc-status: 0$' "$WORK/web.txt"
"$GULP" grpc show --project "$PROJECT" "$CONNECT_ID" | tee "$WORK/connect.txt"
grep -q '^Connect \[connect-unary\] /vulnlab.Echo/Say  status 0 OK$' "$WORK/connect.txt"
grep -q '"message":"connect me connect me"' "$WORK/connect.txt"
echo "PASS 3: gRPC-Web text mode and Connect unary decode (messages, trailers, status)"

# 4. Fuzz inside the protobuf `message` field: every payload is re-encoded, parsed and echoed.
printf 'POST /vulnlab.Echo/Say HTTP/1.1\r\nHost: localhost:8443\r\nContent-Type: application/grpc\r\nTE: trailers\r\nContent-Length: 12\r\n\r\n' \
  > "$WORK/say.req"
cat "$WORK/say.bin" >> "$WORK/say.req"
"$GULP" fuzz --project "$PROJECT" --raw "$WORK/say.req" --target "$LAB" --grpc-field message \
  --set "list:gulp1,gulp-a-much-longer-payload-that-changes-every-length-prefix,gulp' OR '1'='1,gulp<script>alert(1)</script>" \
  --match "grpc-status: 0" --match "grpc-status: 3" --extract 'regex:gulp[ -~]*' --print-extracts \
  | tee "$WORK/fuzz.txt"
grep -qE '^attack #[0-9]+: sent 4 of 4 in [0-9.]+ s \([0-9]+ req/s\), errors 0$' "$WORK/fuzz.txt"
grep -q '^match "grpc-status: 0": 4 rows$' "$WORK/fuzz.txt"
grep -q '^match "grpc-status: 3": 0 rows$' "$WORK/fuzz.txt"
grep -q '^extract 1: 4 values (4 unique)$' "$WORK/fuzz.txt"
echo "PASS 4: 4 payloads in the protobuf message field, each re-encoded, parsed (status 0) and echoed"
echo "M10b DoD: PASS"
