#!/usr/bin/env bash
# A sample out-of-process Gulp extension (F18 EXT-002/011) in ~30 lines of bash: it registers one
# passive check that flags a leaked `X-Debug-Token` response header. It speaks JSON-RPC 2.0 with
# length-prefixed framing over stdio — exactly what GulpExtensions' ExtensionHost drives. Any language
# that can read/write stdio can implement the same protocol; this one is dependency-free on purpose.
set -u

emit() { # frame and write one JSON body
  local body="$1"
  printf 'Content-Length: %d\r\n\r\n%s' "${#body}" "$body"
}

while true; do
  # Read the Content-Length header block (until a blank line).
  len=0
  while IFS= read -r line; do
    line=${line%$'\r'}
    [ -z "$line" ] && break
    case "$line" in "Content-Length:"*) len=${line#Content-Length: } ;; esac
  done
  [ "$len" -gt 0 ] || exit 0
  body=$(head -c "$len")
  id=$(printf '%s' "$body" | grep -o '"id":[0-9]*' | head -1 | grep -o '[0-9]*')

  if printf '%s' "$body" | grep -q '"method":"initialize"'; then
    emit "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"passiveChecks\":[{\"id\":\"ext.header-leak\",\"name\":\"Debug header leak\"}]}}"
  elif printf '%s' "$body" | grep -q '"method":"passiveCheck"'; then
    if printf '%s' "$body" | grep -q 'X-Debug-Token'; then
      emit "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"findings\":[{\"typeID\":\"ext.header-leak\",\"name\":\"Debug header leak\",\"severity\":\"low\",\"detail\":\"The response exposes an X-Debug-Token header, which can reveal internal debug endpoints.\",\"marker\":\"X-Debug-Token\"}]}}"
    else
      emit "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"findings\":[]}}"
    fi
  fi
done
