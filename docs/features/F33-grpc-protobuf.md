# F33 — gRPC and protobuf (gRPC, gRPC-Web, Connect; schema-less decode)

> Milestones: M10b (decode, schemas, Repeater, Fuzzer), M11c (Scanner insertion points) · Modules:
> `GulpCodec` (protobuf wire format, gRPC message framing, `.proto`/descriptor parsing),
> `GulpFeatures/GRPC`, `GulpUI` (Protobuf editor tab) · Depends on: F01, F03 (HTTP/2, trailers
> HTTP-027), F05, F06, F07, F08, F12

## 1. Purpose

Many modern backends and mobile apps talk **gRPC** (protobuf over HTTP/2), and browsers reach the
same services through **gRPC-Web** or **Connect**. To a proxy these bodies are opaque binary, so a
tester sees nothing useful and cannot edit a call. F33 makes them first-class: it splits bodies into
messages, decodes protobuf **without a schema** (field numbers and wire types), names the fields when
a schema is available (`.proto` files, a compiled descriptor set, or the server's own reflection
service), and lets the tester edit a message, re-encode it and send it from Repeater, or fuzz inside
its fields. It was added by the 2026-11-08 feature review (A2) and promotes the F23 ADV-053 helper
(best-effort gRPC-Web decode, P2) to a full tool.

> **Concept: the gRPC wire format.** A gRPC request or response body is a sequence of
> **length-prefixed messages**: 1 flag byte (bit 0 = compressed), a 4-byte big-endian length, then the
> protobuf-encoded message. The call's outcome is not the HTTP status but the **trailers**
> `grpc-status` and `grpc-message`, sent as an HTTP/2 HEADERS frame after the data (HTTP-027).
> gRPC-Web carries the trailers in the body instead, as a final message whose flag byte has bit 7 set,
> and its `-text` variant base64-encodes the whole stream. Protobuf itself is a list of
> `(field number, wire type, value)` triples, so it can be decoded into a tree without the schema; the
> schema only adds names and exact types.

## 2. Requirements

| ID | Pri | Requirement |
|---|---|---|
| GRP-001 | P1 | **Recognize and frame RPC traffic**: detect gRPC (`application/grpc`, `+proto`, `+json`), gRPC-Web (`application/grpc-web`, `+proto`, and the base64 `application/grpc-web-text`) and Connect (`application/connect+proto`/`+json` streaming; unary `application/proto`/`application/json` with `Connect-Protocol-Version`) exchanges; split request and response bodies into their messages; show the trailers (HTTP/2 trailers, the gRPC-Web trailer message, or Connect's end-of-stream message) with `grpc-status`/`grpc-message` decoded. History rows show the RPC path (`/package.Service/Method`) and the gRPC status. |
| GRP-002 | P1 | **Schema-less protobuf decode**: decode the wire format into a field tree — varints (shown as int, sint (zigzag) and bool candidates), fixed32/fixed64 (int and float), length-delimited values (tried as a nested message, then UTF-8 text, then bytes, with the chosen reading switchable per field), and packed repeated fields. Compressed messages (`grpc-encoding: gzip`/`deflate`) are decompressed for display. Decoding never alters the stored bytes; anything that fails to decode is shown as hex. |
| GRP-003 | P1 | **Schemas**: import `.proto` files (proto2 and proto3, with imports resolved from a chosen folder), a compiled `FileDescriptorSet` (`protoc --descriptor_set_out`), or fetch them from the server's **reflection** service (`grpc.reflection.v1` and `v1alpha` `ServerReflectionInfo`; a scope-gated, user-initiated call). With a schema, messages show field names, types and enum names, and can be viewed as JSON. Schemas are stored per project and matched to calls by service/method path. |
| GRP-004 | P1 | **Edit and re-send**: in Repeater, edit a decoded message (as a field tree, or as JSON when a schema is known) and re-encode it to the wire format with correct length prefixes and the compression flag; send unary calls over HTTP/2 (gRPC, with `te: trailers`) or HTTP/1.1 (gRPC-Web and Connect unary), and show the response messages and trailers. The raw bytes stay editable too, and re-encoding happens only when the structured view is edited (raw bytes are the truth). |
| GRP-005 | P1 | **Insertion points inside messages**: string, number and nested-message fields can be Fuzzer positions and active-Scanner insertion points (SCN-020); each payload is re-encoded with correct field and message lengths. *(Fuzzer positions ship in M10b; the Scanner insertion points land with the full check catalog — later: M11c.)* |
| GRP-006 | P2 | **Streaming RPCs** (server, client and bidirectional streaming): show an ordered message list per call with direction and timing; Repeater can replay a server-streaming call and show messages as they arrive (uses the streaming support of PRX-050/REP-016). |
| GRP-007 | P2 | Decode rich error details (`grpc-status-details-bin` → `google.rpc.Status` with the well-known detail types), and a "Copy as grpcurl" entry in UI-040. |

## 3. UI

- The `MessageEditor` (UI-010) gains a **Protobuf** tab for RPC bodies: a message list (when a body
  carries more than one message) and, for the selected message, a field tree (number, name when
  known, wire type, value) with a per-field "read as" switch and an optional JSON view when a schema
  is known. The Inspector (UI-020) shows the RPC path, `grpc-encoding`, deadline (`grpc-timeout`) and
  the decoded trailers.
- History, Logger and Repeater show "gRPC", "gRPC-Web" or "Connect" in the protocol column and the
  `grpc-status` next to the HTTP status.
- **Project → gRPC Schemas…**: a sheet listing imported schemas (source, services, methods) with
  Import `.proto`/descriptor set and **Fetch via reflection** actions.

## 4. Implementation notes

- The protobuf wire codec (varint, zigzag, fixed32/64, length-delimited, packed) and the gRPC
  message framing (gRPC, gRPC-Web binary/text, Connect envelopes) are pure Swift in **`GulpCodec`**,
  so they build and test on Linux. Re-encoding preserves field order and **unknown fields** exactly
  as decoded; only the edited field's bytes (and the enclosing lengths) change.
- Descriptors: `descriptor.proto` is itself protobuf, so a `FileDescriptorSet` is decoded with the same
  codec plus hand-written models of the few descriptor messages needed. The `.proto` parser is a small
  hand-written parser for the subset that matters (package, imports, messages, nested types, enums,
  `oneof`, `map`, `repeated`, services); anything it can't parse is reported with the line, and the
  user can import a descriptor set from `protoc` instead. If `apple/swift-protobuf` is adopted for
  the descriptor types, record it in doc 07 and doc 01 §1 first (it is pure Swift and Linux-building).
- Reflection is a bidirectional-streaming gRPC call: send one `list_services` (then
  `file_containing_symbol`) request on an HTTP/2 stream through the engine, half-close, and read the
  responses. It is user-initiated, ScopeGuard-gated and recorded like any Repeater send.
- gRPC over HTTP/2 depends on the M3b engine (HTTP-020…024) and trailers (HTTP-027); the proxy must
  forward trailers unchanged (PRX-009). gRPC-Web text mode is base64 per HTTP chunk: decode
  incrementally, don't assume one base64 blob.
- Imported schemas are stored in a `GRPCSchemaSettings` group in the project `settings` table, each
  as an inline serialized `FileDescriptorSet` (doc 04 §6 — the same pattern as other project-level
  rule sets; no new table). *(2026-11-10: inline instead of blobs — descriptor sets are small; see
  doc 07.)*
- Decompression uses the F03 HTTP-007 helpers; `grpc-encoding` values other than gzip/deflate are
  shown as "unsupported encoding" with the raw bytes.

## 5. Edge cases

- Ambiguous length-delimited fields (text vs nested message vs bytes): pick by heuristic, show the
  confidence, let the user override, and remember the override per field path and method.
- Very large messages or deep nesting: cap the decoded tree (depth and size) and keep the raw view.
- A response without `grpc-status` (a broken intermediary or a missing trailer): show a clear "no
  gRPC status" warning rather than reporting success.
- gRPC over cleartext HTTP/2 (h2c prior knowledge) uses the engine's h2c support (HTTP-020).
- Reflection disabled on the server: explain it and offer `.proto`/descriptor import.
- A schema that doesn't match the traffic (field number/type mismatches): show the mismatching
  fields as unknown rather than mis-decoding them; they are preserved on re-encode.

## 6. Acceptance tests

1. A gRPC unary call through the proxy to VulnLab's `vulnlab.Echo/Say` (HTTP/2 on :8443) shows a
   schema-less field tree for the request and response, and `grpc-status: 0` from the HTTP/2
   trailers.
2. Fetching the schema via reflection (and, separately, importing the fixture's `.proto`) names the
   fields; editing `message` in Repeater and resending returns the edited echo, the raw view shows a
   correct length prefix, and the trailers are displayed.
3. A gRPC-Web text-mode call to VulnLab's gRPC-Web endpoint over HTTP/1.1 decodes the same way
   (base64 stream and the in-body trailer message), and a Connect unary call decodes as well.
4. A Fuzzer position inside a protobuf string field sends correctly re-encoded payloads (VulnLab
   parses every one). *(M11c)* The active Scanner finds the planted SQL injection behind the
   `vulnlab.Orders/Get` `id` field, and the safe twin stays clean.
