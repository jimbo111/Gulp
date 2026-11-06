# F12 — Decoder and Transform Tags

> Milestone: M7 · Modules: `GulpCodec`, `GulpFeatures/Decoder` · Depends on: GulpCore

## 1. Purpose

Testers constantly encode and decode data: URL encoding, Base64, hex, HTML entities, JWTs, hashes,
gzip, etc. The **Decoder** is a scratchpad for chaining these transforms. **Transform Tags** are the
same transforms written inline inside Repeater/Fuzzer requests so they're applied at send time.

## 2. Requirements

### 2.1 Decoder tool

| ID | Pri | Requirement |
|---|---|---|
| DEC-001 | P0 | A stacked editor: an input pane, then a column of transform steps, each producing the next value. Edit any level and the chain re-evaluates. Text and hex views at each level. |
| DEC-002 | P0 | Per step choose Decode-as or Encode-as or Hash or Convert. Operations (see §3). Add/remove/reorder steps. |
| DEC-003 | P0 | **Smart Decode**: heuristically detect and recursively decode (e.g. URL → Base64 → gzip → JSON) and show the detected chain, which the user can accept as explicit steps. |
| DEC-004 | P1 | Load input from a file or from a selection sent via "Send to Decoder"; copy any level out; drag the final value. |
| DEC-005 | P1 | Byte-accurate: operations work on raw bytes, not just strings; the hex view is first-class; show the length at each step. |
| DEC-006 | P1 | A compact **Inspector decoder** (UI-021): select text anywhere → popover shows likely decodings live (URL, Base64, hex, JWT, HTML, unicode-escape) and lets you replace the selection with an encoded form. |
| DEC-007 | P2 | Save named transform chains as reusable "recipes" and expose them as Transform Tags and Fuzzer processors. |

### 2.2 Transform Tags (inline)

| ID | Pri | Requirement |
|---|---|---|
| DEC-020 | P0 | Inline tags in request bytes using delimiters `«op(args){ inner }»` (configurable, doc 07). Tags nest: the inner content is transformed by the op. Example: `«base64{ «var(user)»:«var(pass)» }»`. |
| DEC-021 | P0 | Core ops available as tags: all §3 encoders/decoders/hashes, plus dynamic ops `var(name)`, `now(format)`, `random(charset,len)`, `uuid()`, `counter(name)`, `beacon()` (F10), `len(inner)`. |
| DEC-022 | P0 | Evaluation happens in the F03 send pipeline (a `TransformTagHook`) for Repeater/Fuzzer (and optionally Scanner probes); a toggle enables it per tool. A preview renders the final bytes before sending. |
| DEC-023 | P1 | Clear errors for unknown ops/args, shown in the editor at the tag's location; unbalanced delimiters are reported, not silently ignored. |
| DEC-024 | P1 | A Snippet op `js(name)` runs a JS transform (F18) for custom logic; sandboxed and timeout-bounded. |
| DEC-025 | P2 | A palette/autocomplete for tags in the editor; "wrap selection in tag ▸". |

## 3. Operations (implement in `GulpCodec`, all reversible pairs round-trip)

- **URL**: encode / encode-all / decode (+ `+`-as-space option).
- **HTML entities**: encode / decode (named + numeric).
- **Base64** and **Base64URL**: encode / decode (tolerant of missing padding and whitespace).
- **Base32**, **Base58** (optional), **Ascii85/Base85** (optional).
- **Hex**: encode / decode (tolerant of spaces/`0x`), and a hexdump view.
- **Decimal / octal / binary** per-byte conversions.
- **Unicode escapes** (`\uXXXX`, `\xNN`), **JS string escape**, **CSS escape**.
- **Gzip / zlib(deflate) / raw-deflate / brotli / zstd**: compress / decompress.
- **JWT decode**: split and decode header/payload, show claims, and (JWT Workbench, F23) verify/sign.
- **Hashes**: md5, sha1, sha256, sha384, sha512, sha3, crc32; **HMAC** variants with a key.
- **Char case**, **reverse**, **rot13**, **XOR with key** (hex/ascii key).
- **Escape/unescape for contexts**: SQL string, shell arg, regex, JSON string.

## 4. Implementation notes

- A `Transform` protocol: `func apply(_ input: Bytes, args) throws -> Bytes`; register in a
  `TransformRegistry` keyed by name; used by the Decoder steps, the Inspector popover, Transform
  Tags, and Fuzzer payload processors (one implementation, four UIs).
- Smart Decode: a scored detector per codec (e.g. "looks like Base64 and decodes to printable/known
  magic bytes") applied greedily with a depth cap; present the chain and let the user confirm.
- Transform Tag parser: a small recursive parser over bytes that preserves everything outside tags
  verbatim; evaluate inner-to-outer; expose captured `var`s from the per-project `VariableStore`
  (F06 REP-011).
- Everything is byte-oriented; string views decode as UTF-8 with lossy fallback for display only.

## 5. Edge cases

- Invalid Base64/hex: decode what's valid and flag the rest, or error per a per-op "strict" toggle.
- Compression bombs: cap decompressed size (same limit as F03) and warn.
- Literal delimiter characters in data: support escaping (`««`/`»»`) and let the user change the
  delimiter pair (doc 07).
- Multi-byte boundaries in XOR/case ops operate on bytes, not code points (documented).

## 6. Acceptance tests

1. A chain URL-decode → Base64-decode → gunzip → pretty-JSON produces the expected object; editing
   the JSON and reversing the chain reproduces a valid encoded input.
2. Smart Decode solves a fixture set (nested encodings) and reports the correct chain.
3. In Repeater, `Authorization: Basic «base64{ «var(user)»:«var(pass)» }»` sends the right header;
   the preview matches what's sent; disabling tag evaluation sends the literal text.
4. Every reversible op round-trips over random bytes (property tests).
