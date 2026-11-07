# F02 — TLS and the certificate authority

> Milestone: M3 · Modules: `GulpTLS`, `GulpProxy`, `GulpFeatures/Settings` · Depends on: F24 (install helpers)

## 1. Purpose

To read HTTPS traffic, Gulp acts as a man-in-the-middle. It presents the client a certificate for
the requested host, signed by a **Gulp CA** that the user has chosen to trust. This spec covers the
CA's lifecycle, leaf-certificate minting, and upstream TLS behavior.

> **Concept: how TLS MITM works.** The browser asks the proxy to `CONNECT example.com:443`. Instead
> of blindly tunneling, Gulp completes a TLS handshake with the browser itself, presenting a
> certificate for `example.com` signed by the Gulp CA. If the browser trusts that CA, the handshake
> succeeds and Gulp sees plaintext. Gulp then opens its own, separate TLS connection to the real
> `example.com`. There are two TLS sessions, and Gulp sits in the middle. Certificate pinning in
> apps defeats this on purpose, which is why the pass-through list (PRX-007) exists.

## 2. Requirements

| ID | Pri | Requirement |
|---|---|---|
| TLS-001 | P0 | On first run, generate a CA: key **RSA-2048** (best compatibility; configurable to ECDSA P-256), subject `CN=Gulp CA <short-random>, O=Gulp`, validity 10 years, extensions `basicConstraints=CA:TRUE (critical), pathLen:0`, `keyUsage=keyCertSign, cRLSign (critical)`, `subjectKeyIdentifier`. |
| TLS-002 | P0 | Store the CA private key in the macOS Keychain (generic password item holding the PKCS#8 DER, or a `SecKey` where possible; access: this device only, app-only ACL). On Linux/CLI, store it in `~/.config/gulp/ca/ca.key` with mode 0600. |
| TLS-003 | P0 | Leaf minting: given a hostname (or IP), create a certificate with `subjectAltName` = DNS (or IP) entry, CN = host, `extendedKeyUsage=serverAuth`, `keyUsage=digitalSignature(+keyEncipherment for RSA)`, `authorityKeyIdentifier`, a random 16-byte serial, validity `notBefore = now − 1 day`, `notAfter = now + 396 days` (span ≈ 397 days — Apple's maximum trusted-TLS lifetime is 398 days *inclusive*, so leave a day of margin rather than sitting exactly on the boundary where rounding/clock skew can trip rejection). |
| TLS-004 | P0 | Leaf keys: a shared ECDSA P-256 key pair per CA session (generated at startup) is used for all leaves. Generating a key per host is optional (setting) because it is slower. |
| TLS-005 | P0 | Caches: (a) a **leaf cert+key** LRU (2,000 entries) keyed by (hostname, leaf key id); minting happens off the event loop (`NIOThreadPool`) and is de-duplicated (concurrent requests for the same host await one mint). (b) a separate **`NIOSSLContext`** cache keyed by **(hostname, negotiated client-facing ALPN)** — the context's `applicationProtocols` is fixed at construction and ALPN mirroring (PRX-008) can pick different protocols for the same host on different connections, so a context cached by host alone would replay the wrong ALPN. Each context reuses the cached leaf; constructing contexts is the expensive part. The dedup test (acceptance #2) counts cert mints, not contexts. |
| TLS-006 | P0 | Export the CA certificate as PEM and DER (`Settings → TLS → Export CA certificate…`), and serve it from `http://gulp/cert.pem` (PRX-046). |
| TLS-007 | P0 | Regenerate the CA (with a confirmation: "Clients that trust the old CA will stop working") and import a CA (PKCS#12 or PEM cert + key). |
| TLS-008 | P0 | Upstream TLS: by default, do **not** validate the server certificate (testing tools must work against self-signed staging servers). Still record the server chain fingerprint and the *would-be* validation result in `TLSInfo`, and show a warning badge for invalid certificates. Implement with a `NIOSSLCustomVerificationCallback` (not `certificateVerification = .none`, which skips verification *and* hands you no peer chain): capture the presented chain, compute the validation result, then return `.certificateVerified` when validation is off or honor the result when on. Setting "Validate upstream certificates" is off by default. |
| TLS-009 | P0 | Upstream TLS protocol settings: min/max version (TLS 1.0–1.3; default 1.2–1.3), cipher list override, SNI override per target (F03), ALPN preference. |
| TLS-010 | P0 | Wildcard handling: for SNI `a.b.example.com`, mint an exact-host certificate (never wildcard by default; wildcard leaf mode is an option for performance). |
| TLS-011 | P1 | Client TLS certificates for upstream (mTLS): list of (host pattern → PKCS#12 file + password in the Keychain). Used by every tool. |
| TLS-012 | P1 | IP-address targets: mint a certificate with an IP SAN. |
| TLS-013 | P1 | Certificate details viewer: from any HTTPS history item, show the upstream server's chain (subject, issuer, SANs, validity, key, fingerprints) and the leaf Gulp presented. |
| TLS-014 | P1 | Per-host "TLS profile" overrides: force TLS 1.2, disable SNI, a specific cipher. |
| TLS-015 | P2 | "Mimic browser TLS fingerprint" mode for upstream connections (a JA3/JA4-like ClientHello shape via BoringSSL cipher/extension/curve ordering) to avoid bot-detection blocks. Best effort; document the limits. |
| TLS-016 | P2 | Optional on-disk leaf cache that survives restarts (faster first load). |

## 3. UI

Settings → **TLS** pane:
- CA section: fingerprint (SHA-256), validity, key type, and the buttons "Export…", "Install in
  macOS Keychain…" (F24 MAC-001), "Install in iOS Simulator…" (MAC-003), "Regenerate…", "Import…".
  A status badge shows "Trusted by this Mac ✓ / Not trusted ✗", checked via `SecTrustEvaluateWithError`
  on a freshly minted test leaf.
- Upstream section: validation toggle, protocol versions, ciphers, client certificates table, per-host profiles.

## 4. Implementation notes

- Build certificates with `swift-certificates`:
  `Certificate(version: .v3, serialNumber:, publicKey:, notValidBefore:, notValidAfter:, issuer:, subject:, signatureAlgorithm:, extensions: try Certificate.Extensions { BasicConstraints…; KeyUsage…; SubjectAlternativeNames([.dnsName(host)]); … }, issuerPrivateKey: .init(caKey))`.
  RSA keys come from `_CryptoExtras` (`_RSA.Signing.PrivateKey`).
- Convert to NIOSSL types: serialize DER → `NIOSSLCertificate(bytes:format: .der)` and
  `NIOSSLPrivateKey(bytes:format: .der)`. Build a `NIOSSLContext` keyed by (host, negotiated ALPN)
  (TLS-005), reusing the cached leaf; constructing contexts is the expensive part.
- SNI: `SNIHandler` lives in the **`NIOTLS`** module of the `swift-nio` package (not swift-nio-ssl
  and not swift-nio-extras). It peeks at the ClientHello and reports the server name
  (`SNIResult = .hostname(String) | .fallback`) — **it does not expose the client's ALPN list**. For
  ALPN mirroring (PRX-008) the proxy therefore needs its own ClientHello parser (the same
  pre-TLS sniff it already does for the SNI fallback, PRX-006) to read the
  `application_layer_protocol_negotiation` extension; NIOSSL's context-selection callback doesn't
  surface the client ALPN list either. After the sniff, insert `NIOSSLServerHandler(context:)` with
  the context chosen for (host, mirrored-ALPN). (`TLSConfiguration` has no `sslContextCallback`;
  dynamic selection is done by inserting the right server handler, so don't rely on a callback name.)
- ALPN mirroring sequence: proxy's ClientHello sniff → extract SNI **and** the offered ALPN list →
  open the upstream TLS connection offering the same ALPN list → read the protocol the server chose →
  build/reuse the client-facing context whose `applicationProtocols` = [that protocol] → finish the
  client handshake. Because the upstream handshake completes **before** the client handshake, bound
  it with the connect/TLS timeouts (F03 HTTP-005) and see F01 §5 for the failure path (you cannot
  send a 502 at this point — no client TLS session exists yet).
- Trust check: create a leaf for `gulp-trust-check.invalid`, build a `SecTrust` with
  `SecPolicyCreateSSL(true, host)` and evaluate. Trusted means the CA is in a trust store the system
  uses.

## 5. Edge cases

- Clients that don't send SNI (old Android, some IoT): use the CONNECT host, or the listener's
  "named host" setting in invisible mode.
- Hostnames with uppercase letters or trailing dots: normalize to lowercase without the trailing dot
  for the cache key; put the normalized name in the SAN.
- IDNs: the SAN must be the A-label (punycode) form.
- Clock skew on the client: `notBefore = now − 1 day` covers most cases.

## 6. Acceptance tests

1. A fresh CA has the correct extensions (parse it with `swift-certificates` and assert each one);
   `openssl x509 -text` (in a manual check) shows CA:TRUE.
2. 1,000 concurrent CONNECTs to 50 distinct hosts produce exactly 50 mints (dedup works).
3. With the CA installed in a temporary keychain or trust settings (test helper), a TLS client
   (`NIOSSL` with that root trusted) handshakes successfully against a proxy-minted leaf for
   `localhost`, `127.0.0.1` and `xn--bcher-kva.example`.
4. Upstream to VulnLab's self-signed :8443 succeeds with validation off and records
   `validation = failed(selfSigned)`; with validation on, the request fails with a clear error.
5. An ALPN h2-only client and an h2 upstream → h2 on both sides; an h2 client and an http/1.1-only
   upstream → the client is offered http/1.1.
