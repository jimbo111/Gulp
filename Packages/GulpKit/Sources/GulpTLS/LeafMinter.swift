// GulpTLS — leaf and server-context caches (F02 TLS-004, TLS-005). Minting is de-duplicated
// (concurrent requests for one host await a single mint) and runs off the caller (a detached task),
// so the proxy's event loops never sign certificates.

import NIOSSL

/// Mints and caches leaf certificates and the NIOSSL server contexts built from them.
public actor LeafMinter {
    /// The signing CA.
    public nonisolated let authority: CertificateAuthority
    /// The leaf key pair shared by all leaves of this session (TLS-004).
    public nonisolated let leafKey: SigningKey
    /// Leaf-cache capacity (TLS-005: 2,000).
    public nonisolated let capacity: Int

    private var leaves: LRUCache<CertificateSubject, MintedLeaf>
    private var contexts: LRUCache<ContextKey, NIOSSLContext>
    private var inFlight: [CertificateSubject: Task<MintedLeaf, any Error>] = [:]
    /// Number of certificates minted (acceptance #2 counts mints, not contexts).
    public private(set) var mintCount = 0

    struct ContextKey: Hashable {
        let subject: CertificateSubject
        let alpn: [String]
    }

    /// A minter for `authority`. Leaves share one P-256 key unless `leafKey` is given.
    public init(authority: CertificateAuthority, leafKey: SigningKey? = nil, capacity: Int = 2_000) throws {
        self.authority = authority
        self.leafKey = try leafKey ?? SigningKey.generate(.p256)
        self.capacity = max(1, capacity)
        leaves = LRUCache(capacity: max(1, capacity))
        contexts = LRUCache(capacity: max(1, capacity))
    }

    /// The leaf for `host` (DNS name or IP literal), minting it at most once.
    public func leaf(for host: String) async throws -> MintedLeaf {
        let subject = CertificateSubject(host: host)
        if let leaf = leaves.value(for: subject) { return leaf }
        if let pending = inFlight[subject] { return try await pending.value }
        let authority = self.authority
        let key = leafKey
        let task = Task.detached { try authority.mintLeaf(for: subject, key: key) }
        inFlight[subject] = task
        mintCount += 1
        defer { inFlight[subject] = nil }
        let leaf = try await task.value
        leaves.set(leaf, for: subject)
        return leaf
    }

    /// A server context presenting the leaf for `host` and offering exactly `alpn` (TLS-005: keyed by
    /// host and ALPN, because a context's protocols are fixed when it is built).
    public func serverContext(for host: String, alpn: [String]) async throws -> NIOSSLContext {
        let leaf = try await leaf(for: host)
        let key = ContextKey(subject: leaf.subject, alpn: alpn)
        if let context = contexts.value(for: key) { return context }
        let context = try Self.makeServerContext(leaf: leaf, alpn: alpn, issuer: authorityDER)
        contexts.set(context, for: key)
        return context
    }

    /// Number of cached leaves.
    public var cachedLeafCount: Int { leaves.count }

    /// The SPKI pins of the CA and of the shared leaf key, for a browser that should accept this
    /// minter's certificates without a trust-store change (BRW-002).
    public nonisolated var spkiPins: [String] { [authority.key.spkiPin, leafKey.spkiPin] }

    private var authorityDER: [UInt8]? { try? authority.certificateDER() }

    /// Build a TLS server context for `leaf`. With `issuer`, the CA certificate is sent after the
    /// leaf, so a client pinning the CA's key (Chromium's SPKI list, BRW-002) finds it in the chain.
    public static func makeServerContext(
        leaf: MintedLeaf, alpn: [String], issuer: [UInt8]? = nil
    ) throws -> NIOSSLContext {
        let certificate = try NIOSSLCertificate(bytes: leaf.der, format: .der)
        let key = try NIOSSLPrivateKey(bytes: Array(leaf.key.pem.utf8), format: .pem)
        var chain: [NIOSSLCertificateSource] = [.certificate(certificate)]
        if let issuer { chain.append(.certificate(try NIOSSLCertificate(bytes: issuer, format: .der))) }
        var configuration = TLSConfiguration.makeServerConfiguration(
            certificateChain: chain, privateKey: .privateKey(key))
        configuration.applicationProtocols = alpn
        configuration.minimumTLSVersion = .tlsv1  // accept old clients; the upstream side is separate
        return try NIOSSLContext(configuration: configuration)
    }
}

/// A small least-recently-used map. Eviction scans for the oldest entry, which is fine at the
/// thousands-of-entries scale the TLS caches use.
struct LRUCache<Key: Hashable, Value> {
    let capacity: Int
    private var entries: [Key: (value: Value, used: UInt64)] = [:]
    private var clock: UInt64 = 0

    init(capacity: Int) {
        self.capacity = capacity
    }

    var count: Int { entries.count }

    mutating func value(for key: Key) -> Value? {
        guard let entry = entries[key] else { return nil }
        clock += 1
        entries[key] = (entry.value, clock)
        return entry.value
    }

    mutating func set(_ value: Value, for key: Key) {
        clock += 1
        entries[key] = (value, clock)
        if entries.count > capacity, let oldest = entries.min(by: { $0.value.used < $1.value.used })?.key {
            entries[oldest] = nil
        }
    }
}
