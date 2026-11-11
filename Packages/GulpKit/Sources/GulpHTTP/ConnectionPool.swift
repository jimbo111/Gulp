// GulpHTTP — keep-alive connection pool (HTTP-003): keyed by everything that changes what a
// connection is, capped per key, idle connections expire, and a pooled connection is validated
// before reuse.

import GulpCore
import GulpTLS
import NIOCore

/// Everything that makes two connections interchangeable (HTTP-003).
struct PoolKey: Hashable, Sendable {
    let scheme: Scheme
    let host: String
    let port: Int
    let sni: String?
    let ip: String?
    let tls: UpstreamTLSSettings?
    /// The proxy actually used after rules are applied (nil = direct).
    let route: UpstreamProxy?

    init(target: HTTPTarget, options: SendOptions, route: UpstreamProxy?) {
        scheme = target.scheme
        host = target.host.lowercased()
        port = target.port
        sni = target.sniOverride
        ip = target.ipOverride
        tls = target.scheme == .https ? options.tls : nil
        self.route = route
    }
}

/// Pooled connections plus a per-key cap on connections in use.
actor ConnectionPool {
    struct Idle: Sendable {
        let channel: any Channel
        let id: UInt64
        let since: NIODeadline
        /// The server's own keep-alive deadline (`Keep-Alive: timeout=N`), if it announced one.
        var expires: NIODeadline?
        /// The TLS session this connection carries (reported again for every reuse).
        var tls: TLSInfo?
    }

    private var idle: [PoolKey: [Idle]] = [:]
    private var inUse: [PoolKey: Int] = [:]
    private var waiters: [PoolKey: [CheckedContinuation<Void, Never>]] = [:]
    private var nextID: UInt64 = 1
    private let maxPerKey: Int
    private let idleTimeout: TimeAmount

    init(maxPerKey: Int, idleTimeout: TimeAmount) {
        self.maxPerKey = max(1, maxPerKey)
        self.idleTimeout = idleTimeout
    }

    /// A fresh id for a new connection (`Exchange.connectionID`).
    func newConnectionID() -> UInt64 {
        defer { nextID += 1 }
        return nextID
    }

    /// Wait until fewer than `maxPerKey` (or the send's own `limit`, HTTP-003 "configurable per
    /// tool") connections for `key` are in use, then take a slot.
    func acquireSlot(_ key: PoolKey, limit: Int? = nil) async {
        if inUse[key, default: 0] < max(1, limit ?? maxPerKey) {
            inUse[key, default: 0] += 1
            return
        }
        // The releasing caller hands its slot straight to the first waiter.
        await withCheckedContinuation { waiters[key, default: []].append($0) }
    }

    /// Give a slot back, waking the next waiter if any.
    func releaseSlot(_ key: PoolKey) {
        if var queue = waiters[key], !queue.isEmpty {
            let next = queue.removeFirst()
            waiters[key] = queue
            next.resume()
        } else {
            inUse[key] = max(0, inUse[key, default: 1] - 1)
        }
    }

    /// The most recently used idle connection that is still open and not expired.
    func takeIdle(_ key: PoolKey) -> Idle? {
        let now = NIODeadline.now()
        while let candidate = idle[key]?.popLast() {
            let serverExpired = candidate.expires.map { now >= $0 } ?? false
            if candidate.channel.isActive && now - candidate.since < idleTimeout && !serverExpired {
                return candidate
            }
            candidate.channel.close(promise: nil)
        }
        return nil
    }

    /// Park a reusable connection. `serverTimeout` is the server's announced keep-alive timeout.
    func putIdle(
        _ key: PoolKey, channel: any Channel, id: UInt64, serverTimeout: TimeAmount? = nil,
        tls: TLSInfo? = nil
    ) {
        var list = idle[key, default: []]
        guard list.count < maxPerKey, channel.isActive else {
            channel.close(promise: nil)
            return
        }
        let now = NIODeadline.now()
        let expires = serverTimeout.map { now + $0 }
        list.append(Idle(channel: channel, id: id, since: now, expires: expires, tls: tls))
        idle[key] = list
    }

    /// Close every idle connection.
    func closeAll() {
        for list in idle.values {
            for connection in list { connection.channel.close(promise: nil) }
        }
        idle = [:]
    }
}
