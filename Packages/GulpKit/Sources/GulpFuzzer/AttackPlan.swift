// GulpFuzzer — attack types (F07 FUZ-002) as a lazy request generator. Nothing is preallocated
// except the inner sets of a cluster bomb (each inner set is iterated once per outer payload, so its
// processed payloads are kept), and counts are computed up front (cluster bombs that overflow are
// reported, never allocated).

import Foundation

/// The attack types (FUZ-002).
public enum AttackType: String, Sendable, Hashable, Codable, CaseIterable {
    /// One position at a time with set 1; the others keep their base values.
    case sniper
    /// Set 1's payload in every position at once.
    case batteringRam
    /// Set i in position i, in lockstep (stops at the shortest set).
    case pitchfork
    /// The Cartesian product of every position's set.
    case clusterBomb
}

/// One request of an attack.
public struct AttackItem: Sendable, Hashable {
    /// 1-based sequence number.
    public var seq: Int
    /// The payload per position (nil = the base value was kept).
    public var payloads: [[UInt8]?]
}

/// An attack's requests (FUZ-002).
public struct AttackPlan: Sendable {
    /// The base request split at its positions.
    public let template: FuzzTemplate
    /// The attack type.
    public let type: AttackType
    /// Payload sets (sniper and battering ram use the first; pitchfork and cluster bomb one per
    /// position).
    public let sets: [PayloadSet]
    let pipelines: [PayloadPipeline]

    /// A plan. Throws when the sets don't fit the attack type or a processor is invalid.
    public init(template: FuzzTemplate, type: AttackType, sets: [PayloadSet]) throws {
        guard template.positionCount > 0 else {
            throw FuzzTemplateError(message: "mark at least one position with §…§")
        }
        guard !sets.isEmpty else { throw FuzzTemplateError(message: "add a payload set") }
        if type == .pitchfork || type == .clusterBomb, sets.count < template.positionCount {
            throw FuzzTemplateError(
                message:
                    "\(type.rawValue) needs one payload set per position (\(template.positionCount) positions, \(sets.count) sets)"
            )
        }
        self.template = template
        self.type = type
        self.sets = sets
        pipelines = try sets.map { try PayloadPipeline($0.processors) }
    }

    /// The set used for position `index`.
    public func setIndex(for position: Int) -> Int {
        type == .pitchfork || type == .clusterBomb ? position : 0
    }

    /// Requests in the attack before skip rules (saturating at Int.max).
    public var count: Int {
        let positions = template.positionCount
        func size(_ set: Int, _ position: Int) -> Int {
            sets[set].source.count(base: template.baseValues[position])
        }
        switch type {
        case .sniper:
            return (0..<positions).reduce(0) { total, position in
                let (sum, overflow) = total.addingReportingOverflow(size(0, position))
                return overflow ? .max : sum
            }
        case .batteringRam: return size(0, 0)
        case .pitchfork: return (0..<positions).map { size($0, $0) }.min() ?? 0
        case .clusterBomb:
            var product = 1
            for position in 0..<positions {
                let (next, overflow) = product.multipliedReportingOverflow(by: size(position, position))
                if overflow { return .max }
                product = next
            }
            return product
        }
    }

    /// The processed payload for `raw` from set `set`, or nil if a skip rule drops it.
    public func process(_ raw: [UInt8], set: Int) throws -> [UInt8]? {
        try pipelines[set].process(raw)
    }

    /// The items, lazily.
    public func items() -> AnySequence<AttackItem> {
        let positions = template.positionCount
        let template = self.template
        let pipelines = self.pipelines
        let sets = self.sets
        func processed(_ set: Int, _ position: Int) -> AnySequence<[UInt8]> {
            AnySequence(
                sets[set].source.payloads(base: template.baseValues[position]).lazy.compactMap {
                    try? pipelines[set].process($0)
                })
        }
        switch type {
        case .sniper:
            let all = (0..<positions).lazy.flatMap { position in
                processed(0, position).lazy.map { payload -> [[UInt8]?] in
                    var payloads = [[UInt8]?](repeating: nil, count: positions)
                    payloads[position] = payload
                    return payloads
                }
            }
            return Self.numbered(AnySequence(all))
        case .batteringRam:
            return Self.numbered(
                AnySequence(
                    processed(0, 0).lazy.map { payload in [[UInt8]?](repeating: payload, count: positions) }))
        case .pitchfork:
            return Self.numbered(
                AnySequence { () -> AnyIterator<[[UInt8]?]> in
                    var iterators = (0..<positions).map { processed($0, $0).makeIterator() }
                    return AnyIterator {
                        var row: [[UInt8]?] = []
                        for index in iterators.indices {
                            guard let next = iterators[index].next() else { return nil }
                            row.append(next)
                        }
                        return row
                    }
                })
        case .clusterBomb:
            // The outer (first) set streams; the inner sets are kept (each is replayed per outer payload).
            let inner = (1..<max(1, positions)).map { Array(processed($0, $0)) }
            return Self.numbered(
                AnySequence { () -> AnyIterator<[[UInt8]?]> in
                    var outer = processed(0, 0).makeIterator()
                    var current: [UInt8]? = outer.next()
                    var indices = [Int](repeating: 0, count: inner.count)
                    let empty = inner.contains { $0.isEmpty }
                    return AnyIterator {
                        guard !empty, let head = current else { return nil }
                        let row: [[UInt8]?] = [head] + inner.indices.map { inner[$0][indices[$0]] }
                        // Advance the odometer (last position fastest).
                        var position = indices.count - 1
                        while position >= 0 {
                            indices[position] += 1
                            if indices[position] < inner[position].count { break }
                            indices[position] = 0
                            position -= 1
                        }
                        if position < 0 { current = outer.next() }
                        return row
                    }
                })
        }
    }

    static func numbered(_ rows: AnySequence<[[UInt8]?]>) -> AnySequence<AttackItem> {
        AnySequence(rows.enumerated().lazy.map { AttackItem(seq: $0.offset + 1, payloads: $0.element) })
    }

    /// The request bytes for an item.
    public func request(for item: AttackItem) -> [UInt8] {
        template.render(item.payloads)
    }
}
