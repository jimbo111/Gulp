// GulpCore — the typed event bus (doc 01 §5.3).
//
// Producers never block: each subscriber has a bounded buffer. When it overflows, the events that
// did not fit are dropped and the subscriber later receives one `Delivery(event: nil, lagged: n)`
// marker, telling it to re-query the store for the window it missed.

import Foundation

// MARK: - Identifiers

/// Row id of a background task.
public typealias TaskID = Int64
/// Row id of an issue.
public typealias IssueID = Int64
/// Row id of an item in the intercept queue.
public typealias InterceptItemID = Int64
/// Row id of a WebSocket message.
public typealias WSMessageID = Int64
/// Row id of an OAST interaction.
public typealias OASTInteractionID = Int64
/// Identifies one `EventBus` subscription.
public typealias SubscriptionID = UInt64
/// A subscription id paired with its delivery stream.
public typealias Subscription = (id: SubscriptionID, stream: AsyncStream<Delivery>)

// MARK: - Event payloads

/// Progress of a background task (Gulp's own type, not Foundation's `Progress`).
public struct TaskProgress: Sendable, Hashable, Codable {
    /// Units completed.
    public var completed: Int
    /// Total units, if known.
    public var total: Int?
    /// Estimated seconds remaining, if known.
    public var etaSeconds: Double?

    /// Fraction done in `0...1`, if the total is known.
    public var fractionCompleted: Double? {
        guard let total, total > 0 else { return nil }
        return min(1, Double(completed) / Double(total))
    }

    /// Create a progress value.
    public init(completed: Int, total: Int? = nil, etaSeconds: Double? = nil) {
        self.completed = completed
        self.total = total
        self.etaSeconds = etaSeconds
    }
}

/// Identifies a settings group and, optionally, one key in it (doc 04 §6 `SettingsGroup.key`).
public struct SettingsKey: Sendable, Hashable, Codable {
    /// The settings group, e.g. `proxy`.
    public let group: String
    /// A key within the group; nil means the whole group changed.
    public let key: String?

    /// Create a settings key.
    public init(group: String, key: String? = nil) {
        self.group = group
        self.key = key
    }
}

/// A record shown in the Event Log panel (doc 01 §8): warnings and errors users should see.
public struct LogEntry: Sendable, Hashable, Codable {
    /// Severity.
    public enum Level: String, Sendable, Hashable, Codable { case info, warning, error }
    /// Severity.
    public var level: Level
    /// User-facing message (never contains secrets).
    public var message: String
    /// Producing module, e.g. `gulp.http`.
    public var module: String
    /// When it happened.
    public var timestamp: Date

    /// Create a log entry.
    public init(level: Level, message: String, module: String, timestamp: Date = Date()) {
        self.level = level
        self.message = message
        self.module = module
        self.timestamp = timestamp
    }
}

// MARK: - Events

/// Everything that happened, as a pure description (backpressure lives on `Delivery`, not here).
public enum GulpEvent: Sendable, Hashable {
    case exchangeRecorded(ExchangeID, source: ToolSource)
    case exchangeUpdated(ExchangeID)
    case interceptQueued(InterceptItemID)
    case wsMessage(WSMessageID)
    /// A WebSocket connection opened or closed (its row id).
    case wsConnectionChanged(Int64)
    case issueFound(IssueID)
    case taskProgress(TaskID, TaskProgress)
    case oastInteraction(OASTInteractionID)
    case scopeChanged
    case settingsChanged(SettingsKey)
    case log(LogEntry)
}

/// What a subscriber's stream yields: an event, or an overflow marker.
public struct Delivery: Sendable, Hashable {
    /// The event, or nil when `lagged > 0`.
    public var event: GulpEvent?
    /// 0 normally; N = events this subscriber missed because its buffer overflowed.
    public var lagged: Int

    /// Create a delivery.
    public init(event: GulpEvent?, lagged: Int = 0) {
        self.event = event
        self.lagged = lagged
    }
}

// MARK: - Bus

/// A typed broadcast built on `AsyncStream`. `publish` never blocks.
public actor EventBus {
    private struct Subscriber {
        let continuation: AsyncStream<Delivery>.Continuation
        var lagged: Int
    }

    private var subscribers: [SubscriptionID: Subscriber] = [:]
    private var nextID: SubscriptionID = 1

    /// Create an empty bus.
    public init() {}

    /// The number of live subscriptions.
    public var subscriberCount: Int { subscribers.count }

    /// Fan `event` out to every subscriber's bounded buffer. A full buffer drops the event for that
    /// subscriber and counts it; the count is delivered as a `lagged` marker once there is room.
    public func publish(_ event: GulpEvent) {
        for id in Array(subscribers.keys) {
            guard var sub = subscribers[id] else { continue }
            if sub.lagged > 0 {
                switch sub.continuation.yield(Delivery(event: nil, lagged: sub.lagged)) {
                case .enqueued:
                    sub.lagged = 0
                case .dropped:
                    // Still full: this event is missed as well.
                    sub.lagged += 1
                    subscribers[id] = sub
                    continue
                case .terminated:
                    subscribers[id] = nil
                    continue
                @unknown default:
                    break
                }
            }
            switch sub.continuation.yield(Delivery(event: event)) {
            case .enqueued:
                break
            case .dropped:
                sub.lagged += 1
            case .terminated:
                subscribers[id] = nil
                continue
            @unknown default:
                break
            }
            subscribers[id] = sub
        }
    }

    /// Subscribe with a buffer of `bufferSize` deliveries. The subscription ends automatically when
    /// the stream is dropped or its consuming task is cancelled.
    public func subscribe(bufferSize: Int = 256) -> AsyncStream<Delivery> {
        subscribeWithID(bufferSize: bufferSize).stream
    }

    /// Like `subscribe(bufferSize:)`, also returning the id for an explicit `unsubscribe(_:)`.
    public func subscribeWithID(bufferSize: Int = 256) -> Subscription {
        let id = nextID
        nextID += 1
        // `.bufferingOldest`: when full, the NEW delivery is rejected (`.dropped`), so buffered
        // events keep their order and the lagged marker lands right after them.
        let (stream, continuation) = AsyncStream.makeStream(
            of: Delivery.self, bufferingPolicy: .bufferingOldest(max(1, bufferSize)))
        continuation.onTermination = { [weak self] _ in
            Task { await self?.unsubscribe(id) }
        }
        subscribers[id] = Subscriber(continuation: continuation, lagged: 0)
        return (id, stream)
    }

    /// End a subscription and finish its stream.
    public func unsubscribe(_ id: SubscriptionID) {
        if let sub = subscribers.removeValue(forKey: id) {
            sub.continuation.finish()
        }
    }
}
