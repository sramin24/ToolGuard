import Foundation
import Synchronization

public struct AuditEvent: Sendable, Hashable, Identifiable {
    public enum Kind: Sendable, Hashable {
        case sessionTainted(source: String)
        case sessionReset
        /// The model asked for the call. Recorded before any decision, so blocked calls are still counted.
        case callAttempted(tool: String, arguments: String)
        case decision(tool: String, Decision)
        case confirmation(tool: String, approved: Bool)
        /// The base tool was invoked and returned.
        case callExecuted(tool: String)
        /// The base tool was invoked and threw. Its side effect may have partly happened.
        case callFailed(tool: String, error: String)
        /// The guard returned a refusal to the model instead of running the base tool.
        case callRefused(tool: String)
    }

    /// Position in the log, starting at 0.
    public let id: Int
    public let date: Date
    /// Groups the events of one tool call. `nil` for session-level events.
    public let callID: Int?
    public let kind: Kind
}

/// An append-only, thread-safe record of guard activity, readable as a snapshot or as a stream.
///
/// Recording is synchronous so the order of events matches the order things happened inside a call.
public final class AuditLog: Sendable {
    private struct State {
        var events: [AuditEvent] = []
        var nextCallID = 0
        var subscribers: [UUID: AsyncStream<AuditEvent>.Continuation] = [:]
    }

    private let state = Mutex(State())

    public init() {}

    public var events: [AuditEvent] { state.withLock { $0.events } }

    /// Reserves an ID for grouping the events of one tool call.
    public func nextCallID() -> Int {
        state.withLock { s in
            defer { s.nextCallID += 1 }
            return s.nextCallID
        }
    }

    @discardableResult
    public func record(_ kind: AuditEvent.Kind, callID: Int? = nil) -> AuditEvent {
        let (event, subscribers) = state.withLock { s in
            let event = AuditEvent(id: s.events.count, date: Date(), callID: callID, kind: kind)
            s.events.append(event)
            return (event, Array(s.subscribers.values))
        }
        for subscriber in subscribers { subscriber.yield(event) }
        return event
    }

    /// New events as they are recorded. Past events are available from `events`.
    public func updates() -> AsyncStream<AuditEvent> {
        let (stream, continuation) = AsyncStream<AuditEvent>.makeStream()
        let key = UUID()
        state.withLock { $0.subscribers[key] = continuation }
        continuation.onTermination = { [weak self] _ in
            _ = self?.state.withLock { $0.subscribers.removeValue(forKey: key) }
        }
        return stream
    }
}
