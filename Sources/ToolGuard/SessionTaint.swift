/// A point-in-time view of a session's taint.
public struct TaintState: Sendable, Equatable {
    public var isTainted: Bool
    /// Sources that tainted the session, in the order they first appeared.
    public var sources: [String]

    public static let clean = TaintState(isTainted: false, sources: [])
}

/// Tracks whether untrusted content has entered a model session.
///
/// Taint is sticky: once set it persists across turns and only `reset()` clears it. `reset()` must be paired
/// with a genuinely fresh `LanguageModelSession`, because the old transcript still contains the untrusted text.
public actor SessionTaint {
    public private(set) var state = TaintState.clean

    public init() {}

    public var isTainted: Bool { state.isTainted }
    public var sources: [String] { state.sources }

    /// Marks the session tainted by `source`. Returns `true` if this source had not been recorded before.
    @discardableResult
    public func taint(source: String) -> Bool {
        state.isTainted = true
        guard !state.sources.contains(source) else { return false }
        state.sources.append(source)
        return true
    }

    /// Taints the session if `label` is untrusted. Returns `true` if a new source was recorded.
    @discardableResult
    public func absorb(_ label: Label) -> Bool {
        label.trust == .untrusted ? taint(source: label.source) : false
    }

    public func reset() {
        state = .clean
    }
}
