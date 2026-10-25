public enum Sensitivity: Sendable, Hashable {
    case low
    case high
}

/// What a tool can do to the outside world.
public enum ToolEffect: Sendable, Hashable {
    /// No external effect. A tool that reaches the network is *not* read-only: a request URL can carry data out.
    case readOnly
    /// Sends, deletes, shares, or writes something.
    case sideEffect(Sensitivity)
}

public enum Decision: Sendable, Hashable {
    case allow
    case requireConfirmation(reason: String)
    case deny(reason: String)

    private var strictness: Int {
        switch self {
        case .allow: 0
        case .requireConfirmation: 1
        case .deny: 2
        }
    }

    /// The stricter of the two decisions. Used so extra checks can escalate but never relax a decision.
    public func escalated(to other: Decision) -> Decision {
        other.strictness > strictness ? other : self
    }
}

/// Everything a user needs to judge a flagged tool call.
public struct ToolCallRequest: Sendable, Hashable {
    public var toolName: String
    /// The complete arguments. Never truncated; use `displayArguments(maxLength:)` to shorten for display.
    public var arguments: String
    public var reason: String
    public var taintSources: [String]

    public init(toolName: String, arguments: String, reason: String, taintSources: [String]) {
        self.toolName = toolName
        self.arguments = arguments
        self.reason = reason
        self.taintSources = taintSources
    }

    /// Arguments shortened to `maxLength` characters. Shortened text ends with an explicit marker,
    /// so a confirmation UI cannot silently hide attacker data past the cut.
    public func displayArguments(maxLength: Int) -> (text: String, isTruncated: Bool) {
        guard arguments.count > maxLength else { return (arguments, false) }
        let shown = arguments.prefix(max(0, maxLength))
        return ("\(shown)… [TRUNCATED: showing \(shown.count) of \(arguments.count) characters]", true)
    }
}

/// Asks the user to approve a flagged call. Returning `false` means the base tool never runs.
public typealias ConfirmationHandler = @Sendable (ToolCallRequest) async -> Bool

/// Maps a tool's effect and the session's taint to a decision.
public struct Policy: Sendable, Hashable {
    public enum Rule: Sendable, Hashable {
        case allow
        case confirm
        case deny
    }

    public var cleanSideEffect: Rule
    public var taintedReadOnly: Rule
    public var taintedLowSensitivity: Rule
    public var taintedHighSensitivity: Rule

    public init(
        cleanSideEffect: Rule = .allow,
        taintedReadOnly: Rule = .allow,
        taintedLowSensitivity: Rule = .confirm,
        taintedHighSensitivity: Rule = .deny
    ) {
        self.cleanSideEffect = cleanSideEffect
        self.taintedReadOnly = taintedReadOnly
        self.taintedLowSensitivity = taintedLowSensitivity
        self.taintedHighSensitivity = taintedHighSensitivity
    }

    /// Clean: allow. Tainted: read-only allowed, low-sensitivity side effects confirmed, high denied.
    public static let `default` = Policy()

    /// Never blocks. Used for unguarded configurations so the audit log still records attempts.
    public static let allowAll = Policy(
        cleanSideEffect: .allow, taintedReadOnly: .allow, taintedLowSensitivity: .allow, taintedHighSensitivity: .allow)

    public func decide(tool: String, effect: ToolEffect, taint: TaintState) -> Decision {
        let rule: Rule
        switch (effect, taint.isTainted) {
        case (.readOnly, false): return .allow
        case (.sideEffect, false): rule = cleanSideEffect
        case (.readOnly, true): rule = taintedReadOnly
        case (.sideEffect(.low), true): rule = taintedLowSensitivity
        case (.sideEffect(.high), true): rule = taintedHighSensitivity
        }
        let reason = taint.isTainted
            ? "The session contains untrusted content from \(taint.sources.joined(separator: ", ")), and \(tool) has side effects."
            : "\(tool) has side effects."
        switch rule {
        case .allow: return .allow
        case .confirm: return .requireConfirmation(reason: reason)
        case .deny: return .deny(reason: reason)
        }
    }
}
