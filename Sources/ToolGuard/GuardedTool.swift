import FoundationModels

/// The output of a guarded tool: the base tool's output, or a refusal the model can read.
///
/// A refusal is returned rather than thrown, so the model can tell the user what happened.
public enum GuardedOutput<Wrapped: PromptRepresentable>: PromptRepresentable {
    case ran(Wrapped)
    case refused(String)

    public static var deniedMessage: String {
        "This action was blocked by the security policy. Do not retry it; tell the user it was blocked."
    }

    public static var declinedMessage: String {
        "The user declined this action. Do not retry it; tell the user it was not done."
    }

    public var promptRepresentation: Prompt {
        switch self {
        case .ran(let output): return output.promptRepresentation
        case .refused(let message): return Prompt(message)
        }
    }
}

extension GuardedOutput: Sendable where Wrapped: Sendable {}

/// Wraps a tool so the policy decides, outside the model, whether each call may run.
public struct GuardedTool<Base: Tool>: Tool {
    public typealias Arguments = Base.Arguments
    public typealias Output = GuardedOutput<Base.Output>
    /// An extra per-tool check (e.g. "recipient must be a contact"). It can escalate the policy's decision, never relax it.
    public typealias ArgumentCheck = @Sendable (Base.Arguments, TaintState) async -> Decision

    public let base: Base
    public let effect: ToolEffect
    public let outputTrust: TrustLevel
    /// The taint source recorded when this tool returns untrusted output.
    public let outputSource: String
    public let taint: SessionTaint
    public let policy: Policy
    public let log: AuditLog
    private let confirm: ConfirmationHandler
    private let argumentCheck: ArgumentCheck?

    public var name: String { base.name }
    public var description: String { base.description }
    public var parameters: GenerationSchema { base.parameters }
    public var includesSchemaInInstructions: Bool { base.includesSchemaInInstructions }

    /// - Parameter confirm: Called for `.requireConfirmation`. Defaults to declining everything.
    public init(
        _ base: Base,
        effect: ToolEffect,
        outputTrust: TrustLevel,
        outputSource: String? = nil,
        taint: SessionTaint,
        policy: Policy = .default,
        log: AuditLog,
        confirm: @escaping ConfirmationHandler = { _ in false },
        argumentCheck: ArgumentCheck? = nil
    ) {
        self.base = base
        self.effect = effect
        self.outputTrust = outputTrust
        self.outputSource = outputSource ?? "tool:\(base.name)"
        self.taint = taint
        self.policy = policy
        self.log = log
        self.confirm = confirm
        self.argumentCheck = argumentCheck
    }

    public func call(arguments: Base.Arguments) async throws -> GuardedOutput<Base.Output> {
        let callID = log.nextCallID()
        let rendered = Self.render(arguments)
        log.record(.callAttempted(tool: name, arguments: rendered), callID: callID)

        let state = await taint.state
        var decision = policy.decide(tool: name, effect: effect, taint: state)
        if let argumentCheck {
            decision = decision.escalated(to: await argumentCheck(arguments, state))
        }
        log.record(.decision(tool: name, decision), callID: callID)

        switch decision {
        case .allow:
            break
        case .deny:
            log.record(.callRefused(tool: name), callID: callID)
            return .refused(Output.deniedMessage)
        case .requireConfirmation(let reason):
            let request = ToolCallRequest(toolName: name, arguments: rendered, reason: reason, taintSources: state.sources)
            // A cancelled task counts as a decline: the user is no longer there to approve.
            let approved = Task.isCancelled ? false : await confirm(request)
            log.record(.confirmation(tool: name, approved: approved), callID: callID)
            guard approved, !Task.isCancelled else {
                log.record(.callRefused(tool: name), callID: callID)
                return .refused(Output.declinedMessage)
            }
        }

        do {
            let output = try await base.call(arguments: arguments)
            log.record(.callExecuted(tool: name), callID: callID)
            await absorbOutputTaint(callID: callID)
            return .ran(output)
        } catch {
            log.record(.callFailed(tool: name, error: String(describing: error)), callID: callID)
            // The error text reaches the model too and may quote untrusted content.
            await absorbOutputTaint(callID: callID)
            throw error
        }
    }

    private func absorbOutputTaint(callID: Int) async {
        guard outputTrust == .untrusted else { return }
        if await taint.taint(source: outputSource) {
            log.record(.sessionTainted(source: outputSource), callID: callID)
        }
    }

    /// Full, untruncated rendering of the arguments for the audit log and confirmation UI.
    static func render(_ arguments: Base.Arguments) -> String {
        if let convertible = arguments as? any ConvertibleToGeneratedContent {
            return convertible.generatedContent.jsonString
        }
        return String(describing: arguments)
    }
}
