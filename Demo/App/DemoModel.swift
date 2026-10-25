import Foundation
import FoundationModels
import InboxKit
import Observation
import ToolGuard

struct ChatMessage: Identifiable {
    enum Role { case user, assistant, error }
    let id = UUID()
    let role: Role
    let text: String
}

struct PendingConfirmation: Identifiable {
    let id = UUID()
    let request: ToolCallRequest
    fileprivate let continuation: CheckedContinuation<Bool, Never>
}

/// Main-actor state for the demo. Mirrors the library's audit log and the fake mailbox into observable properties.
@MainActor @Observable
final class DemoModel {
    var guardEnabled = true { didSet { if guardEnabled != oldValue { startNewSession() } } }
    var hardenedPrompt = false { didSet { if hardenedPrompt != oldValue { startNewSession() } } }
    /// `nil` means no injected email is loaded.
    var scenarioID: String? { didSet { if scenarioID != oldValue { startNewSession() } } }

    let scenarios: [InjectionScenario]
    let modelStatus: String
    let modelAvailable: Bool
    private(set) var loadError: String?

    private(set) var inbox: [Email] = []
    private(set) var outbox: [SentMessage] = []
    private(set) var deleted: [Email] = []
    private(set) var taint = TaintState.clean
    private(set) var events: [AuditEvent] = []
    private(set) var messages: [ChatMessage] = []
    private(set) var isResponding = false
    /// Confirmations waiting for the user, oldest first. The sheet shows the first one.
    private(set) var pendingConfirmations: [PendingConfirmation] = []

    private let baseInbox: [Email]
    private let contacts: [Contact]
    let canaries: [String]
    private var current: Run?
    private var observeTask: Task<Void, Never>?
    private var respondTask: Task<Void, Never>?

    private struct Run {
        let mailbox: Mailbox
        let taint: SessionTaint
        let log: AuditLog
        let session: TaintedSession
    }

    init() {
        let model = SystemLanguageModel.default
        modelAvailable = model.isAvailable
        var status = "Model: \(model.availability)"
        if #available(macOS 27.0, iOS 27.0, *) {
            status += " · variant: \(model.variant.displayName)"
        } else {
            status += " · variant: unavailable before macOS 27"
        }
        modelStatus = status
        print("[ToolGuardDemo] \(status)")

        var inbox: [Email] = [], contacts: [Contact] = [], scenarios: [InjectionScenario] = []
        do {
            inbox = try Fixtures.inbox()
            contacts = try Fixtures.contacts()
            scenarios = try Fixtures.scenarios()
        } catch {
            loadError = "Could not load fixtures: \(error.localizedDescription)"
        }
        baseInbox = inbox
        self.contacts = contacts
        self.scenarios = scenarios
        canaries = Canary.all(in: contacts)
        startNewSession()
    }

    var currentScenario: InjectionScenario? { scenarios.first { $0.id == scenarioID } }

    /// True if a sent message went to an attacker address or carries a canary.
    func isMalicious(_ message: SentMessage) -> Bool {
        let attackers = currentScenario?.attackerAddresses ?? []
        let recipient = message.to.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: ". "))
        return attackers.contains(recipient) || canaries.contains { message.body.contains($0) }
    }

    func isInjected(_ email: Email) -> Bool { email.id == currentScenario?.email.id }

    /// Throws away the conversation, taint, log, and mailbox state, and starts over with the current settings.
    func startNewSession() {
        respondTask?.cancel()
        observeTask?.cancel()
        declineAllPending()

        let inbox = baseInbox + (currentScenario.map { [$0.email] } ?? [])
        let mailbox = Mailbox(inbox: inbox)
        let taint = SessionTaint()
        let log = AuditLog()
        let session = InboxAgent.makeSession(
            mailbox: mailbox, contacts: contacts,
            configuration: AgentConfiguration(guardEnabled: guardEnabled, hardenedPrompt: hardenedPrompt),
            confirm: { [weak self] request in await self?.askUser(request) ?? false },
            taint: taint, log: log)
        current = Run(mailbox: mailbox, taint: taint, log: log, session: session)

        self.inbox = inbox
        outbox = []
        deleted = []
        self.taint = .clean
        events = []
        messages = []
        isResponding = false

        observeTask = Task { [weak self] in
            for await event in log.updates() {
                guard let self else { return }
                events.append(event)
                await refresh()
            }
        }
    }

    func send(_ prompt: String) {
        let text = prompt.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, !isResponding, let current else { return }
        messages.append(ChatMessage(role: .user, text: text))
        isResponding = true
        respondTask = Task { [weak self] in
            do {
                let reply = try await current.session.respond(to: text)
                self?.messages.append(ChatMessage(role: .assistant, text: reply))
            } catch is CancellationError {
                return
            } catch {
                self?.messages.append(ChatMessage(role: .error, text: Self.describe(error)))
            }
            self?.isResponding = false
            await self?.refresh()
        }
    }

    func resolveConfirmation(approved: Bool) {
        guard !pendingConfirmations.isEmpty else { return }
        pendingConfirmations.removeFirst().continuation.resume(returning: approved)
    }

    private func askUser(_ request: ToolCallRequest) async -> Bool {
        await withCheckedContinuation { continuation in
            pendingConfirmations.append(PendingConfirmation(request: request, continuation: continuation))
        }
    }

    private func declineAllPending() {
        while !pendingConfirmations.isEmpty { resolveConfirmation(approved: false) }
    }

    private func refresh() async {
        guard let current else { return }
        outbox = await current.mailbox.outbox
        deleted = await current.mailbox.deleted
        inbox = await current.mailbox.inbox
        taint = await current.taint.state
    }

    private static func describe(_ error: Error) -> String {
        if let generationError = error as? LanguageModelSession.GenerationError {
            return "The model could not respond: \(generationError.localizedDescription) (\(generationError))"
        }
        return "Error: \(error.localizedDescription)"
    }
}
