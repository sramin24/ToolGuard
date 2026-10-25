import InboxKit
import SwiftUI
import ToolGuard

struct SecurityPanel: View {
    @Environment(DemoModel.self) private var model

    var body: some View {
        @Bindable var model = model
        VStack(alignment: .leading, spacing: 10) {
            Text("Security").font(.headline)

            Toggle("Guard", isOn: $model.guardEnabled)
                .accessibilityHint("Turning this on or off starts a new session")
            Toggle("Hardened prompt", isOn: $model.hardenedPrompt)
                .accessibilityHint("Turning this on or off starts a new session")

            sessionStatus

            GroupBox("Audit log") {
                List(model.events.reversed()) { event in
                    AuditRow(event: event)
                }
                .listStyle(.plain)
                .frame(minHeight: 160)
            }

            GroupBox("Outbox (nothing is really sent)") {
                if model.outbox.isEmpty && model.deleted.isEmpty {
                    Text("Empty").foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading)
                } else {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 6) {
                            ForEach(model.outbox) { message in
                                OutboxRow(message: message, malicious: model.isMalicious(message))
                            }
                            ForEach(model.deleted) { email in
                                Label("Deleted: \(email.subject) (\(email.id))", systemImage: "trash")
                                    .foregroundStyle(.red)
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .frame(maxHeight: 180)
                }
            }
        }
        .padding(12)
    }

    private var sessionStatus: some View {
        HStack(alignment: .top) {
            Image(systemName: model.taint.isTainted ? "exclamationmark.shield.fill" : "checkmark.shield.fill")
                .foregroundStyle(model.taint.isTainted ? .orange : .green)
                .imageScale(.large)
            VStack(alignment: .leading) {
                Text(model.taint.isTainted ? "Session tainted" : "Session clean").fontWeight(.semibold)
                Text(model.taint.isTainted
                     ? "Untrusted content from: \(model.taint.sources.joined(separator: ", "))"
                     : "No untrusted content has entered this session.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if !model.guardEnabled {
                    Text("Guard is off: every tool call runs.").font(.caption).foregroundStyle(.red)
                }
            }
        }
        .accessibilityElement(children: .combine)
    }
}

struct OutboxRow: View {
    let message: SentMessage
    let malicious: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack {
                if malicious {
                    Image(systemName: "exclamationmark.octagon.fill").foregroundStyle(.red)
                        .accessibilityLabel("Sent to attacker or contains private data")
                }
                Text("To: \(message.to)").fontWeight(.medium)
            }
            Text(message.body).font(.caption).textSelection(.enabled)
        }
        .padding(6)
        .background(malicious ? Color.red.opacity(0.12) : Color.clear, in: RoundedRectangle(cornerRadius: 6))
        .accessibilityElement(children: .combine)
    }
}

struct AuditRow: View {
    let event: AuditEvent

    var body: some View {
        HStack(alignment: .top, spacing: 6) {
            Image(systemName: symbol).foregroundStyle(color).frame(width: 16)
            Text(text).font(.caption).textSelection(.enabled)
        }
        .accessibilityElement(children: .combine)
    }

    private var text: String {
        let call = event.callID.map { "#\($0) " } ?? ""
        switch event.kind {
        case .sessionTainted(let source): return "Session tainted by \(source)"
        case .sessionReset: return "Session reset"
        case .callAttempted(let tool, let arguments): return "\(call)\(tool) requested \(arguments)"
        case .decision(let tool, .allow): return "\(call)\(tool): allowed"
        case .decision(let tool, .requireConfirmation(let reason)): return "\(call)\(tool): needs confirmation. \(reason)"
        case .decision(let tool, .deny(let reason)): return "\(call)\(tool): denied. \(reason)"
        case .confirmation(let tool, let approved): return "\(call)\(tool): user \(approved ? "approved" : "declined")"
        case .callExecuted(let tool): return "\(call)\(tool): executed"
        case .callFailed(let tool, let error): return "\(call)\(tool): failed (\(error))"
        case .callRefused(let tool): return "\(call)\(tool): blocked, refusal returned to model"
        }
    }

    private var symbol: String {
        switch event.kind {
        case .sessionTainted: "drop.triangle"
        case .sessionReset: "arrow.counterclockwise"
        case .callAttempted: "arrow.right.circle"
        case .decision(_, .allow): "checkmark.circle"
        case .decision(_, .requireConfirmation): "questionmark.circle"
        case .decision(_, .deny): "xmark.octagon"
        case .confirmation(_, let approved): approved ? "hand.thumbsup" : "hand.thumbsdown"
        case .callExecuted: "bolt.fill"
        case .callFailed: "exclamationmark.triangle"
        case .callRefused: "nosign"
        }
    }

    private var color: Color {
        switch event.kind {
        case .sessionTainted, .decision(_, .requireConfirmation): .orange
        case .decision(_, .deny), .callRefused, .callFailed: .red
        case .callExecuted, .decision(_, .allow): .green
        default: .secondary
        }
    }
}
