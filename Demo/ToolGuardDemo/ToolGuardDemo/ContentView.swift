import InboxKit
import SwiftUI

struct ContentView: View {
    @Environment(DemoModel.self) private var model

    var body: some View {
        @Bindable var model = model
        VStack(spacing: 0) {
            HSplitView {
                InboxColumn()
                    .frame(minWidth: 250, idealWidth: 280)
                ChatColumn()
                    .frame(minWidth: 380, idealWidth: 460)
                SecurityPanel()
                    .frame(minWidth: 320, idealWidth: 360)
            }
            Divider()
            Text(model.loadError ?? model.modelStatus)
                .font(.caption)
                .foregroundStyle(model.loadError == nil ? Color.secondary : Color.red)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 12)
                .padding(.vertical, 4)
        }
        .sheet(item: Binding(
            get: { model.pendingConfirmations.first },
            set: { if $0 == nil { model.resolveConfirmation(approved: false) } }
        )) { pending in
            ConfirmationSheet(request: pending.request) { approved in
                model.resolveConfirmation(approved: approved)
            }
        }
    }
}

struct InboxColumn: View {
    @Environment(DemoModel.self) private var model

    var body: some View {
        @Bindable var model = model
        VStack(alignment: .leading, spacing: 8) {
            Text("Inbox").font(.headline)
            Picker("Injected email", selection: $model.scenarioID) {
                Text("None").tag(String?.none)
                ForEach(model.scenarios) { scenario in
                    Text(scenario.title).tag(Optional(scenario.id))
                }
            }
            .accessibilityHint("Adds an attacker's email to the inbox and starts a new session")

            List(model.inbox) { email in
                VStack(alignment: .leading, spacing: 2) {
                    HStack {
                        if model.isInjected(email) {
                            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                                .accessibilityLabel("Injected email")
                        }
                        Text(email.subject).fontWeight(.medium).lineLimit(1)
                    }
                    Text(email.from).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                    Text(email.body).font(.caption).lineLimit(2)
                }
                .padding(.vertical, 2)
                .accessibilityElement(children: .combine)
            }
        }
        .padding(12)
    }
}

struct ChatColumn: View {
    @Environment(DemoModel.self) private var model
    @State private var draft = ""

    private let suggestions = [
        "Read my inbox and summarize it for me.",
        "Read my inbox and take care of any requests in it.",
        "Read my inbox, then reply to Sam's lunch email saying noon Thursday works.",
    ]

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Assistant").font(.headline)
                Spacer()
                Button("New Session") { model.startNewSession() }
                    .help("Clears the conversation, taint, outbox, and audit log")
            }

            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 10) {
                        ForEach(model.messages) { message in
                            MessageBubble(message: message).id(message.id)
                        }
                        if model.isResponding {
                            ProgressView().controlSize(.small).accessibilityLabel("Assistant is responding")
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .onChange(of: model.messages.count) {
                    if let last = model.messages.last { proxy.scrollTo(last.id, anchor: .bottom) }
                }
            }

            ScrollView(.horizontal, showsIndicators: false) {
                HStack {
                    ForEach(suggestions, id: \.self) { suggestion in
                        Button(suggestion) { model.send(suggestion) }
                            .buttonStyle(.bordered)
                            .controlSize(.small)
                    }
                }
            }
            .disabled(model.isResponding || !model.modelAvailable)

            HStack {
                TextField("Ask the assistant", text: $draft)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit(submit)
                Button("Send", action: submit)
                    .keyboardShortcut(.defaultAction)
            }
            .disabled(model.isResponding || !model.modelAvailable)
        }
        .padding(12)
    }

    private func submit() {
        model.send(draft)
        draft = ""
    }
}

struct MessageBubble: View {
    let message: ChatMessage

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            Text(message.text)
                .textSelection(.enabled)
                .padding(8)
                .background(background, in: RoundedRectangle(cornerRadius: 8))
        }
        .accessibilityElement(children: .combine)
    }

    private var label: String {
        switch message.role {
        case .user: "You"
        case .assistant: "Assistant"
        case .error: "Error"
        }
    }

    private var background: Color {
        switch message.role {
        case .user: .accentColor.opacity(0.15)
        case .assistant: .secondary.opacity(0.12)
        case .error: .red.opacity(0.15)
        }
    }
}
