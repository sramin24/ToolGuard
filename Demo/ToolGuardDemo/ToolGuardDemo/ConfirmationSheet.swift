import SwiftUI
import ToolGuard

/// Shows exactly what the model is trying to do. The full arguments are always shown (scrollable, never cut off).
struct ConfirmationSheet: View {
    let request: ToolCallRequest
    let decide: (Bool) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("The assistant wants to run \(request.toolName)", systemImage: "exclamationmark.shield.fill")
                .font(.title3.weight(.semibold))
                .foregroundStyle(.orange)

            Text("Why this was flagged").font(.headline)
            Text(request.reason)
                .accessibilityLabel("Reason: \(request.reason)")

            if !request.taintSources.isEmpty {
                Text("Untrusted sources in this session: \(request.taintSources.joined(separator: ", "))")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            HStack {
                Text("Full arguments").font(.headline)
                Spacer()
                Text("\(request.arguments.count) characters, all shown")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            ScrollView {
                Text(request.arguments)
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(8)
            }
            .frame(minHeight: 120, maxHeight: 320)
            .background(.secondary.opacity(0.1), in: RoundedRectangle(cornerRadius: 6))
            .accessibilityLabel("Arguments: \(request.arguments)")

            Text("Check the recipient and the whole message. Text from an untrusted email may have shaped it.")
                .font(.callout)

            HStack {
                Spacer()
                Button("Deny", role: .cancel) { decide(false) }
                    .keyboardShortcut(.cancelAction)
                Button("Approve") { decide(true) }
                    .accessibilityHint("Runs \(request.toolName) with the arguments shown")
            }
        }
        .padding(20)
        .frame(minWidth: 520)
        .interactiveDismissDisabled()
    }
}
