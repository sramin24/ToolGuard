import Foundation
import FoundationModels

// Phase 0, steps 2-5: availability, a real tool call, a generic wrapper, and latency.

@Generable
struct EchoArguments {
    @Guide(description: "The exact text to echo back")
    var text: String
}

struct EchoTool: Tool {
    let name = "echo"
    let description = "Echoes the given text back, prefixed with ECHO:."

    func call(arguments: EchoArguments) async throws -> String {
        "ECHO: \(arguments.text) [token-4417]"
    }
}

/// Spike version of the planned GuardedTool: generic over any `Tool`, forwarding every requirement.
/// `Output` is wrapped so a refusal can be returned as model-readable text whatever `Base.Output` is.
struct WrappedTool<Base: Tool>: Tool {
    typealias Arguments = Base.Arguments
    typealias Output = GatedOutput<Base.Output>

    let base: Base
    let allow: Bool

    var name: String { base.name }
    var description: String { base.description }
    var parameters: GenerationSchema { base.parameters }
    var includesSchemaInInstructions: Bool { base.includesSchemaInInstructions }

    func call(arguments: Base.Arguments) async throws -> GatedOutput<Base.Output> {
        guard allow else {
            log("[wrapper] \(name): REFUSED")
            return .refused("This action was blocked by the security policy.")
        }
        log("[wrapper] \(name): forwarding to base")
        let output = try await base.call(arguments: arguments)
        log("[wrapper] \(name): base returned")
        return .ran(output)
    }
}

enum GatedOutput<Wrapped: PromptRepresentable>: PromptRepresentable {
    case ran(Wrapped)
    case refused(String)

    var promptRepresentation: Prompt {
        switch self {
        case .ran(let output): return output.promptRepresentation
        case .refused(let message): return Prompt(message)
        }
    }
}

func log(_ message: String) {
    print(message)
    fflush(stdout)
}

func runFeasibility() async throws {
    let model = SystemLanguageModel.default
    log("availability: \(model.availability)")
    if #available(macOS 27.0, iOS 27.0, *) {
        log("variant: \(model.variant.displayName)")
    } else {
        log("variant: unavailable (SystemLanguageModel.variant requires macOS 27; running \(ProcessInfo.processInfo.operatingSystemVersionString))")
    }
    log("contextSize: \(model.contextSize)")
    guard model.isAvailable else {
        log("STOP: on-device model unavailable.")
        return
    }

    let clock = ContinuousClock()
    let prompt = "Call the echo tool with the text 'hello wrapper', then tell me exactly what it returned."

    for (label, tool) in [("plain", EchoTool() as any Tool), ("wrapped", WrappedTool(base: EchoTool(), allow: true)),
                          ("wrapped-refusing", WrappedTool(base: EchoTool(), allow: false))] {
        let session = LanguageModelSession(tools: [tool])
        let start = clock.now
        let response = try await session.respond(to: prompt)
        let elapsed = clock.now - start
        let calls = session.transcript.compactMap { entry -> String? in
            if case .toolCalls(let calls) = entry { return calls.map { "\($0.toolName)(\($0.arguments))" }.joined(separator: ", ") }
            return nil
        }
        log("[\(label)] latency: \(elapsed.formatted(.units(allowed: [.seconds, .milliseconds])))")
        log("[\(label)] tool calls in transcript: \(calls)")
        log("[\(label)] response: \(response.content)")
        log("[\(label)] token seen by model: \(response.content.contains("4417"))")
    }
}
