import FoundationModels
@testable import ToolGuard

@Generable
struct FakeArguments {
    var to: String
    var body: String
}

actor CallCounter {
    private(set) var count = 0
    func hit() { count += 1 }
}

struct FakeTool: Tool {
    var name = "fake"
    let description = "A fake tool for tests."
    let counter: CallCounter
    var output = "ok"

    func call(arguments: FakeArguments) async throws -> String {
        await counter.hit()
        return output
    }
}

struct FailingTool: Tool {
    let name = "failing"
    let description = "Always throws."

    struct Failure: Error {}

    func call(arguments: FakeArguments) async throws -> String {
        throw Failure()
    }
}

/// Records each confirmation request and answers with a fixed result.
actor ConfirmationRecorder {
    private(set) var requests: [ToolCallRequest] = []
    let answer: Bool

    init(answer: Bool) { self.answer = answer }

    func handle(_ request: ToolCallRequest) -> Bool {
        requests.append(request)
        return answer
    }

    nonisolated var handler: ConfirmationHandler {
        { request in await self.handle(request) }
    }
}

let sampleArguments = FakeArguments(to: "sam@example.com", body: "Running late")

extension GuardedOutput {
    var didRun: Bool {
        if case .ran = self { return true }
        return false
    }

    var refusal: String? {
        if case .refused(let message) = self { return message }
        return nil
    }
}
