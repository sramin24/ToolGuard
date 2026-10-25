import FoundationModels
import InboxKit
import Testing
import ToolGuard

@Suite struct InboxKitTests {
    @Test func fixturesLoad() throws {
        #expect(try Fixtures.inbox().count == 8)
        #expect(try Fixtures.contacts().count == 6)
        #expect(Canary.all(in: try Fixtures.contacts()) == ["CANARY-7f3a", "CANARY-2b9c", "CANARY-d41e"])
        let scenarios = try Fixtures.scenarios()
        let inboxIDs = Set(try Fixtures.inbox().map(\.id))
        for scenario in scenarios {
            #expect(!inboxIDs.contains(scenario.email.id), "scenario \(scenario.id) collides with a fixture email")
        }
    }

    @Test func sendAndDeleteOnlyRecord() async throws {
        let mailbox = Mailbox(inbox: try Fixtures.inbox())
        _ = try await SendMessageTool(mailbox: mailbox).call(arguments: .init(to: "sam@example.com", body: "hi"))
        let result = try await DeleteMessageTool(mailbox: mailbox).call(arguments: .init(messageID: "msg-2"))
        let missing = try await DeleteMessageTool(mailbox: mailbox).call(arguments: .init(messageID: "msg-99"))

        #expect(await mailbox.outbox == [SentMessage(id: 0, to: "sam@example.com", body: "hi")])
        #expect(await mailbox.deleted.map(\.id) == ["msg-2"])
        #expect(await mailbox.inbox.count == 7)
        #expect(result.contains("msg-2"))
        #expect(missing.contains("No message"))
    }

    @Test func readInboxWrapsEachEmailWhenHardened() async throws {
        let mailbox = Mailbox(inbox: try Fixtures.inbox())
        let delimiter = UntrustedDelimiter(boundary: "B0UND")
        let plain = try await ReadInboxTool(mailbox: mailbox, hardening: nil).call(arguments: .init())
        let hardened = try await ReadInboxTool(mailbox: mailbox, hardening: delimiter).call(arguments: .init())

        #expect(!plain.contains("<<untrusted"))
        #expect(hardened.components(separatedBy: "<</untrusted id=B0UND>>").count == 9)
        #expect(hardened.contains("source=\"email:msg-1\""))
    }

    @Test func searchContactsFiltersAndListsAll() async throws {
        let tool = SearchContactsTool(contacts: try Fixtures.contacts())
        #expect(try await tool.call(arguments: .init(query: "sam")).contains("CANARY-7f3a"))
        #expect(try await tool.call(arguments: .init(query: "")).split(separator: "\n").count == 6)
        #expect(try await tool.call(arguments: .init(query: "zzz")).contains("No contacts"))
    }
}
