/// The fake mailbox. Nothing is ever really sent or deleted: calls are recorded for the UI and the evaluation.
public actor Mailbox {
    public private(set) var inbox: [Email]
    public private(set) var outbox: [SentMessage] = []
    public private(set) var deleted: [Email] = []

    public init(inbox: [Email]) {
        self.inbox = inbox
    }

    public func send(to recipient: String, body: String) -> SentMessage {
        let message = SentMessage(id: outbox.count, to: recipient, body: body)
        outbox.append(message)
        return message
    }

    /// Removes a message from the inbox. Returns `nil` if no message has that ID.
    public func delete(id: String) -> Email? {
        guard let index = inbox.firstIndex(where: { $0.id == id }) else { return nil }
        let email = inbox.remove(at: index)
        deleted.append(email)
        return email
    }
}
