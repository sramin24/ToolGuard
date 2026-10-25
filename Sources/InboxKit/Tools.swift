import FoundationModels
import ToolGuard

@Generable
public struct ReadInboxArguments {
    public init() {}
}

public struct ReadInboxTool: Tool {
    public let name = "readInbox"
    public let description = "Returns the emails currently in the user's inbox."
    let mailbox: Mailbox
    /// When set, each email is wrapped as untrusted data (the hardened prompt).
    let hardening: UntrustedDelimiter?

    public init(mailbox: Mailbox, hardening: UntrustedDelimiter?) {
        self.mailbox = mailbox
        self.hardening = hardening
    }

    public func call(arguments: ReadInboxArguments) async throws -> String {
        let emails = await mailbox.inbox
        guard !emails.isEmpty else { return "The inbox is empty." }
        return emails.map { email in
            let text = "[\(email.id)] From: \(email.from)\nDate: \(email.date)\nSubject: \(email.subject)\n\(email.body)"
            return hardening?.wrap(text, source: "email:\(email.id)") ?? text
        }.joined(separator: "\n\n")
    }
}

@Generable
public struct SearchContactsArguments {
    @Guide(description: "Name or email to search for. Use an empty string to list all contacts.")
    public var query: String

    public init(query: String) { self.query = query }
}

public struct SearchContactsTool: Tool {
    public let name = "searchContacts"
    public let description = "Searches the user's contacts and returns names, emails, and private notes."
    let contacts: [Contact]

    public init(contacts: [Contact]) {
        self.contacts = contacts
    }

    public func call(arguments: SearchContactsArguments) async throws -> String {
        let query = arguments.query.lowercased().trimmingCharacters(in: .whitespaces)
        let hits = query.isEmpty ? contacts : contacts.filter {
            $0.name.lowercased().contains(query) || $0.email.lowercased().contains(query)
        }
        guard !hits.isEmpty else { return "No contacts match \"\(arguments.query)\"." }
        return hits.map { "\($0.name) <\($0.email)> notes: \($0.notes)" }.joined(separator: "\n")
    }
}

@Generable
public struct SendMessageArguments {
    @Guide(description: "Recipient email address")
    public var to: String
    @Guide(description: "Message body")
    public var body: String

    public init(to: String, body: String) {
        self.to = to
        self.body = body
    }
}

public struct SendMessageTool: Tool {
    public let name = "sendMessage"
    public let description = "Sends an email message on the user's behalf."
    let mailbox: Mailbox

    public init(mailbox: Mailbox) {
        self.mailbox = mailbox
    }

    public func call(arguments: SendMessageArguments) async throws -> String {
        let sent = await mailbox.send(to: arguments.to, body: arguments.body)
        return "Message sent to \(sent.to)."
    }
}

@Generable
public struct DeleteMessageArguments {
    @Guide(description: "The ID of the message to delete, for example msg-3")
    public var messageID: String

    public init(messageID: String) { self.messageID = messageID }
}

public struct DeleteMessageTool: Tool {
    public let name = "deleteMessage"
    public let description = "Permanently deletes a message from the user's inbox by its ID."
    let mailbox: Mailbox

    public init(mailbox: Mailbox) {
        self.mailbox = mailbox
    }

    public func call(arguments: DeleteMessageArguments) async throws -> String {
        guard let email = await mailbox.delete(id: arguments.messageID) else {
            return "No message with ID \(arguments.messageID)."
        }
        return "Deleted \"\(email.subject)\" (\(email.id))."
    }
}
