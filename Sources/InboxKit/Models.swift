import Foundation

public struct Email: Codable, Sendable, Hashable, Identifiable {
    public var id: String
    public var from: String
    public var subject: String
    public var date: String
    public var body: String

    public init(id: String, from: String, subject: String, date: String, body: String) {
        self.id = id
        self.from = from
        self.subject = subject
        self.date = date
        self.body = body
    }
}

public struct Contact: Codable, Sendable, Hashable {
    public var name: String
    public var email: String
    /// Private notes. Some hold canary strings so exfiltration can be detected mechanically.
    public var notes: String

    public init(name: String, email: String, notes: String) {
        self.name = name
        self.email = email
        self.notes = notes
    }
}

/// An injected email the demo can swap into the inbox.
public struct InjectionScenario: Codable, Sendable, Hashable, Identifiable {
    public var id: String
    public var title: String
    public var attackerAddresses: [String]
    /// For deletion attacks: the message the attacker wants gone.
    public var targetMessageID: String?
    public var email: Email
}

public struct SentMessage: Codable, Sendable, Hashable, Identifiable {
    public var id: Int
    public var to: String
    public var body: String

    public init(id: Int, to: String, body: String) {
        self.id = id
        self.to = to
        self.body = body
    }
}

public enum Fixtures {
    public static func inbox() throws -> [Email] { try load("inbox") }
    public static func contacts() throws -> [Contact] { try load("contacts") }
    public static func scenarios() throws -> [InjectionScenario] { try load("scenarios") }

    private static func load<T: Decodable>(_ name: String) throws -> T {
        guard let url = Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "Fixtures") else {
            throw CocoaError(.fileNoSuchFile, userInfo: [NSFilePathErrorKey: "\(name).json"])
        }
        return try JSONDecoder().decode(T.self, from: Data(contentsOf: url))
    }
}

public enum Canary {
    /// Every canary string in the given contacts' notes.
    public static func all(in contacts: [Contact]) -> [String] {
        contacts.flatMap { contact in
            contact.notes.split(separator: " ").map(String.init).filter { $0.hasPrefix("CANARY-") }
        }
    }
}
