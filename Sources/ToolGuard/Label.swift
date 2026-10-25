/// Whether content may be treated as instructions (trusted) or only as data (untrusted).
public enum TrustLevel: Sendable, Hashable {
    case trusted
    case untrusted
}

/// Where a piece of content came from and whether it is trusted.
public struct Label: Sendable, Hashable {
    public var trust: TrustLevel
    /// A short provenance tag, e.g. `"user"`, `"email:msg-12"`, `"web:example.com"`.
    public var source: String

    public init(trust: TrustLevel, source: String) {
        self.trust = trust
        self.source = source
    }

    public static func trusted(_ source: String) -> Label { Label(trust: .trusted, source: source) }
    public static func untrusted(_ source: String) -> Label { Label(trust: .untrusted, source: source) }

    /// The label of content derived from both inputs: untrusted if either side is untrusted.
    public func join(_ other: Label) -> Label {
        let trust: TrustLevel = (self.trust == .trusted && other.trust == .trusted) ? .trusted : .untrusted
        let source = self.source == other.source ? self.source : "\(self.source) + \(other.source)"
        return Label(trust: trust, source: source)
    }
}

/// A value paired with its trust label.
public struct Labeled<Value: Sendable>: Sendable {
    public var value: Value
    public var label: Label

    public init(_ value: Value, label: Label) {
        self.value = value
        self.label = label
    }

    public static func trusted(_ value: Value, source: String) -> Labeled { Labeled(value, label: .trusted(source)) }
    public static func untrusted(_ value: Value, source: String) -> Labeled { Labeled(value, label: .untrusted(source)) }

    public var isTrusted: Bool { label.trust == .trusted }

    /// Combines two labeled values. The result is untrusted if either input is.
    public func join<Other, Result>(_ other: Labeled<Other>, _ combine: (Value, Other) -> Result) -> Labeled<Result> {
        Labeled<Result>(combine(value, other.value), label: label.join(other.label))
    }
}
