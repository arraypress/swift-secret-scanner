//
//  Finding.swift
//  SecretScanner
//
//  Created by David Sherlock on 2026.
//
//  What a scan reports. The raw secret is carried so a caller can verify or
//  allowlist it, and masked so nothing that prints a finding prints a secret.
//

import Foundation

/// How bad it is if this is real.
public enum Severity: String, Codable, Sendable, Comparable, CaseIterable {
    case low, medium, high

    /// `low < medium < high`.
    public static func < (a: Severity, b: Severity) -> Bool {
        let order: [Severity] = [.low, .medium, .high]
        return order.firstIndex(of: a)! < order.firstIndex(of: b)!
    }
}

/// One secret, where it is, and how sure the scanner is.
public struct Finding: Codable, Sendable, Equatable {
    /// The pattern that matched — a stable slug such as `aws-access-key-id`.
    public let pattern: String
    /// The pattern's name for people: "AWS access key ID".
    public let name: String
    /// How bad it is if this is real.
    public let severity: Severity
    /// The secret as matched. Never print this by default.
    public let secret: String
    /// The secret with its middle hidden: `AKIA…MPLE`.
    public var masked: String { Finding.mask(secret) }
    /// 1-based line and column in the text.
    public let line: Int
    /// 1-based column of the secret's first character.
    public let column: Int
    /// The line it sits on, with the secret masked.
    public let context: String
    /// Shannon entropy of the secret in bits per character, for the generic
    /// rules; `nil` for pattern matches that need no entropy.
    public let entropy: Double?
    /// Where the text came from, when it came from a file.
    public var file: String?
    /// For history findings: the earliest commit that introduced it.
    public var commit: String?
    /// For history findings: who made that commit.
    public var author: String?
    /// For history findings: the commit's date, ISO 8601.
    public var date: String?

    /// A finding with every field given; the scanner builds these.
    public init(pattern: String, name: String, severity: Severity, secret: String,
                line: Int, column: Int, context: String, entropy: Double? = nil,
                file: String? = nil, commit: String? = nil, author: String? = nil, date: String? = nil) {
        self.pattern = pattern
        self.name = name
        self.severity = severity
        self.secret = secret
        self.line = line
        self.column = column
        self.context = context
        self.entropy = entropy
        self.file = file
        self.commit = commit
        self.author = author
        self.date = date
    }

    /// Hides the middle of a secret: the first four and last two characters
    /// survive, which is enough to recognise a key and not enough to use it.
    public static func mask(_ secret: String) -> String {
        let chars = Array(secret)
        guard chars.count >= 10 else { return String(repeating: "•", count: max(chars.count, 3)) }
        return String(chars.prefix(4)) + "…" + String(chars.suffix(2))
    }
}
