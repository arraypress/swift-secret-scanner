//
//  Placeholders.swift
//  SecretScanner
//
//  Created by David Sherlock on 2026.
//
//  The false-positive gate: values that look like secrets to a
//  regex and are obviously not — markers, plain words, and code.
//

import Foundation

/// Values that look like secrets to a regex and are obviously not.
public enum Placeholders {
    static let markers = [
        "xxx", "example", "changeme", "change_me", "change-me", "your_", "your-", "yourkey", "<", ">",
        "${", "$(", "{{", "process.env", "os.environ", "getenv", "placeholder", "dummy", "sample",
        "redacted", "****", "...", "todo", "fixme", "replace", "insert", "enter_", "path/to", "/dev/null",
        // A value that names itself is an example: REPLYTOKEN1, mysecret, fakepassword.
        "secret", "token", "passw", "apikey", "api-key", "api_key", "not-a-", "notreal", "fake", "invalid",
    ]
    static let words: Set<String> = [
        "null", "none", "nil", "true", "false", "undefined", "password", "secret", "token", "string",
        "required", "optional", "default", "unknown", "changeit", "admin", "test", "testing",
    ]

    /// `true` when the "value" is code — a call, a dotted path, a bare
    /// identifier — which the generic rules see a lot of: `token =
    /// SecurePrompt.read(label)` is an assignment whose name says secret and
    /// whose value is not one.
    public static func looksLikeCode(_ value: String) -> Bool {
        if value.contains("(") || value.contains(")") || value.contains("[") || value.contains("]") { return true }
        if value.hasSuffix(".") || value.hasSuffix(",") || value.hasSuffix("+") || value.contains("->") { return true }
        // Optional chaining, and a colon that is not a URL's: selector labels
        // (`token:endpoint:`), dictionary literals, type annotations.
        if value.contains("?.") || value.contains("!.") { return true }
        if value.contains(":") && !value.contains("://") { return true }
        // A dotted path: Bundle.main.infoDictionary, config.apiKey, self.token
        if value.range(of: #"^[@$]?[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$"#, options: .regularExpression) != nil { return true }
        // A bare identifier or hyphenated word with no digits:
        // readFromKeychain, SOME_CONSTANT, not-a-real-key. Real tokens carry
        // digits; a digit-free value this short is a word.
        if value.range(of: #"^[A-Za-z_][A-Za-z0-9_-]*$"#, options: .regularExpression) != nil,
           !value.contains(where: \.isNumber), value.count < 32 { return true }
        return false
    }

    /// `true` when the value is a stand-in rather than a credential.
    public static func matches(_ value: String) -> Bool {
        if looksLikeCode(value) { return true }
        let lower = value.lowercased()
        if words.contains(lower) { return true }
        if markers.contains(where: { lower.contains($0) }) { return true }
        if Set(lower).count <= 2 { return true }               // aaaaaaaa, 00000000
        if lower.allSatisfy({ $0.isLetter }) && lower == lower.lowercased() && lower.count < 24 { return true } // a plain word
        return false
    }
}
