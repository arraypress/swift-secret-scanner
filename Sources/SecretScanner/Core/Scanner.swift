//
//  Scanner.swift
//  SecretScanner
//
//  Created by David Sherlock on 2026.
//
//  Text in, findings out. Deterministic — the same text gives the same
//  findings on every run and every machine, which is what lets a scan gate
//  a release.
//

import Foundation

/// Finds secrets in text: the pattern catalogue first, then the generic assignment rules.
public struct SecretScanner: Sendable {

    /// Paths, values and patterns to stay quiet about.
    public var allowlist: Allowlist
    /// Whether the generic assignment and environment rules run. They find
    /// the most and cry wolf the most; an allowlist tames them.
    public var generic: Bool
    /// The lowest severity to report.
    public var minimumSeverity: Severity

    /// A scanner; the defaults report everything.
    public init(allowlist: Allowlist = Allowlist(), generic: Bool = true, minimumSeverity: Severity = .low) {
        self.allowlist = allowlist
        self.generic = generic
        self.minimumSeverity = minimumSeverity
    }

    /// Scans one text.
    ///
    /// - Parameters:
    ///   - text: What to scan.
    ///   - path: Where it came from, for the allowlist and the report.
    public func scan(_ text: String, path: String? = nil) -> [Finding] {
        if let path, allowlist.ignores(path: path) { return [] }
        let ns = text as NSString
        var findings: [Finding] = []
        var taken: [NSRange] = []

        for pattern in Patterns.catalogue {
            if pattern.generic && !generic { continue }
            if pattern.severity < minimumSeverity { continue }
            if allowlist.disabled.contains(pattern.id) { continue }
            for match in pattern.regex.matches(in: text, range: NSRange(location: 0, length: ns.length)) {
                let range = match.range(at: pattern.group)
                guard range.location != NSNotFound else { continue }
                let secret = ns.substring(with: range)
                if let verify = pattern.verify, !verify(secret) { continue }
                if Placeholders.isDocumentedExample(secret) { continue }
                // One secret, one finding: a Stripe key is not also a
                // generic assignment value.
                if taken.contains(where: { NSIntersectionRange($0, range).length > 0 }) { continue }
                if allowlist.ignores(secret: secret) { continue }
                let lineRange = ns.lineRange(for: NSRange(location: range.location, length: 0))
                let lineText = ns.substring(with: lineRange).trimmingCharacters(in: .newlines)
                if Allowlist.lineOptsOut(lineText) { continue }
                taken.append(range)
                let (line, column) = position(of: range.location, in: ns)
                findings.append(Finding(
                    pattern: pattern.id,
                    name: pattern.name,
                    severity: pattern.severity,
                    secret: secret,
                    line: line,
                    column: column,
                    context: lineText.replacingOccurrences(of: secret, with: Finding.mask(secret)),
                    entropy: pattern.generic ? Entropy.bits(secret) : nil,
                    file: path
                ))
            }
        }
        return findings.sorted { ($0.line, $0.column) < ($1.line, $1.column) }
    }

    private func position(of location: Int, in text: NSString) -> (line: Int, column: Int) {
        var line = 1
        var lineStart = 0
        var i = 0
        while i < location {
            if text.character(at: i) == 10 { line += 1; lineStart = i + 1 }
            i += 1
        }
        return (line, location - lineStart + 1)
    }
}

// MARK: - Allowlist

/// What a scan should not report: paths, exact values, value patterns,
/// whole rules — from a `.secretsignore` file, flags, or both.
public struct Allowlist: Sendable, Equatable {
    /// Glob-ish path patterns (`*` and `**` as in .gitignore, roughly).
    public var paths: [String] = []
    /// Exact secret values that are known and fine (a public test key).
    public var values: Set<String> = []
    /// Regular expressions a value may match to be ignored.
    public var valuePatterns: [String] = []
    /// Pattern ids switched off entirely.
    public var disabled: Set<String> = []

    /// An allowlist built in code; `.secretsignore` is the usual source.
    public init(paths: [String] = [], values: Set<String> = [], valuePatterns: [String] = [], disabled: Set<String> = []) {
        self.paths = paths
        self.values = values
        self.valuePatterns = valuePatterns
        self.disabled = disabled
    }

    /// The file's name.
    public static let fileName = ".secretsignore"

    /// Parses a `.secretsignore`: one entry per line, `#` comments,
    /// `value:`, `regex:` and `pattern:` prefixes; anything else is a path.
    public static func parse(_ text: String) -> Allowlist {
        var list = Allowlist()
        for raw in text.split(separator: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            if line.hasPrefix("value:") { list.values.insert(String(line.dropFirst(6)).trimmingCharacters(in: .whitespaces)) }
            else if line.hasPrefix("regex:") { list.valuePatterns.append(String(line.dropFirst(6)).trimmingCharacters(in: .whitespaces)) }
            else if line.hasPrefix("pattern:") { list.disabled.insert(String(line.dropFirst(8)).trimmingCharacters(in: .whitespaces)) }
            else { list.paths.append(line) }
        }
        return list
    }

    /// Loads the file from a directory, if there is one.
    public static func load(from directory: URL) -> Allowlist {
        let url = directory.appendingPathComponent(fileName)
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return Allowlist() }
        return parse(text)
    }

    /// Whether a path matches any allowlisted glob.
    public func ignores(path: String) -> Bool {
        paths.contains { Allowlist.matches(glob: $0, path: path) }
    }

    /// Whether the value is a known-fine secret, by exact value or regex.
    public func ignores(secret: String) -> Bool {
        if values.contains(secret) { return true }
        return valuePatterns.contains { secret.range(of: $0, options: .regularExpression) != nil }
    }

    /// A line marked `secrets:ignore` (in any comment style) is skipped.
    public static func lineOptsOut(_ line: String) -> Bool {
        line.contains("secrets:ignore") || line.contains("secrets: ignore")
    }

    /// `*` matches within a path segment, `**` across segments; a pattern
    /// without a slash matches the file name anywhere.
    static func matches(glob: String, path: String) -> Bool {
        let target = glob.contains("/") ? path : (path as NSString).lastPathComponent
        var regex = "^"
        var i = glob.startIndex
        while i < glob.endIndex {
            let c = glob[i]
            if c == "*" {
                let next = glob.index(after: i)
                if next < glob.endIndex, glob[next] == "*" {
                    regex += ".*"; i = glob.index(after: next); continue
                }
                regex += "[^/]*"
            } else if c == "?" {
                regex += "[^/]"
            } else {
                regex += NSRegularExpression.escapedPattern(for: String(c))
            }
            i = glob.index(after: i)
        }
        regex += "$"
        return target.range(of: regex, options: .regularExpression) != nil
            || (glob.contains("/") && path.range(of: regex.dropFirst().dropLast() + "(/.*)?$", options: .regularExpression) != nil)
    }
}
