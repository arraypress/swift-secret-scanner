//
//  Repository.swift
//  SecretScanner
//
//  Created by David Sherlock on 2026.
//
//  The git side, through the git binary: what is in the working tree, what
//  is staged, and every blob that was ever committed on any branch — the
//  one that matters, because a secret deleted last year is still in the
//  history a clone brings down.
//

import Foundation

/// A git repository on disk, read through the `git` on PATH.
public struct Repository: Sendable {
    /// The working tree's top level.
    public let root: URL

    /// What can go wrong talking to git.
    public enum GitError: Error, CustomStringConvertible, Sendable {
        case notARepository(String)
        case failed(String)
        /// The message for people.
        public var description: String {
            switch self {
            case .notARepository(let p): return "\(p) is not inside a git repository"
            case .failed(let m): return m
            }
        }
    }

    /// The repository containing `path`, or `nil` if there is none.
    public static func find(from path: String) -> Repository? {
        guard let out = try? Git.run(["rev-parse", "--show-toplevel"], in: URL(fileURLWithPath: path).isDirectory ? path : (path as NSString).deletingLastPathComponent),
              !out.isEmpty else { return nil }
        return Repository(root: URL(fileURLWithPath: out.trimmingCharacters(in: .whitespacesAndNewlines)))
    }

    /// Tracked files plus untracked files that are not ignored — what a
    /// commit could contain. Paths are relative to the root.
    public func workingTreeFiles() throws -> [String] {
        let out = try Git.run(["ls-files", "-z", "--cached", "--others", "--exclude-standard"], in: root.path)
        return out.split(separator: "\0").map(String.init).filter { !$0.isEmpty }
    }

    /// Files with staged changes, with their staged contents.
    public func stagedFiles() throws -> [(path: String, contents: Data)] {
        let names = try Git.run(["diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR"], in: root.path)
        return try names.split(separator: "\0").map(String.init).filter { !$0.isEmpty }.map { path in
            (path, try Git.runData(["show", ":\(path)"], in: root.path))
        }
    }

    /// One blob from history.
    public struct Blob: Sendable {
        /// The blob's object id.
        public let sha: String
        /// The path it was seen at (the first one, if it moved).
        public let path: String
        /// Bytes, so binaries and giants can be skipped before they are read.
        public let size: Int
    }

    /// Every distinct blob reachable from any ref, with a path. Trees and
    /// commits are dropped; a blob that appears under several paths is
    /// listed once.
    public func historyBlobs() throws -> [Blob] {
        let out = try Git.run(["rev-list", "--all", "--objects"], in: root.path)
        var seen: Set<String> = []
        var candidates: [(String, String)] = []
        for line in out.split(separator: "\n") {
            let parts = line.split(separator: " ", maxSplits: 1)
            guard parts.count == 2 else { continue }        // commits and the root tree have no path
            let sha = String(parts[0]), path = String(parts[1])
            guard !seen.contains(sha) else { continue }
            seen.insert(sha)
            candidates.append((sha, path))
        }
        // Type and size in one call: only blobs survive.
        let check = try Git.run(["cat-file", "--batch-check"], in: root.path, input: candidates.map(\.0).joined(separator: "\n") + "\n")
        var sizes: [String: Int] = [:]
        for line in check.split(separator: "\n") {
            let parts = line.split(separator: " ")
            guard parts.count == 3, parts[1] == "blob", let size = Int(parts[2]) else { continue }
            sizes[String(parts[0])] = size
        }
        return candidates.compactMap { sha, path in sizes[sha].map { Blob(sha: sha, path: path, size: $0) } }
    }

    /// Reads blobs in batches through one `cat-file --batch` process each.
    ///
    /// - Parameters:
    ///   - blobs: What to read.
    ///   - batch: How many per process.
    ///   - handler: Called with each blob's contents, in order.
    public func readBlobs(_ blobs: [Blob], batch: Int = 256, handler: (Blob, Data) throws -> Void) throws {
        var index = 0
        while index < blobs.count {
            let slice = Array(blobs[index..<min(index + batch, blobs.count)])
            let data = try Git.runData(["cat-file", "--batch"], in: root.path, input: Data((slice.map(\.sha).joined(separator: "\n") + "\n").utf8))
            var cursor = 0
            for blob in slice {
                // Header: "<sha> blob <size>\n", then <size> bytes, then "\n".
                guard let newline = data[cursor...].firstIndex(of: 10) else { break }
                let header = String(decoding: data[cursor..<newline], as: UTF8.self)
                let parts = header.split(separator: " ")
                guard parts.count == 3, let size = Int(parts[2]) else { throw GitError.failed("unexpected cat-file header: \(header)") }
                let start = newline + 1
                let end = min(start + size, data.count)
                try handler(blob, data[start..<end])
                cursor = end + 1
            }
            index += batch
        }
    }

    /// The earliest commit whose diff introduced `secret` at `path`.
    public func attribution(secret: String, path: String) -> (commit: String, date: String, author: String)? {
        guard let out = try? Git.run(["log", "--all", "--format=%h\u{1f}%as\u{1f}%an", "-S", secret, "--", path], in: root.path) else { return nil }
        guard let last = out.split(separator: "\n").last else { return nil }
        let parts = last.split(separator: "\u{1f}", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 3 else { return nil }
        return (parts[0], parts[1], parts[2])
    }
}

// MARK: - git

enum Git {
    static func run(_ arguments: [String], in directory: String, input: String? = nil) throws -> String {
        String(decoding: try runData(arguments, in: directory, input: input.map { Data($0.utf8) }), as: UTF8.self)
    }

    static func runData(_ arguments: [String], in directory: String, input: Data? = nil) throws -> Data {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
        process.arguments = arguments
        process.currentDirectoryURL = URL(fileURLWithPath: directory)
        let out = Pipe(), err = Pipe()
        process.standardOutput = out
        process.standardError = err
        let inPipe = Pipe()
        if input != nil { process.standardInput = inPipe }
        try process.run()
        if let input {
            // Written on another thread: a large batch would deadlock a
            // single thread writing stdin while stdout fills.
            let writer = inPipe.fileHandleForWriting
            Thread { try? writer.write(contentsOf: input); try? writer.close() }.start()
        }
        let data = out.fileHandleForReading.readDataToEndOfFile()
        let errData = err.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw Repository.GitError.failed(String(decoding: errData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines))
        }
        return data
    }
}

private extension URL {
    var isDirectory: Bool {
        (try? resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory ?? false
    }
}
