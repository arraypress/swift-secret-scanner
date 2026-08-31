//
//  Scan.swift
//  SecretScanner
//
//  Created by David Sherlock on 2026.
//
//  The whole job: files or a repository in, findings and a count out. What
//  is skipped is skipped for a stated reason — lock files are hashes, build
//  products are not source, binaries are not text.
//

import Foundation

/// What a scan found and how much it looked at.
public struct ScanReport: Sendable {
    /// Every secret found.
    public var findings: [Finding] = []
    /// Working-tree or staged files read.
    public var filesScanned = 0
    /// History blobs read.
    public var blobsScanned = 0
    /// Files and blobs passed over: binaries, lockfiles, oversize, allowlisted paths.
    public var skipped = 0
    /// An empty report.
    public init() {}
}

/// Scanning a working tree, the index, or history.
public enum Scan {

    /// Directories nobody wants scanned and never should commit.
    public static let skippedDirectories: Set<String> = [
        ".git", ".build", ".swiftpm", "node_modules", "dist", "Pods", "DerivedData", ".venv", "venv",
        "__pycache__", ".next", ".nuxt", "target", "vendor", ".cache", ".idea", ".vscode",
    ]
    /// Files that are hashes and URLs all the way down.
    public static let skippedFiles: Set<String> = [
        "Package.resolved", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Cargo.lock",
        "Gemfile.lock", "poetry.lock", "composer.lock", "Podfile.lock", "go.sum", "flake.lock",
    ]
    /// Binary and generated formats there is no point reading.
    public static let skippedExtensions: Set<String> = [
        "png", "jpg", "jpeg", "gif", "webp", "heic", "ico", "icns", "pdf", "zip", "gz", "tgz", "bz2", "xz", "7z",
        "dmg", "pkg", "mp3", "m4a", "wav", "aiff", "flac", "ogg", "mp4", "mov", "mkv", "ttf", "otf", "woff",
        "woff2", "mlmodel", "mlmodelc", "safetensors", "bin", "o", "a", "dylib", "so", "class", "jar", "pyc",
        "map", "min.js", "min.css",
    ]
    /// Larger than this is not a source file.
    public static let maxBytes = 5_000_000

    /// Whether a path is worth reading at all.
    public static func shouldScan(path: String, size: Int? = nil) -> Bool {
        let parts = path.split(separator: "/").map(String.init)
        if parts.dropLast().contains(where: { skippedDirectories.contains($0) }) { return false }
        guard let name = parts.last else { return false }
        if skippedFiles.contains(name) { return false }
        let lower = name.lowercased()
        if skippedExtensions.contains(where: { lower.hasSuffix("." + $0) }) { return false }
        if let size, size > maxBytes { return false }
        return true
    }

    /// Text, or `nil` when the bytes are not text.
    public static func text(from data: Data) -> String? {
        if data.prefix(8192).contains(0) { return nil }
        return String(data: data, encoding: .utf8) ?? String(data: data, encoding: .isoLatin1)
    }

    // MARK: Files

    /// Scans files and folders (recursively), outside any git awareness.
    public static func files(_ paths: [String], scanner: SecretScanner) throws -> ScanReport {
        var report = ScanReport()
        let manager = FileManager.default
        for path in paths {
            var isDirectory: ObjCBool = false
            guard manager.fileExists(atPath: path, isDirectory: &isDirectory) else { continue }
            if isDirectory.boolValue {
                guard let walker = manager.enumerator(atPath: path) else { continue }
                for case let relative as String in walker {
                    let full = (path as NSString).appendingPathComponent(relative)
                    var isDir: ObjCBool = false
                    guard manager.fileExists(atPath: full, isDirectory: &isDir), !isDir.boolValue else {
                        if isDir.boolValue, skippedDirectories.contains((relative as NSString).lastPathComponent) { walker.skipDescendants() }
                        continue
                    }
                    scanFile(full, display: full, into: &report, scanner: scanner)
                }
            } else {
                scanFile(path, display: path, into: &report, scanner: scanner)
            }
        }
        return report
    }

    static func scanFile(_ path: String, display: String, into report: inout ScanReport, scanner: SecretScanner) {
        let size = (try? FileManager.default.attributesOfItem(atPath: path)[.size] as? Int) ?? 0
        guard shouldScan(path: display, size: size), let data = FileManager.default.contents(atPath: path),
              let text = text(from: data) else { report.skipped += 1; return }
        report.filesScanned += 1
        report.findings += scanner.scan(text, path: display)
    }

    // MARK: Repositories

    /// Scans a repository's working tree (tracked and unignored files).
    public static func workingTree(_ repo: Repository, scanner: SecretScanner) throws -> ScanReport {
        var report = ScanReport()
        for relative in try repo.workingTreeFiles() {
            scanFile(repo.root.appendingPathComponent(relative).path, display: relative, into: &report, scanner: scanner)
        }
        return report
    }

    /// Scans what is staged for the next commit — the pre-commit hook.
    public static func staged(_ repo: Repository, scanner: SecretScanner) throws -> ScanReport {
        var report = ScanReport()
        for (path, data) in try repo.stagedFiles() {
            guard shouldScan(path: path, size: data.count), let text = text(from: data) else { report.skipped += 1; continue }
            report.filesScanned += 1
            report.findings += scanner.scan(text, path: path)
        }
        return report
    }

    /// Scans every blob ever committed on any branch, attributing each
    /// finding to the earliest commit that introduced it.
    public static func history(_ repo: Repository, scanner: SecretScanner, progress: ((Int, Int) -> Void)? = nil) throws -> ScanReport {
        var report = ScanReport()
        let blobs = try repo.historyBlobs().filter { shouldScan(path: $0.path, size: $0.size) }
        report.skipped = 0
        var done = 0
        var seenSecrets: Set<String> = []
        try repo.readBlobs(blobs) { blob, data in
            done += 1
            progress?(done, blobs.count)
            guard let text = text(from: data) else { report.skipped += 1; return }
            report.blobsScanned += 1
            for var finding in scanner.scan(text, path: blob.path) {
                // The same secret in twenty revisions of one file is one finding.
                let key = finding.secret + "\u{1f}" + blob.path
                guard !seenSecrets.contains(key) else { continue }
                seenSecrets.insert(key)
                if let who = repo.attribution(secret: finding.secret, path: blob.path) {
                    finding.commit = who.commit
                    finding.date = who.date
                    finding.author = who.author
                }
                report.findings.append(finding)
            }
        }
        return report
    }
}
