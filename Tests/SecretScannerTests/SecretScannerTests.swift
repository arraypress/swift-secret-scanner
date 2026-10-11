//
//  SecretScannerTests.swift
//  SecretScanner
//
//  Created by David Sherlock on 2026.
//
//  Every fixture secret is built from fragments at run time and shaped like
//  the real thing without being one, so no literal token sits in this
//  file — a scanner's own test suite must not be the thing that trips a
//  push-protection scanner.
//

import Foundation
import XCTest
@testable import SecretScanner

/// Deterministic fake secrets of the right shape.
enum Fake {
    static func upper(_ n: Int, seed: Int = 1) -> String { run("ABCDEFGHJKLMNPQRSTUVWXYZ0123456789", n, seed) }
    static func alnum(_ n: Int, seed: Int = 2) -> String { run("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", n, seed) }
    static func hex(_ n: Int, seed: Int = 3) -> String { run("0123456789abcdef", n, seed) }
    static func b64(_ n: Int, seed: Int = 4) -> String { run("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/", n, seed) }
    private static func run(_ alphabet: String, _ n: Int, _ seed: Int) -> String {
        var state = UInt64(seed) &* 0x9E3779B97F4A7C15 | 1
        let chars = Array(alphabet)
        return String((0..<n).map { _ in
            state = state &* 6364136223846793005 &+ 1442695040888963407
            return chars[Int(state >> 33) % chars.count]
        })
    }
}

final class PatternTests: XCTestCase {

    /// One positive per catalogue entry, assembled from fragments.
    static let positives: [(id: String, text: String)] = [
        ("aws-access-key-id", "key = " + "AKIA" + Fake.upper(16)),
        ("aws-secret-access-key", "aws_secret_access_key = " + Fake.b64(40)),
        ("google-api-key", "AIza" + Fake.alnum(35)),
        ("google-oauth-token", "ya29." + Fake.alnum(40)),
        ("azure-storage-key", "DefaultEndpointsProtocol=https;AccountKey=" + Fake.b64(86) + "=="),
        ("digitalocean-token", "dop_v1_" + Fake.hex(64)),
        ("cloudflare-token", "CLOUDFLARE_API_TOKEN=\"" + Fake.alnum(40) + "\""),
        ("heroku-api-key", "heroku api key: " + Fake.hex(8) + "-" + Fake.hex(4, seed: 5) + "-" + Fake.hex(4, seed: 6) + "-" + Fake.hex(4, seed: 7) + "-" + Fake.hex(12, seed: 8)),
        ("github-token", "ghp_" + Fake.alnum(36)),
        ("github-fine-grained-token", "github_pat_" + Fake.alnum(22) + "_" + Fake.alnum(59)),
        ("gitlab-token", "glpat-" + Fake.alnum(20)),
        ("npm-token", "npm_" + Fake.alnum(36)),
        ("pypi-token", "pypi-AgEIcHlwaS5vcmc" + Fake.alnum(60)),
        ("huggingface-token", "hf_" + Fake.alnum(34)),
        ("databricks-token", "dapi" + Fake.hex(32)),
        ("doppler-token", "dp.pt." + Fake.alnum(43)),
        ("planetscale-token", "pscale_tkn_" + Fake.alnum(43)),
        ("postman-key", "PMAK-" + Fake.hex(24) + "-" + Fake.hex(34, seed: 9)),
        ("supabase-token", "sbp_" + Fake.hex(40)),
        ("linear-key", "lin_api_" + Fake.alnum(40)),
        ("notion-token", "secret_" + Fake.alnum(43)),
        ("anthropic-key", "sk-ant-api03-" + Fake.alnum(80)),
        ("openai-key", "sk-proj-" + Fake.alnum(48)),
        ("stripe-live-key", "sk_live_" + Fake.alnum(24)),
        ("stripe-test-key", "sk_test_" + Fake.alnum(24)),
        ("square-token", "sq0atp-" + Fake.alnum(22)),
        ("shopify-token", "shpat_" + Fake.hex(32)),
        ("slack-token", "xoxb-" + "1234567890-" + Fake.alnum(24)),
        ("slack-webhook", "https://hooks.slack.com/services/T" + Fake.upper(8) + "/B" + Fake.upper(10) + "/" + Fake.alnum(24)),
        ("discord-bot-token", "M" + Fake.alnum(23) + "." + Fake.alnum(6) + "." + Fake.alnum(27)),
        ("telegram-bot-token", "1234567890:AA" + Fake.alnum(33)),
        ("sendgrid-key", "SG." + Fake.alnum(22) + "." + Fake.alnum(43)),
        ("twilio-key", "SK" + Fake.hex(32)),
        ("mailgun-key", "key-" + Fake.hex(32)),
        ("private-key", "-----BEGIN RSA PRIVATE KEY-----\n" + Fake.b64(64) + "\n-----END RSA PRIVATE KEY-----"),
        ("age-secret-key", "AGE-SECRET-KEY-1" + Fake.upper(58)),
        ("jwt", "eyJ" + Fake.alnum(20) + ".eyJ" + Fake.alnum(40) + "." + Fake.alnum(43)),
        ("url-basic-auth", "postgres://app:" + Fake.alnum(16) + "@db.internal:5432/app"),
        ("app-specific-password", "notarytool password: " + "abcd-efgh-ijkl-mnop"),
        ("generic-assignment", "let apiKey = \"" + Fake.alnum(32) + "\""),
        ("env-secret", "STRIPE_WEBHOOK_SECRET=" + Fake.alnum(40)),
    ]

    func testEveryCatalogueEntryHasAPositiveAndFindsIt() {
        let scanner = SecretScanner()
        for pattern in Patterns.catalogue {
            guard let sample = Self.positives.first(where: { $0.id == pattern.id }) else {
                XCTFail("no positive fixture for \(pattern.id)"); continue
            }
            let found = scanner.scan(sample.text)
            XCTAssertTrue(found.contains { $0.pattern == pattern.id }, "\(pattern.id) not found in: \(sample.text.prefix(60)) — got \(found.map(\.pattern))")
        }
    }

    func testDecoysAreQuiet() {
        // Hashes, ids, versions, placeholders, references to secrets — none are secrets.
        let decoys = [
            "sha256: " + Fake.hex(64),
            "git commit " + Fake.hex(40),
            "id: 123e4567-e89b-12d3-a456-426614174000",
            "version = \"1.2.3\"",
            "password = \"${DB_PASSWORD}\"",
            "token = process.env.API_TOKEN",
            "api_key: <your-api-key>",
            "secret = 'changeme'",
            "PASSWORD=xxxxxxxxxxxx",
            "let token = \"placeholder\"",
            "STRIPE_SECRET_KEY=sk_test_example",
            "The password is required.",
            "ERROR-CODE-4042 in module",
            "https://example.com/path?x=1",
            "let statusCode = 200",
            "data:image/png;base64," + Fake.b64(200),
            // Code, not values: what the generic rules meet in real source.
            "let token = SecurePrompt.read(label)",
            "secret = Bundle.main.infoDictionary",
            "password = getPassword()",
            "apiKey = config.apiKey",
            "let accessToken = readFromKeychain",
            "TOKEN=$(cat token.txt)",
            "api_key: self.apiKey,",
            // …and the shapes the first fleet scan tripped on.
            "configuration.accessToken = token?.nilIfEmpty",
            "/// see ``download(variant:from:token:endpoint:progress:)``",
            "Configuration(accessKey: \"not-a-real-key\")",
            "\"continuationCommand\": { \"token\": \"REPLYTOKEN1\" }",
            "let password = \"fakepassword123\"",
            "var token: String? = startToken",
        ]
        let scanner = SecretScanner()
        for decoy in decoys {
            let found = scanner.scan(decoy)
            XCTAssertTrue(found.isEmpty, "decoy flagged: \(decoy.prefix(50)) → \(found.map(\.pattern))")
        }
    }

    func testAnthropicKeysAreNotAlsoOpenAIKeys() {
        let found = SecretScanner().scan("sk-ant-api03-" + Fake.alnum(80))
        XCTAssertEqual(found.map(\.pattern), ["anthropic-key"])
    }

    func testFindingsCarryPositionMaskAndContext() {
        let key = "ghp_" + Fake.alnum(36)
        let text = "first line\nlet token = \"\(key)\" // rotate\n"
        let f = SecretScanner().scan(text, path: "Sources/App.swift")
        XCTAssertEqual(f.count, 1)
        XCTAssertEqual(f[0].line, 2)
        XCTAssertEqual(f[0].column, 14)
        XCTAssertEqual(f[0].file, "Sources/App.swift")
        XCTAssertEqual(f[0].masked, "ghp_…" + String(key.suffix(2)))
        XCTAssertFalse(f[0].context.contains(key), "context must be masked")
        XCTAssertTrue(f[0].context.contains("ghp_…"))
    }
}

final class AllowlistTests: XCTestCase {

    func testIgnoreFileParsesEveryKind() {
        let list = Allowlist.parse("""
            # comment
            Tests/**
            *.example
            value:sk_live_knownpublic
            regex:^ghp_TEST
            pattern:env-secret
            """)
        XCTAssertEqual(list.paths, ["Tests/**", "*.example"])
        XCTAssertTrue(list.ignores(path: "Tests/Fixtures/keys.txt"))
        XCTAssertTrue(list.ignores(path: "config/app.example"))
        XCTAssertFalse(list.ignores(path: "Sources/App.swift"))
        XCTAssertTrue(list.ignores(secret: "sk_live_knownpublic"))
        XCTAssertTrue(list.ignores(secret: "ghp_TESTabc"))
        XCTAssertEqual(list.disabled, ["env-secret"])
    }

    func testAllowlistSilencesTheScanner() {
        let key = "sk_live_" + Fake.alnum(24)
        var scanner = SecretScanner()
        XCTAssertEqual(scanner.scan(key).count, 1)
        scanner.allowlist.values.insert(key)
        XCTAssertEqual(scanner.scan(key).count, 0)
        XCTAssertEqual(SecretScanner().scan("key = \(key) // secrets:ignore").count, 0)
        XCTAssertEqual(SecretScanner(allowlist: Allowlist(paths: ["Fixtures/*"])).scan(key, path: "Fixtures/a.txt").count, 0)
        XCTAssertEqual(SecretScanner(generic: false).scan("let apiKey = \"" + Fake.alnum(32) + "\"").count, 0)
        XCTAssertEqual(SecretScanner(minimumSeverity: .high).scan("sk_test_" + Fake.alnum(24)).count, 0)
    }
}

final class EntropyTests: XCTestCase {
    func testEntropySeparatesTokensFromWords() {
        XCTAssertGreaterThan(Entropy.bits(Fake.alnum(40)), 4.0)
        XCTAssertLessThan(Entropy.bits("aaaaaaaaaaaaaaaa"), 0.01)
        XCTAssertLessThan(Entropy.bits("passwordpassword"), 3.0)
        XCTAssertTrue(Placeholders.matches("your_api_key_here"))
        XCTAssertTrue(Placeholders.matches("${SECRET}"))
        XCTAssertTrue(Placeholders.matches("00000000"))
        XCTAssertFalse(Placeholders.matches(Fake.alnum(24)))
    }
}

final class ScanTests: XCTestCase {

    private var scratch: URL!

    override func setUpWithError() throws {
        scratch = FileManager.default.temporaryDirectory.appendingPathComponent("secret-scanner-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: scratch)
    }

    private func write(_ relative: String, _ text: String) throws {
        let url = scratch.appendingPathComponent(relative)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try text.write(to: url, atomically: true, encoding: .utf8)
    }

    @discardableResult
    private func git(_ args: [String]) throws -> String {
        try Git.run(["-c", "user.name=Test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false"] + args, in: scratch.path)
    }

    func testSkipsWhatIsNotSource() {
        XCTAssertFalse(Scan.shouldScan(path: "Package.resolved"))
        XCTAssertFalse(Scan.shouldScan(path: "node_modules/x/index.js"))
        XCTAssertFalse(Scan.shouldScan(path: ".build/debug/app"))
        XCTAssertFalse(Scan.shouldScan(path: "assets/logo.png"))
        XCTAssertFalse(Scan.shouldScan(path: "Sources/big.swift", size: 10_000_000))
        XCTAssertTrue(Scan.shouldScan(path: "Sources/App.swift", size: 1000))
        XCTAssertNil(Scan.text(from: Data([0x89, 0x50, 0x4E, 0x47, 0x00, 0x01])))
        XCTAssertNotNil(Scan.text(from: Data("hello".utf8)))
    }

    func testFilesAndFoldersAreWalked() throws {
        let key = "AKIA" + Fake.upper(16)
        try write("Sources/Config.swift", "let region = \"eu-west-1\"\nlet accessKey = \"\(key)\"\n")
        try write("node_modules/dep/index.js", "const k = \"\(key)\"")
        try write("Package.resolved", "{\"checksum\": \"\(key)\"}")
        let report = try Scan.files([scratch.path], scanner: SecretScanner())
        XCTAssertEqual(report.findings.count, 1)
        XCTAssertEqual(report.findings[0].line, 2)
        XCTAssertTrue(report.findings[0].file?.hasSuffix("Sources/Config.swift") ?? false)
    }

    func testHistoryFindsASecretThatWasDeleted() throws {
        let key = "ghp_" + Fake.alnum(36)
        try git(["init", "-q", "-b", "main"])
        try write("README.md", "# App\n")
        try git(["add", "."]); try git(["commit", "-q", "-m", "start"])
        try write(".env", "GITHUB_TOKEN=\(key)\n")
        try git(["add", "."]); try git(["commit", "-q", "-m", "oops"])
        try FileManager.default.removeItem(at: scratch.appendingPathComponent(".env"))
        try git(["add", "-A"]); try git(["commit", "-q", "-m", "remove env"])
        try write("Sources/App.swift", "print(\"hello\")\n")

        let repo = try XCTUnwrap(Repository.find(from: scratch.path))
        let scanner = SecretScanner()

        // The working tree is clean of it…
        let tree = try Scan.workingTree(repo, scanner: scanner)
        XCTAssertTrue(tree.findings.isEmpty, "\(tree.findings)")
        XCTAssertEqual(tree.filesScanned, 2)

        // …and history is not.
        let history = try Scan.history(repo, scanner: scanner)
        XCTAssertEqual(history.findings.count, 1, "\(history.findings)")
        let f = history.findings[0]
        XCTAssertEqual(f.pattern, "github-token")
        XCTAssertEqual(f.file, ".env")
        XCTAssertNotNil(f.commit)
        XCTAssertEqual(f.author, "Test")
        XCTAssertGreaterThan(history.blobsScanned, 0)

        // Staged: a secret about to be committed is caught before it is.
        try write("Sources/Keys.swift", "let stripe = \"sk_live_\(Fake.alnum(24))\"\n")
        try git(["add", "Sources/Keys.swift"])
        let staged = try Scan.staged(repo, scanner: scanner)
        XCTAssertEqual(staged.findings.map(\.pattern), ["stripe-live-key"])
    }
}

/// Ground truth: a corpus of planted secrets and decoys, scored for recall
/// and precision. The numbers in the README come from here.
final class GroundTruthTests: XCTestCase {

    func testRecallAndPrecisionOnTheCorpus() {
        let planted = PatternTests.positives
        let decoys = [
            "sha256 " + Fake.hex(64, seed: 11), "commit " + Fake.hex(40, seed: 12),
            "uuid 123e4567-e89b-12d3-a456-426614174000", "version = \"2.0.1\"",
            "password = \"${DB_PASSWORD}\"", "token = os.environ[\"TOKEN\"]", "api_key: <your-api-key>",
            "secret = 'changeme'", "PASSWORD=xxxxxxxxxxxx", "let token = \"placeholder\"",
            "The password field is required", "https://example.com/a/b?c=1", "let statusCode = 200",
            "data:image/png;base64," + Fake.b64(120, seed: 13), "AKIAEXAMPLE", "sk_test_example",
            "ghp_short", "-----BEGIN CERTIFICATE-----", "xoxb-not", "SG.short",
        ]
        let scanner = SecretScanner()
        var hits = 0, wrongKind = 0
        for p in planted {
            let found = scanner.scan(p.text)
            if found.contains(where: { $0.pattern == p.id }) { hits += 1 } else if !found.isEmpty { wrongKind += 1 }
        }
        var falseAlarms = 0
        for d in decoys where !scanner.scan(d).isEmpty { falseAlarms += 1 }
        let recall = Double(hits) / Double(planted.count)
        let precision = Double(hits) / Double(hits + falseAlarms)
        XCTAssertEqual(hits, planted.count, "recall \(recall): \(wrongKind) found as the wrong kind")
        XCTAssertEqual(falseAlarms, 0, "precision \(precision)")
    }

    /// The code-shape gate, pinned rule by rule: calls, dotted paths,
    /// selector colons and bare digit-free words are code; a URL's colon
    /// and a digit-bearing token are not.
    func testLooksLikeCodeRules() {
        XCTAssertTrue(Placeholders.looksLikeCode("SecurePrompt.read(label)"))
        XCTAssertTrue(Placeholders.looksLikeCode("config.apiKey"))
        XCTAssertTrue(Placeholders.looksLikeCode("token:endpoint:"))
        XCTAssertTrue(Placeholders.looksLikeCode("READ_FROM_KEYCHAIN"))
        XCTAssertFalse(Placeholders.looksLikeCode("https://example.com/a"))
        XCTAssertFalse(Placeholders.looksLikeCode("ghp_9a8B7c6D5e4F3g2H1i0J"))
    }
}

/// Three false alarms from the 2026-10-11 fleet sweep, each pinned both
/// ways: the stand-in goes quiet, a real-shaped secret is still found.
final class SweepFalseAlarmTests: XCTestCase {

    func testAnEllipsisIsAPlaceholder() {
        let key = "secret" + "="
        XCTAssertEqual(SecretScanner().scan("let uri = \"otpauth://totp/a?\(key)…&issuer=ACME\"").count, 0)
        XCTAssertEqual(SecretScanner().scan("let apiKey = \"" + Fake.alnum(32) + "\"").count, 1,
                       "a real-shaped value is still a finding")
    }

    func testURLCredentialsDoNotRunAcrossJSON() {
        let json = #"{"repository":{"url":"git+https://github.com/x/left-pad.git"},"_npmOperationalInternal":{"host":"s3://npm-registry-packages"},"_id":"left-pad@1.3.0"}"#
        XCTAssertEqual(SecretScanner().scan(json).filter { $0.pattern == "url-basic-auth" }.count, 0)
        let password = Fake.alnum(14, seed: 9)
        let url = "https://" + "deploy:" + password + "@example.org/repo.git"
        let found = SecretScanner().scan("remote = \(url)").filter { $0.pattern == "url-basic-auth" }
        XCTAssertEqual(found.count, 1, "a real user:password@host is still caught")
    }

    func testAWSDocumentedExamplesAreNotFindings() {
        let example = "AKIA" + "IOSFODNN7" + "EXAMPLE"
        XCTAssertEqual(SecretScanner().scan("aws key \(example) ok").count, 0)
        XCTAssertEqual(SecretScanner().scan("aws key AKIA\(Fake.upper(16, seed: 11)) ok").count, 1)
    }
}
