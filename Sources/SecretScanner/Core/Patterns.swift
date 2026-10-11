//
//  Patterns.swift
//  SecretScanner
//
//  Created by David Sherlock on 2026.
//
//  The catalogue. Every entry is a regex with one capture group holding the
//  secret, a severity, and an optional check on the captured value. Provider
//  shapes are taken from the providers' own documentation; the generic rules
//  at the end catch `password = …` and `SOME_TOKEN=…` lines and are the only
//  ones that consult entropy and the placeholder list.
//

import Foundation

/// One shape of secret.
public struct SecretPattern: Sendable {
    /// A stable slug: `aws-access-key-id`.
    public let id: String
    /// The name for people: "AWS access key ID".
    public let name: String
    /// How bad a leak of one of these is.
    public let severity: Severity
    let regex: NSRegularExpression
    /// Which capture group holds the secret.
    let group: Int
    /// A last check on the captured value; `nil` accepts every match.
    let verify: (@Sendable (String) -> Bool)?
    /// Whether the generic rules apply — these are the ones an allowlist
    /// most often needs to quiet.
    public let generic: Bool

    init(_ id: String, _ name: String, _ severity: Severity, _ pattern: String, group: Int = 1,
         options: NSRegularExpression.Options = [], generic: Bool = false,
         verify: (@Sendable (String) -> Bool)? = nil) {
        self.id = id
        self.name = name
        self.severity = severity
        // Patterns are literals below; a typo is a programming error, not a runtime one.
        self.regex = try! NSRegularExpression(pattern: pattern, options: options)
        self.group = group
        self.verify = verify
        self.generic = generic
    }
}

/// The catalogue of secret shapes the scanner knows.
public enum Patterns {

    /// Rejects placeholders and low-entropy values for the generic rules.
    static let credible: @Sendable (String) -> Bool = { value in
        !Placeholders.matches(value) && Entropy.bits(value) >= 3.0
    }

    /// Hex of a length that is a hash, not a secret, unless a pattern says otherwise.
    static let notPlainHex: @Sendable (String) -> Bool = { value in
        !(value.count >= 32 && value.allSatisfy { $0.isHexDigit })
    }

    /// Every pattern, tried in this order. Ids are stable; the `patterns` verb lists them.
    public static let catalogue: [SecretPattern] = [
        // ── Cloud ───────────────────────────────────────────────────────
        SecretPattern("aws-access-key-id", "AWS access key ID", .high, #"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"#),
        SecretPattern("aws-secret-access-key", "AWS secret access key", .high,
                      #"(?i)aws[_-]?secret[_-]?access[_-]?key["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})\b"#),
        SecretPattern("google-api-key", "Google API key", .high, #"\b(AIza[0-9A-Za-z_-]{35})\b"#),
        SecretPattern("google-oauth-token", "Google OAuth access token", .high, #"\b(ya29\.[0-9A-Za-z_-]{20,})\b"#),
        SecretPattern("azure-storage-key", "Azure storage account key", .high, #"AccountKey=([A-Za-z0-9+/=]{86,90})"#),
        SecretPattern("digitalocean-token", "DigitalOcean token", .high, #"\b(do[po]_v1_[0-9a-f]{64})\b"#),
        SecretPattern("cloudflare-token", "Cloudflare API token", .medium,
                      #"(?i)cloudflare[^\n]{0,40}?["']?([A-Za-z0-9_-]{40})\b"#, verify: credible),
        SecretPattern("heroku-api-key", "Heroku API key", .medium,
                      #"(?i)heroku[^\n]{0,40}?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b"#),

        // ── Source hosting and packages ─────────────────────────────────
        SecretPattern("github-token", "GitHub token", .high, #"\b(gh[pousr]_[A-Za-z0-9]{36,})\b"#),
        SecretPattern("github-fine-grained-token", "GitHub fine-grained token", .high, #"\b(github_pat_[A-Za-z0-9_]{60,})\b"#),
        SecretPattern("gitlab-token", "GitLab token", .high, #"\b(glpat-[A-Za-z0-9_-]{20,})\b"#),
        SecretPattern("npm-token", "npm token", .high, #"\b(npm_[A-Za-z0-9]{36})\b"#),
        SecretPattern("pypi-token", "PyPI token", .high, #"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{20,})\b"#),
        SecretPattern("huggingface-token", "Hugging Face token", .high, #"\b(hf_[A-Za-z0-9]{30,})\b"#),
        SecretPattern("databricks-token", "Databricks token", .high, #"\b(dapi[0-9a-f]{32})\b"#),
        SecretPattern("doppler-token", "Doppler token", .high, #"\b(dp\.pt\.[A-Za-z0-9]{40,})\b"#),
        SecretPattern("planetscale-token", "PlanetScale token", .high, #"\b(pscale_(?:tkn|pw|oauth)_[A-Za-z0-9_.-]{30,})\b"#),
        SecretPattern("postman-key", "Postman API key", .high, #"\b(PMAK-[0-9a-f]{24}-[0-9a-f]{34})\b"#),
        SecretPattern("supabase-token", "Supabase token", .high, #"\b(sbp_[0-9a-f]{40})\b"#),
        SecretPattern("linear-key", "Linear API key", .high, #"\b(lin_api_[A-Za-z0-9]{40})\b"#),
        SecretPattern("notion-token", "Notion integration token", .medium, #"\b((?:secret|ntn)_[A-Za-z0-9]{43})\b"#),

        // ── AI providers ────────────────────────────────────────────────
        SecretPattern("anthropic-key", "Anthropic API key", .high, #"\b(sk-ant-[A-Za-z0-9_-]{20,})\b"#),
        SecretPattern("openai-key", "OpenAI API key", .high, #"\b(sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,})\b"#,
                      verify: { !$0.hasPrefix("sk-ant-") }),

        // ── Payments and commerce ───────────────────────────────────────
        SecretPattern("stripe-live-key", "Stripe live secret key", .high, #"\b((?:sk|rk)_live_[A-Za-z0-9]{16,})\b"#),
        SecretPattern("stripe-test-key", "Stripe test secret key", .medium, #"\b((?:sk|rk)_test_[A-Za-z0-9]{16,})\b"#),
        SecretPattern("square-token", "Square access token", .high, #"\b(sq0(?:atp|csp)-[A-Za-z0-9_-]{20,})\b"#),
        SecretPattern("shopify-token", "Shopify token", .high, #"\b(shp(?:at|ss|ca|pa)_[0-9a-fA-F]{32})\b"#),

        // ── Messaging and mail ──────────────────────────────────────────
        SecretPattern("slack-token", "Slack token", .high, #"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"#),
        SecretPattern("slack-webhook", "Slack webhook", .high,
                      #"(https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+)"#),
        SecretPattern("discord-bot-token", "Discord bot token", .medium,
                      #"\b([MN][A-Za-z0-9_-]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,})\b"#),
        SecretPattern("telegram-bot-token", "Telegram bot token", .high, #"\b(\d{8,10}:AA[A-Za-z0-9_-]{33})\b"#),
        SecretPattern("sendgrid-key", "SendGrid API key", .high, #"\b(SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})\b"#),
        SecretPattern("twilio-key", "Twilio API key", .medium, #"\b(SK[0-9a-f]{32})\b"#),
        SecretPattern("mailgun-key", "Mailgun API key", .medium, #"\b(key-[0-9a-f]{32})\b"#),

        // ── Keys, tokens and credentials by shape ───────────────────────
        SecretPattern("private-key", "Private key block", .high,
                      #"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)"#),
        SecretPattern("age-secret-key", "age secret key", .high, #"\b(AGE-SECRET-KEY-1[0-9A-Z]{58})\b"#),
        SecretPattern("jwt", "JSON Web Token", .medium,
                      #"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"#),
        SecretPattern("url-basic-auth", "Credentials in a URL", .high,
                      // Quotes, brackets, braces and commas cannot appear unescaped in
                      // a URL's user info; allowing them let a match run across JSON
                      // (a recorded npm response) from one string into the next.
                      #"(?i)\b[a-z][a-z0-9+.-]*://([^\s:/@"'<>{}\[\],]+:[^\s@/"'<>{}\[\],]{4,})@[^\s/"']+"#,
                      verify: { !Placeholders.matches($0.split(separator: ":").last.map(String.init) ?? "") }),
        SecretPattern("app-specific-password", "Apple app-specific password", .medium,
                      #"(?i)(?:password|pass|pwd)[^\n]{0,20}?([a-z]{4}-[a-z]{4}-[a-z]{4}-[a-z]{4})\b"#),

        // ── Generic: an assignment whose name says secret and whose value looks like one ──
        SecretPattern("generic-assignment", "Secret assigned in code", .medium,
                      #"(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|auth[_-]?token|access[_-]?token|access[_-]?key|private[_-]?key|client[_-]?secret|secret[_-]?key|signing[_-]?key)["']?\s*[:=]\s*["']?([^\s"'`,;)]{8,})"#,
                      generic: true, verify: { credible($0) && notPlainHex($0) }),
        SecretPattern("env-secret", "Secret in an environment line", .medium,
                      #"(?m)^\s*(?:export\s+)?[A-Z][A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|APIKEY|PRIVATE_KEY|ACCESS_KEY|SIGNING_KEY)[A-Z0-9_]*\s*=\s*["']?([^\s"'#]{8,})"#,
                      generic: true, verify: { credible($0) && notPlainHex($0) }),
    ]

    /// The pattern with this id, or `nil`.
    public static func named(_ id: String) -> SecretPattern? {
        catalogue.first { $0.id == id }
    }
}
