# Swift Secret Scanner

Find secrets in text, files and git history — deterministically, on-device, with no model in the loop.

```swift
import SecretScanner

let scanner = SecretScanner()
for finding in scanner.scan(text, path: "Sources/App.swift") {
    print(finding.severity, finding.name, finding.masked, "line", finding.line)
}

// A repository: what is there now, what is staged, and everything ever committed.
let repo = Repository.find(from: ".")!
let tree    = try Scan.workingTree(repo, scanner: scanner)
let staged  = try Scan.staged(repo, scanner: scanner)
let history = try Scan.history(repo, scanner: scanner)   // attributes each secret to the commit that introduced it
```

## Features

- 🔑 **41 patterns** — AWS, Google, Azure, DigitalOcean, Cloudflare, Heroku; GitHub, GitLab, npm, PyPI, Hugging Face, Databricks, Doppler, PlanetScale, Postman, Supabase, Linear, Notion; Anthropic, OpenAI; Stripe (live and test), Square, Shopify; Slack tokens and webhooks, Discord, Telegram, SendGrid, Twilio, Mailgun; private-key blocks, age keys, JWTs, credentials in URLs, Apple app-specific passwords
- 🧮 **Generic rules with judgement** — `password = …`, `SOME_TOKEN=…` lines are reported only when the value has real entropy and is not a placeholder (`${VAR}`, `changeme`, `<your-key>`, `xxxx`, `process.env…`)
- 🕰️ **History, not just the tree** — every blob on every branch, read through one `git cat-file --batch` per batch; each finding attributed to the earliest commit, author and date
- ✋ **Staged** — what is about to be committed, for a pre-commit hook
- 🙈 **Masked by default** — findings carry the secret for verification and a masked form (`ghp_…Q7`) for everything that prints
- 🧹 **Skips what is not source** — lock files, build products, `node_modules`, binaries, files over 5 MB
- 📝 **`.secretsignore`** — paths, exact values, value regexes, whole patterns; `secrets:ignore` on a line
- 🎯 **Deterministic** — the same text gives the same findings on every run and every machine, so a scan can gate a release
- 📦 **Zero dependencies** — Foundation and the git binary

## Measured

Every pattern has a positive fixture assembled from fragments at test time (no literal token in the repository), and twenty decoys — hashes, UUIDs, versions, placeholders, references to environment variables, a base64 image, look-alikes that are too short. On that corpus: **recall 41/41, precision 41/41**. The generic rules are the ones that will cry wolf on real code; that is what the allowlist is for.

**Fleet sweep, 2026-10-11** — 300 repositories scanned in a release gate. Three false-alarm
shapes fixed in 0.2.1 (0.2.0 was tagged by mistake on the 0.1.1 code), each pinned both ways (the stand-in goes quiet, a real-shaped secret is
still found): a written-out `secret=…` placeholder; credentials-in-a-URL matching across JSON
quotes in a recorded API response; AWS's published `…EXAMPLE` keys. What remains is genuine test
vectors (RFC TOTP secrets, fake Stripe/Slack keys in a detector's own tests) — those belong in a
`.secretsignore`.

## Requirements

- macOS 14+, Swift 6, `git` on the path for the repository walkers.

## License

MIT — see LICENSE.
