# Secrets & Key Patterns

Curated regex list for grepping beautified JS. Run with `grep -noE` per file
so matches carry line numbers. These mirror the categories used by common
open-source secret scanners — nothing here is exotic, it's the standard
"what does a leaked key look like" list.

## Cloud provider keys
- AWS access key ID: `AKIA[0-9A-Z]{16}`
- AWS secret key (needs an `aws_secret` / `secret_access_key` label nearby to be meaningful): `[A-Za-z0-9/+=]{40}`
- Google API key: `AIza[0-9A-Za-z_\-]{35}`
- Google OAuth client ID: `[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`
- Azure/Firebase-style connection strings: `AccountKey=[A-Za-z0-9+/=]{20,}`
- Firebase config object: `apiKey\s*:\s*["'][A-Za-z0-9_\-]{20,}["']`

## Source control / VCS tokens
- GitHub: `gh[pousr]_[A-Za-z0-9]{36,}`
- GitLab: `glpat-[A-Za-z0-9\-_]{20}`

## Payments
- Stripe live secret: `sk_live_[0-9a-zA-Z]{24,}`
- Stripe live publishable: `pk_live_[0-9a-zA-Z]{24,}`
- Square: `sq0[a-z]{3}-[0-9A-Za-z\-_]{22,}`

## Comms / SaaS
- Slack token: `xox[baprs]-[0-9A-Za-z\-]{10,}`
- Slack webhook: `hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+`
- Twilio: `SK[0-9a-fA-F]{32}`
- SendGrid: `SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}`
- Mailgun: `key-[0-9a-zA-Z]{32}`

## Generic credential-shaped assignments
- `(api[_-]?key|apikey|secret|token|passwd|password|auth)\s*[:=]\s*["'][A-Za-z0-9_\-\.]{16,}["']`
  (case-insensitive; this is your highest-noise pattern — filter hard, see below)
- JWT: `eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+`
- PEM private key block: `-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`

## Connection strings / basic auth
- `mongodb(\+srv)?://[^"'\s]+`
- `postgres(ql)?://[^"'\s]+`
- `mysql://[^"'\s]+`
- `redis://[^"'\s]+`
- Basic auth embedded in a URL: `https?://[^\s"'/:]+:[^\s"'/@]+@`

## Noise filters (drop matches containing these, case-insensitive)
`xxxx`, `0000`, `example`, `sample`, `changeme`, `your_api_key`, `test_key`,
`dummy`, `placeholder`, `<key>`, `insert_key_here`

## Lower-priority (mention once, don't lead with)
Google Maps browser keys (usually referrer-restricted by design), Sentry DSNs
(`https://[a-f0-9]+@[a-z0-9.]*sentry\.io/`), analytics IDs (GA/GTM/Segment) —
these are routinely public in shipped JS.
