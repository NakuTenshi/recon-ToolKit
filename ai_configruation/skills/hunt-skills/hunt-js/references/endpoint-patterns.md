# Endpoint & Path Discovery Patterns

Goal: pull every URL/path the app talks to, then rank by how interesting it
looks. This is the same idea as classic JS-linkfinding regexes, adapted for a
prose report instead of a raw URL dump.

## Extraction patterns
- Absolute URLs: `https?://[^\s"'<>\\]+`
- Relative/absolute paths in quotes (broad net, expect noise):
  `["'](/[a-zA-Z0-9_\-./]{2,}?)["']`
- Fetch/XHR/axios call targets:
  - `fetch\(\s*["'\`]([^"'\`]+)`
  - `axios\.(get|post|put|delete|patch)\(\s*["'\`]([^"'\`]+)`
  - `\.open\(\s*["'][A-Z]+["']\s*,\s*["'\`]([^"'\`]+)` (XHR)
  - `\$\.(ajax|get|post)\(\s*\{?\s*url\s*:\s*["'\`]([^"'\`]+)` (jQuery)
- GraphQL:
  - `(query|mutation)\s+[A-Za-z0-9_]+\s*[\{\(]`
  - literal `/graphql` path mentions
- WebSocket: `wss?://[^\s"'<>\\]+`

## Interesting-keyword ranking (surface these first)
`admin`, `internal`, `debug`, `staging`, `dev`, `v1`, `v2`, `v3`, `swagger`,
`openapi`, `graphql`, `config`, `backup`, `export`, `import`, `.git`, `.env`,
`upload`, `download`, `reset`, `impersonate`, `sudo`, `become`, `test`,
`sandbox`, `beta`, `private`, `secure`, `token`, `key`, `password`, `console`,
`actuator`, `health`, `metrics`, `status`

## Lower priority
Plain public-looking REST/CDN/static-asset paths, well-known third-party SDK
endpoints (analytics, ad networks, font/CDN hosts) — list them but don't lead
with them.

## Noise to drop
MIME types and file extensions matched as if they were paths
(`.png`/`.css`/`.woff` etc. with no other path segments), data: URIs,
source-map comments (`//# sourceMappingURL=...`) unless the user is
specifically hunting for exposed source maps.
