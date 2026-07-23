---
name: hunt-js
description: Hunt JavaScript security issues — secrets, API endpoints, DOM XSS, and vulns. Trigger when user provides JS files, JS URLs, or wants JS analyzed for security. Covers bug bounty recon, code audit, and vulnerability hunting.
---

# JS Bug Scanner & Security Auditor

Analyzes JavaScript source for bug-bounty-relevant signals: **leaked secrets**, **interesting endpoints**, **DOM XSS patterns**, and **full vulnerability analysis**. Produces actionable findings.

This is a recon and triage tool: it narrows down where to look by hand. Always clarify findings as confirmed vs heuristic.

---

## Step 0: Respect scope

If a `CLAUDE.md`, `scope.md`, or similar scope file exists, read it first. Never download JS from out-of-scope hosts. Skip ambiguous URLs and mention they were skipped.

---

## Step 1: Normalize input

Turn input into a flat list of local `.js`/`.mjs` files:

- **Single file** → use directly.
- **Directory** → recurse, collect `.js`/`.mjs`, skip `node_modules`/`vendor`/`dist` bundles of well-known libraries unless asked, skip files over ~2MB unless asked.
- **List of URLs** → download each with realistic User-Agent, follow redirects, ~15s timeout, small delay between requests. Save into scratch dir with path-derived filenames.
- **Mixed** → handle all in the same pass.

---

## Step 2: Beautify before scanning

Use `jsbeautifier` (pip) or `js-beautify` (npm) on each file into a scratch copy. Scan and report line numbers against the *beautified* copy.

If a file looks packed/obfuscated (giant hex arrays, `eval(function(p,a,c,k,e,...` packers, single-letter everything), flag it as "obfuscated, worth a manual look" and move on.

---

## Step 3: Secrets & key pass

Search for leaked credentials using patterns:

- Cloud provider keys (AWS, GCP, Azure)
- JWTs and tokens
- Private key blocks
- DB connection strings
- Generic `key=`/`token=`/`secret=` assignments
- Basic-auth-in-URL patterns
- GitHub tokens, OAuth secrets

**Filter noise before reporting:**
- Placeholder values (`xxxx`, `0000`, `example`, `test`, `YOUR_API_KEY`, `sample`, `changeme`)
- Well-known public keys (browser-restricted Google Maps keys, Sentry DSNs) — mention as low priority
- Boilerplate from bundled libraries vs app code

---

## Step 4: Endpoint & path pass

Extract from JS:

- Absolute URLs (`https://...`)
- Relative paths in `fetch`/`axios`/`XHR`/jQuery `$.ajax`
- GraphQL operation strings
- WebSocket URLs
- API base paths and versioning

**Rank by interesting keywords:**
- Admin/internal: `admin`, `internal`, `debug`, `staging`, `internal-api`, `beta`
- Sensitive operations: `upload`, `reset`, `impersonate`, `export`, `backup`, `config`
- Sensitive files: `.git`, `.env`, `swagger`, `graphql`
- Versioning: `v1`, `v2`, `v3`

---

## Step 5: DOM XSS sink/source pass

Flag dangerous sinks:
- `innerHTML`, `outerHTML`, `insertAdjacentHTML`
- `document.write`, `eval`, `Function()`
- jQuery `.html()`, `.append()`
- React `dangerouslySetInnerHTML`
- Vue `v-html`

Flag tainted sources:
- `location.hash`, `location.search`, `location.href`
- `document.referrer`, `window.name`
- `postMessage` event data
- `localStorage`/`sessionStorage` reads
- URL parameters and query strings

**Heuristic detection:** If source and sink appear in same function or within ~15 lines, elevate as DOM XSS candidate. Always label as heuristic needing manual confirmation.

---

## Step 6: Full vulnerability analysis

For comprehensive code audits, check for:

### XSS
- Reflected, Stored, DOM, Mutation XSS
- Template injection (React, Vue, Angular)
- Dangerous sinks: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `dangerouslySetInnerHTML`, `document.write`, `eval`, `new Function`

### Prototype Pollution
- `Object.assign`, `_.merge`, deep merge utilities
- Recursive merge functions, JSON merge operations
- Check if attacker controls keys

### Open Redirect
- `location.href`, `window.location`
- `router.push`, redirect handlers
- Any URL from user input

### Authentication Issues
- Login logic, JWT validation, session handling
- Password reset, MFA, magic links
- Look for: missing validation, weak tokens, predictable tokens, missing expiration

### Authorization Issues
- Role checks, permission checks, ownership checks
- Client-side only restrictions, missing server validation
- IDOR patterns

### SSRF
- URL fetching, proxy endpoints, webhook functionality
- Image/file importers
- Dangerous APIs: `fetch()`, `axios()`, `request()`, `got()`

### Command Injection
- `child_process.exec`, `spawn`, `execSync`, `shelljs`
- Check if user input reaches commands

### Path Traversal
- `fs.readFile`, `fs.writeFile`, file uploads
- Look for `../` and path normalization bypasses

### File Upload
- Extension/MIME validation, storage location, filename handling
- Arbitrary upload → RCE chains

### Deserialization
- JSON/YAML parsing, pickle-like libraries
- Serialization frameworks

### ReDoS
- Complex regex, nested quantifiers
- Catastrophic backtracking patterns

### CSRF
- State-changing requests without CSRF protections
- Weak SameSite configurations

### CORS
- Wildcard origins, reflection-based origins
- Credential misconfigurations

### Secrets Exposure
- API keys, tokens, AWS/GCP/Azure credentials
- GitHub tokens, JWT secrets, OAuth secrets

### JWT Issues
- Signature validation, algorithm confusion
- Weak secrets, missing expiration validation

### Electron Security
- `nodeIntegration`, `contextIsolation`
- Preload scripts, IPC handlers

### Browser Extension Security
- Message passing, content/background scripts
- Permissions, `web_accessible_resources`

### Dependency Risks
- Dangerous packages, known risky libraries
- Supply chain concerns

---

## Step 7: Dedup & prioritize

Merge duplicate hits across files. Order by realistic impact:

1. Live-looking secrets (highest priority)
2. High-value endpoints (admin, debug, internal)
3. XSS candidates (confirmed then heuristic)
4. Auth/authorization issues
5. Other vulnerability classes
6. Informational findings

---

## Step 8: Write the report

One flowing paragraph per category (prose, not tables). Reference findings as `filename:line` — never raw matched code unless explicitly asked.

Close with a "worth digging into first" call-out (2-3 items max). If a category is empty, say so in one line.

### Finding Format

**Title**: Clear vulnerability name
**Severity**: Critical / High / Medium / Low / Info
**Location**: File and line number
**Explanation**: Why it is vulnerable
**Exploitation Scenario**: Realistic attack path
**Proof of Concept**: Only if enough evidence exists
**Remediation**: Concrete fix
**Confidence**: High / Medium / Low

---

## Step 9: Save findings to target directory

After analyzing each JS file, create a summary in the asset's folder:

```
~/targets/<program>/<asset>/ai_js_analyz/<js_name>_summary.md
```

**File structure:**

```markdown
# <filename>.js Analysis

**Date**: YYYY-MM-DD
**Source**: <URL or file path>

## Purpose
Brief description of what this JS file does (e.g., "Handles user authentication flows", "Admin dashboard UI logic", "API client for payment processing").

## Interesting Findings
- Most notable discoveries ranked by impact
- Include `filename:line` references

## Secrets
- Any leaked credentials found

## Endpoints
- API paths, URLs, WebSocket connections

## XSS Candidates
- Sink/source proximity matches

## Other Vulnerabilities
- Auth issues, IDOR, SSRF, etc.

## Notes
Any obfuscation, size concerns, or items needing manual review.
```

**Rules:**
- One file per JS file analyzed
- Filename = original JS filename (e.g., `app_main_summary.md`, `auth_bundle_summary.md`)
- Create `ai_js_analyz/` folder if it doesn't exist
- Focus on **what it does** and **why it's interesting**

This builds a persistent per-file knowledge base for future reference.

---

## Step 10: Deep-dive with specialized skills

If the JS file has high-value findings, load and use specialized skills for deeper analysis.

**Trigger conditions for deep-dive:**

| Finding | Load Skill |
|---------|------------|
| DOM XSS candidates (sink/source proximity) | `hunt-dom` |
| Node.js server-side code (Express, Fastify, etc.) | `hunt-nodejs` |
| Prototype Pollution patterns | `prototype-pollution` |
| Next.js / React SSR code | `hunt-nextjs` |
| Source maps (.js.map) or webpack chunks | `hunt-source-leak` |
| Complex XSS patterns | `hunt-xss` |
| Node.js debugging needed | `node-inspect-debugger` |

**Rules:**
- Only deep-dive if findings are **HIGH** confidence or **Critical/High** severity
- Don't waste time on low-value files
- Deep-dive adds more detailed analysis and exploitation paths
- Update the file summary in `ai_js_analyz/` with deep-dive results

---

## Important Rules

- Never claim a vulnerability without evidence.
- Distinguish confirmed findings vs suspicions.
- If evidence insufficient, mark as "Potential Issue".
- Review minified, bundled, generated code.
- Always think like an attacker.
- Prioritize exploitable vulnerabilities over code quality.
- If the user asks for snippets after, show the actual matches.
