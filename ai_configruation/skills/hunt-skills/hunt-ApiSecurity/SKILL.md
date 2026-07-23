---
name: api-security-testing
description: Comprehensive API security testing: REST, GraphQL, gRPC, WebSocket. BOLA/IDOR, mass assignment, rate limiting, auth bypass, documentation exposure, versioning attacks.
---

# API Security Testing

## Overview

APIs are the #1 attack surface in modern applications. Most bug bounty programs expose REST, GraphQL, gRPC, or WebSocket endpoints. This skill covers testing all API types for security vulnerabilities.

---

## REST API Testing

### BOLA/IDOR (Most Common)
```
1. Enumerate all endpoints with ID parameters
2. Create 2 accounts (attacker + victim)
3. For each ID endpoint:
   - GET with attacker's auth, victim's ID
   - PUT/PATCH with attacker's auth, victim's ID
   - DELETE with attacker's auth, victim's ID
4. Check nested resources: /orgs/{org_id}/users/{user_id}
5. Check batch endpoints: /users?ids=1,2,3,4,5
```

### Mass Assignment
```
1. Intercept registration/profile update request
2. Add privileged fields:
   - {"email":"attacker@evil.com","role":"admin"}
   - {"email":"attacker@evil.com","is_admin":true}
   - {"email":"attacker@evil.com","plan":"enterprise"}
3. Check if any added fields are reflected in response
4. Test on ALL user-modifiable endpoints
```

### Rate Limiting
```
1. Test login brute force (100+ attempts)
2. Test OTP brute force (1000+ attempts)
3. Test API key generation limits
4. Check if rate limit is per-IP or per-account
5. Test rate limit bypass:
   - X-Forwarded-For: 127.0.0.1
   - X-Real-IP: 127.0.0.1
   - Rotate through multiple IPs
```

### Authentication Testing
```
1. Test without auth header → should get 401
2. Test with expired token → should get 401
3. Test with revoked token → should get 401
4. Test with token from different user → should get 403
5. Test JWT:
   - None algorithm
   - Algorithm confusion (RS256 → HS256)
   - Expired token
   - Token with modified payload
```

### Versioning Attacks
```
1. Find API version in URL: /api/v1/, /api/v2/
2. Test old version with weaker auth
3. Test version downgrade: v2 endpoint → v1
4. Check if v1 endpoints are still accessible
```

---

## GraphQL API Testing

### Introspection
```graphql
# Full schema introspection
{
  __schema {
    types {
      name
      fields {
        name
        type { name }
      }
    }
  }
}

# Introspection query (compact)
{__type(name:"User"){fields{name type{name}}}}
```

### Missing Field-Level Auth
```graphql
# User query returns only own data
{ user(id: 1) { name email } }

# But node() bypasses per-object auth
{ node(id: "dXNlcjoy") { ... on User { email phoneNumber ssn } } }
```

### Batching Attack (Rate Limit Bypass)
```json
[
  {"query": "{ login(email: \"user@test.com\", password: \"pass1\") }"},
  {"query": "{ login(email: \"user@test.com\", password: \"pass2\") }"},
  "...100 more..."
]
```

### Nested Query DoS
```graphql
# Deeply nested query can cause server resource exhaustion
{
  user(id: 1) {
    posts {
      comments {
        author {
          posts {
            comments {
              author {
                posts { title }
              }
            }
          }
        }
      }
    }
  }
}
```

### Mutation Testing
```
1. Test all mutations without auth
2. Test mutation with wrong user's ID
3. Test mutation with admin-only fields
4. Test batch mutations
5. Test mutation with null/empty inputs
```

---

## gRPC API Testing

### Service Discovery
```bash
# gRPC reflection (if enabled)
grpcurl -plaintext target:50051 list
grpcurl -plaintext target:50051 describe

# Enumerate all methods
grpcurl -plaintext target:50051 list <service>
```

### Authentication Testing
```
1. Test without metadata → should fail
2. Test with expired token
3. Test with wrong tenant/org ID
4. Test with manipulated claims
```

### Common gRPC Vulnerabilities
- Missing authentication on sensitive methods
- Verbose error messages leaking internals
- Unrestricted file upload via streaming
- SSRF via URL parameters in RPC calls

---

## WebSocket API Testing

### Cross-Site WebSocket Hijacking
```
1. Find WebSocket endpoint
2. Check if Origin header is validated
3. If no origin check → hijack from attacker's domain
4. Steal real-time data (chat, notifications, financial data)
```

### Message Injection
```
1. Capture normal WebSocket messages
2. Modify message to include:
   - Different user ID
   - Admin commands
   - Exfiltration payloads
3. Test for:
   - Horizontal privilege escalation
   - Vertical privilege escalation
   - Data manipulation
```

---

## API Documentation Exposure

### Common Documentation Endpoints
```
/swagger-ui.html
/swagger-ui/
/api-docs
/openapi.json
/openapi.yaml
/swagger.json
/swagger.yaml
/docs
/api/v1/docs
/graphql (introspection)
/elmah.axd
/trace.axd
```

###危害 Assessment
| Finding | Severity |
|---------|----------|
| Swagger UI exposed (no auth) | Informational |
| API docs with auth bypass | Medium |
| Internal API endpoints exposed | High |
| Admin API endpoints exposed | Critical |
| Debug endpoints exposed | High |

---

## Testing Checklist

### REST
- [ ] BOLA/IDOR on all ID parameters
- [ ] Mass assignment on all write endpoints
- [ ] Rate limiting on all sensitive endpoints
- [ ] Authentication on all endpoints
- [ ] Authorization (role-based access)
- [ ] Input validation (injection, overflow)
- [ ] Error handling (verbose errors)
- [ ] Versioning (old version access)
- [ ] CORS configuration
- [ ] Content-Type validation

### GraphQL
- [ ] Introspection enabled
- [ ] Field-level authorization
- [ ] Query depth limit
- [ ] Query complexity limit
- [ ] Rate limiting per query
- [ ] Mutation authorization
- [ ] Subscription authorization
- [ ] batching attacks

### gRPC
- [ ] Service reflection enabled
- [ ] Authentication on all methods
- [ ] Authorization on all methods
- [ ] Input validation
- [ ] Error message leakage
- [ ] Streaming abuse

### WebSocket
- [ ] Origin validation
- [ ] Authentication
- [ ] Authorization
- [ ] Message validation
- [ ] Rate limiting
- [ ] Input sanitization

---

## Tools

```bash
# API endpoint discovery
ffuf -u https://target.com/api/FUZZ -w api-endpoints.txt -ac

# GraphQL introspection
curl -s https://target.com/graphql -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name}}}"}'

# gRPC reflection
grpcurl -plaintext target:50051 list

# Swagger/OpenAPI discovery
ffuf -u https://target.com/FUZZ -w swagger-wordlist.txt -mc 200

# API parameter discovery
arjun -u https://target.com/api/endpoint
paramspider -d target.com
```

---

## Impact Assessment

| Finding | Typical Severity | Bounty Range |
|---------|-----------------|--------------|
| BOLA/IDOR on PII | Medium | $500-$2,000 |
| BOLA/IDOR on financial data | High | $2,000-$5,000 |
| Mass assignment (role escalation) | High | $2,000-$5,000 |
| Auth bypass on admin API | Critical | $5,000-$10,000+ |
| GraphQL introspection enabled | Informational | $0-$100 |
| GraphQL missing field auth | High | $2,000-$5,000 |
| gRPC reflection enabled | Low | $100-$500 |
| WebSocket hijacking | High | $2,000-$5,000 |
| Exposed Swagger with sensitive endpoints | Medium | $500-$2,000 |
