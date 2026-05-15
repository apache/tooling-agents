# Security Issues

## Issue: FINDING-002 - No HTTPS Scheme Validation on base_url — Bearer Tokens Could Be Transmitted Over Plaintext HTTP
**Labels:** bug, security, priority:high
**Description:**
### Summary
If `base_url` is configured with an `http://` scheme (misconfiguration, testing leftover, or internal network assumption), the client will send JWT Bearer tokens in plaintext over the network. The `verify` SSL context is silently ignored by httpx for non-HTTPS connections.

### Details
**Attack Scenario:**
An attacker with network visibility (e.g., adjacent pod in Kubernetes, ARP spoofing on LAN) could intercept the JWT token and impersonate the task to the Execution API.

**Data Flow:**
1. Client initialized with `http://` base_url
2. JWT Bearer tokens sent in plaintext Authorization headers
3. All task execution data (connections, variables, XCom values) transmitted unencrypted
4. SSL verification silently bypassed

**CWE:** CWE-319  
**ASVS:** 12.2.1 (L1)

### Remediation
Enforce HTTPS for all production connections by adding validation in `Client.__init__`:

```python
def __init__(self, base_url: str, ...):
    if not base_url.startswith("https://"):
        raise ValueError(
            f"Execution API base_url must use HTTPS scheme for secure communication, got: {base_url!r}. "
            f"Set [api] execution_api_url with an https:// URL."
        )
    # ... existing initialization
```

Consider an environment variable override (e.g., `AIRFLOW__CORE__ALLOW_INSECURE_API=true`) for development environments only, with a loud warning.

### Acceptance Criteria
- [ ] HTTPS scheme validation added to `Client.__init__`
- [ ] ValueError raised for non-HTTPS URLs in production
- [ ] Optional development override with warning implemented
- [ ] Unit tests for HTTPS enforcement
- [ ] Documentation updated with security requirements

### References
- File: `task-sdk/src/airflow/sdk/api/client.py:548-580`
- Source: 12.2.1.md

### Priority
**High** - Credentials transmitted in plaintext; requires network position for exploitation

---

## Issue: FINDING-003 - SecretCache Has No Explicit Cleanup Mechanism for Session Termination
**Labels:** bug, security, priority:high
**Description:**
### Summary
The SecretCache class stores connection URIs (containing plaintext passwords) and variable values (potentially containing secrets) in a `multiprocessing.Manager().dict()`. There is no method to clear all cached authenticated data when a task session terminates.

### Details
The only cleanup mechanisms are:
1. **TTL-based expiration** (default 15 minutes) — data persists long after needed
2. **reset()** — explicitly marked 'test purposes only' and only sets `_cache = None` without clearing the backing manager process data
3. **Process exit** — implicit, not explicit, and unreliable under abnormal termination

**Impact:**
Authenticated credentials (connection passwords, API tokens stored as variables) persist in shared memory beyond task session lifetime. If process isolation fails or process reuse is introduced, secrets from one session may be accessible to subsequent code.

**ASVS Requirement:**
The requirement specifically states 'the client-side should also be able to clear up if the server connection is not available when the session is terminated.'

**ASVS:** 14.3.1 (L1)

### Remediation
Add `clear()` and `shutdown()` class methods to SecretCache:

```python
@classmethod
def clear(cls) -> None:
    """Clear all cached secrets."""
    if cls._cache is not None:
        cls._cache.clear()

@classmethod
def shutdown(cls) -> None:
    """Shutdown the cache and cleanup manager process."""
    cls.clear()
    cls._cache = None
    if cls.__manager is not None:
        cls.__manager.shutdown()
        cls.__manager = None
```

Register `SecretCache.shutdown()` with `atexit` in the `init()` method or call `SecretCache.clear()` explicitly in a finally block at the end of task execution in `task_runner.py`.

### Acceptance Criteria
- [ ] `clear()` method implemented to remove all cached secrets
- [ ] `shutdown()` method implemented with manager cleanup
- [ ] Cleanup registered with atexit or called in task_runner finally block
- [ ] Unit tests for cleanup methods
- [ ] Integration test verifying secrets cleared on session termination

### References
- File: `task-sdk/src/airflow/sdk/execution_time/cache.py:77, 68, 51-55`
- Source: 14.3.1.md

### Priority
**High** - Secrets persist beyond necessary lifetime; requires process isolation failure for exploitation

---

## Issue: FINDING-004 - Refreshed Token Accepted Without Signature Verification
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `_update_auth` method blindly accepts any value from the `Refreshed-API-Token` response header and replaces the active authentication credential. There is no validation that the new token is structurally valid, verification of the token signature or issuer, or check that the response came over a verified TLS connection.

### Details
`_update_auth` is called BEFORE error checking in the response hooks chain, meaning if a 4xx/5xx response includes a `Refreshed-API-Token` header, the client will update its auth token to potentially malicious content before raising an error.

**Attack Scenario:**
If an attacker can inject or manipulate an HTTP response (e.g., via a MITM attack if TLS is misconfigured, or via a compromised proxy), they could return any HTTP response (even 500) with header `Refreshed-API-Token: malicious_token` and the client would replace its valid auth with the attacker-controlled token.

**ASVS:** 9.1.1, 9.1.2, 9.1.3, 9.2.1, 10.4.5 (L1)

### Remediation
Add validation to only accept refreshed tokens from successful responses and validate token structure:

```python
def _update_auth(self, response: httpx.Response):
    # Only accept refreshed tokens from successful responses
    if not response.is_success:
        return
    if new_token := response.headers.get("Refreshed-API-Token"):
        if not new_token.strip():
            log.warning("Received empty Refreshed-API-Token header, ignoring")
            return
        log.debug("Execution API issued us a refreshed Task token")
        self.auth = BearerAuth(new_token)
```

Additionally, fix response hook ordering in `Client.__init__()` by moving `_update_auth` after `raise_on_4xx_5xx` or add a success check within `_update_auth`.

### Acceptance Criteria
- [ ] Success response check added to `_update_auth`
- [ ] Empty token validation implemented
- [ ] Response hook ordering fixed
- [ ] Unit tests for token refresh validation
- [ ] Test cases for error responses with Refreshed-API-Token header

### References
- File: `task-sdk/src/airflow/sdk/api/client.py:1075`
- Source: 9.1.1.md, 9.1.2.md, 9.1.3.md, 9.2.1.md, 10.4.5.md

### Priority
**Medium** - Requires MITM position; mitigated by TLS

---

## Issue: FINDING-005 - No Explicit TLS Minimum Version Enforcement — Relies on Python/OpenSSL Defaults
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The code uses `ssl.create_default_context()` without explicitly setting `minimum_version`, relying on platform-dependent defaults. On Python 3.9 or systems with permissive OpenSSL configurations, the client could negotiate deprecated TLS 1.0 or TLS 1.1 connections.

### Details
These protocol versions have known vulnerabilities (BEAST, POODLE, etc.) that could allow an attacker in a privileged network position to decrypt communications.

On Python 3.9 with an OpenSSL build that has not disabled TLS 1.0/1.1 at compile-time, the client could negotiate deprecated protocols.

**CWE:** CWE-327  
**ASVS:** 12.1.1 (L1)

### Remediation
Add explicit TLS minimum version enforcement by setting `ctx.minimum_version = ssl.TLSVersion.TLSv1_2` in the `_get_ssl_context_cached` method:

```python
@lru_cache()
@staticmethod
def _get_ssl_context_cached(ca_file: str, ca_path: str | None = None) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=ca_file)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if ca_path:
        ctx.load_verify_locations(ca_path)
    return ctx
```

### Acceptance Criteria
- [ ] TLS 1.2 minimum version explicitly set
- [ ] Unit test verifying TLS version enforcement
- [ ] Documentation updated with TLS requirements
- [ ] Test on Python 3.9 with permissive OpenSSL

### References
- File: `task-sdk/src/airflow/sdk/api/client.py:540-545`
- Source: 12.1.1.md

### Priority
**Medium** - Requires privileged network position and specific platform configuration

---

## Issue: FINDING-006 - Use of AES-128-CBC (Fernet) Instead of Approved AEAD Mode (AES-GCM)
**Labels:** enhancement, security, priority:medium
**Description:**
### Summary
Fernet is defined as AES-128-CBC with HMAC-SHA256. While this provides authenticated encryption through the encrypt-then-MAC pattern, it is not an Authenticated Encryption with Associated Data (AEAD) algorithm. The ASVS requirement specifies "approved ciphers and modes such as AES with GCM."

### Details
**Key differences from AES-GCM:**
- AES-128-CBC provides only 128-bit key security (vs. typical 256-bit for AES-GCM deployments)
- CBC requires separate HMAC pass (not atomic authentication)
- No support for Associated Data (AD) binding
- Fernet uses a fixed token format that constrains future algorithm agility

While not currently exploitable (Fernet's construction is secure), this represents a deviation from modern cryptographic best practices. The 128-bit key length is at the minimum acceptable threshold.

**ASVS:** 11.3.2 (L1)

### Remediation
Migrate to AES-256-GCM or ChaCha20-Poly1305 for new data. Maintain Fernet support for backward compatibility during migration:

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

class AESGCMCrypto:
    def __init__(self, key: bytes):
        if len(key) != 32:  # 256-bit key
            raise ValueError("Key must be 32 bytes for AES-256-GCM")
        self.cipher = AESGCM(key)
    
    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = os.urandom(12)  # 96-bit nonce
        ciphertext = self.cipher.encrypt(nonce, plaintext, None)
        return nonce + ciphertext
    
    def decrypt(self, encrypted: bytes) -> bytes:
        nonce, ciphertext = encrypted[:12], encrypted[12:]
        return self.cipher.decrypt(nonce, ciphertext, None)
```

Design and implement a migration path that:
- Supports parallel operation (decrypt with Fernet, encrypt with GCM)
- Includes a data migration tool for re-encrypting existing secrets
- Maintains backward compatibility for at least one major version
- Implements a versioned encryption envelope format

### Acceptance Criteria
- [ ] AES-256-GCM implementation added
- [ ] Versioned encryption envelope format designed
- [ ] Migration path documented
- [ ] Backward compatibility maintained
- [ ] Unit tests for new encryption mode
- [ ] Migration tool implemented

### References
- File: `task-sdk/src/airflow/sdk/crypto.py:84-104`
- Source: 11.3.2.md

### Priority
**Medium** - Architectural improvement; current implementation is secure but not best practice

---

## Issue: FINDING-007 - No Message Size Validation Before Memory Allocation in Frame Reader at Supervisor Layer
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `length_prefixed_frame_reader` function in the supervisor (the trusted service layer) reads a 4-byte length prefix from the untrusted subprocess socket and immediately allocates a buffer of that size without any bounds checking.

### Details
**Attack Scenario:**
A malicious subprocess can send a crafted 4-byte length prefix (e.g., `0xFFFFFFFF` = 4 GiB) to force the supervisor to attempt a large memory allocation, potentially causing an out-of-memory condition in the supervisor process.

**Data Flow:**
Subprocess (untrusted) writes 4-byte length → supervisor reads length → supervisor calls `bytearray(length_needed)` without bounds check → potential OOM

**Proof of Concept:**
A compromised subprocess writes `b'\xff\xff\xff\xff'` (4 bytes indicating ~4GiB payload) to its request socket, causing the supervisor to attempt `bytearray(4294967295)`.

**Impact:**
Denial of service against the supervisor process. While this only affects the current task's supervision (one supervisor per task), it prevents proper state reporting to the API server, potentially leaving the task in an indeterminate state until heartbeat timeout cleanup.

**CWE:** CWE-770  
**ASVS:** 2.2.2, 15.3.1 (L1)

### Remediation
Add a maximum frame size constant and validate before allocation:

```python
MAX_FRAME_SIZE = 64 * 1024 * 1024  # 64 MiB

def length_prefixed_frame_reader(sock: socket.socket):
    while True:
        length_bytes = sock.recv(4)
        if not length_bytes:
            return
        length_needed = struct.unpack("!I", length_bytes)[0]
        
        # Validate frame size
        if length_needed > MAX_FRAME_SIZE:
            raise ValueError(f"Frame size {length_needed} exceeds maximum allowed size {MAX_FRAME_SIZE}")
        
        buffer = bytearray(length_needed)
        # ... rest of implementation
```

### Acceptance Criteria
- [ ] MAX_FRAME_SIZE constant defined
- [ ] Frame size validation added before allocation
- [ ] ValueError raised for oversized frames
- [ ] Unit tests for frame size limits
- [ ] Integration test with malicious subprocess

### References
- File: `task-sdk/src/airflow/sdk/execution_time/supervisor.py:870`
- Related: FINDING-001, FINDING-008
- Source: 2.2.2.md, 15.3.1.md

### Priority
**Medium** - DoS attack requires compromised subprocess; limited to single task

---

## Issue: FINDING-008 - Unbounded Buffer Growth in Log Socket Reader Without Newline Termination
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `make_buffered_socket_reader` function accumulates data from subprocess sockets (stdout, stderr, logs) in a `bytearray` buffer until a newline is found. If the subprocess sends data without newline characters, the buffer grows indefinitely without any size limit.

### Details
**Attack Scenario:**
A malicious subprocess could exploit this to exhaust memory in the supervisor process.

**Data Flow:**
Subprocess (untrusted) writes bytes without `\n` → supervisor `buffer.extend()` accumulates indefinitely → potential OOM

**Proof of Concept:**
A compromised subprocess writes continuous non-newline bytes to stdout/stderr/logs socket:
```python
sock.sendall(b'A' * 4096)  # in a loop without any \n characters
```

**Impact:**
Memory exhaustion in the supervisor process, preventing proper task supervision and state reporting.

**CWE:** CWE-770  
**ASVS:** 2.2.2 (L1)

### Remediation
Add a maximum line buffer size constant and force-flush the buffer when this limit is exceeded:

```python
MAX_LINE_BUFFER_SIZE = 10 * 1024 * 1024  # 10 MiB

def make_buffered_socket_reader(sock: socket.socket, gen: Generator):
    buffer = bytearray()
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            if buffer:
                gen.send(buffer)
            return
        
        buffer.extend(chunk)
        
        # Force flush if buffer exceeds maximum size
        if len(buffer) > MAX_LINE_BUFFER_SIZE:
            gen.send(buffer)
            buffer = bytearray()
            continue
        
        # ... rest of newline processing
```

### Acceptance Criteria
- [ ] MAX_LINE_BUFFER_SIZE constant defined
- [ ] Force-flush logic implemented
- [ ] Unit tests for buffer size limits
- [ ] Integration test with non-newline data stream
- [ ] Documentation of buffer behavior

### References
- File: `task-sdk/src/airflow/sdk/execution_time/supervisor.py:840`
- Related: FINDING-001, FINDING-007
- Source: 2.2.2.md

### Priority
**Medium** - DoS attack requires compromised subprocess; limited to single task

---

## Issue: FINDING-009 - Insufficient Documentation of Input Validation Rules for IPC Message Fields
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
While the Pydantic models in `comms.py` define the structural schema of all IPC messages (discriminated unions, type annotations), there is no documentation that explicitly defines input validation rules for the data items within those messages.

### Details
The models lack:
- Maximum length constraints for string fields (`key`, `dag_id`, `task_id`, `conn_id`, etc.)
- Pattern/format specifications for identifiers (what constitutes a valid `dag_id`?)
- Numeric range constraints (what's the valid range for `limit`, `offset`, `map_index`?)
- Business logic constraints (which resources a subprocess is permitted to access)

**Impact:**
Without documented validation rules, developers implementing new message types or modifying existing ones have no reference for what constraints should be applied. This leads to inconsistent validation across the system and potential for exploitation of unbounded fields.

**ASVS:** 2.1.1 (L1)

### Remediation
Add Pydantic field validators and document rules explicitly:

```python
from pydantic import Field

class GetVariableKeys(BaseModel):
    prefix: str | None = Field(None, max_length=250)
    limit: int = Field(1000, ge=1, le=10000)
    offset: int = Field(0, ge=0)

class GetXCom(BaseModel):
    key: str = Field(..., min_length=1, max_length=512)
    dag_id: str = Field(..., min_length=1, max_length=250, pattern=r'^[a-zA-Z0-9_.\-]+$')
    run_id: str = Field(..., min_length=1, max_length=250)
    task_id: str = Field(..., min_length=1, max_length=250)
    map_index: int | None = Field(None, ge=-1)
```

Additionally, create a validation rules document (e.g., `docs/ipc_validation_rules.md`) that comprehensively defines the expected formats, ranges, and constraints for each field across all message types.

### Acceptance Criteria
- [ ] Pydantic Field constraints added to all message models
- [ ] Validation rules documentation created
- [ ] Examples provided for each constraint type
- [ ] Unit tests for field validation
- [ ] Developer guide updated with validation requirements

### References
- File: `task-sdk/src/airflow/sdk/execution_time/comms.py` (throughout)
- Source: 2.1.1.md

### Priority
**Medium** - Documentation gap; affects maintainability and security consistency

---

## Issue: FINDING-010 - NativeEnvironment Does Not Enforce Sandbox Attribute Access Restrictions
**Labels:** bug, security, priority:medium
**Description:**
### Summary
When a DAG sets `render_template_as_native_obj=True`, templates are processed by `NativeEnvironment` which inherits from `jinja2.nativetypes.NativeEnvironment` (NOT from `jinja2.sandbox.SandboxedEnvironment`). The `is_safe_attribute` method defined in `_AirflowEnvironmentMixin` is effectively dead code for this class.

### Details
The `is_safe_attribute` method exists but is never called because only `SandboxedEnvironment` invokes attribute safety checks during template evaluation.

**This means template expressions in native mode can:**
- Access any attribute on context objects (including `_` prefixed private attributes)
- Call methods without sandbox restrictions
- Traverse object graphs without safety checks

**Data Flow:**
DAG configuration (`render_template_as_native_obj=True`) → `create_template_env(native=True)` → `NativeEnvironment` created → template expressions evaluated WITHOUT sandbox enforcement → unrestricted attribute access on context objects

**Gap Type:** Type B — Control EXISTS (`is_safe_attribute`) but NOT CALLED for `NativeEnvironment` path

**ASVS:** 1.3.2 (L1)

### Remediation
Create a sandboxed native environment that combines both capabilities:

```python
class SandboxedNativeEnvironment(
    _AirflowEnvironmentMixin,
    jinja2.sandbox.SandboxedEnvironment,
):
    """Sandboxed environment that returns native Python types."""
    
    # Override code_generator or concat to return native types
    # while maintaining sandbox restrictions
    code_generator_class = jinja2.nativetypes.NativeCodeGenerator
    concat = staticmethod(jinja2.nativetypes.native_concat)
```

Or alternatively, use `ImmutableSandboxedEnvironment` with native type coercion applied after rendering.

### Acceptance Criteria
- [ ] SandboxedNativeEnvironment class implemented
- [ ] Sandbox restrictions verified in native mode
- [ ] Unit tests for attribute access restrictions
- [ ] Integration tests with native template rendering
- [ ] Documentation updated with security implications

### References
- File: `task-sdk/src/airflow/sdk/definitions/_internal/templater.py:258-259, 245-256`
- Source: 1.3.2.md

### Priority
**Medium** - Sandbox bypass in specific configuration; requires DAG author control

---

## Issue: FINDING-011 - Context Object Exposure Risk in Template Rendering
**Labels:** enhancement, security, priority:medium
**Description:**
### Summary
The security of the sandbox depends critically on what objects are passed in the template context. If context includes references to API clients, database sessions, or secrets caches, even the sandboxed environment (which allows `_` prefix access) could expose sensitive resources.

### Details
This module alone cannot be fully evaluated without understanding context construction. The risk is that sensitive objects in the template context could be accessed through template expressions, bypassing intended security boundaries.

**ASVS:** 1.3.2 (L1)

### Remediation
Audit context construction (outside this module's scope) to verify that:
- Supervisor API clients are not passed as template context variables
- Secrets caches are not reachable through context object graphs
- Database sessions and other sensitive objects are not exposed

Consider adding a `restricted_globals` or `restricted_context` mechanism that explicitly limits which objects are available in template expressions, independent of the sandbox's attribute-level controls.

### Acceptance Criteria
- [ ] Context construction audited for sensitive object exposure
- [ ] Restricted context mechanism designed
- [ ] Allowlist of permitted context objects documented
- [ ] Unit tests for context object access restrictions
- [ ] Security review of template context construction

### References
- Source: 1.3.2.md

### Priority
**Medium** - Requires audit of external code; defense-in-depth concern

---

## Issue: FINDING-012 - No Maximum Frame Size Validation in IPC Protocol Allows Memory Exhaustion
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The IPC protocol in `CommsDecoder._read_frame` does not validate the maximum frame size before allocating memory. A malicious task could craft a 4-byte header claiming length = 0xFFFFFFFF (4 GiB), causing the supervisor process to allocate a 4 GiB buffer, leading to OOM and DoS of the supervisor.

### Details
**Data Flow:**
Task subprocess (running user code) → binary length prefix → `_read_frame` → `bytearray(length)` allocation → no maximum size enforcement

**Attack Scenario:**
A malicious task could craft a 4-byte header claiming length = 0xFFFFFFFF (4 GiB), causing the supervisor process to allocate a 4 GiB buffer, leading to OOM and DoS of the supervisor.

**ASVS:** 2.2.1 (L1)

### Remediation
Implement a configurable maximum frame size (e.g., 64 MiB) in `CommsDecoder._read_frame()`:

```python
MAX_FRAME_SIZE = 64 * 1024 * 1024  # 64 MiB

def _read_frame(self, sock: socket.socket) -> bytes:
    length_bytes = sock.recv(4)
    if not length_bytes:
        raise EOFError("Connection closed")
    
    length = struct.unpack("!I", length_bytes)[0]
    
    if length > MAX_FRAME_SIZE:
        raise ValueError(
            f"Frame size {length} exceeds maximum allowed size {MAX_FRAME_SIZE}"
        )
    
    buffer = bytearray(length)
    # ... rest of implementation
```

This prevents memory exhaustion from malformed length headers regardless of trust model.

### Acceptance Criteria
- [ ] MAX_FRAME_SIZE constant defined
- [ ] Frame size validation added
- [ ] ValueError raised for oversized frames
- [ ] Unit tests for frame size limits
- [ ] Configuration option for maximum frame size

### References
- File: `task-sdk/src/airflow/sdk/execution_time/comms.py:225`
- Related: FINDING-007, FINDING-008
- Source: 2.2.1.md

### Priority
**Medium** - DoS attack requires compromised subprocess; limited to single task

---

## Issue: FINDING-013 - No Version Policy Enforcement for Dynamically-Loaded Providers
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `ProvidersManagerTaskRuntime` discovers and loads all installed provider packages via `discover_all_providers_from_packages()` without verifying that loaded providers are within any documented update or remediation timeframe.

### Details
While `ProviderInfo` objects contain version data from the provider metadata, this version is never checked against a policy that would reject outdated or known-vulnerable components.

**Impact:**
A provider package with a known CVE would be loaded and made available without any warning or rejection, even if the documented remediation timeframe requires updating to a newer version.

**ASVS:** 15.2.1 (L1)

### Remediation
Integrate vulnerability scanning into the `_correctness_check()` function:

```python
import requests

def _check_vulnerabilities(package_name: str, version: str) -> list[dict]:
    """Query OSV API for known vulnerabilities."""
    try:
        resp = requests.post(
            "https://api.osv.dev/v1/query",
            json={"package": {"name": package_name, "ecosystem": "PyPI"}, "version": version},
            timeout=5
        )
        if resp.status_code == 200:
            return resp.json().get("vulns", [])
    except Exception as e:
        log.warning("Failed to check vulnerabilities", package=package_name, error=str(e))
    return []

def _correctness_check(self, provider_info: ProviderInfo):
    # ... existing checks
    
    # Check for known vulnerabilities
    vulns = self._check_vulnerabilities(provider_info.package_name, provider_info.version)
    critical_vulns = [v for v in vulns if v.get("severity") in ("CRITICAL", "HIGH")]
    if critical_vulns:
        raise AirflowException(
            f"Provider {provider_info.package_name} version {provider_info.version} "
            f"has {len(critical_vulns)} critical/high severity vulnerabilities. "
            f"Update required before loading."
        )
```

### Acceptance Criteria
- [ ] Vulnerability checking function implemented
- [ ] OSV API integration added
- [ ] Critical/high vulnerabilities block provider loading
- [ ] Appropriate error handling for API failures
- [ ] Unit tests for vulnerability checking
- [ ] Configuration option to disable checks for development

### References
- File: `task-sdk/src/airflow/sdk/providers_manager_runtime.py:165-168`
- Source: 15.2.1.md

### Priority
**Medium** - Affects security posture; requires vulnerable provider installation

---

## Issue: FINDING-014 - No Runtime Component Inventory for Loaded Plugins and Providers
**Labels:** enhancement, security, priority:medium
**Description:**
### Summary
The `_get_plugins()` function loads plugins from multiple sources (directory, entrypoints, providers) but does not produce a complete inventory (SBOM) of what was actually loaded, including versions and sources.

### Details
While debug logging mentions plugin names, there is no structured inventory output that could be compared against documented update timeframes. The `import_errors` dict tracks failures but successful loads are not inventoried with version metadata.

**Impact:**
This prevents programmatic verification at runtime whether loaded components are within documented update timeframes.

**ASVS:** 15.2.1 (L1)

### Remediation
Add structured audit logging at INFO level for component loading events:

```python
import json

def _get_plugins(self):
    # ... existing loading logic
    
    # Generate audit record
    audit_record = {
        "event": "plugin_loading_complete",
        "timestamp": datetime.utcnow().isoformat(),
        "loaded_count": len(plugins_loaded),
        "error_count": len(self.import_errors),
        "sources": {
            "directory": directory_plugin_count,
            "entrypoint": entrypoint_plugin_count,
            "provider": provider_plugin_count
        },
        "rejected": [
            {"name": name, "reason": str(error)}
            for name, error in self.import_errors.items()
        ]
    }
    
    log.info("Plugin loading audit", audit_record=json.dumps(audit_record))
```

This enables forensic analysis and compliance reporting without requiring debug-level logging.

### Acceptance Criteria
- [ ] Structured audit logging implemented
- [ ] JSON format for audit records
- [ ] INFO level logging for production retention
- [ ] Component count and source breakdown included
- [ ] Rejected components listed with reasons
- [ ] Documentation of audit log format

### References
- File: `task-sdk/src/airflow/sdk/plugins_manager.py:62-101`
- Source: 15.2.1.md

### Priority
**Medium** - Operational visibility gap; affects compliance verification

---

## Issue: FINDING-015 - No Documentation of Update and Remediation Timeframes
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
No documented update and remediation timeframes policy was found in the analyzed files or referenced in the code. ASVS 15.2.1 requires verification that components have not breached documented timeframes, which presupposes that such timeframes exist and are codified.

### Details
Without documented SLAs for addressing vulnerable components, there is no baseline against which to measure compliance. This results in:
- Inconsistent response to vulnerability disclosures
- Inability to audit compliance with ASVS 15.2.1
- No accountability mechanism for timely updates

**ASVS:** 15.2.1 (L1)

### Remediation
Create a `SECURITY_POLICY.md` or `docs/component-update-policy.md` document defining:

**1. Remediation Timeframes by Severity:**
- Critical (9.0-10.0 CVSS): 24 hours
- High (7.0-8.9): 7 days
- Medium (4.0-6.9): 30 days
- Low (0.1-3.9): 90 days

**2. Scope:**
- All Apache Airflow provider packages
- Third-party plugins loaded via entrypoints
- Direct and transitive dependencies in uv.lock

**3. Enforcement Mechanisms:**
- CI/CD pipeline failures for critical/high CVEs
- Runtime rejection of components with known critical/high CVEs

### Acceptance Criteria
- [ ] Security policy document created
- [ ] Remediation timeframes defined by severity
- [ ] Scope clearly documented
- [ ] Enforcement mechanisms specified
- [ ] Policy referenced in main documentation
- [ ] Process for policy exceptions documented

### References
- Source: 15.2.1.md

### Priority
**Medium** - Policy gap; foundational for vulnerability management

---

## Issue: FINDING-016 - User-Controllable Path Segments in API URLs Are Not Percent-Encoded
**Labels:** bug, security, priority:medium
**Description:**
### Summary
User DAG code can supply values containing path separators, query parameter markers, or fragment identifiers that are embedded directly into URLs via f-strings without percent-encoding.

### Details
This allows:
- Path traversal to different API endpoints
- Query parameter injection via '?' characters
- URL truncation via '#' fragment identifiers
- Double-encoding issues

**Data Flow:**
User DAG code → IPC messages → Supervisor → client.py f-string URL construction → HTTP requests to Execution API

While server-side routing and JWT scoping provide outer security layers, this represents a defense-in-depth gap.

**Proof of Concept:**
```python
Variable.get('../connections/my_secret_conn')
# Results in: GET {base_url}/variables/../connections/my_secret_conn
# Which resolves to: GET {base_url}/connections/my_secret_conn
```

**CWE:** CWE-20  
**ASVS:** 1.2.2 (L1)

### Remediation
Create a URL-safe path builder utility function that percent-encodes each path segment:

```python
from urllib.parse import quote

def _path(*segments: str | int | uuid.UUID) -> str:
    """Build a URL path with properly encoded segments."""
    return "/".join(quote(str(s), safe="") for s in segments)

# Usage:
resp = self.client.get(_path("variables", key))
resp = self.client.get(_path("xcoms", dag_id, run_id, task_id, key))
resp = self.client.get(_path("connections", conn_id))
```

Apply this helper across all f-string URL constructions in client.py.

### Acceptance Criteria
- [ ] URL path builder utility implemented
- [ ] All f-string URL constructions replaced
- [ ] Unit tests for path encoding
- [ ] Test cases for special characters (/, ?, #, ..)
- [ ] Integration tests with encoded paths

### References
- File: `task-sdk/src/airflow/sdk/api/client.py:358, 380, 437, 467, 636, 315, 516, 495`
- Related: FINDING-036, FINDING-045
- Source: 1.2.2.md

### Priority
**Medium** - Defense-in-depth gap; mitigated by server-side validation

---

## Issue: FINDING-017 - Old Token Not Explicitly Cleared From Memory During Token Rotation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
When the server rotates a token, the previous token value remains in process memory as an unreachable Python string object until garbage collected. In a long-running supervisor process, this creates a window where memory inspection could reveal previously-valid tokens.

### Details
On Linux without `_make_process_nondumpable()` (or after fork in certain configurations), an attacker with same-UID access could scan `/proc/<supervisor_pid>/maps` and `/proc/<supervisor_pid>/mem` for JWT-pattern strings to recover rotated-but-not-yet-GC'd tokens.

**ASVS:** 7.2.4 (L1)

### Remediation
Clear old token reference before reassignment:

```python
def _update_auth(self, response: httpx.Response):
    if new_token := response.headers.get("Refreshed-API-Token"):
        log.debug("Execution API issued us a refreshed Task token")
        # Clear old token reference before reassignment
        old_auth = self.auth
        self.auth = BearerAuth(new_token)
        if hasattr(old_auth, 'token'):
            # Force dereference; Python strings are immutable so true zeroing
            # isn't possible, but we can minimize the window
            del old_auth
```

**Note:** True secure memory clearing of Python strings is not possible due to immutability; however, minimizing references and forcing GC via `gc.collect()` after rotation reduces the exposure window. For higher assurance, consider using `mmap`-backed buffers or `ctypes` to store tokens in memory that can be explicitly zeroed.

### Acceptance Criteria
- [ ] Old token reference cleared before reassignment
- [ ] Unit tests for token rotation
- [ ] Documentation of memory clearing limitations
- [ ] Consider mmap-backed secure memory for tokens

### References
- File: `task-sdk/src/airflow/sdk/api/client.py:1075`
- Source: 7.2.4.md

### Priority
**Medium** - Requires local access and memory inspection capability

---

## Issue: FINDING-018 - No Explicit Token Revocation/Session Termination API Call on Task Completion
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The architecture uses self-contained JWT tokens but the client has NO mechanism to signal explicit token termination to the server. After a task completes and the supervisor process terminates, the JWT token (if intercepted during its validity window) could be used by an attacker to make API calls on behalf of the terminated task instance until the token's natural expiration.

### Details
**Data Flow:**
Task completes → `update_task_state_if_needed()` sends terminal state → `_upload_logs()` → client closes HTTP connection → NO token invalidation API call → JWT remains valid until natural expiration

The token's scope limits the damage (only operations for that specific task instance), but it violates the principle that terminated sessions should be immediately unusable.

**ASVS:** 7.4.1 (L1)

### Remediation
Add a session termination endpoint call in `wait()` method:

```python
def wait(self):
    # ... existing terminal state handling
    
    # Explicitly terminate session
    try:
        self.client.post(f"task-instances/{self.id}/session-end")
    except Exception:
        log.debug("Failed to explicitly terminate session", ti_id=self.id)
```

**Alternative:** The server should be configured to invalidate the token when it receives the terminal state transition (in `update_task_state_if_needed`). The ASVS requirement says the application disallows any further use of the session — if the server invalidates the token upon receiving the terminal state, this requirement would be satisfied even without a separate session-end call.

### Acceptance Criteria
- [ ] Session termination endpoint designed
- [ ] Client-side session-end call implemented
- [ ] Server-side token invalidation on terminal state
- [ ] Unit tests for session termination
- [ ] Documentation of session lifecycle

### References
- File: `task-sdk/src/airflow/sdk/execution_time/supervisor.py:720-740`
- Source: 7.4.1.md

### Priority
**Medium** - Limited by token scope and expiration time

---

## Issue: FINDING-019 - Token Revocation Window Between Heartbeats Allows Continued API Access After Server-Side Cancellation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The supervisor code operates as a single-task, single-process entity. There is no mechanism visible in the client-side code for broadcasting a 'terminate all sessions for user X' command that would reach all active supervisors simultaneously.

### Details
Each supervisor independently polls the server via heartbeats. If a user has multiple tasks running concurrently (each with their own supervisor and token), disabling the user's account requires the server to revoke ALL tokens associated with that user and wait for EACH supervisor to discover the revocation via heartbeat.

There's no client-side support for immediate cross-task session termination.

**ASVS:** 7.4.2 (L1)

### Remediation
**Option 1:** Reduce heartbeat interval for critical operations by adding per-request token validation check in the request method to trigger immediate shutdown on UNAUTHORIZED or FORBIDDEN responses.

**Option 2:** Implement server-sent events or WebSocket channel for immediate revocation pushes.

**Option 3:** Ensure the server validates the token's validity (not just signature) on EVERY API call, not just heartbeats. If this is already done server-side, then the window is effectively zero for API calls — only the subprocess execution continues without API access.

### Acceptance Criteria
- [ ] Token validation on every API call verified server-side
- [ ] Immediate shutdown on auth failures implemented
- [ ] Consider SSE/WebSocket for push revocation
- [ ] Unit tests for immediate revocation response
- [ ] Documentation of revocation mechanisms

### References
- File: `task-sdk/src/airflow/sdk/execution_time/supervisor.py:940-990`
- Source: 7.4.2.md

### Priority
**Medium** - Window limited by heartbeat interval; requires server-side coordination

---

## Issue: FINDING-020 - Authorization Rules for Function-Level and Data-Specific Access Are Referenced But Not Co-Located With Enforcing Code
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The AGENTS.md document references external authorization documentation but within the audited code scope there is no inline or co-located documentation specifying which specific API operations each task is permitted to call or which data items each task's JWT token authorizes access to.

### Details
The supervisor's `_handle_request()` method handles 40+ message types without any documented access policy mapping which operations should be scoped to `self.id` vs. task-provided identifiers.

**Impact:**
Without co-located authorization rules, developers may not understand which operations require scope validation, leading to inconsistent enforcement. The lack of a clear access matrix makes auditing and verifying correct server-side enforcement more difficult.

**ASVS:** 8.1.1 (L1)

### Remediation
Add inline documentation or a structured authorization matrix in the supervisor module:

```python
"""
Authorization Matrix:

Operations scoped to current task (self.id) - enforced at supervisor:
- succeed, finish, retry, defer, reschedule
- heartbeat, set_rtif, set_rendered_map_index

Operations with cross-task access - enforced at API server via JWT scope:
- GetXCom (reads from upstream tasks)
- TriggerDagRun (external DAGs)

Operations requiring ti_id == self.id - should be validated at supervisor:
- GetTaskState, SetTaskState, DeleteTaskState, ClearTaskState
"""
```

### Acceptance Criteria
- [ ] Authorization matrix documented inline
- [ ] Operations categorized by scope enforcement point
- [ ] Cross-reference with API server JWT validation
- [ ] Developer guide updated with authorization model
- [ ] Code review checklist includes authorization verification

### References
- File: `AGENTS.md`, `task-sdk/src/airflow/sdk/execution_time/supervisor.py:800+`
- Source: 8.1.1.md

### Priority
**Medium** - Documentation gap; affects maintainability and audit capability

---

## Issue: FINDING-021 - Supervisor Mediates All Operations Without Function-Level Filtering — Any Task Can Invoke Any Supported Operation Type
**Labels:** enhancement, security, priority:medium
**Description:**
### Summary
The supervisor's `_handle_request()` method processes ALL `ToSupervisor` message types without any function-level access check. A task subprocess can invoke any operation including TriggerDagRun, PutVariable, DeleteVariable, SetXCom, DeleteXCom, SetTaskState, and asset modification operations.

### Details
The supervisor relies entirely on the API server's JWT validation for function-level restrictions. There is no supervisor-side policy that restricts which operation types a task may invoke.

This is an intentional architectural decision (authorization at API server), but represents a lack of defense-in-depth at the supervisor layer. If the API server has any function-level gap for a specific endpoint, tasks inherit that gap.

**ASVS:** 8.2.1, 8.2.2 (L1)

### Remediation
Consider adding an optional allowlist at the supervisor level for defense-in-depth:

```python
# Configurable operation allowlist per task type
ALLOWED_OPERATIONS = {
    "default": {GetXCom, PutXCom, GetVariable, GetConnection},
    "admin_task": {TriggerDagRun, PutVariable, DeleteVariable},
}

def _handle_request(self, msg: ToSupervisor) -> ToTask | None:
    # Check operation allowlist
    task_type = self.task_instance.task_type or "default"
    allowed = ALLOWED_OPERATIONS.get(task_type, ALLOWED_OPERATIONS["default"])
    
    if type(msg) not in allowed:
        log.warning("Operation not allowed for task type", 
                   operation=type(msg).__name__, task_type=task_type)
        return ErrorResponse(error=f"Operation {type(msg).__name__} not allowed")
    
    # ... existing message handling
```

Add `ti_id` validation for TaskState operations:
```python
if isinstance(msg, (GetTaskState, SetTaskState, DeleteTaskState, ClearTaskState)):
    if msg.ti_id != self.id:
        return ErrorResponse(error="Cannot access state for other task instances")
```

### Acceptance Criteria
- [ ] Operation allowlist mechanism designed
- [ ] Configuration option for per-task-type allowlists
- [ ] ti_id validation for TaskState operations
- [ ] Audit logging for cross-scope operations
- [ ] Unit tests for operation filtering
- [ ] Documentation of allowlist configuration

### References
- File: `task-sdk/src/airflow/sdk/execution_time/supervisor.py:800-1050`
- Source: 8.2.1.md, 8.2.2.md

### Priority
**Medium** - Defense-in-depth enhancement; primary enforcement at API server

---

## Issue: FINDING-022 - No Connection Invalidation Method Prevents Targeted Credential Cleanup
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The SecretCache provides `invalidate_variable()` for removing cached variable values, but has no equivalent `invalidate_connection()` or `invalidate_connection_uri()` method. Connection URIs — which contain plaintext credentials — cannot be individually removed from the cache.

### Details
This asymmetry means:
- Even if a cleanup routine were implemented, it cannot selectively purge connection credentials
- Rotated/compromised connection credentials persist until TTL expiration
- The existing `invalidate_variable()` pattern proves the design intended per-entry invalidation, but connections were omitted

**Impact:**
Authenticated connection credentials cannot be cleared from cache individually, preventing proper data lifecycle management. If a credential rotation or security incident occurs during task execution, the old credentials remain cached and potentially usable.

**ASVS:** 14.3.1 (L1)

### Remediation
Add an `invalidate_connection()` class method to SecretCache:

```python
@classmethod
def invalidate_connection(cls, conn_id: str, team_name: str | None = None) -> None:
    """Invalidate a cached connection URI."""
    if cls._cache is None:
        return
    
    # Construct cache key matching get_connection_uri pattern
    if team_name:
        key = f"{cls._CONNECTION_PREFIX}{team_name}/{conn_id}"
    else:
        key = f"{cls._CONNECTION_PREFIX}{conn_id}"
    
    cls._cache.pop(key, None)
```

### Acceptance Criteria
- [ ] invalidate_connection() method implemented
- [ ] Mirrors invalidate_variable() pattern
- [ ] Handles team_name parameter correctly
- [ ] Unit tests for connection invalidation
- [ ] Documentation updated with credential lifecycle

### References
- File: `task-sdk/src/airflow/sdk/execution_time/cache.py:140-145, 112-120, 122-134`
- Source: 14.3.1.md

### Priority
**Medium** - Credential lifecycle gap; workaround via full cache clear

---

## Issue: FINDING-023 - XCom Data Pushed by Tasks Has No Visible Size Limit Enforcement in the Task Runner
**Labels:** bug, security, priority:medium
**Description:**
### Summary
A task can produce arbitrarily large XCom data that gets serialized and stored, potentially causing memory exhaustion during serialization, disk space exhaustion on the XCom storage backend, network saturation when transmitting to the API server, and DoS against other tasks competing for the same storage.

### Details
**Data Flow:**
Task execution result → `_push_xcom_if_needed()` → `_xcom_push()` → `XCom.set()` → serialization to storage (file/DB) — no size validation at any visible stage.

**ASVS:** 5.2.1 (L1)

### Remediation
Add size validation before XCom serialization:

```python
import sys
from airflow.configuration import conf
from airflow.exceptions import AirflowException

def _xcom_push(self, key: str, value: Any):
    # Validate XCom size
    max_xcom_size = conf.getint("core", "max_xcom_size_bytes", fallback=50 * 1024 * 1024)
    estimated_size = sys.getsizeof(value)
    
    if estimated_size > max_xcom_size:
        raise AirflowException(
            f"XCom value exceeds maximum allowed size "
            f"({estimated_size} > {max_xcom_size} bytes). "
            f"Consider using external storage (S3, GCS) for large data."
        )
    
    # ... existing XCom.set() logic
```

### Acceptance Criteria
- [ ] Maximum XCom size configuration option added
- [ ] Size validation before serialization
- [ ] Clear error message with guidance
- [ ] Unit tests for size limits
- [ ] Documentation of XCom size limits and alternatives

### References
- File: `task-sdk/src/airflow/sdk/execution_time/task_runner.py:650, 1330`
- Source: 5.2.1.md

### Priority
**Medium** - Resource exhaustion risk; requires large XCom push

---

## Issue: FINDING-024 - DAG File Path Resolution Lacks Containment Validation Within Bundle Directory
**Labels:** bug, security, priority:high
**Description:**
### Summary
The task runner resolves DAG file paths by combining bundle path with `dag_rel_path` without validating that the resolved path stays within the bundle directory.

### Details
**Path Traversal Examples:**
- `Path('/bundles/my_bundle', '../../etc/malicious.py')` resolves to `/etc/malicious.py`
- `Path('/bundles/my_bundle', '/tmp/evil.py')` resolves to `/tmp/evil.py`

The `_verify_bundle_access()` function only checks the bundle root path, NOT the resolved `dag_absolute_path`.

**Attack Scenario:**
If an attacker can manipulate the execution API response (e.g., via SQL injection in the API server or a compromised scheduler), they could cause the task runner to execute code from outside the bundle boundary, leading to arbitrary code execution.

**CWE:** CWE-22  
**ASVS:** 5.3.2 (L1)

### Remediation
Validate `dag_rel_path` stays within bundle by resolving both paths and using `Path.relative_to()`:

```python
def _verify_bundle_access(self, what: RuntimeTaskDef):
    bundle_instance = self._get_bundle(what.bundle_name, what.bundle_version)
    bundle_root = bundle_instance.path.resolve()
    dag_absolute_path = (bundle_root / what.dag_rel_path).resolve()
    
    # Validate resolved path is within bundle
    try:
        dag_absolute_path.relative_to(bundle_root)
    except ValueError:
        log.error(
            "DAG path escapes bundle directory",
            dag_rel_path=what.dag_rel_path,
            resolved_path=dag_absolute_path,
            bundle_root=bundle_root
        )
        raise AirflowException(
            f"DAG path {what.dag_rel_path} resolves outside bundle directory"
        )
```

### Acceptance Criteria
- [ ] Path containment validation implemented
- [ ] Both relative and absolute path traversal prevented
- [ ] Clear error message for path escapes
- [ ] Unit tests for path traversal attempts
- [ ] Integration test with malicious dag_rel_path

### References
- File: `task-sdk/src/airflow/sdk/execution_time/task_runner.py:690`
- Related: FINDING-025
- Source: 5.3.2.md

### Priority
**High** - Path traversal vulnerability; requires API manipulation

---

## Issue: FINDING-025 - Log File Path Creation Lacks Visible Path Traversal Validation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `init_log_file()` function accepts `local_relative_path` parameter without validating for path traversal sequences (../, absolute paths). If constructed from user-controllable `run_id`, path traversal is theoretically possible.

### Details
Directory creation with configured permissions (0o775 default) means traversed paths get world-readable directories.

**Example:**
If `run_id='../../etc/cron.d'`, the function would attempt to create files and directories outside the intended log directory.

While `run_id` validation likely exists at the API level and the shared `init_log_file` implementation may contain path validation, no visible validation exists in this code layer.

**CWE:** CWE-22  
**ASVS:** 5.3.2 (L1)

### Remediation
Validate path doesn't escape base directory before file operations:

```python
def init_log_file(local_relative_path: str):
    base_log_folder = Path(conf.get("logging", "base_log_folder")).resolve()
    full_path = (base_log_folder / local_relative_path).resolve()
    
    # Validate path is within base log folder
    try:
        full_path.relative_to(base_log_folder)
    except ValueError:
        raise AirflowException(
            f"Log path {local_relative_path} resolves outside base log folder"
        )
    
    # ... existing file creation logic
```

### Acceptance Criteria
- [ ] Path containment validation added
- [ ] Both relative and absolute path traversal prevented
- [ ] Clear error message for path escapes
- [ ] Unit tests for path traversal attempts
- [ ] Verify run_id validation at API level

### References
- File: `task-sdk/src/airflow/sdk/log.py:123`
- Related: FINDING-024
- Source: 5.3.2.md

### Priority
**Medium** - Path traversal risk; likely mitigated by API-level validation

---

## Issue: FINDING-026 - No Explicit Mechanism to Exclude Source Control Metadata From Production Deployments
**Labels:** enhancement, security, priority:medium
**Description:**
### Summary
The provided codebase does not include any explicit configuration or documentation ensuring that source control metadata (.git, .svn) is excluded from production deployments of the Task SDK.

### Details
While the Task SDK is distributed as a Python library (typically via pip/wheel, which naturally excludes .git from the package), the AGENTS.md file documents that a Helm chart exists for Kubernetes deployment, and the repository uses Docker/Breeze for development.

Container-based deployments that copy source trees could inadvertently include .git directories.

**If .git is present in production, it could expose:**
- Full commit history including potentially sensitive changes
- Developer email addresses and names
- Internal branch structure and development patterns
- Configuration files that may reference internal systems

**ASVS:** 13.4.1 (L1)

### Remediation
1. Add .git and .svn to .dockerignore in the Helm chart's Docker context
2. Document in deployment instructions that SCM metadata must be excluded
3. If deploying from source rather than pip packages, add a build step to strip SCM metadata

**Example .dockerignore:**
```
.git
.svn
.hg
.gitignore
```

### Acceptance Criteria
- [ ] .dockerignore file created/updated
- [ ] Deployment documentation updated
- [ ] Build process verified to exclude SCM metadata
- [ ] Container image inspection confirms no .git directory
- [ ] Security best practices documented

### References
- File: Repository-wide, AGENTS.md
- Source: 13.4.1.md

### Priority
**Medium** - Information disclosure risk; depends on deployment method

---

## Issue: FINDING-027 - No Documented Risk-Based Remediation Timeframes for Third-Party Component Vulnerabilities
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The audited codebase contains no documentation defining risk-based remediation timeframes for addressing vulnerabilities in third-party components.

### Details
The AGENTS.md file provides extensive development instructions, testing standards, and architecture documentation, but does not address:
- Maximum acceptable time to patch critical/high/medium/low severity vulnerabilities
- Timeframes for routine dependency updates
- Process for monitoring new vulnerabilities in dependencies
- Escalation procedures when timeframes are exceeded

**Impact:**
Without defined remediation timeframes:
- Critical vulnerabilities in dependencies may remain unpatched indefinitely
- No accountability mechanism for timely updates
- Increased attack surface as known vulnerabilities persist
- Non-compliance with industry standards (e.g., PCI DSS requires critical patches within 30 days)

**ASVS:** 15.1.1 (L1)

### Remediation
Create a security policy document (e.g., `SECURITY_DEPENDENCY_POLICY.md`) that defines:

**1. Vulnerability Remediation Timeframes:**
- Critical (9.0-10.0 CVSS): 72 hours emergency patch release
- High (7.0-8.9): 7 calendar days priority update PR
- Medium (4.0-6.9): 30 calendar days scheduled update
- Low (0.1-3.9): 90 calendar days next routine update

**2. Routine Update Schedule:**
- Security-critical libraries (httpx, certifi, cryptography): monthly review
- All other dependencies: quarterly review
- Lock file (uv.lock) regeneration with each update cycle

**3. Monitoring:**
- Enable Dependabot/GitHub security advisories
- Monitor PyPI advisory database
- Subscribe to CVE feeds for critical dependencies

**4. Escalation:**
If remediation timeframe cannot be met, a tracking issue must be filed per AGENTS.md tracking issues for deferred work section.

### Acceptance Criteria
- [ ] Security dependency policy document created
- [ ] Remediation timeframes defined by severity
- [ ] Routine update schedule documented
- [ ] Monitoring mechanisms specified
- [ ] Escalation process defined
- [ ] Policy referenced in main documentation

### References
- File: AGENTS.md, client.py:29-44, supervisor.py:30-43
- Source: 15.1.1.md

### Priority
**Medium** - Policy gap; foundational for dependency management

---

## Issue: FINDING-028 - Client Does Not Handle HTTP 429 (Too Many Requests) Responses With Backoff
**Labels:** bug, security, priority:low
**Description:**
### Summary
If the server implements rate limiting (as recommended by NIST SP 800-63B §5.2.2 for brute force prevention), the client will not respect server-side throttling signals. Instead of backing off and retrying, it will raise an unhandled error, potentially losing task execution context.

### Details
**Data Flow:**
Server returns 429 → `raise_on_4xx_5xx` raises `HTTPStatusError` → `_should_retry_api_request` returns False (status 429 < 500) → request fails immediately without backoff

**Proof of Concept:**
Server returns `HTTP 429 Too Many Requests` with `Retry-After: 5` header during a heartbeat call → client raises `HTTPStatusError` → supervisor treats it as a hard failure, potentially killing the task prematurely.

**ASVS:** 6.3.1 (L1)

### Remediation
Extend `_should_retry_api_request` to retry on HTTP 429 status codes:

```python
def _should_retry_api_request(exception: BaseException) -> bool:
    if isinstance(exception, httpx.HTTPStatusError):
        status = exception.response.status_code
        return status >= 500 or status == 429
    return isinstance(exception, httpx.RequestError)
```

Additionally, consider respecting the `Retry-After` header when present.

### Acceptance Criteria
- [ ] 429 status code added to retry logic
- [ ] Retry-After header respected
- [ ] Unit tests for rate limit handling
- [ ] Exponential backoff for retries
- [ ] Documentation of rate limit behavior

### References
- File: `task-sdk/src/airflow/sdk/api/client.py:1020-1025`
- Source: 6.3.1.md

### Priority
**Low** - Operational issue; server-side rate limiting is optional

---

## Issue: FINDING-029 - Token Refresh Hook Executes on All Responses Including Error Responses
**Labels:** bug, security, priority:low
**Description:**
### Summary
ANY HTTP response (including 4xx/5xx) → `_update_auth` executes FIRST → if `Refreshed-API-Token` header present, token is updated → THEN `raise_on_4xx_5xx` raises error.

### Details
A server error response (e.g., 500) that happens to include a `Refreshed-API-Token` header would cause the client to adopt the new token even though the request failed.

While unlikely in normal operation, a server bug or proxy injection could cause unexpected token replacement.

**ASVS:** 9.1.1 (L1)

### Remediation
Add a check at the beginning of `_update_auth()` method to only accept token refresh from successful responses:

```python
def _update_auth(self, response: httpx.Response):
    if not response.is_success:
        return
    # ... existing token refresh logic
```

### Acceptance Criteria
- [ ] Success check added to _update_auth
- [ ] Unit tests for error response with refresh header
- [ ] Verify no token update on error responses

### References
- File: `task-sdk/src/airflow/sdk/api/client.py:1060`
- Source: 9.1.1.md

### Priority
**Low** - Edge case; unlikely in normal operation

---

## Issue: FINDING-030 - Server-Side JWT Algorithm Validation Cannot Be Verified From Provided Code
**Labels:** documentation, security, priority:low
**Description:**
### Summary
The ASVS 9.1.2 requirement mandates that 'only algorithms on an allowlist can be used to create and verify self-contained tokens.' The primary enforcement point for this requirement is the Execution API server, which validates incoming JWT tokens on every request.

### Details
The server-side token validation code (referenced in `airflow-core/docs/security/jwt_token_authentication.rst`) is not included in the audit scope.

The client-side code exclusively acts as a bearer of the token—it never verifies the token's signature or makes authorization decisions based on token content. This is architecturally appropriate, but it means the full ASVS 9.1.2 compliance cannot be assessed from the provided files alone.

**If the server-side code lacks algorithm allowlisting (e.g., accepts `alg: none` or allows algorithm confusion between HMAC and RSA), tokens could be forged.**

**ASVS:** 9.1.2 (L1)

### Remediation
Verify in the Execution API server implementation that:
1. A strict algorithm allowlist is configured (e.g., only RS256 or only HS256)
2. The `none` algorithm is explicitly rejected
3. If both symmetric and asymmetric algorithms must be supported, key confusion prevention is in place

Audit the server-side JWT validation middleware to ensure ASVS 9.1.2, 9.1.3, and 9.2.1 compliance. Document the algorithm allowlist and key management approach.

### Acceptance Criteria
- [ ] Server-side JWT validation audited
- [ ] Algorithm allowlist documented
- [ ] `none` algorithm rejection verified
- [ ] Key confusion prevention confirmed
- [ ] Documentation updated with JWT security model

### References
- Source: 9.1.2.md

### Priority
**Low** - Requires server-side audit; client implementation is correct

---

## Issue: FINDING-031 - Server-Side Key Material Source Validation Cannot Be Verified From Provided Code
**Labels:** documentation, security, priority:low
**Description:**
### Summary
The requirement that headers such as `jku`, `x5u`, and `jwk` must be validated against an allowlist of trusted sources applies to the server-side JWT verification logic. The Execution API server code performing token validation is not included in the audit scope.

### Details
From the architecture documentation, the server creates and validates JWT tokens for task instances. The key configuration (symmetric vs. asymmetric, key storage) is documented in `airflow-core/docs/security/jwt_token_authentication.rst`, which is not provided.

Cannot confirm or deny ASVS 9.1.3 compliance for the system as a whole from the provided client-side code.

**ASVS:** 9.1.3 (L1)

### Remediation
Verify in the server-side code that:
1. `jku`, `x5u`, and `jwk` headers in incoming JWTs are either rejected or validated against a strict allowlist
2. Key material comes from pre-configured sources (e.g., configuration files, KMS)
3. The signing key is not derivable from information in the token itself

### Acceptance Criteria
- [ ] Server-side JWT header validation audited
- [ ] Key material source allowlist documented
- [ ] Dynamic key loading restrictions verified
- [ ] Documentation updated with key management approach

### References
- Source: 9.1.3.md

### Priority
**Low** - Requires server-side audit; client implementation is correct

---

## Issue: FINDING-032 - Initial Token Accepted Without Client-Side Expiration Check
**Labels:** enhancement, security, priority:low
**Description:**
### Summary
The initial token passed to `supervise_task` is used to construct the `Client` without any check of its validity period. If the token was already expired when the supervisor received it (e.g., due to scheduling delays or clock skew), the task will fail on the first API call with an authentication error rather than failing early with a descriptive error.

### Details
**ASVS:** 9.2.1 (L1)

### Remediation
Add early validation of token expiration in `supervise_task` before forking the task subprocess:

```python
import jwt
from datetime import datetime, timezone

def supervise_task(ti: RuntimeTaskInstance, token: str):
    # Validate token expiration before starting task
    try:
        payload = jwt.decode(token, options={"verify_signature": False})
        exp = payload.get("exp")
        if exp:
            exp_time = datetime.fromtimestamp(exp, tz=timezone.utc)
            now = datetime.now(timezone.utc)
            # Allow 30 seconds clock skew
            if exp_time < now - timedelta(seconds=30):
                raise AirflowException(
                    f"Task token already expired at {exp_time}. "
                    f"Check system clock synchronization."
                )
    except jwt.DecodeError:
        log.warning("Could not decode token for expiration check")
    
    # ... existing task supervision logic
```

### Acceptance Criteria
- [ ] Token expiration check added
- [ ] Clock skew tolerance implemented
- [ ] Clear error message with guidance
- [ ] Unit tests for expired tokens
- [ ] Documentation of clock synchronization requirements

### References
- File: `task-sdk/src/airflow/sdk/api/client.py`, `task-sdk/src/airflow/sdk/execution_time/supervisor.py`
- Source: 9.2.1.md

### Priority
**Low** - Improves error messages; server-side validation is primary control

---

## Issue: FINDING-033 - Server-Side Token Expiration Validation Cannot Be Verified From Provided Code
**Labels:** documentation, security, priority:low
**Description:**
### Summary
ASVS 9.2.1 requires verification that tokens with `nbf` and `exp` claims are only accepted within their validity time span. The primary enforcement of this requirement happens in the Execution API server's JWT validation middleware. This code is not included in the audit scope.

### Details
Per the architecture documentation, tokens are designed to be short-lived, suggesting expiration enforcement exists server-side, but cannot be confirmed from client-side code alone.

**ASVS:** 9.2.1 (L1)

### Remediation
Verify in the Execution API server that:
1. `exp` claim is REQUIRED and always validated
2. `nbf` claim is validated when present
3. Appropriate clock skew tolerance is configured (typically 30-60 seconds)
4. Tokens are rejected BEFORE processing the request body

### Acceptance Criteria
- [ ] Server-side token expiration validation audited
- [ ] exp claim validation confirmed
- [ ] nbf claim validation confirmed
- [ ] Clock skew tolerance documented
- [ ] Early rejection of expired tokens verified

### References
- Source: 9.2.1.md

### Priority
**Low** - Requires server-side audit; client implementation is correct

---

## Issue: FINDING-034 - No Certificate Revocation Checking (OCSP/CRL) Configured
**Labels:** enhancement, security, priority:low
**Description:**
### Summary
If the Execution API server's TLS certificate is compromised and revoked by the CA, the client will continue to trust it until the certificate expires naturally. This window could be days to months depending on the certificate's validity period.

### Details
An attacker who compromises a server's private key could perform man-in-the-middle attacks even after the certificate is revoked.

This is a defense-in-depth concern. Python's ssl module has limited OCSP support (no OCSP stapling verification on the client side without additional libraries). CRL checking via `ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF` requires providing CRL distribution points, which is operationally complex.

**CWE:** CWE-299  
**ASVS:** 12.2.2 (L1)

### Remediation
For production deployments, consider:
1. Using a service mesh (Istio, Linkerd) that handles certificate rotation and revocation
2. Short-lived certificates (< 24h) that minimize the revocation window
3. Certificate pinning for the known Execution API server certificate

Optionally enable CRL checking if CRL files are available:
```python
ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
```

For OCSP, consider using a library like pyOpenSSL or certvalidator for production deployments requiring revocation checking.

### Acceptance Criteria
- [ ] Certificate revocation strategy documented
- [ ] Service mesh or short-lived certificates considered
- [ ] CRL checking implementation if applicable
- [ ] OCSP library evaluation for production
- [ ] Documentation of certificate lifecycle

### References
- File: `task-sdk/src/airflow/sdk/api/client.py:540-545`
- Source: 12.2.2.md

### Priority
**Low** - Defense-in-depth; requires certificate compromise

---

## Issue: FINDING-035 - _NullFernet Fallback Allows Operation Without Any Encryption
**Labels:** bug, security, priority:low
**Description:**
### Summary
When FERNET_KEY is not configured, sensitive connection passwords, extra fields, and variables are stored in plaintext. The `_NullFernet` class returns plaintext data without any encryption applied. While a warning is logged, there is no enforcement mechanism to prevent production operation without encryption.

### Details
This means no approved cipher is used at all in this configuration. The system can operate without any encryption, creating a configuration-dependent security posture where sensitive data (passwords, extras, variables) may be stored unencrypted.

**ASVS:** 11.3.2 (L1)

### Remediation
Consider making encryption mandatory in production by failing hard rather than degrading silently:

```python
from airflow.configuration import conf

def get_fernet():
    fernet_key = conf.get("core", "fernet_key", fallback=None)
    
    if not fernet_key:
        # Check for explicit allow_unencrypted flag
        allow_unencrypted = conf.getboolean(
            "core", "allow_unencrypted_secrets", fallback=False
        )
        
        if not allow_unencrypted:
            raise AirflowException(
                "FERNET_KEY must be set for production use. "
                "Set allow_unencrypted_secrets=true in airflow.cfg "
                "for non-production environments only."
            )
        
        log.warning("Operating without encryption - NOT FOR PRODUCTION USE")
        return _NullFernet()
    
    return Fernet(fernet_key.encode())
```

This prevents accidental plaintext storage in production.

### Acceptance Criteria
- [ ] Fail-hard mode for missing FERNET_KEY
- [ ] Configuration flag for development override
- [ ] Clear error message with setup guidance
- [ ] Unit tests for encryption enforcement
- [ ] Documentation of encryption requirements

### References
- File: `task-sdk/src/airflow/sdk/crypto.py:40-58`
- Source: 11.3.2.md

### Priority
**Low** - Configuration issue; warning already logged

---

## Issue: FINDING-036 - Missing Field-Level Validation Constraints on IPC Message Models at Supervisor Layer
**Labels:** bug, security, priority:low
**Description:**
### Summary
The Pydantic models used for IPC message validation at the supervisor (trusted) layer enforce type correctness via the `TypeAdapter` but lack field-level validation constraints. Numeric fields like `limit` and `offset` have no range constraints, and string fields have no length limits.

### Details
While the API server provides secondary validation, the supervisor—as the first trusted validation point—should enforce reasonable bounds to prevent resource abuse.

**Data Flow:**
Subprocess constructs message → Pydantic validates types only → supervisor passes unconstrained values to API client

**Impact:**
Without field constraints at the supervisor layer, a subprocess can send semantically invalid requests (negative offsets, extreme limits, oversized strings) that consume supervisor resources during HTTP request construction before reaching the API server's validation.

**CWE:** CWE-20  
**ASVS:** 2.2.2, 2.2.1 (L1)

### Remediation
Add Pydantic `Field` constraints to all message models:

```python
from pydantic import Field

class GetVariableKeys(BaseModel):
    prefix: str | None = Field(None, max_length=1000)
    limit: int = Field(1000, ge=1, le=10000)
    offset: int = Field(0, ge=0)

class GetXCom(BaseModel):
    key: str = Field(..., min_length=1, max_length=512)
    dag_id: str = Field(..., min_length=1, max_length=250)
    # ... etc
```

Start with the most permissive models (SetXCom.value, GetVariableKeys.limit, string fields) and expand coverage progressively.

### Acceptance Criteria
- [ ] Field constraints added to all message models
- [ ] Numeric range constraints implemented
- [ ] String length limits implemented
- [ ] Unit tests for field validation
- [ ] Documentation of validation constraints

### References
- File: `task-sdk/src/airflow/sdk/execution_time/comms.py`
- Related: FINDING-016, FINDING-045
- Source: 2.2.2.md, 2.2.1.md

### Priority
**Low** - Defense-in-depth; API server provides secondary validation

---

## Issue: FINDING-037 - No Documented Validation Rules for Callback Execution Paths
**Labels:** documentation, security, priority:low
**Description:**
### Summary
The `execute_callback` function accepts a `callback_path` string that is dynamically imported and executed. While this value originates from the trusted supervisor layer (not the subprocess), there is no documentation defining what constitutes a valid callback path.

### Details
Without documented validation rules for callback paths, maintainers cannot easily verify that new callback invocations conform to expected patterns. If an upstream component inadvertently passes an unsanitized callback path, arbitrary code execution could occur within the callback subprocess.

**CWE:** CWE-94  
**ASVS:** 2.1.1 (L1)

### Remediation
Document the expected format and origin of `callback_path` values. Consider adding validation using a regex pattern:

```python
import re

VALID_CALLBACK_PATH_PATTERN = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_.]*\.[a-zA-Z_][a-zA-Z0-9_]*$')

def execute_callback(callback_path: str, ...):
    # Validate callback path format
    if not VALID_CALLBACK_PATH_PATTERN.match(callback_path):
        return False, f"Invalid callback path format: {callback_path}"
    
    # ... existing import and execution logic
```

### Acceptance Criteria
- [ ] Callback path format documented
- [ ] Validation pattern implemented
- [ ] Unit tests for path validation
- [ ] Documentation of allowed callback sources
- [ ] Code review checklist includes callback path validation

### References
- File: `task-sdk/src/airflow/sdk/execution_time/callback_supervisor.py:72-78`
- Source: 2.1.1.md

### Priority
**Low** - Originates from trusted source; documentation improvement

---

## Issue: FINDING-038 - No JSON-Specific Encoding Filters Provided in Custom Filter Set for Template Rendering
**Labels:** enhancement, security, priority:low
**Description:**
### Summary
The custom filter set only includes date/time formatting filters. When templates are used to dynamically build JSON strings (e.g., REST API operator bodies), there is no explicit JSON-safe filter provided or documented in the custom set.

### Details
If a DAG author writes `{"key": "{{ params.user_input }}"}` and `user_input` contains characters like `"`, `\`, or newlines, the resulting JSON structure could be corrupted.

**Mitigating factors:**
- Jinja2's built-in `tojson` filter IS available (not removed) and handles proper JSON escaping
- Template source is authored by DAG developers (trusted within their process boundary)
- Output is task parameters, not served directly to browsers
- `NativeEnvironment` mode returns Python native types (avoiding string-based JSON construction entirely)

**ASVS:** 1.2.3 (L1)

### Remediation
Consider adding a `json` or `tojson` alias to the custom FILTERS dict to make JSON-safe encoding more discoverable:

```python
import json

def json_filter(value: Any) -> str:
    """Safely encode value as JSON string."""
    return json.dumps(value)

FILTERS = {
    "ds": ds_filter,
    "ds_nodash": ds_nodash_filter,
    "ts": ts_filter,
    "ts_nodash": ts_nodash_filter,
    "ts_nodash_with_tz": ts_nodash_with_tz_filter,
    "json": json_filter,
}
```

### Acceptance Criteria
- [ ] JSON filter added to custom filter set
- [ ] Documentation updated with JSON encoding guidance
- [ ] Examples provided for JSON template construction
- [ ] Unit tests for JSON encoding filter

### References
- File: `task-sdk/src/airflow/sdk/definitions/_internal/templater.py:302-308, 309-340`
- Source: 1.2.3.md

### Priority
**Low** - Built-in filter available; documentation improvement

---

## Issue: FINDING-039 - `jinja2.ext.do` Extension Enabled by Default Allows Statement Execution in Templates
**Labels:** enhancement, security, priority:low
**Description:**
### Summary
The `jinja2.ext.do` extension is enabled by default in all template environments. This extension allows executing expression statements (e.g., `{% do items.append(x) %}`) which enables mutation of objects accessible in the template context.

### Details
While the sandbox restricts what methods can be called in `SandboxedEnvironment`, the `do` extension expands the attack surface beyond pure expression evaluation. In native mode (per ASVS-132-MED-001), it enables unrestricted statement execution.

However, template source is authored by DAG developers who already have Python code execution capability.

**ASVS:** 1.3.2 (L1)

### Remediation
Consider whether the `do` extension is necessary for the default template environment. If not required for typical use cases, remove it:

```python
jinja_env_options = {
    "undefined": template_undefined,
    "extensions": [],  # Remove jinja2.ext.do unless explicitly needed
    "cache_size": 0,
}
```

If needed for backward compatibility, document the security implications and consider making it opt-in via `jinja_environment_kwargs`.

### Acceptance Criteria
- [ ] Review necessity of `do` extension
- [ ] Remove or make opt-in if not required
- [ ] Document security implications if retained
- [ ] Update template authoring guidelines
- [ ] Unit tests for template execution restrictions

### References
- File: `task-sdk/src/airflow/sdk/definitions/_internal/templater.py:315`
- Source: 1.3.2.md

### Priority
**Low** - Template authors already have code execution; defense-in-depth concern

---

## Issue: FINDING-040 - Client Does Not Validate Content-Type Header on Successful HTTP Responses Before Parsing
**Labels:** bug, security, priority:low
**Description:**
### Summary
The HTTP client does not validate the Content-Type header on successful (2xx) responses before attempting to parse them as JSON. All operation methods that call `model_validate_json(resp.read())` skip Content-Type validation.

### Details
If a reverse proxy, CDN, or misconfigured load balancer returns `Content-Type: text/html` with an HTML error page on a 200 status code (e.g., captive portal), the client would attempt to parse HTML as JSON, resulting in a confusing `ValidationError` rather than a clear "unexpected content type" error.

The error handling path correctly validates Content-Type in `ServerResponseError.from_response` (line ~555), but this validation is not applied to success responses. This creates an asymmetry where Content-Type is validated for errors but not for successful responses.

**ASVS:** 4.1.1 (L1)

### Remediation
Add a response event hook that validates Content-Type on successful responses with bodies:

```python
def _validate_json_content_type(response: httpx.Response):
    """Validate that successful responses with bodies have JSON content type."""
    if response.is_success and response.headers.get("content-length", "0") != "0":
        ct = response.headers.get("content-type", "")
        if ct and not ct.startswith("application/json"):
            raise httpx.DecodingError(
                f"Expected application/json response but got {ct!r}"
            )

# Add to event_hooks in Client.__init__:
event_hooks={
    "response": [self._update_auth, _validate_json_content_type, raise_on_4xx_5xx],
    # ...
}
```

### Acceptance Criteria
- [ ] Content-Type validation hook implemented
- [ ] Validation applied to successful responses
- [ ] Clear error message for unexpected content types
- [ ] Unit tests for Content-Type validation
- [ ] Test cases for HTML responses with 200 status

### References
- File: `task-sdk/src/airflow/sdk/api/client.py:282, 195, 257, 300, 340, 460`
- Source: 4.1.1.md

### Priority
**Low** - Edge case; improves error messages for misconfigurations

## Issue: FINDING-041 - Client does not set Accept header to signal expected response format
**Labels:** bug, security, priority:low
**Description:**

### Summary
The HTTP client does not set an `Accept` header when making requests to the Execution API, violating HTTP best practices for content negotiation and potentially causing issues if the server implementation changes.

### Details
The client initialization in `Client.__init__` (line ~493 in `task-sdk/src/airflow/sdk/api/client.py`) sets `user-agent` and `airflow-api-version` headers but omits the `accept` header. Without an `Accept` header, the server has no client-side signal to guide content negotiation. If the API server supports multiple response formats, it may default to a non-JSON format.

**ASVS Reference:** 4.1.1 (L1)  
**Risk Level:** Low - Practically low risk given the API is designed for this specific client, but could cause issues if the server implementation changes or if proxies perform content negotiation.

### Remediation
Add the Accept header to the client initialization:

```python
headers={
    "user-agent": f"apache-airflow-task-sdk/{__version__} (Python/{pyver})",
    "airflow-api-version": API_VERSION,
    "accept": "application/json",
},
```

### Acceptance Criteria
- [x] Accept header set to "application/json" in client initialization
- [x] Test added to verify Accept header is sent with all requests
- [x] Documentation updated if needed

### References
- File: `task-sdk/src/airflow/sdk/api/client.py:493`
- ASVS 4.1.1

### Priority
Low

---

## Issue: FINDING-042 - Default Non-Lazy Provider Loading Increases Attack Surface
**Labels:** security, enhancement, priority:low
**Description:**

### Summary
When `settings.LAZY_LOAD_PROVIDERS` is False, all provider plugins are loaded regardless of whether they are needed, unnecessarily expanding the attack surface and making it harder to determine which components are actually in use.

### Details
Eager loading means all installed providers are loaded into memory and available for execution even when not required. This includes components that may have breached update timeframes. All installed providers are loaded even when only a subset is needed, making it harder to determine which components are actually in use for remediation prioritization.

**ASVS Reference:** 15.2.1 (L1)  
**Affected File:** `task-sdk/src/airflow/sdk/plugins_manager.py:95`

### Remediation
1. Make lazy loading (`LAZY_LOAD_PROVIDERS=True`) the default for production deployments
2. Implement and document a provider allowlist mechanism that only loads explicitly required providers
3. Add configuration option to specify `REQUIRED_PROVIDERS` as a list
4. Filter `_provider_dict` to only include allowed providers when this configuration is set

### Acceptance Criteria
- [x] Lazy loading is the default configuration
- [x] Provider allowlist mechanism implemented
- [x] Configuration documentation updated
- [x] Test added for allowlist functionality

### References
- File: `task-sdk/src/airflow/sdk/plugins_manager.py:95`
- ASVS 15.2.1

### Priority
Low

---

## Issue: FINDING-043 - Static Resource Version Not Suitable for Change Detection
**Labels:** bug, security, priority:low
**Description:**

### Summary
The `resource_version` property returns a static string '0', preventing cache invalidation when the set of installed providers changes (e.g., after a security update).

### Details
The static value in `task-sdk/src/airflow/sdk/providers_manager_runtime.py:105` means the cache cannot be invalidated when providers are updated. After updating a provider package to remediate a vulnerability, cached metadata from the old version may still be used until process restart. Cache invalidation requires manual intervention rather than automatic detection of provider landscape changes.

**ASVS Reference:** 15.2.1 (L1)

### Remediation
Generate a dynamic resource version based on installed provider versions:
1. Compute a hash of all provider package names and versions from `_provider_dict`
2. Use this hash as the `resource_version`
3. Cache the computed version to avoid repeated calculations

This enables automatic cache invalidation when the provider landscape changes due to package updates.

### Acceptance Criteria
- [x] Dynamic resource version generation implemented
- [x] Resource version changes when providers are updated
- [x] Test added to verify cache invalidation on provider updates
- [x] Performance impact assessed and acceptable

### References
- File: `task-sdk/src/airflow/sdk/providers_manager_runtime.py:105`
- ASVS 15.2.1

### Priority
Low

---

## Issue: FINDING-044 - Server-controlled header value used in exception notes without output encoding validation
**Labels:** security, bug, priority:low
**Description:**

### Summary
HTTP Response Header (`correlation-id`) is embedded in exception notes and potentially logged without context-aware encoding, creating a potential log injection vector.

### Details
In `task-sdk/src/airflow/sdk/api/client.py:172-180`, if the Execution API server (or a man-in-the-middle in a misconfigured environment) returns a crafted `correlation-id` header containing log-injection payloads (e.g., ANSI escape sequences, multi-line content, or JSON structure-breaking characters), these would be embedded in exception notes without validation.

**ASVS Reference:** 1.2.1 (L1)  
**Risk Level:** Low - Since communication is with a trusted internal API server over TLS, exploitability is low.

### Remediation
Sanitize or validate the correlation-id format (UUID) before embedding in exception notes:

```python
import re
_CORRELATION_RE = re.compile(r'^[0-9a-f-]{36,}$', re.IGNORECASE)

def _safe_correlation_id(response: httpx.Response) -> str:
    cid = response.headers.get('correlation-id') or response.request.headers.get('correlation-id', 'no-correlation-id')
    return cid if _CORRELATION_RE.match(cid) else 'invalid-correlation-id'
```

### Acceptance Criteria
- [x] Correlation ID validation implemented
- [x] Invalid correlation IDs replaced with safe default
- [x] Test added for malformed correlation ID handling
- [x] No log injection possible via correlation-id header

### References
- File: `task-sdk/src/airflow/sdk/api/client.py:172-180`
- ASVS 1.2.1
- Related: FINDING-016, FINDING-036

### Priority
Low

---

## Issue: FINDING-045 - No explicit allowlist for URL protocol schemes in base_url configuration
**Labels:** security, enhancement, priority:low
**Description:**

### Summary
The `Client.__init__` method accepts a `base_url` parameter from Airflow configuration without explicitly validating the URL scheme against an allowlist, representing a defense-in-depth gap.

### Details
In `task-sdk/src/airflow/sdk/api/client.py:810`, while the base_url comes from admin-controlled configuration (not user input) and httpx validates URL schemes internally, there is no explicit runtime validation that only http and https protocols are allowed.

**CWE:** CWE-20  
**ASVS Reference:** 1.2.2 (L1)  
**Risk Level:** Very Low - No runtime user input path, making this a defense-in-depth observation rather than an exploitable vulnerability.

### Remediation
Add explicit scheme validation to enforce only http and https protocols:

```python
from urllib.parse import urlparse

if base_url:
    parsed = urlparse(base_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported URL scheme: {parsed.scheme}")
```

### Acceptance Criteria
- [x] URL scheme validation implemented
- [x] Only http and https schemes allowed
- [x] Test added for invalid URL schemes
- [x] Clear error message for unsupported schemes

### References
- File: `task-sdk/src/airflow/sdk/api/client.py:810`
- ASVS 1.2.2
- CWE-20
- Related: FINDING-016, FINDING-036

### Priority
Low

---

## Issue: FINDING-046 - Supervisor API token accessible in forked child process memory on Linux
**Labels:** security, enhancement, priority:low
**Description:**

### Summary
On Linux (where bare fork is used instead of fork+exec), the child process inherits the parent's memory space, which includes the API token in the `Client` object, creating a potential memory disclosure vector.

### Details
In `task-sdk/src/airflow/sdk/execution_time/supervisor.py:380-420`, while the child doesn't explicitly use the token (communication is via socketpairs), a sufficiently motivated malicious task could potentially scan process memory for the token.

**Mitigating controls:**
- `_make_process_nondumpable()` sets `PR_SET_DUMPABLE=0`, preventing other processes from ptrace-ing or reading `/proc/pid/mem`
- On macOS, fork+exec is used, which replaces the process image entirely
- The token is scoped to the task instance, limiting impact of any leak
- The supervisor process itself IS the trust boundary (per documentation)

**ASVS Reference:** 7.2.4, 8.3.1 (L1)  
**Risk Level:** Low - Token is scoped to current task execution, so even if recovered, it only grants the same access the task already has.

### Remediation
On Linux fork path, explicitly zero or delete the parent's client/token references in the child before calling `_fork_main`:

In the child process (pid == 0), after closing unused sockets and deleting constructor_kwargs and logger, add explicit clearing of any remaining references to API credentials and call `gc.collect()` to ensure cleanup before proceeding to `_fork_main`.

### Acceptance Criteria
- [x] API token references cleared in child process after fork
- [x] Garbage collection triggered before _fork_main
- [x] Memory scanning test demonstrates token is not accessible
- [x] No regression in supervisor functionality

### References
- File: `task-sdk/src/airflow/sdk/execution_time/supervisor.py:380-420`
- ASVS 7.2.4, 8.3.1

### Priority
Low

---

## Issue: FINDING-047 - Token reference retained in Client object after connection close
**Labels:** security, bug, priority:low
**Description:**

### Summary
After `client.close()` is called, the authentication token remains accessible via `client.auth.token` until Python's garbage collector reclaims the object, extending the exposure window for sensitive credentials.

### Details
Data flow: `Client.__init__(token=...)` → `BearerAuth(token)` → `self.auth.token` → `client.close()` closes HTTP connection but doesn't clear `self.auth.token` → token persists until object goes out of scope and GC runs.

In the supervisor's process lifetime, this is a brief window, but for long-running processes or when clients are cached, this extends the exposure unnecessarily.

**ASVS Reference:** 7.4.1 (L1)  
**Affected File:** `task-sdk/src/airflow/sdk/api/client.py`

### Remediation
Override `close()` in Client class to clear sensitive token reference:

```python
def close(self):
    self.auth = BearerAuth("")
    super().close()
```

### Acceptance Criteria
- [x] Token cleared when client.close() is called
- [x] Test added to verify token is no longer accessible after close
- [x] No impact on client reusability if needed
- [x] Documentation updated if close() behavior changes

### References
- File: `task-sdk/src/airflow/sdk/api/client.py`
- ASVS 7.4.1

### Priority
Low

---

## Issue: FINDING-048 - Fernet Key Object Cached Indefinitely Without Clear Mechanism
**Labels:** security, enhancement, priority:low
**Description:**

### Summary
The `get_fernet()` function uses Python's `@cache` decorator, which caches encryption keys in memory indefinitely without any clear mechanism, potentially exposing key material across session boundaries if the architecture evolves.

### Details
In `task-sdk/src/airflow/sdk/crypto.py:86`, the Fernet object and its underlying key material remain in process memory for the entire interpreter lifetime. While `get_fernet.cache_clear()` is available via the decorator's API, it is never called during session termination.

**Current Mitigation:** In the current architecture (process-per-task), this is mitigated by process exit.  
**Future Risk:** If the architecture evolves to reuse processes, key material from one session would be available in the next.

**ASVS Reference:** 14.3.1 (L1)

### Remediation
1. Add a `clear_fernet_cache()` function that calls `get_fernet.cache_clear()` to remove cached Fernet keys from memory
2. Register this function with `atexit` or call it explicitly during session termination in task cleanup code

### Acceptance Criteria
- [x] Cache clear mechanism implemented
- [x] Cache cleared during session termination
- [x] Test added to verify keys are cleared
- [x] Documentation updated for process reuse scenarios

### References
- Files: `task-sdk/src/airflow/sdk/crypto.py:86`, `:67-82`, `:52-64`
- ASVS 14.3.1

### Priority
Low

---

## Issue: FINDING-049 - Email template files read entirely into memory without size validation
**Labels:** security, bug, priority:low
**Description:**

### Summary
Email template files are read entirely into memory using `read_text()` without size validation, potentially causing excessive memory consumption if the configured path points to a large or special file.

### Details
In `task-sdk/src/airflow/sdk/execution_time/task_runner.py:1373`, if the configured path points to a large file (or a special file like `/dev/urandom` on certain OS configurations), unbounded `read_text()` could consume excessive memory.

**Data flow:** Configuration value → `Path().exists()` → `Path().read_text()` (unbounded read) → memory

**ASVS Reference:** 5.2.1 (L1)  
**Risk Level:** Low - The path is admin-configured and not user-controllable at runtime.

### Remediation
Add file size validation before reading email template files:

```python
MAX_TEMPLATE_SIZE = 64 * 1024  # 64 KB

if template_path.stat().st_size > MAX_TEMPLATE_SIZE:
    log.warning("Email subject template exceeds size limit, using default")
else:
    subject = template_path.read_text()
```

### Acceptance Criteria
- [x] File size validation implemented before reading templates
- [x] Reasonable size limit defined (e.g., 64 KB)
- [x] Warning logged when template exceeds size limit
- [x] Test added for oversized template handling

### References
- File: `task-sdk/src/airflow/sdk/execution_time/task_runner.py:1373`
- ASVS 5.2.1

### Priority
Low

---

## Issue: FINDING-050 - relative_path_from_logger validates path relationship but upload_to_remote doesn't handle the ValueError
**Labels:** bug, observability, priority:low
**Description:**

### Summary
The `relative_path_from_logger` function correctly validates path relationships using `Path.relative_to()`, but `upload_to_remote` catches the resulting `ValueError` with a bare except that swallows the error without logging, making debugging difficult.

### Details
In `task-sdk/src/airflow/sdk/log.py:197` and `:178`, the `relative_path_from_logger` function raises `ValueError` if the log file path is not within `base_log_folder`. The `upload_to_remote` function catches this with a bare `except Exception: return`, which silently skips the upload. While this is a positive defensive pattern (preventing path traversal), the bare except swallows the error without logging, which could mask issues.

**CWE:** CWE-703  
**ASVS Reference:** 5.3.2 (L1)

### Remediation
1. Log the exception for debugging purposes
2. Specifically catch `ValueError` to log when log file is not within `base_log_folder` and skipping remote upload
3. Keep the general Exception handler but add debug logging with `exc_info=True` to aid troubleshooting

### Acceptance Criteria
- [x] ValueError specifically caught and logged
- [x] Debug logging added for general exceptions
- [x] Test added to verify logging behavior
- [x] No change to security behavior (upload still skipped on error)

### References
- Files: `task-sdk/src/airflow/sdk/log.py:197`, `:178`
- ASVS 5.3.2
- CWE-703

### Priority
Low

---

## Issue: FINDING-051 - No documentation identifying risky components or components with dangerous functionality
**Labels:** documentation, security, priority:low
**Description:**

### Summary
Per ASVS 15.1.1, documentation should identify components containing dangerous functionality (deserialization, dynamic code execution, etc.) or risky components. The Task SDK uses several such components without explicit risk documentation.

### Details
The Task SDK uses components with dangerous functionality without documented risk assessment:

1. **import_string** from `airflow.sdk._shared.module_loading` performs dynamic code execution - loading arbitrary Python modules by string name
2. **msgspec** library performs binary deserialization (msgpack) of data from subprocess IPC channels in `supervisor.py` and is used to decode server error responses in `client.py`

Without documented risk assessment of these components, developers may not apply appropriate defensive measures when using or updating them.

**ASVS Reference:** 15.1.1 (L1)

### Remediation
Add a Component Risk Assessment section to architectural documentation listing:
1. Components performing dangerous operations (msgspec, import_string, os.fork/os.execv)
2. Their risk classification
3. Mitigations applied (e.g., TypeAdapter validation for msgspec, _correctness_check for import_string)

### Acceptance Criteria
- [x] Component Risk Assessment section added to documentation
- [x] All dangerous/risky components identified
- [x] Mitigations documented for each component
- [x] Review process established for adding new risky components

### References
- Files: `AGENTS.md`, `providers_manager_runtime.py:49`, `supervisor.py:36`, `client.py:33`
- ASVS 15.1.1

### Priority
Low

---

## Issue: FINDING-052 - No documentation of rate limiting, anti-automation, or adaptive response controls for credential access
**Labels:** documentation, security, priority:low
**Description:**

### Summary
The security documentation does not describe controls such as rate limiting, anti-automation, or adaptive response mechanisms that defend against credential stuffing or password brute force attacks on the Execution API.

### Details
The `AGENTS.md` Security Model section documents trust boundaries, JWT tokens, and component isolation, but does not describe defensive controls for credential access. The `ExecutionAPISecretsBackend` retrieves connections/variables with no documented throttling or lockout behavior.

**Data flow:** User/task code → `Connection.get()` → `ExecutionAPISecretsBackend.get_connection()` → SUPERVISOR_COMMS → Execution API — no rate limiting or lockout documented at any stage.

The `AGENTS.md` explicitly references `airflow-core/docs/security/security_model.rst` for authoritative security documentation. Known false positive patterns note that 'No rate limiting on Execution API client (client.py)' is intentional because 'rate limiting belongs on the server side.'

**ASVS Reference:** 6.1.1 (L1)

### Remediation
Add a security documentation section (in the referenced security_model.rst or similar) that explicitly describes:
1. Rate limiting applied to the Execution API for credential retrieval
2. Anti-automation controls for login/authentication endpoints
3. Adaptive response mechanisms (progressive delays, temporary lockout)
4. Configuration to prevent malicious account lockout

### Acceptance Criteria
- [x] Security documentation updated with rate limiting details
- [x] Anti-automation controls documented
- [x] Adaptive response mechanisms described
- [x] Configuration guidance provided

### References
- Files: `AGENTS.md:220-260`, `task-sdk/src/airflow/sdk/execution_time/secrets/execution_api.py:43-67`
- ASVS 6.1.1

### Priority
Low

---

## Issue: FINDING-053 - No client-side token expiration awareness or proactive refresh mechanism
**Labels:** security, enhancement, priority:low
**Description:**

### Summary
The client has no awareness of token expiration and no proactive refresh mechanism. If the server doesn't send a `Refreshed-API-Token` header before the current token expires, the client will continue sending expired tokens until it receives a 401 response, which is not handled.

### Details
The client in `task-sdk/src/airflow/sdk/api/client.py` has no token introspection or handling of 401 responses to trigger re-authentication. The retry logic (`_should_retry_api_request`) only retries on 5xx and network errors — a 401 from an expired token would not be retried and would propagate as an unrecoverable error.

For long-running tasks, there's a risk of token expiry without recovery.

**CWE:** CWE-613  
**ASVS Reference:** 10.4.5 (L1)

### Remediation
Consider implementing one or both:
1. Add 401 handling that logs a clear message about token expiration
2. Implement client-side JWT expiry checking to warn before expiration

### Acceptance Criteria
- [x] Token expiration handling implemented
- [x] Clear error messages for expired tokens
- [x] Test added for token expiration scenario
- [x] Documentation updated with token lifecycle information

### References
- File: `task-sdk/src/airflow/sdk/api/client.py`
- ASVS 10.4.5
- CWE-613

### Priority
Low