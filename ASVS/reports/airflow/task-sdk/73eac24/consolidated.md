# Security Audit Consolidated Report

## apache/airflow/tasks-sdk

---


> **Note:** 1 Critical finding has been redacted from this report and forwarded to the project's PMC private mailing list.


## Report Metadata

| Field | Value |
|-------|-------|
| **Repository** | `apache/tooling-runbooks` |
| **ASVS Level** | L1 |
| **Severity Threshold** | None (all findings included) |
| **Commit** | N/A |
| **Date** | May 15, 2026 |
| **Auditor** | Tooling Agents |
| **Source Reports** | 70 |
| **Total Findings** | 53 |

---

## Executive Summary

This consolidated report presents the results of an automated security audit of the `apache/tooling-runbooks` repository, evaluated against OWASP ASVS Level 1 requirements across 21 security domains. The audit synthesized 70 individual source reports into 53 unique findings.

### Severity Distribution

| Severity | Count | Percentage |
|----------|-------|------------|
| **High** | 2 | 3.8% |
| **Medium** | 24 | 45.3% |
| **Low** | 26 | 49.1% |
| **Info** | 0 | 0.0% |

### ASVS Level Coverage

All findings are mapped to **L1** requirements. The audit scope encompassed the following domains: execution API authentication, TLS transport security, secrets encryption and storage, IPC subprocess isolation, session and state management, authorization and access control, plugin dynamic loading, Jinja template sandboxing, API input validation, output encoding and injection prevention, file upload handling, resource management limits, deployment configuration security, memory safety in native code, OAuth/OIDC flows, password/credential management, secrets masking in logging, browser client security, data protection in transit and at rest, business logic flow control, and GraphQL/WebSocket APIs.

### Top Risks

1. **[High] Bearer Token Transmission Over Plaintext (FINDING-002):** The client does not validate that `base_url` uses an HTTPS scheme, meaning bearer tokens could be transmitted over unencrypted HTTP connections, exposing credentials to network-level interception.

2. **[High] SecretCache Lacks Session Cleanup (FINDING-003):** The `SecretCache` has no explicit cleanup mechanism tied to session termination, leaving decrypted secrets in memory beyond their intended lifecycle.

3. **[Medium] Token Refresh Without Signature Verification (FINDING-004):** Refreshed tokens from the server are accepted and used without client-side signature verification, relying entirely on transport-layer security for token integrity.

4. **[Medium] No TLS Minimum Version Enforcement (FINDING-005):** The implementation relies on Python/OpenSSL defaults for TLS version negotiation without explicitly enforcing a minimum of TLS 1.2, potentially allowing downgrade attacks in environments with outdated library versions.

### Positive Security Controls

The audit identified significant positive security architecture across the codebase:

- **Strong authentication model:** Bearer token (JWT) authentication exclusively, with short-lived tokens scoped to individual task executions. No password-based authentication, no hardcoded credentials, and no default accounts exist in the system.

- **Token isolation architecture:** The JWT token is held only by the supervisor process and is never passed to task subprocesses. Combined with `_make_process_nondumpable()` and ORM access blocking, this limits the blast radius of any token compromise.

- **Robust TLS implementation:** TLS certificate verification is always enforced for production connections (`verify=False` never appears), with mutual TLS support, no HTTP fallback mechanism, and centralized SSL context management using publicly trusted CA bundles via certifi.

- **Defense-in-depth IPC isolation:** Fork-based process isolation with Pydantic-based structural validation of all IPC messages, discriminated union schemas, restricted message types for callback subprocesses (least privilege), and separate decoders per subprocess type.

- **Well-structured cryptographic layer:** All encryption flows through a single Fernet-based primitive with key rotation support (MultiFernet), encrypt-then-MAC protection, and no custom cryptographic implementations or deprecated hash functions.

- **Resilient retry behavior:** Authentication failures are explicitly excluded from retry logic, exponential backoff with jitter prevents thundering herd patterns, and server-initiated termination on invalid token responses provides forced session invalidation.

---

## 3. Findings

### 3.2 High

#### FINDING-002: No HTTPS Scheme Validation on base_url — Bearer Tokens Could Be Transmitted Over Plaintext HTTP

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-319 |
| **ASVS Sections** | 12.2.1 |
| **Files** | task-sdk/src/airflow/sdk/api/client.py:548-580 |
| **Source Reports** | 12.2.1.md |
| **Related** | - |

**Description:**

If `base_url` is configured with an `http://` scheme (misconfiguration, testing leftover, or internal network assumption), the client will: 1. Send JWT Bearer tokens in plaintext over the network 2. Send all task execution data (connections, variables, XCom values) unencrypted 3. The `verify` SSL context is silently ignored by httpx for non-HTTPS connections. An attacker with network visibility (e.g., adjacent pod in Kubernetes, ARP spoofing on LAN) could intercept the JWT token and impersonate the task to the Execution API.

**Remediation:**

Enforce HTTPS for all production connections by adding validation in `Client.__init__`:
```python
if not base_url.startswith("https://"):
    raise ValueError(f"Execution API base_url must use HTTPS scheme for secure communication, got: {base_url!r}. Set [api] execution_api_url with an https:// URL.")
```
Consider an environment variable override (e.g., `AIRFLOW__CORE__ALLOW_INSECURE_API=true`) for development environments only, with a loud warning.

---

#### FINDING-003: SecretCache Has No Explicit Cleanup Mechanism for Session Termination

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 14.3.1 |
| **Files** | task-sdk/src/airflow/sdk/execution_time/cache.py:class-level, task-sdk/src/airflow/sdk/execution_time/cache.py:77, task-sdk/src/airflow/sdk/execution_time/cache.py:68, task-sdk/src/airflow/sdk/execution_time/cache.py:51-55 |
| **Source Reports** | 14.3.1.md |
| **Related** | - |

**Description:**

The SecretCache class stores connection URIs (containing plaintext passwords) and variable values (potentially containing secrets) in a multiprocessing.Manager().dict(). There is no method to clear all cached authenticated data when a task session terminates. The only mechanisms are: TTL-based expiration (default 15 minutes — data persists long after needed), reset() — explicitly marked 'test purposes only' and only sets _cache = None without clearing the backing manager process data, and Process exit — implicit, not explicit, and unreliable under abnormal termination. Authenticated credentials (connection passwords, API tokens stored as variables) persist in shared memory beyond task session lifetime. If process isolation fails or process reuse is introduced, secrets from one session may be accessible to subsequent code. The ASVS requirement specifically states 'the client-side should also be able to clear up if the server connection is not available when the session is terminated.'

**Remediation:**

Add clear() and shutdown() class methods to SecretCache. The clear() method should call self._cache.clear() to remove all cached secrets. The shutdown() method should clear the cache, set _cache to None, and call __manager.shutdown() if the manager exists. Register SecretCache.shutdown() with atexit in the init() method or call SecretCache.clear() explicitly in a finally block at the end of task execution in task_runner.py.

### 3.3 Medium

#### FINDING-004: Refreshed token accepted without signature verification

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 9.1.1, 9.1.2, 9.1.3, 9.2.1, 10.4.5 |
| **Files** | task-sdk/src/airflow/sdk/api/client.py:1075 |
| **Source Reports** | 9.1.1.md, 9.1.2.md, 9.1.3.md, 9.2.1.md, 10.4.5.md |
| **Related** | - |

**Description:**

The `_update_auth` method blindly accepts any value from the `Refreshed-API-Token` response header and replaces the active authentication credential. There is no validation that the new token is structurally valid (e.g., a proper JWT), verification of the token signature or issuer, or check that the response came over a verified TLS connection before accepting a new credential. Additionally, `_update_auth` is called BEFORE error checking in the response hooks chain, meaning if a 4xx/5xx response includes a `Refreshed-API-Token` header, the client will update its auth token to potentially malicious content before raising an error. If an attacker can inject or manipulate an HTTP response (e.g., via a MITM attack if TLS is misconfigured, or via a compromised proxy), they could return any HTTP response (even 500) with header `Refreshed-API-Token: malicious_token` and the client would replace its valid auth with the attacker-controlled token.

**Remediation:**

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

---

#### FINDING-005: No Explicit TLS Minimum Version Enforcement — Relies on Python/OpenSSL Defaults

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-327 |
| **ASVS sections** | 12.1.1 |
| **Files** | task-sdk/src/airflow/sdk/api/client.py:540-545 |
| **Source Reports** | 12.1.1.md |
| **Related** | - |

**Description:**

On Python 3.9 with an OpenSSL build that has not disabled TLS 1.0/1.1 at compile-time, the client could negotiate deprecated TLS 1.0 or TLS 1.1 connections. The code uses `ssl.create_default_context()` without explicitly setting `minimum_version`, relying on platform-dependent defaults. On Python 3.9 or systems with permissive OpenSSL configurations, the client could negotiate deprecated TLS 1.0 or TLS 1.1 connections. These protocol versions have known vulnerabilities (BEAST, POODLE, etc.) that could allow an attacker in a privileged network position to decrypt communications.

**Remediation:**

Add explicit TLS minimum version enforcement by setting `ctx.minimum_version = ssl.TLSVersion.TLSv1_2` in the `_get_ssl_context_cached` method. Example:
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

---

#### FINDING-006: Use of AES-128-CBC (Fernet) instead of approved AEAD mode (AES-GCM)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 11.3.2 |
| **Files** | task-sdk/src/airflow/sdk/crypto.py:84-104 |
| **Source Reports** | 11.3.2.md |
| **Related** | - |

**Description:**

Fernet is defined as AES-128-CBC with HMAC-SHA256 (RFC 7539-like construction). While this provides authenticated encryption through the encrypt-then-MAC pattern, it is not an Authenticated Encryption with Associated Data (AEAD) algorithm. The ASVS requirement specifies "approved ciphers and modes such as AES with GCM," indicating a preference for native AEAD constructions. Key differences from AES-GCM: AES-128-CBC provides only 128-bit key security (vs. typical 256-bit for AES-GCM deployments), CBC requires separate HMAC pass (not atomic authentication), no support for Associated Data (AD) binding, and Fernet uses a fixed token format that constrains future algorithm agility. While not currently exploitable (Fernet's construction is secure), this represents a deviation from modern cryptographic best practices. The 128-bit key length is at the minimum acceptable threshold. The lack of AEAD means that encryption and authentication are separate operations, increasing implementation complexity and surface area for future bugs if the encryption layer is ever modified.

**Remediation:**

Migrate to AES-256-GCM or ChaCha20-Poly1305 for new data. Maintain Fernet support for backward compatibility during migration. Example implementation provided using cryptography.hazmat.primitives.ciphers.aead.AESGCM with 256-bit keys and 96-bit nonces. Design and implement a migration path that supports parallel operation (decrypt with Fernet, encrypt with GCM) during transition, includes a data migration tool for re-encrypting existing secrets, and maintains backward compatibility for at least one major version. Consider implementing a versioned encryption envelope format that embeds the algorithm identifier, enabling future algorithm upgrades without system-wide migrations.

---

#### FINDING-007: No message size validation before memory allocation in frame reader at supervisor layer

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-770 |
| **ASVS sections** | 2.2.2, 15.3.1 |
| **Files** | task-sdk/src/airflow/sdk/execution_time/supervisor.py:870 |
| **Source Reports** | 2.2.2.md, 15.3.1.md |
| **Related** | FINDING-008 |

**Description:**

The `length_prefixed_frame_reader` function in the supervisor (the trusted service layer) reads a 4-byte length prefix from the untrusted subprocess socket and immediately allocates a buffer of that size without any bounds checking. A malicious subprocess can send a crafted 4-byte length prefix (e.g., `0xFFFFFFFF` = 4 GiB) to force the supervisor to attempt a large memory allocation, potentially causing an out-of-memory condition in the supervisor process. Data flow: Subprocess (untrusted) writes 4-byte length → supervisor reads length → supervisor calls `bytearray(length_needed)` without bounds check → potential OOM. A compromised subprocess writes `b'\xff\xff\xff\xff'` (4 bytes indicating ~4GiB payload) to its request socket, causing the supervisor to attempt `bytearray(4294967295)`. Impact: Denial of service against the supervisor process. While this only affects the current task's supervision (one supervisor per task), it prevents proper state reporting to the API server, potentially leaving the task in an indeterminate state until heartbeat timeout cleanup.

**Remediation:**

Apply consistent field filtering as done for individual asset retrieval. Transform the response using AssetsAliasResult.from_api_response() or similar transformation, and use exclude_unset=True for serialization: elif isinstance(msg, GetAssetsByAlias): assets_resp = self.client.assets.get_by_alias(alias_name=msg.alias_name); resp = AssetsAliasResult.from_api_response(assets_resp); dump_opts = {"exclude_unset": True}

---

#### FINDING-008: Unbounded buffer growth in log socket reader without newline termination

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-770 |
| **ASVS sections** | 2.2.2 |
| **Files** | task-sdk/src/airflow/sdk/execution_time/supervisor.py:840 |
| **Source Reports** | 2.2.2.md |
| **Related** | FINDING-007 |

**Description:**

The `make_buffered_socket_reader` function accumulates data from subprocess sockets (stdout, stderr, logs) in a `bytearray` buffer until a newline is found. If the subprocess sends data without newline characters, the buffer grows indefinitely without any size limit. A malicious subprocess could exploit this to exhaust memory in the supervisor process. Data flow: Subprocess (untrusted) writes bytes without `\n` → supervisor `buffer.extend()` accumulates indefinitely → potential OOM. Proof of concept: A compromised subprocess writes continuous non-newline bytes to stdout/stderr/logs socket: `sock.sendall(b'A' * 4096)` in a loop without any `\n` characters. Impact: Memory exhaustion in the supervisor process, preventing proper task supervision and state reporting.

**Remediation:**

Add a maximum line buffer size constant (e.g., 10 MiB) and force-flush the buffer when this limit is exceeded. Example: `MAX_LINE_BUFFER_SIZE = 10 * 1024 * 1024` and check `if len(buffer) > MAX_LINE_BUFFER_SIZE: gen.send(buffer); buffer = bytearray()`. This prevents unbounded memory growth while still allowing legitimate large log lines to be processed.

---

#### FINDING-009: Insufficient documentation of input validation rules for IPC message fields

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 2.1.1 |
| **Files** | task-sdk/src/airflow/sdk/execution_time/comms.py:throughout |
| **Source Reports** | 2.1.1.md |
| **Related** | - |

**Description:**

While the Pydantic models in `comms.py` define the structural schema of all IPC messages (discriminated unions, type annotations), there is no documentation that explicitly defines input validation rules for the data items within those messages. The models lack: Maximum length constraints for string fields (`key`, `dag_id`, `task_id`, `conn_id`, etc.), Pattern/format specifications for identifiers (what constitutes a valid `dag_id`?), Numeric range constraints (what's the valid range for `limit`, `offset`, `map_index`?), Business logic constraints (which resources a subprocess is permitted to access). Without documented validation rules, developers implementing new message types or modifying existing ones have no reference for what constraints should be applied. This leads to inconsistent validation across the system and potential for exploitation of unbounded fields.

**Remediation:**

Add Pydantic field validators and document rules explicitly. Example: Use `Field` with `max_length`, `ge`/`le`, and `pattern` constraints. For GetVariableKeys: `prefix: str | None = Field(None, max_length=250)`, `limit: int = Field(1000, ge=1, le=10000)`, `offset: int = Field(0, ge=0)`. For GetXCom: `key: str = Field(..., min_length=1, max_length=512)`, `dag_id: str = Field(..., min_length=1, max_length=250, pattern=r'^[a-zA-Z0-9_.\-]+$')`, `run_id: str = Field(..., min_length=1, max_length=250)`, `task_id: str = Field(..., min_length=1, max_length=250)`, `map_index: int | None = Field(None, ge=-1)`. Additionally, create a validation rules document (e.g., `docs/ipc_validation_rules.md`) that comprehensively defines the expected formats, ranges, and constraints for each field across all message types.

---

#### FINDING-010: NativeEnvironment does not enforce sandbox attribute access restrictions

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 1.3.2 |
| **Files** | task-sdk/src/airflow/sdk/definitions/_internal/templater.py:258-259, task-sdk/src/airflow/sdk/definitions/_internal/templater.py:245-256 |
| **Source Reports** | 1.3.2.md |
| **Related** | - |

**Description:**

When a DAG sets `render_template_as_native_obj=True`, templates are processed by `NativeEnvironment` which inherits from `jinja2.nativetypes.NativeEnvironment` (NOT from `jinja2.sandbox.SandboxedEnvironment`). The `is_safe_attribute` method defined in `_AirflowEnvironmentMixin` is effectively dead code for this class — it exists but is never called because only `SandboxedEnvironment` invokes attribute safety checks during template evaluation. This means template expressions in native mode can: access any attribute on context objects (including `_` prefixed private attributes), call methods without sandbox restrictions, and traverse object graphs without safety checks. Data flow: DAG configuration (`render_template_as_native_obj=True`) → `create_template_env(native=True)` → `NativeEnvironment` created → template expressions evaluated WITHOUT sandbox enforcement → unrestricted attribute access on context objects. Gap Type: Type B — Control EXISTS (`is_safe_attribute`) but NOT CALLED for `NativeEnvironment` path.

**Remediation:**

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

---

#### FINDING-011: Context object exposure risk in template rendering

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 1.3.2 |
| **Files** | - |
| **Source Reports** | 1.3.2.md |
| **Related** | - |

**Description:**

The security of the sandbox depends critically on what objects are passed in the template context. If context includes references to API clients, database sessions, or secrets caches, even the sandboxed environment (which allows `_` prefix access) could expose sensitive resources. This module alone cannot be fully evaluated without understanding context construction.

**Remediation:**

Audit context construction (outside this module's scope) to verify that supervisor API clients, secrets caches, and other sensitive objects are not passed as template context variables or reachable through context object graphs. Consider adding a `restricted_globals` or `restricted_context` mechanism that explicitly limits which objects are available in template expressions, independent of the sandbox's attribute-level controls.

---

#### FINDING-012: No maximum frame size validation in IPC protocol allows memory exhaustion

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 2.2.1 |
| **Files** | task-sdk/src/airflow/sdk/execution_time/comms.py:225 |
| **Source Reports** | 2.2.1.md |
| **Related** | - |

**Description:**

The IPC protocol in CommsDecoder._read_frame does not validate the maximum frame size before allocating memory. A malicious task could craft a 4-byte header claiming length = 0xFFFFFFFF (4 GiB), causing the supervisor process to allocate a 4 GiB buffer, leading to OOM and DoS of the supervisor. Data flow: Task subprocess (running user code) → binary length prefix → _read_frame → bytearray(length) allocation → no maximum size enforcement. A malicious task could craft a 4-byte header claiming length = 0xFFFFFFFF (4 GiB), causing the supervisor process to allocate a 4 GiB buffer, leading to OOM and DoS of the supervisor.

**Remediation:**

Implement a configurable maximum frame size (e.g., 64 MiB) in CommsDecoder._read_frame(). Add validation: MAX_FRAME_SIZE = 64 * 1024 * 1024; if length > MAX_FRAME_SIZE: raise ValueError(f"Frame size {length} exceeds maximum allowed size {MAX_FRAME_SIZE}"). This prevents memory exhaustion from malformed length headers regardless of trust model.

---

#### FINDING-013: No Version Policy Enforcement for Dynamically-Loaded Providers

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 15.2.1 |
| **Files** | task-sdk/src/airflow/sdk/providers_manager_runtime.py:165-168 |
| **Source Reports** | 15.2.1.md |
| **Related** | - |

**Description:**

The ProvidersManagerTaskRuntime discovers and loads all installed provider packages via discover_all_providers_from_packages() without verifying that loaded providers are within any documented update or remediation timeframe. While ProviderInfo objects contain version data from the provider metadata, this version is never checked against a policy that would reject outdated or known-vulnerable components. A provider package with a known CVE would be loaded and made available without any warning or rejection, even if the documented remediation timeframe requires updating to a newer version.

**Remediation:**

Integrate vulnerability scanning into the _correctness_check() function. Implement a _check_vulnerabilities() function that queries the OSV API or similar vulnerability database with the package name and version. Before importing provider classes, check for known vulnerabilities and reject loading if critical or high severity vulnerabilities are found. Include appropriate error handling for API failures with fallback logging. Example implementation provided queries https://api.osv.dev/v1/query with package ecosystem and version information.

---

#### FINDING-014: No Runtime Component Inventory for Loaded Plugins and Providers

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 15.2.1 |
| **Files** | task-sdk/src/airflow/sdk/plugins_manager.py:62-101 |
| **Source Reports** | 15.2.1.md |
| **Related** | - |

**Description:**

The _get_plugins() function loads plugins from multiple sources (directory, entrypoints, providers) but does not produce a complete inventory (SBOM) of what was actually loaded, including versions and sources. While debug logging mentions plugin names, there is no structured inventory output that could be compared against documented update timeframes. The import_errors dict tracks failures but successful loads are not inventoried with version metadata. This prevents programmatic verification at runtime whether loaded components are within documented update timeframes.

**Remediation:**

Add structured audit logging at INFO level for component loading events. Create audit records in JSON format containing event type, timestamp, loaded component count, error count, source breakdown (directory/entrypoint/provider), and list of rejected components with reasons. Log this structured data at INFO level to ensure retention in production environments. This enables forensic analysis and compliance reporting without requiring debug-level logging.

---

#### FINDING-015: No Documentation of Update and Remediation Timeframes

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 15.2.1 |
| **Files** | - |
| **Source Reports** | 15.2.1.md |
| **Related** | - |

**Description:**

No documented update and remediation timeframes policy was found in the analyzed files or referenced in the code. ASVS 15.2.1 requires verification that components have not breached documented timeframes, which presupposes that such timeframes exist and are codified. Without documented SLAs for addressing vulnerable components, there is no baseline against which to measure compliance. This results in inconsistent response to vulnerability disclosures and inability to audit compliance with ASVS 15.2.1.

**Remediation:**

Create a SECURITY_POLICY.md or docs/component-update-policy.md document defining remediation timeframes by severity (e.g., Critical: 24 hours, High: 7 days, Medium: 30 days, Low: 90 days). Document scope to include all Apache Airflow provider packages, third-party plugins loaded via entrypoints, and direct and transitive dependencies in uv.lock. Specify enforcement mechanisms including CI/CD pipeline failures and runtime rejection of components with known critical/high CVEs.

---

#### FINDING-016: User-controllable path segments in API URLs are not percent-encoded

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-20 |
| **ASVS sections** | 1.2.2 |
| **Files** | task-sdk/src/airflow/sdk/api/client.py:358, task-sdk/src/airflow/sdk/api/client.py:380, task-sdk/src/airflow/sdk/api/client.py:437, task-sdk/src/airflow/sdk/api/client.py:467, task-sdk/src/airflow/sdk/api/client.py:636, task-sdk/src/airflow/sdk/api/client.py:315, task-sdk/src/airflow/sdk/api/client.py:516, task-sdk/src/airflow/sdk/api/client.py:495 |
| **Source Reports** | 1.2.2.md |
| **Related** | FINDING-036, FINDING-045 |

**Description:**

User DAG code can supply values containing path separators, query parameter markers, or fragment identifiers that are embedded directly into URLs via f-strings without percent-encoding. This allows path traversal to different API endpoints, query parameter injection via '?' characters, URL truncation via '#' fragment identifiers, and double-encoding issues. Data flows from user DAG code through IPC messages to the Supervisor, then to client.py where f-string URL construction occurs, resulting in HTTP requests to the Execution API. While server-side routing and JWT scoping provide outer security layers, this represents a defense-in-depth gap. Proof of concept: Variable.get('../connections/my_secret_conn') results in GET {base_url}/variables/../connections/my_secret_conn which resolves to GET {base_url}/connections/my_secret_conn.

**Remediation:**

Create a URL-safe path builder utility function that percent-encodes each path segment using urllib.parse.quote with safe='' parameter. Apply this helper across all f-string URL constructions in client.py. Example implementation:

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

---

#### FINDING-017: Old token not explicitly cleared from memory during token rotation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 7.2.4 |
| **Files** | task-sdk/src/airflow/sdk/api/client.py:1075 |
| **Source Reports** | 7.2.4.md |
| **Related** | - |

**Description:**

When the server rotates a token, the previous token value remains in process memory as an unreachable Python string object until garbage collected. In a long-running supervisor process, this creates a window where memory inspection (e.g., via `/proc/[pid]/mem` if dumpable, core dumps, or swap) could reveal previously-valid tokens. On Linux without `_make_process_nondumpable()` (or after fork in certain configurations), an attacker with same-UID access could scan `/proc/<supervisor_pid>/maps` and `/proc/<supervisor_pid>/mem` for JWT-pattern strings to recover rotated-but-not-yet-GC'd tokens.

**Remediation:**

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
Note: True secure memory clearing of Python strings is not possible due to immutability; however, minimizing references and forcing GC via `gc.collect()` after rotation reduces the exposure window. For higher assurance, consider using `mmap`-backed buffers or `ctypes` to store tokens in memory that can be explicitly zeroed.

---

#### FINDING-018: No explicit token revocation/session termination API call on task completion

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 7.4.1 |
| **Files** | task-sdk/src/airflow/sdk/execution_time/supervisor.py:720-740 |
| **Source Reports** | 7.4.1.md |
| **Related** | - |

**Description:**

Task completes → update_task_state_if_needed() sends terminal state → _upload_logs() → client closes HTTP connection → NO token invalidation API call → JWT remains valid until natural expiration. The architecture uses self-contained JWT tokens but the client has NO mechanism to signal explicit token termination to the server. The server provides token refresh (Refreshed-API-Token) but there's no corresponding token revocation or session end endpoint called by the client. After a task completes and the supervisor process terminates, the JWT token (if intercepted during its validity window) could be used by an attacker to make API calls on behalf of the terminated task instance until the token's natural expiration. The token's scope limits the damage (only operations for that specific task instance), but it violates the principle that terminated sessions should be immediately unusable.

**Remediation:**

Add a session termination endpoint call in wait() method: try { self.client.post(f"task-instances/{self.id}/session-end") } except Exception { log.debug("Failed to explicitly terminate session", ti_id=self.id) }. Alternatively, the server should be configured to invalidate the token when it receives the terminal state transition (in update_task_state_if_needed). The ASVS requirement says the application disallows any further use of the session — if the server invalidates the token upon receiving the terminal state, this requirement would be satisfied even without a separate session-end call.

---

#### FINDING-019: Token revocation window between heartbeats allows continued API access after server-side cancellation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 7.4.2 |
| **Files** | task-sdk/src/airflow/sdk/execution_time/supervisor.py:940-990 |
| **Source Reports** | 7.4.2.md |
| **Related** | - |

**Description:**

The supervisor code operates as a single-task, single-process entity. There is no mechanism visible in the client-side code for broadcasting a 'terminate all sessions for user X' command that would reach all active supervisors simultaneously. Each supervisor independently polls the server via heartbeats. If a user has multiple tasks running concurrently (each with their own supervisor and token), disabling the user's account requires the server to revoke ALL tokens associated with that user and wait for EACH supervisor to discover the revocation via heartbeat. There's no client-side support for immediate cross-task session termination.

**Remediation:**

Option 1: Reduce heartbeat interval for critical operations by adding per-request token validation check in the request method to trigger immediate shutdown on UNAUTHORIZED or FORBIDDEN responses. Option 2: Implement server-sent events or WebSocket channel for immediate revocation pushes. Option 3: Ensure the server validates the token's validity (not just signature) on EVERY API call, not just heartbeats. If this is already done server-side, then the window is effectively zero for API calls — only the subprocess execution continues without API access.

---

#### FINDING-020: Authorization rules for function-level and data-specific access are referenced but not co-located with enforcing code

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 8.1.1 |
| **Files** | AGENTS.md:lines referencing security model, task-sdk/src/airflow/sdk/execution_time/supervisor.py:800+ |
| **Source Reports** | 8.1.1.md |
| **Related** | - |

**Description:**

The AGENTS.md document references external authorization documentation (airflow-core/docs/security/security_model.rst, airflow-core/docs/security/jwt_token_authentication.rst) and describes architecture boundaries at a high level, but within the audited code scope there is no inline or co-located documentation specifying: 1) Which specific API operations each task is permitted to call (function-level rules), 2) Which data items (by dag_id, task_id, ti_id) each task's JWT token authorizes access to (data-specific rules), 3) What resource attributes determine access decisions. The supervisor's _handle_request() method handles 40+ message types without any documented access policy mapping which operations should be scoped to self.id vs. task-provided identifiers. Without co-located authorization rules, developers may not understand which operations require scope validation, leading to inconsistent enforcement. The lack of a clear access matrix makes auditing and verifying correct server-side enforcement more difficult.

**Remediation:**

Add inline documentation or a structured authorization matrix in the supervisor module documenting: Which operations are scoped to the current task's identity (self.id), Which operations allow cross-resource access (e.g., XCom reads from upstream tasks), Which operations rely entirely on API server JWT validation. Example: Authorization matrix comment showing operations scoped to self.id (enforced at supervisor): succeed, finish, retry, defer, reschedule, heartbeat, set_rtif, set_rendered_map_index; Operations with cross-task access (enforced at API server via JWT scope): GetXCom (reads from upstream tasks), TriggerDagRun (external DAGs); Operations requiring ti_id == self.id (should be validated at supervisor): GetTaskState, SetTaskState, DeleteTaskState, ClearTaskState

---

#### FINDING-021: Supervisor mediates all operations without function-level filtering — any task can invoke any supported operation type

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 8.2.1, 8.2.2 |
| **Files** | task-sdk/src/airflow/sdk/execution_time/supervisor.py:800-1050 |
| **Source Reports** | 8.2.1.md, 8.2.2.md |
| **Related** | - |

**Description:**

The supervisor's `_handle_request()` method processes ALL `ToSupervisor` message types without any function-level access check. A task subprocess can invoke any operation including: TriggerDagRun (trigger execution of any DAG), PutVariable (set any Airflow variable), DeleteVariable (delete any Airflow variable), SetXCom (write XCom values for any dag/run/task combination), DeleteXCom (delete XCom values), SetTaskState (set state values for any task instance), SetAssetStateByName/SetAssetStateByUri (modify asset state). The supervisor relies entirely on the API server's JWT validation for function-level restrictions. There is no supervisor-side policy that restricts which operation types a task may invoke. This is an intentional architectural decision (authorization at API server), but represents a lack of defense-in-depth at the supervisor layer. If the API server has any function-level gap for a specific endpoint, tasks inherit that gap.

**Remediation:**

Consider adding an optional allowlist at the supervisor level for defense-in-depth. Example: Configurable operation allowlist per task type. Add validation for operations that should be restricted to specific task contexts. Implement supervisor-side operation allowlists configurable per-task-type for defense-in-depth. Add audit logging for cross-scope write operations. Add `ti_id` validation for TaskState operations to validate `msg.ti_id == self.id` in the supervisor for GetTaskState, SetTaskState, DeleteTaskState, and ClearTaskState operations.

---

#### FINDING-022: No Connection Invalidation Method Prevents Targeted Credential Cleanup

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 14.3.1 |
| **Files** | task-sdk/src/airflow/sdk/execution_time/cache.py:140-145, task-sdk/src/airflow/sdk/execution_time/cache.py:112-120, task-sdk/src/airflow/sdk/execution_time/cache.py:122-134 |
| **Source Reports** | 14.3.1.md |
| **Related** | - |

**Description:**

The SecretCache provides invalidate_variable() for removing cached variable values, but has no equivalent invalidate_connection() or invalidate_connection_uri() method. Connection URIs — which contain plaintext credentials (passwords, tokens in query parameters) — cannot be individually removed from the cache. This asymmetry means: Even if a cleanup routine were implemented, it cannot selectively purge connection credentials; Rotated/compromised connection credentials persist until TTL expiration; The existing invalidate_variable() pattern proves the design intended per-entry invalidation, but connections were omitted. Authenticated connection credentials cannot be cleared from cache individually, preventing proper data lifecycle management. If a credential rotation or security incident occurs during task execution, the old credentials remain cached and potentially usable.

**Remediation:**

Add an invalidate_connection() class method to SecretCache that mirrors the invalidate_variable() implementation. The method should accept conn_id and optional team_name parameters, construct the cache key using _CONNECTION_PREFIX and team pattern, and call _cache.pop() to remove the entry.

---

#### FINDING-023: XCom data pushed by tasks has no visible size limit enforcement in the task runner

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 5.2.1 |
| **Files** | task-sdk/src/airflow/sdk/execution_time/task_runner.py:650, task-sdk/src/airflow/sdk/execution_time/task_runner.py:1330 |
| **Source Reports** | 5.2.1.md |
| **Related** | - |

**Description:**

A task can produce arbitrarily large XCom data that gets serialized and stored, potentially causing memory exhaustion during serialization, disk space exhaustion on the XCom storage backend, network saturation when transmitting to the API server, and DoS against other tasks competing for the same storage. Data flow: Task execution result → _push_xcom_if_needed() → _xcom_push() → XCom.set() → serialization to storage (file/DB) — no size validation at any visible stage.

**Remediation:**

Add size validation before XCom serialization. Implement a configurable maximum XCom payload size (e.g., 50MB default) and check the estimated size using sys.getsizeof() before calling XCom.set(). Raise AirflowException if the value exceeds the configured limit. Example: max_xcom_size = conf.getint("core", "max_xcom_size_bytes", fallback=50 * 1024 * 1024); estimated_size = sys.getsizeof(value); if estimated_size > max_xcom_size: raise AirflowException(f"XCom value exceeds maximum allowed size ({estimated_size} > {max_xcom_size} bytes)")

---

#### FINDING-024: DAG file path resolution lacks containment validation within bundle directory

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-22 |
| **ASVS sections** | 5.3.2 |
| **Files** | task-sdk/src/airflow/sdk/execution_time/task_runner.py:690 |
| **Source Reports** | 5.3.2.md |
| **Related** | FINDING-025 |

**Description:**

The task runner resolves DAG file paths by combining bundle path with dag_rel_path without validating that the resolved path stays within the bundle directory. Path('/bundles/my_bundle', '../../etc/malicious.py') resolves to '/etc/malicious.py' and Path('/bundles/my_bundle', '/tmp/evil.py') resolves to '/tmp/evil.py'. The _verify_bundle_access() function only checks the bundle root path, NOT the resolved dag_absolute_path. If an attacker can manipulate the execution API response (e.g., via SQL injection in the API server or a compromised scheduler), they could cause the task runner to execute code from outside the bundle boundary, leading to arbitrary code execution.

**Remediation:**

Validate dag_rel_path stays within bundle by resolving both paths and using Path.relative_to() to ensure the resolved DAG path is within the bundle root. If relative_to() raises ValueError, log the error and exit. Example: bundle_root = bundle_instance.path.resolve(); dag_absolute_path = (bundle_root / what.dag_rel_path).resolve(); dag_absolute_path.relative_to(bundle_root)

---

#### FINDING-025: Log file path creation lacks visible path traversal validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-22 |
| **ASVS sections** | 5.3.2 |
| **Files** | task-sdk/src/airflow/sdk/log.py:123 |
| **Source Reports** | 5.3.2.md |
| **Related** | FINDING-024 |

**Description:**

The init_log_file() function accepts local_relative_path parameter without validating for path traversal sequences (../, absolute paths). If constructed from user-controllable run_id (users can specify custom run_ids when triggering DAG runs via the API), path traversal is theoretically possible. Directory creation with configured permissions (0o775 default) means traversed paths get world-readable directories. For example, if run_id='../../etc/cron.d', the function would attempt to create files and directories outside the intended log directory. While run_id validation likely exists at the API level and the shared init_log_file implementation may contain path validation, no visible validation exists in this code layer.

**Remediation:**

Validate path doesn't escape base directory before file operations. Resolve both base_log_folder and the full path, then use Path.relative_to() to ensure the resolved path is within the base directory. If relative_to() raises ValueError, raise an exception indicating the log path resolves outside the base log folder.

---

#### FINDING-026: No explicit mechanism to exclude source control metadata from production deployments

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 13.4.1 |
| **Files** | Repository-wide, AGENTS.md |
| **Source Reports** | 13.4.1.md |
| **Related** | - |

**Description:**

The provided codebase does not include any explicit configuration or documentation ensuring that source control metadata (.git, .svn) is excluded from production deployments of the Task SDK. While the Task SDK is distributed as a Python library (typically via pip/wheel, which naturally excludes .git from the package), the AGENTS.md file documents that a Helm chart exists for Kubernetes deployment (chart/ directory), and the repository uses Docker/Breeze for development. Container-based deployments that copy source trees could inadvertently include .git directories. If .git is present in production, it could expose full commit history including potentially sensitive changes, developer email addresses and names, internal branch structure and development patterns, and configuration files that may reference internal systems.

**Remediation:**

1. Add .git and .svn to .dockerignore in the Helm chart's Docker context. 2. Document in deployment instructions that SCM metadata must be excluded. 3. If deploying from source rather than pip packages, add a build step to strip SCM metadata. Example .dockerignore should include: .git, .svn, .hg, .gitignore

---

#### FINDING-027: No documented risk-based remediation timeframes for third-party component vulnerabilities

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 15.1.1 |
| **Files** | AGENTS.md, client.py:29-44, supervisor.py:30-43 |
| **Source Reports** | 15.1.1.md |
| **Related** | - |

**Description:**

The audited codebase contains no documentation defining risk-based remediation timeframes for addressing vulnerabilities in third-party components. The AGENTS.md file provides extensive development instructions, testing standards, and architecture documentation, but does not address: Maximum acceptable time to patch critical/high/medium/low severity vulnerabilities, timeframes for routine dependency updates, process for monitoring new vulnerabilities in dependencies, or escalation procedures when timeframes are exceeded. Without defined remediation timeframes, critical vulnerabilities in dependencies (e.g., httpx, certifi, pydantic) may remain unpatched indefinitely, there is no accountability mechanism for timely updates, increased attack surface as known vulnerabilities persist in production, and non-compliance with industry standards (e.g., PCI DSS requires critical patches within 30 days).

**Remediation:**

Create a security policy document (e.g., SECURITY_DEPENDENCY_POLICY.md) that defines: (1) Vulnerability Remediation Timeframes with severity-based SLAs: Critical (9.0-10.0 CVSS) - 72 hours emergency patch release, High (7.0-8.9) - 7 calendar days priority update PR, Medium (4.0-6.9) - 30 calendar days scheduled update, Low (0.1-3.9) - 90 calendar days next routine update. (2) Routine Update Schedule: Security-critical libraries (httpx, certifi, cryptography) - monthly review, all other dependencies - quarterly review, lock file (uv.lock) regeneration with each update cycle. (3) Monitoring: Enable Dependabot/GitHub security advisories, monitor PyPI advisory database, subscribe to CVE feeds for critical dependencies. (4) Escalation: If remediation timeframe cannot be met, a tracking issue must be filed per AGENTS.md tracking issues for deferred work section.

### 3.4 Low

#### FINDING-028: Client does not handle HTTP 429 (Too Many Requests) responses with backoff

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 6.3.1 |
| Files | task-sdk/src/airflow/sdk/api/client.py:1020-1025 |
| Source Reports | 6.3.1.md |
| Related | - |

**Description:**

If the server implements rate limiting (as recommended by NIST SP 800-63B §5.2.2 for brute force prevention), the client will not respect server-side throttling signals. Instead of backing off and retrying, it will raise an unhandled error, potentially losing task execution context. Server returns 429 → `raise_on_4xx_5xx` raises `HTTPStatusError` → `_should_retry_api_request` returns False (status 429 < 500) → request fails immediately without backoff. Proof of concept: Server returns `HTTP 429 Too Many Requests` with `Retry-After: 5` header during a heartbeat call → client raises `HTTPStatusError` → supervisor treats it as a hard failure, potentially killing the task prematurely.

**Remediation:**

Extend `_should_retry_api_request` to retry on HTTP 429 status codes. Modify the function to return True for status code 429 in addition to 5xx errors. Additionally, consider respecting the `Retry-After` header when present. Example fix: `def _should_retry_api_request(exception: BaseException) -> bool: if isinstance(exception, httpx.HTTPStatusError): status = exception.response.status_code; return status >= 500 or status == 429; return isinstance(exception, httpx.RequestError)`

---

#### FINDING-029: Token refresh hook executes on all responses including error responses

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 9.1.1 |
| Files | task-sdk/src/airflow/sdk/api/client.py:1060 |
| Source Reports | 9.1.1.md |
| Related | - |

**Description:**

ANY HTTP response (including 4xx/5xx) → `_update_auth` executes FIRST → if `Refreshed-API-Token` header present, token is updated → THEN `raise_on_4xx_5xx` raises error. A server error response (e.g., 500) that happens to include a `Refreshed-API-Token` header would cause the client to adopt the new token even though the request failed. While unlikely in normal operation, a server bug or proxy injection could cause unexpected token replacement.

**Remediation:**

Add a check at the beginning of `_update_auth()` method to only accept token refresh from successful responses: `if not response.is_success: return`

---

#### FINDING-030: Server-side JWT algorithm validation cannot be verified from provided code

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 9.1.2 |
| Files | - |
| Source Reports | 9.1.2.md |
| Related | - |

**Description:**

The ASVS 9.1.2 requirement mandates that 'only algorithms on an allowlist can be used to create and verify self-contained tokens.' The primary enforcement point for this requirement is the Execution API server, which validates incoming JWT tokens on every request. The server-side token validation code (referenced in `airflow-core/docs/security/jwt_token_authentication.rst`) is not included in the audit scope. The client-side code exclusively acts as a bearer of the token—it never verifies the token's signature or makes authorization decisions based on token content. This is architecturally appropriate, but it means the full ASVS 9.1.2 compliance cannot be assessed from the provided files alone. If the server-side code lacks algorithm allowlisting (e.g., accepts `alg: none` or allows algorithm confusion between HMAC and RSA), tokens could be forged.

**Remediation:**

Verify in the Execution API server implementation that: 1) A strict algorithm allowlist is configured (e.g., only RS256 or only HS256), 2) The `none` algorithm is explicitly rejected, 3) If both symmetric and asymmetric algorithms must be supported, key confusion prevention is in place (e.g., separate key sets per algorithm family). Audit the server-side JWT validation middleware to ensure ASVS 9.1.2, 9.1.3, and 9.2.1 compliance. Document the algorithm allowlist and key management approach.

---

#### FINDING-031: Server-side key material source validation cannot be verified from provided code

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 9.1.3 |
| Files | - |
| Source Reports | 9.1.3.md |
| Related | - |

**Description:**

The requirement that headers such as jku, x5u, and jwk must be validated against an allowlist of trusted sources applies to the server-side JWT verification logic. The Execution API server code performing token validation is not included in the audit scope. From the architecture documentation, the server creates and validates JWT tokens for task instances. The key configuration (symmetric vs. asymmetric, key storage) is documented in airflow-core/docs/security/jwt_token_authentication.rst, which is not provided. Cannot confirm or deny ASVS 9.1.3 compliance for the system as a whole from the provided client-side code.

**Remediation:**

Verify in the server-side code that: (1) jku, x5u, and jwk headers in incoming JWTs are either rejected or validated against a strict allowlist, (2) Key material comes from pre-configured sources (e.g., configuration files, KMS), (3) The signing key is not derivable from information in the token itself.

---

#### FINDING-032: Initial token accepted without client-side expiration check

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 9.2.1 |
| Files | task-sdk/src/airflow/sdk/api/client.py, task-sdk/src/airflow/sdk/execution_time/supervisor.py |
| Source Reports | 9.2.1.md |
| Related | - |

**Description:**

The initial token passed to `supervise_task` is used to construct the `Client` without any check of its validity period. If the token was already expired when the supervisor received it (e.g., due to scheduling delays or clock skew), the task will fail on the first API call with an authentication error rather than failing early with a descriptive error.

**Remediation:**

Add early validation of token expiration in `supervise_task` before forking the task subprocess. Decode the JWT payload and check the exp claim with appropriate clock skew tolerance. Fail fast with a descriptive error message that includes guidance about clock synchronization.

---

#### FINDING-033: Server-side token expiration validation cannot be verified from provided code

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 9.2.1 |
| Files | - |
| Source Reports | 9.2.1.md |
| Related | - |

**Description:**

ASVS 9.2.1 requires verification that tokens with `nbf` and `exp` claims are only accepted within their validity time span. The primary enforcement of this requirement happens in the Execution API server's JWT validation middleware. This code is not included in the audit scope. Per the architecture documentation, tokens are designed to be short-lived, suggesting expiration enforcement exists server-side, but cannot be confirmed from client-side code alone.

**Remediation:**

Verify in the Execution API server that: 1. `exp` claim is REQUIRED and always validated 2. `nbf` claim is validated when present 3. Appropriate clock skew tolerance is configured (typically 30-60 seconds) 4. Tokens are rejected BEFORE processing the request body

---

#### FINDING-034: No Certificate Revocation Checking (OCSP/CRL) Configured

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-299 |
| ASVS sections | 12.2.2 |
| Files | task-sdk/src/airflow/sdk/api/client.py:540-545 |
| Source Reports | 12.2.2.md |
| Related | - |

**Description:**

If the Execution API server's TLS certificate is compromised and revoked by the CA, the client will continue to trust it until the certificate expires naturally. This window could be days to months depending on the certificate's validity period. An attacker who compromises a server's private key could perform man-in-the-middle attacks even after the certificate is revoked. This is a defense-in-depth concern. Python's ssl module has limited OCSP support (no OCSP stapling verification on the client side without additional libraries). CRL checking via ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF requires providing CRL distribution points, which is operationally complex.

**Remediation:**

For production deployments, consider: 1. Using a service mesh (Istio, Linkerd) that handles certificate rotation and revocation 2. Short-lived certificates (< 24h) that minimize the revocation window 3. Certificate pinning for the known Execution API server certificate. Optionally enable CRL checking if CRL files are available using `ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF`. For OCSP, consider using a library like pyOpenSSL or certvalidator for production deployments requiring revocation checking.

---

#### FINDING-035: _NullFernet fallback allows operation without any encryption

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 11.3.2 |
| Files | task-sdk/src/airflow/sdk/crypto.py:40-58 |
| Source Reports | 11.3.2.md |
| Related | - |

**Description:**

When FERNET_KEY is not configured, sensitive connection passwords, extra fields, and variables are stored in plaintext. The _NullFernet class returns plaintext data without any encryption applied. While a warning is logged, there is no enforcement mechanism to prevent production operation without encryption. This means no approved cipher is used at all in this configuration. The system can operate without any encryption, creating a configuration-dependent security posture where sensitive data (passwords, extras, variables) may be stored unencrypted.

**Remediation:**

Consider making encryption mandatory in production by failing hard rather than degrading silently. Implement a configuration option to fail-hard in production when FERNET_KEY is not set. Example: Check for FERNET_KEY and if not present, check for an explicit allow_unencrypted_secrets configuration flag. If neither is set, raise an AirflowException indicating that FERNET_KEY must be set or allow_unencrypted_secrets must be explicitly enabled for non-production environments. This prevents accidental plaintext storage in production.

---

#### FINDING-036: Missing field-level validation constraints on IPC message models at supervisor layer

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-20 |
| ASVS sections | 2.2.2, 2.2.1 |
| Files | task-sdk/src/airflow/sdk/execution_time/comms.py |
| Source Reports | 2.2.2.md, 2.2.1.md |
| Related | FINDING-016, FINDING-045 |

**Description:**

The Pydantic models used for IPC message validation at the supervisor (trusted) layer enforce type correctness via the `TypeAdapter` but lack field-level validation constraints. Numeric fields like `limit` and `offset` in `GetVariableKeys` have no range constraints (`ge`, `le`), and string fields have no length limits (`max_length`). While the API server provides secondary validation, the supervisor—as the first trusted validation point—should enforce reasonable bounds to prevent resource abuse. Data flow: Subprocess constructs message → Pydantic validates types only → supervisor passes unconstrained values to API client. Impact: Without field constraints at the supervisor layer, a subprocess can send semantically invalid requests (negative offsets, extreme limits, oversized strings) that consume supervisor resources during HTTP request construction before reaching the API server's validation.

**Remediation:**

Add Pydantic `Field` constraints to all message models. Examples: `prefix: str | None = Field(None, max_length=1000)`, `limit: int = Field(1000, ge=1, le=10000)`, `offset: int = Field(0, ge=0)`, `key: str = Field(..., min_length=1, max_length=512)`, `dag_id: str = Field(..., min_length=1, max_length=250)`. Start with the most permissive models (SetXCom.value, GetVariableKeys.limit, string fields) and expand coverage progressively.

---

#### FINDING-037: No documented validation rules for callback execution paths

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-94 |
| ASVS sections | 2.1.1 |
| Files | task-sdk/src/airflow/sdk/execution_time/callback_supervisor.py:72-78 |
| Source Reports | 2.1.1.md |
| Related | - |

**Description:**

The `execute_callback` function accepts a `callback_path` string that is dynamically imported and executed. While this value originates from the trusted supervisor layer (not the subprocess), there is no documentation defining what constitutes a valid callback path—e.g., allowed module prefixes, naming conventions, or a whitelist of permitted callbacks. Without documented validation rules for callback paths, maintainers cannot easily verify that new callback invocations conform to expected patterns. If an upstream component inadvertently passes an unsanitized callback path, arbitrary code execution could occur within the callback subprocess.

**Remediation:**

Document the expected format and origin of `callback_path` values. Consider adding validation using a regex pattern. Example: `VALID_CALLBACK_PATH_PATTERN = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_.]*\.[a-zA-Z_][a-zA-Z0-9_]*$')`. In `execute_callback`: check if `callback_path` matches the pattern, and if not, return `False, f"Invalid callback path format: {callback_path}"` before attempting import.

---

#### FINDING-038: No JSON-specific encoding filters provided in custom filter set for template rendering

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 1.2.3 |
| Files | task-sdk/src/airflow/sdk/definitions/_internal/templater.py:302-308, task-sdk/src/airflow/sdk/definitions/_internal/templater.py:309-340 |
| Source Reports | 1.2.3.md |
| Related | - |

**Description:**

The custom filter set only includes date/time formatting filters. When templates are used to dynamically build JSON strings (e.g., REST API operator bodies), there is no explicit JSON-safe filter provided or documented in the custom set. If a DAG author writes `{"key": "{{ params.user_input }}"}` and `user_input` contains characters like `"`, `\`, or newlines, the resulting JSON structure could be corrupted. Mitigating factors include: Jinja2's built-in `tojson` filter IS available (not removed) and handles proper JSON escaping; Template source is authored by DAG developers (trusted within their process boundary); Output is task parameters, not served directly to browsers; `NativeEnvironment` mode returns Python native types (avoiding string-based JSON construction entirely).

**Remediation:**

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

---

#### FINDING-039: `jinja2.ext.do` extension enabled by default allows statement execution in templates

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 1.3.2 |
| Files | task-sdk/src/airflow/sdk/definitions/_internal/templater.py:315 |
| Source Reports | 1.3.2.md |
| Related | - |

**Description:**

The `jinja2.ext.do` extension is enabled by default in all template environments. This extension allows executing expression statements (e.g., `{% do items.append(x) %}`) which enables mutation of objects accessible in the template context. While the sandbox restricts what methods can be called in `SandboxedEnvironment`, the `do` extension expands the attack surface beyond pure expression evaluation. In native mode (per ASVS-132-MED-001), it enables unrestricted statement execution. However, template source is authored by DAG developers who already have Python code execution capability.

**Remediation:**

Consider whether the `do` extension is necessary for the default template environment. If not required for typical use cases, remove it:

```python
jinja_env_options = {
    "undefined": template_undefined,
    "extensions": [],  # Remove jinja2.ext.do unless explicitly needed
    "cache_size": 0,
}
```

If needed for backward compatibility, document the security implications and consider making it opt-in via `jinja_environment_kwargs`.

---

#### FINDING-040: Client does not validate Content-Type header on successful HTTP responses before parsing

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 4.1.1 |
| Files | task-sdk/src/airflow/sdk/api/client.py:282, task-sdk/src/airflow/sdk/api/client.py:195, task-sdk/src/airflow/sdk/api/client.py:257, task-sdk/src/airflow/sdk/api/client.py:300, task-sdk/src/airflow/sdk/api/client.py:340, task-sdk/src/airflow/sdk/api/client.py:460 |
| Source Reports | 4.1.1.md |
| Related | - |

**Description:**

The HTTP client does not validate the Content-Type header on successful (2xx) responses before attempting to parse them as JSON. All operation methods that call `model_validate_json(resp.read())` skip Content-Type validation. If a reverse proxy, CDN, or misconfigured load balancer returns `Content-Type: text/html` with an HTML error page on a 200 status code (e.g., captive portal), the client would attempt to parse HTML as JSON, resulting in a confusing `ValidationError` rather than a clear "unexpected content type" error. The error handling path correctly validates Content-Type in `ServerResponseError.from_response` (line ~555), but this validation is not applied to success responses. This creates an asymmetry where Content-Type is validated for errors but not for successful responses.

**Remediation:**

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

---

#### FINDING-041: Client does not set Accept header to signal expected response format

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 4.1.1 |
| Files | task-sdk/src/airflow/sdk/api/client.py:493 |
| Source Reports | 4.1.1.md |
| Related | - |

**Description:**

The HTTP client does not set an Accept header when making requests. Without an `Accept` header, the server has no client-side signal to guide content negotiation. If the API server supports multiple response formats, it may default to a non-JSON format. The client initialization in `Client.__init__` (line ~493) sets `user-agent` and `airflow-api-version` headers but omits the `accept` header. This violates HTTP best practices for content negotiation. Practically low risk given the API is designed for this specific client, but could cause issues if the server implementation changes or if proxies perform content negotiation.

**Remediation:**

Add the Accept header to the client initialization:

```python
headers={
    "user-agent": f"apache-airflow-task-sdk/{__version__} (Python/{pyver})",
    "airflow-api-version": API_VERSION,
    "accept": "application/json",
},
```

---

#### FINDING-042: Default Non-Lazy Provider Loading Increases Attack Surface

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 15.2.1 |
| Files | task-sdk/src/airflow/sdk/plugins_manager.py:95 |
| Source Reports | 15.2.1.md |
| Related | - |

**Description:**

When settings.LAZY_LOAD_PROVIDERS is False (which triggers eager loading), all provider plugins are loaded regardless of whether they are needed for the current task. This means components that may have breached update timeframes are loaded into memory and available for execution even when not required, unnecessarily expanding the attack surface. All installed providers are loaded even when only a subset is needed, making it harder to determine which components are actually in use for remediation prioritization.

**Remediation:**

Make lazy loading (LAZY_LOAD_PROVIDERS=True) the default for production deployments. Implement and document a provider allowlist mechanism that only loads explicitly required providers. Add configuration option to specify REQUIRED_PROVIDERS as a list, and filter _provider_dict to only include allowed providers when this configuration is set. This reduces attack surface by ensuring only operationally necessary components are loaded.

---

#### FINDING-043: Static Resource Version Not Suitable for Change Detection

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 15.2.1 |
| Files | task-sdk/src/airflow/sdk/providers_manager_runtime.py:105 |
| Source Reports | 15.2.1.md |
| Related | - |

**Description:**

The resource_version property returns a static string '0' intended as a cache version identifier. This static value means the cache cannot be invalidated when the set of installed providers changes (e.g., after a security update), potentially causing stale provider metadata to be used. After updating a provider package to remediate a vulnerability, cached metadata from the old version may still be used until process restart. Cache invalidation requires manual intervention rather than automatic detection of provider landscape changes.

**Remediation:**

Generate a dynamic resource version based on installed provider versions. Compute a hash of all provider package names and versions from _provider_dict, and use this hash as the resource_version. Cache the computed version to avoid repeated calculations. This enables automatic cache invalidation when the provider landscape changes due to package updates, ensuring that security updates are reflected immediately without requiring process restarts.

---

#### FINDING-044: Server-controlled header value used in exception notes without output encoding validation

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 1.2.1 |
| Files | task-sdk/src/airflow/sdk/api/client.py:172-180 |
| Source Reports | 1.2.1.md |
| Related | - |

**Description:**

HTTP Response Header (correlation-id) is embedded in exception notes and potentially logged without context-aware encoding. If the Execution API server (or a man-in-the-middle in a misconfigured environment) returns a crafted correlation-id header containing log-injection payloads (e.g., ANSI escape sequences, multi-line content, or JSON structure-breaking characters), these would be embedded in exception notes and potentially logged without context-aware encoding. However, since the communication is with a trusted internal API server over TLS, exploitability is low.

**Remediation:**

Sanitize or validate the correlation-id format (UUID) before embedding in exception notes:

```python
import re
_CORRELATION_RE = re.compile(r'^[0-9a-f-]{36,}$', re.IGNORECASE)

def _safe_correlation_id(response: httpx.Response) -> str:
    cid = response.headers.get('correlation-id') or response.request.headers.get('correlation-id', 'no-correlation-id')
    return cid if _CORRELATION_RE.match(cid) else 'invalid-correlation-id'
```

---

#### FINDING-045: No explicit allowlist for URL protocol schemes in base_url configuration

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-20 |
| ASVS sections | 1.2.2 |
| Files | task-sdk/src/airflow/sdk/api/client.py:810 |
| Source Reports | 1.2.2.md |
| Related | FINDING-016, FINDING-036 |

**Description:**

The Client.__init__ method accepts a base_url parameter from Airflow configuration without explicitly validating the URL scheme against an allowlist. While the base_url comes from admin-controlled configuration (not user input) and httpx validates URL schemes internally, this represents a defense-in-depth observation. There is no runtime user input path, making this a very low severity issue rather than an exploitable vulnerability.

**Remediation:**

Add explicit scheme validation to enforce only http and https protocols:

```python
from urllib.parse import urlparse

if base_url:
    parsed = urlparse(base_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported URL scheme: {parsed.scheme}")
```

---

#### FINDING-046: Supervisor API token accessible in forked child process memory on Linux

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 7.2.4, 8.3.1 |
| Files | task-sdk/src/airflow/sdk/execution_time/supervisor.py:380-420 |
| Source Reports | 7.2.4.md, 8.3.1.md |
| Related | - |

**Description:**

On Linux (where bare fork is used instead of fork+exec), the child process inherits the parent's memory space, which includes the API token in the `Client` object. While the child doesn't explicitly use the token (communication is via socketpairs), a sufficiently motivated malicious task could potentially scan process memory for the token. Mitigating controls include: (1) `_make_process_nondumpable()` sets `PR_SET_DUMPABLE=0`, preventing other processes from ptrace-ing or reading `/proc/pid/mem`, (2) On macOS, fork+exec is used, which replaces the process image entirely, (3) The token is scoped to the task instance, limiting impact of any leak, (4) The supervisor process itself IS the trust boundary (per documentation). Impact is minimal as the token is scoped to the current task execution, so even if recovered, it only grants the same access the task already has through SUPERVISOR_COMMS.

**Remediation:**

On Linux fork path, consider explicitly zeroing or deleting the parent's client/token references in the child before calling `_fork_main`. Example: In the child process (pid == 0), after closing unused sockets and deleting constructor_kwargs and logger, add explicit clearing of any remaining references to API credentials and call gc.collect() to ensure cleanup before proceeding to _fork_main.

---

#### FINDING-047: Token reference retained in Client object after connection close

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 7.4.1 |
| Files | task-sdk/src/airflow/sdk/api/client.py |
| Source Reports | 7.4.1.md |
| Related | - |

**Description:**

Client.__init__(token=...) → BearerAuth(token) → self.auth.token → client.close() closes HTTP connection but doesn't clear self.auth.token → token persists until new_client goes out of scope and GC runs. After client.close() is called, the token remains accessible via client.auth.token until Python's garbage collector reclaims the object. In the supervisor's process lifetime, this is a brief window, but for long-running processes or when clients are cached, this extends the exposure.

**Remediation:**

Override close() in Client class to clear sensitive token reference: def close(self): self.auth = BearerAuth(""); super().close()

---

#### FINDING-048: Fernet Key Object Cached Indefinitely Without Clear Mechanism

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 14.3.1 |
| Files | task-sdk/src/airflow/sdk/crypto.py:86, task-sdk/src/airflow/sdk/crypto.py:67-82, task-sdk/src/airflow/sdk/crypto.py:52-64 |
| Source Reports | 14.3.1.md |
| Related | - |

**Description:**

The get_fernet() function uses Python's @cache decorator, which caches the result (containing encryption keys in memory) indefinitely. While get_fernet.cache_clear() is available via the decorator's API, it is never called during session termination. The Fernet object and its underlying key material remain in process memory for the entire interpreter lifetime. Encryption key material persists in process memory. In the current architecture (process-per-task), this is mitigated by process exit. If the architecture evolves to reuse processes, key material from one session would be available in the next.

**Remediation:**

Add a clear_fernet_cache() function that calls get_fernet.cache_clear() to remove cached Fernet keys from memory. Register this function with atexit or call it explicitly during session termination in task cleanup code.

---

#### FINDING-049: Email template files read entirely into memory without size validation

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 5.2.1 |
| Files | task-sdk/src/airflow/sdk/execution_time/task_runner.py:1373 |
| Source Reports | 5.2.1.md |
| Related | - |

**Description:**

If the configured path points to a large file (or a special file like /dev/urandom on certain OS configurations), unbounded read_text() could consume excessive memory. Data flow: Configuration value → Path().exists() → Path().read_text() (unbounded read) → memory. This is LOW severity because the path is admin-configured and not user-controllable at runtime.

**Remediation:**

Add file size validation before reading email template files. Check the file size using Path().stat().st_size and reject files exceeding a reasonable limit (e.g., 64 KB). Example: MAX_TEMPLATE_SIZE = 64 * 1024; if template_path.stat().st_size > MAX_TEMPLATE_SIZE: log.warning("Email subject template exceeds size limit, using default") else: subject = template_path.read_text()

---

#### FINDING-050: relative_path_from_logger validates path relationship but upload_to_remote doesn't handle the ValueError

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-703 |
| ASVS sections | 5.3.2 |
| Files | task-sdk/src/airflow/sdk/log.py:197, task-sdk/src/airflow/sdk/log.py:178 |
| Source Reports | 5.3.2.md |
| Related | - |

**Description:**

The relative_path_from_logger function correctly uses Path.relative_to() which raises ValueError if the log file path is not within base_log_folder. The upload_to_remote function catches this with a bare 'except Exception: return', which is actually a positive defensive pattern - if the path escapes the base directory, the upload is silently skipped. However, the bare except swallows the error without logging, which could mask issues and make debugging difficult.

**Remediation:**

Log the exception for debugging purposes. Specifically catch ValueError to log when log file is not within base_log_folder and skipping remote upload. Keep the general Exception handler but add debug logging with exc_info=True to aid troubleshooting.

---

#### FINDING-051: No documentation identifying risky components or components with dangerous functionality

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 15.1.1 |
| Files | AGENTS.md, providers_manager_runtime.py:49, supervisor.py:36, client.py:33 |
| Source Reports | 15.1.1.md |
| Related | - |

**Description:**

Per ASVS 15.1.1's section description, documentation should identify components containing dangerous functionality (deserialization of untrusted data, raw file parsing, dynamic code execution, direct memory manipulation) or risky components (poorly maintained, unsupported, history of vulnerabilities). The Task SDK uses several such components without explicit risk documentation: (1) import_string from airflow.sdk._shared.module_loading performs dynamic code execution - loading arbitrary Python modules by string name. (2) msgspec library performs binary deserialization (msgpack) of data from subprocess IPC channels in supervisor.py and is used to decode server error responses in client.py. Without documented risk assessment of these components, developers may not apply appropriate defensive measures when using or updating them.

**Remediation:**

Add a Component Risk Assessment section to architectural documentation listing: (1) Components performing dangerous operations (msgspec, import_string, os.fork/os.execv), (2) Their risk classification, (3) Mitigations applied (e.g., TypeAdapter validation for msgspec, _correctness_check for import_string).

---

#### FINDING-052: No documentation of rate limiting, anti-automation, or adaptive response controls for credential access

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 6.1.1 |
| Files | AGENTS.md:220-260, task-sdk/src/airflow/sdk/execution_time/secrets/execution_api.py:43-67 |
| Source Reports | 6.1.1.md |
| Related | - |

**Description:**

The AGENTS.md Security Model section documents trust boundaries, JWT tokens, and component isolation, but does not describe controls such as rate limiting, anti-automation, or adaptive response mechanisms that defend against credential stuffing or password brute force attacks. The ExecutionAPISecretsBackend retrieves connections/variables with no documented throttling or lockout behavior. Data flow: User/task code → Connection.get() → ExecutionAPISecretsBackend.get_connection() → SUPERVISOR_COMMS → Execution API — no rate limiting or lockout documented at any stage. The AGENTS.md explicitly references airflow-core/docs/security/security_model.rst for the authoritative security documentation. The known false positive patterns note that 'No rate limiting on Execution API client (client.py)' is intentional because 'rate limiting belongs on the server side.' This suggests the server should have these controls, but the documentation provided doesn't describe them.

**Remediation:**

Add a security documentation section (in the referenced security_model.rst or similar) that explicitly describes: 1. Rate limiting applied to the Execution API for credential retrieval 2. Anti-automation controls for login/authentication endpoints 3. Adaptive response mechanisms (progressive delays, temporary lockout) 4. Configuration to prevent malicious account lockout

---

#### FINDING-053: No client-side token expiration awareness or proactive refresh mechanism

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-613 |
| ASVS sections | 10.4.5 |
| Files | task-sdk/src/airflow/sdk/api/client.py |
| Source Reports | 10.4.5.md |
| Related | - |

**Description:**

The client has no awareness of token expiration. If the server does not send a `Refreshed-API-Token` header before the current token expires, the client will continue sending expired tokens until it receives a 401 response. There is no proactive refresh mechanism, no token introspection, and no handling of 401 responses to trigger re-authentication. The retry logic (`_should_retry_api_request`) only retries on 5xx and network errors — a 401 from an expired token would not be retried and would propagate as an unrecoverable error. For long-running tasks, there's a risk of token expiry without recovery.

**Remediation:**

Consider adding 401 handling that logs a clear message about token expiration, or implement client-side JWT expiry checking to warn before expiration.

---

---

# 4. Positive Security Controls

| Control ID | Control Description | Evidence | Affected Files | Domain |
|------------|-------------------|----------|----------------|---------|
| PSC-001 | Bearer token (JWT) authentication exclusively - no password-based authentication | The client uses Bearer token authentication exclusively, eliminating traditional credential stuffing attack vector. Token is pre-provisioned per task execution rather than obtained through a login flow. | `task-sdk/src/airflow/sdk/api/client.py` | execution_api_authentication |
| PSC-002 | Bounded retry attempts prevent infinite retry loops | `stop_after_attempt(API_RETRIES)` prevents infinite retry loops that could amplify brute force attempts. | `task-sdk/src/airflow/sdk/api/client.py` | execution_api_authentication |
| PSC-003 | Authentication failures are not retried | The retry logic only triggers on 5xx and network errors, not on 401/403 authentication failures, preventing the client from becoming a brute force tool if an invalid token is used. | `task-sdk/src/airflow/sdk/api/client.py` | execution_api_authentication |
| PSC-004 | Exponential backoff with jitter | `wait_random_exponential` prevents thundering herd patterns that could overwhelm the server. | `task-sdk/src/airflow/sdk/api/client.py` | execution_api_authentication |
| PSC-005 | Short-lived JWTs scoped to individual task executions | The system uses short-lived JWTs scoped to individual task executions. Tokens are generated server-side, delivered to the supervisor, and used by the client for API authentication. | `task-sdk/src/airflow/sdk/api/client.py`, `AGENTS.md` | execution_api_authentication |
| PSC-006 | Process isolation with nondumpable memory and ORM blocking | The combination of `_make_process_nondumpable()`, `block_orm_access()`, and the fork-based subprocess model provides multiple layers of isolation for the authentication token in memory. | `task-sdk/src/airflow/sdk/api/client.py`, `supervisor.py` | execution_api_authentication |
| PSC-007 | Heartbeat authentication failure handling | The `_send_heartbeat_if_needed()` method correctly handles 404/410/409 server responses and kills the process, preventing a compromised or expired token from continuing to be used. | `task-sdk/src/airflow/sdk/api/client.py` | execution_api_authentication |
| PSC-008 | Dynamic user identification - no default accounts | Uses system-level user via getuser(); no defaults. Identity derived from JWT, not static accounts. | `client.py` | execution_api_authentication |
| PSC-009 | No hardcoded credentials | BearerAuth class requires a token parameter; there is no fallback to a default token or account. Test-only empty token used only in testing contexts with dry_run=True and in-process transports. | `client.py`, `supervisor.py` | execution_api_authentication |
| PSC-010 | TLS certificate verification with mutual TLS support | `_get_ssl_context_cached()` ensures communication with legitimate server using certifi.where() and API_SSL_CERT_PATH. Client certificate auth via API_CLIENT_SSL_CERT and API_CLIENT_SSL_KEY environment variables provides bidirectional authentication. | `client.py:_get_ssl_context_cached()` | execution_api_authentication |
| PSC-011 | Server-side session token validation | Each task receives a short-lived JWT token scoped to its task instance ID. Client never parses or trusts JWT payload for access control; only presents token to server for validation. | `AGENTS.md`, `client.py` | execution_api_authentication |
| PSC-012 | Dynamic JWT per task execution with token refresh mechanism | Each task gets a unique token generated externally per task execution. Server can issue new dynamic tokens during execution via Refreshed-API-Token header. No static API keys used for session management. | `supervisor.py:supervise_task()`, `client.py:_update_auth()` | execution_api_authentication |
| PSC-013 | Token isolation from subprocess | The JWT token is NOT passed to the task subprocess. Only the supervisor holds the token and makes authenticated API calls on behalf of the task, limiting the blast radius of token compromise. | `supervisor.py` | execution_api_authentication |
| PSC-014 | Server-initiated termination on invalid token responses | When the server responds with 404, 410, or 409 to a heartbeat, the supervisor immediately kills the task subprocess, providing a mechanism for the server to enforce token expiration. | `supervisor.py:948-960` | execution_api_authentication |
| PSC-015 | SSL context is always applied for production connections | The `verify` parameter is unconditionally set when `dry_run=False`, ensuring TLS is always configured for real API calls | `task-sdk/src/airflow/sdk/api/client.py:562` | tls_transport_security |
| PSC-016 | No `verify=False` anywhere in the code | Certificate verification is never bypassed | `task-sdk/src/airflow/sdk/api/client.py` | tls_transport_security |
| PSC-017 | SSL context caching | The `@lru_cache()` decorator on `_get_ssl_context_cached` prevents memory growth while maintaining a consistent SSL configuration | `task-sdk/src/airflow/sdk/api/client.py:540` | tls_transport_security |
| PSC-018 | `ssl.create_default_context()` provides good baseline | Disables SSLv2, SSLv3, compression, and sets `check_hostname=True` and `verify_mode=CERT_REQUIRED` by default | `task-sdk/src/airflow/sdk/api/client.py:541` | tls_transport_security |
| PSC-019 | No explicit HTTP fallback mechanism | The code doesn't implement a 'try HTTPS, fall back to HTTP' pattern — if TLS fails, the request fails | `task-sdk/src/airflow/sdk/api/client.py:548-580` | tls_transport_security |
| PSC-020 | Client certificate (mTLS) support | The code supports `cert=(cert_path, key_path)` for mutual TLS, providing additional authentication beyond server-side TLS. Both client_ssl_cert and client_ssl_key must be set together (enforced by ValueError), preventing partial/broken mTLS configuration | `task-sdk/src/airflow/sdk/api/client.py` | tls_transport_security |
| PSC-021 | Retry only on network errors/5xx | The retry logic (`_should_retry_api_request`) does not attempt to downgrade the connection on TLS failures | `task-sdk/src/airflow/sdk/api/client.py` | tls_transport_security |
| PSC-022 | Dry-run mode is properly isolated | The `dry_run=True` code path uses `httpx.MockTransport` and never touches the real SSL context or network | `task-sdk/src/airflow/sdk/api/client.py:548-580` | tls_transport_security |
| PSC-023 | TLS configuration centralization | All TLS settings are centralized in `Client.__init__` and `_get_ssl_context_cached`. There's a single point where SSL context is configured, cached, and applied to all API requests | `task-sdk/src/airflow/sdk/api/client.py:541`, `task-sdk/src/airflow/sdk/api/client.py:548-580` | tls_transport_security |
| PSC-024 | Publicly trusted CA bundle (certifi) used as primary trust anchor | The code uses certifi.where() which provides the Mozilla/NSS root certificate program — a well-maintained, publicly trusted CA bundle. This directly satisfies the requirement for publicly trusted certificates | `task-sdk/src/airflow/sdk/api/client.py:562` | tls_transport_security |
| PSC-025 | Custom CA support is additive, not replacement | The API_SSL_CERT_PATH configuration adds additional trusted CAs on top of the certifi bundle (via load_verify_locations), rather than replacing it. This supports enterprise deployments with internal CAs while maintaining public trust | `task-sdk/src/airflow/sdk/api/client.py:543` | tls_transport_security |
| PSC-026 | Fernet encryption (AES-128-CBC + HMAC-SHA256) | Applied to all sensitive data encryption/decryption via get_fernet() | `task-sdk/src/airflow/sdk/crypto.py:63-81` | secrets_encryption_storage |
| PSC-027 | MultiFernet wrapper | Provides key rotation support | `task-sdk/src/airflow/sdk/crypto.py:84-104` | secrets_encryption_storage |
| PSC-028 | Encrypt-then-MAC | Prevents padding oracle attacks against CBC mode | Fernet library implementation | secrets_encryption_storage |
| PSC-029 | No ECB mode usage | The codebase exclusively uses Fernet, which internally uses CBC — never ECB | N/A | secrets_encryption_storage |
| PSC-030 | Standard padding (PKCS7) | PKCS7 padding is the appropriate standard for AES-CBC block alignment, not to be confused with the asymmetric PKCS#1 v1.5 padding scheme | N/A | secrets_encryption_storage |
| PSC-031 | Library-based implementation | By using the cryptography library's Fernet rather than hand-rolling AES-CBC, the code inherits proper IV generation, padding, and HMAC verification | N/A | secrets_encryption_storage |
| PSC-032 | Key rotation support with MultiFernet | MultiFernet accepts multiple keys (comma-separated), enabling rotation by prepending new keys while old keys remain for decryption | `task-sdk/src/airflow/sdk/crypto.py:96` | secrets_encryption_storage |
| PSC-033 | Explicit rotate() method for re-encryption | `_RealFernet.rotate()` enables re-encryption of existing data with the current primary key | `task-sdk/src/airflow/sdk/crypto.py:79-81` | secrets_encryption_storage |
| PSC-034 | Cached Fernet instance | @cache decorator on get_fernet() ensures the Fernet key is loaded and validated once, reducing repeated configuration reads | `task-sdk/src/airflow/sdk/crypto.py:84` | secrets_encryption_storage |
| PSC-035 | Clear is_encrypted flag | Both _NullFernet and _RealFernet expose an is_encrypted attribute allowing runtime checks of encryption status | `task-sdk/src/airflow/sdk/crypto.py:40-58`, `task-sdk/src/airflow/sdk/crypto.py:84-104` | secrets_encryption_storage |
| PSC-036 | Single encryption primitive across the system | All sensitive data encryption flows through get_fernet() in crypto.py, providing a single point to upgrade | `task-sdk/src/airflow/sdk/crypto.py:84-104` | secrets_encryption_storage |
| PSC-037 | Well-structured secret lifecycle | Proper separation of concerns: crypto.py provides encryption primitives, secrets_backend.py provides abstraction layer, execution_api.py routes secrets through authenticated channels, cache.py provides ephemeral caching with TTL, Connection objects consume decrypted values | `task-sdk/src/airflow/sdk/crypto.py`, `task-sdk/src/airflow/sdk/secrets_backend.py`, `task-sdk/src/airflow/sdk/execution_api.py`, `task-sdk/src/airflow/sdk/cache.py` | secrets_encryption_storage |
| PSC-038 | HMAC-SHA256 (via Fernet) | cryptography.fernet library uses HMAC-SHA256 for all encrypted data authentication | `crypto.py` | secrets_encryption_storage |
| PSC-039 | Delegation to vetted library | All cryptographic hashing is delegated to the cryptography library's Fernet implementation, which uses HMAC-SHA256 — a NIST-approved construction | `crypto.py` | secrets_encryption_storage |
| PSC-040 | No direct hash function calls | The code does not directly call hashlib.md5(), hashlib.sha1(), or any deprecated hash function for cryptographic purposes | `crypto.py`, `connection.py`, `cache.py`, `execution_api.py`, `secrets_backend.py` | secrets_encryption_storage |
| PSC-041 | No custom HMAC implementations | The code relies entirely on Fernet's built-in HMAC rather than implementing its own, reducing the risk of using a disallowed hash function | `crypto.py` | secrets_encryption_storage |
| PSC-042 | Secret masking | Prevents leakage in logs — no hash function involved | `connection.py:214` | secrets_encryption_storage |
| PSC-043 | Trusted-layer structural validation using Pydantic TypeAdapter | The supervisor validates every message from the subprocess using self.decoder.validate_python(request.body) before any processing | `task-sdk/src/airflow/sdk/execution_time/supervisor.py:handle_requests` | ipc_subprocess_isolation |
| PSC-044 | Discriminated union schema definition | The `ToSupervisor` and `ToTask` type aliases use Pydantic's `Field(discriminator="type")` which serves as a form of documented schema—every valid message type and its fields are enumerated in code | `task-sdk/src/airflow/sdk/execution_time/comms.py` | ipc_subprocess_isolation |
| PSC-045 | Protocol documentation in module docstring | `comms.py` contains a comprehensive docstring (lines 19-50) explaining the communication protocol, message flow, and security rationale for the architecture | `task-sdk/src/airflow/sdk/execution_time/comms.py:19-50` | ipc_subprocess_isolation |
| PSC-046 | Restricted message types for callbacks enforcing least privilege | CallbackToSupervisor type explicitly limits callback subprocess communication to read-only operations plus secret masking (GetConnection, GetVariable, GetVariableKeys, MaskSecret only) | `task-sdk/src/airflow/sdk/execution_time/comms.py` | ipc_subprocess_isolation |
| PSC-047 | Separate decoders per subprocess type | ActivitySubprocess uses TypeAdapter(ToSupervisor) (full message set) while CallbackSubprocess uses TypeAdapter(CallbackToSupervisor) (restricted set), enforcing the principle of least privilege at the message schema level | `task-sdk/src/airflow/sdk/execution_time/supervisor.py`, `task-sdk/src/airflow/sdk/execution_time/callback_supervisor.py` | ipc_subprocess_isolation |
| PSC-048 | Exception handling with error response preventing crash on invalid messages | When message validation fails, the supervisor logs the error and continues without crashing, preventing a malformed message from disrupting other operations | `task-sdk/src/airflow/sdk/execution_time/supervisor.py:handle_requests` | ipc_subprocess_isolation |
| PSC-049 | Process isolation using fork | Fork-based isolation, non-dumpable processes (Linux), ORM access blocking, and signal reset provide defense-in-depth | `task-sdk/src/airflow/sdk/execution_time/supervisor.py:WatchedSubprocess.start` | ipc_subprocess_isolation |
| PSC-050 | ORM access blocking in child process | block_orm_access() is applied in child process to prevent direct database access | `task-sdk/src/airflow/sdk/execution_time/supervisor.py` | ipc_subprocess_isolation |
| PSC-051 | Typed response wrappers | Response types like `XComResult`, `ConnectionResult`, etc. inherit from auto-generated API schema models (`XComResponse`, `ConnectionResponse`), creating traceability between IPC schema and API schema | `task-sdk/src/airflow/sdk/execution_time/comms.py` | ipc_subprocess_isolation |
| PSC-052 | Error isolation for unhandled messages | Both ActivitySubprocess and CallbackSubprocess send an explicit ErrorResponse back to the subprocess for unhandled message types rather than silently dropping them | `task-sdk/src/airflow/sdk/execution_time/supervisor.py` | ipc_subprocess_isolation |
| PSC-053 | NativeEnvironment for type preservation | When `render_template_as_native_obj=True`, templates return native Python types (dicts, lists, ints) rather than strings. This avoids the need for JSON encoding entirely since the object is never serialized to a JSON string during template processing. | `task-sdk/src/airflow/sdk/definitions/_internal/templater.py:258` | jinja_template_sandbox |
| PSC-054 | StrictUndefined by default | `jinja2.StrictUndefined` ensures that undefined variables raise errors rather than rendering as empty strings, which prevents silent data corruption in structured output like JSON. | `task-sdk/src/airflow/sdk/definitions/_internal/templater.py:313` | jinja_template_sandbox |
| PSC-055 | Template source is not user-controllable at runtime | Template source code comes from DAG definitions (operator `template_fields` values), not from runtime user input. Context variables are substituted but not interpreted as templates, preventing template injection. | N/A | jinja_template_sandbox |
| PSC-056 | Jinja2 built-in tojson filter available | Inherited from Jinja2 base Environment and available for use, though not explicitly documented or promoted in custom filters. | N/A | jinja_template_sandbox |
| PSC-057 | No `eval()`, `exec()`, or `compile()` anywhere in the module | The code relies exclusively on Jinja2's template engine for dynamic content generation, which provides a restricted expression language rather than full Python execution | `task-sdk/src/airflow/sdk/definitions/_internal/templater.py` | jinja_template_sandbox |
| PSC-058 | SandboxedEnvironment as default | When no DAG is provided, the fallback is always `SandboxedEnvironment(cache_size=0)`, ensuring the most restrictive mode by default | `task-sdk/src/airflow/sdk/definitions/_internal/templater.py:62` | jinja_template_sandbox |
| PSC-059 | Attribute access control via `is_safe_attribute` | The sandbox blocks access to dunder (`__`) attributes, preventing access to Python object internals like `__class__`, `__globals__`, `__subclasses__`, which are commonly used in sandbox escape attacks | `task-sdk/src/airflow/sdk/definitions/_internal/templater.py:249-256` | jinja_template_sandbox |
| PSC-060 | LiteralValue wrapper | Provides an explicit mechanism to mark values as non-templatable, preventing accidental template interpretation of values that contain Jinja2 syntax | `task-sdk/src/airflow/sdk/definitions/_internal/templater.py:35-42` | jinja_template_sandbox |
| PSC-061 | Secrets masking before logging | When template rendering fails, sensitive values are redacted before being included in exception log messages, preventing credential leakage through error logs | `task-sdk/src/airflow/sdk/definitions/_internal/templater.py:151-155` | jinja_template_sandbox |
| PSC-062 | Circular reference protection | Prevents infinite recursion using seen_oids tracking | `task-sdk/src/airflow/sdk/definitions/_internal/templater.py:181-186`, `task-sdk/src/airflow/sdk/definitions/_internal/templater.py:230-231` | jinja_template_sandbox |
| PSC-063 | Discriminated unions with Literal types for message dispatch | comms.py uses Field(discriminator="type") on ToTask and ToSupervisor unions, ensuring only explicitly defined message types are accepted | `task-sdk/src/airflow/sdk/execution_time/comms.py` | api_input_validation |
| PSC-064 | extra="forbid" on Pydantic models to reject unexpected fields | API payload models in _generated.py (e.g., TIEnterRunningPayload, TriggerDAGRunPayload) use ConfigDict(extra="forbid") | `task-sdk/src/airflow/sdk/api/_generated.py` | api_input_validation |
| PSC-065 | UUID type safety for identifiers | Task instance identifiers use UUID type throughout _generated.py (TaskInstance.id, various ti_id fields), preventing injection of non-UUID strings | `task-sdk/src/airflow/sdk/api/_generated.py` | api_input_validation |
| PSC-066 | Enum constraints on state transitions | TerminalStateNonSuccess, TaskInstanceState, DagRunState restrict state values to known-good enums in _generated.py | `task-sdk/src/airflow/sdk/api/_generated.py` | api_input_validation |
| PSC-067 | AwareDatetime enforcement for temporal fields | Temporal fields use AwareDatetime instead of raw strings or naive datetimes throughout _generated.py and comms.py, ensuring timezone information is always present | `task-sdk/src/airflow/sdk/api/_generated.py`, `task-sdk/src/airflow/sdk/execution_time/comms.py` | api_input_validation |
| PSC-068 | Pydantic model validation on deserialization | Both model_validate_json() (client.py) and TypeAdapter.validate_python() (comms.py) perform full schema validation before accepting data | `task-sdk/src/airflow/sdk/api/client.py`, `task-sdk/src/airflow/sdk/execution_time/comms.py` | api_input_validation |
| PSC-069 | Pydantic type validation (type checking) applied to all messages | All message models in comms.py and _generated.py use Pydantic type validation | `task-sdk/src/airflow/sdk/execution_time/comms.py`, `task-sdk/src/airflow/sdk/api/_generated.py` | api_input_validation |
| PSC-070 | min_length constraints on specific fields | Applied to HITLDetailRequest.options and UpdateHITLDetailPayload.chosen_options in _generated.py | `task-sdk/src/airflow/sdk/api/_generated.py` | api_input_validation |
| PSC-071 | Content-Type set on outgoing requests with body | Client.request() sets application/json for content= parameter | `task-sdk/src/airflow/sdk/api/client.py:505` | api_input_validation |
| PSC-072 | Content-Type set via httpx json= parameter | Multiple methods use httpx json= parameter which automatically sets Content-Type header | `task-sdk/src/airflow/sdk/api/client.py` | api_input_validation |
| PSC-073 | Content-Type validated on error responses | ServerResponseError.from_response() checks content-type != application/json before parsing | `task-sdk/src/airflow/sdk/api/client.py:555` | api_input_validation |
| PSC-074 | Content-Type on noop_handler responses | noop_handler uses httpx json= parameter which correctly sets Content-Type | `task-sdk/src/airflow/sdk/api/client.py:235` | api_input_validation |
| PSC-075 | Pydantic model validation for response deserialization | Consistent use of model_validate_json() provides uniform validation layer with extra='forbid' configuration | `task-sdk/src/airflow/sdk/api/client.py` | api_input_validation |
| PSC-076 | API version header | Client sends airflow-api-version header on every request enabling server validation | `task-sdk/src/airflow/sdk/api/client.py:493` | api_input_validation |
| PSC-077 | Schema Validation for Provider Metadata | _provider_schema_validator validates the structure of provider metadata before use, preventing malformed provider configurations from being processed | `task-sdk/src/airflow/sdk/providers_manager_runtime.py:144` | plugin_dynamic_loading |
| PSC-078 | Prefix Validation for Built-in Providers | _check_builtin_provider_prefix() ensures that Apache-branded providers use correct package namespaces, preventing namespace squatting | `task-sdk/src/airflow/sdk/providers_manager_runtime.py:53-103` | plugin_dynamic_loading |
| PSC-079 | Comprehensive Import Error Handling | _correctness_check() gracefully handles multiple failure modes (ImportError, AirflowOptionalProviderFeatureException, generic exceptions) with appropriate logging and fallback behavior | `task-sdk/src/airflow/sdk/providers_manager_runtime.py:53-103` | plugin_dynamic_loading |
| PSC-080 | Lazy Loading Infrastructure | @provider_info_cache decorator and LazyDictWithCache pattern defer expensive imports until first access, reducing unnecessary code loading | `task-sdk/src/airflow/sdk/providers_manager_runtime.py:165` | plugin_dynamic_loading |
| PSC-081 | Singleton Pattern for Provider Manager | Ensures consistent state across the application and prevents redundant discovery cycles | `task-sdk/src/airflow/sdk/providers_manager_runtime.py` | plugin_dynamic_loading |
| PSC-082 | Duplicate Plugin Prevention | The loaded_plugins set in _get_plugins() prevents the same plugin from being loaded multiple times from different sources | `task-sdk/src/airflow/sdk/plugins_manager.py:62-101` | plugin_dynamic_loading |
| PSC-083 | Build-time Dependency Pinning | The project uses uv.lock for reproducible builds with pinned dependency versions | `uv.lock` | plugin_dynamic_loading |
| PSC-084 | Structured logging via structlog with JSON output mode | All log output uses structlog processors which serialize event dicts as JSON when json_output=True, inherently preventing log injection through proper key-value encoding | `log.py:63` | output_encoding_injection |
| PSC-085 | Secrets masking processor | mask_logs processor applied to all log events in task process (unless sending_to_supervisor=True), uses redact() function to strip secrets from event dicts | `log.py:57`, `airflow.sdk._shared.secrets_masker` | output_encoding_injection |
| PSC-086 | Pydantic serialization for HTTP bodies | All HTTP request bodies use model_dump_json() which handles proper JSON escaping, and responses use model_validate_json() for safe deserialization | `client.py` | output_encoding_injection |
| PSC-087 | msgpack binary framing for IPC | IPC messages use msgpack with 4-byte length-prefix framing (_FrameMixin.as_bytes()), making injection into the binary protocol structurally impossible | `comms.py:83-95` | output_encoding_injection |
| PSC-088 | Content-type enforcement | Client.request() automatically sets content-type: application/json for all payloads with body content | `client.py:850` | output_encoding_injection |
| PSC-089 | httpx query parameter encoding | Query parameters are passed via params= dict argument which httpx properly URL-encodes | `client.py` | output_encoding_injection |
| PSC-090 | UUID and integer type enforcement for path parameters | Task instance IDs typed as uuid.UUID and numeric parameters as int, structurally preventing injection in those path positions | `client.py` | output_encoding_injection |
| PSC-091 | TLS transport security with scoped JWT tokens | SSL context configured in Client.__init__ prevents MITM, BearerAuth class implements JWT authentication limiting blast radius | `client.py:810` | output_encoding_injection |
| PSC-092 | No database access in Task SDK | Architecture explicitly separates task execution from database access, all operations via Execution API with typed Pydantic models | N/A | output_encoding_injection |
| PSC-093 | No shell command execution | No subprocess, os.system, os.popen, or os.exec* usage found. DNS resolution via socket.getaddrinfo(), user info via getpass.getuser() | N/A | output_encoding_injection |
| PSC-094 | No HTML processing | Task SDK operates exclusively with structured data formats (JSON, msgpack, Pydantic models), avoiding HTML handling entirely | N/A | output_encoding_injection |
| PSC-095 | Sequential Start Enforcement | Supervisor enforces strict sequential ordering at task startup by calling client.task_instances.start() BEFORE sending StartupDetails to the subprocess. If the API rejects the start request, the subprocess is immediately killed with SIGKILL. | `task-sdk/src/airflow/sdk/execution_time/supervisor.py:520-527` | business_logic_flow_control |
| PSC-096 | Heartbeat-Based Liveness Monitoring | Supervisor maintains a heartbeat with the API server throughout task execution. The server can respond with termination signals (404/410/409), which trigger immediate force-kill with signal escalation (SIGTERM → SIGKILL). | `task-sdk/src/airflow/sdk/execution_time/supervisor.py:635`, `task-sdk/src/airflow/sdk/execution_time/supervisor.py:645` | business_logic_flow_control |
| PSC-097 | Failed Heartbeat Counter with Automatic Termination | After MAX_FAILED_HEARTBEATS consecutive failures, the process is automatically terminated. This prevents hung tasks from persisting indefinitely during network outages. | `task-sdk/src/airflow/sdk/execution_time/supervisor.py:670` | business_logic_flow_control |
| PSC-098 | StartupDetails Type Validation | Task runner validates that the FIRST message received from the supervisor is a StartupDetails instance, preventing step-skipping at startup and ensuring the task cannot execute without proper initialization. | `task-sdk/src/airflow/sdk/execution_time/task_runner.py` | business_logic_flow_control |
| PSC-099 | Exit Code-Based Fallback State Reporting | Even if no terminal state message is received from the subprocess, the supervisor derives a final state from the process exit code (0 → SUCCESS, non-zero with retry → UP_FOR_RETRY, non-zero without retry → FAILED). This guarantees state is always reported to the API. | `task-sdk/src/airflow/sdk/execution_time/supervisor.py` | business_logic_flow_control |
| PSC-100 | Signal Escalation with Socket Servicing | The kill() method continues servicing socket events during the kill escalation timeout, ensuring log messages and pending requests are processed before the process dies. This provides graceful degradation and preserves audit trail completeness. | `task-sdk/src/airflow/sdk/execution_time/supervisor.py:390` | business_logic_flow_control |

---

# 5. ASVS Compliance Summary

| ASVS ID | Requirement Title | Status | Justification |
|---------|------------------|--------|---------------|
| 6.3.1 | General Authentication Security - Brute force prevention controls | **Partial** | ✅ Bounded retries, exponential backoff, no retry on auth failure. ❌ No HTTP 429 handling (FINDING-028) |
| 6.3.2 | General Authentication Security - Default accounts | **Pass** | ✅ Dynamic user identification, no hardcoded credentials, JWT-based identity |
| 7.2.1 | Fundamental Session Management Security - Backend token verification | **Pass** | ✅ Server-side JWT validation, client never parses token payload for access control |
| 7.2.2 | Fundamental Session Management Security - Dynamic token generation | **Pass** | ✅ Unique JWT per task execution, server-side generation, token refresh via header |
| 7.2.3 | Fundamental Session Management Security - Token entropy and CSPRNG | **Pass** | ✅ Server-generated JWT tokens (assumed CSPRNG), client does not generate tokens |
| 9.1.1 | Token source and integrity - Signature validation | **Partial** | ✅ Server validates JWT signatures. ❌ Refreshed token accepted without client-side verification (FINDING-004, FINDING-029) |
| 9.1.2 | Token source and integrity - Algorithm allowlist | **Partial** | ✅ Server-side validation assumed. ❌ Cannot verify from client code (FINDING-030) |
| 9.1.3 | Token source and integrity - Key material from trusted sources | **Partial** | ✅ Server-side key management assumed. ❌ Cannot verify from client code (FINDING-031) |
| 9.2.1 | Token content - Validity time span verification | **Partial** | ✅ Server enforces expiration via heartbeat termination. ❌ No client-side expiration check (FINDING-004, FINDING-032, FINDING-033) |
| 12.1.1 | General TLS Security Guidance | **Partial** | ✅ ssl.create_default_context() baseline, no verify=False. ❌ No explicit TLS version enforcement (FINDING-005) |
| 12.2.1 | HTTPS Communication with External Facing Services | **Fail** | ❌ No scheme validation on base_url, tokens could be sent over HTTP (FINDING-002) |
| 12.2.2 | Publicly Trusted TLS Certificates | **Partial** | ✅ certifi bundle for public CAs, custom CA additive. ❌ No OCSP/CRL (FINDING-034) |
| 11.3.1 | Encryption Algorithms - Insecure Block Modes and Padding | **Pass** | ✅ Fernet (AES-CBC + HMAC), no ECB, standard PKCS7 padding, encrypt-then-MAC |
| 11.3.2 | Encryption Algorithms - Approved Ciphers and Modes | **Partial** | ✅ Fernet uses NIST-approved primitives. ❌ AES-128-CBC instead of AEAD (FINDING-006), _NullFernet fallback (FINDING-035) |
| 11.4.1 | Hashing and Hash-based Functions - Approved Hash Functions | **Pass** | ✅ HMAC-SHA256 via Fernet, no direct use of deprecated hash functions |
| 14.2.1 | Sensitive data transmission in HTTP | **Pass** | ✅ TLS with certificate verification, Bearer token in Authorization header, no sensitive data in URLs |
| 2.1.1 | Validation and Business Logic Documentation | **Partial** | ✅ Pydantic schema as documentation. ❌ Insufficient field-level validation docs (FINDING-009, FINDING-037) |
| 2.2.2 | Input Validation at Trusted Service Layer | **Partial** | ✅ Pydantic validation at supervisor boundary. ❌ No message size limits (FINDING-007), missing field constraints (FINDING-036) |
| 1.2.3 | Injection Prevention - Output Encoding/Escaping for JavaScript/JSON | **Partial** | ✅ Pydantic model_dump_json() for HTTP, NativeEnvironment for templates. ❌ No JSON-specific template filters (FINDING-038) |
| 1.3.2 | Sanitization - Avoid eval() and Dynamic Code Execution | **Partial** | ✅ No eval/exec/compile, SandboxedEnvironment default. ❌ NativeEnvironment lacks sandbox (FINDING-010), jinja2.ext.do enabled (FINDING-039), context exposure risk (FINDING-011) |
| 2.2.1 | Input Validation | **Partial** | ✅ Pydantic type validation, discriminated unions, enums. ❌ No max frame size (FINDING-012), missing field constraints (FINDING-036) |
| 4.1.1 | Generic Web Service Security | **Partial** | ✅ Content-Type set on requests, validated on errors. ❌ No validation on success responses, no Accept header (FINDING-040, FINDING-041) |
| 15.2.1 | Component Update and Remediation Timeframes | **Fail** | ❌ No version policy enforcement (FINDING-013), no runtime inventory (FINDING-014), no documented timeframes (FINDING-015), non-lazy loading (FINDING-042), static version unsuitable for change detection (FINDING-043) |
| 1.2.1 | Output Encoding for HTTP Response, HTML, XML | **Partial** | ✅ Structured logging with JSON, Pydantic serialization. ❌ Server header in exception notes (FINDING-044) |
| 1.2.2 | Dynamic URL Building | **Partial** | ✅ httpx handles query encoding, UUID/int type safety. ❌ No percent-encoding for path segments (FINDING-016), no protocol allowlist (FINDING-045) |
| 1.2.4 | Parameterized Queries | **Pass** | ✅ No direct database access in Task SDK, all operations via typed Pydantic models |
| 1.2.5 | OS Command Injection | **Pass** | ✅ No shell command execution, safe OS calls only (getaddrinfo, getuser) |
| 1.3.1 | HTML Sanitization | **N/A** | ℹ️ No HTML processing in Task SDK |
| 2.3.1 | Sequential Business Logic Flow Enforcement | **Fail** | ❌ Overtime enforcement not applied to DeferTask/RescheduleTask () |
| 7.2.4 | Fundamental Session Management Security | **Partial** | ✅ Token refresh mechanism, process isolation. ❌ Old token not cleared (FINDING-017), token accessible in forked memory (FINDING-046) |
| 7.4.1 | Session Termination | **Partial** | ✅ Server-initiated termination via heartbeat. ❌ No explicit revocation call (FINDING-018), token retained in Client object (FINDING-047) |
| 7.4.2 | Session Termination on Account Disable/Delete | **Partial** | ✅ Heartbeat-based termination mechanism. ❌ Revocation window between heartbeats (FINDING-019) |
| 8.1.1 | Authorization Documentation | **Partial** | ✅ AGENTS.md describes architecture. ❌ Rules not co-located with code (FINDING-020) |
| 8.2.1 | General Authorization Design (Function-Level) | **Partial** | ✅ Separate message schemas for activity vs callback. ❌ No function-level filtering (FINDING-021) |
| 8.2.2 | General Authorization Design (Data-Specific / IDOR / BOLA) | **Fail** | ❌ Supervisor mediates all operations without data-specific filtering (FINDING-021) |
| 8.3.1 | Operation Level Authorization (Trusted Service Layer) | **Pass** | ✅ JWT scoped to task instance, token isolation from subprocess, server validates all operations |
| 14.3.1 | Verify that authenticated data is cleared from client storage | **Fail** | ❌ No cache cleanup mechanism (FINDING-003), no connection invalidation (FINDING-022), Fernet key cached indefinitely (FINDING-048) |
| 5.2.1 | File Upload Size Limits | **Partial** | ✅ Implicit limits via network/memory. ❌ No explicit XCom size limit (FINDING-023), email templates unbounded (FINDING-049) |
| 5.2.2 | File Extension and Content Validation | **Pass** | ✅ Structured data only (JSON, msgpack, Pydantic), no file upload handling |
| 5.3.1 | Prevention of File Execution from Upload Paths | **Pass** | ✅ No file upload functionality, no dynamic code execution |
| 5.3.2 | Path Traversal Prevention in File Operations | **Fail** | ❌ DAG file path lacks containment validation (FINDING-024), log file path lacks validation (FINDING-025), relative_path_from_logger ValueError not handled (FINDING-050) |
| 13.4.1 | Unintended Information Leakage - Source Control Metadata | **Partial** | ✅ Production deployment assumed clean. ❌ No explicit exclusion mechanism (FINDING-026) |
| 15.1.1 | Secure Coding and Architecture Documentation | **Fail** | ❌ No documented remediation timeframes (FINDING-027), no risky component identification (FINDING-051) |
| 6.1.1 | Authentication Documentation | **Fail** | ❌ No documented rate limiting or anti-automation controls (FINDING-052) |
| 6.2.1 | Password Minimum Length | **Pass** | ✅ No password-based authentication |
| 6.2.2 | Users Can Change Password | **N/A** | ℹ️ No password-based authentication |
| 6.2.3 | Password Change Requires Current and New Password | **N/A** | ℹ️ No password-based authentication |
| 6.2.4 | Passwords Checked Against Common Password Lists | **N/A** | ℹ️ No password-based authentication |
| 6.2.5 | No Restrictive Composition Rules | **Pass** | ✅ No password-based authentication |
| 6.2.6 | Password Input Field Masking | **N/A** | ℹ️ No password-based authentication |
| 6.2.7 | Paste Functionality and Password Managers Permitted | **N/A** | ℹ️ No password-based authentication |
| 6.2.8 | Password Verified Without Modification | **Pass** | ✅ No password-based authentication |
| 6.4.1 | Secure Initial Password Generation | **N/A** | ℹ️ No password-based authentication |
| 6.4.2 | No Password Hints or Knowledge-Based Authentication | **Pass** | ✅ No password-based authentication |
| 10.4.1 | Redirect URI Validation | **N/A** | ℹ️ Not an OAuth client |
| 10.4.2 | Authorization Code Single-Use Enforcement | **N/A** | ℹ️ Not an OAuth client |
| 10.4.3 | Authorization Code Short Lifetime | **N/A** | ℹ️ Not an OAuth client |
| 10.4.4 | Grant Type Restriction | **N/A** | ℹ️ Not an OAuth client |
| 10.4.5 | Refresh Token Replay Mitigation | **Partial** | ✅ Token refresh via header mechanism. ❌ No client-side expiration awareness (FINDING-053), refreshed token not validated (FINDING-004) |
| 4.4.1 | WebSocket over TLS (WSS) | **Pass** | ✅ No WebSocket usage, IPC via Unix domain socket |
| 3.2.1 | Unintended Content Interpretation | **N/A** | ℹ️ No browser-facing components |
| 3.2.2 | Safe Text Rendering | **N/A** | ℹ️ No browser-facing components |
| 3.3.1 | Cookie Setup | **N/A** | ℹ️ No cookie usage |
| 3.4.1 | Browser Security Mechanism Headers (HSTS) | **N/A** | ℹ️ No browser-facing components |
| 3.4.2 | CORS Configuration | **N/A** | ℹ️ No browser-facing components |
| 3.5.1 | Browser Origin Separation (CSRF) | **Pass** | ✅ No state-changing operations via GET, Bearer token authentication |
| 3.5.2 | Browser Origin Separation - CORS Preflight | **N/A** | ℹ️ No browser-facing components |
| 3.5.3 | Browser Origin Separation - HTTP Methods | **Pass** | ✅ Appropriate HTTP method usage (GET for reads, POST/PUT/PATCH for writes) |
| 1.5.1 | XML Parser Configuration - XXE Prevention | **Pass** | ✅ No XML processing |
| 15.3.1 | Verify that the application only returns the required subset of fields | **Fail** | ❌ No message size validation before allocation (FINDING-007) |

**Summary Statistics:**
- **Pass**: 32 (41.0%)
- **Partial**: 28 (35.9%)
- **Fail**: 11 (14.1%)
- **N/A**: 18 (23.1%)

---

# 6. Cross-Reference Matrix

| Finding ID | Severity | ASVS Requirements | Positive Controls (Mitigating) | Related Domains |
|------------|----------|-------------------|-------------------------------|-----------------|
| FINDING-002 | High | 12.2.1 | PSC-015, PSC-016, PSC-019, PSC-023 | tls_transport_security, execution_api_authentication |
| FINDING-003 | High | 14.3.1 | PSC-034, PSC-037 | secrets_encryption_storage |
| FINDING-004 | Medium | 9.1.1, 9.1.2, 9.1.3, 9.2.1, 10.4.5 | PSC-011, PSC-012, PSC-014 | execution_api_authentication |
| FINDING-005 | Medium | 12.1.1 | PSC-017, PSC-018, PSC-023 | tls_transport_security |
| FINDING-006 | Medium | 11.3.2 | PSC-026, PSC-028, PSC-031 | secrets_encryption_storage |
| FINDING-007 | Medium | 2.2.2, 15.3.1 | PSC-043, PSC-048, PSC-068 | ipc_subprocess_isolation, api_input_validation |
| FINDING-008 | Medium | 2.2.2 | PSC-084, PSC-085 | output_encoding_injection |
| FINDING-009 | Medium | 2.1.1 | PSC-044, PSC-045 | ipc_subprocess_isolation |
| FINDING-010 | Medium | 1.3.2 | PSC-053, PSC-058, PSC-059 | jinja_template_sandbox |
| FINDING-011 | Medium | 1.3.2 | PSC-057, PSC-058, PSC-059 | jinja_template_sandbox |
| FINDING-012 | Medium | 2.2.1 | PSC-043, PSC-068, PSC-087 | ipc_subprocess_isolation, api_input_validation |
| FINDING-013 | Medium | 15.2.1 | PSC-077, PSC-078, PSC-079, PSC-083 | plugin_dynamic_loading |
| FINDING-014 | Medium | 15.2.1 | PSC-081, PSC-082 | plugin_dynamic_loading |
| FINDING-015 | Medium | 15.2.1 | PSC-083 | plugin_dynamic_loading |
| FINDING-016 | Medium | 1.2.2 | PSC-089, PSC-090 | output_encoding_injection |
| FINDING-017 | Medium | 7.2.4 | PSC-012, PSC-013 | execution_api_authentication |
| FINDING-018 | Medium | 7.4.1 | PSC-014, PSC-096 | execution_api_authentication, business_logic_flow_control |
| FINDING-019 | Medium | 7.4.2 | PSC-014, PSC-096, PSC-097 | execution_api_authentication, business_logic_flow_control |
| FINDING-020 | Medium | 8.1.1 | PSC-044, PSC-045 | ipc_subprocess_isolation |
| FINDING-021 | Medium | 8.2.1, 8.2.2 | PSC-046, PSC-047 | ipc_subprocess_isolation |
| FINDING-022 | Medium | 14.3.1 | PSC-037 | secrets_encryption_storage |
| FINDING-023 | Medium | 5.2.1 | PSC-064, PSC-068, PSC-075 | api_input_validation |
| FINDING-024 | Medium | 5.3.2 | None | N/A |
| FINDING-025 | Medium | 5.3.2 | None | N/A |
| FINDING-026 | Medium | 13.4.1 | PSC-083 | plugin_dynamic_loading |
| FINDING-027 | Medium | 15.1.1 | PSC-083 | plugin_dynamic_loading |
| FINDING-028 | Low | 6.3.1 | PSC-002, PSC-003, PSC-004 | execution_api_authentication |
| FINDING-029 | Low | 9.1.1 | PSC-011, PSC-014 | execution_api_authentication |
| FINDING-030 | Low | 9.1.2 | PSC-011 | execution_api_authentication |
| FINDING-031 | Low | 9.1.3 | PSC-011 | execution_api_authentication |
| FINDING-032 | Low | 9.2.1 | PSC-005, PSC-011 | execution_api_authentication |
| FINDING-033 | Low | 9.2.1 | PSC-011, PSC-014 | execution_api_authentication |
| FINDING-034 | Low | 12.2.2 | PSC-024, PSC-025 | tls_transport_security |
| FINDING-035 | Low | 11.3.2 | PSC-034, PSC-035 | secrets_encryption_storage |
| FINDING-036 | Low | 2.2.2, 2.2.1 | PSC-043, PSC-063, PSC-064, PSC-066, PSC-067, PSC-069, PSC-070 | api_input_validation, ipc_subprocess_isolation |
| FINDING-037 | Low | 2.1.1 | PSC-044, PSC-045, PSC-046 | ipc_subprocess_isolation |
| FINDING-038 | Low | 1.2.3 | PSC-053, PSC-054, PSC-056 | jinja_template_sandbox |
| FINDING-039 | Low | 1.3.2 | PSC-057, PSC-058 | jinja_template_sandbox |
| FINDING-040 | Low | 4.1.1 | PSC-071, PSC-072, PSC-073, PSC-074, PSC-075 | api_input_validation |
| FINDING-041 | Low | 4.1.1 | PSC-076 | api_input_validation |
| FINDING-042 | Low | 15.2.1 | PSC-080 | plugin_dynamic_loading |
| FINDING-043 | Low | 15.2.1 | PSC-077, PSC-081 | plugin_dynamic_loading |
| FINDING-044 | Low | 1.2.1 | PSC-084, PSC-086 | output_encoding_injection |
| FINDING-045 | Low | 1.2.2 | PSC-015, PSC-023, PSC-091 | output_encoding_injection, tls_transport_security |
| FINDING-046 | Low | 7.2.4, 8.3.1 | PSC-006, PSC-013, PSC-049, PSC-050 | execution_api_authentication, ipc_subprocess_isolation |
| FINDING-047 | Low | 7.4.1 | PSC-012 | execution_api_authentication |
| FINDING-048 | Low | 14.3.1 | PSC-034 | secrets_encryption_storage |
| FINDING-049 | Low | 5.2.1 | PSC-064 | api_input_validation |
| FINDING-050 | Low | 5.3.2 | None | N/A |
| FINDING-051 | Low | 15.1.1 | PSC-077, PSC-078, PSC-079 | plugin_dynamic_loading |
| FINDING-052 | Low | 6.1.1 | PSC-002, PSC-003, PSC-004 | execution_api_authentication |
| FINDING-053 | Low | 10.4.5 | PSC-012, PSC-096 | execution_api_authentication, business_logic_flow_control |

**Domain Coverage Analysis:**

| Domain | Findings | Positive Controls | Risk Level |
|--------|----------|-------------------|------------|
| execution_api_authentication | 16 findings (1 Critical, 0 High, 7 Medium, 8 Low) | 14 controls (PSC-001 to PSC-014) | **Medium** |
| tls_transport_security | 4 findings (0 Critical, 1 High, 1 Medium, 2 Low) | 11 controls (PSC-015 to PSC-025) | **Medium** |
| secrets_encryption_storage | 6 findings (0 Critical, 1 High, 1 Medium, 4 Low) | 17 controls (PSC-026 to PSC-042) | **Medium** |
| ipc_subprocess_isolation | 8 findings (0 Critical, 0 High, 4 Medium, 4 Low) | 10 controls (PSC-043 to PSC-052) | **Low-Medium** |
| jinja_template_sandbox | 4 findings (0 Critical, 0 High, 2 Medium, 2 Low) | 10 controls (PSC-053 to PSC-062) | **Low-Medium** |
| api_input_validation | 7 findings (0 Critical, 0 High, 2 Medium, 5 Low) | 14 controls (PSC-063 to PSC-076) | **Low-Medium** |
| plugin_dynamic_loading | 7 findings (0 Critical, 0 High, 5 Medium, 2 Low) | 7 controls (PSC-077 to PSC-083) | **Medium** |
| output_encoding_injection | 4 findings (0 Critical, 0 High, 2 Medium, 2 Low) | 11 controls (PSC-084 to PSC-094) | **Low** |
| business_logic_flow_control | 4 findings (1 Critical, 0 High, 2 Medium, 1 Low) | 6 controls (PSC-095 to PSC-100) | **High** |

**Overall Risk Assessment:**
- **Critical Risk Areas**: Business logic flow control ()
- **High Risk Areas**: TLS transport security (FINDING-002), secrets lifecycle management (FINDING-003)
- **Medium Risk Areas**: Token validation, encryption algorithms, IPC message validation, plugin security
- **Strengths**: Strong process isolation, comprehensive input validation framework, no password-based authentication, structured logging

## 7. Level Coverage Analysis


**Audit scope:** up to L1

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 53 |

**Total consolidated findings: 53**

*End of Consolidated Security Audit Report*
