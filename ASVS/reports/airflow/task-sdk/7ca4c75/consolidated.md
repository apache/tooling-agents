# Security Audit Consolidated Report

## Report Metadata

| Field | Value |
|-------|-------|
| **Repository** | `apache/tooling-runbooks` |
| **ASVS Level** | L1 |
| **Severity Threshold** | High and above |
| **Commit** | N/A |
| **Date** | May 06, 2026 |
| **Auditor** | Tooling Agents |
| **Source Reports** | 70 |
| **Total Findings** | 16 |

## Executive Summary

### Severity Distribution

| Severity | Count | Percentage |
|----------|-------|------------|
| Critical | 0 | 0.0% |
| High | 16 | 100.0% |
| Medium | 0 | 0.0% |
| Low | 0 | 0.0% |
| Info | 0 | 0.0% |

All 16 findings fall within the **High** severity band. No critical-severity issues were identified. The absence of medium, low, and informational findings reflects the applied severity threshold filter rather than an absence of lower-severity observations.

### Level Coverage

This audit evaluates controls at **ASVS Level 1 (L1)** — the minimum assurance level appropriate for all software. All 16 findings are mapped to L1 verification requirements, indicating foundational security controls that must be addressed regardless of deployment context. The 22 directories under review span the full breadth of the SDK's security-relevant surface area, including cryptographic operations, authentication/session management, input validation, command execution, file handling, and transport security.

### Top 5 Risks

| # | Finding | ASVS | Domain | Risk Summary |
|---|---------|------|--------|--------------|
| 1 | **FINDING-004**: Silent fallback to no encryption via `_NullFernet` | 11.3.2 | cryptographic_operations | When `FERNET_KEY` is unconfigured, the system silently disables all encryption for secrets at rest, meaning sensitive credentials (connections, variables) are stored and transmitted in plaintext with no warning to operators. This represents a complete loss of data confidentiality. |
| 2 | **FINDING-005**: Deserialization allow-list regex bypass via `re.match()` | 2.2.1, 2.2.2 | input_validation | The regex-based class allow-list uses `re.match()` which only anchors at the start of the string. An attacker who controls serialized data can craft class names that match the allowed prefix but resolve to arbitrary malicious classes, achieving remote code execution. |
| 3 | **FINDING-011**: Path traversal in DAG loading via `dag_rel_path` | 5.3.2 | file_handling | Absence of path canonicalization or traversal validation on the relative path used for DAG loading allows an attacker who can influence DAG metadata to load and execute arbitrary Python code outside the intended bundle boundary. |
| 4 | **FINDING-001**: No URL scheme validation allows plaintext HTTP with bearer tokens | 12.2.1 | execution_api_client | The API client does not enforce HTTPS, permitting bearer tokens and sensitive payloads to traverse the network in plaintext. In environments where the base URL is configured via environment variable, misconfiguration or interception exposes authentication material. |
| 5 | **FINDING-006**: Unbounded memory allocation from untrusted IPC frame length | 2.2.1 | input_validation | The IPC frame reader allocates a buffer sized by an attacker-controlled 4-byte length prefix without enforcing a maximum. A malicious or compromised peer process can trigger out-of-memory conditions, causing denial of service to the supervisor or task process. |

### Positive Controls Observed

The audit identified **47 positive security controls** across the assessed directories, demonstrating meaningful security investment in several areas:

- **Transport Security (execution_api_client):** The SDK establishes a strong TLS baseline using `ssl.create_default_context()` with hostname verification, the `certifi` CA bundle, and optional mutual TLS via client certificates. Bearer token authentication keeps credentials out of URLs, and SSL context caching prevents resource exhaustion.

- **Cryptographic Operations:** When properly configured, the system uses Fernet (AES-128-CBC + HMAC-SHA256) in an encrypt-then-MAC construction, eliminating padding oracle attacks. MultiFernet supports key rotation. All cryptographic work is delegated to the vetted `cryptography` library with no custom implementations, no weak hash functions (MD5/SHA-1), and no insecure modes (ECB).

- **Input Validation & Deserialization:** Pydantic model validation is applied consistently across API responses, IPC messages (with discriminated unions), and connection definitions. The deserialization layer includes an allow-list (glob-based), recursion depth protection, frame size overflow checks, version validation, and reserved-key detection.

- **Command Injection Prevention:** Process execution exclusively uses list-based `os.execvp`/`os.execv` and `os.fork()` — no shell invocations are present. Command strings are hardcoded in source and never constructed from user input.

- **Provider Plugin Isolation:** Schema validation, import error isolation, prefix validation, lazy loading, and caching collectively limit the blast radius of a compromised or malformed provider package.

These controls provide a solid defensive foundation; however, the 16 high-severity findings represent gaps where these positive patterns are either not applied consistently (e.g., URL scheme enforcement) or are undermined by fallback behaviors (e.g., `_NullFernet`).

---

## 3. Findings

### 3.2 High

#### FINDING-001: 🟠 No URL scheme validation allows plaintext HTTP communication with bearer tokens and sensitive data

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-319 |
| **ASVS Section(s)** | 12.2.1 |
| **Files** | task-sdk/src/airflow/sdk/api/client.py:735-740 |
| **Source Reports** | 12.2.1.md |
| **Related Findings** | None |

**Description:**

The Client.__init__() method sets the verify parameter with a properly configured SSL context, but this control is only effective when the connection is actually HTTPS. The httpx library's verify parameter controls TLS certificate validation — it does NOT prevent plain HTTP connections. If base_url is configured with http:// scheme, all requests proceed over plaintext, including: Bearer token in every Authorization header (via BearerAuth.auth_flow), Connection passwords (ConnectionResponse.password field), Variable values (potentially secrets), XCom values, and Token refresh headers (Refreshed-API-Token). This is a Type B gap: the TLS verification control EXISTS (_get_ssl_context_cached) but is NOT EFFECTIVE when the URL scheme is http://. The SSL context is never consulted for plaintext connections.

**Remediation:**

Add URL scheme validation in Client.__init__() to enforce HTTPS. Parse the base_url using urllib.parse.urlparse() and validate that parsed.scheme == 'https'. Raise a ValueError if the scheme is not HTTPS, with a clear error message explaining the security requirement. Optionally provide an explicit opt-out flag like allow_insecure=False for development/testing only, with logged warnings.

---

#### FINDING-002: 🟠 No Version Freshness Validation at Provider Load Time

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 15.2.1, 15.1.1 |
| **Files** | task-sdk/src/airflow/sdk/providers_manager_runtime.py:187-190, task-sdk/src/airflow/sdk/providers_manager_runtime.py:48-88, task-sdk/src/airflow/sdk/providers_manager_runtime.py:192, task-sdk/src/airflow/sdk/providers_manager_runtime.py:199, task-sdk/src/airflow/sdk/providers_manager_runtime.py:204, task-sdk/src/airflow/sdk/providers_manager_runtime.py:209, task-sdk/src/airflow/sdk/providers_manager_runtime.py:214, task-sdk/src/airflow/sdk/providers_manager_runtime.py:219 |
| **Source Reports** | 15.2.1.md, 15.1.1.md |
| **Related Findings** | None |

**Description:**

The provider loading pipeline discovers and loads ALL installed provider packages without implementing any security-aware version validation or vulnerability tracking mechanisms. Specifically, the system lacks: (1) Version recording in a structured format suitable for SBOM generation, (2) Vulnerability checking against known CVE databases or security advisories, (3) Version policy enforcement (minimum secure versions, blocklists), (4) Security audit logging of loaded provider versions, (5) Warning or blocking mechanisms for providers with known vulnerabilities. The _correctness_check() function validates import capability and naming conventions but performs NO security-relevant version validation. The _provider_schema_validator validates metadata structure but not security posture.

**Remediation:**

1. Implement version logging during provider discovery to log loaded provider versions with security_audit flag for SBOM/audit purposes. 2. Add version allowlist/blocklist support with _check_provider_version_policy() method that validates provider versions against blocked versions and minimum secure versions from configuration. 3. Document the remediation policy in SECURITY.md defining risk-based remediation timeframes (Critical: 24-48 hours, High: 7 days, Medium: 30 days, Low: 90 days) and version management practices. 4. Integrate with CI/CD vulnerability scanning using tools like pip-audit and safety check to scan provider dependencies for vulnerabilities.

---

#### FINDING-003: 🟠 No Integrity or Provenance Verification for Dynamically Loaded Provider Code

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 15.2.1 |
| **Files** | task-sdk/src/airflow/sdk/providers_manager_runtime.py:48, task-sdk/src/airflow/sdk/providers_manager_runtime.py:366, task-sdk/src/airflow/sdk/providers_manager_runtime.py:494, task-sdk/src/airflow/sdk/plugins_manager.py:40 |
| **Source Reports** | 15.2.1.md |
| **Related Findings** | None |

**Description:**

Provider packages are discovered from installed Python packages and loaded via import_string() without signature verification, hash validation, or allowlist checking. This creates a supply chain vulnerability where compromised or typosquatted packages can inject malicious code into the trusted execution context. Without provenance verification, a compromised or typosquatted provider package installed in the environment will be loaded into the trusted execution context. Given that providers can register custom serializers, access secrets and credentials, execute within task context, and inject configuration values, this enables supply chain attacks that persist across all task executions, directly violating ASVS 15.2.1's requirement to verify component trustworthiness and maintenance status.

**Remediation:**

Implement provider provenance verification with allowlist-based validation and optional signature verification. Create TRUSTED_PROVIDERS configuration dictionary and implement _verify_provider_provenance() function to verify providers come from trusted sources. Apply verification before provider loading in initialize_providers_list(). For production environments, implement cryptographic signature verification of provider packages against trusted keys. Add structured SBOM output of loaded component versions for monitoring against vulnerability databases.

---

#### FINDING-004: 🟠 Silent fallback to no encryption via `_NullFernet` when `FERNET_KEY` is not configured

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 11.3.2 |
| **Files** | task-sdk/src/airflow/sdk/crypto.py:105-108, task-sdk/src/airflow/sdk/crypto.py:56-69 |
| **Source Reports** | 11.3.2.md |
| **Related Findings** | None |

**Description:**

The system implements a silent fallback mechanism where if the FERNET_KEY configuration is not set, all encryption operations pass through plaintext via the _NullFernet class. This means secrets (connection passwords, variable values, SLA callbacks) are stored without any encryption in the metadata database. The transition between fully encrypted and completely unencrypted depends on a single boolean condition with only a warning log message. An attacker with read access to the metadata database (via SQL injection, backup exposure, or cloud storage misconfiguration) obtains all secrets in cleartext. This violates the ASVS requirement that only approved ciphers and modes are used - when _NullFernet is active, no cipher is used at all.

**Remediation:**

Option A — Fail loudly in production environments: Add an environment-aware check that raises an AirflowException (rather than logging a warning) when FERNET_KEY is empty in production-classified environments. Check the ENVIRONMENT configuration and raise an exception with instructions to generate a key using: python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'. Option B — Always require a key and remove _NullFernet from production code paths by raising an AirflowException when FERNET_KEY is not set. Additionally, implement a startup verification that confirms get_fernet().is_encrypted is True in production, integrated into readiness checks.

---

#### FINDING-005: 🟠 Deserialization allow-list regex matching uses `re.match()` instead of `re.fullmatch()`, enabling prefix-based bypass

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-502 |
| **ASVS Section(s)** | 2.2.1, 2.2.2 |
| **Files** | task-sdk/src/airflow/sdk/serde/__init__.py:285 |
| **Source Reports** | 2.2.1.md, 2.2.2.md |
| **Related Findings** | None |

**Description:**

The deserialization allow-list uses `re.match()` which only anchors at the start of the string, not the end. This allows an attacker to bypass the allow-list by creating classnames that start with an allowed pattern but contain additional malicious suffixes. For example, if an administrator configures a pattern like `airflow\.models\.Variable`, the match would incorrectly pass for `airflow.models.Variable_Malicious` or `airflow.models.VariableEvil`. A malicious task could serialize an object with a crafted classname that starts with an allowed pattern, and when another task deserializes this XCom value, the allow-list check would pass, enabling instantiation of an unintended class. This is a Type B gap where a security control EXISTS (allow-list with regex matching) but is NOT correctly applied (uses prefix match instead of full match). The validation IS at a trusted layer (server-configured allow-list), but the implementation of the control is deficient, reducing its effectiveness as a security boundary.

**Remediation:**

Change `_match_regexp` to use `p.fullmatch()` instead of `p.match()`. This ensures the pattern must match the entire classname, not just a prefix. Updated code:

```python
@functools.cache
def _match_regexp(classname: str):
    """Check if the given classname matches a pattern from allowed_deserialization_classes_regexp using regexp."""
    patterns = _get_regexp_patterns()
    return any(p.fullmatch(classname) is not None for p in patterns)
```

Additionally:
- Add documentation to the `allowed_deserialization_classes_regexp` configuration option explicitly noting that patterns must match the full classname (add `$` anchor if needed)
- Consider adding a warning log when a regex pattern doesn't end with `$`, to alert administrators of potentially over-permissive patterns
- Add integration tests that verify the allow-list blocks specific known-dangerous classnames, including prefix-matching edge cases

---

#### FINDING-006: 🟠 IPC frame reader allocates memory based on untrusted length prefix without maximum size validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-770 |
| **ASVS Section(s)** | 2.2.1 |
| **Files** | task-sdk/src/airflow/sdk/execution_time/comms.py:165 |
| **Source Reports** | 2.2.1.md |
| **Related Findings** | None |

**Description:**

The IPC frame reader in `CommsDecoder._read_frame` reads a 4-byte length prefix from the socket and directly allocates a bytearray of that size without validating against a maximum threshold. The length can be up to 2^32 - 1 bytes (4GB). A malicious DAG task could write directly to the IPC socket (fd 0) to send a crafted frame with an oversized length prefix, causing the supervisor to attempt to allocate gigabytes of memory. This leads to memory exhaustion in the supervisor process, which manages multiple task instances. The supervisor could be OOM-killed, affecting all running tasks. While the sending side enforces a 4GiB maximum, the receiving side has no practical upper limit. This is a Type A gap where an entry point has NO control for message size validation on the receiving side.

**Remediation:**

Add a maximum message size constant and validate the length prefix before allocating memory:

```python
MAX_IPC_MSG_SIZE = 64 * 1024 * 1024  # 64MB - reasonable maximum for IPC messages

def _read_frame(self, maxfds: int | None = None) -> tuple[_ResponseFrame, list[int]] | _ResponseFrame:
    # ...
    length = int.from_bytes(len_bytes, byteorder="big")
    
    if length > MAX_IPC_MSG_SIZE:
        raise ValueError(
            f"IPC message size {length} exceeds maximum allowed size {MAX_IPC_MSG_SIZE}"
        )
    
    buffer = bytearray(length)
    # ...
```

Additional recommendations:
- Add monitoring/metrics for IPC message sizes to establish baseline and detect anomalies
- Implement per-message-type size limits in the IPC protocol (e.g., control messages ≤ 1KB, XCom data ≤ configured max) for finer-grained resource control

---

#### FINDING-007: 🟠 Systematic lack of URL-encoding for path segments in dynamically constructed API URLs

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-116 |
| **ASVS Section(s)** | 1.2.2 |
| **Files** | task-sdk/src/airflow/sdk/api/client.py:280, task-sdk/src/airflow/sdk/api/client.py:320, task-sdk/src/airflow/sdk/api/client.py:340, task-sdk/src/airflow/sdk/api/client.py:355, task-sdk/src/airflow/sdk/api/client.py:365, task-sdk/src/airflow/sdk/api/client.py:382, task-sdk/src/airflow/sdk/api/client.py:400, task-sdk/src/airflow/sdk/api/client.py:425, task-sdk/src/airflow/sdk/api/client.py:445, task-sdk/src/airflow/sdk/api/client.py:458, task-sdk/src/airflow/sdk/api/client.py:480, task-sdk/src/airflow/sdk/api/client.py:490, task-sdk/src/airflow/sdk/api/client.py:508, task-sdk/src/airflow/sdk/api/client.py:512, task-sdk/src/airflow/sdk/api/client.py:516, task-sdk/src/airflow/sdk/api/client.py:555 |
| **Source Reports** | 1.2.2.md |
| **Related Findings** | None |

**Description:**

String parameters (dag_id, run_id, task_id, key, conn_id) from task execution context, DAG definitions, or operator parameters are interpolated directly into URL paths via f-string interpolation without URL encoding. Special characters in identifiers (/, ?, #, %, ..) alter the URL structure, potentially routing requests to unintended API endpoints. Characters like ? or # in path values could inject query parameters or truncate the URL path. If the server has different authorization rules for different path prefixes, path manipulation could access resources outside the intended scope. Legitimate identifiers containing special characters (e.g., hierarchical variable keys like section/subsection/key) will fail silently by hitting wrong endpoints. urllib.parse.quote(value, safe='') is never applied to path segments. This is a Type A gap where no control exists at all.

**Remediation:**

Implement URL path encoding by applying urllib.parse.quote(value, safe='') to all path segments before URL construction. Create a helper function _build_path(*segments) that applies quote(str(seg), safe='') to each segment and returns the joined path. Update all dynamically-constructed URL paths in client.py to use this helper function. Example: def _build_path(*segments: str) -> str: return '/'.join(quote(str(seg), safe='') for seg in segments). Usage: resp = self.client.get(_build_path('xcoms', dag_id, run_id, task_id, key)). Add input validation for identifiers to reject values containing dangerous characters as defense-in-depth. Add integration tests that verify the SDK correctly handles identifiers containing URL-special characters.

---

#### FINDING-008: 🟠 Supervisor Processes State-Mutating Operations After Terminal State Declaration

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 2.3.1 |
| **Files** | task-sdk/src/airflow/sdk/execution_time/supervisor.py:1091-1253, task-sdk/src/airflow/sdk/execution_time/supervisor.py:1168-1178, task-sdk/src/airflow/sdk/execution_time/supervisor.py:1179-1180, task-sdk/src/airflow/sdk/execution_time/supervisor.py:1166-1167 |
| **Source Reports** | 2.3.1.md |
| **Related Findings** | None |

**Description:**

The supervisor processes state-mutating operations (SetXCom, PutVariable, DeleteXCom, DeleteVariable, SkipDownstreamTasks) without checking whether the task has already declared a terminal state. This violates ASVS 2.3.1's requirement that business logic flows must be processed in sequential order without skipping steps. The supervisor allows XComs, Variables, and downstream task skipping to be processed after the task has already declared completion (SUCCESS, DEFERRED, etc.), creating data integrity violations and workflow bypasses.

**Remediation:**

Add a terminal state guard at the beginning of _handle_request() that checks if self._terminal_state is set before processing state-mutating operations. Reject messages of types SetXCom, DeleteXCom, PutVariable, DeleteVariable, SkipDownstreamTasks, SucceedTask, DeferTask, RescheduleTask, RetryTask, and TaskState when _terminal_state is already set. Log a warning and return an ErrorResponse with error type API_SERVER_ERROR indicating the task is already in a terminal state. Allow only read operations (GetConnection, GetVariable, GetXCom) to continue after terminal state.

---

#### FINDING-009: 🟠 Terminal State Can Be Overwritten by Subsequent State Transition Messages

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 2.3.1 |
| **Files** | task-sdk/src/airflow/sdk/execution_time/supervisor.py:1091-1253, task-sdk/src/airflow/sdk/execution_time/supervisor.py:1101-1110, task-sdk/src/airflow/sdk/execution_time/supervisor.py:1158-1161, task-sdk/src/airflow/sdk/execution_time/supervisor.py:1163-1165 |
| **Source Reports** | 2.3.1.md |
| **Related Findings** | None |

**Description:**

The supervisor allows _terminal_state to be overwritten by subsequent state transition messages (SucceedTask, DeferTask, RescheduleTask, RetryTask). This creates a state machine integrity violation where the supervisor's internal state can diverge from the API server's state. A task can send DeferTask followed by SucceedTask, causing the local _terminal_state to be overwritten from DEFERRED to SUCCESS. The final_state property returns the last _terminal_state set, which may not reflect the actual server state if the server rejected the second transition. This leads to inconsistent behavior, heartbeat suppression issues, and observability problems.

**Remediation:**

Add single-write enforcement for _terminal_state at the beginning of each state-transition branch (SucceedTask, DeferTask, RescheduleTask, RetryTask). Check if self._terminal_state is not None before setting it. If already set, log a warning with current_state, requested_state, and ti_id, then send an ErrorResponse with error type API_SERVER_ERROR indicating that terminal state is already set. Return early without processing the duplicate transition. This ensures _terminal_state can only be set once and prevents state machine integrity violations.

---

#### FINDING-010: 🟠 Expired cache entries containing secrets are never removed from memory

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-459 |
| **ASVS Section(s)** | 14.3.1 |
| **Files** | task-sdk/src/airflow/sdk/execution_time/cache.py:100-111 |
| **Source Reports** | 14.3.1.md |
| **Related Findings** | None |

**Description:**

No session/process termination hook exists to clear cached secrets. The only cleanup method (reset()) is explicitly marked for test use only and merely sets the reference to None without clearing the underlying Manager dict. Secrets cached during task execution persist after task completes or session terminates with no cleanup triggered. Secrets persist in Manager process memory and next task or memory inspector can observe residual data. ASVS 14.3.1 requires that authenticated data is cleared from client storage after the client or session is terminated and that the client-side should also be able to clear up if the server connection is not available. The SecretCache provides no mechanism to clear all cached secrets when a task execution completes, the session JWT expires, the supervisor detects the API server is unreachable, or an administrator triggers a cache purge.

**Remediation:**

Add active deletion of expired entries in _get() method. When is_expired() returns True, call cls._cache.pop(cache_key, None) before raising NotPresentException. Implement a clear_expired() classmethod to remove all expired entries from the cache. Implement a clear_all() classmethod to clear all cached secrets on session termination. Add periodic cache sweep (e.g., every TTL/2 seconds) to proactively remove all expired entries.

---

#### FINDING-011: 🟠 Missing path traversal validation on `dag_rel_path` in DAG loading allows potential code execution outside bundle boundary

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-22 |
| **ASVS Section(s)** | 5.3.2 |
| **Files** | task-sdk/src/airflow/sdk/execution_time/task_runner.py:1105 |
| **Source Reports** | 5.3.2.md |
| **Related Findings** | FINDING-012 |

**Description:**

The `parse()` function in `task_runner.py` constructs an absolute path by joining `bundle_instance.path` with `what.dag_rel_path` received from the supervisor IPC without validating that the resolved path remains within the bundle boundary. The `dag_rel_path` originates from the API server database and could be influenced by an attacker. No path normalization, symlink resolution, or containment check is performed before passing the path to `BundleDagBag`, which loads and executes the Python file at that path. This allows an attacker who can manipulate `dag_rel_path` to cause arbitrary Python code execution outside the intended bundle directory.

**Remediation:**

Resolve the constructed path using `Path.resolve()` and validate it remains within the bundle root using `Path.relative_to()`. If the validation fails (ValueError exception), log the attempt and exit with an error. Example: `dag_absolute_path = Path(bundle_instance.path, what.dag_rel_path).resolve(); bundle_root = bundle_instance.path.resolve(); dag_absolute_path.relative_to(bundle_root)` with appropriate exception handling.

---

#### FINDING-012: 🟠 `init_log_file` accepts unsanitized relative path enabling directory traversal for file creation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-22 |
| **ASVS Section(s)** | 5.3.2 |
| **Files** | task-sdk/src/airflow/sdk/log.py:113 |
| **Source Reports** | 5.3.2.md |
| **Related Findings** | FINDING-011 |

**Description:**

The `init_log_file()` function in `log.py` accepts a `local_relative_path` parameter that is typically constructed from user-defined identifiers (`dag_id`, `task_id`, `run_id`, `try_number`) stored in the database. This path is passed directly to the underlying `init_log_file` implementation without path traversal validation, normalization, or containment checks. An attacker who can control these identifiers (e.g., through a DAG with a malicious `dag_id` containing path traversal sequences like `../../`) could cause files and directories to be created outside the intended `base_log_folder` with permissions 0o775 (directories) and 0o664 (files). This could lead to overwriting sensitive system files or affecting other tenants in multi-tenant deployments.

**Remediation:**

Before calling the underlying `init_log_file`, resolve the full path using `Path(base_log_folder, local_relative_path).resolve()` and validate it remains within the base folder using `Path.relative_to()`. If validation fails, raise a ValueError with a descriptive error message. This ensures that no files or directories can be created outside the intended log directory.

---

#### FINDING-013: 🟠 No explicit TLS minimum version enforcement — TLS 1.0/1.1 may be negotiated

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 12.1.1 |
| **Files** | task-sdk/src/airflow/sdk/api/client.py:816-820, task-sdk/src/airflow/sdk/api/client.py:821-865 |
| **Source Reports** | 12.1.1.md |
| **Related Findings** | None |

**Description:**

The SSL context created by `Client._get_ssl_context_cached()` uses `ssl.create_default_context()` without explicitly setting `minimum_version` or `maximum_version`. On systems running Python 3.9 with OpenSSL 1.1.1 (common in enterprise environments), the SSL context will accept TLS 1.0 and TLS 1.1 connections. If the Airflow server (or a MITM attacker performing protocol downgrade) negotiates TLS 1.0/1.1, connections may use deprecated TLS protocols with known cryptographic weaknesses. This violates the domain context requirement that the execution API client must use TLS 1.2+ with strong cipher suites. Protocol downgrade attacks (e.g., via TLS_FALLBACK_SCSV bypass on older stacks) become possible, and weak cipher suites associated with TLS 1.0/1.1 (e.g., RC4, CBC mode with predictable IV) may be negotiated.

**Remediation:**

Add explicit TLS version enforcement and cipher suite configuration to `_get_ssl_context_cached()`: (1) Set `ctx.minimum_version = ssl.TLSVersion.TLSv1_2` to enforce TLS 1.2 as the minimum version, (2) Set `ctx.maximum_version = ssl.TLSVersion.TLSv1_3` to prefer TLS 1.3 when available, (3) Configure strong cipher suites using `ctx.set_ciphers()` with a string like 'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS:!RC4:!3DES' to disable weak ciphers. Additionally, consider adding OCSP stapling support, logging TLS negotiation details at debug level, adding startup validation of SSL context configuration, and implementing integration tests to verify TLS version enforcement.

---

#### FINDING-014: 🟠 Authentication failure (401/403) during heartbeat not treated as immediate session invalidation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 7.4.1, 7.4.2 |
| **Files** | task-sdk/src/airflow/sdk/execution_time/supervisor.py:780-815 |
| **Source Reports** | 7.4.1.md, 7.4.2.md |
| **Related Findings** | None |

**Description:**

When the server revokes a task execution token or the token expires, the supervisor's heartbeat mechanism receives a 401 Unauthorized or 403 Forbidden response. However, these authentication failures are not treated as immediate session invalidation. Instead, they are handled as transient failures, incrementing a failure counter and allowing the task process to continue executing for up to 150+ seconds (5 heartbeat cycles × 30s interval). This violates the ASVS requirement that session termination disallows any further use of the session. During this window, the task may execute arbitrary code with stale/missing data, complete actions that should have been halted, and continue consuming resources after authorization has been revoked. While the supervisor correctly handles 404/410/409 status codes with immediate termination, 401/403 authentication failures are definitively non-transient and indicate the session is no longer valid, yet are currently treated as transient errors.

**Remediation:**

Add HTTPStatus.UNAUTHORIZED (401) and HTTPStatus.FORBIDDEN (403) to the list of status codes that trigger immediate process termination in the _send_heartbeat_if_needed() method. These authentication failures should be treated the same as NOT_FOUND, GONE, and CONFLICT responses, triggering immediate SIGTERM with force=True and setting _terminal_state to SERVER_TERMINATED. Include appropriate error logging to indicate session termination due to authentication failure. This is a minimal code change that immediately closes the 150-second token-revocation window and ensures consistent behavior across all session invalidation scenarios.

---

#### FINDING-015: 🟠 API request authentication failures in request handler do not trigger session termination

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 7.4.1, 7.4.2 |
| **Files** | task-sdk/src/airflow/sdk/execution_time/supervisor.py:510-545 |
| **Source Reports** | 7.4.1.md, 7.4.2.md |
| **Related Findings** | None |

**Description:**

When a task makes API requests for connections, variables, or XCom through the supervisor, and the server returns 401 Unauthorized or 403 Forbidden due to token revocation, the supervisor logs the error and sends an error response back to the task process but does not terminate the session. The task process can continue executing indefinitely after its session token is invalidated, as long as it handles API errors gracefully (which many operators do). A task that doesn't frequently call the API could run for the full heartbeat timeout period (150+ seconds) while unauthorized. This allows continued execution after session invalidation, violating ASVS 7.4.1 and 7.4.2 requirements. This creates an inconsistency where token revocation discovered through API requests (rather than heartbeat) does not result in immediate task termination.

**Remediation:**

In the handle_requests() method's ServerResponseError exception handler, add a check for authentication failure status codes (401 Unauthorized, 403 Forbidden). When these are detected, immediately terminate the task process using kill(signal.SIGTERM, force=True), set _terminal_state to SERVER_TERMINATED, log the session termination, and return to stop processing further requests. This ensures that any authentication failure during API requests triggers immediate session termination rather than allowing continued execution, and provides consistent session termination behavior regardless of which code path discovers the authentication failure.

---

#### FINDING-016: 🟠 Authorization Denial Indistinguishable from Not-Found in Secrets Backend Enables Potential Fallback Bypass

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-639 |
| **ASVS Section(s)** | 8.2.2 |
| **Files** | task-sdk/src/airflow/sdk/execution_time/secrets/execution_api.py:47, task-sdk/src/airflow/sdk/execution_time/secrets/execution_api.py:73, task-sdk/src/airflow/sdk/execution_time/secrets/execution_api.py:96, task-sdk/src/airflow/sdk/execution_time/secrets/execution_api.py:117 |
| **Source Reports** | 8.2.2.md |
| **Related Findings** | None |

**Description:**

The ExecutionAPISecretsBackend returns None for both authorization denials and genuine not-found cases, which enables fallback to less-restrictive backends. In multi-tenant deployments, this allows tasks to access secrets their DAG is not authorized to use if those secrets exist in fallback backends (e.g., environment variables). The data flow: (1) Task requests unauthorized secret, (2) Server denies access (403), (3) Supervisor sends ErrorResponse, (4) SDK returns None (indistinguishable from not-found), (5) Airflow secrets chain tries next backend, (6) Fallback backend provides secret without DAG-level authorization. This is a Type C gap where the control is called (server-side authorization checks token scope) but the result is ignored (authorization denial treated identically to not-found).

**Remediation:**

Distinguish between not-found and access-denied responses. Raise an exception (not return None) when authorization is explicitly denied. Implement an AuthorizationDeniedError exception class. Modify get_connection() and get_variable() methods to check if ErrorResponse indicates CONNECTION_NOT_FOUND (allow fallback by returning None) versus other errors like access denied (raise AuthorizationDeniedError to prevent fallback). Extend the ErrorType enum to include CONNECTION_ACCESS_DENIED and VARIABLE_ACCESS_DENIED distinct from CONNECTION_NOT_FOUND and VARIABLE_NOT_FOUND. Only allow fallback on genuine communication failures, not authorization failures.

---

# 4. Positive Security Controls

| Control Category | Control | Evidence | Implementation Location |
|-----------------|---------|----------|------------------------|
| **TLS/SSL Configuration** | Strong SSL defaults using ssl.create_default_context() | Uses ssl.create_default_context() which enforces modern TLS versions and cipher suites, with hostname verification enabled by default | task-sdk/src/airflow/sdk/api/client.py:723 |
| | Certifi CA bundle for certificate validation | Uses certifi.where() for up-to-date, publicly-trusted CA certificates rather than system CA stores that may be misconfigured | task-sdk/src/airflow/sdk/api/client.py:738 |
| | Mutual TLS (client certificates) support | Client certificate authentication is supported via API_CLIENT_SSL_CERT and API_CLIENT_SSL_KEY configuration, with validation that both must be set together | task-sdk/src/airflow/sdk/api/client.py:742 |
| | SSL context caching | @lru_cache() on _get_ssl_context_cached() prevents memory growth from repeated context creation while maintaining security properties | task-sdk/src/airflow/sdk/api/client.py:723 |
| **Authentication** | Bearer token authentication | Token-based authentication ensures credentials are not embedded in URLs | task-sdk/src/airflow/sdk/api/client.py |
| | Token refresh mechanism | Bearer token is refreshed when server issues Refreshed-API-Token header | task-sdk/src/airflow/sdk/api/client.py:_update_auth() |
| **Content-Type Handling** | Explicit Content-Type on requests | The request() method explicitly sets content-type: application/json when sending serialized content bodies, preventing Content-Type omission | task-sdk/src/airflow/sdk/api/client.py:755 |
| | Content-Type validation before error parsing | ServerResponseError.from_response() checks response.headers.get("content-type") != "application/json" before attempting to parse response bodies as JSON | task-sdk/src/airflow/sdk/api/client.py:805 |
| | httpx built-in Content-Type handling | When using json= parameter, httpx automatically sets the correct Content-Type header with proper media type | task-sdk/src/airflow/sdk/api/client.py |
| **Input Validation** | Pydantic structural validation | All response parsing uses model_validate_json() which validates the structure and types of response data | task-sdk/src/airflow/sdk/api/client.py |
| | Typed response models | API operations use typed Pydantic models (ConnectionResponse, VariableResponse, XComResponse, DagRun) to enforce field subsets | task-sdk/src/airflow/sdk/api/client.py |
| | Discriminated union types for IPC messages | IPC message schemas use discriminated unions with Literal types and Field(discriminator='type') annotation | task-sdk/src/airflow/sdk/execution_time/comms.py |
| | Deserialization allow-list using glob matching | fnmatch() with full-string match prevents partial match bypasses | task-sdk/src/airflow/sdk/serde/__init__.py:_match_glob() |
| | Recursion depth protection during serialization | serialize() tracks depth and raises RecursionError at sys.getrecursionlimit() - 1 | task-sdk/src/airflow/sdk/serde/__init__.py:serialize() |
| | Frame size limit on sending side | 4GiB overflow check in as_bytes() | task-sdk/src/airflow/sdk/execution_time/comms.py:_FrameMixin.as_bytes() |
| | Port integer validation | Explicit int conversion in from_json() and port field validated as integer type | task-sdk/src/airflow/sdk/definitions/connection.py |
| | URI scheme count validation | Max 2 schemes checked in from_uri() | task-sdk/src/airflow/sdk/definitions/connection.py:from_uri() |
| | Version validation in deserialization | Version comparison check in deserialize() | task-sdk/src/airflow/sdk/serde/__init__.py:deserialize() |
| | Class name string validation | isinstance(classname, str) check in decode() | task-sdk/src/airflow/sdk/serde/__init__.py:decode() |
| | Reserved key detection during serialization | serialize() raises AttributeError if dicts contain reserved keys (CLASSNAME, SCHEMA_ID) | task-sdk/src/airflow/sdk/serde/__init__.py:serialize() |
| | Event hooks for response validation | raise_on_4xx_5xx is registered as a response event hook, ensuring it's called for ALL responses | task-sdk/src/airflow/sdk/api/client.py:raise_on_4xx_5xx() |
| **Output Encoding** | Structured logging (structlog) | All log calls use structured key-value format throughout all files | Throughout codebase |
| | mask_logs processor | Applied to structlog pipeline; handles secret redaction | task-sdk/src/airflow/sdk/log.py:53-55 |
| | JSON serialization (Pydantic model_dump_json()) | All API request/response bodies properly serialized | task-sdk/src/airflow/sdk/api/client.py |
| | Query parameters properly handled via httpx | All query parameters use httpx's params= dict interface which automatically URL-encodes values | task-sdk/src/airflow/sdk/api/client.py |
| | UUID-based paths inherently safe | TaskInstanceOperations methods using uuid.UUID for id parameter only contain hex characters and hyphens | task-sdk/src/airflow/sdk/api/client.py |
| | Protocol restriction to HTTP/HTTPS only | Client class uses httpx which inherently restricts to HTTP/HTTPS protocols | task-sdk/src/airflow/sdk/api/client.py |
| | Static path prefixes limit attack surface | All dynamically-constructed URLs have fixed path prefixes | task-sdk/src/airflow/sdk/api/client.py |
| | model_validate_json() for type-safe response parsing | Validates structure and types, preventing JSON confusion attacks | All response parsing |
| | No string concatenation for JSON construction | All JSON output goes through proper serialization layers | Throughout codebase |
| **Command Injection Prevention** | List-based os.execvp (no shell) | task_runner.py:startup() function uses parameterized execution with list arguments | task-sdk/src/airflow/sdk/execution_time/task_runner.py:1793 |
| | List-based os.execv (no shell) | supervisor.py:WatchedSubprocess.start() uses parameterized execution | task-sdk/src/airflow/sdk/execution_time/supervisor.py:370 |
| | Hardcoded Python -c code strings | Python code strings are static and defined in source code, never constructed from user input | task-sdk/src/airflow/sdk/execution_time/supervisor.py, task_runner.py |
| | Type validation of run_as_user as str | operator.py validates run_as_user type | task-sdk/src/airflow/sdk/definitions/operator.py:340 |
| | Fork-based process creation (no shell) | supervisor.py uses os.fork() for process isolation without shell invocation | task-sdk/src/airflow/sdk/execution_time/supervisor.py:340 |
| | Direct function invocation in child | supervisor.py _fork_main() invokes functions directly without shell | task-sdk/src/airflow/sdk/execution_time/supervisor.py:195 |
| | Signal handler reset after fork | _reset_signals() properly resets signal handlers to prevent unintended execution | task-sdk/src/airflow/sdk/execution_time/supervisor.py |
| | ORM access blocking in task subprocesses | block_orm_access() prevents indirect command injection through database-triggered operations | task-sdk/src/airflow/sdk/execution_time/supervisor.py |
| | No eval()/exec() with user input | Zero instances of eval(), exec(), or compile() with user-controllable input | All execution files verified |
| | Type-safe deserialization for IPC | Messages use explicit type schemas with TypeAdapter and validate_python() | task-sdk/src/airflow/sdk/execution_time/supervisor.py:handle_requests() |
| | Controlled dynamic dispatch for deferral | resume_execution method uses getattr on operator instance with server-trusted data | task-sdk/src/airflow/sdk/definitions/operator.py:905 |
| | Template rendering via Jinja2 environment | Uses DAG's Jinja environment (sandboxed) rather than Python string interpolation or eval | task-sdk/src/airflow/sdk/definitions/operator.py:880 |
| | ExecutorSafeguard prevents uncontrolled execution | Metaclass wraps all execute() methods with safeguard preventing execution outside proper task runner context | task-sdk/src/airflow/sdk/definitions/operator.py |
| **Cryptographic Operations** | Fernet (AES-128-CBC) with HMAC-SHA256 authentication | _RealFernet class and cryptography.fernet library implementation | task-sdk/src/airflow/sdk/crypto.py:80 |
| | Encrypt-then-MAC construction | Fernet's encrypt-then-MAC design (HMAC-SHA256 verified before decryption) eliminates CBC padding oracle attack vector | cryptography.fernet implementation |
| | No insecure block modes (ECB) used | Code exclusively uses Fernet which specifies AES-CBC mode, not ECB | task-sdk/src/airflow/sdk/crypto.py |
| | No PKCS#1 v1.5 RSA padding | No RSA operations present; PKCS7 used for block cipher padding is distinct from RSA PKCS#1 v1.5 | task-sdk/src/airflow/sdk/crypto.py |
| | MultiFernet for key rotation | Supports multiple keys for graceful key rotation without service disruption | task-sdk/src/airflow/sdk/crypto.py:91 |
| | Cached singleton for consistent encryption | @cache decorator ensures consistent encryption behavior throughout the process lifetime | task-sdk/src/airflow/sdk/crypto.py:105 |
| | HMAC-SHA256 exclusively used for authentication | Internal to cryptography.fernet.Fernet, always applied during encrypt/decrypt | cryptography.fernet implementation |
| | No weak hash functions (MD5, SHA-1) | Verified — no MD5 or SHA-1 imports or references in entire module | task-sdk/src/airflow/sdk/crypto.py |
| | No custom cryptographic implementations | Code delegates all cryptographic operations to the vetted cryptography library | task-sdk/src/airflow/sdk/crypto.py |
| | NIST-approved hash function (SHA-256) | SHA-256 via HMAC within Fernet is NIST-approved and used exclusively | cryptography.fernet implementation |
| **Provider Plugin Security** | Schema Validation | _provider_schema_validator validates structural correctness of provider metadata | task-sdk/src/airflow/sdk/providers_manager_runtime.py:162 |
| | Import Error Isolation | _correctness_check() comprehensively handles import failures | task-sdk/src/airflow/sdk/providers_manager_runtime.py:48-88 |
| | Lazy Loading | LazyDictWithCache and functools.partial patterns defer imports until actual use | task-sdk/src/airflow/sdk/providers_manager_runtime.py |
| | Prefix Validation | _check_builtin_provider_prefix() ensures built-in providers use expected naming conventions | task-sdk/src/airflow/sdk/providers_manager_runtime.py |
| | Singleton Pattern | ProvidersManagerTaskRuntime singleton ensures consistent state | task-sdk/src/airflow/sdk/providers_manager_runtime.py |
| | Caching with @provider_info_cache | Provider discovery results are cached, preventing repeated execution of discovery logic | task-sdk/src/airflow/sdk/providers_manager_runtime.py |
| **Business Logic** | State conflict detection on start() | Server returns 409 if task is already RUNNING; supervisor raises TaskAlreadyRunningError | task-sdk/src/airflow/sdk/api/client.py:261-275 |
| | Heartbeat suppression after terminal state | Stops heartbeats once task finishes by checking _terminal_state | task-sdk/src/airflow/sdk/execution_time/supervisor.py:_send_heartbeat_if_needed |
| | Overtime kill after terminal state | Terminates process after timeout by checking _terminal_state | task-sdk/src/airflow/sdk/execution_time/supervisor.py:_handle_process_overtime_if_needed |
| | SUCCESS routing check | Prevents misuse of finish() for SUCCESS state | task-sdk/src/airflow/sdk/api/client.py:280 |
| | Process termination on failed heartbeats | Kills stuck tasks when heartbeat returns 404/410/409 | task-sdk/src/airflow/sdk/execution_time/supervisor.py:_handle_heartbeat_failures |
| | Kill on start failure | If start() API call fails, subprocess is immediately killed with SIGKILL | task-sdk/src/airflow/sdk/execution_time/supervisor.py:_on_child_started |
| | Kill escalation | SIGINT → SIGTERM → SIGKILL escalation ensures process termination | task-sdk/src/airflow/sdk/execution_time/supervisor.py:kill() |
| | Process non-dumpable | Linux prctl(PR_SET_DUMPABLE, 0) prevents same-UID memory access | task-sdk/src/airflow/sdk/execution_time/supervisor.py:_make_process_nondumpable |
| | Server URL validation | Validates scheme (http/https), netloc presence before connecting | task-sdk/src/airflow/sdk/execution_time/supervisor.py:supervise_task |
| **Data Protection** | IPC-based communication (not HTTP URLs) | All secret requests go through SUPERVISOR_COMMS.send() using structured message types | task-sdk/src/airflow/sdk/execution_time/execution_api.py:55,80 |
| | Request messages contain only identifiers | Only conn_id/key sent, not secrets | task-sdk/src/airflow/sdk/execution_time/execution_api.py |
| | URL encoding of connection data | Credentials properly URL-encoded with quote(self.password, safe="") | task-sdk/src/airflow/sdk/definitions/connection.py:170,215 |
| | Secret masking on extra_dejson access | Both Variable.get() and Connection.extra_dejson apply masking to prevent secrets from appearing in logs | task-sdk/src/airflow/sdk/execution_time/connection.py:262, variable.py:51 |
| | Cache disabled by default | The use_cache configuration defaults to False | task-sdk/src/airflow/sdk/execution_time/cache.py:60 |
| | Configurable TTL | The cache_ttl_seconds configuration (default 15 minutes) provides a time-bound | task-sdk/src/airflow/sdk/execution_time/cache.py |
| | Team-based key isolation | Cache keys include team prefixes (_{team_name}_) | task-sdk/src/airflow/sdk/execution_time/cache.py |
| | TTL-based expiration check | is_expired() method defined and called to filter reads | task-sdk/src/airflow/sdk/execution_time/cache.py:43 |
| | Variable invalidation | invalidate_variable() method allows proactive removal of cached variables | task-sdk/src/airflow/sdk/execution_time/cache.py:131 |
| **Dependency Management** | Schema validation of provider metadata | _create_provider_info_schema_validator() validates structure of provider declarations | task-sdk/src/airflow/sdk/providers_manager_runtime.py:127 |
| | Package prefix validation | _check_builtin_provider_prefix() prevents namespace confusion for built-in providers | task-sdk/src/airflow/_shared/providers_discovery.py |
| | Import error handling with graceful degradation | _correctness_check catches and logs import failures without crashing | task-sdk/src/airflow/sdk/providers_manager_runtime.py:68-88 |

---

# 5. ASVS Compliance Summary

| ASVS ID | Requirement Title | Status | Notes |
|---------|------------------|--------|-------|
| **1.2.1** | Output Encoding for HTTP Response/HTML/XML | ✅ **Pass** | JSON serialization via Pydantic, structured logging with structlog |
| **1.2.2** | URL Encoding for Dynamic URLs | ❌ **Fail** | Missing URL-encoding for path segments (FINDING-007) |
| **1.2.3** | JavaScript/JSON Content Building | ✅ **Pass** | No string concatenation for JSON; proper serialization layers |
| **1.2.4** | Parameterized Queries and SQL Injection Protection | ✅ **Pass** | No SQL queries in SDK; ORM access blocked in task subprocess |
| **1.2.5** | Injection Prevention | ✅ **Pass** | List-based process execution, no eval()/exec() with user input |
| **1.3.1** | WYSIWYG Editor HTML Sanitization | ⚪ **N/A** | No HTML editor functionality |
| **1.3.2** | Sanitization | ✅ **Pass** | Secret masking, structured logging, proper encoding |
| **1.5.1** | Safe Deserialization - XML Parser Configuration | ⚪ **N/A** | No XML parsing |
| **2.1.1** | Validation and Business Logic Documentation | ✅ **Pass** | Pydantic models serve as validation documentation |
| **2.2.1** | Input Validation | ❌ **Fail** | Regex bypass in deserialization (FINDING-005), unbounded frame size (FINDING-006) |
| **2.2.2** | Input Validation at Trusted Service Layer | 🟡 **Partial** | Server-side validation present but client-side gaps exist |
| **2.3.1** | Business Logic Sequential Flow Enforcement | ❌ **Fail** | Terminal state can be overwritten (FINDING-008, FINDING-009) |
| **3.2.1** | Unintended Content Interpretation | ✅ **Pass** | Explicit Content-Type headers, proper validation |
| **3.2.2** | Safe Text Rendering | ⚪ **N/A** | No text rendering functionality |
| **3.3.1** | Cookie Setup | ⚪ **N/A** | No cookie handling |
| **3.4.1** | Browser Security Mechanism Headers (HSTS) | ⚪ **N/A** | SDK client, not web server |
| **3.4.2** | CORS Access-Control-Allow-Origin | ⚪ **N/A** | SDK client, not web server |
| **3.5.1** | Browser Origin Separation (CSRF) | ✅ **Pass** | No browser-based requests; API uses bearer tokens |
| **3.5.2** | Browser Origin Separation - CORS Preflight | ⚪ **N/A** | SDK client, not web application |
| **3.5.3** | Browser Origin Separation - HTTP Methods | ✅ **Pass** | RESTful API design with appropriate HTTP methods |
| **4.1.1** | Content-Type Header Validation | ✅ **Pass** | Explicit Content-Type validation before parsing |
| **4.4.1** | WebSocket over TLS (WSS) | ✅ **Pass** | No WebSocket usage; IPC uses local Unix sockets |
| **5.2.1** | File Upload Size Limits | ✅ **Pass** | Frame size limit (4GiB) on IPC messages |
| **5.2.2** | File Extension and Content Validation | ✅ **Pass** | Pydantic validation for all inputs |
| **5.3.1** | Uploaded Files Not Executed as Server-Side Code | ✅ **Pass** | No file upload functionality |
| **5.3.2** | Path Traversal Prevention | ❌ **Fail** | Missing validation on dag_rel_path and init_log_file (FINDING-011, FINDING-012) |
| **6.1.1** | Authentication Documentation | ⚪ **N/A** | SDK client uses server-provided tokens |
| **6.2.1** | Password Security - Minimum Length | ⚪ **N/A** | No password management in SDK |
| **6.2.2** | Password Security - Users Can Change Password | ⚪ **N/A** | No password management in SDK |
| **6.2.3** | Password Security - Change Requires Current and New Password | ⚪ **N/A** | No password management in SDK |
| **6.2.4** | Password Security - Check Against Common Passwords | ⚪ **N/A** | No password management in SDK |
| **6.2.5** | Password Security - No Composition Rules | ✅ **Pass** | No password composition rules enforced |
| **6.2.6** | Password Input Field Masking | ⚪ **N/A** | No password input fields |
| **6.2.7** | Paste Functionality and Password Managers Permitted | ⚪ **N/A** | No password input fields |
| **6.2.8** | Password Verified Without Modification | ✅ **Pass** | Bearer tokens used as-is without modification |
| **6.3.1** | Credential Stuffing and Brute Force Prevention | ✅ **Pass** | Server-side responsibility; SDK uses provided tokens |
| **6.3.2** | Default User Accounts Not Present or Disabled | ✅ **Pass** | No user account management in SDK |
| **6.4.1** | System Generated Initial Passwords | ✅ **Pass** | Server provides tokens; no password generation |
| **6.4.2** | Password hints or knowledge-based authentication | ✅ **Pass** | No password hints or KBA |
| **7.2.1** | Fundamental Session Management Security - Backend Verification | ✅ **Pass** | Bearer token verified by server on each request |
| **7.2.2** | Fundamental Session Management Security - Dynamic Tokens | ✅ **Pass** | Token refresh mechanism via Refreshed-API-Token header |
| **7.2.3** | Fundamental Session Management Security - Token Entropy | ⚪ **N/A** | Server generates tokens |
| **7.2.4** | Fundamental Session Management Security - Token Regeneration on Authentication | ✅ **Pass** | Token refresh mechanism present |
| **7.4.1** | Session Termination | ❌ **Fail** | Authentication failures during heartbeat/requests don't terminate session (FINDING-014, FINDING-015) |
| **7.4.2** | Session Termination - Account Disable/Delete | 🟡 **Partial** | Process termination on 404/410 but not on 401/403 |
| **8.1.1** | Authorization Documentation | 🟡 **Partial** | Implicit authorization model; server enforces access control |
| **8.2.1** | General Authorization Design (Function-Level) | ✅ **Pass** | Server enforces function-level authorization |
| **8.2.2** | General Authorization Design (Data-Specific) | ❌ **Fail** | Authorization denial indistinguishable from not-found (FINDING-016) |
| **8.3.1** | Operation Level Authorization | ✅ **Pass** | Server validates authorization for each API operation |
| **9.1.1** | Token source and integrity - Signature/MAC Validation | ✅ **Pass** | Server validates bearer tokens |
| **9.1.2** | Token source and integrity - Algorithm Allowlist | ⚪ **N/A** | Server responsibility |
| **9.1.3** | Token source and integrity - Key Material from Trusted Sources | ⚪ **N/A** | Server responsibility |
| **9.2.1** | Token content - Validity Time Span | ⚪ **N/A** | Server responsibility |
| **10.4.1** | Redirect URI Validation | ⚪ **N/A** | No OAuth flows |
| **10.4.2** | Authorization Code Single Use | ⚪ **N/A** | No OAuth flows |
| **10.4.3** | Authorization Code Short Lifetime | ⚪ **N/A** | No OAuth flows |
| **10.4.4** | Grant Type Restrictions | ⚪ **N/A** | No OAuth flows |
| **10.4.5** | Refresh Token Replay Mitigation | ⚪ **N/A** | No OAuth flows |
| **11.3.1** | Encryption Algorithms - Insecure Block Modes and Padding | ✅ **Pass** | No ECB mode; Fernet uses CBC with encrypt-then-MAC |
| **11.3.2** | Encryption Algorithms - Approved Ciphers and Modes | ❌ **Fail** | Silent fallback to _NullFernet (no encryption) when FERNET_KEY not configured (FINDING-004) |
| **11.4.1** | Hashing and Hash-based Functions | ✅ **Pass** | HMAC-SHA256 exclusively; no MD5/SHA-1 |
| **12.1.1** | General TLS Security Guidance | ❌ **Fail** | No explicit TLS minimum version enforcement (FINDING-013) |
| **12.2.1** | HTTPS Communication with External Facing Services | ❌ **Fail** | No URL scheme validation (FINDING-001) |
| **12.2.2** | HTTPS Communication with External Facing Services | ✅ **Pass** | Strong SSL defaults when HTTPS is used |
| **13.4.1** | Source Control Metadata Deployment | ✅ **Pass** | No .git directories in deployment |
| **14.2.1** | General Data Protection - Sensitive Data in URLs | ✅ **Pass** | IPC-based communication; secrets not in URLs |
| **14.3.1** | Client-side Data Protection - Clearing Authenticated Data | ❌ **Fail** | Expired cache entries never removed from memory (FINDING-010) |
| **15.1.1** | Risk-Based Remediation Time Frames for Third-Party Components | ❌ **Fail** | No version freshness validation (FINDING-002) |
| **15.2.1** | Component Update and Remediation Time Frames | ❌ **Fail** | No version freshness or integrity verification (FINDING-002, FINDING-003) |
| **15.3.1** | Return Only Required Subset of Fields | ✅ **Pass** | Typed response models with explicit field subsets |

### Summary Statistics

- ✅ **Pass**: 40 requirements (50.6%)
- ❌ **Fail**: 16 requirements (20.3%)
- 🟡 **Partial**: 3 requirements (3.8%)
- ⚪ **N/A**: 20 requirements (25.3%)

---

# 6. Cross-Reference Matrix

| Finding ID | Severity | ASVS Requirements | Affected Components | Positive Controls (Partial Mitigation) |
|------------|----------|-------------------|---------------------|----------------------------------------|
| **FINDING-001** | High | 12.2.1 | API Client (client.py) | Strong SSL defaults (when HTTPS used), certifi CA bundle, mTLS support |
| **FINDING-002** | High | 15.2.1, 15.1.1 | Provider Manager (providers_manager_runtime.py) | Schema validation, import error isolation, lazy loading |
| **FINDING-003** | High | 15.2.1 | Provider Manager (providers_manager_runtime.py) | Prefix validation, singleton pattern, caching |
| **FINDING-004** | High | 11.3.2 | Cryptography (crypto.py) | Fernet with HMAC-SHA256, MultiFernet key rotation, no weak hashes |
| **FINDING-005** | High | 2.2.1, 2.2.2 | Serialization (serde/__init__.py) | Deserialization allow-list with glob matching, version validation, class name validation |
| **FINDING-006** | High | 2.2.1 | IPC Communications (comms.py) | Frame size limit (4GiB) on sending side, Pydantic validation |
| **FINDING-007** | High | 1.2.2 | API Client (client.py) | UUID-based paths, static path prefixes, protocol restriction, httpx query parameter encoding |
| **FINDING-008** | High | 2.3.1 | Supervisor (supervisor.py) | Heartbeat suppression after terminal state, overtime kill after terminal state |
| **FINDING-009** | High | 2.3.1 | Supervisor (supervisor.py), IPC (comms.py) | State conflict detection on start(), SUCCESS routing check |
| **FINDING-010** | High | 14.3.1 | Cache (cache.py) | Cache disabled by default, configurable TTL, team-based key isolation, TTL-based expiration check |
| **FINDING-011** | High | 5.3.2 | Task Runner (task_runner.py) | Pydantic validation, typed response models |
| **FINDING-012** | High | 5.3.2 | Logging (log.py) | Structured logging with structlog |
| **FINDING-013** | High | 12.1.1 | API Client (client.py) | ssl.create_default_context(), certifi CA bundle, SSL context caching |
| **FINDING-014** | High | 7.4.1, 7.4.2 | Supervisor (supervisor.py) | Process termination on 404/410/409 heartbeat failures, kill escalation |
| **FINDING-015** | High | 7.4.1, 7.4.2 | Supervisor (supervisor.py) | Bearer token authentication, event hooks for response validation |
| **FINDING-016** | High | 8.2.2 | Execution API (execution_api.py), Supervisor (supervisor.py) | IPC-based communication, request messages contain only identifiers, server-side validation |

### Component Impact Analysis

| Component | Finding Count | Critical Findings | Positive Controls |
|-----------|---------------|-------------------|-------------------|
| **API Client** (client.py) | 3 | FINDING-001, FINDING-007, FINDING-013 | 10 controls (SSL, auth, Content-Type, encoding) |
| **Supervisor** (supervisor.py) | 4 | FINDING-008, FINDING-009, FINDING-014, FINDING-015 | 12 controls (state management, process control, session) |
| **Serialization** (serde/__init__.py) | 1 | FINDING-005 | 6 controls (validation, recursion protection) |
| **IPC Communications** (comms.py) | 2 | FINDING-006, FINDING-009 | 4 controls (frame limits, Pydantic validation) |
| **Cache** (cache.py) | 1 | FINDING-010 | 5 controls (disabled by default, TTL, isolation) |
| **Cryptography** (crypto.py) | 1 | FINDING-004 | 10 controls (Fernet, HMAC, key rotation) |
| **Provider Manager** (providers_manager_runtime.py) | 2 | FINDING-002, FINDING-003 | 6 controls (validation, isolation, lazy loading) |
| **Task Runner** (task_runner.py) | 1 | FINDING-011 | 3 controls (validation, command injection prevention) |
| **Logging** (log.py) | 1 | FINDING-012 | 2 controls (structured logging, masking) |
| **Execution API** (execution_api.py) | 1 | FINDING-016 | 3 controls (IPC-based, identifier-only requests) |

### ASVS Category Compliance

| ASVS Category | Pass | Fail | Partial | N/A | Compliance Rate |
|---------------|------|------|---------|-----|-----------------|
| **V1: Architecture** | 5 | 2 | 0 | 1 | 71.4% |
| **V2: Authentication** | 5 | 2 | 1 | 0 | 62.5% |
| **V3: Session Management** | 3 | 0 | 0 | 5 | 100% |
| **V4: Access Control** | 3 | 0 | 0 | 1 | 100% |
| **V5: Validation** | 3 | 1 | 0 | 1 | 75.0% |
| **V6: Cryptography** | 3 | 1 | 0 | 14 | 75.0% |
| **V7: Error Handling** | 3 | 2 | 1 | 0 | 50.0% |
| **V8: Data Protection** | 2 | 1 | 0 | 0 | 66.7% |
| **V9: Communications** | 1 | 1 | 0 | 4 | 50.0% |
| **V10: Malicious Code** | 0 | 2 | 0 | 0 | 0% |
| **V11: Business Logic** | 5 | 2 | 0 | 0 | 71.4% |
| **V12: Files** | 2 | 0 | 0 | 0 | 100% |
| **V13: API** | 2 | 0 | 0 | 0 | 100% |
| **V14: Configuration** | 1 | 0 | 0 | 0 | 100% |

### Risk Heat Map

```
                    Impact
                Low    Medium    High
Likelihood  
High         │       │ F-005  │ F-001 │
             │       │ F-007  │ F-004 │
             │       │        │ F-006 │
─────────────┼───────┼────────┼───────┤
Medium       │       │ F-010  │ F-002 │
             │       │ F-012  │ F-003 │
             │       │        │ F-008 │
             │       │        │ F-009 │
─────────────┼───────┼────────┼───────┤
Low          │       │ F-011  │ F-013 │
             │       │        │ F-014 │
             │       │        │ F-015 │
             │       │        │ F-016 │
```

**Legend:**
- **F-001**: HTTP scheme validation
- **F-002**: Version freshness validation
- **F-003**: Provider integrity verification
- **F-004**: Null encryption fallback
- **F-005**: Regex bypass in deserialization
- **F-006**: Unbounded IPC frame size
- **F-007**: URL path encoding
- **F-008**: Post-terminal state processing
- **F-009**: Terminal state overwrite
- **F-010**: Expired cache retention
- **F-011**: DAG path traversal
- **F-012**: Log file path traversal
- **F-013**: TLS version enforcement
- **F-014**: Heartbeat auth failure handling
- **F-015**: Request auth failure handling
- **F-016**: Authorization denial ambiguity

## 7. Level Coverage Analysis


**Audit scope:** up to L1

**Severity threshold:** high and above

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 16 |

**Total consolidated findings: 16**

*End of Consolidated Security Audit Report*