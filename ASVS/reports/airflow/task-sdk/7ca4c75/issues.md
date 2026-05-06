# Security Issues

## Issue: FINDING-001 - No URL scheme validation allows plaintext HTTP communication with bearer tokens and sensitive data
**Labels:** bug, security, priority:high
**Description:**
### Summary
The Client initialization accepts HTTP URLs without validation, allowing bearer tokens, connection passwords, variable values, XCom data, and token refresh headers to be transmitted in plaintext. The SSL context configuration is bypassed entirely when using HTTP scheme.

### Details
The `Client.__init__()` method in `task-sdk/src/airflow/sdk/api/client.py` (lines 735-740) configures SSL verification but does not validate the URL scheme. The httpx library's `verify` parameter only controls TLS certificate validation for HTTPS connections—it does not prevent plaintext HTTP connections. When `base_url` uses the `http://` scheme, all requests proceed over plaintext, exposing:
- Bearer tokens in Authorization headers (via BearerAuth.auth_flow)
- Connection passwords (ConnectionResponse.password field)
- Variable values (potentially secrets)
- XCom values
- Token refresh headers (Refreshed-API-Token)

**CWE:** CWE-319  
**ASVS:** 12.2.1 (L1)

### Remediation
1. Add URL scheme validation in `Client.__init__()` to enforce HTTPS
2. Parse `base_url` using `urllib.parse.urlparse()` and validate that `parsed.scheme == 'https'`
3. Raise `ValueError` if the scheme is not HTTPS with a clear security-focused error message
4. Optionally provide an explicit opt-out flag `allow_insecure=False` (default False) for development/testing only, with logged warnings

### Acceptance Criteria
- [ ] URL scheme validation added to `Client.__init__()`
- [ ] ValueError raised for non-HTTPS URLs with descriptive message
- [ ] Optional `allow_insecure` parameter implemented with warnings
- [ ] Unit tests added for HTTP rejection and HTTPS acceptance
- [ ] Integration tests verify bearer tokens only sent over HTTPS

### References
- Source: 12.2.1.md
- File: task-sdk/src/airflow/sdk/api/client.py:735-740

### Priority
**High** - Credentials transmitted in plaintext over HTTP

---

## Issue: FINDING-002 - No Version Freshness Validation at Provider Load Time
**Labels:** bug, security, priority:high
**Description:**
### Summary
The provider loading pipeline discovers and loads all installed provider packages without implementing security-aware version validation, vulnerability tracking, or enforcement of minimum secure versions. This creates supply chain risk by allowing vulnerable provider versions to execute.

### Details
The provider loading system in `task-sdk/src/airflow/sdk/providers_manager_runtime.py` lacks:
1. Version recording in structured format for SBOM generation
2. Vulnerability checking against CVE databases or security advisories
3. Version policy enforcement (minimum secure versions, blocklists)
4. Security audit logging of loaded provider versions
5. Warning/blocking mechanisms for providers with known vulnerabilities

The `_correctness_check()` function (lines 187-190) validates import capability and naming conventions but performs no security-relevant version validation. The `_provider_schema_validator` validates metadata structure but not security posture.

**ASVS:** 15.2.1, 15.1.1 (L1)

### Remediation
1. Implement version logging during provider discovery with `security_audit` flag for SBOM/audit purposes
2. Add version allowlist/blocklist support with `_check_provider_version_policy()` method validating against blocked versions and minimum secure versions from configuration
3. Document remediation policy in SECURITY.md defining risk-based timeframes:
   - Critical: 24-48 hours
   - High: 7 days
   - Medium: 30 days
   - Low: 90 days
4. Integrate CI/CD vulnerability scanning using tools like `pip-audit` and `safety check`

### Acceptance Criteria
- [ ] Version logging implemented in provider discovery
- [ ] Version policy checking added with allowlist/blocklist support
- [ ] SECURITY.md updated with remediation policy
- [ ] CI/CD vulnerability scanning integrated
- [ ] Tests added for version policy enforcement

### References
- Source: 15.2.1.md, 15.1.1.md
- Files: task-sdk/src/airflow/sdk/providers_manager_runtime.py (multiple lines)

### Priority
**High** - Supply chain vulnerability exposure

---

## Issue: FINDING-003 - No Integrity or Provenance Verification for Dynamically Loaded Provider Code
**Labels:** bug, security, priority:high
**Description:**
### Summary
Provider packages are loaded via `import_string()` without signature verification, hash validation, or allowlist checking. Compromised or typosquatted packages can inject malicious code into the trusted execution context with access to secrets, credentials, and task execution.

### Details
Providers are discovered from installed Python packages (line 48) and loaded without provenance verification (lines 366, 494 in `providers_manager_runtime.py` and line 40 in `plugins_manager.py`). Without verification:
- Compromised/typosquatted packages are loaded into trusted context
- Providers can register custom serializers
- Providers access secrets and credentials
- Providers execute within task context
- Providers inject configuration values

This enables supply chain attacks persisting across all task executions.

**ASVS:** 15.2.1 (L1)

### Remediation
1. Implement provider provenance verification with allowlist-based validation
2. Create `TRUSTED_PROVIDERS` configuration dictionary mapping provider names to trusted sources
3. Implement `_verify_provider_provenance()` function to verify providers come from trusted sources
4. Apply verification before provider loading in `initialize_providers_list()`
5. For production environments, implement cryptographic signature verification of provider packages against trusted keys
6. Add structured SBOM output of loaded component versions for monitoring

### Acceptance Criteria
- [ ] Provider allowlist configuration implemented
- [ ] Provenance verification function added
- [ ] Verification integrated into provider loading pipeline
- [ ] Optional signature verification implemented for production
- [ ] SBOM output generation added
- [ ] Tests added for allowlist enforcement and signature verification

### References
- Source: 15.2.1.md
- Files: task-sdk/src/airflow/sdk/providers_manager_runtime.py:48,366,494; plugins_manager.py:40

### Priority
**High** - Supply chain attack vector

---

## Issue: FINDING-004 - Silent fallback to no encryption via `_NullFernet` when `FERNET_KEY` is not configured
**Labels:** bug, security, priority:high
**Description:**
### Summary
When `FERNET_KEY` is not configured, all encryption operations silently pass through plaintext via the `_NullFernet` class. Secrets (connection passwords, variable values, SLA callbacks) are stored without encryption in the metadata database with only a warning log message.

### Details
In `task-sdk/src/airflow/sdk/crypto.py` (lines 105-108, 56-69), the system implements silent fallback where missing `FERNET_KEY` results in no encryption. The `_NullFernet` class (lines 56-69) passes all data through unchanged. An attacker with read access to the metadata database (SQL injection, backup exposure, cloud storage misconfiguration) obtains all secrets in cleartext. This violates ASVS 11.3.2's requirement that only approved ciphers are used—when `_NullFernet` is active, no cipher is used at all.

**ASVS:** 11.3.2 (L1)

### Remediation
**Option A** - Fail loudly in production:
1. Add environment-aware check raising `AirflowException` when `FERNET_KEY` is empty in production
2. Check `ENVIRONMENT` configuration and raise exception with key generation instructions
3. Command: `python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'`

**Option B** - Always require key:
1. Remove `_NullFernet` from production code paths
2. Raise `AirflowException` when `FERNET_KEY` is not set
3. Implement startup verification confirming `get_fernet().is_encrypted` is True
4. Integrate into readiness checks

### Acceptance Criteria
- [ ] Production environment check added
- [ ] Exception raised when FERNET_KEY missing in production
- [ ] Startup verification implemented
- [ ] Documentation updated with key generation instructions
- [ ] Tests added for key requirement enforcement

### References
- Source: 11.3.2.md
- File: task-sdk/src/airflow/sdk/crypto.py:105-108,56-69

### Priority
**High** - Secrets stored in plaintext

---

## Issue: FINDING-005 - Deserialization allow-list regex matching uses `re.match()` instead of `re.fullmatch()`, enabling prefix-based bypass
**Labels:** bug, security, priority:high
**Description:**
### Summary
The deserialization allow-list uses `re.match()` which only anchors at the start of the string, allowing bypass via classnames that start with allowed patterns but contain malicious suffixes (e.g., `airflow.models.Variable_Malicious` bypassing pattern `airflow\.models\.Variable`).

### Details
In `task-sdk/src/airflow/sdk/serde/__init__.py` (line 285), the `_match_regexp` function uses `p.match()` instead of `p.fullmatch()`. This allows:
- Pattern `airflow\.models\.Variable` incorrectly matches `airflow.models.Variable_Malicious`
- Malicious tasks can serialize objects with crafted classnames starting with allowed patterns
- When deserialized, allow-list check passes, enabling unintended class instantiation

This is a Type B gap where the security control exists but is incorrectly implemented.

**CWE:** CWE-502  
**ASVS:** 2.2.1, 2.2.2 (L1)

### Remediation
1. Change `_match_regexp` to use `p.fullmatch()` instead of `p.match()`:
```python
@functools.cache
def _match_regexp(classname: str):
    """Check if the given classname matches a pattern from allowed_deserialization_classes_regexp using regexp."""
    patterns = _get_regexp_patterns()
    return any(p.fullmatch(classname) is not None for p in patterns)
```
2. Add documentation noting patterns must match full classname (add `$` anchor if needed)
3. Add warning log when regex pattern doesn't end with `$`
4. Add integration tests verifying allow-list blocks prefix-matching edge cases

### Acceptance Criteria
- [ ] `_match_regexp` changed to use `fullmatch()`
- [ ] Documentation updated for pattern requirements
- [ ] Warning added for patterns without `$` anchor
- [ ] Tests added for prefix-matching bypass scenarios
- [ ] Integration tests verify known-dangerous classnames blocked

### References
- Source: 2.2.1.md, 2.2.2.md
- File: task-sdk/src/airflow/sdk/serde/__init__.py:285

### Priority
**High** - Arbitrary code execution via deserialization bypass

---

## Issue: FINDING-006 - IPC frame reader allocates memory based on untrusted length prefix without maximum size validation
**Labels:** bug, security, priority:high
**Description:**
### Summary
The IPC frame reader reads a 4-byte length prefix from the socket and directly allocates a bytearray without validating against a maximum threshold. A malicious DAG task could send an oversized length prefix causing memory exhaustion in the supervisor process.

### Details
In `task-sdk/src/airflow/sdk/execution_time/comms.py` (line 165), `_read_frame` reads a length prefix and allocates `bytearray(length)` without validation. The length can be up to 2^32 - 1 bytes (4GB). A malicious task writing to the IPC socket (fd 0) can:
- Send crafted frame with oversized length prefix
- Cause supervisor to attempt gigabyte memory allocation
- Trigger OOM kill of supervisor affecting all running tasks

While the sending side enforces 4GiB maximum, the receiving side has no practical upper limit. This is a Type A gap with no control for message size validation on the receiving side.

**CWE:** CWE-770  
**ASVS:** 2.2.1 (L1)

### Remediation
Add maximum message size constant and validate length prefix before allocation:
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
- Add monitoring/metrics for IPC message sizes
- Implement per-message-type size limits (control messages ≤ 1KB, XCom data ≤ configured max)

### Acceptance Criteria
- [ ] MAX_IPC_MSG_SIZE constant added
- [ ] Length validation implemented before allocation
- [ ] ValueError raised for oversized messages
- [ ] Tests added for size limit enforcement
- [ ] Monitoring/metrics added for message sizes

### References
- Source: 2.2.1.md
- File: task-sdk/src/airflow/sdk/execution_time/comms.py:165

### Priority
**High** - Denial of service via memory exhaustion

---

## Issue: FINDING-007 - Systematic lack of URL-encoding for path segments in dynamically constructed API URLs
**Labels:** bug, security, priority:high
**Description:**
### Summary
String parameters (dag_id, run_id, task_id, key, conn_id) are interpolated directly into URL paths via f-string without URL encoding. Special characters alter URL structure, potentially routing requests to unintended endpoints or bypassing authorization rules.

### Details
In `task-sdk/src/airflow/sdk/api/client.py` (lines 280, 320, 340, 355, 365, 382, 400, 425, 445, 458, 480, 490, 508, 512, 516, 555), parameters are inserted into URLs without `urllib.parse.quote()`. This allows:
- Characters like `?` or `#` to inject query parameters or truncate paths
- Path manipulation to access resources outside intended scope if server has different authorization rules for path prefixes
- Legitimate identifiers with special characters (e.g., `section/subsection/key`) to fail by hitting wrong endpoints

This is a Type A gap with no control for output encoding.

**CWE:** CWE-116  
**ASVS:** 1.2.2 (L1)

### Remediation
1. Implement URL path encoding helper function:
```python
def _build_path(*segments: str) -> str:
    return '/'.join(quote(str(seg), safe='') for seg in segments)
```
2. Update all dynamically-constructed URL paths to use helper:
```python
resp = self.client.get(_build_path('xcoms', dag_id, run_id, task_id, key))
```
3. Add input validation for identifiers to reject dangerous characters as defense-in-depth
4. Add integration tests verifying SDK handles identifiers with URL-special characters

### Acceptance Criteria
- [ ] `_build_path()` helper function implemented
- [ ] All dynamic URL constructions updated to use helper
- [ ] Input validation added for identifiers
- [ ] Tests added for special characters in identifiers
- [ ] Integration tests verify correct URL encoding

### References
- Source: 1.2.2.md
- File: task-sdk/src/airflow/sdk/api/client.py (multiple lines)

### Priority
**High** - Path traversal and authorization bypass potential

---

## Issue: FINDING-008 - Supervisor Processes State-Mutating Operations After Terminal State Declaration
**Labels:** bug, security, priority:high
**Description:**
### Summary
The supervisor processes state-mutating operations (SetXCom, PutVariable, DeleteXCom, DeleteVariable, SkipDownstreamTasks) without checking whether the task has already declared a terminal state. This creates data integrity violations and workflow bypasses.

### Details
In `task-sdk/src/airflow/sdk/execution_time/supervisor.py` (lines 1091-1253, 1168-1178, 1179-1180, 1166-1167), the supervisor allows XComs, Variables, and downstream task skipping after task completion (SUCCESS, DEFERRED, etc.). This violates ASVS 2.3.1's requirement that business logic flows must be processed in sequential order without skipping steps.

**ASVS:** 2.3.1 (L1)

### Remediation
Add terminal state guard at the beginning of `_handle_request()`:
1. Check if `self._terminal_state` is set before processing state-mutating operations
2. Reject messages of types SetXCom, DeleteXCom, PutVariable, DeleteVariable, SkipDownstreamTasks, SucceedTask, DeferTask, RescheduleTask, RetryTask, TaskState when `_terminal_state` is already set
3. Log warning and return `ErrorResponse` with error type `API_SERVER_ERROR` indicating task is already in terminal state
4. Allow only read operations (GetConnection, GetVariable, GetXCom) after terminal state

### Acceptance Criteria
- [ ] Terminal state guard added to `_handle_request()`
- [ ] State-mutating operations rejected after terminal state
- [ ] Error response returned with appropriate error type
- [ ] Read operations still allowed after terminal state
- [ ] Tests added for post-terminal-state operation rejection

### References
- Source: 2.3.1.md
- File: task-sdk/src/airflow/sdk/execution_time/supervisor.py (multiple lines)

### Priority
**High** - Data integrity and workflow bypass

---

## Issue: FINDING-009 - Terminal State Can Be Overwritten by Subsequent State Transition Messages
**Labels:** bug, security, priority:high
**Description:**
### Summary
The supervisor allows `_terminal_state` to be overwritten by subsequent state transition messages, creating state machine integrity violations where supervisor's internal state can diverge from API server's state.

### Details
In `task-sdk/src/airflow/sdk/execution_time/supervisor.py` (lines 1091-1253, 1101-1110, 1158-1161, 1163-1165), a task can send DeferTask followed by SucceedTask, overwriting `_terminal_state` from DEFERRED to SUCCESS. The `final_state` property returns the last `_terminal_state` set, which may not reflect actual server state if the server rejected the second transition. This leads to:
- Inconsistent behavior
- Heartbeat suppression issues
- Observability problems

**ASVS:** 2.3.1 (L1)

### Remediation
Add single-write enforcement for `_terminal_state`:
1. Check if `self._terminal_state` is not None before setting it in each state-transition branch (SucceedTask, DeferTask, RescheduleTask, RetryTask)
2. If already set, log warning with current_state, requested_state, and ti_id
3. Send `ErrorResponse` with error type `API_SERVER_ERROR` indicating terminal state already set
4. Return early without processing duplicate transition

### Acceptance Criteria
- [ ] Single-write enforcement added to all state-transition branches
- [ ] Warning logged for duplicate terminal state attempts
- [ ] Error response sent for duplicate transitions
- [ ] Tests added for duplicate terminal state prevention
- [ ] State machine integrity verified in tests

### References
- Source: 2.3.1.md
- File: task-sdk/src/airflow/sdk/execution_time/supervisor.py (multiple lines)

### Priority
**High** - State machine integrity violation

---

## Issue: FINDING-010 - Expired cache entries containing secrets are never removed from memory
**Labels:** bug, security, priority:high
**Description:**
### Summary
No session/process termination hook exists to clear cached secrets. Secrets cached during task execution persist after task completes with no cleanup, allowing next task or memory inspector to observe residual data.

### Details
In `task-sdk/src/airflow/sdk/execution_time/cache.py` (lines 100-111), the only cleanup method (`reset()`) is marked for test use only and sets reference to None without clearing the underlying Manager dict. Secrets persist in Manager process memory after:
- Task execution completes
- Session JWT expires
- API server becomes unreachable
- Administrator triggers cache purge

This violates ASVS 14.3.1's requirement that authenticated data is cleared from client storage after session termination.

**CWE:** CWE-459  
**ASVS:** 14.3.1 (L1)

### Remediation
1. Add active deletion of expired entries in `_get()` method: when `is_expired()` returns True, call `cls._cache.pop(cache_key, None)` before raising `NotPresentException`
2. Implement `clear_expired()` classmethod to remove all expired entries
3. Implement `clear_all()` classmethod to clear all cached secrets on session termination
4. Add periodic cache sweep (e.g., every TTL/2 seconds) to proactively remove all expired entries

### Acceptance Criteria
- [ ] Active deletion added to `_get()` method for expired entries
- [ ] `clear_expired()` classmethod implemented
- [ ] `clear_all()` classmethod implemented
- [ ] Periodic cache sweep added
- [ ] Session termination hook integrated
- [ ] Tests added for cache cleanup mechanisms

### References
- Source: 14.3.1.md
- File: task-sdk/src/airflow/sdk/execution_time/cache.py:100-111

### Priority
**High** - Secrets persistence in memory after session termination

---

## Issue: FINDING-011 - Missing path traversal validation on `dag_rel_path` in DAG loading allows potential code execution outside bundle boundary
**Labels:** bug, security, priority:high
**Description:**
### Summary
The `parse()` function constructs an absolute path by joining `bundle_instance.path` with `what.dag_rel_path` without validating the resolved path remains within the bundle boundary. This allows arbitrary Python code execution outside the intended bundle directory.

### Details
In `task-sdk/src/airflow/sdk/execution_time/task_runner.py` (line 1105), the path is constructed without normalization, symlink resolution, or containment check. The `dag_rel_path` originates from the API server database and could be influenced by an attacker. No validation is performed before passing the path to `BundleDagBag`, which loads and executes the Python file.

**CWE:** CWE-22  
**ASVS:** 5.3.2 (L1)

### Remediation
Resolve and validate the constructed path:
```python
dag_absolute_path = Path(bundle_instance.path, what.dag_rel_path).resolve()
bundle_root = bundle_instance.path.resolve()
try:
    dag_absolute_path.relative_to(bundle_root)
except ValueError:
    log.error("Path traversal attempt detected: %s", what.dag_rel_path)
    sys.exit(1)
```

### Acceptance Criteria
- [ ] Path resolution with `.resolve()` implemented
- [ ] Containment validation with `.relative_to()` added
- [ ] Error handling for validation failures
- [ ] Tests added for path traversal attempts
- [ ] Tests verify legitimate relative paths still work

### References
- Source: 5.3.2.md
- File: task-sdk/src/airflow/sdk/execution_time/task_runner.py:1105

### Priority
**High** - Arbitrary code execution outside bundle boundary

---

## Issue: FINDING-012 - `init_log_file` accepts unsanitized relative path enabling directory traversal for file creation
**Labels:** bug, security, priority:high
**Description:**
### Summary
The `init_log_file()` function accepts a `local_relative_path` constructed from user-defined identifiers without path traversal validation. An attacker controlling these identifiers could create files and directories outside the intended `base_log_folder`.

### Details
In `task-sdk/src/airflow/sdk/log.py` (line 113), `local_relative_path` is constructed from `dag_id`, `task_id`, `run_id`, `try_number` stored in the database. This path is passed directly to the underlying implementation without normalization or containment checks. A malicious `dag_id` containing `../../` could:
- Create files/directories outside `base_log_folder` with permissions 0o775 (directories) and 0o664 (files)
- Overwrite sensitive system files
- Affect other tenants in multi-tenant deployments

**CWE:** CWE-22  
**ASVS:** 5.3.2 (L1)

### Remediation
Validate path containment before calling underlying `init_log_file`:
```python
full_path = Path(base_log_folder, local_relative_path).resolve()
base_folder_resolved = Path(base_log_folder).resolve()
try:
    full_path.relative_to(base_folder_resolved)
except ValueError:
    raise ValueError(f"Path traversal detected in log path: {local_relative_path}")
```

### Acceptance Criteria
- [ ] Path resolution and validation added
- [ ] ValueError raised for path traversal attempts
- [ ] Tests added for traversal attempts with `../`
- [ ] Tests verify legitimate paths still work
- [ ] Multi-tenant isolation verified

### References
- Source: 5.3.2.md
- File: task-sdk/src/airflow/sdk/log.py:113

### Priority
**High** - Directory traversal enabling file creation outside intended directory

---

## Issue: FINDING-013 - No explicit TLS minimum version enforcement — TLS 1.0/1.1 may be negotiated
**Labels:** bug, security, priority:high
**Description:**
### Summary
The SSL context uses `ssl.create_default_context()` without explicitly setting `minimum_version` or `maximum_version`. On systems with Python 3.9 and OpenSSL 1.1.1, TLS 1.0 and TLS 1.1 connections may be accepted, enabling protocol downgrade attacks.

### Details
In `task-sdk/src/airflow/sdk/api/client.py` (lines 816-820, 821-865), `_get_ssl_context_cached()` creates an SSL context without explicit version enforcement. On enterprise systems with older OpenSSL, TLS 1.0/1.1 may be negotiated. This enables:
- Protocol downgrade attacks
- Weak cipher suites (RC4, CBC mode with predictable IV)
- Cryptographic weaknesses in deprecated protocols

**ASVS:** 12.1.1 (L1)

### Remediation
Add explicit TLS version enforcement to `_get_ssl_context_cached()`:
```python
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.maximum_version = ssl.TLSVersion.TLSv1_3
ctx.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS:!RC4:!3DES')
```

Additional recommendations:
- Add OCSP stapling support
- Log TLS negotiation details at debug level
- Add startup validation of SSL context configuration
- Implement integration tests verifying TLS version enforcement

### Acceptance Criteria
- [ ] TLS 1.2 minimum version enforced
- [ ] TLS 1.3 maximum version set
- [ ] Strong cipher suite configuration added
- [ ] Tests added for TLS version enforcement
- [ ] Integration tests verify TLS 1.0/1.1 rejection

### References
- Source: 12.1.1.md
- File: task-sdk/src/airflow/sdk/api/client.py:816-820,821-865

### Priority
**High** - Protocol downgrade attack enabling weak cryptography

---

## Issue: FINDING-014 - Authentication failure (401/403) during heartbeat not treated as immediate session invalidation
**Labels:** bug, security, priority:high
**Description:**
### Summary
When the server revokes a task execution token, the supervisor's heartbeat receives 401/403 but treats these as transient failures. The task continues executing for up to 150+ seconds (5 heartbeat cycles × 30s interval) after authorization revocation.

### Details
In `task-sdk/src/airflow/sdk/execution_time/supervisor.py` (lines 780-815), authentication failures during heartbeat are not treated as immediate session invalidation. While 404/410/409 status codes trigger immediate termination, 401/403 authentication failures are treated as transient errors. During the 150-second window:
- Task executes arbitrary code with stale/missing data
- Actions complete that should have been halted
- Resources consumed after authorization revocation

This violates ASVS 7.4.1 and 7.4.2's requirement that session termination disallows further use.

**ASVS:** 7.4.1, 7.4.2 (L1)

### Remediation
Add HTTPStatus.UNAUTHORIZED (401) and HTTPStatus.FORBIDDEN (403) to the list of status codes triggering immediate process termination in `_send_heartbeat_if_needed()`:
1. Treat authentication failures same as NOT_FOUND, GONE, and CONFLICT
2. Trigger immediate SIGTERM with `force=True`
3. Set `_terminal_state` to `SERVER_TERMINATED`
4. Include error logging indicating session termination due to authentication failure

### Acceptance Criteria
- [ ] 401/403 added to immediate termination status codes
- [ ] SIGTERM triggered with force=True for auth failures
- [ ] `_terminal_state` set to SERVER_TERMINATED
- [ ] Error logging added for auth failure termination
- [ ] Tests added for 401/403 immediate termination
- [ ] 150-second window eliminated

### References
- Source: 7.4.1.md, 7.4.2.md
- File: task-sdk/src/airflow/sdk/execution_time/supervisor.py:780-815

### Priority
**High** - 150-second window after token revocation

---

## Issue: FINDING-015 - API request authentication failures in request handler do not trigger session termination
**Labels:** bug, security, priority:high
**Description:**
### Summary
When a task makes API requests and the server returns 401/403 due to token revocation, the supervisor logs the error and sends an error response but does not terminate the session. The task can continue executing indefinitely after session token invalidation.

### Details
In `task-sdk/src/airflow/sdk/execution_time/supervisor.py` (lines 510-545), authentication failures during API requests (connections, variables, XCom) do not trigger session termination. A task that doesn't frequently call the API could run for the full heartbeat timeout period (150+ seconds) while unauthorized. This creates inconsistency where token revocation discovered through API requests (rather than heartbeat) does not result in immediate termination.

**ASVS:** 7.4.1, 7.4.2 (L1)

### Remediation
In the `handle_requests()` method's `ServerResponseError` exception handler:
1. Add check for authentication failure status codes (401, 403)
2. When detected, immediately terminate task process using `kill(signal.SIGTERM, force=True)`
3. Set `_terminal_state` to `SERVER_TERMINATED`
4. Log the session termination
5. Return to stop processing further requests

### Acceptance Criteria
- [ ] Authentication failure check added to exception handler
- [ ] Immediate SIGTERM triggered for 401/403 during API requests
- [ ] `_terminal_state` set to SERVER_TERMINATED
- [ ] Session termination logged
- [ ] Tests added for API request auth failure termination
- [ ] Consistent behavior with heartbeat auth failures

### References
- Source: 7.4.1.md, 7.4.2.md
- File: task-sdk/src/airflow/sdk/execution_time/supervisor.py:510-545

### Priority
**High** - Continued execution after session invalidation

---

## Issue: FINDING-016 - Authorization Denial Indistinguishable from Not-Found in Secrets Backend Enables Potential Fallback Bypass
**Labels:** bug, security, priority:high
**Description:**
### Summary
The ExecutionAPISecretsBackend returns None for both authorization denials and genuine not-found cases, enabling fallback to less-restrictive backends. In multi-tenant deployments, tasks can access secrets their DAG is not authorized to use if those secrets exist in fallback backends.

### Details
In `task-sdk/src/airflow/sdk/execution_time/secrets/execution_api.py` (lines 47, 73, 96, 117), the data flow:
1. Task requests unauthorized secret
2. Server denies access (403)
3. Supervisor sends ErrorResponse
4. SDK returns None (indistinguishable from not-found)
5. Airflow secrets chain tries next backend
6. Fallback backend provides secret without DAG-level authorization

This is a Type C gap where the control is called (server-side authorization) but the result is ignored (denial treated identically to not-found).

**CWE:** CWE-639  
**ASVS:** 8.2.2 (L1)

### Remediation
1. Distinguish between not-found and access-denied responses
2. Raise exception (not return None) when authorization is explicitly denied
3. Implement `AuthorizationDeniedError` exception class
4. Modify `get_connection()` and `get_variable()` to:
   - Check if ErrorResponse indicates `CONNECTION_NOT_FOUND` (allow fallback by returning None)
   - Check for access denied errors (raise `AuthorizationDeniedError` to prevent fallback)
5. Extend ErrorType enum to include `CONNECTION_ACCESS_DENIED` and `VARIABLE_ACCESS_DENIED` distinct from `CONNECTION_NOT_FOUND` and `VARIABLE_NOT_FOUND`
6. Only allow fallback on genuine communication failures, not authorization failures

### Acceptance Criteria
- [ ] `AuthorizationDeniedError` exception class implemented
- [ ] ErrorType enum extended with access denied types
- [ ] `get_connection()` and `get_variable()` distinguish not-found from access-denied
- [ ] Exception raised for authorization denials
- [ ] Tests added for authorization denial handling
- [ ] Multi-tenant isolation verified
- [ ] Fallback only occurs for communication failures

### References
- Source: 8.2.2.md
- File: task-sdk/src/airflow/sdk/execution_time/secrets/execution_api.py:47,73,96,117

### Priority
**High** - Multi-tenant authorization bypass via fallback