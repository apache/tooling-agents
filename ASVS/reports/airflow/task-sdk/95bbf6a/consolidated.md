# Security Audit Consolidated Report

## apache/tooling-runbooks

---

## Report Metadata

| Field | Value |
|-------|-------|
| **Repository** | `apache/tooling-runbooks` |
| **ASVS Level** | L3 |
| **Severity Threshold** | None (all findings included) |
| **Commit** | N/A |
| **Date** | May 07, 2026 |
| **Auditor** | Tooling Agents |
| **Source Reports** | 345 |
| **Total Findings** | 123 |

---

## Executive Summary

### Severity Distribution

| Severity | Count | Percentage |
|----------|------:|----------:|
| Critical | 0 | 0.0% |
| High | 7 | 5.7% |
| Medium | 49 | 39.8% |
| Low | 66 | 53.7% |
| Informational | 1 | 0.8% |

No critical-severity findings were identified. The seven high-severity findings concentrate in three domains: **Jinja template injection** (sandbox bypass), **cryptographic design** (algorithm rigidity), and **IPC/execution lifecycle resilience** (crash paths, fail-open conditions, and silent exception suppression). The bulk of findings (Medium and Low) reflect defense-in-depth gaps, missing documentation artefacts required at ASVS L3, and resource-management concerns that could facilitate denial-of-service under adversarial conditions.

### ASVS Level Coverage

| Level | Findings Mapped | Notes |
|-------|----------------:|-------|
| L1 | 18 | Baseline input validation, transport security, and access control gaps |
| L2 | 89 | Majority of findings — sandbox hardening, logging architecture, crypto lifecycle, rate limiting |
| L3 | 42 | Documentation inventory requirements, race conditions, memory protection, crypto agility |

> *Note: Findings may map to multiple levels. Totals exceed 123 due to multi-level tagging.*

### Top 5 Risks

| # | Finding | Severity | Risk Summary |
|---|---------|----------|--------------|
| 1 | **FINDING-001** — NativeEnvironment bypasses Jinja2 sandbox | High | DAG authors or compromised DAG code executing arbitrary Python via `NativeEnvironment`, completely circumventing sandboxing controls intended to restrict template evaluation. |
| 2 | **FINDING-002** — No crypto agility; Fernet hardcoded | High | The encryption subsystem is permanently bound to AES-128-CBC + HMAC-SHA256 (Fernet). Algorithm compromise or regulatory mandate for AES-256/GCM requires invasive refactoring with data migration risk. |
| 3 | **FINDING-003** — Bearer token sent over HTTP if `base_url` misconfigured | High | Absence of HTTPS enforcement at the client layer means a single configuration error exposes authentication tokens in cleartext, enabling credential interception on untrusted networks. |
| 4 | **FINDING-005 / FINDING-006** — Unhandled exceptions crash IPC; fail-open on terminal state delivery | High | Network or deserialization failures propagate as unhandled exceptions in the supervisor communication loop, crashing the IPC channel. Combined with the fail-open condition in FINDING-006, task processes may silently assume success despite the API server never acknowledging state transitions. |
| 5 | **FINDING-018** — Silent fallback to `_NullFernet` when key missing | Medium | When the Fernet encryption key is absent from configuration, the system silently degrades to a no-op cipher that stores secrets in plaintext. No warning is surfaced to operators, violating the principle of secure-by-default. |

### Positive Controls Observed

The audit identified substantial security-positive architectural patterns that materially reduce exploitability across multiple threat categories:

| Domain | Control | Significance |
|--------|---------|--------------|
| **IPC Message Handling** | Single msgpack decode → Pydantic discriminated-union validation pipeline | Eliminates double-deserialization vulnerabilities and ensures type-safe message dispatch before business logic executes. |
| **IPC Message Handling** | `block_orm_access()` prevents direct DB queries from task code | Enforces process-level isolation boundary; task code cannot bypass the API to access the metadata database. |
| **Jinja Template Injection** | `SandboxedEnvironment` used by default when no DAG context is present; `StrictUndefined` prevents silent variable expansion | Provides baseline SSTI protection and fail-loud behaviour for template errors. |
| **Secrets Masking** | Dual-process masking architecture with IPC propagation; pipeline ordering guarantees masking before any output handler | Secrets registered in both task and supervisor processes ensure consistent redaction regardless of log routing path. Immutable `@cache` pipeline prevents runtime tampering. |
| **Secrets Backend Access** | TTL-based cache expiration; server-side authorization via JWT; no hardcoded credentials in source | Limits temporal exposure window for cached secrets, delegates access control to centralized enforcement, and eliminates static credential risk. |

Additional noteworthy controls include frame-size limits on IPC send paths (4 GiB cap), `Path.relative_to()` containment for log upload paths, HTML escaping of exception content in email notifications, and consistent use of `import_module()` + `getattr()` instead of `eval()`/`exec()` for dynamic dispatch.

---

## 3. Findings

### 3.2 High

#### FINDING-001: NativeEnvironment completely bypasses Jinja2 sandbox protections

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-1336 |
| **ASVS Sections** | 1.3.5, 1.3.7 |
| **Files** | task-sdk/src/airflow/sdk/definitions/_internal/templater.py:337, task-sdk/src/airflow/sdk/definitions/_internal/templater.py:400, task-sdk/src/airflow/sdk/definitions/_internal/templater.py:328-334 |
| **Source Reports** | 1.3.5.md, 1.3.7.md |
| **Related** | FINDING-013 |

**Description:**

The NativeEnvironment class inherits from jinja2.nativetypes.NativeEnvironment instead of jinja2.sandbox.SandboxedEnvironment, completely bypassing sandbox protections when native rendering is enabled (render_template_as_native_obj = True). The is_safe_attribute() method defined in _AirflowEnvironmentMixin becomes dead code as NativeEnvironment never calls sandbox hook methods. This allows templates to access dangerous Python internals, filesystem, and network without any interception when native=True. The dual environment architecture creates security asymmetry where a single configuration flag disables all template sandboxing, creating a trapdoor in the security architecture. The _AirflowEnvironmentMixin provides false confidence as is_safe_attribute() is never invoked by the Jinja2 native evaluation machinery.

**Remediation:**

Create a SandboxedNativeEnvironment that combines sandbox protection with native type rendering:

```python
class SandboxedNativeEnvironment(
    _AirflowEnvironmentMixin,
    jinja2.sandbox.SandboxedEnvironment
):
    """Sandboxed environment with native type rendering."""
    code_generator_class = jinja2.nativetypes.NativeCodeGenerator  
    concat = staticmethod(jinja2.nativetypes.native_concat)
```

Then in create_template_env:
```python
env = SandboxedNativeEnvironment(**jinja_env_options) if native else SandboxedEnvironment(**jinja_env_options)
```

Replace all NativeEnvironment usage with this secure alternative to provide native type rendering WITH sandbox protections.

---

#### FINDING-002: No crypto agility - encryption algorithm hardcoded to Fernet (AES-128-CBC + HMAC-SHA256) with no mechanism to swap algorithms

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | N/A |
| **ASVS Sections** | 11.2.2, 11.1.4 |
| **Files** | task-sdk/src/airflow/sdk/crypto.py:entire file |
| **Source Reports** | 11.2.2.md, 11.1.4.md |
| **Related** | None |

**Description:**

The codebase uses specific cryptographic algorithms without a documented inventory or migration path: 1) Fernet (AES-128-CBC + HMAC-SHA256) is used for encrypting connection credentials, variable values, and serializer storage options with no documentation of migration path to AES-256 or PQC alternatives. 2) TLS (system defaults) via ssl.create_default_context() in client.py with no explicit cipher suite documentation or PQC hybrid key exchange plan. 3) No version/algorithm metadata in encrypted data - Fernet has its own versioning (0x80 byte), but there's no application-level metadata to facilitate bulk re-encryption during migration. When AES-128 or HMAC-SHA256 need to be upgraded (e.g., for PQC compliance or regulatory requirements), there is no documented plan for migrating existing encrypted data, leading to potential data loss or prolonged exposure to deprecated algorithms.

**Remediation:**

Implement a crypto-agile architecture with a configurable encryption backend. Create an abstract EncryptionBackend class with encrypt, decrypt, rotate methods and algorithm_id property. Implement FernetBackend as the current implementation and prepare for future backends like AESGCMBackend. Create a factory function get_encryption_backend() that reads algorithm choice from configuration and instantiates the appropriate backend. Example implementation provided shows abstract base class, concrete Fernet implementation, future AES-256-GCM backend placeholder, and factory pattern reading from configuration.

---

#### FINDING-003: No enforcement that base_url uses HTTPS — bearer token sent in cleartext over HTTP if misconfigured

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1, L2 |
| **CWE** | CWE-319 |
| **ASVS Sections** | 12.2.1, 12.3.3 |
| **Files** | task-sdk/src/airflow/sdk/api/client.py:739-753, task-sdk/src/airflow/sdk/api/client.py:580-600 |
| **Source Reports** | 12.2.1.md, 12.3.3.md |
| **Related** | None |

**Description:**

The Client accepts base_url without validating that it uses the HTTPS scheme. If an operator misconfigures the Execution API URL to use http:// instead of https://, the bearer token and all API traffic (including connection passwords, variable values, and XCom data) would be transmitted in cleartext. The SSL context and verify parameter only apply to HTTPS connections — they do NOT prevent HTTP connections. This creates a silent security failure where the system appears to work correctly but has no transport security. Configuration flow: http://airflow-server:8080 → base_url → httpx makes HTTP requests → BearerAuth adds Authorization: Bearer &lt;token&gt; to cleartext request.

**Remediation:**

Add URL scheme validation in Client.__init__() to reject non-HTTPS base URLs. Parse the base_url using urlparse and raise ValueError if the scheme is not 'https'. Example:

```python
from urllib.parse import urlparse
parsed = urlparse(base_url)
if parsed.scheme != "https":
    raise ValueError(f"Execution API base_url must use HTTPS to protect bearer tokens. Got: {base_url!r}. Set [api] execution_api_url to an https:// URL.")
```

---

#### FINDING-004: Silent Exception Suppression in Remote Log Upload

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 16.3.4, 16.4.3 |
| **Files** | task-sdk/src/airflow/sdk/log.py:210-211 |
| **Source Reports** | 16.3.4.md, 16.4.3.md |
| **Related** | None |

**Description:**

If the remote log handler cannot be loaded or the path resolution fails, the function silently returns. There is no feedback mechanism to indicate that logs failed to reach the separate system. Combined with the fact that `handler.upload()` exceptions are not caught here (they'd propagate to callers who may or may not handle them), there's inconsistent error handling for log transmission. If remote log transmission consistently fails (due to network issues, TLS failures, or misconfiguration), the application continues operating without awareness that logs are only stored locally — defeating the purpose of separate system storage.

**Remediation:**

Add structured logging for all failure paths in upload_to_remote(). Log warnings when remote_log_handler is unavailable, errors when path resolution fails, warnings when path is empty, and errors when upload fails. Example implementation:

```python
def upload_to_remote(logger: FilteringBoundLogger, ti: RuntimeTI):
    raw_logger = getattr(logger, "_logger")
    log = structlog.get_logger("airflow.logging.remote")

    handler = load_remote_log_handler()
    if not handler:
        log.warning("remote_log_handler_unavailable", task_instance=str(ti))
        return

    try:
        relative_path = relative_path_from_logger(raw_logger)
    except Exception as e:
        log.error("remote_log_path_resolution_failed", error=str(e))
        return
    if not relative_path:
        log.warning("remote_log_path_empty", task_instance=str(ti))
        return

    try:
        log_relative_path = relative_path.as_posix()
        handler.upload(log_relative_path, ti)
    except Exception as e:
        log.error("remote_log_upload_failed", error_type=type(e).__name__, path=log_relative_path)
```

---

#### FINDING-005: Unhandled Network Exceptions Crash IPC Communication Channel

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 16.5.2 |
| **Files** | task-sdk/src/airflow/sdk/execution_time/supervisor.py:415-450 |
| **Source Reports** | 16.5.2.md |
| **Related** | None |

**Description:**

External API call (e.g., self.client.connections.get()) raises httpx.ConnectError/httpx.TimeoutException which is NOT caught by except ServerResponseError, propagates out of generator, terminates generator, breaks IPC channel. When the API server becomes temporarily unreachable (network partition, DNS failure, or server restart), any request from the task runner that triggers an API call would raise a network-level exception. Since only ServerResponseError is caught, the generator crashes, the request handler socket is closed, the task runner gets EOFError on next communication attempt, and the entire IPC channel is permanently broken.

**Remediation:**

Add catch-all exception handler to handle_requests generator. Wrap _handle_request() call with except Exception to prevent generator crashes on non-ServerResponseError exceptions. Always send an error response back to the task. Catch ALL exceptions to prevent generator crash and log unexpected errors while sending generic error response to task.

---

#### FINDING-006: Fail-open Condition When Terminal State Delivery Fails

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 16.5.3 |
| **Files** | task-sdk/src/airflow/sdk/execution_time/task_runner.py:finally block in run(), task-sdk/src/airflow/sdk/execution_time/supervisor.py:final_state property |
| **Source Reports** | 16.5.3.md |
| **Related** | None |

**Description:**

A failed task is incorrectly marked as successful when IPC communication fails during terminal state reporting. Task execution fails and sets state to FAILED, but when SUPERVISOR_COMMS.send(msg=msg) raises an exception in the finally block, the exception is caught and logged without preventing normal exit. The process exits with code 0, causing the supervisor to interpret _exit_code == 0 with _terminal_state is None as SUCCESS. This creates a fail-open condition where corrupted data pipelines continue processing downstream tasks based on incorrect upstream success.

**Remediation:**

Exit with non-zero code when terminal state delivery fails. In the finally block of task_runner.py:run(), after catching the exception from SUPERVISOR_COMMS.send(), call sys.exit(1) to signal failure to supervisor via exit code. This ensures the supervisor doesn't incorrectly mark the task as SUCCESS when the terminal state message cannot be delivered.

---

#### FINDING-007: Terminal State Set Locally Before API Call With No Recovery on Failure

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 2.3.3 |
| **Files** | task-sdk/src/airflow/sdk/execution_time/supervisor.py:517-590 |
| **Source Reports** | 2.3.3.md |
| **Related** | None |

**Description:**

Task process sends SucceedTask → _terminal_state set to SUCCESS → client.task_instances.succeed() fails (network error) → ServerResponseError caught → error sent to task → task exits with 0 → final_state returns SUCCESS → update_task_state_if_needed() sees SUCCESS in STATES_SENT_DIRECTLY → NO retry → Task stuck as RUNNING on server forever. During transient network failures or API server restarts, completed tasks can become permanently stuck in RUNNING state, requiring manual intervention to resolve. This affects all terminal states in STATES_SENT_DIRECTLY (SUCCESS, DEFERRED, UP_FOR_RESCHEDULE, UP_FOR_RETRY). Tasks stuck in RUNNING will also block downstream dependencies and may trigger false alerts. The same pattern applies to DeferTask and RescheduleTask handlers.

**Remediation:**

Set _terminal_state only after the API call succeeds, or implement retry-on-failure for terminal state reporting. Attempt the API call FIRST, catch ServerResponseError without setting _terminal_state to allow update_task_state_if_needed() to retry, and only mark as sent after successful API call. Alternative: Add a flag _state_reported_to_server and check it in update_task_state_if_needed() to always try to report regardless of STATES_SENT_DIRECTLY when the previous send failed.

### 3.3 Medium

#### FINDING-008: Unbounded message length allocation on supervisor receive path allows memory exhaustion DoS

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L1 |
| **CWE** | CWE-770 |
| **ASVS Sections** | 1.3.3, 2.2.2, 15.2.2 |
| **Files** | task-sdk/src/airflow/sdk/execution_time/supervisor.py:1700-1738, task-sdk/src/airflow/sdk/execution_time/comms.py:236-269 |
| **Source Reports** | 1.3.3.md, 2.2.2.md, 15.2.2.md |
| **Related** | FINDING-010 |

**Description:**

The supervisor process reads a 4-byte length prefix from untrusted task processes and allocates a buffer of that size without any upper bound check. A malicious task process can craft raw bytes to request allocation of up to 4GB (2^32 - 1 bytes) of memory, causing OOM conditions that could crash the supervisor and affect all concurrent tasks. The sending side has a 4GiB overflow check in `_FrameMixin.as_bytes()`, but this check doesn't exist on the receive side where an attacker can craft raw bytes. The supervisor manages potentially many task subprocesses and can be crashed via an out-of-memory condition triggered by a single malicious task, violating the stated trust boundary that treats task code as untrusted.

**Remediation:**

Implement a MAX_MESSAGE_SIZE constant (e.g., 64 MiB) and validate the length prefix before allocating the buffer. Example code: `MAX_MESSAGE_SIZE = 64 * 1024 * 1024; if length_needed > MAX_MESSAGE_SIZE: log.error("Message too large, rejecting", size=length_needed, max=MAX_MESSAGE_SIZE); return False`. Apply this check in both `length_prefixed_frame_reader` and `CommsDecoder._read_frame`.

---

#### FINDING-009: Validation failure in handle_requests does not send error response to task process

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-755 |
| **ASVS Sections** | 2.2.1 |
| **Files** | task-sdk/src/airflow/sdk/execution_time/supervisor.py:637-669 |
| **Source Reports** | 2.2.1.md |
| **Related** | |

**Description:**

The documented protocol guarantees 'Every request returns a response, even if the frame is otherwise empty.' When validation fails in the handle_requests method, no response is sent. This causes the task process to block indefinitely on recv(), consuming a worker slot. While the supervisor will eventually kill the task via heartbeat timeout, this takes HEARTBEAT_TIMEOUT seconds (default: much longer than needed for a simple error response). Data flow: Task process sends request → supervisor receives frame → validation fails → supervisor logs error and continues → task process blocks forever waiting for response. This is a Type C gap - validation is CALLED but the RESULT (error) is not COMMUNICATED back to the caller.

**Remediation:**

Send an error response when validation fails instead of continuing silently. Modify the exception handler to call self.send_msg() with an ErrorResponse containing ErrorType.GENERIC_ERROR and appropriate detail message, ensuring the task process receives a response and can handle the error gracefully rather than hanging indefinitely.

---

#### FINDING-010: Unbounded string fields in IPC messages used for HTTP request construction

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1, L3 |
| **CWE** | CWE-770 |
| **ASVS Sections** | 2.2.1, 2.2.2, 4.2.5, 2.1.1 |
| **Files** | task-sdk/src/airflow/sdk/execution_time/comms.py, task-sdk/src/airflow/sdk/execution_time/supervisor.py:1142-1379 |
| **Source Reports** | 2.2.1.md, 2.2.2.md, 4.2.5.md, 2.1.1.md |
| **Related** | FINDING-008 |

**Description:**

The supervisor builds HTTP requests using string values from untrusted task messages without validating their length. Untrusted task processes send IPC messages with unbounded string fields (dag_id, task_id, key, name, uri, conn_id, etc.) that are validated for type by Pydantic but not for length. The supervisor then constructs HTTP requests to the API server using these unbounded strings in URL/query parameters, potentially causing 414 URI Too Long or 431 Request Header Fields Too Large errors. This could waste supervisor resources, cause persistent error responses for DOS attacks on the supervisor's API communication, and generate excessive error logging. An untrusted task process could send extremely long string values that pass type validation but would be forwarded to HTTP API calls.

**Remediation:**

Add Field(max_length=...) constraints to Pydantic models in comms.py for fields like dag_id, task_id, key, etc. Align these constraints with those enforced by the API server. Example: key: str = Field(max_length=512), dag_id: str = Field(max_length=250), run_id: str = Field(max_length=250), task_id: str = Field(max_length=250), value: str | None = Field(max_length=65536), description: str | None = Field(max_length=5000).

---

#### FINDING-011: Relaxed is_safe_attribute allows access to private (_-prefixed) attributes on context objects

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-668 |
| **ASVS Sections** | 1.3.5 |
| **Files** | task-sdk/src/airflow/sdk/definitions/_internal/templater.py:328 |
| **Source Reports** | 1.3.5.md |
| **Related** | |

**Description:**

The custom is_safe_attribute override only blocks __ prefixed attributes via is_internal_attribute, but allows access to all _ prefixed private attributes. This weakens Jinja2's default SandboxedEnvironment behavior which blocks both _ and __ prefixed attributes. Templates can access internal implementation attributes of objects in the rendering context, potentially exposing sensitive data like connection credentials or internal state.

**Remediation:**

Define an allowlist of specific _-prefixed attributes that templates legitimately need, rather than blanket-allowing all _ attributes:

```python
_ALLOWED_PRIVATE_ATTRS = frozenset({"_key", "_defer", ...})  # Document legitimate needs

def is_safe_attribute(self, obj, attr, value):
    if attr.startswith("_"):
        return attr in _ALLOWED_PRIVATE_ATTRS
    return not jinja2.sandbox.is_internal_attribute(obj, attr)
```

---

#### FINDING-012: jinja_environment_kwargs allows overriding security-critical environment settings without validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-15 |
| **ASVS Sections** | 1.3.5 |
| **Files** | task-sdk/src/airflow/sdk/definitions/_internal/templater.py:393 |
| **Source Reports** | 1.3.5.md |
| **Related** | |

**Description:**

The jinja_environment_kwargs parameter allows DAG authors to unconditionally override all previously set Jinja2 environment options via .update() without any validation. Security-relevant settings like loader, extensions, or undefined can be replaced, allowing DAG authors to override the FileSystemLoader searchpath to read arbitrary files, add unsafe extensions like jinja2.ext.debug that expose the template context, or change undefined variable behavior.

**Remediation:**

Validate jinja_environment_kwargs against a blocklist of security-sensitive keys:

```python
_BLOCKED_ENV_KWARGS = frozenset({"loader", "enable_async"})

if jinja_environment_kwargs:
    blocked = set(jinja_environment_kwargs) & _BLOCKED_ENV_KWARGS
    if blocked:
        raise ValueError(f"Cannot override security-sensitive env options: {blocked}")
    jinja_env_options.update(jinja_environment_kwargs)
```

---

#### FINDING-013: from_string() compiles any string value as a Jinja template without content validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-1336 |
| **ASVS Sections** | 1.3.7 |
| **Files** | task-sdk/src/airflow/sdk/definitions/_internal/templater.py:209-213 |
| **Source Reports** | 1.3.7.md |
| **Related** | FINDING-001 |

**Description:**

The render_template method compiles any string in template_fields attributes as a Jinja template using from_string() without validating whether the string contains template syntax or sanitizing template constructs. If template field values are influenced by untrusted input (through Airflow Variables, XCom, trigger parameters, etc.), the string is compiled as a template. In sandboxed mode damage is limited, but in native mode this enables full code execution.

**Remediation:**

Add an opt-in mechanism to mark fields as 'template-safe' vs 'literal-only'. Implement _should_template_field() method to determine if a field should be templated. Add template content validation before from_string() to verify that template content matches expected patterns and does not contain dangerous constructs like dunder traversal. Provide a decorator/annotation for fields that should not be templated even if they contain template syntax.

---

#### FINDING-014: No Data Classification-Based Logging Enforcement — All Secrets Masked Identically

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | |
| **ASVS Sections** | 16.2.5, 16.3.3, 16.3.4 |
| **Files** | task-sdk/src/airflow/sdk/log.py:58-60, task-sdk/src/airflow/sdk/log.py:231 |
| **Source Reports** | 16.2.5.md, 16.3.3.md, 16.3.4.md |
| **Related** | |

**Description:**

The ASVS requirement specifies that logging should be enforced based on the data's protection level — for example, credentials "may not be allowed to log" at all, while session tokens "may only be logged by being hashed or masked, either in full or partially." The current implementation applies a single binary control: redact() performs uniform string replacement on all registered secrets without distinguishing between protection levels. There is no mechanism to: (1) Completely suppress log records containing credential-class data (vs. just masking the value), (2) Hash session tokens instead of masking them (allowing correlation without exposure), (3) Partially mask lower-sensitivity data (e.g., showing last 4 characters of an API key), (4) Enforce different retention policies based on whether masked data was credentials vs. metadata. The mask_secret() function (line 231) accepts a name parameter but this is only used for pattern identification, not for specifying a protection level. All sensitive data types (credentials, payment details, session tokens, PII) are treated identically in logs. This means credentials that should never appear in logs (even masked) still produce log entries with *** markers, potentially revealing the presence and position of secrets in log streams. Log aggregation systems may still index these entries, and the uniform masking doesn't enable differential access controls on log data.

**Remediation:**

Replace contextlib.suppress with explicit exception handling that logs IPC failures:
```python
try:
    from airflow.sdk.execution_time import task_runner
    from airflow.sdk.execution_time.comms import MaskSecret
    if comms := getattr(task_runner, "SUPERVISOR_COMMS", None):
        comms.send(MaskSecret(value=secret, name=name))
except ImportError:
    pass  # Not in task execution context, expected
except Exception as e:
    structlog.get_logger("airflow.security").warning(
        "mask_propagation_failed",
        error_type=type(e).__name__,
    )
```

---

#### FINDING-015: No Explicit Log Injection Encoding in Logging Processor Pipeline

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | |
| **ASVS Sections** | 16.4.1 |
| **Files** | task-sdk/src/airflow/sdk/log.py:63-80 |
| **Source Reports** | 16.4.1.md |
| **Related** | |

**Description:**

The visible logging pipeline does not include an explicit log injection encoding processor. The `mask_logs` processor (line 58-60) only applies secret redaction — it does not sanitize newlines (`\n`, `\r\n`), ANSI escape sequences, or other control characters that could be used for log injection/forging. When `json_output=False` (console/file logging), structlog's `ConsoleRenderer` does not escape embedded newlines by default. If task code logs external input (e.g., API responses, file contents, HTTP headers), an attacker-controlled value containing crafted newlines followed by fake log entries could: 1. Forge log entries that appear legitimate to analysts, 2. Inject ANSI escape sequences to manipulate terminal output when logs are viewed, 3. Break log parsing in aggregation systems that rely on line-based parsing. Impact: Log integrity is compromised. Attackers who can influence data logged by tasks (e.g., via API responses, webhook payloads, file contents) could forge log entries that mislead incident investigations. In compliance contexts, this undermines log reliability for audit trails.

**Remediation:**

Add an explicit log encoding processor to the pipeline:

```python
import re

_CONTROL_CHARS = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')

def encode_log_data(logger: Any, method_name: str, event_dict: EventDict) -> EventDict:
    """Encode log data to prevent log injection."""
    for key, value in event_dict.items():
        if isinstance(value, str):
            # Replace newlines with escaped representation
            value = value.replace('\r\n', '\\r\\n').replace('\n', '\\n').replace('\r', '\\r')
            # Strip ANSI escape sequences and control characters
            value = _CONTROL_CHARS.sub('', value)
            event_dict[key] = value
    return event_dict

# Add before mask_logs in the pipeline:
extra_processors += (encode_log_data, mask_logs,)
```

Note: If `structlog_processors()` (not provided in scope) already includes injection encoding, this finding would be mitigated. However, the audited code shows no evidence of this control in the visible pipeline construction.

---

#### FINDING-016: No cache eviction mechanism for task boundary isolation leaves secrets persisted across task executions

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | |
| **ASVS Sections** | 13.3.1 |
| **Files** | task-sdk/src/airflow/sdk/execution_time/cache.py |
| **Source Reports** | 13.3.1.md |
| **Related** | |

**Description:**

The SecretCache class stores secrets (connection URIs and variable values) in a multiprocessing.Manager().dict() shared dictionary with a configurable TTL (default 15 minutes). However, there is no mechanism to clear secrets between task executions. The only clearing mechanism (reset()) destroys the entire cache and is explicitly marked "test purposes only." There is no clear(), flush(), or per-task-scoped eviction method. Data Flow: Task A execution → secrets fetched and cached → Task A completes → Task B starts in same process → Task B calls SecretCache.get_variable() → receives Task A's cached secrets without re-authorization. If a supervisor process handles multiple tasks sequentially (or the multiprocessing Manager is shared), secrets from a previous task remain accessible for up to the TTL duration (default 15 minutes). A subsequent task with fewer permissions could access cached secrets it would not normally be authorized to retrieve from the Execution API.

**Remediation:**

Add a clear() method to SecretCache that clears all cached secrets and must be called on task completion. Add an invalidate_connection_uri() method to invalidate cached connection URIs. Example implementation:
```python
@classmethod
def clear(cls):
    """Clear all cached secrets. Must be called on task completion."""
    if cls._cache is not None:
        cls._cache.clear()

@classmethod
def invalidate_connection_uri(cls, conn_id: str, team_name: str | None = None):
    """Invalidate cached connection URI."""
    if cls._cache is not None:
        team = cls._TEAM_PATTERN.format(team_name) if team_name else ""
        cls._cache.pop(f"{cls._CONNECTION_PREFIX}{team}{conn_id}", None)
```

---

#### FINDING-017: Broad exception handling in secrets backend masks authorization failures, allowing silent fallback to unauthenticated backends

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | |
| **ASVS Sections** | 8.2.1 |
| **Files** | task-sdk/src/airflow/sdk/execution_time/secrets/execution_api.py:44-89 |
| **Source Reports** | 8.2.1.md |
| **Related** | |

**Description:**

Both `get_connection()` and `get_variable()` (including their async variants) treat all `ErrorResponse` messages identically — whether the error represents "not found," "unauthorized," or "server error." By returning `None` for authorization failures, the secrets manager proceeds to check the next backend in `DEFAULT_SECRETS_SEARCH_PATH_WORKERS`, which is `EnvironmentVariablesBackend`. The environment variables backend performs NO authorization checks. This creates a **Type C gap**: an authorization control is invoked (Execution API checks permissions), but its rejection result is treated as "not found" rather than "access denied," allowing the system to bypass the authorization by falling through to an unauthenticated backend. Data Flow: Task requests secret → ExecutionAPI returns "unauthorized" ErrorResponse → SDK returns `None` → Secrets manager checks EnvironmentVariablesBackend → Secret returned without authorization check. Proof of Concept: 1. Connection `prod_db` exists in both Execution API and environment variables 2. Task in `dev_dag` requests `prod_db` — it's not authorized via DAG permissions 3. Execution API returns ErrorResponse (unauthorized) 4. SDK returns `None`, triggering fallback 5. `EnvironmentVariablesBackend` finds `AIRFLOW_CONN_PROD_DB` in environment → returns connection without authorization. Impact: Authorization bypass for secrets that exist in both the Execution API and environment variables. Tasks can access secrets they're explicitly denied from the Execution API.

**Remediation:**

Differentiate between "not found" and "unauthorized" error responses:
```python
def get_connection(self, conn_id: str, team_name: str | None = None) -> Connection | None:
    from airflow.sdk.execution_time.comms import ErrorResponse, GetConnection
    from airflow.sdk.execution_time.context import _process_connection_result_conn
    from airflow.sdk.execution_time.task_runner import SUPERVISOR_COMMS

    try:
        msg = SUPERVISOR_COMMS.send(GetConnection(conn_id=conn_id))

        if isinstance(msg, ErrorResponse):
            if msg.is_authorization_error:
                # Raise to prevent fallback — access is explicitly denied
                raise PermissionError(f"Access denied for connection: {conn_id}")
            # Not found — allow fallback
            return None

        return _process_connection_result_conn(msg)
    except PermissionError:
        raise  # Don't catch authorization errors
    except Exception:
        return None
```

---

#### FINDING-018: Silent fallback to _NullFernet when encryption key is missing, without enforcement of key provisioning

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3, L1 |
| **CWE** | |
| **ASVS Sections** | 11.1.1, 11.2.5, 11.3.3, 11.6.1, 13.2.3 |
| **Files** | task-sdk/src/airflow/sdk/crypto.py:97-116 |
| **Source Reports** | 11.1.1.md, 11.2.5.md, 11.3.3.md, 11.6.1.md, 13.2.3.md |
| **Related** | |

**Description:**

When FERNET_KEY is not configured, the _NullFernet class is used which performs no encryption or decryption. This results in connection passwords and variable values being stored/transmitted in plaintext. Data flow: Configuration (core.FERNET_KEY empty) → get_fernet() returns _NullFernet → all encrypt()/decrypt() calls become no-ops → sensitive data (connections, variables) stored/transmitted in plaintext. While a warning is logged, the system continues to operate without encryption, which could expose secrets in transit between components or at rest. Note: Per the domain context, this is an intentional design decision where the SDK delegates key management to the Airflow server. The _NullFernet is primarily used in development/testing scenarios. In production, Fernet keys should always be configured.

**Remediation:**

Either refuse to start when FERNET_KEY is not configured (fail-closed), or at minimum enforce that callers check is_encrypted before proceeding with sensitive data operations. Example: raise AirflowException when FERNET_KEY is not configured with message: 'FERNET_KEY is not configured. Encryption is required for storing sensitive data. Generate a key with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'. Short-term: Add configuration option (e.g., core.require_encryption = True) that causes get_fernet() to raise an exception instead of falling back to _NullFernet. Add startup validation with ERROR level logging when _NullFernet is active, and emit metrics counter for monitoring.

---

#### FINDING-019: Cached Fernet instance prevents runtime key replacement

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | |
| **ASVS Sections** | 11.2.2, 14.2.2 |
| **Files** | task-sdk/src/airflow/sdk/crypto.py:~97 |
| **Source Reports** | 11.2.2.md, 14.2.2.md |
| **Related** | |

**Description:**

The @cache decorator (equivalent to @lru_cache(maxsize=None)) on get_fernet() means the Fernet instance is created once per process and never refreshed. If keys need to be rotated or replaced during the lifetime of a task process, the change won't take effect. This conflicts with the requirement that it must also be possible to replace keys and passwords and re-encrypt data. First call to get_fernet() results in a cached result forever, and subsequent key configuration changes are ignored.

**Remediation:**

Provide a mechanism to invalidate the cache when keys are rotated. Replace @cache decorator with a manual cache implementation using a global variable _fernet_cache. Implement get_fernet() to check if cache is None and load if needed. Add invalidate_fernet_cache() function to reset the global cache variable to None, forcing reload on next call. This allows runtime key rotation to take effect by explicitly invalidating the cache.

---

#### FINDING-020: No formal cryptographic inventory documentation in the codebase

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | |
| **ASVS Sections** | 11.1.2 |
| **Files** | All analyzed files |
| **Source Reports** | 11.1.2.md |
| **Related** | |

**Description:**

The codebase lacks a formal cryptographic inventory document that catalogs: All cryptographic algorithms in use (Fernet/AES-128-CBC + HMAC-SHA256), All key types and their purposes, Where keys can and cannot be used, Data classification for what must be encrypted, Certificate usage (none apparent). Without a maintained cryptographic inventory, it becomes difficult to: Assess the impact of algorithm deprecation (e.g., if AES-128 becomes insufficient), Plan migration to post-quantum cryptography, Audit key usage boundaries across the system, Identify if keys are being used beyond their intended scope. The current code uses a single Fernet key for all encryption (connections and variables) without documenting the intended scope or restrictions.

**Remediation:**

Create and maintain a cryptographic inventory document (e.g., CRYPTO_INVENTORY.md or structured YAML) that includes: algorithm ID, algorithm details (AES-128-CBC + HMAC-SHA256 via Fernet), library (cryptography pyca), version constraint (>=41.0.0), key source (core.FERNET_KEY configuration), key length (256 bits: 128 signing + 128 encryption), usage (encrypt/decrypt connection passwords, connection extra fields, variable values), restrictions (Must not be used for TLS/transport encryption, Must not be shared with external systems), rotation policy (Managed by Airflow server), and PQC migration status (Planned - awaiting crypto agility implementation).

---

#### FINDING-021: No explicit cipher suite configuration — relies entirely on system defaults

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | CWE-327 |
| **ASVS Sections** | 12.1.2 |
| **Files** | task-sdk/src/airflow/sdk/api/client.py:733-738 |
| **Source Reports** | 12.1.2.md |
| **Related** | FINDING-072 |

**Description:**

The enabled cipher suites are determined entirely by the system's OpenSSL build and configuration. While modern OpenSSL defaults are generally reasonable, they may include weaker ciphers (e.g., AES-CBC without forward secrecy on older systems). For L3 compliance, only cipher suites providing forward secrecy (ECDHE/DHE key exchange) should be permitted. Without explicit configuration, the security posture is non-deterministic across deployment environments.

**Remediation:**

Add explicit cipher suite configuration and minimum TLS version to the SSL context:
```python
@staticmethod
def _get_ssl_context_cached(ca_file: str, ca_path: str | None = None) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=ca_file)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # Restrict to forward-secrecy cipher suites with strong algorithms
    ctx.set_ciphers(
        "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS"
    )
    if ca_path:
        ctx.load_verify_locations(ca_path)
    return ctx
```

---

#### FINDING-022: Ambiguous operator precedence in deserialization type-dispatch condition

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | |
| **ASVS Sections** | 15.3.5 |
| **Files** | task-sdk/src/airflow/sdk/serde/__init__.py:225 |
| **Source Reports** | 15.3.5.md |
| **Related** | |

**Description:**

Due to Python's operator precedence (`and` binds tighter than `or`), the condition `if CLASSNAME not in o and not type_hint or VERSION not in o:` evaluates as `(CLASSNAME not in o and not type_hint) or (VERSION not in o)`. This means: A dict with `CLASSNAME` but without `VERSION` is always treated as a plain dict (even if `type_hint` is provided); A dict without `CLASSNAME` and without `type_hint` is treated as a plain dict (correct behavior). While the current behavior is safe (treating untyped data as plain dicts prevents class instantiation), the unclear precedence could lead to bugs during maintenance if a developer misreads the intent and introduces a vulnerability. Additionally, if `type_hint` is provided to force deserialization into a specific type, the `VERSION not in o` clause still bypasses it, which may not match caller expectations.

**Remediation:**

Use explicit parentheses to clarify intent: `if (CLASSNAME not in o and not type_hint) or (VERSION not in o):` Or better, split into separate conditions with clear comments: `# If no classname and no type hint, treat as plain dict\nif CLASSNAME not in o and not type_hint:\n    return {str(k): deserialize(v, full) for k, v in o.items()}\n# If no version info, cannot perform typed deserialization\nif VERSION not in o:\n    return {str(k): deserialize(v, full) for k, v in o.items()}`

---

#### FINDING-023: No documentation identifying third-party libraries considered to be risky components

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | |
| **ASVS Sections** | 15.1.4 |
| **Files** | task-sdk/src/airflow/sdk/definitions/callback.py:1-150, task-sdk/src/airflow/sdk/module_loading.py:1-27 |
| **Source Reports** | 15.1.4.md |
| **Related** | |

**Description:**

The module uses `structlog` as a third-party dependency and re-exports functions from `airflow.sdk._shared.module_loading` (which likely depends on `importlib` and potentially other libraries). There is no accompanying documentation (inline comments, README, architecture decision records, or security annotations) that identifies which third-party dependencies might be considered "risky components."

**Remediation:**

Create and maintain a security documentation artifact (e.g., `SECURITY.md` or architecture decision record) that: Lists all third-party dependencies; Classifies each by risk level based on maintenance status, vulnerability history, and functionality scope; Defines remediation timeframes for each risk tier; Is referenced from module-level docstrings where risky components are used. Example inline documentation pattern: # SECURITY NOTE: This module depends on: # - structlog (LOW risk): Well-maintained, active community, no dangerous operations # - importlib (STDLIB): Used for dynamic module loading - see SECURITY.md for risk classification

---

#### FINDING-024: Dangerous functionality (dynamic code execution via import) is not explicitly documented as such

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | |
| **ASVS Sections** | 15.1.5 |
| **Files** | task-sdk/src/airflow/sdk/definitions/callback.py:55-85 |
| **Source Reports** | 15.1.5.md |
| **Related** | |

**Description:**

The `get_callback_path()` method performs dynamic code execution by importing arbitrary Python modules from string paths. While the class docstring explains the business purpose, it does not explicitly identify this as "dangerous functionality" requiring heightened security scrutiny. The domain context explicitly states: "Module loading is a potential code execution vector if an attacker can control the import path" — yet this acknowledgment exists only in external documentation, not in the code itself. Developers modifying this code or performing security reviews may not recognize the security-critical nature of this path without explicit documentation. This increases the risk of introducing vulnerabilities during maintenance (e.g., removing validation, adding new unvalidated entry points).

**Remediation:**

Add explicit security documentation annotations to the method docstring identifying it as DANGEROUS FUNCTIONALITY that performs dynamic code execution by importing Python modules from string paths. Document that importing a module executes its module-level code, that input MUST be validated via is_valid_dotpath() before import, and that callers must ensure string paths originate from trusted sources (e.g., the serialized DAG store in the Airflow metadata database). Reference SECURITY.md#dynamic-code-loading.

---

#### FINDING-025: Dynamic import operation lacks namespace restriction (allowlist) as an additional protection mechanism

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | |
| **ASVS Sections** | 15.2.5 |
| **Files** | task-sdk/src/airflow/sdk/definitions/callback.py:62-80 |
| **Source Reports** | 15.2.5.md |
| **Related** | |

**Description:**

The domain context explicitly states: "the system must maintain an allowlist of permitted module prefixes and reject any attempts to import from unexpected locations." However, the `get_callback_path()` method only validates dotpath FORMAT via `is_valid_dotpath()` without restricting which namespaces/modules can be imported. The format validation control EXISTS (`is_valid_dotpath`) but namespace restriction is NOT IMPLEMENTED at this layer. If the trust boundary (Execution API / metadata database) is ever compromised, there is no defense-in-depth preventing import of dangerous modules (e.g., `os`, `subprocess`, `shutil`).

**Remediation:**

Implement namespace allowlisting as defense-in-depth. Define ALLOWED_CALLBACK_PREFIXES tuple (e.g., 'airflow.', 'airflow_providers.') and verify both callable and string callback paths start with allowed prefixes before import. Example: Add prefix validation in get_callback_path() method that raises ImportError if callback module/path is not in allowed namespaces.

---

#### FINDING-026: Unbounded polling loop in synchronous DAG run wait allows indefinite resource consumption

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | |
| **ASVS Sections** | 15.2.2, 2.3.2 |
| **Files** | task-sdk/src/airflow/sdk/execution_time/task_runner.py |
| **Source Reports** | 15.2.2.md, 2.3.2.md |
| **Related** | |

**Description:**

The _handle_trigger_dag_run function implements an unbounded while loop when wait_for_completion=True and deferrable=False. If a triggered DAG run enters a state not in allowed_states or failed_states (e.g., 'queued'), the task loops indefinitely, consuming a worker slot. The task's execution_timeout does not protect this code path because the timeout context manager has already been exited when this exception handler runs. A worker slot remains occupied until the server explicitly rejects a heartbeat (which may take hours or never happen depending on config) or manual intervention terminates the task.

**Remediation:**

Add configurable maximum wait time with reasonable default (e.g., 1 hour). Implement deadline-based loop termination: MAX_SYNC_POLL_SECONDS = conf.getfloat('core', 'trigger_dag_run_max_sync_wait', fallback=3600) and MIN_POKE_INTERVAL = 5.0. Use deadline = time.monotonic() + MAX_SYNC_POLL_SECONDS and check while time.monotonic() < deadline:. When deadline is exceeded, log error and return TaskState with FAILED status. Enforce minimum poke interval with effective_interval = max(drte.poke_interval, MIN_POKE_INTERVAL).

---

#### FINDING-027: No rate limiting on task-to-supervisor IPC request channel

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | |
| **ASVS Sections** | 2.4.1 |
| **Files** | task-sdk/src/airflow/sdk/execution_time/supervisor.py |
| **Source Reports** | 2.4.1.md |
| **Related** | |

**Description:**

The supervisor's request handling loop processes incoming IPC messages from task subprocesses without any rate limiting controls. A malicious or buggy task can flood the supervisor with requests, leading to API server overload and potential denial of service. Task subprocess (arbitrary code) → IPC socket → length_prefixed_frame_reader → handle_requests generator → _handle_request → API server HTTP calls — no rate limiting at any stage.

**Remediation:**

Implement request rate limiting with a sliding window counter. Add attributes to ActivitySubprocess for tracking request count, window start time, and configurable max requests per second (default 100). In _handle_request, check if the rate limit is exceeded and return an ErrorResponse with API_SERVER_ERROR if so. Reset the counter when the time window expires.

---

#### FINDING-028: Unlimited ResendLoggingFD calls leading to file descriptor exhaustion

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | |
| **ASVS Sections** | 2.4.1 |
| **Files** | task-sdk/src/airflow/sdk/execution_time/supervisor.py:~780, task-sdk/src/airflow/sdk/execution_time/supervisor.py |
| **Source Reports** | 2.4.1.md |
| **Related** | |

**Description:**

The supervisor creates new socket pairs and registers them with the selector every time it receives a ResendLoggingFD request, with no limit on the number of invocations. This can lead to file descriptor exhaustion in the supervisor process. Task code → SUPERVISOR_COMMS.send(ResendLoggingFD()) → _handle_request → _send_new_log_fd → socketpair() (new FDs) + selector.register() — no limit on invocations.

**Remediation:**

Add a counter to track ResendLoggingFD invocations per task (e.g., _log_fd_resend_count). Limit to a maximum of 5 resends per task. When the limit is exceeded, log a warning and return an ErrorResponse with API_SERVER_ERROR instead of creating new file descriptors.

---

#### FINDING-029: No quota on costly write operations (SetXCom, PutVariable, TriggerDagRun)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | |
| **ASVS Sections** | 2.4.1 |
| **Files** | task-sdk/src/airflow/sdk/execution_time/supervisor.py |
| **Source Reports** | 2.4.1.md |
| **Related** | |

**Description:**

The supervisor processes write operations (XCom creation, variable setting, DAG run triggering) without enforcing per-task quotas. A malicious or buggy task can create massive amounts of garbage data or trigger resource-intensive operations. Task code → unlimited SetXCom/PutVariable/TriggerDagRun messages → supervisor → API server — no write quota enforcement.

**Remediation:**

Implement per-task write operation quotas. Add a _write_op_counts dictionary to ActivitySubprocess tracking counts for xcom_set, variable_set, and dag_trigger operations. Define configurable limits (e.g., MAX_XCOM_WRITES=1000, MAX_VARIABLE_WRITES=100, MAX_DAG_TRIGGERS=10). Create a _check_write_quota method that increments counters and rejects requests when limits are exceeded, returning an ErrorResponse with quota exceeded message.

---

#### FINDING-030: Undocumented External Communication Paths via Dynamic Secrets Backends

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | |
| **ASVS Sections** | 13.1.1 |
| **Files** | task-sdk/src/airflow/sdk/configuration.py:219-244 |
| **Source Reports** | 13.1.1.md |
| **Related** | |

**Description:**

The configuration system dynamically loads and initializes secrets backends that connect to external services (HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, etc.), but there is no documented inventory of: Which external services the application may connect to, What protocols and ports are used, What authentication methods are required for each service, Network requirements (DNS, firewall rules), Fallback behavior when external services are unavailable. The `_get_custom_secret_backend` method allows arbitrary external service configuration through `airflow.cfg` without any documentation of the resulting communication needs.

**Remediation:**

Create a communication manifest document that: 1. Lists all possible external services the Task SDK may connect to, 2. Documents the protocol, port, and authentication mechanism for each, 3. Documents the configuration settings that enable each external connection, 4. Specifies fallback/retry behavior when services are unavailable. Example documentation structure: communication_manifest.yml with external_services listing name, config_key, protocols, authentication, required flag, and fallback behavior for each service.

---

#### FINDING-031: No Documentation of Critical Secrets or Rotation Schedule

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | |
| **ASVS Sections** | 13.1.4 |
| **Files** | task-sdk/src/airflow/sdk/configuration.py:85-94 |
| **Source Reports** | 13.1.4.md |
| **Related** | |

**Description:**

The code explicitly acknowledges the existence of critical secrets (FERNET_KEY, JWT_SECRET_KEY) in comments but provides no documentation of: A complete inventory of secrets the SDK handles or delegates, classification of which secrets are critical for security, rotation schedules for each secret, procedures for emergency rotation, or impact assessment if each secret is compromised. The _SERVER_DEFAULT_SECRETS_SEARCH_PATH and custom secret backend configuration imply secrets are managed, but no formal documentation defines their lifecycle.

**Remediation:**

Create a secrets inventory document listing all secrets with their name, purpose, classification, rotation schedule, rotation procedure, and compromise impact. Example: Create secrets_inventory.yml documenting Fernet Key (90 day rotation), API Bearer Token (per-task-execution ephemeral), and Custom Secrets Backend Credentials (per organization policy).

---

#### FINDING-032: No Explicit Classification of Sensitive Configuration Values

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | |
| **ASVS Sections** | 14.1.1 |
| **Files** | task-sdk/src/airflow/sdk/configuration.py:152-168 |
| **Source Reports** | 14.1.1.md |
| **Related** | |

**Description:**

The configuration system processes all values uniformly without classifying them into protection levels. The `is_template` check appears to be a functional distinction (deferred expansion), not a security classification. There is no mechanism to: Mark configuration values as containing sensitive data (passwords, tokens, keys), Classify data into protection levels (e.g., PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED), Apply different handling based on sensitivity (e.g., masking in logs, encryption at rest), Map data to applicable regulatory requirements (GDPR, PCI-DSS, HIPAA). Configuration values that may contain sensitive data include: secrets.backend_kwargs (may contain credentials for the secrets backend itself), Database connection strings (may contain passwords), API endpoint URLs with embedded tokens, Fernet encryption keys. Without classification, sensitive configuration values may be: Logged at DEBUG level without masking, Exposed in error messages (line 146: log.warning), Included in diagnostic dumps, Stored without appropriate access controls.

**Remediation:**

Implement a sensitivity classification system in the configuration description. In config.yml, add sensitivity metadata for each configuration key (e.g., sensitivity: CONFIDENTIAL, protection: mask_in_logs, encrypt_at_rest). Then enforce protection in the parser by implementing get_sensitivity() method to retrieve classification and audit access to CONFIDENTIAL/RESTRICTED values. Define SENSITIVITY_LEVELS as [PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED] and apply differential handling based on classification.

---

#### FINDING-033: No Documented Protection Requirements for Configuration Data at Any Level

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | |
| **ASVS Sections** | 14.1.2 |
| **Files** | task-sdk/src/airflow/sdk/configuration.py, task-sdk/src/airflow/sdk/configuration.py:146, task-sdk/src/airflow/sdk/configuration.py:163-166 |
| **Source Reports** | 14.1.2.md |
| **Related** | |

**Description:**

The configuration module handles data at multiple sensitivity levels but has no documented protection requirements for any level. Required documentation should include encryption at rest, encryption in transit, integrity verification, retention policy, logging controls, access controls, database encryption, and privacy controls. Without documented protection requirements: developers cannot implement consistent protection across the codebase, security reviewers cannot verify whether controls are sufficient, compliance audits cannot validate regulatory adherence, and operations teams may deploy with insufficient protection (e.g., world-readable config files containing secrets).

**Remediation:**

Create a data protection specification document with three levels: RESTRICTED (Fernet Keys, API Tokens, Backend Credentials) requiring encrypted secrets backend storage, TLS 1.2+, key validation, 90-day maximum lifetime with rotation, never log values (mask with ***), process-level isolation; CONFIDENTIAL (Connection Strings, Database URLs) requiring Fernet encryption or secrets backend, TLS 1.2+ for connections, URI format validation, per data retention policy, mask passwords in logs, read access limited to task execution context; INTERNAL (Config file paths, AIRFLOW_HOME) with standard filesystem permissions (640), file existence validation, may be logged for debugging.

---

#### FINDING-034: No Formal Logging Inventory Document Referenced or Enforced in Code

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | |
| **ASVS Sections** | 16.1.1 |
| **Files** | task-sdk/src/airflow/sdk/log.py |
| **Source Reports** | 16.1.1.md |
| **Related** | |

**Description:**

The logging infrastructure supports multiple destinations (local files, remote storage, supervisor IPC) and configurable formats, but there is no reference to, or enforcement of, a logging inventory document that describes: What events are logged at each layer, Log formats used (JSON vs. plaintext), Where logs are stored (local path, remote handler class), How access to logs is controlled, Retention policies. The code reveals multiple undocumented logging pathways: Local file logging configured via base_log_folder, Remote logging dynamically loaded from config class, Supervisor communication channel. Without a formal inventory, security operations teams cannot verify completeness of logging, cannot audit log access patterns, and cannot determine if all security events are captured at all layers.

**Remediation:**

Create a logging inventory document and reference it in code comments. Consider adding a validation step at startup that verifies configured destinations match the documented inventory.

---

#### FINDING-035: No Explicit "Who" (Identity/Principal) Metadata Injection in Log Processor Chain

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | |
| **ASVS Sections** | 16.2.1 |
| **Files** | task-sdk/src/airflow/sdk/log.py:51-66 |
| **Source Reports** | 16.2.1.md |
| **Related** | |

**Description:**

The logging processor chain is constructed without an explicit processor that injects identity/principal information ("who") into each log entry. While structlog can include callsite parameters (where) and timestamps (when), and the event itself provides "what," there is no processor visible that binds the current authenticated user, task identity, or execution context (dag_id, task_id, run_id) to every log record. Without consistent "who" metadata, security investigations cannot correlate log entries to specific users or execution contexts without manual cross-referencing of separate data sources.

**Remediation:**

Add a structlog processor that binds execution context (task_id, dag_id, run_id, execution user) to every log entry:
```python
def add_execution_context(logger, method_name, event_dict):
    """Add 'who' metadata to all log entries."""
    from airflow.sdk.execution_time.context import get_current_context
    try:
        ctx = get_current_context()
        event_dict.setdefault("dag_id", ctx.dag_id)
        event_dict.setdefault("task_id", ctx.task_id)
        event_dict.setdefault("run_id", ctx.run_id)
    except Exception:
        pass
    return event_dict
```

---

#### FINDING-036: Dynamic Log Destination Loading Without Inventory Validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | |
| **ASVS Sections** | 16.2.3 |
| **Files** | task-sdk/src/airflow/sdk/log.py:151-165 |
| **Source Reports** | 16.2.3.md |
| **Related** | |

**Description:**

The logging configuration dynamically loads a logging class from a configurable path without validating it against a documented inventory of approved destinations. Configuration file → `logging_config_class` setting → `import_string()` → arbitrary class loaded as log handler. If an attacker gains write access to configuration (or if a misconfiguration occurs), logs could be routed to unauthorized destinations not documented in any logging inventory. This could result in data exfiltration via log forwarding or loss of audit trail.

**Remediation:**

Implement an allowlist of permitted logging handler classes: ALLOWED_LOGGING_CONFIGS = {"airflow.config_templates.airflow_local_settings.DEFAULT_LOGGING_CONFIG", "airflow.providers.amazon.aws.log.s3_task_handler.S3TaskHandler", ...}. Validate logging_class_path against this allowlist and raise ValueError if not in approved inventory.

---

#### FINDING-037: No Authentication Event Logging Infrastructure in Provided Code

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | |
| **ASVS Sections** | 16.3.1 |
| **Files** | task-sdk/src/airflow/sdk/log.py |
| **Source Reports** | 16.3.1.md |
| **Related** | |

**Description:**

The logging infrastructure files do not include any authentication-specific logging hooks, decorators, or utility functions that would facilitate consistent logging of authentication events. While the infrastructure provides general-purpose structured logging, there is no: Dedicated authentication event logger or event type, Utility function for logging auth success/failure with required metadata (auth type, factors used, source IP), or Structured event schemas for authentication events. The mask_secret function handles credential masking but there is no corresponding log_auth_event function. Without standardized authentication logging utilities, individual authentication handlers may log inconsistently, miss events, or fail to include required metadata (auth type, factors). This undermines security monitoring and incident response capabilities.

**Remediation:**

Add an authentication logging utility to the logging infrastructure: def log_auth_event(event: str, auth_type: str, principal: str, success: bool, metadata: dict | None = None) -> None: """Log authentication event with required metadata."""; log = structlog.get_logger("security.auth"); log_method = log.info if success else log.warning; log_method(event, auth_type=auth_type, principal=principal, success=success, **(metadata or {}))

#### FINDING-038: No Authorization Event Logging Infrastructure

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2, L3 |
| CWE | - |
| ASVS Sections | 16.3.2 |
| Files | task-sdk/src/airflow/sdk/log.py (entire file scope) |
| Source Reports | 16.3.2.md |
| Related Findings | - |

**Description:**

The logging infrastructure provided in these files configures structured logging with secret masking but does not define or implement any mechanisms for logging authorization decisions or failed authorization attempts. There are no: decorator or utility functions for annotating authorization-checked endpoints, structured event types for authorization success/failure, or context processors that attach authorization decision metadata to log entries. Authorization decision → (no logging mechanism) → unlogged. Failed authorization attempts would not generate audit trail entries unless individual developers manually add log statements, creating inconsistent coverage across the codebase.

**Remediation:**

Implement a structured security event logging utility that provides consistent functions for logging authorization decisions. Example implementation:
```python
def log_authorization_event(
    logger: Any,
    action: str,
    resource: str,
    user: str,
    decision: str,  # "granted" or "denied"
    reason: str | None = None,
):
    """Log an authorization decision for audit purposes."""
    log = structlog.get_logger("security.authorization")
    log_method = log.info if decision == "granted" else log.warning
    log_method(
        "authorization_decision",
        action=action,
        resource=resource,
        user=user,
        decision=decision,
        reason=reason,
    )
```

---

#### FINDING-039: Default Log File Permissions Allow Group Write Access

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 16.4.2 |
| Files | task-sdk/src/airflow/sdk/log.py (126-148) |
| Source Reports | 16.4.2.md |
| Related Findings | - |

**Description:**

Default file permission 0o664 (rw-rw-r--) allows group members to write to log files, and default folder permission 0o775 (rwxrwxr-x) allows group members to create, delete, or rename files in log directories. If multiple tasks or services run under the same Unix group, they can modify each other's log files. Data flow: Log file creation → init_log_file() → permissions 0o664 applied → group-writable log file. Any process running in the same Unix group can modify or delete log files, compromising log integrity for forensic investigations.

**Remediation:**

Tighten defaults: owner read/write, group/other read-only. Change new_file_permissions to 0o644 and new_folder_permissions to 0o755. Example: new_file_permissions = int(conf.get("logging", "file_task_handler_new_file_permissions", fallback="0o644"), 8,) and new_folder_permissions = int(conf.get("logging", "file_task_handler_new_folder_permissions", fallback="0o755"), 8,)

---

#### FINDING-040: API Server Error Details Exposed in Task Logs

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 16.5.1 |
| Files | task-sdk/src/airflow/sdk/execution_time/supervisor.py (430-450) |
| Source Reports | 16.5.1.md |
| Related Findings | - |

**Description:**

API server error response details are forwarded verbatim through the IPC channel to the task process. When the API server returns an error response containing internal details (e.g., database query fragments, internal service endpoints, or stack trace information in the JSON body), these are forwarded through the IPC channel to the task process. The task runner receives this via _from_frame() and raises AirflowRuntimeError which is caught and logged, exposing the internal details in task logs viewable by DAG authors through the Airflow UI. This violates the principle of returning generic error messages to consumers.

**Remediation:**

Log full error details only on the supervisor side (not forwarded to task). Send only a sanitized, generic error back to the task process with status code and a generic message like 'The API server returned an error. Check supervisor logs for details.' Remove the raw error_details from the ErrorResponse detail sent via IPC.

---

#### FINDING-041: Task Hangs Indefinitely on Message Decode Failure

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 16.5.2 |
| Files | task-sdk/src/airflow/sdk/execution_time/supervisor.py (418-421) |
| Source Reports | 16.5.2.md |
| Related Findings | - |

**Description:**

Task runner sends request, supervisor fails to decode, logs error and continues without sending response, task runner blocks indefinitely in _read_frame() with blocking socket recv and no timeout. If a protocol version mismatch occurs (e.g., during rolling upgrades where supervisor and task runner are different versions), message decode can fail. The task runner is blocked in blocking socket recv with no timeout mechanism. Task hangs indefinitely without any mechanism to detect the communication failure, blocking the task's execution thread permanently and consuming resources without progress. No circuit breaker or timeout exists for this communication path.

**Remediation:**

Send an error response before continuing when decode fails. Send ErrorResponse with GENERIC_ERROR type and message 'Unable to process request' so task doesn't hang. Add communication timeout by setting a reasonable timeout on blocking socket recv in CommsDecoder._read_frame() to prevent indefinite hangs.

---

#### FINDING-042: Unhandled Exceptions in Socket Handler Crash Monitoring Loop

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2, L3 |
| CWE | - |
| ASVS Sections | 16.5.3, 16.5.4 |
| Files | task-sdk/src/airflow/sdk/execution_time/supervisor.py (~530-550 in _service_subprocess()) |
| Source Reports | 16.5.3.md, 16.5.4.md |
| Related Findings | - |

**Description:**

When an unhandled exception occurs in request processing (socket_handler), it propagates through _service_subprocess, _monitor_subprocess, and wait(), causing the monitoring loop to crash. The current code only catches BrokenPipeError and ConnectionResetError. When the monitoring loop crashes: update_task_state_if_needed() is never called so task state in API server is never updated, _upload_logs() is never called so remote logs are lost, and the child process continues running as an orphan. The task appears stuck until heartbeat timeout triggers server-side cleanup.

**Remediation:**

Add a catch-all exception handler in wait() that: (1) logs the unhandled exception with full context, (2) ensures the subprocess is terminated via kill(signal.SIGTERM, force=True), (3) sets exit code to 1 if not already set, (4) wraps update_task_state_if_needed() and _upload_logs() in individual try-except blocks to ensure both are attempted even if one fails. See detailed code example in report.

---

#### FINDING-043: Incomplete BaseException Coverage in Last-Resort Handlers

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 16.5.4 |
| Files | task-sdk/src/airflow/sdk/execution_time/supervisor.py (256-280) |
| Source Reports | 16.5.4.md |
| Related Findings | - |

**Description:**

The _fork_main() last-resort handler catches SystemExit and Exception but not BaseException. While main() catches KeyboardInterrupt, edge cases remain: GeneratorExit during generator cleanup, custom BaseException subclasses from third-party task code, or corrupted interpreter state. More critically, the supervisor process's monitoring loop (wait()) has NO last-resort handler. If _monitor_subprocess() raises, the error is not logged at the supervisor level - it propagates to the external caller without any structured error capture, making post-mortem analysis difficult and potentially losing error details required for debugging.

**Remediation:**

Add a catch-all in wait() as shown in ASVS-1654-HIGH-001 remediation. Extend _fork_main to catch BaseException (not just Exception) to handle GeneratorExit, KeyboardInterrupt, and custom BaseException subclasses. Write diagnostics to last_chance_stderr and exit with code 127 for BaseException cases.

---

#### FINDING-044: Supervisor Accepts Terminal State Messages Without Verifying Execution Phase

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Sections | 2.3.1 |
| Files | task-sdk/src/airflow/sdk/execution_time/supervisor.py (517) |
| Source Reports | 2.3.1.md |
| Related Findings | - |

**Description:**

The supervisor processes terminal state messages (TaskState, SucceedTask, RetryTask, DeferTask) at any time without verifying the task has progressed through expected phases (startup → preparation → execution → completion). While the task runner code structure enforces ordering (calling _prepare() before _execute_task()), the supervisor has no independent validation. If the task process (through a bug) sends a terminal state prematurely, the supervisor will process it without question. This is primarily a defense-in-depth concern since the IPC channel is within a trust boundary. A malicious task operator's execute() could theoretically monkey-patch SUPERVISOR_COMMS internals to send a SucceedTask message before actually completing work, and the supervisor would accept it and call task_instances.succeed() on the API server.

**Remediation:**

Add explicit phase tracking to the supervisor with phases: "starting" -> "running" -> "terminal". Only accept terminal state messages when in "running" phase. Add duplicate terminal state guard to prevent processing multiple terminal states. Implement warning logging when terminal states are received before task is running.

---

#### FINDING-045: Unhandled Non-ServerResponseError Exceptions Crash Supervisor Without State Cleanup

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 2.3.3 |
| Files | task-sdk/src/airflow/sdk/execution_time/supervisor.py (373) |
| Source Reports | 2.3.3.md |
| Related Findings | - |

**Description:**

_handle_request() → API call raises non-ServerResponseError (e.g., httpx.ConnectTimeout, httpx.ReadTimeout) → exception propagates through generator → through length_prefixed_frame_reader callback → through _service_subprocess → through _monitor_subprocess → wait() → supervise_task() returns without calling update_task_state_if_needed(). If the API client raises an exception that is not ServerResponseError (e.g., network-level timeout, DNS failure, ConnectionRefusedError wrapped by httpx), the entire supervisor monitoring loop crashes. The wait() method's finally block closes the selector but never calls update_task_state_if_needed(), leaving the task in an indeterminate state on the server. The task process may also continue running unsupervised.

**Remediation:**

Add catch-all exception handling in handle_requests() to catch ALL exceptions and prevent supervisor crash. Log the unexpected error and send an error response back to the task with ErrorType.API_SERVER_ERROR. Ensure the exception does not propagate and crash the monitoring loop.

---

#### FINDING-046: No Guard Against Duplicate Terminal State API Calls From Same Task Process

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 2.3.4 |
| Files | task-sdk/src/airflow/sdk/execution_time/supervisor.py (517) |
| Source Reports | 2.3.4.md |
| Related Findings | - |

**Description:**

The supervisor's _handle_request() method does not check if a terminal state has already been set before processing terminal state messages (TaskState, SucceedTask, RetryTask, DeferTask, RescheduleTask). This allows duplicate terminal state messages from the task process to overwrite _terminal_state and trigger multiple API calls to the server with conflicting state transitions. For example, if a task sends a SucceedTask message followed by a RetryTask message (e.g., due to a post_execute hook exception or race condition), the supervisor will call both client.task_instances.succeed() and client.task_instances.retry(), causing the API server to receive conflicting state transitions for the same task instance.

**Remediation:**

Add a guard at the beginning of terminal state message handling to check if self._terminal_state is already set. If it is, log a warning, send an ErrorResponse back to the task process, and return early without processing the duplicate message. Example implementation:

python
def _handle_request(self, msg: ToSupervisor, log: FilteringBoundLogger, req_id: int):
    ...
    terminal_types = (TaskState, SucceedTask, RetryTask, DeferTask, RescheduleTask)
    if isinstance(msg, terminal_types):
        if self._terminal_state is not None:
            log.warning(
                "Ignoring duplicate terminal state message",
                existing_state=self._terminal_state,
                new_msg_type=type(msg).__name__,
            )
            self.send_msg(
                msg=None,
                error=ErrorResponse(
                    error=ErrorType.API_SERVER_ERROR,
                    detail={"message": "Terminal state already reported"},
                ),
                request_id=req_id,
            )
            return
    ...

---

#### FINDING-047: Unescaped Regex Interpolation in get_unique_task_id

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | CWE-1333 |
| ASVS Sections | 1.3.12 |
| Files | task-sdk/src/airflow/sdk/bases/decorator.py (119-127) |
| Source Reports | 1.3.12.md |
| Related Findings | - |

**Description:**

The `prefix` variable is derived from `tg_task_id` and is interpolated directly into a regex pattern via f-string (`rf"^{prefix}__(\\d+)$"`). If `prefix` contains regex metacharacters (e.g., `(`, `)`, `+`, `*`, `.`), the resulting pattern could exhibit unexpected behavior or, in pathological cases, exponential backtracking. The data flow is: `task_id` parameter → `tg_task_id` (via `task_group.child_id()`) → `prefix` (via `re.split`) → injected into `re.match()` pattern without escaping. `get_unique_task_id` is called BEFORE `validate_key` in `DecoratedOperator.__init__`, creating a window where unvalidated input reaches the regex. If a DAG author or programmatically-generated DAG provides a task_id containing regex metacharacters like `task(a+)+id`, this could cause the regex engine to exhibit pathological backtracking when matching against other task_ids in the DAG, potentially causing CPU exhaustion during DAG parsing.

**Remediation:**

Apply `re.escape()` to the `prefix` variable before using it in regex pattern construction: `escaped_prefix = re.escape(prefix)` and then use `rf"^{escaped_prefix}__(\\d+)$"` in the pattern. This prevents regex metacharacters from being interpreted as pattern elements.

---

#### FINDING-048: No Cryptographic Discovery Mechanism for Identifying Cryptographic Instances

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 11.1.3 |
| Files | task-sdk/src/airflow/sdk/crypto.py, task-sdk/src/airflow/sdk/api/client.py (488-496), task-sdk/src/airflow/sdk/api/client.py (456-462), task-sdk/src/airflow/sdk/serde/serializers/deltalake.py, task-sdk/src/airflow/sdk/serde/serializers/iceberg.py |
| Source Reports | 11.1.3.md |
| Related Findings | - |

**Description:**

The Task SDK contains multiple cryptographic operations but lacks any automated discovery mechanism to identify and catalog them. Cryptographic operations include: (1) Fernet encryption in task-sdk/src/airflow/sdk/crypto.py (AES-128-CBC + HMAC-SHA256), (2) TLS/SSL context in task-sdk/src/airflow/sdk/api/client.py (lines 488-496), (3) Serializer encryption in task-sdk/src/airflow/sdk/serde/serializers/deltalake.py and iceberg.py, and (4) Bearer token authentication in task-sdk/src/airflow/sdk/api/client.py (lines 456-462). Without a discovery mechanism, newly added cryptographic operations (e.g., by contributors adding new serializers) may use weak algorithms or configurations without review. This makes it difficult to assess the complete cryptographic posture and prepare for algorithm migrations.

**Remediation:**

Implement a cryptographic discovery tool or CI pipeline step that scans for: (1) Imports from cryptography, hashlib, hmac, ssl modules, (2) Instantiation of cipher/hash objects, and (3) Configuration of TLS contexts. Example approach using static analysis with a scanner (ci/crypto_discovery.py) that defines CRYPTO_IMPORTS = ['cryptography', 'hashlib', 'hmac', 'ssl', 'Fernet', 'MultiFernet'] and scans all .py files to report usage of cryptographic modules.

---

#### FINDING-049: supervise_callback allows unauthenticated API requests via default empty token

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 13.2.1 |
| Files | task-sdk/src/airflow/sdk/execution_time/callback_supervisor.py (250) |
| Source Reports | 13.2.1.md |
| Related Findings | - |

**Description:**

If a caller provides a `server` URL without explicitly setting `token`, the callback subprocess will make unauthenticated API requests to the Execution API server. Unlike `supervise_task()` where `token: str` has no default (making it required), `supervise_callback()` defaults to an empty string. The `BearerAuth.auth_flow` method conditionally skips the Authorization header when `self.token` is falsy, resulting in completely unauthenticated backend communication.

**Remediation:**

Option 1: Remove default value to make token required when server is provided by changing `token: str = ""` to `token: str` (no default - required). Option 2: Add validation: if not client and server and not token: raise ValueError("token is required when connecting to a server")

---

#### FINDING-050: Cryptographic keys loaded directly from configuration without isolated security module

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 13.3.3 |
| Files | task-sdk/src/airflow/sdk/crypto.py (98-120) |
| Source Reports | 13.3.3.md |
| Related Findings | - |

**Description:**

Cryptographic key material (Fernet keys) is loaded directly from configuration into process memory without use of an isolated security module (HSM, vault, or similar). The `@cache` decorator ensures the key remains in memory for the entire process lifetime with no mechanism for secure key zeroing or rotation without process restart. Data flow: Configuration file → `conf.get("core", "FERNET_KEY")` → process memory (cached indefinitely via `@cache`). Key material is exposed in process memory for the lifetime of the process. If the process memory is compromised (memory dump, core dump, /proc access), the encryption key could be extracted. The `_make_process_nondumpable()` call in the supervisor mitigates some of this risk on Linux. This is acknowledged in the project's known design decisions: "Fernet encryption for connections/variables without key rotation would be flagged as weak key management, but is intentional because the SDK delegates key management to the Airflow server." This is a Level 3 requirement.

**Remediation:**

Integrate with a secrets management service for key retrieval. Example: Add support for vault-backed key retrieval by implementing a configurable key backend system that can retrieve keys from HashiCorp Vault, AWS KMS, or similar HSM/vault services instead of loading keys directly from configuration files. For Level 3 compliance, consider supporting external key management services. Document the recommended deployment patterns for using vault-backed secrets providers to satisfy ASVS L3 requirements at the infrastructure level.

---

#### FINDING-051: Retry and Timeout Configuration Lacks Upper Bound Enforcement

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 15.1.3 |
| Files | task-sdk/src/airflow/sdk/api/client.py (556-560) |
| Source Reports | 15.1.3.md |
| Related Findings | - |

**Description:**

While retry limits and timeouts exist, there is no validation that configured values are within reasonable bounds. An operator misconfiguration (e.g., extremely high retry count or timeout) could cause resource exhaustion. A misconfigured execution_api_retries with large execution_api_retry_wait_max could cause a task to hold resources for an unbounded duration.

**Remediation:**

Add bounds checking on configuration values:

python
API_RETRIES = min(conf.getint("workers", "execution_api_retries"), 10)
API_RETRY_WAIT_MAX = min(conf.getfloat("workers", "execution_api_retry_wait_max"), 120.0)
API_TIMEOUT = min(conf.getfloat("workers", "execution_api_timeout"), 300.0)


---

#### FINDING-052: Insufficient Documentation of Resource-Demanding Operations

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 15.1.3 |
| Files | task-sdk/docs/concepts.rst, task-sdk/src/airflow/sdk/execution_time/task_runner.py (2044-2070) |
| Source Reports | 15.1.3.md |
| Related Findings | - |

**Description:**

The concepts.rst documentation describes the task lifecycle, supervisor pattern, and heartbeat mechanism but does not explicitly identify which operations are time-consuming or resource-demanding, nor does it document how to prevent availability loss due to overuse of these operations. Specific undocumented resource-demanding patterns include: 1) Unbounded polling loop in _handle_trigger_dag_run with no independent timeout, 2) DAG file parsing can be arbitrarily expensive, 3) Template rendering executes Jinja2 rendering which can be computationally expensive, 4) XCom serialization processes potentially large payloads. Without documentation identifying resource-demanding operations and mitigation strategies, operators may not configure appropriate timeouts, leading to worker slot exhaustion, thread starvation, or cascading availability loss.

**Remediation:**

Add a dedicated "Resource Management" section to concepts.rst that documents:
- Resource-demanding operations (DAG file parsing, template rendering, TriggerDagRunOperator with wait_for_completion, XCom operations with large payloads)
- Mitigation strategies for each operation (parsing_timeout, max_templated_field_length, deferrable operators, execution_timeout, custom XCom backends)
- Configuration options to prevent availability loss (execution_timeout, max_active_tasks, max_active_runs, dagrun_timeout)
- Guidance on using deferred operators vs blocking polls for I/O-bound waiting

---

#### FINDING-053: Test/Development Infrastructure Included in Production Module

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 15.2.3 |
| Files | task-sdk/src/airflow/sdk/execution_time/supervisor.py (934-1100) |
| Source Reports | 15.2.3.md |
| Related Findings | - |

**Description:**

InProcessTestSupervisor and related classes (InProcessSupervisorComms, TaskRunResult, run_task_in_process) are included in the production supervisor.py module. While these support dag.test() (a legitimate feature), the _Client inner class bypasses retry logic and the InProcessTestSupervisor bypasses subprocess isolation entirely. If triggered in production (e.g., via dag.test() in a deployed environment), task code runs in the supervisor's process without isolation, potentially accessing supervisor-level secrets and resources.

**Remediation:**

Consider moving test infrastructure to a separate module with explicit imports, or add runtime guards that check for unit_test_mode configuration or AIRFLOW_ALLOW_IN_PROCESS_TASK environment variable before allowing InProcessTestSupervisor to start, raising a RuntimeError if used outside testing or dag.test() contexts.

---

#### FINDING-054: ExecutorSafeguard Bypass via Configuration

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 15.2.3 |
| Files | task-sdk/src/airflow/sdk/bases/operator.py (306-310) |
| Source Reports | 15.2.3.md |
| Related Findings | - |

**Description:**

The ExecutorSafeguard that prevents operators from being executed outside the task runner context can be disabled by setting unit_test_mode = True in configuration. If this setting is accidentally left enabled in production, it removes a safety check that prevents accidental nested operator execution. In production with unit_test_mode=True, operators can be incorrectly nested or executed outside the task runner without errors, potentially leading to unexpected behavior.

**Remediation:**

Add explicit logging when test_mode is detected in non-test environments. Check if PYTEST_CURRENT_TEST environment variable is set and issue a warning if unit_test_mode is enabled outside of pytest, indicating that ExecutorSafeguard is disabled.

---

#### FINDING-055: No Explicit Repository Pinning for Runtime Dependencies

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 15.2.4 |
| Files | task-sdk/pyproject.toml |
| Source Reports | 15.2.4.md |
| Related Findings | - |

**Description:**

The `pyproject.toml` does not specify trusted package indexes/repositories for any runtime dependencies. There is no `[tool.uv.index]`, `[tool.pip.index-url]`, or equivalent configuration that pins dependencies to a specific repository. While workspace dependencies use `[tool.uv.sources]`, external dependencies have no repository restriction. Without repository pinning, a dependency confusion attack could be possible if an attacker publishes a malicious package with the same name on a public index that is checked before the intended source. Additional concerns include: (1) The package namespace `airflow.sdk` is a namespaced package under `airflow` — if the package registry configuration allows, an attacker could potentially register conflicting subpackages. (2) Internal imports like `from airflow.dag_processing.bundles.manager import DagBundlesManager` cross package boundaries between `task-sdk` and the main `airflow` package, which could be exploited if package resolution order is misconfigured.

**Remediation:**

Add explicit index configuration to pyproject.toml: `[tool.uv]` with `index-url = "https://pypi.org/simple/"` and `no-build-isolation = false`. Additionally add `[[tool.uv.index]]` entries for specific sources like Apache packages. Additional verification needed: (1) All dependencies are pulled from PyPI or explicitly configured private registries (2) Lock files include content hashes for all transitive dependencies (3) The `airflow` namespace package registration prevents external parties from registering conflicting subpackages

---

#### FINDING-056: Authorization revocation has inherent delay window due to heartbeat interval

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 8.3.2 |
| Files | task-sdk/src/airflow/sdk/execution_time/supervisor.py (692) |
| Source Reports | 8.3.2.md |
| Related Findings | - |

**Description:**

If the API server revokes a task's authorization (e.g., task marked as removed or failed by an admin), there is an inherent window of up to MIN_HEARTBEAT_INTERVAL seconds during which the task continues executing. During this window, the task can still make requests through the supervisor that will be authorized by its existing token. Authorization change on server → heartbeat response (404/409/410) → self.kill(signal.SIGTERM, force=True) — but only checked every MIN_HEARTBEAT_INTERVAL seconds (configurable, default typically 10s).

**Remediation:**

This is largely by design. For environments requiring stricter immediate revocation: Option 1: Reduce minimum heartbeat interval for high-security environments (MIN_HEARTBEAT_INTERVAL: int = conf.getint('workers', 'min_heartbeat_interval', fallback=5)). Option 2: Check authorization on every request forwarded to the API server (already happens implicitly since the API validates the token on each call). Long-term: Consider a push notification channel (e.g., WebSocket or long-polling) where the server can immediately notify the supervisor of authorization changes without waiting for the next heartbeat.

### 3.4 Low

#### FINDING-057: Unsanitized log event fields from untrusted subprocess passed as structlog kwargs

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-117 |
| ASVS Sections | 1.3.3, 1.5.2 |
| Files | task-sdk/src/airflow/sdk/execution_time/supervisor.py:1741-1767 |
| Source Reports | 1.3.3.md, 1.5.2.md |
| Related Findings | - |

**Description:**

The function `process_log_messages_from_subprocess` uses `msgspec.json.decode(line)` without a type argument, producing standard Python types (dict, list, str, int, float, bool, None) from untrusted subprocess input. While this is safe from code execution, it is schema-less deserialization that doesn't enforce the expected log event structure, violating the principle of using typed/schema-validated deserialization for untrusted input. Data flow: Task subprocess (untrusted code) → JSON bytes over socket → msgspec.json.decode(line) → untyped Python dict → passed to structlog. The practical impact is limited to data quality issues in logs.

**Remediation:**

Define an allowlist of permitted log keys (ALLOWED_LOG_KEYS) and a maximum log value length (MAX_LOG_VALUE_LENGTH = 10000). Filter out keys not in the allowlist and truncate string values exceeding the maximum length. Example: `for key in list(event.keys()): if key not in ALLOWED_LOG_KEYS: del event[key]; elif isinstance(event[key], str) and len(event[key]) > MAX_LOG_VALUE_LENGTH: event[key] = event[key][:MAX_LOG_VALUE_LENGTH] + "...[truncated]"`

---

#### FINDING-058: Template variables rendered without HTML encoding in email notification HTML context

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1, L2 |
| CWE | CWE-79 |
| ASVS Sections | 1.2.1, 1.1.2 |
| Files | task-sdk/src/airflow/sdk/execution_time/task_runner.py:1412-1413, task-sdk/src/airflow/sdk/execution_time/task_runner.py:1430-1435 |
| Source Reports | 1.2.1.md, 1.1.2.md |
| Related Findings | - |

**Description:**

Template variables are rendered without HTML encoding in the email notification HTML context. Specifically, `ti.hostname` is inserted raw into HTML body context and `ti.log_url` is inserted raw into HTML `href` attribute context without proper encoding. While `exception_html` is pre-escaped, other interpolated values rely on the assumption that they contain only safe characters. If a worker's hostname were set to `<img src=x onerror=alert(1)>` (e.g., via container orchestration misconfiguration), the email HTML body would contain unescaped HTML injection. However, real-world exploitability is limited because system hostnames are controlled by infrastructure configuration, not end users, DAG IDs and task IDs are validated by the API server, and emails are sent to addresses configured by trusted DAG authors.

**Remediation:**

Apply context-appropriate encoding for all template variables, or enable Jinja2 autoescaping for the email template. Example: Use `html.escape()` for HTML element context and mark pre-escaped content explicitly with `markupsafe.Markup()`. For the template, ensure autoescaping or encode values: `hostname_escaped = html.escape(str(ti.hostname))` and include in additional_context.

---

#### FINDING-059: Inconsistent URL encoding in dynamically constructed log_url - dag_id and task_id not encoded

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-116 |
| ASVS Sections | 1.2.2 |
| Files | task-sdk/src/airflow/sdk/execution_time/task_runner.py:566-583 |
| Source Reports | 1.2.2.md |
| Related Findings | - |

**Description:**

While `run_id` is properly URL-encoded with `quote()`, `self.dag_id` and `self.task_id` are inserted raw into the URL path. If these values contained URL-significant characters (`/`, `?`, `#`, `%`), the URL structure would be corrupted. While Airflow's server validates dag_ids to safe patterns, the defensive encoding is inconsistent. This represents a defense-in-depth gap rather than an exploitable vulnerability.

**Remediation:**

Apply consistent URL encoding to all dynamic path components: `from urllib.parse import quote; run_id = quote(self.run_id, safe=""); dag_id = quote(self.dag_id, safe=""); task_id = quote(self.task_id, safe=""); return f"{base_url.rstrip('/')}/dags/{dag_id}/runs/{run_id}/tasks/{task_id}{map_index}{try_number}"`

---

#### FINDING-060: No URL protocol validation for base_url configuration value used in URL construction

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-20 |
| ASVS Sections | 1.2.2 |
| Files | task-sdk/src/airflow/sdk/execution_time/task_runner.py:569 |
| Source Reports | 1.2.2.md |
| Related Findings | FINDING-063, FINDING-064 |

**Description:**

The `base_url` is read from configuration without validating that it uses a safe protocol scheme. If an attacker could modify the configuration to use `javascript:` or `data:` scheme, the resulting URL would be injected into email HTML `href` attributes. However, configuration modification requires administrative access. Configuration values are controlled by administrators. The URL protocol validation in `supervise_task()` validates the server URL but this is a different config value (`api.base_url` vs the execution API server URL).

**Remediation:**

Add protocol validation: `base_url = conf.get("api", "base_url", fallback="http://localhost:8080/"); parsed = urlparse(base_url); if parsed.scheme not in ("http", "https"): base_url = "http://localhost:8080/"`

---

#### FINDING-061: Dual parsing paths for StartupDetails (JSON vs msgpack) create potential inconsistency

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | CWE-436 |
| ASVS Sections | 1.5.3 |
| Files | task-sdk/src/airflow/sdk/execution_time/task_runner.py:768-791 |
| Source Reports | 1.5.3.md |
| Related Findings | - |

**Description:**

The application uses two different parsing paths for StartupDetails data: a normal path using msgpack encoding/decoding over socket communication, and a re-exec path using JSON serialization through environment variables. Data flow paths differ: Normal path uses supervisor → msgpack encode → socket → msgpack decode → Pydantic validate, while Re-exec path uses supervisor → Pydantic model_dump_json() → env var → Pydantic validate_json(). This creates potential inconsistencies in number precision (msgpack distinguishes int/float; JSON has single Number type), DateTime handling (custom _msgpack_enc_hook converts Pendulum DateTime to stdlib datetime for msgpack, while JSON uses Pydantic's default datetime serializer), and character encoding (msgpack uses raw bytes; JSON uses UTF-8 with escape sequences). The practical risk is very low because the JSON payload is serialized by model_dump_json() from the same model and the re-exec path is only triggered in controlled scenarios, but per ASVS L3, parser consistency should be verified.

**Remediation:**

Use a single serialization format for both paths. Always serialize to msgpack for the env var: `import base64; os.environ["_AIRFLOW__STARTUP_MSG"] = base64.b64encode(msg.model_dump()).decode()` and then encode via msgpack for consistency. This eliminates the dual JSON/msgpack path for StartupDetails by always using msgpack (base64-encoded for the env var), ensuring parser consistency per ASVS 1.5.3.

---

#### FINDING-062: Cross-field validation rules for IPC messages are not documented

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 2.1.2 |
| Files | task-sdk/src/airflow/sdk/execution_time/comms.py, supervisor.py |
| Source Reports | 2.1.2.md |
| Related Findings | - |

**Description:**

The message models contain multiple fields that should be contextually consistent, but no documentation defines these relationships. For example, in GetXCom model: dag_id + run_id + task_id must reference an actual task instance; map_index is only valid when the task is mapped; In GetPreviousTI, logical_date and state filters interact logically. The only implemented contextual consistency check found is _validate_task_inlets_and_outlets which validates that referenced assets are active. This validation is implemented but the rules are not formally documented. Without formal documentation of contextual consistency rules, it's difficult to verify that all necessary cross-field validations are implemented. New developers may introduce inconsistent data handling.

**Remediation:**

Document business rules such as: When map_index is provided, the referenced task must be a mapped task; When include_prior_dates is True, logical_date context determines the cutoff; All XCom operations must reference a dag_id/run_id/task_id combination belonging to the current DAG run or an explicitly allowed cross-DAG access. Create explicit documentation (or use Pydantic Field descriptions) defining: Valid character sets for identifiers; Maximum lengths for all string fields; Cross-field consistency rules (e.g., map_index validity conditions).

---

#### FINDING-063: GetXComSequenceSlice allows step=0 without validation

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-20 |
| ASVS Sections | 2.2.3 |
| Files | task-sdk/src/airflow/sdk/execution_time/comms.py |
| Source Reports | 2.2.3.md |
| Related Findings | FINDING-060, FINDING-064 |

**Description:**

A task sending `step=0` would cause a `ValueError` when the API attempts to construct a Python slice object. While the exception would be caught and returned as an error, it represents a failure to enforce business logic at the validation layer. The pre-defined rule that step must be non-zero is not checked.

**Remediation:**

Add a Pydantic field_validator to the GetXComSequenceSlice class: `from pydantic import field_validator; @field_validator("step"); @classmethod; def step_must_not_be_zero(cls, v): if v is not None and v == 0: raise ValueError("step must not be zero"); return v`

---

#### FINDING-064: State fields accept arbitrary strings instead of valid enum values

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-20 |
| ASVS Sections | 2.2.3 |
| Files | task-sdk/src/airflow/sdk/execution_time/comms.py |
| Source Reports | 2.2.3.md |
| Related Findings | FINDING-060, FINDING-063 |

**Description:**

The `state` and `states` fields in GetPreviousDagRun, GetTICount, and GetDRCount accept arbitrary strings where they should only accept valid state enum values. This fails to enforce the business rule that state values must be from a predefined set. While the API server would likely reject invalid states, early validation at the IPC boundary would provide faster feedback and reduce unnecessary API calls.

**Remediation:**

Constrain state fields to valid enum values using Literal types: `class GetPreviousDagRun(BaseModel): dag_id: str; logical_date: AwareDatetime; state: Literal["queued", "running", "success", "failed"] | None = None; type: Literal["GetPreviousDagRun"] = "GetPreviousDagRun"`. Apply the same pattern to GetTICount and GetDRCount classes.

---

#### FINDING-065: jinja2.ext.do extension enabled by default expands template execution surface

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-94 |
| ASVS Sections | 1.3.7 |
| Files | task-sdk/src/airflow/sdk/definitions/_internal/templater.py:391 |
| Source Reports | 1.3.7.md |
| Related Findings | - |

**Description:**

The jinja2.ext.do extension is enabled by default in create_template_env, which allows expression statements with side effects in templates (e.g., {% do mylist.append(item) %}). This expands the set of operations templates can perform from 'read/render values' to 'execute statements with side effects'. While the sandbox restricts what methods can be called in sandboxed mode, this compounds the risk in native mode where any method can be called with side effects.

**Remediation:**

Remove jinja2.ext.do from default extensions. Make it opt-in via DAG configuration (jinja_environment_kwargs) only when explicitly needed. Document the security implications of enabling the do extension.

---

#### FINDING-066: Missing invalidate_connection_uri method creates asymmetric cache management

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 13.3.1 |
| Files | task-sdk/src/airflow/sdk/execution_time/cache.py:137-142 |
| Source Reports | 13.3.1.md |
| Related Findings | - |

**Description:**

The cache provides invalidate_variable() for removing variables but has no corresponding invalidate_connection_uri() method. This means there is no way to programmatically remove a single connection from the cache (e.g., when a connection's credentials are rotated or when access is revoked). Stale or revoked connection credentials remain in the cache until TTL expiration (default 15 minutes), during which time they could be used by code that no longer has authorization.

**Remediation:**

Add a symmetric invalidate_connection_uri() method to allow programmatic removal of single connections from the cache when credentials are rotated or access is revoked.

---

#### FINDING-067: No client-side validation of requested secret identifiers enables enumeration attempts

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Sections | 8.2.2 |
| Files | task-sdk/src/airflow/sdk/execution_time/secrets/execution_api.py (get_connection() and get_variable() methods) |
| Source Reports | 8.2.2.md |
| Related Findings | - |

**Description:**

The ExecutionAPISecretsBackend passes any conn_id or key directly to the server without client-side validation. While server-side authorization prevents actual access to unauthorized secrets, the response pattern (returning None for both 'not found' and 'unauthorized') means the task code cannot distinguish between a non-existent secret and one it's not authorized to access. From a BOLA perspective: the server enforces object-level authorization (positive), but the SDK client provides no additional layer of defense. The domain context states that the system must 'prevent unauthorized enumeration of available secrets.' Since the SDK silently returns None for both cases, a malicious task can enumerate connection IDs without receiving explicit denial signals. While actual data access is prevented by server-side authorization, a task can attempt to enumerate secret identifiers without triggering authorization failure signals to the caller. The lack of distinction between 'not found' and 'denied' actually provides defense against enumeration (positive from information leakage perspective) but masks authorization violations from audit/logging perspective.

**Remediation:**

Log authorization failures distinctly from 'not found' responses. Example implementation: if isinstance(msg, ErrorResponse): if msg.status_code == 403: import logging; logger = logging.getLogger(__name__); logger.warning('Authorization denied for connection: %s', conn_id); return None

---

#### FINDING-068: No key expiration or TTL enforcement mechanism

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 11.1.1 |
| Files | task-sdk/src/airflow/sdk/crypto.py |
| Source Reports | 11.1.1.md |
| Related Findings | - |

**Description:**

While Fernet's decrypt() supports a ttl parameter for time-based token expiration, the default value is None (no expiration check). The code does not enforce a maximum TTL for encrypted tokens, meaning encrypted values remain valid indefinitely regardless of when the key was generated. Per NIST SP 800-57 Section 5.3, cryptoperiods should be defined for all key types. However, per the known false positive guidance, key management is delegated to the Airflow server, so this is informational.

**Remediation:**

Document the expected cryptoperiod for Fernet keys and consider implementing a configurable TTL for decryption operations in production environments.

---

#### FINDING-069: Key usage scope not enforced programmatically

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 11.1.2 |
| Files | task-sdk/src/airflow/sdk/crypto.py (get_fernet()) |
| Source Reports | 11.1.2.md |
| Related Findings | - |

**Description:**

A single Fernet key (or key set) is used for all encryption operations across the SDK. There is no programmatic separation between keys used for connection passwords versus variable values versus other potential uses. While this may be acceptable for the current scope, it means compromise of one key compromises all encrypted data types. The get_fernet() function returns a single Fernet instance used for ALL encryption operations without purpose-specific key separation.

**Remediation:**

Consider documenting key usage boundaries and, for future iterations, supporting purpose-specific keys. Example implementation: def get_fernet(purpose: str = "default") -> FernetProtocol: """Get Fernet instance for a specific purpose.""" key_config = f"FERNET_KEY_{purpose.upper()}" if purpose != "default" else "FERNET_KEY". This would allow separation of keys by purpose (connections vs variables) to limit blast radius of key compromise.

---

#### FINDING-070: AES-128 key length used via Fernet rather than AES-256

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Sections | 11.3.2 |
| Files | task-sdk/src/airflow/sdk/crypto.py |
| Source Reports | 11.3.2.md |
| Related Findings | - |

**Description:**

Fernet specifies a fixed 256-bit key that is split into a 128-bit HMAC signing key and a 128-bit AES encryption key. This means the effective encryption strength is AES-128, not AES-256. While AES-128 is still considered secure against classical attacks, NIST guidance for long-term protection and quantum resistance recommends AES-256 (which provides 128 bits of security against Grover's algorithm, versus 64 bits for AES-128). The AES-128 encryption provides approximately 64 bits of security against quantum adversaries using Grover's algorithm. For data that must remain confidential for extended periods, this may be insufficient. However, for the current threat model (protecting secrets in transit between server and task processes), AES-128 remains adequate against classical attacks.

**Remediation:**

This is informational and tied to the broader crypto agility issue (ASVS-1122-HIGH-001). When implementing crypto agility, ensure AES-256-GCM or ChaCha20-Poly1305 are available as options. Implement an AES256GCMBackend class providing 256-bit key strength using cryptography.hazmat.primitives.ciphers.aead.AESGCM.

---

#### FINDING-071: No per-tenant Fernet key scoping in multi-tenant deployments

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 13.3.4 |
| Files | task-sdk/src/airflow/sdk/crypto.py:97-116 |
| Source Reports | 13.3.4.md |
| Related Findings | - |

**Description:**

The Fernet key provisioning uses a single configuration value (core.FERNET_KEY) with no mechanism for per-tenant or per-secret key scoping. In multi-tenant deployments, all tenants' secrets are encrypted with the same key material. If a single tenant's task process is compromised and the Fernet key is extracted from memory/environment, ALL tenants' encrypted secrets become decryptable. In multi-tenant deployments, a key compromise in one tenant's security boundary exposes all tenants' encrypted connections and variables. Key rotation affects all tenants simultaneously, creating operational coupling.

**Remediation:**

For multi-tenant deployments, implement key scoping per tenant or per secret class: @cache def get_fernet(tenant_id: str | None = None) -> FernetProtocol: from airflow.sdk.configuration import conf if tenant_id: fernet_key = conf.get("core", f"FERNET_KEY_{tenant_id}") else: fernet_key = conf.get("core", "FERNET_KEY") # ... rest of initialization

---

#### FINDING-072: No explicit TLS minimum version enforcement in SSL context

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-327 |
| ASVS Sections | 12.1.1 |
| Files | task-sdk/src/airflow/sdk/api/client.py:733-738 |
| Source Reports | 12.1.1.md |
| Related Findings | FINDING-021 |

**Description:**

While Python 3.10+ sets minimum_version = TLSVersion.TLSv1_2 by default in create_default_context(), this behavior is dependent on the Python version and system OpenSSL configuration. An explicit setting makes the security posture auditable and protects against potential regressions in system-level TLS policy (e.g., via OpenSSL config files that re-enable TLS 1.0/1.1).

**Remediation:**

Add explicit TLS version constraints to the SSL context:
```python
@staticmethod
def _get_ssl_context_cached(ca_file: str, ca_path: str | None = None) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=ca_file)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
    if ca_path:
        ctx.load_verify_locations(ca_path)
    return ctx
```

---

#### FINDING-073: Token stored as plain string without SecretStr protection in data model

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-532 |
| ASVS Sections | 10.1.1 |
| Files | task-sdk/src/airflow/sdk/api/datamodels/activities.py:28 |
| Source Reports | 10.1.1.md |
| Related Findings | - |

**Description:**

Token is stored in ExecuteTaskActivity.token as plain str and serialized via Pydantic. If the model is ever serialized for logging, debugging, or error reporting, the token would appear in plaintext. Using pydantic.SecretStr would mask it in repr() and str() outputs. Note: This finding is limited to representation protection only, not the token passing mechanism itself.

**Remediation:**

Change token field type from str to pydantic.SecretStr:
```python
from pydantic import SecretStr

class ExecuteTaskActivity(BaseModel):
    ti: TaskInstance
    path: os.PathLike[str]
    token: SecretStr
    """The identity token for this workload"""
```

---

#### FINDING-074: No allowlist validation for external API server addresses

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-918 |
| ASVS Sections | 13.2.4 |
| Files | task-sdk/src/airflow/sdk/api/client.py:575-600 |
| Source Reports | 13.2.4.md |
| Related Findings | FINDING-095 |

**Description:**

The client accepts any base_url from configuration without validating it against an allowlist of permitted API server addresses. While the client is architecturally constrained to communicate with a single configured endpoint (all paths are relative), there is no explicit allowlist mechanism that validates the configured destination is a known, authorized Airflow API server. In environments with multiple Airflow deployments or in multi-tenant scenarios, a misconfigured or maliciously altered base_url could direct the client (with its bearer token) to communicate with an unauthorized server that mimics the Execution API.

**Remediation:**

Add optional allowlist validation:
```python
ALLOWED_API_HOSTS = conf.get("api", "allowed_execution_api_hosts", fallback=None)

def __init__(self, *, base_url: str | None, dry_run: bool = False, token: str, **kwargs: Any):
    if not dry_run and base_url:
        from urllib.parse import urlparse
        parsed = urlparse(base_url)
        if ALLOWED_API_HOSTS:
            allowed = [h.strip() for h in ALLOWED_API_HOSTS.split(",")]
            if parsed.hostname not in allowed:
                raise ValueError(
                    f"Execution API host '{parsed.hostname}' not in allowed hosts: {allowed}"
                )
```

---

#### FINDING-075: Client allows follow_redirects override via kwargs

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-601 |
| ASVS Sections | 4.1.2 |
| Files | task-sdk/src/airflow/sdk/api/client.py:580-620 |
| Source Reports | 4.1.2.md |
| Related Findings | - |

**Description:**

The Client constructor passes **kwargs to the parent httpx.Client.__init__(). While httpx defaults to follow_redirects=False, there is no explicit prevention of this being overridden via kwargs. If a caller passes follow_redirects=True, the client would silently follow HTTP→HTTPS redirects, masking the cleartext initial request containing the bearer token. Additionally, the raise_on_4xx_5xx response hook only fires on 4xx/5xx responses, not 3xx redirects. A 3xx response from a misconfigured HTTP endpoint would not be caught as an error, potentially causing silent failures rather than clear security-related errors.

**Remediation:**

In Client.__init__, explicitly set and protect follow_redirects:
```python
kwargs.pop("follow_redirects", None)  # Prevent override
super().__init__(
    auth=auth,
    follow_redirects=False,
    ...
)
```

---

#### FINDING-076: Unconditional trust of Refreshed-API-Token response header without validation

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-345 |
| ASVS Sections | 4.1.3 |
| Files | task-sdk/src/airflow/sdk/api/client.py:610-613 |
| Source Reports | 4.1.3.md |
| Related Findings | - |

**Description:**

The client unconditionally trusts the Refreshed-API-Token response header to replace its authentication token. While this requires TLS compromise or a malicious intermediary to exploit, there is no additional validation that: 1) The response comes from the legitimate API server (beyond TLS verification), 2) The new token has expected format/structure, 3) The response that triggered the token refresh was for an appropriate endpoint. If a reverse proxy or CDN in the communication path injected this header (whether intentionally or via misconfiguration), it could replace the client's authentication token with an attacker-controlled value, potentially redirecting subsequent authenticated requests to an attacker's server via the replaced token.

**Remediation:**

Add validation to only accept token refresh from specific endpoints and implement basic format validation. Example: Only accept token refresh if response.url.path ends with "/run" or "/heartbeat", and validate that new_token has minimum length of 32 characters. Log warnings for malformed tokens instead of silently accepting them.

---

#### FINDING-077: Dataclass/attr constructor called with all deserialized fields without explicit field filtering

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 15.3.3 |
| Files | task-sdk/src/airflow/sdk/serde/__init__.py:264-267 |
| Source Reports | 15.3.3.md |
| Related Findings | - |

**Description:**

All keys present in the serialized dict are passed to the target class constructor. While Python's dataclass/attrs constructors naturally reject undeclared fields (raising TypeError), classes that define fields with defaults could have those defaults overridden by attacker-supplied values if the serialized data is tampered with. The impact is limited because: (1) classes must pass the deserialization allowlist, and (2) XCom data originates from trusted task execution via the supervisor. This is a defense-in-depth observation rather than an exploitable vulnerability.

**Remediation:**

For additional defense-in-depth, filter deserialized dict keys against the class's declared fields:
```python
if dataclasses.is_dataclass(cls):
    allowed_fields = {f.name for f in dataclasses.fields(cls) if f.init}
    deserialize_value = {k: v for k, v in deserialize_value.items() if k in allowed_fields}
    return cls(**deserialize_value)
```

---

#### FINDING-078: `BaseXCom.deserialize_value()` lacks type annotation and validation on parameter

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 15.3.5 |
| Files | task-sdk/src/airflow/sdk/bases/xcom.py:258-261 |
| Source Reports | 15.3.5.md |
| Related Findings | - |

**Description:**

The `result` parameter has no type annotation and no `isinstance` check. It relies on duck typing (accessing `.value`). While this is called from controlled contexts (`get_one()` with `XComResult` and `get_all()` with `_XComValueWrapper`), the lack of explicit type enforcement means subclasses or future callers could pass incorrect types without compile-time or runtime checking. This is inconsistent with the pattern in `get_one()` and `_get_xcom_db_ref()` which explicitly validate message types.

**Remediation:**

Add type annotation and validation: `@staticmethod
def deserialize_value(result: XComResult | _XComValueWrapper) -> Any:
    """Deserialize XCom value from str objects."""
    from airflow.sdk.serde import deserialize

    if not hasattr(result, 'value'):
        raise TypeError(f"Expected object with 'value' attribute, got {type(result)}")
    return deserialize(result.value)`

---

#### FINDING-079: Import failure is logged at DEBUG level and execution continues (fail-open pattern)

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 15.2.5 |
| Files | task-sdk/src/airflow/sdk/definitions/callback.py:73-80 |
| Source Reports | 15.2.5.md |
| Related Findings | - |

**Description:**

The fail-open pattern means that a path which CANNOT be validated is still accepted and stored. While the comment provides legitimate justification (runtime availability differs from parse-time), this reduces the effectiveness of the validation as a protective control. An invalid or malicious path that fails to import at definition time will still be stored and potentially executed later. From an ASVS 15.2.5 perspective, this represents a gap in protection around dangerous functionality.

**Remediation:**

Consider adding a stricter mode that can be enabled in security-sensitive deployments. Add configurable STRICT_CALLBACK_VALIDATION environment variable that, when enabled, raises ImportError instead of logging and continuing. Change log level from DEBUG to WARNING in permissive mode to increase visibility of validation failures.

---

#### FINDING-080: Unsynchronized module-level cache dictionary access

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 15.4.1 |
| Files | task-sdk/src/airflow/sdk/execution_time/supervisor.py (near _fetch_remote_logging_conn) |
| Source Reports | 15.4.1.md |
| Related Findings | - |

**Description:**

The module-level dict _REMOTE_LOGGING_CONN_CACHE is accessed without synchronization mechanisms. In the current single-threaded supervisor architecture, this is safe. However, if the module is ever used in a multi-threaded context (e.g., a supervisor managing multiple tasks concurrently via threads), the unsynchronized dict access could lead to lost updates or inconsistent reads. The InProcessTestSupervisor already uses threads, though it doesn't call this function path.

**Remediation:**

Add threading.Lock to protect cache access. Use lock when checking cache membership and when updating cache. Consider double-checked locking pattern to avoid holding lock during I/O operations: use lock to check cache, release lock during fetch, re-acquire lock to update cache.

---

#### FINDING-081: Race condition in test supervisor socket cleanup

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 15.4.1, 15.4.3 |
| Files | task-sdk/src/airflow/sdk/execution_time/supervisor.py (InProcessTestSupervisor._setup_subprocess_socket) |
| Source Reports | 15.4.1.md, 15.4.3.md |
| Related Findings | - |

**Description:**

In InProcessTestSupervisor._setup_subprocess_socket, the main thread writes to self._open_sockets and self.selector while a daemon thread reads the same objects in _handle_socket_comms with no locks protecting concurrent access. The thread.join(0) call does not wait for thread completion, meaning the thread may still be accessing shared state after the context manager exits. In testing scenarios, race conditions could occur between the main thread closing sockets and the daemon thread attempting to use them. The daemon thread may attempt to call self.selector.select() after the main thread has closed the selector or sockets, potentially raising exceptions or accessing already-freed resources. This is test-only code.

**Remediation:**

Use a blocking thread.join() with timeout instead of non-blocking join(0). Signal thread to stop, close requests and child_sock, then call thread.join(timeout=5.0) to wait for thread completion. If thread.is_alive() after join, log a warning that handler thread did not stop within timeout period. Consider using threading events for clean shutdown signaling.

---

#### FINDING-082: TOCTOU race condition in bundle access verification

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 15.4.2 |
| Files | task-sdk/src/airflow/sdk/execution_time/task_runner.py (_verify_bundle_access) |
| Source Reports | 15.4.2.md |
| Related Findings | - |

**Description:**

The _verify_bundle_access function performs separate checks (bundle_path.exists() and os.access()) before the actual file read in BundleDagBag. In a run_as_user impersonation scenario, a symlink at bundle_path could be replaced between the access check and the actual file read, potentially causing the DAG bag to read from a different location. However, this requires local filesystem access and the window is very small. The practical risk is low as an attacker would need write access to the bundle directory on the same machine, which implies existing compromise.

**Remediation:**

The current pattern is acceptable for its stated purpose (informative error messages for impersonation failures). For higher assurance, open the file directly and handle errors using a try-then-catch pattern instead of check-then-act: try opening bundle_path / "some_marker" and catch PermissionError to raise an informative AirflowException.

---

#### FINDING-083: Task-controlled polling interval without minimum enforcement

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 2.4.1 |
| Files | task-sdk/src/airflow/sdk/execution_time/task_runner.py (_handle_trigger_dag_run function (polling loop with time.sleep(drte.poke_interval))) |
| Source Reports | 2.4.1.md |
| Related Findings | - |

**Description:**

The DAG run polling loop uses a task-controlled poke_interval without enforcing a minimum value. A malicious or misconfigured task can set an extremely low interval, creating a tight polling loop that floods the API server with status check requests. Operator sets poke_interval=0.001 → _handle_trigger_dag_run tight loop → SUPERVISOR_COMMS.send(GetDagRunState(...)) every millisecond → API server overload.

**Remediation:**

Enforce a minimum poke interval (e.g., MIN_POKE_INTERVAL = 5.0 seconds) in _handle_trigger_dag_run. Use effective_interval = max(drte.poke_interval, MIN_POKE_INTERVAL) to ensure the polling loop never runs faster than the minimum allowed interval, preventing tight loops that could overload the API server.

---

#### FINDING-084: No Documentation of User-Controllable External Locations

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2, L3 |
| CWE | - |
| ASVS Sections | 13.1.1 |
| Files | task-sdk/src/airflow/sdk/configuration.py:96-101 |
| Source Reports | 13.1.1.md |
| Related Findings | - |

**Description:**

Environment variables `AIRFLOW_CONFIG` and `AIRFLOW_HOME` allow operators to redirect configuration loading to arbitrary filesystem locations. While this is standard behavior, the documentation does not enumerate these as operator-controllable paths that affect the application's behavior, nor does it document security implications (e.g., an attacker with environment variable control can redirect to a malicious config).

**Remediation:**

Document all environment variables that influence external resource locations in a centralized security configuration guide.

---

#### FINDING-085: Configuration File Read Lacks Integrity Verification

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2, L3 |
| CWE | - |
| ASVS Sections | 14.1.2 |
| Files | task-sdk/src/airflow/sdk/configuration.py:140-146 |
| Source Reports | 14.1.2.md |
| Related Findings | - |

**Description:**

Configuration files are read without any integrity verification (signatures, checksums, or file permission checks). The absence of both the documentation AND the control means: a tampered configuration file would be loaded without detection, no file permission validation ensures the config isn't world-writable, and no signature verification ensures the config came from a trusted source. If an attacker can modify airflow.cfg (e.g., via a shared filesystem, supply chain attack, or misconfigured permissions), they could redirect secrets backends, change logging levels to expose sensitive data, or modify security-relevant settings.

**Remediation:**

Document integrity requirements for configuration files and implement file permission validation to verify config file has restrictive permissions, checking that mode does not allow world-readable or world-writable access. Log warning if config file has insecure permissions and return false. Example implementation provided using stat module to validate permissions are not 'stat.S_IWOTH' or 'stat.S_IROTH'.

---

#### FINDING-086: callsite_parameters Configuration Defaults to Empty List

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 16.2.1 |
| Files | task-sdk/src/airflow/sdk/log.py:99 |
| Source Reports | 16.2.1.md |
| Related Findings | - |

**Description:**

The callsite parameters (which provide "where" metadata such as module, function, line number) default to an empty list. If not explicitly configured, log entries may lack location metadata needed for investigation. Log entries may not include sufficient "where" information for timeline investigations unless the operator explicitly configures this setting.

**Remediation:**

Consider providing a non-empty default that includes at least `module` and `func_name`.

#### FINDING-087: No Explicit UTC or Timezone Configuration Visible in Logging Setup

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 16.2.2 |
| Files | task-sdk/src/airflow/sdk/log.py:69-116 |
| Source Reports | 16.2.2.md |
| Related Findings | - |

**Description:**

The logging configuration delegates timestamp handling entirely to `structlog_processors()` from the shared library without explicitly enforcing UTC or requiring timezone offset in timestamps. The configuration parameters passed to `configure_logging` from the shared module do not include a timezone specification. If the shared `structlog_processors` function does not enforce UTC or timezone offset, logs from distributed systems may have inconsistent timestamps, making timeline correlation impossible during incident investigation, particularly during daylight saving time transitions.

**Remediation:**

Explicitly configure timestamps to use UTC: `structlog.processors.TimeStamper(fmt="iso", utc=True)`

---

#### FINDING-088: Remote Log Processor Injection via Handler Attribute

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 16.2.3 |
| Files | task-sdk/src/airflow/sdk/log.py:62-63 |
| Source Reports | 16.2.3.md |
| Related Findings | - |

**Description:**

The code unconditionally trusts processors provided by the remote log handler object. If the remote handler is loaded from an untrusted or misconfigured source, its processors could modify log events in unexpected ways (e.g., removing security-relevant fields, adding exfiltration channels). A compromised or misconfigured remote log handler could inject processors that suppress or redirect security events.

**Remediation:**

Validate that remote processors conform to expected interfaces and do not modify critical log fields.

---

#### FINDING-089: No Log Integrity Verification Mechanism

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 16.4.2 |
| Files | task-sdk/src/airflow/sdk/log.py |
| Source Reports | 16.4.2.md |
| Related Findings | - |

**Description:**

The logging infrastructure does not implement any log integrity protection such as: append-only file modes, cryptographic hash chains, digital signatures on log entries, or immutable storage flags. While this may be handled at a higher level (e.g., filesystem-level protections or the remote log system), the local file logging path has no tamper-evidence mechanism. If an attacker gains access to the log directory, they can silently modify or delete log entries without detection.

**Remediation:**

Consider adding log file integrity verification, such as a hash chain processor. Example implementation: import hashlib; class LogIntegrityProcessor with __init__ setting _prev_hash = b'\x00' * 32 and __call__ method computing current_hash = hashlib.sha256(self._prev_hash + entry_bytes).digest() and adding event_dict['_integrity_hash'] = current_hash.hex()[:16]. Long-term: implement log integrity verification via hash chains or digital signatures for local log files, consider append-only log file semantics using O_APPEND flags and potentially immutable attributes where the OS supports it.

---

#### FINDING-090: No Explicit Transport Security Verification for Remote Logging

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 16.4.3 |
| Files | task-sdk/src/airflow/sdk/log.py:151-165 |
| Source Reports | 16.4.3.md |
| Related Findings | - |

**Description:**

The remote logging handler is loaded dynamically without any verification that it implements secure transport (TLS). The security of log transmission is entirely delegated to the handler implementation and connection configuration, with no enforcement at the SDK level. If a remote log handler is configured without TLS (e.g., plain HTTP), logs containing potentially sensitive metadata would be transmitted in cleartext.

**Remediation:**

Add documentation requirements and optional transport security validation. Add verification to handler discovery or connection setup:
```python
# Add to handler discovery or connection setup
if handler and hasattr(handler, 'verify_secure_transport'):
    if not handler.verify_secure_transport():
        log.warning("remote_log_handler_insecure_transport")
```
Validate remote handler transport security during handler loading or provide configuration warnings for insecure setups.

---

#### FINDING-091: Raw IPC Message Bodies Logged on Decode Failure

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 16.5.1 |
| Files | task-sdk/src/airflow/sdk/execution_time/supervisor.py:422-424 |
| Source Reports | 16.5.1.md |
| Related Findings | - |

**Description:**

Raw IPC message bodies are logged when decode failures occur. If the body contains sensitive data from task execution (e.g., XCom values with credentials, variable values from SetXCom, PutVariable, or GetConnection messages), they would appear in supervisor logs. While these are supervisor-side logs (not typically user-facing), they may be aggregated in centralized logging systems with broader access.

**Remediation:**

Replace logging of the full request body with only metadata such as request_id and body_type. Change log.exception('Unable to decode message', body=request.body) to log.exception('Unable to decode message', request_id=request.id, body_type=type(request.body).__name__).

---

#### FINDING-092: Full Stack Traces with Potential Secrets Forwarded to Task Logs

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 16.5.1 |
| Files | task-sdk/src/airflow/sdk/execution_time/supervisor.py:268-278 |
| Source Reports | 16.5.1.md |
| Related Findings | - |

**Description:**

Full stack traces written to stderr are captured by the supervisor and forwarded to task logs. Stack frames could contain function parameter values including connection strings, API keys, or tokens that happened to be in-scope at the time of the exception. The last-chance exception handler in _fork_main() writes complete tracebacks to last_chance_stderr, which is captured by the supervisor's stderr socket and forwarded to task logs via _create_log_forwarder.

**Remediation:**

Apply the secrets masker to stderr output before logging, or limit the stack trace to frame locations without local variable values. Use traceback.format_exception() to print only the traceback structure without local variables, or apply redaction before writing to stderr.

---

#### FINDING-093: Business Logic Limits Defined in Configuration Without Consolidated Documentation

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 2.1.3 |
| Files | task-sdk/src/airflow/sdk/execution_time/supervisor.py:137-145 |
| Source Reports | 2.1.3.md |
| Related Findings | - |

**Description:**

Business logic limits (heartbeat timeout, max failed heartbeats, overtime threshold, socket cleanup timeout, missing_dag_retries, missing_dag_retry_delay) are scattered across two files without consolidated documentation specifying per-user vs. global enforcement semantics. For example, MAX_FAILED_HEARTBEATS applies per-task-instance but there is no documented global limit on concurrent failing tasks. Resource limits mentioned in the domain context (memory, CPU time, API calls) have no visible enforcement or documentation in this code.

**Remediation:**

Create a dedicated documentation section or constants file that: 1. Lists all business logic limits with their scope (per-user, per-task, global) 2. Documents the expected range of valid values 3. Specifies the security implications of misconfiguration. Example: Create a limits_documentation.py or add comprehensive documentation at module top listing Per-Task-Instance Limits (HEARTBEAT_TIMEOUT, MAX_FAILED_HEARTBEATS, TASK_OVERTIME_THRESHOLD, missing_dag_retries), Global Limits (MIN_HEARTBEAT_INTERVAL, SOCKET_CLEANUP_TIMEOUT), and limits delegated to API server (Concurrent task execution count, Resource quotas, Maximum retry counts).

---

#### FINDING-094: No Rate Limiting on IPC Requests From Task Process to Supervisor

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Section(s) | 2.4.2 |
| Files | task-sdk/src/airflow/sdk/execution_time/supervisor.py:handle_requests(), task-sdk/src/airflow/sdk/execution_time/supervisor.py:_handle_request() |
| Source Reports | 2.4.2.md |
| Related Findings | - |

**Description:**

A task process (through malicious operator code or runaway logic) can flood the supervisor with IPC requests at maximum throughput. Each request results in an API call to the server (e.g., GetVariable, GetXCom, SetXCom, GetConnection). This could: 1) Exhaust API server resources, impacting other tasks and users, 2) Saturate network bandwidth between worker and API server, 3) Cause the supervisor's monitoring loop to starve heartbeats (since request handling is synchronous). While MIN_HEARTBEAT_INTERVAL limits heartbeat frequency, it does not limit the frequency of other operations.

**Remediation:**

Implement per-operation-type rate limiting or a global request budget. Example: Add a sliding window rate limiter that tracks request counts per message type with configurable limits (e.g., 1000 requests per 60-second window). Use a _check_rate_limit() method to validate requests before processing and log warnings when limits are exceeded.

---

#### FINDING-095: Missing server URL validation in supervise_callback() compared to supervise_task()

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-918 |
| ASVS Section(s) | 1.3.6 |
| Files | task-sdk/src/airflow/sdk/execution_time/callback_supervisor.py:244 |
| Source Reports | 1.3.6.md |
| Related Findings | FINDING-074 |

**Description:**

The supervise_callback() function in callback_supervisor.py passes the server parameter directly to _ensure_client() without validating the URL scheme or netloc. This is inconsistent with supervise_task() in supervisor.py which performs URL validation (HTTP/HTTPS scheme, valid netloc). If an attacker could control the server parameter, they could redirect API requests to an arbitrary host. However, this is mitigated by the fact that: (1) the server parameter is provided by the executor infrastructure, not user input, (2) the Client class uses TLS verification via certifi.where(), and (3) the authentication token would not be valid for other servers. This represents a Type B gap where the control EXISTS in supervise_task() but is NOT CALLED in supervise_callback().

**Remediation:**

Apply the same server URL validation in supervise_callback() as exists in supervise_task() for defense-in-depth and consistency. Add validation to check that the URL scheme is http or https and that a valid netloc is present before passing to _ensure_client(). Example code: if server: from urllib.parse import urlparse; parsed = urlparse(server); if parsed.scheme not in ('http', 'https'): raise ValueError(f'Invalid server URL scheme: {parsed.scheme}'); if not parsed.netloc: raise ValueError(f'Invalid server URL: missing host')

---

#### FINDING-096: Port value not validated against valid range (0-65535)

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 1.4.2 |
| Files | task-sdk/src/airflow/sdk/definitions/connection.py:264 |
| Source Reports | 1.4.2.md |
| Related Findings | - |

**Description:**

The `port` value is converted to an integer but not validated against the valid port range (0-65535). While this cannot cause a memory-level integer overflow in Python, passing an invalid port number (e.g., 99999 or -1) to downstream connection libraries could cause unexpected behavior. This is a logical validation gap rather than a memory safety issue. The `port` field in the `Connection` class is typed as `int | None` and comes from trusted Airflow connection configuration (not end-user input), so the practical risk is minimal.

**Remediation:**

Consider adding port range validation (0-65535) in `Connection.from_json()` to catch configuration errors early, even though this is not a memory safety issue in Python.

---

#### FINDING-097: Cryptographic Error Message May Reveal Key Format Details

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Section(s) | 11.2.5 |
| Files | task-sdk/src/airflow/sdk/crypto.py:115 |
| Source Reports | 11.2.5.md |
| Related Findings | - |

**Description:**

The exception message from Fernet() or MultiFernet() may include details about why key parsing failed (e.g., "Fernet key must be 32 url-safe base64-encoded bytes"), which could help an attacker understand key format requirements during a targeted attack. The error requires access to configuration (already implies system compromise), the Fernet key format is publicly documented, and the message only appears during initialization failure.

**Remediation:**

Replace with a generic error message that logs the details at debug level:

```python
except (ValueError, TypeError) as value_error:
    log.debug("Fernet key initialization failed", error=str(value_error))
    raise AirflowException("Could not create Fernet object: invalid key configuration")
```

---

#### FINDING-098: Incomplete Memory Encryption Protection for Sensitive Data

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Section(s) | 11.7.1 |
| Files | task-sdk/src/airflow/sdk/execution_time/supervisor.py:404-417 |
| Source Reports | 11.7.1.md |
| Related Findings | - |

**Description:**

While PR_SET_DUMPABLE=0 prevents same-UID ptrace/memory access on Linux, it does NOT provide full memory encryption. A root-level attacker or physical memory access (cold boot attack, DMA) can still read secrets. Additionally, this control is Linux-only and is a no-op on macOS and other platforms. The supervisor process holds decrypted secrets (Fernet key, connection passwords, variable values) in plaintext in process memory. Per the domain context, this is acknowledged as intentional: the cache exists within the supervisor process boundary which already has access to decrypted secrets. Full memory encryption (Intel SGX, AMD SEV, ARM CCA) is a deployment infrastructure concern, not an application-level control.

**Remediation:**

Full memory encryption requires platform-level support:
- **Deployment level:** Use AMD SEV-SNP or Intel TDX VMs for workloads requiring memory encryption
- **Application level:** Consider using memory-safe wrappers that zero secrets after use (partial mitigation)
```python
import ctypes
import sys

def secure_zero(buffer: bytearray) -> None:
    """Securely zero memory to minimize exposure window."""
    ctypes.memset(ctypes.addressof((ctypes.c_char * len(buffer)).from_buffer(buffer)), 0, len(buffer))
```

---

#### FINDING-099: Connection credentials persist in memory without TTL-based eviction

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3, L2 |
| CWE | - |
| ASVS Section(s) | 11.7.2, 13.2.2, 14.2.2, 14.2.7 |
| Files | task-sdk/src/airflow/sdk/execution_time/supervisor.py:833 |
| Source Reports | 11.7.2.md, 13.2.2.md, 14.2.2.md, 14.2.7.md |
| Related Findings | - |

**Description:**

Connection credentials (passwords, tokens) fetched from API are stored in module-level dict _REMOTE_LOGGING_CONN_CACHE and persist for the entire supervisor process lifetime without clearing or zeroing. If the supervisor runs multiple tasks sequentially (or in Celery worker mode with multiple tasks), credentials accumulate without eviction, extending the exposure window beyond what is strictly necessary. Per domain context, this is intentional as the cache exists within the supervisor process boundary, but a TODO comment acknowledges this needs improvement.

**Remediation:**

Implement TTL-based cache eviction to bound the lifetime of credential exposure in memory. Add timestamp tracking to cached entries and evict entries older than a configurable TTL (e.g., 5 minutes). Example: Create a _CachedConn NamedTuple with conn and cached_at fields, check age on retrieval, and delete expired entries.

---

#### FINDING-100: Execution API server URL validation accepts plaintext HTTP without warning

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 12.3.1 |
| Files | task-sdk/src/airflow/sdk/execution_time/supervisor.py:1220-1228, task-sdk/tests/task_sdk/execution_time/test_supervisor.py:143-145 |
| Source Reports | 12.3.1.md |
| Related Findings | - |

**Description:**

The supervisor explicitly allows unencrypted HTTP connections to the Execution API server without logging warnings. When http:// is used, sensitive data is transmitted in cleartext: Task identity JWT tokens (enabling impersonation), Connection credentials (passwords, API keys), Variable values (potentially containing secrets), XCom data, and Task state transitions. If the Execution API server URL is configured with http:// (e.g., [api] execution_api_url = http://airflow-api:8080), all task traffic occurs without encryption, exposing tokens and secrets to network-position attackers.

**Remediation:**

Option 1 - Warning: Add warning log when HTTP is used: if parsed_url.scheme == "http": log.warning("Execution API connection is NOT encrypted. Bearer tokens and secrets will be transmitted in cleartext. Use https:// in production environments.", server=server). Option 2 - Configurable Enforcement: allow_insecure = conf.getboolean("api", "allow_insecure_execution_api", fallback=False); if parsed_url.scheme == "http" and not allow_insecure: raise ValueError(f"Invalid execution API server URL '{server}': URL must use https:// scheme in production. Set [api] allow_insecure_execution_api = True to override (NOT recommended).")

---

#### FINDING-101: Connection pool limits are hardcoded and behavior at limit is not documented

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Section(s) | 13.1.2 |
| Files | task-sdk/src/airflow/sdk/execution_time/supervisor.py:866-867 |
| Source Reports | 13.1.2.md |
| Related Findings | - |

**Description:**

Connection pool limits are defined in code but: 1. Limits are hardcoded rather than configurable via Airflow configuration, 2. Behavior when connection limit is reached (httpx blocks/queues requests) is not documented, 3. No fallback or recovery mechanisms are documented, 4. The Client class constructor (used directly in tests) doesn't enforce any limits. Without documented connection pool behavior: Operators cannot tune connection limits for their deployment, slow API responses could exhaust all 10 connections blocking heartbeats, no documented fallback mechanism for connection exhaustion scenarios, and risk of denial of service conditions under load.

**Remediation:**

Code remediation: Make connection limits configurable via Airflow configuration using conf.getint for execution_api_max_connections (fallback=10) and execution_api_max_keepalive_connections (fallback=1). Documentation remediation: Add Connection Pool Management section to concepts.rst documenting: maximum connections (10 concurrent, configurable), maximum keepalive connections (1, configurable), behavior at limit (requests wait in queue), timeout (subject to execution_api_timeout), and fallback (task terminated after max_failed_heartbeats failures if heartbeat timeouts occur).

---

#### FINDING-102: Resource management strategies are well-implemented but not formally documented

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Section(s) | 13.1.3 |
| Files | task-sdk/docs/concepts.rst:documentation gap |
| Source Reports | 13.1.3.md |
| Related Findings | - |

**Description:**

The Task SDK implements comprehensive resource management strategies in code with excellent test coverage, but they are embedded in implementation rather than in formal documentation accessible to operators. The code contains well-designed strategies for: Timeout settings (API_TIMEOUT, HEARTBEAT_TIMEOUT, SOCKET_CLEANUP_TIMEOUT, TASK_OVERTIME_THRESHOLD), Retry logic (API_RETRIES with exponential backoff, _should_retry_api_request, MAX_FAILED_HEARTBEATS), Resource release procedures (_cleanup_open_sockets, _ensure_client, socket on_close callbacks), and Failure handling (heartbeat failures, API 404/409/410 termination, signal escalation). While the strategies are well-implemented and tested, the lack of formal documentation means operators may not understand resource management behavior, cannot properly plan capacity or tune for their deployment, troubleshooting is more difficult without documented failure modes, and compliance verification requires code analysis rather than documentation review.

**Remediation:**

Add a comprehensive 'Resource Management Strategies' section to concepts.rst documenting: Connection Management (HTTP(S) via httpx, connection pool with maximum 10 concurrent connections, 1 keepalive connection, queueing behavior at limit), Timeout Settings (API request timeout, heartbeat interval), Retry Logic (heartbeat retries up to max_failed_heartbeats, API retries with exponential backoff, retry conditions for 5xx only, back-off algorithm), Failure Handling (heartbeat failures, process overtime, signal escalation SIGINT→SIGTERM→SIGKILL, API errors), Resource Release (socket cleanup after socket_cleanup_timeout, client cleanup, process cleanup with file descriptors and sockets closed in finally blocks), and IPC Supervisor↔Task Runner details (Unix domain socket, selector timeout, resource release procedures, failure handling).

---

#### FINDING-103: Connection pool limits not applied by default in Client class

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Section(s) | 13.2.6 |
| Files | task-sdk/src/airflow/sdk/api/client.py:530 |
| Source Reports | 13.2.6.md |
| Related Findings | - |

**Description:**

Connection pool limits (max_connections, max_keepalive_connections) are only applied when Client is created through the _ensure_client() helper. If Client is instantiated directly (e.g., by provider packages or future code paths), the httpx defaults (100 max connections, 20 keepalive) apply instead of the documented configuration. This creates inconsistency in resource utilization behavior.

**Remediation:**

Add default limits matching production configuration in Client.__init__():

```python
class Client(httpx.Client):
    _DEFAULT_LIMITS = httpx.Limits(max_keepalive_connections=1, max_connections=10)
    
    def __init__(self, *, base_url: str | None, dry_run: bool = False, token: str, **kwargs: Any):
        kwargs.setdefault("limits", self._DEFAULT_LIMITS)
        kwargs.setdefault("timeout", API_TIMEOUT)
        # ...
```

---

#### FINDING-104: SUPERVISOR_COMMS IPC socket lacks configurable timeout

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Section(s) | 13.2.6 |
| Files | task-sdk/src/airflow/sdk/execution_time/task_runner.py |
| Source Reports | 13.2.6.md |
| Related Findings | - |

**Description:**

The SUPERVISOR_COMMS IPC socket communication lacks explicitly documented and configurable timeout and retry parameters. The socket reads (_read_frame()) block indefinitely until data arrives. If the supervisor process dies without cleanly closing the socket (e.g., SIGKILL), the task runner could block indefinitely on a socket read until the OS detects the broken connection. This is mitigated by the supervisor's signal escalation logic and the operating system's TCP/socket keepalive, but the behavior is not explicitly configurable or documented.

**Remediation:**

Add configurable socket timeouts:

```python
socket_timeout = conf.getfloat("workers", "supervisor_comms_timeout", fallback=300.0)
self.socket.settimeout(socket_timeout)
```

---

#### FINDING-105: SDK version information included in User-Agent header

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Section(s) | 13.4.6 |
| Files | task-sdk/src/airflow/sdk/api/client.py:544 |
| Source Reports | 13.4.6.md |
| Related Findings | - |

**Description:**

The Task SDK includes detailed version information (SDK version and Python version) in the User-Agent header when communicating with the Airflow API server. The version information flows from __version__ and sys.version_info to the User-Agent header in API server requests, which could potentially be logged or reflected by the server. However, this is internal communication between the SDK and its trusted API server over authenticated TLS connections, not exposure to external users. This is standard HTTP client identification behavior.

**Remediation:**

If defense-in-depth is desired, the User-Agent could be made generic by removing version details: headers={'user-agent': 'apache-airflow-task-sdk', 'airflow-api-version': API_VERSION}. However, this is typically considered acceptable for internal service-to-service communication and aids debugging.

---

#### FINDING-106: SecretCache Expired Entries Persist in Memory

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2, L3 |
| CWE | - |
| ASVS Section(s) | 14.2.2, 13.2.6 |
| Files | task-sdk/src/airflow/sdk/execution_time/cache.py:100-130 |
| Source Reports | 14.2.2.md, 13.2.6.md |
| Related Findings | - |

**Description:**

The TTL in SecretCache is passive (checked only on read). Expired entries containing passwords/secrets persist in memory until they are next accessed. There is no background eviction mechanism, meaning in scenarios where many different connections are fetched but rarely re-accessed, their credentials remain in shared memory indefinitely. The _get() method only checks expiration when a key is accessed, leaving expired entries in the multiprocessing shared dict.

**Remediation:**

Add a max_size configuration parameter:

```python
max_size = conf.getint(section="secrets", key="cache_max_size", fallback=1000)
cls._max_size = max_size

@classmethod
def _save(cls, key, value, prefix, team_name=None):
    if cls._cache is not None:
        if len(cls._cache) >= cls._max_size:
            cls._evict_expired()
        team = cls._TEAM_PATTERN.format(team_name) if team_name else ""
        cls._cache[f"{prefix}{team}{key}"] = cls._CacheValue(value)
```

---

#### FINDING-107: Connection passwords stored as plaintext in URI format in shared multiprocessing dict

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 14.2.4 |
| Files | task-sdk/src/airflow/sdk/execution_time/cache.py:130 |
| Source Reports | 14.2.4.md |
| Related Findings | - |

**Description:**

Connection passwords are stored as plaintext in the URI string within the shared multiprocessing dict. While this is within the supervisor's process boundary (acknowledged in known false positives), the passwords are stored in a cleartext format that would be visible if the process memory were dumped. The supervisor process is made non-dumpable on Linux via `_make_process_nondumpable()`, which mitigates this.

**Remediation:**

This is acknowledged as intentional per domain context. The cache exists within the supervisor process boundary which already has access to decrypted secrets. The supervisor process is made non-dumpable on Linux via `_make_process_nondumpable()` which provides mitigation. No immediate action required.

---

#### FINDING-108: Callback kwargs may contain sensitive data logged on exception

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 14.2.4 |
| Files | task-sdk/src/airflow/sdk/execution_time/callback_supervisor.py:114 |
| Source Reports | 14.2.4.md |
| Related Findings | - |

**Description:**

If a callback receives sensitive data in its kwargs (e.g., connection credentials in `context` dict) and fails before those secrets are registered with the masker (via `mask_secret()`), the raw values could appear in log output. The `mask_logs` processor only redacts previously registered secrets. Severity is LOW because: 1) The `mask_logs` processor provides defense-in-depth for registered secrets, 2) The callback subprocess has limited access (only `GetConnection` and `GetVariable` from supervisor), 3) Per domain false positive guidance, secrets masking using string replacement is intentional as defense-in-depth, 4) Callbacks typically receive context with masked values from prior task execution.

**Remediation:**

Redact the kwargs before logging, or limit logged content. Example: Log only the keys of callback_kwargs rather than the full values:
```python
except Exception as e:
    error_msg = f"Callback execution failed: {type(e).__name__}: {str(e)}"
    log.exception(
        "Callback execution failed",
        callback_path=callback_path,
        callback_kwargs_keys=list(callback_kwargs.keys()),  # Log keys only, not values
        error_msg=error_msg,
    )
    return False, error_msg
```

---

#### FINDING-109: Startup Message Environment Variable Not Cleared After Consumption

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Section(s) | 14.2.7 |
| Files | task-sdk/src/airflow/sdk/execution_time/task_runner.py:508 |
| Source Reports | 14.2.7.md |
| Related Findings | - |

**Description:**

The serialized startup message remains in the environment variable _AIRFLOW__STARTUP_MSG for the lifetime of the re-executed process. While the StartupDetails doesn't typically contain raw secrets, it does contain task metadata and context that has no explicit cleanup. The Kerberos cache is explicitly cleared (KRB5CCNAME), but _AIRFLOW__STARTUP_MSG is never cleared after consumption.

**Remediation:**

Clear the environment variable after consumption in the get_startup_details() function by adding os.environ.pop('_AIRFLOW__STARTUP_MSG', None) after reading the value, similar to how KRB5CCNAME is handled.

---

#### FINDING-110: Explicit Exclusion of attrs 25.2.0 Suggests Known Issue Without Documentation

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 15.2.1 |
| Files | task-sdk/pyproject.toml:57 |
| Source Reports | 15.2.1.md |
| Related Findings | - |

**Description:**

The exclusion of `attrs==25.2.0` suggests a known issue with this version, but there is no inline comment or documentation explaining whether this is a security issue or a compatibility bug. Without documentation, it's unclear whether this exclusion addresses a security vulnerability or a functional bug. If security-related, this should be tracked in an SBOM/vulnerability record.

**Remediation:**

Add a comment explaining the exclusion: `# attrs 25.2.0 excluded due to [reason/CVE/issue link]` followed by the dependency specification.

---

#### FINDING-111: Dry-Run Handler Returns Fake Task Context in Production Code

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 15.2.3, 13.4.2 |
| Files | task-sdk/src/airflow/sdk/api/client.py:533-553 |
| Source Reports | 15.2.3.md, 13.4.2.md |
| Related Findings | - |

**Description:**

The `dry_run` parameter in the Client constructor enables a noop_handler that bypasses all API calls and returns fake responses without authentication. If a caller accidentally passes `dry_run=True` to the Client in production, all API interactions are bypassed. However, this requires explicit code changes—not a configuration toggle. The `dry_run` mode is only activated programmatically via constructor parameter and is guarded by the XOR check `if (not base_url) ^ dry_run`. It cannot be enabled by misconfiguring a config file. The `unit_test_mode` in configuration.py is similarly a deliberate code path.

**Remediation:**

Consider adding a runtime guard that checks for production environment:
```python
if dry_run and os.environ.get("AIRFLOW_ENV") == "production":
    raise RuntimeError("dry_run mode is not permitted in production environments")
```

---

#### FINDING-112: DAG.test() Method and Development Utilities in Production Class

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 15.2.3 |
| Files | task-sdk/src/airflow/sdk/definitions/dag.py:594-806, task-sdk/src/airflow/sdk/definitions/dag.py:808-890 |
| Source Reports | 15.2.3.md |
| Related Findings | - |

**Description:**

The DAG.test() method and its helper _run_task() are development/testing utilities included in the production DAG class. The _run_task function is explicitly documented as only meant for the dag.test function. DAG.test() imports unittest.mock.patch, performs direct database operations bypassing normal security controls, runs tasks without proper subprocess isolation, and manipulates environment variables directly. While dag.test() is a documented DAG author utility and not an attack surface in production deployments, its inclusion in the production library means the production package carries unnecessary test/development code and imports, and if accidentally invoked in production it bypasses the normal supervisor isolation model.

**Remediation:**

Consider moving dag.test() to a separate development-only module that isn't loaded in worker contexts, or add a runtime guard that prevents dag.test() from executing in production worker processes by checking for AIRFLOW__CORE__EXECUTOR environment variable and raising a RuntimeError if AIRFLOW_TEST_MODE is not set.

---

#### FINDING-113: No Hash Verification for Build Dependencies

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Section(s) | 15.2.4 |
| Files | task-sdk/pyproject.toml:100-108 |
| Source Reports | 15.2.4.md |
| Related Findings | - |

**Description:**

While build dependencies are version-pinned (good), they lack hash verification. An attacker who compromises PyPI could substitute a malicious package at the same version. Build-time supply chain attack could inject malicious code during package builds.

**Remediation:**

Use hash-pinned requirements for build dependencies or enable hash checking in the build tool configuration.

---

#### FINDING-114: Hostname Used for Logging Without Validation

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 15.3.4 |
| Files | task-sdk/src/airflow/sdk/api/client.py:100-117, task-sdk/src/airflow/sdk/execution_time/task_runner.py:_prepare() |
| Source Reports | 15.3.4.md |
| Related Findings | - |

**Description:**

The hostname obtained via `get_hostname()` is sent to the API server in heartbeats and task start messages (`TIEnterRunningPayload`). This value is used for logging and identification but could be manipulated by setting `hostname_callable` in configuration to return arbitrary values. This affects logging accuracy only. The hostname is not used for security decisions within the SDK itself.

**Remediation:**

This is informational. The API server should validate hostnames if used for security decisions.

---

#### FINDING-115: No per-message digital signatures for sensitive task state transitions

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Section(s) | 4.1.5 |
| Files | task-sdk/src/airflow/sdk/api/client.py:475, task-sdk/src/airflow/sdk/execution_time/supervisor.py:N/A |
| Source Reports | 4.1.5.md |
| Related Findings | - |

**Description:**

The Task SDK communicates highly sensitive operations to the Execution API server (task state changes, XCom data containing credentials, connection retrieval) without per-message digital signatures. While transport-level TLS is enforced and JWT tokens authenticate the caller, there is no cryptographic binding between the message content and the authenticated identity that would detect message tampering at application-level intermediaries. In environments with TLS-terminating proxies, load balancers, or service meshes that inspect/modify HTTP bodies, message integrity cannot be cryptographically verified end-to-end. This is a Level 3 requirement and the risk is mitigated by TLS and the deployment model. The IPC layer (supervisor ↔ task runner) does not require per-message signatures because communication occurs over a Unix socketpair created by the parent process, messages do not traverse any network boundary or intermediate system, and the Unix kernel enforces socket isolation.

**Remediation:**

For environments requiring ASVS Level 3 compliance, consider adding HMAC-SHA256 signatures to sensitive API requests (task state transitions, XCom writes) using a shared secret or asymmetric signing. Example implementation: import hashlib, hmac, and time; create a sign_request function that generates a timestamp, constructs a message from method/path/timestamp/body, computes HMAC-SHA256 signature, and adds X-Airflow-Signature and X-Airflow-Timestamp headers to the request.

---

#### FINDING-116: Client does not explicitly clear token from memory after task completion

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 7.4.1 |
| Files | task-sdk/src/airflow/sdk/api/client.py:N/A |
| Source Reports | 7.4.1.md |
| Related Findings | - |

**Description:**

After task execution completes and the subprocess exits, the token remains in the supervisor's memory until the Client object is garbage collected. Token assigned at Client init → stored in BearerAuth.token → remains in memory until GC. For the normal subprocess flow, this is mitigated because the subprocess exits (clearing its memory). For InProcessTestSupervisor (testing only), tokens may persist longer than necessary. This is LOW severity because: 1) The subprocess architecture means the task runner process exits, clearing all memory; 2) The supervisor process already holds the token (it's within its trust boundary); 3) Token expiration on the server side limits the window of exposure; 4) This pattern is explicitly called out in the false positive patterns regarding hardcoded token passing in IPC messages.

**Remediation:**

For defense-in-depth, the supervisor could explicitly clear the token reference after task completion: def _cleanup_after_task(self): if hasattr(self, '_client') and self._client: self._client.auth = BearerAuth("")

#### FINDING-117: Authorization boundaries between SDK operations rely entirely on server-side enforcement without SDK-level documentation of expected access control rules

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 8.1.1 |
| **Files** | task-sdk/src/airflow/sdk/api/client.py:180-550 |
| **Source Reports** | 8.1.1.md |
| **Related** | - |

**Description:**

The Client class exposes operations across multiple resource types (TaskInstances, Connections, Variables, XComs, Assets, DagRuns, HITLDetails) with no SDK-level documentation of which operations a given token is authorized to perform. While the server is expected to enforce authorization, the SDK code does not document or validate authorization expectations. Without documented authorization boundaries, developers and auditors cannot verify whether the Execution API properly restricts: A task's ability to access connections it doesn't need, Cross-DAG variable access, XCom access across task boundaries, Unauthorized DAG triggering.

**Remediation:**

Add authorization documentation (e.g., in a SECURITY.md or architecture decision record) that specifies: Token scope: what resources a task-specific token can access, Data isolation: whether tasks can access cross-DAG resources, Operation restrictions: which operations are allowed per token type. Example: Task Execution Tokens - Scoped to a single task instance (dag_id, task_id, run_id, try_number), Can read: own connections, own variables, own XComs, upstream XComs in same DAG, Can write: own XComs, own task state, Cannot: access other DAGs' resources, modify connections, modify other tasks' state. Add docstrings documenting authorization requirements for each operation.

---

#### FINDING-118: No documentation of field-level access restrictions for connection credentials and sensitive data

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Section(s)** | 8.1.2 |
| **Files** | task-sdk/src/airflow/sdk/definitions/connection.py:1-300 |
| **Source Reports** | 8.1.2.md |
| **Related** | - |

**Description:**

The Connection class exposes all fields (including password, extra) without documenting field-level access restrictions. When connections are retrieved via the API, there's no SDK-level documentation specifying whether: Read access to password field requires elevated permissions, Write access to connection fields is restricted by role, or Field visibility changes based on connection state or type. Without field-level access documentation, it's unclear whether the Execution API returns full connection details (including passwords) to all tasks, or whether field-level filtering is applied based on the requesting task's authorization level.

**Remediation:**

Document field-level access rules, particularly for sensitive fields like password and extra. Create a markdown table documenting: Field name, Read Access permissions, Write Access permissions, and Notes. Example: conn_id (Read: All tasks, Write: Admin only), password (Read: Tasks with conn_id access, Write: Admin only, encrypted at rest), extra (Read: Tasks with conn_id access, Write: Admin only, may contain secrets).

---

#### FINDING-119: Environmental and contextual attributes used in security decisions are not documented

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Section(s)** | 8.1.3 |
| **Files** | task-sdk/src/airflow/sdk/api/client.py:183-195 |
| **Source Reports** | 8.1.3.md |
| **Related** | - |

**Description:**

The Task SDK collects and transmits environmental attributes (hostname, username, PID, start_date) as part of the TIEnterRunningPayload, but there is no documentation of how these attributes are used by the server to make security decisions. The start method transmits hostname via get_hostname(), username via getuser(), and start_date as contextual time attribute. Additionally, heartbeat transmits hostname and PID. Without documentation, it's unclear whether the server validates that hostname matches expected worker, PID is used to prevent duplicate execution, time attributes are used for timeout enforcement, or IP address/network location is considered in authorization decisions.

**Remediation:**

Document all environmental/contextual attributes and their security role in a table format showing: Attribute (hostname, unixname, pid, start_date, IP address), Source (get_hostname(), getuser(), Process ID, System clock, server extracts from request), Used For (Task identification, Audit trail, Heartbeat validation, SLA enforcement, Network policy), and Security Role (Validates task is running on expected worker, Identifies OS user executing task, Prevents zombie processes and conflict detection, Detects stale tasks, Rate limiting and geo-restriction).

---

#### FINDING-120: Connection cache lacks explicit eviction/TTL mechanism for authorization-relevant data

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Section(s)** | 8.3.2 |
| **Files** | task-sdk/src/airflow/sdk/execution_time/context.py:134-155 |
| **Source Reports** | 8.3.2.md |
| **Related** | - |

**Description:**

If a connection's credentials are revoked or rotated at the API server level, cached connection URIs in SecretCache may continue to be served to tasks until the cache entry is evicted or the process terminates. API server revokes/changes connection → SecretCache still holds stale URI → Task uses revoked connection. In practice, since each task runner process handles a single task and exits, the window is limited to the task's execution duration.

**Remediation:**

Verify that SecretCache in the dag processor context (where processes are long-lived) implements TTL-based eviction. For task runner contexts, the current design is acceptable as processes exit after task completion. Long-term: If the SecretCache is used in long-lived processes (dag processor), ensure TTL-based eviction is implemented to prevent serving stale authorization data after credential rotation.

---

#### FINDING-121: Supervisor uses single task-scoped token for all API calls — positive pattern with architectural note

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Section(s)** | 8.3.3 |
| **Files** | task-sdk/src/airflow/sdk/execution_time/supervisor.py:529 |
| **Source Reports** | 8.3.3.md |
| **Related** | - |

**Description:**

The supervisor does not validate that msg.dag_id or msg.task_id match the current task's identity (self.ti.dag_id, self.id). It relies entirely on the API server to enforce scope restrictions based on the token. This is architecturally correct (the API server is the authorization authority), but means the SDK itself provides no defense-in-depth against a compromised task process requesting data outside its intended scope. If the API server's token validation has gaps (e.g., cross-DAG XCom access is permitted by design for legitimate use cases like xcom_pull(dag_id="other_dag")), the Task SDK provides no additional guardrails.

**Remediation:**

N/A for Task SDK — server-side token validation should enforce tenant/DAG boundaries as appropriate. Optional long-term enhancement: Consider adding optional configuration to validate that task requests are within their declared scope (e.g., reject GetXCom requests for DAGs not in an allowlist). This would provide defense-in-depth but should remain optional to support legitimate cross-DAG patterns.

---

#### FINDING-122: No client-side tenant boundary enforcement in request forwarding

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Section(s)** | 8.4.1 |
| **Files** | task-sdk/src/airflow/sdk/execution_time/supervisor.py:529, task-sdk/src/airflow/sdk/execution_time/secrets/execution_api.py:42-65 |
| **Source Reports** | 8.4.1.md |
| **Related** | - |

**Description:**

The supervisor forwards TriggerDagRun requests with any dag_id specified by the task process to the API server. In a multi-tenant deployment where different tenants own different DAGs, the Task SDK provides no client-side validation that the target DAG belongs to the same tenant as the requesting task. Cross-tenant triggering must be enforced entirely by the API server's token-based authorization. The SDK has no defense-in-depth mechanism to detect or prevent cross-tenant data access at the SDK layer. If the API server's JWT validation has a vulnerability or misconfiguration, the SDK would silently serve connections/variables from other tenants. Data Flow: Task code → TriggerDagRunOperator → SUPERVISOR_COMMS.send(TriggerDagRun(dag_id="other_tenant_dag")) → Supervisor → API Server (must enforce tenant boundary). In multi-tenant deployments, if the API server's token validation does not properly enforce tenant boundaries, a task from one tenant could trigger DAG runs in another tenant's namespace or access cross-tenant data. The Task SDK provides no defense-in-depth layer.

**Remediation:**

This is primarily a server-side concern. For defense-in-depth at the SDK level: Add optional validation that cross-DAG operations target allowed DAG IDs. This would need to be informed by startup metadata about the task's tenant scope. Optional defense-in-depth: log cross-DAG triggers for audit. If msg.dag_id != self.ti.dag_id, log cross-DAG trigger requested with source_dag and target_dag. Consider adding an optional SDK-level assertion that validates returned resources match the expected tenant context (e.g., a tenant identifier in StartupDetails that can be cross-checked against API responses). This would provide defense-in-depth without breaking the current architecture.

### 3.5 Informational

#### FINDING-123: Potential Token Exposure in Exception Logging

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Info |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Section(s)** | 6.3.5 |
| **File(s)** | task-sdk/src/airflow/sdk/api/client.py:_log_and_trace_retry |
| **Source Report(s)** | 6.3.5.md |
| **Related** | None |

**Description:**

The `_log_and_trace_retry` function logs exceptions which could potentially contain token information in request headers. While this is a client library and not responsible for authentication notifications, inadvertent token logging could create security risks if logs are exposed.

**Remediation:**

Verify that tokens are not inadvertently logged in error messages or stack traces. Implement sanitization of sensitive headers before logging exceptions.

---

---

# 4. Positive Security Controls

| Control ID | Control Description | Evidence Location | Domain |
|------------|-------------------|-------------------|---------|
| PSC-001 | Single msgpack decode in CommsDecoder._read_frame() performs deserialization once before validation | comms.py:236-269 | IPC Message Handling |
| PSC-002 | Pydantic validation after decode | supervisor.py:651 | IPC Message Handling |
| PSC-003 | Msgpack encoding at send time | comms.py:_FrameMixin.as_bytes() | IPC Message Handling |
| PSC-004 | Secrets redaction before transmission | task_runner.py:_serialize_rendered_fields() | IPC Message Handling |
| PSC-005 | Exception HTML escaping | task_runner.py:_send_error_email_notification | IPC Message Handling |
| PSC-006 | URL encoding for run_id | task_runner.py:RuntimeTaskInstance.log_url | IPC Message Handling |
| PSC-007 | Server URL validation in supervise_task() | supervisor.py:1544-1570 | IPC Message Handling |
| PSC-008 | msgspec JSON encoder for custom type serialization | comms.py:_msgpack_enc_hook | IPC Message Handling |
| PSC-009 | No eval()/exec() usage | Codebase-wide | IPC Message Handling |
| PSC-010 | block_orm_access() prevents DB access from task code | supervisor.py:203-249 | IPC Message Handling |
| PSC-011 | Template field length enforcement | task_runner.py:_serialize_template_field | IPC Message Handling |
| PSC-012 | Single msgpack serialization for IPC | comms.py:_FrameMixin.as_bytes() | IPC Message Handling |
| PSC-013 | Pydantic type enforcement | task-sdk/src/airflow/sdk/execution_time/comms.py | IPC Message Handling |
| PSC-014 | Discriminated union validation using TypeAdapter | supervisor.py:handle_requests() | IPC Message Handling |
| PSC-015 | Server-side validation | supervisor.py | IPC Message Handling |
| PSC-016 | Clear protocol separation - IPC layer uses msgpack with explicit frame structure | Architectural | IPC Message Handling |
| PSC-017 | httpx connection limits | supervisor.py:_ensure_client() | IPC Message Handling |
| PSC-018 | Frame size limit on send | comms.py:_FrameMixin.as_bytes() | IPC Message Handling |
| PSC-019 | Default to sandboxed environment | templater.py:341 | Jinja Template Injection |
| PSC-020 | LiteralValue class for explicit template bypass | templater.py:39-49 | Jinja Template Injection |
| PSC-021 | StrictUndefined default | templater.py:390 | Jinja Template Injection |
| PSC-022 | Secret masking on exceptions | templater.py:165-182 | Jinja Template Injection |
| PSC-023 | Circular reference protection | templater.py:189-193 | Jinja Template Injection |
| PSC-024 | is_safe_attribute blocks dunder access in sandboxed mode | templater.py:328-334 | Jinja Template Injection |
| PSC-025 | Template field declaration pattern | Architectural | Jinja Template Injection |
| PSC-026 | File-based templates via get_template | templater.py:209-213 | Jinja Template Injection |
| PSC-027 | Secret masking before log output | log.py:58-60 | Secrets Masking |
| PSC-028 | Remote handler from trusted config | log.py:161-176 | Secrets Masking |
| PSC-029 | IPC within security boundary | log.py:247 | Secrets Masking |
| PSC-030 | Path containment for log upload | log.py:196-211 | Secrets Masking |
| PSC-031 | Masking before remote transmission | log.py:214-228 | Secrets Masking |
| PSC-032 | Safe handling of stdout | log.py:214-228 | Secrets Masking |
| PSC-033 | Exception suppression in mask_secret() | log.py:247 | Secrets Masking |
| PSC-034 | No analytics/tracking integrations | Codebase-wide | Secrets Masking |
| PSC-035 | Dual masking architecture | log.py:247, log.py:231-251 | Secrets Masking |
| PSC-036 | Pipeline ordering correctness | log.py:63-80 | Secrets Masking |
| PSC-037 | Immutable pipeline configuration | log.py:63-80 | Secrets Masking |
| PSC-038 | Defense-in-depth masking applied early in the pipeline | log.py:58-60 | Secrets Masking |
| PSC-039 | Initialization before user code | Architectural | Secrets Masking |
| PSC-040 | Explicit exclusion rationale for supervisor path | log.py:72-73, log.py:113-114 | Secrets Masking |
| PSC-041 | JSON output mode provides natural encoding | log.py:63-80 | Secrets Masking |
| PSC-042 | Structured logging approach | log.py | Secrets Masking |
| PSC-043 | Processor pipeline architecture | log.py:63-80 | Secrets Masking |
| PSC-044 | Pluggable backend architecture | secrets_backend.py | Secrets Backend Access |
| PSC-045 | No secrets in source code | All files | Secrets Backend Access |
| PSC-046 | TTL-based expiration | cache.py:_CacheValue.is_expired() | Secrets Backend Access |
| PSC-047 | Configuration-gated caching | cache.py:init() | Secrets Backend Access |
| PSC-048 | Separation of concerns | Architectural | Secrets Backend Access |
| PSC-049 | Server-side authorization enforcement | execution_api.py | Secrets Backend Access |
| PSC-050 | Structured message protocol | execution_api.py | Secrets Backend Access |
| PSC-051 | Async parity | execution_api.py | Secrets Backend Access |
| PSC-052 | Server-side object-level authorization | Execution API (external) | Secrets Backend Access |
| PSC-053 | Opaque error responses | execution_api.py | Secrets Backend Access |
| PSC-054 | Token-scoped access | Execution API (external) | Secrets Backend Access |
| PSC-055 | Authorization delegated to trusted service layer | execution_api.py | Secrets Backend Access |
| PSC-056 | Client-supplied parameters not used for authorization | execution_api.py | Secrets Backend Access |
| PSC-057 | No authorization logic in client code | Codebase-wide | Secrets Backend Access |
| PSC-058 | Structured IPC prevents tampering | execution_api.py | Secrets Backend Access |
| PSC-059 | Search path designed for worker context | execution_api.py | Secrets Backend Access |
| PSC-060 | Use of industry-validated cryptography library | crypto.py:get_fernet() | Fernet Encryption |
| PSC-061 | No custom cryptographic implementations | crypto.py | Fernet Encryption |
| PSC-062 | MultiFernet key rotation support | crypto.py:get_fernet() | Fernet Encryption |
| PSC-063 | Dedicated rotate() method | crypto.py:_RealFernet.rotate() | Fernet Encryption |
| PSC-064 | Single point of cryptographic access | crypto.py:get_fernet() | Fernet Encryption |
| PSC-065 | Protocol-based typing | crypto.py | Fernet Encryption |
| PSC-066 | Separation of data model and encryption | connection.py, variable.py | Fernet Encryption |
| PSC-067 | Secret masking as defense-in-depth | connection.py:extra_dejson, variable.py:get() | Fernet Encryption |
| PSC-068 | Authenticated encryption via Fernet encrypt-then-MAC construction | crypto.py | Fernet Encryption |
| PSC-069 | NIST-approved primitives | crypto.py | Fernet Encryption |
| PSC-070 | TTL-capable decrypt interface | crypto.py:_RealFernet.decrypt() | Fernet Encryption |
| PSC-071 | Bearer token auth (token only in Authorization header) | client.py:685 | Execution API Client |
| PSC-072 | No redirect following (prevents token leak to other hosts) | client.py | Execution API Client |
| PSC-073 | Token refresh via response header | client.py:770 | Execution API Client |
| PSC-074 | Token not logged | client.py:771 | Execution API Client |
| PSC-075 | Token scoped to single base_url | client.py:740 | Execution API Client |
| PSC-076 | Use of ssl.create_default_context() | client.py:735 | Execution API Client |
| PSC-077 | Cached SSL context | client.py:733-738 | Execution API Client |
| PSC-078 | Certificate verification enabled | client.py | Execution API Client |
| PSC-079 | Use of certifi package for publicly trusted CA bundle | client.py:747 | Execution API Client |
| PSC-080 | Additive custom CA support (not replacement) | client.py:737 | Execution API Client |
| PSC-081 | Client certificate support (mTLS) | client.py:749-753 | Execution API Client |
| PSC-082 | All API paths are hardcoded relative paths | client.py | Execution API Client |
| PSC-083 | Single base_url architecture | client.py | Execution API Client |
| PSC-084 | Strict schema validation with extra='forbid' | _generated.py | Execution API Client |
| PSC-085 | Retry logic with exponential backoff | client.py | Execution API Client |
| PSC-086 | Correlation-id always generated fresh | client.py | Execution API Client |
| PSC-087 | Trace context injection | client.py | Execution API Client |
| PSC-088 | Type-restricted msgpack decoder | comms.py | XCom Serialization |
| PSC-089 | Discriminated union TypeAdapter | supervisor.py | XCom Serialization |
| PSC-090 | Callback msg TypeAdapter | callback_supervisor.py | XCom Serialization |
| PSC-091 | Pydantic body validation | comms.py | XCom Serialization |
| PSC-092 | Typed msgspec decoders with frozen structs | comms.py | XCom Serialization |
| PSC-093 | Supervisor-mediated XCom access | bases/xcom.py | XCom Serialization |
| PSC-094 | Explicit key parameter | Architectural | XCom Serialization |
| PSC-095 | Typed protocol for keys | Architectural | XCom Serialization |
| PSC-096 | Defense-in-depth layering | Architectural | XCom Serialization |
| PSC-097 | JSON-compatible serialization | Architectural | XCom Serialization |
| PSC-098 | Trust boundary clarity | Architectural | XCom Serialization |
| PSC-099 | Configuration-driven security | Architectural | XCom Serialization |
| PSC-100 | Deserialization allowlist | serde/__init__.py:_match() | XCom Serialization |

---

# 5. ASVS Compliance Summary

| ASVS ID | Title | Status | Primary Finding(s) |
|---------|-------|--------|-------------------|
| 1.1.1 | Encoding and Sanitization Architecture - Input Decoding | **Pass** | PSC-001, PSC-002 |
| 1.1.2 | Encoding and Sanitization Architecture - Output Encoding as Final Step | **Partial** | FINDING-058 |
| 1.2.1 | Injection Prevention - Context-Specific Output Encoding | **Partial** | FINDING-058 |
| 1.2.2 | Injection Prevention - URL Encoding | **Partial** | FINDING-059, FINDING-060 |
| 1.2.3 | Injection Prevention - JavaScript/JSON Content | **Pass** | PSC-008 |
| 1.2.4 | SQL/Database Injection Prevention | **Pass** | PSC-010 |
| 1.2.5 | Injection Prevention | **Pass** | PSC-009 |
| 1.2.6 | LDAP Injection Prevention | **Pass** | N/A |
| 1.2.7 | XPath Injection Prevention | **Pass** | N/A |
| 1.2.8 | LaTeX Injection Prevention | **Pass** | N/A |
| 1.2.9 | Regex Special Character Escaping | **Pass** | N/A |
| 1.2.10 | CSV/Formula Injection Prevention | **Pass** | N/A |
| 1.3.1 | HTML Input from WYSIWYG Editors | **N/A** | N/A |
| 1.3.2 | Sanitization - Avoiding eval() and Dynamic Code Execution | **Pass** | PSC-009 |
| 1.3.3 | Sanitization | **Partial** | FINDING-008, FINDING-057 |
| 1.3.4 | SVG Scriptable Content | **N/A** | N/A |
| 1.3.5 | Sanitization of user-supplied scriptable or expression template language content | **Fail** | FINDING-001, FINDING-011, FINDING-012 |
| 1.3.6 | SSRF Protection | **Partial** | FINDING-095 |
| 1.3.7 | Template Injection | **Fail** | FINDING-001, FINDING-013, FINDING-065 |
| 1.3.8 | JNDI Injection | **N/A** | N/A |
| 1.3.9 | Memcache Injection | **N/A** | N/A |
| 1.3.10 | Format String Injection | **N/A** | N/A |
| 1.3.11 | SMTP/IMAP Injection | **Pass** | PSC-005 |
| 1.3.12 | ReDoS Prevention | **Partial** | FINDING-047 |
| 1.4.1 | Memory-Safe String Operations | **N/A** | Python language |
| 1.4.2 | Integer Overflow Prevention | **Pass** | FINDING-096 (minor validation gap) |
| 1.4.3 | Memory/Resource Release | **Pass** | PSC-017 |
| 1.5.1 | XML Parser XXE Protection | **Pass** | No XML parsing |
| 1.5.2 | Safe Deserialization | **Partial** | FINDING-057, PSC-088-092, PSC-100 |
| 1.5.3 | Parser Consistency | **Partial** | FINDING-061 |
| 2.1.1 | Validation and Business Logic Documentation | **Partial** | FINDING-010 |
| 2.1.2 | Contextual Consistency Documentation | **Partial** | FINDING-062 |
| 2.1.3 | Validation and Business Logic Documentation | **Partial** | FINDING-093 |
| 2.2.1 | Input Validation | **Partial** | FINDING-009, FINDING-010 |
| 2.2.2 | Input Validation at Trusted Service Layer | **Partial** | FINDING-008, FINDING-010 |
| 2.2.3 | Combinations of Related Data Items | **Partial** | FINDING-063, FINDING-064 |
| 2.3.1 | Business Logic Security - Sequential Step Order | **Partial** | FINDING-044 |
| 2.3.2 | Business Logic Limits | **Partial** | FINDING-026 |
| 2.3.3 | Business Logic Security - Transactions | **Fail** | FINDING-007, FINDING-045 |
| 2.3.4 | Business Logic Security - Locking Mechanisms | **Partial** | FINDING-046 |
| 2.3.5 | Business Logic Security - Multi-User Approval | **N/A** | N/A |
| 2.4.1 | Anti-Automation Controls | **Fail** | FINDING-027, FINDING-028, FINDING-029, FINDING-083 |
| 2.4.2 | Anti-automation - Realistic Human Timing | **Partial** | FINDING-094 |
| 3.1.1 | Web Frontend Security Documentation | **N/A** | Not a web frontend |
| 3.2.1-3.7.5 | Browser-specific controls | **N/A** | Not a web application |
| 4.1.1 | Content-Type Header in HTTP Responses | **N/A** | Client, not server |
| 4.1.2 | HTTP to HTTPS Redirect Behavior | **Pass** | PSC-072, FINDING-075 |
| 4.1.3 | Header Override Protection | **Partial** | FINDING-076 |
| 4.1.4 | HTTP Method Restriction | **N/A** | Client |
| 4.1.5 | Per-Message Digital Signatures | **Partial** | FINDING-115 |
| 4.2.1 | HTTP Message Structure Validation | **Pass** | httpx library |
| 4.2.2 | Content-Length Consistency in Generated HTTP Messages | **Pass** | httpx library |
| 4.2.3 | HTTP Message Structure Validation - Connection-Specific Headers | **N/A** | httpx library |
| 4.2.4 | HTTP Message Structure Validation - CR/LF in Headers | **N/A** | httpx library |
| 4.2.5 | URI and Header Field Length Validation | **Partial** | FINDING-010 |
| 4.3.1-4.4.4 | GraphQL/WebSocket controls | **N/A** | Not applicable |
| 5.1.1-5.4.3 | File handling controls | **N/A** | Not applicable |
| 6.1.1-6.8.4 | Authentication controls | **N/A** | Token-based, delegated to server |
| 7.1.1-7.6.2 | Session management controls | **Pass/N/A** | JWT tokens, PSC-071-075, FINDING-116 |
| 8.1.1 | Authorization Documentation - Function-Level and Data-Specific Access | **Partial** | FINDING-117 |
| 8.1.2 | Authorization Documentation - Field-Level Access Restrictions | **Partial** | FINDING-118 |
| 8.1.3 | Authorization Documentation - Environmental/Contextual Attributes | **Fail** | FINDING-119 |
| 8.1.4 | Authorization Documentation - Environmental/Contextual Decision-Making | **N/A** | N/A |
| 8.2.1 | Function-Level Access Control | **Partial** | FINDING-017 |
| 8.2.2 | Data-Specific Access (IDOR/BOLA) | **Partial** | FINDING-067, PSC-052 |
| 8.2.3 | Field-Level Access Control (BOPLA) | **N/A** | N/A |
| 8.2.4 | Adaptive Security Controls | **N/A** | N/A |
| 8.3.1 | Server-Side Authorization Enforcement | **Pass** | PSC-049, PSC-055 |
| 8.3.2 | Immediate Application of Authorization Changes | **Partial** | FINDING-056, FINDING-120 |
| 8.3.3 | Subject-Based Access Control (Originating Subject) | **Pass** | PSC-054, FINDING-121 |
| 8.4.1 | Multi-Tenant Controls | **Partial** | FINDING-122 |
| 8.4.2 | Administrative Interface Security | **N/A** | N/A |
| 9.1.1-9.2.4 | Token validation controls | **N/A** | Delegated to server |
| 10.1.1 | Generic OAuth and OIDC Security | **Pass** | PSC-071-075, FINDING-073 |
| 10.1.2-10.7.3 | OAuth/OIDC specific controls | **N/A** | Not OAuth/OIDC |
| 11.1.1 | Cryptographic Key Management Policy | **Partial** | FINDING-068 |
| 11.1.2 | Cryptographic Inventory | **Partial** | FINDING-020, FINDING-069 |
| 11.1.3 | Cryptographic Discovery Mechanisms | **Fail** | FINDING-048 |
| 11.1.4 | Cryptographic Inventory and Migration Plan | **Fail** | FINDING-002 |
| 11.2.1 | Industry-Validated Implementations | **Pass** | PSC-060, PSC-061 |
| 11.2.2 | Crypto Agility | **Fail** | FINDING-002, FINDING-019 |
| 11.2.3 | Minimum 128-bits of Security | **Pass** | Fernet uses AES-128 |
| 11.2.4 | Constant-time Cryptographic Operations | **Pass** | pyca/cryptography |
| 11.2.5 | Secure Cryptographic Failure Handling | **Partial** | FINDING-018, FINDING-097 |
| 11.3.1 | Insecure Block Modes and Padding | **Pass** | Fernet uses CBC + HMAC |
| 11.3.2 | Approved Ciphers and Modes | **Partial** | FINDING-070 |
| 11.3.3 | Authenticated Encryption | **Partial** | FINDING-018, PSC-068 |
| 11.3.4 | Nonce/IV Uniqueness | **Pass** | Fernet spec |
| 11.3.5 | Encrypt-then-MAC | **Pass** | PSC-068 |
| 11.4.1 | Approved Hash Functions | **Pass** | HMAC-SHA256 |
| 11.4.2 | Password Storage KDF | **Pass** | Not applicable (no passwords) |
| 11.4.3 | Hash Function Collision Resistance | **Pass** | SHA-256 |
| 11.4.4 | Key Derivation from Passwords | **Pass** | Not applicable |
| 11.5.1 | Cryptographically Secure Random Values | **Pass** | Fernet spec |
| 11.5.2 | Random Values | **Pass** | uuid7() |
| 11.6.1 | Public Key Cryptography - Approved Algorithms | **Partial** | TLS via ssl module |
| 11.6.2 | Public Key Cryptography - Key Exchange | **Pass** | TLS |
| 11.7.1 | In-Use Data Cryptography - Full Memory Encryption | **Partial** | FINDING-098 |
| 11.7.2 | In-Use Data Cryptography - Data Minimization | **Partial** | FINDING-099 |
| 12.1.1 | General TLS Security Guidance | **Partial** | FINDING-072, PSC-076 |
| 12.1.2 | General TLS Security Guidance | **Fail** | FINDING-021 |
| 12.1.3 | mTLS Certificate Validation | **Pass** | PSC-081 |
| 12.1.4 | Certificate Revocation (OCSP Stapling) | **N/A** | httpx default |
| 12.1.5 | Encrypted Client Hello (ECH) | **N/A** | Not applicable |
| 12.2.1 | HTTPS Communication with External Facing Services | **Fail** | FINDING-003 |
| 12.2.2 | HTTPS Communication with External Facing Services | **Pass** | PSC-078 |
| 12.3.1 | TLS for All Connections | **Partial** | FINDING-100 |
| 12.3.2 | General Service to Service Communication Security | **Pass** | PSC-071 |
| 12.3.3 | TLS for Internal HTTP-based Service Communications | **Fail** | FINDING-003 |
| 12.3.4 | TLS Connections Use Trusted Certificates | **Pass** | PSC-078-080 |
| 12.3.5 | Strong Authentication for Intra-Service Communications | **Pass** | PSC-071 |
| 13.1.1 | Configuration Documentation - Communication Needs | **Fail** | FINDING-030, FINDING-084 |
| 13.1.2 | Connection Pool Limits Documentation | **Partial** | FINDING-101 |
| 13.1.3 | Resource Management Strategies Documentation | **Partial** | FINDING-102 |
| 13.1.4 | Configuration Documentation - Secrets Definition and Rotation | **Fail** | FINDING-031 |
| 13.2.1 | Backend Communication Authentication | **Partial** | FINDING-049 |
| 13.2.2 | Least Privilege Backend Communication | **Pass** | PSC-049 |
| 13.2.3 | No Default Credentials | **Pass** | PSC-045, FINDING-018 |
| 13.2.4 | Allowlist for External Resources | **Partial** | FINDING-074 |
| 13.2.5 | Server Allowlist for Outbound Requests | **Pass** | PSC-083 |
| 13.2.6 | Documented Connection Configuration | **Partial** | FINDING-103, FINDING-104, FINDING-106 |
| 13.3.1 | Secret Management | **Partial** | FINDING-016 |
| 13.3.3 | Isolated Security Module for Cryptographic Operations | **Fail** | FINDING-050 |
| 13.3.4 | Secret Expiration and Rotation | **Partial** | FINDING-071 |
| 13.4.1 | No Source Control Metadata Exposure | **N/A** | Not applicable |
| 13.4.2 | Debug Modes Disabled in Production | **Pass** | FINDING-111 (minor) |
| 13.4.3-13.4.5 | Web server controls | **N/A** | Not applicable |
| 13.4.6 | Backend Version Information Not Exposed | **Pass** | FINDING-105 (minor) |
| 13.4.7 | Web Tier Serves Only Specific File Extensions | **N/A** | Not applicable |
| 14.1.1 | Data Protection Documentation - Sensitive Data Classification | **Fail** | FINDING-032 |
| 14.1.2 | Data Protection Documentation - Protection Requirements per Level | **Fail** | FINDING-033, FINDING-085 |
| 14.2.1 | Sensitive Data in URL/Query String | **Pass** | PSC-071 |
| 14.2.2 | Sensitive Data Caching Prevention | **Partial** | FINDING-019, FINDING-106 |
| 14.2.3 | Sensitive Data Not Sent to Untrusted Parties | **Pass** | PSC-027, PSC-031 |
| 14.2.4 | Controls Around Sensitive Data | **Pass** | PSC-067, FINDING-107, FINDING-108 |
| 14.2.5 | Cache Mechanisms and Web Cache Deception | **N/A** | Not applicable |
| 14.2.6 | Minimum Required Sensitive Data Returned | **Pass** | PSC-053 |
| 14.2.7 | Sensitive Information Retention Classification | **Partial** | FINDING-099, FINDING-109 |
| 14.2.8 | General Data Protection - File Metadata | **N/A** | Not applicable |
| 14.3.1-14.3.3 | Client-side data protection | **N/A** | Not applicable |
| 15.1.1 | Remediation Timeframes | **N/A** | Organizational control |
| 15.1.2 | SBOM and Library Inventory | **Partial** | pyproject.toml present, FINDING-110 |
| 15.1.3 | Resource Management Documentation | **Partial** | FINDING-051, FINDING-052 |
| 15.1.4 | Secure Coding and Architecture Documentation | **Fail** | FINDING-023 |
| 15.1.5 | Secure Coding and Architecture Documentation | **Fail** | FINDING-024 |
| 15.2.1 | Component Update Compliance | **Partial** | FINDING-110 |
| 15.2.2 | Loss of Availability Defenses | **Partial** | FINDING-026 |
| 15.2.3 | Production Functionality Only | **Partial** | FINDING-053, FINDING-054, FINDING-111, FINDING-112 |
| 15.2.4 | Dependency Confusion Prevention | **Partial** | FINDING-055, FINDING-113 |
| 15.2.5 | Security Architecture and Dependencies | **Partial** | FINDING-025, FINDING-079 |
| 15.3.1 | Defensive Coding - Return Required Subset | **Pass** | PSC-014, PSC-089-091 |
| 15.3.2 | Redirect Following Configuration | **Pass** | PSC-072 |
| 15.3.3 | Defensive Coding - Mass Assignment | **Pass** | PSC-084, FINDING-077 |
| 15.3.4 | IP Address Handling | **Pass** | FINDING-114 (minor) |
| 15.3.5 | Defensive Coding - Type Safety | **Partial** | FINDING-022, FINDING-078, PSC-013 |
| 15.3.6 | Defensive Coding - Prototype Pollution | **N/A** | Not JavaScript |
| 15.3.7 | HTTP Parameter Pollution Defenses | **N/A** | Not applicable |
| 15.4.1 | Thread-Safe Shared Objects | **Partial** | FINDING-080, FINDING-081 |
| 15.4.2 | TOCTOU Race Conditions | **Partial** | FINDING-082 |
| 15.4.3 | Consistent Lock Usage | **Pass** | FINDING-081 (test code only) |
| 15.4.4 | Resource Allocation and Thread Starvation Prevention | **Pass** | PSC-017 |
| 16.1.1 | Security Logging Documentation | **Fail** | FINDING-034 |
| 16.2.1 | General Logging — Metadata Requirements | **Partial** | FINDING-035, FINDING-086 |
| 16.2.2 | General Logging — Time Synchronization | **Partial** | FINDING-087 |
| 16.2.3 | General Logging — Documented Destinations Only | **Fail** | FINDING-036, FINDING-088 |
| 16.2.4 | General Logging — Common Format and Correlation | **Pass** | PSC-086 |
| 16.2.5 | Sensitive Data Logging Protection Levels | **Partial** | FINDING-014 |
| 16.3.1 | Security Events — Authentication Logging | **Fail** | FINDING-037 |
| 16.3.2 | Security Events — Failed Authorization Logging | **Fail** | FINDING-038 |
| 16.3.3 | Security Events — Logging Bypass Attempts | **Partial** | FINDING-014 |
| 16.3.4 | Security Events — Logging Unexpected Errors | **Fail** | FINDING-004, FINDING-014 |
| 16.4.1 | Log Injection Prevention | **Partial** | FINDING-015, PSC-041, PSC-042 |
| 16.4.2 | Log Protection — Unauthorized Access and Modification Prevention | **Partial** | FINDING-039, FINDING-089 |
| 16.4.3 | Log Protection — Secure Transmission to Separate System | **Partial** | FINDING-004, FINDING-090 |
| 16.5.1 | Error Handling - Generic Error Messages | **Partial** | FINDING-040, FINDING-091, FINDING-092 |
| 16.5.2 | Error Handling - Graceful Degradation on External Resource Failure | **Fail** | FINDING-005, FINDING-041 |
| 16.5.3 | Error Handling - Fail Gracefully, No Fail-Open Conditions | **Fail** | FINDING-006, FINDING-042 |
| 16.5.4 | Error Handling - Last Resort Error Handler | **Fail** | FINDING-042, FINDING-043 |
| 17.1.1-17.3.2 | WebRTC controls | **N/A/Pass** | FINDING-123 (informational) |

---

# 6. Cross-Reference Matrix

## Findings to ASVS Mapping

| Finding ID | Severity | ASVS Requirements | Positive Controls |
|------------|----------|-------------------|-------------------|
| FINDING-001 | High | 1.3.5, 1.3.7 | PSC-019, PSC-021 |
| FINDING-002 | High | 11.2.2, 11.1.4 | PSC-060, PSC-062 |
| FINDING-003 | High | 12.2.1, 12.3.3 | PSC-076, PSC-078 |
| FINDING-004 | High | 16.3.4, 16.4.3 | PSC-031, PSC-033 |
| FINDING-005 | High | 16.5.2 | PSC-017 |
| FINDING-006 | High | 16.5.3 | PSC-015 |
| FINDING-007 | High | 2.3.3 | PSC-015 |
| FINDING-008 | Medium | 1.3.3, 2.2.2, 15.2.2 | PSC-018 |
| FINDING-009 | Medium | 2.2.1 | PSC-002, PSC-014 |
| FINDING-010 | Medium | 2.2.1, 2.2.2, 4.2.5, 2.1.1 | PSC-013 |
| FINDING-011 | Medium | 1.3.5 | PSC-024 |
| FINDING-012 | Medium | 1.3.5 | PSC-019 |
| FINDING-013 | Medium | 1.3.7 | PSC-025, PSC-026 |
| FINDING-014 | Medium | 16.2.5, 16.3.3, 16.3.4 | PSC-027, PSC-038 |
| FINDING-015 | Medium | 16.4.1 | PSC-041, PSC-042 |
| FINDING-016 | Medium | 13.3.1 | PSC-046, PSC-047 |
| FINDING-017 | Medium | 8.2.1 | PSC-049, PSC-055 |
| FINDING-018 | Medium | 11.1.1, 11.2.5, 11.3.3, 11.6.1, 13.2.3 | PSC-060, PSC-068 |
| FINDING-019 | Medium | 11.2.2, 14.2.2 | PSC-062, PSC-064 |
| FINDING-020 | Medium | 11.1.2 | PSC-065 |
| FINDING-021 | Medium | 12.1.2 | PSC-076 |
| FINDING-022 | Medium | 15.3.5 | PSC-013, PSC-091 |
| FINDING-023 | Medium | 15.1.4 | None |
| FINDING-024 | Medium | 15.1.5 | PSC-009 |
| FINDING-025 | Medium | 15.2.5 | PSC-009 |
| FINDING-026 | Medium | 15.2.2, 2.3.2 | PSC-017 |
| FINDING-027 | Medium | 2.4.1 | PSC-014 |
| FINDING-028 | Medium | 2.4.1 | PSC-014 |
| FINDING-029 | Medium | 2.4.1 | PSC-015 |
| FINDING-030 | Medium | 13.1.1 | PSC-044, PSC-048 |
| FINDING-031 | Medium | 13.1.4 | PSC-062, PSC-063 |
| FINDING-032 | Medium | 14.1.1 | None |
| FINDING-033 | Medium | 14.1.2 | None |
| FINDING-034 | Medium | 16.1.1 | PSC-042 |
| FINDING-035 | Medium | 16.2.1 | PSC-086 |
| FINDING-036 | Medium | 16.2.3 | PSC-028 |
| FINDING-037 | Medium | 16.3.1 | None |
| FINDING-038 | Medium | 16.3.2 | None |
| FINDING-039 | Medium | 16.4.2 | PSC-030 |
| FINDING-040 | Medium | 16.5.1 | PSC-053 |
| FINDING-041 | Medium | 16.5.2 | PSC-014 |
| FINDING-042 | Medium | 16.5.3, 16.5.4 | None |
| FINDING-043 | Medium | 16.5.4 | None |
| FINDING-044 | Medium | 2.3.1 | PSC-015 |
| FINDING-045 | Medium | 2.3.3 | PSC-015 |
| FINDING-046 | Medium | 2.3.4 | PSC-015 |
| FINDING-047 | Medium | 1.3.12 | None |
| FINDING-048 | Medium | 11.1.3 | PSC-064 |
| FINDING-049 | Medium | 13.2.1 | PSC-071 |
| FINDING-050 | Medium | 13.3.3 | PSC-064 |
| FINDING-051 | Medium | 15.1.3 | PSC-017, PSC-085 |
| FINDING-052 | Medium | 15.1.3 | PSC-017 |
| FINDING-053 | Medium | 15.2.3 | None |
| FINDING-054 | Medium | 15.2.3 | PSC-010 |
| FINDING-055 | Medium | 15.2.4 | None |
| FINDING-056 | Medium | 8.3.2 | PSC-049 |
| FINDING-057 | Low | 1.3.3, 1.5.2 | PSC-042 |
| FINDING-058 | Low | 1.2.1, 1.1.2 | PSC-005 |
| FINDING-059 | Low | 1.2.2 | PSC-006 |
| FINDING-060 | Low | 1.2.2 | PSC-007 |
| FINDING-061 | Low | 1.5.3 | PSC-001, PSC-002 |
| FINDING-062 | Low | 2.1.2 | PSC-013 |
| FINDING-063 | Low | 2.2.3 | PSC-013 |
| FINDING-064 | Low | 2.2.3 | PSC-013 |
| FINDING-065 | Low | 1.3.7 | PSC-019 |
| FINDING-066 | Low | 13.3.1 | PSC-046 |
| FINDING-067 | Low | 8.2.2 | PSC-052, PSC-053 |
| FINDING-068 | Low | 11.1.1 | PSC-046, PSC-070 |
| FINDING-069 | Low | 11.1.2 | PSC-065 |
| FINDING-070 | Low | 11.3.2 | PSC-069 |
| FINDING-071 | Low | 13.3.4 | PSC-062 |
| FINDING-072 | Low | 12.1.1 | PSC-076 |
| FINDING-073 | Low | 10.1.1 | PSC-071, PSC-074 |
| FINDING-074 | Low | 13.2.4 | PSC-083 |
| FINDING-075 | Low | 4.1.2 | PSC-072 |
| FINDING-076 | Low | 4.1.3 | PSC-073 |
| FINDING-077 | Low | 15.3.3 | PSC-084 |
| FINDING-078 | Low | 15.3.5 | PSC-092 |
| FINDING-079 | Low | 15.2.5 | PSC-009 |
| FINDING-080 | Low | 15.4.1 | None |
| FINDING-081 | Low | 15.4.1, 15.4.3 | None |
| FINDING-082 | Low | 15.4.2 | None |
| FINDING-083 | Low | 2.4.1 | None |
| FINDING-084 | Low | 13.1.1 | PSC-044 |
| FINDING-085 | Low | 14.1.2 | None |
| FINDING-086 | Low | 16.2.1 | PSC-086 |
| FINDING-087 | Low | 16.2.2 | None |
| FINDING-088 | Low | 16.2.3 | PSC-028 |
| FINDING-089 | Low | 16.4.2 | None |
| FINDING-090 | Low | 16.4.3 | PSC-031 |
| FINDING-091 | Low | 16.5.1 | PSC-027 |
| FINDING-092 | Low | 16.5.1 | PSC-022, PSC-027 |
| FINDING-093 | Low | 2.1.3 | None |
| FINDING-094 | Low | 2.4.2 | PSC-014 |
| FINDING-095 | Low | 1.3.6 | PSC-007 |
| FINDING-096 | Low | 1.4.2 | None |
| FINDING-097 | Low | 11.2.5 | PSC-060 |
| FINDING-098 | Low | 11.7.1 | None |
| FINDING-099 | Low | 11.7.2, 13.2.2, 14.2.2, 14.2.7 | PSC-046 |
| FINDING-100 | Low | 12.3.1 | PSC-007 |
| FINDING-101 | Low | 13.1.2 | PSC-017 |
| FINDING-102 | Low | 13.1.3 | PSC-017 |
| FINDING-103 | Low | 13.2.6 | PSC-017 |
| FINDING-104 | Low | 13.2.6 | None |
| FINDING-105 | Low | 13.4.6 | None |
| FINDING-106 | Low | 14.2.2, 13.2.6 | PSC-046 |
| FINDING-107 | Low | 14.2.4 | PSC-067 |
| FINDING-108 | Low | 14.2.4 | PSC-067 |
| FINDING-109 | Low | 14.2.7 | None |
| FINDING-110 | Low | 15.2.1 | None |
| FINDING-111 | Low | 15.2.3, 13.4.2 | None |
| FINDING-112 | Low | 15.2.3 | None |
| FINDING-113 | Low | 15.2.4 | None |
| FINDING-114 | Low | 15.3.4 | None |
| FINDING-115 | Low | 4.1.5 | None |
| FINDING-116 | Low | 7.4.1 | PSC-071 |
| FINDING-117 | Low | 8.1.1 | PSC-049, PSC-055 |
| FINDING-118 | Low | 8.1.2 | PSC-052 |
| FINDING-119 | Low | 8.1.3 | None |
| FINDING-120 | Low | 8.3.2 | PSC-049 |
| FINDING-121 | Low | 8.3.3 | PSC-054, PSC-075 |
| FINDING-122 | Low | 8.4.1 | PSC-048 |
| FINDING-123 | Info | 6.3.5 | PSC-074 |

## ASVS to Controls and Findings

| ASVS ID | Status | Positive Controls | Findings |
|---------|--------|-------------------|----------|
| 1.1.1 | Pass | PSC-001, PSC-002 | None |
| 1.1.2 | Partial | PSC-003, PSC-005 | FINDING-058 |
| 1.2.1 | Partial | PSC-005 | FINDING-058 |
| 1.2.2 | Partial | PSC-006, PSC-007 | FINDING-059, FINDING-060 |
| 1.2.3 | Pass | PSC-008 | None |
| 1.3.2 | Pass | PSC-009 | None |
| 1.3.3 | Partial | PSC-011, PSC-042 | FINDING-008, FINDING-057 |
| 1.3.5 | Fail | PSC-019, PSC-021, PSC-024 | FINDING-001, FINDING-011, FINDING-012 |
| 1.3.7 | Fail | PSC-019, PSC-025, PSC-026 | FINDING-001, FINDING-013, FINDING-065 |
| 1.5.2 | Partial | PSC-088-092, PSC-100 | FINDING-057 |
| 1.5.3 | Partial | PSC-001, PSC-002 | FINDING-061 |
| 2.1.1 | Partial | PSC-013 | FINDING-010 |
| 2.1.2 | Partial | PSC-013 | FINDING-062 |
| 2.2.1 | Partial | PSC-002, PSC-013, PSC-014 | FINDING-009, FINDING-010 |
| 2.2.2 | Partial | PSC-013, PSC-015 | FINDING-008, FINDING-010 |
| 2.2.3 | Partial | PSC-013 | FINDING-063, FINDING-064 |
| 2.3.1 | Partial | PSC-015 | FINDING-044 |
| 2.3.2 | Partial | PSC-017 | FINDING-026 |
| 2.3.3 | Fail | PSC-015 | FINDING-007, FINDING-045 |
| 2.3.4 | Partial | PSC-015 | FINDING-046 |
| 2.4.1 | Fail | PSC-014, PSC-015 | FINDING-027, FINDING-028, FINDING-029, FINDING-083 |
| 8.2.1 | Partial | PSC-049, PSC-055 | FINDING-017 |
| 8.2.2 | Partial | PSC-052, PSC-053 | FINDING-067 |
| 8.3.1 | Pass | PSC-049, PSC-055 | None |
| 8.3.2 | Partial | PSC-049 | FINDING-056, FINDING-120 |
| 10.1.1 | Pass | PSC-071-075 | FINDING-073 |
| 11.1.1 | Partial | PSC-046, PSC-070 | FINDING-068 |
| 11.1.2 | Partial | PSC-065 | FINDING-020, FINDING-069 |
| 11.2.1 | Pass | PSC-060, PSC-061 | None |
| 11.2.2 | Fail | PSC-062, PSC-064 | FINDING-002, FINDING-019 |
| 11.3.2 | Partial | PSC-069 | FINDING-070 |
| 12.1.1 | Partial | PSC-076 | FINDING-072 |
| 12.1.2 | Fail | PSC-076 | FINDING-021 |
| 12.2.1 | Fail | PSC-076, PSC-078 | FINDING-003 |
| 12.3.3 | Fail | PSC-076 | FINDING-003 |
| 13.1.1 | Fail | PSC-044, PSC-048 | FINDING-030, FINDING-084 |
| 13.3.1 | Partial | PSC-046, PSC-047 | FINDING-016 |
| 14.2.3 | Pass | PSC-027, PSC-031 | None |
| 15.2.2 | Partial | PSC-017 | FINDING-008, FINDING-026 |
| 15.3.5 | Partial | PSC-013, PSC-091, PSC-092 | FINDING-022, FINDING-078 |
| 16.2.5 | Partial | PSC-027, PSC-038 | FINDING-014 |
| 16.4.1 | Partial | PSC-041, PSC-042 | FINDING-015 |
| 16.5.2 | Fail | PSC-017 | FINDING-005, FINDING-041 |
| 16.5.3 | Fail | PSC-015 | FINDING-006, FINDING-042 |

**Summary Statistics:**
- **Total ASVS Requirements Assessed:** 190
- **Pass:** 52 (27%)
- **Partial:** 73 (38%)
- **Fail:** 34 (18%)
- **N/A:** 31 (16%)
- **Total Findings:** 123 (6 High, 50 Medium, 66 Low, 1 Informational)
- **Total Positive Controls:** 100

## 7. Level Coverage Analysis


**Audit scope:** up to L3

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 15 |
| L2 | 182 | 79 |
| L3 | 92 | 46 |

**Total consolidated findings: 123**


### Reports Not Included in Consolidation

1 per-section report(s) could not be automatically extracted into this consolidated report. 
Findings from these sections are available in the original per-section reports:

| Section | Per-Section Report |
|---------|-------------------|
| 13.3.2 | [secrets_backend_access/13.3.2.md](https://github.com/apache/tooling-runbooks/blob/main/secrets_backend_access/13.3.2.md) |

*End of Consolidated Security Audit Report*