# Security Issues

## Issue: FINDING-001 - NativeEnvironment completely bypasses Jinja2 sandbox protections
**Labels:** bug, security, priority:high
**Description:**
### Summary
The NativeEnvironment class inherits from jinja2.nativetypes.NativeEnvironment instead of jinja2.sandbox.SandboxedEnvironment, completely bypassing sandbox protections when native rendering is enabled (render_template_as_native_obj = True). This allows templates to access dangerous Python internals, filesystem, and network without any interception when native=True.

### Details
The is_safe_attribute() method defined in _AirflowEnvironmentMixin becomes dead code as NativeEnvironment never calls sandbox hook methods. The dual environment architecture creates security asymmetry where a single configuration flag disables all template sandboxing, creating a trapdoor in the security architecture. The _AirflowEnvironmentMixin provides false confidence as is_safe_attribute() is never invoked by the Jinja2 native evaluation machinery.

**CWE:** CWE-1336  
**ASVS:** 1.3.5 (L2), 1.3.7 (L2)

### Affected Files
- `task-sdk/src/airflow/sdk/definitions/_internal/templater.py:337`
- `task-sdk/src/airflow/sdk/definitions/_internal/templater.py:400`
- `task-sdk/src/airflow/sdk/definitions/_internal/templater.py:328-334`

### Remediation
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

### Acceptance Criteria
- [ ] SandboxedNativeEnvironment class implemented combining sandbox and native features
- [ ] All NativeEnvironment usage replaced with SandboxedNativeEnvironment
- [ ] Test added verifying sandbox protections work in native mode
- [ ] Test added verifying native type rendering still functions correctly
- [ ] Documentation updated explaining the security model

### References
- Related: FINDING-013
- Source Reports: 1.3.5.md, 1.3.7.md

### Priority
**High** - Complete sandbox bypass allowing arbitrary code execution in native mode

---

## Issue: FINDING-002 - No crypto agility - encryption algorithm hardcoded to Fernet with no migration path
**Labels:** bug, security, priority:high
**Description:**
### Summary
The codebase uses Fernet (AES-128-CBC + HMAC-SHA256) with no documented migration path to AES-256 or post-quantum cryptography alternatives. When encryption algorithms need upgrading for compliance or security, there is no documented plan for migrating existing encrypted data.

### Details
Fernet (AES-128-CBC + HMAC-SHA256) is used for encrypting connection credentials, variable values, and serializer storage options. There is no version/algorithm metadata in encrypted data beyond Fernet's own versioning (0x80 byte), and no application-level metadata to facilitate bulk re-encryption during migration. The system lacks crypto agility to respond to algorithm deprecation or regulatory requirements.

**ASVS:** 11.2.2 (L2, L3), 11.1.4 (L2, L3)

### Affected Files
- `task-sdk/src/airflow/sdk/crypto.py` (entire file)

### Remediation
Implement a crypto-agile architecture with a configurable encryption backend:

1. Create an abstract EncryptionBackend class with encrypt, decrypt, rotate methods and algorithm_id property
2. Implement FernetBackend as the current implementation
3. Prepare for future backends like AESGCMBackend
4. Create a factory function get_encryption_backend() that reads algorithm choice from configuration

Example:
```python
class EncryptionBackend(ABC):
    @abstractmethod
    def encrypt(self, data: bytes) -> bytes: ...
    @abstractmethod
    def decrypt(self, data: bytes) -> bytes: ...
    @property
    @abstractmethod
    def algorithm_id(self) -> str: ...

def get_encryption_backend() -> EncryptionBackend:
    algorithm = conf.get("core", "encryption_algorithm", fallback="fernet")
    if algorithm == "fernet":
        return FernetBackend()
    elif algorithm == "aes-256-gcm":
        return AESGCMBackend()
    raise ValueError(f"Unknown encryption algorithm: {algorithm}")
```

### Acceptance Criteria
- [ ] Abstract EncryptionBackend interface defined
- [ ] FernetBackend implementation created wrapping existing code
- [ ] Factory function implemented with configuration support
- [ ] Documentation added for algorithm migration procedures
- [ ] Test added verifying backend switching mechanism

### References
- Source Reports: 11.2.2.md, 11.1.4.md

### Priority
**High** - Blocks future security upgrades and regulatory compliance

---

## Issue: FINDING-003 - No enforcement that base_url uses HTTPS - bearer token sent in cleartext over HTTP
**Labels:** bug, security, priority:high
**Description:**
### Summary
The Client accepts base_url without validating that it uses the HTTPS scheme. If misconfigured to use http://, the bearer token and all API traffic (including connection passwords, variable values, and XCom data) would be transmitted in cleartext.

### Details
The SSL context and verify parameter only apply to HTTPS connections - they do NOT prevent HTTP connections. This creates a silent security failure where the system appears to work correctly but has no transport security. Configuration flow: http://airflow-server:8080 → base_url → httpx makes HTTP requests → BearerAuth adds Authorization: Bearer &lt;token&gt; to cleartext request.

**CWE:** CWE-319  
**ASVS:** 12.2.1 (L1, L2), 12.3.3 (L1, L2)

### Affected Files
- `task-sdk/src/airflow/sdk/api/client.py:739-753`
- `task-sdk/src/airflow/sdk/api/client.py:580-600`

### Remediation
Add URL scheme validation in Client.__init__() to reject non-HTTPS base URLs:

```python
from urllib.parse import urlparse

parsed = urlparse(base_url)
if parsed.scheme != "https":
    raise ValueError(
        f"Execution API base_url must use HTTPS to protect bearer tokens. "
        f"Got: {base_url!r}. Set [api] execution_api_url to an https:// URL."
    )
```

### Acceptance Criteria
- [ ] URL scheme validation added to Client.__init__()
- [ ] ValueError raised for non-HTTPS URLs with clear error message
- [ ] Test added verifying HTTPS enforcement
- [ ] Test added verifying clear error message for HTTP URLs
- [ ] Documentation updated explaining HTTPS requirement

### References
- Source Reports: 12.2.1.md, 12.3.3.md

### Priority
**High** - Credentials transmitted in cleartext if misconfigured

---

## Issue: FINDING-004 - Silent Exception Suppression in Remote Log Upload
**Labels:** bug, security, priority:high
**Description:**
### Summary
If the remote log handler cannot be loaded or the path resolution fails, the function silently returns with no feedback mechanism to indicate that logs failed to reach the separate system. If remote log transmission consistently fails, the application continues operating without awareness that logs are only stored locally.

### Details
Combined with the fact that handler.upload() exceptions are not caught in upload_to_remote(), there's inconsistent error handling for log transmission. If remote log transmission consistently fails (due to network issues, TLS failures, or misconfiguration), the application continues operating without awareness - defeating the purpose of separate system storage required for security monitoring.

**ASVS:** 16.3.4 (L2), 16.4.3 (L2)

### Affected Files
- `task-sdk/src/airflow/sdk/log.py:210-211`

### Remediation
Add structured logging for all failure paths in upload_to_remote():

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

### Acceptance Criteria
- [ ] Structured logging added for all failure paths
- [ ] Warning logged when remote handler unavailable
- [ ] Error logged when path resolution fails
- [ ] Error logged when upload fails
- [ ] Test added verifying all error paths are logged
- [ ] Monitoring alert configured for remote log failures

### References
- Source Reports: 16.3.4.md, 16.4.3.md

### Priority
**High** - Silent failure defeats security monitoring requirements

---

## Issue: FINDING-005 - Unhandled Network Exceptions Crash IPC Communication Channel
**Labels:** bug, security, priority:high
**Description:**
### Summary
External API calls raise httpx.ConnectError/httpx.TimeoutException which are NOT caught by except ServerResponseError, causing the generator to crash and permanently breaking the IPC channel.

### Details
When the API server becomes temporarily unreachable (network partition, DNS failure, or server restart), any request from the task runner that triggers an API call would raise a network-level exception. Since only ServerResponseError is caught, the generator crashes, the request handler socket is closed, the task runner gets EOFError on next communication attempt, and the entire IPC channel is permanently broken.

**ASVS:** 16.5.2 (L2)

### Affected Files
- `task-sdk/src/airflow/sdk/execution_time/supervisor.py:415-450`

### Remediation
Add catch-all exception handler to handle_requests generator:

```python
try:
    response = _handle_request(msg)
    yield response
except ServerResponseError as e:
    log.error("api_server_error", error=str(e))
    yield ErrorResponse(...)
except Exception as e:
    # Catch ALL exceptions to prevent generator crash
    log.error("unexpected_request_error", error_type=type(e).__name__, error=str(e))
    yield ErrorResponse(
        error=ErrorType.GENERIC_ERROR,
        detail=f"Internal error processing request: {type(e).__name__}"
    )
```

### Acceptance Criteria
- [ ] Catch-all exception handler added to prevent generator crashes
- [ ] Generic error response sent to task on unexpected exceptions
- [ ] Test added verifying IPC channel survives network errors
- [ ] Test added verifying task receives error response
- [ ] Logging added for unexpected exceptions

### References
- Source Reports: 16.5.2.md

### Priority
**High** - Permanent IPC channel failure requires supervisor restart

---

## Issue: FINDING-006 - Fail-open Condition When Terminal State Delivery Fails
**Labels:** bug, security, priority:high
**Description:**
### Summary
A failed task is incorrectly marked as successful when IPC communication fails during terminal state reporting. The process exits with code 0, causing the supervisor to interpret the task as SUCCESS when terminal state message delivery fails.

### Details
Task execution fails and sets state to FAILED, but when SUPERVISOR_COMMS.send(msg=msg) raises an exception in the finally block, the exception is caught and logged without preventing normal exit. The process exits with code 0, causing the supervisor to interpret _exit_code == 0 with _terminal_state is None as SUCCESS. This creates a fail-open condition where corrupted data pipelines continue processing downstream tasks based on incorrect upstream success.

**ASVS:** 16.5.3 (L2)

### Affected Files
- `task-sdk/src/airflow/sdk/execution_time/task_runner.py` (finally block in run())
- `task-sdk/src/airflow/sdk/execution_time/supervisor.py` (final_state property)

### Remediation
Exit with non-zero code when terminal state delivery fails:

```python
finally:
    try:
        SUPERVISOR_COMMS.send(msg=msg)
    except Exception:
        log.exception("Failed to send terminal state to supervisor")
        sys.exit(1)  # Signal failure to supervisor via exit code
```

This ensures the supervisor doesn't incorrectly mark the task as SUCCESS when the terminal state message cannot be delivered.

### Acceptance Criteria
- [ ] Non-zero exit code on terminal state delivery failure
- [ ] Test added verifying failed state delivery causes task failure
- [ ] Test added verifying supervisor interprets exit code correctly
- [ ] Documentation updated explaining state delivery failure handling

### References
- Source Reports: 16.5.3.md

### Priority
**High** - Data corruption via incorrect success status

---

## Issue: FINDING-007 - Terminal State Set Locally Before API Call With No Recovery on Failure
**Labels:** bug, security, priority:high
**Description:**
### Summary
Task process sends SucceedTask → _terminal_state set to SUCCESS → client.task_instances.succeed() fails (network error) → ServerResponseError caught → error sent to task → task exits with 0 → final_state returns SUCCESS → update_task_state_if_needed() sees SUCCESS in STATES_SENT_DIRECTLY → NO retry → Task stuck as RUNNING on server forever.

### Details
During transient network failures or API server restarts, completed tasks can become permanently stuck in RUNNING state, requiring manual intervention to resolve. This affects all terminal states in STATES_SENT_DIRECTLY (SUCCESS, DEFERRED, UP_FOR_RESCHEDULE, UP_FOR_RETRY). Tasks stuck in RUNNING will block downstream dependencies and may trigger false alerts. The same pattern applies to DeferTask and RescheduleTask handlers.

**ASVS:** 2.3.3 (L2)

### Affected Files
- `task-sdk/src/airflow/sdk/execution_time/supervisor.py:517-590`

### Remediation
Set _terminal_state only after the API call succeeds, or implement retry-on-failure:

```python
# Attempt the API call FIRST
try:
    msg = SUPERVISOR_COMMS.send(GetConnection(conn_id=conn_id))
    if isinstance(msg, ErrorResponse):
        # Don't set _terminal_state - allow retry
        return
    # Only mark as sent after successful API call
    self._terminal_state = TerminalState.SUCCESS
except Exception:
    # Allow update_task_state_if_needed() to retry
    return
```

Alternative: Add a _state_reported_to_server flag and check it in update_task_state_if_needed() to always try to report regardless of STATES_SENT_DIRECTLY when the previous send failed.

### Acceptance Criteria
- [ ] Terminal state only set after successful API call
- [ ] Retry logic implemented for failed terminal state reporting
- [ ] Test added verifying retry on network failure
- [ ] Test added verifying eventual state consistency
- [ ] Monitoring added for stuck RUNNING tasks

### References
- Source Reports: 2.3.3.md

### Priority
**High** - Tasks permanently stuck requiring manual intervention

---

## Issue: FINDING-008 - Unbounded message length allocation allows memory exhaustion DoS
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The supervisor process reads a 4-byte length prefix from untrusted task processes and allocates a buffer of that size without any upper bound check. A malicious task process can request allocation of up to 4GB, causing OOM conditions that could crash the supervisor and affect all concurrent tasks.

### Details
The sending side has a 4GiB overflow check in _FrameMixin.as_bytes(), but this check doesn't exist on the receive side where an attacker can craft raw bytes. The supervisor manages potentially many task subprocesses and can be crashed via an out-of-memory condition triggered by a single malicious task, violating the stated trust boundary that treats task code as untrusted.

**CWE:** CWE-770  
**ASVS:** 1.3.3 (L2), 2.2.2 (L2, L1), 15.2.2 (L2, L1)

### Affected Files
- `task-sdk/src/airflow/sdk/execution_time/supervisor.py:1700-1738`
- `task-sdk/src/airflow/sdk/execution_time/comms.py:236-269`

### Remediation
Implement a MAX_MESSAGE_SIZE constant (e.g., 64 MiB) and validate the length prefix before allocating the buffer:

```python
MAX_MESSAGE_SIZE = 64 * 1024 * 1024  # 64 MiB

if length_needed > MAX_MESSAGE_SIZE:
    log.error("Message too large, rejecting", size=length_needed, max=MAX_MESSAGE_SIZE)
    return False
```

Apply this check in both length_prefixed_frame_reader and CommsDecoder._read_frame.

### Acceptance Criteria
- [ ] MAX_MESSAGE_SIZE constant defined
- [ ] Length validation added before buffer allocation
- [ ] Test added verifying oversized messages are rejected
- [ ] Error logged when oversized message detected
- [ ] Documentation updated with message size limits

### References
- Related: FINDING-010
- Source Reports: 1.3.3.md, 2.2.2.md, 15.2.2.md

### Priority
**Medium** - DoS attack requires malicious task code

---

## Issue: FINDING-009 - Validation failure in handle_requests does not send error response to task
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The documented protocol guarantees 'Every request returns a response, even if the frame is otherwise empty.' When validation fails in the handle_requests method, no response is sent, causing the task process to block indefinitely on recv().

### Details
While the supervisor will eventually kill the task via heartbeat timeout, this takes HEARTBEAT_TIMEOUT seconds (much longer than needed for a simple error response). Data flow: Task process sends request → supervisor receives frame → validation fails → supervisor logs error and continues → task process blocks forever waiting for response. This is a Type C gap - validation is CALLED but the RESULT (error) is not COMMUNICATED back to the caller.

**CWE:** CWE-755  
**ASVS:** 2.2.1 (L1)

### Affected Files
- `task-sdk/src/airflow/sdk/execution_time/supervisor.py:637-669`

### Remediation
Send an error response when validation fails:

```python
except ValidationError as e:
    log.error("Invalid request", error=str(e))
    self.send_msg(ErrorResponse(
        error=ErrorType.GENERIC_ERROR,
        detail=f"Invalid request: {e}"
    ))
    continue
```

This ensures the task process receives a response and can handle the error gracefully rather than hanging indefinitely.

### Acceptance Criteria
- [ ] Error response sent on validation failure
- [ ] Test added verifying task receives error response
- [ ] Test added verifying task doesn't hang on invalid request
- [ ] Documentation updated explaining error response protocol

### References
- Source Reports: 2.2.1.md

### Priority
**Medium** - Task hangs until timeout but is eventually killed

---

## Issue: FINDING-010 - Unbounded string fields in IPC messages used for HTTP request construction
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The supervisor builds HTTP requests using string values from untrusted task messages without validating their length. Untrusted task processes can send extremely long strings that would cause 414 URI Too Long or 431 Request Header Fields Too Large errors.

### Details
Task processes send IPC messages with unbounded string fields (dag_id, task_id, key, name, uri, conn_id, etc.) that are validated for type by Pydantic but not for length. The supervisor then constructs HTTP requests to the API server using these unbounded strings in URL/query parameters, potentially causing persistent error responses, wasting supervisor resources, and generating excessive error logging.

**CWE:** CWE-770  
**ASVS:** 2.2.1 (L1), 2.2.2 (L1), 4.2.5 (L3), 2.1.1 (L1)

### Affected Files
- `task-sdk/src/airflow/sdk/execution_time/comms.py`
- `task-sdk/src/airflow/sdk/execution_time/supervisor.py:1142-1379`

### Remediation
Add Field(max_length=...) constraints to Pydantic models in comms.py:

```python
key: str = Field(max_length=512)
dag_id: str = Field(max_length=250)
run_id: str = Field(max_length=250)
task_id: str = Field(max_length=250)
value: str | None = Field(max_length=65536)
description: str | None = Field(max_length=5000)
```

Align these constraints with those enforced by the API server.

### Acceptance Criteria
- [ ] max_length constraints added to all string fields
- [ ] Constraints aligned with API server limits
- [ ] Test added verifying oversized strings are rejected
- [ ] ValidationError raised with clear message
- [ ] Documentation updated with field size limits

### References
- Related: FINDING-008
- Source Reports: 2.2.1.md, 2.2.2.md, 4.2.5.md, 2.1.1.md

### Priority
**Medium** - DoS via resource exhaustion requires malicious task

---

## Issue: FINDING-011 - Relaxed is_safe_attribute allows access to private attributes
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The custom is_safe_attribute override only blocks __ prefixed attributes via is_internal_attribute, but allows access to all _ prefixed private attributes. This weakens Jinja2's default SandboxedEnvironment behavior which blocks both _ and __ prefixed attributes.

### Details
Templates can access internal implementation attributes of objects in the rendering context, potentially exposing sensitive data like connection credentials or internal state. The relaxed check allows templates to access any attribute starting with a single underscore, which may include internal implementation details not intended for template access.

**CWE:** CWE-668  
**ASVS:** 1.3.5 (L2)

### Affected Files
- `task-sdk/src/airflow/sdk/definitions/_internal/templater.py:328`

### Remediation
Define an allowlist of specific _-prefixed attributes that templates legitimately need:

```python
_ALLOWED_PRIVATE_ATTRS = frozenset({"_key", "_defer", ...})  # Document legitimate needs

def is_safe_attribute(self, obj, attr, value):
    if attr.startswith("_"):
        return attr in _ALLOWED_PRIVATE_ATTRS
    return not jinja2.sandbox.is_internal_attribute(obj, attr)
```

### Acceptance Criteria
- [ ] Allowlist of permitted private attributes defined
- [ ] is_safe_attribute updated to use allowlist
- [ ] Test added verifying blocked private attributes are rejected
- [ ] Test added verifying allowed private attributes work
- [ ] Documentation added explaining allowlist rationale

### References
- Source Reports: 1.3.5.md

### Priority
**Medium** - Requires specific context object with sensitive private attributes

---

## Issue: FINDING-012 - jinja_environment_kwargs allows overriding security-critical settings
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The jinja_environment_kwargs parameter allows DAG authors to unconditionally override all previously set Jinja2 environment options via .update() without any validation. Security-relevant settings like loader, extensions, or undefined can be replaced.

### Details
DAG authors can override the FileSystemLoader searchpath to read arbitrary files, add unsafe extensions like jinja2.ext.debug that expose the template context, or change undefined variable behavior. The .update() call happens after security settings are configured, allowing them to be silently overridden.

**CWE:** CWE-15  
**ASVS:** 1.3.5 (L2)

### Affected Files
- `task-sdk/src/airflow/sdk/definitions/_internal/templater.py:393`

### Remediation
Validate jinja_environment_kwargs against a blocklist of security-sensitive keys:

```python
_BLOCKED_ENV_KWARGS = frozenset({"loader", "enable_async"})

if jinja_environment_kwargs:
    blocked = set(jinja_environment_kwargs) & _BLOCKED_ENV_KWARGS
    if blocked:
        raise ValueError(f"Cannot override security-sensitive env options: {blocked}")
    jinja_env_options.update(jinja_environment_kwargs)
```

### Acceptance Criteria
- [ ] Blocklist of security-sensitive keys defined
- [ ] Validation added before .update() call
- [ ] ValueError raised when blocked keys present
- [ ] Test added verifying blocked keys are rejected
- [ ] Documentation updated listing blocked keys

### References
- Source Reports: 1.3.5.md

### Priority
**Medium** - Requires DAG author access but bypasses sandbox

---

## Issue: FINDING-013 - from_string() compiles any string value as Jinja template without validation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The render_template method compiles any string in template_fields attributes as a Jinja template using from_string() without validating whether the string contains template syntax or sanitizing template constructs.

### Details
If template field values are influenced by untrusted input (through Airflow Variables, XCom, trigger parameters, etc.), the string is compiled as a template. In sandboxed mode damage is limited, but in native mode this enables full code execution. There is no mechanism to distinguish between fields that should be templated and fields that should be treated as literal strings.

**CWE:** CWE-1336  
**ASVS:** 1.3.7 (L2)

### Affected Files
- `task-sdk/src/airflow/sdk/definitions/_internal/templater.py:209-213`

### Remediation
Add an opt-in mechanism to mark fields as 'template-safe' vs 'literal-only':

1. Implement _should_template_field() method to determine if a field should be templated
2. Add template content validation before from_string() to verify that template content matches expected patterns
3. Provide a decorator/annotation for fields that should not be templated even if they contain template syntax

### Acceptance Criteria
- [ ] Field-level templating control mechanism added
- [ ] Template content validation implemented
- [ ] Test added verifying literal-only fields aren't templated
- [ ] Test added verifying dangerous constructs are blocked
- [ ] Documentation added explaining field annotation system

### References
- Related: FINDING-001
- Source Reports: 1.3.7.md

### Priority
**Medium** - Requires untrusted input in template fields

---

## Issue: FINDING-014 - No Data Classification-Based Logging Enforcement
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The ASVS requirement specifies that logging should be enforced based on the data's protection level. The current implementation applies uniform string replacement on all registered secrets without distinguishing between protection levels (credentials vs. session tokens vs. PII).

### Details
There is no mechanism to: (1) Completely suppress log records containing credential-class data, (2) Hash session tokens instead of masking them (allowing correlation without exposure), (3) Partially mask lower-sensitivity data, (4) Enforce different retention policies based on data classification. All sensitive data types are treated identically in logs, meaning credentials that should never appear in logs still produce log entries with *** markers.

**ASVS:** 16.2.5 (L2), 16.3.3 (L2), 16.3.4 (L2)

### Affected Files
- `task-sdk/src/airflow/sdk/log.py:58-60`
- `task-sdk/src/airflow/sdk/log.py:231`

### Remediation
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

### Acceptance Criteria
- [ ] Data classification system implemented for secrets
- [ ] Different handling based on classification level
- [ ] Test added verifying credentials are fully suppressed
- [ ] Test added verifying session tokens are hashed
- [ ] Documentation added explaining classification levels

### References
- Source Reports: 16.2.5.md, 16.3.3.md, 16.3.4.md

### Priority
**Medium** - Enhanced security control for L2 compliance

---

## Issue: FINDING-015 - No Explicit Log Injection Encoding in Logging Processor Pipeline
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The visible logging pipeline does not include an explicit log injection encoding processor. The mask_logs processor only applies secret redaction - it does not sanitize newlines, ANSI escape sequences, or other control characters that could be used for log injection/forging.

### Details
When json_output=False (console/file logging), structlog's ConsoleRenderer does not escape embedded newlines by default. If task code logs external input (e.g., API responses, file contents, HTTP headers), an attacker-controlled value containing crafted newlines followed by fake log entries could forge log entries, inject ANSI escape sequences, or break log parsing in aggregation systems.

**ASVS:** 16.4.1 (L2)

### Affected Files
- `task-sdk/src/airflow/sdk/log.py:63-80`

### Remediation
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

### Acceptance Criteria
- [ ] Log injection encoding processor implemented
- [ ] Processor added to pipeline before mask_logs
- [ ] Test added verifying newlines are escaped
- [ ] Test added verifying ANSI sequences are stripped
- [ ] Test added verifying control characters are removed

### References
- Source Reports: 16.4.1.md

### Priority
**Medium** - Requires attacker-controlled input in logs

---

## Issue: FINDING-016 - No cache eviction mechanism for task boundary isolation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The SecretCache class stores secrets in a shared dictionary with configurable TTL (default 15 minutes) but has no mechanism to clear secrets between task executions. Secrets from a previous task remain accessible for up to the TTL duration, allowing subsequent tasks with fewer permissions to access cached secrets.

### Details
The only clearing mechanism (reset()) destroys the entire cache and is explicitly marked "test purposes only." If a supervisor process handles multiple tasks sequentially, secrets from Task A remain accessible when Task B starts in the same process. Task B calls SecretCache.get_variable() and receives Task A's cached secrets without re-authorization.

**ASVS:** 13.3.1 (L2)

### Affected Files
- `task-sdk/src/airflow/sdk/execution_time/cache.py`

### Remediation
Add a clear() method to SecretCache that clears all cached secrets and must be called on task completion:

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

### Acceptance Criteria
- [ ] clear() method implemented
- [ ] invalidate_connection_uri() method implemented
- [ ] Supervisor calls clear() on task completion
- [ ] Test added verifying cache cleared between tasks
- [ ] Test added verifying secrets not leaked across tasks

### References
- Source Reports: 13.3.1.md

### Priority
**Medium** - Requires specific multi-task execution scenario

---

## Issue: FINDING-017 - Broad exception handling masks authorization failures
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Both get_connection() and get_variable() treat all ErrorResponse messages identically - whether the error represents "not found," "unauthorized," or "server error." By returning None for authorization failures, the secrets manager proceeds to check the next backend (EnvironmentVariablesBackend) which performs NO authorization checks.

### Details
This is a Type C gap: an authorization control is invoked (Execution API checks permissions), but its rejection result is treated as "not found" rather than "access denied," allowing the system to bypass the authorization by falling through to an unauthenticated backend. Tasks can access secrets they're explicitly denied from the Execution API if those secrets also exist in environment variables.

**ASVS:** 8.2.1 (L1)

### Affected Files
- `task-sdk/src/airflow/sdk/execution_time/secrets/execution_api.py:44-89`

### Remediation
Differentiate between "not found" and "unauthorized" error responses:

```python
def get_connection(self, conn_id: str, team_name: str | None = None) -> Connection | None:
    try:
        msg = SUPERVISOR_COMMS.send(GetConnection(conn_id=conn_id))

        if isinstance(msg, ErrorResponse):
            if msg.is_authorization_error:
                # Raise to prevent fallback - access is explicitly denied
                raise PermissionError(f"Access denied for connection: {conn_id}")
            # Not found - allow fallback
            return None

        return _process_connection_result_conn(msg)
    except PermissionError:
        raise  # Don't catch authorization errors
    except Exception:
        return None
```

### Acceptance Criteria
- [ ] Authorization errors distinguished from not-found errors
- [ ] PermissionError raised for authorization failures
- [ ] Test added verifying no fallback on authorization denial
- [ ] Test added verifying fallback on not-found
- [ ] Documentation updated explaining error handling

### References
- Source Reports: 8.2.1.md

### Priority
**Medium** - Authorization bypass for secrets in multiple backends

---

## Issue: FINDING-018 - Silent fallback to _NullFernet when encryption key missing
**Labels:** bug, security, priority:medium
**Description:**
### Summary
When FERNET_KEY is not configured, the _NullFernet class is used which performs no encryption or decryption. This results in connection passwords and variable values being stored/transmitted in plaintext. While a warning is logged, the system continues to operate without encryption.

### Details
Configuration (core.FERNET_KEY empty) → get_fernet() returns _NullFernet → all encrypt()/decrypt() calls become no-ops → sensitive data stored/transmitted in plaintext. Note: Per the domain context, this is an intentional design decision where the SDK delegates key management to the Airflow server. The _NullFernet is primarily used in development/testing scenarios. In production, Fernet keys should always be configured.

**ASVS:** 11.1.1 (L2), 11.2.5 (L2, L3), 11.3.3 (L2, L3), 11.6.1 (L2, L3), 13.2.3 (L1, L2)

### Affected Files
- `task-sdk/src/airflow/sdk/crypto.py:97-116`

### Remediation
Either refuse to start when FERNET_KEY is not configured (fail-closed), or at minimum enforce that callers check is_encrypted before proceeding:

```python
def get_fernet() -> Fernet | _NullFernet:
    fernet_key = conf.get("core", "FERNET_KEY")
    if not fernet_key:
        if conf.getboolean("core", "require_encryption", fallback=True):
            raise AirflowException(
                'FERNET_KEY is not configured. Encryption is required for storing sensitive data. '
                'Generate a key with: python -c "from cryptography.fernet import Fernet; '
                'print(Fernet.generate_key().decode())"'
            )
        log.error("FERNET_KEY not configured - encryption disabled")
        return _NullFernet()
    return Fernet(fernet_key.encode())
```

### Acceptance Criteria
- [ ] Configuration option added to require encryption
- [ ] Startup validation with ERROR level logging
- [ ] Metrics counter emitted when _NullFernet active
- [ ] Test added verifying exception when required
- [ ] Documentation updated explaining encryption requirement

### References
- Source Reports: 11.1.1.md, 11.2.5.md, 11.3.3.md, 11.6.1.md, 13.2.3.md

### Priority
**Medium** - Intentional design but needs better enforcement

---

## Issue: FINDING-019 - Cached Fernet instance prevents runtime key replacement
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The @cache decorator (equivalent to @lru_cache(maxsize=None)) on get_fernet() means the Fernet instance is created once per process and never refreshed. If keys need to be rotated or replaced during the lifetime of a task process, the change won't take effect.

### Details
This conflicts with the requirement that it must be possible to replace keys and passwords and re-encrypt data. First call to get_fernet() results in a cached result forever, and subsequent key configuration changes are ignored.

**ASVS:** 11.2.2 (L2), 14.2.2 (L2)

### Affected Files
- `task-sdk/src/airflow/sdk/crypto.py:~97`

### Remediation
Provide a mechanism to invalidate the cache when keys are rotated:

```python
_fernet_cache: Fernet | _NullFernet | None = None

def get_fernet() -> Fernet | _NullFernet:
    global _fernet_cache
    if _fernet_cache is None:
        # Load Fernet instance
        _fernet_cache = _load_fernet()
    return _fernet_cache

def invalidate_fernet_cache():
    """Invalidate cached Fernet instance to force reload on next call."""
    global _fernet_cache
    _fernet_cache = None
```

This allows runtime key rotation to take effect by explicitly invalidating the cache.

### Acceptance Criteria
- [ ] Manual cache implementation with global variable
- [ ] invalidate_fernet_cache() function added
- [ ] Test added verifying cache invalidation works
- [ ] Test added verifying new key loaded after invalidation
- [ ] Documentation added explaining key rotation procedure

### References
- Source Reports: 11.2.2.md, 14.2.2.md

### Priority
**Medium** - Blocks runtime key rotation capability

---

## Issue: FINDING-020 - No formal cryptographic inventory documentation
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The codebase lacks a formal cryptographic inventory document that catalogs all cryptographic algorithms in use, key types and purposes, usage boundaries, data classification requirements, and certificate usage. Without this inventory, it's difficult to assess impact of algorithm deprecation or plan migration to post-quantum cryptography.

### Details
The current code uses a single Fernet key for all encryption (connections and variables) without documenting the intended scope or restrictions. A maintained cryptographic inventory is needed to: assess impact of algorithm deprecation, plan migration to post-quantum cryptography, audit key usage boundaries, and identify if keys are being used beyond their intended scope.

**ASVS:** 11.1.2 (L2)

### Affected Files
- All analyzed files

### Remediation
Create and maintain a cryptographic inventory document (e.g., CRYPTO_INVENTORY.md or structured YAML) that includes:

- Algorithm ID: fernet-aes128-cbc-hmac-sha256
- Algorithm Details: AES-128-CBC + HMAC-SHA256 via Fernet
- Library: cryptography (pyca)
- Version Constraint: >=41.0.0
- Key Source: core.FERNET_KEY configuration
- Key Length: 256 bits (128 signing + 128 encryption)
- Usage: encrypt/decrypt connection passwords, connection extra fields, variable values
- Restrictions: Must not be used for TLS/transport encryption, Must not be shared with external systems
- Rotation Policy: Managed by Airflow server
- PQC Migration Status: Planned - awaiting crypto agility implementation

### Acceptance Criteria
- [ ] CRYPTO_INVENTORY.md document created
- [ ] All cryptographic algorithms documented
- [ ] Key usage boundaries documented
- [ ] Rotation policies documented
- [ ] PQC migration plan documented
- [ ] Document referenced from code comments

### References
- Source Reports: 11.1.2.md

### Priority
**Medium** - Documentation gap affecting future planning

---

## Issue: FINDING-021 - No explicit cipher suite configuration - relies on system defaults
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The enabled cipher suites are determined entirely by the system's OpenSSL build and configuration. While modern OpenSSL defaults are generally reasonable, they may include weaker ciphers (e.g., AES-CBC without forward secrecy on older systems). For L3 compliance, only cipher suites providing forward secrecy should be permitted.

### Details
Without explicit configuration, the security posture is non-deterministic across deployment environments. Different systems may have different cipher suite configurations, leading to inconsistent security levels.

**CWE:** CWE-327  
**ASVS:** 12.1.2 (L2, L3)

### Affected Files
- `task-sdk/src/airflow/sdk/api/client.py:733-738`

### Remediation
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

### Acceptance Criteria
- [ ] Explicit cipher suite configuration added
- [ ] Minimum TLS version set to TLSv1.2
- [ ] Forward secrecy required for all cipher suites
- [ ] Test added verifying cipher suite restrictions
- [ ] Documentation updated explaining cipher suite policy

### References
- Related: FINDING-072
- Source Reports: 12.1.2.md

### Priority
**Medium** - Security posture varies across environments

---

## Issue: FINDING-022 - Ambiguous operator precedence in deserialization type-dispatch
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Due to Python's operator precedence (and binds tighter than or), the condition `if CLASSNAME not in o and not type_hint or VERSION not in o:` evaluates incorrectly. While the current behavior is safe (treating untyped data as plain dicts), the unclear precedence could lead to bugs during maintenance.

### Details
The condition evaluates as `(CLASSNAME not in o and not type_hint) or (VERSION not in o)`. This means: A dict with CLASSNAME but without VERSION is always treated as a plain dict (even if type_hint is provided); A dict without CLASSNAME and without type_hint is treated as a plain dict (correct behavior). The ambiguous precedence could lead to vulnerabilities during maintenance if a developer misreads the intent.

**ASVS:** 15.3.5 (L2)

### Affected Files
- `task-sdk/src/airflow/sdk/serde/__init__.py:225`

### Remediation
Use explicit parentheses to clarify intent:

```python
if (CLASSNAME not in o and not type_hint) or (VERSION not in o):
```

Or better, split into separate conditions with clear comments:

```python
# If no classname and no type hint, treat as plain dict
if CLASSNAME not in o and not type_hint:
    return {str(k): deserialize(v, full) for k, v in o.items()}

# If no version info, cannot perform typed deserialization
if VERSION not in o:
    return {str(k): deserialize(v, full) for k, v in o.items()}
```

### Acceptance Criteria
- [ ] Explicit parentheses added or conditions split
- [ ] Comments added explaining intent
- [ ] Test added verifying correct evaluation order
- [ ] Code review confirms clarity improvement

### References
- Source Reports: 15.3.5.md

### Priority
**Medium** - Code clarity issue with potential security implications

---

## Issue: FINDING-023 - No documentation identifying risky third-party components
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The module uses structlog as a third-party dependency and re-exports functions from airflow.sdk._shared.module_loading. There is no accompanying documentation identifying which third-party dependencies might be considered "risky components" or what remediation timeframes apply.

### Details
Without documentation of risky components, developers and security reviewers cannot: assess the risk level of dependencies, prioritize security updates appropriately, or plan remediation timeframes for vulnerable components.

**ASVS:** 15.1.4 (L3)

### Affected Files
- `task-sdk/src/airflow/sdk/definitions/callback.py:1-150`
- `task-sdk/src/airflow/sdk/module_loading.py:1-27`

### Remediation
Create and maintain a security documentation artifact (e.g., SECURITY.md or architecture decision record) that:

- Lists all third-party dependencies
- Classifies each by risk level based on maintenance status, vulnerability history, and functionality scope
- Defines remediation timeframes for each risk tier
- Is referenced from module-level docstrings where risky components are used

Example inline documentation pattern:
```python
# SECURITY NOTE: This module depends on:
# - structlog (LOW risk): Well-maintained, active community, no dangerous operations
# - importlib (STDLIB): Used for dynamic module loading - see SECURITY.md for risk classification
```

### Acceptance Criteria
- [ ] SECURITY.md document created
- [ ] All third-party dependencies classified by risk
- [ ] Remediation timeframes defined per risk tier
- [ ] Module docstrings reference security documentation
- [ ] Document maintained as dependencies change

### References
- Source Reports: 15.1.4.md

### Priority
**Medium** - L3 requirement for risk management

---

## Issue: FINDING-024 - Dynamic code execution via import not documented as dangerous functionality
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The get_callback_path() method performs dynamic code execution by importing arbitrary Python modules from string paths. While the class docstring explains the business purpose, it does not explicitly identify this as "dangerous functionality" requiring heightened security scrutiny.

### Details
The domain context explicitly states: "Module loading is a potential code execution vector if an attacker can control the import path" — yet this acknowledgment exists only in external documentation, not in the code itself. Developers modifying this code may not recognize the security-critical nature without explicit documentation, increasing the risk of introducing vulnerabilities during maintenance.

**ASVS:** 15.1.5 (L3)

### Affected Files
- `task-sdk/src/airflow/sdk/definitions/callback.py:55-85`

### Remediation
Add explicit security documentation annotations to the method docstring:

```python
def get_callback_path(self) -> tuple[Callable, str]:
    """
    Resolve callback to (callable, import_path) tuple.
    
    **SECURITY WARNING - DANGEROUS FUNCTIONALITY**
    
    This method performs dynamic code execution by importing Python modules
    from string paths. Importing a module executes its module-level code.
    
    Input MUST be validated via is_valid_dotpath() before import.
    Callers must ensure string paths originate from trusted sources
    (e.g., the serialized DAG store in the Airflow metadata database).
    
    See SECURITY.md#dynamic-code-loading for additional context.
    """
```

### Acceptance Criteria
- [ ] Security warning added to method docstring
- [ ] Dynamic code execution explicitly documented
- [ ] Input validation requirements documented
- [ ] Trusted source requirement documented
- [ ] Reference to SECURITY.md added

### References
- Source Reports: 15.1.5.md

### Priority
**Medium** - Documentation gap for security-critical code

---

## Issue: FINDING-025 - Dynamic import lacks namespace restriction allowlist
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The domain context explicitly states: "the system must maintain an allowlist of permitted module prefixes and reject any attempts to import from unexpected locations." However, the get_callback_path() method only validates dotpath FORMAT via is_valid_dotpath() without restricting which namespaces/modules can be imported.

### Details
The format validation control EXISTS (is_valid_dotpath) but namespace restriction is NOT IMPLEMENTED at this layer. If the trust boundary (Execution API / metadata database) is ever compromised, there is no defense-in-depth preventing import of dangerous modules (e.g., os, subprocess, shutil).

**ASVS:** 15.2.5 (L3)

### Affected Files
- `task-sdk/src/airflow/sdk/definitions/callback.py:62-80`

### Remediation
Implement namespace allowlisting as defense-in-depth:

```python
ALLOWED_CALLBACK_PREFIXES = (
    'airflow.',
    'airflow_providers.',
)

def get_callback_path(self) -> tuple[Callable, str]:
    # ... existing code ...
    
    if isinstance(self.callback, str):
        if not any(self.callback.startswith(prefix) for prefix in ALLOWED_CALLBACK_PREFIXES):
            raise ImportError(
                f"Callback module {self.callback!r} is not in allowed namespaces. "
                f"Allowed prefixes: {ALLOWED_CALLBACK_PREFIXES}"
            )
```

### Acceptance Criteria
- [ ] ALLOWED_CALLBACK_PREFIXES defined
- [ ] Namespace validation added before import
- [ ] Test added verifying disallowed namespaces rejected
- [ ] Test added verifying allowed namespaces work
- [ ] Documentation updated with allowlist rationale

### References
- Source Reports: 15.2.5.md

### Priority
**Medium** - Defense-in-depth control for L3 compliance

---

## Issue: FINDING-026 - Unbounded polling loop in synchronous DAG run wait
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The _handle_trigger_dag_run function implements an unbounded while loop when wait_for_completion=True and deferrable=False. If a triggered DAG run enters a state not in allowed_states or failed_states (e.g., 'queued'), the task loops indefinitely, consuming a worker slot.

### Details
The task's execution_timeout does not protect this code path because the timeout context manager has already been exited when this exception handler runs. A worker slot remains occupied until the server explicitly rejects a heartbeat (which may take hours or never happen) or manual intervention terminates the task.

**ASVS:** 15.2.2 (L2), 2.3.2 (L2)

### Affected Files
- `task-sdk/src/airflow/sdk/execution_time/task_runner.py` (_handle_trigger_dag_run while True loop)

### Remediation
Add configurable maximum wait time with reasonable default:

```python
MAX_SYNC_POLL_SECONDS = conf.getfloat('core', 'trigger_dag_run_max_sync_wait', fallback=3600)
MIN_POKE_INTERVAL = 5.0

deadline = time.monotonic() + MAX_SYNC_POLL_SECONDS

while time.monotonic() < deadline:
    effective_interval = max(drte.poke_interval, MIN_POKE_INTERVAL)
    time.sleep(effective_interval)
    
    # ... check state ...

# If we exit the loop due to deadline
log.error("trigger_dag_run_timeout", max_wait=MAX_SYNC_POLL_SECONDS)
return TaskState(state=TerminalState.FAILED)
```

### Acceptance Criteria
- [ ] Maximum wait time configuration added
- [ ] Deadline-based loop termination implemented
- [ ] Minimum poke interval enforced
- [ ] Test added verifying timeout after deadline
- [ ] Test added verifying task marked FAILED on timeout

### References
- Source Reports: 15.2.2.md, 2.3.2.md

### Priority
**Medium** - Resource exhaustion requires specific conditions

---

## Issue: FINDING-027 - No rate limiting on task-to-supervisor IPC requests
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The supervisor's request handling loop processes incoming IPC messages from task subprocesses without any rate limiting controls. A malicious or buggy task can flood the supervisor with requests, leading to API server overload and potential denial of service.

### Details
Task subprocess (arbitrary code) → IPC socket → length_prefixed_frame_reader → handle_requests generator → _handle_request → API server HTTP calls — no rate limiting at any stage. This allows a single task to consume excessive supervisor and API server resources.

**ASVS:** 2.4.1 (L2)

### Affected Files
- `task-sdk/src/airflow/sdk/execution_time/supervisor.py` (handle_requests function)

### Remediation
Implement request rate limiting with a sliding window counter:

```python
class ActivitySubprocess:
    def __init__(self, ...):
        # ... existing code ...
        self._request_count = 0
        self._request_window_start = time.monotonic()
        self._max_requests_per_second = 100

    def _handle_request(self, msg):
        # Check rate limit
        now = time.monotonic()
        if now - self._request_window_start >= 1.0:
            # Reset window
            self._request_count = 0
            self._request_window_start = now
        
        self._request_count += 1
        if self._request_count > self._max_requests_per_second:
            log.warning("rate_limit_exceeded", task_id=self.id)
            return ErrorResponse(
                error=ErrorType.API_SERVER_ERROR,
                detail="Rate limit exceeded"
            )
        
        # ... existing request handling ...
```

### Acceptance Criteria
- [ ] Rate limiting implemented with sliding window
- [ ] Configurable max requests per second
- [ ] ErrorResponse returned when limit exceeded
- [ ] Test added verifying rate limit enforcement
- [ ] Metrics emitted for rate limit violations

### References
- Source Reports: 2.4.1.md

### Priority
**Medium** - DoS requires malicious or buggy task code

---

## Issue: FINDING-028 - Unlimited ResendLoggingFD calls leading to file descriptor exhaustion
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The supervisor creates new socket pairs and registers them with the selector every time it receives a ResendLoggingFD request, with no limit on the number of invocations. This can lead to file descriptor exhaustion in the supervisor process.

### Details
Task code → SUPERVISOR_COMMS.send(ResendLoggingFD()) → _handle_request → _send_new_log_fd → socketpair() (new FDs) + selector.register() — no limit on invocations. A malicious or buggy task could exhaust the supervisor's file descriptor limit, affecting all concurrent tasks.

**ASVS:** 2.4.1 (L2)

### Affected Files
- `task-sdk/src/airflow/sdk/execution_time/supervisor.py:~780` (in _handle_request, called via ResendLoggingFD)
- `task-sdk/src/airflow/sdk/execution_time/supervisor.py` (_send_new_log_fd function)

### Remediation
Add a counter to track ResendLoggingFD invocations per task:

```python
class ActivitySubprocess:
    def __init__(self, ...):
        # ... existing code ...
        self._log_fd_resend_count = 0
        self._max_log_fd_resends = 5

    def _handle_request(self, msg):
        if isinstance(msg, ResendLoggingFD):
            self._log_fd_resend_count += 1
            if self._log_fd_resend_count > self._max_log_fd_resends:
                log.warning("log_fd_resend_limit_exceeded", task_id=self.id)
                return ErrorResponse(
                    error=ErrorType.API_SERVER_ERROR,
                    detail="Log FD resend limit exceeded"
                )
```

### Acceptance Criteria
- [ ] Resend counter added per task
- [ ] Maximum resend limit enforced (default: 5)
- [ ] ErrorResponse returned when limit exceeded
- [ ] Test added verifying limit enforcement
- [ ] Warning logged when limit exceeded

### References
- Source Reports: 2.4.1.md

### Priority
**Medium** - Requires malicious or buggy task code

---

## Issue: FINDING-029 - No quota on costly write operations
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The supervisor processes write operations (XCom creation, variable setting, DAG run triggering) without enforcing per-task quotas. A malicious or buggy task can create massive amounts of garbage data or trigger resource-intensive operations.

### Details
Task code → unlimited SetXCom/PutVariable/TriggerDagRun messages → supervisor → API server — no write quota enforcement. This allows a single task to consume excessive storage and API server resources, potentially affecting other tasks and users.

**ASVS:** 2.4.1 (L2)

### Affected Files
- `task-sdk/src/airflow/sdk/execution_time/supervisor.py` (ActivitySubprocess._handle_request multiple branches)

### Remediation
Implement per-task write operation quotas:

```python
class ActivitySubprocess:
    MAX_XCOM_WRITES = 1000
    MAX_VARIABLE_WRITES = 100
    MAX_DAG_TRIGGERS = 10

    def __init__(self, ...):
        # ... existing code ...
        self._write_op_counts = {
            'xcom_set': 0,
            'variable_set': 0,
            'dag_trigger': 0,
        }

    def _check_write_quota(self, operation: str, limit: int) -> bool:
        self._write_op_counts[operation] += 1
        if self._write_op_counts[operation] > limit:
            log.warning("write_quota_exceeded", operation=operation, limit=limit)
            return False
        return True

    def _handle_request(self, msg):
        if isinstance(msg, SetXCom):
            if not self._check_write_quota('xcom_set', self.MAX_XCOM_WRITES):
                return ErrorResponse(error=ErrorType.GENERIC_ERROR, detail="XCom write quota exceeded")
```

### Acceptance Criteria
- [ ] Write operation quotas implemented
- [ ] Configurable limits per operation type
- [ ] ErrorResponse returned when quota exceeded
- [ ] Test added verifying quota enforcement
- [ ] Metrics emitted for quota violations

### References
- Source Reports: 2.4.1.md

### Priority
**Medium** - Requires malicious or buggy task code

---

## Issue: FINDING-030 - Undocumented External Communication Paths via Dynamic Secrets Backends
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The configuration system dynamically loads and initializes secrets backends that connect to external services (HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, etc.), but there is no documented inventory of which external services the application may connect to, what protocols and ports are used, or what network requirements exist.

### Details
The _get_custom_secret_backend method allows arbitrary external service configuration through airflow.cfg without any documentation of the resulting communication needs. This makes it impossible for network administrators to properly configure firewalls or for security teams to audit external dependencies.

**ASVS:** 13.1.1 (L2, L3)

### Affected Files
- `task-sdk/src/airflow/sdk/configuration.py:219-244`

### Remediation
Create a communication manifest document that:

1. Lists all possible external services the Task SDK may connect to
2. Documents the protocol, port, and authentication mechanism for each
3. Documents the configuration settings that enable each external connection
4. Specifies fallback/retry behavior when services are unavailable

Example structure (communication_manifest.yml):
```yaml
external_services:
  - name: HashiCorp Vault
    config_key: secrets.backend (when set to airflow.providers.hashicorp.secrets.vault.VaultBackend)
    protocols:
      - https (TCP/443)
      - http (TCP/8200, development only)
    authentication: Token-based or AppRole
    required: false
    fallback: Falls back to next backend in search path
```

### Acceptance Criteria
- [ ] Communication manifest document created
- [ ] All possible external services documented
- [ ] Protocols and ports documented per service
- [ ] Authentication mechanisms documented
- [ ] Configuration keys documented
- [ ] Fallback behavior documented

### References
- Source Reports: 13.1.1.md

### Priority
**Medium** - Documentation gap affecting deployment

---

## Issue: FINDING-031 - No Documentation of Critical Secrets or Rotation Schedule
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The code explicitly acknowledges the existence of critical secrets (FERNET_KEY, JWT_SECRET_KEY) in comments but provides no documentation of: a complete inventory of secrets, classification of which secrets are critical, rotation schedules for each secret, procedures for emergency rotation, or impact assessment if each secret is compromised.

### Details
The _SERVER_DEFAULT_SECRETS_SEARCH_PATH and custom secret backend configuration imply secrets are managed, but no formal documentation defines their lifecycle. Without this documentation, security operations cannot properly manage secret rotation or respond to compromise incidents.

**ASVS:** 13.1.4 (L3)

### Affected Files
- `task-sdk/src/airflow/sdk/configuration.py:85-94`

### Remediation
Create a secrets inventory document (secrets_inventory.yml):

```yaml
secrets:
  - name: Fernet Key
    config_key: core.FERNET_KEY
    purpose: Encrypt connection passwords and variable values
    classification: CRITICAL
    rotation_schedule: Every 90 days
    rotation_procedure: See docs/key_rotation.md
    compromise_impact: All encrypted connections and variables exposed
  
  - name: API Bearer Token
    config_key: Generated per task execution
    purpose: Authenticate task to Execution API
    classification: HIGH
    rotation_schedule: Per-task-execution (ephemeral)
    rotation_procedure: Automatic
    compromise_impact: Single task execution compromised
```

### Acceptance Criteria
- [ ] secrets_inventory.yml document created
- [ ] All secrets documented with classification
- [ ] Rotation schedules defined per secret
- [ ] Rotation procedures documented
- [ ] Compromise impact documented
- [ ] Document referenced from code comments

### References
- Source Reports: 13.1.4.md

### Priority
**Medium** - L3 requirement for secret lifecycle management

---

## Issue: FINDING-032 - No Explicit Classification of Sensitive Configuration Values
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The configuration system processes all values uniformly without classifying them into protection levels. There is no mechanism to mark configuration values as containing sensitive data, classify data into protection levels, or apply different handling based on sensitivity.

### Details
Configuration values that may contain sensitive data include: secrets.backend_kwargs (may contain credentials), database connection strings (may contain passwords), API endpoint URLs with embedded tokens, and Fernet encryption keys. Without classification, sensitive configuration values may be: logged at DEBUG level without masking, exposed in error messages, included in diagnostic dumps, or stored without appropriate access controls.

**ASVS:** 14.1.1 (L2, L3)

### Affected Files
- `task-sdk/src/airflow/sdk/configuration.py:152-168`

### Remediation
Implement a sensitivity classification system in the configuration description:

In config.yml, add sensitivity metadata:
```yaml
core:
  fernet_key:
    type: string
    sensitivity: CONFIDENTIAL
    protection:
      - mask_in_logs
      - encrypt_at_rest
```

Then enforce protection in the parser:
```python
SENSITIVITY_LEVELS = ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED']

def get_sensitivity(self, section: str, key: str) -> str:
    """Retrieve classification for configuration key."""
    # ... implementation ...

def get(self, section: str, key: str) -> str:
    value = super().get(section, key)
    sensitivity = self.get_sensitivity(section, key)
    if sensitivity in ('CONFIDENTIAL', 'RESTRICTED'):
        log.audit("config_access", section=section, key=key, sensitivity=sensitivity)
    return value
```

### Acceptance Criteria
- [ ] Sensitivity classification system implemented
- [ ] config.yml updated with sensitivity metadata
- [ ] Protection enforcement added in parser
- [ ] Audit logging for sensitive config access
- [ ] Test added verifying classification enforcement

### References
- Source Reports: 14.1.1.md

### Priority
**Medium** - L2/L3 requirement for data classification

---

## Issue: FINDING-033 - No Documented Protection Requirements for Configuration Data
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The configuration module handles data at multiple sensitivity levels but has no documented protection requirements for any level. Required documentation should include encryption at rest, encryption in transit, integrity verification, retention policy, logging controls, access controls, and privacy controls.

### Details
Without documented protection requirements: developers cannot implement consistent protection across the codebase, security reviewers cannot verify whether controls are sufficient, compliance audits cannot validate regulatory adherence, and operations teams may deploy with insufficient protection (e.g., world-readable config files containing secrets).

**ASVS:** 14.1.2 (L2, L3)

### Affected Files
- `task-sdk/src/airflow/sdk/configuration.py` (entire module)
- `task-sdk/src/airflow/sdk/configuration.py:146`
- `task-sdk/src/airflow/sdk/configuration.py:163-166`

### Remediation
Create a data protection specification document with three levels:

**RESTRICTED** (Fernet Keys, API Tokens, Backend Credentials):
- At rest: Encrypted secrets backend storage
- In transit: TLS 1.2+
- Integrity: Key validation on load
- Retention: 90-day maximum lifetime with rotation
- Logging: Never log values (mask with ***)
- Access: Process-level isolation

**CONFIDENTIAL** (Connection Strings, Database URLs):
- At rest: Fernet encryption or secrets backend
- In transit: TLS 1.2+ for connections
- Integrity: URI format validation
- Retention: Per data retention policy
- Logging: Mask passwords in logs
- Access: Read access limited to task execution context

**INTERNAL** (Config file paths, AIRFLOW_HOME):
- At rest: Standard filesystem permissions (640)
- Integrity: File existence validation
- Logging: May be logged for debugging

### Acceptance Criteria
- [ ] Data protection specification document created
- [ ] Protection requirements defined per sensitivity level
- [ ] Document referenced from configuration code
- [ ] Implementation verified against specification

### References
- Source Reports: 14.1.2.md

### Priority
**Medium** - L2/L3 requirement for protection documentation

---

## Issue: FINDING-034 - No Formal Logging Inventory Document
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The logging infrastructure supports multiple destinations (local files, remote storage, supervisor IPC) and configurable formats, but there is no reference to, or enforcement of, a logging inventory document that describes what events are logged, log formats used, where logs are stored, how access is controlled, or retention policies.

### Details
The code reveals multiple undocumented logging pathways: local file logging configured via base_log_folder, remote logging dynamically loaded from config class, and supervisor communication channel. Without a formal inventory, security operations teams cannot verify completeness of logging, audit log access patterns, or determine if all security events are captured.

**ASVS:** 16.1.1 (L2)

### Affected Files
- `task-sdk/src/airflow/sdk/log.py` (entire file)

### Remediation
Create a logging inventory document and reference it in code comments. Consider adding a validation step at startup that verifies configured destinations match the documented inventory.

Example structure (logging_inventory.yml):
```yaml
log_destinations:
  - name: Local Task Logs
    path: {base_log_folder}/{dag_id}/{task_id}/{execution_date}/{try_number}.log
    format: JSON (when json_output=True) or plaintext
    access_control: Filesystem permissions
    retention: Per logging.task_log_retention_days
    
  - name: Remote Task Logs
    handler_class: Configured via logging.remote_logging
    format: Same as local
    access_control: Per remote storage provider
    retention: Per remote storage provider policy
```

### Acceptance Criteria
- [ ] logging_inventory.yml document created
- [ ] All log destinations documented
- [ ] Formats documented per destination
- [ ] Access controls documented
- [ ] Retention policies documented
- [ ] Document referenced from code

### References
- Source Reports: 16.1.1.md

### Priority
**Medium** - L2 requirement for logging inventory

---

## Issue: FINDING-035 - No Explicit Identity Metadata Injection in Log Processor Chain
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The logging processor chain is constructed without an explicit processor that injects identity/principal information ("who") into each log entry. While structlog can include callsite parameters (where) and timestamps (when), there is no processor visible that binds the current authenticated user, task identity, or execution context to every log record.

### Details
Without consistent "who" metadata, security investigations cannot correlate log entries to specific users or execution contexts without manual cross-referencing of separate data sources. This makes incident investigation and compliance auditing significantly more difficult.

**ASVS:** 16.2.1 (L2)

### Affected Files
- `task-sdk/src/airflow/sdk/log.py:51-66`

### Remediation
Add a structlog processor that binds execution context to every log entry:

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
        pass  # No context available
    return event_dict

# Add to processor chain:
extra_processors += (add_execution_context, mask_logs,)
```

### Acceptance Criteria
- [ ] Execution context processor implemented
- [ ] Processor added to logging pipeline
- [ ] Test added verifying context in log entries
- [ ] Test added verifying graceful handling when no context
- [ ] Documentation updated explaining context injection

### References
- Source Reports: 16.2.1.md

### Priority
**Medium** - L2 requirement for audit trail completeness

---

## Issue: FINDING-036 - Dynamic Log Destination Loading Without Inventory Validation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The logging configuration dynamically loads a logging class from a configurable path without validating it against a documented inventory of approved destinations. If an attacker gains write access to configuration, logs could be routed to unauthorized destinations not documented in any logging inventory.

### Details
Configuration file → logging_config_class setting → import_string() → arbitrary class loaded as log handler. This could result in data exfiltration via log forwarding or loss of audit trail if logs are routed to attacker-controlled destinations.

**ASVS:** 16.2.3 (L2)

### Affected Files
- `task-sdk/src/airflow/sdk/log.py:151-165`

### Remediation
Implement an allowlist of permitted logging handler classes:

```python
ALLOWED_LOGGING_CONFIGS = {
    "airflow.config_templates.airflow_local_settings.DEFAULT_LOGGING_CONFIG",
    "airflow.providers.amazon.aws.log.s3_task_handler.S3TaskHandler",
    "airflow.providers.google.cloud.log.gcs_task_handler.GCSTaskHandler",
    # ... other approved handlers ...
}

logging_class_path = conf.get("logging", "logging_config_class")
if logging_class_path not in ALLOWED_LOGGING_CONFIGS:
    raise ValueError(
        f"Logging handler {logging_class_path!r} is not in approved inventory. "
        f"See LOGGING_INVENTORY.md for approved handlers."
    )
```

### Acceptance Criteria
- [ ] ALLOWED_LOGGING_CONFIGS allowlist defined
- [ ] Validation added before import_string()
- [ ] ValueError raised for unapproved handlers
- [ ] Test added verifying allowlist enforcement
- [ ] Documentation updated with approved handlers

### References
- Source Reports: 16.2.3.md

### Priority
**Medium** - Requires configuration write access

---

## Issue: FINDING-037 - No Authentication Event Logging Infrastructure
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The logging infrastructure files do not include any authentication-specific logging hooks, decorators, or utility functions that would facilitate consistent logging of authentication events. Without standardized utilities, individual authentication handlers may log inconsistently or miss events.

### Details
While the infrastructure provides general-purpose structured logging, there is no: dedicated authentication event logger or event type, utility function for logging auth success/failure with required metadata (auth type, factors used, source IP), or structured event schemas for authentication events. This undermines security monitoring and incident response capabilities.

**ASVS:** 16.3.1 (L2)

### Affected Files
- `task-sdk/src/airflow/sdk/log.py` (entire file)

### Remediation
Add an authentication logging utility to the logging infrastructure:

```python
def log_auth_event(
    event: str,
    auth_type: str,
    principal: str,
    success: bool,
    metadata: dict | None = None
) -> None:
    """Log authentication event with required metadata."""
    log = structlog.get_logger("security.auth")
    log_method = log.info if success else log.warning
    log_method(
        event,
        auth_type=auth_type,
        principal=principal,
        success=success,
        **(metadata or {})
    )
```

### Acceptance Criteria
- [ ] log_auth_event() utility function implemented
- [ ] Required metadata parameters defined
- [ ] Success/failure differentiation implemented
- [ ] Test added verifying correct logging
- [ ] Documentation added explaining usage

### References
- Source Reports: 16.3.1.md

### Priority
**Medium** - L2 requirement for authentication monitoring

---

## Issue: FINDING-038 - No Authorization Event Logging Infrastructure
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The logging infrastructure does not define or implement any mechanisms for logging authorization decisions or failed authorization attempts. There are no decorator or utility functions for annotating authorization-checked endpoints, structured event types for authorization success/failure, or context processors that attach authorization decision metadata to log entries.

### Details
Failed authorization attempts would not generate audit trail entries unless individual developers manually add log statements, creating inconsistent coverage across the codebase. This undermines the ability to detect and investigate authorization-based attacks.

**ASVS:** 16.3.2 (L2, L3)

### Affected Files
- `task-sdk/src/airflow/sdk/log.py` (entire file scope)

### Remediation
Implement a structured security event logging utility:

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

### Acceptance Criteria
- [ ] log_authorization_event() utility implemented
- [ ] Required metadata parameters defined
- [ ] Granted/denied differentiation implemented
- [ ] Test added verifying correct logging
- [ ] Documentation added explaining usage

### References
- Source Reports: 16.3.2.md

### Priority
**Medium** - L2/L3 requirement for authorization monitoring

---

## Issue: FINDING-039 - Default Log File Permissions Allow Group Write Access
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Default file permission 0o664 (rw-rw-r--) allows group members to write to log files, and default folder permission 0o775 (rwxrwxr-x) allows group members to create, delete, or rename files in log directories. Any process running in the same Unix group can modify or delete log files, compromising log integrity.

### Details
If multiple tasks or services run under the same Unix group, they can modify each other's log files. Data flow: Log file creation → init_log_file() → permissions 0o664 applied → group-writable log file. This violates log integrity requirements for forensic investigations and compliance auditing.

**ASVS:** 16.4.2 (L2)

### Affected Files
- `task-sdk/src/airflow/sdk/log.py:126-148`

### Remediation
Tighten defaults: owner read/write, group/other read-only:

```python
new_file_permissions = int(
    conf.get("logging", "file_task_handler_new_file_permissions", fallback="0o644"),
    8,
)
new_folder_permissions = int(
    conf.get("logging", "file_task_handler_new_folder_permissions", fallback="0o755"),
    8,
)
```

### Acceptance Criteria
- [ ] Default file permissions changed to 0o644
- [ ] Default folder permissions changed to 0o755
- [ ] Test added verifying new permissions
- [ ] Documentation updated explaining permission model
- [ ] Migration guide for existing deployments

### References
- Source Reports: 16.4.2.md

### Priority
**Medium** - Log integrity compromise in multi-tenant environments

---

## Issue: FINDING-040 - API Server Error Details Exposed in Task Logs
**Labels:** bug, security, priority:medium
**Description:**
### Summary
API server error response details are forwarded verbatim through the IPC channel to the task process. When the API server returns an error response containing internal details (e.g., database query fragments, internal service endpoints, or stack traces), these are exposed in task logs viewable by DAG authors through the Airflow UI.

### Details
The task runner receives error details via _from_frame() and raises AirflowRuntimeError which is caught and logged, exposing internal details in task logs. This violates the principle of returning generic error messages to consumers and could aid attackers in reconnaissance.

**ASVS:** 16.5.1 (L2)

### Affected Files
- `task-sdk/src/airflow/sdk/execution_time/supervisor.py:430-450`

### Remediation
Log full error details only on the supervisor side (not forwarded to task):

```python
# In supervisor
if isinstance(response, httpx.Response) and response.is_error:
    log.error("api_server_error", status=response.status_code, detail=response.text)
    return ErrorResponse(
        error=ErrorType.API_SERVER_ERROR,
        detail=f"The API server returned an error (status {response.status_code}). Check supervisor logs for details."
    )
```

Send only a sanitized, generic error back to the task process with status code and generic message.

### Acceptance Criteria
- [ ] Full error details logged only on supervisor side
- [ ] Generic error message sent to task
- [ ] Test added verifying internal details not in task logs
- [ ] Test added verifying supervisor logs contain full details
- [ ] Documentation updated explaining error handling

### References
- Source Reports: 16.5.1.md

### Priority
**Medium** - Information disclosure to DAG authors

## Issue: FINDING-041 - Task Hangs Indefinitely on Message Decode Failure
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Task runner blocks indefinitely when supervisor fails to decode a message due to protocol version mismatch or other decode errors. The supervisor logs the error but does not send an error response, leaving the task runner waiting forever in blocking socket recv with no timeout mechanism.

### Details
**Data Flow:**
- Task runner sends request → supervisor fails to decode → logs error and continues without response → task runner blocks in `_read_frame()` with blocking socket recv and no timeout
- **Affected Code:** `task-sdk/src/airflow/sdk/execution_time/supervisor.py:418-421`
- **Trigger Scenario:** Protocol version mismatch during rolling upgrades where supervisor and task runner are different versions
- **Impact:** Task hangs indefinitely, blocking execution thread permanently and consuming resources without progress
- **CWE:** None specified
- **ASVS:** 16.5.2 (L2)

### Remediation
1. Send an error response before continuing when decode fails:
   - Send `ErrorResponse` with `GENERIC_ERROR` type and message 'Unable to process request' so task doesn't hang
2. Add communication timeout:
   - Set a reasonable timeout on blocking socket recv in `CommsDecoder._read_frame()` to prevent indefinite hangs
   - Implement circuit breaker or timeout mechanism for this communication path

### Acceptance Criteria
- [ ] Error response sent to task runner when message decode fails
- [ ] Timeout added to blocking socket recv operations
- [ ] Test added for protocol version mismatch scenario
- [ ] Test added for timeout behavior
- [ ] Verify task runner properly handles error response

### References
- Source Report: 16.5.2.md
- Merged From: ASVS-1652-MED-001
- Related Domain: error_handling

### Priority
Medium

---

## Issue: FINDING-042 - Unhandled Exceptions in Socket Handler Crash Monitoring Loop
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Unhandled exceptions in request processing propagate through the monitoring loop and crash the supervisor without proper cleanup. The current code only catches `BrokenPipeError` and `ConnectionResetError`, allowing other exceptions to crash the monitoring loop and leave tasks in indeterminate states.

### Details
**Data Flow:**
- Unhandled exception in `socket_handler` → propagates through `_service_subprocess` → `_monitor_subprocess` → `wait()` → crashes monitoring loop
- **Affected Code:** `task-sdk/src/airflow/sdk/execution_time/supervisor.py:~530-550 in _service_subprocess()`
- **Impact:**
  - `update_task_state_if_needed()` never called, task state in API server never updated
  - `_upload_logs()` never called, remote logs are lost
  - Child process continues running as orphan
  - Task appears stuck until heartbeat timeout triggers server-side cleanup
- **CWE:** None specified
- **ASVS:** 16.5.3 (L2), 16.5.4 (L3)

### Remediation
Add catch-all exception handler in `wait()` that:
1. Logs the unhandled exception with full context
2. Ensures subprocess is terminated via `kill(signal.SIGTERM, force=True)`
3. Sets exit code to 1 if not already set
4. Wraps `update_task_state_if_needed()` and `_upload_logs()` in individual try-except blocks to ensure both are attempted even if one fails

### Acceptance Criteria
- [ ] Catch-all exception handler added to wait() method
- [ ] Exception logging includes full context
- [ ] Subprocess termination guaranteed on exception
- [ ] State update and log upload wrapped in individual error handlers
- [ ] Test added for various exception types in socket handler
- [ ] Verify orphan process prevention

### References
- Source Reports: 16.5.3.md, 16.5.4.md
- Merged From: ASVS-1653-MED-001, ERROR_HANDLING-8
- Related Domain: error_handling

### Priority
Medium

---

## Issue: FINDING-043 - Incomplete BaseException Coverage in Last-Resort Handlers
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Last-resort exception handlers do not catch `BaseException`, only `Exception` and `SystemExit`. The supervisor monitoring loop has no last-resort handler at all. Edge cases like `GeneratorExit`, custom `BaseException` subclasses, and corrupted interpreter state are not handled, making post-mortem analysis difficult.

### Details
**Data Flow:**
- `_fork_main()` catches `SystemExit` and `Exception` but not `BaseException`
- Supervisor `wait()` has NO last-resort handler - errors propagate to external caller without structured capture
- **Affected Code:** `task-sdk/src/airflow/sdk/execution_time/supervisor.py:256-280`
- **Missing Coverage:**
  - `GeneratorExit` during generator cleanup
  - Custom `BaseException` subclasses from third-party task code
  - Corrupted interpreter state
- **Impact:** Error details required for debugging may be lost without structured error capture
- **CWE:** None specified
- **ASVS:** 16.5.4 (L3)

### Remediation
1. Add catch-all in `wait()` as shown in ASVS-1654-HIGH-001 remediation
2. Extend `_fork_main` to catch `BaseException` (not just `Exception`) to handle:
   - `GeneratorExit`
   - `KeyboardInterrupt`
   - Custom `BaseException` subclasses
3. Write diagnostics to `last_chance_stderr` and exit with code 127 for `BaseException` cases

### Acceptance Criteria
- [ ] BaseException handler added to _fork_main()
- [ ] Last-resort handler added to wait() method
- [ ] Diagnostics written to last_chance_stderr for all exception types
- [ ] Exit code 127 used for BaseException cases
- [ ] Test added for GeneratorExit scenario
- [ ] Test added for custom BaseException subclass

### References
- Source Report: 16.5.4.md
- Merged From: ASVS-1654-MED-001
- Related Domain: error_handling

### Priority
Medium

---

## Issue: FINDING-044 - Supervisor Accepts Terminal State Messages Without Verifying Execution Phase
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The supervisor processes terminal state messages (TaskState, SucceedTask, RetryTask, DeferTask) without verifying the task has progressed through expected phases (startup → preparation → execution → completion). This defense-in-depth gap could allow premature terminal state reporting.

### Details
**Data Flow:**
- Task process sends terminal state message → supervisor processes without phase verification → calls API server state update
- **Affected Code:** `task-sdk/src/airflow/sdk/execution_time/supervisor.py:517`
- **Risk Scenario:** A malicious task operator's `execute()` could monkey-patch `SUPERVISOR_COMMS` internals to send a `SucceedTask` message before actually completing work
- **Impact:** Supervisor would accept premature terminal state and call `task_instances.succeed()` on API server
- **Trust Boundary:** IPC channel is within trust boundary, making this primarily a defense-in-depth concern
- **CWE:** None specified
- **ASVS:** 2.3.1 (L1)

### Remediation
1. Add explicit phase tracking to supervisor with phases: "starting" → "running" → "terminal"
2. Only accept terminal state messages when in "running" phase
3. Add duplicate terminal state guard to prevent processing multiple terminal states
4. Implement warning logging when terminal states are received before task is running

Example implementation:
```python
self._phase = "starting"  # Initialize in __init__
# In handle_startup_complete:
self._phase = "running"
# In terminal state handling:
if self._phase != "running":
    log.warning("Terminal state received in wrong phase", phase=self._phase)
    return
```

### Acceptance Criteria
- [ ] Phase tracking added to supervisor
- [ ] Terminal state messages only accepted in "running" phase
- [ ] Duplicate terminal state guard implemented
- [ ] Warning logging added for out-of-phase terminal states
- [ ] Test added for premature terminal state scenario
- [ ] Test added for duplicate terminal state scenario

### References
- Source Report: 2.3.1.md
- Merged From: ASVS-231-MED-001
- Related Domain: business_logic_validation

### Priority
Medium

---

## Issue: FINDING-045 - Unhandled Non-ServerResponseError Exceptions Crash Supervisor Without State Cleanup
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Non-`ServerResponseError` exceptions from API calls (e.g., `httpx.ConnectTimeout`, `httpx.ReadTimeout`) crash the supervisor monitoring loop without calling `update_task_state_if_needed()`, leaving tasks in indeterminate states on the server.

### Details
**Data Flow:**
- `_handle_request()` → API call raises non-ServerResponseError → exception propagates through generator → through `length_prefixed_frame_reader` callback → through `_service_subprocess` → through `_monitor_subprocess` → `wait()` → `supervise_task()` returns without state update
- **Affected Code:** `task-sdk/src/airflow/sdk/execution_time/supervisor.py:373`
- **Exception Types:**
  - Network-level timeout
  - DNS failure
  - `ConnectionRefusedError` wrapped by httpx
- **Impact:**
  - Entire supervisor monitoring loop crashes
  - `wait()` finally block closes selector but never calls `update_task_state_if_needed()`
  - Task left in indeterminate state on server
  - Task process may continue running unsupervised
- **CWE:** None specified
- **ASVS:** 2.3.3 (L2)

### Remediation
Add catch-all exception handling in `handle_requests()` to:
1. Catch ALL exceptions and prevent supervisor crash
2. Log the unexpected error
3. Send an error response back to the task with `ErrorType.API_SERVER_ERROR`
4. Ensure the exception does not propagate and crash the monitoring loop

### Acceptance Criteria
- [ ] Catch-all exception handler added to handle_requests()
- [ ] All non-ServerResponseError exceptions caught
- [ ] Error response sent back to task with API_SERVER_ERROR type
- [ ] Monitoring loop continues after exception
- [ ] Test added for httpx.ConnectTimeout
- [ ] Test added for httpx.ReadTimeout
- [ ] Test added for DNS failure scenario

### References
- Source Report: 2.3.3.md
- Merged From: ASVS-233-MED-001
- Related Domain: business_logic_validation

### Priority
Medium

---

## Issue: FINDING-046 - No Guard Against Duplicate Terminal State API Calls From Same Task Process
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The supervisor does not check if a terminal state has already been set before processing terminal state messages, allowing duplicate messages to overwrite `_terminal_state` and trigger multiple conflicting API calls to the server.

### Details
**Data Flow:**
- Task sends first terminal state message → supervisor sets `_terminal_state` and calls API → task sends second terminal state message → supervisor overwrites `_terminal_state` and calls API again
- **Affected Code:** `task-sdk/src/airflow/sdk/execution_time/supervisor.py:517`
- **Example Scenario:** Task sends `SucceedTask` followed by `RetryTask` (e.g., due to post_execute hook exception or race condition)
- **Impact:**
  - Supervisor calls both `client.task_instances.succeed()` and `client.task_instances.retry()`
  - API server receives conflicting state transitions for same task instance
- **CWE:** None specified
- **ASVS:** 2.3.4 (L2)

### Remediation
Add a guard at the beginning of terminal state message handling:
1. Check if `self._terminal_state` is already set
2. If set, log a warning and send `ErrorResponse` back to task process
3. Return early without processing the duplicate message

Example implementation:
```python
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
```

### Acceptance Criteria
- [ ] Duplicate terminal state guard implemented
- [ ] Warning logged when duplicate detected
- [ ] ErrorResponse sent to task process
- [ ] Early return prevents duplicate API call
- [ ] Test added for duplicate SucceedTask messages
- [ ] Test added for SucceedTask followed by RetryTask
- [ ] Verify API server receives only first terminal state

### References
- Source Report: 2.3.4.md
- Merged From: ASVS-234-MED-001
- Related Domain: business_logic_validation

### Priority
Medium

---

## Issue: FINDING-047 - Unescaped Regex Interpolation in get_unique_task_id
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `prefix` variable is interpolated directly into a regex pattern without escaping. If `prefix` contains regex metacharacters, it could cause unexpected behavior or pathological backtracking (ReDoS).

### Details
**Data Flow:**
- `task_id` parameter → `tg_task_id` (via `task_group.child_id()`) → `prefix` (via `re.split`) → injected into `re.match()` pattern without escaping
- **Affected Code:** `task-sdk/src/airflow/sdk/bases/decorator.py:119-127`
- **Pattern:** `rf"^{prefix}__(\d+)$"` where `prefix` is unescaped
- **Timing:** Called BEFORE `validate_key` in `DecoratedOperator.__init__`, creating window where unvalidated input reaches regex
- **Example Attack:** `task(a+)+id` could cause exponential backtracking when matching against other task_ids
- **Impact:** CPU exhaustion during DAG parsing
- **CWE:** CWE-1333 (Inefficient Regular Expression Complexity)
- **ASVS:** 1.3.12 (L3)

### Remediation
Apply `re.escape()` to the `prefix` variable before using it in regex pattern construction:

```python
escaped_prefix = re.escape(prefix)
pattern = rf"^{escaped_prefix}__(\d+)$"
```

This prevents regex metacharacters from being interpreted as pattern elements.

### Acceptance Criteria
- [ ] re.escape() applied to prefix before regex construction
- [ ] Test added with task_id containing regex metacharacters
- [ ] Test added for pathological backtracking scenario
- [ ] Performance test added to verify no ReDoS vulnerability
- [ ] Verify existing functionality not broken

### References
- Source Report: 1.3.12.md
- Merged From: ASVS-1312-MED-001
- Related Domain: general_security

### Priority
Medium

---

## Issue: FINDING-048 - No Cryptographic Discovery Mechanism for Identifying Cryptographic Instances
**Labels:** security, documentation, priority:medium
**Description:**
### Summary
The Task SDK lacks an automated discovery mechanism to identify and catalog cryptographic operations. Without this, newly added cryptographic operations may use weak algorithms or configurations without review, making it difficult to assess the complete cryptographic posture and prepare for algorithm migrations.

### Details
**Cryptographic Operations:**
1. Fernet encryption in `task-sdk/src/airflow/sdk/crypto.py` (AES-128-CBC + HMAC-SHA256)
2. TLS/SSL context in `task-sdk/src/airflow/sdk/api/client.py:488-496`
3. Serializer encryption in `task-sdk/src/airflow/sdk/serde/serializers/deltalake.py` and `iceberg.py`
4. Bearer token authentication in `task-sdk/src/airflow/sdk/api/client.py:456-462`

**Impact:**
- Newly added cryptographic operations (e.g., by contributors adding new serializers) may use weak algorithms without review
- Difficult to assess complete cryptographic posture
- Challenging to prepare for algorithm migrations
- **ASVS:** 11.1.3 (L3)

### Remediation
Implement a cryptographic discovery tool or CI pipeline step that scans for:
1. Imports from `cryptography`, `hashlib`, `hmac`, `ssl` modules
2. Instantiation of cipher/hash objects
3. Configuration of TLS contexts

Example approach using static analysis:
```python
# ci/crypto_discovery.py
CRYPTO_IMPORTS = ['cryptography', 'hashlib', 'hmac', 'ssl', 'Fernet', 'MultiFernet']

def scan_file(filepath):
    # Scan all .py files to report usage of cryptographic modules
    pass
```

### Acceptance Criteria
- [ ] Cryptographic discovery tool implemented
- [ ] CI pipeline step added to run discovery on each PR
- [ ] Documentation added listing all cryptographic operations
- [ ] Report generated showing algorithm types and locations
- [ ] Process documented for reviewing new cryptographic additions
- [ ] Test added to verify discovery tool finds known crypto usage

### References
- Source Report: 11.1.3.md
- Merged From: ASVS-1113-MED-001
- Related Domain: general_security

### Priority
Medium

---

## Issue: FINDING-049 - supervise_callback allows unauthenticated API requests via default empty token
**Labels:** bug, security, priority:medium
**Description:**
### Summary
`supervise_callback()` defaults the `token` parameter to an empty string, allowing unauthenticated API requests when a `server` URL is provided without explicitly setting `token`. This differs from `supervise_task()` which requires the token parameter.

### Details
**Data Flow:**
- Caller provides `server` URL without `token` → `token=""` used by default → `BearerAuth.auth_flow` skips Authorization header when `self.token` is falsy → unauthenticated backend communication
- **Affected Code:** `task-sdk/src/airflow/sdk/execution_time/callback_supervisor.py:250`
- **Comparison:** `supervise_task()` has `token: str` with no default (required), but `supervise_callback()` has `token: str = ""`
- **Impact:** Callback subprocess makes completely unauthenticated API requests to Execution API server
- **CWE:** None specified
- **ASVS:** 13.2.1 (L2)

### Remediation
**Option 1 (Recommended):** Remove default value to make token required:
```python
def supervise_callback(..., token: str):  # No default - required
```

**Option 2:** Add validation:
```python
if not client and server and not token:
    raise ValueError("token is required when connecting to a server")
```

### Acceptance Criteria
- [ ] Token parameter made required when server is provided
- [ ] Validation added to prevent empty token with server URL
- [ ] Test added for missing token scenario
- [ ] Test added to verify authentication header present
- [ ] Documentation updated to clarify token requirement
- [ ] Verify backward compatibility or document breaking change

### References
- Source Report: 13.2.1.md
- Merged From: ASVS-1321-MED-001
- Related Domain: general_security

### Priority
Medium

---

## Issue: FINDING-050 - Cryptographic keys loaded directly from configuration without isolated security module
**Labels:** security, enhancement, priority:medium
**Description:**
### Summary
Fernet keys are loaded directly from configuration into process memory without use of an isolated security module (HSM, vault). The `@cache` decorator ensures keys remain in memory for the entire process lifetime with no mechanism for secure key zeroing or rotation without process restart.

### Details
**Data Flow:**
- Configuration file → `conf.get("core", "FERNET_KEY")` → process memory (cached indefinitely via `@cache`)
- **Affected Code:** `task-sdk/src/airflow/sdk/crypto.py:98-120`
- **Risks:**
  - Key material exposed in process memory for process lifetime
  - If process memory compromised (memory dump, core dump, /proc access), encryption key could be extracted
- **Mitigations:**
  - `_make_process_nondumpable()` call in supervisor mitigates some risk on Linux
- **Design Decision:** Acknowledged in project: "Fernet encryption for connections/variables without key rotation would be flagged as weak key management, but is intentional because the SDK delegates key management to the Airflow server."
- **ASVS:** 13.3.3 (L3)

### Remediation
Integrate with a secrets management service for key retrieval:
1. Add support for vault-backed key retrieval
2. Implement configurable key backend system that can retrieve keys from:
   - HashiCorp Vault
   - AWS KMS
   - Similar HSM/vault services
3. Document recommended deployment patterns for using vault-backed secrets providers

Example:
```python
def get_fernet_key():
    backend = conf.get("core", "fernet_key_backend", fallback="config")
    if backend == "vault":
        return retrieve_from_vault()
    elif backend == "kms":
        return retrieve_from_kms()
    else:
        return conf.get("core", "FERNET_KEY")
```

### Acceptance Criteria
- [ ] Vault backend support added for key retrieval
- [ ] KMS backend support added for key retrieval
- [ ] Configuration option added to select key backend
- [ ] Documentation added for vault-backed deployment patterns
- [ ] Test added for vault backend
- [ ] Test added for KMS backend
- [ ] Migration guide created for existing deployments

### References
- Source Report: 13.3.3.md
- Merged From: ASVS-1333-MED-001
- Related Domain: general_security

### Priority
Medium

---

## Issue: FINDING-051 - Retry and Timeout Configuration Lacks Upper Bound Enforcement
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Retry limits and timeouts exist but lack validation that configured values are within reasonable bounds. An operator misconfiguration (e.g., extremely high retry count or timeout) could cause resource exhaustion.

### Details
**Data Flow:**
- Configuration values read without bounds checking → used directly in retry/timeout logic
- **Affected Code:** `task-sdk/src/airflow/sdk/api/client.py:556-560`
- **Risk Scenario:** Misconfigured `execution_api_retries` with large `execution_api_retry_wait_max` could cause task to hold resources for unbounded duration
- **Impact:**
  - Resource exhaustion
  - Worker slot starvation
  - Unbounded resource holding
- **CWE:** None specified
- **ASVS:** 15.1.3 (L3)

### Remediation
Add bounds checking on configuration values:

```python
API_RETRIES = min(conf.getint("workers", "execution_api_retries"), 10)
API_RETRY_WAIT_MAX = min(conf.getfloat("workers", "execution_api_retry_wait_max"), 120.0)
API_TIMEOUT = min(conf.getfloat("workers", "execution_api_timeout"), 300.0)
```

Also consider:
- Logging warnings when configured values exceed recommended bounds
- Documenting recommended ranges for each configuration parameter

### Acceptance Criteria
- [ ] Upper bounds enforced on retry configuration
- [ ] Upper bounds enforced on timeout configuration
- [ ] Warning logged when configured values exceed bounds
- [ ] Documentation added for recommended configuration ranges
- [ ] Test added for configuration values exceeding bounds
- [ ] Test added to verify clamping behavior

### References
- Source Report: 15.1.3.md
- Merged From: ASVS-1513-MED-001
- Related Domain: general_security

### Priority
Medium

---

## Issue: FINDING-052 - Insufficient Documentation of Resource-Demanding Operations
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The `concepts.rst` documentation does not explicitly identify which operations are time-consuming or resource-demanding, nor does it document how to prevent availability loss due to overuse of these operations.

### Details
**Undocumented Resource-Demanding Patterns:**
1. Unbounded polling loop in `_handle_trigger_dag_run` with no independent timeout
2. DAG file parsing can be arbitrarily expensive
3. Template rendering executes Jinja2 rendering which can be computationally expensive
4. XCom serialization processes potentially large payloads

**Affected Code:**
- `task-sdk/docs/concepts.rst`
- `task-sdk/src/airflow/sdk/execution_time/task_runner.py:2044-2070`

**Impact:**
- Operators may not configure appropriate timeouts
- Worker slot exhaustion
- Thread starvation
- Cascading availability loss
- **ASVS:** 15.1.3 (L3)

### Remediation
Add a dedicated "Resource Management" section to `concepts.rst` that documents:

1. **Resource-demanding operations:**
   - DAG file parsing
   - Template rendering
   - TriggerDagRunOperator with wait_for_completion
   - XCom operations with large payloads

2. **Mitigation strategies for each operation:**
   - parsing_timeout
   - max_templated_field_length
   - Deferrable operators
   - execution_timeout
   - Custom XCom backends

3. **Configuration options to prevent availability loss:**
   - execution_timeout
   - max_active_tasks
   - max_active_runs
   - dagrun_timeout

4. **Guidance on using deferred operators vs blocking polls** for I/O-bound waiting

### Acceptance Criteria
- [ ] Resource Management section added to concepts.rst
- [ ] All resource-demanding operations documented
- [ ] Mitigation strategies documented for each operation
- [ ] Configuration options documented
- [ ] Examples added for common scenarios
- [ ] Guidance added for choosing deferrable vs blocking operators

### References
- Source Report: 15.1.3.md
- Merged From: ASVS-1513-MED-002
- Related Domain: general_security

### Priority
Medium

---

## Issue: FINDING-053 - Test/Development Infrastructure Included in Production Module
**Labels:** security, refactoring, priority:medium
**Description:**
### Summary
`InProcessTestSupervisor` and related test classes are included in the production `supervisor.py` module. While these support `dag.test()` (a legitimate feature), they bypass subprocess isolation and retry logic. If triggered in production, task code runs in the supervisor's process without isolation.

### Details
**Affected Classes:**
- `InProcessTestSupervisor`
- `InProcessSupervisorComms`
- `TaskRunResult`
- `run_task_in_process`

**Affected Code:** `task-sdk/src/airflow/sdk/execution_time/supervisor.py:934-1100`

**Bypassed Security Controls:**
- Subprocess isolation - task code runs in supervisor's process
- Retry logic - `_Client` inner class bypasses retry logic
- Resource isolation

**Risk Scenario:**
- If `dag.test()` called in deployed production environment
- Task code accesses supervisor-level secrets and resources
- No process boundary protection

**Current Mitigation:**
- Single-threaded supervisor architecture makes this safe in current design
- `InProcessTestSupervisor` already uses threads but doesn't call vulnerable paths

**CWE:** None specified
**ASVS:** 15.2.3 (L2)

### Remediation
**Option 1 (Recommended):** Move test infrastructure to separate module:
- Create `task-sdk/src/airflow/sdk/execution_time/testing/` module
- Move test classes to testing module
- Require explicit import for test functionality

**Option 2:** Add runtime guards:
```python
if not (conf.getboolean("core", "unit_test_mode") or 
        os.environ.get("AIRFLOW_ALLOW_IN_PROCESS_TASK")):
    raise RuntimeError(
        "InProcessTestSupervisor can only be used in testing contexts"
    )
```

### Acceptance Criteria
- [ ] Test infrastructure moved to separate module OR runtime guards added
- [ ] Production code cannot accidentally use test infrastructure
- [ ] dag.test() functionality preserved
- [ ] Documentation updated to explain test infrastructure usage
- [ ] Test added to verify runtime guards work
- [ ] Verify no production code paths can trigger InProcessTestSupervisor

### References
- Source Report: 15.2.3.md
- Merged From: ASVS-1523-MED-001
- Related Domain: general_security

### Priority
Medium

---

## Issue: FINDING-054 - ExecutorSafeguard Bypass via Configuration
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `ExecutorSafeguard` that prevents operators from being executed outside the task runner context can be disabled by setting `unit_test_mode = True` in configuration. If accidentally left enabled in production, operators can be incorrectly nested or executed outside the task runner without errors.

### Details
**Data Flow:**
- Configuration `unit_test_mode=True` → `ExecutorSafeguard` disabled → no error on nested operator execution
- **Affected Code:** `task-sdk/src/airflow/sdk/bases/operator.py:306-310`
- **Risk Scenario:** In production with `unit_test_mode=True`:
  - Operators can be incorrectly nested
  - Operators can be executed outside task runner
  - No errors raised
  - Unexpected behavior occurs
- **Impact:** Safety check bypassed, potential for unexpected execution behavior
- **CWE:** None specified
- **ASVS:** 15.2.3 (L2)

### Remediation
Add explicit logging when test_mode is detected in non-test environments:

```python
if conf.getboolean("core", "unit_test_mode", fallback=False):
    # Check if we're actually in a test environment
    if "PYTEST_CURRENT_TEST" not in os.environ:
        import logging
        logger = logging.getLogger(__name__)
        logger.warning(
            "unit_test_mode is enabled outside of pytest. "
            "ExecutorSafeguard is disabled. "
            "This should not happen in production."
        )
```

### Acceptance Criteria
- [ ] Warning logged when unit_test_mode enabled outside pytest
- [ ] Check for PYTEST_CURRENT_TEST environment variable
- [ ] Documentation added explaining unit_test_mode security implications
- [ ] Test added to verify warning is logged
- [ ] Recommendation added to deployment checklist to verify unit_test_mode=False

### References
- Source Report: 15.2.3.md
- Merged From: ASVS-1523-MED-002
- Related Domain: general_security

### Priority
Medium

---

## Issue: FINDING-055 - No Explicit Repository Pinning for Runtime Dependencies
**Labels:** security, supply-chain, priority:medium
**Description:**
### Summary
The `pyproject.toml` does not specify trusted package indexes/repositories for runtime dependencies. Without repository pinning, dependency confusion attacks are possible if an attacker publishes a malicious package with the same name on a public index.

### Details
**Missing Configuration:**
- No `[tool.uv.index]`
- No `[tool.pip.index-url]`
- No equivalent repository restriction for external dependencies
- Workspace dependencies use `[tool.uv.sources]` but external dependencies have no repository restriction

**Additional Concerns:**
1. Package namespace `airflow.sdk` is namespaced under `airflow` - potential for conflicting subpackages
2. Internal imports like `from airflow.dag_processing.bundles.manager import DagBundlesManager` cross package boundaries between `task-sdk` and main `airflow` package

**Attack Vector:**
- Attacker publishes malicious package with same name on public index
- Public index checked before intended source
- Malicious package installed instead of legitimate one

**Affected File:** `task-sdk/pyproject.toml`
**CWE:** None specified
**ASVS:** 15.2.4 (L3)

### Remediation
Add explicit index configuration to `pyproject.toml`:

```toml
[tool.uv]
index-url = "https://pypi.org/simple/"
no-build-isolation = false

[[tool.uv.index]]
name = "pypi"
url = "https://pypi.org/simple/"
default = true

[[tool.uv.index]]
name = "apache"
url = "https://repository.apache.org/content/repositories/releases/"
```

**Additional Verification Needed:**
1. All dependencies pulled from PyPI or explicitly configured private registries
2. Lock files include content hashes for all transitive dependencies
3. The `airflow` namespace package registration prevents external parties from registering conflicting subpackages

### Acceptance Criteria
- [ ] Explicit index configuration added to pyproject.toml
- [ ] Default index set to PyPI
- [ ] Apache repository configured if needed
- [ ] Lock files verified to include content hashes
- [ ] Namespace package registration verified
- [ ] Documentation added explaining repository security
- [ ] CI check added to verify repository configuration

### References
- Source Report: 15.2.4.md
- Merged From: ASVS-1524-MED-001
- Related Domain: general_security

### Priority
Medium

---

## Issue: FINDING-056 - Authorization revocation has inherent delay window due to heartbeat interval
**Labels:** security, enhancement, priority:medium
**Description:**
### Summary
If the API server revokes a task's authorization, there is an inherent window of up to `MIN_HEARTBEAT_INTERVAL` seconds during which the task continues executing with its existing token. This is largely by design but creates a revocation delay window.

### Details
**Data Flow:**
- Authorization change on server → heartbeat response (404/409/410) → `self.kill(signal.SIGTERM, force=True)` - but only checked every `MIN_HEARTBEAT_INTERVAL` seconds
- **Affected Code:** `task-sdk/src/airflow/sdk/execution_time/supervisor.py:692`
- **Default Interval:** Typically 10 seconds (configurable)
- **Impact:**
  - Task continues executing for up to interval duration after revocation
  - Task can still make requests through supervisor that will be authorized
- **CWE:** None specified
- **ASVS:** 8.3.2 (L3)

### Remediation
This is largely by design. For environments requiring stricter immediate revocation:

**Option 1:** Reduce minimum heartbeat interval for high-security environments:
```python
MIN_HEARTBEAT_INTERVAL: int = conf.getint('workers', 'min_heartbeat_interval', fallback=5)
```

**Option 2:** Check authorization on every request forwarded to API server (already happens implicitly since API validates token on each call)

**Long-term:** Consider push notification channel:
- WebSocket or long-polling
- Server can immediately notify supervisor of authorization changes
- No waiting for next heartbeat

### Acceptance Criteria
- [ ] Documentation added explaining revocation delay window
- [ ] Configuration option added for environments requiring faster revocation
- [ ] Recommendation added for high-security deployments
- [ ] Long-term push notification solution designed (if needed)
- [ ] Test added to measure actual revocation delay

### References
- Source Report: 8.3.2.md
- Merged From: ASVS-832-MED-001
- Related Domain: general_security

### Priority
Medium

---

## Issue: FINDING-057 - Unsanitized log event fields from untrusted subprocess passed as structlog kwargs
**Labels:** security, logging, priority:low
**Description:**
### Summary
The function `process_log_messages_from_subprocess` uses schema-less deserialization (`msgspec.json.decode(line)` without type argument) for untrusted subprocess input, violating the principle of using typed/schema-validated deserialization for untrusted input.

### Details
**Data Flow:**
- Task subprocess (untrusted code) → JSON bytes over socket → `msgspec.json.decode(line)` → untyped Python dict → passed to structlog
- **Affected Code:** `task-sdk/src/airflow/sdk/execution_time/supervisor.py:1741-1767`
- **Issue:** Schema-less deserialization doesn't enforce expected log event structure
- **Practical Impact:** Limited to data quality issues in logs
- **CWE:** CWE-117 (Improper Output Neutralization for Logs)
- **ASVS:** 1.3.3 (L2), 1.5.2 (L2)

### Remediation
Define an allowlist of permitted log keys and maximum log value length:

```python
ALLOWED_LOG_KEYS = {
    "event", "level", "timestamp", "logger", "task_id", 
    "dag_id", "run_id", "try_number", "map_index"
}
MAX_LOG_VALUE_LENGTH = 10000

for key in list(event.keys()):
    if key not in ALLOWED_LOG_KEYS:
        del event[key]
    elif isinstance(event[key], str) and len(event[key]) > MAX_LOG_VALUE_LENGTH:
        event[key] = event[key][:MAX_LOG_VALUE_LENGTH] + "...[truncated]"
```

### Acceptance Criteria
- [ ] Allowlist of permitted log keys defined
- [ ] Maximum log value length enforced
- [ ] Keys not in allowlist filtered out
- [ ] String values exceeding max length truncated
- [ ] Test added for oversized log values
- [ ] Test added for unexpected log keys
- [ ] Verify log quality not degraded

### References
- Source Reports: 1.3.3.md, 1.5.2.md
- Merged From: ASVS-133-LOW-001, XCOM_SERIALIZATION-1
- Related Domain: ipc_message_handling

### Priority
Low

---

## Issue: FINDING-058 - Template variables rendered without HTML encoding in email notification HTML context
**Labels:** security, xss, priority:low
**Description:**
### Summary
Template variables are rendered without HTML encoding in email notification HTML context. `ti.hostname` is inserted raw into HTML body and `ti.log_url` is inserted raw into HTML `href` attribute without proper encoding.

### Details
**Data Flow:**
- Task info → template variables → inserted into HTML without encoding
- **Affected Code:**
  - `task-sdk/src/airflow/sdk/execution_time/task_runner.py:1412-1413`
  - `task-sdk/src/airflow/sdk/execution_time/task_runner.py:1430-1435`
- **Risk Scenario:** If worker's hostname set to `<img src=x onerror=alert(1)>`, email HTML body would contain unescaped HTML injection
- **Real-world Exploitability:** Limited because:
  - System hostnames controlled by infrastructure, not end users
  - DAG IDs and task IDs validated by API server
  - Emails sent to addresses configured by trusted DAG authors
- **CWE:** CWE-79 (Cross-site Scripting)
- **ASVS:** 1.2.1 (L1), 1.1.2 (L2)

### Remediation
Apply context-appropriate encoding for all template variables, or enable Jinja2 autoescaping:

```python
import html
from markupsafe import Markup

# For HTML element context
hostname_escaped = html.escape(str(ti.hostname))

# For pre-escaped content
exception_html = Markup(exception_html)

# Include in additional_context
additional_context = {
    "hostname_escaped": hostname_escaped,
    "exception_html": exception_html,
}
```

Or enable Jinja2 autoescaping for the email template.

### Acceptance Criteria
- [ ] HTML encoding applied to hostname in HTML context
- [ ] URL encoding applied to log_url in href context
- [ ] Pre-escaped content marked with Markup()
- [ ] Jinja2 autoescaping enabled for email templates OR manual encoding applied
- [ ] Test added with malicious hostname
- [ ] Test added with malicious log_url
- [ ] Verify encoded output in generated emails

### References
- Source Reports: 1.2.1.md, 1.1.2.md
- Merged From: ASVS-121-LOW-001, IPC-5
- Related Domain: ipc_message_handling

### Priority
Low

---

## Issue: FINDING-059 - Inconsistent URL encoding in dynamically constructed log_url - dag_id and task_id not encoded
**Labels:** bug, security, priority:low
**Description:**
### Summary
While `run_id` is properly URL-encoded with `quote()`, `self.dag_id` and `self.task_id` are inserted raw into the URL path. If these values contained URL-significant characters, the URL structure would be corrupted.

### Details
**Data Flow:**
- `dag_id` and `task_id` → inserted raw into URL path → potential URL corruption
- **Affected Code:** `task-sdk/src/airflow/sdk/execution_time/task_runner.py:566-583`
- **Inconsistency:** `run_id` is encoded but `dag_id` and `task_id` are not
- **Current Protection:** Airflow's server validates dag_ids to safe patterns
- **Issue Type:** Defense-in-depth gap rather than exploitable vulnerability
- **CWE:** CWE-116 (Improper Encoding or Escaping of Output)
- **ASVS:** 1.2.2 (L1)

### Remediation
Apply consistent URL encoding to all dynamic path components:

```python
from urllib.parse import quote

run_id = quote(self.run_id, safe="")
dag_id = quote(self.dag_id, safe="")
task_id = quote(self.task_id, safe="")

return f"{base_url.rstrip('/')}/dags/{dag_id}/runs/{run_id}/tasks/{task_id}{map_index}{try_number}"
```

### Acceptance Criteria
- [ ] URL encoding applied to dag_id
- [ ] URL encoding applied to task_id
- [ ] URL encoding applied to run_id (already done, verify)
- [ ] Consistent encoding across all path components
- [ ] Test added with URL-significant characters in dag_id
- [ ] Test added with URL-significant characters in task_id
- [ ] Verify generated URLs are valid

### References
- Source Report: 1.2.2.md
- Merged From: ASVS-122-LOW-001
- Related Domain: ipc_message_handling
- Related Findings: FINDING-060, FINDING-064

### Priority
Low

---

## Issue: FINDING-060 - No URL protocol validation for base_url configuration value used in URL construction
**Labels:** security, configuration, priority:low
**Description:**
### Summary
The `base_url` is read from configuration without validating that it uses a safe protocol scheme. If configuration is modified to use `javascript:` or `data:` scheme, the resulting URL would be injected into email HTML `href` attributes.

### Details
**Data Flow:**
- Configuration → `base_url` → used in URL construction → inserted into email HTML
- **Affected Code:** `task-sdk/src/airflow/sdk/execution_time/task_runner.py:569`
- **Risk Scenario:** Configuration modified to use `javascript:` or `data:` scheme
- **Current Protection:** Configuration modification requires administrative access
- **Note:** This is different from the execution API server URL validation
- **CWE:** CWE-20 (Improper Input Validation)
- **ASVS:** 1.2.2 (L1)

### Remediation
Add protocol validation:

```python
from urllib.parse import urlparse

base_url = conf.get("api", "base_url", fallback="http://localhost:8080/")
parsed = urlparse(base_url)

if parsed.scheme not in ("http", "https"):
    base_url = "http://localhost:8080/"
```

### Acceptance Criteria
- [ ] Protocol validation added for base_url
- [ ] Only http and https schemes allowed
- [ ] Fallback to safe default for invalid schemes
- [ ] Warning logged when invalid scheme detected
- [ ] Test added for javascript: scheme
- [ ] Test added for data: scheme
- [ ] Test added for file: scheme

### References
- Source Report: 1.2.2.md
- Merged From: ASVS-122-LOW-002
- Related Domain: ipc_message_handling
- Related Findings: FINDING-063, FINDING-064

### Priority
Low

---

## Issue: FINDING-061 - Dual parsing paths for StartupDetails (JSON vs msgpack) create potential inconsistency
**Labels:** bug, security, priority:low
**Description:**
### Summary
The application uses two different parsing paths for `StartupDetails` data: normal path using msgpack over socket communication, and re-exec path using JSON through environment variables. This creates potential inconsistencies in number precision, DateTime handling, and character encoding.

### Details
**Data Flow Paths:**
- **Normal:** supervisor → msgpack encode → socket → msgpack decode → Pydantic validate
- **Re-exec:** supervisor → Pydantic model_dump_json() → env var → Pydantic validate_json()

**Affected Code:** `task-sdk/src/airflow/sdk/execution_time/task_runner.py:768-791`

**Potential Inconsistencies:**
1. **Number precision:** msgpack distinguishes int/float; JSON has single Number type
2. **DateTime handling:** 
   - msgpack: custom `_msgpack_enc_hook` converts Pendulum DateTime to stdlib datetime
   - JSON: Pydantic's default datetime serializer
3. **Character encoding:**
   - msgpack: raw bytes
   - JSON: UTF-8 with escape sequences

**Practical Risk:** Very low because:
- JSON payload serialized by `model_dump_json()` from same model
- Re-exec path only triggered in controlled scenarios

**CWE:** CWE-436 (Interpretation Conflict)
**ASVS:** 1.5.3 (L3)

### Remediation
Use a single serialization format for both paths. Always serialize to msgpack for the env var:

```python
import base64

# Encode via msgpack for consistency
os.environ["_AIRFLOW__STARTUP_MSG"] = base64.b64encode(msg.model_dump()).decode()
```

This eliminates the dual JSON/msgpack path by always using msgpack (base64-encoded for the env var).

### Acceptance Criteria
- [ ] Single serialization format used for both paths
- [ ] msgpack used for env var (base64-encoded)
- [ ] JSON path removed
- [ ] Test added to verify consistency between paths
- [ ] Test added for DateTime serialization consistency
- [ ] Test added for number precision consistency
- [ ] Verify re-exec functionality not broken

### References
- Source Report: 1.5.3.md
- Merged From: ASVS-153-LOW-001
- Related Domain: ipc_message_handling

### Priority
Low

---

## Issue: FINDING-062 - Cross-field validation rules for IPC messages are not documented
**Labels:** documentation, security, priority:low
**Description:**
### Summary
Message models contain multiple fields that should be contextually consistent, but no documentation defines these relationships. Without formal documentation of contextual consistency rules, it's difficult to verify that all necessary cross-field validations are implemented.

### Details
**Undocumented Relationships:**

**GetXCom model:**
- `dag_id` + `run_id` + `task_id` must reference an actual task instance
- `map_index` is only valid when the task is mapped

**GetPreviousTI:**
- `logical_date` and `state` filters interact logically

**Existing Validation:**
- Only implemented check found: `_validate_task_inlets_and_outlets` validates that referenced assets are active
- This validation exists but rules are not formally documented

**Affected Files:**
- `task-sdk/src/airflow/sdk/execution_time/comms.py`
- `supervisor.py`

**Impact:**
- Difficult to verify all necessary cross-field validations implemented
- New developers may introduce inconsistent data handling
- **ASVS:** 2.1.2 (L2)

### Remediation
Document business rules:
1. When `map_index` is provided, the referenced task must be a mapped task
2. When `include_prior_dates` is True, `logical_date` context determines the cutoff
3. All XCom operations must reference a `dag_id`/`run_id`/`task_id` combination belonging to the current DAG run or an explicitly allowed cross-DAG access

Create explicit documentation (or use Pydantic Field descriptions) defining:
- Valid character sets for identifiers
- Maximum lengths for all string fields
- Cross-field consistency rules (e.g., map_index validity conditions)

### Acceptance Criteria
- [ ] Documentation added for all cross-field validation rules
- [ ] Pydantic Field descriptions added where appropriate
- [ ] Valid character sets documented for identifiers
- [ ] Maximum lengths documented for string fields
- [ ] Examples added for valid and invalid combinations
- [ ] Test coverage verified for all documented rules

### References
- Source Report: 2.1.2.md
- Merged From: ASVS-212-LOW-001
- Related Domain: ipc_message_handling

### Priority
Low

---

## Issue: FINDING-063 - GetXComSequenceSlice allows step=0 without validation
**Labels:** bug, security, priority:low
**Description:**
### Summary
A task sending `step=0` in `GetXComSequenceSlice` would cause a `ValueError` when the API attempts to construct a Python slice object. While the exception would be caught and returned as an error, it represents a failure to enforce business logic at the validation layer.

### Details
**Data Flow:**
- Task sends `step=0` → API constructs slice object → ValueError raised
- **Affected Code:** `task-sdk/src/airflow/sdk/execution_time/comms.py`
- **Issue:** Pre-defined rule that step must be non-zero is not checked at validation layer
- **Current Behavior:** Exception caught and returned as error
- **Desired Behavior:** Validation prevents invalid value from reaching API
- **CWE:** CWE-20 (Improper Input Validation)
- **ASVS:** 2.2.3 (L2)

### Remediation
Add a Pydantic field_validator to the `GetXComSequenceSlice` class:

```python
from pydantic import field_validator

class GetXComSequenceSlice(BaseModel):
    # ... existing fields ...
    
    @field_validator("step")
    @classmethod
    def step_must_not_be_zero(cls, v):
        if v is not None and v == 0:
            raise ValueError("step must not be zero")
        return v
```

### Acceptance Criteria
- [ ] Field validator added for step parameter
- [ ] Validation rejects step=0
- [ ] Validation allows step=None
- [ ] Validation allows positive and negative non-zero values
- [ ] Test added for step=0 (should fail validation)
- [ ] Test added for valid step values
- [ ] Error message is clear and helpful

### References
- Source Report: 2.2.3.md
- Merged From: ASVS-223-LOW-001
- Related Domain: ipc_message_handling
- Related Findings: FINDING-060, FINDING-064

### Priority
Low

---

## Issue: FINDING-064 - State fields accept arbitrary strings instead of valid enum values
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `state` and `states` fields in `GetPreviousDagRun`, `GetTICount`, and `GetDRCount` accept arbitrary strings where they should only accept valid state enum values. This fails to enforce the business rule that state values must be from a predefined set.

### Details
**Affected Classes:**
- `GetPreviousDagRun`
- `GetTICount`
- `GetDRCount`

**Affected Code:** `task-sdk/src/airflow/sdk/execution_time/comms.py`

**Issue:**
- Fields accept any string value
- Should only accept valid state enum values
- API server would likely reject invalid states, but early validation at IPC boundary would:
  - Provide faster feedback
  - Reduce unnecessary API calls

**CWE:** CWE-20 (Improper Input Validation)
**ASVS:** 2.2.3 (L2)

### Remediation
Constrain state fields to valid enum values using Literal types:

```python
from typing import Literal

class GetPreviousDagRun(BaseModel):
    dag_id: str
    logical_date: AwareDatetime
    state: Literal["queued", "running", "success", "failed"] | None = None
    type: Literal["GetPreviousDagRun"] = "GetPreviousDagRun"
```

Apply the same pattern to `GetTICount` and `GetDRCount` classes.

### Acceptance Criteria
- [ ] Literal types added for state fields in GetPreviousDagRun
- [ ] Literal types added for state fields in GetTICount
- [ ] Literal types added for state fields in GetDRCount
- [ ] Test added for invalid state value (should fail validation)
- [ ] Test added for each valid state value
- [ ] Test added for None state value
- [ ] Error messages are clear and list valid options

### References
- Source Report: 2.2.3.md
- Merged From: ASVS-223-LOW-002
- Related Domain: ipc_message_handling
- Related Findings: FINDING-060, FINDING-063

### Priority
Low

---

## Issue: FINDING-065 - jinja2.ext.do extension enabled by default expands template execution surface
**Labels:** security, enhancement, priority:low
**Description:**
### Summary
The `jinja2.ext.do` extension is enabled by default in `create_template_env`, which allows expression statements with side effects in templates (e.g., `{% do mylist.append(item) %}`). This expands the set of operations templates can perform from 'read/render values' to 'execute statements with side effects'.

### Details
**Data Flow:**
- Template environment created with `jinja2.ext.do` → templates can execute statements with side effects
- **Affected Code:** `task-sdk/src/airflow/sdk/definitions/_internal/templater.py:391`
- **Risk:** Compounds risk in native mode where any method can be called with side effects
- **Current Protection:** Sandbox restricts what methods can be called in sandboxed mode
- **CWE:** CWE-94 (Improper Control of Generation of Code)
- **ASVS:** 1.3.7 (L2)

### Remediation
1. Remove `jinja2.ext.do` from default extensions
2. Make it opt-in via DAG configuration (`jinja_environment_kwargs`) only when explicitly needed
3. Document the security implications of enabling the do extension

Example:
```python
# Default extensions without 'do'
DEFAULT_EXTENSIONS = ['jinja2.ext.loopcontrols']

# Allow opt-in via DAG configuration
if dag.jinja_environment_kwargs.get('enable_do_extension'):
    extensions.append('jinja2.ext.do')
```

### Acceptance Criteria
- [ ] jinja2.ext.do removed from default extensions
- [ ] Opt-in mechanism added via DAG configuration
- [ ] Documentation added explaining security implications
- [ ] Warning logged when do extension is enabled
- [ ] Test added to verify do extension disabled by default
- [ ] Test added to verify opt-in mechanism works
- [ ] Migration guide created for DAGs using do extension

### References
- Source Report: 1.3.7.md
- Merged From: ASVS-137-LOW-001
- Related Domain: jinja_template_injection

### Priority
Low

---

## Issue: FINDING-066 - Missing invalidate_connection_uri method creates asymmetric cache management
**Labels:** bug, security, priority:low
**Description:**
### Summary
The cache provides `invalidate_variable()` for removing variables but has no corresponding `invalidate_connection_uri()` method. This means there is no way to programmatically remove a single connection from the cache when credentials are rotated or access is revoked.

### Details
**Data Flow:**
- Connection cached → credentials rotated or revoked → stale credentials remain in cache until TTL expiration
- **Affected Code:** `task-sdk/src/airflow/sdk/execution_time/cache.py:137-142`
- **Asymmetry:** Variable invalidation supported, connection invalidation not supported
- **Default TTL:** 15 minutes
- **Impact:** Stale or revoked connection credentials remain usable for up to TTL duration
- **CWE:** None specified
- **ASVS:** 13.3.1 (L2)

### Remediation
Add a symmetric `invalidate_connection_uri()` method:

```python
def invalidate_connection_uri(self, conn_id: str) -> None:
    """Remove a connection from the cache.
    
    Args:
        conn_id: The connection ID to invalidate
    """
    cache_key = f"connection:{conn_id}"
    if cache_key in self._cache:
        del self._cache[cache_key]
```

### Acceptance Criteria
- [ ] invalidate_connection_uri() method added
- [ ] Method signature matches invalidate_variable() pattern
- [ ] Connection removed from cache when method called
- [ ] Test added for connection invalidation
- [ ] Test added to verify invalidated connection is re-fetched
- [ ] Documentation added explaining when to use invalidation

### References
- Source Report: 13.3.1.md
- Merged From: ASVS-1331-LOW-001
- Related Domain: secrets_backend_access

### Priority
Low

---

## Issue: FINDING-067 - No client-side validation of requested secret identifiers enables enumeration attempts
**Labels:** security, enhancement, priority:low
**Description:**
### Summary
The `ExecutionAPISecretsBackend` passes any `conn_id` or `key` directly to the server without client-side validation. While server-side authorization prevents actual access, the response pattern (returning None for both 'not found' and 'unauthorized') means task code cannot distinguish between a non-existent secret and one it's not authorized to access.

### Details
**Data Flow:**
- Task requests secret → client passes to server without validation → server enforces authorization → returns None for both 'not found' and 'unauthorized'
- **Affected Code:** `task-sdk/src/airflow/sdk/execution_time/secrets/execution_api.py` (get_connection() and get_variable() methods)
- **Positive:** Server enforces object-level authorization
- **Negative:** SDK client provides no additional layer of defense
- **Enumeration Risk:** Task can attempt to enumerate secret identifiers without triggering authorization failure signals
- **Trade-off:** Lack of distinction between 'not found' and 'denied' provides defense against information leakage but masks authorization violations from audit/logging perspective
- **CWE:** None specified
- **ASVS:** 8.2.2 (L1)

### Remediation
Log authorization failures distinctly from 'not found' responses:

```python
if isinstance(msg, ErrorResponse):
    if msg.status_code == 403:
        import logging
        logger = logging.getLogger(__name__)
        logger.warning('Authorization denied for connection: %s', conn_id)
    return None
```

### Acceptance Criteria
- [ ] Authorization failures logged distinctly
- [ ] Log includes secret identifier that was denied
- [ ] Log level appropriate for security events (WARNING or higher)
- [ ] Test added to verify authorization denial logging
- [ ] Verify 'not found' responses not logged as authorization failures
- [ ] Documentation added explaining logging behavior

### References
- Source Report: 8.2.2.md
- Merged From: ASVS-822-LOW-001
- Related Domain: secrets_backend_access

### Priority
Low

---

## Issue: FINDING-068 - No key expiration or TTL enforcement mechanism
**Labels:** security, enhancement, priority:low
**Description:**
### Summary
While Fernet's `decrypt()` supports a `ttl` parameter for time-based token expiration, the default value is None (no expiration check). The code does not enforce a maximum TTL for encrypted tokens, meaning encrypted values remain valid indefinitely.

### Details
**Data Flow:**
- Fernet key generated → used indefinitely without expiration → encrypted tokens valid forever
- **Affected Code:** `task-sdk/src/airflow/sdk/crypto.py`
- **Standard:** Per NIST SP 800-57 Section 5.3, cryptoperiods should be defined for all key types
- **Design Decision:** Per known false positive guidance, key management is delegated to the Airflow server, so this is informational
- **CWE:** None specified
- **ASVS:** 11.1.1 (L2)

### Remediation
1. Document the expected cryptoperiod for Fernet keys
2. Consider implementing a configurable TTL for decryption operations in production environments

Example:
```python
# In configuration
FERNET_TOKEN_TTL = conf.getint("core", "fernet_token_ttl_seconds", fallback=None)

# In decrypt
if FERNET_TOKEN_TTL:
    return fernet.decrypt(token, ttl=FERNET_TOKEN_TTL)
else:
    return fernet.decrypt(token)
```

### Acceptance Criteria
- [ ] Documentation added for expected Fernet key cryptoperiod
- [ ] Configuration option added for token TTL (optional)
- [ ] If TTL implemented, test added to verify expiration
- [ ] If TTL implemented, test added to verify non-expired tokens work
- [ ] Recommendation added for production TTL values

### References
- Source Report: 11.1.1.md
- Merged From: ASVS-1111-LOW-001
- Related Domain: fernet_encryption

### Priority
Low

---

## Issue: FINDING-069 - Key usage scope not enforced programmatically
**Labels:** security, enhancement, priority:low
**Description:**
### Summary
A single Fernet key (or key set) is used for all encryption operations across the SDK. There is no programmatic separation between keys used for connection passwords versus variable values versus other potential uses. This means compromise of one key compromises all encrypted data types.

### Details
**Data Flow:**
- Single Fernet key → used for ALL encryption operations → no purpose-specific key separation
- **Affected Code:** `task-sdk/src/airflow/sdk/crypto.py` (get_fernet())
- **Usage:** Single key used for:
  - Connection passwords
  - Variable values
  - Other encrypted data
- **Impact:** Compromise of one key compromises all encrypted data types
- **CWE:** None specified
- **ASVS:** 11.1.2 (L2)

### Remediation
Consider documenting key usage boundaries and, for future iterations, supporting purpose-specific keys:

```python
def get_fernet(purpose: str = "default") -> FernetProtocol:
    """Get Fernet instance for a specific purpose.
    
    Args:
        purpose: The purpose for this key ("connections", "variables", "default")
    """
    key_config = f"FERNET_KEY_{purpose.upper()}" if purpose != "default" else "FERNET_KEY"
    fernet_key = conf.get("core", key_config)
    # ... rest of initialization
```

This would allow separation of keys by purpose (connections vs variables) to limit blast radius of key compromise.

### Acceptance Criteria
- [ ] Documentation added for key usage boundaries
- [ ] Purpose-specific key support designed (optional implementation)
- [ ] If implemented, test added for each purpose
- [ ] If implemented, migration guide created
- [ ] Recommendation added for key separation in high-security environments

### References
- Source Report: 11.1.2.md
- Merged From: ASVS-1112-LOW-001
- Related Domain: fernet_encryption

### Priority
Low

---

## Issue: FINDING-070 - AES-128 key length used via Fernet rather than AES-256
**Labels:** security, enhancement, priority:low
**Description:**
### Summary
Fernet uses a 256-bit key split into a 128-bit HMAC signing key and a 128-bit AES encryption key, meaning the effective encryption strength is AES-128, not AES-256. While AES-128 is secure against classical attacks, NIST guidance for long-term protection and quantum resistance recommends AES-256.

### Details
**Fernet Key Structure:**
- 256-bit key split into:
  - 128-bit HMAC signing key
  - 128-bit AES encryption key
- **Effective Encryption:** AES-128

**Quantum Considerations:**
- AES-128 provides ~64 bits of security against quantum adversaries using Grover's algorithm
- AES-256 provides ~128 bits of security against Grover's algorithm
- For data requiring long-term confidentiality, AES-128 may be insufficient

**Current Threat Model:**
- For protecting secrets in transit between server and task processes
- AES-128 remains adequate against classical attacks

**Affected File:** `task-sdk/src/airflow/sdk/crypto.py`
**CWE:** None specified
**ASVS:** 11.3.2 (L1)

### Remediation
This is informational and tied to the broader crypto agility issue (ASVS-1122-HIGH-001). When implementing crypto agility, ensure AES-256-GCM or ChaCha20-Poly1305 are available as options.

Example implementation:
```python
class AES256GCMBackend:
    """AES-256-GCM encryption backend providing 256-bit key strength."""
    
    def __init__(self, key: bytes):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        self.aesgcm = AESGCM(key)  # key must be 256 bits
```

### Acceptance Criteria
- [ ] Documentation added explaining Fernet key structure
- [ ] Documentation added for quantum considerations
- [ ] AES-256-GCM backend designed as alternative
- [ ] Configuration option added to select encryption backend
- [ ] If implemented, test added for AES-256-GCM backend
- [ ] Migration path documented for moving to AES-256

### References
- Source Report: 11.3.2.md
- Merged From: ASVS-1132-LOW-001
- Related Domain: fernet_encryption
- Related Issues: ASVS-1122-HIGH-001 (crypto agility)

### Priority
Low

---

## Issue: FINDING-071 - No per-tenant Fernet key scoping in multi-tenant deployments
**Labels:** security, enhancement, priority:low
**Description:**
### Summary
The Fernet key provisioning uses a single configuration value (`core.FERNET_KEY`) with no mechanism for per-tenant or per-secret key scoping. In multi-tenant deployments, all tenants' secrets are encrypted with the same key material, creating a blast radius issue.

### Details
**Data Flow:**
- Single Fernet key → used for all tenants → no tenant isolation
- **Affected Code:** `task-sdk/src/airflow/sdk/crypto.py:97-116`
- **Multi-tenant Risks:**
  - Single tenant's task process compromised → key extracted from memory → ALL tenants' secrets decryptable
  - Key rotation affects all tenants simultaneously → operational coupling
- **CWE:** None specified
- **ASVS:** 13.3.4 (L3)

### Remediation
For multi-tenant deployments, implement key scoping per tenant or per secret class:

```python
@cache
def get_fernet(tenant_id: str | None = None) -> FernetProtocol:
    from airflow.sdk.configuration import conf
    
    if tenant_id:
        fernet_key = conf.get("core", f"FERNET_KEY_{tenant_id}")
    else:
        fernet_key = conf.get("core", "FERNET_KEY")
    
    # ... rest of initialization
```

### Acceptance Criteria
- [ ] Per-tenant key scoping designed
- [ ] Configuration schema updated for tenant-specific keys
- [ ] Test added for multi-tenant key isolation
- [ ] Test added to verify tenant A cannot decrypt tenant B's secrets
- [ ] Documentation added for multi-tenant deployment
- [ ] Migration guide created for existing multi-tenant deployments

### References
- Source Report: 13.3.4.md
- Merged From: ASVS-1334-LOW-001
- Related Domain: fernet_encryption

### Priority
Low

---

## Issue: FINDING-072 - No explicit TLS minimum version enforcement in SSL context
**Labels:** security, enhancement, priority:low
**Description:**
### Summary
While Python 3.10+ sets `minimum_version = TLSVersion.TLSv1_2` by default in `create_default_context()`, this behavior is dependent on the Python version and system OpenSSL configuration. An explicit setting makes the security posture auditable and protects against regressions.

### Details
**Data Flow:**
- SSL context created → relies on Python/OpenSSL defaults for minimum TLS version
- **Affected Code:** `task-sdk/src/airflow/sdk/api/client.py:733-738`
- **Current Behavior:** Python 3.10+ defaults to TLS 1.2 minimum
- **Risk:** Dependent on:
  - Python version
  - System OpenSSL configuration
  - Potential regressions in system-level TLS policy
- **CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
- **ASVS:** 12.1.1 (L2)
- **Related:** FINDING-021

### Remediation
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

### Acceptance Criteria
- [ ] Explicit minimum_version set to TLSv1_2
- [ ] Explicit maximum_version set to MAXIMUM_SUPPORTED
- [ ] Test added to verify TLS 1.0 connections rejected
- [ ] Test added to verify TLS 1.1 connections rejected
- [ ] Test added to verify TLS 1.2 connections accepted
- [ ] Test added to verify TLS 1.3 connections accepted

### References
- Source Report: 12.1.1.md
- Merged From: ASVS-1211-LOW-001
- Related Domain: execution_api_client
- Related Findings: FINDING-021

### Priority
Low

---

## Issue: FINDING-073 - Token stored as plain string without SecretStr protection in data model
**Labels:** security, enhancement, priority:low
**Description:**
### Summary
Token is stored in `ExecuteTaskActivity.token` as plain `str` and serialized via Pydantic. If the model is ever serialized for logging, debugging, or error reporting, the token would appear in plaintext. Using `pydantic.SecretStr` would mask it in `repr()` and `str()` outputs.

### Details
**Data Flow:**
- Token stored as plain str → serialized via Pydantic → potentially exposed in logs/debug output
- **Affected Code:** `task-sdk/src/airflow/sdk/api/datamodels/activities.py:28`
- **Risk:** Token exposed in:
  - Log messages
  - Debug output
  - Error reports
  - Serialized representations
- **Scope:** This finding is limited to representation protection only, not the token passing mechanism itself
- **CWE:** CWE-532 (Insertion of Sensitive Information into Log File)
- **ASVS:** 10.1.1 (L2)

### Remediation
Change token field type from `str` to `pydantic.SecretStr`:

```python
from pydantic import SecretStr

class ExecuteTaskActivity(BaseModel):
    ti: TaskInstance
    path: os.PathLike[str]
    token: SecretStr
    """The identity token for this workload"""
```

### Acceptance Criteria
- [ ] Token field type changed to SecretStr
- [ ] Test added to verify token masked in repr()
- [ ] Test added to verify token masked in str()
- [ ] Test added to verify token masked in JSON serialization
- [ ] Test added to verify token can still be accessed via .get_secret_value()
- [ ] Verify all code accessing token updated to use .get_secret_value()

### References
- Source Report: 10.1.1.md
- Merged From: ASVS-1011-LOW-001
- Related Domain: execution_api_client

### Priority
Low

---

## Issue: FINDING-074 - No allowlist validation for external API server addresses
**Labels:** security, enhancement, priority:low
**Description:**
### Summary
The client accepts any `base_url` from configuration without validating it against an allowlist of permitted API server addresses. In multi-tenant or multi-deployment scenarios, a misconfigured or maliciously altered `base_url` could direct the client (with its bearer token) to communicate with an unauthorized server.

### Details
**Data Flow:**
- Configuration → base_url → client communicates with any configured endpoint
- **Affected Code:** `task-sdk/src/airflow/sdk/api/client.py:575-600`
- **Current Protection:** Client architecturally constrained to communicate with single configured endpoint (all paths are relative)
- **Missing:** No explicit allowlist mechanism validating configured destination is authorized Airflow API server
- **Risk Scenario:**
  - Multiple Airflow deployments
  - Multi-tenant environment
  - Misconfigured or maliciously altered base_url
  - Client directs bearer token to unauthorized server mimicking Execution API
- **CWE:** CWE-918 (Server-Side Request Forgery)
- **ASVS:** 13.2.4 (L2)
- **Related:** FINDING-095

### Remediation
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

### Acceptance Criteria
- [ ] Allowlist configuration option added
- [ ] Hostname validation implemented when allowlist configured
- [ ] ValueError raised for disallowed hosts
- [ ] Test added for allowed host (should succeed)
- [ ] Test added for disallowed host (should fail)
- [ ] Test added for no allowlist configured (should allow any)
- [ ] Documentation added explaining allowlist configuration

### References
- Source Report: 13.2.4.md
- Merged From: ASVS-1324-LOW-001
- Related Domain: execution_api_client
- Related Findings: FINDING-095

### Priority
Low

---

## Issue: FINDING-075 - Client allows follow_redirects override via kwargs
**Labels:** security, bug, priority:low
**Description:**
### Summary
The `Client` constructor passes `**kwargs` to the parent `httpx.Client.__init__()`. While httpx defaults to `follow_redirects=False`, there is no explicit prevention of this being overridden via kwargs. If a caller passes `follow_redirects=True`, the client would silently follow HTTP→HTTPS redirects, masking cleartext initial requests containing bearer tokens.

### Details
**Data Flow:**
- Caller passes `follow_redirects=True` via kwargs → httpx client follows redirects → bearer token sent in cleartext HTTP request
- **Affected Code:** `task-sdk/src/airflow/sdk/api/client.py:580-620`
- **Issue:** `raise_on_4xx_5xx` response hook only fires on 4xx/5xx responses, not 3xx redirects
- **Risk:** 3xx response from misconfigured HTTP endpoint:
  - Would not be caught as error
  - Causes silent failures rather than clear security-related errors
- **CWE:** CWE-601 (URL Redirection to Untrusted Site)
- **ASVS:** 4.1.2 (L2)

### Remediation
In `Client.__init__`, explicitly set and protect `follow_redirects`:

```python
kwargs.pop("follow_redirects", None)  # Prevent override
super().__init__(
    auth=auth,
    follow_redirects=False,
    ...
)
```

### Acceptance Criteria
- [ ] follow_redirects explicitly set to False
- [ ] kwargs override prevented
- [ ] Test added attempting to override follow_redirects
- [ ] Test added to verify redirects not followed
- [ ] Test added to verify 3xx responses handled appropriately
- [ ] Documentation added explaining redirect policy

### References
- Source Report: 4.1.2.md
- Merged From: ASVS-412-LOW-001
- Related Domain: execution_api_client

### Priority
Low

---

## Issue: FINDING-076 - Unconditional trust of Refreshed-API-Token response header without validation
**Labels:** security, enhancement, priority:low
**Description:**
### Summary
The client unconditionally trusts the `Refreshed-API-Token` response header to replace its authentication token without validating that the response comes from the legitimate API server (beyond TLS verification) or that the new token has expected format/structure.

### Details
**Data Flow:**
- Response received → `Refreshed-API-Token` header present → token unconditionally replaced
- **Affected Code:** `task-sdk/src/airflow/sdk/api/client.py:610-613`
- **Missing Validation:**
  1. Response comes from legitimate API server (beyond TLS verification)
  2. New token has expected format/structure
  3. Response that triggered token refresh was for appropriate endpoint
- **Risk Scenario:**
  - Reverse proxy or CDN in communication path injects header (intentionally or via misconfiguration)
  - Client's authentication token replaced with attacker-controlled value
  - Subsequent authenticated requests potentially redirected to attacker's server
- **CWE:** CWE-345 (Insufficient Verification of Data Authenticity)
- **ASVS:** 4.1.3 (L2)

### Remediation
Add validation to only accept token refresh from specific endpoints and implement basic format validation:

```python
# Only accept token refresh from specific endpoints
if response.url.path.endswith(("/run", "/heartbeat")):
    new_token = response.headers.get("Refreshed-API-Token")
    if new_token:
        # Validate token format
        if len(new_token) >= 32:
            self.auth.token = new_token
        else:
            logger.warning("Ignoring malformed token refresh: token too short")
```

### Acceptance Criteria
- [ ] Token refresh only accepted from specific endpoints
- [ ] Minimum token length validation added
- [ ] Warning logged for malformed tokens
- [ ] Test added for token refresh from /run endpoint
- [ ] Test added for token refresh from /heartbeat endpoint
- [ ] Test added for token refresh from other endpoint (should be ignored)
- [ ] Test added for too-short token (should be ignored)

### References
- Source Report: 4.1.3.md
- Merged From: ASVS-413-LOW-001
- Related Domain: execution_api_client

### Priority
Low

---

## Issue: FINDING-077 - Dataclass/attr constructor called with all deserialized fields without explicit field filtering
**Labels:** security, enhancement, priority:low
**Description:**
### Summary
All keys present in the serialized dict are passed to the target class constructor without explicit field filtering. While Python's dataclass/attrs constructors naturally reject undeclared fields (raising TypeError), classes that define fields with defaults could have those defaults overridden by attacker-supplied values if serialized data is tampered with.

### Details
**Data Flow:**
- Serialized dict → all keys passed to constructor → potential override of defaults
- **Affected Code:** `task-sdk/src/airflow/sdk/serde/__init__.py:264-267`
- **Current Protection:**
  1. Classes must pass deserialization allowlist
  2. XCom data originates from trusted task execution via supervisor
- **Risk:** Limited to classes with default field values that could be overridden
- **Assessment:** Defense-in-depth observation rather than exploitable vulnerability
- **CWE:** None specified
- **ASVS:** 15.3.3 (L2)

### Remediation
For additional defense-in-depth, filter deserialized dict keys against the class's declared fields:

```python
if dataclasses.is_dataclass(cls):
    allowed_fields = {f.name for f in dataclasses.fields(cls) if f.init}
    deserialize_value = {k: v for k, v in deserialize_value.items() if k in allowed_fields}
    return cls(**deserialize_value)
```

### Acceptance Criteria
- [ ] Field filtering added for dataclass deserialization
- [ ] Field filtering added for attrs deserialization
- [ ] Only declared fields with init=True passed to constructor
- [ ] Test added with extra fields in serialized data
- [ ] Test added to verify defaults not overridden by extra fields
- [ ] Verify existing functionality not broken

### References
- Source Report: 15.3.3.md
- Merged From: ASVS-1533-LOW-001
- Related Domain: xcom_serialization

### Priority
Low

---

## Issue: FINDING-078 - BaseXCom.deserialize_value() lacks type annotation and validation on parameter
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `result` parameter in `BaseXCom.deserialize_value()` has no type annotation and no `isinstance` check. While called from controlled contexts, the lack of explicit type enforcement means subclasses or future callers could pass incorrect types without compile-time or runtime checking.

### Details
**Data Flow:**
- `result` parameter → accessed via `.value` → no type validation
- **Affected Code:** `task-sdk/src/airflow/sdk/bases/xcom.py:258-261`
- **Current Callers:**
  - `get_one()` with `XComResult`
  - `get_all()` with `_XComValueWrapper`
- **Issue:** Relies on duck typing (accessing `.value`)
- **Inconsistency:** `get_one()` and `_get_xcom_db_ref()` explicitly validate message types
- **CWE:** None specified
- **ASVS:** 15.3.5 (L2)

### Remediation
Add type annotation and validation:

```python
@staticmethod
def deserialize_value(result: XComResult | _XComValueWrapper) -> Any:
    """Deserialize XCom value from str objects."""
    from airflow.sdk.serde import deserialize

    if not hasattr(result, 'value'):
        raise TypeError(f"Expected object with 'value' attribute, got {type(result)}")
    
    return deserialize(result.value)
```

### Acceptance Criteria
- [ ] Type annotation added to result parameter
- [ ] hasattr check added for 'value' attribute
- [ ] TypeError raised for invalid types
- [ ] Test added for XComResult (should succeed)
- [ ] Test added for _XComValueWrapper (should succeed)
- [ ] Test added for invalid type (should raise TypeError)
- [ ] Error message includes actual type received

### References
- Source Report: 15.3.5.md
- Merged From: ASVS-1535-LOW-001
- Related Domain: xcom_serialization

### Priority
Low

---

## Issue: FINDING-079 - Import failure is logged at DEBUG level and execution continues (fail-open pattern)
**Labels:** security, enhancement, priority:low
**Description:**
### Summary
The fail-open pattern in callback validation means that a path which CANNOT be validated is still accepted and stored. While the comment provides legitimate justification (runtime availability differs from parse-time), this reduces the effectiveness of validation as a protective control.

### Details
**Data Flow:**
- Callback path → import attempted → import fails → logged at DEBUG level → path still stored
- **Affected Code:** `task-sdk/src/airflow/sdk/definitions/callback.py:73-80`
- **Issue:** Invalid or malicious path that fails to import at definition time will still be stored and potentially executed later
- **Justification:** Runtime availability differs from parse-time (legitimate concern)
- **ASVS Perspective:** Gap in protection around dangerous functionality per 15.2.5
- **CWE:** None specified
- **ASVS:** 15.2.5 (L3)

### Remediation
Consider adding a stricter mode that can be enabled in security-sensitive deployments:

1. Add configurable `STRICT_CALLBACK_VALIDATION` environment variable
2. When enabled, raise `ImportError` instead of logging and continuing
3. Change log level from DEBUG to WARNING in permissive mode to increase visibility of validation failures

```python
STRICT_CALLBACK_VALIDATION = os.environ.get("STRICT_CALLBACK_VALIDATION", "false").lower() == "true"

try:
    _validate_python_callable_name(path)
except Exception:
    if STRICT_CALLBACK_VALIDATION:
        raise
    else:
        logger.warning("Callback validation failed for %s", path, exc_info=True)
```

### Acceptance Criteria
- [ ] STRICT_CALLBACK_VALIDATION environment variable added
- [ ] ImportError raised in strict mode
- [ ] Log level changed to WARNING in permissive mode
- [ ] Test added for strict mode (should raise)
- [ ] Test added for permissive mode (should log and continue)
- [ ] Documentation added explaining strict mode

### References
- Source Report: 15.2.5.md
- Merged From: ASVS-1525-LOW-001
- Related Domain: module_loading

### Priority
Low

---

## Issue: FINDING-080 - Unsynchronized module-level cache dictionary access
**Labels:** bug, concurrency, priority:low
**Description:**
### Summary
The module-level dict `_REMOTE_LOGGING_CONN_CACHE` is accessed without synchronization mechanisms. In the current single-threaded supervisor architecture, this is safe. However, if the module is ever used in a multi-threaded context, unsynchronized dict access could lead to lost updates or inconsistent reads.

### Details
**Data Flow:**
- Module-level dict → accessed without lock → potential race conditions in multi-threaded context
- **Affected Code:** `task-sdk/src/airflow/sdk/execution_time/supervisor.py` (near `_fetch_remote_logging_conn`)
- **Current Safety:** Single-threaded supervisor architecture
- **Risk:** If supervisor manages multiple tasks concurrently via threads:
  - Lost updates
  - Inconsistent reads
  - Cache corruption
- **Note:** `InProcessTestSupervisor` already uses threads, though it doesn't call this function path
- **CWE:** None specified
- **ASVS:** 15.4.1 (L3)

### Remediation
Add `threading.Lock` to protect cache access:

```python
import threading

_REMOTE_LOGGING_CONN_CACHE_LOCK = threading.Lock()

def _fetch_remote_logging_conn():
    # Check cache with lock
    with _REMOTE_LOGGING_CONN_CACHE_LOCK:
        if key in _REMOTE_LOGGING_CONN_CACHE:
            return _REMOTE_LOGGING_CONN_CACHE[key]
    
    # Fetch without lock (I/O operation)
    conn = fetch_from_api()
    
    # Update cache with lock
    with _REMOTE_LOGGING_CONN_CACHE_LOCK:
        _REMOTE_LOGGING_CONN_CACHE[key] = conn
    
    return conn
```

Consider double-checked locking pattern to avoid holding lock during I/O operations.

### Acceptance Criteria
- [ ] threading.Lock added for cache access
- [ ] Lock used when checking cache membership
- [ ] Lock used when updating cache
- [ ] Lock not held during I/O operations
- [ ] Test added for concurrent cache access
- [ ] Test added to verify no deadlocks
- [ ] Performance impact measured and documented

### References
- Source Report: 15.4.1.md
- Merged From: ASVS-1541-LOW-001
- Related Domain: process_isolation

### Priority
Low

## Issue: FINDING-081 - Race condition in test supervisor socket cleanup
**Labels:** bug, security, priority:low
**Description:**
### Summary
In InProcessTestSupervisor._setup_subprocess_socket, the main thread writes to self._open_sockets and self.selector while a daemon thread reads the same objects in _handle_socket_comms with no locks protecting concurrent access. The thread.join(0) call does not wait for thread completion, meaning the thread may still be accessing shared state after the context manager exits.

### Details
In testing scenarios, race conditions could occur between the main thread closing sockets and the daemon thread attempting to use them. The daemon thread may attempt to call self.selector.select() after the main thread has closed the selector or sockets, potentially raising exceptions or accessing already-freed resources. This is test-only code.

**Affected Files:**
- task-sdk/src/airflow/sdk/execution_time/supervisor.py (InProcessTestSupervisor._setup_subprocess_socket)

**ASVS:** 15.4.1, 15.4.3 (Level L3)

### Remediation
Use a blocking thread.join() with timeout instead of non-blocking join(0). Signal thread to stop, close requests and child_sock, then call thread.join(timeout=5.0) to wait for thread completion. If thread.is_alive() after join, log a warning that handler thread did not stop within timeout period. Consider using threading events for clean shutdown signaling.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 15.4.1.md, 15.4.3.md

### Priority
Low

---

## Issue: FINDING-082 - TOCTOU race condition in bundle access verification
**Labels:** bug, security, priority:low
**Description:**
### Summary
The _verify_bundle_access function performs separate checks (bundle_path.exists() and os.access()) before the actual file read in BundleDagBag. In a run_as_user impersonation scenario, a symlink at bundle_path could be replaced between the access check and the actual file read.

### Details
A symlink at bundle_path could be replaced between the access check and the actual file read, potentially causing the DAG bag to read from a different location. However, this requires local filesystem access and the window is very small. The practical risk is low as an attacker would need write access to the bundle directory on the same machine, which implies existing compromise.

**Affected Files:**
- task-sdk/src/airflow/sdk/execution_time/task_runner.py (_verify_bundle_access)

**ASVS:** 15.4.2 (Level L3)

### Remediation
The current pattern is acceptable for its stated purpose (informative error messages for impersonation failures). For higher assurance, open the file directly and handle errors using a try-then-catch pattern instead of check-then-act: try opening bundle_path / "some_marker" and catch PermissionError to raise an informative AirflowException.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 15.4.2.md

### Priority
Low

---

## Issue: FINDING-083 - Task-controlled polling interval without minimum enforcement
**Labels:** bug, security, priority:low
**Description:**
### Summary
The DAG run polling loop uses a task-controlled poke_interval without enforcing a minimum value. A malicious or misconfigured task can set an extremely low interval, creating a tight polling loop that floods the API server with status check requests.

### Details
Operator sets poke_interval=0.001 → _handle_trigger_dag_run tight loop → SUPERVISOR_COMMS.send(GetDagRunState(...)) every millisecond → API server overload.

**Affected Files:**
- task-sdk/src/airflow/sdk/execution_time/task_runner.py (_handle_trigger_dag_run function)

**ASVS:** 2.4.1 (Level L2)

### Remediation
Enforce a minimum poke interval (e.g., MIN_POKE_INTERVAL = 5.0 seconds) in _handle_trigger_dag_run. Use effective_interval = max(drte.poke_interval, MIN_POKE_INTERVAL) to ensure the polling loop never runs faster than the minimum allowed interval, preventing tight loops that could overload the API server.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 2.4.1.md

### Priority
Low

---

## Issue: FINDING-084 - No Documentation of User-Controllable External Locations
**Labels:** documentation, security, priority:low
**Description:**
### Summary
Environment variables `AIRFLOW_CONFIG` and `AIRFLOW_HOME` allow operators to redirect configuration loading to arbitrary filesystem locations. While this is standard behavior, the documentation does not enumerate these as operator-controllable paths that affect the application's behavior, nor does it document security implications.

### Details
An attacker with environment variable control can redirect to a malicious config. The documentation does not enumerate these as operator-controllable paths that affect the application's behavior, nor does it document security implications (e.g., an attacker with environment variable control can redirect to a malicious config).

**Affected Files:**
- task-sdk/src/airflow/sdk/configuration.py (lines 96-101)

**ASVS:** 13.1.1 (Level L2, L3)

### Remediation
Document all environment variables that influence external resource locations in a centralized security configuration guide.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 13.1.1.md

### Priority
Low

---

## Issue: FINDING-085 - Configuration File Read Lacks Integrity Verification
**Labels:** bug, security, priority:low
**Description:**
### Summary
Configuration files are read without any integrity verification (signatures, checksums, or file permission checks). The absence of both the documentation AND the control means: a tampered configuration file would be loaded without detection, no file permission validation ensures the config isn't world-writable, and no signature verification ensures the config came from a trusted source.

### Details
If an attacker can modify airflow.cfg (e.g., via a shared filesystem, supply chain attack, or misconfigured permissions), they could redirect secrets backends, change logging levels to expose sensitive data, or modify security-relevant settings.

**Affected Files:**
- task-sdk/src/airflow/sdk/configuration.py (lines 140-146)

**ASVS:** 14.1.2 (Level L2, L3)

### Remediation
Document integrity requirements for configuration files and implement file permission validation to verify config file has restrictive permissions, checking that mode does not allow world-readable or world-writable access. Log warning if config file has insecure permissions and return false. Example implementation provided using stat module to validate permissions are not 'stat.S_IWOTH' or 'stat.S_IROTH'.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 14.1.2.md

### Priority
Low

---

## Issue: FINDING-086 - callsite_parameters Configuration Defaults to Empty List
**Labels:** bug, security, priority:low
**Description:**
### Summary
The callsite parameters (which provide "where" metadata such as module, function, line number) default to an empty list. If not explicitly configured, log entries may lack location metadata needed for investigation.

### Details
Log entries may not include sufficient "where" information for timeline investigations unless the operator explicitly configures this setting.

**Affected Files:**
- task-sdk/src/airflow/sdk/log.py (line 99)

**ASVS:** 16.2.1 (Level L2)

### Remediation
Consider providing a non-empty default that includes at least `module` and `func_name`.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 16.2.1.md

### Priority
Low

---

## Issue: FINDING-087 - No Explicit UTC or Timezone Configuration Visible in Logging Setup
**Labels:** bug, security, priority:low
**Description:**
### Summary
The logging configuration delegates timestamp handling entirely to `structlog_processors()` from the shared library without explicitly enforcing UTC or requiring timezone offset in timestamps. The configuration parameters passed to `configure_logging` from the shared module do not include a timezone specification.

### Details
If the shared `structlog_processors` function does not enforce UTC or timezone offset, logs from distributed systems may have inconsistent timestamps, making timeline correlation impossible during incident investigation, particularly during daylight saving time transitions.

**Affected Files:**
- task-sdk/src/airflow/sdk/log.py (lines 69-116)

**ASVS:** 16.2.2 (Level L2)

### Remediation
Explicitly configure timestamps to use UTC: `structlog.processors.TimeStamper(fmt="iso", utc=True)`

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 16.2.2.md

### Priority
Low

---

## Issue: FINDING-088 - Remote Log Processor Injection via Handler Attribute
**Labels:** bug, security, priority:low
**Description:**
### Summary
The code unconditionally trusts processors provided by the remote log handler object. If the remote handler is loaded from an untrusted or misconfigured source, its processors could modify log events in unexpected ways (e.g., removing security-relevant fields, adding exfiltration channels).

### Details
A compromised or misconfigured remote log handler could inject processors that suppress or redirect security events.

**Affected Files:**
- task-sdk/src/airflow/sdk/log.py (lines 62-63)

**ASVS:** 16.2.3 (Level L2)

### Remediation
Validate that remote processors conform to expected interfaces and do not modify critical log fields.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 16.2.3.md

### Priority
Low

---

## Issue: FINDING-089 - No Log Integrity Verification Mechanism
**Labels:** bug, security, priority:low
**Description:**
### Summary
The logging infrastructure does not implement any log integrity protection such as: append-only file modes, cryptographic hash chains, digital signatures on log entries, or immutable storage flags. While this may be handled at a higher level (e.g., filesystem-level protections or the remote log system), the local file logging path has no tamper-evidence mechanism.

### Details
If an attacker gains access to the log directory, they can silently modify or delete log entries without detection.

**Affected Files:**
- task-sdk/src/airflow/sdk/log.py

**ASVS:** 16.4.2 (Level L2)

### Remediation
Consider adding log file integrity verification, such as a hash chain processor. Example implementation: import hashlib; class LogIntegrityProcessor with __init__ setting _prev_hash = b'\x00' * 32 and __call__ method computing current_hash = hashlib.sha256(self._prev_hash + entry_bytes).digest() and adding event_dict['_integrity_hash'] = current_hash.hex()[:16]. Long-term: implement log integrity verification via hash chains or digital signatures for local log files, consider append-only log file semantics using O_APPEND flags and potentially immutable attributes where the OS supports it.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 16.4.2.md

### Priority
Low

---

## Issue: FINDING-090 - No Explicit Transport Security Verification for Remote Logging
**Labels:** bug, security, priority:low
**Description:**
### Summary
The remote logging handler is loaded dynamically without any verification that it implements secure transport (TLS). The security of log transmission is entirely delegated to the handler implementation and connection configuration, with no enforcement at the SDK level.

### Details
If a remote log handler is configured without TLS (e.g., plain HTTP), logs containing potentially sensitive metadata would be transmitted in cleartext.

**Affected Files:**
- task-sdk/src/airflow/sdk/log.py (lines 151-165)

**ASVS:** 16.4.3 (Level L2)

### Remediation
Add documentation requirements and optional transport security validation. Add verification to handler discovery or connection setup:
```python
# Add to handler discovery or connection setup
if handler and hasattr(handler, 'verify_secure_transport'):
    if not handler.verify_secure_transport():
        log.warning("remote_log_handler_insecure_transport")
```
Validate remote handler transport security during handler loading or provide configuration warnings for insecure setups.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 16.4.3.md

### Priority
Low

---

## Issue: FINDING-091 - Raw IPC Message Bodies Logged on Decode Failure
**Labels:** bug, security, priority:low
**Description:**
### Summary
Raw IPC message bodies are logged when decode failures occur. If the body contains sensitive data from task execution (e.g., XCom values with credentials, variable values from SetXCom, PutVariable, or GetConnection messages), they would appear in supervisor logs.

### Details
While these are supervisor-side logs (not typically user-facing), they may be aggregated in centralized logging systems with broader access.

**Affected Files:**
- task-sdk/src/airflow/sdk/execution_time/supervisor.py (lines 422-424)

**ASVS:** 16.5.1 (Level L2)

### Remediation
Replace logging of the full request body with only metadata such as request_id and body_type. Change log.exception('Unable to decode message', body=request.body) to log.exception('Unable to decode message', request_id=request.id, body_type=type(request.body).__name__).

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 16.5.1.md

### Priority
Low

---

## Issue: FINDING-092 - Full Stack Traces with Potential Secrets Forwarded to Task Logs
**Labels:** bug, security, priority:low
**Description:**
### Summary
Full stack traces written to stderr are captured by the supervisor and forwarded to task logs. Stack frames could contain function parameter values including connection strings, API keys, or tokens that happened to be in-scope at the time of the exception.

### Details
The last-chance exception handler in _fork_main() writes complete tracebacks to last_chance_stderr, which is captured by the supervisor's stderr socket and forwarded to task logs via _create_log_forwarder.

**Affected Files:**
- task-sdk/src/airflow/sdk/execution_time/supervisor.py (lines 268-278)

**ASVS:** 16.5.1 (Level L2)

### Remediation
Apply the secrets masker to stderr output before logging, or limit the stack trace to frame locations without local variable values. Use traceback.format_exception() to print only the traceback structure without local variables, or apply redaction before writing to stderr.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 16.5.1.md

### Priority
Low

---

## Issue: FINDING-093 - Business Logic Limits Defined in Configuration Without Consolidated Documentation
**Labels:** documentation, security, priority:low
**Description:**
### Summary
Business logic limits (heartbeat timeout, max failed heartbeats, overtime threshold, socket cleanup timeout, missing_dag_retries, missing_dag_retry_delay) are scattered across two files without consolidated documentation specifying per-user vs. global enforcement semantics.

### Details
For example, MAX_FAILED_HEARTBEATS applies per-task-instance but there is no documented global limit on concurrent failing tasks. Resource limits mentioned in the domain context (memory, CPU time, API calls) have no visible enforcement or documentation in this code.

**Affected Files:**
- task-sdk/src/airflow/sdk/execution_time/supervisor.py (lines 137-145)

**ASVS:** 2.1.3 (Level L2)

### Remediation
Create a dedicated documentation section or constants file that: 1. Lists all business logic limits with their scope (per-user, per-task, global) 2. Documents the expected range of valid values 3. Specifies the security implications of misconfiguration. Example: Create a limits_documentation.py or add comprehensive documentation at module top listing Per-Task-Instance Limits (HEARTBEAT_TIMEOUT, MAX_FAILED_HEARTBEATS, TASK_OVERTIME_THRESHOLD, missing_dag_retries), Global Limits (MIN_HEARTBEAT_INTERVAL, SOCKET_CLEANUP_TIMEOUT), and limits delegated to API server (Concurrent task execution count, Resource quotas, Maximum retry counts).

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 2.1.3.md

### Priority
Low

---

## Issue: FINDING-094 - No Rate Limiting on IPC Requests From Task Process to Supervisor
**Labels:** bug, security, priority:low
**Description:**
### Summary
A task process (through malicious operator code or runaway logic) can flood the supervisor with IPC requests at maximum throughput. Each request results in an API call to the server (e.g., GetVariable, GetXCom, SetXCom, GetConnection).

### Details
This could: 1) Exhaust API server resources, impacting other tasks and users, 2) Saturate network bandwidth between worker and API server, 3) Cause the supervisor's monitoring loop to starve heartbeats (since request handling is synchronous). While MIN_HEARTBEAT_INTERVAL limits heartbeat frequency, it does not limit the frequency of other operations.

**Affected Files:**
- task-sdk/src/airflow/sdk/execution_time/supervisor.py (handle_requests(), _handle_request())

**ASVS:** 2.4.2 (Level L3)

### Remediation
Implement per-operation-type rate limiting or a global request budget. Example: Add a sliding window rate limiter that tracks request counts per message type with configurable limits (e.g., 1000 requests per 60-second window). Use a _check_rate_limit() method to validate requests before processing and log warnings when limits are exceeded.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 2.4.2.md

### Priority
Low

---

## Issue: FINDING-095 - Missing server URL validation in supervise_callback() compared to supervise_task()
**Labels:** bug, security, priority:low
**Description:**
### Summary
The supervise_callback() function in callback_supervisor.py passes the server parameter directly to _ensure_client() without validating the URL scheme or netloc. This is inconsistent with supervise_task() in supervisor.py which performs URL validation (HTTP/HTTPS scheme, valid netloc).

### Details
If an attacker could control the server parameter, they could redirect API requests to an arbitrary host. However, this is mitigated by the fact that: (1) the server parameter is provided by the executor infrastructure, not user input, (2) the Client class uses TLS verification via certifi.where(), and (3) the authentication token would not be valid for other servers. This represents a Type B gap where the control EXISTS in supervise_task() but is NOT CALLED in supervise_callback().

**Affected Files:**
- task-sdk/src/airflow/sdk/execution_time/callback_supervisor.py (line 244)

**CWE:** CWE-918  
**ASVS:** 1.3.6 (Level L2)

### Remediation
Apply the same server URL validation in supervise_callback() as exists in supervise_task() for defense-in-depth and consistency. Add validation to check that the URL scheme is http or https and that a valid netloc is present before passing to _ensure_client(). Example code: if server: from urllib.parse import urlparse; parsed = urlparse(server); if parsed.scheme not in ('http', 'https'): raise ValueError(f'Invalid server URL scheme: {parsed.scheme}'); if not parsed.netloc: raise ValueError(f'Invalid server URL: missing host')

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 1.3.6.md
- Related: FINDING-074

### Priority
Low

---

## Issue: FINDING-096 - Port value not validated against valid range (0-65535)
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `port` value is converted to an integer but not validated against the valid port range (0-65535). While this cannot cause a memory-level integer overflow in Python, passing an invalid port number (e.g., 99999 or -1) to downstream connection libraries could cause unexpected behavior.

### Details
This is a logical validation gap rather than a memory safety issue. The `port` field in the `Connection` class is typed as `int | None` and comes from trusted Airflow connection configuration (not end-user input), so the practical risk is minimal.

**Affected Files:**
- task-sdk/src/airflow/sdk/definitions/connection.py (line 264)

**ASVS:** 1.4.2 (Level L2)

### Remediation
Consider adding port range validation (0-65535) in `Connection.from_json()` to catch configuration errors early, even though this is not a memory safety issue in Python.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 1.4.2.md

### Priority
Low

---

## Issue: FINDING-097 - Cryptographic Error Message May Reveal Key Format Details
**Labels:** bug, security, priority:low
**Description:**
### Summary
The exception message from Fernet() or MultiFernet() may include details about why key parsing failed (e.g., "Fernet key must be 32 url-safe base64-encoded bytes"), which could help an attacker understand key format requirements during a targeted attack.

### Details
The error requires access to configuration (already implies system compromise), the Fernet key format is publicly documented, and the message only appears during initialization failure.

**Affected Files:**
- task-sdk/src/airflow/sdk/crypto.py (line 115)

**ASVS:** 11.2.5 (Level L3)

### Remediation
Replace with a generic error message that logs the details at debug level:

```python
except (ValueError, TypeError) as value_error:
    log.debug("Fernet key initialization failed", error=str(value_error))
    raise AirflowException("Could not create Fernet object: invalid key configuration")
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 11.2.5.md

### Priority
Low

---

## Issue: FINDING-098 - Incomplete Memory Encryption Protection for Sensitive Data
**Labels:** bug, security, priority:low
**Description:**
### Summary
While PR_SET_DUMPABLE=0 prevents same-UID ptrace/memory access on Linux, it does NOT provide full memory encryption. A root-level attacker or physical memory access (cold boot attack, DMA) can still read secrets. Additionally, this control is Linux-only and is a no-op on macOS and other platforms.

### Details
The supervisor process holds decrypted secrets (Fernet key, connection passwords, variable values) in plaintext in process memory. Per the domain context, this is acknowledged as intentional: the cache exists within the supervisor process boundary which already has access to decrypted secrets. Full memory encryption (Intel SGX, AMD SEV, ARM CCA) is a deployment infrastructure concern, not an application-level control.

**Affected Files:**
- task-sdk/src/airflow/sdk/execution_time/supervisor.py (lines 404-417)

**ASVS:** 11.7.1 (Level L3)

### Remediation
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

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 11.7.1.md

### Priority
Low

---

## Issue: FINDING-099 - Connection credentials persist in memory without TTL-based eviction
**Labels:** bug, security, priority:low
**Description:**
### Summary
Connection credentials (passwords, tokens) fetched from API are stored in module-level dict _REMOTE_LOGGING_CONN_CACHE and persist for the entire supervisor process lifetime without clearing or zeroing. If the supervisor runs multiple tasks sequentially (or in Celery worker mode with multiple tasks), credentials accumulate without eviction, extending the exposure window beyond what is strictly necessary.

### Details
Per domain context, this is intentional as the cache exists within the supervisor process boundary, but a TODO comment acknowledges this needs improvement.

**Affected Files:**
- task-sdk/src/airflow/sdk/execution_time/supervisor.py (line 833)

**ASVS:** 11.7.2, 13.2.2, 14.2.2, 14.2.7 (Level L2, L3)

### Remediation
Implement TTL-based cache eviction to bound the lifetime of credential exposure in memory. Add timestamp tracking to cached entries and evict entries older than a configurable TTL (e.g., 5 minutes). Example: Create a _CachedConn NamedTuple with conn and cached_at fields, check age on retrieval, and delete expired entries.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 11.7.2.md, 13.2.2.md, 14.2.2.md, 14.2.7.md

### Priority
Low

---

## Issue: FINDING-100 - Execution API server URL validation accepts plaintext HTTP without warning
**Labels:** bug, security, priority:low
**Description:**
### Summary
The supervisor explicitly allows unencrypted HTTP connections to the Execution API server without logging warnings. When http:// is used, sensitive data is transmitted in cleartext: Task identity JWT tokens (enabling impersonation), Connection credentials (passwords, API keys), Variable values (potentially containing secrets), XCom data, and Task state transitions.

### Details
If the Execution API server URL is configured with http:// (e.g., [api] execution_api_url = http://airflow-api:8080), all task traffic occurs without encryption, exposing tokens and secrets to network-position attackers.

**Affected Files:**
- task-sdk/src/airflow/sdk/execution_time/supervisor.py (lines 1220-1228)
- task-sdk/tests/task_sdk/execution_time/test_supervisor.py (lines 143-145)

**ASVS:** 12.3.1 (Level L2)

### Remediation
Option 1 - Warning: Add warning log when HTTP is used: if parsed_url.scheme == "http": log.warning("Execution API connection is NOT encrypted. Bearer tokens and secrets will be transmitted in cleartext. Use https:// in production environments.", server=server). Option 2 - Configurable Enforcement: allow_insecure = conf.getboolean("api", "allow_insecure_execution_api", fallback=False); if parsed_url.scheme == "http" and not allow_insecure: raise ValueError(f"Invalid execution API server URL '{server}': URL must use https:// scheme in production. Set [api] allow_insecure_execution_api = True to override (NOT recommended).")

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 12.3.1.md

### Priority
Low

---

## Issue: FINDING-101 - Connection pool limits are hardcoded and behavior at limit is not documented
**Labels:** documentation, security, priority:low
**Description:**
### Summary
Connection pool limits are defined in code but: 1. Limits are hardcoded rather than configurable via Airflow configuration, 2. Behavior when connection limit is reached (httpx blocks/queues requests) is not documented, 3. No fallback or recovery mechanisms are documented, 4. The Client class constructor (used directly in tests) doesn't enforce any limits.

### Details
Without documented connection pool behavior: Operators cannot tune connection limits for their deployment, slow API responses could exhaust all 10 connections blocking heartbeats, no documented fallback mechanism for connection exhaustion scenarios, and risk of denial of service conditions under load.

**Affected Files:**
- task-sdk/src/airflow/sdk/execution_time/supervisor.py (lines 866-867)

**ASVS:** 13.1.2 (Level L3)

### Remediation
Code remediation: Make connection limits configurable via Airflow configuration using conf.getint for execution_api_max_connections (fallback=10) and execution_api_max_keepalive_connections (fallback=1). Documentation remediation: Add Connection Pool Management section to concepts.rst documenting: maximum connections (10 concurrent, configurable), maximum keepalive connections (1, configurable), behavior at limit (requests wait in queue), timeout (subject to execution_api_timeout), and fallback (task terminated after max_failed_heartbeats failures if heartbeat timeouts occur).

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 13.1.2.md

### Priority
Low

---

## Issue: FINDING-102 - Resource management strategies are well-implemented but not formally documented
**Labels:** documentation, security, priority:low
**Description:**
### Summary
The Task SDK implements comprehensive resource management strategies in code with excellent test coverage, but they are embedded in implementation rather than in formal documentation accessible to operators.

### Details
The code contains well-designed strategies for: Timeout settings (API_TIMEOUT, HEARTBEAT_TIMEOUT, SOCKET_CLEANUP_TIMEOUT, TASK_OVERTIME_THRESHOLD), Retry logic (API_RETRIES with exponential backoff, _should_retry_api_request, MAX_FAILED_HEARTBEATS), Resource release procedures (_cleanup_open_sockets, _ensure_client, socket on_close callbacks), and Failure handling (heartbeat failures, API 404/409/410 termination, signal escalation). While the strategies are well-implemented and tested, the lack of formal documentation means operators may not understand resource management behavior, cannot properly plan capacity or tune for their deployment, troubleshooting is more difficult without documented failure modes, and compliance verification requires code analysis rather than documentation review.

**Affected Files:**
- task-sdk/docs/concepts.rst (documentation gap)

**ASVS:** 13.1.3 (Level L3)

### Remediation
Add a comprehensive 'Resource Management Strategies' section to concepts.rst documenting: Connection Management (HTTP(S) via httpx, connection pool with maximum 10 concurrent connections, 1 keepalive connection, queueing behavior at limit), Timeout Settings (API request timeout, heartbeat interval), Retry Logic (heartbeat retries up to max_failed_heartbeats, API retries with exponential backoff, retry conditions for 5xx only, back-off algorithm), Failure Handling (heartbeat failures, process overtime, signal escalation SIGINT→SIGTERM→SIGKILL, API errors), Resource Release (socket cleanup after socket_cleanup_timeout, client cleanup, process cleanup with file descriptors and sockets closed in finally blocks), and IPC Supervisor↔Task Runner details (Unix domain socket, selector timeout, resource release procedures, failure handling).

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 13.1.3.md

### Priority
Low

---

## Issue: FINDING-103 - Connection pool limits not applied by default in Client class
**Labels:** bug, security, priority:low
**Description:**
### Summary
Connection pool limits (max_connections, max_keepalive_connections) are only applied when Client is created through the _ensure_client() helper. If Client is instantiated directly (e.g., by provider packages or future code paths), the httpx defaults (100 max connections, 20 keepalive) apply instead of the documented configuration. This creates inconsistency in resource utilization behavior.

### Details
This creates inconsistency in resource utilization behavior.

**Affected Files:**
- task-sdk/src/airflow/sdk/api/client.py (line 530)

**ASVS:** 13.2.6 (Level L3)

### Remediation
Add default limits matching production configuration in Client.__init__():

```python
class Client(httpx.Client):
    _DEFAULT_LIMITS = httpx.Limits(max_keepalive_connections=1, max_connections=10)
    
    def __init__(self, *, base_url: str | None, dry_run: bool = False, token: str, **kwargs: Any):
        kwargs.setdefault("limits", self._DEFAULT_LIMITS)
        kwargs.setdefault("timeout", API_TIMEOUT)
        # ...
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 13.2.6.md

### Priority
Low

---

## Issue: FINDING-104 - SUPERVISOR_COMMS IPC socket lacks configurable timeout
**Labels:** bug, security, priority:low
**Description:**
### Summary
The SUPERVISOR_COMMS IPC socket communication lacks explicitly documented and configurable timeout and retry parameters. The socket reads (_read_frame()) block indefinitely until data arrives. If the supervisor process dies without cleanly closing the socket (e.g., SIGKILL), the task runner could block indefinitely on a socket read until the OS detects the broken connection.

### Details
This is mitigated by the supervisor's signal escalation logic and the operating system's TCP/socket keepalive, but the behavior is not explicitly configurable or documented.

**Affected Files:**
- task-sdk/src/airflow/sdk/execution_time/task_runner.py

**ASVS:** 13.2.6 (Level L3)

### Remediation
Add configurable socket timeouts:

```python
socket_timeout = conf.getfloat("workers", "supervisor_comms_timeout", fallback=300.0)
self.socket.settimeout(socket_timeout)
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 13.2.6.md

### Priority
Low

---

## Issue: FINDING-105 - SDK version information included in User-Agent header
**Labels:** bug, security, priority:low
**Description:**
### Summary
The Task SDK includes detailed version information (SDK version and Python version) in the User-Agent header when communicating with the Airflow API server. The version information flows from __version__ and sys.version_info to the User-Agent header in API server requests, which could potentially be logged or reflected by the server.

### Details
However, this is internal communication between the SDK and its trusted API server over authenticated TLS connections, not exposure to external users. This is standard HTTP client identification behavior.

**Affected Files:**
- task-sdk/src/airflow/sdk/api/client.py (line 544)

**ASVS:** 13.4.6 (Level L3)

### Remediation
If defense-in-depth is desired, the User-Agent could be made generic by removing version details: headers={'user-agent': 'apache-airflow-task-sdk', 'airflow-api-version': API_VERSION}. However, this is typically considered acceptable for internal service-to-service communication and aids debugging.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 13.4.6.md

### Priority
Low

---

## Issue: FINDING-106 - SecretCache Expired Entries Persist in Memory
**Labels:** bug, security, priority:low
**Description:**
### Summary
The TTL in SecretCache is passive (checked only on read). Expired entries containing passwords/secrets persist in memory until they are next accessed. There is no background eviction mechanism, meaning in scenarios where many different connections are fetched but rarely re-accessed, their credentials remain in shared memory indefinitely.

### Details
The _get() method only checks expiration when a key is accessed, leaving expired entries in the multiprocessing shared dict.

**Affected Files:**
- task-sdk/src/airflow/sdk/execution_time/cache.py (lines 100-130)

**ASVS:** 14.2.2, 13.2.6 (Level L2, L3)

### Remediation
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

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 14.2.2.md, 13.2.6.md

### Priority
Low

---

## Issue: FINDING-107 - Connection passwords stored as plaintext in URI format in shared multiprocessing dict
**Labels:** bug, security, priority:low
**Description:**
### Summary
Connection passwords are stored as plaintext in the URI string within the shared multiprocessing dict. While this is within the supervisor's process boundary (acknowledged in known false positives), the passwords are stored in a cleartext format that would be visible if the process memory were dumped.

### Details
The supervisor process is made non-dumpable on Linux via `_make_process_nondumpable()`, which mitigates this.

**Affected Files:**
- task-sdk/src/airflow/sdk/execution_time/cache.py (line 130)

**ASVS:** 14.2.4 (Level L2)

### Remediation
This is acknowledged as intentional per domain context. The cache exists within the supervisor process boundary which already has access to decrypted secrets. The supervisor process is made non-dumpable on Linux via `_make_process_nondumpable()` which provides mitigation. No immediate action required.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 14.2.4.md

### Priority
Low

---

## Issue: FINDING-108 - Callback kwargs may contain sensitive data logged on exception
**Labels:** bug, security, priority:low
**Description:**
### Summary
If a callback receives sensitive data in its kwargs (e.g., connection credentials in `context` dict) and fails before those secrets are registered with the masker (via `mask_secret()`), the raw values could appear in log output. The `mask_logs` processor only redacts previously registered secrets.

### Details
Severity is LOW because: 1) The `mask_logs` processor provides defense-in-depth for registered secrets, 2) The callback subprocess has limited access (only `GetConnection` and `GetVariable` from supervisor), 3) Per domain false positive guidance, secrets masking using string replacement is intentional as defense-in-depth, 4) Callbacks typically receive context with masked values from prior task execution.

**Affected Files:**
- task-sdk/src/airflow/sdk/execution_time/callback_supervisor.py (line 114)

**ASVS:** 14.2.4 (Level L2)

### Remediation
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

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 14.2.4.md

### Priority
Low

---

## Issue: FINDING-109 - Startup Message Environment Variable Not Cleared After Consumption
**Labels:** bug, security, priority:low
**Description:**
### Summary
The serialized startup message remains in the environment variable _AIRFLOW__STARTUP_MSG for the lifetime of the re-executed process. While the StartupDetails doesn't typically contain raw secrets, it does contain task metadata and context that has no explicit cleanup. The Kerberos cache is explicitly cleared (KRB5CCNAME), but _AIRFLOW__STARTUP_MSG is never cleared after consumption.

### Details
The Kerberos cache is explicitly cleared (KRB5CCNAME), but _AIRFLOW__STARTUP_MSG is never cleared after consumption.

**Affected Files:**
- task-sdk/src/airflow/sdk/execution_time/task_runner.py (line 508)

**ASVS:** 14.2.7 (Level L3)

### Remediation
Clear the environment variable after consumption in the get_startup_details() function by adding os.environ.pop('_AIRFLOW__STARTUP_MSG', None) after reading the value, similar to how KRB5CCNAME is handled.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 14.2.7.md

### Priority
Low

---

## Issue: FINDING-110 - Explicit Exclusion of attrs 25.2.0 Suggests Known Issue Without Documentation
**Labels:** documentation, security, priority:low
**Description:**
### Summary
The exclusion of `attrs==25.2.0` suggests a known issue with this version, but there is no inline comment or documentation explaining whether this is a security issue or a compatibility bug. Without documentation, it's unclear whether this exclusion addresses a security vulnerability or a functional bug. If security-related, this should be tracked in an SBOM/vulnerability record.

### Details
Without documentation, it's unclear whether this exclusion addresses a security vulnerability or a functional bug. If security-related, this should be tracked in an SBOM/vulnerability record.

**Affected Files:**
- task-sdk/pyproject.toml (line 57)

**ASVS:** 15.2.1 (Level L1)

### Remediation
Add a comment explaining the exclusion: `# attrs 25.2.0 excluded due to [reason/CVE/issue link]` followed by the dependency specification.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 15.2.1.md

### Priority
Low

---

## Issue: FINDING-111 - Dry-Run Handler Returns Fake Task Context in Production Code
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `dry_run` parameter in the Client constructor enables a noop_handler that bypasses all API calls and returns fake responses without authentication. If a caller accidentally passes `dry_run=True` to the Client in production, all API interactions are bypassed. However, this requires explicit code changes—not a configuration toggle.

### Details
The `dry_run` mode is only activated programmatically via constructor parameter and is guarded by the XOR check `if (not base_url) ^ dry_run`. It cannot be enabled by misconfiguring a config file. The `unit_test_mode` in configuration.py is similarly a deliberate code path.

**Affected Files:**
- task-sdk/src/airflow/sdk/api/client.py (lines 533-553)

**ASVS:** 15.2.3, 13.4.2 (Level L2)

### Remediation
Consider adding a runtime guard that checks for production environment:

```python
if dry_run and os.environ.get("AIRFLOW_ENV") == "production":
    raise RuntimeError("dry_run mode is not permitted in production environments")
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 15.2.3.md, 13.4.2.md

### Priority
Low

---

## Issue: FINDING-112 - DAG.test() Method and Development Utilities in Production Class
**Labels:** bug, security, priority:low
**Description:**
### Summary
The DAG.test() method and its helper _run_task() are development/testing utilities included in the production DAG class. The _run_task function is explicitly documented as only meant for the dag.test function. DAG.test() imports unittest.mock.patch, performs direct database operations bypassing normal security controls, runs tasks without proper subprocess isolation, and manipulates environment variables directly.

### Details
While dag.test() is a documented DAG author utility and not an attack surface in production deployments, its inclusion in the production library means the production package carries unnecessary test/development code and imports, and if accidentally invoked in production it bypasses the normal supervisor isolation model.

**Affected Files:**
- task-sdk/src/airflow/sdk/definitions/dag.py (lines 594-806, 808-890)

**ASVS:** 15.2.3 (Level L2)

### Remediation
Consider moving dag.test() to a separate development-only module that isn't loaded in worker contexts, or add a runtime guard that prevents dag.test() from executing in production worker processes by checking for AIRFLOW__CORE__EXECUTOR environment variable and raising a RuntimeError if AIRFLOW_TEST_MODE is not set.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 15.2.3.md

### Priority
Low

---

## Issue: FINDING-113 - No Hash Verification for Build Dependencies
**Labels:** bug, security, priority:low
**Description:**
### Summary
While build dependencies are version-pinned (good), they lack hash verification. An attacker who compromises PyPI could substitute a malicious package at the same version. Build-time supply chain attack could inject malicious code during package builds.

### Details
Build-time supply chain attack could inject malicious code during package builds.

**Affected Files:**
- task-sdk/pyproject.toml (lines 100-108)

**ASVS:** 15.2.4 (Level L3)

### Remediation
Use hash-pinned requirements for build dependencies or enable hash checking in the build tool configuration.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 15.2.4.md

### Priority
Low

---

## Issue: FINDING-114 - Hostname Used for Logging Without Validation
**Labels:** bug, security, priority:low
**Description:**
### Summary
The hostname obtained via `get_hostname()` is sent to the API server in heartbeats and task start messages (`TIEnterRunningPayload`). This value is used for logging and identification but could be manipulated by setting `hostname_callable` in configuration to return arbitrary values. This affects logging accuracy only. The hostname is not used for security decisions within the SDK itself.

### Details
This affects logging accuracy only. The hostname is not used for security decisions within the SDK itself.

**Affected Files:**
- task-sdk/src/airflow/sdk/api/client.py (lines 100-117)
- task-sdk/src/airflow/sdk/execution_time/task_runner.py (_prepare())

**ASVS:** 15.3.4 (Level L2)

### Remediation
This is informational. The API server should validate hostnames if used for security decisions.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 15.3.4.md

### Priority
Low

---

## Issue: FINDING-115 - No per-message digital signatures for sensitive task state transitions
**Labels:** bug, security, priority:low
**Description:**
### Summary
The Task SDK communicates highly sensitive operations to the Execution API server (task state changes, XCom data containing credentials, connection retrieval) without per-message digital signatures. While transport-level TLS is enforced and JWT tokens authenticate the caller, there is no cryptographic binding between the message content and the authenticated identity that would detect message tampering at application-level intermediaries.

### Details
In environments with TLS-terminating proxies, load balancers, or service meshes that inspect/modify HTTP bodies, message integrity cannot be cryptographically verified end-to-end. This is a Level 3 requirement and the risk is mitigated by TLS and the deployment model. The IPC layer (supervisor ↔ task runner) does not require per-message signatures because communication occurs over a Unix socketpair created by the parent process, messages do not traverse any network boundary or intermediate system, and the Unix kernel enforces socket isolation.

**Affected Files:**
- task-sdk/src/airflow/sdk/api/client.py (line 475)
- task-sdk/src/airflow/sdk/execution_time/supervisor.py (N/A)

**ASVS:** 4.1.5 (Level L3)

### Remediation
For environments requiring ASVS Level 3 compliance, consider adding HMAC-SHA256 signatures to sensitive API requests (task state transitions, XCom writes) using a shared secret or asymmetric signing. Example implementation: import hashlib, hmac, and time; create a sign_request function that generates a timestamp, constructs a message from method/path/timestamp/body, computes HMAC-SHA256 signature, and adds X-Airflow-Signature and X-Airflow-Timestamp headers to the request.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 4.1.5.md

### Priority
Low

---

## Issue: FINDING-116 - Client does not explicitly clear token from memory after task completion
**Labels:** bug, security, priority:low
**Description:**
### Summary
After task execution completes and the subprocess exits, the token remains in the supervisor's memory until the Client object is garbage collected. Token assigned at Client init → stored in BearerAuth.token → remains in memory until GC. For the normal subprocess flow, this is mitigated because the subprocess exits (clearing its memory). For InProcessTestSupervisor (testing only), tokens may persist longer than necessary.

### Details
This is LOW severity because: 1) The subprocess architecture means the task runner process exits, clearing all memory; 2) The supervisor process already holds the token (it's within its trust boundary); 3) Token expiration on the server side limits the window of exposure; 4) This pattern is explicitly called out in the false positive patterns regarding hardcoded token passing in IPC messages.

**Affected Files:**
- task-sdk/src/airflow/sdk/api/client.py (N/A)

**ASVS:** 7.4.1 (Level L1)

### Remediation
For defense-in-depth, the supervisor could explicitly clear the token reference after task completion: def _cleanup_after_task(self): if hasattr(self, '_client') and self._client: self._client.auth = BearerAuth("")

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 7.4.1.md

### Priority
Low

---

## Issue: FINDING-117 - Authorization boundaries between SDK operations rely entirely on server-side enforcement without SDK-level documentation of expected access control rules
**Labels:** documentation, security, priority:low
**Description:**
### Summary
The Client class exposes operations across multiple resource types (TaskInstances, Connections, Variables, XComs, Assets, DagRuns, HITLDetails) with no SDK-level documentation of which operations a given token is authorized to perform. While the server is expected to enforce authorization, the SDK code does not document or validate authorization expectations.

### Details
Without documented authorization boundaries, developers and auditors cannot verify whether the Execution API properly restricts: A task's ability to access connections it doesn't need, Cross-DAG variable access, XCom access across task boundaries, Unauthorized DAG triggering.

**Affected Files:**
- task-sdk/src/airflow/sdk/api/client.py (lines 180-550)

**ASVS:** 8.1.1 (Level L1)

### Remediation
Add authorization documentation (e.g., in a SECURITY.md or architecture decision record) that specifies: Token scope: what resources a task-specific token can access, Data isolation: whether tasks can access cross-DAG resources, Operation restrictions: which operations are allowed per token type. Example: Task Execution Tokens - Scoped to a single task instance (dag_id, task_id, run_id, try_number), Can read: own connections, own variables, own XComs, upstream XComs in same DAG, Can write: own XComs, own task state, Cannot: access other DAGs' resources, modify connections, modify other tasks' state. Add docstrings documenting authorization requirements for each operation.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 8.1.1.md

### Priority
Low

---

## Issue: FINDING-118 - No documentation of field-level access restrictions for connection credentials and sensitive data
**Labels:** documentation, security, priority:low
**Description:**
### Summary
The Connection class exposes all fields (including password, extra) without documenting field-level access restrictions. When connections are retrieved via the API, there's no SDK-level documentation specifying whether: Read access to password field requires elevated permissions, Write access to connection fields is restricted by role, or Field visibility changes based on connection state or type.

### Details
Without field-level access documentation, it's unclear whether the Execution API returns full connection details (including passwords) to all tasks, or whether field-level filtering is applied based on the requesting task's authorization level.

**Affected Files:**
- task-sdk/src/airflow/sdk/definitions/connection.py (lines 1-300)

**ASVS:** 8.1.2 (Level L2)

### Remediation
Document field-level access rules, particularly for sensitive fields like password and extra. Create a markdown table documenting: Field name, Read Access permissions, Write Access permissions, and Notes. Example: conn_id (Read: All tasks, Write: Admin only), password (Read: Tasks with conn_id access, Write: Admin only, encrypted at rest), extra (Read: Tasks with conn_id access, Write: Admin only, may contain secrets).

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 8.1.2.md

### Priority
Low

---

## Issue: FINDING-119 - Environmental and contextual attributes used in security decisions are not documented
**Labels:** documentation, security, priority:low
**Description:**
### Summary
The Task SDK collects and transmits environmental attributes (hostname, username, PID, start_date) as part of the TIEnterRunningPayload, but there is no documentation of how these attributes are used by the server to make security decisions.

### Details
The start method transmits hostname via get_hostname(), username via getuser(), and start_date as contextual time attribute. Additionally, heartbeat transmits hostname and PID. Without documentation, it's unclear whether the server validates that hostname matches expected worker, PID is used to prevent duplicate execution, time attributes are used for timeout enforcement, or IP address/network location is considered in authorization decisions.

**Affected Files:**
- task-sdk/src/airflow/sdk/api/client.py (lines 183-195)

**ASVS:** 8.1.3 (Level L3)

### Remediation
Document all environmental/contextual attributes and their security role in a table format showing: Attribute (hostname, unixname, pid, start_date, IP address), Source (get_hostname(), getuser(), Process ID, System clock, server extracts from request), Used For (Task identification, Audit trail, Heartbeat validation, SLA enforcement, Network policy), and Security Role (Validates task is running on expected worker, Identifies OS user executing task, Prevents zombie processes and conflict detection, Detects stale tasks, Rate limiting and geo-restriction).

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 8.1.3.md

### Priority
Low

---

## Issue: FINDING-120 - Connection cache lacks explicit eviction/TTL mechanism for authorization-relevant data
**Labels:** bug, security, priority:low
**Description:**
### Summary
If a connection's credentials are revoked or rotated at the API server level, cached connection URIs in SecretCache may continue to be served to tasks until the cache entry is evicted or the process terminates. API server revokes/changes connection → SecretCache still holds stale URI → Task uses revoked connection. In practice, since each task runner process handles a single task and exits, the window is limited to the task's execution duration.

### Details
In practice, since each task runner process handles a single task and exits, the window is limited to the task's execution duration.

**Affected Files:**
- task-sdk/src/airflow/sdk/execution_time/context.py (lines 134-155)

**ASVS:** 8.3.2 (Level L3)

### Remediation
Verify that SecretCache in the dag processor context (where processes are long-lived) implements TTL-based eviction. For task runner contexts, the current design is acceptable as processes exit after task completion. Long-term: If the SecretCache is used in long-lived processes (dag processor), ensure TTL-based eviction is implemented to prevent serving stale authorization data after credential rotation.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 8.3.2.md

### Priority
Low

## Issue: FINDING-121 - Supervisor uses single task-scoped token for all API calls — positive pattern with architectural note

**Labels:** security, priority:low, defense-in-depth

**Description:**

### Summary
The supervisor does not validate that `msg.dag_id` or `msg.task_id` match the current task's identity (`self.ti.dag_id`, `self.id`). It relies entirely on the API server to enforce scope restrictions based on the token. While this is architecturally correct (the API server is the authorization authority), the SDK provides no defense-in-depth against a compromised task process requesting data outside its intended scope.

### Details
- **Location:** `task-sdk/src/airflow/sdk/execution_time/supervisor.py:529`
- **ASVS:** 8.3.3 (Level 3)
- **CWE:** N/A

If the API server's token validation has gaps (e.g., cross-DAG XCom access is permitted by design for legitimate use cases like `xcom_pull(dag_id="other_dag")`), the Task SDK provides no additional guardrails. A compromised task process could potentially request data outside its intended scope without any SDK-level validation.

**Current architecture:**
- Task SDK forwards all requests with task-scoped token
- API server is sole enforcement point for authorization
- No client-side validation of request scope

### Remediation
N/A for Task SDK — server-side token validation should enforce tenant/DAG boundaries as appropriate. 

**Optional long-term enhancement:** Consider adding optional configuration to validate that task requests are within their declared scope (e.g., reject GetXCom requests for DAGs not in an allowlist). This would provide defense-in-depth but should remain optional to support legitimate cross-DAG patterns.

### Acceptance Criteria
- [ ] Evaluate whether optional SDK-level scope validation would add value without breaking legitimate cross-DAG patterns
- [ ] Document current security boundaries in architecture documentation
- [ ] Ensure API server token validation properly enforces all necessary scope restrictions
- [ ] Consider adding configuration option for strict scope validation in high-security deployments

### References
- Source: ASVS 8.3.3 analysis
- Related: FINDING-122 (tenant boundary enforcement)

### Priority
**Low** - Current architecture is sound; this is an optional defense-in-depth enhancement. API server is the appropriate authorization boundary.

---

## Issue: FINDING-122 - No client-side tenant boundary enforcement in request forwarding

**Labels:** security, priority:low, multi-tenancy, defense-in-depth

**Description:**

### Summary
The supervisor forwards `TriggerDagRun` requests and secret/connection requests with any `dag_id` specified by the task process to the API server without client-side validation of tenant boundaries. In multi-tenant deployments, the Task SDK provides no defense-in-depth mechanism to detect or prevent cross-tenant data access at the SDK layer.

### Details
- **Locations:** 
  - `task-sdk/src/airflow/sdk/execution_time/supervisor.py:529`
  - `task-sdk/src/airflow/sdk/execution_time/secrets/execution_api.py:42-65`
- **ASVS:** 8.4.1 (Level 2)
- **CWE:** N/A

**Data Flow:**
```
Task code → TriggerDagRunOperator → SUPERVISOR_COMMS.send(TriggerDagRun(dag_id="other_tenant_dag")) 
→ Supervisor → API Server (must enforce tenant boundary)
```

**Risk:** In multi-tenant deployments, if the API server's token validation does not properly enforce tenant boundaries, a task from one tenant could:
- Trigger DAG runs in another tenant's namespace
- Access cross-tenant connections/variables/XComs
- Read or modify data outside their tenant scope

The Task SDK provides no defense-in-depth layer to prevent this.

### Remediation
This is primarily a server-side concern. For defense-in-depth at the SDK level:

1. **Audit logging:** If `msg.dag_id != self.ti.dag_id`, log cross-DAG trigger requested with `source_dag` and `target_dag`
2. **Optional validation:** Add optional SDK-level assertion that validates returned resources match the expected tenant context (e.g., a tenant identifier in `StartupDetails` that can be cross-checked against API responses)
3. **Allowlist support:** Add optional validation that cross-DAG operations target allowed DAG IDs, informed by startup metadata about the task's tenant scope

This would provide defense-in-depth without breaking the current architecture or legitimate cross-DAG patterns.

### Acceptance Criteria
- [ ] Add audit logging for cross-DAG/cross-tenant operations
- [ ] Implement optional tenant context validation (configurable)
- [ ] Ensure API server properly enforces tenant boundaries in token validation
- [ ] Document multi-tenancy security model and boundaries
- [ ] Add configuration guide for strict tenant isolation in multi-tenant deployments
- [ ] Test cross-tenant access prevention at API server level

### References
- Source: ASVS 8.4.1 analysis
- Related: FINDING-121 (task scope validation)
- Multi-tenant deployment security documentation needed

### Priority
**Low** - Current architecture delegates authorization to API server (correct design). This enhancement would add defense-in-depth for multi-tenant deployments but is not required for single-tenant or properly configured systems.