# Security Issues

## Issue: FINDING-001 - Variable.set() Does Not Mask Sensitive Value Before Logging Exception

**Labels:** bug, security, priority:medium

**Description:**

### Summary
The `Variable.set()` method fails to apply masking to sensitive values before potential exception logging. When exceptions occur during variable set operations (e.g., network errors), the `AirflowRuntimeError` may expose raw variable values in logs, creating a defense-in-depth gap despite existing masking infrastructure in the codebase.

### Details
- **CWE:** CWE-532 (Insertion of Sensitive Information into Log File)
- **ASVS:** 15.3.1 (Level 1)
- **Affected File:** `task-sdk/src/airflow/sdk/definitions/variable.py`
- **Severity:** Medium

The Variable.set() method does not apply masking to sensitive values before potential exception logging. When an exception occurs during the set operation (e.g., network error), the AirflowRuntimeError may expose the raw variable value in logs. While exploitation requires an exception condition and DAG authors are considered trusted users per the project's threat model, this represents a defense-in-depth gap since the codebase has existing masking infrastructure that is applied inconsistently across variable operations.

### Remediation
Add `mask_secret(value, name=key)` to `Variable.set()` before the try block to ensure consistent masking across all variable operations. This will prevent sensitive values from appearing in exception messages and logs.

Example implementation:
```python
def set(key: str, value: str, ...):
    mask_secret(value, name=key)  # Add this line
    try:
        # existing code
    except Exception as e:
        # exception handling
```

### Acceptance Criteria
- [ ] Fixed: `mask_secret()` called in `Variable.set()` before the try block
- [ ] Test added: Unit test verifying sensitive values are masked in exception scenarios
- [ ] Test added: Integration test confirming masking works during network failures
- [ ] Code review completed confirming consistent masking pattern across all variable operations

### References
- Source Report: 15.3.1.md
- Related CWE: https://cwe.mitre.org/data/definitions/532.html
- ASVS 15.3.1: Application Logging and Monitoring

### Priority
**Medium** - While exploitation requires specific exception conditions and DAG authors are trusted users, this represents an inconsistency in the defense-in-depth strategy that should be addressed to maintain security posture across all code paths.

---

## Issue: FINDING-002 - Inconsistent Server URL Validation Between supervise_task and supervise_callback

**Labels:** bug, security, priority:low

**Description:**

### Summary
The `supervise_callback` function does not validate server URLs (scheme, netloc) before passing them to `_ensure_client`, unlike `supervise_task` which performs explicit validation. This inconsistency in defensive programming between parallel entry points creates potential security gaps.

### Details
- **CWE:** CWE-20 (Improper Input Validation)
- **ASVS:** 2.2.1 (Level 1)
- **Affected Files:** 
  - `task-sdk/src/airflow/sdk/execution_time/callback_supervisor.py`
  - `task-sdk/src/airflow/sdk/execution_time/supervisor.py`
- **Severity:** Low

The `supervise_callback` function does not validate the server URL (scheme, netloc) before passing it to `_ensure_client`, unlike `supervise_task` which performs explicit validation. While the server parameter originates from trusted infrastructure configuration, this represents an inconsistency in defensive programming between two parallel entry points.

### Remediation
Extract URL validation logic from `supervise_task` into a shared utility function and apply it in `supervise_callback` for consistency and defense-in-depth.

Suggested approach:
1. Create a shared validation function (e.g., `validate_server_url()`)
2. Extract existing validation logic from `supervise_task`
3. Apply the same validation in `supervise_callback`
4. Ensure consistent error handling and messaging

### Acceptance Criteria
- [ ] Fixed: Shared URL validation utility function created
- [ ] Fixed: Validation applied consistently in both `supervise_task` and `supervise_callback`
- [ ] Test added: Unit tests for the shared validation utility
- [ ] Test added: Tests confirming both entry points reject invalid URLs
- [ ] Test added: Tests confirming valid URLs are accepted by both entry points
- [ ] Documentation updated to describe URL validation requirements

### References
- Source Report: 2.2.1.md
- Related CWE: https://cwe.mitre.org/data/definitions/20.html
- ASVS 2.2.1: General Authenticator Security

### Priority
**Low** - Server parameters originate from trusted infrastructure configuration, but fixing this improves code consistency and defense-in-depth posture with minimal effort.

---

## Issue: FINDING-003 - Connection URI Representation Embeds Credentials in Query-String-Like Format Suitable for Logging/Caching

**Labels:** bug, security, priority:low

**Description:**

### Summary
The `Connection.get_uri()` method generates URI strings with passwords and extras in query-string format, increasing the risk of accidental credential exposure through logging, caching, or tracing mechanisms that may not properly redact these fields.

### Details
- **CWE:** CWE-598 (Use of GET Request Method With Sensitive Query Strings)
- **ASVS:** 14.2.1 (Level 1)
- **Affected File:** `task-sdk/src/airflow/sdk/definitions/connection.py`
- **Severity:** Low

The `Connection.get_uri()` method generates URI strings with passwords and extras in query-string format. While this is an internal connection-string representation transmitted via IPC (not HTTP URLs) and `mask_secret()` is applied on access, the risk exists for accidental logging of the internal format in its unmasked state. The query-string-like structure increases the likelihood of credentials being inadvertently exposed through logging, caching, or tracing mechanisms that may not properly redact these fields.

### Remediation
Consider one or more of the following approaches:

1. **Separate sensitive fields from URI representation** for caching purposes
2. **Implement a dedicated internal format** that does not resemble URL query strings to reduce risk of accidental exposure through systems that assume standard URL patterns
3. **Ensure all logging/tracing automatically redacts URI credentials** by registering connection URIs with the masking system
4. **Add explicit warnings** in documentation about the sensitive nature of connection URIs

### Acceptance Criteria
- [ ] Fixed: Sensitive fields separated from cacheable URI representation OR alternative internal format implemented
- [ ] Fixed: All connection URI instances automatically registered with masking system
- [ ] Test added: Unit tests verifying credentials are not exposed in logs
- [ ] Test added: Integration tests with various logging/tracing scenarios
- [ ] Documentation updated: Clear warnings about connection URI sensitivity
- [ ] Code review: Audit all code paths that handle connection URIs for potential exposure

### References
- Source Report: 14.2.1.md
- Related CWE: https://cwe.mitre.org/data/definitions/598.html
- ASVS 14.2.1: Configuration

### Priority
**Low** - `mask_secret()` is already applied on access and this is an internal IPC format, but the query-string-like structure creates unnecessary risk. This is a defense-in-depth improvement that reduces the attack surface for credential exposure.