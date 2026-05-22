# Security Issues

*13 actionable finding(s). 7 informational finding(s) from the consolidated report are not opened as issues — see consolidated.md for those.*

---
## Issue: FINDING-001 - Silent Exception Suppression in Cross-Process Secret Registration May Leave Supervisor Logs Unmasked
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `mask_secret()` function silently suppresses all exceptions when communicating with the supervisor process, potentially leaving secrets unmasked in supervisor-level logs without any visibility into the failure.

### Details
In `task-sdk/src/airflow/sdk/log.py`, the secret masking implementation uses a blanket `suppress(Exception)` context manager when registering secrets with the supervisor. When `sending_to_supervisor=True`, the local task process delegates masking responsibility entirely to the supervisor by skipping the `mask_logs` processor. If supervisor communication fails silently, the supervisor never receives the secret registration, resulting in unmasked sensitive data in supervisor-level logs without any indication that registration failed.

**CWE:** CWE-532  
**ASVS:** 16.2.5 (L2, L3)

### Remediation
Replace the blanket `suppress(Exception)` with targeted exception handling that logs a warning when the supervisor IS available but communication fails. This ensures that failures in secret registration are visible and can be investigated, preventing scenarios where secrets remain unmasked in supervisor logs due to silent communication failures.

### Acceptance Criteria
- [ ] Replace `suppress(Exception)` with specific exception handling
- [ ] Add warning log when supervisor communication fails
- [ ] Test added for supervisor communication failure scenario
- [ ] Verify secrets are still masked locally when supervisor registration fails

### References
- Source: 16.2.5.md
- Related: ASVS-1625-LOW-001

### Priority
Low - Requires both supervisor communication failure AND secret exposure to logs

---
## Issue: FINDING-002 - General Log Entries Do Not Enforce Identity ("Who") Context at Framework Level
**Labels:** bug, security, priority:low
**Description:**
### Summary
The logging processor pipeline does not automatically inject task identity context (task_id, dag_id, run_id) into every log entry, relying instead on manual context binding by callers.

### Details
In `task-sdk/src/airflow/sdk/log.py`, the logging configuration in `logging_processors()` and `configure_logging()` does not include an automatic processor that injects task identity into every log entry. While Sentry integration explicitly adds `task_id`, `dag_id`, and `try_number` as tags, the general structlog pipeline requires callers to manually bind identity context. The `callsite_parameters` config defaults to an empty list (`fallback=[]`), making "where" metadata (file, function, line number) opt-in rather than default.

**ASVS:** 16.2.1 (L2)

### Remediation
Add a structlog processor that automatically injects available task execution context (task_id, dag_id, run_id) when available. This ensures consistent identity attribution across all log entries without requiring manual binding.

### Acceptance Criteria
- [ ] Add automatic task context injection processor
- [ ] Test that task identity appears in all log entries during task execution
- [ ] Verify processor handles cases where task context is not available
- [ ] Documentation updated to describe automatic context injection

### References
- Source: 16.2.1.md
- Related: ASVS-1621-LOW-001

### Priority
Low - Impacts log forensics and audit trail quality

---
## Issue: FINDING-003 - No Explicit UTC Enforcement in Timestamp Configuration
**Labels:** bug, security, priority:low
**Description:**
### Summary
The logging configuration does not explicitly enforce UTC timestamps or validate that configured log formats include timezone information.

### Details
In `task-sdk/src/airflow/sdk/log.py`, timestamp handling is delegated entirely to the shared module (`structlog_processors` from `airflow.sdk._shared.logging.structlog`). Neither `logging_processors()` nor `configure_logging()` explicitly enforces UTC timestamps or includes timezone offset configuration. The `log_format` parameter is user-configurable without validation that the format includes timezone information.

**ASVS:** 16.2.2 (L2)

### Remediation
Verify that `airflow.sdk._shared.logging.structlog.structlog_processors()` includes a `TimeStamper(utc=True)` processor, or add explicit UTC enforcement in the Task SDK logging configuration. Add validation that rejects log format configurations lacking timezone information.

### Acceptance Criteria
- [ ] Verify UTC timestamp enforcement in shared logging module
- [ ] Add explicit UTC configuration if not present in shared module
- [ ] Add validation for timezone information in log_format parameter
- [ ] Test that all timestamps are in UTC with timezone offset
- [ ] Documentation updated with timestamp format requirements

### References
- Source: 16.2.2.md
- Related: ASVS-1622-LOW-001

### Priority
Low - Impacts log correlation across distributed systems

---
## Issue: FINDING-004 - No Explicit Authorization Failure Logging in Task SDK Logging Infrastructure
**Labels:** bug, security, priority:low
**Description:**
### Summary
The Task SDK logging infrastructure does not include dedicated mechanisms for logging authorization failures, making it difficult to detect and investigate access control violations.

### Details
In `task-sdk/src/airflow/sdk/log.py` and `task-sdk/src/airflow/sdk/execution_time/sentry/configured.py`, the logging infrastructure lacks any processor or mechanism specifically designed to identify and tag authorization failures. While `ConfiguredSentry.enrich_errors` captures all exceptions, it does not differentiate or explicitly tag authorization-related failures (e.g., HTTP 401/403 responses from the Execution API).

**ASVS:** 16.3.2 (L2, L3)

### Remediation
Add a structlog processor or dedicated logging call that identifies and tags authorization-related errors (HTTP 401/403 responses from the Execution API) as security events. Ensure these events are logged with sufficient context to enable security monitoring and incident response.

### Acceptance Criteria
- [ ] Add processor/handler for authorization failure detection
- [ ] Tag HTTP 401/403 responses as security events
- [ ] Include relevant context (endpoint, task_id, timestamp) in auth failure logs
- [ ] Test authorization failure logging for various failure scenarios
- [ ] Documentation updated with security event logging details

### References
- Source: 16.3.2.md
- Related: ASVS-1632-LOW-001

### Priority
Low - Impacts security monitoring and incident response capabilities

---
## Issue: FINDING-005 - Missing Exception Handling in _load_logging_config() Causes Uncontrolled Propagation When Remote Logging Discovery Fails
**Labels:** bug, security, priority:low
**Description:**
### Summary
Exceptions during remote logging configuration can propagate to the task lifecycle handler, potentially disrupting task state transitions.

### Details
In `task-sdk/src/airflow/sdk/log.py`, the `upload_to_remote()` function correctly handles cases where the handler is `None` and wraps `handler.upload()` in try/except. However, if `load_remote_log_handler()` itself raises an exception (rather than returning None), the exception propagates to the task lifecycle handler, potentially disrupting task state transitions. The `discover_remote_log_handler()` call in `_load_logging_config()` lacks exception handling.

**ASVS:** 16.5.2 (L2)

### Remediation
Add try/except around `discover_remote_log_handler()` in `_load_logging_config()` to ensure remote logging configuration failures don't prevent the logging system from initializing. Log failures as warnings and continue with local-only logging.

### Acceptance Criteria
- [ ] Add exception handling around remote log handler discovery
- [ ] Log configuration failures as warnings
- [ ] Verify logging system initializes successfully even when remote logging fails
- [ ] Test task execution continues normally when remote logging is unavailable
- [ ] Documentation updated with remote logging failure behavior

### References
- Source: 16.5.2.md
- Related: ASVS-1652-LOW-001, LOGGING-5

### Priority
Low - Remote logging is supplementary; local logging remains functional

---
## Issue: FINDING-006 - No Top-Level Exception Guard Around Sentry Instrumentation in Task Execution Wrapper
**Labels:** bug, security, priority:low
**Description:**
### Summary
Failures in Sentry instrumentation can prevent task execution from running, making non-critical monitoring failures indistinguishable from actual task failures.

### Details
In `task-sdk/src/airflow/sdk/execution_time/sentry/configured.py`, the `enrich_errors()` function wraps task execution with Sentry instrumentation. If `add_tagging` or `add_breadcrumbs` raises an exception, the task's `run()` function never executes and the exception propagates as if the task itself failed. This makes failures in non-critical Sentry instrumentation indistinguishable from actual task execution failures.

**ASVS:** 16.5.4 (L3)

### Remediation
Separate Sentry instrumentation from task execution so that tagging/breadcrumb failures cannot prevent the task `run()` from executing. Wrap instrumentation calls in their own try/except blocks and log instrumentation failures without impacting task execution.

### Acceptance Criteria
- [ ] Wrap Sentry instrumentation calls in try/except blocks
- [ ] Ensure task execution proceeds even if Sentry instrumentation fails
- [ ] Log Sentry instrumentation failures separately from task failures
- [ ] Test that task execution continues when Sentry tagging/breadcrumbs fail
- [ ] Documentation updated with Sentry instrumentation failure handling

### References
- Source: 16.5.4.md
- Related: ASVS-1654-LOW-001

### Priority
Low - Affects observability but not core task execution

---
## Issue: FINDING-007 - No explicit enforcement that base URL uses HTTPS scheme before transmitting bearer token
**Labels:** bug, security, priority:low
**Description:**
### Summary
The Execution API client accepts HTTP URLs without validation, potentially transmitting bearer tokens and sensitive data over unencrypted connections.

### Details
In `task-sdk/src/airflow/sdk/api/client.py` (lines 568-579), the `base_url` parameter is accepted without scheme validation. If it contains `http://`, the SSL context set via `verify` is silently ignored by httpx for non-TLS connections. This creates a configuration vulnerability where misconfiguration (setting `base_url` to `http://` instead of `https://`) would result in JWT authentication tokens, Airflow connection credentials, variables, and XCom data being transmitted in plaintext.

An attacker with network-level access between worker and API server could capture bearer tokens and impersonate task instances if HTTP is used.

**ASVS:** 12.1.1, 12.3.1 (L1, L2)

### Remediation
Add URL scheme validation at client initialization to reject non-HTTPS base URLs:

```python
if not base_url.startswith("https://"):
    raise ValueError(
        f"Execution API base_url must use HTTPS scheme for secure communication, got: {base_url!r}"
    )
```

### Acceptance Criteria
- [ ] Add HTTPS scheme validation in `Client.__init__`
- [ ] Raise `ValueError` with clear message for non-HTTPS URLs
- [ ] Test that HTTP URLs are rejected during client initialization
- [ ] Test that HTTPS URLs are accepted normally
- [ ] Documentation updated with HTTPS requirement

### References
- Source: 12.1.1.md, 12.3.1.md
- Related: ASVS-1211-LOW-001, TLS-3

### Priority
Low - Requires misconfiguration to exploit, but high impact if exploited

---
## Issue: FINDING-008 - Mutual TLS (mTLS) Client Authentication is Optional, Not Enforced by Default
**Labels:** bug, security, priority:low
**Description:**
### Summary
The client supports mutual TLS (mTLS) client authentication but does not enforce it by default, relying solely on JWT bearer tokens for authentication.

### Details
In `task-sdk/src/airflow/sdk/api/client.py` (lines 560-564), the client supports mTLS through configuration but does not enforce it by default. Without explicit configuration, no client certificate is presented during TLS handshake. This means authentication relies solely on JWT bearer tokens, and if a token is leaked (e.g., from process memory, logs, or network capture), it can be used from any client that can reach the API server without requiring a valid client certificate.

**ASVS:** 12.3.5 (L3)

### Remediation
Consider adding a configuration option to mandate mTLS and fail if client certificates are not configured:

```python
API_REQUIRE_MTLS = conf.getboolean("api", "require_client_cert", fallback=False)

# In Client.__init__:
if API_REQUIRE_MTLS and not (API_CLIENT_SSL_CERT and API_CLIENT_SSL_KEY):
    raise ValueError(
        "api.require_client_cert is True but client_ssl_cert and client_ssl_key "
        "are not configured. mTLS is required for intra-service communication."
    )
```

For microservice/Kubernetes deployments, document service mesh integration (e.g., Istio) as an alternative path to mTLS.

### Acceptance Criteria
- [ ] Add configuration option for mandatory mTLS
- [ ] Implement validation that fails when mTLS is required but not configured
- [ ] Test mTLS enforcement with and without certificates configured
- [ ] Document mTLS configuration requirements
- [ ] Document service mesh integration as alternative

### References
- Source: 12.3.5.md
- Related: ASVS-1235-LOW-001

### Priority
Low - Applies to L3 (highest security) deployments

---
## Issue: FINDING-009 - Algorithm selection is hardcoded to Fernet with no configuration-driven mechanism to swap cipher suites
**Labels:** bug, security, priority:low
**Description:**
### Summary
The crypto module is tightly coupled to Fernet (AES-128-CBC + HMAC-SHA256) with no configuration-driven mechanism to select alternative authenticated encryption schemes.

### Details
In `task-sdk/src/airflow/sdk/crypto.py`, the encryption implementation is hardcoded to use Fernet. While key rotation IS supported via MultiFernet, algorithm migration requires code changes. This creates inflexibility when cryptographic requirements change or when stronger algorithms become necessary.

**CWE:** CWE-327  
**ASVS:** 11.2.2 (L2)

### Remediation
Introduce a configuration-driven encryption backend selector and abstract the protocol to be algorithm-agnostic. This enables algorithm migration without code changes and supports future cryptographic requirements.

### Acceptance Criteria
- [ ] Design and implement encryption backend abstraction layer
- [ ] Add configuration mechanism for algorithm selection
- [ ] Maintain backward compatibility with existing Fernet-encrypted data
- [ ] Test algorithm selection and migration scenarios
- [ ] Documentation updated with algorithm configuration options

### References
- Source: 11.2.2.md
- Related: ASVS-1122-LOW-001

### Priority
Low - Current algorithm is secure; this enables future flexibility

---
## Issue: FINDING-010 - No Formal Communication Service Inventory Document in SDK Codebase
**Labels:** bug, security, priority:low
**Description:**
### Summary
The SDK communicates with multiple external/internal services but lacks a consolidated communication inventory document within or alongside the codebase.

### Details
The SDK communicates with multiple services including:
1. Execution API Server (HTTPS) — `Client` class, all `*Operations` classes
2. Remote Logging Services — `_fetch_remote_logging_conn()`, `_remote_logging_conn()` in supervisor.py
3. Secrets Backends — `ensure_secrets_backend_loaded()` in supervisor.py
4. Subprocess IPC — `WatchedSubprocess.start()`, `_fork_main()`
5. DNS Resolution — `_get_fqdn()` in client.py

While high-level architecture is described in project documentation, there is no formal communication inventory enumerating each service endpoint, protocol, port, expected data flows, and whether end users can control target locations.

**ASVS:** 13.1.1 (L2)

### Remediation
Create a communication architecture document (e.g., in `task-sdk/docs/`) that explicitly lists:
- Each external service (Execution API, secrets backends, remote logging services)
- Protocol and transport security requirements for each
- Whether user-controlled inputs can influence target locations
- Data sensitivity classification per channel

### Acceptance Criteria
- [ ] Create communication architecture document
- [ ] Document all external service dependencies
- [ ] Document protocols and security requirements
- [ ] Document data sensitivity per channel
- [ ] Include diagram of communication flows
- [ ] Review and approve document with security team

### References
- Source: 13.1.1.md
- Related: ASVS-1311-LOW-001

### Priority
Low - Documentation improvement for operational security

---
## Issue: FINDING-011 - Inconsistent Connection Pool Limits and Undocumented Exhaustion Behavior
**Labels:** bug, security, priority:low
**Description:**
### Summary
Connection pool configuration is inconsistent between client instantiation paths, and behavior when pools are exhausted is not documented.

### Details
Connection pool limits differ between instantiation paths:
- The supervisor path (`_ensure_client` in `task-sdk/src/airflow/sdk/execution_time/supervisor.py`) sets `max_connections=10`
- The default `Client.__init__()` in `task-sdk/src/airflow/sdk/api/client.py` does not set explicit limits (inheriting httpx defaults of 100 max connections)

Neither path documents what happens when the connection pool is exhausted, fallback or queuing behavior, expected impact on task execution latency, or recovery mechanisms. Under high concurrency, undocumented pool behavior could lead to unexpected timeouts or request failures.

**ASVS:** 13.1.2 (L3)

### Remediation
1. Document the intended connection pool limits for each deployment context
2. Standardize limits in `Client.__init__()` by setting default limits:
   ```python
   kwargs.setdefault("limits", httpx.Limits(max_keepalive_connections=5, max_connections=20))
   ```
3. Document expected behavior when limits are reached (httpx will queue requests, with timeout per API_TIMEOUT)

### Acceptance Criteria
- [ ] Standardize connection pool limits across instantiation paths
- [ ] Document connection pool configuration and exhaustion behavior
- [ ] Add configuration options for connection pool tuning
- [ ] Test behavior under connection pool exhaustion
- [ ] Documentation updated with operational guidance

### References
- Source: 13.1.2.md
- Related: ASVS-1312-LOW-001

### Priority
Low - Impacts high-concurrency deployments

---
## Issue: FINDING-012 - Resource Management Strategies Implemented but Not Formally Documented
**Labels:** bug, security, priority:low
**Description:**
### Summary
The codebase implements comprehensive resource management strategies but lacks formal documentation defining them as a cohesive policy.

### Details
Implemented strategies include:
- HTTP connections with timeout (API_TIMEOUT)
- HTTP retries with exponential backoff and jitter (in `task-sdk/src/airflow/sdk/api/client.py`)
- Subprocess socket cleanup timeout after exit
- Task heartbeat with min interval and max failures before kill (in `task-sdk/src/airflow/sdk/execution_time/supervisor.py`)
- Task overtime kill after threshold
- Client lifecycle with context manager

However, no document defines:
- Why specific values were chosen
- Interaction effects (e.g., total retry time vs. heartbeat timeout)
- Per-service strategy differentiation
- Thread/file-handle release procedures for subprocess socket infrastructure

**ASVS:** 13.1.3 (L3)

### Remediation
Create a resource management strategy document that maps each external dependency to its timeout, retry, backoff, release, and failure handling configuration. Include rationale for chosen values and guidance for tuning.

### Acceptance Criteria
- [ ] Create resource management strategy document
- [ ] Document all timeout, retry, and backoff configurations
- [ ] Document interaction effects between strategies
- [ ] Include tuning guidance for different deployment scenarios
- [ ] Review and approve document with operations team

### References
- Source: 13.1.3.md
- Related: ASVS-1313-LOW-001

### Priority
Low - Documentation improvement for operational resilience

---
## Issue: FINDING-013 - User-Agent header exposes SDK version and Python version on internal API requests
**Labels:** bug, security, priority:low
**Description:**
### Summary
The application exposes detailed version information of backend components through the User-Agent header when making requests to the Execution API server.

### Details
In `task-sdk/src/airflow/sdk/api/client.py` (lines 594-598), the User-Agent header includes exact Airflow Task SDK version and Python version (e.g., `apache-airflow-task-sdk/{__version__} (Python/{pyver})`). This information is sent in outbound HTTP requests and may be logged by API servers, intermediary proxies, or load balancers.

An attacker with network position to intercept traffic or access to API server logs could use this information to identify known CVEs applicable to the deployment. While this is internal component-to-component communication with JWT authentication and expected TLS encryption, it still represents version disclosure that could aid attackers who have gained internal network or log access.

**ASVS:** 13.4.6 (L3)

### Remediation
Make the User-Agent version detail configurable to allow security-conscious deployments to reduce version fingerprinting:

**Option 1:** Add configuration flag `include_version_in_user_agent` (defaults to True for backward compatibility). When disabled, use generic User-Agent like `apache-airflow-task-sdk` without version details.

**Option 2:** Document that Deployment Managers should configure reverse proxies to strip/normalize User-Agent headers on internal traffic if version disclosure is a concern.

### Acceptance Criteria
- [ ] Add configuration option for User-Agent version disclosure
- [ ] Implement generic User-Agent when version disclosure is disabled
- [ ] Test User-Agent with version disclosure enabled and disabled
- [ ] Document configuration option and security implications
- [ ] Document reverse proxy configuration alternative

### References
- Source: 13.4.6.md
- Related: ASVS-1346-LOW-001

### Priority
Low - Applies to L3 (highest security) deployments; requires internal access to exploit