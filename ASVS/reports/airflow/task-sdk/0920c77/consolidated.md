# Security Audit Consolidated Report — apache/airflow/task-sdk

## Report Metadata

| Field | Value |
|-------|-------|
| Repository | apache/airflow/task-sdk |
| ASVS Level | L3 |
| Severity Threshold | None (all findings included) |
| Commit | `0920c77` |
| Date | May 22, 2026 |
| Auditor | Tooling Agents |
| Source Reports | 345 |
| Total Findings | 20 |
| Actionable Issues | 13 |

*Informational findings are recorded in this report but not opened as GitHub issues — see issues.md for the 13 actionable items.*

## Executive Summary

### Severity Distribution

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 13 |
| Informational | 7 |

The audit of the Apache Airflow Task SDK at ASVS Level 3 produced **no critical, high, or medium severity findings**. All 13 actionable issues are rated Low, reflecting hardening gaps and documentation shortfalls rather than exploitable vulnerabilities. The 7 informational findings document architectural observations, non-applicable requirements, and items not assessable from client-side code alone.

### ASVS Level Coverage

The audit evaluated controls across L1, L2, and L3 requirements spanning 30 security domains including secrets management, TLS and certificates, cryptographic implementation, logging and monitoring, service communication, and execution API client security. Findings were identified against ASVS chapters 10 (OAuth), 11 (Cryptography), 12 (TLS), 13 (Service Communication), and 16 (Logging), indicating mature coverage of chapters 1–9 with remaining gaps concentrated in operational hardening areas.

### Top 5 Risks

1. **Silent exception suppression in secret registration (FINDING-001):** Failed cross-process secret registration silently swallows exceptions, potentially leaving sensitive values unmasked in supervisor-level logs. This is the only finding spanning both L2 and L3 with direct data exposure implications.

2. **No HTTPS scheme enforcement before token transmission (FINDING-007):** The execution API client does not programmatically validate that the configured base URL uses the `https://` scheme before attaching the bearer token to outbound requests, relying on deployment configuration correctness.

3. **Missing exception handling in logging configuration (FINDING-005):** Uncontrolled exception propagation when remote logging provider discovery fails could cause task processes to crash without meaningful diagnostics.

4. **Inconsistent connection pool limits (FINDING-011):** Undocumented connection pool exhaustion behavior under high concurrency could lead to degraded service communication without clear failure signals.

5. **User-Agent header information disclosure (FINDING-013):** SDK and Python version strings exposed in internal API request headers increase reconnaissance surface for adversaries with network visibility.

### Positive Controls

The audit identified substantial defense-in-depth measures already in place:

- **Secrets architecture:** Pluggable secrets backend with API indirection ensures workers never access the database directly. JWT-scoped, short-lived tokens restrict each task's access to only its authorized secrets. Authorization denial is enforced consistently across all four access methods with hard-deny semantics for `PERMISSION_DENIED` responses.

- **Cryptographic implementation:** All cryptographic operations delegate to the well-maintained `cryptography` library via a single cached factory (`get_fernet()`). MultiFernet supports zero-downtime key rotation with explicit `rotate()` method isolation. No custom primitives or hardcoded keys exist in source.

- **TLS enforcement:** The client uses `ssl.create_default_context()` enforcing TLS 1.2+ with OpenSSL hardened cipher suites. SSL verification is mandatory and non-overridable in production. Mutual TLS is supported. No security downgrade paths exist — connection failure is preferred over insecure fallback.

- **Log masking:** `mask_secret()` is called at access boundaries for connections and variables, with cross-process registration to the supervisor's masking filter.

- **Process isolation:** DAG parsing isolation relies on process-level boundaries as the primary multi-tenant control. The trust model explicitly documents DAG authors as trusted identities, scoping mitigation responsibilities appropriately.

- **Token lifecycle management:** Automatic token refresh via response hooks ensures current credentials with minimal replay windows. Retry logic explicitly excludes 4xx responses, preventing credential leakage through repeated authentication attempts.

---

## 3. Findings

### 3.4 Low

#### FINDING-001: Silent Exception Suppression in Cross-Process Secret Registration May Leave Supervisor Logs Unmasked

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | CWE-532 |
| **ASVS Section(s)** | 16.2.5 |
| **Files** | task-sdk/src/airflow/sdk/log.py |
| **Source Reports** | 16.2.5.md |
| **Related Findings** | |

**Description:**

The `mask_secret()` function attempts to register secrets with both the local masker and the supervisor process. However, it uses a blanket `suppress(Exception)` context manager when communicating with the supervisor, causing all failures to be silently ignored without logging or alerting. When `sending_to_supervisor=True`, the local task process skips applying the `mask_logs` processor, delegating masking responsibility entirely to the supervisor. If the supervisor communication fails silently, the supervisor never receives the secret registration, resulting in unmasked sensitive data in supervisor-level logs.

**Remediation:**

Replace the blanket `suppress(Exception)` with targeted exception handling that logs a warning when the supervisor IS available but communication fails. This ensures that failures in secret registration are visible and can be investigated, preventing scenarios where secrets remain unmasked in supervisor logs due to silent communication failures.

---

#### FINDING-002: General Log Entries Do Not Enforce Identity ("Who") Context at Framework Level

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | |
| **ASVS Section(s)** | 16.2.1 |
| **Files** | task-sdk/src/airflow/sdk/log.py |
| **Source Reports** | 16.2.1.md |
| **Related Findings** | |

**Description:**

The logging processor pipeline configured in `logging_processors()` and `configure_logging()` does not include an automatic processor that injects task identity (who) into every log entry. While Sentry integration explicitly adds `task_id`, `dag_id`, and `try_number` as tags, the general structlog pipeline relies on callers manually binding identity context. The `callsite_parameters` config defaults to an empty list (`fallback=[]`), meaning "where" metadata (file, function, line number) is opt-in rather than default.

**Remediation:**

Add a structlog processor that automatically injects available task execution context (task_id, dag_id, run_id) when available.

---

#### FINDING-003: No Explicit UTC Enforcement in Timestamp Configuration

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | |
| **ASVS Section(s)** | 16.2.2 |
| **Files** | task-sdk/src/airflow/sdk/log.py |
| **Source Reports** | 16.2.2.md |
| **Related Findings** | |

**Description:**

The logging configuration in `logging_processors()` and `configure_logging()` delegates timestamp handling entirely to the shared module (`structlog_processors` from `airflow.sdk._shared.logging.structlog`). Neither function explicitly enforces UTC timestamps or includes timezone offset configuration. The `log_format` parameter is user-configurable, and there is no validation that the configured format includes timezone information.

**Remediation:**

Verify that `airflow.sdk._shared.logging.structlog.structlog_processors()` includes a `TimeStamper(utc=True)` processor, or add explicit UTC enforcement.

---

#### FINDING-004: No Explicit Authorization Failure Logging in Task SDK Logging Infrastructure

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | |
| **ASVS Section(s)** | 16.3.2 |
| **Files** | task-sdk/src/airflow/sdk/log.py, task-sdk/src/airflow/sdk/execution_time/sentry/configured.py |
| **Source Reports** | 16.3.2.md |
| **Related Findings** | |

**Description:**

The Task SDK's logging infrastructure does not include any dedicated mechanism or processor for logging authorization failures. The `ConfiguredSentry.enrich_errors` captures all exceptions but does not differentiate or explicitly tag authorization-related failures.

**Remediation:**

Add a structlog processor or dedicated logging call that identifies and tags authorization-related errors (HTTP 401/403 responses from the Execution API) as security events.

---

#### FINDING-005: Missing Exception Handling in _load_logging_config() Causes Uncontrolled Propagation When Remote Logging Discovery Fails

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | |
| **ASVS Section(s)** | 16.5.2 |
| **Files** | task-sdk/src/airflow/sdk/log.py |
| **Source Reports** | 16.5.2.md |
| **Related Findings** | |

**Description:**

The `upload_to_remote()` function correctly handles the case where the handler is `None` and wraps `handler.upload()` in try/except, but if `load_remote_log_handler()` itself raises (rather than returning None), the exception propagates to the task lifecycle handler, potentially disrupting task state transitions.

**Remediation:**

Add try/except around `discover_remote_log_handler()` in `_load_logging_config()` to ensure remote logging configuration failures don't prevent the logging system from initializing.

---

#### FINDING-006: No Top-Level Exception Guard Around Sentry Instrumentation in Task Execution Wrapper

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L3 |
| **CWE** | |
| **ASVS Section(s)** | 16.5.4 |
| **Files** | task-sdk/src/airflow/sdk/execution_time/sentry/configured.py |
| **Source Reports** | 16.5.4.md |
| **Related Findings** | |

**Description:**

In `enrich_errors()`, if `add_tagging` or `add_breadcrumbs` raises an exception, the task's `run()` function never executes and the exception propagates as if the task itself failed. A failure in non-critical Sentry instrumentation would be indistinguishable from a task execution failure.

**Remediation:**

Separate Sentry instrumentation from task execution so that tagging/breadcrumb failures cannot prevent the task `run()` from executing. Wrap instrumentation calls in their own try/except blocks.

---

#### FINDING-007: No explicit enforcement that base URL uses HTTPS scheme before transmitting bearer token

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1, L2 |
| **CWE** | |
| **ASVS Section(s)** | 12.1.1, 12.3.1 |
| **Files** | task-sdk/src/airflow/sdk/api/client.py:568-579 |
| **Source Reports** | 12.1.1.md, 12.3.1.md |
| **Related Findings** | |

**Description:**

The `base_url` parameter is accepted without scheme validation. If it contains `http://`, the SSL context set via `verify` is silently ignored by httpx for non-TLS connections. Configuration (`base_url` parameter) flows to `httpx.Client(base_url=...)` and then to HTTP requests carrying Bearer tokens, connection strings, variables, and XCom data. This is a Type A gap (entry point with no control). An attacker with network-level access between worker and API server (e.g., on the same network segment) combined with a misconfiguration where `base_url` is set to `http://` instead of `https://` could exploit this. Alternatively, an active MITM downgrade attack if DNS or routing is compromised. Impact includes exposure of JWT authentication tokens, Airflow connection credentials, variables (potentially secrets), and XCom data transmitted in plaintext. An attacker with network visibility could capture the short-lived JWT token and impersonate the task instance. Exploitability depends entirely on deployment configuration. If the Execution API is configured with an HTTP URL (no default visible in this file), all communications would be unencrypted. The SSL verify context would be set but completely unused.

**Remediation:**

Add URL scheme validation at client initialization to reject non-HTTPS base URLs. Add validation in `Client.__init__` that rejects `base_url` values not starting with `https://`. Example code: if not base_url.startswith("https://"): raise ValueError(f"Execution API base_url must use HTTPS scheme for secure communication, got: {base_url!r}")

---

#### FINDING-008: Mutual TLS (mTLS) Client Authentication is Optional, Not Enforced by Default

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L3 |
| **CWE** | |
| **ASVS Section(s)** | 12.3.5 |
| **Files** | task-sdk/src/airflow/sdk/api/client.py:560-564 |
| **Source Reports** | 12.3.5.md |
| **Related Findings** | |

**Description:**

The client supports mutual TLS (mTLS) client authentication but does not enforce it by default. Without explicit configuration, no client certificate is presented during TLS handshake. This is a Type B gap where the control EXISTS (mTLS support) but is NOT APPLIED by default. Without mandatory mTLS, the security of intra-service authentication relies solely on JWT bearer tokens. If a token is leaked (e.g., from process memory, logs, or network capture), it can be used from any client that can reach the API server without needing a valid client certificate. Exploitation would require: (1) compromising a network position where the attacker can reach the Execution API, AND (2) obtaining a valid JWT token. Without mTLS, a valid JWT token alone is sufficient for API access. With mTLS, both a valid certificate AND token would be required.

**Remediation:**

Consider adding a configuration option to mandate mTLS and fail if client certificates are not configured:

API_REQUIRE_MTLS = conf.getboolean("api", "require_client_cert", fallback=False)

# In Client.__init__:
if API_REQUIRE_MTLS and not (API_CLIENT_SSL_CERT and API_CLIENT_SSL_KEY):
    raise ValueError(
        "api.require_client_cert is True but client_ssl_cert and client_ssl_key "
        "are not configured. mTLS is required for intra-service communication."
    )

For microservice/Kubernetes deployments, document service mesh integration (e.g., Istio) as an alternative path to mTLS without application-level certificate management.

---

#### FINDING-009: Algorithm selection is hardcoded to Fernet with no configuration-driven mechanism to swap cipher suites

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-327 |
| **ASVS Section(s)** | 11.2.2 |
| **Files** | task-sdk/src/airflow/sdk/crypto.py |
| **Source Reports** | 11.2.2.md |
| **Related Findings** | |

**Description:**

The crypto module is tightly coupled to Fernet (AES-128-CBC + HMAC-SHA256) with no configuration-driven mechanism to select alternative authenticated encryption schemes. Key rotation IS supported via MultiFernet, but algorithm migration requires code changes.

**Remediation:**

Introduce a configuration-driven encryption backend selector and abstract the protocol to be algorithm-agnostic.

---

#### FINDING-010: No Formal Communication Service Inventory Document in SDK Codebase

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | |
| **ASVS Section(s)** | 13.1.1 |
| **Files** | task-sdk/src/airflow/sdk/api/client.py:entire file, task-sdk/src/airflow/sdk/execution_time/supervisor.py:entire file |
| **Source Reports** | 13.1.1.md |
| **Related Findings** | |

**Description:**

The SDK communicates with multiple external/internal services but lacks a consolidated communication inventory document within or alongside the codebase. Communication channels identified from code analysis include: 1) Execution API Server (HTTPS) — Client class, all *Operations classes; 2) Remote Logging Services — _fetch_remote_logging_conn(), _remote_logging_conn() in supervisor.py; 3) Secrets Backends (potentially external: AWS Secrets Manager, Vault, etc.) — ensure_secrets_backend_loaded() in supervisor.py; 4) Subprocess IPC (stdin/stdout socket pairs) — WatchedSubprocess.start(), _fork_main(); 5) DNS Resolution — _get_fqdn() in client.py via socket.getaddrinfo. While the architecture is described at a high level in project documentation, there is no formal communication inventory that enumerates each service endpoint, protocol, port, expected data flows, and whether end users can control target locations.

**Remediation:**

Create a communication architecture document (e.g., in task-sdk/docs/) that explicitly lists: Each external service (Execution API, secrets backends, remote logging services); Protocol and transport security requirements for each; Whether user-controlled inputs can influence target locations; Data sensitivity classification per channel

---

#### FINDING-011: Inconsistent Connection Pool Limits and Undocumented Exhaustion Behavior

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L3 |
| **CWE** | |
| **ASVS Section(s)** | 13.1.2 |
| **Files** | task-sdk/src/airflow/sdk/execution_time/supervisor.py:_ensure_client() function, task-sdk/src/airflow/sdk/api/client.py:Client.__init__() |
| **Source Reports** | 13.1.2.md |
| **Related Findings** | |

**Description:**

Connection pool configuration is inconsistent between client instantiation paths: The supervisor path (_ensure_client) sets max_connections=10, while the default Client.__init__() does not set explicit limits (inheriting httpx defaults of 100 max connections). Neither path documents what happens when the connection pool is exhausted, fallback or queuing behavior, expected impact on task execution latency, or recovery mechanisms for pool exhaustion scenarios. Under high concurrency (many tasks on same worker), undocumented pool behavior could lead to unexpected timeouts or request failures without clear operational guidance.

**Remediation:**

1. Document the intended connection pool limits for each deployment context. 2. Standardize limits in Client.__init__() by setting default limits: kwargs.setdefault("limits", httpx.Limits(max_keepalive_connections=5, max_connections=20)). 3. Document expected behavior when limits are reached (httpx will queue requests, with timeout per API_TIMEOUT).

---

#### FINDING-012: Resource Management Strategies Implemented but Not Formally Documented

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L3 |
| **CWE** | |
| **ASVS Section(s)** | 13.1.3 |
| **Files** | task-sdk/src/airflow/sdk/api/client.py:retry decorator on Client.request(), task-sdk/src/airflow/sdk/execution_time/supervisor.py:multiple timeout/heartbeat constants |
| **Source Reports** | 13.1.3.md |
| **Related Findings** | |

**Description:**

The codebase implements comprehensive resource management strategies but lacks formal documentation that defines them as a cohesive policy. The implemented strategies include: HTTP connections with timeout (API_TIMEOUT), HTTP retries with exponential backoff and jitter, subprocess socket cleanup timeout after exit, task heartbeat with min interval and max failures before kill, task overtime kill after threshold, and client lifecycle with context manager. However, no document defines why these specific values were chosen, interaction effects (e.g., total retry time vs. heartbeat timeout), per-service strategy differentiation (Execution API vs. secrets backends vs. remote logging), or thread/file-handle release procedures for the subprocess socket infrastructure.

**Remediation:**

Create a resource management strategy document that maps each external dependency to its timeout, retry, backoff, release, and failure handling configuration.

---

#### FINDING-013: User-Agent header exposes SDK version and Python version on internal API requests

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L3 |
| **CWE** | |
| **ASVS Section(s)** | 13.4.6 |
| **Files** | task-sdk/src/airflow/sdk/api/client.py:594-598 |
| **Source Reports** | 13.4.6.md |
| **Related Findings** | |

**Description:**

The application exposes detailed version information of backend components through the User-Agent header when making requests to the Execution API server. The header includes exact Airflow Task SDK version and Python version (e.g., 'apache-airflow-task-sdk/{__version__} (Python/{pyver})'). This information is constructed from airflow.sdk.__version__ and sys.version_info and sent in outbound HTTP requests, potentially being logged by API servers, intermediary proxies, or load balancers. An attacker with network position to intercept traffic between worker and API server or access to API server logs could use this information to identify known CVEs applicable to the deployment. While this is internal component-to-component communication with JWT authentication and expected TLS encryption, and version information in User-Agent is common practice for compatibility and debugging, it still represents version disclosure that could aid attackers who have gained internal network or log access.

**Remediation:**

Make the User-Agent version detail configurable to allow security-conscious deployments to reduce version fingerprinting on internal API traffic. Option 1: Allow configuration to suppress version details using a configuration flag like 'include_version_in_user_agent' that defaults to True for backward compatibility but can be set to False in production. When disabled, use a generic User-Agent like 'apache-airflow-task-sdk' without version details. Option 2: Document that Deployment Managers should configure reverse proxies to strip/normalize User-Agent headers on internal traffic if version disclosure is a concern.

### 3.5 Informational

#### FINDING-014: Fernet Cryptographic Operations Performed In-Process Without Isolated Security Module

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Info |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS sections** | 13.3.3 |
| **Files** | task-sdk/src/airflow/sdk/crypto.py:101-125 |
| **Source Reports** | 13.3.3.md |
| **Related** | None |

**Description:**

Fernet cryptographic operations are performed in-process without an isolated security module (HSM/vault). Configuration file/environment → `conf.get("core", "FERNET_KEY")` → plaintext key in process memory → `Fernet()` object in process memory → `@cache` holds reference indefinitely. This allows extraction of symmetric encryption key used for all connection passwords and variable values stored in the backend if an attacker has local access to worker process memory (e.g., `/proc/<pid>/mem`, debugger attach, memory dump from container escape). Rated INFO because this is a documented architectural decision — the project explicitly delegates sensitive credential configuration (including key storage mechanism) to the Deployment Manager. The pluggable secrets backend architecture allows integration with external vault systems that may provide envelope encryption or HSM-backed operations. The in-process Fernet pattern is standard for Python applications at L1/L2 assurance and only becomes a gap at L3 compliance.

**Remediation:**

For Level 3 deployments requiring HSM isolation: Integrate with a KMS that performs envelope encryption (e.g., AWS KMS, GCP Cloud KMS, HashiCorp Vault Transit backend) so plaintext data keys are never stored at rest. Consider implementing a custom `FernetProtocol` wrapper that delegates to vault transit operations (VaultTransitFernet class example provided in report). Consider providing a built-in `VaultTransitFernet` implementation that wraps HashiCorp Vault's Transit secrets engine or cloud KMS APIs behind the `FernetProtocol` interface for Level 3 compliance deployments.

---

#### FINDING-015: No Certificate Revocation Checking Configured in SSL Context

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Info |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS sections** | 12.1.4 |
| **Files** | task-sdk/src/airflow/sdk/api/client.py:582-586 |
| **Source Reports** | 12.1.4.md |
| **Related** | None |

**Description:**

The SSL context created by `_get_ssl_context_cached` does not enable certificate revocation checking via CRL or OCSP. The method uses `ssl.create_default_context()` which provides baseline certificate chain validation but does not configure `VERIFY_CRL_CHECK_LEAF` or OCSP verification flags. An attacker with a compromised and revoked server certificate could still present it to the client, and it would be accepted. This follows Python's standard SSL behavior and OCSP stapling is primarily a server-side feature. The project explicitly delegates TLS infrastructure to the Deployment Manager.

**Remediation:**

If certificate revocation checking is desired at the client level, the SSL context could be enhanced: `ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF` or use a library like pyOpenSSL for OCSP checking. However, this is documented as a deployment-layer responsibility. For Level 3 compliance, document how Deployment Managers can configure certificate revocation checking at the infrastructure layer (e.g., via reverse proxy or custom SSL contexts).

---

#### FINDING-016: No Documented Secrets Rotation Schedule Within SDK Codebase

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Info |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS sections** | 13.1.4 |
| **Files** | task-sdk/src/airflow/sdk/api/client.py:BearerAuth class and Client._update_auth(), task-sdk/src/airflow/sdk/execution_time/supervisor.py:supervise_task() token parameter |
| **Source Reports** | 13.1.4.md |
| **Related** | None |

**Description:**

The SDK uses the following security-critical secrets: (1) JWT Bearer Token passed via token parameter to Client, scoped to task instance; (2) SSL Client Certificate (API_CLIENT_SSL_CERT + API_CLIENT_SSL_KEY) for mTLS; (3) SSL CA Certificate (API_SSL_CERT_PATH) for server verification; (4) Remote Logging Connection Credentials fetched via _fetch_remote_logging_conn(). The codebase implements token refresh (_update_auth) indicating short-lived tokens, but there is no formal document within the SDK defining: classification of each secret's criticality, rotation schedule for SSL certificates, token lifetime expectations, or procedures when rotation fails. Per the project's security model, secret lifecycle management is delegated to the Deployment Manager, and this is an intentional design choice. The SDK provides the configuration surface; rotation scheduling is an operational concern.

**Remediation:**

Consider documenting secret classification and rotation guidance in deployment documentation (acknowledging this is a Deployment Manager responsibility per the project's security model).

---

#### FINDING-017: Dry-run mode exists but is properly guarded against accidental production use

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Info |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS sections** | 13.4.2 |
| **Files** | task-sdk/src/airflow/sdk/api/client.py:574-585, task-sdk/src/airflow/sdk/execution_time/supervisor.py:~1190 |
| **Source Reports** | 13.4.2.md |
| **Related** | None |

**Description:**

The `dry_run` mode installs a mock transport (`noop_handler`) that returns static fake responses without contacting the real API server. However, the XOR guard `(not base_url) ^ dry_run` ensures that you cannot provide both a real `base_url` AND `dry_run=True` (raises `ValueError`), and you must provide either a valid `base_url` or `dry_run=True` — not neither. Additionally, in `supervise_task()` there is validation: `if dry_run and server: raise ValueError(f"Can only specify one of {server=} or {dry_run=}")`. The guards are properly implemented and `dry_run` defaults to `False`. There is no code path that auto-enables dry-run in production. Attacker capability required: Deployment Manager misconfiguration — setting `dry_run=True` in production executor configuration. Impact: Task heartbeats and state transitions would be silently ignored, causing operational issues but no security data exposure.

**Remediation:**

No remediation required. The guards are properly implemented. The `dry_run` mode requires explicit opt-in via parameter (defaults to `False`), and mutual exclusion guard prevents combining dry-run with real API server URLs.

---

#### FINDING-018: ASVS 13.4.7 requirement not applicable to audited components (client and supervisor)

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Info |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS sections** | 13.4.7 |
| **Files** | task-sdk/src/airflow/sdk/api/client.py, task-sdk/src/airflow/sdk/execution_time/supervisor.py |
| **Source Reports** | 13.4.7.md |
| **Related** | None |

**Description:**

ASVS 13.4.7 requires that the web tier (web servers, application servers, reverse proxies) be configured to serve only files with specific extensions, preventing unintentional leakage of source code, configuration files, or other sensitive data. The audited components do not constitute a web tier. client.py is an HTTP client library that makes outbound requests to the Execution API server and does not bind to any HTTP port, accept incoming HTTP requests, serve static or dynamic files, or process user-facing web requests. supervisor.py is a subprocess supervisor that manages task execution via forked processes and Unix socket-based IPC and does not expose any HTTP endpoints, serve files over any protocol, or accept network connections from external clients. The audited components operate entirely downstream of the web tier and do not serve content to external users.

**Remediation:**

To satisfy ASVS 13.4.7, audit the following components instead: (1) FastAPI static file configuration - Verify StaticFiles mount points restrict extensions; (2) Reverse proxy configuration - Verify nginx/Apache rules block sensitive extensions (.py, .pyc, .conf, .env, .git, etc.); (3) Helm chart ingress rules - Verify Kubernetes ingress annotations enforce file type restrictions; (4) Default deny policy - Verify web tier returns 403/404 for unrecognized extensions. These components are documented as Deployment Manager responsibilities in the Airflow security model.

---

#### FINDING-019: Resource server audience validation not assessable from client code

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Info |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS sections** | 10.3.1 |
| **Files** | client.py:576 |
| **Source Reports** | 10.3.1.md |
| **Related** | None |

**Description:**

The Task SDK client (client.py) sends bearer tokens to the Execution API but does not perform resource server functions. Audience validation must be implemented server-side in the Execution API's token validation middleware. This requirement is N/A for the client component under review. The client is a token presenter, not a token validator. The Execution API (resource server) is responsible for aud claim verification.

**Remediation:**

A separate audit of the Execution API server code is needed to verify audience validation. The server must validate the 'aud' claim in JWT tokens or use token introspection to ensure tokens are intended for the resource server.

---

#### FINDING-020: Delegated authorization enforcement not assessable from client code

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Info |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS sections** | 10.3.2 |
| **Files** | N/A |
| **Source Reports** | 10.3.2.md |
| **Related** | None |

**Description:**

The Task SDK client does not enforce authorization decisions — it makes requests and receives responses. Authorization based on token claims (subject, scope, delegated permissions) must be enforced by the Execution API server, which is not in the provided source files. This requirement is N/A for the client component under review. The client operates within the scope of its issued token (scoped to task instance ID per architecture documentation). The client cannot elevate its own privileges through this code — the server enforces boundaries. Server-side 401/403 handling in ConnectionOperations.get() and VariableOperations.get() (returning ErrorType.PERMISSION_DENIED) confirms the server enforces authorization.

**Remediation:**

Conduct a complementary audit of the Execution API server code to verify: JWT aud claim is included in issued tokens (ASVS 9.2.4), Resource server validates aud before processing requests (ASVS 10.3.1), Authorization decisions use sub, scope, and other relevant claims (ASVS 10.3.2)

---

# 4. Positive Security Controls

| Domain | Control | Evidence Source | Supporting Files |
|--------|---------|-----------------|------------------|
| Subprocess Execution Isolation | DAG authors are trusted identities; resource exhaustion via crafted IPC from task subprocess is not in scope for application-level mitigation | source: Dropped finding ASVS-142-LOW-001 | — |
| Secrets Management | Pluggable secrets backend architecture | Allows vault integration with external systems (HashiCorp Vault, AWS Secrets Manager, etc.) | task-sdk/src/airflow/sdk/bases/secrets_backend.py, execution_api.py |
| Secrets Management | Execution API secrets routing | Workers access secrets via API indirection, not directly from database | task-sdk/src/airflow/sdk/execution_time/secrets/execution_api.py |
| Secrets Management | Fernet encryption for stored secrets | Encrypts connection and variable values at rest using cryptography.fernet.MultiFernet | task-sdk/src/airflow/sdk/crypto.py, crypto.py:_RealFernet |
| Secrets Management | Secret masking in logs | mask_secret() called on sensitive values at access boundaries | task-sdk/src/airflow/sdk/definitions/variable.py:50, task-sdk/src/airflow/sdk/definitions/connection.py:241, connection.py:extra_dejson, variable.py:get() |
| Secrets Management | No hardcoded secrets in source | Fernet key loaded from runtime configuration (conf.get) at line 115, not embedded in source or build artifacts | task-sdk/src/airflow/sdk/crypto.py:115 |
| Secrets Management | JWT-scoped task access | Team inferred from JWT token, not passed by caller; provides authorization layer. Short-lived tokens scoped to task instance ID | task-sdk/src/airflow/sdk/execution_time/secrets/execution_api.py, execution_api.py:67-72 |
| Secrets Management | Consistent cryptographic delegation | All cryptographic operations delegate to well-maintained cryptography library; no custom primitives | task-sdk/src/airflow/sdk/crypto.py, crypto.py |
| Secrets Management | Single encryption factory pattern | get_fernet() function serves as sole factory with @cache decorator, ensuring consistent algorithm usage | task-sdk/src/airflow/sdk/crypto.py |
| Secrets Management | Defense-in-depth authorization | Layered authorization model: JWT scoping, _raise_if_authz_denied prevention, AirflowSecretsBackendAccessDenied as PermissionError subclass | task-sdk/src/airflow/sdk/execution_time/secrets/execution_api.py, execution_api.py:46-60 |
| Secrets Management | Authorization denial enforcement | _raise_if_authz_denied method detects PERMISSION_DENIED responses and raises AirflowSecretsBackendAccessDenied to prevent fallback to less-restrictive backends | execution_api.py:46-60, execution_api.py:80-81, execution_api.py:86-87, execution_api.py:100-101, execution_api.py:106-107 |
| Secrets Management | Separation of not-found vs denied | Only PERMISSION_DENIED is treated as hard deny, not-found returns None and allows fallback | execution_api.py:50-60 |
| Secrets Management | Consistent enforcement across all access methods | All four access methods (get_connection, get_variable, aget_connection, aget_variable) implement the same authorization check pattern | execution_api.py:46-60, execution_api.py:80-81, execution_api.py:86-87, execution_api.py:100-101, execution_api.py:106-107 |
| Secrets Management | Multi-key Fernet support for rotation | Comma-separated keys create MultiFernet, enabling zero-downtime key rotation | crypto.py:get_fernet():120, crypto.py:118-120 |
| Secrets Management | Key rotation method | crypto.py:_RealFernet.rotate() delegates to MultiFernet.rotate() for re-encrypting with current primary key | crypto.py:93-95 |
| Secrets Management | Null encryption warning | Logs warning when no key configured | crypto.py:get_fernet():115 |
| Secrets Management | Per-execution secret retrieval | Secrets fetched from Execution API for each task execution rather than cached, ensuring rotated credentials picked up on subsequent runs | execution_api.py |
| Secrets Management | Protocol design separates rotation from general encryption | rotate() method excluded from FernetProtocol type, ensuring only safe contexts (CLI commands with guaranteed Fernet key) can call it | crypto.py:FernetProtocol |
| Secrets Management | Key material isolation by process | Workers receive secrets via the Execution API with JWT-scoped access — the Fernet key on the API server side and per-task secrets are never co-resident in untrusted DAG code context unless the worker itself has the Fernet key (which is a deployment configuration choice) | — |
| Dag Parsing Isolation | Process-level isolation is the documented primary multi-tenant boundary for DAG parsing; env-var-based context is a convenience mechanism for accidental leakage prevention only. | Promoted from dropped finding ASVS-841-LOW-001 | — |
| Callback Execution | Bundle access verification provides informative error messages for misconfigured impersonation | Observed in bundle access verification code | — |
| Callback Execution | Atomic file open pattern used | Observed in execute_workload.py | execute_workload.py |
| Logging And Monitoring | Task SDK operates within a trust boundary where DAG authors are trusted identities; input validation bypass detection is not applicable at this layer. | Dropped finding ASVS-1633-LOW-001 | — |
| Logging And Monitoring | Log file permissions are configurable via `file_task_handler_new_file_permissions` and `file_task_handler_new_folder_permissions` settings, delegating restrictive defaults to Deployment Manager. | Configuration settings available in file task handler | — |
| Logging And Monitoring | Remote log transmission infrastructure exists and is configurable; enforcement of remote logging is delegated to Deployment Manager. | Promoted from dropped finding ASVS-1643-LOW-001 | — |
| Tls And Certificates | SSL context with create_default_context() enforces TLS 1.2+ on Python 3.10+ | Uses Python's hardened SSL context which disables SSLv2, SSLv3, and on Python 3.10+ enforces TLS 1.2 minimum | client.py:564-567 |
| Tls And Certificates | Certificate verification via certifi | The verify parameter is always set in non-dry-run mode, preventing accidental unverified connections | client.py:579 |
| Tls And Certificates | Custom CA certificate support | Configurable custom CA certificate path via API_SSL_CERT_PATH | client.py:567 |
| Tls And Certificates | Mutual TLS (mTLS) support | Client certificate and key support for additional transport-layer security | client.py:581-584 |
| Tls And Certificates | Cached SSL context | Prevents memory growth from repeated context creation while maintaining security configuration consistency | client.py:564-567 |
| Tls And Certificates | Default cipher suites via ssl.create_default_context() | Uses OpenSSL hardened defaults which automatically configure cipher suites according to Python/OpenSSL security recommendations, including forward-secrecy suites (ECDHE, DHE) as preferred | client.py:564-567 |
| Tls And Certificates | No explicit weakening of cipher suites | No code explicitly weakens cipher suites or adds deprecated ciphers | — |
| Tls And Certificates | Client certificate + key pair enforcement | Both client_ssl_cert and client_ssl_key must be set together, raising ValueError if only one is set | client.py:590-594 |
| Tls And Certificates | Defense-in-depth layering | Multiple security layers including TLS with certificate validation, bearer token authentication, mTLS support, correlation IDs for audit trails, and retry logic that never degrades security posture | client.py |
| Tls And Certificates | No security downgrade paths | No mechanism to disable TLS verification, fall back to HTTP, or skip certificate validation. Only non-TLS mode is explicit dry_run=True mock transport for development | client.py |
| Tls And Certificates | SSL verification mandatory and non-overridable | SSL verification is mandatory and non-overridable for production connections | client.py |
| Tls And Certificates | Standard CA trust model using ssl.create_default_context() | Uses ssl.create_default_context() which provides baseline certificate chain validation | task-sdk/src/airflow/sdk/api/client.py:582-586 |
| Tls And Certificates | Bearer token in Authorization header | The token is transmitted via a standard header, not in the URL, ensuring it benefits from TLS encryption of the HTTP body/headers | — |
| Tls And Certificates | Public CA trust store (certifi) | The client uses certifi.where() which provides Mozilla's curated set of publicly trusted root CA certificates | client.py:588 |
| Tls And Certificates | Automatic certifi updates | Since certifi is a separate package, CA bundle updates are decoupled from application releases | — |
| Tls And Certificates | Retry logic does not retry auth failures | The _should_retry_api_request function only retries 5xx and network errors, not 4xx, preventing token leakage via repeated auth attempts to wrong servers | task-sdk/src/airflow/sdk/api/client.py |
| Tls And Certificates | Single communication path | All task-to-API communication flows through the Client class, which provides a single point of enforcement for TLS, authentication, and retry policies | task-sdk/src/airflow/sdk/api/client.py |
| Tls And Certificates | Token lifecycle management | The automatic token refresh via _update_auth response hook ensures the client always uses the most current token, reducing the window for token replay | task-sdk/src/airflow/sdk/api/client.py |
| Tls And Certificates | No insecure fallback on connection failure | The retry logic (_should_retry_api_request) retries on 5xx errors and httpx.RequestError but never falls back to an unencrypted connection. If TLS fails, the connection fails. | — |
| Tls And Certificates | Custom CA bundle support | The API_SSL_CERT_PATH configuration allows deployments to specify internal CA certificates for trusting self-signed or privately-issued server certificates | — |
| Tls And Certificates | JWT tokens provide baseline strong authentication | Short-lived, task-instance-scoped JWT tokens provide replay-resistant authentication even without mTLS. The token refresh mechanism (_update_auth) ensures tokens are rotated during long-running operations | task-sdk/src/airflow/sdk/api/client.py |
| Cryptographic Implementation | Industry-validated cryptographic implementations are used | ASVS 11.2.1 Pass status | — |
| Cryptographic Implementation | Key rotation supported via MultiFernet | Mentioned in 11.2.2 finding context | task-sdk/src/airflow/sdk/crypto.py |
| Cryptographic Implementation | Cryptographic primitives meet minimum 128-bit security requirement | ASVS 11.2.3 Pass status | — |
| Cryptographic Implementation | Constant-time cryptographic operations implemented | ASVS 11.2.4 Pass status | — |
| Cryptographic Implementation | Cryptographic modules fail securely | ASVS 11.2.5 Pass status | — |
| Cryptographic Implementation | Only approved hash functions used for cryptographic purposes | ASVS 11.4.1 Pass status | — |
| Cryptographic Implementation | Hash functions meet collision resistance and bit-length requirements | ASVS 11.4.3 Pass status | — |
| Cryptographic Implementation | Cryptographically secure pseudo-random number generator (CSPRNG) used with adequate entropy | ASVS 11.5.1 Pass status | — |
| Cryptographic Implementation | Random number generation mechanism designed to work securely under heavy demand | ASVS 11.5.2 Pass status | — |
| Cryptographic Implementation | Hardware memory encryption is delegated to Deployment Manager as an infrastructure control | Dropped finding ASVS-1171-LOW-001 | — |
| Cryptographic Implementation | Memory-level protections (core dumps, swap encryption, memory encryption) are delegated to Deployment Manager as infrastructure controls | source: Dropped finding ASVS-1172-LOW-001 | — |
| Dependency Management | XOR guard prevents accidental co-activation of dry_run with real base_url; production instantiation paths never set dry_run=True | Identified during ASVS 15.2.3 review - production environment isolation from test functionality | — |
| Authentication System | InProcessTestSupervisor is dev/test-only, uses mock transport and dry_run=True, not reachable in production execution flows | 6.3.2.md - Dropped finding ASVS-632-LOW-001 | — |
| Authentication System | Password hints and knowledge-based authentication (secret questions) are not present in the application | 6.4.2 passed - no password hints or secret questions found | — |
| Session Management | Server-side JWT validation on every request ensures session termination is enforced regardless of client-side token state | Observed during 7.4.1 assessment (source: Dropped finding ASVS-741-LOW-001) | — |
| Authorization And Access Control | Server-side authorization enforcement via JWT-scoped tokens is the correct and documented security boundary for data-specific access; client is not a trust boundary. | ASVS 8.2.2 audit - dropped finding ASVS-822-LOW-001 | — |
| Authorization And Access Control | Object-level authorization properly enforced server-side; tasks within trust boundary have legitimate need for full connection properties. | ASVS 8.2.3 audit - dropped finding ASVS-823-LOW-001 | — |
| Authorization And Access Control | Short-lived JWT tokens scoped to task instance ID with server-pushed refresh on every response provide near-continuous authorization state updates | ASVS 8.3.2 audit - promoted from dropped finding ASVS-832-LOW-001 | — |
| Input Validation | Server-side state machine enforcement via 409 CONFLICT | Server enforces state machine via HTTP 409 CONFLICT responses preventing out-of-order business logic flow execution | — |
| Input Validation | Rate limiting and anti-automation delegated to infrastructure layer | Anti-automation controls (rate limiting, request throttling) are implemented at the reverse proxy/API gateway level as documented in delegated_infrastructure_controls.md | — |
| Data Sanitization | NativeEnvironment requires explicit opt-in by trusted DAG author via render_template_as_native_obj; template strings originate exclusively from trusted DAG code | Section 1.3.3 audit - Dropped finding ASVS-133-LOW-001 | — |
| Sensitive Data Protection | Cache disabled by default | Noted in dropped finding rationale for 14.2.4 | — |
| Sensitive Data Protection | Manager uses authkey authentication | Noted in dropped finding rationale for shared process memory in 14.2.4 | — |
| Sensitive Data Protection | Processes on same host share a trust boundary per AGENTS.md | Referenced in threat model justification for 14.2.4 | AGENTS.md |
| Service Communication | Bearer token authentication for all Execution API requests | All Execution API requests use bearer tokens via BearerAuth.auth_flow() | client.py:BearerAuth.auth_flow() |
| Service Communication | Short-lived JWT tokens scoped to task instance | Each task receives instance-scoped token per task execution, limiting blast radius of token compromise | — |
| Service Communication | Automatic token refresh mechanism | All responses checked for token refresh via _update_auth(); client transparently refreshes tokens when server issues Refreshed-API-Token header | client.py:Client._update_auth() |
| Service Communication | mTLS support | Client supports mutual TLS when cert and key are configured | client.py:Client.__init__() |
| Service Communication | TLS verification with secure defaults | ssl.create_default_context() used for all non-dry-run connections | client.py:Client._get_ssl_context_cached() |
| Service Communication | Permission-denied distinction | 401/403 responses return PERMISSION_DENIED rather than NOT_FOUND, preventing fallback to less-restrictive sources | client.py:ConnectionOperations.get(), client.py:VariableOperations.get() |
| Service Communication | HTTPS enforcement for API client | URL scheme validation in supervise_task() validates that the API server URL uses http:// or https:// scheme and has a valid host, preventing misconfiguration with arbitrary protocols | client.py:supervise_task() |
| Service Communication | Configuration-driven endpoints | All service endpoints are configured via airflow.sdk.configuration.conf, making communication targets auditable and overridable per environment | airflow.sdk.configuration.conf |
| Service Communication | Clear separation of communication channels | The code cleanly separates API communication (HTTP client), subprocess IPC (socket pairs), and logging (separate socket/FD), making each channel independently auditable | client.py, supervisor.py |
| Service Communication | Subprocess IPC via socketpair (no network exposure) | Subprocess communication uses local socket pairs, not network sockets | supervisor.py:WatchedSubprocess.start() |
| Service Communication | Pluggable secrets backend abstraction | ensure_secrets_backend_loaded() supports pluggable backends (environment variables, Vault, AWS Secrets Manager) allowing organizations to implement their own rotation policies | supervisor.py:ensure_secrets_backend_loaded() |
| Service Communication | Configurable SSL cert paths | API_SSL_CERT_PATH, API_CLIENT_SSL_CERT, API_CLIENT_SSL_KEY environment variables provide deployment-configurable certificate management | client.py |
| Service Communication | Explicit connection limits in supervisor context | The _ensure_client() function sets conservative connection limits (max_connections=10), demonstrating awareness of resource constraints | supervisor.py:_ensure_client() |
| Service Communication | Configurable request timeout | API_TIMEOUT is configurable via conf.getfloat("workers", "execution_api_timeout"), allowing deployment-specific tuning; Client.__init__() sets kwargs.setdefault("timeout", API_TIMEOUT) for all requests | client.py:Client.__init__() |
| Service Communication | Retry with exponential backoff and jitter | Retry decorator uses wait_random_exponential(min=API_RETRY_WAIT_MIN, max=API_RETRY_WAIT_MAX) with jitter to prevent thundering herd, stop_after_attempt(API_RETRIES) for bounded retries | client.py:Client.request() |
| Service Communication | Selective retry predicate | _should_retry_api_request() — only retries on server errors (5xx) and network errors (RequestError), never on client errors (4xx) | client.py:_should_retry_api_request() |
| Service Communication | Graceful socket cleanup with timeout | _cleanup_open_sockets() after SOCKET_CLEANUP_TIMEOUT; waits before force-closing sockets, preventing resource leaks | supervisor.py:_cleanup_open_sockets() |
| Service Communication | Heartbeat failure escalation | _handle_heartbeat_failures() — kill after MAX_FAILED_HEARTBEATS | supervisor.py:_handle_heartbeat_failures() |
| Service Communication | Client close in context manager | _ensure_client() — finally: new_client.close() | supervisor.py:_ensure_client() |
| Service Communication | Process signal escalation | WatchedSubprocess.kill() — SIGINT→SIGTERM→SIGKILL | supervisor.py:WatchedSubprocess.kill() |
| Service Communication | Reasonable hardcoded connection pool defaults | max_connections=10, max_keepalive=1 with architectural single-target communication pattern limiting outbound surface | — |
| Deployment Security | No source control metadata paths referenced or served | The codebase does not reference or serve .git or .svn directories in the audited runtime library source files | — |
| Deployment Security | Monorepo deployment structure with separate artifact management | The codebase uses a monorepo structure with deployment managed separately via Helm charts and Docker builds | — |
| Deployment Security | Client-only scope with no HTTP serving functionality | Both files under review implement client-side and subprocess-management functionality. They do not serve HTTP requests, expose endpoints, or configure web servers | — |
| Deployment Security | XOR guard preventing dry_run + base_url | Applied on every Client instantiation | task-sdk/src/airflow/sdk/api/client.py:575 |
| Deployment Security | Default dry_run=False | Must be explicitly enabled | task-sdk/src/airflow/sdk/api/client.py:574 |
| Deployment Security | supervise_task() server/dry_run validation | Applied at supervisor entry point | task-sdk/src/airflow/sdk/execution_time/supervisor.py:~1190 |
| Deployment Security | InProcessTestSupervisor clearly labeled as test-only | Only invoked by test infrastructure | task-sdk/src/airflow/sdk/execution_time/supervisor.py:~950 |
| Deployment Security | InProcessExecutionAPI cached and only used from test supervisor | Test-only code path | task-sdk/src/airflow/sdk/execution_time/supervisor.py:~920 |
| Deployment Security | Dry-run mode requires explicit opt-in | Defaults to False, mutual exclusion guard prevents combining with real API server URLs | task-sdk/src/airflow/sdk/api/client.py:574-585 |
| Deployment Security | InProcessTestSupervisor architecturally separate from production path | Separate from ActivitySubprocess (the production path) | task-sdk/src/airflow/sdk/execution_time/supervisor.py |
| Deployment Security | Debug-level logging gated by structlog configuration | Respects production log configuration | task-sdk/src/airflow/sdk/execution_time/supervisor.py |
| Deployment Security | Secret content omitted from debug logs | if isinstance(msg, MaskSecret): log.debug("Received message from task runner (body omitted)", msg=type(msg)) | task-sdk/src/airflow/sdk/execution_time/supervisor.py |
| Deployment Security | No static file serving or directory-browsing functionality | Neither client.py nor supervisor.py implement HTTP server functionality, serve static files, or expose filesystem directories to clients | client.py, supervisor.py |
| Deployment Security | Socket-pair IPC without filesystem exposure | The supervisor uses socket-pair IPC rather than filesystem-exposed endpoints | supervisor.py |
| Deployment Security | Test/dev code properly segregated | InProcessTestSupervisor, InProcessSupervisorComms, and noop_handler are clearly labeled as test/dev utilities and architecturally isolated from production code path | supervisor.py |
| Deployment Security | Subprocess security hardening | Defense-in-depth measures including block_orm_access, _make_process_nondumpable, and _reset_signals reduce attack surface of forked task process | supervisor.py |
| Deployment Security | Client class does not expose HTTP methods on a listening socket | The Client class in client.py extends httpx.Client and only performs outbound requests (GET, POST, PUT, PATCH, DELETE, HEAD). It does not bind to a port or serve HTTP requests. | client.py |
| Deployment Security | Client request() method is for outbound communication only | The client's request() method is for outbound communication only and cannot respond to HTTP TRACE method. | client.py |
| Deployment Security | InProcessExecutionAPI network isolation | in_process_api_server() is cached with @functools.lru_cache(maxsize=1) and only called from InProcessTestSupervisor._api_client() — clearly test-only infrastructure with no network binding | supervisor.py:920 |
| Deployment Security | No endpoint registration or route definitions | The audited files do not define or expose HTTP endpoints. They are consumers of the Execution API, not providers | client.py, supervisor.py |
| Deployment Security | ServerResponseError class processes error details internally without external exposure | The ServerResponseError class processes error details from the API server but does not expose them externally — they remain within the task process for internal error handling and logging | task-sdk/src/airflow/sdk/api/client.py:635-660 |
| Deployment Security | SIGSEGV_MESSAGE debugging guidance logged internally only | The SIGSEGV_MESSAGE constant contains debugging guidance but is logged to task-specific logs, not exposed via HTTP | task-sdk/src/airflow/sdk/execution_time/supervisor.py |
| Deployment Security | Connection strings properly scoped and cleaned up | Connection strings set in environment variables during remote logging setup are scoped to the current process and cleaned up in a finally block | — |
| Deployment Security | Error responses sanitized before sending to subprocess | Error responses sent back to the task subprocess via send_msg() contain only the error type and a summarized detail dict — not raw server response bodies | — |
| Deployment Security | Correlation-ID exposure limited to internal exception handling | Correlation-ID in exception notes only exposed in Python 3.11+ exception handling, not HTTP responses | task-sdk/src/airflow/sdk/api/client.py:156-162 |
| Deployment Security | JWT authentication on Execution API | The Execution API requires JWT authentication with short-lived, TI-scoped tokens for internal communication | — |
| Deployment Security | SSL/TLS Enforcement | Ensures encrypted communication with API server using certifi CA bundle | task-sdk/src/airflow/sdk/api/client.py:578-590 |
| Deployment Security | Bearer Token Authentication | Authenticates all API requests via BearerAuth class | task-sdk/src/airflow/sdk/api/client.py |
| Deployment Security | Mutual TLS (Optional) | Supports client certificate authentication via client_ssl_cert/client_ssl_key | task-sdk/src/airflow/sdk/api/client.py |
| Deployment Security | Correlation-ID Tracking | UUID7-based request tracing for audit trails via add_correlation_id() | task-sdk/src/airflow/sdk/api/client.py |
| Deployment Security | Process Isolation | Linux prctl PR_SET_DUMPABLE=0 prevents memory dumping via _make_process_nondumpable() | task-sdk/src/airflow/sdk/execution_time/supervisor.py |
| Deployment Security | Database Access Control | Prevents task code from direct metadata DB access via block_orm_access() | task-sdk/src/airflow/sdk/execution_time/supervisor.py |
| Deployment Security | Token Refresh Handling | Dynamic token rotation from Refreshed-API-Token header via _update_auth() | task-sdk/src/airflow/sdk/api/client.py |
| Deployment Security | Intelligent Retry Logic | Retries only on 5xx/connection errors, not 4xx via _should_retry_api_request() | task-sdk/src/airflow/sdk/api/client.py |
| Deployment Security | Permission Error Handling | Distinguishes 401/403 as PERMISSION_DENIED vs NOT_FOUND in ConnectionOperations.get() and VariableOperations.get() | task-sdk/src/airflow/sdk/api/client.py |
| Api Security | Retry logic excludes 4xx responses, preventing amplification of oversized-request failures | Promoted from dropped finding ASVS-425-LOW-001 | — |
| Api Security | TLS with certificate verification enforced by default; mTLS supported; scoped JWT tokens provide message-level authentication within deployment-managed transport | Source: Dropped finding ASVS-415-LOW-001 | — |
| File Upload Security | File paths (log_path, dag_rel_path) originate exclusively from trusted infrastructure components (executor/API server), not from untrusted user input | Verified in ASVS 5.3.2 audit - paths are internally generated and not derived from user-submitted filenames | — |
| Oauth Implementation | Bearer token in Authorization header only | BearerAuth.auth_flow implementation ensures tokens are only sent via Authorization header | client.py:556-559 |
| Oauth Implementation | Token not included in URLs | All Operations classes - no token in query params or path | — |
| Oauth Implementation | Token not logged | Only logs 'issued us a refreshed Task token' without the value | client.py:598 |
| Oauth Implementation | Token contained to single base_url | Sent only to configured Execution API endpoint | client.py:576 |
| Oauth Implementation | No token in error details | ServerResponseError.from_response - Error details don't include auth headers | — |
| Oauth Implementation | Token isolation to backend | Task SDK runs as backend process; tokens never exposed to browser clients, logs, or URL parameters | — |
| Oauth Implementation | Single-destination auth | BearerAuth only adds Authorization header to requests for configured base_url (Execution API) | — |
| Oauth Implementation | Token refresh handled server-side | Refreshed-API-Token header mechanism keeps token lifecycle within authenticated channel | — |
| Oauth Implementation | Correlation IDs instead of tokens | Request tracing uses uuid7() correlation IDs (add_correlation_id) rather than tokens | — |
| Oauth Implementation | Dry-run mode isolation | When dry_run=True, mock transport used with no real network calls, no token leaves process | — |
| Oauth Implementation | Task instance tokens tied to specific task_instance_id and try_number | Documented security model in concepts.rst: 'Each task receives a short-lived JWT token scoped to its task instance ID' | concepts.rst |
| Oauth Implementation | Clear separation between token-holding supervisor and untrusted task code | BFF-like pattern where supervisor process is exclusive holder of authentication credentials. Task subprocesses never receive JWT token and communicate through length-prefixed binary IPC protocol over Unix socketpairs | comms.py |
| Oauth Implementation | Token lifecycle managed server-side | Token issuance at task start, refresh via Refreshed-API-Token header on heartbeat responses, and expiration controlled by API server. SDK has no capability to extend token lifetime, request additional permissions, or bypass audience restrictions | — |
| Oauth Implementation | Defense-in-depth on token exposure | Process isolation (fork without token inheritance), PR_SET_DUMPABLE=0 on Linux (prevents ptrace/core dump access), no token in startup messages to child, no token logging, ORM access blocked in child process (block_orm_access()), secrets masking in serialized fields | — |
| Oauth Implementation | Single-server design eliminates mix-up attack precondition | Client class constructor enforces exactly one base URL with validation logic | Client.__init__() |
| Oauth Implementation | No dynamic authorization server discovery | Client is instantiated with a single, fixed base_url from configuration | Client.__init__() |
| Oauth Implementation | Principle of least privilege by design | Architecture issues tokens scoped to individual task instance executions. Task SDK cannot request broader permissions — token's scope is determined entirely by API server at issuance time | — |
| Oauth Implementation | TLS certificate verification enabled | Security model relies on TLS (with certificate verification) as primary transport protection | — |
| Oauth Implementation | Proper handling of authorization failures | Client correctly handles permission-denied responses (401/403) as distinct from not-found (404), preventing fallback to less-restrictive mechanisms | client.py:298-308, client.py:339-349 |
| Oauth Implementation | Client does not parse or validate tokens | No token introspection, no JWT decoding, and no user-identification logic. Follows principle of least privilege for client components | — |
| Oauth Implementation | mTLS readiness for sender-constrained tokens | Infrastructure for sender-constrained tokens (mTLS) exists at client layer with opt-in pattern (fallback=None) | — |
| Oauth Implementation | Mutual TLS support for API connection | Client supports mutual TLS via client_ssl_cert and client_ssl_key configuration for authenticating to the API server | Client.__init__():~1165 |
| Oauth Implementation | Validation of paired certificate configuration | Code raises ValueError if only one of cert/key is provided, preventing misconfiguration | Client.__init__():~1167-1168 |
| Oauth Implementation | SSL context with CA verification | Server certificate validation implemented in SSL context with configurable CA path (API_SSL_CERT_PATH) | Client._get_ssl_context_cached():~1143-1147 |
| Oauth Implementation | Pre-issued JWT tokens used instead of OAuth authorization code flows | The client uses pre-issued JWT tokens (passed via environment per the architecture), avoiding the complexity and attack surface of OAuth authorization code flows within the task execution path | — |
| Oauth Implementation | Well-designed bearer token lifecycle with transparent refresh | Token provided at initialization (from environment per architecture), Token sent on every request via BearerAuth, Token refreshed transparently via Refreshed-API-Token response header, No token storage to disk | — |
| Oauth Implementation | mTLS readiness for sender-constrained tokens | The infrastructure for sender-constrained tokens (mTLS) exists at the client layer, but enforcement is a deployment decision. The fallback=None pattern means mTLS is opt-in | — |
| Oauth Implementation | Correct architectural separation of concerns | This file is purely an API client component within the Task SDK. All OAuth/OIDC concerns (token validation, claim-based authorization, redirect URI validation, authorization code management) are appropriately delegated to the server-side Execution API and the Airflow backend's authentication layer | — |
| Oauth Implementation | Bearer token authentication separated into dedicated class | BearerAuth class cleanly separates authentication concerns into a dedicated class, making the authentication mechanism transparent and auditable | unknown:590-596 |
| Oauth Implementation | TLS verification with configurable CA bundles | The file demonstrates good transport-security practices including TLS verification with configurable CA bundles | — |
| Oauth Implementation | Optional mutual TLS support | Optional mutual TLS support implemented for enhanced transport security | — |
| Oauth Implementation | Token refresh via authenticated channels | Token refresh mechanism uses authenticated channels. Client._update_auth() accepts refreshed tokens only from the Refreshed-API-Token response header of the already-authenticated API server, preventing token injection from arbitrary sources | — |
| Oauth Implementation | Correlation IDs for request tracing | Correlation IDs implemented for request tracing | — |
| Oauth Implementation | Structured error handling | Structured error handling with distinct error types (separating NOT_FOUND from PERMISSION_DENIED) | — |
| Oauth Implementation | Client does not interpret JWT claims locally, deferring all authorization decisions to the server side | The BearerAuth class transmits an opaque token without parsing or interpreting token contents. Server-side validation delegation is the appropriate pattern for a task execution client that receives pre-scoped tokens | — |
| Oauth Implementation | Clear separation between internal execution tokens and federated authentication | Task SDK uses internally-issued JWT tokens scoped to individual task instances, while OAuth/OIDC integration resides in the Airflow backend | — |
| Oauth Implementation | Fixed base URL prevents redirection attacks | The client connects to a single, explicitly configured base_url, which prevents redirection to unauthorized servers within the internal API context | Client.__init__() |
| Oauth Implementation | TLS server verification with SSL context | ssl.create_default_context(cafile=ca_file) ensures the server's identity is verified against trusted CAs, preventing connection to impersonating servers. Server certificate validation via SSL context authenticates the API server via TLS | _get_ssl_context_cached() |
| Oauth Implementation | Configurable CA bundle | Allows deployment-specific trust anchors | _get_ssl_context_cached() |
| General Security | Consistent use of exclude_defaults=True in IPC layer minimizes data in supervisor-to-task communication | IPC layer implementation | — |
| General Security | Server-side authorization scoping via JWT | Workers operate within the trust boundary with scoped JWT tokens per AGENTS.md | — |

---

# 5. ASVS Compliance Summary

| ASVS ID | Requirement Title | Status | Notes |
|---------|-------------------|--------|-------|
| **V1: Encoding and Sanitization** | | | |
| 1.1.1 | Verify that input is decoded or unescaped into a canonical form only once, it is only decoded when encoded data in that form is expected, and that this is done before processing the input further, for example it is not performed after input validation or sanitization. | **Pass** |  |
| 1.1.2 | Verify that the application performs output encoding and escaping either as a final step before being used by the interpreter for which it is intended or by the interpreter itself. | **Pass** |  |
| 1.2.1 | Verify that output encoding for an HTTP response, HTML document, or XML document is relevant for the context required, such as encoding the relevant characters for HTML elements, HTML attributes, HTML comments, CSS, or HTTP header fields, to avoid changing the message or document structure. | **Pass** |  |
| 1.2.2 | Verify that when dynamically building URLs, untrusted data is encoded according to its context (e.g., URL encoding or base64url encoding for query or path parameters). Ensure that only safe URL protocols are permitted (e.g., disallow javascript: or data:). | **N/A** |  |
| 1.2.3 | Verify that output encoding or escaping is used when dynamically building JavaScript content (including JSON), to avoid changing the message or document structure (to avoid JavaScript and JSON injection). | **Pass** |  |
| 1.2.4 | Verify that data selection or database queries (e.g., SQL, HQL, NoSQL, Cypher) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from SQL Injection and other database injection attacks. This is also relevant when writing stored procedures. | **N/A** |  |
| 1.2.5 | Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use contextual command line output encoding. | **Pass** |  |
| 1.2.6 | Verify that the application protects against LDAP injection vulnerabilities, or that specific security controls to prevent LDAP injection have been implemented. | **N/A** |  |
| 1.2.7 | Verify that the application is protected against XPath injection attacks by using query parameterization or precompiled queries. | **N/A** |  |
| 1.2.8 | Verify that LaTeX processors are configured securely (such as not using the "--shell-escape" flag) and an allowlist of commands is used to prevent LaTeX injection attacks. | **N/A** |  |
| 1.2.9 | Verify that the application escapes special characters in regular expressions (typically using a backslash) to prevent them from being misinterpreted as metacharacters. | **Pass** |  |
| 1.2.10 | Verify that the application is protected against CSV and Formula Injection. The application must follow the escaping rules defined in RFC 4180 sections 2.6 and 2.7 when exporting CSV content. Additionally, when exporting to CSV or other spreadsheet formats (such as XLS, XLSX, or ODF), special characters (including '=', '+', '-', '@', '\t' (tab), and '\0' (null character)) must be escaped with a single quote if they appear as the first character in a field value. | **N/A** |  |
| 1.3.1 | Verify that all untrusted HTML input from WYSIWYG editors or similar is sanitized using a well-known and secure HTML sanitization library or framework feature. | **N/A** |  |
| 1.3.2 | Verify that the application avoids the use of eval() or other dynamic code execution features such as Spring Expression Language (SpEL). Where there is no alternative, any user input being included must be sanitized before being executed. | **Pass** |  |
| 1.3.3 | Verify that data being passed to a potentially dangerous context is sanitized beforehand to enforce safety measures, such as only allowing characters which are safe for this context and trimming input which is too long. | **N/A** |  |
| 1.3.4 | Verify that user-supplied Scalable Vector Graphics (SVG) scriptable content is validated or sanitized to contain only tags and attributes (such as draw graphics) that are safe for the application, e.g., do not contain scripts and foreignObject. | **N/A** |  |
| 1.3.5 | Verify that the application sanitizes or disables user-supplied scriptable or expression template language content, such as Markdown, CSS or XSL stylesheets, BBCode, or similar. | **Pass** |  |
| 1.3.6 | Verify that the application protects against Server-side Request Forgery (SSRF) attacks, by validating untrusted data against an allowlist of protocols, domains, paths and ports and sanitizing potentially dangerous characters before using the data to call another service. | **N/A** |  |
| 1.3.7 | Verify that the application protects against template injection attacks by not allowing templates to be built based on untrusted input. Where there is no alternative, any untrusted input being included dynamically during template creation must be sanitized or strictly validated. | **Pass** |  |
| 1.3.8 | Verify that the application appropriately sanitizes untrusted input before use in Java Naming and Directory Interface (JNDI) queries and that JNDI is configured securely to prevent JNDI injection attacks. | **N/A** |  |
| 1.3.9 | Verify that the application sanitizes content before it is sent to memcache to prevent injection attacks. | **N/A** |  |
| 1.3.10 | Verify that format strings which might resolve in an unexpected or malicious way when used are sanitized before being processed. | **Pass** |  |
| 1.3.11 | Verify that the application sanitizes user input before passing to mail systems to protect against SMTP or IMAP injection. | **N/A** |  |
| 1.3.12 | Verify that regular expressions are free from elements causing exponential backtracking, and ensure untrusted input is sanitized to mitigate ReDoS or Runaway Regex attacks. | **N/A** |  |
| 1.4.1 | Verify that the application uses memory-safe string, safer memory copy and pointer arithmetic to detect or prevent stack, buffer, or heap overflows. | **Pass** |  |
| 1.4.2 | Verify that sign, range, and input validation techniques are used to prevent integer overflows. | **Pass** |  |
| 1.4.3 | Verify that dynamically allocated memory and resources are released, and that references or pointers to freed memory are removed or set to null to prevent dangling pointers and use-after-free vulnerabilities. | **Pass** |  |
| 1.5.1 | Verify that the application configures XML parsers to use a restrictive configuration and that unsafe features such as resolving external entities are disabled to prevent XML eXternal Entity (XXE) attacks. | **N/A** |  |
| 1.5.2 | Verify that deserialization of untrusted data enforces safe input handling, such as using an allowlist of object types or restricting client-defined object types, to prevent deserialization attacks. Deserialization mechanisms that are explicitly defined as insecure must not be used with untrusted input. | **Pass** |  |
| 1.5.3 | Verify that different parsers used in the application for the same data type (e.g., JSON parsers, XML parsers, URL parsers), perform parsing in a consistent way and use the same character encoding mechanism to avoid issues such as JSON Interoperability vulnerabilities or different URI or file parsing behavior being exploited in Remote File Inclusion (RFI) or Server-side Request Forgery (SSRF) attacks. | **N/A** |  |
| **V2: Validation and Business Logic** | | | |
| 2.1.1 | Verify that the application's documentation defines input validation rules for how to check the validity of data items against an expected structure. This could be common data formats such as credit card numbers, email addresses, telephone numbers, or it could be an internal data format. | **Pass** |  |
| 2.1.2 | Verify that the application's documentation defines how to validate the logical and contextual consistency of combined data items, such as checking that suburb and ZIP code match. | **Pass** |  |
| 2.1.3 | Verify that expectations for business logic limits and validations are documented, including both per-user and globally across the application. | **Pass** |  |
| 2.2.1 | Verify that input is validated to enforce business or functional expectations for that input. This should either use positive validation against an allow list of values, patterns, and ranges, or be based on comparing the input to an expected structure and logical limits according to predefined rules. For L1, this can focus on input which is used to make specific business or security decisions. For L2 and up, this should apply to all input. | **Pass** |  |
| 2.2.2 | Verify that the application is designed to enforce input validation at a trusted service layer. While client-side validation improves usability and should be encouraged, it must not be relied upon as a security control. | **Pass** |  |
| 2.2.3 | Verify that the application ensures that combinations of related data items are reasonable according to the pre-defined rules. | **Pass** |  |
| 2.3.1 | Verify that the application will only process business logic flows for the same user in the expected sequential step order and without skipping steps. | **Pass** |  |
| 2.3.2 | Verify that business logic limits are implemented per the application's documentation to avoid business logic flaws being exploited. | **Pass** |  |
| 2.3.3 | Verify that transactions are being used at the business logic level such that either a business logic operation succeeds in its entirety or it is rolled back to the previous correct state. | **Pass** |  |
| 2.3.4 | Verify that business logic level locking mechanisms are used to ensure that limited quantity resources (such as theater seats or delivery slots) cannot be double-booked by manipulating the application's logic. | **Pass** |  |
| 2.3.5 | Verify that high-value business logic flows require multi-user approval to prevent unauthorized or accidental actions. This could include but is not limited to large monetary transfers, contract approvals, access to classified information, or safety overrides in manufacturing. | **Pass** |  |
| 2.4.1 | Verify that anti-automation controls are in place to protect against excessive calls to application functions that could lead to data exfiltration, garbage-data creation, quota exhaustion, rate-limit breaches, denial-of-service, or overuse of costly resources. | **N/A** |  |
| 2.4.2 | Verify that business logic flows require realistic human timing, preventing excessively rapid transaction submissions. | **N/A** |  |
| **V3: Web Frontend Security** | | | |
| 3.1.1 | Verify that application documentation states the expected security features that browsers using the application must support (such as HTTPS, HTTP Strict Transport Security (HSTS), Content Security Policy (CSP), and other relevant HTTP security mechanisms). It must also define how the application must behave when some of these features are not available (such as warning the user or blocking access). | **N/A** |  |
| 3.2.1 | Verify that security controls are in place to prevent browsers from rendering content or functionality in HTTP responses in an incorrect context (e.g., when an API, a user-uploaded file or other resource is requested directly). Possible controls could include: not serving the content unless HTTP request header fields (such as Sec-Fetch-\*) indicate it is the correct context, using the sandbox directive of the Content-Security-Policy header field or using the attachment disposition type in the Content-Disposition header field. | **N/A** |  |
| 3.2.2 | Verify that content intended to be displayed as text, rather than rendered as HTML, is handled using safe rendering functions (such as createTextNode or textContent) to prevent unintended execution of content such as HTML or JavaScript. | **N/A** |  |
| 3.2.3 | Verify that the application avoids DOM clobbering when using client-side JavaScript by employing explicit variable declarations, performing strict type checking, avoiding storing global variables on the document object, and implementing namespace isolation. | **N/A** |  |
| 3.3.1 | Verify that cookies have the 'Secure' attribute set, and if the '\__Host-' prefix is not used for the cookie name, the '__Secure-' prefix must be used for the cookie name. | **N/A** |  |
| 3.3.2 | Verify that each cookie's 'SameSite' attribute value is set according to the purpose of the cookie, to limit exposure to user interface redress attacks and browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF). | **N/A** |  |
| 3.3.3 | Verify that cookies have the '__Host-' prefix for the cookie name unless they are explicitly designed to be shared with other hosts. | **N/A** |  |
| 3.3.4 | Verify that if the value of a cookie is not meant to be accessible to client-side scripts (such as a session token), the cookie must have the 'HttpOnly' attribute set and the same value (e. g. session token) must only be transferred to the client via the 'Set-Cookie' header field. | **N/A** |  |
| 3.3.5 | Verify that when the application writes a cookie, the cookie name and value length combined are not over 4096 bytes. Overly large cookies will not be stored by the browser and therefore not sent with requests, preventing the user from using application functionality which relies on that cookie. | **N/A** |  |
| 3.4.1 | Verify that a Strict-Transport-Security header field is included on all responses to enforce an HTTP Strict Transport Security (HSTS) policy. A maximum age of at least 1 year must be defined, and for L2 and up, the policy must apply to all subdomains as well. | **N/A** |  |
| 3.4.2 | Verify that the Cross-Origin Resource Sharing (CORS) Access-Control-Allow-Origin header field is a fixed value by the application, or if the Origin HTTP request header field value is used, it is validated against an allowlist of trusted origins. When 'Access-Control-Allow-Origin: *' needs to be used, verify that the response does not include any sensitive information. | **N/A** |  |
| 3.4.3 | Verify that HTTP responses include a Content-Security-Policy response header field which defines directives to ensure the browser only loads and executes trusted content or resources, in order to limit execution of malicious JavaScript. As a minimum, a global policy must be used which includes the directives object-src 'none' and base-uri 'none' and defines either an allowlist or uses nonces or hashes. For an L3 application, a per-response policy with nonces or hashes must be defined. | **N/A** |  |
| 3.4.4 | Verify that all HTTP responses contain an 'X-Content-Type-Options: nosniff' header field. This instructs browsers not to use content sniffing and MIME type guessing for the given response, and to require the response's Content-Type header field value to match the destination resource. For example, the response to a request for a style is only accepted if the response's Content-Type is 'text/css'. This also enables the use of the Cross-Origin Read Blocking (CORB) functionality by the browser. | **N/A** |  |
| 3.4.5 | Verify that the application sets a referrer policy to prevent leakage of technically sensitive data to third-party services via the 'Referer' HTTP request header field. This can be done using the Referrer-Policy HTTP response header field or via HTML element attributes. Sensitive data could include path and query data in the URL, and for internal non-public applications also the hostname. | **N/A** |  |
| 3.4.6 | Verify that the web application uses the frame-ancestors directive of the Content-Security-Policy header field for every HTTP response to ensure that it cannot be embedded by default and that embedding of specific resources is allowed only when necessary. Note that the X-Frame-Options header field, although supported by browsers, is obsolete and may not be relied upon. | **N/A** |  |
| 3.4.7 | Verify that the Content-Security-Policy header field specifies a location to report violations. | **N/A** |  |
| 3.4.8 | Verify that all HTTP responses that initiate a document rendering (such as responses with Content-Type text/html), include the Cross‑Origin‑Opener‑Policy header field with the same-origin directive or the same-origin-allow-popups directive as required. This prevents attacks that abuse shared access to Window objects, such as tabnabbing and frame counting. | **N/A** |  |
| 3.5.1 | Verify that, if the application does not rely on the CORS preflight mechanism to prevent disallowed cross-origin requests to use sensitive functionality, these requests are validated to ensure they originate from the application itself. This may be done by using and validating anti-forgery tokens or requiring extra HTTP header fields that are not CORS-safelisted request-header fields. This is to defend against browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF). | **N/A** |  |
| 3.5.2 | Verify that, if the application relies on the CORS preflight mechanism to prevent disallowed cross-origin use of sensitive functionality, it is not possible to call the functionality with a request which does not trigger a CORS-preflight request. This may require checking the values of the 'Origin' and 'Content-Type' request header fields or using an extra header field that is not a CORS-safelisted header-field. | **N/A** |  |
| 3.5.3 | Verify that HTTP requests to sensitive functionality use appropriate HTTP methods such as POST, PUT, PATCH, or DELETE, and not methods defined by the HTTP specification as "safe" such as HEAD, OPTIONS, or GET. Alternatively, strict validation of the Sec-Fetch-* request header fields can be used to ensure that the request did not originate from an inappropriate cross-origin call, a navigation request, or a resource load (such as an image source) where this is not expected. | **N/A** |  |
| 3.5.4 | Verify that separate applications are hosted on different hostnames to leverage the restrictions provided by same-origin policy, including how documents or scripts loaded by one origin can interact with resources from another origin and hostname-based restrictions on cookies. | **N/A** |  |
| 3.5.5 | Verify that messages received by the postMessage interface are discarded if the origin of the message is not trusted, or if the syntax of the message is invalid. | **N/A** |  |
| 3.5.6 | Verify that JSONP functionality is not enabled anywhere across the application to avoid Cross-Site Script Inclusion (XSSI) attacks. | **N/A** |  |
| 3.5.7 | Verify that data requiring authorization is not included in script resource responses, like JavaScript files, to prevent Cross-Site Script Inclusion (XSSI) attacks. | **N/A** |  |
| 3.5.8 | Verify that authenticated resources (such as images, videos, scripts, and other documents) can be loaded or embedded on behalf of the user only when intended. This can be accomplished by strict validation of the Sec-Fetch-* HTTP request header fields to ensure that the request did not originate from an inappropriate cross-origin call, or by setting a restrictive Cross-Origin-Resource-Policy HTTP response header field to instruct the browser to block returned content. | **N/A** |  |
| 3.6.1 | Verify that client-side assets, such as JavaScript libraries, CSS, or web fonts, are only hosted externally (e.g., on a Content Delivery Network) if the resource is static and versioned and Subresource Integrity (SRI) is used to validate the integrity of the asset. If this is not possible, there should be a documented security decision to justify this for each resource. | **N/A** |  |
| 3.7.1 | Verify that the application only uses client-side technologies which are still supported and considered secure. Examples of technologies which do not meet this requirement include NSAPI plugins, Flash, Shockwave, ActiveX, Silverlight, NACL, or client-side Java applets. | **N/A** |  |
| 3.7.2 | Verify that the application will only automatically redirect the user to a different hostname or domain (which is not controlled by the application) where the destination appears on an allowlist. | **N/A** |  |
| 3.7.3 | Verify that the application shows a notification when the user is being redirected to a URL outside of the application's control, with an option to cancel the navigation. | **N/A** |  |
| 3.7.4 | Verify that the application's top-level domain (e.g., site.tld) is added to the public preload list for HTTP Strict Transport Security (HSTS). This ensures that the use of TLS for the application is built directly into the main browsers, rather than relying only on the Strict-Transport-Security response header field. | **N/A** |  |
| 3.7.5 | Verify that the application behaves as documented (such as warning the user or blocking access) if the browser used to access the application does not support the expected security features. | **N/A** |  |
| **V4: API and Web Service** | | | |
| 4.1.1 | Verify that every HTTP response with a message body contains a Content-Type header field that matches the actual content of the response, including the charset parameter to specify safe character encoding (e.g., UTF-8, ISO-8859-1) according to IANA Media Types, such as "text/", "/+xml" and "/xml". | **Pass** |  |
| 4.1.2 | Verify that only user-facing endpoints (intended for manual web-browser access) automatically redirect from HTTP to HTTPS, while other services or endpoints do not implement transparent redirects. This is to avoid a situation where a client is erroneously sending unencrypted HTTP requests, but since the requests are being automatically redirected to HTTPS, the leakage of sensitive data goes undiscovered. | **Pass** |  |
| 4.1.3 | Verify that any HTTP header field used by the application and set by an intermediary layer, such as a load balancer, a web proxy, or a backend-for-frontend service, cannot be overridden by the end-user. Example headers might include X-Real-IP, X-Forwarded-*, or X-User-ID. | **Pass** |  |
| 4.1.4 | Verify that only HTTP methods that are explicitly supported by the application or its API (including OPTIONS during preflight requests) can be used and that unused methods are blocked. | **Pass** |  |
| 4.1.5 | Verify that per-message digital signatures are used to provide additional assurance on top of transport protections for requests or transactions which are highly sensitive or which traverse a number of systems. | **N/A** |  |
| 4.2.1 | Verify that all application components (including load balancers, firewalls, and application servers) determine boundaries of incoming HTTP messages using the appropriate mechanism for the HTTP version to prevent HTTP request smuggling. In HTTP/1.x, if a Transfer-Encoding header field is present, the Content-Length header must be ignored per RFC 2616. When using HTTP/2 or HTTP/3, if a Content-Length header field is present, the receiver must ensure that it is consistent with the length of the DATA frames. | **Pass** |  |
| 4.2.2 | Verify that when generating HTTP messages, the Content-Length header field does not conflict with the length of the content as determined by the framing of the HTTP protocol, in order to prevent request smuggling attacks. | **Pass** |  |
| 4.2.3 | Verify that the application does not send nor accept HTTP/2 or HTTP/3 messages with connection-specific header fields such as Transfer-Encoding to prevent response splitting and header injection attacks. | **Pass** |  |
| 4.2.4 | Verify that the application only accepts HTTP/2 and HTTP/3 requests where the header fields and values do not contain any CR (\r), LF (\n), or CRLF (\r\n) sequences, to prevent header injection attacks. | **Pass** |  |
| 4.2.5 | Verify that, if the application (backend or frontend) builds and sends requests, it uses validation, sanitization, or other mechanisms to avoid creating URIs (such as for API calls) or HTTP request header fields (such as Authorization or Cookie), which are too long to be accepted by the receiving component. This could cause a denial of service, such as when sending an overly long request (e.g., a long cookie header field), which results in the server always responding with an error status. | **N/A** |  |
| 4.3.1 | Verify that a query allowlist, depth limiting, amount limiting, or query cost analysis is used to prevent GraphQL or data layer expression Denial of Service (DoS) as a result of expensive, nested queries. | **N/A** |  |
| 4.3.2 | Verify that GraphQL introspection queries are disabled in the production environment unless the GraphQL API is meant to be used by other parties. | **N/A** |  |
| 4.4.1 | Verify that WebSocket over TLS (WSS) is used for all WebSocket connections. | **N/A** |  |
| 4.4.2 | Verify that, during the initial HTTP WebSocket handshake, the Origin header field is checked against a list of origins allowed for the application. | **N/A** |  |
| 4.4.3 | Verify that, if the application's standard session management cannot be used, dedicated tokens are being used for this, which comply with the relevant Session Management security requirements. | **N/A** |  |
| 4.4.4 | Verify that dedicated WebSocket session management tokens are initially obtained or validated through the previously authenticated HTTPS session when transitioning an existing HTTPS session to a WebSocket channel. | **N/A** |  |
| **V5: File Handling** | | | |
| 5.1.1 | Verify that the documentation defines the permitted file types, expected file extensions, and maximum size (including unpacked size) for each upload feature. Additionally, ensure that the documentation specifies how files are made safe for end-users to download and process, such as how the application behaves when a malicious file is detected. | **N/A** |  |
| 5.2.1 | Verify that the application will only accept files of a size which it can process without causing a loss of performance or a denial of service attack. | **N/A** |  |
| 5.2.2 | Verify that when the application accepts a file, either on its own or within an archive such as a zip file, it checks if the file extension matches an expected file extension and validates that the contents correspond to the type represented by the extension. This includes, but is not limited to, checking the initial 'magic bytes', performing image re-writing, and using specialized libraries for file content validation. For L1, this can focus just on files which are used to make specific business or security decisions. For L2 and up, this must apply to all files being accepted. | **N/A** |  |
| 5.2.3 | Verify that the application checks compressed files (e.g., zip, gz, docx, odt) against maximum allowed uncompressed size and against maximum number of files before uncompressing the file. | **N/A** |  |
| 5.2.4 | Verify that a file size quota and maximum number of files per user are enforced to ensure that a single user cannot fill up the storage with too many files, or excessively large files. | **N/A** |  |
| 5.2.5 | Verify that the application does not allow uploading compressed files containing symlinks unless this is specifically required (in which case it will be necessary to enforce an allowlist of the files that can be symlinked to). | **N/A** |  |
| 5.2.6 | Verify that the application rejects uploaded images with a pixel size larger than the maximum allowed, to prevent pixel flood attacks. | **N/A** |  |
| 5.3.1 | Verify that files uploaded or generated by untrusted input and stored in a public folder, are not executed as server-side program code when accessed directly with an HTTP request. | **N/A** |  |
| 5.3.2 | Verify that when the application creates file paths for file operations, instead of user-submitted filenames, it uses internally generated or trusted data, or if user-submitted filenames or file metadata must be used, strict validation and sanitization must be applied. This is to protect against path traversal, local or remote file inclusion (LFI, RFI), and server-side request forgery (SSRF) attacks. | **N/A** |  |
| 5.3.3 | Verify that server-side file processing, such as file decompression, ignores user-provided path information to prevent vulnerabilities such as zip slip. | **N/A** |  |
| 5.4.1 | Verify that the application validates or ignores user-submitted filenames, including in a JSON, JSONP, or URL parameter and specifies a filename in the Content-Disposition header field in the response. | **N/A** |  |
| 5.4.2 | Verify that file names served (e.g., in HTTP response header fields or email attachments) are encoded or sanitized (e.g., following RFC 6266) to preserve document structure and prevent injection attacks. | **N/A** |  |
| 5.4.3 | Verify that files obtained from untrusted sources are scanned by antivirus scanners to prevent serving of known malicious content. | **N/A** |  |
| **V6: Authentication** | | | |
| 6.1.1 | Verify that application documentation defines how controls such as rate limiting, anti-automation, and adaptive response, are used to defend against attacks such as credential stuffing and password brute force. The documentation must make clear how these controls are configured and prevent malicious account lockout. | **Pass** |  |
| 6.1.2 | Verify that a list of context-specific words is documented in order to prevent their use in passwords. The list could include permutations of organization names, product names, system identifiers, project codenames, department or role names, and similar. | **N/A** |  |
| 6.1.3 | Verify that, if the application includes multiple authentication pathways, these are all documented together with the security controls and authentication strength which must be consistently enforced across them. | **Pass** |  |
| 6.2.1 | Verify that user set passwords are at least 8 characters in length although a minimum of 15 characters is strongly recommended. | **N/A** |  |
| 6.2.2 | Verify that users can change their password. | **N/A** |  |
| 6.2.3 | Verify that password change functionality requires the user's current and new password. | **N/A** |  |
| 6.2.4 | Verify that passwords submitted during account registration or password change are checked against an available set of, at least, the top 3000 passwords which match the application's password policy, e.g. minimum length. | **N/A** |  |
| 6.2.5 | Verify that passwords of any composition can be used, without rules limiting the type of characters permitted. There must be no requirement for a minimum number of upper or lower case characters, numbers, or special characters. | **N/A** |  |
| 6.2.6 | Verify that password input fields use type=password to mask the entry. Applications may allow the user to temporarily view the entire masked password, or the last typed character of the password. | **N/A** |  |
| 6.2.7 | Verify that "paste" functionality, browser password helpers, and external password managers are permitted. | **N/A** |  |
| 6.2.8 | Verify that the application verifies the user's password exactly as received from the user, without any modifications such as truncation or case transformation. | **N/A** |  |
| 6.2.9 | Verify that passwords of at least 64 characters are permitted. | **N/A** |  |
| 6.2.10 | Verify that a user's password stays valid until it is discovered to be compromised or the user rotates it. The application must not require periodic credential rotation. | **N/A** |  |
| 6.2.11 | Verify that the documented list of context specific words is used to prevent easy to guess passwords being created. | **N/A** |  |
| 6.2.12 | Verify that passwords submitted during account registration or password changes are checked against a set of breached passwords. | **N/A** |  |
| 6.3.1 | Verify that controls to prevent attacks such as credential stuffing and password brute force are implemented according to the application's security documentation. | **Pass** |  |
| 6.3.2 | Verify that default user accounts (e.g., "root", "admin", or "sa") are not present in the application or are disabled. | **N/A** |  |
| 6.3.3 | Verify that either a multi-factor authentication mechanism or a combination of single-factor authentication mechanisms, must be used in order to access the application. For L3, one of the factors must be a hardware-based authentication mechanism which provides compromise and impersonation resistance against phishing attacks while verifying the intent to authenticate by requiring a user-initiated action (such as a button press on a FIDO hardware key or a mobile phone). Relaxing any of the considerations in this requirement requires a fully documented rationale and a comprehensive set of mitigating controls. | **N/A** |  |
| 6.3.4 | Verify that, if the application includes multiple authentication pathways, there are no undocumented pathways and that security controls and authentication strength are enforced consistently. | **N/A** |  |
| 6.3.5 | Verify that users are notified of suspicious authentication attempts (successful or unsuccessful). This may include authentication attempts from an unusual location or client, partially successful authentication (only one of multiple factors), an authentication attempt after a long period of inactivity or a successful authentication after several unsuccessful attempts. | **N/A** |  |
| 6.3.6 | Verify that email is not used as either a single-factor or multi-factor authentication mechanism. | **Pass** |  |
| 6.3.7 | Verify that users are notified after updates to authentication details, such as credential resets or modification of the username or email address. | **N/A** |  |
| 6.3.8 | Verify that valid users cannot be deduced from failed authentication challenges, such as by basing on error messages, HTTP response codes, or different response times. Registration and forgot password functionality must also have this protection. | **N/A** |  |
| 6.4.1 | Verify that system generated initial passwords or activation codes are securely randomly generated, follow the existing password policy, and expire after a short period of time or after they are initially used. These initial secrets must not be permitted to become the long term password. | **N/A** |  |
| 6.4.2 | Verify that password hints or knowledge-based authentication (so-called "secret questions") are not present. | **Pass** |  |
| 6.4.3 | Verify that a secure process for resetting a forgotten password is implemented, that does not bypass any enabled multi-factor authentication mechanisms. | **N/A** |  |
| 6.4.4 | Verify that if a multi-factor authentication factor is lost, evidence of identity proofing is performed at the same level as during enrollment. | **N/A** |  |
| 6.4.5 | Verify that renewal instructions for authentication mechanisms which expire are sent with enough time to be carried out before the old authentication mechanism expires, configuring automated reminders if necessary. | **N/A** |  |
| 6.4.6 | Verify that administrative users can initiate the password reset process for the user, but that this does not allow them to change or choose the user's password. This prevents a situation where they know the user's password. | **N/A** |  |
| 6.5.1 | Verify that lookup secrets, out-of-band authentication requests or codes, and time-based one-time passwords (TOTPs) are only successfully usable once. | **N/A** |  |
| 6.5.2 | Verify that, when being stored in the application's backend, lookup secrets with less than 112 bits of entropy (19 random alphanumeric characters or 34 random digits) are hashed with an approved password storage hashing algorithm that incorporates a 32-bit random salt. A standard hash function can be used if the secret has 112 bits of entropy or more. | **N/A** |  |
| 6.5.3 | Verify that lookup secrets, out-of-band authentication code, and time-based one-time password seeds, are generated using a Cryptographically Secure Pseudorandom Number Generator (CSPRNG) to avoid predictable values. | **N/A** |  |
| 6.5.4 | Verify that lookup secrets and out-of-band authentication codes have a minimum of 20 bits of entropy (typically 4 random alphanumeric characters or 6 random digits is sufficient). | **N/A** |  |
| 6.5.5 | Verify that out-of-band authentication requests, codes, or tokens, as well as time-based one-time passwords (TOTPs) have a defined lifetime. Out of band requests must have a maximum lifetime of 10 minutes and for TOTP a maximum lifetime of 30 seconds. | **N/A** |  |
| 6.5.6 | Verify that any authentication factor (including physical devices) can be revoked in case of theft or other loss. | **N/A** |  |
| 6.5.7 | Verify that biometric authentication mechanisms are only used as secondary factors together with either something you have or something you know. | **N/A** |  |
| 6.5.8 | Verify that time-based one-time passwords (TOTPs) are checked based on a time source from a trusted service and not from an untrusted or client provided time. | **N/A** |  |
| 6.6.1 | Verify that authentication mechanisms using the Public Switched Telephone Network (PSTN) to deliver One-time Passwords (OTPs) via phone or SMS are offered only when the phone number has previously been validated, alternate stronger methods (such as Time based One-time Passwords) are also offered, and the service provides information on their security risks to users. For L3 applications, phone and SMS must not be available as options. | **N/A** |  |
| 6.6.2 | Verify that out-of-band authentication requests, codes, or tokens are bound to the original authentication request for which they were generated and are not usable for a previous or subsequent one. | **N/A** |  |
| 6.6.3 | Verify that a code based out-of-band authentication mechanism is protected against brute force attacks by using rate limiting. Consider also using a code with at least 64 bits of entropy. | **N/A** |  |
| 6.6.4 | Verify that, where push notifications are used for multi-factor authentication, rate limiting is used to prevent push bombing attacks. Number matching may also mitigate this risk. | **N/A** |  |
| 6.7.1 | Verify that the certificates used to verify cryptographic authentication assertions are stored in a way protects them from modification. | **N/A** |  |
| 6.7.2 | Verify that the challenge nonce is at least 64 bits in length, and statistically unique or unique over the lifetime of the cryptographic device. | **N/A** |  |
| 6.8.1 | Verify that, if the application supports multiple identity providers (IdPs), the user's identity cannot be spoofed via another supported identity provider (eg. by using the same user identifier). The standard mitigation would be for the application to register and identify the user using a combination of the IdP ID (serving as a namespace) and the user's ID in the IdP. | **N/A** |  |
| 6.8.2 | Verify that the presence and integrity of digital signatures on authentication assertions (for example on JWTs or SAML assertions) are always validated, rejecting any assertions that are unsigned or have invalid signatures. | **N/A** |  |
| 6.8.3 | Verify that SAML assertions are uniquely processed and used only once within the validity period to prevent replay attacks. | **N/A** |  |
| 6.8.4 | Verify that, if an application uses a separate Identity Provider (IdP) and expects specific authentication strength, methods, or recentness for specific functions, the application verifies this using the information returned by the IdP. For example, if OIDC is used, this might be achieved by validating ID Token claims such as 'acr', 'amr', and 'auth_time' (if present). If the IdP does not provide this information, the application must have a documented fallback approach that assumes that the minimum strength authentication mechanism was used (for example, single-factor authentication using username and password). | **N/A** |  |
| **V7: Session Management** | | | |
| 7.1.1 | Verify that the user's session inactivity timeout and absolute maximum session lifetime are documented, are appropriate in combination with other controls, and that the documentation includes justification for any deviations from NIST SP 800-63B re-authentication requirements. | **Pass** |  |
| 7.1.2 | Verify that the documentation defines how many concurrent (parallel) sessions are allowed for one account as well as the intended behaviors and actions to be taken when the maximum number of active sessions is reached. | **Pass** |  |
| 7.1.3 | Verify that all systems that create and manage user sessions as part of a federated identity management ecosystem (such as SSO systems) are documented along with controls to coordinate session lifetimes, termination, and any other conditions that require re-authentication. | **N/A** |  |
| 7.2.1 | Verify that the application performs all session token verification using a trusted, backend service. | **Pass** |  |
| 7.2.2 | Verify that the application uses either self-contained or reference tokens that are dynamically generated for session management, i.e. not using static API secrets and keys. | **Pass** |  |
| 7.2.3 | Verify that if reference tokens are used to represent user sessions, they are unique and generated using a cryptographically secure pseudo-random number generator (CSPRNG) and possess at least 128 bits of entropy. | **N/A** |  |
| 7.2.4 | Verify that the application generates a new session token on user authentication, including re-authentication, and terminates the current session token. | **Pass** |  |
| 7.3.1 | Verify that there is an inactivity timeout such that re-authentication is enforced according to risk analysis and documented security decisions. | **Pass** |  |
| 7.3.2 | Verify that there is an absolute maximum session lifetime such that re-authentication is enforced according to risk analysis and documented security decisions. | **Pass** |  |
| 7.4.1 | Verify that when session termination is triggered (such as logout or expiration), the application disallows any further use of the session. For reference tokens or stateful sessions, this means invalidating the session data at the application backend. Applications using self-contained tokens will need a solution such as maintaining a list of terminated tokens, disallowing tokens produced before a per-user date and time or rotating a per-user signing key. | **Pass** |  |
| 7.4.2 | Verify that the application terminates all active sessions when a user account is disabled or deleted (such as an employee leaving the company). | **Pass** |  |
| 7.4.3 | Verify that the application gives the option to terminate all other active sessions after a successful change or removal of any authentication factor (including password change via reset or recovery and, if present, an MFA settings update). | **N/A** |  |
| 7.4.4 | Verify that all pages that require authentication have easy and visible access to logout functionality. | **N/A** |  |
| 7.4.5 | Verify that application administrators are able to terminate active sessions for an individual user or for all users. | **Pass** |  |
| 7.5.1 | Verify that the application requires full re-authentication before allowing modifications to sensitive account attributes which may affect authentication such as email address, phone number, MFA configuration, or other information used in account recovery. | **N/A** |  |
| 7.5.2 | Verify that users are able to view and (having authenticated again with at least one factor) terminate any or all currently active sessions. | **N/A** |  |
| 7.5.3 | Verify that the application requires further authentication with at least one factor or secondary verification before performing highly sensitive transactions or operations. | **N/A** |  |
| 7.6.1 | Verify that session lifetime and termination between Relying Parties (RPs) and Identity Providers (IdPs) behave as documented, requiring re-authentication as necessary such as when the maximum time between IdP authentication events is reached. | **N/A** |  |
| 7.6.2 | Verify that creation of a session requires either the user's consent or an explicit action, preventing the creation of new application sessions without user interaction. | **N/A** |  |
| **V8: Authorization** | | | |
| 8.1.1 | Verify that authorization documentation defines rules for restricting function-level and data-specific access based on consumer permissions and resource attributes. | **Pass** |  |
| 8.1.2 | Verify that authorization documentation defines rules for field-level access restrictions (both read and write) based on consumer permissions and resource attributes. Note that these rules might depend on other attribute values of the relevant data object, such as state or status. | **Pass** |  |
| 8.1.3 | Verify that the application's documentation defines the environmental and contextual attributes (including but not limited to, time of day, user location, IP address, or device) that are used in the application to make security decisions, including those pertaining to authentication and authorization. | **Pass** |  |
| 8.1.4 | Verify that authentication and authorization documentation defines how environmental and contextual factors are used in decision-making, in addition to function-level, data-specific, and field-level authorization. This should include the attributes evaluated, thresholds for risk, and actions taken (e.g., allow, challenge, deny, step-up authentication). | **Pass** |  |
| 8.2.1 | Verify that the application ensures that function-level access is restricted to consumers with explicit permissions. | **Pass** |  |
| 8.2.2 | Verify that the application ensures that data-specific access is restricted to consumers with explicit permissions to specific data items to mitigate insecure direct object reference (IDOR) and broken object level authorization (BOLA). | **Pass** |  |
| 8.2.3 | Verify that the application ensures that field-level access is restricted to consumers with explicit permissions to specific fields to mitigate broken object property level authorization (BOPLA). | **Pass** |  |
| 8.2.4 | Verify that adaptive security controls based on a consumer's environmental and contextual attributes (such as time of day, location, IP address, or device) are implemented for authentication and authorization decisions, as defined in the application's documentation. These controls must be applied when the consumer tries to start a new session and also during an existing session. | **Pass** |  |
| 8.3.1 | Verify that the application enforces authorization rules at a trusted service layer and doesn't rely on controls that an untrusted consumer could manipulate, such as client-side JavaScript. | **Pass** |  |
| 8.3.2 | Verify that changes to values on which authorization decisions are made are applied immediately. Where changes cannot be applied immediately, (such as when relying on data in self-contained tokens), there must be mitigating controls to alert when a consumer performs an action when they are no longer authorized to do so and revert the change. Note that this alternative would not mitigate information leakage. | **Pass** |  |
| 8.3.3 | Verify that access to an object is based on the originating subject's (e.g. consumer's) permissions, not on the permissions of any intermediary or service acting on their behalf. For example, if a consumer calls a web service using a self-contained token for authentication, and the service then requests data from a different service, the second service will use the consumer's token, rather than a machine-to-machine token from the first service, to make permission decisions. | **Pass** |  |
| 8.4.1 | Verify that multi-tenant applications use cross-tenant controls to ensure consumer operations will never affect tenants with which they do not have permissions to interact. | **N/A** |  |
| 8.4.2 | Verify that access to administrative interfaces incorporates multiple layers of security, including continuous consumer identity verification, device security posture assessment, and contextual risk analysis, ensuring that network location or trusted endpoints are not the sole factors for authorization even though they may reduce the likelihood of unauthorized access. | **N/A** |  |
| **V9: Self-contained Tokens** | | | |
| 9.1.1 | Verify that self-contained tokens are validated using their digital signature or MAC to protect against tampering before accepting the token's contents. | **Pass** |  |
| 9.1.2 | Verify that only algorithms on an allowlist can be used to create and verify self-contained tokens, for a given context. The allowlist must include the permitted algorithms, ideally only either symmetric or asymmetric algorithms, and must not include the 'None' algorithm. If both symmetric and asymmetric must be supported, additional controls will be needed to prevent key confusion. | **N/A** |  |
| 9.1.3 | Verify that key material that is used to validate self-contained tokens is from trusted pre-configured sources for the token issuer, preventing attackers from specifying untrusted sources and keys. For JWTs and other JWS structures, headers such as 'jku', 'x5u', and 'jwk' must be validated against an allowlist of trusted sources. | **N/A** |  |
| 9.2.1 | Verify that, if a validity time span is present in the token data, the token and its content are accepted only if the verification time is within this validity time span. For example, for JWTs, the claims 'nbf' and 'exp' must be verified. | **N/A** |  |
| 9.2.2 | Verify that the service receiving a token validates the token to be the correct type and is meant for the intended purpose before accepting the token's contents. For example, only access tokens can be accepted for authorization decisions and only ID Tokens can be used for proving user authentication. | **N/A** |  |
| 9.2.3 | Verify that the service only accepts tokens which are intended for use with that service (audience). For JWTs, this can be achieved by validating the 'aud' claim against an allowlist defined in the service. | **N/A** |  |
| 9.2.4 | Verify that, if a token issuer uses the same private key for issuing tokens to different audiences, the issued tokens contain an audience restriction that uniquely identifies the intended audiences. This will prevent a token from being reused with an unintended audience. If the audience identifier is dynamically provisioned, the token issuer must validate these audiences in order to make sure that they do not result in audience impersonation. | **N/A** |  |
| **V10: OAuth and OIDC** | | | |
| 10.1.1 | Verify that tokens are only sent to components that strictly need them. For example, when using a backend-for-frontend pattern for browser-based JavaScript applications, access and refresh tokens shall only be accessible for the backend. | **Pass** |  |
| 10.1.2 | Verify that the client only accepts values from the authorization server (such as the authorization code or ID Token) if these values result from an authorization flow that was initiated by the same user agent session and transaction. This requires that client-generated secrets, such as the proof key for code exchange (PKCE) 'code_verifier', 'state' or OIDC 'nonce', are not guessable, are specific to the transaction, and are securely bound to both the client and the user agent session in which the transaction was started. | **N/A** |  |
| 10.2.1 | Verify that, if the code flow is used, the OAuth client has protection against browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF), which trigger token requests, either by using proof key for code exchange (PKCE) functionality or checking the 'state' parameter that was sent in the authorization request. | **N/A** |  |
| 10.2.2 | Verify that, if the OAuth client can interact with more than one authorization server, it has a defense against mix-up attacks. For example, it could require that the authorization server return the 'iss' parameter value and validate it in the authorization response and the token response. | **N/A** |  |
| 10.2.3 | Verify that the OAuth client only requests the required scopes (or other authorization parameters) in requests to the authorization server. | **N/A** |  |
| 10.3.1 | Verify that the resource server only accepts access tokens that are intended for use with that service (audience). The audience may be included in a structured access token (such as the 'aud' claim in JWT), or it can be checked using the token introspection endpoint. | **N/A** | See FINDING-019 |
| 10.3.2 | Verify that the resource server enforces authorization decisions based on claims from the access token that define delegated authorization. If claims such as 'sub', 'scope', and 'authorization_details' are present, they must be part of the decision. | **N/A** | See FINDING-020 |
| 10.3.3 | Verify that if an access control decision requires identifying a unique user from an access token (JWT or related token introspection response), the resource server identifies the user from claims that cannot be reassigned to other users. Typically, it means using a combination of 'iss' and 'sub' claims. | **N/A** |  |
| 10.3.4 | Verify that, if the resource server requires specific authentication strength, methods, or recentness, it verifies that the presented access token satisfies these constraints. For example, if present, using the OIDC 'acr', 'amr' and 'auth_time' claims respectively. | **N/A** |  |
| 10.3.5 | Verify that the resource server prevents the use of stolen access tokens or replay of access tokens (from unauthorized parties) by requiring sender-constrained access tokens, either Mutual TLS for OAuth 2 or OAuth 2 Demonstration of Proof of Possession (DPoP). | **N/A** |  |
| 10.4.1 | Verify that the authorization server validates redirect URIs based on a client-specific allowlist of pre-registered URIs using exact string comparison. | **N/A** |  |
| 10.4.2 | Verify that, if the authorization server returns the authorization code in the authorization response, it can be used only once for a token request. For the second valid request with an authorization code that has already been used to issue an access token, the authorization server must reject a token request and revoke any issued tokens related to the authorization code. | **N/A** |  |
| 10.4.3 | Verify that the authorization code is short-lived. The maximum lifetime can be up to 10 minutes for L1 and L2 applications and up to 1 minute for L3 applications. | **N/A** |  |
| 10.4.4 | Verify that for a given client, the authorization server only allows the usage of grants that this client needs to use. Note that the grants 'token' (Implicit flow) and 'password' (Resource Owner Password Credentials flow) must no longer be used. | **N/A** |  |
| 10.4.5 | Verify that the authorization server mitigates refresh token replay attacks for public clients, preferably using sender-constrained refresh tokens, i.e., Demonstrating Proof of Possession (DPoP) or Certificate-Bound Access Tokens using mutual TLS (mTLS). For L1 and L2 applications, refresh token rotation may be used. If refresh token rotation is used, the authorization server must invalidate the refresh token after usage, and revoke all refresh tokens for that authorization if an already used and invalidated refresh token is provided. | **N/A** |  |
| 10.4.6 | Verify that, if the code grant is used, the authorization server mitigates authorization code interception attacks by requiring proof key for code exchange (PKCE). For authorization requests, the authorization server must require a valid 'code_challenge' value and must not accept a 'code_challenge_method' value of 'plain'. For a token request, it must require validation of the 'code_verifier' parameter. | **N/A** |  |
| 10.4.7 | Verify that if the authorization server supports unauthenticated dynamic client registration, it mitigates the risk of malicious client applications. It must validate client metadata such as any registered URIs, ensure the user's consent, and warn the user before processing an authorization request with an untrusted client application. | **N/A** |  |
| 10.4.8 | Verify that refresh tokens have an absolute expiration, including if sliding refresh token expiration is applied. | **N/A** |  |
| 10.4.9 | Verify that refresh tokens and reference access tokens can be revoked by an authorized user using the authorization server user interface, to mitigate the risk of malicious clients or stolen tokens. | **N/A** |  |
| 10.4.10 | Verify that confidential client is authenticated for client-to-authorized server backchannel requests such as token requests, pushed authorization requests (PAR), and token revocation requests. | **N/A** |  |
| 10.4.11 | Verify that the authorization server configuration only assigns the required scopes to the OAuth client. | **N/A** |  |
| 10.4.12 | Verify that for a given client, the authorization server only allows the 'response_mode' value that this client needs to use. For example, by having the authorization server validate this value against the expected values or by using pushed authorization request (PAR) or JWT-secured Authorization Request (JAR). | **N/A** |  |
| 10.4.13 | Verify that grant type 'code' is always used together with pushed authorization requests (PAR). | **N/A** |  |
| 10.4.14 | Verify that the authorization server issues only sender-constrained (Proof-of-Possession) access tokens, either with certificate-bound access tokens using mutual TLS (mTLS) or DPoP-bound access tokens (Demonstration of Proof of Possession). | **N/A** |  |
| 10.4.15 | Verify that, for a server-side client (which is not executed on the end-user device), the authorization server ensures that the 'authorization_details' parameter value is from the client backend and that the user has not tampered with it. For example, by requiring the usage of pushed authorization request (PAR) or JWT-secured Authorization Request (JAR). | **N/A** |  |
| 10.4.16 | Verify that the client is confidential and the authorization server requires the use of strong client authentication methods (based on public-key cryptography and resistant to replay attacks), such as mutual TLS ('tls_client_auth', 'self_signed_tls_client_auth') or private key JWT ('private_key_jwt'). | **N/A** |  |
| 10.5.1 | Verify that the client (as the relying party) mitigates ID Token replay attacks. For example, by ensuring that the 'nonce' claim in the ID Token matches the 'nonce' value sent in the authentication request to the OpenID Provider (in OAuth2 refereed to as the authorization request sent to the authorization server). | **N/A** |  |
| 10.5.2 | Verify that the client uniquely identifies the user from ID Token claims, usually the 'sub' claim, which cannot be reassigned to other users (for the scope of an identity provider). | **N/A** |  |
| 10.5.3 | Verify that the client rejects attempts by a malicious authorization server to impersonate another authorization server through authorization server metadata. The client must reject authorization server metadata if the issuer URL in the authorization server metadata does not exactly match the pre-configured issuer URL expected by the client. | **N/A** |  |
| 10.5.4 | Verify that the client validates that the ID Token is intended to be used for that client (audience) by checking that the 'aud' claim from the token is equal to the 'client_id' value for the client. | **N/A** |  |
| 10.5.5 | Verify that, when using OIDC back-channel logout, the relying party mitigates denial of service through forced logout and cross-JWT confusion in the logout flow. The client must verify that the logout token is correctly typed with a value of 'logout+jwt', contains the 'event' claim with the correct member name, and does not contain a 'nonce' claim. Note that it is also recommended to have a short expiration (e.g., 2 minutes). | **N/A** |  |
| 10.6.1 | Verify that the OpenID Provider only allows values 'code', 'ciba', 'id_token', or 'id_token code' for response mode. Note that 'code' is preferred over 'id_token code' (the OIDC Hybrid flow), and 'token' (any Implicit flow) must not be used. | **N/A** |  |
| 10.6.2 | Verify that the OpenID Provider mitigates denial of service through forced logout. By obtaining explicit confirmation from the end-user or, if present, validating parameters in the logout request (initiated by the relying party), such as the 'id_token_hint'. | **N/A** |  |
| 10.7.1 | Verify that the authorization server ensures that the user consents to each authorization request. If the identity of the client cannot be assured, the authorization server must always explicitly prompt the user for consent. | **N/A** |  |
| 10.7.2 | Verify that when the authorization server prompts for user consent, it presents sufficient and clear information about what is being consented to. When applicable, this should include the nature of the requested authorizations (typically based on scope, resource server, Rich Authorization Requests (RAR) authorization details), the identity of the authorized application, and the lifetime of these authorizations. | **N/A** |  |
| 10.7.3 | Verify that the user can review, modify, and revoke consents which the user has granted through the authorization server. | **N/A** |  |
| **V11: Cryptography** | | | |
| 11.1.1 | Verify that there is a documented policy for management of cryptographic keys and a cryptographic key lifecycle that follows a key management standard such as NIST SP 800-57. This should include ensuring that keys are not overshared (for example, with more than two entities for shared secrets and more than one entity for private keys). | **Pass** |  |
| 11.1.2 | Verify that a cryptographic inventory is performed, maintained, regularly updated, and includes all cryptographic keys, algorithms, and certificates used by the application. It must also document where keys can and cannot be used in the system, and the types of data that can and cannot be protected using the keys. | **Pass** |  |
| 11.1.3 | Verify that cryptographic discovery mechanisms are employed to identify all instances of cryptography in the system, including encryption, hashing, and signing operations. | **Pass** |  |
| 11.1.4 | Verify that a cryptographic inventory is maintained. This must include a documented plan that outlines the migration path to new cryptographic standards, such as post-quantum cryptography, in order to react to future threats. | **Pass** |  |
| 11.2.1 | Verify that industry-validated implementations (including libraries and hardware-accelerated implementations) are used for cryptographic operations. | **Pass** |  |
| 11.2.2 | Verify that the application is designed with crypto agility such that random number, authenticated encryption, MAC, or hashing algorithms, key lengths, rounds, ciphers and modes can be reconfigured, upgraded, or swapped at any time, to protect against cryptographic breaks. Similarly, it must also be possible to replace keys and passwords and re-encrypt data. This will allow for seamless upgrades to post-quantum cryptography (PQC), once high-assurance implementations of approved PQC schemes or standards are widely available. | **Partial** | See FINDING-009 |
| 11.2.3 | Verify that all cryptographic primitives utilize a minimum of 128-bits of security based on the algorithm, key size, and configuration. For example, a 256-bit ECC key provides roughly 128 bits of security where RSA requires a 3072-bit key to achieve 128 bits of security. | **Pass** |  |
| 11.2.4 | Verify that all cryptographic operations are constant-time, with no 'short-circuit' operations in comparisons, calculations, or returns, to avoid leaking information. | **Pass** |  |
| 11.2.5 | Verify that all cryptographic modules fail securely, and errors are handled in a way that does not enable vulnerabilities, such as Padding Oracle attacks. | **Pass** |  |
| 11.3.1 | Verify that insecure block modes (e.g., ECB) and weak padding schemes (e.g., PKCS#1 v1.5) are not used. | **Pass** |  |
| 11.3.2 | Verify that only approved ciphers and modes such as AES with GCM are used. | **Pass** |  |
| 11.3.3 | Verify that encrypted data is protected against unauthorized modification preferably by using an approved authenticated encryption method or by combining an approved encryption method with an approved MAC algorithm. | **Pass** |  |
| 11.3.4 | Verify that nonces, initialization vectors, and other single-use numbers are not used for more than one encryption key and data-element pair. The method of generation must be appropriate for the algorithm being used. | **Pass** |  |
| 11.3.5 | Verify that any combination of an encryption algorithm and a MAC algorithm is operating in encrypt-then-MAC mode. | **Pass** |  |
| 11.4.1 | Verify that only approved hash functions are used for general cryptographic use cases, including digital signatures, HMAC, KDF, and random bit generation. Disallowed hash functions, such as MD5, must not be used for any cryptographic purpose. | **Pass** |  |
| 11.4.2 | Verify that passwords are stored using an approved, computationally intensive, key derivation function (also known as a "password hashing function"), with parameter settings configured based on current guidance. The settings should balance security and performance to make brute-force attacks sufficiently challenging for the required level of security. | **N/A** |  |
| 11.4.3 | Verify that hash functions used in digital signatures, as part of data authentication or data integrity are collision resistant and have appropriate bit-lengths. If collision resistance is required, the output length must be at least 256 bits. If only resistance to second pre-image attacks is required, the output length must be at least 128 bits. | **Pass** |  |
| 11.4.4 | Verify that the application uses approved key derivation functions with key stretching parameters when deriving secret keys from passwords. The parameters in use must balance security and performance to prevent brute-force attacks from compromising the resulting cryptographic key. | **N/A** |  |
| 11.5.1 | Verify that all random numbers and strings which are intended to be non-guessable must be generated using a cryptographically secure pseudo-random number generator (CSPRNG) and have at least 128 bits of entropy. Note that UUIDs do not respect this condition. | **Pass** |  |
| 11.5.2 | Verify that the random number generation mechanism in use is designed to work securely, even under heavy demand. | **Pass** |  |
| 11.6.1 | Verify that only approved cryptographic algorithms and modes of operation are used for key generation and seeding, and digital signature generation and verification. Key generation algorithms must not generate insecure keys vulnerable to known attacks, for example, RSA keys which are vulnerable to Fermat factorization. | **Pass** |  |
| 11.6.2 | Verify that approved cryptographic algorithms are used for key exchange (such as Diffie-Hellman) with a focus on ensuring that key exchange mechanisms use secure parameters. This will prevent attacks on the key establishment process which could lead to adversary-in-the-middle attacks or cryptographic breaks. | **N/A** |  |
| 11.7.1 | Verify that full memory encryption is in use that protects sensitive data while it is in use, preventing access by unauthorized users or processes. | **N/A** |  |
| 11.7.2 | Verify that data minimization ensures the minimal amount of data is exposed during processing, and ensure that data is encrypted immediately after use or as soon as feasible. | **N/A** |  |
| **V12: Secure Communication** | | | |
| 12.1.1 | Verify that only the latest recommended versions of the TLS protocol are enabled, such as TLS 1.2 and TLS 1.3. The latest version of the TLS protocol must be the preferred option. | **Partial** | See FINDING-007 |
| 12.1.2 | Verify that only recommended cipher suites are enabled, with the strongest cipher suites set as preferred. L3 applications must only support cipher suites which provide forward secrecy. | **Pass** |  |
| 12.1.3 | Verify that the application validates that mTLS client certificates are trusted before using the certificate identity for authentication or authorization. | **Pass** |  |
| 12.1.4 | Verify that proper certification revocation, such as Online Certificate Status Protocol (OCSP) Stapling, is enabled and configured. | **Partial** | See FINDING-015 |
| 12.1.5 | Verify that Encrypted Client Hello (ECH) is enabled in the application's TLS settings to prevent exposure of sensitive metadata, such as the Server Name Indication (SNI), during TLS handshake processes. | **N/A** |  |
| 12.2.1 | Verify that TLS is used for all connectivity between a client and external facing, HTTP-based services, and does not fall back to insecure or unencrypted communications. | **Pass** |  |
| 12.2.2 | Verify that external facing services use publicly trusted TLS certificates. | **Pass** |  |
| 12.3.1 | Verify that an encrypted protocol such as TLS is used for all inbound and outbound connections to and from the application, including monitoring systems, management tools, remote access and SSH, middleware, databases, mainframes, partner systems, or external APIs. The server must not fall back to insecure or unencrypted protocols. | **Partial** | See FINDING-007 |
| 12.3.2 | Verify that TLS clients validate certificates received before communicating with a TLS server. | **Pass** |  |
| 12.3.3 | Verify that TLS or another appropriate transport encryption mechanism used for all connectivity between internal, HTTP-based services within the application, and does not fall back to insecure or unencrypted communications. | **Pass** |  |
| 12.3.4 | Verify that TLS connections between internal services use trusted certificates. Where internally generated or self-signed certificates are used, the consuming service must be configured to only trust specific internal CAs and specific self-signed certificates. | **Pass** |  |
| 12.3.5 | Verify that services communicating internally within a system (intra-service communications) use strong authentication to ensure that each endpoint is verified. Strong authentication methods, such as TLS client authentication, must be employed to ensure identity, using public-key infrastructure and mechanisms that are resistant to replay attacks. For microservice architectures, consider using a service mesh to simplify certificate management and enhance security. | **Partial** | See FINDING-008 |
| **V13: Configuration** | | | |
| 13.1.1 | Verify that all communication needs for the application are documented. This must include external services which the application relies upon and cases where an end user might be able to provide an external location to which the application will then connect. | **Partial** | See FINDING-010 |
| 13.1.2 | Verify that for each service the application uses, the documentation defines the maximum number of concurrent connections (e.g., connection pool limits) and how the application behaves when that limit is reached, including any fallback or recovery mechanisms, to prevent denial of service conditions. | **Partial** | See FINDING-011 |
| 13.1.3 | Verify that the application documentation defines resource‑management strategies for every external system or service it uses (e.g., databases, file handles, threads, HTTP connections). This should include resource‑release procedures, timeout settings, failure handling, and where retry logic is implemented, specifying retry limits, delays, and back‑off algorithms. For synchronous HTTP request–response operations it should mandate short timeouts and either disable retries or strictly limit retries to prevent cascading delays and resource exhaustion. | **Partial** | See FINDING-012 |
| 13.1.4 | Verify that the application's documentation defines the secrets that are critical for the security of the application and a schedule for rotating them, based on the organization's threat model and business requirements. | **Partial** | See FINDING-016 |
| 13.2.1 | Verify that communications between backend application components that don't support the application's standard user session mechanism, including APIs, middleware, and data layers, are authenticated. Authentication must use individual service accounts, short-term tokens, or certificate-based authentication and not unchanging credentials such as passwords, API keys, or shared accounts with privileged access. | **Pass** |  |
| 13.2.2 | Verify that communications between backend application components, including local or operating system services, APIs, middleware, and data layers, are performed with accounts assigned the least necessary privileges. | **Pass** |  |
| 13.2.3 | Verify that if a credential has to be used for service authentication, the credential being used by the consumer is not a default credential (e.g., root/root or admin/admin). | **Pass** |  |
| 13.2.4 | Verify that an allowlist is used to define the external resources or systems with which the application is permitted to communicate (e.g., for outbound requests, data loads, or file access). This allowlist can be implemented at the application layer, web server, firewall, or a combination of different layers. | **Pass** |  |
| 13.2.5 | Verify that the web or application server is configured with an allowlist of resources or systems to which the server can send requests or load data or files from. | **Pass** |  |
| 13.2.6 | Verify that where the application connects to separate services, it follows the documented configuration for each connection, such as maximum parallel connections, behavior when maximum allowed connections is reached, connection timeouts, and retry strategies. | **Pass** |  |
| 13.3.1 | Verify that a secrets management solution, such as a key vault, is used to securely create, store, control access to, and destroy backend secrets. These could include passwords, key material, integrations with databases and third-party systems, keys and seeds for time-based tokens, other internal secrets, and API keys. Secrets must not be included in application source code or included in build artifacts. For an L3 application, this must involve a hardware-backed solution such as an HSM. | **Pass** |  |
| 13.3.2 | Verify that access to secret assets adheres to the principle of least privilege. | **Pass** |  |
| 13.3.3 | Verify that all cryptographic operations are performed using an isolated security module (such as a vault or hardware security module) to securely manage and protect key material from exposure outside of the security module. | **Partial** | See FINDING-014 |
| 13.3.4 | Verify that secrets are configured to expire and be rotated based on the application's documentation. | **Pass** |  |
| 13.4.1 | Verify that the application is deployed either without any source control metadata, including the .git or .svn folders, or in a way that these folders are inaccessible both externally and to the application itself. | **N/A** |  |
| 13.4.2 | Verify that debug modes are disabled for all components in production environments to prevent exposure of debugging features and information leakage. | **Pass** | See FINDING-017 |
| 13.4.3 | Verify that web servers do not expose directory listings to clients unless explicitly intended. | **N/A** |  |
| 13.4.4 | Verify that using the HTTP TRACE method is not supported in production environments, to avoid potential information leakage. | **N/A** |  |
| 13.4.5 | Verify that documentation (such as for internal APIs) and monitoring endpoints are not exposed unless explicitly intended. | **N/A** |  |
| 13.4.6 | Verify that the application does not expose detailed version information of backend components. | **Partial** | See FINDING-013 |
| 13.4.7 | Verify that the web tier is configured to only serve files with specific file extensions to prevent unintentional information, configuration, and source code leakage. | **N/A** | See FINDING-018 |
| **V14: Data Protection** | | | |
| 14.1.1 | Verify that all sensitive data created and processed by the application has been identified and classified into protection levels. This includes data that is only encoded and therefore easily decoded, such as Base64 strings or the plaintext payload inside a JWT. Protection levels need to take into account any data protection and privacy regulations and standards which the application is required to comply with. | **Pass** |  |
| 14.1.2 | Verify that all sensitive data protection levels have a documented set of protection requirements. This must include (but not be limited to) requirements related to general encryption, integrity verification, retention, how the data is to be logged, access controls around sensitive data in logs, database-level encryption, privacy and privacy-enhancing technologies to be used, and other confidentiality requirements. | **Pass** |  |
| 14.2.1 | Verify that sensitive data is only sent to the server in the HTTP message body or header fields, and that the URL and query string do not contain sensitive information, such as an API key or session token. | **Pass** |  |
| 14.2.2 | Verify that the application prevents sensitive data from being cached in server components, such as load balancers and application caches, or ensures that the data is securely purged after use. | **Pass** |  |
| 14.2.3 | Verify that defined sensitive data is not sent to untrusted parties (e.g., user trackers) to prevent unwanted collection of data outside of the application's control. | **Pass** |  |
| 14.2.4 | Verify that controls around sensitive data related to encryption, integrity verification, retention, how the data is to be logged, access controls around sensitive data in logs, privacy and privacy-enhancing technologies, are implemented as defined in the documentation for the specific data's protection level. | **Pass** |  |
| 14.2.5 | Verify that caching mechanisms are configured to only cache responses which have the expected content type for that resource and do not contain sensitive, dynamic content. The web server should return a 404 or 302 response when a non-existent file is accessed rather than returning a different, valid file. This should prevent Web Cache Deception attacks. | **N/A** |  |
| 14.2.6 | Verify that the application only returns the minimum required sensitive data for the application's functionality. For example, only returning some of the digits of a credit card number and not the full number. If the complete data is required, it should be masked in the user interface unless the user specifically views it. | **Pass** |  |
| 14.2.7 | Verify that sensitive information is subject to data retention classification, ensuring that outdated or unnecessary data is deleted automatically, on a defined schedule, or as the situation requires. | **Pass** |  |
| 14.2.8 | Verify that sensitive information is removed from the metadata of user-submitted files unless storage is consented to by the user. | **N/A** |  |
| 14.3.1 | Verify that authenticated data is cleared from client storage, such as the browser DOM, after the client or session is terminated. The 'Clear-Site-Data' HTTP response header field may be able to help with this but the client-side should also be able to clear up if the server connection is not available when the session is terminated. | **N/A** |  |
| 14.3.2 | Verify that the application sets sufficient anti-caching HTTP response header fields (i.e., Cache-Control: no-store) so that sensitive data is not cached in browsers. | **N/A** |  |
| 14.3.3 | Verify that data stored in browser storage (such as localStorage, sessionStorage, IndexedDB, or cookies) does not contain sensitive data, with the exception of session tokens. | **N/A** |  |
| **V15: Secure Coding and Architecture** | | | |
| 15.1.1 | Verify that application documentation defines risk based remediation time frames for 3rd party component versions with vulnerabilities and for updating libraries in general, to minimize the risk from these components. | **N/A** |  |
| 15.1.2 | Verify that an inventory catalog, such as software bill of materials (SBOM), is maintained of all third-party libraries in use, including verifying that components come from pre-defined, trusted, and continually maintained repositories. | **Pass** |  |
| 15.1.3 | Verify that the application documentation identifies functionality which is time-consuming or resource-demanding. This must include how to prevent a loss of availability due to overusing this functionality and how to avoid a situation where building a response takes longer than the consumer's timeout. Potential defenses may include asynchronous processing, using queues, and limiting parallel processes per user and per application. | **Pass** |  |
| 15.1.4 | Verify that application documentation highlights third-party libraries which are considered to be "risky components". | **Pass** |  |
| 15.1.5 | Verify that application documentation highlights parts of the application where "dangerous functionality" is being used. | **Pass** |  |
| 15.2.1 | Verify that the application only contains components which have not breached the documented update and remediation time frames. | **N/A** |  |
| 15.2.2 | Verify that the application has implemented defenses against loss of availability due to functionality which is time-consuming or resource-demanding, based on the documented security decisions and strategies for this. | **Pass** |  |
| 15.2.3 | Verify that the production environment only includes functionality that is required for the application to function, and does not expose extraneous functionality such as test code, sample snippets, and development functionality. | **Pass** |  |
| 15.2.4 | Verify that third-party components and all of their transitive dependencies are included from the expected repository, whether internally owned or an external source, and that there is no risk of a dependency confusion attack. | **Pass** |  |
| 15.2.5 | Verify that the application implements additional protections around parts of the application which are documented as containing "dangerous functionality" or using third-party libraries considered to be "risky components". This could include techniques such as sandboxing, encapsulation, containerization or network level isolation to delay and deter attackers who compromise one part of an application from pivoting elsewhere in the application. | **Pass** |  |
| 15.3.1 | Verify that the application only returns the required subset of fields from a data object. For example, it should not return an entire data object, as some individual fields should not be accessible to users. | **Pass** |  |
| 15.3.2 | Verify that where the application backend makes calls to external URLs, it is configured to not follow redirects unless it is intended functionality. | **Pass** |  |
| 15.3.3 | Verify that the application has countermeasures to protect against mass assignment attacks by limiting allowed fields per controller and action, e.g., it is not possible to insert or update a field value when it was not intended to be part of that action. | **Pass** |  |
| 15.3.4 | Verify that all proxying and middleware components transfer the user's original IP address correctly using trusted data fields that cannot be manipulated by the end user, and the application and web server use this correct value for logging and security decisions such as rate limiting, taking into account that even the original IP address may not be reliable due to dynamic IPs, VPNs, or corporate firewalls. | **N/A** |  |
| 15.3.5 | Verify that the application explicitly ensures that variables are of the correct type and performs strict equality and comparator operations. This is to avoid type juggling or type confusion vulnerabilities caused by the application code making an assumption about a variable type. | **N/A** |  |
| 15.3.6 | Verify that JavaScript code is written in a way that prevents prototype pollution, for example, by using Set() or Map() instead of object literals. | **N/A** |  |
| 15.3.7 | Verify that the application has defenses against HTTP parameter pollution attacks, particularly if the application framework makes no distinction about the source of request parameters (query string, body parameters, cookies, or header fields). | **N/A** |  |
| 15.4.1 | Verify that shared objects in multi-threaded code (such as caches, files, or in-memory objects accessed by multiple threads) are accessed safely by using thread-safe types and synchronization mechanisms like locks or semaphores to avoid race conditions and data corruption. | **Pass** |  |
| 15.4.2 | Verify that checks on a resource's state, such as its existence or permissions, and the actions that depend on them are performed as a single atomic operation to prevent time-of-check to time-of-use (TOCTOU) race conditions. For example, checking if a file exists before opening it, or verifying a user’s access before granting it. | **N/A** |  |
| 15.4.3 | Verify that locks are used consistently to avoid threads getting stuck, whether by waiting on each other or retrying endlessly, and that locking logic stays within the code responsible for managing the resource to ensure locks cannot be inadvertently or maliciously modified by external classes or code. | **Pass** |  |
| 15.4.4 | Verify that resource allocation policies prevent thread starvation by ensuring fair access to resources, such as by leveraging thread pools, allowing lower-priority threads to proceed within a reasonable timeframe. | **Pass** |  |
| **V16: Security Logging and Error Handling** | | | |
| 16.1.1 | Verify that an inventory exists documenting the logging performed at each layer of the application's technology stack, what events are being logged, log formats, where that logging is stored, how it is used, how access to it is controlled, and for how long logs are kept. | **Pass** |  |
| 16.2.1 | Verify that each log entry includes necessary metadata (such as when, where, who, what) that would allow for a detailed investigation of the timeline when an event happens. | **Partial** | See FINDING-002 |
| 16.2.2 | Verify that time sources for all logging components are synchronized, and that timestamps in security event metadata use UTC or include an explicit time zone offset. UTC is recommended to ensure consistency across distributed systems and to prevent confusion during daylight saving time transitions. | **Partial** | See FINDING-003 |
| 16.2.3 | Verify that the application only stores or broadcasts logs to the files and services that are documented in the log inventory. | **Pass** |  |
| 16.2.4 | Verify that logs can be read and correlated by the log processor that is in use, preferably by using a common logging format. | **Pass** |  |
| 16.2.5 | Verify that when logging sensitive data, the application enforces logging based on the data's protection level. For example, it may not be allowed to log certain data, such as credentials or payment details. Other data, such as session tokens, may only be logged by being hashed or masked, either in full or partially. | **Partial** | See FINDING-001 |
| 16.3.1 | Verify that all authentication operations are logged, including successful and unsuccessful attempts. Additional metadata, such as the type of authentication or factors used, should also be collected. | **N/A** |  |
| 16.3.2 | Verify that failed authorization attempts are logged. For L3, this must include logging all authorization decisions, including logging when sensitive data is accessed (without logging the sensitive data itself). | **Partial** | See FINDING-004 |
| 16.3.3 | Verify that the application logs the security events that are defined in the documentation and also logs attempts to bypass the security controls, such as input validation, business logic, and anti-automation. | **N/A** |  |
| 16.3.4 | Verify that the application logs unexpected errors and security control failures such as backend TLS failures. | **Pass** |  |
| 16.4.1 | Verify that all logging components appropriately encode data to prevent log injection. | **Pass** |  |
| 16.4.2 | Verify that logs are protected from unauthorized access and cannot be modified. | **Partial** |  |
| 16.4.3 | Verify that logs are securely transmitted to a logically separate system for analysis, detection, alerting, and escalation. The aim is to ensure that if the application is breached, the logs are not compromised. | **N/A** |  |
| 16.5.1 | Verify that a generic message is returned to the consumer when an unexpected or security-sensitive error occurs, ensuring no exposure of sensitive internal system data such as stack traces, queries, secret keys, and tokens. | **Pass** |  |
| 16.5.2 | Verify that the application continues to operate securely when external resource access fails, for example, by using patterns such as circuit breakers or graceful degradation. | **Partial** | See FINDING-005 |
| 16.5.3 | Verify that the application fails gracefully and securely, including when an exception occurs, preventing fail-open conditions such as processing a transaction despite errors resulting from validation logic. | **Pass** |  |
| 16.5.4 | Verify that a "last resort" error handler is defined which will catch all unhandled exceptions. This is both to avoid losing error details that must go to log files and to ensure that an error does not take down the entire application process, leading to a loss of availability. | **Partial** | See FINDING-006 |
| **V17: WebRTC** | | | |
| 17.1.1 | Verify that the Traversal Using Relays around NAT (TURN) service only allows access to IP addresses that are not reserved for special purposes (e.g., internal networks, broadcast, loopback). Note that this applies to both IPv4 and IPv6 addresses. | **N/A** |  |
| 17.1.2 | Verify that the Traversal Using Relays around NAT (TURN) service is not susceptible to resource exhaustion when legitimate users attempt to open a large number of ports on the TURN server. | **N/A** |  |
| 17.2.1 | Verify that the key for the Datagram Transport Layer Security (DTLS) certificate is managed and protected based on the documented policy for management of cryptographic keys. | **N/A** |  |
| 17.2.2 | Verify that the media server is configured to use and support approved Datagram Transport Layer Security (DTLS) cipher suites and a secure protection profile for the DTLS Extension for establishing keys for the Secure Real-time Transport Protocol (DTLS-SRTP). | **N/A** |  |
| 17.2.3 | Verify that Secure Real-time Transport Protocol (SRTP) authentication is checked at the media server to prevent Real-time Transport Protocol (RTP) injection attacks from leading to either a Denial of Service condition or audio or video media insertion into media streams. | **N/A** |  |
| 17.2.4 | Verify that the media server is able to continue processing incoming media traffic when encountering malformed Secure Real-time Transport Protocol (SRTP) packets. | **N/A** |  |
| 17.2.5 | Verify that the media server is able to continue processing incoming media traffic during a flood of Secure Real-time Transport Protocol (SRTP) packets from legitimate users. | **N/A** |  |
| 17.2.6 | Verify that the media server is not susceptible to the "ClientHello" Race Condition vulnerability in Datagram Transport Layer Security (DTLS) by checking if the media server is publicly known to be vulnerable or by performing the race condition test. | **N/A** |  |
| 17.2.7 | Verify that any audio or video recording mechanisms associated with the media server are able to continue processing incoming media traffic during a flood of Secure Real-time Transport Protocol (SRTP) packets from legitimate users. | **N/A** |  |
| 17.2.8 | Verify that the Datagram Transport Layer Security (DTLS) certificate is checked against the Session Description Protocol (SDP) fingerprint attribute, terminating the media stream if the check fails, to ensure the authenticity of the media stream. | **N/A** |  |
| 17.3.1 | Verify that the signaling server is able to continue processing legitimate incoming signaling messages during a flood attack. This should be achieved by implementing rate limiting at the signaling level. | **N/A** |  |
| 17.3.2 | Verify that the signaling server is able to continue processing legitimate signaling messages when encountering malformed signaling message that could cause a denial of service condition. This could include implementing input validation, safely handling integer overflows, preventing buffer overflows, and employing other robust error-handling techniques. | **N/A** |  |

**Summary Statistics:**
- **Pass**: 125 requirements (36.2%)
- **Partial**: 18 requirements (5.2%)
- **N/A**: 202 requirements (58.6%)
- **Fail**: 0 requirements (0.0%)

---

# 6. Cross-Reference Matrix

| Finding ID | Severity | ASVS Requirements | Related Findings | Affected Components |
|------------|----------|-------------------|------------------|---------------------|
| FINDING-001 | Low | 16.2.5 | — | task-sdk/src/airflow/sdk/log.py |
| FINDING-002 | Low | 16.2.1 | — | task-sdk/src/airflow/sdk/log.py |
| FINDING-003 | Low | 16.2.2 | — | task-sdk/src/airflow/sdk/log.py |
| FINDING-004 | Low | 16.3.2 | — | task-sdk/src/airflow/sdk/log.py, task-sdk/src/airflow/sdk/execution_time/sentry/configured.py |
| FINDING-005 | Low | 16.5.2 | — | task-sdk/src/airflow/sdk/log.py |
| FINDING-006 | Low | 16.5.4 | — | task-sdk/src/airflow/sdk/execution_time/sentry/configured.py |
| FINDING-007 | Low | 12.1.1, 12.3.1 | — | task-sdk/src/airflow/sdk/api/client.py |
| FINDING-008 | Low | 12.3.5 | — | task-sdk/src/airflow/sdk/api/client.py |
| FINDING-009 | Low | 11.2.2 | — | task-sdk/src/airflow/sdk/crypto.py |
| FINDING-010 | Low | 13.1.1 | — | task-sdk/src/airflow/sdk/api/client.py, task-sdk/src/airflow/sdk/execution_time/supervisor.py |
| FINDING-011 | Low | 13.1.2 | — | task-sdk/src/airflow/sdk/execution_time/supervisor.py, task-sdk/src/airflow/sdk/api/client.py |
| FINDING-012 | Low | 13.1.3 | — | task-sdk/src/airflow/sdk/api/client.py, task-sdk/src/airflow/sdk/execution_time/supervisor.py |
| FINDING-013 | Low | 13.4.6 | — | task-sdk/src/airflow/sdk/api/client.py |
| FINDING-014 | Informational | 13.3.3 | — | task-sdk/src/airflow/sdk/crypto.py |
| FINDING-015 | Informational | 12.1.4 | — | task-sdk/src/airflow/sdk/api/client.py |
| FINDING-016 | Informational | 13.1.4 | — | task-sdk/src/airflow/sdk/api/client.py, task-sdk/src/airflow/sdk/execution_time/supervisor.py |
| FINDING-017 | Informational | 13.4.2 | — | task-sdk/src/airflow/sdk/api/client.py, task-sdk/src/airflow/sdk/execution_time/supervisor.py |
| FINDING-018 | Informational | 13.4.7 | — | task-sdk/src/airflow/sdk/api/client.py, task-sdk/src/airflow/sdk/execution_time/supervisor.py |
| FINDING-019 | Informational | 10.3.1 | — | client.py |
| FINDING-020 | Informational | 10.3.2 | — | — |

**Total Unique Findings**: 20 (0 Critical, 0 High, 0 Medium, 13 Low, 7 Info)

*13 of 20 are actionable. Informational findings are recorded here but not opened as GitHub issues; see issues.md for the 13 actionable items.*

## 7. Level Coverage Analysis


**Audit scope:** up to L3

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 1 |
| L2 | 183 | 11 |
| L3 | 92 | 11 |

**Total consolidated findings: 20**

*End of Consolidated Security Audit Report*