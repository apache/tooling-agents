# Security Issues

---

## Issue: FINDING-001 - JWTValidator Does Not Check Token Revocation During Validation

**Labels:** bug, security, priority:high

**Description:**

### Summary
The JWTValidator.avalidated_claims() method performs cryptographic and claim validation but does not check RevokedToken.is_revoked(jti). A revoked token continues to pass validation until its natural exp time.

### Details
- **CWE:** CWE-613
- **ASVS:** 7.4.1 (L1)
- **Severity:** Medium
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/auth/tokens.py`
  - `airflow-core/src/airflow/models/revoked_token.py`

The revocation infrastructure exists (RevokedToken model, revoke_token method) but is not integrated into the validation path. While resolve_user_from_token (not in analyzed files) may perform this check separately, the validator itself should enforce revocation to ensure consistent protection regardless of calling code patterns.

### Remediation
Add RevokedToken.is_revoked(jti) check within avalidated_claims() to ensure revoked tokens are consistently rejected regardless of calling code patterns.

### Acceptance Criteria
- [ ] Fixed: RevokedToken.is_revoked(jti) check added to avalidated_claims()
- [ ] Test added: Verify revoked tokens are rejected during validation
- [ ] Test added: Verify valid tokens continue to pass validation

### References
- Related findings: FINDING-003, FINDING-004
- Source reports: 7.4.1.md

### Priority
**High** - Session management control bypass allowing use of revoked credentials

---

## Issue: FINDING-002 - Bulk Create with Overwrite Does Not Look Up Existing Resource Team Context

**Labels:** bug, security, priority:high

**Description:**

### Summary
When action_on_existence=overwrite is specified for a CREATE action, the authorization code adds a PUT method check but the team lookup explicitly excludes CREATE entities. A user can overwrite team-restricted resources without proper authorization.

### Details
- **CWE:** CWE-863
- **ASVS:** 8.2.2 (L1)
- **Severity:** Medium
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/core_api/security.py`

The PUT authorization check runs with team_name=None instead of the existing resource's actual team. A user not belonging to 'team-A' could overwrite a pool/connection/variable belonging to 'team-A' by using the bulk API with action_on_existence=overwrite, bypassing the team membership check that the single-item PUT endpoint enforces.

### Remediation
Include action_on_existence=overwrite entities in the team name lookup for requires_access_pool_bulk(), requires_access_connection_bulk(), and requires_access_variable_bulk(). This aligns bulk behavior with single-item PUT authorization.

### Acceptance Criteria
- [ ] Fixed: Team lookup includes overwrite entities in bulk operations
- [ ] Test added: Verify cross-team overwrite is blocked
- [ ] Test added: Verify same-team overwrite is allowed
- [ ] Test added: Verify single-item PUT behavior remains unchanged

### References
- Source reports: 8.2.2.md

### Priority
**High** - Authorization bypass allowing unauthorized modification of team-restricted resources

---

## Issue: FINDING-003 - No bulk token revocation mechanism for user-level factor invalidation

**Labels:** enhancement, security, priority:medium

**Description:**

### Summary
The BaseAuthManager interface and JWTValidator provide only single-token revocation that requires the caller to supply the actual token string. There is no mechanism to revoke all active tokens for a specific user.

### Details
- **CWE:** CWE-613
- **ASVS:** 6.5.6, 8.3.2 (L3)
- **Severity:** Low
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py`
  - `airflow-core/src/airflow/api_fastapi/auth/tokens.py`

There is no mechanism to revoke all active tokens for a specific user (e.g., revoke_all_tokens_for_user(user_id)), map tokens to users in the RevokedToken table, or invalidate a user's ability to use existing tokens without knowing each token's string. In a device-theft scenario, the legitimate account holder cannot independently invalidate tokens they don't possess.

### Remediation
Add a user-scoped revocation mechanism such as a token_issued_at_threshold per user — any token issued before this timestamp is considered revoked. Alternatively, store user_id alongside JTI in the RevokedToken table to enable bulk revocation.

### Acceptance Criteria
- [ ] Fixed: User-scoped revocation mechanism implemented
- [ ] Test added: Verify all user tokens can be revoked at once
- [ ] Test added: Verify revocation doesn't affect other users
- [ ] Documentation: User revocation API documented

### References
- Related findings: FINDING-001, FINDING-004
- Source reports: 6.5.6.md, 8.3.2.md

### Priority
**Medium** - L3 control for account compromise scenarios

---

## Issue: FINDING-004 - Previous Token Not Revoked During Token Refresh

**Labels:** bug, security, priority:medium

**Description:**

### Summary
The refresh middleware generates a new JWT without revoking the old token, creating a time window where both old and new tokens remain valid.

### Details
- **CWE:** CWE-613
- **ASVS:** 7.2.4 (L1)
- **Severity:** Low
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py`

Cookie overwrite ensures the browser transitions cleanly, and exploitation requires prior token extraction (e.g., XSS) with a window limited to jwt_expiration_time (default 3600s). However, this creates a time window where both old and new tokens remain valid.

### Remediation
Revoke the current token before issuing the new one during refresh: call get_jwt_validator().revoke_token(current_token) before generating new_token.

### Acceptance Criteria
- [ ] Fixed: Old token revoked before new token issued
- [ ] Test added: Verify old token is invalid after refresh
- [ ] Test added: Verify new token works after refresh
- [ ] Test added: Verify refresh still works with cookie overwrite

### References
- Related findings: FINDING-001, FINDING-003
- Source reports: 7.2.4.md

### Priority
**Medium** - Session management gap with limited exploitation window

---

## Issue: FINDING-005 - Inconsistent Configuration Keys Between Token Signer and Validator Audience

**Labels:** bug, security, priority:medium

**Description:**

### Summary
The token signer reads audience from [api] jwt_audience while the validator reads from [api_auth] jwt_audience. If configured differently, valid tokens are rejected OR audience validation is effectively bypassed.

### Details
- **CWE:** CWE-16
- **ASVS:** 10.3.1 (L2)
- **Severity:** Low
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py`

Both default to apache-airflow so out-of-the-box behavior is correct. However, configuration mismatch could lead to security bypass or denial of service.

### Remediation
Both signer and validator should read from the same configuration key (api_auth.jwt_audience) to prevent accidental mismatch.

### Acceptance Criteria
- [ ] Fixed: Unified configuration key for JWT audience
- [ ] Test added: Verify signer and validator use same audience
- [ ] Documentation: Configuration migration guide for existing deployments

### References
- Source reports: 10.3.1.md

### Priority
**Medium** - Configuration inconsistency risk

---

## Issue: FINDING-006 - Fernet encryption layer lacks algorithm agility and PQC migration path for data-at-rest protection

**Labels:** enhancement, security, priority:low

**Description:**

### Summary
The Fernet encryption layer used for data at rest uses a fixed cipher suite (AES-128-CBC + HMAC-SHA256) with no algorithm version indicator, configuration option for different algorithms, or migration path to post-quantum cryptography.

### Details
- **CWE:** N/A
- **ASVS:** 11.1.4, 11.2.2 (L2, L3)
- **Severity:** Low
- **Affected Files:**
  - `airflow-core/src/airflow/models/crypto.py`
  - `airflow-core/src/airflow/models/connection.py`
  - `airflow-core/src/airflow/models/variable.py`

This prevents both crypto agility for responding to cryptographic breaks and future migration to post-quantum cryptography standards. There is no mechanism to transition encrypted data to a different scheme without a complete re-encryption with a new implementation.

### Remediation
Introduce an encryption backend abstraction that supports algorithm selection and stores version metadata with encrypted data. Add algorithm versioning to encrypted data with version prefixes to enable gradual migration to new cryptographic standards including post-quantum cryptography. Document a migration path for transitioning existing encrypted data.

### Acceptance Criteria
- [ ] Fixed: Encryption backend abstraction implemented
- [ ] Fixed: Version metadata stored with encrypted data
- [ ] Documentation: Migration path for existing encrypted data
- [ ] Documentation: PQC readiness strategy

### References
- Source reports: 11.1.4.md, 11.2.2.md

### Priority
**Low** - L2/L3 future-proofing requirement

---

## Issue: FINDING-007 - LIKE wildcard characters not escaped in non-search filter parameters

**Labels:** bug, security, priority:low

**Description:**

### Summary
LIKE wildcard characters are not escaped in non-search filter parameters (_OwnersFilter, _AssetDependencyFilter, _ConsumingAssetFilter). An authenticated user can supply % or _ in filter parameters to broaden match results beyond the semantically intended filter behavior.

### Details
- **CWE:** CWE-943
- **ASVS:** 1.3.3 (L2)
- **Severity:** Low
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/common/parameters.py`

Results are still limited to what the user is authorized to see via RBAC. This is not SQL injection (SQLAlchemy uses parameterized queries) but allows pattern matching rather than literal substring matching.

### Remediation
Escape LIKE metacharacters (%, _) before wrapping with wildcards using SQLAlchemy's escape parameter on .ilike() calls in _OwnersFilter, _AssetDependencyFilter, and _ConsumingAssetFilter.

### Acceptance Criteria
- [ ] Fixed: LIKE wildcards escaped in all non-search filters
- [ ] Test added: Verify % and _ are treated as literals
- [ ] Test added: Verify search parameters still support wildcards
- [ ] Test added: Verify RBAC boundaries are respected

### References
- Source reports: 1.3.3.md

### Priority
**Low** - Information disclosure limited by RBAC

---

## Issue: FINDING-008 - ILIKE Filters Do Not Escape SQL Wildcard Metacharacters in Non-Search-Param Contexts

**Labels:** bug, security, priority:low

**Description:**

### Summary
Several filter classes embed user-supplied input directly into ILIKE patterns without escaping SQL wildcard metacharacters (%, _). While _SearchParam explicitly documents wildcard support, these filter classes don't document this behavior and appear to intend substring matching only.

### Details
- **CWE:** CWE-20
- **ASVS:** 2.2.1 (L1)
- **Severity:** Low
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/common/parameters.py`

This is NOT SQL injection — SQLAlchemy uses parameterized queries. However, a user providing % or _ in these filter values would trigger pattern matching rather than literal substring matching. Affected classes: _OwnersFilter, _AssetDependencyFilter, _ConsumingAssetFilter.

### Remediation
Escape SQL wildcards in user input before embedding in ILIKE patterns using a helper function like _escape_like.

### Acceptance Criteria
- [ ] Fixed: SQL wildcards escaped in affected filter classes
- [ ] Test added: Verify % treated as literal character
- [ ] Test added: Verify _ treated as literal character
- [ ] Test added: Verify search parameters remain unaffected

### References
- Source reports: 2.2.1.md

### Priority
**Low** - Input validation gap with limited security impact

---

## Issue: FINDING-009 - Cookie-Setting Code Not Observable in Provided Files — __Host- Prefix Cannot Be Verified

**Labels:** investigation, security, priority:low

**Description:**

### Summary
The init_middlewares() function registers JWTRefreshMiddleware which is responsible for setting/refreshing JWT cookies. However, the implementation is not in the provided files, meaning the presence or absence of the __Host- prefix cannot be verified.

### Details
- **CWE:** CWE-614
- **ASVS:** 3.3.3 (L2)
- **Severity:** Low
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/core_api/app.py`

The __Host- prefix prevents subdomain attacks by requiring cookies to be set with Secure, no Domain attribute, and Path=/. Without verification of the actual middleware implementation, compliance cannot be confirmed.

### Remediation
Verify that the JWTRefreshMiddleware implementation uses the __Host- prefix for session/JWT cookies to prevent subdomain attacks.

### Acceptance Criteria
- [ ] Investigation: Review JWTRefreshMiddleware implementation
- [ ] Fixed: Add __Host- prefix if missing
- [ ] Test added: Verify cookie attributes (Secure, Path, no Domain)
- [ ] Documentation: Cookie security configuration documented

### References
- Source reports: 3.3.3.md

### Priority
**Low** - Verification needed for L2 browser security control

---

## Issue: FINDING-010 - Login Redirect `next` Parameter Without Visible Allowlist Validation

**Labels:** bug, security, priority:medium

**Description:**

### Summary
The client-side code constructs a next parameter from the current browser location and passes it to the login endpoint. The getNextHref and getRedirectPath utility functions are not provided for review, so we cannot confirm whether they validate against an allowlist.

### Details
- **CWE:** CWE-601
- **ASVS:** 3.7.2 (L2)
- **Severity:** Low
- **Affected Files:**
  - `airflow-core/src/airflow/ui/src/main.tsx`

The actual post-login redirect logic (server-side) is not in the provided code files. An attacker could craft a URL that causes post-authentication redirect to a phishing page.

### Remediation
Ensure getNextHref validates the URL is relative or same-origin. Server-side should also validate the next parameter against allowed paths/origins before redirecting.

### Acceptance Criteria
- [ ] Investigation: Review getNextHref and getRedirectPath implementations
- [ ] Fixed: Client-side validation for relative/same-origin URLs
- [ ] Fixed: Server-side allowlist validation for next parameter
- [ ] Test added: Verify absolute external URLs are rejected
- [ ] Test added: Verify relative URLs are accepted

### References
- Source reports: 3.7.2.md

### Priority
**Medium** - Open redirect risk post-authentication

---

## Issue: FINDING-011 - ConnectionResponse returns login field unredacted — may expose API keys/tokens for connection types that store credentials in the login field

**Labels:** bug, security, priority:medium

**Description:**

### Summary
The ConnectionResponse model returns the login field without redaction. For connection types where providers store API keys or tokens in the login field, the credential value is returned verbatim in the API response.

### Details
- **CWE:** CWE-200
- **ASVS:** 14.2.6 (L3)
- **Severity:** Low
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/core_api/datamodels/connections.py`

Requires authenticated user with connection-read permission. Certain HTTP, GitHub, or token-based connections may store credentials in the login field rather than the password field.

### Remediation
Add conditional redaction for the login field in ConnectionResponse when the connection type is known to use tokens/API keys in that field, or when the value matches token-like patterns.

### Acceptance Criteria
- [ ] Fixed: Login field redacted for token-based connection types
- [ ] Test added: Verify redaction for known token-based types
- [ ] Test added: Verify non-sensitive login fields remain visible
- [ ] Documentation: List of connection types with login redaction

### References
- Source reports: 14.2.6.md

### Priority
**Medium** - Credential exposure to authenticated users

---

## Issue: FINDING-012 - Development Mode Code Path Present in Production Binary

**Labels:** bug, security, priority:low

**Description:**

### Summary
The DEV_MODE environment variable controls a code path that serves unminified development assets. If accidentally set to 'true' in production, development JavaScript with potential source maps could be served.

### Details
- **CWE:** CWE-489
- **ASVS:** 15.2.3 (L2)
- **Severity:** Low
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/core_api/app.py`

Default is secure (False). Risk is accidental misconfiguration, not active exploitation.

### Remediation
Consider logging a prominent warning when DEV_MODE is enabled, or rejecting it entirely when another signal indicates a production environment.

### Acceptance Criteria
- [ ] Fixed: Warning logged when DEV_MODE enabled
- [ ] Fixed: Optional production environment detection to block DEV_MODE
- [ ] Test added: Verify warning appears in logs
- [ ] Documentation: DEV_MODE security implications documented

### References
- Source reports: 15.2.3.md

### Priority
**Low** - Configuration safety improvement

---

## Issue: FINDING-013 - HTTP Access Log Missing Authenticated User Identity

**Labels:** enhancement, security, priority:medium

**Description:**

### Summary
The HTTP access log middleware logs network metadata (method, path, query, status, duration, client_addr) but does not capture authenticated user identity. Investigators cannot determine who made a specific HTTP request without correlating across log systems.

### Details
- **CWE:** N/A
- **ASVS:** 16.2.1 (L2)
- **Severity:** Low
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/common/http_access_log.py`

Correlation requires timestamp proximity matching which is imprecise and error-prone.

### Remediation
Extract user identity from request state after authentication middleware runs and add as a field to the structlog info call.

### Acceptance Criteria
- [ ] Fixed: User identity added to HTTP access logs
- [ ] Test added: Verify user identity present for authenticated requests
- [ ] Test added: Verify graceful handling for unauthenticated requests
- [ ] Documentation: Log format update documented

### References
- Source reports: 16.2.1.md

### Priority
**Medium** - Audit trail completeness for L2 compliance

---

## Issue: FINDING-014 - Audit Log (Database) Missing Client IP Address and Correlation ID

**Labels:** enhancement, security, priority:medium

**Description:**

### Summary
The audit log entries written to the database Log model do not include client IP address or request_id correlation ID. Correlating an HTTP access log entry with its corresponding audit log entry requires imprecise timestamp-based matching.

### Details
- **CWE:** N/A
- **ASVS:** 16.2.1, 16.2.4 (L2)
- **Severity:** Low
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/logging/decorators.py`
  - `airflow-core/src/airflow/models/log.py`

The Log model has no request_id column, and the action_logging decorator does not extract or store the request ID in the extra JSON field.

### Remediation
In action_logging decorator, capture client info from request.client and request_id from x-request-id header, adding both to extra_fields:
```python
request_id = request.headers.get('x-request-id')
if request_id:
    extra_fields['request_id'] = request_id
```

### Acceptance Criteria
- [ ] Fixed: Client IP added to audit logs
- [ ] Fixed: Request ID added to audit logs
- [ ] Test added: Verify correlation between HTTP and audit logs
- [ ] Documentation: Audit log format updated

### References
- Source reports: 16.2.1.md, 16.2.4.md

### Priority
**Medium** - Audit correlation for incident investigation

---

## Issue: FINDING-015 - HTTP Access Log Middleware Logs Query String Without Secret Masking

**Labels:** bug, security, priority:medium

**Description:**

### Summary
The HTTP access log middleware logs the raw query string without applying secrets_masker.redact(). A secret inadvertently passed as a query parameter would be logged in plaintext.

### Details
- **CWE:** N/A
- **ASVS:** 16.2.5 (L2)
- **Severity:** Low
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/common/http_access_log.py`

The secrets_masker control exists and is extensively used in the audit logging layer (decorators.py), but is NOT applied to the query string in the HTTP access log middleware.

### Remediation
Apply secrets_masker.redact() to the query string before logging in HttpAccessLogMiddleware.

### Acceptance Criteria
- [ ] Fixed: secrets_masker.redact() applied to query strings
- [ ] Test added: Verify secrets in query params are masked
- [ ] Test added: Verify non-secret params remain visible
- [ ] Documentation: Secret masking patterns documented

### References
- Source reports: 16.2.5.md

### Priority
**Medium** - Secret exposure in logs

---

## Issue: FINDING-016 - Audit Log Does Not Explicitly Record Authorization Decision Outcome

**Labels:** enhancement, security, priority:low

**Description:**

### Summary
The action_logging decorator logs the user's attempted action and commits before the endpoint handler completes, meaning it captures the attempt but does not record whether authorization was granted or denied.

### Details
- **CWE:** N/A
- **ASVS:** 16.3.2 (L2)
- **Severity:** Low
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/logging/decorators.py`

Authorization failures produce a 403 status in the HTTP access log, but the semantic audit trail does not include an authorization decision field.

### Remediation
Enhance the action_logging pattern to capture a post-execution callback that records whether the operation succeeded (200) or was denied (403/404), enriching the audit trail without requiring cross-source correlation.

### Acceptance Criteria
- [ ] Fixed: Authorization outcome recorded in audit log
- [ ] Test added: Verify success/denial outcome captured
- [ ] Test added: Verify correlation with HTTP status
- [ ] Documentation: Audit log schema updated

### References
- Source reports: 16.3.2.md

### Priority
**Low** - Audit trail enrichment for L2 compliance

---

## Issue: FINDING-017 - No Explicit Logging of Input Validation or Anti-Automation Bypass Attempts

**Labels:** enhancement, security, priority:low

**Description:**

### Summary
The logging infrastructure captures defined security events and all HTTP requests, but there is no explicit mechanism to log bypass attempts with semantic context about what security control was triggered.

### Details
- **CWE:** N/A
- **ASVS:** 16.3.3 (L2)
- **Severity:** Low
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/logging/decorators.py`
  - `airflow-core/src/airflow/api_fastapi/common/http_access_log.py`

4xx HTTP responses are visible in the access log but without enrichment about the nature of the validation failure.

### Remediation
Add semantic event logging for input validation failures at the API layer, e.g., by emitting structured log events when Pydantic validation rejects input or when business logic denies an operation.

### Acceptance Criteria
- [ ] Fixed: Validation failure events logged with context
- [ ] Test added: Verify Pydantic validation failures are logged
- [ ] Test added: Verify business rule violations are logged
- [ ] Documentation: Security event types documented

### References
- Source reports: 16.3.3.md

### Priority
**Low** - Security monitoring enhancement

---

## Issue: FINDING-018 - User-Controlled Input Passed to Standard Logger Without Encoding

**Labels:** bug, security, priority:medium

**Description:**

### Summary
The logger.exception() call passes a user-controlled query parameter (logical_date_value) directly to Python's standard logging module via %s format substitution. If a non-JSON log handler is configured, newline characters could inject fake log entries.

### Details
- **CWE:** N/A
- **ASVS:** 16.4.1 (L2)
- **Severity:** Low
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/logging/decorators.py`

Only exploitable with non-default plaintext formatters. Default structured logging is not vulnerable.

### Remediation
Use structlog instead of standard logging for this call, or sanitize the value by replacing newline/carriage-return characters before logging.

### Acceptance Criteria
- [ ] Fixed: User input sanitized before logging
- [ ] Test added: Verify newlines don't create fake log entries
- [ ] Test added: Verify legitimate values still logged correctly
- [ ] Documentation: Log injection prevention documented

### References
- Source reports: 16.4.1.md

### Priority
**Medium** - Log injection with non-default configuration

---

## Issue: FINDING-019 - Finally Block in HTTP Middleware Lacks Exception Protection for Logging Failures

**Labels:** bug, security, priority:low

**Description:**

### Summary
The finally block in HttpAccessLogMiddleware does not wrap the logger.info() call in try/except. If logger.info() raises and the original try block also raised, Python's exception replacement semantics would cause the original application exception to be lost.

### Details
- **CWE:** N/A
- **ASVS:** 16.5.2, 16.5.4 (L2, L3)
- **Severity:** Low
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/common/http_access_log.py`

This affects both continued operation when logging infrastructure fails (16.5.2) and preservation of original exception details for last-resort handlers (16.5.4). Impact is minimal as the HTTP response has already been sent to the client.

### Remediation
Wrap the logging call in the finally block with try/except to ensure logging failures never disrupt the application or mask original exceptions.

### Acceptance Criteria
- [ ] Fixed: Logging call wrapped in try/except in finally block
- [ ] Test added: Verify logging failure doesn't mask original exception
- [ ] Test added: Verify application continues on logging failure
- [ ] Test added: Verify successful logging still works

### References
- Source reports: 16.5.2.md, 16.5.4.md

### Priority
**Low** - Exception handling robustness

---

## Issue: FINDING-020 - Connection Pool Limits and Exhaustion Behavior Not Formally Defined Per Service

**Labels:** documentation, security, priority:low

**Description:**

### Summary
The scheduler documentation acknowledges database connection exhaustion as a known problem and recommends PGBouncer, but does not formally define the maximum number of concurrent connections per service, nor specify fallback/recovery behavior when limits are reached.

### Details
- **CWE:** CWE-770
- **ASVS:** 13.1.2 (L3)
- **Severity:** Low
- **Affected Files:**
  - `airflow-core/docs/administration-and-deployment/scheduler.rst`

ASVS 13.1.2 requires this to be documented for each service.

### Remediation
Add connection pool documentation for each service specifying default pool size, maximum overflow, behavior at limit, and recovery mechanisms.

### Acceptance Criteria
- [ ] Documentation: Connection pool limits per service documented
- [ ] Documentation: Exhaustion behavior documented
- [ ] Documentation: Recovery mechanisms documented
- [ ] Documentation: PGBouncer configuration guidance

### References
- Source reports: 13.1.2.md

### Priority
**Low** - L3 documentation requirement

---

## Issue: FINDING-021 - Resource Management Strategies Not Formally Documented With Required Detail

**Labels:** documentation, security, priority:low

**Description:**

### Summary
While the codebase implements various resource management mechanisms (retry logic, timeouts, connection pooling), the documentation does not formally define resource-management strategies for every external system as required by ASVS 13.1.3.

### Details
- **CWE:** CWE-400
- **ASVS:** 13.1.3 (L3)
- **Severity:** Low
- **Affected Files:**
  - `airflow-core/docs/administration-and-deployment/scheduler.rst`
  - `airflow-core/src/airflow/executors/base_executor.py`

The documentation lacks formal specification of: resource-release procedures, timeout settings, failure handling, retry limits/delays/back-off algorithms, and short timeout mandates for synchronous HTTP operations.

### Remediation
Create a formal resource management strategy document covering metadata database, execution API, and message broker with explicit specification of connection pool limits, timeout settings, retry algorithms, and failure behavior.

### Acceptance Criteria
- [ ] Documentation: Resource management strategy document created
- [ ] Documentation: Timeout settings documented per external system
- [ ] Documentation: Retry algorithms documented
- [ ] Documentation: Failure handling procedures documented

### References
- Related findings: FINDING-023
- Source reports: 13.1.3.md

### Priority
**Low** - L3 documentation requirement

---

## Issue: FINDING-022 - No Formal Secrets Inventory or Rotation Schedule Documented

**Labels:** documentation, security, priority:medium

**Description:**

### Summary
The codebase references multiple security-critical secrets (JWT signing keys, database credentials, broker URLs) but no formal secrets inventory or rotation schedule is documented in the provided files.

### Details
- **CWE:** CWE-320
- **ASVS:** 13.1.4 (L3)
- **Severity:** Low
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/execution_api/app.py`
  - `airflow-core/src/airflow/executors/base_executor.py`

ASVS 13.1.4 requires documentation defining which secrets are critical and a rotation schedule based on threat model.

### Remediation
Create a secrets management document listing all security-critical secrets, their storage locations, rotation procedures, and recommended rotation schedules covering JWT signing keys, Fernet keys, database credentials, and broker credentials.

### Acceptance Criteria
- [ ] Documentation: Secrets inventory created
- [ ] Documentation: Rotation schedules defined per secret type
- [ ] Documentation: Rotation procedures documented
- [ ] Documentation: Threat model considerations documented

### References
- Source reports: 13.1.4.md

### Priority
**Medium** - L3 secrets management requirement

---

## Issue: FINDING-023 - Base Executor Lacks Explicit HTTP Connection Parameters for Execution API Communication

**Labels:** bug, security, priority:medium

**Description:**

### Summary
The base executor's run_workload() function connects to the execution API server without explicit connection timeout, max connection, or retry configuration visible at this layer. Workers may hang indefinitely if the execution API is slow or unresponsive.

### Details
- **CWE:** CWE-400
- **ASVS:** 13.2.6 (L3)
- **Severity:** Low
- **Affected Files:**
  - `airflow-core/src/airflow/executors/base_executor.py`

If the execution API is slow or unresponsive, workers may hang indefinitely without documented timeout behavior, potentially exhausting available worker slots.

### Remediation
Document and enforce connection parameters in the executor configuration including connection_timeout, max_retries, and pool_connections settings.

### Acceptance Criteria
- [ ] Fixed: Explicit connection parameters added to executor
- [ ] Test added: Verify timeout prevents indefinite hangs
- [ ] Test added: Verify retry behavior on transient failures
- [ ] Documentation: Connection parameters documented

### References
- Related findings: FINDING-021
- Source reports: 13.2.6.md

### Priority
**Medium** - Resource exhaustion prevention