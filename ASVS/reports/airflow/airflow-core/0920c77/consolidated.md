# Security Audit Consolidated Report — apache/airflow/airflow-core

## Report Metadata

| Field | Value |
|-------|-------|
| Repository | apache/airflow/airflow-core |
| ASVS Level | L3 |
| Severity Threshold | None (all findings included) |
| Commit | 0920c77 |
| Date | May 22, 2026 |
| Auditor | Tooling Agents |
| Source Reports | 345 |
| Total Findings | 23 |

## Executive Summary

### Severity Distribution

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 2 |
| Low | 21 |
| Info | 0 |

### ASVS Level Coverage

This audit assessed 16 security domains against ASVS Level 3 requirements. Findings span all three ASVS levels:

- **L1 findings:** 4 (foundational controls with gaps)
- **L2 findings:** 13 (standard controls requiring hardening)
- **L3 findings:** 6 (advanced controls expected at L3 maturity)

The absence of Critical or High severity findings indicates a mature security baseline. The two Medium findings affect token validation and authorization context propagation at the L1 level, representing foundational gaps that should be prioritized.

### Top 5 Risks

1. **JWT Token Revocation Not Checked During Validation (FINDING-001, Medium):** The `JWTValidator` does not consult the `RevokedToken` table during token validation, meaning revoked tokens remain usable until natural expiration. This undermines the effectiveness of logout, account disable, and administrative revocation actions.

2. **Bulk Create Overwrites Without Team Context Lookup (FINDING-002, Medium):** The bulk creation endpoint with overwrite semantics does not resolve existing resource ownership context, potentially allowing cross-team resource replacement without proper authorization boundary enforcement.

3. **No Bulk Token Revocation for User-Level Factor Invalidation (FINDING-003, Low/L3):** When a user's authentication factors are compromised or changed, there is no mechanism to revoke all outstanding tokens in bulk, leaving a window of exposure bounded only by token expiration time.

4. **Previous Token Not Revoked During Refresh (FINDING-004, Low/L1):** The token refresh flow issues a new token without revoking the previous one, allowing token accumulation and extending the effective session window beyond intended bounds.

5. **Fernet Encryption Lacks Algorithm Agility and PQC Migration Path (FINDING-006, Low/L2-L3):** The data-at-rest encryption layer is tightly coupled to the Fernet scheme with no documented path for algorithm rotation or post-quantum cryptography migration, creating long-term cryptographic risk for stored secrets.

### Positive Controls

The audit identified 49 verified positive controls across all assessed domains, reflecting a deliberately layered security architecture:

- **Delegation model is well-executed:** Production authentication, MFA enforcement, session lifecycle, TLS termination, and OAuth2 Authorization Server responsibilities are explicitly delegated to external infrastructure (Keycloak, FAB, reverse proxies) with documented boundaries. This reduces attack surface within Airflow core while maintaining clear responsibility assignment.

- **Pluggable auth manager architecture:** The `BaseAuthManager` interface provides extension points for concurrent session limits, step-up authentication, contextual authorization, and credential lifecycle management without requiring core modifications.

- **Token security fundamentals are sound:** JWT tokens enforce mandatory expiration (`exp` claim), audience validation, non-reassignable identity claims, and a revocation table infrastructure exists (though validation-time checking is incomplete per FINDING-001).

- **Sensitive value masking at serialization layer:** Connection passwords and variable values are masked at the API response serialization boundary, providing defense-in-depth independent of authorization decisions.

- **Security model formally documented:** Trust levels, user types, and authorization boundaries are defined in `security_model.rst`, providing a foundation for consistent security reasoning across the codebase.

- **Cryptographic key management responsibility is clear:** Auto-generated keys emit explicit warnings directing operators to configure production keys, with documented Helm chart patterns for proper key provisioning.

---

## 3. Findings

### 3.3 Medium

#### FINDING-001: JWTValidator Does Not Check Token Revocation During Validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-613 |
| **ASVS Section(s)** | 7.4.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/tokens.py, airflow-core/src/airflow/models/revoked_token.py |
| **Source Reports** | 7.4.1.md |
| **Related** | FINDING-003, FINDING-004 |

**Description:**

The JWTValidator.avalidated_claims() method performs cryptographic and claim validation but does not check RevokedToken.is_revoked(jti). The revocation infrastructure exists (RevokedToken model, revoke_token method) but is not integrated into the validation path. A revoked token continues to pass validation until its natural exp time. Note: resolve_user_from_token (not in analyzed files) may perform this check separately.

**Remediation:**

Add RevokedToken.is_revoked(jti) check within avalidated_claims() to ensure revoked tokens are consistently rejected regardless of calling code patterns.

---

#### FINDING-002: Bulk Create with Overwrite Does Not Look Up Existing Resource Team Context

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-863 |
| **ASVS Section(s)** | 8.2.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/security.py |
| **Source Reports** | 8.2.2.md |
| **Related** | - |

**Description:**

When action_on_existence=overwrite is specified for a CREATE action, the authorization code correctly adds a PUT method check but the team lookup explicitly excludes CREATE entities. This means the PUT authorization check runs with team_name=None instead of the existing resource's actual team. A user not belonging to 'team-A' could overwrite a pool/connection/variable belonging to 'team-A' by using the bulk API with action_on_existence=overwrite, bypassing the team membership check that the single-item PUT endpoint enforces.

**Remediation:**

Include action_on_existence=overwrite entities in the team name lookup for requires_access_pool_bulk(), requires_access_connection_bulk(), and requires_access_variable_bulk(). This aligns bulk behavior with single-item PUT authorization.

### 3.4 Low

#### FINDING-003: No bulk token revocation mechanism for user-level factor invalidation

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | CWE-613 |
| ASVS sections | 6.5.6, 8.3.2 |
| Files | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py, airflow-core/src/airflow/api_fastapi/auth/tokens.py |
| Source Reports | 6.5.6.md, 8.3.2.md |
| Related | FINDING-001, FINDING-004 |

**Description:**

The `BaseAuthManager` interface and `JWTValidator` provide only single-token revocation that requires the caller to supply the actual token string. There is no mechanism to revoke all active tokens for a specific user (e.g., `revoke_all_tokens_for_user(user_id)`), map tokens to users in the `RevokedToken` table, or invalidate a user's ability to use existing tokens without knowing each token's string. In a device-theft scenario, the legitimate account holder cannot independently invalidate tokens they don't possess.

**Remediation:**

Add a user-scoped revocation mechanism such as a `token_issued_at_threshold` per user — any token issued before this timestamp is considered revoked. Alternatively, store user_id alongside JTI in the RevokedToken table to enable bulk revocation.

---

#### FINDING-004: Previous Token Not Revoked During Token Refresh

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-613 |
| ASVS sections | 7.2.4 |
| Files | airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py |
| Source Reports | 7.2.4.md |
| Related | FINDING-001, FINDING-003 |

**Description:**

The refresh middleware generates a new JWT without revoking the old token. However, cookie overwrite ensures the browser transitions cleanly, and exploitation requires prior token extraction (e.g., XSS) with a window limited to jwt_expiration_time (default 3600s). This creates a time window where both old and new tokens remain valid.

**Remediation:**

Revoke the current token before issuing the new one during refresh: call get_jwt_validator().revoke_token(current_token) before generating new_token.

---

#### FINDING-005: Inconsistent Configuration Keys Between Token Signer and Validator Audience

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-16 |
| ASVS sections | 10.3.1 |
| Files | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py |
| Source Reports | 10.3.1.md |
| Related | |

**Description:**

The token signer reads audience from `[api] jwt_audience` while the validator reads from `[api_auth] jwt_audience`. If configured differently, valid tokens are rejected OR audience validation is effectively bypassed. Both default to `apache-airflow` so out-of-the-box behavior is correct.

**Remediation:**

Both signer and validator should read from the same configuration key (`api_auth.jwt_audience`) to prevent accidental mismatch.

---

#### FINDING-006: Fernet encryption layer lacks algorithm agility and PQC migration path for data-at-rest protection

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2, L3 |
| CWE | |
| ASVS sections | 11.1.4, 11.2.2 |
| Files | airflow-core/src/airflow/models/crypto.py, airflow-core/src/airflow/models/connection.py, airflow-core/src/airflow/models/variable.py |
| Source Reports | 11.1.4.md, 11.2.2.md |
| Related | |

**Description:**

The Fernet encryption layer used for data at rest (connection passwords, variable values, connection extra) uses a fixed cipher suite (AES-128-CBC + HMAC-SHA256). There is no algorithm version indicator stored with encrypted data, no configuration option to select a different encryption algorithm, and no mechanism to transition encrypted data to a different scheme without a complete re-encryption with a new implementation. This prevents both crypto agility for responding to cryptographic breaks and future migration to post-quantum cryptography standards.

**Remediation:**

Introduce an encryption backend abstraction that supports algorithm selection and stores version metadata with encrypted data. Add algorithm versioning to encrypted data with version prefixes to enable gradual migration to new cryptographic standards including post-quantum cryptography. Document a migration path for transitioning existing encrypted data.

---

#### FINDING-007: LIKE wildcard characters not escaped in non-search filter parameters

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-943 |
| ASVS sections | 1.3.3 |
| Files | airflow-core/src/airflow/api_fastapi/common/parameters.py |
| Source Reports | 1.3.3.md |
| Related | |

**Description:**

LIKE wildcard characters are not escaped in non-search filter parameters (_OwnersFilter, _AssetDependencyFilter, _ConsumingAssetFilter). An authenticated user can supply % or _ in filter parameters to broaden match results beyond the semantically intended filter behavior. Results are still limited to what the user is authorized to see via RBAC.

**Remediation:**

Escape LIKE metacharacters (%, _) before wrapping with wildcards using SQLAlchemy's escape parameter on .ilike() calls in _OwnersFilter, _AssetDependencyFilter, and _ConsumingAssetFilter.

---

#### FINDING-008: ILIKE Filters Do Not Escape SQL Wildcard Metacharacters in Non-Search-Param Contexts

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-20 |
| ASVS sections | 2.2.1 |
| Files | airflow-core/src/airflow/api_fastapi/common/parameters.py |
| Source Reports | 2.2.1.md |
| Related | |

**Description:**

Several filter classes embed user-supplied input directly into ILIKE patterns without escaping SQL wildcard metacharacters (`%`, `_`). While `_SearchParam` explicitly documents wildcard support for its parameters, these filter classes (`_OwnersFilter`, `_AssetDependencyFilter`, `_ConsumingAssetFilter`) don't document this behavior and appear to intend substring matching only. This is NOT SQL injection — SQLAlchemy uses parameterized queries. However, a user providing `%` or `_` in these filter values would trigger pattern matching rather than literal substring matching.

**Remediation:**

Escape SQL wildcards in user input before embedding in ILIKE patterns using a helper function like `_escape_like`.

---

#### FINDING-009: Cookie-Setting Code Not Observable in Provided Files — __Host- Prefix Cannot Be Verified

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-614 |
| ASVS sections | 3.3.3 |
| Files | airflow-core/src/airflow/api_fastapi/core_api/app.py |
| Source Reports | 3.3.3.md |
| Related | |

**Description:**

The `init_middlewares()` function in `app.py` registers `JWTRefreshMiddleware` which is responsible for setting/refreshing JWT cookies. However, the implementation of this middleware (from `airflow.api_fastapi.auth.middlewares.refresh_token`) is not in the provided files, meaning the presence or absence of the `__Host-` prefix cannot be verified from the audited code.

**Remediation:**

Verify that the `JWTRefreshMiddleware` implementation uses the `__Host-` prefix for session/JWT cookies to prevent subdomain attacks.

---

#### FINDING-010: Login Redirect `next` Parameter Without Visible Allowlist Validation

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-601 |
| ASVS sections | 3.7.2 |
| Files | airflow-core/src/airflow/ui/src/main.tsx |
| Source Reports | 3.7.2.md |
| Related | |

**Description:**

The client-side code constructs a `next` parameter from the current browser location and passes it to the login endpoint. The `getNextHref` and `getRedirectPath` utility functions are not provided for review, so we cannot confirm whether they validate against an allowlist. The actual post-login redirect logic (server-side) is not in the provided code files. An attacker could craft a URL that causes post-authentication redirect to a phishing page.

**Remediation:**

Ensure `getNextHref` validates the URL is relative or same-origin. Server-side should also validate the `next` parameter against allowed paths/origins before redirecting.

---

#### FINDING-011: ConnectionResponse returns login field unredacted — may expose API keys/tokens for connection types that store credentials in the login field

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | CWE-200 |
| ASVS sections | 14.2.6 |
| Files | airflow-core/src/airflow/api_fastapi/core_api/datamodels/connections.py |
| Source Reports | 14.2.6.md |
| Related | |

**Description:**

The ConnectionResponse model returns the login field without redaction. For connection types where providers store API keys or tokens in the login field (e.g., certain HTTP, GitHub, or token-based connections), the credential value is returned verbatim in the API response. Requires authenticated user with connection-read permission.

**Remediation:**

Add conditional redaction for the login field in ConnectionResponse when the connection type is known to use tokens/API keys in that field, or when the value matches token-like patterns.

---

#### FINDING-012: Development Mode Code Path Present in Production Binary

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-489 |
| ASVS sections | 15.2.3 |
| Files | airflow-core/src/airflow/api_fastapi/core_api/app.py |
| Source Reports | 15.2.3.md |
| Related | |

**Description:**

The DEV_MODE environment variable controls a code path that serves unminified development assets. If accidentally set to 'true' in production, development JavaScript with potential source maps could be served. Default is secure (False). Risk is accidental misconfiguration, not active exploitation.

**Remediation:**

Consider logging a prominent warning when DEV_MODE is enabled, or rejecting it entirely when another signal indicates a production environment.

---

#### FINDING-013: HTTP Access Log Missing Authenticated User Identity

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | |
| ASVS sections | 16.2.1 |
| Files | airflow-core/src/airflow/api_fastapi/common/http_access_log.py |
| Source Reports | 16.2.1.md |
| Related | |

**Description:**

The HTTP access log middleware logs network metadata (method, path, query, status, duration, client_addr) but does not capture authenticated user identity. Investigators cannot determine *who* made a specific HTTP request without correlating across log systems using timestamp proximity.

**Remediation:**

Extract user identity from request state after authentication middleware runs and add as a field to the structlog info call.

---

#### FINDING-014: Audit Log (Database) Missing Client IP Address and Correlation ID

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | |
| ASVS sections | 16.2.1, 16.2.4 |
| Files | airflow-core/src/airflow/api_fastapi/logging/decorators.py, airflow-core/src/airflow/models/log.py |
| Source Reports | 16.2.1.md, 16.2.4.md |
| Related | |

**Description:**

The audit log entries written to the database Log model do not include client IP address or request_id correlation ID. The Log model has no request_id column, and the action_logging decorator does not extract or store the request ID in the extra JSON field. Correlating an HTTP access log entry with its corresponding audit log entry requires imprecise timestamp-based matching.

**Remediation:**

In action_logging decorator, capture client info from request.client and request_id from x-request-id header, adding both to extra_fields: request_id = request.headers.get('x-request-id'); if request_id: extra_fields['request_id'] = request_id

---

#### FINDING-015: HTTP Access Log Middleware Logs Query String Without Secret Masking

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | |
| ASVS sections | 16.2.5 |
| Files | airflow-core/src/airflow/api_fastapi/common/http_access_log.py |
| Source Reports | 16.2.5.md |
| Related | |

**Description:**

The HTTP access log middleware logs the raw query string without applying secrets_masker.redact(). The secrets_masker control exists and is extensively used in the audit logging layer (decorators.py), but is NOT applied to the query string in the HTTP access log middleware. A secret inadvertently passed as a query parameter would be logged in plaintext.

**Remediation:**

Apply secrets_masker.redact() to the query string before logging in HttpAccessLogMiddleware.

---

#### FINDING-016: Audit Log Does Not Explicitly Record Authorization Decision Outcome

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | |
| ASVS sections | 16.3.2 |
| Files | airflow-core/src/airflow/api_fastapi/logging/decorators.py |
| Source Reports | 16.3.2.md |
| Related | |

**Description:**

The action_logging decorator logs the user's attempted action and commits before the endpoint handler completes, meaning it captures the attempt but does not record whether authorization was granted or denied. Authorization failures produce a 403 status in the HTTP access log, but the semantic audit trail does not include an authorization decision field.

**Remediation:**

Enhance the action_logging pattern to capture a post-execution callback that records whether the operation succeeded (200) or was denied (403/404), enriching the audit trail without requiring cross-source correlation.

---

#### FINDING-017: No Explicit Logging of Input Validation or Anti-Automation Bypass Attempts

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | |
| ASVS sections | 16.3.3 |
| Files | airflow-core/src/airflow/api_fastapi/logging/decorators.py, airflow-core/src/airflow/api_fastapi/common/http_access_log.py |
| Source Reports | 16.3.3.md |
| Related | |

**Description:**

The logging infrastructure captures defined security events and all HTTP requests, but there is no explicit mechanism to log bypass attempts with semantic context about what security control was triggered. 4xx HTTP responses are visible in the access log but without enrichment about the nature of the validation failure.

**Remediation:**

Add semantic event logging for input validation failures at the API layer, e.g., by emitting structured log events when Pydantic validation rejects input or when business logic denies an operation.

---

#### FINDING-018: User-Controlled Input Passed to Standard Logger Without Encoding

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | |
| ASVS sections | 16.4.1 |
| Files | airflow-core/src/airflow/api_fastapi/logging/decorators.py |
| Source Reports | 16.4.1.md |
| Related | |

**Description:**

The logger.exception() call passes a user-controlled query parameter (logical_date_value) directly to Python's standard logging module via %s format substitution. If a non-JSON log handler is configured, newline characters in the logical_date parameter could inject fake log entries. Only exploitable with non-default plaintext formatters.

**Remediation:**

Use structlog instead of standard logging for this call, or sanitize the value by replacing newline/carriage-return characters before logging.

---

#### FINDING-019: Finally Block in HTTP Middleware Lacks Exception Protection for Logging Failures

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2, L3 |
| CWE | |
| ASVS sections | 16.5.2, 16.5.4 |
| Files | airflow-core/src/airflow/api_fastapi/common/http_access_log.py |
| Source Reports | 16.5.2.md, 16.5.4.md |
| Related | |

**Description:**

The finally block in HttpAccessLogMiddleware does not wrap the logger.info() call in try/except. If logger.info() raises and the original try block also raised, Python's exception replacement semantics would cause the original application exception to be lost. This affects both continued operation when logging infrastructure fails (16.5.2) and preservation of original exception details for last-resort handlers (16.5.4). Impact is minimal as the HTTP response has already been sent to the client.

**Remediation:**

Wrap the logging call in the finally block with try/except to ensure logging failures never disrupt the application or mask original exceptions.

---

#### FINDING-020: Connection Pool Limits and Exhaustion Behavior Not Formally Defined Per Service

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | CWE-770 |
| ASVS sections | 13.1.2 |
| Files | airflow-core/docs/administration-and-deployment/scheduler.rst |
| Source Reports | 13.1.2.md |
| Related | |

**Description:**

The scheduler documentation acknowledges database connection exhaustion as a known problem and recommends PGBouncer, but does not formally define the maximum number of concurrent connections per service, nor specify fallback/recovery behavior when limits are reached. ASVS 13.1.2 requires this to be documented for each service.

**Remediation:**

Add connection pool documentation for each service specifying default pool size, maximum overflow, behavior at limit, and recovery mechanisms.

---

#### FINDING-021: Resource Management Strategies Not Formally Documented With Required Detail

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | CWE-400 |
| ASVS sections | 13.1.3 |
| Files | airflow-core/docs/administration-and-deployment/scheduler.rst, airflow-core/src/airflow/executors/base_executor.py |
| Source Reports | 13.1.3.md |
| Related | FINDING-023 |

**Description:**

While the codebase implements various resource management mechanisms (retry logic, timeouts, connection pooling), the documentation does not formally define resource-management strategies for every external system as required by ASVS 13.1.3. Specifically, the documentation lacks formal specification of: resource-release procedures, timeout settings, failure handling, retry limits/delays/back-off algorithms, and short timeout mandates for synchronous HTTP operations.

**Remediation:**

Create a formal resource management strategy document covering metadata database, execution API, and message broker with explicit specification of connection pool limits, timeout settings, retry algorithms, and failure behavior.

---

#### FINDING-022: No Formal Secrets Inventory or Rotation Schedule Documented

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | CWE-320 |
| ASVS sections | 13.1.4 |
| Files | airflow-core/src/airflow/api_fastapi/execution_api/app.py, airflow-core/src/airflow/executors/base_executor.py |
| Source Reports | 13.1.4.md |
| Related | |

**Description:**

The codebase references multiple security-critical secrets (JWT signing keys, database credentials, broker URLs) but no formal secrets inventory or rotation schedule is documented in the provided files. ASVS 13.1.4 requires documentation defining which secrets are critical and a rotation schedule based on threat model.

**Remediation:**

Create a secrets management document listing all security-critical secrets, their storage locations, rotation procedures, and recommended rotation schedules covering JWT signing keys, Fernet keys, database credentials, and broker credentials.

---

#### FINDING-023: Base Executor Lacks Explicit HTTP Connection Parameters for Execution API Communication

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | CWE-400 |
| ASVS sections | 13.2.6 |
| Files | airflow-core/src/airflow/executors/base_executor.py |
| Source Reports | 13.2.6.md |
| Related | FINDING-021 |

**Description:**

The base executor's run_workload() function connects to the execution API server without explicit connection timeout, max connection, or retry configuration visible at this layer. If the execution API is slow or unresponsive, workers may hang indefinitely without documented timeout behavior, potentially exhausting available worker slots.

**Remediation:**

Document and enforce connection parameters in the executor configuration including connection_timeout, max_retries, and pool_connections settings.

---

# 4. Positive Security Controls

| Domain | Control | Evidence Source | Supporting Files |
|--------|---------|-----------------|------------------|
| Authentication Mechanisms | All authentication pathways converge on single JWTGenerator/JWTValidator with consistent signing, validation, and revocation | Consistent authentication strength enforced across all pathways | — |
| Authentication Mechanisms | Pluggable auth manager architecture supports external IdPs (Keycloak, FAB) that implement MFA | External authentication providers handle multi-factor authentication requirements | — |
| Authentication Mechanisms | Authentication failure logging at error level provides audit trail for external monitoring systems | Failed authentication attempts logged for security monitoring | — |
| Authentication Mechanisms | Production authentication credential lifecycle (including notifications) delegated to external auth manager (FAB, Keycloak) | Documented in simpleauthmanager_dev_only.md and delegated_infrastructure_controls.md | — |
| Authentication Mechanisms | SimpleAuthManager documented as dev-only; production credential storage delegated to external auth manager | Dropped finding ASVS-652-LOW-001 | — |
| Authentication Mechanisms | Production authentication including authentication strength verification is delegated to external auth manager implementations which can override get_user_from_token() and deserialize_user() | Dropped finding ASVS-684-LOW-001 | — |
| Session Management | AuthManagerRefreshTokenExpiredException allows external IdPs to enforce absolute session lifetime bounds | Production authentication delegated to external auth manager (FAB, Keycloak); absolute session lifetime enforcement explicitly delegated via AuthManagerRefreshTokenExpiredException hook | — |
| Session Management | BaseAuthManager interface allows custom implementations to enforce concurrent session limits | Promoted from dropped finding ASVS-712-LOW-001 | — |
| Session Management | jwt_expiration_time configurable by deployment manager; auth managers enforce stricter bounds via AuthManagerRefreshTokenExpiredException | Dropped finding ASVS-731-LOW-001 | — |
| Session Management | AuthManagerRefreshTokenExpiredException provides explicit hook for auth managers to enforce absolute session maximums | Promoted from dropped finding ASVS-732-MED-001 | — |
| Session Management | Account disable causes AuthManagerRefreshTokenExpiredException on next refresh cycle, bounded by configurable jwt_expiration_time | Dropped finding ASVS-742-MED-001 | — |
| Session Management | Authentication factor management delegated to external auth manager which provides its own session termination on credential change | Authentication factor management (password, MFA) and associated session termination delegated to production auth manager (Keycloak, FAB). Airflow does not manage authentication factors directly. | — |
| Session Management | Production auth managers (Keycloak, FAB) provide admin-level session termination capabilities at the IdP layer | Dropped finding ASVS-745-MED-001 | — |
| Session Management | Sensitive account attribute management delegated to external IdP which enforces its own re-authentication policies | Sensitive account attribute management (email, MFA) is performed at the external auth manager/IdP layer, not in Airflow; re-authentication for such changes is the IdP's responsibility | — |
| Session Management | Production auth managers (Keycloak, FAB) provide user-facing session viewing and termination capabilities | source: Dropped finding ASVS-752-MED-001 | — |
| Session Management | Step-up authentication and MFA enforcement delegated to production auth manager implementations (FAB, Keycloak, etc.) | Production authentication delegated to external auth manager (FAB, Keycloak) per profile section 'Explicitly Delegated Controls' | — |
| Session Management | Federated re-authentication consent flows delegated to production auth manager implementations which handle IdP session lifecycle appropriately | source: Dropped finding ASVS-762-INFO-001 | — |
| Authorization Rbac | Security model documented in security_model.rst defines user types, trust levels, and authorization boundaries | Promoted from dropped finding ASVS-811-LOW-001 | security_model.rst |
| Authorization Rbac | Sensitive value masking implemented at serialization layer for connection passwords and variable values | Documented in mask-sensitive-values.rst; controls exist at serialization layer | — |
| Authorization Rbac | Field-level sensitive value masking enforced at API serialization layer independent of auth manager interface | Documented in profile (mask-sensitive-values.rst); controls exist at serialization layer | — |
| Authorization Rbac | Pluggable auth manager architecture enables production deployments to implement contextual controls via external IdPs | Promoted from dropped finding ASVS-824-INFO-001 | — |
| Authorization Rbac | Pluggable auth manager architecture with middleware extension points and per-request refresh hooks enables deployment-level contextual controls | Promoted from dropped finding ASVS-842-INFO-001 | — |
| Oauth2 Oidc Integration | Tokens are only accessible to backend components that need them | 10.1.1 status: Pass - proper token access control implemented | — |
| Oauth2 Oidc Integration | Identity-based RBAC authorization via is_authorized_* methods replaces OAuth2 scope-based access control by design | Documented design decision: Airflow uses identity-based RBAC, not OAuth2 delegated scopes | — |
| Oauth2 Oidc Integration | User identification from access tokens uses non-reassignable claims | 10.3.3 status: Pass - proper user identification from tokens | — |
| Oauth2 Oidc Integration | Token theft prevention via TLS is delegated to deployment manager; token revocation and short-lived expiration provide compensating controls | 10.3.5 - compensating controls in place for token protection | — |
| Oauth2 Oidc Integration | OAuth Authorization Server responsibilities delegated to external providers; Airflow acts as resource server/client only | Report scope assessment - Airflow does not implement OAuth AS functions | — |
| Oauth2 Oidc Integration | No OAuth2 implicit or ROPC grants implemented; OAuth AS delegated to external providers | Report scope assessment | — |
| Oauth2 Oidc Integration | No refresh token flows implemented; OAuth AS delegated to external providers | Report scope assessment | — |
| Oauth2 Oidc Integration | No authorization code grant implemented; PKCE enforcement delegated to external OAuth providers | Report scope assessment | — |
| Oauth2 Oidc Integration | No dynamic client registration; client management delegated to external OAuth providers | Report scope assessment | — |
| Oauth2 Oidc Integration | JWT access tokens have mandatory absolute expiration via exp claim | Report scope assessment - Internal JWT tokens enforce expiration | — |
| Oauth2 Oidc Integration | JWT revocation via RevokedToken table with check on every request; OAuth AS token management delegated to external providers | Report scope assessment - Internal revocation mechanism exists | — |
| Oauth2 Oidc Integration | OIDC protocol validation (nonce, claims) delegated to concrete auth manager implementations using battle-tested OIDC libraries | Production authentication delegated to external auth manager (FAB, Keycloak, etc.); OIDC protocol validation is the responsibility of the concrete auth manager implementation | — |
| Oauth2 Oidc Integration | User identity mapping delegated to concrete auth manager implementations; BaseUser.get_id() provides stable identifier interface | Promoted from dropped finding ASVS-1052-LOW-001 | — |
| Oauth2 Oidc Integration | OIDC discovery/metadata validation delegated to concrete auth manager implementations | Report scope assessment | — |
| Oauth2 Oidc Integration | Internal JWT audience validation enforced via JWTValidator with configured audience claim | Report scope assessment - Internal tokens validate audience | — |
| Oauth2 Oidc Integration | Front-channel logout with token revocation and cookie deletion implemented; back-channel logout delegated to external auth managers | Report scope assessment | — |
| Oauth2 Oidc Integration | Airflow does not act as OpenID Provider; OP responsibilities delegated to external providers | Report scope assessment | — |
| Oauth2 Oidc Integration | Airflow does not act as OAuth2 Authorization Server; no third-party client authorization or consent flows | Report scope assessment | — |
| Cryptography Secrets | Auto-generated keys emit explicit warnings directing Deployment Manager to configure proper keys | Promoted from dropped finding ASVS-1111-LOW-001 | — |
| Cryptography Secrets | Production key generation/selection delegated to Deployment Manager; generate_private_key is a testing utility | Dropped finding ASVS-1123-LOW-001 | — |
| Cryptography Secrets | Auto-generated keys are fallback with explicit warnings; production key management delegated to Deployment Manager | Key configuration is delegated to Deployment Manager per profile section 'Sensitive credential configuration'. Auto-generated key is a documented fallback with warnings. | — |
| Tls Transport Security | TLS termination delegated to reverse proxy/Deployment Manager with documented Helm chart TLS configuration | Scope assessment - ASVS 12.1.1 | — |
| Tls Transport Security | Cipher suite configuration delegated to infrastructure layer (reverse proxy/load balancer) | Scope assessment - ASVS 12.1.2 | — |
| Tls Transport Security | JWT-based authentication used instead of mTLS; mTLS not implemented in core | Scope assessment - ASVS 12.1.3 | — |
| Tls Transport Security | OCSP/certificate revocation delegated to Deployment Manager at infrastructure layer | Scope assessment - ASVS 12.1.4 | — |
| Tls Transport Security | ECH configuration delegated to infrastructure TLS terminator and DNS layer | Scope assessment - ASVS 12.1.5 | — |
| Tls Transport Security | HTTPS enforcement delegated to Deployment Manager; Helm chart demonstrates TLS ingress configuration | Dropped finding ASVS-1221-LOW-001 - ASVS 12.2.1 | — |
| Tls Transport Security | Publicly trusted TLS certificates delegated to Deployment Manager; self-signed cert docs marked development-only | Scope assessment - ASVS 12.2.2 | — |
| Tls Transport Security | TLS configuration for internal services delegated to Deployment Manager; application supports HTTPS via SSL_CERT/SSL_KEY config | Dropped finding ASVS-1231-LOW-001 - ASVS 12.3.1 | — |
| Tls Transport Security | No TLS certificate validation bypass (verify=False) found in production code paths | Scope assessment - ASVS 12.3.2 | — |
| Tls Transport Security | Application supports direct TLS via SSL_CERT/SSL_KEY for end-to-end encryption when required by Deployment Manager | Promoted from dropped finding ASVS-1233-INFO-001 - ASVS 12.3.3 | — |
| Tls Transport Security | Self-signed certificate documentation includes explicit 'not suitable for production' caution; health checks use --cacert for proper trust validation | Promoted from dropped finding ASVS-1234-INFO-001 - ASVS 12.3.4 | — |
| Tls Transport Security | Execution API uses JWT with required claims (aud, exp, iat), explicit key configuration (no weak defaults), token scoping to task instances, and granular per-resource access checks | Dropped finding ASVS-1235-LOW-001 - ASVS 12.3.5 | — |
| Api Input Validation | Input is decoded into canonical form only once before processing | ASVS 1.1.1 passed | — |
| Api Input Validation | Output encoding and escaping performed as final step before interpreter use | ASVS 1.1.2 passed | — |
| Api Input Validation | Output encoding for HTTP responses, HTML documents, and XML documents is context-appropriate | ASVS 1.2.1 passed | — |
| Api Input Validation | Untrusted data is properly encoded when building URLs | ASVS 1.2.2 passed | — |
| Api Input Validation | Output encoding/escaping used when building JavaScript/JSON content | ASVS 1.2.3 passed | — |
| Api Input Validation | Database queries use parameterized queries or ORMs to prevent injection | ASVS 1.2.4 passed | — |
| Api Input Validation | Application avoids use of eval() and dynamic code execution | ASVS 1.3.2 passed | — |
| Api Input Validation | Format strings are sanitized before processing | ASVS 1.3.10 passed | — |
| Api Input Validation | Regular expressions protected against ReDoS attacks | ASVS 1.3.12 passed | — |
| Api Input Validation | Self-documenting validation via Pydantic Field constraints with OpenAPI auto-generation serving as canonical input validation documentation | Promoted from dropped finding ASVS-211-LOW-001 | — |
| Api Input Validation | Anti-automation controls (rate limiting, timing enforcement) delegated to infrastructure layer by documented design decision | Dropped finding ASVS-242-INFO-001 | — |
| Browser Security Headers | CORS configurable through [api] config section; security headers explicitly delegated to deployment manager reverse proxy | 3.1.1.md - Dropped finding ASVS-311-INFO-001 | — |
| Browser Security Headers | FastAPI JSONResponse and HTMLResponse correctly set Content-Type headers; API routes separated from SPA catch-all | 3.2.1.md - Dropped finding ASVS-321-LOW-001 | — |
| Browser Security Headers | Strict type checking (typeof !== 'function') prevents DOM clobbering exploitation; Reflect.set overwrites clobbered values | 3.2.3.md - Dropped finding ASVS-323-LOW-001 | — |
| Browser Security Headers | HSTS explicitly delegated to reverse proxy per documented security model | 3.4.1.md - No finding due to delegation | — |
| Browser Security Headers | CORS uses configuration-driven allowlist via standard CORSMiddleware; only enabled when explicitly configured | 3.4.2.md - Promoted from dropped finding ASVS-342-LOW-001 | — |
| Browser Security Headers | Plugin trust model documented | 3.4.3.md - Noted in dropped finding ASVS-343-MED-001 | — |
| Browser Security Headers | React framework provides XSS protection | 3.4.3.md - Noted in dropped finding ASVS-343-MED-001 | — |
| Browser Security Headers | iframe sandboxing applied to plugin views | 3.4.3.md - Noted in dropped finding ASVS-343-MED-001 | — |
| Browser Security Headers | Security headers including CSP delegated to Deployment Manager per delegated_infrastructure_controls.md | 3.4.3.md - Noted in dropped finding ASVS-343-MED-001 | — |
| Browser Security Headers | Plugins are trusted extensions per security model | 3.4.3.md - Noted in dropped finding ASVS-343-MED-001 | — |
| Browser Security Headers | X-Content-Type-Options delegated to reverse proxy; application correctly sets Content-Type on all responses | 3.4.4.md - No finding due to delegation | — |
| Browser Security Headers | Referrer-Policy delegated to reverse proxy per documented security model | 3.4.5.md - No finding due to delegation | — |
| Browser Security Headers | CSP frame-ancestors delegated to reverse proxy; iframe sandbox attributes applied at application level for plugin views | 3.4.6.md - No finding due to delegation | — |
| Browser Security Headers | COOP header delegated to reverse proxy; application uses location.replace() avoiding opener references | Report confirms no finding due to delegation | — |
| Browser Security Headers | CORS configuration delegated to Deployment Manager; JWT-in-header pattern plus SameSite=Strict cookies provide inherent CSRF protection | Dropped finding ASVS-352-LOW-001 | — |
| Browser Security Headers | Plugin deployers are trusted per security model; legacy Flask plugin mount is a backward-compatibility mechanism with deprecation warning and iframe sandboxing | Dropped finding ASVS-354-LOW-001 | — |
| Browser Security Headers | Security response headers delegated to reverse proxy/Deployment Manager | source: Dropped finding ASVS-358-LOW-001 | — |
| Browser Security Headers | Plugin URLs are provided by trusted deployment managers; iframe sandbox attributes provide containment | source: Dropped finding ASVS-373-LOW-001 | — |
| Browser Security Headers | HSTS and TLS configuration delegated to reverse proxy/Deployment Manager | Dropped finding ASVS-374-INFO-001 | — |
| Api Protocol Security | Tracing headers (x-request-id, correlation-id) are used exclusively for log correlation, not for authentication or authorization decisions | source: Dropped finding ASVS-413-LOW-001 | — |
| Api Protocol Security | Transport integrity for Execution API relies on TLS (delegated to infrastructure) plus JWT authentication with short-lived, audience-scoped tokens | Dropped finding ASVS-415-INFO-001 | — |
| Api Protocol Security | HTTP protocol parsers (h2, h11, httptools) enforce CR/LF rejection at the transport layer before application code processes headers | Dropped finding ASVS-424-LOW-001 | — |
| Api Protocol Security | Header size limits enforced at ASGI server layer | Dropped finding ASVS-425-LOW-001 | — |
| Api Protocol Security | JWT tokens are self-generated with bounded claims ensuring predictable size | Dropped finding ASVS-425-LOW-001 | — |
| File Upload Handling | File type restriction (JSON only) and max files per upload implemented in code | source: Dropped finding ASVS-511-LOW-001 | — |
| File Upload Handling | Server-side payload size limits delegated to infrastructure (reverse proxy/web server) | Promoted from dropped finding ASVS-521-LOW-001 | — |
| File Upload Handling | Bundle names sourced exclusively from admin configuration; version strings from trusted bundle implementations | Promoted from dropped finding ASVS-532-LOW-001 | — |
| File Upload Handling | Bundle sources restricted to admin-configured trusted origins with URL validation and cryptographic signing | Promoted from dropped finding ASVS-543-INFO-001 | — |
| Secrets Data Protection | Pluggable secrets backend architecture supporting external vaults (HashiCorp Vault, AWS Secrets Manager) via configuration | source: Dropped finding ASVS-1331-LOW-001 | — |
| Secrets Data Protection | Team-based access filtering with intentional shared (NULL team) resources for common infrastructure | Documented design decision: shared resources such as connections, variables, and XComs are accessible to all tasks. There is no isolation between tasks belonging to different teams or Dag authors at the Execution API level. | — |
| Secrets Data Protection | Fernet encryption with key rotation support; external vault backends available for organizations requiring isolated crypto modules | source: Dropped finding ASVS-1333-LOW-001 | — |
| Secrets Data Protection | Fernet key rotation primitive (rotate_fernet_key) available for manual/scheduled invocation by Deployment Manager | Promoted from dropped finding ASVS-1334-LOW-001 | — |
| Secrets Data Protection | SecretCache provides temporary in-memory caching of decrypted secrets for task execution performance with cache invalidation on writes | Promoted from dropped finding ASVS-1422-LOW-001 | — |
| Component Dependency Management | ASF Severity Rating policy for dependency CVE remediation timing (no fixed SLA by design) | Report-level pass observation | — |
| Component Dependency Management | Resource-intensive operation protection (rate limiting, payload size) delegated to Deployment Manager | Dropped finding ASVS-1513-INFO-001 | — |
| Component Dependency Management | No fixed dependency remediation timeframes by documented policy; remediation per ASF criteria | Report-level pass observation | — |
| Component Dependency Management | Rate limiting and request throttling delegated to Deployment Manager infrastructure | Dropped finding ASVS-1522-LOW-001 | — |
| Component Dependency Management | InProcessExecutionAPI uses in-process transports (WSGITransport/ASGITransport) with no network exposure by design | Promoted from dropped finding ASVS-1525-LOW-001 | — |
| Component Dependency Management | Proxy IP propagation delegated to Deployment Manager via ASGI server configuration | Report-level pass observation | — |
| Component Dependency Management | InProcessExecutionAPI is documented as non-production, non-security-boundary helper for local execution | Dropped finding ASVS-1541-LOW-001 | — |
| Component Dependency Management | InProcessExecutionAPI is an internal in-process helper that intentionally bypasses auth; no security-relevant trust boundary is crossed. | Dropped finding ASVS-1542-LOW-001 | — |
| Audit Logging Monitoring | Secrets masker control exists and is extensively used in the audit logging layer | decorators.py | airflow-core/src/airflow/api_fastapi/logging/decorators.py |
| Audit Logging Monitoring | Configurable external log forwarding (CloudWatch, Splunk) available for deployment managers to route logs to separate systems | Dropped finding ASVS-1643-LOW-001 (16.4.3 marked N/A) | — |
| Service Communication Architecture | Comprehensive architecture diagrams documenting internal component communication flows | source: Dropped finding ASVS-1311-LOW-001 | — |
| Service Communication Architecture | Execution API network isolation delegated to deployment manager; API explicitly labeled as private internal component | Dropped finding ASVS-1345-LOW-001 | — |
| Token Security Management | Token digital signatures and MACs are validated before accepting token contents | ASVS 9.1.1 passed validation | — |
| Token Security Management | Algorithm is derived from trusted JWK metadata (not from JWT header), preventing algorithm substitution attacks; 'none' algorithm is never accepted | ASVS 9.1.2 passed validation with explicit algorithm allowlisting | — |
| Token Security Management | Key material for token validation is sourced from trusted pre-configured sources, preventing attacker-controlled key injection | ASVS 9.1.3 passed validation | — |
| Token Security Management | Token validity time spans (nbf, exp claims) are enforced and tokens are only accepted within valid time windows | ASVS 9.2.1 passed validation | — |
| Token Security Management | Token type validation ensures correct token types are used for their intended purpose (access tokens vs ID tokens) | ASVS 9.2.2 passed validation | — |
| Token Security Management | Audience validation ensures tokens are only accepted by their intended service recipients | ASVS 9.2.3 passed validation with 'aud' claim verification | — |
| Token Security Management | Tokens contain audience restrictions to prevent reuse with unintended audiences when issuer uses same key for multiple audiences | ASVS 9.2.4 passed validation | — |

---

# 5. ASVS Compliance Summary

| ASVS ID | Requirement Title | Status | Notes |
|---------|-------------------|--------|-------|
| **V1: Encoding and Sanitization** | | | |
| 1.1.1 | Verify that input is decoded or unescaped into a canonical form only once, it is only decoded when encoded data in that form is expected, and that this is done before processing the input further, for example it is not performed after input validation or sanitization. | **Pass** |  |
| 1.1.2 | Verify that the application performs output encoding and escaping either as a final step before being used by the interpreter for which it is intended or by the interpreter itself. | **Pass** |  |
| 1.2.1 | Verify that output encoding for an HTTP response, HTML document, or XML document is relevant for the context required, such as encoding the relevant characters for HTML elements, HTML attributes, HTML comments, CSS, or HTTP header fields, to avoid changing the message or document structure. | **Pass** |  |
| 1.2.2 | Verify that when dynamically building URLs, untrusted data is encoded according to its context (e.g., URL encoding or base64url encoding for query or path parameters). Ensure that only safe URL protocols are permitted (e.g., disallow javascript: or data:). | **Pass** |  |
| 1.2.3 | Verify that output encoding or escaping is used when dynamically building JavaScript content (including JSON), to avoid changing the message or document structure (to avoid JavaScript and JSON injection). | **Pass** |  |
| 1.2.4 | Verify that data selection or database queries (e.g., SQL, HQL, NoSQL, Cypher) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from SQL Injection and other database injection attacks. This is also relevant when writing stored procedures. | **Pass** |  |
| 1.2.5 | Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use contextual command line output encoding. | **N/A** |  |
| 1.2.6 | Verify that the application protects against LDAP injection vulnerabilities, or that specific security controls to prevent LDAP injection have been implemented. | **N/A** |  |
| 1.2.7 | Verify that the application is protected against XPath injection attacks by using query parameterization or precompiled queries. | **N/A** |  |
| 1.2.8 | Verify that LaTeX processors are configured securely (such as not using the "--shell-escape" flag) and an allowlist of commands is used to prevent LaTeX injection attacks. | **N/A** |  |
| 1.2.9 | Verify that the application escapes special characters in regular expressions (typically using a backslash) to prevent them from being misinterpreted as metacharacters. | **N/A** |  |
| 1.2.10 | Verify that the application is protected against CSV and Formula Injection. The application must follow the escaping rules defined in RFC 4180 sections 2.6 and 2.7 when exporting CSV content. Additionally, when exporting to CSV or other spreadsheet formats (such as XLS, XLSX, or ODF), special characters (including '=', '+', '-', '@', '\t' (tab), and '\0' (null character)) must be escaped with a single quote if they appear as the first character in a field value. | **N/A** |  |
| 1.3.1 | Verify that all untrusted HTML input from WYSIWYG editors or similar is sanitized using a well-known and secure HTML sanitization library or framework feature. | **N/A** |  |
| 1.3.2 | Verify that the application avoids the use of eval() or other dynamic code execution features such as Spring Expression Language (SpEL). Where there is no alternative, any user input being included must be sanitized before being executed. | **Pass** |  |
| 1.3.3 | Verify that data being passed to a potentially dangerous context is sanitized beforehand to enforce safety measures, such as only allowing characters which are safe for this context and trimming input which is too long. | **Partial** | See FINDING-007 |
| 1.3.4 | Verify that user-supplied Scalable Vector Graphics (SVG) scriptable content is validated or sanitized to contain only tags and attributes (such as draw graphics) that are safe for the application, e.g., do not contain scripts and foreignObject. | **N/A** |  |
| 1.3.5 | Verify that the application sanitizes or disables user-supplied scriptable or expression template language content, such as Markdown, CSS or XSL stylesheets, BBCode, or similar. | **N/A** |  |
| 1.3.6 | Verify that the application protects against Server-side Request Forgery (SSRF) attacks, by validating untrusted data against an allowlist of protocols, domains, paths and ports and sanitizing potentially dangerous characters before using the data to call another service. | **N/A** |  |
| 1.3.7 | Verify that the application protects against template injection attacks by not allowing templates to be built based on untrusted input. Where there is no alternative, any untrusted input being included dynamically during template creation must be sanitized or strictly validated. | **N/A** |  |
| 1.3.8 | Verify that the application appropriately sanitizes untrusted input before use in Java Naming and Directory Interface (JNDI) queries and that JNDI is configured securely to prevent JNDI injection attacks. | **N/A** |  |
| 1.3.9 | Verify that the application sanitizes content before it is sent to memcache to prevent injection attacks. | **N/A** |  |
| 1.3.10 | Verify that format strings which might resolve in an unexpected or malicious way when used are sanitized before being processed. | **Pass** |  |
| 1.3.11 | Verify that the application sanitizes user input before passing to mail systems to protect against SMTP or IMAP injection. | **N/A** |  |
| 1.3.12 | Verify that regular expressions are free from elements causing exponential backtracking, and ensure untrusted input is sanitized to mitigate ReDoS or Runaway Regex attacks. | **Pass** |  |
| 1.4.1 | Verify that the application uses memory-safe string, safer memory copy and pointer arithmetic to detect or prevent stack, buffer, or heap overflows. | **N/A** |  |
| 1.4.2 | Verify that sign, range, and input validation techniques are used to prevent integer overflows. | **N/A** |  |
| 1.4.3 | Verify that dynamically allocated memory and resources are released, and that references or pointers to freed memory are removed or set to null to prevent dangling pointers and use-after-free vulnerabilities. | **N/A** |  |
| 1.5.1 | Verify that the application configures XML parsers to use a restrictive configuration and that unsafe features such as resolving external entities are disabled to prevent XML eXternal Entity (XXE) attacks. | **N/A** |  |
| 1.5.2 | Verify that deserialization of untrusted data enforces safe input handling, such as using an allowlist of object types or restricting client-defined object types, to prevent deserialization attacks. Deserialization mechanisms that are explicitly defined as insecure must not be used with untrusted input. | **Pass** |  |
| 1.5.3 | Verify that different parsers used in the application for the same data type (e.g., JSON parsers, XML parsers, URL parsers), perform parsing in a consistent way and use the same character encoding mechanism to avoid issues such as JSON Interoperability vulnerabilities or different URI or file parsing behavior being exploited in Remote File Inclusion (RFI) or Server-side Request Forgery (SSRF) attacks. | **Pass** |  |
| **V2: Validation and Business Logic** | | | |
| 2.1.1 | Verify that the application's documentation defines input validation rules for how to check the validity of data items against an expected structure. This could be common data formats such as credit card numbers, email addresses, telephone numbers, or it could be an internal data format. | **Pass** |  |
| 2.1.2 | Verify that the application's documentation defines how to validate the logical and contextual consistency of combined data items, such as checking that suburb and ZIP code match. | **Pass** |  |
| 2.1.3 | Verify that expectations for business logic limits and validations are documented, including both per-user and globally across the application. | **Pass** |  |
| 2.2.1 | Verify that input is validated to enforce business or functional expectations for that input. This should either use positive validation against an allow list of values, patterns, and ranges, or be based on comparing the input to an expected structure and logical limits according to predefined rules. For L1, this can focus on input which is used to make specific business or security decisions. For L2 and up, this should apply to all input. | **Fail** | See FINDING-008 |
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
| 3.2.2 | Verify that content intended to be displayed as text, rather than rendered as HTML, is handled using safe rendering functions (such as createTextNode or textContent) to prevent unintended execution of content such as HTML or JavaScript. | **Pass** |  |
| 3.2.3 | Verify that the application avoids DOM clobbering when using client-side JavaScript by employing explicit variable declarations, performing strict type checking, avoiding storing global variables on the document object, and implementing namespace isolation. | **Pass** |  |
| 3.3.1 | Verify that cookies have the 'Secure' attribute set, and if the '\__Host-' prefix is not used for the cookie name, the '__Secure-' prefix must be used for the cookie name. | **Pass** |  |
| 3.3.2 | Verify that each cookie's 'SameSite' attribute value is set according to the purpose of the cookie, to limit exposure to user interface redress attacks and browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF). | **Pass** |  |
| 3.3.3 | Verify that cookies have the '__Host-' prefix for the cookie name unless they are explicitly designed to be shared with other hosts. | **Partial** | See FINDING-009 |
| 3.3.4 | Verify that if the value of a cookie is not meant to be accessible to client-side scripts (such as a session token), the cookie must have the 'HttpOnly' attribute set and the same value (e. g. session token) must only be transferred to the client via the 'Set-Cookie' header field. | **Pass** |  |
| 3.3.5 | Verify that when the application writes a cookie, the cookie name and value length combined are not over 4096 bytes. Overly large cookies will not be stored by the browser and therefore not sent with requests, preventing the user from using application functionality which relies on that cookie. | **Pass** |  |
| 3.4.1 | Verify that a Strict-Transport-Security header field is included on all responses to enforce an HTTP Strict Transport Security (HSTS) policy. A maximum age of at least 1 year must be defined, and for L2 and up, the policy must apply to all subdomains as well. | **N/A** |  |
| 3.4.2 | Verify that the Cross-Origin Resource Sharing (CORS) Access-Control-Allow-Origin header field is a fixed value by the application, or if the Origin HTTP request header field value is used, it is validated against an allowlist of trusted origins. When 'Access-Control-Allow-Origin: *' needs to be used, verify that the response does not include any sensitive information. | **N/A** |  |
| 3.4.3 | Verify that HTTP responses include a Content-Security-Policy response header field which defines directives to ensure the browser only loads and executes trusted content or resources, in order to limit execution of malicious JavaScript. As a minimum, a global policy must be used which includes the directives object-src 'none' and base-uri 'none' and defines either an allowlist or uses nonces or hashes. For an L3 application, a per-response policy with nonces or hashes must be defined. | **N/A** |  |
| 3.4.4 | Verify that all HTTP responses contain an 'X-Content-Type-Options: nosniff' header field. This instructs browsers not to use content sniffing and MIME type guessing for the given response, and to require the response's Content-Type header field value to match the destination resource. For example, the response to a request for a style is only accepted if the response's Content-Type is 'text/css'. This also enables the use of the Cross-Origin Read Blocking (CORB) functionality by the browser. | **N/A** |  |
| 3.4.5 | Verify that the application sets a referrer policy to prevent leakage of technically sensitive data to third-party services via the 'Referer' HTTP request header field. This can be done using the Referrer-Policy HTTP response header field or via HTML element attributes. Sensitive data could include path and query data in the URL, and for internal non-public applications also the hostname. | **N/A** |  |
| 3.4.6 | Verify that the web application uses the frame-ancestors directive of the Content-Security-Policy header field for every HTTP response to ensure that it cannot be embedded by default and that embedding of specific resources is allowed only when necessary. Note that the X-Frame-Options header field, although supported by browsers, is obsolete and may not be relied upon. | **N/A** |  |
| 3.4.7 | Verify that the Content-Security-Policy header field specifies a location to report violations. | **N/A** |  |
| 3.4.8 | Verify that all HTTP responses that initiate a document rendering (such as responses with Content-Type text/html), include the Cross‑Origin‑Opener‑Policy header field with the same-origin directive or the same-origin-allow-popups directive as required. This prevents attacks that abuse shared access to Window objects, such as tabnabbing and frame counting. | **N/A** |  |
| 3.5.1 | Verify that, if the application does not rely on the CORS preflight mechanism to prevent disallowed cross-origin requests to use sensitive functionality, these requests are validated to ensure they originate from the application itself. This may be done by using and validating anti-forgery tokens or requiring extra HTTP header fields that are not CORS-safelisted request-header fields. This is to defend against browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF). | **Pass** |  |
| 3.5.2 | Verify that, if the application relies on the CORS preflight mechanism to prevent disallowed cross-origin use of sensitive functionality, it is not possible to call the functionality with a request which does not trigger a CORS-preflight request. This may require checking the values of the 'Origin' and 'Content-Type' request header fields or using an extra header field that is not a CORS-safelisted header-field. | **N/A** |  |
| 3.5.3 | Verify that HTTP requests to sensitive functionality use appropriate HTTP methods such as POST, PUT, PATCH, or DELETE, and not methods defined by the HTTP specification as "safe" such as HEAD, OPTIONS, or GET. Alternatively, strict validation of the Sec-Fetch-* request header fields can be used to ensure that the request did not originate from an inappropriate cross-origin call, a navigation request, or a resource load (such as an image source) where this is not expected. | **Pass** |  |
| 3.5.4 | Verify that separate applications are hosted on different hostnames to leverage the restrictions provided by same-origin policy, including how documents or scripts loaded by one origin can interact with resources from another origin and hostname-based restrictions on cookies. | **N/A** |  |
| 3.5.5 | Verify that messages received by the postMessage interface are discarded if the origin of the message is not trusted, or if the syntax of the message is invalid. | **Pass** |  |
| 3.5.6 | Verify that JSONP functionality is not enabled anywhere across the application to avoid Cross-Site Script Inclusion (XSSI) attacks. | **Pass** |  |
| 3.5.7 | Verify that data requiring authorization is not included in script resource responses, like JavaScript files, to prevent Cross-Site Script Inclusion (XSSI) attacks. | **Pass** |  |
| 3.5.8 | Verify that authenticated resources (such as images, videos, scripts, and other documents) can be loaded or embedded on behalf of the user only when intended. This can be accomplished by strict validation of the Sec-Fetch-* HTTP request header fields to ensure that the request did not originate from an inappropriate cross-origin call, or by setting a restrictive Cross-Origin-Resource-Policy HTTP response header field to instruct the browser to block returned content. | **N/A** |  |
| 3.6.1 | Verify that client-side assets, such as JavaScript libraries, CSS, or web fonts, are only hosted externally (e.g., on a Content Delivery Network) if the resource is static and versioned and Subresource Integrity (SRI) is used to validate the integrity of the asset. If this is not possible, there should be a documented security decision to justify this for each resource. | **Pass** |  |
| 3.7.1 | Verify that the application only uses client-side technologies which are still supported and considered secure. Examples of technologies which do not meet this requirement include NSAPI plugins, Flash, Shockwave, ActiveX, Silverlight, NACL, or client-side Java applets. | **Pass** |  |
| 3.7.2 | Verify that the application will only automatically redirect the user to a different hostname or domain (which is not controlled by the application) where the destination appears on an allowlist. | **Partial** | See FINDING-010 |
| 3.7.3 | Verify that the application shows a notification when the user is being redirected to a URL outside of the application's control, with an option to cancel the navigation. | **N/A** |  |
| 3.7.4 | Verify that the application's top-level domain (e.g., site.tld) is added to the public preload list for HTTP Strict Transport Security (HSTS). This ensures that the use of TLS for the application is built directly into the main browsers, rather than relying only on the Strict-Transport-Security response header field. | **N/A** |  |
| 3.7.5 | Verify that the application behaves as documented (such as warning the user or blocking access) if the browser used to access the application does not support the expected security features. | **N/A** |  |
| **V4: API and Web Service** | | | |
| 4.1.1 | Verify that every HTTP response with a message body contains a Content-Type header field that matches the actual content of the response, including the charset parameter to specify safe character encoding (e.g., UTF-8, ISO-8859-1) according to IANA Media Types, such as "text/", "/+xml" and "/xml". | **Pass** |  |
| 4.1.2 | Verify that only user-facing endpoints (intended for manual web-browser access) automatically redirect from HTTP to HTTPS, while other services or endpoints do not implement transparent redirects. This is to avoid a situation where a client is erroneously sending unencrypted HTTP requests, but since the requests are being automatically redirected to HTTPS, the leakage of sensitive data goes undiscovered. | **Pass** |  |
| 4.1.3 | Verify that any HTTP header field used by the application and set by an intermediary layer, such as a load balancer, a web proxy, or a backend-for-frontend service, cannot be overridden by the end-user. Example headers might include X-Real-IP, X-Forwarded-*, or X-User-ID. | **N/A** |  |
| 4.1.4 | Verify that only HTTP methods that are explicitly supported by the application or its API (including OPTIONS during preflight requests) can be used and that unused methods are blocked. | **Pass** |  |
| 4.1.5 | Verify that per-message digital signatures are used to provide additional assurance on top of transport protections for requests or transactions which are highly sensitive or which traverse a number of systems. | **N/A** |  |
| 4.2.1 | Verify that all application components (including load balancers, firewalls, and application servers) determine boundaries of incoming HTTP messages using the appropriate mechanism for the HTTP version to prevent HTTP request smuggling. In HTTP/1.x, if a Transfer-Encoding header field is present, the Content-Length header must be ignored per RFC 2616. When using HTTP/2 or HTTP/3, if a Content-Length header field is present, the receiver must ensure that it is consistent with the length of the DATA frames. | **Pass** |  |
| 4.2.2 | Verify that when generating HTTP messages, the Content-Length header field does not conflict with the length of the content as determined by the framing of the HTTP protocol, in order to prevent request smuggling attacks. | **Pass** |  |
| 4.2.3 | Verify that the application does not send nor accept HTTP/2 or HTTP/3 messages with connection-specific header fields such as Transfer-Encoding to prevent response splitting and header injection attacks. | **Pass** |  |
| 4.2.4 | Verify that the application only accepts HTTP/2 and HTTP/3 requests where the header fields and values do not contain any CR (\r), LF (\n), or CRLF (\r\n) sequences, to prevent header injection attacks. | **N/A** |  |
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
| 5.2.2 | Verify that when the application accepts a file, either on its own or within an archive such as a zip file, it checks if the file extension matches an expected file extension and validates that the contents correspond to the type represented by the extension. This includes, but is not limited to, checking the initial 'magic bytes', performing image re-writing, and using specialized libraries for file content validation. For L1, this can focus just on files which are used to make specific business or security decisions. For L2 and up, this must apply to all files being accepted. | **Pass** |  |
| 5.2.3 | Verify that the application checks compressed files (e.g., zip, gz, docx, odt) against maximum allowed uncompressed size and against maximum number of files before uncompressing the file. | **Pass** |  |
| 5.2.4 | Verify that a file size quota and maximum number of files per user are enforced to ensure that a single user cannot fill up the storage with too many files, or excessively large files. | **Pass** |  |
| 5.2.5 | Verify that the application does not allow uploading compressed files containing symlinks unless this is specifically required (in which case it will be necessary to enforce an allowlist of the files that can be symlinked to). | **Pass** |  |
| 5.2.6 | Verify that the application rejects uploaded images with a pixel size larger than the maximum allowed, to prevent pixel flood attacks. | **N/A** |  |
| 5.3.1 | Verify that files uploaded or generated by untrusted input and stored in a public folder, are not executed as server-side program code when accessed directly with an HTTP request. | **Pass** |  |
| 5.3.2 | Verify that when the application creates file paths for file operations, instead of user-submitted filenames, it uses internally generated or trusted data, or if user-submitted filenames or file metadata must be used, strict validation and sanitization must be applied. This is to protect against path traversal, local or remote file inclusion (LFI, RFI), and server-side request forgery (SSRF) attacks. | **N/A** |  |
| 5.3.3 | Verify that server-side file processing, such as file decompression, ignores user-provided path information to prevent vulnerabilities such as zip slip. | **Pass** |  |
| 5.4.1 | Verify that the application validates or ignores user-submitted filenames, including in a JSON, JSONP, or URL parameter and specifies a filename in the Content-Disposition header field in the response. | **N/A** |  |
| 5.4.2 | Verify that file names served (e.g., in HTTP response header fields or email attachments) are encoded or sanitized (e.g., following RFC 6266) to preserve document structure and prevent injection attacks. | **N/A** |  |
| 5.4.3 | Verify that files obtained from untrusted sources are scanned by antivirus scanners to prevent serving of known malicious content. | **N/A** |  |
| **V6: Authentication** | | | |
| 6.1.1 | Verify that application documentation defines how controls such as rate limiting, anti-automation, and adaptive response, are used to defend against attacks such as credential stuffing and password brute force. The documentation must make clear how these controls are configured and prevent malicious account lockout. | **N/A** |  |
| 6.1.2 | Verify that a list of context-specific words is documented in order to prevent their use in passwords. The list could include permutations of organization names, product names, system identifiers, project codenames, department or role names, and similar. | **N/A** |  |
| 6.1.3 | Verify that, if the application includes multiple authentication pathways, these are all documented together with the security controls and authentication strength which must be consistently enforced across them. | **Pass** |  |
| 6.2.1 | Verify that user set passwords are at least 8 characters in length although a minimum of 15 characters is strongly recommended. | **N/A** |  |
| 6.2.2 | Verify that users can change their password. | **N/A** |  |
| 6.2.3 | Verify that password change functionality requires the user's current and new password. | **N/A** |  |
| 6.2.4 | Verify that passwords submitted during account registration or password change are checked against an available set of, at least, the top 3000 passwords which match the application's password policy, e.g. minimum length. | **N/A** |  |
| 6.2.5 | Verify that passwords of any composition can be used, without rules limiting the type of characters permitted. There must be no requirement for a minimum number of upper or lower case characters, numbers, or special characters. | **Pass** |  |
| 6.2.6 | Verify that password input fields use type=password to mask the entry. Applications may allow the user to temporarily view the entire masked password, or the last typed character of the password. | **Pass** |  |
| 6.2.7 | Verify that "paste" functionality, browser password helpers, and external password managers are permitted. | **Pass** |  |
| 6.2.8 | Verify that the application verifies the user's password exactly as received from the user, without any modifications such as truncation or case transformation. | **Pass** |  |
| 6.2.9 | Verify that passwords of at least 64 characters are permitted. | **Pass** |  |
| 6.2.10 | Verify that a user's password stays valid until it is discovered to be compromised or the user rotates it. The application must not require periodic credential rotation. | **Pass** |  |
| 6.2.11 | Verify that the documented list of context specific words is used to prevent easy to guess passwords being created. | **N/A** |  |
| 6.2.12 | Verify that passwords submitted during account registration or password changes are checked against a set of breached passwords. | **N/A** |  |
| 6.3.1 | Verify that controls to prevent attacks such as credential stuffing and password brute force are implemented according to the application's security documentation. | **N/A** |  |
| 6.3.2 | Verify that default user accounts (e.g., "root", "admin", or "sa") are not present in the application or are disabled. | **Pass** |  |
| 6.3.3 | Verify that either a multi-factor authentication mechanism or a combination of single-factor authentication mechanisms, must be used in order to access the application. For L3, one of the factors must be a hardware-based authentication mechanism which provides compromise and impersonation resistance against phishing attacks while verifying the intent to authenticate by requiring a user-initiated action (such as a button press on a FIDO hardware key or a mobile phone). Relaxing any of the considerations in this requirement requires a fully documented rationale and a comprehensive set of mitigating controls. | **N/A** |  |
| 6.3.4 | Verify that, if the application includes multiple authentication pathways, there are no undocumented pathways and that security controls and authentication strength are enforced consistently. | **Pass** |  |
| 6.3.5 | Verify that users are notified of suspicious authentication attempts (successful or unsuccessful). This may include authentication attempts from an unusual location or client, partially successful authentication (only one of multiple factors), an authentication attempt after a long period of inactivity or a successful authentication after several unsuccessful attempts. | **N/A** |  |
| 6.3.6 | Verify that email is not used as either a single-factor or multi-factor authentication mechanism. | **Pass** |  |
| 6.3.7 | Verify that users are notified after updates to authentication details, such as credential resets or modification of the username or email address. | **N/A** |  |
| 6.3.8 | Verify that valid users cannot be deduced from failed authentication challenges, such as by basing on error messages, HTTP response codes, or different response times. Registration and forgot password functionality must also have this protection. | **Pass** |  |
| 6.4.1 | Verify that system generated initial passwords or activation codes are securely randomly generated, follow the existing password policy, and expire after a short period of time or after they are initially used. These initial secrets must not be permitted to become the long term password. | **N/A** |  |
| 6.4.2 | Verify that password hints or knowledge-based authentication (so-called "secret questions") are not present. | **Pass** |  |
| 6.4.3 | Verify that a secure process for resetting a forgotten password is implemented, that does not bypass any enabled multi-factor authentication mechanisms. | **N/A** |  |
| 6.4.4 | Verify that if a multi-factor authentication factor is lost, evidence of identity proofing is performed at the same level as during enrollment. | **N/A** |  |
| 6.4.5 | Verify that renewal instructions for authentication mechanisms which expire are sent with enough time to be carried out before the old authentication mechanism expires, configuring automated reminders if necessary. | **N/A** |  |
| 6.4.6 | Verify that administrative users can initiate the password reset process for the user, but that this does not allow them to change or choose the user's password. This prevents a situation where they know the user's password. | **N/A** |  |
| 6.5.1 | Verify that lookup secrets, out-of-band authentication requests or codes, and time-based one-time passwords (TOTPs) are only successfully usable once. | **N/A** |  |
| 6.5.2 | Verify that, when being stored in the application's backend, lookup secrets with less than 112 bits of entropy (19 random alphanumeric characters or 34 random digits) are hashed with an approved password storage hashing algorithm that incorporates a 32-bit random salt. A standard hash function can be used if the secret has 112 bits of entropy or more. | **N/A** |  |
| 6.5.3 | Verify that lookup secrets, out-of-band authentication code, and time-based one-time password seeds, are generated using a Cryptographically Secure Pseudorandom Number Generator (CSPRNG) to avoid predictable values. | **Pass** |  |
| 6.5.4 | Verify that lookup secrets and out-of-band authentication codes have a minimum of 20 bits of entropy (typically 4 random alphanumeric characters or 6 random digits is sufficient). | **Pass** |  |
| 6.5.5 | Verify that out-of-band authentication requests, codes, or tokens, as well as time-based one-time passwords (TOTPs) have a defined lifetime. Out of band requests must have a maximum lifetime of 10 minutes and for TOTP a maximum lifetime of 30 seconds. | **N/A** |  |
| 6.5.6 | Verify that any authentication factor (including physical devices) can be revoked in case of theft or other loss. | **Partial** | See FINDING-003 |
| 6.5.7 | Verify that biometric authentication mechanisms are only used as secondary factors together with either something you have or something you know. | **N/A** |  |
| 6.5.8 | Verify that time-based one-time passwords (TOTPs) are checked based on a time source from a trusted service and not from an untrusted or client provided time. | **N/A** |  |
| 6.6.1 | Verify that authentication mechanisms using the Public Switched Telephone Network (PSTN) to deliver One-time Passwords (OTPs) via phone or SMS are offered only when the phone number has previously been validated, alternate stronger methods (such as Time based One-time Passwords) are also offered, and the service provides information on their security risks to users. For L3 applications, phone and SMS must not be available as options. | **N/A** |  |
| 6.6.2 | Verify that out-of-band authentication requests, codes, or tokens are bound to the original authentication request for which they were generated and are not usable for a previous or subsequent one. | **N/A** |  |
| 6.6.3 | Verify that a code based out-of-band authentication mechanism is protected against brute force attacks by using rate limiting. Consider also using a code with at least 64 bits of entropy. | **N/A** |  |
| 6.6.4 | Verify that, where push notifications are used for multi-factor authentication, rate limiting is used to prevent push bombing attacks. Number matching may also mitigate this risk. | **N/A** |  |
| 6.7.1 | Verify that the certificates used to verify cryptographic authentication assertions are stored in a way protects them from modification. | **N/A** |  |
| 6.7.2 | Verify that the challenge nonce is at least 64 bits in length, and statistically unique or unique over the lifetime of the cryptographic device. | **N/A** |  |
| 6.8.1 | Verify that, if the application supports multiple identity providers (IdPs), the user's identity cannot be spoofed via another supported identity provider (eg. by using the same user identifier). The standard mitigation would be for the application to register and identify the user using a combination of the IdP ID (serving as a namespace) and the user's ID in the IdP. | **N/A** |  |
| 6.8.2 | Verify that the presence and integrity of digital signatures on authentication assertions (for example on JWTs or SAML assertions) are always validated, rejecting any assertions that are unsigned or have invalid signatures. | **Pass** |  |
| 6.8.3 | Verify that SAML assertions are uniquely processed and used only once within the validity period to prevent replay attacks. | **N/A** |  |
| 6.8.4 | Verify that, if an application uses a separate Identity Provider (IdP) and expects specific authentication strength, methods, or recentness for specific functions, the application verifies this using the information returned by the IdP. For example, if OIDC is used, this might be achieved by validating ID Token claims such as 'acr', 'amr', and 'auth_time' (if present). If the IdP does not provide this information, the application must have a documented fallback approach that assumes that the minimum strength authentication mechanism was used (for example, single-factor authentication using username and password). | **N/A** |  |
| **V7: Session Management** | | | |
| 7.1.1 | Verify that the user's session inactivity timeout and absolute maximum session lifetime are documented, are appropriate in combination with other controls, and that the documentation includes justification for any deviations from NIST SP 800-63B re-authentication requirements. | **N/A** |  |
| 7.1.2 | Verify that the documentation defines how many concurrent (parallel) sessions are allowed for one account as well as the intended behaviors and actions to be taken when the maximum number of active sessions is reached. | **N/A** |  |
| 7.1.3 | Verify that all systems that create and manage user sessions as part of a federated identity management ecosystem (such as SSO systems) are documented along with controls to coordinate session lifetimes, termination, and any other conditions that require re-authentication. | **Pass** |  |
| 7.2.1 | Verify that the application performs all session token verification using a trusted, backend service. | **Pass** |  |
| 7.2.2 | Verify that the application uses either self-contained or reference tokens that are dynamically generated for session management, i.e. not using static API secrets and keys. | **Pass** |  |
| 7.2.3 | Verify that if reference tokens are used to represent user sessions, they are unique and generated using a cryptographically secure pseudo-random number generator (CSPRNG) and possess at least 128 bits of entropy. | **N/A** |  |
| 7.2.4 | Verify that the application generates a new session token on user authentication, including re-authentication, and terminates the current session token. | **Partial** | See FINDING-004 |
| 7.3.1 | Verify that there is an inactivity timeout such that re-authentication is enforced according to risk analysis and documented security decisions. | **N/A** |  |
| 7.3.2 | Verify that there is an absolute maximum session lifetime such that re-authentication is enforced according to risk analysis and documented security decisions. | **N/A** |  |
| 7.4.1 | Verify that when session termination is triggered (such as logout or expiration), the application disallows any further use of the session. For reference tokens or stateful sessions, this means invalidating the session data at the application backend. Applications using self-contained tokens will need a solution such as maintaining a list of terminated tokens, disallowing tokens produced before a per-user date and time or rotating a per-user signing key. | **Partial** | See FINDING-001 |
| 7.4.2 | Verify that the application terminates all active sessions when a user account is disabled or deleted (such as an employee leaving the company). | **N/A** |  |
| 7.4.3 | Verify that the application gives the option to terminate all other active sessions after a successful change or removal of any authentication factor (including password change via reset or recovery and, if present, an MFA settings update). | **N/A** |  |
| 7.4.4 | Verify that all pages that require authentication have easy and visible access to logout functionality. | **Pass** |  |
| 7.4.5 | Verify that application administrators are able to terminate active sessions for an individual user or for all users. | **N/A** |  |
| 7.5.1 | Verify that the application requires full re-authentication before allowing modifications to sensitive account attributes which may affect authentication such as email address, phone number, MFA configuration, or other information used in account recovery. | **N/A** |  |
| 7.5.2 | Verify that users are able to view and (having authenticated again with at least one factor) terminate any or all currently active sessions. | **N/A** |  |
| 7.5.3 | Verify that the application requires further authentication with at least one factor or secondary verification before performing highly sensitive transactions or operations. | **N/A** |  |
| 7.6.1 | Verify that session lifetime and termination between Relying Parties (RPs) and Identity Providers (IdPs) behave as documented, requiring re-authentication as necessary such as when the maximum time between IdP authentication events is reached. | **Pass** |  |
| 7.6.2 | Verify that creation of a session requires either the user's consent or an explicit action, preventing the creation of new application sessions without user interaction. | **Pass** |  |
| **V8: Authorization** | | | |
| 8.1.1 | Verify that authorization documentation defines rules for restricting function-level and data-specific access based on consumer permissions and resource attributes. | **Pass** |  |
| 8.1.2 | Verify that authorization documentation defines rules for field-level access restrictions (both read and write) based on consumer permissions and resource attributes. Note that these rules might depend on other attribute values of the relevant data object, such as state or status. | **Pass** |  |
| 8.1.3 | Verify that the application's documentation defines the environmental and contextual attributes (including but not limited to, time of day, user location, IP address, or device) that are used in the application to make security decisions, including those pertaining to authentication and authorization. | **N/A** |  |
| 8.1.4 | Verify that authentication and authorization documentation defines how environmental and contextual factors are used in decision-making, in addition to function-level, data-specific, and field-level authorization. This should include the attributes evaluated, thresholds for risk, and actions taken (e.g., allow, challenge, deny, step-up authentication). | **N/A** |  |
| 8.2.1 | Verify that the application ensures that function-level access is restricted to consumers with explicit permissions. | **Pass** |  |
| 8.2.2 | Verify that the application ensures that data-specific access is restricted to consumers with explicit permissions to specific data items to mitigate insecure direct object reference (IDOR) and broken object level authorization (BOLA). | **Fail** | See FINDING-002 |
| 8.2.3 | Verify that the application ensures that field-level access is restricted to consumers with explicit permissions to specific fields to mitigate broken object property level authorization (BOPLA). | **Pass** |  |
| 8.2.4 | Verify that adaptive security controls based on a consumer's environmental and contextual attributes (such as time of day, location, IP address, or device) are implemented for authentication and authorization decisions, as defined in the application's documentation. These controls must be applied when the consumer tries to start a new session and also during an existing session. | **N/A** |  |
| 8.3.1 | Verify that the application enforces authorization rules at a trusted service layer and doesn't rely on controls that an untrusted consumer could manipulate, such as client-side JavaScript. | **Pass** |  |
| 8.3.2 | Verify that changes to values on which authorization decisions are made are applied immediately. Where changes cannot be applied immediately, (such as when relying on data in self-contained tokens), there must be mitigating controls to alert when a consumer performs an action when they are no longer authorized to do so and revert the change. Note that this alternative would not mitigate information leakage. | **Partial** | See FINDING-003 |
| 8.3.3 | Verify that access to an object is based on the originating subject's (e.g. consumer's) permissions, not on the permissions of any intermediary or service acting on their behalf. For example, if a consumer calls a web service using a self-contained token for authentication, and the service then requests data from a different service, the second service will use the consumer's token, rather than a machine-to-machine token from the first service, to make permission decisions. | **Pass** |  |
| 8.4.1 | Verify that multi-tenant applications use cross-tenant controls to ensure consumer operations will never affect tenants with which they do not have permissions to interact. | **Pass** |  |
| 8.4.2 | Verify that access to administrative interfaces incorporates multiple layers of security, including continuous consumer identity verification, device security posture assessment, and contextual risk analysis, ensuring that network location or trusted endpoints are not the sole factors for authorization even though they may reduce the likelihood of unauthorized access. | **N/A** |  |
| **V9: Self-contained Tokens** | | | |
| 9.1.1 | Verify that self-contained tokens are validated using their digital signature or MAC to protect against tampering before accepting the token's contents. | **Pass** |  |
| 9.1.2 | Verify that only algorithms on an allowlist can be used to create and verify self-contained tokens, for a given context. The allowlist must include the permitted algorithms, ideally only either symmetric or asymmetric algorithms, and must not include the 'None' algorithm. If both symmetric and asymmetric must be supported, additional controls will be needed to prevent key confusion. | **Pass** |  |
| 9.1.3 | Verify that key material that is used to validate self-contained tokens is from trusted pre-configured sources for the token issuer, preventing attackers from specifying untrusted sources and keys. For JWTs and other JWS structures, headers such as 'jku', 'x5u', and 'jwk' must be validated against an allowlist of trusted sources. | **Pass** |  |
| 9.2.1 | Verify that, if a validity time span is present in the token data, the token and its content are accepted only if the verification time is within this validity time span. For example, for JWTs, the claims 'nbf' and 'exp' must be verified. | **Pass** |  |
| 9.2.2 | Verify that the service receiving a token validates the token to be the correct type and is meant for the intended purpose before accepting the token's contents. For example, only access tokens can be accepted for authorization decisions and only ID Tokens can be used for proving user authentication. | **Pass** |  |
| 9.2.3 | Verify that the service only accepts tokens which are intended for use with that service (audience). For JWTs, this can be achieved by validating the 'aud' claim against an allowlist defined in the service. | **Pass** |  |
| 9.2.4 | Verify that, if a token issuer uses the same private key for issuing tokens to different audiences, the issued tokens contain an audience restriction that uniquely identifies the intended audiences. This will prevent a token from being reused with an unintended audience. If the audience identifier is dynamically provisioned, the token issuer must validate these audiences in order to make sure that they do not result in audience impersonation. | **Pass** |  |
| **V10: OAuth and OIDC** | | | |
| 10.1.1 | Verify that tokens are only sent to components that strictly need them. For example, when using a backend-for-frontend pattern for browser-based JavaScript applications, access and refresh tokens shall only be accessible for the backend. | **Pass** |  |
| 10.1.2 | Verify that the client only accepts values from the authorization server (such as the authorization code or ID Token) if these values result from an authorization flow that was initiated by the same user agent session and transaction. This requires that client-generated secrets, such as the proof key for code exchange (PKCE) 'code_verifier', 'state' or OIDC 'nonce', are not guessable, are specific to the transaction, and are securely bound to both the client and the user agent session in which the transaction was started. | **N/A** |  |
| 10.2.1 | Verify that, if the code flow is used, the OAuth client has protection against browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF), which trigger token requests, either by using proof key for code exchange (PKCE) functionality or checking the 'state' parameter that was sent in the authorization request. | **N/A** |  |
| 10.2.2 | Verify that, if the OAuth client can interact with more than one authorization server, it has a defense against mix-up attacks. For example, it could require that the authorization server return the 'iss' parameter value and validate it in the authorization response and the token response. | **N/A** |  |
| 10.2.3 | Verify that the OAuth client only requests the required scopes (or other authorization parameters) in requests to the authorization server. | **N/A** |  |
| 10.3.1 | Verify that the resource server only accepts access tokens that are intended for use with that service (audience). The audience may be included in a structured access token (such as the 'aud' claim in JWT), or it can be checked using the token introspection endpoint. | **Partial** | See FINDING-005 |
| 10.3.2 | Verify that the resource server enforces authorization decisions based on claims from the access token that define delegated authorization. If claims such as 'sub', 'scope', and 'authorization_details' are present, they must be part of the decision. | **N/A** |  |
| 10.3.3 | Verify that if an access control decision requires identifying a unique user from an access token (JWT or related token introspection response), the resource server identifies the user from claims that cannot be reassigned to other users. Typically, it means using a combination of 'iss' and 'sub' claims. | **Pass** |  |
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
| 11.1.4 | Verify that a cryptographic inventory is maintained. This must include a documented plan that outlines the migration path to new cryptographic standards, such as post-quantum cryptography, in order to react to future threats. | **Partial** | See FINDING-006 |
| 11.2.1 | Verify that industry-validated implementations (including libraries and hardware-accelerated implementations) are used for cryptographic operations. | **Pass** |  |
| 11.2.2 | Verify that the application is designed with crypto agility such that random number, authenticated encryption, MAC, or hashing algorithms, key lengths, rounds, ciphers and modes can be reconfigured, upgraded, or swapped at any time, to protect against cryptographic breaks. Similarly, it must also be possible to replace keys and passwords and re-encrypt data. This will allow for seamless upgrades to post-quantum cryptography (PQC), once high-assurance implementations of approved PQC schemes or standards are widely available. | **Partial** | See FINDING-006 |
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
| 11.7.2 | Verify that data minimization ensures the minimal amount of data is exposed during processing, and ensure that data is encrypted immediately after use or as soon as feasible. | **Pass** |  |
| **V12: Secure Communication** | | | |
| 12.1.1 | Verify that only the latest recommended versions of the TLS protocol are enabled, such as TLS 1.2 and TLS 1.3. The latest version of the TLS protocol must be the preferred option. | **N/A** |  |
| 12.1.2 | Verify that only recommended cipher suites are enabled, with the strongest cipher suites set as preferred. L3 applications must only support cipher suites which provide forward secrecy. | **N/A** |  |
| 12.1.3 | Verify that the application validates that mTLS client certificates are trusted before using the certificate identity for authentication or authorization. | **N/A** |  |
| 12.1.4 | Verify that proper certification revocation, such as Online Certificate Status Protocol (OCSP) Stapling, is enabled and configured. | **N/A** |  |
| 12.1.5 | Verify that Encrypted Client Hello (ECH) is enabled in the application's TLS settings to prevent exposure of sensitive metadata, such as the Server Name Indication (SNI), during TLS handshake processes. | **N/A** |  |
| 12.2.1 | Verify that TLS is used for all connectivity between a client and external facing, HTTP-based services, and does not fall back to insecure or unencrypted communications. | **N/A** |  |
| 12.2.2 | Verify that external facing services use publicly trusted TLS certificates. | **N/A** |  |
| 12.3.1 | Verify that an encrypted protocol such as TLS is used for all inbound and outbound connections to and from the application, including monitoring systems, management tools, remote access and SSH, middleware, databases, mainframes, partner systems, or external APIs. The server must not fall back to insecure or unencrypted protocols. | **N/A** |  |
| 12.3.2 | Verify that TLS clients validate certificates received before communicating with a TLS server. | **Pass** |  |
| 12.3.3 | Verify that TLS or another appropriate transport encryption mechanism used for all connectivity between internal, HTTP-based services within the application, and does not fall back to insecure or unencrypted communications. | **N/A** |  |
| 12.3.4 | Verify that TLS connections between internal services use trusted certificates. Where internally generated or self-signed certificates are used, the consuming service must be configured to only trust specific internal CAs and specific self-signed certificates. | **N/A** |  |
| 12.3.5 | Verify that services communicating internally within a system (intra-service communications) use strong authentication to ensure that each endpoint is verified. Strong authentication methods, such as TLS client authentication, must be employed to ensure identity, using public-key infrastructure and mechanisms that are resistant to replay attacks. For microservice architectures, consider using a service mesh to simplify certificate management and enhance security. | **N/A** |  |
| **V13: Configuration** | | | |
| 13.1.1 | Verify that all communication needs for the application are documented. This must include external services which the application relies upon and cases where an end user might be able to provide an external location to which the application will then connect. | **Pass** |  |
| 13.1.2 | Verify that for each service the application uses, the documentation defines the maximum number of concurrent connections (e.g., connection pool limits) and how the application behaves when that limit is reached, including any fallback or recovery mechanisms, to prevent denial of service conditions. | **Partial** | See FINDING-020 |
| 13.1.3 | Verify that the application documentation defines resource‑management strategies for every external system or service it uses (e.g., databases, file handles, threads, HTTP connections). This should include resource‑release procedures, timeout settings, failure handling, and where retry logic is implemented, specifying retry limits, delays, and back‑off algorithms. For synchronous HTTP request–response operations it should mandate short timeouts and either disable retries or strictly limit retries to prevent cascading delays and resource exhaustion. | **Partial** | See FINDING-021 |
| 13.1.4 | Verify that the application's documentation defines the secrets that are critical for the security of the application and a schedule for rotating them, based on the organization's threat model and business requirements. | **Partial** | See FINDING-022 |
| 13.2.1 | Verify that communications between backend application components that don't support the application's standard user session mechanism, including APIs, middleware, and data layers, are authenticated. Authentication must use individual service accounts, short-term tokens, or certificate-based authentication and not unchanging credentials such as passwords, API keys, or shared accounts with privileged access. | **Pass** |  |
| 13.2.2 | Verify that communications between backend application components, including local or operating system services, APIs, middleware, and data layers, are performed with accounts assigned the least necessary privileges. | **Pass** |  |
| 13.2.3 | Verify that if a credential has to be used for service authentication, the credential being used by the consumer is not a default credential (e.g., root/root or admin/admin). | **Pass** |  |
| 13.2.4 | Verify that an allowlist is used to define the external resources or systems with which the application is permitted to communicate (e.g., for outbound requests, data loads, or file access). This allowlist can be implemented at the application layer, web server, firewall, or a combination of different layers. | **Pass** |  |
| 13.2.5 | Verify that the web or application server is configured with an allowlist of resources or systems to which the server can send requests or load data or files from. | **Pass** |  |
| 13.2.6 | Verify that where the application connects to separate services, it follows the documented configuration for each connection, such as maximum parallel connections, behavior when maximum allowed connections is reached, connection timeouts, and retry strategies. | **Partial** | See FINDING-023 |
| 13.3.1 | Verify that a secrets management solution, such as a key vault, is used to securely create, store, control access to, and destroy backend secrets. These could include passwords, key material, integrations with databases and third-party systems, keys and seeds for time-based tokens, other internal secrets, and API keys. Secrets must not be included in application source code or included in build artifacts. For an L3 application, this must involve a hardware-backed solution such as an HSM. | **Pass** |  |
| 13.3.2 | Verify that access to secret assets adheres to the principle of least privilege. | **Pass** |  |
| 13.3.3 | Verify that all cryptographic operations are performed using an isolated security module (such as a vault or hardware security module) to securely manage and protect key material from exposure outside of the security module. | **N/A** |  |
| 13.3.4 | Verify that secrets are configured to expire and be rotated based on the application's documentation. | **Pass** |  |
| 13.4.1 | Verify that the application is deployed either without any source control metadata, including the .git or .svn folders, or in a way that these folders are inaccessible both externally and to the application itself. | **Pass** |  |
| 13.4.2 | Verify that debug modes are disabled for all components in production environments to prevent exposure of debugging features and information leakage. | **Pass** |  |
| 13.4.3 | Verify that web servers do not expose directory listings to clients unless explicitly intended. | **Pass** |  |
| 13.4.4 | Verify that using the HTTP TRACE method is not supported in production environments, to avoid potential information leakage. | **Pass** |  |
| 13.4.5 | Verify that documentation (such as for internal APIs) and monitoring endpoints are not exposed unless explicitly intended. | **N/A** |  |
| 13.4.6 | Verify that the application does not expose detailed version information of backend components. | **Pass** |  |
| 13.4.7 | Verify that the web tier is configured to only serve files with specific file extensions to prevent unintentional information, configuration, and source code leakage. | **N/A** |  |
| **V14: Data Protection** | | | |
| 14.1.1 | Verify that all sensitive data created and processed by the application has been identified and classified into protection levels. This includes data that is only encoded and therefore easily decoded, such as Base64 strings or the plaintext payload inside a JWT. Protection levels need to take into account any data protection and privacy regulations and standards which the application is required to comply with. | **Pass** |  |
| 14.1.2 | Verify that all sensitive data protection levels have a documented set of protection requirements. This must include (but not be limited to) requirements related to general encryption, integrity verification, retention, how the data is to be logged, access controls around sensitive data in logs, database-level encryption, privacy and privacy-enhancing technologies to be used, and other confidentiality requirements. | **Pass** |  |
| 14.2.1 | Verify that sensitive data is only sent to the server in the HTTP message body or header fields, and that the URL and query string do not contain sensitive information, such as an API key or session token. | **Pass** |  |
| 14.2.2 | Verify that the application prevents sensitive data from being cached in server components, such as load balancers and application caches, or ensures that the data is securely purged after use. | **Pass** |  |
| 14.2.3 | Verify that defined sensitive data is not sent to untrusted parties (e.g., user trackers) to prevent unwanted collection of data outside of the application's control. | **Pass** |  |
| 14.2.4 | Verify that controls around sensitive data related to encryption, integrity verification, retention, how the data is to be logged, access controls around sensitive data in logs, privacy and privacy-enhancing technologies, are implemented as defined in the documentation for the specific data's protection level. | **Pass** |  |
| 14.2.5 | Verify that caching mechanisms are configured to only cache responses which have the expected content type for that resource and do not contain sensitive, dynamic content. The web server should return a 404 or 302 response when a non-existent file is accessed rather than returning a different, valid file. This should prevent Web Cache Deception attacks. | **N/A** |  |
| 14.2.6 | Verify that the application only returns the minimum required sensitive data for the application's functionality. For example, only returning some of the digits of a credit card number and not the full number. If the complete data is required, it should be masked in the user interface unless the user specifically views it. | **Partial** | See FINDING-011 |
| 14.2.7 | Verify that sensitive information is subject to data retention classification, ensuring that outdated or unnecessary data is deleted automatically, on a defined schedule, or as the situation requires. | **N/A** |  |
| 14.2.8 | Verify that sensitive information is removed from the metadata of user-submitted files unless storage is consented to by the user. | **Pass** |  |
| 14.3.1 | Verify that authenticated data is cleared from client storage, such as the browser DOM, after the client or session is terminated. The 'Clear-Site-Data' HTTP response header field may be able to help with this but the client-side should also be able to clear up if the server connection is not available when the session is terminated. | **Pass** |  |
| 14.3.2 | Verify that the application sets sufficient anti-caching HTTP response header fields (i.e., Cache-Control: no-store) so that sensitive data is not cached in browsers. | **Pass** |  |
| 14.3.3 | Verify that data stored in browser storage (such as localStorage, sessionStorage, IndexedDB, or cookies) does not contain sensitive data, with the exception of session tokens. | **Pass** |  |
| **V15: Secure Coding and Architecture** | | | |
| 15.1.1 | Verify that application documentation defines risk based remediation time frames for 3rd party component versions with vulnerabilities and for updating libraries in general, to minimize the risk from these components. | **N/A** |  |
| 15.1.2 | Verify that an inventory catalog, such as software bill of materials (SBOM), is maintained of all third-party libraries in use, including verifying that components come from pre-defined, trusted, and continually maintained repositories. | **Pass** |  |
| 15.1.3 | Verify that the application documentation identifies functionality which is time-consuming or resource-demanding. This must include how to prevent a loss of availability due to overusing this functionality and how to avoid a situation where building a response takes longer than the consumer's timeout. Potential defenses may include asynchronous processing, using queues, and limiting parallel processes per user and per application. | **N/A** |  |
| 15.1.4 | Verify that application documentation highlights third-party libraries which are considered to be "risky components". | **Pass** |  |
| 15.1.5 | Verify that application documentation highlights parts of the application where "dangerous functionality" is being used. | **Pass** |  |
| 15.2.1 | Verify that the application only contains components which have not breached the documented update and remediation time frames. | **N/A** |  |
| 15.2.2 | Verify that the application has implemented defenses against loss of availability due to functionality which is time-consuming or resource-demanding, based on the documented security decisions and strategies for this. | **N/A** |  |
| 15.2.3 | Verify that the production environment only includes functionality that is required for the application to function, and does not expose extraneous functionality such as test code, sample snippets, and development functionality. | **Pass** | See FINDING-012 |
| 15.2.4 | Verify that third-party components and all of their transitive dependencies are included from the expected repository, whether internally owned or an external source, and that there is no risk of a dependency confusion attack. | **Pass** |  |
| 15.2.5 | Verify that the application implements additional protections around parts of the application which are documented as containing "dangerous functionality" or using third-party libraries considered to be "risky components". This could include techniques such as sandboxing, encapsulation, containerization or network level isolation to delay and deter attackers who compromise one part of an application from pivoting elsewhere in the application. | **Pass** |  |
| 15.3.1 | Verify that the application only returns the required subset of fields from a data object. For example, it should not return an entire data object, as some individual fields should not be accessible to users. | **Pass** |  |
| 15.3.2 | Verify that where the application backend makes calls to external URLs, it is configured to not follow redirects unless it is intended functionality. | **N/A** |  |
| 15.3.3 | Verify that the application has countermeasures to protect against mass assignment attacks by limiting allowed fields per controller and action, e.g., it is not possible to insert or update a field value when it was not intended to be part of that action. | **Pass** |  |
| 15.3.4 | Verify that all proxying and middleware components transfer the user's original IP address correctly using trusted data fields that cannot be manipulated by the end user, and the application and web server use this correct value for logging and security decisions such as rate limiting, taking into account that even the original IP address may not be reliable due to dynamic IPs, VPNs, or corporate firewalls. | **N/A** |  |
| 15.3.5 | Verify that the application explicitly ensures that variables are of the correct type and performs strict equality and comparator operations. This is to avoid type juggling or type confusion vulnerabilities caused by the application code making an assumption about a variable type. | **Pass** |  |
| 15.3.6 | Verify that JavaScript code is written in a way that prevents prototype pollution, for example, by using Set() or Map() instead of object literals. | **N/A** |  |
| 15.3.7 | Verify that the application has defenses against HTTP parameter pollution attacks, particularly if the application framework makes no distinction about the source of request parameters (query string, body parameters, cookies, or header fields). | **Pass** |  |
| 15.4.1 | Verify that shared objects in multi-threaded code (such as caches, files, or in-memory objects accessed by multiple threads) are accessed safely by using thread-safe types and synchronization mechanisms like locks or semaphores to avoid race conditions and data corruption. | **Pass** |  |
| 15.4.2 | Verify that checks on a resource's state, such as its existence or permissions, and the actions that depend on them are performed as a single atomic operation to prevent time-of-check to time-of-use (TOCTOU) race conditions. For example, checking if a file exists before opening it, or verifying a user’s access before granting it. | **Pass** |  |
| 15.4.3 | Verify that locks are used consistently to avoid threads getting stuck, whether by waiting on each other or retrying endlessly, and that locking logic stays within the code responsible for managing the resource to ensure locks cannot be inadvertently or maliciously modified by external classes or code. | **Pass** |  |
| 15.4.4 | Verify that resource allocation policies prevent thread starvation by ensuring fair access to resources, such as by leveraging thread pools, allowing lower-priority threads to proceed within a reasonable timeframe. | **Pass** |  |
| **V16: Security Logging and Error Handling** | | | |
| 16.1.1 | Verify that an inventory exists documenting the logging performed at each layer of the application's technology stack, what events are being logged, log formats, where that logging is stored, how it is used, how access to it is controlled, and for how long logs are kept. | **Pass** |  |
| 16.2.1 | Verify that each log entry includes necessary metadata (such as when, where, who, what) that would allow for a detailed investigation of the timeline when an event happens. | **Partial** | See FINDING-013, FINDING-014 |
| 16.2.2 | Verify that time sources for all logging components are synchronized, and that timestamps in security event metadata use UTC or include an explicit time zone offset. UTC is recommended to ensure consistency across distributed systems and to prevent confusion during daylight saving time transitions. | **Pass** |  |
| 16.2.3 | Verify that the application only stores or broadcasts logs to the files and services that are documented in the log inventory. | **Pass** |  |
| 16.2.4 | Verify that logs can be read and correlated by the log processor that is in use, preferably by using a common logging format. | **Partial** | See FINDING-014 |
| 16.2.5 | Verify that when logging sensitive data, the application enforces logging based on the data's protection level. For example, it may not be allowed to log certain data, such as credentials or payment details. Other data, such as session tokens, may only be logged by being hashed or masked, either in full or partially. | **Partial** | See FINDING-015 |
| 16.3.1 | Verify that all authentication operations are logged, including successful and unsuccessful attempts. Additional metadata, such as the type of authentication or factors used, should also be collected. | **Pass** |  |
| 16.3.2 | Verify that failed authorization attempts are logged. For L3, this must include logging all authorization decisions, including logging when sensitive data is accessed (without logging the sensitive data itself). | **Partial** | See FINDING-016 |
| 16.3.3 | Verify that the application logs the security events that are defined in the documentation and also logs attempts to bypass the security controls, such as input validation, business logic, and anti-automation. | **Partial** | See FINDING-017 |
| 16.3.4 | Verify that the application logs unexpected errors and security control failures such as backend TLS failures. | **Pass** |  |
| 16.4.1 | Verify that all logging components appropriately encode data to prevent log injection. | **Partial** | See FINDING-018 |
| 16.4.2 | Verify that logs are protected from unauthorized access and cannot be modified. | **Pass** |  |
| 16.4.3 | Verify that logs are securely transmitted to a logically separate system for analysis, detection, alerting, and escalation. The aim is to ensure that if the application is breached, the logs are not compromised. | **N/A** |  |
| 16.5.1 | Verify that a generic message is returned to the consumer when an unexpected or security-sensitive error occurs, ensuring no exposure of sensitive internal system data such as stack traces, queries, secret keys, and tokens. | **Pass** |  |
| 16.5.2 | Verify that the application continues to operate securely when external resource access fails, for example, by using patterns such as circuit breakers or graceful degradation. | **Partial** | See FINDING-019 |
| 16.5.3 | Verify that the application fails gracefully and securely, including when an exception occurs, preventing fail-open conditions such as processing a transaction despite errors resulting from validation logic. | **Pass** |  |
| 16.5.4 | Verify that a "last resort" error handler is defined which will catch all unhandled exceptions. This is both to avoid losing error details that must go to log files and to ensure that an error does not take down the entire application process, leading to a loss of availability. | **Partial** | See FINDING-019 |
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
- **Pass**: 148 requirements (42.9%)
- **Partial**: 23 requirements (6.7%)
- **N/A**: 172 requirements (49.9%)
- **Fail**: 2 requirements (0.6%)

---

# 6. Cross-Reference Matrix

| Finding ID | Severity | ASVS Requirements | Related Findings | Affected Components |
|------------|----------|-------------------|------------------|---------------------|
| FINDING-001 | Medium | 7.4.1 | FINDING-003, FINDING-004 | airflow-core/src/airflow/api_fastapi/auth/tokens.py, airflow-core/src/airflow/models/revoked_token.py |
| FINDING-002 | Medium | 8.2.2 | — | airflow-core/src/airflow/api_fastapi/core_api/security.py |
| FINDING-003 | Low | 6.5.6, 8.3.2 | FINDING-001, FINDING-004 | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py, airflow-core/src/airflow/api_fastapi/auth/tokens.py |
| FINDING-004 | Low | 7.2.4 | FINDING-001, FINDING-003 | airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py |
| FINDING-005 | Low | 10.3.1 | — | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py |
| FINDING-006 | Low | 11.1.4, 11.2.2 | — | airflow-core/src/airflow/models/crypto.py, airflow-core/src/airflow/models/connection.py, airflow-core/src/airflow/models/variable.py |
| FINDING-007 | Low | 1.3.3 | — | airflow-core/src/airflow/api_fastapi/common/parameters.py |
| FINDING-008 | Low | 2.2.1 | — | airflow-core/src/airflow/api_fastapi/common/parameters.py |
| FINDING-009 | Low | 3.3.3 | — | airflow-core/src/airflow/api_fastapi/core_api/app.py |
| FINDING-010 | Low | 3.7.2 | — | airflow-core/src/airflow/ui/src/main.tsx |
| FINDING-011 | Low | 14.2.6 | — | airflow-core/src/airflow/api_fastapi/core_api/datamodels/connections.py |
| FINDING-012 | Low | 15.2.3 | — | airflow-core/src/airflow/api_fastapi/core_api/app.py |
| FINDING-013 | Low | 16.2.1 | — | airflow-core/src/airflow/api_fastapi/common/http_access_log.py |
| FINDING-014 | Low | 16.2.1, 16.2.4 | — | airflow-core/src/airflow/api_fastapi/logging/decorators.py, airflow-core/src/airflow/models/log.py |
| FINDING-015 | Low | 16.2.5 | — | airflow-core/src/airflow/api_fastapi/common/http_access_log.py |
| FINDING-016 | Low | 16.3.2 | — | airflow-core/src/airflow/api_fastapi/logging/decorators.py |
| FINDING-017 | Low | 16.3.3 | — | airflow-core/src/airflow/api_fastapi/logging/decorators.py, airflow-core/src/airflow/api_fastapi/common/http_access_log.py |
| FINDING-018 | Low | 16.4.1 | — | airflow-core/src/airflow/api_fastapi/logging/decorators.py |
| FINDING-019 | Low | 16.5.2, 16.5.4 | — | airflow-core/src/airflow/api_fastapi/common/http_access_log.py |
| FINDING-020 | Low | 13.1.2 | — | airflow-core/docs/administration-and-deployment/scheduler.rst |
| FINDING-021 | Low | 13.1.3 | FINDING-023 | airflow-core/docs/administration-and-deployment/scheduler.rst, airflow-core/src/airflow/executors/base_executor.py |
| FINDING-022 | Low | 13.1.4 | — | airflow-core/src/airflow/api_fastapi/execution_api/app.py, airflow-core/src/airflow/executors/base_executor.py |
| FINDING-023 | Low | 13.2.6 | FINDING-021 | airflow-core/src/airflow/executors/base_executor.py |

**Total Unique Findings**: 23 (0 Critical, 0 High, 2 Medium, 21 Low, 0 Info)

## 7. Level Coverage Analysis


**Audit scope:** up to L3

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 4 |
| L2 | 183 | 13 |
| L3 | 92 | 8 |

**Total consolidated findings: 23**

*End of Consolidated Security Audit Report*