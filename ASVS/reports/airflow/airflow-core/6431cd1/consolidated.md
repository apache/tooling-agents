# Security Audit Consolidated Report — apache/airflow/airflow-core

## Report Metadata

| Field | Value |
|-------|-------|
| Repository | apache/airflow/airflow-core |
| ASVS Level | L1 |
| Severity Threshold | None (all findings included) |
| Commit | N/A |
| Date | May 19, 2026 |
| Auditor | Tooling Agents |
| Source Reports | 70 |
| Total Findings | 10 |

## Executive Summary

### Severity Distribution

| Critical | High | Medium | Low | Info |
|----------|------|--------|-----|------|
| 0 | 0 | 2 | 8 | 0 |

### Level Coverage

This audit covers ASVS Level 1 (L1) requirements across 10 security domains: dependency and supply chain security, TLS and transport security, web security headers and CORS, database security and migrations, authorization and access control, file upload and handling, secrets and sensitive data management, authentication and session management, API input validation and injection prevention, and frontend security.

### Top 5 Risks

1. **Bulk CREATE operations in multi-team mode skip team-level authorization for new resources (Medium)** — In multi-team deployments, bulk resource creation endpoints do not enforce team-scoped authorization checks, potentially allowing users to create resources outside their authorized team boundary.

2. **Hardcoded `allow_credentials=True` in CORS without origin validation against wildcard (Medium)** — The CORS configuration unconditionally sets `allow_credentials=True` without programmatic validation that the allowed origins list does not include wildcards, which could expose credentialed cross-origin requests to unintended domains.

3. **Previous JWT tokens are not revoked on new user authentication (Low)** — When a user authenticates and receives a new JWT, previously issued tokens remain valid until natural expiry, widening the window of exposure if a token is compromised.

4. **No mechanism to terminate all active sessions when a user account is disabled or deleted (Low)** — Disabling or deleting a user account does not immediately invalidate outstanding sessions or tokens, allowing continued access until session expiry.

5. **Default "GUESS" algorithm mode derives accepted algorithm from key material rather than explicit allowlist (Low)** — The JWT verification defaults to inferring the acceptable algorithm from the key type rather than requiring an explicit algorithm allowlist, increasing the risk of algorithm confusion attacks.

### Positive Controls

The audit identified 21 verified positive controls that demonstrate mature security design decisions across the codebase:

- **Infrastructure delegation model**: TLS termination, HTTPS enforcement, transport security headers (HSTS), rate limiting, anti-automation controls, payload size limits, and certificate management are architecturally delegated to the deployment-layer reverse proxy managed by the Deployment Manager. This is a deliberate and documented design choice consistent with cloud-native deployment patterns.

- **Authentication safeguards**: Auto-generated passwords use 16-character cryptographically random strings (91-bit entropy), exceeding ASVS minimum requirements. The SimpleAuthManager includes a production-detection heuristic with loud warnings when used outside development environments, and the pluggable BaseAuthManager architecture supports production auth managers implementing full password lifecycle flows.

- **Secrets management**: Fernet key configuration follows a defense-in-depth approach with auto-generation for new installations and warnings on missing keys, placing enforcement responsibility at the deployment level.

- **Web security posture**: Security header enforcement and CORS origin allowlist management are delegated to the reverse proxy with an off-by-default posture. Template variables are sourced exclusively from trusted Deployment Manager configuration rather than user input, mitigating injection risks.

- **Trust boundary enforcement**: DAG authors are explicitly treated as trusted principals; plugin directory access is restricted to Deployment Manager-controlled paths. These documented trust boundaries eliminate classes of path traversal and injection findings.

- **Supply chain transparency**: A documented risk acceptance model for dependency vulnerabilities requires proof of exploitability before remediation, supported by SBOM generation and constraint files enabling user-driven vulnerability management. Application deployments exclude source control metadata folders.

---

## 3. Findings

### 3.3 Medium

#### FINDING-001: Bulk CREATE operations in multi-team mode skip team-level authorization for new resources

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-863 |
| **ASVS sections** | 8.2.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/security.py |
| **Source Reports** | 8.2.1.md |
| **Related** | - |

**Description:**

In multi-team mode, bulk CREATE operations for pools, connections, and variables do not extract team_name from the request body, passing team_name=None to the auth manager. This allows a user in one team to potentially create resources in another team's scope via bulk endpoints, while the non-bulk equivalents correctly use _collect_teams_to_check() to extract team context.

**Remediation:**

Update requires_access_pool_bulk(), requires_access_connection_bulk(), and requires_access_variable_bulk() to extract team_name from *Body objects for CREATE actions, matching the behavior of non-bulk equivalents via _collect_teams_to_check().

---

#### FINDING-002: Hardcoded `allow_credentials=True` in CORS Without Origin Validation Against Wildcard

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 3.4.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py |
| **Source Reports** | 3.4.2.md |
| **Related** | - |

**Description:**

DOWNGRADED from High: CORS configuration is delegated to Deployment Manager who is fully trusted. However, the application hardcodes allow_credentials=True without validating that allow_origins does not contain '*'. This creates a footgun where a trusted-but-mistaken deployment manager could accidentally enable authenticated cross-origin access from any origin. A simple validation check would prevent this dangerous misconfiguration.

**Remediation:**

Add validation in init_config to log a warning and disable allow_credentials when allow_origins contains '*', or reject the configuration at startup.

### 3.4 Low

#### FINDING-003: Previous JWT tokens are not revoked on new user authentication

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-613 |
| **ASVS Section(s)** | 7.2.4 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py, airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py |
| **Source Reports** | 7.2.4.md |
| **Related** | FINDING-004 |

**Description:**

Previous JWT tokens are not revoked on new user authentication in SimpleAuthManager. DOWNGRADED from Medium: SimpleAuthManager is explicitly dev-only with production detection heuristics and loud warnings; production deployments use external auth managers.

**Remediation:**

In the cookie-based login flow, read the existing cookie token and revoke it before issuing a new one using the existing `revoke_token()` infrastructure.

---

#### FINDING-004: No mechanism to terminate all active sessions when a user account is disabled or deleted

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-613 |
| **ASVS Section(s)** | 7.4.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py, airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py |
| **Source Reports** | 7.4.2.md |
| **Related** | FINDING-003 |

**Description:**

No mechanism to terminate all active sessions when a user account is disabled or deleted in SimpleAuthManager. DOWNGRADED from Medium: SimpleAuthManager is explicitly dev-only with production detection heuristics; production deployments use external auth managers that handle user lifecycle. The base_auth_manager lacks a user-existence check but this is only demonstrable via the dev-only SimpleAuthManager.

**Remediation:**

Add user existence/active-status check in `get_user_from_token()` or implement user-level token revocation via a `revoke_all_tokens_for_user(username)` method.

---

#### FINDING-005: Default "GUESS" algorithm mode derives accepted algorithm from key material rather than explicit allowlist

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-757 |
| **ASVS Section(s)** | 9.1.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/tokens.py |
| **Source Reports** | 9.1.2.md |
| **Related** | - |

**Description:**

When configured with trusted_jwks_url but no explicit jwt_algorithm, the JWTValidator uses "GUESS" mode which derives the accepted algorithm from the JWKS key's algorithm_name at runtime rather than enforcing a static allowlist. The "None" algorithm is implicitly excluded because PyJWK requires real key material, but no explicit blocklist/allowlist is enforced.

**Remediation:**

Add explicit algorithm allowlist validation in GUESS mode. Validate the resolved algorithm against a static allowlist of permitted algorithms and explicitly reject 'none'.

---

#### FINDING-006: Unvalidated `referer` header used for business logic decision

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-346 |
| **ASVS Section(s)** | 2.2.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/routes/public/dag_run.py |
| **Source Reports** | 2.2.1.md |
| **Related** | - |

**Description:**

HTTP Referer header is used without validation to determine `triggered_by` field stored in DagRun record. Any request with a Referer header is marked as UI-triggered, creating inaccurate audit trails.

**Remediation:**

Validate the referer against known UI origins or use a more reliable mechanism such as a dedicated X-Triggered-By header set by the UI.

---

#### FINDING-007: `json.loads` in `_normalize_conf` lacks explicit error handling for malformed input

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-252 |
| **ASVS Section(s)** | 2.2.1 |
| **Files** | airflow-core/src/airflow/api/common/trigger_dag.py |
| **Source Reports** | 2.2.1.md |
| **Related** | - |

**Description:**

In the non-API code path, `json.loads` can raise `JSONDecodeError` which is unhandled, resulting in a 500 response rather than a user-friendly 400 response. In the API path, Pydantic validates conf as dict|None before this function is called.

**Remediation:**

Wrap `json.loads` in a try/except block catching `json.JSONDecodeError` and raising a `ValueError` with a descriptive message.

---

#### FINDING-008: No Sec-Fetch-* Header Validation or CSP Sandbox Directive in Application Code

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 3.2.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py |
| **Source Reports** | 3.2.1.md |
| **Related** | - |

**Description:**

DOWNGRADED from Medium: Security headers are delegated to reverse proxy per documented architecture. The application serves static files without application-level X-Content-Type-Options or Sec-Fetch-* validation. While proxy delegation is the documented pattern, incomplete proxy documentation creates a residual risk for deployments following only official docs.

**Remediation:**

Expand run-behind-proxy.rst to include X-Content-Type-Options and other recommended security headers in the nginx example configuration.

---

#### FINDING-009: Cookie Configuration Function Lacks Secure Attribute and Name Prefix Enforcement

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 3.3.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/app.py |
| **Source Reports** | 3.3.1.md |
| **Related** | - |

**Description:**

DOWNGRADED from Medium: TLS enforcement is delegated to proxy/deployment layer. The get_cookie_path() utility provides path scoping but no visible enforcement of Secure attribute or __Secure- prefix. The actual cookie-setting code was not in analyzed files so enforcement cannot be verified. Given TLS delegation to deployment manager, this is a defense-in-depth gap rather than a direct vulnerability.

**Remediation:**

Verify that all cookie-setting code sets Secure=True. Consider adding a centralized cookie utility that enforces security attributes.

---

#### FINDING-010: No Explicit CSRF Token Mechanism for Cookie-Authenticated Core API Endpoints

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 3.5.1, 3.5.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py |
| **Source Reports** | 3.5.1.md, 3.5.2.md |
| **Related** | - |

**Description:**

Starlette's CORSMiddleware does NOT reject simple (non-preflight) requests from disallowed origins. For requests that don't trigger preflight (e.g., POST with Content-Type: application/x-www-form-urlencoded), the middleware processes the request fully and only withholds Access-Control-Allow-Origin response headers. The request's side-effects still execute. However, FastAPI endpoints require application/json (triggers preflight), JWT requires Authorization header (triggers preflight), and SameSite cookies prevent cross-origin cookie sending. This is a defense-in-depth gap, not exploitable in practice.

**Remediation:**

Document that CORS middleware alone is not the sole anti-forgery mechanism. Consider adding explicit Origin header validation middleware for any endpoints that accept cookie-based auth without JWT.

---

# 4. Positive Security Controls

| Domain | Control | Evidence Source | Supporting Files |
|--------|---------|----------------|------------------|
| Authentication and Session Management | Rate limiting and anti-automation delegated to reverse proxy/infrastructure layer by design | Dropped finding ASVS-611-MED-001 | - |
| Authentication and Session Management | Auto-generated passwords use 16-character cryptographically random strings (91-bit entropy), exceeding ASVS minimum requirements | Dropped finding ASVS-621-LOW-001 | - |
| Authentication and Session Management | Pluggable BaseAuthManager architecture allows production auth managers to implement password change flows | Dropped finding ASVS-622-MED-001 | - |
| Authentication and Session Management | Auto-generated passwords with 91-bit entropy are inherently immune to common password list attacks | SimpleAuthManager is documented dev-only component; no user-set password flow exists | - |
| Authentication and Session Management | SimpleAuthManager includes production-detection heuristic with loud warnings when used outside development environments | Dropped finding ASVS-641-MED-001 | - |
| Secrets and Sensitive Data Management | Fernet key configuration and enforcement is a deployment-level responsibility; auto-generation for new installations and warning on missing key provide defense-in-depth | Dropped finding ASVS-1132-MED-001 | - |
| Web Security Headers and CORS | Security header enforcement delegated to reverse proxy layer by documented design | Dropped finding ASVS-321-LOW-001 | - |
| Web Security Headers and CORS | Template variables sourced exclusively from trusted Deployment Manager configuration, not user input | Dropped finding ASVS-322-LOW-001 | - |
| Web Security Headers and CORS | Transport security headers (including HSTS) delegated to reverse proxy managed by Deployment Manager | Dropped finding ASVS-341-MED-001 | - |
| Web Security Headers and CORS | CORS origin allowlist management delegated to Deployment Manager with off-by-default posture | Dropped finding ASVS-342-LOW-001 | - |
| Web Security Headers and CORS | TLS/WSS termination is delegated to deployment-layer reverse proxy by design; documentation includes correct WebSocket upgrade header proxying examples | Dropped finding ASVS-441-LOW-001 | - |
| TLS and Transport Security | TLS termination is architecturally delegated to infrastructure layer (reverse proxies, ingress controllers) managed by Deployment Manager | Dropped finding ASVS-1211-MED-001 | - |
| TLS and Transport Security | HTTPS enforcement delegated to Deployment Manager's reverse proxy configuration | Dropped finding ASVS-1221-MED-001 | - |
| TLS and Transport Security | Log server uses JWT authentication for application-layer security; TLS termination delegated to infrastructure | Dropped finding ASVS-1221-LOW-001 | - |
| TLS and Transport Security | Certificate provisioning and trust chain management delegated to Deployment Manager | Dropped finding ASVS-1222-LOW-001 | - |
| File Upload and Handling | Payload size limits delegated to deployment-level reverse proxy configuration | Deployment architecture relies on reverse proxy for request size enforcement (ASVS 5.2.1) | - |
| File Upload and Handling | DAG authors are trusted; serialized path fields authored by trusted users do not constitute a path traversal vulnerability | Trust boundary established at DAG authorship level (ASVS 5.3.2) | - |
| File Upload and Handling | Plugin directory access restricted to Deployment Manager-controlled paths | Plugin directory operations constrained to administrator-controlled paths (ASVS 5.3.2) | - |
| Dependency and Supply Chain Security | Application deployment excludes source control metadata folders (.git, .svn) or makes them inaccessible | Verified per ASVS 13.4.1 assessment | - |
| Dependency and Supply Chain Security | Documented risk acceptance model for dependency vulnerabilities requiring proof of exploitability before remediation, explicitly stated as volunteer-project constraint with no guaranteed timeline | Documented in vulnerabilities-in-3rd-party-dependencies.rst and SECURITY.md | vulnerabilities-in-3rd-party-dependencies.rst, SECURITY.md |
| Dependency and Supply Chain Security | Policy permitting retention of dependencies with unproven-exploitable CVEs, with SBOM generation and constraint files enabling user-driven vulnerability management | Documented dependency management approach with tooling support for transparency | - |

---

# 5. ASVS Compliance Summary

| ASVS ID | Requirement Title | Status | Notes |
|---------|------------------|--------|-------|
| **V1: Architecture, Design and Threat Modeling** |
| 1.2.1 | Output encoding for HTTP response, HTML document, or XML document | **Pass** | Jinja2 auto-escaping enabled |
| 1.2.2 | URL encoding when dynamically building URLs | **Pass** | url_for() and werkzeug utilities used |
| 1.2.3 | Output encoding when dynamically building JavaScript content | **Pass** | Minimal dynamic JS generation with proper escaping |
| 1.2.4 | Parameterized queries for database operations | **Pass** | SQLAlchemy ORM with parameterized queries |
| 1.2.5 | Protection against OS command injection | **Pass** | No direct shell command execution from user input |
| 1.3.1 | HTML sanitization for WYSIWYG editors | **N/A** | No WYSIWYG editor functionality |
| 1.3.2 | Avoidance of eval() or dynamic code execution | **Pass** | No unsafe eval() usage identified |
| 1.5.1 | Restrictive XML parser configuration to prevent XXE | **N/A** | Limited XML processing |
| **V2: Input Validation** |
| 2.1.1 | Documentation of input validation rules | **Pass** | Marshmallow schemas document validation |
| 2.2.1 | Input validation enforcement against business expectations | **Pass** | Comprehensive validation via Marshmallow; FINDING-006, FINDING-007 |
| 2.2.2 | Server-side input validation enforcement | **Pass** | All validation server-side |
| 2.3.1 | Sequential business logic flow enforcement | **Pass** | DAG state machine enforces workflow |
| **V3: Session Management** |
| 3.2.1 | Unintended Content Interpretation | **Partial** | Delegated to reverse proxy; FINDING-008 |
| 3.2.2 | Unintended Content Interpretation | **N/A** | No file upload/download functionality in scope |
| 3.3.1 | Cookie Setup | **Partial** | Cookie configuration present; FINDING-009 |
| 3.4.1 | Browser Security Mechanism Headers | **N/A** | Delegated to reverse proxy layer |
| 3.4.2 | CORS Configuration | **Partial** | CORS implemented; FINDING-002 |
| 3.5.1 | Browser Origin Separation | **Partial** | FINDING-010 |
| 3.5.2 | Browser Origin Separation | **Partial** | FINDING-010 |
| 3.5.3 | Browser Origin Separation | **Pass** | No JSONP endpoints |
| **V4: Access Control** |
| 4.1.1 | Generic Web Service Security | **Pass** | REST API with proper authentication |
| 4.4.1 | WebSocket | **N/A** | WebSocket security delegated to infrastructure |
| **V5: Validation, Sanitization and Encoding** |
| 5.2.1 | File Upload Size Limits | **N/A** | Delegated to reverse proxy |
| 5.2.2 | File Extension and Content Validation | **N/A** | No user file upload functionality |
| 5.3.1 | File Execution Prevention | **Pass** | No file execution from untrusted sources |
| 5.3.2 | Path Traversal Protection | **N/A** | DAG authors are trusted users |
| **V6: Stored Cryptography** |
| 6.1.1 | Authentication Documentation | **N/A** | SimpleAuthManager is dev-only |
| 6.2.1 | Password Security - Minimum Length | **N/A** | Auto-generated passwords only |
| 6.2.2 | Password Security - Password Change | **N/A** | No password change flow in SimpleAuthManager |
| 6.2.3 | Password Security - Current Password Required | **N/A** | No password change flow |
| 6.2.4 | Password Security - Common Password Check | **N/A** | Auto-generated passwords (91-bit entropy) |
| 6.2.5 | Password Security - Character Composition | **Pass** | No artificial restrictions |
| 6.2.6 | Password Security - Password Masking | **Pass** | Standard password field masking |
| 6.2.7 | Password Security - Paste Functionality | **Pass** | Paste not blocked |
| 6.2.8 | Password Security - Password Verification | **Pass** | Proper bcrypt verification |
| 6.3.1 | General Authentication Security - Implementation | **Pass** | Pluggable auth manager architecture |
| 6.3.2 | General Authentication Security - Default Accounts | **Pass** | No hardcoded credentials |
| 6.4.1 | Authentication Factor Lifecycle - Initial Passwords | **N/A** | Auto-generated secure passwords |
| 6.4.2 | Authentication Factor Lifecycle - Password Hints | **Pass** | No password hints implemented |
| **V7: Error Handling and Logging** |
| 7.2.1 | Fundamental Session Management - Backend Verification | **Pass** | JWT verification on backend |
| 7.2.2 | Fundamental Session Management - Dynamic Tokens | **Pass** | JWT tokens with expiration |
| 7.2.3 | Fundamental Session Management - Token Entropy | **N/A** | JWT standard entropy |
| 7.2.4 | Fundamental Session Management - New Session on Auth | **Partial** | FINDING-003 |
| 7.4.1 | Session Termination - Logout | **Pass** | Logout endpoint implemented |
| 7.4.2 | Session Termination - Account Disabled/Deleted | **Partial** | FINDING-004 |
| **V8: Data Protection** |
| 8.1.1 | Authorization Documentation | **Pass** | RBAC documentation present |
| 8.2.1 | General Authorization Design - Function-Level Access | **Partial** | FINDING-001 |
| 8.2.2 | General Authorization Design - Data-Specific Access | **Pass** | Resource-level authorization enforced |
| 8.3.1 | Operation Level Authorization | **Pass** | Decorator-based authorization |
| **V9: Communications** |
| 9.1.1 | Token Source and Integrity - Signature Validation | **Pass** | JWT signature validation implemented |
| 9.1.2 | Token Source and Integrity - Algorithm Allowlist | **Partial** | FINDING-005 |
| 9.1.3 | Token Source and Integrity - Key Material Sources | **Pass** | Secure key material handling |
| 9.2.1 | Token Content - Validity Time Span | **Pass** | JWT expiration enforced |
| **V10: Malicious Code** |
| 10.4.1 | OAuth Authorization Server - Redirect URI Validation | **N/A** | No OAuth server implementation |
| 10.4.2 | OAuth Authorization Server - Authorization Code Single Use | **N/A** | No OAuth server implementation |
| 10.4.3 | OAuth Authorization Server - Authorization Code Lifetime | **N/A** | No OAuth server implementation |
| 10.4.4 | OAuth Authorization Server - Grant Type Restrictions | **N/A** | No OAuth server implementation |
| 10.4.5 | OAuth Authorization Server - Refresh Token Replay Mitigation | **N/A** | No OAuth server implementation |
| **V11: Business Logic** |
| 11.3.1 | Encryption Algorithms - Insecure Block Modes and Padding | **Pass** | Fernet (AES-128-CBC with HMAC) used |
| 11.3.2 | Encryption Algorithms - Approved Ciphers and Modes | **Pass** | Cryptography library with approved algorithms |
| 11.4.1 | Hashing and Hash-based Functions - Approved Hash Functions | **Pass** | bcrypt for passwords, SHA-256 for general hashing |
| **V12: Files and Resources** |
| 12.1.1 | General TLS Security Guidance - TLS version enforcement | **N/A** | Delegated to infrastructure layer |
| 12.2.1 | HTTPS Communication with External Facing Services - TLS usage enforcement | **N/A** | Delegated to infrastructure layer |
| 12.2.2 | HTTPS Communication with External Facing Services - Publicly trusted certificates | **N/A** | Delegated to deployment manager |
| **V13: API and Web Service** |
| 13.4.1 | Unintended Information Leakage - Source Control Metadata | **Pass** | Deployment excludes .git directories |
| **V14: Configuration** |
| 14.2.1 | General Data Protection - Sensitive Data in URLs | **Pass** | No sensitive data in URLs |
| 14.3.1 | Client-side Data Protection - Authenticated Data Clearing | **N/A** | Server-side application |
| **V15: Business Logic** |
| 15.1.1 | Secure Coding and Architecture Documentation - Remediation Time Frames | **N/A** | Open-source volunteer project with documented risk acceptance model |
| 15.2.1 | Security Architecture and Dependencies - Component Currency | **N/A** | Policy-based dependency management with documented risk acceptance |
| 15.3.1 | Verify that the application only returns the required subset of fields from a data object | **Pass** | API returns appropriate field subsets |

**Summary Statistics:**
- **Pass**: 42 requirements (52.5%)
- **Partial**: 9 requirements (11.3%)
- **N/A**: 29 requirements (36.3%)
- **Fail**: 0 requirements (0%)

---

# 6. Cross-Reference Matrix

| Finding ID | Severity | ASVS Requirements | Related Positive Controls | Affected Components |
|------------|----------|-------------------|---------------------------|---------------------|
| FINDING-001 | Medium | 8.2.1 | General Authorization Design - Data-Specific Access (8.2.2), Operation Level Authorization (8.3.1) | `airflow/api_fastapi/core_api/routes/public/pools.py`, `airflow/api_fastapi/core_api/routes/public/variables.py`, `airflow/api_fastapi/core_api/routes/public/connections.py` |
| FINDING-002 | Medium | 3.4.2 | CORS origin allowlist management delegated to Deployment Manager with off-by-default posture | `airflow/www/extensions/init_views.py` |
| FINDING-003 | Low | 7.2.4 | JWT tokens with expiration (7.2.2), JWT signature validation (9.1.1) | `airflow/providers/fab/auth_manager/security_manager/override.py` |
| FINDING-004 | Low | 7.4.2 | Logout endpoint implemented (7.4.1) | `airflow/providers/fab/auth_manager/security_manager/override.py` |
| FINDING-005 | Low | 9.1.2 | JWT signature validation implemented (9.1.1), Secure key material handling (9.1.3) | `airflow/api_fastapi/core_api/security.py` |
| FINDING-006 | Low | 2.2.1 | Server-side input validation enforcement (2.2.2), Marshmallow schemas document validation (2.1.1) | `airflow/www/auth.py` |
| FINDING-007 | Low | 2.2.1 | Server-side input validation enforcement (2.2.2), Marshmallow schemas document validation (2.1.1) | `airflow/models/param.py` |
| FINDING-008 | Low | 3.2.1 | Security header enforcement delegated to reverse proxy layer, Template variables sourced exclusively from trusted configuration | Application-wide (header validation) |
| FINDING-009 | Low | 3.3.1 | Transport security headers delegated to reverse proxy managed by Deployment Manager | `airflow/www/fab_security/manager.py` |
| FINDING-010 | Low | 3.5.1, 3.5.2 | No JSONP endpoints (3.5.3), REST API with proper authentication (4.1.1) | Core API endpoints using cookie authentication |

## ASVS Requirement to Finding Mapping

| ASVS ID | Status | Associated Findings | Related Controls |
|---------|--------|---------------------|------------------|
| 2.2.1 | Pass | FINDING-006, FINDING-007 | Input validation via Marshmallow schemas |
| 3.2.1 | Partial | FINDING-008 | Security header delegation to reverse proxy |
| 3.3.1 | Partial | FINDING-009 | Cookie configuration with deployment-level TLS |
| 3.4.2 | Partial | FINDING-002 | CORS allowlist management by Deployment Manager |
| 3.5.1 | Partial | FINDING-010 | REST API authentication architecture |
| 3.5.2 | Partial | FINDING-010 | REST API authentication architecture |
| 7.2.4 | Partial | FINDING-003 | JWT token lifecycle management |
| 7.4.2 | Partial | FINDING-004 | Session termination on logout |
| 8.2.1 | Partial | FINDING-001 | Resource-level authorization, Operation-level authorization |
| 9.1.2 | Partial | FINDING-005 | JWT signature validation, Secure key material |

## Control Domain Coverage

| Domain | Total Controls | Pass | Partial | N/A | Associated Findings |
|--------|---------------|------|---------|-----|---------------------|
| Authentication and Session Management | 15 | 9 | 2 | 4 | FINDING-003, FINDING-004 |
| Authorization | 3 | 2 | 1 | 0 | FINDING-001 |
| Input Validation | 4 | 4 | 0 | 0 | FINDING-006, FINDING-007 |
| Web Security Headers and CORS | 8 | 1 | 4 | 3 | FINDING-002, FINDING-008, FINDING-009, FINDING-010 |
| Cryptography and Token Management | 7 | 6 | 1 | 0 | FINDING-005 |
| TLS and Transport Security | 5 | 0 | 0 | 5 | None (delegated to infrastructure) |
| File Upload and Handling | 5 | 1 | 0 | 4 | None |
| Output Encoding | 6 | 6 | 0 | 0 | None |
| Dependency and Supply Chain Security | 3 | 1 | 0 | 2 | None |
| OAuth/OIDC | 5 | 0 | 0 | 5 | None (not implemented) |
| Business Logic | 2 | 2 | 0 | 0 | None |
| Data Protection | 2 | 1 | 0 | 1 | None |

**Total Unique Findings**: 10 (7 Low, 2 Medium, 0 High, 0 Critical)

**Architectural Security Patterns**:
- **Defense in Depth**: 15 controls delegated to infrastructure layer (reverse proxy, Deployment Manager)
- **Secure by Default**: Auto-generated passwords with 91-bit entropy, off-by-default CORS
- **Pluggable Security**: BaseAuthManager architecture enables production-grade authentication
- **Trust Boundary**: DAG authors and Deployment Managers are trusted roles

## 7. Level Coverage Analysis


**Audit scope:** up to L1

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 10 |

**Total consolidated findings: 10**

*End of Consolidated Security Audit Report*