# Security Issues

## Issue: FINDING-001 - No Refresh Token Invalidation After Use — Replay Attack Possible
**Labels:** bug, security, priority:high
**Description:**
### Summary
The refresh token middleware implements token rotation (generating a new JWT after refresh) but does NOT invalidate the previous token after use. Per ASVS 10.4.5, when refresh token rotation is used, 'the authorization server must invalidate the refresh token after usage.' No such invalidation control exists in this middleware — there is no token blacklist, revocation list, or consumed-token tracking mechanism. An attacker who obtains a refresh token (JWT) at any point during its validity window can replay it to establish a parallel authenticated session, even after the legitimate user has already rotated to a newer token.

### Details
- **CWE:** CWE-294
- **ASVS Sections:** 10.4.5 (Level 1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py` (lines 45-70, 103-105)

### Remediation
Implement server-side token tracking with invalidation on use. When a token is used for refresh, mark it as consumed. If a consumed token is presented again, revoke all tokens in that family. Add a TokenStore interface with methods: is_consumed(), mark_consumed(), revoke_family(). Integrate token consumption checking in the dispatch() method before processing refresh requests. JWTs should include a jti (unique token ID) claim to enable tracking.

### Acceptance Criteria
- [ ] TokenStore interface implemented with consumption tracking
- [ ] JTI claim added to all refresh tokens
- [ ] Token consumption check integrated in dispatch() method
- [ ] Test added for replay attack prevention
- [ ] Test added for consumed token rejection

### References
- Source Report: 10.4.5.md
- Related Finding: FINDING-002

### Priority
High

---

## Issue: FINDING-002 - No Token Family Revocation on Reuse Detection
**Labels:** bug, security, priority:high
**Description:**
### Summary
ASVS 10.4.5 requires: 'revoke all refresh tokens for that authorization if an already used and invalidated refresh token is provided.' This is the critical security mechanism that limits damage from token theft — if an attacker replays a used token, the system should recognize this as compromise and revoke ALL tokens for that session/authorization, forcing re-authentication. No such mechanism exists in this middleware. There is no token family concept, no reuse detection, and no cascading revocation logic. Without family revocation, token theft cannot be detected or contained through the refresh mechanism.

### Details
- **CWE:** CWE-613
- **ASVS Sections:** 10.4.5 (Level 1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py` (lines 45-60, 103-105)

### Remediation
Implement token family tracking with automatic revocation. Create a TokenFamilyStore interface with methods: register_token(), mark_consumed(), is_consumed(), revoke_family(), is_family_revoked(). JWTs should include both a jti (unique token ID) and family_id claim to enable tracking. When a consumed token is presented (replay detected), automatically revoke all tokens in that family and force re-authentication. Implement this check at the beginning of the dispatch() method before processing any refresh logic.

### Acceptance Criteria
- [ ] TokenFamilyStore interface implemented
- [ ] Family_id claim added to refresh tokens
- [ ] Automatic family revocation on reuse detection
- [ ] Test added for family revocation on replay
- [ ] Test added for forced re-authentication after revocation

### References
- Source Report: 10.4.5.md
- Related Finding: FINDING-001

### Priority
High

---

## Issue: FINDING-003 - No Clear-Site-Data header implementation for session termination
**Labels:** bug, security, priority:high
**Description:**
### Summary
When a user logs out or their session is terminated, authenticated data (cached API responses, stored tokens in localStorage/sessionStorage, cookies) remains in the browser. This creates a risk that: Subsequent users on shared devices can access previously authenticated data from browser cache; Sensitive data persists in browser storage after logout; Tokens or session information remain available to client-side scripts. No control exists for clearing client-side authenticated data upon session termination.

### Details
- **ASVS Sections:** 14.3.1 (Level 1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/core_api/app.py` (entire file scope)

### Remediation
Implement a Clear-Site-Data header on logout responses and add client-side cleanup logic. Server-side (logout endpoint or middleware): Add response.headers["Clear-Site-Data"] = '"cache", "cookies", "storage"' on logout endpoint. Additionally, add a middleware that sets appropriate Cache-Control headers to prevent sensitive response caching using AuthenticatedResponseMiddleware that sets Cache-Control: no-store, no-cache, must-revalidate, private and Pragma: no-cache for API and UI paths.

### Acceptance Criteria
- [ ] Clear-Site-Data header added to logout endpoint
- [ ] AuthenticatedResponseMiddleware implemented with Cache-Control headers
- [ ] Test added for Clear-Site-Data header presence
- [ ] Test added for Cache-Control headers on authenticated responses
- [ ] Documentation updated with session termination security

### References
- Source Reports: 14.3.1.md

### Priority
High

---

## Issue: FINDING-004 - No Strict-Transport-Security (HSTS) header in middleware stack
**Labels:** bug, security, priority:high
**Description:**
### Summary
The complete middleware initialization function is shown, and no middleware sets the `Strict-Transport-Security` header. The domain context explicitly requires "Strict-Transport-Security (HSTS) to enforce HTTPS" with "A maximum age of at least 1 year." None of the registered middlewares (`JWTRefreshMiddleware`, auth manager middlewares, `GZipMiddleware`, `HttpAccessLogMiddleware`) appear to be security header middlewares. Without HSTS, users are vulnerable to SSL stripping attacks where an attacker downgrades the connection from HTTPS to HTTP. First-time visitors or those with expired HSTS cache are vulnerable. This enables credential theft, session hijacking, and content injection.

### Details
- **ASVS Sections:** 3.4.1 (Level 1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/core_api/app.py` (lines 172-189)

### Remediation
Implement an HSTS middleware that adds the Strict-Transport-Security header to all responses with max-age=31536000 (1 year), includeSubDomains, and optionally preload directives. Example implementation provided in the report shows a BaseHTTPMiddleware that sets the HSTS header on all responses.

### Acceptance Criteria
- [ ] HSTSMiddleware implemented and registered
- [ ] HSTS header includes max-age >= 31536000
- [ ] includeSubDomains directive included
- [ ] Test added for HSTS header presence on all responses
- [ ] Documentation updated with HSTS configuration

### References
- Source Report: 3.4.1.md

### Priority
High

---

## Issue: FINDING-005 - CORS `allow_credentials=True` hardcoded without origin wildcard validation
**Labels:** bug, security, priority:high
**Description:**
### Summary
The CORS configuration unconditionally sets `allow_credentials=True` without validating whether the origins list contains a wildcard (`*`). When an administrator configures `access_control_allow_origins = *`, Starlette's CORSMiddleware with `allow_credentials=True` will reflect the requesting `Origin` header value in `Access-Control-Allow-Origin` and include `Access-Control-Allow-Credentials: true`. This effectively allows ANY origin to make credentialed cross-origin requests. No allowlist validation logic is performed - the configured origins list is passed directly to the middleware without checking for `*`, validating format, or ensuring they're specific trusted domains.

### Details
- **ASVS Sections:** 3.4.2 (Level 1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/core_api/app.py` (lines 148-162)

### Remediation
Add validation to prevent `allow_credentials=True` when wildcard origin is configured. If `*` is detected in the origins list, either disable `allow_credentials` or reject the configuration. Additionally, validate that configured origins are proper URLs and preferably use HTTPS. Example: Check if '*' is in allow_origins list; if so, log a warning and set allow_credentials=False. For non-wildcard origins, validate they start with 'https://' or 'http://localhost' and log warnings for non-HTTPS origins.

### Acceptance Criteria
- [ ] Validation added to reject wildcard with credentials
- [ ] Origin URL format validation implemented
- [ ] HTTPS enforcement for production origins
- [ ] Test added for wildcard + credentials rejection
- [ ] Test added for origin format validation
- [ ] Configuration error logged with remediation guidance

### References
- Source Report: 3.4.2.md

### Priority
High

---

## Issue: FINDING-006 - API documentation demonstrates sending credentials over plaintext HTTP
**Labels:** bug, security, priority:high, documentation
**Description:**
### Summary
The API security documentation contains no mention of HTTPS requirements, HTTP-to-HTTPS redirect requirements, or HSTS (HTTP Strict Transport Security) headers. For an external-facing API, the documentation should explicitly state that TLS is mandatory and HTTP fallback must be disabled. Without explicit documentation requiring HTTPS and prohibiting HTTP fallback, deployers may configure the Airflow API server to accept both HTTP and HTTPS, or HTTP-only, violating ASVS 12.2.1's requirement that services 'do not fall back to insecure or unencrypted communications.'

### Details
- **ASVS Sections:** 12.2.1 (Level 1)
- **Affected Files:**
  - `airflow-core/docs/security/api.rst` (lines 45-55)

### Remediation
Update all API examples to use HTTPS and add a security warning. Include a prominent warning section stating that HTTPS (TLS) must always be used when communicating with the Airflow API, credentials must never be sent over unencrypted HTTP connections, and http://localhost examples are for local development only. Update all curl examples to use https:// URLs.

### Acceptance Criteria
- [ ] Security warning section added to API documentation
- [ ] All API examples updated to use HTTPS
- [ ] HTTP-only localhost exception documented for dev environments
- [ ] HSTS header requirements documented
- [ ] HTTP-to-HTTPS redirect guidance added

### References
- Source Report: 12.2.1.md

### Priority
High

---

## Issue: FINDING-007 - Missing Documentation of Risk-Based Remediation Timeframes for Third-Party Components
**Labels:** bug, security, priority:high, documentation
**Description:**
### Summary
The primary developer and architecture documentation (AGENTS.md) extensively documents security model boundaries, coding standards, testing requirements, and contribution workflows, but contains no section defining risk-based remediation timeframes for updating vulnerable third-party dependencies or libraries in general. No classification system (Critical/High/Medium/Low) with corresponding remediation timeframes exists. No distinction between actively exploited vulnerabilities vs. theoretical issues. No documentation of what constitutes a 'risky component' or 'dangerous functionality' in the context of third-party libraries.

### Details
- **ASVS Sections:** 15.1.1 (Level 1)
- **Affected Files:**
  - `AGENTS.md` (project-wide)

### Remediation
Create a dedicated security policy document (e.g., airflow-core/docs/security/dependency_management.rst or a top-level DEPENDENCY_POLICY.md) that includes: (1) Risk Classification and Remediation Timeframes with severity levels (Critical: 9.0-10.0 CVSS, 48 hours; High: 7.0-8.9, 7 days; Medium: 4.0-6.9, 30 days; Low: 0.1-3.9, 90 days max); (2) General Library Update Policy with quarterly reviews for all direct dependencies, 14-day updates for security-critical libraries, and 90-day migration plans for EOL libraries; (3) Dangerous Functionality Components list including deserialization libraries, code execution engines, cryptographic libraries, network/HTTP clients, and database drivers/ORMs; (4) Risky Component Identification criteria.

### Acceptance Criteria
- [ ] Dependency management policy document created
- [ ] Risk classification matrix with timeframes defined
- [ ] Dangerous functionality components list documented
- [ ] Risky component identification criteria established
- [ ] Policy linked from main security documentation

### References
- Source Report: 15.1.1.md
- Related Finding: FINDING-008

### Priority
High

---

## Issue: FINDING-008 - Cannot Verify Compliance — No Documented Timeframes Exist to Measure Against
**Labels:** bug, security, priority:high
**Description:**
### Summary
ASVS 15.2.1 requires verifying that the application only contains components which have not breached the documented update and remediation time frames. This verification is impossible because: 1) No remediation timeframes are documented (as identified in FINDING-007), 2) No automated enforcement mechanism exists in the CI/CD pipeline, 3) The uv.lock regeneration guidance treats dependency resolution as a conflict-resolution mechanism, not a security maintenance activity. The CI/CD pipeline includes static checks, type checking, testing, linting, and documentation building, but no dependency vulnerability scanning step is documented.

### Details
- **ASVS Sections:** 15.2.1 (Level 1)
- **Affected Files:**
  - Project-wide
  - `AGENTS.md`

### Remediation
1. Define timeframes first (prerequisite — see FINDING-007 remediation). 2. Implement automated enforcement with GitHub Actions workflow for dependency audit that runs weekly and on PRs modifying uv.lock or pyproject.toml, using pip-audit to scan exported dependencies and a custom script to check component age against policy thresholds. 3. Add to AGENTS.md CI description: Dependency security audit that runs automatically on PRs modifying uv.lock or pyproject.toml and blocks merge if components breach documented remediation timeframes.

### Acceptance Criteria
- [ ] Dependency audit workflow implemented in CI/CD
- [ ] pip-audit or equivalent scanner integrated
- [ ] Component age checking script created
- [ ] PR blocking on policy violations configured
- [ ] Test added for vulnerability detection
- [ ] Weekly automated scan scheduled

### References
- Source Report: 15.2.1.md
- Related Finding: FINDING-007

### Priority
High

---

## Issue: FINDING-009 - Authentication Documentation Missing Rate Limiting, Anti-Automation, and Adaptive Response Controls
**Labels:** bug, security, priority:high, documentation
**Description:**
### Summary
The API security documentation defines JWT authentication flow (token generation via POST /auth/token with username/password credentials) but contains zero documentation about how rate limiting, anti-automation, or adaptive response controls defend this endpoint against credential stuffing and brute force attacks. Without documented (and presumably implemented) rate limiting, attackers can repeatedly call the authentication endpoint unchecked. Additionally, if account lockout IS implemented somewhere (e.g., in an auth manager plugin), there is no documentation explaining how legitimate users are protected from being maliciously locked out.

### Details
- **ASVS Sections:** 6.1.1 (Level 1)
- **Affected Files:**
  - `airflow-core/docs/security/api.rst`

### Remediation
Add a dedicated section to airflow-core/docs/security/api.rst (or a separate authentication security document) that addresses: Rate Limiting - Configure rate limiting using options in the [api] section of airflow.cfg. For production deployments behind a reverse proxy, configure rate limiting at the proxy layer. Anti-Automation Controls - Deploy a Web Application Firewall (WAF) with bot detection capabilities, consider integrating CAPTCHA challenges after repeated failures. Adaptive Response - Apply progressive delays after repeated failed authentication attempts. Account Lockout Prevention - Apply rate limiting per-IP by default (not per-account), use temporary lockout with automatic unlock after a configurable period.

### Acceptance Criteria
- [ ] Rate limiting documentation section added
- [ ] Anti-automation controls documented
- [ ] Adaptive response mechanisms documented
- [ ] Account lockout prevention guidance added
- [ ] Configuration examples provided for common scenarios

### References
- Source Report: 6.1.1.md

### Priority
High

---

## Issue: FINDING-010 - Token Revocation Silently Fails on Any Exception Without Caller Notification
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The revoke_token() method returns None in all cases (success, validation failure, database error). A caller implementing ASVS 7.2.4 (terminate old session on re-authentication) cannot determine whether revocation succeeded. If a database connectivity issue occurs during re-authentication, the old token remains valid without the calling code being aware. The broad except (jwt.InvalidTokenError, Exception) clause catches database connection errors, serialization errors, and any unexpected runtime error, all treated identically with only a log warning.

### Details
- **ASVS Sections:** 7.2.4 (Level 1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/auth/tokens.py` (lines 273-280)

### Remediation
Modify revoke_token() to return bool indicating success/failure. Separate validation errors (token already invalid) from database errors (token not revoked). Let database errors propagate so callers can retry or handle appropriately. Example: return True on successful revocation, False on invalid token (revocation not needed), and raise exceptions for database errors to allow caller retry logic.

### Acceptance Criteria
- [ ] revoke_token() returns bool for success/failure
- [ ] Database errors propagate to caller
- [ ] Test added for successful revocation
- [ ] Test added for invalid token handling
- [ ] Test added for database error propagation

### References
- Source Report: 7.2.4.md

### Priority
Medium

---

## Issue: FINDING-011 - No Explicit Validation to Reject "none" Algorithm from Configuration
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The JWTValidator and JWTGenerator classes do not explicitly validate that the configured algorithm is not "none". If an administrator misconfigures jwt_algorithm = none, the validator would pass algorithms=["none"] to jwt.decode(), and PyJWT would accept tokens with alg: "none" without signature verification, allowing any attacker to forge tokens. This represents a complete authentication bypass if the algorithm is misconfigured. An attacker who discovers (or causes) this misconfiguration can forge arbitrary JWT tokens without possessing any key material.

### Details
- **ASVS Sections:** 9.1.2 (Level 1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/auth/tokens.py` (lines 226-233, 334-340)

### Remediation
Add explicit validation in both JWTValidator.__attrs_post_init__() and JWTGenerator.__attrs_post_init__() to reject the "none" algorithm. Implement allowlist validation using _FORBIDDEN_ALGORITHMS = frozenset({"none"}) and _ALLOWED_ALGORITHMS containing only approved algorithms. Validate configured algorithms against these lists and raise ValueError if "none" is detected or if an algorithm is not in the allowlist.

### Acceptance Criteria
- [ ] Algorithm validation added to JWTValidator
- [ ] Algorithm validation added to JWTGenerator
- [ ] "none" algorithm explicitly rejected
- [ ] Allowlist of approved algorithms defined
- [ ] Test added for "none" algorithm rejection
- [ ] Test added for unapproved algorithm rejection

### References
- Source Report: 9.1.2.md

### Priority
Medium

---

## Issue: FINDING-012 - No enforcement mechanism in base class ensures authorization is called at API entry points
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `BaseAuthManager` defines authorization methods as abstract interfaces but provides no mechanism (decorator, middleware requirement, or dependency injection pattern) that FORCES API endpoints to call these methods. The `get_fastapi_middlewares()` method returns an empty list by default. This represents a gap where controls EXIST (abstract authorization methods defined) but the base class provides no mechanism to ensure they are CALLED at every API entry point. Enforcement relies entirely on the API layer code. If any API endpoint omits the authorization check, function-level access control is bypassed.

### Details
- **ASVS Sections:** 8.2.1 (Level 1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py` (entire class)

### Remediation
Consider providing a FastAPI dependency or decorator in the base auth framework that enforces authorization. Implement a require_authorization() dependency that can be used with FastAPI's Depends() mechanism to ensure authorization checks are performed before handler execution. Additionally, conduct a comprehensive audit of all API endpoint handlers to verify that `is_authorized_*` methods are consistently called with appropriate `details` before resource access.

### Acceptance Criteria
- [ ] Authorization enforcement dependency/decorator created
- [ ] Documentation added for using authorization enforcement
- [ ] Audit of existing endpoints completed
- [ ] Test added for authorization enforcement
- [ ] Example endpoint updated to demonstrate usage

### References
- Source Report: 8.2.1.md

### Priority
Medium

---

## Issue: FINDING-013 - Optional `details` parameter allows authorization calls without data-specific context
**Labels:** bug, security, priority:medium
**Description:**
### Summary
All `is_authorized_*` methods accept `details` as an optional parameter defaulting to `None`. This means callers can invoke authorization checks without specifying which specific resource instance is being accessed. If an API endpoint that operates on a specific resource calls the authorization check without providing details (e.g., omitting `conn_id`), the auth manager implementation may grant access without validating the user has permission to the specific resource instance, creating a BOLA vulnerability. This is a design-level concern where nothing enforces data-specific authorization at the type level.

### Details
- **CWE:** CWE-639
- **ASVS Sections:** 8.2.2 (Level 1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py` (lines 205-271, 290-301)

### Remediation
Consider splitting function-level and data-level authorization into separate method signatures. Create separate methods for type-level authorization (is_authorized_connection_type) and instance-level authorization (is_authorized_connection_instance with required details parameter). Or use @overload to make the type checker flag calls without details when accessing specific instances.

### Acceptance Criteria
- [ ] Separate type-level and instance-level authorization methods defined
- [ ] Type hints enforced for required details parameter
- [ ] Documentation clarified for when details is required
- [ ] Test added for type-level authorization
- [ ] Test added for instance-level authorization with details

### References
- Source Report: 8.2.2.md

### Priority
Medium

---

## Issue: FINDING-014 - No mechanism for users to change their password
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The SimpleAuthManager provides no mechanism for users to change their passwords. The only password management is auto-generation during initialization when a user doesn't yet have a password. There is no PUT /password, POST /change-password, or equivalent endpoint anywhere in the router. The only way to 'change' a password is to delete the password file and restart the application (which generates new random passwords for all users) or manually edit the JSON file. Users cannot change their password if they believe it has been compromised, or if they wish to set a memorable password. This violates the fundamental NIST SP 800-63B requirement that memorized secrets can be changed by the subscriber.

### Details
- **ASVS Sections:** 6.2.2, 6.2.3 (Level 1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py` (entire file)
  - `airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py` (entire class)

### Remediation
Implement a password change endpoint that requires both current and new password. Add validation for minimum password length (8 characters) and verify current password before allowing change. Store updated password in the password file with appropriate file locking to prevent race conditions.

### Acceptance Criteria
- [ ] Password change endpoint implemented
- [ ] Current password verification required
- [ ] Minimum length validation (8 characters)
- [ ] Password file update with proper locking
- [ ] Test added for successful password change
- [ ] Test added for incorrect current password rejection
- [ ] Test added for weak new password rejection

### References
- Source Reports: 6.2.2.md, 6.2.3.md

### Priority
Medium

---

## Issue: FINDING-015 - No Rate Limiting or Brute Force Protection on Login Endpoints
**Labels:** bug, security, priority:medium
**Description:**
### Summary
An attacker can perform unlimited credential stuffing or brute force attacks against the login endpoints. While auto-generated passwords have ~91 bits of entropy making brute force computationally infeasible, if users are configured with weak passwords through the `simple_auth_manager_users` config, or if the password file is manually edited with weak passwords, the lack of rate limiting enables rapid dictionary attacks. The code includes a production detection heuristic (`_looks_like_production`) that only WARNS without enforcing any protective measures.

### Details
- **ASVS Sections:** 6.3.1 (Level 1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py` (lines 41, 99)
  - `airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py` (line 28)

### Remediation
Option 1: Add rate limiting middleware to login routes using fastapi_limiter.depends.RateLimiter with configuration such as 5 attempts per 60 seconds. Option 2: Implement progressive delay in SimpleAuthManagerLogin.create_token by tracking failed attempts per username and raising HTTP 429 after 5 recent failures within a 300-second window. Store failed attempt timestamps and clean up old entries to prevent memory exhaustion.

### Acceptance Criteria
- [ ] Rate limiting implemented on login endpoints
- [ ] Failed attempt tracking added
- [ ] Progressive delay or lockout mechanism implemented
- [ ] Test added for rate limit enforcement
- [ ] Test added for progressive delay behavior
- [ ] Memory cleanup for failed attempt tracking

### References
- Source Report: 6.3.1.md

### Priority
Medium

---

## Issue: FINDING-016 - System-Generated Passwords Never Expire and Become Permanent Credentials
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Generated initial passwords never expire and have no TTL or expiration mechanism. Once written to the password file, they remain valid indefinitely and become long-term passwords. There is no password change mechanism, no "must change on first login" flag, and no mechanism to force rotation. Additionally, passwords are printed to stdout/logs on first initialization, creating a persistent record in log files. Data flow: First startup → init() → _generate_password() → password stored in JSON file permanently → used for all future logins with no expiry.

### Details
- **ASVS Sections:** 6.4.1 (Level 1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py` (lines 143-184, 392)

### Remediation
Option 1: Add timestamp tracking and expiration. Modify _generate_password() to return tuple[str, float] with creation timestamp. In create_token, check if time.time() - password_entry["created_at"] > INITIAL_PASSWORD_TTL and raise HTTPException if expired. Option 2: Add a password change endpoint that invalidates initial passwords and mark generated passwords with a "must_change" flag.

### Acceptance Criteria
- [ ] Password creation timestamp tracking added
- [ ] Expiration check implemented in authentication
- [ ] "must_change" flag added for initial passwords
- [ ] Test added for expired password rejection
- [ ] Test added for password change requirement
- [ ] Documentation updated with password lifecycle

### References
- Source Report: 6.4.1.md

### Priority
Medium

---

## Issue: FINDING-017 - Inability to verify session termination effectiveness from app initialization layer
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The JWTRefreshMiddleware is added to the middleware stack, which is the documented mechanism for handling token lifecycle. However, from the initialization code alone, the following cannot be verified: 1. Whether the refresh middleware checks a revocation/termination list before issuing new tokens 2. Whether logout triggers invalidation of the refresh token (preventing new access tokens) 3. The actual token expiration duration (whether it's "appropriately short"). If the refresh middleware does not check token termination state, logged-out users could continue using their tokens until natural expiration.

### Details
- **ASVS Sections:** 7.4.1 (Level 1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/core_api/app.py` (lines 172-189)

### Remediation
Verify in the JWTRefreshMiddleware implementation that: 1. Logout marks the refresh token as terminated (e.g., in database or cache) 2. The middleware rejects refresh requests for terminated tokens 3. Access token lifetime is configured to be short (e.g., ≤15 minutes)

### Acceptance Criteria
- [ ] JWTRefreshMiddleware implementation verified
- [ ] Token termination on logout confirmed
- [ ] Refresh rejection for terminated tokens confirmed
- [ ] Access token lifetime configuration verified
- [ ] Test added for logout token invalidation
- [ ] Test added for terminated token refresh rejection

### References
- Source Report: 7.4.1.md

### Priority
Medium

---

## Issue: FINDING-018 - No visible mechanism for immediate session termination on account disable/delete
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application initialization code does not contain or reference any mechanism for: 1) Event-driven session termination when accounts are disabled or deleted, 2) A per-user token invalidation date/time that could be updated on account status change, 3) Account status checking during token refresh or request validation, 4) Hooks or signals for account lifecycle events that trigger session cleanup. If an employee is terminated and their account disabled, their existing access tokens and refresh tokens may remain valid until natural expiration.

### Details
- **ASVS Sections:** 7.4.2 (Level 1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/app.py` (entire file)
  - `airflow-core/src/airflow/api_fastapi/core_api/app.py` (entire file)

### Remediation
Implement account status checking in auth manager middleware or JWTRefreshMiddleware. Check if account is disabled/deleted on every request or at minimum on refresh, raising 401 if disabled. Consider adding a per-user 'tokens_valid_after' timestamp field that is updated on account disable and checked during token validation.

### Acceptance Criteria
- [ ] Account status check added to authentication flow
- [ ] tokens_valid_after timestamp field added to user model
- [ ] Token validation checks account status
- [ ] Test added for disabled account rejection
- [ ] Test added for deleted account rejection
- [ ] Test added for tokens_valid_after enforcement

### References
- Source Report: 7.4.2.md

### Priority
Medium

---

## Issue: FINDING-019 - API Input Validation Rules Not Documented in Available Application Documentation
**Labels:** bug, security, priority:medium, documentation
**Description:**
### Summary
The only public API reference documentation provided (stable-rest-api-ref.rst) is a stub file containing no content. While documentation is auto-generated during the build process, the absence of source validation documentation means we cannot verify that: 1) Input validation rules for API endpoints are formally defined, 2) Data format specifications exist for structured inputs, 3) Business logic constraints are documented. Without documented validation rules, developers may implement inconsistent validation, and security reviewers cannot verify that all inputs are properly constrained.

### Details
- **ASVS Sections:** 2.1.1 (Level 1)
- **Affected Files:**
  - `airflow-core/docs/stable-rest-api-ref.rst` (entire file)

### Remediation
Ensure the generated API documentation includes: 1) Explicit field-level validation rules (types, formats, ranges, patterns), 2) Business logic constraints for each endpoint, 3) Expected data formats with examples. Example: DAG ID Validation Rules: Type: string, Pattern: ^[a-zA-Z0-9._-]+$, Max length: 250 characters, Must not start with a period.

### Acceptance Criteria
- [ ] API documentation generation verified
- [ ] Field-level validation rules documented
- [ ] Business logic constraints documented
- [ ] Data format examples added
- [ ] Documentation build process verified

### References
- Source Report: 2.1.1.md

### Priority
Medium

---

## Issue: FINDING-020 - No Sec-Fetch-* header validation or Content-Security-Policy middleware for API/static responses
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The middleware stack contains JWT refresh, auth manager middlewares, GZip compression, and access logging. There is no middleware that: 1. Validates Sec-Fetch-Dest, Sec-Fetch-Mode, or Sec-Fetch-Site headers on API endpoints 2. Sets X-Content-Type-Options: nosniff on responses 3. Sets Content-Security-Policy headers 4. Sets Content-Disposition: attachment for user-uploaded or generated file downloads. Without these headers, browsers may MIME-sniff API responses as HTML (enabling XSS), injected content has no execution restrictions, and API endpoints can be directly navigated to in unexpected contexts.

### Details
- **ASVS Sections:** 3.2.1 (Level 1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/core_api/app.py` (lines 172-189)

### Remediation
Implement a SecurityHeadersMiddleware that sets X-Content-Type-Options: nosniff, Content-Security-Policy with restrictive directives, and Referrer-Policy: strict-origin-when-cross-origin on all responses. Add middleware to init_middlewares function.

### Acceptance Criteria
- [ ] SecurityHeadersMiddleware implemented
- [ ] X-Content-Type-Options header set on all responses
- [ ] Content-Security-Policy header with restrictive directives
- [ ] Referrer-Policy header set
- [ ] Test added for security headers presence
- [ ] Test added for CSP directive validation

### References
- Source Report: 3.2.1.md

### Priority
Medium

---

## Issue: FINDING-021 - Cookie path scoping function exists but no evidence of Secure attribute or __Host-/__Secure- prefix enforcement
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `get_cookie_path()` function provides path scoping for cookies but does not enforce the `Secure` attribute or cookie name prefixes (`__Host-` or `__Secure-`). The actual cookie-setting code is not present in the provided files, but the infrastructure for ensuring secure cookie attributes is not visible. Without `Secure` attribute, cookies can be transmitted over unencrypted HTTP. Without `__Host-` or `__Secure-` prefixes, cookies are vulnerable to domain/path override attacks from subdomains.

### Details
- **ASVS Sections:** 3.3.1 (Level 1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/app.py` (lines 48-54)

### Remediation
Implement a secure cookie-setting function that enforces security attributes including Secure, HttpOnly, SameSite, and __Host-/__Secure- prefix usage. Audit JWTRefreshMiddleware and any other cookie-setting code to verify these attributes are used.

### Acceptance Criteria
- [ ] Secure cookie-setting function implemented
- [ ] Secure attribute enforced on all cookies
- [ ] __Host- or __Secure- prefix used appropriately
- [ ] HttpOnly attribute set on authentication cookies
- [ ] SameSite attribute configured
- [ ] Test added for secure cookie attributes
- [ ] Audit of existing cookie-setting code completed

### References
- Source Report: 3.3.1.md

### Priority
Medium

---

## Issue: FINDING-022 - CORS middleware only conditionally applied — unprotected if no CORS config set
**Labels:** security, priority:medium, documentation
**Description:**
### Summary
If no CORS configuration is provided (access_control_allow_origins, access_control_allow_methods, access_control_allow_headers are all empty/unset), no CORSMiddleware is added at all. Without CORSMiddleware, FastAPI does not set CORS headers, which means cross-origin requests will be rejected by default by the browser's Same-Origin Policy. The absence of CORS middleware means there's no explicit denial of cross-origin requests at the server level, but responses won't include Access-Control-Allow-Origin headers, which is actually the more restrictive default. This is downgraded as it represents secure-by-default behavior.

### Details
- **ASVS Sections:** 3.4.2 (Level 1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/core_api/app.py` (lines 155-162)

### Remediation
This is informational - the absence of CORS middleware when unconfigured means the browser's Same-Origin Policy is the default protection, which is correct. No remediation required, but documentation should clarify that CORS is opt-in and secure by default.

### Acceptance Criteria
- [ ] Documentation clarifies CORS opt-in behavior
- [ ] Documentation explains secure-by-default SOP protection
- [ ] Configuration examples added for CORS setup

### References
- Source Report: 3.4.2.md

### Priority
Medium

---

## Issue: FINDING-023 - No explicit CSRF token middleware or anti-forgery mechanism visible for state-changing operations
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application's CSRF protection strategy needs assessment. JWT-based authentication via cookies is inherently vulnerable to CSRF unless additional protections are in place. The middleware stack does not include explicit CSRF token generation/validation middleware. CORS provides partial protection for non-simple requests but has limitations: only configured when origins are explicitly set, simple requests don't trigger preflight, and GET requests with side effects aren't protected. Without SameSite=Strict cookies and without CSRF tokens, an attacker can craft pages that submit state-changing requests on behalf of authenticated users.

### Details
- **ASVS Sections:** 3.5.1 (Level 1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/core_api/app.py` (lines 172-189)
  - `airflow-core/src/airflow/api_fastapi/app.py` (lines 78-124)

### Remediation
Option 1: Require non-CORS-safelisted header on all state-changing endpoints using CSRFProtectionMiddleware that checks for x-requested-with header on POST, PUT, DELETE, PATCH methods. Option 2: Ensure cookies use SameSite=Strict. Option 3: Validate Origin/Referer headers against expected values.

### Acceptance Criteria
- [ ] CSRF protection mechanism chosen and implemented
- [ ] State-changing endpoints protected
- [ ] Test added for CSRF protection
- [ ] Test added for cross-origin request rejection
- [ ] Documentation updated with CSRF protection strategy

### References
- Source Report: 3.5.1.md

### Priority
Medium

---

## Issue: FINDING-024 - No custom header requirement to enforce CORS preflight for cookie-authenticated requests
**Labels:** bug, security, priority:medium
**Description:**
### Summary
A cross-origin POST request with Content-Type: text/plain (a CORS-safelisted content type) sent via form submission will NOT trigger a CORS preflight, yet the browser will attach cookies due to allow_credentials=True. If any POST endpoint doesn't strictly require application/json parsing or can process the body as text, a cross-origin attacker could forge requests using a victim's session cookies without triggering CORS preflight. FastAPI's JSON body parsing mitigates this for most endpoints, but endpoints without required bodies or with optional bodies remain potentially exposed.

### Details
- **ASVS Sections:** 3.5.2 (Level 1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/core_api/app.py` (lines 148-162)

### Remediation
Add a requirement for a non-safelisted custom header (e.g., X-Requested-With) for all state-changing operations, or validate the Origin header server-side for all sensitive requests regardless of CORS configuration. Implement an OriginValidationMiddleware that checks the Origin header for POST, PUT, PATCH, and DELETE requests and rejects simple content types that don't trigger preflight unless the Origin is validated.

### Acceptance Criteria
- [ ] Custom header requirement added for state-changing operations
- [ ] Origin validation middleware implemented
- [ ] Test added for missing custom header rejection
- [ ] Test added for Origin validation
- [ ] Documentation updated with custom header requirements

### References
- Source Report: 3.5.2.md

### Priority
Medium

---

## Issue: FINDING-025 - No Sec-Fetch-* header validation for defense-in-depth against cross-origin attacks
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Without Sec-Fetch-* header validation, the application cannot distinguish between same-origin navigation requests, cross-origin requests, navigation vs. API calls, or resource loads like image src attributes. This means that even if endpoints use correct HTTP methods, there's no defense-in-depth mechanism to reject requests that originate from unexpected contexts (e.g., a cross-origin navigation or image load targeting a state-changing endpoint).

### Details
- **ASVS Sections:** 3.5.3 (Level 1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/core_api/app.py` (lines 172-189)

### Remediation
Add a Sec-Fetch-* validation middleware that rejects requests to API endpoints from unexpected origins or navigation contexts. Implement SecFetchValidationMiddleware that validates sec-fetch-site and sec-fetch-mode headers, rejecting cross-site navigation to API endpoints and no-cors mode for state-changing requests. Apply this middleware to all API endpoints while excluding static/SPA routes.

### Acceptance Criteria
- [ ] SecFetchValidationMiddleware implemented
- [ ] Cross-site navigation to API endpoints rejected
- [ ] No-cors mode for state-changing requests rejected
- [ ] Test added for Sec-Fetch-Site validation
- [ ] Test added for Sec-Fetch-Mode validation
- [ ] Static/SPA routes excluded from validation

### References
- Source Report: 3.5.3.md

### Priority
Medium

---

## Issue: FINDING-026 - Security documentation lacks TLS protocol version requirements for Public API
**Labels:** bug, security, priority:medium, documentation
**Description:**
### Summary
Security documentation for the Public API contains no guidance on TLS protocol version requirements. Given this is the authoritative security documentation for API access, the absence of TLS version requirements means deployers have no guidance on configuring TLS 1.2+ as the minimum protocol version. Deployers following this documentation may not configure TLS protocol version restrictions, leaving the API server vulnerable to protocol downgrade attacks (BEAST, POODLE) or running with deprecated TLS versions that have known cryptographic weaknesses.

### Details
- **ASVS Sections:** 12.1.1 (Level 1)
- **Affected Files:**
  - `airflow-core/docs/security/api.rst` (entire file)

### Remediation
Add a TLS configuration section to the API security documentation specifying that all external-facing Airflow services must be configured with TLS 1.2 as the minimum protocol version, with TLS 1.3 preferred. Earlier protocol versions (TLS 1.0, TLS 1.1, SSLv3) must be disabled. Include example configurations for reverse proxies (nginx, Apache) showing how to enable only TLS 1.2 and TLS 1.3.

### Acceptance Criteria
- [ ] TLS configuration section added to documentation
- [ ] Minimum TLS version requirements specified
- [ ] Example configurations for common reverse proxies
- [ ] Weak cipher suite exclusion guidance
- [ ] TLS 1.3 preference documented

### References
- Source Report: 12.1.1.md

### Priority
Medium

---

## Issue: FINDING-027 - API security documentation lacks publicly trusted TLS certificate guidance
**Labels:** bug, security, priority:medium, documentation
**Description:**
### Summary
The API security documentation for external-facing services contains no guidance on certificate requirements. There is no mention of using publicly trusted TLS certificates (issued by CAs in browser/OS trust stores) for external-facing services, nor any distinction between internal CA certificates and publicly trusted certificates. Without documentation specifying publicly trusted certificate requirements, deployers may use self-signed certificates or internal CA certificates for external-facing API endpoints.

### Details
- **ASVS Sections:** 12.2.2 (Level 1)
- **Affected Files:**
  - `airflow-core/docs/security/api.rst` (entire file)

### Remediation
Add certificate guidance to the security documentation specifying that external-facing Airflow services must use TLS certificates issued by publicly trusted CAs. Self-signed or internal CA certificates should only be used for internal service-to-service communication. Include guidance for automatic certificate renewal and proper trust chain configuration.

### Acceptance Criteria
- [ ] TLS certificate requirements section added
- [ ] Publicly trusted CA requirement documented
- [ ] Internal vs. external certificate guidance provided
- [ ] Automatic renewal recommendations included
- [ ] Certificate validation enforcement documented

### References
- Source Report: 12.2.2.md

### Priority
Medium

---

## Issue: FINDING-028 - Deployment Documentation Lacks SCM Metadata Exclusion Guidance
**Labels:** bug, security, priority:medium, documentation
**Description:**
### Summary
The administration and deployment documentation covers extensive operational concerns including high availability, database requirements, performance tuning, and multi-scheduler configuration. However, no section addresses basic production hardening requirements including excluding .git/.svn directories from deployment artifacts, blocking web requests to source control metadata paths, or stripping development files from production containers. The documentation provides production deployment guidance without addressing this fundamental security hardening measure.

### Details
- **ASVS Sections:** 13.4.1 (Level 1)
- **Affected Files:**
  - `airflow-core/docs/administration-and-deployment/scheduler.rst` (entire document scope)

### Remediation
Add a security hardening section to the administration-and-deployment documentation with guidance on excluding source control metadata from production deployments. Include .dockerignore patterns, reverse proxy path blocking configuration, and verification procedures for container images.

### Acceptance Criteria
- [ ] Security hardening section added to deployment docs
- [ ] .dockerignore patterns documented
- [ ] Reverse proxy blocking configuration examples provided
- [ ] Container image verification procedures documented
- [ ] SCM metadata exclusion verified in build process

### References
- Source Report: 13.4.1.md

### Priority
Medium

---

## Issue: FINDING-029 - AGENTS.md Contains Detailed Internal Architecture Information at Repository Root
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The AGENTS.md file at the repository root contains extensive internal security architecture information that would aid an attacker if accessible in production. This file reveals internal API paths, security boundary limitations, JWT token architecture details, database model structure, and component isolation assumptions. The file documents scheduler behavior, Execution API details, SQLAlchemy model structure, and explicitly documents where security guards can be bypassed.

### Details
- **ASVS Sections:** 13.4.1 (Level 1)
- **Affected Files:**
  - `AGENTS.md` (lines 1-400+)

### Remediation
Ensure AGENTS.md and similar development-only documentation is excluded from production artifacts. Add to .dockerignore (.git, .svn, AGENTS.md, contributing-docs/, dev/, *.md, !README.md). Alternative: explicitly remove in Dockerfile using RUN rm -rf commands. Add FastAPI middleware to reject requests matching /.git/ or /.svn/ patterns as defense in depth.

### Acceptance Criteria
- [ ] AGENTS.md excluded from production builds
- [ ] .dockerignore updated with development files
- [ ] Dockerfile cleanup commands added (if applicable)
- [ ] Middleware added to block SCM metadata requests
- [ ] Test added for development file exclusion
- [ ] Production build verification documented

### References
- Source Report: 13.4.1.md

### Priority
Medium

---

## Issue: FINDING-030 - No SBOM Generation or Component Inventory Documentation
**Labels:** bug, security, priority:medium, documentation
**Description:**
### Summary
The AGENTS.md documents extensive processes for code formatting, linting, type checking, testing, and documentation building, but contains no documented process for: periodic review of dependency versions, scheduled security scanning, release-blocking criteria for vulnerable dependencies, or responsibility assignment for dependency maintenance. Dependency updates happen reactively (when breakage occurs) rather than proactively (when vulnerabilities are disclosed). No ownership model exists for monitoring dependency health across 100+ provider packages.

### Details
- **ASVS Sections:** 15.1.1, 15.2.1 (Level 1)
- **Affected Files:**
  - `AGENTS.md` (Repository Structure section)

### Remediation
Add a Dependency Maintenance section to AGENTS.md or a dedicated policy document that includes: Scheduled Reviews (weekly automated scan, monthly human review, quarterly full audit); Responsibilities (core dependencies, provider dependencies, development tooling); Blocking Criteria (PRs with new Critical/High CVEs blocked, releases exceeding remediation timeframe blocked).

### Acceptance Criteria
- [ ] Dependency maintenance section added to documentation
- [ ] Scheduled review process documented
- [ ] Responsibility assignments defined
- [ ] Blocking criteria established
- [ ] Automated scanning workflow implemented

### References
- Source Reports: 15.1.1.md, 15.2.1.md

### Priority
Medium

---

## Issue: FINDING-031 - Missing documentation for OAuth grant type restrictions and per-client allowlists
**Labels:** bug, security, priority:medium, documentation
**Description:**
### Summary
The documented /auth/token endpoint using username/password direct exchange resembles the ROPC grant type pattern. While this is a first-party endpoint, the documentation does not clarify: which OAuth grant types are supported per client, whether implicit or ROPC grants are disabled for OAuth-integrated auth managers, and per-client grant type restrictions. Without documented grant type restrictions, operators deploying OAuth-integrated auth managers may not be aware they should restrict grant types.

### Details
- **ASVS Sections:** 10.4.4 (Level 1)
- **Affected Files:**
  - `airflow-core/docs/security/api.rst` (lines 28-48)

### Remediation
Add documentation specifying: (1) Which grant types each auth manager supports, (2) That implicit and ROPC grants should not be used for third-party clients, (3) How to configure per-client grant type restrictions. Include examples showing authorization code grant with PKCE as the preferred flow for interactive authentication.

### Acceptance Criteria
- [ ] OAuth grant type documentation section added
- [ ] Grant type restrictions per auth manager documented
- [ ] Third-party client restrictions specified
- [ ] Per-client configuration examples provided
- [ ] PKCE recommendation documented

### References
- Source Report: 10.4.4.md

### Priority
Medium

---

## Issue: FINDING-032 - UUID4 Token Identifier (jti) Provides 122 Bits of Entropy, Marginally Below 128-Bit Threshold
**Labels:** security, priority:low
**Description:**
### Summary
UUID version 4 generates 128 random bits but reserves 6 bits for version and variant, yielding exactly 122 bits of cryptographic randomness. While this is sourced from a CSPRNG, it technically falls below the 128-bit entropy threshold specified by ASVS 7.2.3. However, the jti serves as a unique identifier within a cryptographically signed JWT — session security relies on signature unforgeability, not on the unpredictability of the jti. The 122-bit randomness provides negligible collision probability. This is a marginal compliance observation since Airflow uses signed JWTs where guessability is not a threat.

### Details
- **ASVS Sections:** 7.2.3 (Level 1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/auth/tokens.py` (line 330)

### Remediation
If strict 128-bit compliance is required for the token identifier, use os.urandom(16) with base64url encoding instead of UUID4.

### Acceptance Criteria
- [ ] Decision made on strict 128-bit compliance requirement
- [ ] If required: Implementation changed to use os.urandom(16)
- [ ] Test added for jti uniqueness
- [ ] Documentation updated with jti generation method

### References
- Source Report: 7.2.3.md

### Priority
Low

---

## Issue: FINDING-033 - Token Refresh Does Not Revoke Previous Token (Documented Design Decision)
**Labels:** security, priority:low, documentation
**Description:**
### Summary
The JWTRefreshMiddleware generates a new token when the current token approaches expiry but does not revoke the old token. This means both old and new tokens are valid simultaneously until the old one expires naturally. During the overlap window between token refresh and old token expiry, both tokens are valid. For REST API tokens (24-hour default lifetime), this window could be significant. For Execution API tokens (10-minute lifetime), the exposure is minimal. This is acknowledged as an intentional design decision.

### Details
- **ASVS Sections:** 7.2.4 (Level 1)
- **Affected Files:**
  - `jwt_token_authentication.rst`

### Remediation
Acknowledged as intentional design decision. The short token lifetime for Execution API tokens (10 minutes with 20% refresh threshold = ~2 minute overlap) provides adequate mitigation. REST API tokens (24-hour lifetime) have a longer overlap but this is mitigated by the SameSite=Lax cookie and HTTP-only flag preventing token theft via XSS.

### Acceptance Criteria
- [ ] Design decision documented in architecture docs
- [ ] Token overlap window documented
- [ ] Mitigation factors documented (SameSite, HttpOnly)
- [ ] Risk acceptance recorded

### References
- Source Report: 7.2.4.md

### Priority
Low

---

## Issue: FINDING-034 - No enforcement mechanism in base class ensures authorization is called at API entry points
**Labels:** security, priority:low, documentation
**Description:**
### Summary
The authorization documentation comprehensively defines WHAT authorization checks exist but does not explicitly document: 1. WHERE in the request processing pipeline authorization MUST be checked, 2. The required call sequence (authenticate → authorize → process → respond), 3. Mandatory enforcement points. Custom auth manager implementers may inadvertently apply authorization checks at incorrect points in the request pipeline (e.g., after data is retrieved), creating a gap where the control is called but after the sensitive operation.

### Details
- **ASVS Sections:** 8.1.1 (Level 1)
- **Affected Files:**
  - `airflow-core/docs/core-concepts/auth-manager/index.rst` (entire file)

### Remediation
Add a section to the documentation explicitly stating authorization enforcement requirements: All is_authorized_* methods MUST be called BEFORE any data access or mutation operation, at the API server layer, as early as possible after authentication completes, and with specific resource details when accessing a specific resource instance.

### Acceptance Criteria
- [ ] Authorization enforcement requirements section added
- [ ] Call sequence documented
- [ ] Enforcement points specified
- [ ] Examples provided for correct implementation
- [ ] Anti-patterns documented

### References
- Source Report: 8.1.1.md

### Priority
Low

---

## Issue: FINDING-035 - Documentation does not define handling of details=None authorization semantics for data-specific access
**Labels:** security, priority:low, documentation
**Description:**
### Summary
The documentation mentions 'Some details about the connection can be provided' but doesn't clearly distinguish between function-level check (details=None for general capability) vs data-level check (details provided for specific resource). This ambiguity could lead auth manager implementations to treat details=None as 'authorize access to ALL resources' rather than 'check general capability'. Custom auth managers may incorrectly grant broad access when details=None is passed, creating IDOR/BOLA vulnerabilities.

### Details
- **ASVS Sections:** 8.1.1 (Level 1)
- **Affected Files:**
  - `airflow-core/docs/core-concepts/auth-manager/index.rst` (lines 99-155)
  - `base_auth_manager.py` (lines 205-216)

### Remediation
Document the semantic difference explicitly: When details is None, the check determines whether the user has the capability to perform the action on the resource type in general (typically for listing operations). When details is provided, it performs a data-specific check for that exact resource instance. Auth manager implementations MUST NOT treat details=None as granting access to all instances of a resource type.

### Acceptance Criteria
- [ ] details=None semantics documented
- [ ] Function-level vs. data-level distinction clarified
- [ ] Examples provided for both scenarios
- [ ] Anti-patterns documented
- [ ] Auth manager implementation guide updated

### References
- Source Report: 8.1.1.md

### Priority
Low

---

## Issue: FINDING-036 - Default `filter_authorized_*` implementations may allow timing-based inference attacks
**Labels:** security, priority:low
**Description:**
### Summary
The default filter_authorized_* implementations iterate over all resource IDs and call individual authorization checks. This is flagged as a performance concern in the documentation, but it also creates a potential timing side-channel: if the response time correlates with the number of resources checked, an attacker could infer the total number of resources in the system (even those they can't access). The implementation iterates through conn_ids and checks authorization for each, which could leak information through timing variations.

### Details
- **CWE:** CWE-208
- **ASVS Sections:** 8.2.2 (Level 1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py` (lines 459-481, 510-532, 559-581, 639-661)

### Remediation
This is adequately addressed by the existing recommendation to override these methods. Consider adding a note that performance optimization also mitigates timing side-channels. Implementations should batch authorization checks or use constant-time filtering approaches to prevent timing-based inference.

### Acceptance Criteria
- [ ] Documentation note added about timing side-channels
- [ ] Batch authorization check pattern documented
- [ ] Constant-time filtering guidance provided
- [ ] Performance optimization recommendations updated

### References
- Source Report: 8.2.2.md

### Priority
Low

---

## Issue: FINDING-037 - No minimum password length validation for manually configured passwords
**Labels:** security, priority:low
**Description:**
### Summary
The authentication service validates that a password is provided (non-empty) but does not enforce a minimum length requirement. While auto-generated passwords are 16 characters, there is no validation that passwords stored in the password file meet any minimum length. An administrator could manually edit the password file or configure it to point to a file with short passwords, and no runtime validation would reject them. If the password file is manually managed, passwords shorter than 8 characters could be accepted without any warning or enforcement.

### Details
- **ASVS Sections:** 6.2.1 (Level 1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py` (lines 37-58)

### Remediation
Add password length validation when reading from the password file or add a startup check that warns about passwords shorter than 8 characters with a recommendation for 15+ character passwords.

### Acceptance Criteria
- [ ] Password length validation added
- [ ] Minimum 8 character requirement enforced
- [ ] Warning logged for short passwords
- [ ] Test added for password length validation
- [ ] Documentation updated with password requirements

### References
- Source Report: 6.2.1.md

### Priority
Low

---

## Issue: FINDING-038 - No common password list validation mechanism
**Labels:** security, priority:low
**Description:**
### Summary
There is no mechanism to check passwords against a list of commonly used or breached passwords. The system does not integrate with any breach database (e.g., Have I Been Pwned API) or maintain a local list of the top 3000+ common passwords. Since passwords are auto-generated using cryptographic randomness with ~85 bits of entropy, the probability of collision with a common password is negligible. However, if password change functionality were added (per 6.2.2), user-chosen passwords would not be validated against common password lists.

### Details
- **ASVS Sections:** 6.2.4 (Level 1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py` (line 445)

### Remediation
Implement a common password check utility for future use that loads a bundled list of common passwords and provides an is_common_password() function for validation when password change functionality is added.

### Acceptance Criteria
- [ ] Common password list bundled with application
- [ ] is_common_password() utility function implemented
- [ ] Test added for common password detection
- [ ] Documentation added for future password change integration

### References
- Source Report: 6.2.4.md

### Priority
Low

---

## Issue: FINDING-039 - Cannot verify password input field masking in UI template
**Labels:** security, priority:low
**Description:**
### Summary
The login UI is served via Jinja2 templates from a ui/dist or ui/dev directory. The actual HTML template (index.html) is not included in the provided code scope, making it impossible to verify whether password input fields use type="password". The UI files are either compiled frontend assets or development files external to this audit scope. If the password input field uses type="text" instead of type="password", passwords would be visible on screen, exposing them to shoulder surfing.

### Details
- **ASVS Sections:** 6.2.6 (Level 1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py` (lines 342-377)

### Remediation
Verify the login form HTML in the ui/dist/index.html or ui/dev/index.html template contains input type="password" with appropriate autocomplete attributes. The form should also support a visibility toggle for accessibility.

### Acceptance Criteria
- [ ] UI template audit completed
- [ ] Password field type="password" verified
- [ ] Autocomplete attributes verified
- [ ] Visibility toggle functionality verified
- [ ] Test added for password field masking

### References
- Source Report: 6.2.6.md

### Priority
Low

---

## Issue: FINDING-040 - "Anonymous" Admin Account Created in All-Admins Mode Without Explicit Credential Requirements
**Labels:** security, priority:low
**Description:**
### Summary
When simple_auth_manager_all_admins=True, any unauthenticated user can obtain a full ADMIN JWT token via a simple GET request. This is a default credential-equivalent scenario — there is effectively a pre-existing admin account ("Anonymous") that requires no authentication. This is rated LOW because: (1) it requires explicit configuration, (2) it's documented as development-only, (3) the method checks the config flag and returns 403 if not enabled, and (4) the production detection heuristic emits warnings. However, if this configuration is accidentally left enabled in a non-development environment, it constitutes a complete authentication bypass.

### Details
- **ASVS Sections:** 6.3.2 (Level 1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py` (line 78)
  - `airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py` (line 69)

### Remediation
Add enforcement to prevent all-admins mode in production-like deployments by blocking the feature if _looks_like_production() returns True, raising HTTP 403 with an appropriate error message.

### Acceptance Criteria
- [ ] Production detection enforcement added
- [ ] HTTP 403 raised in production-like environments
- [ ] Test added for production blocking
- [ ] Documentation updated with security warning
- [ ] Configuration validation added at startup

### References
- Source Report: 6.3.2.md

### Priority
Low

## Issue: FINDING-041 - Potential JavaScript injection via template variable in SPA initialization
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `request.base_url.path` variable is passed to the Jinja2 template without validation. While Jinja2's HTML auto-escaping protects against basic XSS in HTML context, if the template uses this value in a JavaScript context (e.g., within `<script>` tags), the HTML escaping is insufficient and could allow JavaScript injection through proxy header manipulation.

### Details
**CWE:** CWE-79  
**ASVS Sections:** 1.2.3, 1.2.1 (Level L1)  
**Affected File:** `airflow-core/src/airflow/api_fastapi/core_api/app.py` (lines 108-114)

The `backend_server_base_url` is constructed from `request.base_url.path`, which can be influenced by:
- The `root_path` ASGI setting
- Trusted proxy headers like `X-Forwarded-Prefix` (when `ProxyHeadersMiddleware` is used)

If the `index.html` template embeds this value in a JavaScript context like:
```html
<script>window.BASE='{{backend_server_base_url}}'</script>
```

An attacker controlling proxy headers could inject: `/';</script><script>alert(1)//`

While HTML-escaped, this could still break out of the JavaScript string context.

### Remediation
1. Validate `base_url.path` before passing to template:
```python
import re

@app.get("/{rest_of_path:path}", response_class=HTMLResponse, include_in_schema=False)
def webapp(request: Request, rest_of_path: str):
    base_path = request.base_url.path
    # Ensure base_path only contains valid URL path characters
    if not re.match(r'^[/a-zA-Z0-9._~:@!$&\'()*+,;=-]*$', base_path):
        base_path = "/"
    return templates.TemplateResponse(
        request,
        "/index.html",
        {"backend_server_base_url": base_path},
        media_type="text/html",
    )
```

2. Verify `index.html` template and use `|tojson` filter if embedding in `<script>` blocks

### Acceptance Criteria
- [ ] Input validation added for `base_url.path`
- [ ] Template reviewed and uses appropriate context-aware escaping
- [ ] Test added for malicious proxy header values
- [ ] Documentation updated for secure proxy configuration

### References
- Source Reports: 1.2.3.md, 1.2.1.md
- Related Findings: None

### Priority
Low

---

## Issue: FINDING-042 - Static file serving without Content-Disposition or Sec-Fetch validation
**Labels:** bug, security, priority:low
**Description:**
### Summary
Static files are served with `html=True`, allowing HTML file serving without Sec-Fetch-* header validation or Content-Disposition headers. If user-controlled content reaches the static directory, it could be served and executed as HTML.

### Details
**ASVS Sections:** 3.2.1 (Level L1)  
**Affected File:** `airflow-core/src/airflow/api_fastapi/core_api/app.py` (lines 65-70)

The static file serving configuration allows HTML files to be served without:
- Sec-Fetch-* header validation to ensure resources are loaded as sub-resources only
- Content-Disposition headers to force download of potentially dangerous file types
- Validation that prevents user-influenced content from being served in HTML context

Current severity is Low because these are application-owned static files, but risk increases if any mechanism allows user content in the static directory.

### Remediation
1. Set `html=False` if HTML serving from static directory is not required:
```python
app.mount(
    "/static",
    StaticFiles(directory=str(ROOT_APP_DIR / "static"), html=False),
    name="static",
)
```

2. Implement Sec-Fetch-* header validation middleware:
```python
@app.middleware("http")
async def validate_sec_fetch(request: Request, call_next):
    if request.url.path.startswith("/static/"):
        sec_fetch_dest = request.headers.get("sec-fetch-dest")
        if sec_fetch_dest not in [None, "script", "style", "image", "font"]:
            return Response(status_code=403)
    return await call_next(request)
```

3. Ensure security headers middleware covers static file responses

### Acceptance Criteria
- [ ] Static file serving configuration updated
- [ ] Sec-Fetch-* validation implemented
- [ ] Test added for direct navigation attempts to static files
- [ ] Security review confirms no user content can reach static directory

### References
- Source Reports: 3.2.1.md

### Priority
Low

---

## Issue: FINDING-043 - Template rendering with dynamic context values — limited audit scope
**Labels:** security, priority:low, needs-review
**Description:**
### Summary
The React/TypeScript frontend code is not included in the audit scope, preventing assessment of client-side rendering safety. Cannot verify if the frontend uses safe rendering methods or potentially dangerous patterns like `dangerouslySetInnerHTML`.

### Details
**ASVS Sections:** 3.2.2 (Level L1)  
**Affected File:** `airflow-core/src/airflow/api_fastapi/core_api/app.py` (lines 104-112)

The backend correctly uses Jinja2 auto-escaping for server-side template rendering of `request.base_url.path`. However, the React UI code in `airflow/ui/` is not provided, preventing verification of:
- Whether React's JSX interpolation (safe by default) is used consistently
- Whether `dangerouslySetInnerHTML` is used with user-controlled content
- Whether markdown/rich-text rendering uses proper sanitization (e.g., DOMPurify)

**Impact:** Cannot be determined without frontend code review.

### Remediation
Conduct a separate security audit of the React frontend code in `airflow-core/src/airflow/ui/` to verify:

1. Dynamic content uses React's JSX interpolation:
```jsx
// Safe
<div>{userContent}</div>

// Unsafe
<div dangerouslySetInnerHTML={{__html: userContent}} />
```

2. Any HTML rendering uses sanitization:
```jsx
import DOMPurify from 'dompurify';

const sanitized = DOMPurify.sanitize(userContent);
<div dangerouslySetInnerHTML={{__html: sanitized}} />
```

3. URL construction uses safe methods:
```jsx
// Safe
const url = new URL(userPath, window.location.origin);

// Unsafe
window.location = userPath;
```

### Acceptance Criteria
- [ ] Frontend code audit completed
- [ ] All uses of `dangerouslySetInnerHTML` reviewed and validated
- [ ] Markdown/rich-text rendering verified to use sanitization
- [ ] Test suite includes XSS test cases for frontend

### References
- Source Reports: 3.2.2.md
- Frontend Location: `airflow-core/src/airflow/ui/`

### Priority
Low

---

## Issue: FINDING-044 - Catch-all SPA route uses GET method appropriately but lacks method restriction
**Labels:** enhancement, priority:low
**Description:**
### Summary
The catch-all SPA route correctly uses GET method for serving static content. This is noted as a positive pattern, but verification is needed that state-changing endpoints in other routers use appropriate HTTP methods.

### Details
**ASVS Sections:** 3.5.3 (Level L1)  
**Affected File:** `airflow-core/src/airflow/api_fastapi/core_api/app.py` (lines 104-112)

The visible routes correctly use GET for non-sensitive, read-only operations. The catch-all route appropriately serves the SPA with GET. However, the actual sensitive endpoints in `public_router` and `ui_router` are not visible in the provided code.

This is an informational finding to ensure completeness of HTTP method usage across the application.

### Remediation
Audit `public_router` and `ui_router` to ensure:

1. State-changing operations use appropriate methods:
```python
# Correct patterns
@router.post("/dags")  # Create
@router.put("/dags/{dag_id}")  # Replace
@router.patch("/dags/{dag_id}")  # Update
@router.delete("/dags/{dag_id}")  # Delete

# Incorrect patterns to avoid
@router.get("/dags/{dag_id}/delete")  # Don't use GET for state changes
```

2. Safe methods are only used for read operations:
```python
# Correct
@router.get("/dags")  # List/read only
@router.head("/dags/{dag_id}")  # Check existence
@router.options("/dags")  # CORS preflight

# Incorrect
@router.get("/dags/{dag_id}/trigger")  # State change via GET
```

### Acceptance Criteria
- [ ] All routers audited for HTTP method usage
- [ ] No state-changing operations use GET/HEAD/OPTIONS
- [ ] API documentation reflects correct HTTP method semantics
- [ ] Test suite validates method restrictions

### References
- Source Reports: 3.5.3.md

### Priority
Low

---

## Issue: FINDING-045 - Architecture documentation missing TLS protocol version guidance for internal communications
**Labels:** documentation, security, priority:low
**Description:**
### Summary
The architecture documentation describes multiple network communication channels but provides no guidance on required TLS protocol versions for internal communications between Airflow components.

### Details
**ASVS Sections:** 12.1.1 (Level L1)  
**Affected File:** `AGENTS.md` (Architecture Boundaries section)

The architecture describes these communication channels without TLS guidance:
- Worker ↔ API Server (Execution API)
- Scheduler ↔ Database
- API Server ↔ Database
- Client ↔ API Server

Without explicit guidance, deployments may:
- Use unencrypted connections for internal traffic
- Use deprecated TLS versions (TLS 1.0, 1.1)
- Lack mutual authentication where appropriate

### Remediation
Add a "Security Requirements" section to `AGENTS.md` with TLS guidance:

```markdown
## Security Requirements

### TLS Configuration

All network communications must use TLS 1.2 or higher. TLS 1.0 and 1.1 are deprecated and must not be used.

| Communication Channel | Minimum TLS | Certificate Type | Mutual Auth |
|----------------------|-------------|------------------|-------------|
| Client → API Server  | TLS 1.2     | Public CA        | Optional    |
| Worker → API Server  | TLS 1.2     | Internal CA      | Required    |
| Scheduler → Database | TLS 1.2     | Internal CA      | Recommended |
| API Server → Database| TLS 1.2     | Internal CA      | Recommended |

### Configuration Examples

**PostgreSQL** (airflow.cfg):
```ini
[database]
sql_alchemy_conn = postgresql://user:pass@host:5432/airflow?sslmode=require&sslrootcert=/path/to/ca.crt
```

**MySQL** (airflow.cfg):
```ini
[database]
sql_alchemy_conn = mysql://user:pass@host:3306/airflow?ssl_ca=/path/to/ca.crt&ssl_verify_cert=true
```
```

### Acceptance Criteria
- [ ] Documentation updated with TLS version requirements
- [ ] Per-component TLS configuration examples added
- [ ] Certificate management guidance included
- [ ] Deployment checklist includes TLS verification

### References
- Source Reports: 12.1.1.md

### Priority
Low

---

## Issue: FINDING-046 - Architecture documentation lacks certificate management guidance for external-facing services
**Labels:** documentation, security, priority:low
**Description:**
### Summary
The architecture documentation identifies external-facing services (API Server, public REST API) but provides no guidance on certificate management, trust requirements, or validation procedures for these services.

### Details
**ASVS Sections:** 12.2.2 (Level L1)  
**Affected File:** `AGENTS.md` (Architecture Boundaries section)

External-facing services identified:
- API Server serving React UI
- Public REST API

Missing guidance on:
- Certificate authority requirements (public CA vs. internal CA)
- Certificate validation procedures
- Certificate rotation and renewal processes
- Trust store configuration
- Certificate pinning considerations

Without this guidance, security reviews may not verify certificate trust requirements for each component.

### Remediation
Add certificate management section to `AGENTS.md`:

```markdown
## Certificate Management

### External-Facing Services

Services accessible from external networks must use certificates from trusted public Certificate Authorities.

**API Server (React UI & REST API)**
- Certificate Type: Public CA (e.g., Let's Encrypt, DigiCert)
- Validation: Must pass browser/OS trust store validation
- Renewal: Automated renewal required (e.g., certbot)
- SAN: Must include all public DNS names

### Internal Services

Services only accessible within the deployment environment may use internal CA certificates.

**Worker → API Server (Execution API)**
- Certificate Type: Internal CA or mutual TLS
- Validation: Pin internal CA certificate
- Renewal: Coordinate with deployment lifecycle

### Certificate Lifecycle

1. **Issuance**: Use automated certificate management (ACME protocol for public CAs)
2. **Rotation**: Certificates should be rotated before expiration (recommend 30-day buffer)
3. **Revocation**: Maintain certificate revocation checking (OCSP or CRL)
4. **Monitoring**: Alert on certificates expiring within 30 days

### Validation Requirements

```python
# Example: Verify certificate in client code
import ssl
import certifi

ssl_context = ssl.create_default_context(cafile=certifi.where())
ssl_context.check_hostname = True
ssl_context.verify_mode = ssl.CERT_REQUIRED
```
```

### Acceptance Criteria
- [ ] Certificate management section added to architecture docs
- [ ] External vs. internal certificate requirements documented
- [ ] Certificate lifecycle procedures defined
- [ ] Validation examples provided for each component type

### References
- Source Reports: 12.2.2.md

### Priority
Low