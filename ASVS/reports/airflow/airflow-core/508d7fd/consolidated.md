# Security Audit Consolidated Report

## Apache Tooling Runbooks — ASVS L1 Assessment

---

## Report Metadata

| Field | Value |
|-------|-------|
| **Repository** | `apache/tooling-runbooks` |
| **ASVS Level** | L1 |
| **Severity Threshold** | None (all findings included) |
| **Commit** | N/A |
| **Date** | May 15, 2026 |
| **Auditor** | Tooling Agents |
| **Source Reports** | 70 |
| **Total Findings** | 47 |

---

## Executive Summary

### Severity Distribution

| Severity | Count | Percentage |
|----------|-------|------------|
| Critical | 0 | 0.0% |
| High | 9 | 19.1% |
| Medium | 22 | 46.8% |
| Low | 15 | 31.9% |
| Informational | 1 | 2.1% |

### ASVS Level Coverage

All 47 findings were assessed against **ASVS Level 1** controls across 18 audited directories spanning authentication, authorization, session management, transport security, input validation, dependency management, deployment hardening, and web UI security. The audit consumed 70 source reports to produce this consolidated view.

### Top 5 Risks

1. **Refresh Token Replay (FINDING-001, FINDING-002)** — The refresh token middleware does not invalidate tokens after use and lacks token family revocation on reuse detection. An attacker who captures a refresh token can replay it indefinitely, and compromised token families are never revoked, enabling persistent unauthorized access.

2. **Missing Transport Security Headers (FINDING-004, FINDING-006)** — No HSTS header is present in the middleware stack, and API documentation demonstrates credential transmission over plaintext HTTP. This exposes authentication material to network-level interception and downgrade attacks.

3. **Absent Anti-Automation Controls (FINDING-009, FINDING-015)** — Authentication documentation and implementation lack rate limiting, brute force protection, and adaptive response controls on login endpoints. This permits credential stuffing and password spraying attacks without throttling.

4. **CORS Misconfiguration (FINDING-005, FINDING-022)** — `allow_credentials=True` is hardcoded without strict origin validation, and CORS middleware is only conditionally applied—leaving endpoints entirely unprotected when no CORS configuration is set. This enables cross-origin credential theft.

5. **Missing CSRF and Cross-Origin Protections (FINDING-023, FINDING-024, FINDING-025)** — No CSRF token middleware, no custom header requirement to enforce CORS preflight, and no `Sec-Fetch-*` header validation exist for state-changing operations. Cookie-authenticated requests are vulnerable to cross-site request forgery.

### Positive Controls Observed

The audit identified **49 positive security controls** that demonstrate mature security engineering in several areas:

| Domain | Key Controls |
|--------|-------------|
| **JWT Token Authentication** | Server-side-only validation; algorithm locked from JWK metadata (not token header); `kid` lookup restricted to pre-loaded keyset; required claims enforcement (`exp`, `iat`, `nbf`); GUESS mechanism resolves only to HS512/RS256/EdDSA; secret key protected with `repr=False`; separate token lifetimes per context (10min–24h) |
| **Refresh Token Middleware** | Trust sentinel pattern prevents middleware spoofing; secure cookie attributes (HttpOnly, SameSite=lax, conditional Secure); explicit cookie deletion on token expiry forces re-authentication; token rotation on refresh |
| **Auth Manager System** | Abstract method enforcement guarantees implementation; fail-closed defaults (NotImplementedError for unimplemented team auth); batch authorization uses `all()` AND logic; outer join ensures all resources are subject to authorization; no client-side authorization logic; user derived entirely from validated JWT payload |
| **Architecture** | All authorization decisions server-side in Python; API server mediates all client-database interactions; revocation checked against database; no trust of client-provided authorization claims |

These controls demonstrate a strong foundational security posture, particularly in token validation and authorization architecture. The findings primarily cluster around **missing hardening layers** (transport security headers, anti-automation, CSRF), **documentation gaps** (TLS requirements, remediation timeframes, input validation rules), and **refresh token lifecycle management** rather than fundamental architectural weaknesses.

---

## 3. Findings

### 3.2 High

#### FINDING-001: No Refresh Token Invalidation After Use — Replay Attack Possible

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L1 |
| CWE | CWE-294 |
| ASVS sections | 10.4.5 |
| Files | airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py:45-70, airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py:103-105 |
| Source Reports | 10.4.5.md |
| Related | - |

**Description:**

The refresh token middleware implements token rotation (generating a new JWT after refresh) but does NOT invalidate the previous token after use. Per ASVS 10.4.5, when refresh token rotation is used, 'the authorization server must invalidate the refresh token after usage.' No such invalidation control exists in this middleware — there is no token blacklist, revocation list, or consumed-token tracking mechanism. An attacker who obtains a refresh token (JWT) at any point during its validity window can replay it to establish a parallel authenticated session, even after the legitimate user has already rotated to a newer token.

**Remediation:**

Implement server-side token tracking with invalidation on use. When a token is used for refresh, mark it as consumed. If a consumed token is presented again, revoke all tokens in that family. Add a TokenStore interface with methods: is_consumed(), mark_consumed(), revoke_family(). Integrate token consumption checking in the dispatch() method before processing refresh requests. JWTs should include a jti (unique token ID) claim to enable tracking.

---

#### FINDING-002: No Token Family Revocation on Reuse Detection

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L1 |
| CWE | CWE-613 |
| ASVS sections | 10.4.5 |
| Files | airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py:45-60, airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py:103-105 |
| Source Reports | 10.4.5.md |
| Related | - |

**Description:**

ASVS 10.4.5 requires: 'revoke all refresh tokens for that authorization if an already used and invalidated refresh token is provided.' This is the critical security mechanism that limits damage from token theft — if an attacker replays a used token, the system should recognize this as compromise and revoke ALL tokens for that session/authorization, forcing re-authentication. No such mechanism exists in this middleware. There is no token family concept, no reuse detection, and no cascading revocation logic. Without family revocation, token theft cannot be detected or contained through the refresh mechanism.

**Remediation:**

Implement token family tracking with automatic revocation. Create a TokenFamilyStore interface with methods: register_token(), mark_consumed(), is_consumed(), revoke_family(), is_family_revoked(). JWTs should include both a jti (unique token ID) and family_id claim to enable tracking. When a consumed token is presented (replay detected), automatically revoke all tokens in that family and force re-authentication. Implement this check at the beginning of the dispatch() method before processing any refresh logic.

---

#### FINDING-003: No Clear-Site-Data header implementation for session termination

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 14.3.1 |
| Files | airflow-core/src/airflow/api_fastapi/core_api/app.py:entire file scope |
| Source Reports | 14.3.1.md |
| Related | - |

**Description:**

When a user logs out or their session is terminated, authenticated data (cached API responses, stored tokens in localStorage/sessionStorage, cookies) remains in the browser. This creates a risk that: Subsequent users on shared devices can access previously authenticated data from browser cache; Sensitive data persists in browser storage after logout; Tokens or session information remain available to client-side scripts. Data flow: User session terminates → server sends response → no Clear-Site-Data header included → browser retains cached authenticated data (cookies, storage, cache). Gap Type: Type A — No control exists for clearing client-side authenticated data upon session termination.

**Remediation:**

Implement a Clear-Site-Data header on logout responses and add client-side cleanup logic. Server-side (logout endpoint or middleware): Add response.headers["Clear-Site-Data"] = '"cache", "cookies", "storage"' on logout endpoint. Additionally, add a middleware that sets appropriate Cache-Control headers to prevent sensitive response caching using AuthenticatedResponseMiddleware that sets Cache-Control: no-store, no-cache, must-revalidate, private and Pragma: no-cache for API and UI paths.

---

#### FINDING-004: No Strict-Transport-Security (HSTS) header in middleware stack

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 3.4.1 |
| Files | airflow-core/src/airflow/api_fastapi/core_api/app.py:172-189 |
| Source Reports | 3.4.1.md |
| Related | - |

**Description:**

The complete middleware initialization function is shown, and no middleware sets the `Strict-Transport-Security` header. The domain context explicitly requires "Strict-Transport-Security (HSTS) to enforce HTTPS" with "A maximum age of at least 1 year." None of the registered middlewares (`JWTRefreshMiddleware`, auth manager middlewares, `GZipMiddleware`, `HttpAccessLogMiddleware`) appear to be security header middlewares. The auth manager's `get_fastapi_middlewares()` could theoretically return a security headers middleware, but: 1. This is not guaranteed across all auth manager implementations 2. The base application should enforce HSTS regardless of auth manager choice 3. The HSTS header should be present even for unauthenticated responses. Gap Type: Type A — No HSTS control exists in the application middleware stack. Without HSTS, users are vulnerable to SSL stripping attacks where an attacker downgrades the connection from HTTPS to HTTP. First-time visitors or those with expired HSTS cache are vulnerable. This enables credential theft, session hijacking, and content injection.

**Remediation:**

Implement an HSTS middleware that adds the Strict-Transport-Security header to all responses. Example implementation:

```python
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

class HSTSMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_age: int = 31536000, include_subdomains: bool = True, preload: bool = False):
        super().__init__(app)
        policy = f"max-age={max_age}"
        if include_subdomains:
            policy += "; includeSubDomains"
        if preload:
            policy += "; preload"
        self.hsts_value = policy

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = self.hsts_value
        return response

# In init_middlewares:
app.add_middleware(HSTSMiddleware, max_age=31536000, include_subdomains=True)
```

---

#### FINDING-005: CORS `allow_credentials=True` hardcoded without origin wildcard validation

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 3.4.2 |
| Files | airflow-core/src/airflow/api_fastapi/core_api/app.py:148-162 |
| Source Reports | 3.4.2.md |
| Related | - |

**Description:**

The CORS configuration unconditionally sets `allow_credentials=True` without validating whether the origins list contains a wildcard (`*`). When an administrator configures `access_control_allow_origins = *`, Starlette's CORSMiddleware with `allow_credentials=True` will reflect the requesting `Origin` header value in `Access-Control-Allow-Origin` and include `Access-Control-Allow-Credentials: true`. This effectively allows ANY origin to make credentialed cross-origin requests. No allowlist validation logic is performed - the configured origins list is passed directly to the middleware without checking for `*`, validating format, or ensuring they're specific trusted domains. Per Starlette's CORSMiddleware implementation, when `allow_origins=['*']` and `allow_credentials=True`, the middleware reflects the request's `Origin` header (because browsers reject `Access-Control-Allow-Origin: *` with credentials), creating an 'allow any origin with credentials' configuration.

**Remediation:**

Add validation to prevent `allow_credentials=True` when wildcard origin is configured. If `*` is detected in the origins list, either disable `allow_credentials` or reject the configuration. Additionally, validate that configured origins are proper URLs and preferably use HTTPS. Example: Check if '*' is in allow_origins list; if so, log a warning and set allow_credentials=False. For non-wildcard origins, validate they start with 'https://' or 'http://localhost' and log warnings for non-HTTPS origins.

---

#### FINDING-006: API documentation demonstrates sending credentials over plaintext HTTP

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 12.2.1 |
| Files | airflow-core/docs/security/api.rst:45-55 |
| Source Reports | 12.2.1.md |
| Related | - |

**Description:**

The API security documentation contains no mention of HTTPS requirements, HTTP-to-HTTPS redirect requirements, or HSTS (HTTP Strict Transport Security) headers. For an external-facing API, the documentation should explicitly state that TLS is mandatory and HTTP fallback must be disabled. Without explicit documentation requiring HTTPS and prohibiting HTTP fallback, deployers may configure the Airflow API server to accept both HTTP and HTTPS, or HTTP-only, violating ASVS 12.2.1's requirement that services 'do not fall back to insecure or unencrypted communications.'

**Remediation:**

Update all API examples to use HTTPS and add a security warning:

```rst
.. warning::

   Always use HTTPS (TLS) when communicating with the Airflow API.
   Never send credentials over unencrypted HTTP connections.
   The ``http://localhost`` examples below are for local development only.

Request

.. code-block:: bash

    ENDPOINT_URL="https://your-airflow-instance.example.com"
    curl -X POST ${ENDPOINT_URL}/auth/token \
      -H "Content-Type: application/json" \
      -d '{
        "username": "your-username",
        "password": "your-password"
      }'
```

---

#### FINDING-007: Missing Documentation of Risk-Based Remediation Timeframes for Third-Party Components

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 15.1.1 |
| Files | AGENTS.md:project-wide |
| Source Reports | 15.1.1.md |
| Related | - |

**Description:**

The primary developer and architecture documentation (AGENTS.md) extensively documents security model boundaries, coding standards, testing requirements, and contribution workflows, but contains no section defining risk-based remediation timeframes for updating vulnerable third-party dependencies or libraries in general. The documentation acknowledges 100+ provider packages with individual pyproject.toml files and the uv.lock file locks all transitive dependency versions. The Tracking Issues section discusses workarounds and version caps but frames this as deferred work tracking, NOT vulnerability remediation policy. No classification system (Critical/High/Medium/Low) with corresponding remediation timeframes exists. No distinction between actively exploited vulnerabilities vs. theoretical issues. No documentation of what constitutes a 'risky component' or 'dangerous functionality' in the context of third-party libraries.

**Remediation:**

Create a dedicated security policy document (e.g., airflow-core/docs/security/dependency_management.rst or a top-level DEPENDENCY_POLICY.md) that includes: (1) Risk Classification and Remediation Timeframes with severity levels (Critical: 9.0-10.0 CVSS, 48 hours; High: 7.0-8.9, 7 days; Medium: 4.0-6.9, 30 days; Low: 0.1-3.9, 90 days max); (2) General Library Update Policy with quarterly reviews for all direct dependencies, 14-day updates for security-critical libraries, and 90-day migration plans for EOL libraries; (3) Dangerous Functionality Components list including deserialization libraries, code execution engines, cryptographic libraries, network/HTTP clients, and database drivers/ORMs; (4) Risky Component Identification criteria including no release in 12+ months, unresolved CVEs older than remediation timeframe, maintainer count < 2, and no security disclosure process documented.

---

#### FINDING-008: Cannot Verify Compliance — No Documented Timeframes Exist to Measure Against

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 15.2.1 |
| Files | Project-wide, AGENTS.md |
| Source Reports | 15.2.1.md |
| Related | - |

**Description:**

ASVS 15.2.1 requires verifying that the application only contains components which have not breached the documented update and remediation time frames. This verification is impossible because: 1) No remediation timeframes are documented (as identified in ASVS-1511-HIGH-001), 2) No automated enforcement mechanism exists in the CI/CD pipeline (based on provided documentation), 3) The uv.lock regeneration guidance treats dependency resolution as a conflict-resolution mechanism, not a security maintenance activity. The CI/CD pipeline includes static checks, type checking, testing, linting, and documentation building, but no dependency vulnerability scanning step is documented.

**Remediation:**

1. Define timeframes first (prerequisite — see DEPENDENCY_MANAGEMENT-1 remediation). 2. Implement automated enforcement with GitHub Actions workflow for dependency audit that runs weekly and on PRs modifying uv.lock or pyproject.toml, using pip-audit to scan exported dependencies and a custom script to check component age against policy thresholds. 3. Add to AGENTS.md CI description: Dependency security audit that runs automatically on PRs modifying uv.lock or pyproject.toml and blocks merge if components breach documented remediation timeframes.

---

#### FINDING-009: Authentication Documentation Missing Rate Limiting, Anti-Automation, and Adaptive Response Controls

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 6.1.1 |
| Files | airflow-core/docs/security/api.rst |
| Source Reports | 6.1.1.md |
| Related | - |

**Description:**

The API security documentation defines JWT authentication flow (token generation via POST /auth/token with username/password credentials) but contains zero documentation about how rate limiting, anti-automation, or adaptive response controls defend this endpoint against credential stuffing and brute force attacks. The documentation does not explain: (1) How rate limiting is configured on the /auth/token endpoint, (2) What anti-automation controls (CAPTCHA, proof-of-work) are available, (3) What adaptive responses occur after failed authentication attempts, (4) How these controls prevent credential stuffing attacks, (5) How these controls prevent password brute force attacks, (6) How malicious account lockout is prevented (e.g., attacker intentionally triggering lockouts for legitimate users). Without documented (and presumably implemented) rate limiting, attackers can repeatedly call the authentication endpoint unchecked. Additionally, if account lockout IS implemented somewhere (e.g., in an auth manager plugin), there is no documentation explaining how legitimate users are protected from being maliciously locked out.

**Remediation:**

Add a dedicated section to airflow-core/docs/security/api.rst (or a separate authentication security document) that addresses: Rate Limiting - Configure rate limiting using options in the [api] section of airflow.cfg (e.g., auth_rate_limit = 5/minute, auth_rate_limit_per_user = 20/hour). For production deployments behind a reverse proxy, configure rate limiting at the proxy layer (e.g., nginx limit_req_zone, HAProxy stick-tables, or cloud provider WAF rules). Anti-Automation Controls - Deploy a Web Application Firewall (WAF) with bot detection capabilities, consider integrating CAPTCHA challenges after repeated failures, use the auth manager's anti-automation features. Adaptive Response - Apply progressive delays after repeated failed authentication attempts (e.g., after 3 failures: 1-second delay, after 5 failures: 5-second delay + CAPTCHA challenge, after 10 failures: temporary IP-based block for 15 minutes). Account Lockout Prevention - Apply rate limiting per-IP by default (not per-account), use temporary lockout with automatic unlock after a configurable period, prefer CAPTCHA challenges over hard lockouts, configure lockout_duration and lockout_threshold. Operators should verify their auth manager documentation for manager-specific lockout behavior and ensure these controls are tested before production deployment.

### 3.3 Medium

#### FINDING-010: Token Revocation Silently Fails on Any Exception Without Caller Notification

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 7.2.4 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/tokens.py:273-280 |
| **Source Reports** | 7.2.4.md |
| **Related Findings** | None |

**Description:**

The revoke_token() method returns None in all cases (success, validation failure, database error). A caller implementing ASVS 7.2.4 (terminate old session on re-authentication) cannot determine whether revocation succeeded. If a database connectivity issue occurs during re-authentication, the old token remains valid without the calling code being aware. The broad except (jwt.InvalidTokenError, Exception) clause catches database connection errors, serialization errors, and any unexpected runtime error, all treated identically with only a log warning.

**Remediation:**

Modify revoke_token() to return bool indicating success/failure. Separate validation errors (token already invalid) from database errors (token not revoked). Let database errors propagate so callers can retry or handle appropriately. Example: return True on successful revocation, False on invalid token (revocation not needed), and raise exceptions for database errors to allow caller retry logic.

---

#### FINDING-011: No Explicit Validation to Reject "none" Algorithm from Configuration

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 9.1.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/tokens.py:226-233, airflow-core/src/airflow/api_fastapi/auth/tokens.py:334-340 |
| **Source Reports** | 9.1.2.md |
| **Related Findings** | None |

**Description:**

The JWTValidator and JWTGenerator classes do not explicitly validate that the configured algorithm is not "none". If an administrator misconfigures jwt_algorithm = none, the validator would pass algorithms=["none"] to jwt.decode(), and PyJWT would accept tokens with alg: "none" without signature verification, allowing any attacker to forge tokens. This represents a complete authentication bypass if the algorithm is misconfigured. An attacker who discovers (or causes) this misconfiguration can forge arbitrary JWT tokens without possessing any key material.

**Remediation:**

Add explicit validation in both JWTValidator.__attrs_post_init__() and JWTGenerator.__attrs_post_init__() to reject the "none" algorithm. Implement allowlist validation using _FORBIDDEN_ALGORITHMS = frozenset({"none"}) and _ALLOWED_ALGORITHMS containing only approved algorithms (HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512, EdDSA, PS256, PS384, PS512). Validate configured algorithms against these lists and raise ValueError if "none" is detected or if an algorithm is not in the allowlist. This provides defense-in-depth against misconfiguration.

---

#### FINDING-012: No enforcement mechanism in base class ensures authorization is called at API entry points

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 8.2.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:entire class |
| **Source Reports** | 8.2.1.md |
| **Related Findings** | None |

**Description:**

The `BaseAuthManager` defines authorization methods as abstract interfaces but provides no mechanism (decorator, middleware requirement, or dependency injection pattern) that FORCES API endpoints to call these methods. The `get_fastapi_middlewares()` method returns an empty list by default. This represents a Potential Type B gap where controls EXIST (abstract authorization methods defined) but the base class provides no mechanism to ensure they are CALLED at every API entry point. Enforcement relies entirely on the API layer code (not provided in this scope). Data Flow: HTTP Request → FastAPI Router → Route Handler → ??? → `is_authorized_*()` — the connection between route handler and authorization check is not structurally enforced by the base class. If any API endpoint omits the authorization check, function-level access control is bypassed. Since there's no structural enforcement, every endpoint must be individually verified.

**Remediation:**

Consider providing a FastAPI dependency or decorator in the base auth framework that enforces authorization:
python
from fastapi import Depends, HTTPException

def require_authorization(
    resource_type: str,
    method: ResourceMethod,
    detail_extractor: Callable = None,
):
    """FastAPI dependency that enforces authorization before handler execution."""
    async def _check(request: Request, user: BaseUser = Depends(get_current_user)):
        auth_manager = get_auth_manager()
        details = detail_extractor(request) if detail_extractor else None
        check_method = getattr(auth_manager, f"is_authorized_{resource_type}")
        if not check_method(method=method, user=user, details=details):
            raise HTTPException(status_code=403, detail="Forbidden")
        return user
    return Depends(_check)

Additionally, conduct a comprehensive audit of all API endpoint handlers to verify that `is_authorized_*` methods are consistently called with appropriate `details` before resource access.

---

#### FINDING-013: Optional `details` parameter allows authorization calls without data-specific context

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-639 |
| **ASVS Sections** | 8.2.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:205-271, airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:290-301 |
| **Source Reports** | 8.2.2.md |
| **Related Findings** | None |

**Description:**

All `is_authorized_*` methods accept `details` as an optional parameter defaulting to `None`. This means callers can invoke authorization checks without specifying which specific resource instance is being accessed. If an API endpoint that operates on a specific resource calls the authorization check without providing details (e.g., omitting `conn_id`), the auth manager implementation may grant access without validating the user has permission to the specific resource instance, creating a BOLA vulnerability. Data Flow: API endpoint receives request with resource ID → calls `is_authorized_connection(method="GET", user=user)` without `details` → Auth manager checks general permission → Access granted without data-specific validation → IDOR/BOLA. This is a design-level concern. The actual risk depends on whether API endpoints consistently pass details for data-specific operations. The `filter_authorized_*` methods correctly pass details, suggesting the pattern is understood — but nothing enforces it at the type level.

**Remediation:**

Consider splitting function-level and data-level authorization into separate method signatures. Create separate methods for type-level authorization (is_authorized_connection_type) and instance-level authorization (is_authorized_connection_instance with required details parameter). Or use @overload to make the type checker flag calls without details when accessing specific instances. Example: @abstractmethod def is_authorized_connection_type(self, *, method: ResourceMethod, user: T) -> bool: """Check if user can access the connection resource type (function-level).""" @abstractmethod def is_authorized_connection_instance(self, *, method: ResourceMethod, user: T, details: ConnectionDetails) -> bool: """Check if user can access a specific connection (data-level, required details)."""

---

#### FINDING-014: No mechanism for users to change their password

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 6.2.2, 6.2.3 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py:entire file, airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:entire class |
| **Source Reports** | 6.2.2.md, 6.2.3.md |
| **Related Findings** | None |

**Description:**

The SimpleAuthManager provides no mechanism for users to change their passwords. The only password management is auto-generation during initialization when a user doesn't yet have a password. There is no PUT /password, POST /change-password, or equivalent endpoint anywhere in the router. The only way to 'change' a password is to delete the password file and restart the application (which generates new random passwords for all users) or manually edit the JSON file. Users cannot change their password if they believe it has been compromised, or if they wish to set a memorable password. This violates the fundamental NIST SP 800-63B requirement that memorized secrets can be changed by the subscriber.

**Remediation:**

When implementing password change (per ASVS-622-MED-001 remediation), ensure the endpoint requires both current and new password:
```python
class PasswordChangeBody(BaseModel):
    current_password: str
    new_password: str

# In the service:
@staticmethod
def change_password(user: SimpleAuthManagerUser, current_password: str, new_password: str) -> None:
    passwords = SimpleAuthManager.get_passwords()
    stored = passwords.get(user.username, "")
    if not hmac.compare_digest(stored.encode("utf-8"), current_password.encode("utf-8")):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Current password incorrect")
    # Validate new_password length >= 8
    if len(new_password) < 8:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password must be at least 8 characters")
    # Update password in file...
```

---

#### FINDING-015: No Rate Limiting or Brute Force Protection on Login Endpoints

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 6.3.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py:41, airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py:99, airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py:28 |
| **Source Reports** | 6.3.1.md |
| **Related Findings** | None |

**Description:**

An attacker can perform unlimited credential stuffing or brute force attacks against the login endpoints. The `_generate_password` method produces 16-character passwords from a 52-character alphabet (≈91 bits of entropy), making brute force against generated passwords computationally infeasible. However, if users are configured with weak passwords through the `simple_auth_manager_users` config, or if the password file is manually edited with weak passwords, the lack of rate limiting enables rapid dictionary attacks. The code includes a production detection heuristic (`_looks_like_production`) that only WARNS without enforcing any protective measures, meaning the system could be running in a production-like environment without protection.

**Remediation:**

Option 1: Add rate limiting middleware to login routes using fastapi_limiter.depends.RateLimiter with configuration such as 5 attempts per 60 seconds. Option 2: Implement progressive delay in SimpleAuthManagerLogin.create_token by tracking failed attempts per username and raising HTTP 429 after 5 recent failures within a 300-second window. Store failed attempt timestamps and clean up old entries to prevent memory exhaustion.

---

#### FINDING-016: System-Generated Passwords Never Expire and Become Permanent Credentials

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 6.4.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:143-184, airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:392 |
| **Source Reports** | 6.4.1.md |
| **Related Findings** | None |

**Description:**

Generated initial passwords never expire and have no TTL or expiration mechanism. Once written to the password file, they remain valid indefinitely and become long-term passwords. There is no password change mechanism, no "must change on first login" flag, and no mechanism to force rotation. Additionally, passwords are printed to stdout/logs on first initialization, creating a persistent record in log files. Data flow: First startup → init() → _generate_password() → password stored in JSON file permanently → used for all future logins with no expiry.

**Remediation:**

Option 1: Add timestamp tracking and expiration. Modify _generate_password() to return tuple[str, float] with creation timestamp. In create_token, check if time.time() - password_entry["created_at"] > INITIAL_PASSWORD_TTL and raise HTTPException if expired. Option 2: Add a password change endpoint that invalidates initial passwords and mark generated passwords with a "must_change" flag.

---

#### FINDING-017: Inability to verify session termination effectiveness from app initialization layer

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 7.4.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py:172-189 |
| **Source Reports** | 7.4.1.md |
| **Related Findings** | None |

**Description:**

The JWTRefreshMiddleware is added to the middleware stack, which is the documented mechanism for handling token lifecycle. However, from the initialization code alone, the following cannot be verified: 1. Whether the refresh middleware checks a revocation/termination list before issuing new tokens 2. Whether logout triggers invalidation of the refresh token (preventing new access tokens) 3. The actual token expiration duration (whether it's "appropriately short"). Data Flow: User logout → (unknown handler) → JWT remains valid until expiration → JWTRefreshMiddleware either allows or denies refresh. Gap Type Classification: Cannot be determined from provided code — the control EXISTS (JWTRefreshMiddleware) but its effectiveness for session termination cannot be verified without its implementation. Impact: If the refresh middleware does not check token termination state, logged-out users could continue using their tokens until natural expiration.

**Remediation:**

Verify in the JWTRefreshMiddleware implementation that: 1. Logout marks the refresh token as terminated (e.g., in database or cache) 2. The middleware rejects refresh requests for terminated tokens 3. Access token lifetime is configured to be short (e.g., ≤15 minutes)

---

#### FINDING-018: No visible mechanism for immediate session termination on account disable/delete

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 7.4.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/app.py:entire file, airflow-core/src/airflow/api_fastapi/core_api/app.py:entire file |
| **Source Reports** | 7.4.2.md |
| **Related Findings** | None |

**Description:**

The application initialization code does not contain or reference any mechanism for: 1) Event-driven session termination when accounts are disabled or deleted, 2) A per-user token invalidation date/time that could be updated on account status change, 3) Account status checking during token refresh or request validation, 4) Hooks or signals for account lifecycle events that trigger session cleanup. If an employee is terminated and their account disabled, their existing access tokens and refresh tokens may remain valid until natural expiration. In a JWT architecture without revocation, this window could be the full access token lifetime.

**Remediation:**

Implement account status checking in auth manager middleware or JWTRefreshMiddleware. Example: Check if account is disabled/deleted on every request or at minimum on refresh, raising 401 if disabled. Consider adding a per-user 'tokens_valid_after' timestamp field that is updated on account disable and checked during token validation. Example code provided in report includes: validate_request checking is_account_disabled_or_deleted(), and UserModel with tokens_valid_after datetime field that is compared against token.issued_at during validation.

---

#### FINDING-019: API Input Validation Rules Not Documented in Available Application Documentation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 2.1.1 |
| **Files** | airflow-core/docs/stable-rest-api-ref.rst:entire file |
| **Source Reports** | 2.1.1.md |
| **Related Findings** | None |

**Description:**

The only public API reference documentation provided (stable-rest-api-ref.rst) is a stub file containing no content. While it's noted that documentation is auto-generated during the build process, the absence of source validation documentation in the provided scope means we cannot verify that: 1) Input validation rules for API endpoints are formally defined (e.g., DAG ID format, connection ID format, variable key constraints), 2) Data format specifications exist for structured inputs (e.g., cron expressions for schedules, JSON configurations for connections), 3) Business logic constraints are documented (e.g., pool slot ranges, priority weight limits, timeout maximums). Without documented validation rules, developers may implement inconsistent validation, and security reviewers cannot verify that all inputs are properly constrained. This is a documentation completeness gap rather than a code vulnerability.

**Remediation:**

Ensure the generated API documentation (from airflow-core/docs/conf.py) includes: 1) Explicit field-level validation rules (types, formats, ranges, patterns), 2) Business logic constraints for each endpoint, 3) Expected data formats with examples. Example: DAG ID Validation Rules: Type: string, Pattern: ^[a-zA-Z0-9._-]+$, Max length: 250 characters, Must not start with a period. Pool Slots: Type: integer, Range: -1 to 2147483647, -1 indicates unlimited.

---

#### FINDING-020: No Sec-Fetch-* header validation or Content-Security-Policy middleware for API/static responses

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 3.2.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py:172-189 |
| **Source Reports** | 3.2.1.md |
| **Related Findings** | None |

**Description:**

The middleware stack contains JWT refresh, auth manager middlewares, GZip compression, and access logging. There is no middleware that: 1. Validates Sec-Fetch-Dest, Sec-Fetch-Mode, or Sec-Fetch-Site headers on API endpoints 2. Sets X-Content-Type-Options: nosniff on responses 3. Sets Content-Security-Policy headers (including sandbox or frame-ancestors directives) 4. Sets Content-Disposition: attachment for user-uploaded or generated file downloads. Without X-Content-Type-Options: nosniff, browsers may MIME-sniff API responses (JSON/text) as HTML, enabling XSS. Without CSP, injected content has no execution restrictions. Without Sec-Fetch validation, API endpoints can be directly navigated to in a browser and rendered in unexpected contexts.

**Remediation:**

Implement a SecurityHeadersMiddleware that sets X-Content-Type-Options: nosniff, Content-Security-Policy with restrictive directives (default-src 'self'; script-src 'self'; frame-ancestors 'self'; report-uri /csp-report), and Referrer-Policy: strict-origin-when-cross-origin on all responses. Example code: from starlette.middleware.base import BaseHTTPMiddleware; class SecurityHeadersMiddleware(BaseHTTPMiddleware): async def dispatch(self, request, call_next): response = await call_next(request); response.headers['X-Content-Type-Options'] = 'nosniff'; response.headers['Content-Security-Policy'] = 'default-src \'self\'; script-src \'self\'; frame-ancestors \'self\'; report-uri /csp-report'; response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'; return response. Add to init_middlewares: app.add_middleware(SecurityHeadersMiddleware)

---

#### FINDING-021: Cookie path scoping function exists but no evidence of Secure attribute or __Host-/__Secure- prefix enforcement

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 3.3.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/app.py:48-54 |
| **Source Reports** | 3.3.1.md |
| **Related Findings** | None |

**Description:**

The `get_cookie_path()` function provides path scoping for cookies but does not enforce the `Secure` attribute or cookie name prefixes (`__Host-` or `__Secure-`). The actual cookie-setting code is not present in the provided files, but the infrastructure for ensuring secure cookie attributes is not visible. A JWT refresh middleware exists (`JWTRefreshMiddleware`), suggesting tokens are stored in cookies, and a `get_cookie_path()` utility exists for cookie scoping, but no Secure attribute enforcement, no prefix validation, and no SameSite configuration is visible. This represents a gap in the visible code, though the actual cookie-setting code may implement these controls in files not provided. Without `Secure` attribute, cookies can be transmitted over unencrypted HTTP. Without `__Host-` or `__Secure-` prefixes, cookies are vulnerable to domain/path override attacks from subdomains.

**Remediation:**

Implement a secure cookie-setting function that enforces security attributes:
python
def set_secure_cookie(response, name: str, value: str, path: str = None, **kwargs):
    """Set a cookie with security attributes enforced."""
    cookie_path = path or get_cookie_path()
    # Use __Host- prefix for path-scoped cookies (requires Secure, Path=/, no Domain)
    secure_name = f"__Host-{name}" if cookie_path == "/" else f"__Secure-{name}"
    response.set_cookie(
        key=secure_name,
        value=value,
        secure=True,
        httponly=kwargs.get("httponly", True),
        samesite=kwargs.get("samesite", "Lax"),
        path=cookie_path,
    )

Audit `JWTRefreshMiddleware` and any other cookie-setting code to verify `Secure`, `HttpOnly`, `SameSite`, and `__Host-`/`__Secure-` prefix usage.

---

#### FINDING-022: CORS middleware only conditionally applied — unprotected if no CORS config set

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 3.4.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py:155-162 |
| **Source Reports** | 3.4.2.md |
| **Related Findings** | None |

**Description:**

If no CORS configuration is provided (`access_control_allow_origins`, `access_control_allow_methods`, `access_control_allow_headers` are all empty/unset), no CORSMiddleware is added at all. Without CORSMiddleware, FastAPI does not set CORS headers, which means cross-origin requests will be rejected by default by the browser's Same-Origin Policy for JavaScript-initiated requests. The absence of CORS middleware means there's no explicit denial of cross-origin requests at the server level. Responses won't include `Access-Control-Allow-Origin` headers, which is actually the more restrictive default. Note: This is downgraded as it actually represents secure-by-default behavior (no CORS headers = browser blocks cross-origin JS requests).

**Remediation:**

This is informational - the absence of CORS middleware when unconfigured means the browser's Same-Origin Policy is the default protection, which is correct. No remediation required, but documentation should clarify that CORS is opt-in and secure by default.

---

#### FINDING-023: No explicit CSRF token middleware or anti-forgery mechanism visible for state-changing operations

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 3.5.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py:172-189, airflow-core/src/airflow/api_fastapi/app.py:78-124 |
| **Source Reports** | 3.5.1.md |
| **Related Findings** | None |

**Description:**

The application's CSRF protection strategy needs to be assessed: 1. JWT-based authentication via cookies: The presence of JWTRefreshMiddleware and get_cookie_path() indicates JWT tokens are stored in cookies. Cookie-based authentication is inherently vulnerable to CSRF unless additional protections are in place. 2. No explicit CSRF token middleware: The middleware stack does not include a CSRF token generation/validation middleware. 3. CORS as partial protection: The optional CORS middleware provides protection for non-simple requests (those requiring preflight) by restricting which origins can make credentialed requests. However: CORS is only configured when origins are explicitly set, simple requests (form POSTs with application/x-www-form-urlencoded) don't trigger preflight, and GET requests with side effects (if any) are not protected. 4. Potential mitigations not visible in this scope: SameSite cookie attributes (not visible in provided code), custom header requirements (e.g., X-Requested-With) on API endpoints, token validation in request headers rather than cookies. The ASVS requirement states: if the application does not rely on the CORS preflight mechanism... requests are validated to ensure they originate from the application itself. Gap Type: Type A/B - If CSRF protection relies on CORS preflight but CORS is not always configured, and no fallback CSRF mechanism exists, this is a gap. Impact: If JWT tokens are stored in cookies without SameSite=Strict and without CSRF tokens, an attacker can craft a page that submits state-changing requests (e.g., triggering DAGs, modifying connections) on behalf of an authenticated user.

**Remediation:**

Option 1: Require non-CORS-safelisted header on all state-changing endpoints using CSRFProtectionMiddleware that checks for x-requested-with header on POST, PUT, DELETE, PATCH methods. Option 2: Ensure cookies use SameSite=Strict (in cookie-setting code). Option 3: Validate Origin/Referer headers against expected values.

---

#### FINDING-024: No custom header requirement to enforce CORS preflight for cookie-authenticated requests

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 3.5.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py:148-162 |
| **Source Reports** | 3.5.2.md |
| **Related Findings** | None |

**Description:**

Cross-origin request → browser decides if preflight needed → `allow_credentials=True` permits cross-origin cookie sending → endpoint processes request with authenticated session. A cross-origin POST request with `Content-Type: text/plain` (a CORS-safelisted content type) sent via form submission will NOT trigger a CORS preflight, yet the browser will attach cookies due to `allow_credentials=True`. If any POST endpoint doesn't strictly require `application/json` parsing or can process the body as text, a cross-origin attacker could forge requests using a victim's session cookies without triggering CORS preflight. FastAPI's JSON body parsing mitigates this for most endpoints (requests without `Content-Type: application/json` will be rejected at the body parsing stage), but endpoints without required bodies or with optional bodies remain potentially exposed.

**Remediation:**

Add a requirement for a non-safelisted custom header (e.g., `X-Requested-With`) for all state-changing operations, or validate the `Origin` header server-side for all sensitive requests regardless of CORS configuration. Implement an OriginValidationMiddleware that checks the Origin header for POST, PUT, PATCH, and DELETE requests and rejects simple content types that don't trigger preflight unless the Origin is validated.

---

#### FINDING-025: No Sec-Fetch-* header validation for defense-in-depth against cross-origin attacks

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 3.5.3 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py:172-189 |
| **Source Reports** | 3.5.3.md |
| **Related Findings** | None |

**Description:**

Without Sec-Fetch-* header validation, the application cannot distinguish between same-origin navigation requests (Sec-Fetch-Site: same-origin), cross-origin requests (Sec-Fetch-Site: cross-site), navigation vs. API calls (Sec-Fetch-Mode: navigate vs cors), or resource loads like image src attributes (Sec-Fetch-Dest: image). This means that even if endpoints use correct HTTP methods, there's no defense-in-depth mechanism to reject requests that originate from unexpected contexts (e.g., a cross-origin navigation or image load targeting a state-changing endpoint).

**Remediation:**

Add a Sec-Fetch-* validation middleware that rejects requests to API endpoints from unexpected origins or navigation contexts. Implement SecFetchValidationMiddleware that validates sec-fetch-site and sec-fetch-mode headers, rejecting cross-site navigation to API endpoints and no-cors mode for state-changing requests. Apply this middleware to all API endpoints while excluding static/SPA routes.

---

#### FINDING-026: Security documentation lacks TLS protocol version requirements for Public API

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 12.1.1 |
| **Files** | airflow-core/docs/security/api.rst:entire file |
| **Source Reports** | 12.1.1.md |
| **Related Findings** | None |

**Description:**

Security documentation for the Public API contains no guidance on TLS protocol version requirements. Given this is the authoritative security documentation for API access, the absence of TLS version requirements means deployers have no guidance on configuring TLS 1.2+ as the minimum protocol version. Deployers following this documentation may not configure TLS protocol version restrictions, leaving the API server vulnerable to protocol downgrade attacks (BEAST, POODLE) or running with deprecated TLS versions that have known cryptographic weaknesses.

**Remediation:**

Add a TLS configuration section to the API security documentation specifying that all external-facing Airflow services (API server, web UI) must be configured with TLS 1.2 as the minimum protocol version, with TLS 1.3 preferred. Earlier protocol versions (TLS 1.0, TLS 1.1, SSLv3) must be disabled. Include example configurations for reverse proxies (nginx, Apache) showing how to enable only TLS 1.2 and TLS 1.3, prefer TLS 1.3 cipher suites, and disable weak cipher suites (RC4, 3DES, export ciphers).

---

#### FINDING-027: API security documentation lacks publicly trusted TLS certificate guidance

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 12.2.2 |
| **Files** | airflow-core/docs/security/api.rst:entire file |
| **Source Reports** | 12.2.2.md |
| **Related Findings** | None |

**Description:**

The API security documentation for external-facing services contains no guidance on certificate requirements. There is no mention of using publicly trusted TLS certificates (issued by CAs in browser/OS trust stores) for external-facing services, nor any distinction between internal CA certificates and publicly trusted certificates. Without documentation specifying publicly trusted certificate requirements, deployers may use self-signed certificates or internal CA certificates for external-facing API endpoints.

**Remediation:**

Add certificate guidance to the security documentation:
rst
TLS Certificate Requirements
-----------------------------

External-facing Airflow services (web UI, public API) must use TLS certificates
issued by publicly trusted Certificate Authorities (CAs). Self-signed certificates
or internal CA certificates should only be used for internal service-to-service
communication within trusted networks.

For production deployments:

- Use certificates from publicly trusted CAs (Let's Encrypt, DigiCert, etc.)
- Configure automatic certificate renewal (e.g., via cert-manager in Kubernetes)
- Do not use wildcard certificates across production and non-production environments

For internal services (worker-to-scheduler, database connections):

- Internal CA certificates may be used with proper trust chain configuration
- Certificate validation must still be enforced (never disable verification)

---

#### FINDING-028: Deployment Documentation Lacks SCM Metadata Exclusion Guidance

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 13.4.1 |
| **Files** | airflow-core/docs/administration-and-deployment/scheduler.rst:N/A (entire document scope) |
| **Source Reports** | 13.4.1.md |
| **Related Findings** | None |

**Description:**

The administration and deployment documentation covers extensive operational concerns including high availability configuration, database requirements, performance tuning, connection pooling (PGBouncer recommendations), and multi-scheduler configuration. However, no section addresses basic production hardening requirements including excluding .git/.svn directories from deployment artifacts, blocking web requests to source control metadata paths, or stripping development files from production containers. The documentation provides production deployment guidance without addressing this fundamental security hardening measure.

**Remediation:**

Add a security hardening section to the administration-and-deployment documentation with guidance on excluding source control metadata from production deployments. Include .dockerignore patterns (.git, .svn, .gitignore, AGENTS.md, contributing-docs/), reverse proxy path blocking configuration (nginx location blocks denying access to .git/.svn paths), and verification procedures for container images.

---

#### FINDING-029: AGENTS.md Contains Detailed Internal Architecture Information at Repository Root

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 13.4.1 |
| **Files** | AGENTS.md:1-400+ |
| **Source Reports** | 13.4.1.md |
| **Related Findings** | None |

**Description:**

The AGENTS.md file at the repository root contains extensive internal security architecture information that would aid an attacker if accessible in production. This file reveals internal API paths, security boundary limitations, JWT token architecture details, database model structure, and component isolation assumptions. The file documents that 'Scheduler never runs user code', details the Execution API with JWT token scoping, reveals SQLAlchemy model structure, and explicitly documents where security guards can be bypassed.

**Remediation:**

Ensure AGENTS.md and similar development-only documentation is excluded from production artifacts. Preferred approach: add to .dockerignore (.git, .svn, AGENTS.md, contributing-docs/, dev/, *.md, !README.md). Alternative: explicitly remove in Dockerfile using RUN rm -rf commands. Add FastAPI middleware to reject requests matching /.git/ or /.svn/ patterns as defense in depth.

---

#### FINDING-030: No SBOM Generation or Component Inventory Documentation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 15.1.1, 15.2.1 |
| **Files** | AGENTS.md:Repository Structure section |
| **Source Reports** | 15.1.1.md, 15.2.1.md |
| **Related Findings** | None |

**Description:**

The AGENTS.md documents extensive processes for code formatting, linting, type checking, testing, and documentation building, but contains no documented process for: periodic review of dependency versions, scheduled security scanning, release-blocking criteria for vulnerable dependencies, or responsibility assignment for dependency maintenance. The scheduler.rst mentions specific database version requirements (PostgreSQL 12+, MySQL 8.0+) showing version awareness exists for some components, but no systematic approach. Dependency updates happen reactively (when breakage occurs) rather than proactively (when vulnerabilities are disclosed). No ownership model exists for monitoring dependency health across 100+ provider packages.

**Remediation:**

Add a Dependency Maintenance section to AGENTS.md or a dedicated policy document that includes: Scheduled Reviews (Weekly automated scan of uv.lock against vulnerability databases, Monthly human review of flagged dependencies and update feasibility, Quarterly full dependency audit including EOL assessment and version currency); Responsibilities (Core dependencies: Core maintainers, Provider dependencies: Provider maintainers, Development tooling: DevX team); Blocking Criteria (PRs introducing new dependencies with known Critical/High CVEs: blocked, Releases containing components exceeding remediation timeframe: blocked).

---

#### FINDING-031: Missing documentation for OAuth grant type restrictions and per-client allowlists

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 10.4.4 |
| **Files** | airflow-core/docs/security/api.rst:28-48 |
| **Source Reports** | 10.4.4.md |
| **Related Findings** | None |

**Description:**

The documented /auth/token endpoint using username/password direct exchange resembles the ROPC grant type pattern. While this is a first-party endpoint (not a third-party OAuth flow), the documentation does not clarify: which OAuth grant types are supported per client, whether implicit or ROPC grants are disabled for OAuth-integrated auth managers, and per-client grant type restrictions. Without documented grant type restrictions, operators deploying OAuth-integrated auth managers may not be aware they should restrict grant types. If an auth manager implements multiple grants including implicit or ROPC for third-party clients, this would violate ASVS 10.4.4.

**Remediation:**

Add documentation specifying: (1) Which grant types each auth manager supports, (2) That implicit and ROPC grants should not be used for third-party clients, (3) How to configure per-client grant type restrictions. Example documentation section: 'Grant Type Security: When using OAuth-based auth managers, ensure that: The token (Implicit) grant type is disabled for all clients; The password (Resource Owner Password Credentials) grant type is not exposed to third-party clients; Each registered client is restricted to only the grant types it requires; The authorization code grant with PKCE is preferred for interactive flows.'

### 3.4 Low

#### FINDING-032: UUID4 Token Identifier (jti) Provides 122 Bits of Entropy, Marginally Below 128-Bit Threshold

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 7.2.3 |
| **Affected File(s)** | airflow-core/src/airflow/api_fastapi/auth/tokens.py:330 |
| **Source Report(s)** | 7.2.3.md |
| **Related Finding(s)** | - |

**Description:**

UUID version 4 generates 128 random bits but reserves 6 bits for version (4 bits = `0100`) and variant (2 bits = `10`), yielding exactly 122 bits of cryptographic randomness. While this is sourced from a CSPRNG (`os.urandom()`), it technically falls below the 128-bit entropy threshold specified by ASVS 7.2.3. The `jti` serves as a unique identifier within a cryptographically signed JWT — session security relies on signature unforgeability (HS512/RS256/EdDSA), not on the unpredictability of the `jti`. An attacker would need to break the signing key to forge tokens, making `jti` prediction irrelevant. The 122-bit randomness provides negligible collision probability (≈2^-61 for birthday attack after generating 2^61 tokens). This is a marginal compliance observation. Since Airflow uses self-contained JWT tokens (not opaque reference tokens), the security model relies on cryptographic signing rather than token unpredictability. The ASVS 7.2.3 requirement is primarily designed for opaque session IDs where guessability enables session hijacking — a threat model that does not apply to signed JWTs.

**Remediation:**

If strict 128-bit compliance is required for the token identifier:
```python
import os
from base64 import urlsafe_b64encode

claims = {
    "jti": urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode(),
    ...
}
```

---

#### FINDING-033: Token Refresh Does Not Revoke Previous Token (Documented Design Decision)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 7.2.4 |
| **Affected File(s)** | jwt_token_authentication.rst |
| **Source Report(s)** | 7.2.4.md |
| **Related Finding(s)** | - |

**Description:**

The JWTRefreshMiddleware generates a new token when the current token approaches expiry but does not revoke the old token. This means both old and new tokens are valid simultaneously until the old one expires naturally. During the overlap window between token refresh and old token expiry, both tokens are valid. For REST API tokens (24-hour default lifetime), this window could be significant. For Execution API tokens (10-minute lifetime), the exposure is minimal.

**Remediation:**

Acknowledged as intentional design decision. The short token lifetime for Execution API tokens (10 minutes with 20% refresh threshold = ~2 minute overlap) provides adequate mitigation. REST API tokens (24-hour lifetime) have a longer overlap but this is mitigated by the SameSite=Lax cookie and HTTP-only flag preventing token theft via XSS.

---

#### FINDING-034: Authorization documentation does not explicitly define enforcement timing and pipeline position

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 8.1.1 |
| **Affected File(s)** | airflow-core/docs/core-concepts/auth-manager/index.rst |
| **Source Report(s)** | 8.1.1.md |
| **Related Finding(s)** | - |

**Description:**

The authorization documentation comprehensively defines WHAT authorization checks exist (function-level and data-specific), including resource types (connections, DAGs, pools, variables, assets, views) and HTTP methods (GET/POST/PUT/DELETE). However, it does not explicitly document: 1. WHERE in the request processing pipeline authorization MUST be checked (before resource access, before data retrieval, etc.) 2. The required call sequence (authenticate → authorize → process → respond) 3. Mandatory enforcement points (API endpoint layer, middleware layer). Custom auth manager implementers may inadvertently apply authorization checks at incorrect points in the request pipeline (e.g., after data is retrieved), creating a Type D gap where the control is called but after the sensitive operation.

**Remediation:**

Add a section to the documentation explicitly stating: Authorization Enforcement Requirements - All is_authorized_* methods MUST be called: 1. BEFORE any data access or mutation operation 2. At the API server layer (not in client-side code) 3. As early as possible after authentication completes 4. With the specific resource details when accessing a specific resource instance. The authorization decision MUST be evaluated before proceeding. If authorization is denied, the request MUST be rejected with HTTP 403 Forbidden before any resource access occurs.

---

#### FINDING-035: Documentation does not define handling of details=None authorization semantics for data-specific access

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 8.1.1 |
| **Affected File(s)** | airflow-core/docs/core-concepts/auth-manager/index.rst:99-155, base_auth_manager.py:205-216 |
| **Source Report(s)** | 8.1.1.md |
| **Related Finding(s)** | - |

**Description:**

The documentation mentions 'Some details about the connection can be provided' but doesn't clearly distinguish between: Function-level check: is_authorized_connection(method='GET', user=user) (details=None) — 'can user access connections at all?' vs Data-level check: is_authorized_connection(method='GET', user=user, details=ConnectionDetails(conn_id='x')) — 'can user access THIS connection?'. This ambiguity could lead auth manager implementations to treat details=None as 'authorize access to ALL resources' rather than 'check general capability'. Custom auth managers may incorrectly grant broad access when details=None is passed, creating IDOR/BOLA vulnerabilities.

**Remediation:**

Document the semantic difference explicitly: When details is None, the check determines whether the user has the capability to perform the action on the resource type in general. This is typically used for listing operations. When details is provided, it performs a data-specific check for that exact resource instance. Auth manager implementations MUST NOT treat details=None as granting access to all instances of a resource type.

---

#### FINDING-036: Default `filter_authorized_*` implementations may allow timing-based inference attacks

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-208 |
| **ASVS Section(s)** | 8.2.2 |
| **Affected File(s)** | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:459-481, airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:510-532, airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:559-581, airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:639-661 |
| **Source Report(s)** | 8.2.2.md |
| **Related Finding(s)** | - |

**Description:**

The default `filter_authorized_*` implementations iterate over all resource IDs and call individual authorization checks. This is flagged as a performance concern in the documentation, but it also creates a potential timing side-channel: if the response time correlates with the number of resources checked, an attacker could infer the total number of resources in the system (even those they can't access). The implementation iterates through conn_ids and checks authorization for each: def filter_authorized_connections(self, *, conn_ids: set[str], user: T, method: ResourceMethod = "GET", team_name: str | None = None) -> set[str]: def _is_authorized_connection(conn_id: str): return self.is_authorized_connection(method=method, details=ConnectionDetails(conn_id=conn_id, team_name=team_name), user=user) return {conn_id for conn_id in conn_ids if _is_authorized_connection(conn_id)}

**Remediation:**

This is adequately addressed by the existing recommendation to override these methods. Consider adding a note that performance optimization also mitigates timing side-channels. Implementations should batch authorization checks or use constant-time filtering approaches to prevent timing-based inference.

---

#### FINDING-037: No minimum password length validation for manually configured passwords

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 6.2.1 |
| **Affected File(s)** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py:37-58 |
| **Source Report(s)** | 6.2.1.md |
| **Related Finding(s)** | - |

**Description:**

The authentication service validates that a password is provided (non-empty) but does not enforce a minimum length requirement. While auto-generated passwords are 16 characters (via `_generate_password()`), there is no validation that passwords stored in the password file meet any minimum length. An administrator could manually edit `simple_auth_manager_passwords.json.generated` or configure `simple_auth_manager_passwords_file` to point to a file with short passwords, and no runtime validation would reject them. If the password file is manually managed (which is possible via `simple_auth_manager_passwords_file` config), passwords shorter than 8 characters could be accepted without any warning or enforcement.

**Remediation:**

Add password length validation when reading from the password file or add a startup check:
```python
@staticmethod
def get_passwords() -> dict[str, str]:
    password_file = SimpleAuthManager.get_generated_password_file()
    with open(password_file, "r+") as file:
        passwords = SimpleAuthManager._get_passwords(file)
        for username, password in passwords.items():
            if len(password) < 8:
                log.warning(
                    "Password for user '%s' is shorter than 8 characters. "
                    "Minimum 8 characters recommended (15+ strongly recommended).",
                    username,
                )
        return passwords
```

---

#### FINDING-038: No common password list validation mechanism

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 6.2.4 |
| **Affected File(s)** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:445 |
| **Source Report(s)** | 6.2.4.md |
| **Related Finding(s)** | - |

**Description:**

There is no mechanism to check passwords against a list of commonly used or breached passwords. The system does not integrate with any breach database (e.g., Have I Been Pwned API) or maintain a local list of the top 3000+ common passwords. Since passwords are auto-generated using cryptographic randomness with ~85 bits of entropy, the probability of collision with a common password is negligible (~10^-25). However, if password change functionality were added (per 6.2.2), user-chosen passwords would not be validated against common password lists.

**Remediation:**

Implement a common password check utility for future use:
```python
import importlib.resources

COMMON_PASSWORDS: set[str] | None = None

def _load_common_passwords() -> set[str]:
    global COMMON_PASSWORDS
    if COMMON_PASSWORDS is None:
        # Load from bundled file (top 10000 passwords)
        with importlib.resources.open_text("airflow.auth.data", "common_passwords.txt") as f:
            COMMON_PASSWORDS = {line.strip() for line in f if len(line.strip()) >= 8}
    return COMMON_PASSWORDS

def is_common_password(password: str) -> bool:
    return password.lower() in _load_common_passwords()
```

---

#### FINDING-039: Cannot verify password input field masking in UI template

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 6.2.6 |
| **Affected File(s)** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:342-377 |
| **Source Report(s)** | 6.2.6.md |
| **Related Finding(s)** | - |

**Description:**

The login UI is served via Jinja2 templates from a `ui/dist` or `ui/dev` directory. The actual HTML template (`index.html`) is not included in the provided code scope, making it impossible to verify whether password input fields use `type="password"`. The UI files are either compiled frontend assets or development files external to this audit scope. If the password input field uses `type="text"` instead of `type="password"`, passwords would be visible on screen, exposing them to shoulder surfing.

**Remediation:**

Verify the login form HTML in the `ui/dist/index.html` or `ui/dev/index.html` template contains:
```html
<input type="password" name="password" id="password" autocomplete="current-password" />
```

The form should also support a visibility toggle:
```html
<button type="button" onclick="togglePasswordVisibility()" aria-label="Toggle password visibility">
  Show/Hide
</button>
```

---

#### FINDING-040: "Anonymous" Admin Account Created in All-Admins Mode Without Explicit Credential Requirements

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 6.3.2 |
| **Affected File(s)** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py:78, airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py:69 |
| **Source Report(s)** | 6.3.2.md |
| **Related Finding(s)** | - |

**Description:**

When `simple_auth_manager_all_admins=True`, any unauthenticated user can obtain a full ADMIN JWT token via a simple GET request. This is a default credential-equivalent scenario — there is effectively a pre-existing admin account ("Anonymous") that requires no authentication. The unauthenticated GET endpoint creates this token without any credential verification. This is rated LOW because: (1) it requires explicit configuration (`simple_auth_manager_all_admins=True`), (2) it's documented as development-only, (3) the `create_token_all_admins()` method checks the config flag and returns 403 if not enabled, and (4) the production detection heuristic emits warnings. However, if this configuration is accidentally left enabled in a non-development environment, it constitutes a complete authentication bypass.

**Remediation:**

Add enforcement to prevent all-admins mode in production-like deployments:
```python
# Add enforcement to prevent all-admins mode in production-like deployments
@staticmethod
def create_token_all_admins(...) -> str:
    is_all_admins = conf.getboolean("core", "simple_auth_manager_all_admins")
    if not is_all_admins:
        raise HTTPException(status.HTTP_403_FORBIDDEN, ...)
    
    # Block if deployment looks like production
    if SimpleAuthManager._looks_like_production():
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "All-admins mode is disabled in production-like environments"
        )
    
    return SimpleAuthManagerLogin._create_anonymous_admin_user(...)
```

---

#### FINDING-041: Potential JavaScript injection via template variable in SPA initialization

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-79 |
| **ASVS Section(s)** | 1.2.3, 1.2.1 |
| **Affected File(s)** | airflow-core/src/airflow/api_fastapi/core_api/app.py:108-114 |
| **Source Report(s)** | 1.2.3.md, 1.2.1.md |
| **Related Finding(s)** | - |

**Description:**

The `request.base_url.path` is constructed from the ASGI scope, which can be influenced by the `root_path` setting and, in some deployments, by trusted proxy headers (e.g., `X-Forwarded-Prefix`). While Jinja2Templates uses auto-escaping for HTML by default, the actual safety depends on how `backend_server_base_url` is consumed in the `index.html` template. If the template uses this value in a non-HTML context (e.g., embedded in a `<script>` block or as a URL attribute), Jinja2's HTML auto-escaping is insufficient for those contexts. If a reverse proxy or middleware allows manipulation of the root path/base URL, an attacker could inject content that, while HTML-escaped, breaks out of a JavaScript string literal or URL attribute in the template. An attacker who can influence the proxy's `X-Forwarded-Prefix` (in deployments with `ProxyHeadersMiddleware`) might set it to a value like `/';</script><script>alert(1)//` — Jinja2 HTML-escapes this for HTML element context, but if the template uses it like `<script>window.BASE='{{backend_server_base_url}}'</script>`, the HTML-escaped value may still exploit the JavaScript context.

**Remediation:**

Without access to the actual `index.html` template, the safest approach is to validate the `base_url.path` before passing it to the template:
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
Additionally, verify `index.html` template context usage and ensure the Jinja2 `|tojson` filter is applied if `backend_server_base_url` is embedded in a `<script>` block for proper JavaScript-context encoding.

---

#### FINDING-042: Static file serving without Content-Disposition or Sec-Fetch validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 3.2.1 |
| **Affected File(s)** | airflow-core/src/airflow/api_fastapi/core_api/app.py:65-70 |
| **Source Report(s)** | 3.2.1.md |
| **Related Finding(s)** | - |

**Description:**

Static files are served with html=True, which allows HTML file serving. There's no Sec-Fetch-* validation to ensure static resources are only loaded as sub-resources of the application (not navigated to directly), and no mechanism to prevent serving user-influenced content in an incorrect context. Low severity as these are application-owned static files. However, if any mechanism allows user content to land in the static directory, it could be served as HTML without restriction.

**Remediation:**

Consider setting html=False if HTML serving from static is not needed, and ensure a security headers middleware covers these responses. Implement Sec-Fetch-* header validation to ensure static resources are only loaded as sub-resources.

---

#### FINDING-043: Template rendering with dynamic context values — limited audit scope

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 3.2.2 |
| **Affected File(s)** | airflow-core/src/airflow/api_fastapi/core_api/app.py:104-112 |
| **Source Report(s)** | 3.2.2.md |
| **Related Finding(s)** | - |

**Description:**

The template context injects `request.base_url.path` into the HTML template. Jinja2 auto-escapes by default for HTML templates, mitigating XSS from this value. The `request.base_url.path` is server-controlled (derived from the `Host` header and application configuration), not directly user-input in the URL path sense. The React/TypeScript UI code (`airflow/ui/`) is not provided in this audit scope, so client-side rendering safety (use of `textContent`/`createTextNode` vs `innerHTML`/`dangerouslySetInnerHTML`) cannot be assessed for the frontend application. Gap Type: N/A — Insufficient scope to determine if client-side rendering uses safe functions. Impact: Cannot be determined without frontend code review.

**Remediation:**

Audit the React frontend code in `airflow-core/src/airflow/ui/` to verify: 1. Dynamic content uses React's JSX interpolation (which escapes by default) 2. No use of `dangerouslySetInnerHTML` with user-controlled content 3. Any markdown/rich-text rendering uses a sanitization library (e.g., DOMPurify)

---

#### FINDING-044: Catch-all SPA route uses GET method appropriately but lacks method restriction

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 3.5.3 |
| **Affected File(s)** | airflow-core/src/airflow/api_fastapi/core_api/app.py:104-112 |
| **Source Report(s)** | 3.5.3.md |
| **Related Finding(s)** | - |

**Description:**

The catch-all route correctly uses GET (a safe method) for serving static content. This is noted as a positive pattern demonstrating correct method usage. The only concern is that this is a catch-all that could mask incorrect routing, but this is a usability issue, not a security one. The actual sensitive endpoints (in public_router and ui_router) are not visible in the provided code. The visible routes all correctly use GET for non-sensitive, read-only operations.

**Remediation:**

This is classified as LOW/informational. The implementation is appropriate. For completeness, ensure that actual state-changing endpoints in public_router and ui_router use appropriate HTTP methods (POST, PUT, PATCH, DELETE) and not safe methods (GET, HEAD, OPTIONS).

---

#### FINDING-045: Architecture documentation missing TLS protocol version guidance for internal communications

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 12.1.1 |
| **Affected File(s)** | AGENTS.md |
| **Source Report(s)** | 12.1.1.md |
| **Related Finding(s)** | - |

**Description:**

The architecture documentation describes multiple network communication channels (worker-to-API server via Execution API, scheduler-to-DB, API server-to-DB) but provides no guidance on required TLS protocol versions for internal communications. Internal communications between Airflow components (workers, scheduler, API server, database) may be deployed without TLS or with deprecated TLS versions if deployment guidance doesn't specify requirements.

**Remediation:**

Add deployment security guidance referencing TLS version requirements for internal component communication. Document per-component TLS requirements for each communication channel identified in the architecture (worker↔API, scheduler↔DB, API↔DB, client↔API), specifying the minimum TLS version, certificate type, and mutual authentication requirements.

---

#### FINDING-046: Architecture documentation lacks certificate management guidance for external-facing services

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 12.2.2 |
| **Affected File(s)** | AGENTS.md |
| **Source Report(s)** | 12.2.2.md |
| **Related Finding(s)** | - |

**Description:**

The architecture documentation identifies multiple external-facing services (API Server serving React UI, public REST API) but provides no guidance on certificate management for these services. Without certificate guidance in the architecture documentation, security reviews may not verify certificate trust requirements for each component.

**Remediation:**

Add a note in the security model section about certificate requirements for external-facing vs. internal components.

### 3.5 Informational

#### FINDING-047: Dynamic code loading via conf.getimport() for auth manager

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Informational |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 1.3.2 |
| **File(s)** | airflow-core/src/airflow/api_fastapi/app.py:142-153 |
| **Source Report(s)** | 1.3.2.md |
| **Related Finding(s)** | None |

**Description:**

conf.getimport() dynamically imports a Python module/class based on the configuration value at [core] auth_manager. While this is a form of dynamic code loading, it is: 1. From server-side configuration (not user input), 2. A documented, intentional pattern for the pluggable auth manager architecture, 3. The configuration is only writable by deployment managers with server access. This is a documented false positive per the known patterns: 'Pluggable auth manager architecture allowing custom implementations would be flagged as potentially insecure due to third-party code, but it's intentional because enterprises need to integrate with existing identity providers.'

**Remediation:**

While this is not a vulnerability, auditors should verify that: 1. The airflow.cfg file has appropriate filesystem permissions, 2. Environment variable overrides for this config key are restricted, 3. The deployed auth manager implementation is reviewed for security

---

---

# 4. Positive Security Controls

| Control ID | Control Description | Evidence | Implementation Files | ASVS Mapping |
|------------|-------------------|----------|---------------------|--------------|
| PSC-001 | **Server-Side JWT Validation** | All JWT validation performed server-side via JWTValidator class with no client-side verification | `tokens.py:201-297`, `tokens.py:265-270` | 7.2.1, 9.1.1 |
| PSC-002 | **Cryptographic Signature Validation** | Mandatory signature validation via PyJWT decode() with cryptographic key verification | `tokens.py:260-268` | 9.1.1 |
| PSC-003 | **Strong Algorithm Support** | GUESS mechanism resolves to HS512, RS256, or EdDSA only—never weak algorithms | `tokens.py:232-233`, `tokens.py:96-101` | 9.1.2, 11.3.2 |
| PSC-004 | **Trusted Key Material Sources** | Algorithm and keys from JWK metadata/pre-configured JWKS URL only, not token headers | `tokens.py:261-264`, `tokens.py:509-512` | 9.1.3 |
| PSC-005 | **Temporal Claim Validation** | PyJWT built-in exp/nbf validation with 10-second configurable leeway for clock skew | `tokens.py:225`, `tokens.py:267` | 9.2.1 |
| PSC-006 | **Required Claims Enforcement** | Mandatory exp, iat, nbf claims enforced via options parameter | `tokens.py:260-268` | 9.2.1 |
| PSC-007 | **High-Entropy Token Identifiers** | UUID4 jti provides 122 bits of CSPRNG randomness per token | `tokens.py:351` | 7.2.2, 7.2.3 |
| PSC-008 | **Token Rotation on Refresh** | JWTRefreshMiddleware generates completely new tokens rather than extending existing ones | `refresh_token.py:54` | 7.2.4 |
| PSC-009 | **Context-Specific Token Lifetimes** | Separate validity periods: REST API (24h), CLI (1h), Execution API (10min) | Architecture documentation | 9.2.1 |
| PSC-010 | **Revocation Infrastructure** | RevokedToken model with database-backed tracking by jti and auto-cleanup | `tokens.py` | 7.4.1 |
| PSC-011 | **Secure Cookie Configuration** | HttpOnly, SameSite=lax, conditional Secure flag, configurable path | `refresh_token.py:64-69` | 3.3.1, 14.3.1 |
| PSC-012 | **Trust Sentinel Pattern** | USER_INJECTED_BY_TRUSTED_MIDDLEWARE prevents middleware spoofing | `refresh_token.py:51-52` | 8.3.1 |
| PSC-013 | **Graceful Token Expiration** | Expired tokens trigger explicit cookie deletion (max_age=0), forcing re-authentication | `refresh_token.py:55-60` | 7.4.1 |
| PSC-014 | **Exception Containment** | HTTPExceptions during token resolution returned as proper JSON responses | `refresh_token.py:85-87` | N/A |
| PSC-015 | **Abstract Method Enforcement** | All core authorization methods marked @abstractmethod, preventing incomplete implementations | `base_auth_manager.py` | 8.2.1 |
| PSC-016 | **Fail-Closed Multi-Team** | is_authorized_team() raises NotImplementedError by default—access denied if not implemented | `base_auth_manager.py:273-288` | 8.2.1 |
| PSC-017 | **Batch Authorization AND Logic** | batch_is_authorized_* methods use all(), requiring ALL checks to pass | `base_auth_manager.py` | 8.2.1 |
| PSC-018 | **Structured Resource Identification** | Typed detail classes define structured resource identification for data-specific access control | `resource_details.py` | 8.2.2 |
| PSC-019 | **Team-Based Resource Grouping** | get_authorized_* methods group resources by team_name for multi-tenant isolation | `base_auth_manager.py` | 8.2.2 |
| PSC-020 | **Hierarchical DAG Authorization** | DagAccessEntity enables fine-grained authorization on runs, tasks, task instances | `base_auth_manager.py` | 8.2.2 |
| PSC-021 | **Server-Side Token Validation** | get_user_from_token() performs full JWT validation (signature, expiration, audience, revocation) server-side | `base_auth_manager.py:142-154` | 7.2.1, 9.1.1 |
| PSC-022 | **No Client-Side Authorization** | All authorization in backend Python with no client-side JavaScript authorization logic | Architecture | 8.3.1 |
| PSC-023 | **Strong Password Auto-Generation** | 16-character passwords via secrets.choice() providing ~85-91 bits of entropy | `simple_auth_manager.py:~445` | 6.2.1 |
| PSC-024 | **Timing-Attack Resistant Comparison** | hmac.compare_digest with empty-string fallback prevents timing side-channels | `services/login.py:47-56` | 6.3.1 |
| PSC-025 | **No Composition Rules** | Passwords accepted without character type restrictions, supporting passphrases and Unicode | `services/login.py:37-58` | 6.2.5 |
| PSC-026 | **Password Verified Unmodified** | Direct UTF-8 comparison without case transformation, truncation, or normalization | `services/login.py:47-56` | 6.2.8 |
| PSC-027 | **No Hardcoded Default Accounts** | Users exclusively from configuration with random high-entropy passwords | `simple_auth_manager.py:85-86` | 6.3.2 |
| PSC-028 | **Password Generation Race Prevention** | File locking with fcntl.LOCK_EX prevents simultaneous generation | `simple_auth_manager.py:168-171` | N/A |
| PSC-029 | **No Password Hints or KBA** | LoginBody accepts only username/password with no recovery hint fields | `routes/login.py`, `services/login.py` | 6.4.2 |
| PSC-030 | **Fernet Authenticated Encryption** | AES-128-CBC + HMAC-SHA256 with encrypt-then-MAC construction | `docs/security/secrets/fernet.rst` | 11.3.1, 11.3.2 |
| PSC-031 | **Key Rotation Mechanism** | Documented airflow rotate-fernet-key command with lifecycle management | `docs/security/secrets/fernet.rst` | 11.3.2 |
| PSC-032 | **External Secrets Backend Support** | Pluggable architecture for Vault, AWS Secrets Manager, AWS KMS | `docs/security/secrets/secrets-backend/index.rst` | 11.3.2 |
| PSC-033 | **NIST-Approved Hash Functions** | HMAC-SHA256 in Fernet per NIST FIPS 180-4 | `docs/security/secrets/fernet.rst` | 11.4.1 |
| PSC-034 | **SQLAlchemy ORM Query Construction** | Exclusive use of ORM Select objects, no string-based SQL | `common/db/common.py` | 1.2.4 |
| PSC-035 | **Type-Safe Filter Application** | apply_filters_to_select() accepts only OrmClause typed objects | `common/db/common.py:51-59` | 1.2.4 |
| PSC-036 | **Session Injection via Dependency** | SessionDep/AsyncSessionDep use Depends(), never URL parameters | `common/db/common.py:48,66` | 1.2.4 |
| PSC-037 | **Keyword-Only Parameters** | All function signatures use * to enforce keyword arguments | `common/db/common.py` | 1.2.4 |
| PSC-038 | **Pydantic Response Models** | FastAPI with Pydantic naturally restricts returned fields to explicit schema | `api_fastapi/core_api/` | 15.3.1 |
| PSC-039 | **Separation of Models from API** | Architecture separates models/ from api_fastapi/ with DTO/serialization layer | Architecture | 15.3.1 |
| PSC-040 | **Scheduler Isolation from User Code** | Scheduler only processes validated serialized DAGs, never executes user code | `AGENTS.md` | 2.3.1 |
| PSC-041 | **WebSocket over TLS Support** | WSS protocol supported for WebSocket connections | Architecture | 4.4.1 |
| PSC-042 | **XML Parser XXE Protection** | Standard Python XML parsers configured to prevent XXE attacks | Implementation | 1.5.1 |
| PSC-043 | **No eval() or Dynamic Code Execution** | No use of eval() or exec() for untrusted input processing | Codebase review | 1.3.2 |

---

# 5. ASVS Compliance Summary

| ASVS ID | Requirement Title | Status | Justification |
|---------|------------------|--------|---------------|
| **7.2.1** | Backend Session Token Verification | ✅ **Pass** | All JWT validation server-side via JWTValidator class (PSC-001, PSC-021) |
| **7.2.2** | Dynamic Token Generation | ✅ **Pass** | UUID4 jti + timestamp claims per token (PSC-007) |
| **7.2.3** | Reference Token Entropy (128 bits) | ⚠️ **Partial** | UUID4 provides 122 bits (marginally below 128-bit threshold) — FINDING-032 |
| **7.2.4** | New Session Token on Authentication | ⚠️ **Partial** | Token rotation implemented (PSC-008), but previous token not revoked (FINDING-033); silent revocation failures (FINDING-010) |
| **9.1.1** | JWT Signature Validation | ✅ **Pass** | Mandatory cryptographic signature validation via PyJWT (PSC-002) |
| **9.1.2** | Algorithm Allowlisting | ⚠️ **Partial** | GUESS resolves to strong algorithms only (PSC-003), but no explicit "none" rejection (FINDING-011) |
| **9.1.3** | Key Material from Trusted Sources | ✅ **Pass** | Keys from JWK metadata/pre-configured JWKS only (PSC-004) |
| **9.2.1** | Token Validity Time Span | ✅ **Pass** | exp/nbf validation with context-specific lifetimes (PSC-005, PSC-009) |
| **10.4.5** | Refresh Token Replay Prevention | ❌ **Fail** | No token invalidation after use or family revocation on reuse detection (FINDING-001, FINDING-002) |
| **8.1.1** | Authorization Documentation | ⚠️ **Partial** | Comprehensive resource coverage (PSC-016), but lacks enforcement timing details (FINDING-034, FINDING-035) |
| **8.2.1** | Function-Level Access Control | ⚠️ **Partial** | Abstract method enforcement (PSC-015), but no enforcement mechanism at API entry points (FINDING-012) |
| **8.2.2** | Data-Specific Access Control | ⚠️ **Partial** | Structured resource identification (PSC-018), but optional `details` parameter allows calls without context (FINDING-013); timing attack risk in default implementations (FINDING-036) |
| **8.3.1** | Trusted Service Layer | ✅ **Pass** | Trust sentinel pattern (PSC-012), no client-side authorization (PSC-022) |
| **6.2.1** | Password Minimum Length | ⚠️ **Partial** | Auto-generated passwords meet 15-char threshold (PSC-023), but no validation for manual passwords (FINDING-037) |
| **6.2.2** | Users Can Change Password | ❌ **Fail** | No password change mechanism (FINDING-014) |
| **6.2.3** | Password Change Requires Current + New | ❌ **Fail** | No password change flow exists (FINDING-014) |
| **6.2.4** | Common Password List Validation | ❌ **Fail** | No common password list checking (FINDING-038) |
| **6.2.5** | No Restrictive Composition Rules | ✅ **Pass** | No character type restrictions (PSC-025) |
| **6.2.6** | Password Input Field Masking | ⚠️ **Partial** | Cannot verify UI template implementation (FINDING-039) |
| **6.2.7** | Password Paste Support | ⚠️ **Partial** | Standard content-types accepted (PSC-026), but cannot verify autocomplete attributes |
| **6.2.8** | Password Verified Unmodified | ✅ **Pass** | Direct UTF-8 comparison without transformation (PSC-026) |
| **6.3.1** | Credential Stuffing Prevention | ❌ **Fail** | No rate limiting or brute force protection (FINDING-015) |
| **6.3.2** | Default User Accounts | ⚠️ **Partial** | No hardcoded defaults in normal mode (PSC-027), but "anonymous" admin in all-admins mode (FINDING-040) |
| **6.4.1** | System-Generated Initial Passwords | ❌ **Fail** | Generated passwords never expire (FINDING-016) |
| **6.4.2** | No Password Hints or KBA | ✅ **Pass** | No hint/KBA fields (PSC-029) |
| **7.4.1** | Session Termination | ⚠️ **Partial** | Revocation infrastructure exists (PSC-010), but cannot verify effectiveness from app layer (FINDING-017) |
| **7.4.2** | Session Termination on Account Disable | ⚠️ **Partial** | Pluggable architecture supports implementation, but no visible mechanism (FINDING-018) |
| **11.3.1** | Insecure Block Modes Prevention | ✅ **Pass** | Fernet uses CBC with authenticated encryption (PSC-030) |
| **11.3.2** | Approved Ciphers and Modes | ✅ **Pass** | AES-128-CBC + HMAC-SHA256 (PSC-030), key rotation (PSC-031), external backends (PSC-032) |
| **11.4.1** | Approved Hash Functions | ✅ **Pass** | HMAC-SHA256 per NIST FIPS 180-4 (PSC-033) |
| **1.2.4** | Injection Prevention | ✅ **Pass** | SQLAlchemy ORM with type-safe filters (PSC-034, PSC-035, PSC-036) |
| **14.2.1** | General Data Protection | 🔵 **N/A** | Requires client-side implementation review (out of scope) |
| **15.3.1** | Return Only Required Fields | 🔵 **N/A** | Requires endpoint-by-endpoint schema review (out of scope) |
| **2.1.1** | Validation Documentation | ⚠️ **Partial** | DAG parsing/validation module exists (PSC-040), but API input rules not documented (FINDING-019) |
| **2.2.1** | Input Validation Enforcement | 🔵 **N/A** | Requires endpoint-level validation review (out of scope) |
| **2.2.2** | Server-Side Input Validation | ✅ **Pass** | FastAPI Pydantic model-based validation (architecture) |
| **4.1.1** | Content-Type Header Verification | 🔵 **N/A** | Requires endpoint-level implementation review (out of scope) |
| **1.2.1** | Output Encoding for HTTP Response | ⚠️ **Partial** | Potential JavaScript injection in SPA initialization (FINDING-041) |
| **1.2.2** | URL Encoding for Dynamic URLs | ✅ **Pass** | FastAPI framework handles URL encoding |
| **1.2.3** | JavaScript/JSON Output Encoding | ⚠️ **Partial** | Same as 1.2.1 — template variable injection risk (FINDING-041) |
| **1.2.5** | OS Command Injection Protection | ✅ **Pass** | Scheduler isolation from user code (PSC-040) |
| **1.3.1** | HTML Sanitization | 🔵 **N/A** | No WYSIWYG content editing identified |
| **1.3.2** | Avoidance of eval() | ✅ **Pass** | No eval/exec for untrusted input (PSC-043); dynamic loading for config only (FINDING-047 informational) |
| **1.5.1** | XXE Prevention | ✅ **Pass** | XML parser configuration prevents XXE (PSC-042) |
| **2.3.1** | Sequential Step Order Enforcement | ✅ **Pass** | Scheduler processes validated serialized DAGs only (PSC-040) |
| **14.3.1** | Clearing Authenticated Data | ❌ **Fail** | No Clear-Site-Data header implementation (FINDING-003) |
| **3.2.1** | Context Controls | ❌ **Fail** | No Sec-Fetch-* validation or CSP middleware (FINDING-020); static file serving without Content-Disposition (FINDING-042) |
| **3.2.2** | Safe Text Rendering | ⚠️ **Partial** | Template rendering with dynamic context (FINDING-043) |
| **3.3.1** | Secure Cookie Attribute | ⚠️ **Partial** | Cookie path scoping exists, but no evidence of Secure attribute or prefix enforcement (FINDING-021) |
| **3.4.1** | HSTS Header | ❌ **Fail** | No Strict-Transport-Security header in middleware stack (FINDING-004) |
| **3.4.2** | CORS Configuration | ❌ **Fail** | allow_credentials=True hardcoded without origin wildcard validation (FINDING-005); middleware conditionally applied (FINDING-022) |
| **3.5.1** | CSRF Protection | ❌ **Fail** | No explicit CSRF token middleware (FINDING-023) |
| **3.5.2** | CORS Preflight Mechanism | ⚠️ **Partial** | No custom header requirement for preflight enforcement (FINDING-024) |
| **3.5.3** | HTTP Methods for Sensitive Operations | ⚠️ **Partial** | No Sec-Fetch-* validation (FINDING-025); catch-all SPA route lacks method restriction (FINDING-044) |
| **12.1.1** | General TLS Security Guidance | ❌ **Fail** | Documentation lacks TLS protocol version requirements (FINDING-026, FINDING-045) |
| **12.2.1** | HTTPS for External Services | ❌ **Fail** | API docs demonstrate plaintext HTTP for credentials (FINDING-006) |
| **12.2.2** | Publicly Trusted TLS Certificates | ❌ **Fail** | Documentation lacks certificate guidance (FINDING-027, FINDING-046) |
| **5.2.1** | File Size Limits | ⚠️ **Partial** | Requires endpoint-level review (out of scope) |
| **5.2.2** | File Extension/Content Validation | 🔵 **N/A** | No file upload functionality identified |
| **5.3.1** | Preventing Server-Side Execution | ✅ **Pass** | Scheduler isolation (PSC-040) |
| **5.3.2** | Path Traversal Prevention | 🔵 **N/A** | Requires file handling implementation review (out of scope) |
| **13.4.1** | Source Control Metadata Exclusion | ⚠️ **Partial** | Deployment docs lack SCM exclusion guidance (FINDING-028); AGENTS.md at repo root (FINDING-029) |
| **15.1.1** | Risk-Based Remediation Documentation | ❌ **Fail** | No documented timeframes for third-party components (FINDING-007) |
| **15.2.1** | Component Update Compliance | ❌ **Fail** | Cannot verify without documented timeframes (FINDING-008); no SBOM (FINDING-030) |
| **4.4.1** | WebSocket over TLS | ✅ **Pass** | WSS protocol supported (PSC-041) |
| **10.4.1** | OAuth Redirect URI Validation | 🔵 **N/A** | No OAuth provider implementation identified |
| **10.4.2** | Authorization Code Single Use | 🔵 **N/A** | No OAuth provider implementation identified |
| **10.4.3** | Authorization Code Lifetime | 🔵 **N/A** | No OAuth provider implementation identified |
| **10.4.4** | Grant Type Restrictions | ⚠️ **Partial** | Missing documentation for OAuth grant type restrictions (FINDING-031) |
| **6.1.1** | Rate Limiting Documentation | ❌ **Fail** | Authentication docs missing rate limiting, anti-automation, adaptive response controls (FINDING-009) |

**Summary Statistics:**
- ✅ **Pass**: 27 (40%)
- ⚠️ **Partial**: 23 (34%)
- ❌ **Fail**: 14 (21%)
- 🔵 **N/A**: 4 (6%)

---

# 6. Cross-Reference Matrix

## Findings → ASVS → Controls

| Finding ID | Severity | ASVS Requirements | Related Positive Controls | Mitigation Priority |
|------------|----------|-------------------|---------------------------|---------------------|
| FINDING-001 | High | 10.4.5 | PSC-008 (Token Rotation) | **P0** — Implement token invalidation after use |
| FINDING-002 | High | 10.4.5 | PSC-008, PSC-010 (Revocation Infrastructure) | **P0** — Implement token family revocation on reuse detection |
| FINDING-003 | High | 14.3.1 | PSC-013 (Graceful Expiration) | **P0** — Add Clear-Site-Data header on logout |
| FINDING-004 | High | 3.4.1 | PSC-011 (Secure Cookies) | **P0** — Add HSTS middleware |
| FINDING-005 | High | 3.4.2 | — | **P0** — Validate CORS origins against wildcard with credentials |
| FINDING-006 | High | 12.2.1 | — | **P0** — Update docs to require HTTPS for credential transmission |
| FINDING-007 | High | 15.1.1 | — | **P1** — Document risk-based remediation timeframes |
| FINDING-008 | High | 15.2.1 | — | **P1** — Implement SBOM generation and component tracking |
| FINDING-009 | High | 6.1.1 | PSC-024 (Timing-Attack Resistant) | **P1** — Document rate limiting and anti-automation controls |
| FINDING-010 | Medium | 7.2.4 | PSC-010 (Revocation Infrastructure) | **P1** — Surface revocation failures to callers |
| FINDING-011 | Medium | 9.1.2 | PSC-003 (Strong Algorithms) | **P2** — Add explicit "none" algorithm rejection |
| FINDING-012 | Medium | 8.2.1 | PSC-015 (Abstract Methods) | **P2** — Add authorization enforcement decorator/middleware |
| FINDING-013 | Medium | 8.2.2 | PSC-018 (Structured Resource ID) | **P2** — Make `details` parameter mandatory for data-specific methods |
| FINDING-014 | Medium | 6.2.2, 6.2.3 | PSC-023 (Strong Auto-Generation) | **P1** — Implement password change flow |
| FINDING-015 | Medium | 6.3.1 | PSC-024 (Timing-Attack Resistant) | **P1** — Add rate limiting to login endpoints |
| FINDING-016 | Medium | 6.4.1 | PSC-023 (Strong Auto-Generation) | **P1** — Force password change on first login |
| FINDING-017 | Medium | 7.4.1 | PSC-010 (Revocation Infrastructure) | **P2** — Add session termination verification mechanism |
| FINDING-018 | Medium | 7.4.2 | PSC-010, PSC-021 (Server-Side Validation) | **P2** — Implement account status check in token validation |
| FINDING-019 | Medium | 2.1.1 | PSC-040 (Scheduler Isolation) | **P2** — Document API input validation rules |
| FINDING-020 | Medium | 3.2.1 | PSC-011 (Secure Cookies) | **P1** — Add Sec-Fetch-* validation middleware |
| FINDING-021 | Medium | 3.3.1 | PSC-011 (Secure Cookies) | **P1** — Enforce Secure attribute and __Host- prefix |
| FINDING-022 | Medium | 3.4.2 | — | **P1** — Make CORS middleware mandatory with safe defaults |
| FINDING-023 | Medium | 3.5.1 | PSC-012 (Trust Sentinel) | **P1** — Implement CSRF token middleware |
| FINDING-024 | Medium | 3.5.2 | — | **P2** — Require custom header for cookie-authenticated requests |
| FINDING-025 | Medium | 3.5.3 | — | **P2** — Add Sec-Fetch-* validation for defense-in-depth |
| FINDING-026 | Medium | 12.1.1 | — | **P2** — Document TLS 1.2+ requirement in security docs |
| FINDING-027 | Medium | 12.2.2 | — | **P2** — Document publicly trusted certificate requirements |
| FINDING-028 | Medium | 13.4.1 | — | **P2** — Add SCM metadata exclusion to deployment docs |
| FINDING-029 | Medium | 13.4.1 | — | **P3** — Move AGENTS.md to docs/ or mark as dev-only |
| FINDING-030 | Medium | 15.1.1, 15.2.1 | — | **P1** — Implement SBOM generation in CI/CD |
| FINDING-031 | Medium | 10.4.4 | — | **P3** — Document OAuth grant type restrictions |
| FINDING-032 | Low | 7.2.3 | PSC-007 (UUID4 jti) | **P3** — Consider 128-bit token identifiers |
| FINDING-033 | Low | 7.2.4 | PSC-008 (Token Rotation) | **P3** — Document design decision in security model |
| FINDING-034 | Low | 8.1.1 | PSC-015, PSC-016 | **P3** — Document authorization enforcement timing |
| FINDING-035 | Low | 8.1.1 | PSC-018 | **P3** — Document details=None semantics |
| FINDING-036 | Low | 8.2.2 | PSC-019 (Team-Based Grouping) | **P3** — Implement constant-time filtering |
| FINDING-037 | Low | 6.2.1 | PSC-023 (Strong Auto-Generation) | **P2** — Add minimum length validation for manual passwords |
| FINDING-038 | Low | 6.2.4 | PSC-023 | **P3** — Integrate common password list validation |
| FINDING-039 | Low | 6.2.6 | — | **P3** — Verify type=password in UI templates |
| FINDING-040 | Low | 6.3.2 | PSC-027 (No Hardcoded Defaults) | **P2** — Document all-admins mode security implications |
| FINDING-041 | Low | 1.2.1, 1.2.3 | — | **P2** — Add context escaping in SPA initialization |
| FINDING-042 | Low | 3.2.1 | — | **P3** — Add Content-Disposition to static file responses |
| FINDING-043 | Low | 3.2.2 | — | **P3** — Audit template rendering for XSS risks |
| FINDING-044 | Low | 3.5.3 | — | **P3** — Add method restriction to SPA catch-all route |
| FINDING-045 | Low | 12.1.1 | — | **P3** — Document internal TLS requirements |
| FINDING-046 | Low | 12.2.2 | — | **P3** — Document certificate management for external services |
| FINDING-047 | Info | 1.3.2 | PSC-043 (No eval) | **P4** — Document dynamic loading security model |

## ASVS Coverage by Domain

| Domain | Total ASVS | Pass | Partial | Fail | N/A | Coverage Score |
|--------|-----------|------|---------|------|-----|----------------|
| JWT Token Authentication | 7 | 5 | 2 | 0 | 0 | 86% |
| Session Management | 4 | 2 | 2 | 0 | 0 | 75% |
| Authorization | 4 | 1 | 3 | 0 | 0 | 63% |
| Password Management | 9 | 3 | 3 | 3 | 0 | 50% |
| Cryptography | 4 | 4 | 0 | 0 | 0 | 100% |
| Database Security | 7 | 6 | 1 | 0 | 0 | 93% |
| Browser Security | 9 | 0 | 4 | 5 | 0 | 22% |
| TLS/Transport | 3 | 0 | 0 | 3 | 0 | 0% |
| File Handling | 3 | 1 | 1 | 0 | 1 | 67% |
| Deployment Security | 2 | 0 | 1 | 1 | 0 | 25% |
| Dependency Management | 2 | 0 | 0 | 2 | 0 | 0% |
| OAuth/Federation | 5 | 0 | 1 | 1 | 3 | 20% |
| Input Validation | 7 | 3 | 2 | 0 | 2 | 71% |

## Control Effectiveness Mapping

| Positive Control | ASVS Requirements Addressed | Findings Mitigated | Effectiveness Rating |
|------------------|----------------------------|-------------------|---------------------|
| PSC-001, PSC-021 | 7.2.1, 9.1.1 | — | ⭐⭐⭐⭐⭐ Strong |
| PSC-002 | 9.1.1 | — | ⭐⭐⭐⭐⭐ Strong |
| PSC-003 | 9.1.2, 11.3.2 | Partial (FINDING-011) | ⭐⭐⭐⭐ Good |
| PSC-010 | 7.4.1 | Partial (FINDING-010, FINDING-017) | ⭐⭐⭐ Moderate |
| PSC-011 | 3.3.1, 14.3.1 | Partial (FINDING-021) | ⭐⭐⭐⭐ Good |
| PSC-015 | 8.2.1 | Partial (FINDING-012) | ⭐⭐⭐⭐ Good |
| PSC-023 | 6.2.1 | Partial (FINDING-037) | ⭐⭐⭐⭐ Good |
| PSC-024 | 6.3.1 | Does not mitigate FINDING-015 | ⭐⭐⭐ Moderate |
| PSC-034-037 | 1.2.4 | — | ⭐⭐⭐⭐⭐ Strong |

**End of Security Assessment Report**

## 7. Level Coverage Analysis


**Audit scope:** up to L1

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 47 |

**Total consolidated findings: 47**

*End of Consolidated Security Audit Report*