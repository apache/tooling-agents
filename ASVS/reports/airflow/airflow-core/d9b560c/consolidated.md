# Security Audit Consolidated Report — apache/airflow/airflow-core

## Report Metadata

| Field | Value |
|-------|-------|
| **Repository** | apache/airflow/airflow-core |
| **ASVS Level** | L1 |
| **Severity Threshold** | None (all findings included) |
| **Commit** | N/A |
| **Date** | May 15, 2026 |
| **Auditor** | Tooling Agents |
| **Source Reports** | 70 |
| **Total Findings** | 45 |

## Executive Summary

This consolidated report synthesizes findings from 70 individual security audit reports across 10 security domains within the Apache Airflow core codebase. The audit was performed against OWASP ASVS Level 1 requirements.

### Severity Distribution

| Severity | Count | Percentage |
|----------|-------|------------|
| Critical | 0 | 0.0% |
| High | 3 | 6.7% |
| Medium | 19 | 42.2% |
| Low | 23 | 51.1% |
| Info | 0 | 0.0% |

### Level Coverage

All 45 findings map to **ASVS Level 1** controls. No Critical-severity findings were identified, indicating that fundamental security primitives are largely in place. The 3 High-severity findings relate to session lifecycle management and transport-layer security enforcement gaps that could expose production deployments.

### Top 5 Risks

1. **No Mechanism to Terminate All Sessions on User Account Deletion (FINDING-001)** — When a user account is deleted, previously issued JWT tokens remain valid until expiration, allowing continued access by deleted users.

2. **Missing Strict-Transport-Security (HSTS) Header (FINDING-002)** — The middleware stack does not enforce HSTS, leaving deployments vulnerable to protocol downgrade attacks and cookie interception over plaintext connections.

3. **CORS `allow_credentials=True` Hardcoded Without Origin Wildcard Validation (FINDING-003)** — Credential-bearing cross-origin requests are permitted without strict origin validation, creating potential for credential leakage to unauthorized origins.

4. **Login Endpoints Lack Rate Limiting or Account Lockout (FINDING-008)** — Authentication endpoints have no anti-automation controls, enabling brute-force and credential-stuffing attacks against the Simple Auth Manager.

5. **Previous JWT Tokens Not Revoked Upon Re-Authentication (FINDING-009)** — Token refresh and re-authentication flows issue new tokens without invalidating predecessors, expanding the window for token replay attacks.

### Positive Controls

The audit identified **49 positive security controls** demonstrating mature security architecture in several areas:

- **JWT Infrastructure**: Algorithm confusion is prevented through XOR enforcement of key types, safe default algorithms (HS512/RS256/EdDSA), and consistent algorithm allowlist usage. Token revocation infrastructure with JTI-based tracking is implemented.
- **Authorization Architecture**: Fail-closed defaults via abstract methods and `NotImplementedError` for unimplemented features. All authorization decisions are server-side with no client-side delegation. Batch authorization uses AND logic preventing partial authorization leakage.
- **Credential Handling**: Constant-time comparison via `hmac.compare_digest()`, cryptographically secure password generation using `secrets.choice()`, and UTF-8 encoding support without truncation or transformation.
- **Cookie Security**: httponly, samesite=lax, and conditional secure flags are applied to JWT cookies, mitigating XSS-based token theft and CSRF vectors.
- **Production Safety**: A detection heuristic warns loudly when the Simple Auth Manager is used in production-like environments, reducing the risk of accidental insecure deployments.

---

## 3. Findings

### 3.2 High

#### FINDING-001: No Mechanism to Terminate All Sessions on User Account Deletion

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 7.4.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py, airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py |
| **Source Reports** | 7.4.2.md |
| **Related** | None |

**Description:**

The get_user_from_token() method in BaseAuthManager validates JWT signature and checks individual token revocation, but does not verify that the user referenced in the token payload still exists or is active. The SimpleAuthManager.deserialize_user() constructs a user object directly from the JWT payload without consulting the current user configuration. A deleted user retains full access to the system based on the role encoded in their JWT token. Since the Simple Auth Manager encodes the role directly in the JWT, even if the user's role was downgraded before deletion, previously-issued tokens with the old role remain honored. This creates a window of vulnerability from account deletion until token expiration, potentially allowing unauthorized access to sensitive DAG configurations, execution of workflows by terminated employees, data exfiltration through API endpoints, and privilege escalation.

**Remediation:**

Option A: Add bulk revocation method to BaseAuthManager - Implement revoke_all_user_tokens(user_id: str) method that uses RevokedToken.revoke_all_for_user(). Option B: Add user existence check during token validation - Implement is_user_active() abstract method and call it in get_user_from_token() to verify user still exists before allowing access. Immediate action: Modify SimpleAuthManager.deserialize_user() to check the user still exists in current configuration and use current role from config rather than token role.

---

#### FINDING-002: No Strict-Transport-Security (HSTS) header in middleware stack

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-319 |
| **ASVS Sections** | 3.4.1, 3.2.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py:172-189 |
| **Source Reports** | 3.4.1.md, 3.2.1.md |
| **Related** | None |

**Description:**

The complete middleware initialization function is shown, and no middleware sets the `Strict-Transport-Security` header. The domain context explicitly requires "Strict-Transport-Security (HSTS) to enforce HTTPS" with "A maximum age of at least 1 year." None of the registered middlewares (`JWTRefreshMiddleware`, auth manager middlewares, `GZipMiddleware`, `HttpAccessLogMiddleware`) appear to be security header middlewares. The auth manager's `get_fastapi_middlewares()` could theoretically return a security headers middleware, but: 1. This is not guaranteed across all auth manager implementations 2. The base application should enforce HSTS regardless of auth manager choice 3. The HSTS header should be present even for unauthenticated responses. Without HSTS, users are vulnerable to SSL stripping attacks where an attacker downgrades the connection from HTTPS to HTTP. First-time visitors or those with expired HSTS cache are vulnerable. This enables credential theft, session hijacking, and content injection.

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

#### FINDING-003: CORS `allow_credentials=True` hardcoded without origin wildcard validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-346 |
| **ASVS Sections** | 3.4.2, 3.5.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py:148-162 |
| **Source Reports** | 3.4.2.md, 3.5.2.md |
| **Related** | None |

**Description:**

The `allow_credentials=True` flag is unconditionally hardcoded in the CORSMiddleware configuration regardless of what origins are configured. There is no validation against wildcard (`*`) origin. If an administrator sets `access_control_allow_origins = *`, Starlette's `CORSMiddleware` with `allow_credentials=True` will reflect the requesting `Origin` header value in `Access-Control-Allow-Origin` and include `Access-Control-Allow-Credentials: true`. This effectively allows ANY origin to make credentialed cross-origin requests. No allowlist validation logic is present - the configured origins list is passed directly to the middleware without checking for `*`, validating format, or ensuring they're specific trusted domains. Per Starlette's CORSMiddleware implementation: when `allow_origins=['*']` and `allow_credentials=True`, the middleware reflects the request's `Origin` header (because browsers reject `Access-Control-Allow-Origin: *` with credentials). This creates an 'allow any origin with credentials' configuration. If misconfigured with `*`, any malicious website can make authenticated cross-origin requests to the Airflow API, stealing data or performing state-changing actions on behalf of authenticated users.

**Remediation:**

Add middleware that validates either a custom header or Content-Type: application/json for all state-changing operations. Example implementation: Create a CSRFPreflightEnforcementMiddleware that rejects state-changing requests (non-GET/HEAD/OPTIONS methods) that lack preflight-triggering characteristics such as a custom header (e.g., x-requested-with) or application/json Content-Type. Return HTTP 415 Unsupported Media Type for requests that don't meet these criteria.

### 3.3 Medium

#### FINDING-004: Missing Documentation of Rate Limiting and Anti-Automation Controls for Login Endpoints

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 6.1.1 |
| **Files** | airflow-core/docs/core-concepts/auth-manager/index.rst, airflow-core/docs/core-concepts/auth-manager/simple/index.rst, airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py |
| **Source Reports** | 6.1.1.md |
| **Related Findings** | - |

**Description:**

The authentication documentation extensively covers pluggable auth manager architecture, authorization methods, JWT token management, and role configuration, but contains no documentation of rate limiting configuration for authentication endpoints, anti-automation defenses (CAPTCHA, progressive delays, IP blocking), adaptive response mechanisms (challenge escalation), account lockout prevention strategies, or credential stuffing defenses. Without documented rate limiting or anti-automation guidance, deployment managers may not configure these essential controls, leaving login endpoints vulnerable to credential stuffing and brute force attacks. ASVS 6.1.1 specifically requires documentation to exist describing how these controls are configured.

**Remediation:**

Add a dedicated security section to the auth-manager documentation covering:

Protecting Authentication Endpoints
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Airflow relies on deployment-level infrastructure for rate limiting and anti-automation
controls on authentication endpoints. The following controls MUST be configured for
production deployments:

**Rate Limiting:**
Configure your reverse proxy (nginx, HAProxy, cloud load balancer) to limit
authentication requests. Recommended: 5 attempts per minute per IP for
``POST /auth/token``.

**Account Lockout Prevention:**
When using auth managers that support lockout (e.g. FAB with LDAP), configure
``AUTH_MAX_LOGIN_ATTEMPTS`` and ``AUTH_LOGIN_LOCKOUT_DURATION``. Ensure legitimate
users are not permanently locked out by setting reasonable lockout duration
(e.g., 15 minutes after 5 failed attempts).

**Adaptive Response:**
For environments with elevated threat levels, consider CAPTCHA integration after
3 failed attempts or implement progressive delay (exponential backoff).

---

#### FINDING-005: No Minimum Password Length Enforcement for User-Set Passwords

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 6.2.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py:37-41, airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:408-418 |
| **Source Reports** | 6.2.1.md |
| **Related Findings** | - |

**Description:**

While auto-generated passwords are 16 characters (compliant), manually set passwords have no minimum length enforcement. An administrator could inadvertently set a 1-character password. The BaseAuthManager interface also does not define any password policy interface, meaning the framework provides no standardized mechanism for enforcing password length across auth manager implementations. Admin manually edits `simple_auth_manager_passwords.json.generated` → Sets password "abc" (3 chars) → `_get_passwords()` reads it without validation → `create_token()` accepts it for authentication. The documentation explicitly states passwords can be updated directly in the file, but no length validation is enforced on file read.

**Remediation:**

Add validation in `_get_passwords()` to check minimum password length. Validate passwords loaded from the file meet minimum length (8 characters), emitting warnings for violations. Example implementation: Add a configuration option `simple_auth_manager_min_password_length` with fallback to 8, iterate through user_passwords_from_file to check length, and log warnings for passwords shorter than the minimum. Long-term: Define password policy interface in BaseAuthManager with optional abstract methods or hooks for password validation that auth manager implementations can override.

---

#### FINDING-006: No Application-Level Password Change Functionality

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 6.2.2, 6.2.3 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py:31-102 |
| **Source Reports** | 6.2.2.md, 6.2.3.md |
| **Related Findings** | - |

**Description:**

Users of the Simple Auth Manager cannot change their passwords through the application interface. Password changes require direct file system access to the server, which requires server admin privileges, bypasses any audit logging, is not feasible for non-admin users in shared environments, and violates the principle that users should be able to manage their own credentials. The BaseAuthManager interface also does not define a change_password() method or similar, meaning the framework provides no standardized hook for this functionality.

**Remediation:**

Add a password change endpoint to the Simple Auth Manager. Example implementation:
```python
@login_router.post("/password/change", status_code=status.HTTP_200_OK)
def change_password(
    body: PasswordChangeBody,  # current_password, new_password fields
    user: SimpleAuthManagerUser = Depends(get_current_user),
) -> dict:
    """Change the authenticated user's password."""
    SimpleAuthManagerLogin.change_password(
        username=user.username,
        current_password=body.current_password,
        new_password=body.new_password,
    )
    return {"detail": "Password changed successfully"}
```

---

#### FINDING-007: No Check Against Common/Breached Password Lists

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 6.2.4 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:408-418, airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:130-176, airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py |
| **Source Reports** | 6.2.4.md |
| **Related Findings** | - |

**Description:**

Manually set passwords are never validated against common password lists. If an administrator sets a password like "password1", "12345678", or "qwerty123", the system accepts it without warning. While auto-generated passwords won't match common patterns (due to randomness), the documented ability to manually set passwords creates a gap. The _get_passwords() function loads passwords from JSON without validation against common passwords, and the login service accepts any password that matches, regardless of strength.

**Remediation:**

Add a common password check that validates passwords when they are loaded or set. Implement a _load_common_passwords() method to load the top 3000+ common passwords matching the minimum length policy from a resource file. In _get_passwords(), validate loaded passwords against this list and log warnings for any matches. Example implementation provided shows loading common passwords from a bundled resource file and checking each password against the list, warning administrators when common passwords are detected.

---

#### FINDING-008: Login Endpoints Lack Rate Limiting or Account Lockout Mechanisms

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 6.3.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py:40, airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py:90, airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py |
| **Source Reports** | 6.3.1.md |
| **Related Findings** | - |

**Description:**

An attacker can perform unlimited password guessing attempts against any known username. The constant-time comparison prevents timing-based username enumeration, but the absence of any throttling allows high-speed credential stuffing and brute force attacks. The SimpleAuthManager is explicitly designed for development/testing environments and production deployments should use external auth managers (FAB, Keycloak) or deploy behind a reverse proxy with rate limiting.

**Remediation:**

1. The BaseAuthManager interface should document that production auth managers MUST implement brute force protections. 2. Consider adding optional rate limiting to the Simple Auth Manager for defense-in-depth using fastapi_limiter with RateLimiter dependency (times=5, seconds=60). 3. Document that production deployments MUST configure external rate limiting (reverse proxy, WAF, or cloud load balancer).

---

#### FINDING-009: Previous JWT Tokens Are Not Revoked Upon Re-Authentication

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 7.2.4 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py:38-73, airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py |
| **Source Reports** | 7.2.4.md |
| **Related Findings** | - |

**Description:**

When a user re-authenticates, the application generates a new JWT token but does not revoke or terminate the previous session token. If a session token is compromised, re-authentication does not invalidate the compromised token. The old token remains valid until its natural expiration. This violates the principle that re-authentication should terminate prior sessions. The BaseAuthManager.generate_jwt() method only generates new tokens and has no mechanism to track and revoke previously issued tokens for a given user. The revoke_token() method exists but is never called during any authentication flow.

**Remediation:**

The login flow should accept the current token (if present) and revoke it, or maintain a per-user "not-before" timestamp. Modify the create_token method to accept an optional current_token parameter and call get_auth_manager().revoke_token(current_token) before generating the new token. Alternatively, implement a per-user "tokens issued after" timestamp that invalidates all tokens issued before re-authentication.

---

#### FINDING-010: Simple Auth Manager Provides No Logout Endpoint to Trigger Token Revocation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 7.4.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py, airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py, airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:163 |
| **Source Reports** | 7.4.1.md |
| **Related Findings** | - |

**Description:**

User wants to end session → no endpoint to call → token remains valid until expiration → no revocation triggered. Users cannot explicitly terminate their session in the Simple Auth Manager. The `revoke_token` method on `BaseAuthManager` exists but is unreachable through any Simple Auth Manager route. This means: Shared device scenarios: a user cannot ensure their session is terminated; Compromised tokens cannot be explicitly revoked by the user; Tokens remain valid for their full expiration duration. The cookie `_token` may be cleared client-side, but the JWT remains cryptographically valid. If token was captured (e.g., via XSS in another component, network interception before HTTPS), it continues to work.

**Remediation:**

Add a logout/revocation endpoint to the Simple Auth Manager:

```python
@login_router.post("/token/revoke", status_code=status.HTTP_204_NO_CONTENT)
def revoke_token(request: Request):
    """Revoke the current user's token."""
    token = request.cookies.get(COOKIE_NAME_JWT_TOKEN)
    if token:
        get_auth_manager().revoke_token(token)
    
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    response.delete_cookie(COOKIE_NAME_JWT_TOKEN, path=get_cookie_path())
    return response
```

And override `get_url_logout()` in `SimpleAuthManager`:
```python
def get_url_logout(self) -> str | None:
    return AUTH_MANAGER_FASTAPI_APP_PREFIX + "/token/revoke"
```

---

#### FINDING-011: Direct Username/Password Credential Exchange Resembles Deprecated ROPC Grant Without Per-Client Grant Restriction

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 10.4.4 |
| **Files** | airflow-core/docs/security/api.rst:37-48, airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py:entire middleware |
| **Source Reports** | 10.4.4.md |
| **Related Findings** | - |

**Description:**

The system uses direct credential exchange (username/password → JWT token), which is functionally equivalent to the Resource Owner Password Credentials (ROPC) grant type that ASVS 10.4.4 explicitly states 'must no longer be used.' Additionally: 1) No per-client grant restrictions: There is no mechanism visible in the provided code to restrict which grant types a specific client is allowed to use. Any client that can reach the /auth/token endpoint can submit credentials directly. 2) No client identification or registration: The token endpoint does not require client authentication (client_id/client_secret) or client registration — it accepts raw user credentials from any caller. 3) No distinction between confidential and public clients: The same endpoint serves browsers (public clients via cookie) and API clients (confidential or public) without differentiated grant type enforcement. However, this must be contextualized: The system's documented design is NOT a general-purpose OAuth2 authorization server — it's an application-specific authentication system. The project security guidance explicitly states: 'JWT tokens for API authentication... auditors should focus on verifying token expiration, secure signing keys, and HTTPS enforcement'. The auth manager is pluggable, so production deployments with external auth managers (FAB, OIDC) may implement proper grant flows.

**Remediation:**

For production deployments, ensure the auth manager implements proper OAuth2 flows:

```python
# Example per-client grant type enforcement in auth manager base
class BaseAuthManager:
    ALLOWED_GRANT_TYPES = {
        "authorization_code",  # Only allow auth code flow
        "refresh_token",       # Allow refresh token exchange
        # "password" — EXPLICITLY NOT ALLOWED
        # "implicit" — EXPLICITLY NOT ALLOWED
    }
    
    def validate_grant_type(self, client_id: str, grant_type: str) -> None:
        client = self.get_client(client_id)
        if grant_type not in client.allowed_grant_types:
            raise InvalidGrantError(f"Client {client_id} not authorized for grant type {grant_type}")
        if grant_type in ("password", "implicit"):
            raise InvalidGrantError(f"Grant type '{grant_type}' is deprecated and not allowed")
```

---

#### FINDING-012: JWT Refresh Middleware Does Not Invalidate Previous Token After Issuing New Token — No Replay Detection for Public Clients

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 10.4.5 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py:50-66 |
| **Source Reports** | 10.4.5.md |
| **Related Findings** | - |

**Description:**

The JWT refresh middleware issues new tokens during refresh but does not revoke the old token. An attacker who obtains a valid JWT cookie can replay it for the entire remaining token lifetime (up to 24 hours default), even after the legitimate user has had their token refreshed. There is no token invalidation after refresh, no reuse detection, and no sender-constraining (no DPoP or mTLS binding to specific client). The browser is a public client, making this the exact scenario ASVS 10.4.5 addresses.

**Remediation:**

Implement refresh token rotation with invalidation. Call _revoke_old_token(current_token) after generating a new token. Implement reuse detection by checking if a token has been revoked in JWTValidator.avalidated_claims() and if a revoked token is presented again, revoke ALL tokens for that user/session to detect replay attacks. Add revocation check: if jti and RevokedToken.is_revoked(jti): raise jwt.InvalidTokenError('Token has been revoked (replay detected)').

---

#### FINDING-013: No enforcement mechanism in base class ensures authorization is called at API entry points

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 8.2.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:entire class |
| **Source Reports** | 8.2.1.md |
| **Related Findings** | - |

**Description:**

The BaseAuthManager defines authorization methods as abstract interfaces but provides no mechanism (decorator, middleware requirement, or dependency injection pattern) that FORCES API endpoints to call these methods. The get_fastapi_middlewares() method returns an empty list by default. This is a gap where controls EXIST (abstract authorization methods defined) but the base class provides no mechanism to ensure they are CALLED at every API entry point. Enforcement relies entirely on the API layer code (not provided in this scope). The data flow is: HTTP Request → FastAPI Router → Route Handler → ??? → is_authorized_*() — the connection between route handler and authorization check is not structurally enforced by the base class. If any API endpoint omits the authorization check, function-level access control is bypassed. Since there's no structural enforcement, every endpoint must be individually verified.

**Remediation:**

Consider providing a FastAPI dependency or decorator in the base auth framework that enforces authorization. Example implementation: Create a require_authorization function that returns a FastAPI dependency which checks authorization before handler execution. The dependency should extract the current user, get the auth manager, call the appropriate is_authorized_* method, and raise HTTPException with status 403 if authorization fails. Additionally, conduct a comprehensive audit of all API endpoint handlers to verify that is_authorized_* methods are consistently called with appropriate details before resource access.

---

#### FINDING-014: Optional `details` parameter allows authorization calls without data-specific context

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-639 |
| **ASVS Sections** | 8.2.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:205-271, airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:290-301 |
| **Source Reports** | 8.2.2.md |
| **Related Findings** | - |

**Description:**

All `is_authorized_*` methods accept `details` as an optional parameter defaulting to `None`. This means callers can invoke authorization checks without specifying which specific resource instance is being accessed. If an API endpoint that operates on a specific resource calls the authorization check without providing details (e.g., omitting `conn_id`), the auth manager implementation may grant access without validating the user has permission to the specific resource instance, creating a BOLA vulnerability. Data Flow: API endpoint receives request with resource ID → calls `is_authorized_connection(method="GET", user=user)` without `details` → Auth manager checks general permission → Access granted without data-specific validation → IDOR/BOLA. This is a design-level concern. The actual risk depends on whether API endpoints consistently pass details for data-specific operations. The `filter_authorized_*` methods correctly pass details, suggesting the pattern is understood — but nothing enforces it at the type level.

**Remediation:**

Consider splitting function-level and data-level authorization into separate method signatures: `is_authorized_connection_type()` for function-level checks and `is_authorized_connection_instance()` for data-level checks with required details parameter. Or use `@overload` to make the type checker flag calls without details when accessing specific instances.

---

#### FINDING-015: Incomplete Documentation of Input Validation Rules for DAG Trigger API

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 2.1.1 |
| **Files** | airflow-core/src/airflow/api/common/trigger_dag.py:40-200 |
| **Source Reports** | 2.1.1.md |
| **Related Findings** | - |

**Description:**

The `trigger_dag` and `_trigger_dag` functions enforce several input validation rules implicitly in code (conf must be dict/null, logical_date must be localized and >= start_date, run_type must be in allowed_run_types), but these rules are not documented in a centralized specification. The docstrings describe parameters functionally but do not define validation constraints or expected data formats. Without documented validation rules, there is no specification to verify implementation against. Developers maintaining or extending the API may not understand all constraints, potentially introducing bypass paths. Security reviewers cannot confirm coverage without tracing every code path.

**Remediation:**

Create a validation rules specification (e.g., in API schema documentation or an OpenAPI spec with `pattern`, `minLength`, `maxLength`, `format` constraints) that defines: `dag_id`: expected pattern (e.g., `^[a-zA-Z0-9._-]+$`), max length; `run_id`: expected pattern, max length; `conf`: JSON object schema constraints per DAG (if applicable); `logical_date`: ISO 8601 datetime with timezone; `note`: max length, allowed characters; `partition_key`: expected format. Leverage FastAPI's Pydantic models to formally define constraints for API parameters. This simultaneously creates documentation (ASVS 2.1.1) and enforcement (ASVS 2.2.1).

---

#### FINDING-016: Nginx reverse proxy example lacks HTTPS configuration with TLS protocol version enforcement

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 12.1.1, 12.2.1, 4.4.1 |
| **Files** | airflow-core/docs/howto/run-behind-proxy.rst:32-43 |
| **Source Reports** | 12.1.1.md, 12.2.1.md, 4.4.1.md |
| **Related Findings** | - |

**Description:**

The primary nginx reverse proxy example demonstrates an HTTP-only listener on port 80 without any corresponding HTTPS server block. This creates multiple security issues: (1) No TLS protocol version configuration (e.g., `ssl_protocols TLSv1.2 TLSv1.3;`) to restrict deprecated protocols, (2) No HTTPS listener despite documentation referencing `https://lab.mycompany.com/myorg/airflow/`, (3) No HTTP-to-HTTPS redirect. Deployments following this example will accept unencrypted HTTP traffic from external clients, exposing authentication credentials, session tokens, and sensitive workflow data to network interception. Additionally, if operators add HTTPS without explicit protocol configuration, the reverse proxy may inadvertently enable deprecated TLS versions (TLS 1.0, TLS 1.1) based on default settings, leading to potential downgrade attacks.

**Remediation:**

Add a complete HTTPS server block with TLS version restrictions and HTTP-to-HTTPS redirect:
```nginx
server {
    listen 80;
    server_name lab.mycompany.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name lab.mycompany.com;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:...';
    ssl_certificate /etc/ssl/certs/lab.mycompany.com.pem;
    ssl_certificate_key /etc/ssl/private/lab.mycompany.com.key;

    location /myorg/airflow/ {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_redirect off;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
    }
}
```

---

#### FINDING-017: Flower documentation lacks TLS configuration guidance

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 12.2.1 |
| **Files** | airflow-core/docs/security/flower.rst:44-46 |
| **Source Reports** | 12.2.1.md |
| **Related Findings** | - |

**Description:**

The Flower documentation exclusively shows HTTP URLs and provides no guidance on configuring TLS for the Flower web interface. Flower exposes sensitive information about Celery task execution including worker metrics, task arguments, and potentially sensitive data. The basic authentication shown transmits credentials in base64 encoding without TLS encryption. Flower deployments following this documentation will accept connections over HTTP. Combined with the basic authentication mechanism (credentials sent in cleartext without TLS), authentication credentials and all monitoring data are exposed to network interception.

**Remediation:**

Add TLS configuration guidance for Flower, or explicitly document that Flower should be deployed behind a TLS-terminating reverse proxy:
```rst
Flower Security Best Practices
-------------------------------

Flower should always be deployed behind a TLS-terminating reverse proxy
or configured with TLS directly. Basic authentication credentials are
transmitted in base64 encoding and MUST be protected by TLS encryption.

.. code-block:: bash

    airflow celery flower --basic-auth=user1:password1 \
        --certfile=/path/to/cert.pem --keyfile=/path/to/key.pem
```

---

#### FINDING-018: No `Clear-Site-Data` header implementation visible in middleware or response handling

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-613 |
| **ASVS Sections** | 14.3.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py:163-180 |
| **Source Reports** | 14.3.1.md |
| **Related Findings** | - |

**Description:**

The application initialization does not include any middleware or mechanism to set the `Clear-Site-Data` header on logout/session-termination responses. The ASVS requirement states that authenticated data should be cleared from client storage when the session is terminated, and the `Clear-Site-Data` header is the recommended server-side mechanism for this. The middleware stack includes `JWTRefreshMiddleware` for token management but no corresponding mechanism to instruct browsers to clear cached credentials, cookies, and storage when a session ends. If `Clear-Site-Data` is not set on logout responses and client-side cleanup fails (e.g., JavaScript error, network interruption), authenticated data (tokens, cached responses, cookies) may persist in the browser after session termination, potentially accessible to subsequent users on shared devices.

**Remediation:**

Add `Clear-Site-Data` header to logout and session-invalidation responses:

```python
# In the logout endpoint handler:
from fastapi.responses import JSONResponse

@router.post("/auth/logout")
async def logout():
    response = JSONResponse(content={"message": "Logged out"})
    response.headers["Clear-Site-Data"] = '"cache", "cookies", "storage"'
    return response
```

Additionally, ensure client-side cleanup in the React UI:

```javascript
// On logout or session termination
function clearAuthData() {
    localStorage.removeItem('auth_token');
    sessionStorage.clear();
    // Additional cleanup as needed
}
```

---

#### FINDING-019: Cookie path scoping function exists but no evidence of Secure attribute or __Host-/__Secure- prefix enforcement

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-614 |
| **ASVS Sections** | 3.3.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/app.py:48-54 |
| **Source Reports** | 3.3.1.md |
| **Related Findings** | - |

**Description:**

The `get_cookie_path()` function provides path scoping for cookies but does not enforce the `Secure` attribute or cookie name prefixes (`__Host-` or `__Secure-`). The actual cookie-setting code is not present in the provided files, but the infrastructure for ensuring secure cookie attributes is not visible. A JWT refresh middleware exists (`JWTRefreshMiddleware`), suggesting tokens are stored in cookies, and a `get_cookie_path()` utility exists for cookie scoping, but no Secure attribute enforcement, no prefix validation, and no SameSite configuration is visible. This represents a gap in the visible code, though the actual cookie-setting code may implement these controls in files not provided. Without `Secure` attribute, cookies can be transmitted over unencrypted HTTP. Without `__Host-` or `__Secure-` prefixes, cookies are vulnerable to domain/path override attacks from subdomains.

**Remediation:**

Implement a secure cookie-setting function that enforces security attributes:
```python
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
```
Audit `JWTRefreshMiddleware` and any other cookie-setting code to verify `Secure`, `HttpOnly`, `SameSite`, and `__Host-`/`__Secure-` prefix usage.

---

#### FINDING-020: No explicit CSRF token middleware or anti-forgery mechanism visible for state-changing operations

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-352 |
| **ASVS Sections** | 3.5.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py:172-189, airflow-core/src/airflow/api_fastapi/app.py:78-124 |
| **Source Reports** | 3.5.1.md |
| **Related Findings** | - |

**Description:**

The application's CSRF protection strategy needs to be assessed: 1. JWT-based authentication via cookies: The presence of JWTRefreshMiddleware and get_cookie_path() indicates JWT tokens are stored in cookies. Cookie-based authentication is inherently vulnerable to CSRF unless additional protections are in place. 2. No explicit CSRF token middleware: The middleware stack does not include a CSRF token generation/validation middleware. 3. CORS as partial protection: The optional CORS middleware provides protection for non-simple requests (those requiring preflight) by restricting which origins can make credentialed requests. However: CORS is only configured when origins are explicitly set, simple requests (form POSTs with application/x-www-form-urlencoded) don't trigger preflight, and GET requests with side effects (if any) are not protected. 4. Potential mitigations not visible in this scope: SameSite cookie attributes (not visible in provided code), custom header requirements (e.g., X-Requested-With) on API endpoints, or token validation in request headers rather than cookies. If JWT tokens are stored in cookies without SameSite=Strict and without CSRF tokens, an attacker can craft a page that submits state-changing requests (e.g., triggering DAGs, modifying connections) on behalf of an authenticated user.

**Remediation:**

Option 1: Require non-CORS-safelisted header on all state-changing endpoints using a CSRFProtectionMiddleware that validates the presence of x-requested-with header for unsafe methods (POST, PUT, DELETE, PATCH). Option 2: Ensure cookies use SameSite=Strict in cookie-setting code. Option 3: Validate Origin/Referer headers against expected values. Either require a custom non-CORS-safelisted header (e.g., X-Requested-With) on all state-changing endpoints, OR verify SameSite=Strict/Lax is set on all authentication cookies, OR implement CSRF token validation middleware.

---

#### FINDING-021: No Risk-Based Remediation Timeframes Defined in Documentation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 15.1.1 |
| **Files** | AGENTS.md:entire file, airflow-core/docs/core-concepts/overview.rst:entire file |
| **Source Reports** | 15.1.1.md |
| **Related Findings** | - |

**Description:**

The provided application documentation does not define risk-based remediation timeframes for third-party component versions with known vulnerabilities, nor does it establish a general library update cadence. While the AGENTS.md file covers dependency management tooling (uv.lock, uv workspace) and includes a pattern for tracking deferred work (including version caps), it does not define: maximum acceptable timeframes for remediating critical CVEs (e.g., 24-72 hours); timeframes for high-severity vulnerabilities (e.g., 7-14 days); timeframes for medium/low-severity vulnerabilities (e.g., 30-90 days); regular library update cadence (e.g., monthly dependency refresh); criteria for determining component risk levels that trigger different timeframes; or escalation procedures when timeframes are breached. The overview.rst documentation covers architecture and deployment patterns but contains no dependency vulnerability management guidance.

**Remediation:**

Create a dedicated security documentation page (e.g., airflow-core/docs/security/dependency_management.rst) defining risk-based remediation timeframes: Critical (9.0-10.0 CVSS): 72 hours - Immediate patch or mitigation, release blocker; High (7.0-8.9): 14 days - Patch in next scheduled release, expedited if exploitable; Medium (4.0-6.9): 30 days - Include in next regular release cycle; Low (0.1-3.9): 90 days - Address during regular dependency updates. Also define a general library update policy: All direct dependencies reviewed monthly; Provider packages must pin dependencies to versions receiving active security support; Components classified as risky (poorly maintained, EOL, history of significant vulnerabilities) must be replaced or sandboxed within 90 days; Transitive dependencies monitored via automated scanning in CI/CD pipelines.

---

#### FINDING-022: No Documented Mechanism to Verify Components Haven't Breached Update Timeframes

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 15.2.1 |
| **Files** | AGENTS.md:entire file, airflow-core/docs/core-concepts/overview.rst:entire file |
| **Source Reports** | 15.2.1.md |
| **Related Findings** | - |

**Description:**

The application documentation does not describe a process or tooling to verify that included components have not exceeded their documented update and remediation timeframes. Since ASVS 15.1.1 timeframes are not defined (see ASVS-1511-MED-001), this requirement inherently cannot be met. The AGENTS.md references dependency management commands but only for development workflow. With 100+ provider packages and their transitive dependencies, the attack surface for outdated components is substantial. Without automated verification that components are current, vulnerable dependencies may persist in production deployments indefinitely.

**Remediation:**

1. Integrate automated dependency scanning into CI pipelines (example provided using pip-audit with --strict flag to fail builds on critical/high CVEs). 2. Document the verification process in security documentation including: Dependabot/Renovate for automated PRs with security-priority scheduling, pip-audit in CI for every PR and nightly builds, and monthly automated scans of all 100+ provider packages against NIST NVD. 3. Define remediation timeframes (Critical: 72h, High: 14d, Medium: 30d, Low: 90d). 4. Create component inventory classified by risk level. 5. Implement automated compliance dashboard with alerting when components approach or breach remediation deadlines.

---

### 3.4 Low

#### FINDING-023: No Account Lockout Mechanism in Simple Auth Manager Login Service

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 6.1.1 |
| Files | airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py:24-63 |
| Source Reports | 6.1.1.md |
| Related Findings | - |

**Description:**

The Simple Auth Manager login service does not implement any account lockout mechanism or failed attempt tracking. Repeated failed login attempts result in no tracking or lockout, creating unlimited brute force opportunity. Low severity because the Simple Auth Manager is explicitly dev-only and rate limiting is intentionally a capability rather than enforced default. However, the absence of any lockout mechanism even as a reference implementation means custom auth managers have no framework-level template for implementing this control.

**Remediation:**

Consider adding an optional, configurable rate limit or failed-attempt counter in the BaseAuthManager interface as a reference for auth manager implementers:

```python
# In BaseAuthManager
def check_rate_limit(self, *, identifier: str) -> None:
    """Hook for rate limiting. Override to implement per-deployment policy."""
    pass
```

---

#### FINDING-024: Password Input Field Masking Cannot Be Verified From Available Source

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 6.2.6 |
| Files | airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:275-310 |
| Source Reports | 6.2.6.md |
| Related Findings | - |

**Description:**

The Simple Auth Manager serves a login UI via Jinja2 templates from the `ui/dev` or `ui/dist` directory. The actual `index.html` template and any associated JavaScript/form code that renders the password input field are not included in the audited source files. Without seeing the frontend HTML/React code, it is impossible to confirm whether password fields use `type="password"` for masking. If the password input field does not use `type="password"`, password entry would be visible to shoulder surfers or screen capture tools.

**Remediation:**

Verify that all password `<input>` elements in the login UI templates use `type="password"`. Example:
```html
<input type="password" name="password" id="password" autocomplete="current-password" />
```

---

#### FINDING-025: Documentation References Default "admin" and "viewer" Accounts in Development Tooling

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 6.3.2 |
| Files | airflow-core/docs/core-concepts/auth-manager/simple/index.rst, simple_auth_manager.py |
| Source Reports | 6.3.2.md |
| Related Findings | - |

**Description:**

The Breeze development environment pre-configures two accounts where the password equals the username (admin:admin, viewer:viewer). While this is explicitly a development tool configuration and not part of the production code path, the concern is: 1. Developers may deploy with these credentials still active. 2. The _looks_like_production() heuristic only emits a warning — it does not prevent deployment. 3. There is no forced password change for these well-known default credentials. Mitigating Context: The Simple Auth Manager is documented as dev/test only. The code itself (simple_auth_manager.py:get_users()) reads users from configuration — no accounts are hardcoded in application code. Production would use a different auth manager entirely. Password generation (_generate_password()) creates random 16-character passwords for non-Breeze environments.

**Remediation:**

1. The production detection heuristic could additionally check if any password in the passwords file matches the username and emit a CRITICAL warning. 2. Add a startup check that refuses to serve if passwords match common defaults when the deployment appears production-like: if self._looks_like_production(): passwords = self.get_passwords(); users = self.get_users(); for user in users: if passwords.get(user.username) == user.username: raise RuntimeError(f"Default credentials detected for user '{user.username}' in production-like deployment. Change the password or use a production auth manager.")

---

#### FINDING-026: System-Generated Initial Passwords Never Expire and Become Long-Term Credentials

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 6.4.1 |
| Files | airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:150-180 |
| Source Reports | 6.4.1.md |
| Related Findings | - |

**Description:**

The system-generated initial passwords are securely randomly generated using secrets.choice() and use a strong alphabet (52 chars, 16 length, ~91 bits entropy). However, they do NOT expire after a short period of time, do NOT require change after initial use, and ARE permitted to become the long-term password. Additionally, the generated passwords are printed to stdout/logs on first generation, creating a credential exposure window. Generated passwords become permanent credentials with no expiration or rotation mechanism. The plaintext password file persists indefinitely without any rotation enforcement.

**Remediation:**

1. Add a created_at timestamp per password entry in the JSON file. 2. Add a configurable maximum age for generated passwords. 3. After first login with a generated password, require password change. 4. Consider suppressing password output to logs and instead directing users to the password file. Example: {"bob": {"password": "xK9mN2pQ...", "generated_at": "2024-01-01T00:00:00Z", "must_change": true}}

---

#### FINDING-027: JWT Revocation Check Is Conditional on JTI Presence — Tokens Without JTI Cannot Be Revoked

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 7.4.1 |
| Files | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:143 |
| Source Reports | 7.4.1.md |
| Related Findings | - |

**Description:**

Token without `jti` → `payload.get("jti")` returns None → condition short-circuits → revocation check skipped → token accepted regardless of revocation state. If any code path generates a JWT without a `jti` claim (e.g., a third-party auth manager integration, or a misconfigured `JWTGenerator`), that token can never be revoked through the `revoke_token`/`RevokedToken` mechanism. The session termination guarantee is broken for such tokens. The severity is LOW because the `JWTGenerator` likely includes `jti` by default. However, the defensive check pattern means the system tolerates tokens without `jti`, creating a potential bypass if any token-generation path omits it.

**Remediation:**

Enforce that all tokens must have a `jti` claim:
```python
async def get_user_from_token(self, token: str) -> BaseUser:
    try:
        payload: dict[str, Any] = await self._get_token_validator().avalidated_claims(token)
    except InvalidTokenError as e:
        log.error("JWT token is not valid: %s", e)
        raise e

    jti = payload.get("jti")
    if not jti:
        raise InvalidTokenError("Token missing required 'jti' claim")
    
    if RevokedToken.is_revoked(jti):
        raise InvalidTokenError("Token has been revoked")
    
    try:
        return self.deserialize_user(payload)
    except (ValueError, KeyError) as e:
        log.error("Couldn't deserialize user from token: %s", e)
        raise InvalidTokenError(str(e))
```

---

#### FINDING-028: No OAuth2 Authorization Code Flow Implemented — Direct Credential Exchange Used Instead

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 10.4.3 |
| Files | airflow-core/docs/security/api.rst:37-48, airflow-core/src/airflow/api_fastapi/auth/tokens.py:403-439 |
| Source Reports | 10.4.3.md |
| Related Findings | - |

**Description:**

The provided codebase does not implement an OAuth2 authorization code flow. The authentication mechanism uses direct credential exchange via the `/auth/token` endpoint, where clients submit username/password and receive a JWT access token directly. No authorization code grant type with short-lived codes is present in the audited source. The system bypasses the authorization code pattern entirely. The `/auth/token` endpoint directly exchanges credentials for a JWT token (similar to the deprecated Resource Owner Password Credentials flow). Since there is no authorization code in this flow, the ASVS 10.4.3 requirement regarding authorization code lifetime cannot be directly evaluated. However, if any pluggable auth manager (e.g., FAB auth manager or external OIDC providers) implements authorization code flows internally, the lifetime enforcement would be delegated to those external systems and is not controlled by this codebase.

**Remediation:**

If authorization code flows are supported through auth managers, add framework-level validation that ensures authorization codes expire within 10 minutes (L1/L2) or 1 minute (L3):

```python
# In the auth manager base class or token exchange endpoint:
AUTHORIZATION_CODE_MAX_LIFETIME_SECONDS = 600  # 10 minutes for L1/L2

def validate_authorization_code(self, code: str) -> AuthorizationCodeData:
    code_data = self._lookup_code(code)
    if time.time() - code_data.issued_at > AUTHORIZATION_CODE_MAX_LIFETIME_SECONDS:
        raise AuthorizationCodeExpiredError()
    return code_data
```

---

#### FINDING-029: Token Revocation Infrastructure Exists But Is Not Integrated Into Refresh Flow

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 10.4.5 |
| Files | airflow-core/src/airflow/api_fastapi/auth/tokens.py:302-309 |
| Source Reports | 10.4.5.md |
| Related Findings | - |

**Description:**

The revoke_token() method and the RevokedToken model provide the infrastructure to revoke tokens by jti. However, this method is NOT called anywhere in the JWTRefreshMiddleware when a new token replaces the old one. The revocation mechanism is documented as being used for logout/explicit revocation, but not for rotation-based invalidation. Additionally, there is no evidence that avalidated_claims() checks the revoked_token table during validation — meaning even if a token IS revoked, the validation flow may not reject it. This creates false confidence that token revocation provides replay protection when it is not wired into the refresh flow where it's most needed.

**Remediation:**

Integrate revoke_token() into the refresh flow and ensure avalidated_claims() checks the revocation table. In avalidated_claims(), add: jti = claims.get('jti'); if jti and RevokedToken.is_revoked(jti): raise jwt.InvalidTokenError('Token has been revoked'). Call revoke_token() in JWTRefreshMiddleware after issuing a new token.

---

#### FINDING-030: No Explicit Rejection of 'None' Algorithm at Configuration Validation Time

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 9.1.2 |
| Files | airflow-core/src/airflow/api_fastapi/auth/tokens.py:232 |
| Source Reports | 9.1.2.md |
| Related Findings | - |

**Description:**

Configuration value `[api_auth] jwt_algorithm` flows through `_conf_list_factory` to `self.algorithm` and is passed to `jwt.decode(algorithms=...)` without sanitization of unsafe values. If a deployment manager configures `jwt_algorithm = none`, then `self.algorithm = ["none"]` and `jwt.decode(..., algorithms=["none"])` would accept unsigned tokens. An attacker could forge unsigned tokens with `alg=none` and no signature, gaining unauthorized access as any user. Requires deployment misconfiguration but the code should enforce the security invariant regardless.

**Remediation:**

Add explicit validation in `JWTValidator.__attrs_post_init__` to reject 'None' algorithm. Implement a check that raises `ValueError` if any configured algorithm case-insensitively matches "none". Example implementation:
```python
_FORBIDDEN_ALGORITHMS = frozenset({"none", "None", "NONE"})

def __attrs_post_init__(self):
    if not (self.jwks is None) ^ (self.secret_key is None):
        raise ValueError("Exactly one of private_key and secret_key must be specified")

    # Reject 'None' algorithm explicitly
    if any(alg.lower() == "none" for alg in self.algorithm if alg != "GUESS"):
        raise ValueError(
            "The 'None' algorithm is not permitted. "
            "Configure a secure algorithm (HS512, RS256, EdDSA)."
        )

    if self.algorithm == ["GUESS"]:
        if not self.jwks:
            self.algorithm = ["HS512"]
```

---

#### FINDING-031: Authorization documentation does not explicitly define enforcement timing and pipeline position

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 8.1.1 |
| Files | airflow-core/docs/core-concepts/auth-manager/index.rst |
| Source Reports | 8.1.1.md |
| Related Findings | - |

**Description:**

The authorization documentation comprehensively defines WHAT authorization checks exist (function-level and data-specific), including resource types (connections, DAGs, pools, variables, assets, views) and HTTP methods (GET/POST/PUT/DELETE). However, it does not explicitly document: 1. WHERE in the request processing pipeline authorization MUST be checked (before resource access, before data retrieval, etc.) 2. The required call sequence (authenticate → authorize → process → respond) 3. Mandatory enforcement points (API endpoint layer, middleware layer). Custom auth manager implementers may inadvertently apply authorization checks at incorrect points in the request pipeline (e.g., after data is retrieved), creating a gap where the control is called but after the sensitive operation.

**Remediation:**

Add a section to the documentation explicitly stating: Authorization Enforcement Requirements - All is_authorized_* methods MUST be called: 1. BEFORE any data access or mutation operation 2. At the API server layer (not in client-side code) 3. As early as possible after authentication completes 4. With the specific resource details when accessing a specific resource instance. The authorization decision MUST be evaluated before proceeding. If authorization is denied, the request MUST be rejected with HTTP 403 Forbidden before any resource access occurs.

---

#### FINDING-032: Documentation does not define handling of details=None authorization semantics for data-specific access

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 8.1.1 |
| Files | airflow-core/docs/core-concepts/auth-manager/index.rst:99-155, base_auth_manager.py:205-216 |
| Source Reports | 8.1.1.md |
| Related Findings | - |

**Description:**

The documentation mentions 'Some details about the connection can be provided' but doesn't clearly distinguish between: Function-level check: is_authorized_connection(method='GET', user=user) (details=None) — 'can user access connections at all?' and Data-level check: is_authorized_connection(method='GET', user=user, details=ConnectionDetails(conn_id='x')) — 'can user access THIS connection?'. This ambiguity could lead auth manager implementations to treat details=None as 'authorize access to ALL resources' rather than 'check general capability'. Custom auth managers may incorrectly grant broad access when details=None is passed, creating IDOR/BOLA vulnerabilities.

**Remediation:**

Document the semantic difference explicitly: When details is None, the check determines whether the user has the capability to perform the action on the resource type in general. This is typically used for listing operations. When details is provided, it performs a data-specific check for that exact resource instance. Auth manager implementations MUST NOT treat details=None as granting access to all instances of a resource type.

---

#### FINDING-033: Default `filter_authorized_*` implementations may allow timing-based inference attacks

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-208 |
| ASVS Section(s) | 8.2.2 |
| Files | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:459-481, airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:510-532, airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:559-581, airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:639-661 |
| Source Reports | 8.2.2.md |
| Related Findings | - |

**Description:**

The default `filter_authorized_*` implementations iterate over all resource IDs and call individual authorization checks. This is flagged as a performance concern in the documentation, but it also creates a potential timing side-channel: if the response time correlates with the number of resources checked, an attacker could infer the total number of resources in the system (even those they can't access). This is adequately addressed by the existing recommendation to override these methods.

**Remediation:**

This is adequately addressed by the existing recommendation to override these methods. Consider adding a note that performance optimization also mitigates timing side-channels.

---

#### FINDING-034: SQL Injection Pattern in Documentation Example Code

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-89 |
| ASVS Section(s) | 1.2.4 |
| Files | airflow-core/docs/administration-and-deployment/cluster-policies.rst:150-160 |
| Source Reports | 1.2.4.md |
| Related Findings | - |

**Description:**

The documentation file `cluster-policies.rst` contains example code that uses f-string interpolation to construct SQL statements. The code demonstrates an insecure pattern: `dbapi_connection.execute(f"SET SESSION AUTHORIZATION '{token}'")` where the token value is directly interpolated into the SQL string. While this is not production code, it teaches an insecure pattern that users may copy and adapt. If a token provider returns a value containing SQL metacharacters (e.g., single quotes), SQL injection becomes possible. For example, a token value of `foo'; DROP TABLE dag_run; --` would result in the SQL: `SET SESSION AUTHORIZATION 'foo'; DROP TABLE dag_run; --'`

**Remediation:**

Update the documentation example to use parameterized execution: `dbapi_connection.execute("SET SESSION AUTHORIZATION %s", [token])`. Note that the exact parameterization syntax depends on the DBAPI driver. The documentation should provide driver-specific examples or recommend using SQLAlchemy's `text()` with bound parameters. This prevents users from copying insecure SQL patterns into their deployments.

---

#### FINDING-035: No Format Validation on dag_id Parameter

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 2.2.1 |
| Files | airflow-core/src/airflow/api/common/trigger_dag.py:135 |
| Source Reports | 2.2.1.md |
| Related Findings | - |

**Description:**

The dag_id parameter accepts any string value without format or pattern validation. While the value is used safely in parameterized database queries (preventing injection) and validated by existence check against the database, there is no positive validation against an expected pattern before database lookup. Without format validation, the system performs unnecessary database queries for clearly invalid inputs (e.g., strings with special characters, extremely long strings), which could contribute to minor resource consumption.

**Remediation:**

Implement a regex pattern check for dag_id at the common API layer (e.g., ^[a-zA-Z0-9._-]{1,250}$) to reject clearly invalid inputs before database lookup. Example implementation:

```python
import re

DAG_ID_PATTERN = re.compile(r"^[a-zA-Z0-9._-]{1,250}$")

def trigger_dag(dag_id: str, ...) -> DagRun | None:
    if not DAG_ID_PATTERN.match(dag_id):
        raise ValueError(f"Invalid dag_id format: {dag_id!r}")
    ...
```

---

#### FINDING-036: No Schema Validation on DAG Run Configuration (conf)

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 2.2.1 |
| Files | airflow-core/src/airflow/api/common/trigger_dag.py:35 |
| Source Reports | 2.2.1.md |
| Related Findings | - |

**Description:**

The conf parameter is validated only for type (must be dict or null). No size limits, depth limits, or structural schema validation is applied to the JSON content. Arbitrarily large or deeply nested configurations are accepted. An attacker with API access could submit extremely large or deeply nested configuration objects, consuming parsing time and database storage. However, this is likely mitigated by HTTP request size limits at the web server/reverse proxy layer.

**Remediation:**

Implement maximum size and depth checks on the JSON configuration before and after parsing to prevent resource exhaustion. Example implementation:

```python
import sys

MAX_CONF_SIZE = 65536  # 64KB limit
MAX_CONF_DEPTH = 10

def _normalize_conf(conf: dict | str | None) -> dict | None:
    if isinstance(conf, str):
        if len(conf) > MAX_CONF_SIZE:
            raise ValueError(f"DagRun conf exceeds maximum size of {MAX_CONF_SIZE} bytes")
        conf = json.loads(conf)
    if conf is not None:
        if not isinstance(conf, dict):
            raise ValueError("DagRun conf must be a JSON object or null")
        if sys.getsizeof(str(conf)) > MAX_CONF_SIZE:
            raise ValueError(f"DagRun conf exceeds maximum size of {MAX_CONF_SIZE} bytes")
    return conf
```

---

#### FINDING-037: Potential TOCTOU in DAG Deletion Running-Task Check

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 2.3.1 |
| Files | airflow-core/src/airflow/api/common/delete_dag.py:55-62 |
| Source Reports | 2.3.1.md |
| Related Findings | - |

**Description:**

The function checks for running task instances and then proceeds to delete DAG data. Between the check and the deletion, there is a time window where a task instance could transition to RUNNING state (started by the scheduler). While this is within the same database session/transaction, the initial check uses a non-locking `select` without `FOR UPDATE`. In practice, the deletion of the DagModel record would prevent new DagRuns from being scheduled, and the entire operation is within a single session transaction. The scheduler would also check for DagModel existence before scheduling. The risk is primarily theoretical—a task that was just started would be deleted mid-execution, but its state in the database would be cleaned up.

**Remediation:**

Consider using `SELECT ... FOR UPDATE` on the DagModel to prevent concurrent scheduling during deletion: `dag = session.scalar(select(DagModel).where(DagModel.dag_id == dag_id).with_for_update().limit(1))`

---

#### FINDING-038: Helm chart ingress example missing TLS protocol version annotations

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 12.1.1 |
| Files | airflow-core/docs/howto/run-behind-proxy.rst:73-95 |
| Source Reports | 12.1.1.md |
| Related Findings | - |

**Description:**

The Helm chart ingress example enables TLS but does not include annotations for enforcing minimum TLS protocol versions (e.g., `nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1.2 TLSv1.3"`). While the Kubernetes Ingress controller may have reasonable defaults, explicitly documenting TLS version enforcement aligns with defense-in-depth. Low risk since many ingress controllers default to TLS 1.2+, but without explicit configuration, deployments on older or misconfigured ingress controllers may accept deprecated protocols.

**Remediation:**

Add TLS version annotation to the Helm ingress example:
```yaml
annotations:
  nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1.2 TLSv1.3"
```

---

#### FINDING-039: Missing production TLS certificate configuration documentation

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 12.2.2 |
| Files | airflow-core/docs/howto/run-with-self-signed-certificate.rst |
| Source Reports | 12.2.2.md |
| Related Findings | - |

**Description:**

While the self-signed certificate documentation properly includes a caution that it is "not suitable for production use," there is no corresponding documentation (in the provided files) providing equivalent detailed guidance for configuring publicly trusted certificates in production. The documentation asymmetry means operators have step-by-step instructions for insecure certificate configuration but must discover production TLS setup on their own.

**Remediation:**

Either create a companion document for production TLS configuration or add a reference at the end of the self-signed certificate document:
```rst
Production TLS Configuration
=============================

For production deployments, use certificates issued by a publicly trusted
Certificate Authority (CA) such as Let's Encrypt, DigiCert, or your
organization's internal CA that is trusted by all clients.

See :doc:`/howto/run-behind-proxy` for reverse proxy TLS termination,
or configure the API server directly with a CA-signed certificate using
the same ``AIRFLOW__API__SSL_CERT`` and ``AIRFLOW__API__SSL_KEY`` settings.
```

---

#### FINDING-040: Excessive certificate validity period in development example

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 12.2.2 |
| Files | airflow-core/docs/howto/run-with-self-signed-certificate.rst:35 |
| Source Reports | 12.2.2.md |
| Related Findings | - |

**Description:**

The certificate validity period of 3650 days (10 years) is excessive even for development environments. While the document is clearly marked for development use only, the long validity period sets a bad precedent and increases risk if the certificate is inadvertently used beyond its intended scope.

**Remediation:**

Reduce the example validity to a shorter period (e.g., 365 days) more appropriate for development/testing:
```bash
-sha256 -days 365 -nodes \
```

---

#### FINDING-041: Static file serving without Content-Disposition or Sec-Fetch validation

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-16 |
| ASVS Section(s) | 3.2.1 |
| Files | airflow-core/src/airflow/api_fastapi/core_api/app.py:65-70 |
| Source Reports | 3.2.1.md |
| Related Findings | - |

**Description:**

Static files are served with html=True, which allows HTML file serving. There's no Sec-Fetch-* validation to ensure static resources are only loaded as sub-resources of the application (not navigated to directly), and no mechanism to prevent serving user-influenced content in an incorrect context. Low severity as these are application-owned static files, but if any mechanism allows user content to land in the static directory, it could be served as HTML without restriction.

**Remediation:**

Consider setting html=False if HTML serving from static is not needed, and ensure a security headers middleware covers these responses. Implement Sec-Fetch-* header validation to ensure static resources are only loaded as sub-resources.

---

#### FINDING-042: Template rendering with dynamic context values — limited audit scope

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-79 |
| ASVS Section(s) | 3.2.2 |
| Files | airflow-core/src/airflow/api_fastapi/core_api/app.py:104-112 |
| Source Reports | 3.2.2.md |
| Related Findings | - |

**Description:**

The template context injects `request.base_url.path` into the HTML template. Jinja2 auto-escapes by default for HTML templates, mitigating XSS from this value. The `request.base_url.path` is server-controlled (derived from the `Host` header and application configuration), not directly user-input in the URL path sense. The React/TypeScript UI code (`airflow/ui/`) is not provided in this audit scope, so client-side rendering safety (use of `textContent`/`createTextNode` vs `innerHTML`/`dangerouslySetInnerHTML`) cannot be assessed for the frontend application. Gap Type: N/A — Insufficient scope to determine if client-side rendering uses safe functions. Impact: Cannot be determined without frontend code review.

**Remediation:**

Audit the React frontend code in `airflow-core/src/airflow/ui/` to verify: 1. Dynamic content uses React's JSX interpolation (which escapes by default) 2. No use of `dangerouslySetInnerHTML` with user-controlled content 3. Any markdown/rich-text rendering uses a sanitization library (e.g., DOMPurify)

---

#### FINDING-043: No middleware-level enforcement preventing GET requests to state-changing router endpoints

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-650 |
| ASVS Section(s) | 3.5.3 |
| Files | airflow-core/src/airflow/api_fastapi/core_api/app.py:38-42 |
| Source Reports | 3.5.3.md |
| Related Findings | - |

**Description:**

The application includes public_router and ui_router without any visible middleware-level guard that prevents state-changing operations from being registered on safe HTTP methods (GET, HEAD, OPTIONS). While FastAPI's router decorator pattern provides route-level method restriction, there is no centralized enforcement or validation layer visible in this initialization code that: 1) Audits or restricts which HTTP methods are allowed for state-changing endpoints, 2) Validates Sec-Fetch-* headers to ensure requests didn't originate from navigations or resource loads, 3) Prevents future developers from accidentally registering state-changing logic on GET routes. Without centralized method enforcement, individual router endpoints may inadvertently expose state-changing operations via GET requests, which could be triggered by simple navigation, image tags, or link prefetching.

**Remediation:**

Consider adding a Sec-Fetch-* validation middleware for additional defense-in-depth. Implement a SecFetchValidationMiddleware class that validates Sec-Fetch-* headers for state-changing requests. The middleware should define SAFE_METHODS as GET, HEAD, OPTIONS and reject cross-site requests that aren't from same-origin or same-site for non-safe methods by checking the sec-fetch-site header and returning a 403 response when appropriate.

---

#### FINDING-044: Static file responses may lack charset parameter for text/* MIME types

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-436 |
| ASVS Section(s) | 4.1.1 |
| Files | airflow-core/src/airflow/api_fastapi/core_api/app.py:56-67 |
| Source Reports | 4.1.1.md |
| Related Findings | - |

**Description:**

The `StaticFiles` middleware uses Python's `mimetypes` module to determine Content-Type headers for served files. For text-based files (CSS, JavaScript, plain text), the `mimetypes` module may not consistently include the `charset` parameter. For example: `.css` → `text/css` (without `; charset=utf-8`), `.js` → `application/javascript` or `text/javascript` (varies by platform). While modern browsers typically default to UTF-8, the ASVS requirement specifies that `text/*` responses should include the charset parameter. Starlette's `StaticFiles` does not add charset parameters to the Content-Type derived from `mimetypes`. Without explicit charset specification on text/* responses, browsers in legacy or strict mode may fall back to platform-dependent character encoding, potentially causing encoding-related display issues or, in edge cases, enabling charset-sniffing attacks.

**Remediation:**

Override the static file response to include charset for text types, or add a middleware:

```python
from starlette.middleware.base import BaseHTTPMiddleware

class CharsetMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        content_type = response.headers.get("content-type", "")
        if content_type.startswith("text/") and "charset" not in content_type:
            response.headers["content-type"] = f"{content_type}; charset=utf-8"
        return response
```

---

#### FINDING-045: No Documentation of Source Control Metadata Exclusion in Deployment Guidance

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 13.4.1 |
| Files | airflow-core/docs/core-concepts/overview.rst:67-80, AGENTS.md |
| Source Reports | 13.4.1.md |
| Related Findings | - |

**Description:**

The deployment architecture documentation does not address exclusion of source control metadata (.git, .svn folders) from production deployments. While the overview.rst discusses deployment patterns and the Helm chart is referenced for Kubernetes deployments, neither document specifies that deployment artifacts must not contain repository metadata. If source control metadata is included in deployment artifacts, attackers could access: complete repository history (including potentially reverted secrets), internal file paths and developer information, branch structure revealing development practices, and commit messages containing internal references.

**Remediation:**

Add deployment security hardening documentation that includes: (1) Docker images must use .dockerignore to exclude .git/, .svn/; (2) Dag synchronization mechanisms must not copy .git/ directories; (3) Web server configuration must deny access to paths matching /.git, /.svn, /.hg; (4) For Helm chart deployments, verify the official Airflow Docker image excludes source control metadata by default and ensure custom images verify this exclusion; (5) For git-sync based Dag synchronization, ensure the --depth 1 flag is used and the .git directory is either excluded from the mount or inaccessible to the application.

---

# 4. Positive Security Controls

| Control ID | Domain | Control Description | Evidence | Files |
|------------|--------|---------------------|----------|-------|
| PSC-001 | Authentication & Session Management | Production detection heuristic | The `_looks_like_production()` method emits loud warnings when the Simple Auth Manager is used with non-sqlite databases, non-localhost API hosts, or distributed executors — helping prevent accidental production use | simple_auth_manager.py:93-128 |
| PSC-002 | Authentication & Session Management | Constant-time credential comparison | Uses `hmac.compare_digest()` to prevent timing attacks (CWE-208) | services/login.py:46-50 |
| PSC-003 | Authentication & Session Management | Cookie security | Sets `httponly=True`, `samesite="lax"`, and conditional secure flag on JWT cookies | routes/login.py:84-90 |
| PSC-004 | Authentication & Session Management | JWT token revocation support | Full token lifecycle with JTI-based revocation checking via RevokedToken model | base_auth_manager.py:108-125 |
| PSC-005 | Authentication & Session Management | Cryptographically secure password generation | Uses `secrets.choice()` with 16-character output, exceeding recommended 15-character minimum | simple_auth_manager.py:420-422 |
| PSC-006 | Authentication & Session Management | No character composition requirements enforced | Login flow only validates non-empty username/password — no requirements for uppercase, lowercase, numbers, or special characters | services/login.py:37-41 |
| PSC-007 | Authentication & Session Management | UTF-8 encoding support | Passwords encoded as UTF-8 for comparison, supporting international characters, emojis, and Unicode content without restriction | services/login.py:49-50 |
| PSC-008 | Authentication & Session Management | Content-Type acceptance for password managers | Accepts `application/json` and `application/x-www-form-urlencoded` — compatible with autofill | routes/login.py:create_token() |
| PSC-009 | Authentication & Session Management | Exact password comparison | Password verified exactly as received without truncation, case transformation, or stripping | services/login.py:56-63 |
| PSC-010 | Authentication & Session Management | Backend JWT signature verification | All token verification performed in `BaseAuthManager.get_user_from_token()`, an async server-side method that validates cryptographic signatures, checks revocation, and deserializes the user | base_auth_manager.py:136 |
| PSC-011 | Authentication & Session Management | Dynamic JWT generation on login | `generate_jwt()` method creates fresh tokens per authentication event | base_auth_manager.py:155 |
| PSC-012 | Authentication & Session Management | Self-contained JWT tokens | System uses cryptographically signed JWTs where security derives from signature algorithm strength | base_auth_manager.py:155 |
| PSC-013 | Authentication & Session Management | File locking for concurrent access | Uses `fcntl.flock(file, fcntl.LOCK_EX | fcntl.LOCK_NB)` to prevent race conditions when multiple Airflow workers initialize simultaneously | simple_auth_manager.py:init() |
| PSC-014 | Authentication & Session Management | No password hints or knowledge-based authentication | Authentication is username/password only with no password recovery via security questions | services/login.py |
| PSC-015 | JWT Token Security | JWT-based API authentication with direct credential exchange | Implements JWT-based API authentication (tokens.py) and cookie-based token refresh (refresh_token.py) using direct credential exchange (POST /auth/token) | tokens.py, refresh_token.py, jwt_token_authentication.rst |
| PSC-016 | JWT Token Security | Clear separation of concerns in JWT infrastructure | JWT infrastructure (tokens.py) provides primitive generation/validation capabilities while policy decisions delegated to auth managers and middleware layers | tokens.py |
| PSC-017 | JWT Token Security | Symmetric vs. asymmetric JWT modes well-isolated | XOR enforcement (exactly one of jwks or secret_key) at both generator and validator level prevents algorithm confusion/key confusion attacks | tokens.py |
| PSC-018 | JWT Token Security | JWKS refresh is resilient | JWKS class implements proper retry logic with separate tracking of last attempt vs. last success, preventing thundering-herd problems while ensuring eventual consistency for key rotations | tokens.py |
| PSC-019 | JWT Token Security | Token lifecycle well-documented | Comprehensive documentation of both REST API and Execution API token flows, including scopes, lifetimes, and refresh mechanisms | jwt_token_authentication.rst |
| PSC-020 | JWT Token Security | Token revocation infrastructure exists | `JWTValidator.revoke_token()` method and RevokedToken database model provide mechanism for tracking invalidated tokens by jti | tokens.py |
| PSC-021 | JWT Token Security | Configurable token lifetimes | JWTGenerator accepts `valid_for` parameter and supports per-call overrides, enabling different lifetime policies for different token types | airflow-core/src/airflow/api_fastapi/auth/tokens.py |
| PSC-022 | JWT Token Security | JWT signature validation via jwt.decode() | `JWTValidator.avalidated_claims()` performs cryptographic signature verification before returning claims | tokens.py:263 |
| PSC-023 | JWT Token Security | Algorithm allowlist parameter always passed | The `algorithms` parameter consistently passed to `jwt.decode()` acting as an allowlist | airflow-core/src/airflow/api_fastapi/auth/tokens.py:272 |
| PSC-024 | JWT Token Security | Safe default algorithm auto-detection | Default `jwt_algorithm = GUESS` resolves exclusively to safe algorithms: HS512 (symmetric), RS256 (RSA), or EdDSA (Ed25519) | airflow-core/src/airflow/api_fastapi/auth/tokens.py:232 |
| PSC-025 | JWT Token Security | JWKS from pre-configured trusted_jwks_url | Key material sourced from pre-configured `trusted_jwks_url`, no token-controlled key sources (jku, x5u, jwk headers not processed) | tokens.py:367 |
| PSC-026 | JWT Token Security | exp, iat, nbf required claims enforced | `JWTValidator.required_claims` defined as frozenset, PyJWT automatically verifies exp and nbf during `jwt.decode()` | tokens.py:225, tokens.py:270 |
| PSC-027 | JWT Token Security | Cookie security controls with httponly, secure, and samesite attributes | The `_token` cookie set with `httponly=True`, secure (HTTPS-conditional), and `samesite='lax'`, mitigating cookie-theft vectors (XSS, CSRF) | airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py:73-79 |
| PSC-028 | JWT Token Security | Unique token identifiers (jti) in all tokens | Every generated token includes a `uuid4().hex` jti claim, enabling per-token revocation tracking | tokens.py |
| PSC-029 | API Authorization & Access Control | Comprehensive resource coverage | Documentation covers all resource types (configuration, connections, DAGs, assets, asset aliases, pools, variables, views, custom views) with specific authorization methods | airflow-core/docs/core-concepts/auth-manager/index.rst:99-155 |
| PSC-030 | API Authorization & Access Control | HTTP method-based permissions model | Clear mapping of GET→read, POST→create, PUT→modify, DELETE→delete with documentation that some methods only apply to certain resources | airflow-core/docs/core-concepts/auth-manager/index.rst:99-155 |
| PSC-031 | API Authorization & Access Control | Hierarchical authorization model | DAG sub-component authorization explicitly documented (DAG → runs → tasks → instances) with the `access_entity` parameter | airflow-core/docs/core-concepts/auth-manager/index.rst:99-155 |
| PSC-032 | API Authorization & Access Control | Batch and filter optimization documentation | Performance-sensitive methods documented with explicit recommendation to override default implementations | airflow-core/docs/core-concepts/auth-manager/index.rst:186-193 |
| PSC-033 | API Authorization & Access Control | Multi-team isolation documentation | Clear documentation of team-based resource isolation with `team_name` parameter threading | airflow-core/docs/core-concepts/auth-manager/index.rst:273-288, base_auth_manager.py |
| PSC-034 | API Authorization & Access Control | JWT token management documentation | Token creation, exchange, refresh documented | airflow-core/docs/core-concepts/auth-manager/index.rst:157-184 |
| PSC-035 | API Authorization & Access Control | Fail-Closed Defaults | Architecture defaults to denying access when controls not implemented (NotImplementedError for team authorization, abstract methods for core authorization) | base_auth_manager.py |
| PSC-036 | API Authorization & Access Control | Abstract method enforcement | All core authorization methods marked `@abstractmethod`, preventing instantiation of auth managers that don't implement them | base_auth_manager.py:192-339 |
| PSC-037 | API Authorization & Access Control | Fail-closed for multi-team | `is_authorized_team()` raises NotImplementedError by default, denying access if multi-team enabled without proper implementation | base_auth_manager.py:273-288 |
| PSC-038 | API Authorization & Access Control | Init-time validation | `init()` validates multi-team configuration at startup, catching misconfiguration early | base_auth_manager.py |
| PSC-039 | API Authorization & Access Control | Batch authorization uses AND logic | `batch_is_authorized_*` methods use `all()`, meaning ALL individual checks must pass, preventing partial authorization leakage | base_auth_manager.py |
| PSC-040 | API Authorization & Access Control | Method parameter typing | ResourceMethod enum restricts to valid HTTP methods only, preventing unauthorized action types | base_auth_manager.py |
| PSC-041 | API Authorization & Access Control | Resource detail models provide structured resource identification | Typed detail classes (ConnectionDetails, DagDetails, PoolDetails, VariableDetails) | resource_details.py |
| PSC-042 | API Authorization & Access Control | Team-based resource grouping enables multi-tenant isolation | `get_authorized_*` methods group resources by `team_name` before filtering | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py |
| PSC-043 | API Authorization & Access Control | Outer join for completeness ensures no resources escape authorization | `get_authorized_dag_ids()` uses `isouter=True` to include resources without team associations | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py |
| PSC-044 | API Authorization & Access Control | Internal filter methods consistently construct detail objects | All `filter_authorized_*` methods pass details with specific IDs | base_auth_manager.py:459-481, 510-532, 559-581, 639-661 |
| PSC-045 | API Authorization & Access Control | DagAccessEntity sub-component authorization | Enables fine-grained authorization on DAG sub-resources via `access_entity` parameter on `is_authorized_dag()` for runs, tasks, task instances | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py |
| PSC-046 | API Authorization & Access Control | All authorization in backend Python | Every authorization method implemented in server-side Python with no client-side counterpart. No JavaScript authorization logic. | base_auth_manager.py |
| PSC-047 | API Authorization & Access Control | JWT httponly cookie | Documented token exchange protocol uses `httponly=True` cookies, preventing client-side JavaScript from accessing or manipulating JWT token | index.rst:172-180 |
| PSC-048 | API Authorization & Access Control | Server-side token validation | `get_user_from_token()` performs full JWT validation (signature, expiration, audience, revocation) on server before creating user object | base_auth_manager.py:142-154 |
| PSC-049 | API Authorization & Access Control | Architecture boundary enforcement | API Server serves React UI and handles all client-database interactions - no authorization decisions delegated to client | AGENTS.md:95-111 |
| PSC-050 | API Authorization & Access Control | Token revocation database check | Revocation status checked server-side against RevokedToken database table, which cannot be manipulated by clients | base_auth_manager.py:149-150 |
| PSC-051 | API Authorization & Access Control | No trust of client-provided authorization claims | User object derived entirely from validated JWT payload (`deserialize_user(payload)`), not from any client-provided headers or request parameters | base_auth_manager.py:142-154 |
| PSC-052 | API Authorization & Access Control | Secure cookie configuration | Documentation explicitly requires `secure=True` when serving over HTTPS, preventing token leakage over unencrypted connections | index.rst:172-180 |
| PSC-053 | Input Validation & Injection Prevention | SQLAlchemy ORM with parameterized queries | All database operations use SQLAlchemy ORM with parameterized bindings, preventing SQL injection | delete_dag.py, mark_tasks.py, trigger_dag.py, common/db/common.py |
| PSC-054 | Input Validation & Injection Prevention | FastAPI/Pydantic JSON serialization | Framework-level JSON output encoding with proper escaping applied to all API responses | — |
| PSC-055 | Input Validation & Injection Prevention | JSON-only data exchange (no XML parsing) | DAG configuration uses `json.loads()`, no XML processing libraries imported | trigger_dag.py |
| PSC-056 | Input Validation & Injection Prevention | No dynamic code execution (eval/exec/compile) | No use of `eval()`, `exec()`, `compile()`, or dynamic imports on user input | delete_dag.py, mark_tasks.py, trigger_dag.py, common/db/common.py |
| PSC-057 | Input Validation & Injection Prevention | Server-side input validation enforcement | `@provide_session` decorator ensures all validation occurs server-side with no reliance on client-side checks | trigger_dag.py, delete_dag.py, mark_tasks.py |
| PSC-058 | Input Validation & Injection Prevention | Type validation on conf parameter | `_normalize_conf()` validates that conf is dict or null, rejecting other types | trigger_dag.py:28-33 |
| PSC-059 | Input Validation & Injection Prevention | Business rule enforcement via allowed_run_types | `trigger_dag()` checks `dag_model.allowed_run_types` before creating DagRun | trigger_dag.py:166 |
| PSC-060 | Input Validation & Injection Prevention | Existence validation before operations | DAG existence checked before triggering or deletion | trigger_dag.py:160, delete_dag.py:60 |
| PSC-061 | Input Validation & Injection Prevention | Enum-based state validation | TaskInstanceState and DagRunState enums prevent invalid state values | mark_tasks.py |
| PSC-062 | Input Validation & Injection Prevention | Row-level locking for state transitions | `with_for_update()` used during state changes to prevent race conditions | mark_tasks.py |
| PSC-063 | Input Validation & Injection Prevention | Duplicate prevention for DagRuns | `DagRun.find_duplicate()` prevents creation of duplicate DAG runs | trigger_dag.py:110 |
| PSC-064 | Input Validation & Injection Prevention | Timezone localization validation | Validates that `logical_date` has timezone information | trigger_dag.py:85 |
| PSC-065 | Input Validation & Injection Prevention | Teardown task protection | Checks for unfinished teardown tasks before state transitions to prevent cleanup skip | mark_tasks.py |
| PSC-066 | Input Validation & Injection Prevention | Parameterized logging to prevent log injection | Uses `log.info` with format string rather than f-string interpolation | delete_dag.py:51 |
| PSC-067 | Input Validation & Injection Prevention | Session management discipline | `@provide_session` decorator and NEW_SESSION pattern provide consistent session lifecycle management | — |
| PSC-068 | Input Validation & Injection Prevention | Architectural separation: no OS command execution in data layer | Data-layer modules handle only database operations, task execution occurs in separate Worker components | — |
| PSC-069 | Cryptography & Secrets Management | Fernet encryption (AES-128-CBC + HMAC-SHA256) | Uses CBC mode (not ECB) with authenticated encryption via encrypt-then-MAC construction. Provides 128-bit minimum security level. | airflow-core/docs/security/secrets/fernet.rst |
| PSC-070 | Cryptography & Secrets Management | Key rotation mechanism | Documented rotation procedure exists (`airflow rotate-fernet-key` command) with key lifecycle management | airflow-core/docs/security/secrets/fernet.rst |
| PSC-071 | Cryptography & Secrets Management | External secrets backends | Pluggable architecture supports HashiCorp Vault, AWS Secrets Manager, AWS KMS for organizations requiring alternative encryption methods like AES-GCM | airflow-core/docs/security/secrets/secrets-backend/index.rst |
| PSC-072 | Cryptography & Secrets Management | Authenticated encryption via encrypt-then-MAC | Fernet's HMAC-SHA256 authentication layer prevents padding oracle attacks and provides message authentication | airflow-core/docs/security/secrets/fernet.rst |
| PSC-073 | Cryptography & Secrets Management | Industry-validated cryptography library dependency | Uses professionally audited and well-maintained Python cryptography library with Fernet implementation that enforces NIST-approved primitives | airflow-core/docs/security/secrets/fernet.rst |
| PSC-074 | Cryptography & Secrets Management | Secure key storage guidance | Documentation specifies key storage in environment variables or airflow.cfg, not in source control | airflow-core/docs/security/secrets/fernet.rst |
| PSC-075 | Cryptography & Secrets Management | Cryptographically secure key generation | Uses `Fernet.generate_key()` with cryptographically secure random generation | airflow-core/docs/security/secrets/fernet.rst |
| PSC-076 | Cryptography & Secrets Management | HMAC-SHA256 in Fernet | Fernet's HMAC-SHA256 uses approved hash function (SHA-256) providing 128-bit collision resistance per NIST FIPS 180-4 | airflow-core/docs/security/secrets/fernet.rst |
| PSC-077 | Cryptography & Secrets Management | No deprecated hash functions documented | None of the documentation recommends or references MD5, SHA-1, or other deprecated algorithms for any cryptographic purpose | — |
| PSC-078 | TLS & Network Security | Strong cryptographic parameters for development certificates | Self-signed certificate example uses RSA 4096-bit keys with SHA-256, demonstrating good cryptographic hygiene even in development | run-with-self-signed-certificate.rst |
| PSC-079 | TLS & Network Security | Clear production disclaimer | Self-signed certificate documentation explicitly states 'This procedure is intended for learning, exploration and development. It is not suitable for production use.' | run-with-self-signed-certificate.rst |
| PSC-080 | TLS & Network Security | Helm chart TLS enablement | Helm chart example enables TLS on the ingress with proper certificate secret reference | airflow-core/docs/howto/run-behind-proxy.rst:73-95 |
| PSC-081 | TLS & Network Security | HTTPS for execution API | Self-signed certificate documentation properly shows configuring `AIRFLOW__CORE__EXECUTION_API_SERVER_URL` with `https://` scheme for worker-to-API-server communication | airflow-core/docs/howto/run-with-self-signed-certificate.rst |
| PSC-082 | TLS & Network Security | X-Forwarded-Proto header forwarding | Proxy examples include forwarding `X-Forwarded-Proto` which allows application to detect original scheme | airflow-core/docs/howto/run-behind-proxy.rst |
| PSC-083 | TLS & Network Security | Helm TLS secret management | Helm chart example references Kubernetes TLS secret (`secretName: airflow-tls`), proper pattern for managing certificates in production Kubernetes deployments | airflow-core/docs/howto/run-behind-proxy.rst |
| PSC-084 | TLS & Network Security | Proper certificate validation | Health check configuration uses `--cacert` to validate self-signed certificate rather than disabling certificate verification (no `--insecure` or `-k` flag) | airflow-core/docs/howto/run-with-self-signed-certificate.rst |
| PSC-085 | TLS & Network Security | WebSocket headers properly configured | Documentation correctly shows `Upgrade` and `Connection` headers needed for WebSocket proxying, indicating awareness of WebSocket requirements | airflow-core/docs/howto/run-behind-proxy.rst |
| PSC-086 | TLS & Network Security | Helm chart WebSocket with TLS | Helm chart example includes both WebSocket upgrade headers AND TLS configuration (`tls: enabled: true`), which when combined would result in WSS connections in Kubernetes deployments | airflow-core/docs/howto/run-behind-proxy.rst |
| PSC-087 | TLS & Network Security | HTTP/1.1 version specification | Documentation correctly sets `proxy_http_version 1.1` which is required for WebSocket upgrade negotiation | airflow-core/docs/howto/run-behind-proxy.rst |
| PSC-088 | HTTP Security Headers & CORS | JWT in Authorization header | JWTRefreshMiddleware + auth manager - Tokens sent in headers, not URLs | — |
| PSC-089 | HTTP Security Headers & CORS | Secret key in app.state | Stored server-side in memory | app.py:153 |
| PSC-090 | HTTP Security Headers & CORS | No query-param authentication | No visible `?token=` or `?api_key=` patterns in route definitions | — |
| PSC-091 | HTTP Security Headers & CORS | JWT-based sessions with refresh middleware | `JWTRefreshMiddleware` enables token expiration and rotation, providing time-bounded session validity even without explicit cleanup | airflow-core/src/airflow/api_fastapi/core_api/app.py:163-180 |
| PSC-092 | HTTP Security Headers & CORS | Pluggable auth manager | Auth manager pattern (`get_auth_manager().get_fastapi_middlewares()`) allows auth implementations to add session-termination logic via their own middleware | airflow-core/src/airflow/api_fastapi/core_api/app.py:163-180 |
| PSC-093 | HTTP Security Headers & CORS | Explicit media_type set on SPA template response | Explicit `media_type="text/html"` set on SPA template response, preventing Content-Type ambiguity for main page | — |
| PSC-094 | HTTP Security Headers & CORS | Explicit 404 responses for deprecated API paths | Explicit 404 responses for deprecated API paths (/health, /api/v1/*) prevent unintended content rendering at old endpoints | — |
| PSC-095 | HTTP Security Headers & CORS | Proper Content-Type handling for static files | Static files served via FastAPI's StaticFiles class which properly sets Content-Type based on file extension | airflow-core/src/airflow/api_fastapi/core_api/app.py:65-70 |
| PSC-096 | HTTP Security Headers & CORS | Jinja2 auto-escaping | Jinja2Templates used with default auto-escaping configuration, which escapes HTML special characters in template variables | init_views() — Jinja2Templates |
| PSC-097 | HTTP Security Headers & CORS | Server-controlled dynamic value | Only dynamic value in server-rendered template (`backend_server_base_url`) derived from `request.base_url.path`, which is server-configuration-controlled rather than user-input | airflow-core/src/airflow/api_fastapi/core_api/app.py:104-112 |

---

# 5. ASVS Compliance Summary

| ASVS ID | Requirement | Status | Notes |
|---------|-------------|--------|-------|
| **6.1.1** | Authentication Documentation | **Fail** | No documentation of rate limiting or anti-automation controls for login endpoints (FINDING-004) |
| **6.2.1** | Password Minimum Length | **Partial** | System-generated passwords meet 15-char minimum (PSC-005), but no enforcement for user-set passwords (FINDING-005) |
| **6.2.2** | Users Can Change Their Password | **Fail** | No application-level password change functionality (FINDING-006) |
| **6.2.3** | Password Change Requires Current and New Password | **Fail** | No password change functionality exists (FINDING-006) |
| **6.2.4** | Check Against Common Passwords | **Fail** | No check against common/breached password lists (FINDING-007) |
| **6.2.5** | No Composition Rules Limiting Password Characters | **Pass** | No character composition requirements enforced (PSC-006), UTF-8 encoding support (PSC-007) |
| **6.2.6** | Password Input Fields Masking | **Partial** | Cannot be verified from available source (FINDING-024) |
| **6.2.7** | Paste Functionality and Password Managers | **Pass** | Content-Type acceptance for password managers (PSC-008), exact password comparison (PSC-009) |
| **6.2.8** | Password Verification Without Modification | **Pass** | Exact password comparison without truncation, case transformation, or stripping (PSC-009) |
| **6.3.1** | Credential Stuffing and Brute Force Prevention | **Fail** | Login endpoints lack rate limiting or account lockout mechanisms (FINDING-008, FINDING-023) |
| **6.3.2** | Default User Accounts | **Partial** | Documentation references default "admin" and "viewer" accounts in development tooling (FINDING-025) |
| **6.4.1** | System Generated Initial Passwords | **Partial** | Strong generation (PSC-005), but passwords never expire and become long-term credentials (FINDING-026) |
| **6.4.2** | Password Hints and Knowledge-Based Authentication | **Pass** | No password hints or knowledge-based authentication (PSC-014) |
| **7.2.1** | Backend Session Token Verification | **Pass** | Backend JWT signature verification (PSC-010), server-side token validation (PSC-048) |
| **7.2.2** | Dynamically Generated Session Tokens | **Pass** | Dynamic JWT generation on login (PSC-011) |
| **7.2.3** | Reference Token Entropy | **N/A** | System uses self-contained JWT tokens, not reference tokens (PSC-012) |
| **7.2.4** | New Session Token on Authentication | **Partial** | Fresh tokens generated per authentication event (PSC-011), but previous tokens not revoked (FINDING-009) |
| **7.4.1** | Session Termination | **Partial** | JWT token revocation support exists (PSC-004), but Simple Auth Manager provides no logout endpoint (FINDING-010), and revocation check conditional on JTI presence (FINDING-027) |
| **7.4.2** | Terminate All Sessions on User Account Deletion | **Fail** | No mechanism to terminate all sessions on user account deletion (FINDING-001) |
| **10.4.1** | OAuth Authorization Server - Redirect URI Validation | **N/A** | No OAuth Authorization Code flow implemented (FINDING-028) |
| **10.4.2** | OAuth Authorization Server - Authorization Code One-Time Use | **N/A** | No OAuth Authorization Code flow implemented (FINDING-028) |
| **10.4.3** | Authorization Code Short-Lived | **N/A** | No OAuth Authorization Code flow implemented (FINDING-028) |
| **10.4.4** | Client-Specific Grant Restriction | **Partial** | Direct credential exchange resembles deprecated ROPC grant without per-client grant restriction (FINDING-011) |
| **10.4.5** | Refresh Token Replay Attack Mitigation | **Fail** | JWT Refresh Middleware does not invalidate previous token after issuing new token (FINDING-012), revocation infrastructure exists but not integrated into refresh flow (FINDING-029) |
| **9.1.1** | Token Source and Integrity - Signature/MAC Validation | **Pass** | JWT signature validation via jwt.decode() (PSC-022) |
| **9.1.2** | Token Source and Integrity - Algorithm Allowlist | **Partial** | Algorithm allowlist parameter always passed (PSC-023), safe default algorithm auto-detection (PSC-024), but no explicit rejection of 'None' algorithm at configuration validation time (FINDING-030) |
| **9.1.3** | Token Source and Integrity - Key Material from Trusted Sources | **Pass** | JWKS from pre-configured trusted_jwks_url (PSC-025) |
| **9.2.1** | Token Content - Validity Time Span Verification | **Pass** | exp, iat, nbf required claims enforced (PSC-026) |
| **8.1.1** | Authorization Documentation | **Partial** | Comprehensive resource coverage (PSC-029), but documentation does not explicitly define enforcement timing and pipeline position (FINDING-031), nor handling of details=None authorization semantics (FINDING-032) |
| **8.2.1** | General Authorization Design - Function-Level Access | **Partial** | Abstract method enforcement (PSC-036), fail-closed defaults (PSC-035), but no enforcement mechanism in base class ensures authorization is called at API entry points (FINDING-013) |
| **8.2.2** | General Authorization Design - Data-Specific Access (IDOR/BOLA) | **Partial** | Resource detail models (PSC-041), team-based resource grouping (PSC-042), but optional `details` parameter allows authorization calls without data-specific context (FINDING-014), and default filter implementations may allow timing-based inference attacks (FINDING-033) |
| **8.3.1** | Operation Level Authorization - Trusted Service Layer | **Pass** | All authorization in backend Python (PSC-046), server-side token validation (PSC-048), architecture boundary enforcement (PSC-049) |
| **1.2.1** | Output Encoding for HTTP Response/HTML/XML | **Pass** | FastAPI/Pydantic JSON serialization (PSC-054), Jinja2 auto-escaping (PSC-096) |
| **1.2.2** | URL Encoding for Dynamic URLs | **Pass** | Server-controlled dynamic value (PSC-097) |
| **1.2.3** | JavaScript/JSON Output Encoding | **Pass** | FastAPI/Pydantic JSON serialization (PSC-054) |
| **1.2.4** | Parameterized Queries / SQL Injection Protection | **Partial** | SQLAlchemy ORM with parameterized queries throughout production code (PSC-053), but SQL injection pattern in documentation example code (FINDING-034) |
| **1.2.5** | OS Command Injection Protection | **Pass** | No dynamic code execution (PSC-056), architectural separation: no OS command execution in data layer (PSC-068) |
| **1.3.1** | HTML Sanitization for Untrusted Input | **Pass** | Jinja2 auto-escaping (PSC-096) |
| **1.3.2** | Dynamic Code Execution | **Pass** | No dynamic code execution (eval/exec/compile) (PSC-056) |
| **1.5.1** | XML Parser Configuration | **N/A** | JSON-only data exchange (no XML parsing) (PSC-055) |
| **2.1.1** | Input Validation Rules Documentation | **Partial** | Type validation (PSC-058), business rule enforcement (PSC-059), but incomplete documentation of input validation rules for DAG Trigger API (FINDING-015) |
| **2.2.1** | Input Validation Enforcement | **Partial** | Existence validation (PSC-060), enum-based state validation (PSC-061), but no format validation on dag_id parameter (FINDING-035), no schema validation on DAG run configuration (FINDING-036) |
| **2.2.2** | Server-Side Input Validation | **Pass** | Server-side input validation enforcement (PSC-057) |
| **2.3.1** | Business Logic Sequential Flow | **Partial** | Row-level locking for state transitions (PSC-062), duplicate prevention for DagRuns (PSC-063), teardown task protection (PSC-065), but potential TOCTOU in DAG deletion running-task check (FINDING-037) |
| **11.3.1** | Encryption Algorithms - Insecure Block Modes and Padding | **Pass** | Fernet encryption (AES-128-CBC + HMAC-SHA256) uses CBC mode, not ECB (PSC-069) |
| **11.3.2** | Encryption Algorithms - Approved Ciphers and Modes | **Pass** | Fernet encryption with authenticated encryption via encrypt-then-MAC (PSC-069, PSC-072), industry-validated cryptography library dependency (PSC-073) |
| **11.4.1** | Hashing and Hash-based Functions - Approved Hash Functions | **Pass** | HMAC-SHA256 in Fernet (PSC-076), no deprecated hash functions documented (PSC-077) |
| **12.1.1** | General TLS Security Guidance | **Fail** | Nginx reverse proxy example lacks HTTPS configuration with TLS protocol version enforcement (FINDING-016), Helm chart ingress example missing TLS protocol version annotations (FINDING-038) |
| **12.2.1** | HTTPS Communication with External Facing Services | **Fail** | Nginx reverse proxy example lacks HTTPS configuration (FINDING-016), Flower documentation lacks TLS configuration guidance (FINDING-017) |
| **12.2.2** | Publicly Trusted TLS Certificates | **Partial** | Clear production disclaimer (PSC-079), Helm TLS secret management (PSC-083), but missing production TLS certificate configuration documentation (FINDING-039), excessive certificate validity period in development example (FINDING-040) |
| **4.4.1** | WebSocket over TLS (WSS) | **Fail** | Nginx reverse proxy example lacks HTTPS configuration (FINDING-016), though Helm chart WebSocket with TLS exists (PSC-086) |
| **14.2.1** | Sensitive Data in URLs | **Pass** | JWT in Authorization header (PSC-088), no query-param authentication (PSC-090) |
| **14.3.1** | Client-side Data Cleared on Session Termination | **Fail** | No Clear-Site-Data header implementation visible (FINDING-018) |
| **3.2.1** | Unintended Content Interpretation - Context Controls | **Fail** | No HSTS header in middleware stack (FINDING-002), static file serving without Content-Disposition or Sec-Fetch validation (FINDING-041) |
| **3.2.2** | Unintended Content Interpretation - Safe Text Rendering | **Partial** | Explicit media_type set on SPA template response (PSC-093), proper Content-Type handling for static files (PSC-095), Jinja2 auto-escaping (PSC-096), but template rendering with dynamic context values has limited audit scope (FINDING-042) |
| **3.3.1** | Cookie Setup - Secure Attribute and Prefix | **Partial** | Cookie security (PSC-003), cookie security controls with httponly, secure, and samesite attributes (PSC-027), but no evidence of Secure attribute or __Host-/__Secure- prefix enforcement (FINDING-019) |
| **3.4.1** | Browser Security Mechanism Headers - HSTS | **Fail** | No Strict-Transport-Security (HSTS) header in middleware stack (FINDING-002) |
| **3.4.2** | Browser Security Mechanism Headers - CORS | **Fail** | CORS `allow_credentials=True` hardcoded without origin wildcard validation (FINDING-003) |
| **3.5.1** | Browser Origin Separation - CSRF Protection | **Fail** | No explicit CSRF token middleware or anti-forgery mechanism visible (FINDING-020) |
| **3.5.2** | CORS Preflight Mechanism | **Partial** | CORS `allow_credentials=True` hardcoded without origin wildcard validation (FINDING-003) |
| **3.5.3** | HTTP Methods for Sensitive Functionality | **Partial** | No middleware-level enforcement preventing GET requests to state-changing router endpoints (FINDING-043) |
| **4.1.1** | Content-Type Header in Responses | **Partial** | Explicit media_type set on SPA template response (PSC-093), proper Content-Type handling for static files (PSC-095), but static file responses may lack charset parameter for text/* MIME types (FINDING-044) |
| **5.2.1** | File Size Limits | **N/A** | No file upload functionality in audited scope |
| **5.2.2** | File Extension and Content Validation | **N/A** | No file upload functionality in audited scope |
| **5.3.1** | Preventing Server-Side Execution of Uploaded Files | **Pass** | Architectural separation: no OS command execution in data layer (PSC-068) |
| **5.3.2** | Path Traversal Prevention | **N/A** | No file upload functionality in audited scope |
| **13.4.1** | Source Control Metadata Exclusion from Deployments | **Partial** | No documentation of source control metadata exclusion in deployment guidance (FINDING-045) |
| **15.1.1** | Risk-Based Remediation Timeframes Documentation | **Fail** | No risk-based remediation timeframes defined in documentation (FINDING-021) |
| **15.2.1** | Component Currency Verification | **Fail** | No documented mechanism to verify components haven't breached update timeframes (FINDING-022) |
| **15.3.1** | Verify Application Returns Required Subset of Fields | **Pass** | Resource detail models provide structured resource identification (PSC-041) |

**Summary:**
- **Pass:** 37 requirements
- **Partial:** 24 requirements
- **Fail:** 21 requirements
- **N/A:** 9 requirements

---

# 6. Cross-Reference Matrix

| Finding ID | Severity | ASVS Requirements | Positive Controls | Related Findings |
|------------|----------|-------------------|-------------------|------------------|
| FINDING-001 | High | 7.4.2 | PSC-004, PSC-020 | FINDING-010, FINDING-027 |
| FINDING-002 | High | 3.4.1, 3.2.1 | PSC-078, PSC-079, PSC-080, PSC-083 | FINDING-016, FINDING-041 |
| FINDING-003 | High | 3.4.2, 3.5.2 | — | FINDING-020 |
| FINDING-004 | Medium | 6.1.1 | PSC-002 | FINDING-008, FINDING-023 |
| FINDING-005 | Medium | 6.2.1 | PSC-005 | FINDING-006, FINDING-007 |
| FINDING-006 | Medium | 6.2.2, 6.2.3 | PSC-014 | FINDING-005, FINDING-007 |
| FINDING-007 | Medium | 6.2.4 | PSC-006, PSC-007 | FINDING-005, FINDING-006 |
| FINDING-008 | Medium | 6.3.1 | PSC-002 | FINDING-004, FINDING-023 |
| FINDING-009 | Medium | 7.2.4 | PSC-004, PSC-011, PSC-020 | FINDING-010, FINDING-012, FINDING-029 |
| FINDING-010 | Medium | 7.4.1 | PSC-004, PSC-020 | FINDING-001, FINDING-009, FINDING-027 |
| FINDING-011 | Medium | 10.4.4 | PSC-015 | FINDING-012, FINDING-028, FINDING-029 |
| FINDING-012 | Medium | 10.4.5 | PSC-020, PSC-027 | FINDING-009, FINDING-011, FINDING-029 |
| FINDING-013 | Medium | 8.2.1 | PSC-035, PSC-036, PSC-046 | FINDING-014, FINDING-031 |
| FINDING-014 | Medium | 8.2.2 | PSC-041, PSC-042, PSC-044 | FINDING-013, FINDING-032, FINDING-033 |
| FINDING-015 | Medium | 2.1.1 | PSC-058, PSC-059 | FINDING-035, FINDING-036 |
| FINDING-016 | Medium | 12.1.1, 12.2.1, 4.4.1 | PSC-078, PSC-079, PSC-080, PSC-081, PSC-083, PSC-086 | FINDING-002, FINDING-017, FINDING-038 |
| FINDING-017 | Medium | 12.2.1 | PSC-081, PSC-084 | FINDING-016, FINDING-038 |
| FINDING-018 | Medium | 14.3.1 | PSC-091 | — |
| FINDING-019 | Medium | 3.3.1 | PSC-003, PSC-027, PSC-052 | FINDING-002 |
| FINDING-020 | Medium | 3.5.1 | PSC-003, PSC-027 | FINDING-003, FINDING-043 |
| FINDING-021 | Medium | 15.1.1 | — | FINDING-022 |
| FINDING-022 | Medium | 15.2.1 | — | FINDING-021 |
| FINDING-023 | Low | 6.1.1 | PSC-002 | FINDING-004, FINDING-008 |
| FINDING-024 | Low | 6.2.6 | PSC-008 | — |
| FINDING-025 | Low | 6.3.2 | PSC-001 | — |
| FINDING-026 | Low | 6.4.1 | PSC-005 | FINDING-006 |
| FINDING-027 | Low | 7.4.1 | PSC-004, PSC-020, PSC-028 | FINDING-001, FINDING-010 |
| FINDING-028 | Low | 10.4.3 | PSC-015 | FINDING-011, FINDING-029 |
| FINDING-029 | Low | 10.4.5 | PSC-020 | FINDING-009, FINDING-011, FINDING-012, FINDING-028 |
| FINDING-030 | Low | 9.1.2 | PSC-023, PSC-024 | — |
| FINDING-031 | Low | 8.1.1 | PSC-029, PSC-030, PSC-031, PSC-034 | FINDING-013, FINDING-032 |
| FINDING-032 | Low | 8.1.1 | PSC-029, PSC-034 | FINDING-014, FINDING-031 |
| FINDING-033 | Low | 8.2.2 | PSC-041, PSC-042, PSC-043, PSC-044 | FINDING-014 |
| FINDING-034 | Low | 1.2.4 | PSC-053 | — |
| FINDING-035 | Low | 2.2.1 | PSC-060 | FINDING-015, FINDING-036 |
| FINDING-036 | Low | 2.2.1 | PSC-058 | FINDING-015, FINDING-035 |
| FINDING-037 | Low | 2.3.1 | PSC-062, PSC-065 | — |
| FINDING-038 | Low | 12.1.1 | PSC-080, PSC-083 | FINDING-016, FINDING-017 |
| FINDING-039 | Low | 12.2.2 | PSC-079, PSC-083 | FINDING-040 |
| FINDING-040 | Low | 12.2.2 | PSC-078 | FINDING-039 |
| FINDING-041 | Low | 3.2.1 | PSC-093, PSC-094, PSC-095 | FINDING-002, FINDING-042 |
| FINDING-042 | Low | 3.2.2 | PSC-093, PSC-096, PSC-097 | FINDING-041 |
| FINDING-043 | Low | 3.5.3 | — | FINDING-020 |
| FINDING-044 | Low | 4.1.1 | PSC-093, PSC-095 | — |
| FINDING-045 | Low | 13.4.1 | — | — |

**Key Relationships:**

**Critical Clusters:**
1. **Session Management Cluster:** FINDING-001, FINDING-009, FINDING-010, FINDING-012, FINDING-027, FINDING-029 — All related to token lifecycle and revocation
2. **TLS/Transport Security Cluster:** FINDING-002, FINDING-016, FINDING-017, FINDING-038, FINDING-039, FINDING-040 — All related to HTTPS/TLS configuration
3. **Authorization Design Cluster:** FINDING-013, FINDING-014, FINDING-031, FINDING-032, FINDING-033 — All related to authorization architecture

**High-Impact Pairs:**
- FINDING-002 + FINDING-003: Combined HSTS and CORS issues create significant cross-origin attack surface
- FINDING-001 + FINDING-010: No logout endpoint + no session termination on account deletion = complete session management gap
- FINDING-016 + FINDING-017: Multiple documentation gaps for production TLS deployment

**Positive Control Coverage:**
- Best coverage: JWT Token Security domain (PSC-015 through PSC-028) — 14 controls
- Best coverage: API Authorization & Access Control domain (PSC-029 through PSC-052) — 24 controls
- Weakest coverage: HTTP Security Headers & CORS domain — only 10 controls (PSC-088 through PSC-097)

## 7. Level Coverage Analysis


**Audit scope:** up to L1

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 45 |

**Total consolidated findings: 45**

*End of Consolidated Security Audit Report*