# Security Issues

## Issue: FINDING-001 - Authentication documentation completely lacks rate limiting, anti-automation, and account lockout guidance
**Labels:** bug, security, priority:high, documentation, authentication

**Description:**

### Summary
The authentication documentation provides no guidance on rate limiting, anti-automation controls, or account lockout mechanisms, leaving deployments vulnerable to brute force attacks. The Simple Auth Manager implementation has no built-in protection against unlimited authentication attempts.

### Details
The authentication documentation (index.rst) covers auth manager architecture, user representation, authorization methods, JWT token management, and custom auth manager development but contains zero references to:
- Rate limiting for login endpoints
- Anti-automation controls (CAPTCHA, challenge-response)
- Adaptive response mechanisms (progressive delays, temporary lockout)
- Account lockout prevention (distinguishing legitimate users from attackers)
- Monitoring/alerting for brute force patterns

**Data Flow:**
```
Attacker → POST /auth/token → SimpleAuthManagerLogin.create_token() 
→ unlimited password attempts → no rate limiting or lockout
```

The domain context confirms this is a known architectural gap: "Rate limiting for login attempts must be configured at the deployment level as it's not enforced by the simple auth manager by default" but the documentation never communicates this to operators.

**Affected Files:**
- `airflow-core/docs/core-concepts/auth-manager/index.rst` (entire document)
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py` (lines 41-68)
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py` (lines 36-75)

### Remediation
1. **Add a dedicated security section to the auth manager documentation** covering:
   - **Rate Limiting and Brute Force Protection**: Deploy reverse proxy with rate limiting on POST /auth/token endpoint, configure max 5 failed login attempts per IP per minute, implement progressive delays, consider IP-based temporary blocking after 10 failed attempts
   - **Account Lockout Prevention**: Rate limit by IP address not username alone, use CAPTCHA challenges after N failed attempts, implement monitoring/alerting on authentication failure spikes, consider temporary lockout rather than permanent lockout
   - **Custom Auth Managers**: Implementing local password authentication should implement `max_failed_attempts` configuration, `lockout_duration` configuration, and failed attempt tracking per user and per IP

2. **Add a `get_rate_limit_config()` method** to the BaseAuthManager interface that returns rate limiting configuration for authentication endpoints with recommended values for `max_attempts_per_minute`, `lockout_threshold`, and `lockout_duration_seconds`.

### Acceptance Criteria
- [ ] Documentation includes dedicated "Security Considerations" section with rate limiting guidance
- [ ] Documentation specifies deployment-level requirements for brute force protection
- [ ] BaseAuthManager interface includes optional `get_rate_limit_config()` method
- [ ] Documentation includes example configurations for common reverse proxies (nginx, Apache)
- [ ] Test added verifying documentation completeness

### References
- ASVS 6.1.1: Verify that rate limiting is applied to authentication endpoints
- CWE: Not specified
- Source: 6.1.1.md

### Priority
**High** - L1 requirement, leaves all deployments vulnerable to credential stuffing and brute force attacks

---

## Issue: FINDING-002 - No rate limiting or brute force protection on authentication endpoints
**Labels:** bug, security, priority:high, authentication, brute-force

**Description:**

### Summary
Authentication endpoints allow unlimited login attempts with no application-level rate limiting, account lockout, progressive delays, or CAPTCHA mechanisms, enabling brute force attacks against user credentials.

### Details
An attacker can perform unlimited authentication attempts against the login endpoints without any application-level protection. The HTTP POST endpoints `/auth/token` and `/auth/token/cli` allow unlimited brute force attempts with no throttling.

Given that the Simple Auth Manager generates 16-character alphanumeric passwords, a targeted attack on known usernames could succeed if passwords are weak or if the attacker can enumerate through the limited character space at high speed.

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py` (lines 36-70)
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py` (lines 42-67, 96-107)

### Remediation
**Option 1: Add rate limiting middleware** to the login router using a library like `slowapi` with a limit of 5 attempts per minute per IP address.

**Option 2: Add progressive delay** after failed attempts in the service by tracking failed attempts per username with a 5-minute window and raising HTTP 429 after 5 failures.

**Long-term:** Define rate limiting interface in BaseAuthManager to provide a configurable rate limiting hook that all auth managers can leverage, enforced by framework middleware.

### Acceptance Criteria
- [ ] Rate limiting middleware implemented on authentication endpoints
- [ ] Configuration option added for rate limit thresholds
- [ ] HTTP 429 responses returned when rate limit exceeded
- [ ] Test added verifying rate limiting behavior
- [ ] Documentation updated with rate limiting configuration

### References
- ASVS 6.3.1: Verify that authentication rate limiting is implemented
- CWE: Not specified
- Source: 6.3.1.md

### Priority
**High** - L1 requirement, enables credential stuffing attacks

---

## Issue: FINDING-003 - System-generated passwords use non-cryptographic PRNG (random.choices)
**Labels:** bug, security, priority:high, cryptography, authentication

**Description:**

### Summary
The `_generate_password()` method uses Python's `random.choices()` which relies on the Mersenne Twister PRNG, making generated passwords predictable if the internal state can be determined.

### Details
The `_generate_password()` method in SimpleAuthManager uses `random.choices()` which is deterministic and predictable. If an attacker can observe any outputs from the same random instance or determine the internal state (624 consecutive 32-bit outputs), they can predict future passwords.

While the character space is reasonable (50^16 ≈ 2^90 combinations), the non-cryptographic nature of the PRNG means the actual entropy may be significantly lower than the theoretical maximum, especially if the process state can be inferred.

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py` (line 297)

### Remediation
Replace `random.choices()` with `secrets.choice()` from Python's `secrets` module:

```python
import secrets

@staticmethod
def _generate_password() -> str:
    alphabet = "abcdefghkmnpqrstuvwxyzABCDEFGHKMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(16))
```

### Acceptance Criteria
- [ ] `random.choices()` replaced with `secrets.choice()`
- [ ] Unit test added verifying password generation uses cryptographic randomness
- [ ] Documentation updated noting use of cryptographically secure PRNG
- [ ] Code review confirms no other uses of non-cryptographic random in security contexts

### References
- ASVS 6.4.1: Verify cryptographically strong random values are used
- CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
- Source: 6.4.1.md

### Priority
**High** - L1 requirement, weakens password strength significantly

---

## Issue: FINDING-004 - System-generated initial passwords never expire and become permanent credentials
**Labels:** bug, security, priority:high, authentication, password-management

**Description:**

### Summary
Generated initial passwords are stored with no expiration timestamp or mechanism to force password change after first use, allowing disclosed passwords to remain valid indefinitely.

### Details
Generated initial passwords are stored as plain key-value pairs in a JSON file with no associated creation timestamp or expiry. There is no mechanism to:
- Detect whether a password has been used
- Force a change after initial use
- Provide an endpoint or CLI command for users to change passwords

Once written to the JSON file, passwords remain valid indefinitely until the file is manually deleted or the server is reconfigured. If a password is disclosed (e.g., from logs, console output, or file access), it remains valid indefinitely with no mechanism for rotation or forced change.

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py` (lines 128-148)

### Remediation
Implement password expiration with creation timestamps and validation:

```python
import time
import secrets

@staticmethod
def _generate_password() -> tuple[str, float]:
    """Generate password with creation timestamp."""
    alphabet = "abcdefghkmnpqrstuvwxyzABCDEFGHKMNPQRSTUVWXYZ23456789"
    password = "".join(secrets.choice(alphabet) for _ in range(16))
    return password, time.time()

# In create_token validation:
def create_token(body: LoginBody, ...) -> str:
    # ... existing validation ...
    password_entry = passwords[body.username]
    if isinstance(password_entry, dict):
        created_at = password_entry.get("created_at", 0)
        max_age = conf.getint("core", "simple_auth_manager_password_max_age", fallback=86400)
        if time.time() - created_at > max_age:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Password has expired. Please contact your administrator.",
            )
```

### Acceptance Criteria
- [ ] Password generation includes creation timestamp
- [ ] Password validation checks expiration
- [ ] Configuration option added for password max age
- [ ] Test added verifying password expiration behavior
- [ ] Documentation updated with password lifecycle management

### References
- ASVS 6.4.1: Verify initial passwords expire after first use
- CWE-620: Unverified Password Change
- Source: 6.4.1.md

### Priority
**High** - L1 requirement, allows indefinite use of disclosed credentials

---

## Issue: FINDING-005 - Token revocation mechanism exists but is not enforced during token validation
**Labels:** bug, security, priority:high, session-management, authentication

**Description:**

### Summary
The application has a token revocation write mechanism (`revoke_token()`) but the validation method (`avalidated_claims()`) never checks the revocation list, allowing revoked tokens to remain usable until natural expiration.

### Details
**Data Flow:**
```
Logout/termination → revoke_token() writes jti to RevokedToken table 
→ subsequent request with same token → avalidated_claims() validates signature/expiration 
but NEVER queries RevokedToken table → token accepted as valid
```

This is a Type B control gap where the control EXISTS but is NOT CHECKED during validation. After logout, tokens remain usable until natural expiration.

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/tokens.py` (lines 260-290, 295-305)

### Remediation
Add revocation check to `avalidated_claims()` method:

```python
async def avalidated_claims(
    self, unvalidated: str, required_claims: dict[str, Any] | None = None
) -> dict[str, Any]:
    key = await self._get_validation_key(unvalidated)
    # ... existing validation ...
    claims = jwt.decode(
        unvalidated, validation_key, audience=self.audience,
        issuer=self.issuer, options={"require": list(self.required_claims)},
        algorithms=algorithms, leeway=self.leeway,
    )
    
    # Check revocation list
    jti = claims.get("jti")
    if jti and RevokedToken.is_revoked(jti):
        raise jwt.InvalidTokenError("Token has been revoked")
    
    # existing additional claims validation...
    return claims
```

**Additional recommendations:**
1. Implement per-user token invalidation timestamp (tokens_invalid_before column) for immediate session termination
2. Ensure account disable/delete workflow updates per-user invalidation timestamp
3. Consider token introspection cache (Redis-backed) for strict revocation without sacrificing scalability
4. Document security implications of token lifetime configuration
5. Consider adding user account status verification as optional check in avalidated_claims

### Acceptance Criteria
- [ ] Token validation checks revocation list
- [ ] Test added verifying revoked tokens are rejected
- [ ] Performance impact measured and documented
- [ ] Documentation updated with revocation behavior
- [ ] Integration test added for logout → token rejection flow

### References
- ASVS 7.4.1: Verify tokens are checked against revocation list
- CWE: Not specified
- Source: 7.4.1.md

### Priority
**High** - L1 requirement, allows continued access after logout

---

## Issue: FINDING-006 - No mechanism to invalidate all active sessions when a user account is disabled or deleted
**Labels:** bug, security, priority:high, session-management, authentication

**Description:**

### Summary
When an admin disables or deletes a user account, there is no mechanism to identify or invalidate all outstanding JWTs for that user, allowing disabled users to retain access until token expiration.

### Details
**Data Flow:**
```
Admin disables/deletes user account → NO mechanism to identify or invalidate all outstanding JWTs 
→ previously issued tokens remain valid until natural expiration → disabled user retains access
```

When an employee leaves the company or an account is compromised and disabled, all existing sessions for that user remain active until token expiration. This violates the principle that account termination should immediately prevent all access.

**Limitations:**
- The system has no record of which jti values belong to which user (tokens are stateless)
- `revoke_token()` requires the actual token string (admin doesn't have all user's tokens)
- Token validation (`avalidated_claims()`) doesn't check user account status

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/tokens.py` (JWTValidator class and JWTGenerator class)

### Remediation
**Option 1: Add per-user invalidation timestamp**
- Create a `UserTokenInvalidation` model with `user_id` and `tokens_invalid_before` timestamp
- In `JWTValidator.avalidated_claims`, check the per-user invalidation timestamp and reject tokens with `iat` before the invalidation timestamp
- In account disable/delete handler, set the per-user invalidation timestamp to `datetime.now()` so all tokens issued before this timestamp will be rejected

**Option 2: Alternative approaches**
- Implement token introspection cache (e.g., Redis-backed) for deployments requiring strict revocation
- Add user account status verification within `avalidated_claims`
- Implement per-user signing key rotation

### Acceptance Criteria
- [ ] Per-user invalidation timestamp mechanism implemented
- [ ] Token validation checks user invalidation timestamp
- [ ] Account disable/delete workflow updates invalidation timestamp
- [ ] Test added verifying disabled user tokens are rejected
- [ ] Documentation updated with session invalidation behavior

### References
- ASVS 7.4.2: Verify all sessions can be invalidated on account disable/delete
- CWE: Not specified
- Source: 7.4.2.md

### Priority
**High** - L1 requirement, allows access after account termination

---

## Issue: FINDING-007 - Authorization documentation lacks specification of default-deny behavior and handling of undefined/wildcard resource identifiers
**Labels:** bug, security, priority:high, documentation, authorization

**Description:**

### Summary
The authorization documentation defines the interface for function-level and data-specific access control but fails to specify the security contract for default-deny behavior, undefined resources, and wildcard operations.

### Details
The authorization documentation fails to specify:
1. What `is_authorized_*` methods MUST return when `details` is `None` (i.e., no specific resource identified) — should implementations default to deny?
2. Whether a deny-by-default policy is required for all custom auth manager implementations
3. How authorization methods should behave when resource identifiers cannot be resolved (e.g., non-existent DAG ID)
4. The security contract between the base framework (which passes `details=None` for wildcard/list operations in `requires_access_dag`) and the auth manager implementation

Auth manager implementors may create overly permissive implementations due to ambiguous documentation, leading to unauthorized function-level and data-level access across the deployment.

**Affected Files:**
- `airflow-core/docs/core-concepts/auth-manager/index.rst` (lines 95-117)
- `base_auth_manager.py` (lines 179-191)
- `security.py` (line 136)

### Remediation
Add explicit security contracts to the documentation:

```rst
Security Requirements for Authorization Methods
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

All ``is_authorized_*`` methods MUST follow these rules:

* **Default Deny**: If the ``details`` parameter is ``None`` or any identifying field 
  within details is ``None``, implementations MUST return ``False`` for mutating operations 
  (``POST``, ``PUT``, ``DELETE``). For ``GET`` operations, returning ``True`` with 
  ``details=None`` is acceptable only when paired with result filtering 
  (e.g., ``filter_authorized_dag_ids``).
* **Unknown Resources**: If a resource identifier does not exist in the backing store, 
  the method MUST return ``False``.
* **Deny by Default**: Unless a user has been explicitly granted permission, 
  access MUST be denied.
```

### Acceptance Criteria
- [ ] Documentation includes explicit security contract for authorization methods
- [ ] Documentation specifies default-deny requirements
- [ ] Documentation includes examples of correct and incorrect implementations
- [ ] Test added verifying documentation completeness
- [ ] Security review of existing auth manager implementations

### References
- ASVS 8.1.1: Verify authorization controls default to deny
- CWE: Not specified
- Source: 8.1.1.md

### Priority
**High** - L1 requirement, ambiguous documentation leads to insecure implementations

---

## Issue: FINDING-009 - Missing /auth prefix in RESERVED_URL_PREFIXES allows plugin route shadowing
**Labels:** bug, security, priority:high, api-security, plugins

**Description:**

### Summary
The RESERVED_URL_PREFIXES list does not include `/auth` or `/pluginsv2`, allowing malicious plugins to register routes that shadow authentication endpoints and intercept credentials.

### Details
The RESERVED_URL_PREFIXES list in app.py does not include `/auth` or `/pluginsv2`, creating a gap where plugins could register routes that shadow authentication endpoints. The initialization order (init_plugins before init_auth_manager) creates a window where plugin routes at `/auth` could be registered before the auth manager mounts its routes.

Since Starlette matches routes in registration order, a malicious plugin installed via pip can mount at `url_prefix="/auth"` and intercept authentication requests, enabling credential theft or forged token issuance.

**Data Flow:**
```
Plugin url_prefix value → RESERVED_URL_PREFIXES validation (missing /auth) 
→ app.mount(url_prefix, subapp) → shadows auth manager routes
```

**Gap Type:** Control EXISTS (RESERVED_URL_PREFIXES validation) but NOT APPLIED to the /auth path.

**Affected Files:**
- `core_api/app.py` (line 56)
- `airflow-core/src/airflow/api_fastapi/app.py` (lines 56-57, 160-182, 185-187, 99-101, 172-211)

### Remediation
**Immediate:** Add `/auth` and `/pluginsv2` to the RESERVED_URL_PREFIXES list:

```python
RESERVED_URL_PREFIXES = ["/api/v2", "/ui", "/execution", "/auth", "/pluginsv2"]
```

**Alternative:** Derive reserved prefixes dynamically:
```python
RESERVED_URL_PREFIXES = [
    "/api/v2", "/ui", "/execution",
    AUTH_MANAGER_FASTAPI_APP_PREFIX.removeprefix(API_ROOT_PATH.rstrip("/"))
]
```

**Short-term:**
- Consider mounting the auth manager BEFORE plugins
- Add post-mount verification that no plugin routes shadow critical system paths
- Add integration test verifying plugins cannot mount at reserved prefixes

**Long-term:**
- Implement plugin capability/permission system restricting route prefix registration
- Require explicit approval for security-sensitive operations

### Acceptance Criteria
- [ ] `/auth` and `/pluginsv2` added to RESERVED_URL_PREFIXES
- [ ] Test added verifying plugin cannot register at reserved prefixes
- [ ] Integration test added for route shadowing prevention
- [ ] Documentation updated with plugin security guidelines
- [ ] Security review of plugin system architecture

### References
- ASVS 1.2.1, 1.2.2, 2.2.1: Verify authentication mechanisms cannot be bypassed
- CWE: Not specified
- Source: 1.2.1.md, 1.2.2.md, 2.2.1.md

### Priority
**High** - L1 requirement, enables credential theft and authentication bypass

---

## Issue: FINDING-010 - No Security Headers Middleware for Content Interpretation Prevention
**Labels:** bug, security, priority:high, web-security, middleware

**Description:**

### Summary
The middleware stack lacks security headers middleware to prevent content type sniffing, enforce CSP, and protect against clickjacking, leaving the application vulnerable to XSS and content injection attacks.

### Details
The middleware stack is fully defined in `init_middlewares` and `init_config`, yet no security headers middleware is registered. Without proper security headers:

- **X-Content-Type-Options: nosniff** - Browsers may interpret API responses (JSON) or user-uploaded files as HTML, enabling XSS
- **Content-Security-Policy** - Injected content can execute scripts
- **X-Frame-Options** - Application can be embedded in malicious iframes
- **Sec-Fetch-*** validation - API endpoints can be navigated to directly in browser context

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/core_api/app.py` (lines 158-173)

### Remediation
Add SecurityHeadersMiddleware to the middleware stack:

```python
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
        )
        response.headers["X-Frame-Options"] = "DENY"
        return response

def init_middlewares(app: FastAPI) -> None:
    # ... existing middleware ...
    app.add_middleware(SecurityHeadersMiddleware)
```

### Acceptance Criteria
- [ ] SecurityHeadersMiddleware implemented and registered
- [ ] X-Content-Type-Options header set to nosniff
- [ ] Content-Security-Policy header configured
- [ ] X-Frame-Options header set to DENY
- [ ] Test added verifying security headers presence
- [ ] Documentation updated with security headers configuration

### References
- ASVS 3.2.1: Verify security headers prevent content interpretation attacks
- CWE: Not specified
- Source: 3.2.1.md

### Priority
**High** - L1 requirement, enables XSS and clickjacking attacks

---

## Issue: FINDING-011 - Cookie Path Utility Lacks Secure Attribute and Name Prefix Enforcement
**Labels:** bug, security, priority:high, web-security, cookies

**Description:**

### Summary
The application uses cookies for authentication but lacks centralized enforcement of the Secure attribute or `__Host-`/`__Secure-` prefixes, allowing cookies to be transmitted over unencrypted connections and vulnerable to subdomain attacks.

### Details
The application uses cookies for authentication (confirmed by `get_cookie_path()` utility and JWTRefreshMiddleware), but lacks centralized enforcement of:

- **Secure attribute** - Cookies may be transmitted over unencrypted HTTP connections, enabling session hijacking via network sniffing
- **__Host-/__Secure- prefix** - Cookies may be set by subdomain attackers or over insecure connections

The architecture provides path scoping but omits security attribute enforcement.

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/app.py` (lines 49-55)

### Remediation
Create a centralized cookie creation utility that enforces required security attributes:

```python
def create_secure_cookie(
    key: str,
    value: str,
    path: str = "/",
    max_age: int | None = None,
    httponly: bool = True,
    samesite: str = "lax"
) -> dict:
    """Create a secure cookie with enforced security attributes."""
    # Use __Host- prefix when path is '/' or __Secure- otherwise
    prefix = "__Host-" if path == "/" else "__Secure-"
    cookie_name = f"{prefix}{key}"
    
    return {
        "key": cookie_name,
        "value": value,
        "path": path,
        "max_age": max_age,
        "secure": True,  # Always enforce
        "httponly": httponly,
        "samesite": samesite
    }
```

Update JWTRefreshMiddleware and auth managers to use this utility instead of setting cookies directly.

### Acceptance Criteria
- [ ] Centralized secure cookie creation utility implemented
- [ ] Secure attribute enforced on all authentication cookies
- [ ] __Host- or __Secure- prefix enforced on all cookies
- [ ] JWTRefreshMiddleware updated to use secure cookie utility
- [ ] Test added verifying cookie security attributes
- [ ] Documentation updated with cookie security requirements

### References
- ASVS 3.3.1: Verify cookies use Secure attribute and security prefixes
- CWE: Not specified
- Source: 3.3.1.md

### Priority
**High** - L1 requirement, enables session hijacking and subdomain attacks

---

## Issue: FINDING-012 - No Strict-Transport-Security Header Configured in Application Middleware
**Labels:** bug, security, priority:high, web-security, middleware

**Description:**

### Summary
The application middleware stack does not include any middleware to add the Strict-Transport-Security (HSTS) header, leaving the application vulnerable to SSL stripping attacks and protocol downgrade.

### Details
The application middleware stack does not include any middleware to add the Strict-Transport-Security header to HTTP responses. Both the `init_middlewares` and `init_config` functions lack HSTS implementation.

**Without HSTS, the application is vulnerable to:**
- SSL stripping attacks (MITM downgrades HTTPS to HTTP)
- Users accessing the application over HTTP if they type the URL without https://
- Cookie theft during the initial HTTP request before redirect to HTTPS
- Protocol downgrade on first visit

ASVS 3.4.1 requires a minimum max-age of 1 year (31536000 seconds) and for L2+, the policy must apply to all subdomains.

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/core_api/app.py` (lines 158-173, 134-148)

### Remediation
Create and add an HSTSMiddleware to the middleware stack:

```python
from starlette.middleware.base import BaseHTTPMiddleware

class HSTSMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        return response

def init_middlewares(app: FastAPI) -> None:
    # ... existing middleware ...
    app.add_middleware(HSTSMiddleware)
```

### Acceptance Criteria
- [ ] HSTSMiddleware implemented and registered
- [ ] Strict-Transport-Security header set with max-age=31536000
- [ ] includeSubDomains directive included
- [ ] Test added verifying HSTS header presence
- [ ] Documentation updated with HSTS configuration
- [ ] Consider adding preload directive for L2+ deployments

### References
- ASVS 3.4.1: Verify HSTS header with minimum 1 year max-age
- CWE: Not specified
- Source: 3.4.1.md

### Priority
**High** - L1/L2 requirement, enables SSL stripping and protocol downgrade attacks

---

## Issue: FINDING-014 - No Explicit CSRF Protection Middleware in Base Application Framework
**Labels:** bug, security, priority:high, web-security, csrf

**Description:**

### Summary
The application uses cookie-based authentication but lacks mechanisms to ensure all state-changing requests trigger CORS preflight, allowing simple cross-origin requests to bypass CORS protection and execute authenticated operations.

### Details
The application uses cookie-based authentication with `allow_credentials=True` in CORS configuration, but does not enforce mechanisms to ensure all state-changing requests trigger CORS preflight.

**The CORSMiddleware is purely reactive** and does not block 'simple' requests. A simple cross-origin request (e.g., POST with Content-Type: application/x-www-form-urlencoded) will:
1. Bypass CORS preflight entirely
2. Include session cookies automatically
3. Be authenticated by the server
4. Execute state-changing operations

**No additional defense layer is visible:**
- No CSRF token middleware
- No mandatory custom header that would force preflight
- No Origin or Sec-Fetch-* header validation middleware
- No Content-Type enforcement at middleware level

The auth manager at `/auth` is particularly vulnerable as authentication endpoints commonly accept form-encoded POST bodies which are simple requests.

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/core_api/app.py` (lines 158-173)
- `airflow-core/src/airflow/api_fastapi/app.py` (lines 79-110)

### Remediation
**Option 1: Require custom header** that forces preflight:

```python
class CSRFPreflightMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method in ["POST", "PUT", "DELETE", "PATCH"]:
            # Require custom header that forces preflight
            if not request.headers.get("X-Requested-With"):
                raise HTTPException(status_code=403, detail="Missing required header")
            
            # Validate Sec-Fetch-Site header as defense-in-depth
            sec_fetch_site = request.headers.get("Sec-Fetch-Site")
            if sec_fetch_site == "cross-site":
                raise HTTPException(status_code=403, detail="Cross-site requests not allowed")
        
        return await call_next(request)
```

**Option 2: Validate Origin header:**

```python
class OriginValidationMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, allowed_origins: list[str]):
        super().__init__(app)
        self.allowed_origins = set(allowed_origins)
    
    async def dispatch(self, request: Request, call_next):
        if request.method in ["POST", "PUT", "DELETE", "PATCH"]:
            origin = request.headers.get("Origin")
            if origin and origin not in self.allowed_origins:
                raise HTTPException(status_code=403, detail="Invalid origin")
        
        return await call_next(request)
```

**Also ensure:**
- SameSite=Lax (minimum) or SameSite=Strict is set on all authentication cookies
- Implement Sec-Fetch-* header validation middleware as defense-in-depth

### Acceptance Criteria
- [ ] CSRF protection middleware implemented
- [ ] Custom header requirement or Origin validation enforced
- [ ] SameSite attribute set on authentication cookies
- [ ] Sec-Fetch-* header validation added
- [ ] Test added verifying CSRF protection
- [ ] Test added verifying simple requests are blocked
- [ ] Documentation updated with CSRF protection mechanism

### References
- ASVS 3.5.1, 3.5.2: Verify CSRF protection on state-changing operations
- CWE-352: Cross-Site Request Forgery (CSRF)
- Source: 3.5.1.md, 3.5.2.md

### Priority
**High** - L1 requirement, enables CSRF attacks on all state-changing operations

---

## Issue: FINDING-015 - Documentation explicitly disclaims risk-based remediation timeframes for third-party dependency vulnerabilities
**Labels:** bug, security, priority:high, documentation, dependencies

**Description:**

### Summary
ASVS 15.1.1 requires documented risk-based remediation timeframes for third-party vulnerabilities, but the documentation explicitly states "we do not provide any guarantees that we will upgrade to dependencies that are CVE-free."

### Details
ASVS 15.1.1 requires that application documentation defines risk-based remediation timeframes (e.g., Critical: 48 hours, High: 7 days, Medium: 30 days, Low: 90 days) for addressing vulnerabilities in third-party components.

**The provided documentation explicitly contradicts this requirement:**

1. `releasing_security_patches.rst` describes the mechanism of releasing patches (SemVer PATCHLEVEL releases) but defines no timeframes based on vulnerability severity
2. `vulnerabilities-in-3rd-party-dependencies.rst` explicitly states "we do not provide any guarantees that we will upgrade to dependencies that are CVE-free" — directly contradicting the requirement for defined remediation timeframes
3. `sbom.rst` documents dependency inventory capabilities but contains no remediation timeframe policy

**What is missing:**
- Critical severity CVE (CVSS ≥ 9.0): remediate within X days
- High severity CVE (CVSS 7.0-8.9): remediate within Y days
- Medium severity CVE (CVSS 4.0-6.9): remediate within Z days
- Low severity CVE (CVSS < 4.0): remediate within W days
- General library update cadence for non-vulnerable updates

**Impact:**
Without defined remediation timeframes, there is no measurable standard against which to hold dependency updates accountable. Deployments may unknowingly run with exploitable vulnerabilities indefinitely. Operators have no SLA-based expectation for when patches will be available.

**Affected Files:**
- `airflow-core/docs/security/vulnerabilities-in-3rd-party-dependencies.rst` (lines 28-35)

### Remediation
Create a dedicated security policy document defining risk-based remediation timeframes:

```rst
Remediation Timeframes for 3rd-Party Vulnerabilities
-----------------------------------------------------

When a vulnerability in a third-party dependency is confirmed to be exploitable
in the context of Apache Airflow, the following remediation timeframes apply:

* **Critical** (CVSS >= 9.0, actively exploited): Patch release within 72 hours
* **High** (CVSS 7.0-8.9): Patch release within 14 days
* **Medium** (CVSS 4.0-6.9): Addressed in next scheduled PATCHLEVEL release
* **Low** (CVSS < 4.0): Addressed in next scheduled MINOR release

For general library maintenance (non-vulnerability-driven):

* Dependencies with available updates should be evaluated monthly
* Dependencies at end-of-life must be replaced within 90 days of EOL announcement
* Dependencies with no maintenance activity for 12+ months must be assessed for replacement

These timeframes begin from the date a vulnerability is confirmed exploitable
in an Airflow deployment context, not from CVE publication date.
```

### Acceptance Criteria
- [ ] Remediation timeframe policy documented
- [ ] Policy includes severity-based SLAs
- [ ] Policy includes general maintenance cadence
- [ ] Policy includes EOL dependency handling
- [ ] Test added verifying documentation completeness
- [ ] Security team review and approval

### References
- ASVS 15.1.1: Verify documentation defines remediation timeframes
- CWE: Not specified
- Source: 15.1.1.md

### Priority
**High** - L1 requirement, lack of policy allows indefinite vulnerable dependency retention

---

## Issue: FINDING-016 - Documentation explicitly acknowledges retention of known-vulnerable components without defined compliance criteria
**Labels:** bug, security, priority:high, documentation, dependencies, compliance

**Description:**

### Summary
ASVS 15.2.1 requires verification that all components are within their documented update and remediation timeframes, but the documentation explicitly acknowledges that vulnerable components are retained in released versions with no compliance mechanism.

### Details
ASVS 15.2.1 requires verification that all application components are within their documented update and remediation timeframes. This requirement depends on 15.1.1 being satisfied (having defined timeframes).

**The documentation reveals a dual failure:**

1. **No timeframes are defined** (15.1.1 gap), making compliance impossible to measure
2. **The documentation explicitly acknowledges that vulnerable components are retained** in released versions, with the explanation being resource constraints rather than risk-based decisions

**Additional issues:**
- When a new MINOR version is released, PATCHLEVEL releases stop for the previous MINOR version, meaning users on older MINOR versions receive NO security updates regardless of vulnerability severity
- Constraint files are explicitly stated as NOT being updated post-release
- Container images are not republished with updated dependencies
- The project places the burden on users to track and update vulnerable dependencies themselves

**Affected Files:**
- `airflow-core/docs/security/vulnerabilities-in-3rd-party-dependencies.rst` (lines 30-35, 43-45)
- `airflow-core/docs/security/releasing_security_patches.rst`

### Remediation
1. **Define remediation timeframes** (addresses prerequisite 15.1.1)
2. **Implement automated compliance verification** in the CI/CD pipeline using tools like Anchore scan-action to scan dependencies for CVEs and check remediation timeframe compliance against defined policies
3. **Document exceptions explicitly** when components cannot be updated within timeframes:

```rst
Exception Management
--------------------

When a dependency cannot be updated within the defined timeframe due to
breaking changes or compatibility issues, the following process applies:

1. Document the exception with justification
2. Identify and document compensating controls
3. Set a review date for re-evaluation

+----------------+---------------+-------------------+----------------------+--------------+
| Component      | CVE           | Exception Reason  | Compensating Control | Review Date  |
+================+===============+===================+======================+==============+
| library-x      | CVE-2024-1234 | Breaking changes  | Input validation     | 2024-12-31   |
+----------------+---------------+-------------------+----------------------+--------------+
```

4. **Automate post-release constraint file updates** for critical/high severity CVE fixes
5. **Implement periodic container image rebuilds** for supported releases incorporating dependency security updates
6. **Create a dependency risk classification system** with enhanced monitoring and faster remediation requirements

### Acceptance Criteria
- [ ] Remediation timeframes defined (see FINDING-015)
- [ ] Automated compliance verification implemented in CI/CD
- [ ] Exception documentation process established
- [ ] Post-release update mechanism implemented for critical/high CVEs
- [ ] Container image rebuild process implemented
- [ ] Dependency risk classification system documented
- [ ] Test added verifying compliance automation
- [ ] Documentation updated with compliance process

### References
- ASVS 15.2.1: Verify components are within remediation timeframes
- CWE: Not specified
- Source: 15.2.1.md

### Priority
**High** - L1 requirement, lack of compliance mechanism allows indefinite vulnerable component retention