# Security Issues

## Issue: FINDING-001 - No Mechanism to Terminate All Sessions on User Account Deletion
**Labels:** bug, security, priority:high
**Description:**
### Summary
The authentication system does not verify user existence during JWT token validation. When a user account is deleted, all previously-issued JWT tokens remain valid until natural expiration, potentially allowing unauthorized access by terminated users for up to 24 hours.

### Details
The `get_user_from_token()` method in BaseAuthManager validates JWT signature and checks individual token revocation, but does not verify that the user referenced in the token payload still exists or is active. The SimpleAuthManager.deserialize_user() constructs a user object directly from the JWT payload without consulting the current user configuration.

**Attack Scenario:**
1. User account is deleted from configuration
2. User's previously-issued JWT tokens remain cryptographically valid
3. Deleted user retains full access based on role encoded in JWT
4. Access continues until token expiration (up to 24 hours default)

**Impact:**
- Unauthorized access to sensitive DAG configurations
- Execution of workflows by terminated employees
- Data exfiltration through API endpoints
- Privilege escalation if user's role was downgraded before deletion

### Remediation
**Option A:** Add bulk revocation method to BaseAuthManager
```python
def revoke_all_user_tokens(self, user_id: str) -> None:
    """Revoke all tokens for a given user."""
    RevokedToken.revoke_all_for_user(user_id)
```

**Option B:** Add user existence check during token validation
```python
async def get_user_from_token(self, token: str) -> BaseUser:
    payload = await self._get_token_validator().avalidated_claims(token)
    
    # Check user still exists and is active
    if not self.is_user_active(payload.get("sub")):
        raise InvalidTokenError("User account no longer exists or is inactive")
    
    return self.deserialize_user(payload)
```

**Immediate action:** Modify SimpleAuthManager.deserialize_user() to check the user still exists in current configuration and use current role from config rather than token role.

### Acceptance Criteria
- [ ] User existence check added to token validation flow
- [ ] Deleted users' tokens are rejected with appropriate error
- [ ] Test added for deleted user token rejection
- [ ] Documentation updated with session termination behavior
- [ ] Audit log entry created when deleted user token is rejected

### References
- ASVS 7.4.2: Session termination must invalidate all tokens
- CWE-613: Insufficient Session Expiration
- Files: `airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py`, `airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py`

### Priority
**High** - Allows unauthorized access by deleted users until token expiration

---

## Issue: FINDING-002 - No Strict-Transport-Security (HSTS) header in middleware stack
**Labels:** bug, security, priority:high
**Description:**
### Summary
The FastAPI application does not set the `Strict-Transport-Security` (HSTS) header, leaving users vulnerable to SSL stripping attacks where connections can be downgraded from HTTPS to HTTP.

### Details
The middleware initialization function in `app.py` registers multiple middlewares (`JWTRefreshMiddleware`, `GZipMiddleware`, `HttpAccessLogMiddleware`) but none set the HSTS header. While auth managers can return custom middlewares via `get_fastapi_middlewares()`, HSTS should be enforced at the application level regardless of auth manager choice.

**Attack Scenario:**
1. User visits Airflow for the first time (no HSTS cache)
2. Attacker performs MITM attack with SSL stripping
3. Connection is downgraded to HTTP
4. Credentials and session tokens transmitted in cleartext
5. Attacker captures authentication credentials

**Impact:**
- Credential theft during first visit or after HSTS expiration
- Session hijacking via intercepted JWT tokens
- Content injection in downgraded HTTP responses

### Remediation
Implement an HSTS middleware that adds the header to all responses:

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

# In init_middlewares():
app.add_middleware(HSTSMiddleware, max_age=31536000, include_subdomains=True)
```

### Acceptance Criteria
- [ ] HSTS middleware implemented and registered
- [ ] Header includes `max-age` of at least 1 year (31536000 seconds)
- [ ] `includeSubDomains` directive included
- [ ] Test added verifying HSTS header presence on all responses
- [ ] Documentation updated with HSTS configuration options

### References
- ASVS 3.4.1, 3.2.1: HSTS required with minimum 1 year max-age
- CWE-319: Cleartext Transmission of Sensitive Information
- File: `airflow-core/src/airflow/api_fastapi/core_api/app.py` (lines 172-189)

### Priority
**High** - Enables SSL stripping attacks against first-time users

---

## Issue: FINDING-003 - CORS allow_credentials=True hardcoded without origin wildcard validation
**Labels:** bug, security, priority:high
**Description:**
### Summary
The CORS middleware configuration hardcodes `allow_credentials=True` without validating that the configured origins list doesn't contain wildcards. If an administrator sets `access_control_allow_origins = *`, any origin can make credentialed cross-origin requests.

### Details
The `allow_credentials=True` flag is unconditionally set regardless of configured origins. When combined with `allow_origins=['*']`, Starlette's CORSMiddleware reflects the requesting `Origin` header and includes `Access-Control-Allow-Credentials: true`, effectively allowing ANY origin to make authenticated requests.

**Attack Scenario:**
1. Administrator misconfigures: `access_control_allow_origins = *`
2. Attacker hosts malicious site at `evil.com`
3. Victim visits `evil.com` while authenticated to Airflow
4. Malicious JavaScript makes credentialed API requests
5. Airflow reflects `Access-Control-Allow-Origin: https://evil.com` with `Access-Control-Allow-Credentials: true`
6. Attacker exfiltrates data or executes state-changing operations

**Impact:**
- Cross-origin data theft from authenticated users
- CSRF-like attacks executing state-changing operations
- Privilege escalation via API manipulation

### Remediation
Add validation to reject wildcard origins when credentials are enabled:

```python
def init_cors(app: FastAPI) -> None:
    origins = conf.get("api_auth", "access_control_allow_origins", fallback=None)
    if origins:
        origins_list = [origin.strip() for origin in origins.split(",")]
        
        # Validate no wildcards when credentials enabled
        if "*" in origins_list:
            raise ValueError(
                "CORS configuration error: allow_credentials=True cannot be used with "
                "allow_origins=['*']. Specify explicit trusted origins."
            )
        
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins_list,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
```

Additionally, implement preflight enforcement middleware to reject state-changing requests without proper CORS preflight characteristics.

### Acceptance Criteria
- [ ] Wildcard origin validation added to CORS initialization
- [ ] Application startup fails with clear error if wildcard + credentials configured
- [ ] Test added for wildcard validation
- [ ] Documentation updated warning against wildcard origins
- [ ] Preflight enforcement middleware implemented for state-changing operations

### References
- ASVS 3.4.2, 3.5.2: CORS configuration must not allow wildcard with credentials
- CWE-346: Origin Validation Error
- File: `airflow-core/src/airflow/api_fastapi/core_api/app.py` (lines 148-162)

### Priority
**High** - Enables cross-origin attacks if misconfigured

---

## Issue: FINDING-004 - Missing Documentation of Rate Limiting and Anti-Automation Controls for Login Endpoints
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The authentication documentation does not describe how to configure rate limiting, anti-automation defenses (CAPTCHA, progressive delays), or account lockout prevention for authentication endpoints, leaving deployments vulnerable to credential stuffing and brute force attacks.

### Details
The authentication documentation covers pluggable auth manager architecture, authorization methods, JWT token management, and role configuration, but contains no guidance on:
- Rate limiting configuration for authentication endpoints
- Anti-automation defenses (CAPTCHA, progressive delays, IP blocking)
- Adaptive response mechanisms (challenge escalation)
- Account lockout prevention strategies
- Credential stuffing defenses

Without documented guidance, deployment managers may not configure these essential controls.

### Remediation
Add a dedicated security section to the auth-manager documentation:

```rst
Protecting Authentication Endpoints
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Airflow relies on deployment-level infrastructure for rate limiting and anti-automation
controls on authentication endpoints. The following controls MUST be configured for
production deployments:

**Rate Limiting:**
Configure your reverse proxy (nginx, HAProxy, cloud load balancer) to limit
authentication requests. Recommended: 5 attempts per minute per IP for
``POST /auth/token``.

Example nginx configuration:

.. code-block:: nginx

    limit_req_zone $binary_remote_addr zone=auth_limit:10m rate=5r/m;
    
    location /auth/token {
        limit_req zone=auth_limit burst=2 nodelay;
        proxy_pass http://airflow_backend;
    }

**Account Lockout Prevention:**
When using auth managers that support lockout (e.g. FAB with LDAP), configure
``AUTH_MAX_LOGIN_ATTEMPTS`` and ``AUTH_LOGIN_LOCKOUT_DURATION``. Ensure legitimate
users are not permanently locked out by setting reasonable lockout duration
(e.g., 15 minutes after 5 failed attempts).

**Adaptive Response:**
For environments with elevated threat levels, consider CAPTCHA integration after
3 failed attempts or implement progressive delay (exponential backoff).
```

### Acceptance Criteria
- [ ] Security section added to auth-manager documentation
- [ ] Rate limiting configuration examples provided for nginx, HAProxy, AWS ALB
- [ ] Account lockout guidance documented
- [ ] CAPTCHA integration guidance added
- [ ] Link added from Simple Auth Manager docs to security guidance

### References
- ASVS 6.1.1: Rate limiting and anti-automation documentation required
- File: `airflow-core/docs/core-concepts/auth-manager/index.rst`

### Priority
**Medium** - Documentation gap that could lead to insecure deployments

---

## Issue: FINDING-005 - No Minimum Password Length Enforcement for User-Set Passwords
**Labels:** bug, security, priority:medium
**Description:**
### Summary
While auto-generated passwords are 16 characters (compliant), manually set passwords in the Simple Auth Manager have no minimum length enforcement. An administrator could inadvertently set a 1-character password.

### Details
The Simple Auth Manager generates secure 16-character passwords automatically, but when administrators manually edit `simple_auth_manager_passwords.json.generated`, no validation enforces minimum password length. The `_get_passwords()` method reads passwords from the file without validation.

**Attack Scenario:**
1. Admin manually edits `simple_auth_manager_passwords.json.generated`
2. Sets password "abc" (3 chars) for user
3. `_get_passwords()` reads it without validation
4. `create_token()` accepts it for authentication
5. Attacker easily brute forces 3-character password

### Remediation
Add validation in `_get_passwords()` to check minimum password length:

```python
def _get_passwords(self) -> dict[str, str]:
    """Load passwords from file with validation."""
    MIN_PASSWORD_LENGTH = conf.getint(
        "simple_auth_manager",
        "min_password_length",
        fallback=8
    )
    
    user_passwords_from_file = self._read_password_file()
    
    # Validate password lengths
    for username, password in user_passwords_from_file.items():
        if len(password) < MIN_PASSWORD_LENGTH:
            log.warning(
                f"Password for user '{username}' is shorter than minimum length "
                f"({len(password)} < {MIN_PASSWORD_LENGTH}). This password should be changed."
            )
    
    return user_passwords_from_file
```

Long-term: Define password policy interface in BaseAuthManager with optional abstract methods for password validation that auth manager implementations can override.

### Acceptance Criteria
- [ ] Minimum password length validation added to `_get_passwords()`
- [ ] Configuration option `simple_auth_manager_min_password_length` added (default: 8)
- [ ] Warning logged for passwords shorter than minimum
- [ ] Test added for password length validation
- [ ] Documentation updated with password requirements

### References
- ASVS 6.2.1: Minimum password length of 8 characters required
- File: `airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py` (lines 37-41)

### Priority
**Medium** - Allows weak passwords if manually configured

---

## Issue: FINDING-006 - No Application-Level Password Change Functionality
**Labels:** enhancement, security, priority:medium
**Description:**
### Summary
Users of the Simple Auth Manager cannot change their passwords through the application interface. Password changes require direct file system access to the server, which bypasses audit logging and is not feasible for non-admin users.

### Details
The Simple Auth Manager provides no `/password/change` endpoint or similar functionality. Users must:
1. Have server admin privileges to access the file system
2. Manually edit `simple_auth_manager_passwords.json.generated`
3. Restart or reload the application

This approach:
- Requires server admin privileges (violates least privilege)
- Bypasses any audit logging
- Is not feasible for non-admin users in shared environments
- Violates the principle that users should manage their own credentials

The BaseAuthManager interface also does not define a `change_password()` method, providing no standardized hook for this functionality.

### Remediation
Add a password change endpoint to the Simple Auth Manager:

```python
from pydantic import BaseModel, Field

class PasswordChangeBody(BaseModel):
    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8)

@login_router.post("/password/change", status_code=status.HTTP_200_OK)
def change_password(
    body: PasswordChangeBody,
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

Implement `SimpleAuthManagerLogin.change_password()` to:
1. Verify current password
2. Validate new password against policy (length, complexity)
3. Update password file atomically
4. Log the password change event
5. Optionally revoke existing tokens

### Acceptance Criteria
- [ ] Password change endpoint implemented
- [ ] Current password verification required
- [ ] New password validated against policy
- [ ] Password file updated atomically
- [ ] Audit log entry created for password changes
- [ ] Test added for password change flow
- [ ] Documentation updated with password change instructions

### References
- ASVS 6.2.2, 6.2.3: Users must be able to change their passwords
- File: `airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py` (lines 31-102)

### Priority
**Medium** - Missing essential user account management functionality

---

## Issue: FINDING-007 - No Check Against Common/Breached Password Lists
**Labels:** enhancement, security, priority:medium
**Description:**
### Summary
Manually set passwords in the Simple Auth Manager are never validated against common password lists. Administrators can set passwords like "password1", "12345678", or "qwerty123" without warning.

### Details
While auto-generated passwords are secure (16 random characters), the documented ability to manually set passwords creates a security gap. The `_get_passwords()` function loads passwords from JSON without validation against common passwords, and the login service accepts any password that matches, regardless of strength.

**Common passwords that would be accepted:**
- password123
- 12345678
- qwerty123
- admin123
- letmein1

### Remediation
Add a common password check that validates passwords when loaded:

```python
import importlib.resources

class SimpleAuthManager(BaseAuthManager):
    _common_passwords: set[str] | None = None
    
    def _load_common_passwords(self) -> set[str]:
        """Load common passwords list (top 3000+ matching min length)."""
        if self._common_passwords is None:
            try:
                # Load from bundled resource file
                passwords_text = importlib.resources.read_text(
                    "airflow.api_fastapi.auth.managers.simple.resources",
                    "common_passwords.txt"
                )
                self._common_passwords = set(
                    line.strip() for line in passwords_text.splitlines()
                    if len(line.strip()) >= 8  # Match min password length
                )
            except FileNotFoundError:
                log.warning("Common passwords list not found, skipping validation")
                self._common_passwords = set()
        return self._common_passwords
    
    def _get_passwords(self) -> dict[str, str]:
        """Load passwords from file with common password validation."""
        user_passwords_from_file = self._read_password_file()
        common_passwords = self._load_common_passwords()
        
        # Check each password against common list
        for username, password in user_passwords_from_file.items():
            if password.lower() in common_passwords:
                log.warning(
                    f"Password for user '{username}' matches a common password. "
                    f"This password should be changed immediately."
                )
        
        return user_passwords_from_file
```

### Acceptance Criteria
- [ ] Common passwords list added to resources (e.g., top 10000 from HIBP)
- [ ] Password validation checks against common list
- [ ] Warning logged for common password matches
- [ ] Test added with sample common passwords
- [ ] Documentation updated recommending against common passwords

### References
- ASVS 6.2.4: Passwords must be checked against common/breached lists
- File: `airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py` (lines 408-418)

### Priority
**Medium** - Allows weak passwords if manually configured

---

## Issue: FINDING-008 - Login Endpoints Lack Rate Limiting or Account Lockout Mechanisms
**Labels:** enhancement, security, priority:medium
**Description:**
### Summary
The Simple Auth Manager login endpoints have no rate limiting or account lockout mechanisms, allowing unlimited password guessing attempts against any known username.

### Details
An attacker can perform unlimited login attempts:
```
POST /auth/token
{"username": "admin", "password": "guess1"}
→ 401 Unauthorized

POST /auth/token
{"username": "admin", "password": "guess2"}
→ 401 Unauthorized

... (repeat indefinitely)
```

While constant-time comparison prevents timing-based username enumeration, the absence of throttling allows high-speed credential stuffing and brute force attacks.

**Mitigating Context:**
- Simple Auth Manager is explicitly designed for development/testing
- Production deployments should use external auth managers (FAB, Keycloak) or deploy behind a reverse proxy with rate limiting
- The BaseAuthManager interface provides no rate limiting framework

### Remediation
1. Document that production auth managers MUST implement brute force protections
2. Consider adding optional rate limiting to Simple Auth Manager for defense-in-depth:

```python
from fastapi_limiter.depends import RateLimiter

@login_router.post(
    "/token",
    dependencies=[Depends(RateLimiter(times=5, seconds=60))]
)
async def create_token(body: LoginBody) -> dict:
    """Login endpoint with rate limiting (5 attempts per minute)."""
    # ... existing implementation
```

3. Document that production deployments MUST configure external rate limiting (reverse proxy, WAF, or cloud load balancer)

### Acceptance Criteria
- [ ] Documentation added requiring brute force protections for production
- [ ] Optional rate limiting added to Simple Auth Manager
- [ ] Reverse proxy rate limiting examples added to documentation
- [ ] Test added verifying rate limit enforcement
- [ ] Warning logged on startup if Simple Auth Manager used without rate limiting

### References
- ASVS 6.3.1: Anti-automation controls required for authentication
- File: `airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py` (line 40)

### Priority
**Medium** - Enables brute force attacks in development deployments

---

## Issue: FINDING-009 - Previous JWT Tokens Are Not Revoked Upon Re-Authentication
**Labels:** bug, security, priority:medium
**Description:**
### Summary
When a user re-authenticates, the application generates a new JWT token but does not revoke or terminate the previous session token. If a session token is compromised, re-authentication does not invalidate the compromised token.

### Details
The authentication flow:
1. User authenticates → receives JWT token A
2. Token A is potentially compromised
3. User re-authenticates → receives JWT token B
4. **Token A remains valid until natural expiration**

The `BaseAuthManager.generate_jwt()` method only generates new tokens and has no mechanism to track and revoke previously issued tokens for a given user. The `revoke_token()` method exists but is never called during any authentication flow.

**Attack Scenario:**
1. Attacker compromises user's JWT token (XSS, network interception)
2. User suspects compromise and re-authenticates
3. User receives new token but old token still works
4. Attacker continues using compromised token for up to 24 hours

### Remediation
The login flow should accept the current token (if present) and revoke it:

```python
def create_token(
    username: str,
    password: str,
    current_token: str | None = None
) -> dict:
    """Create new token and revoke previous token if provided."""
    # Verify credentials
    user = _verify_credentials(username, password)
    
    # Revoke current token if provided
    if current_token:
        try:
            get_auth_manager().revoke_token(current_token)
        except Exception as e:
            log.warning(f"Failed to revoke previous token: {e}")
    
    # Generate new token
    token = get_auth_manager().generate_jwt(...)
    return {"access_token": token}
```

Alternatively, implement a per-user "tokens issued after" timestamp that invalidates all tokens issued before re-authentication.

### Acceptance Criteria
- [ ] Login endpoint accepts optional current_token parameter
- [ ] Previous token revoked before issuing new token
- [ ] Token validation checks "issued after" timestamp
- [ ] Test added verifying old token rejection after re-authentication
- [ ] Documentation updated describing session invalidation behavior

### References
- ASVS 7.2.4: Re-authentication must terminate prior sessions
- File: `airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py` (lines 38-73)

### Priority
**Medium** - Compromised tokens remain valid after re-authentication

---

## Issue: FINDING-010 - Simple Auth Manager Provides No Logout Endpoint to Trigger Token Revocation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Users cannot explicitly terminate their session in the Simple Auth Manager. The `revoke_token` method exists but is unreachable through any Simple Auth Manager route, meaning tokens remain valid for their full expiration duration even if the user wants to log out.

### Details
Current situation:
- User wants to end session
- No endpoint to call
- Token remains valid until expiration
- No revocation triggered

**Impact:**
- Shared device scenarios: user cannot ensure session is terminated
- Compromised tokens cannot be explicitly revoked by the user
- Tokens remain valid for full expiration duration (up to 24 hours)

The cookie `_token` may be cleared client-side, but the JWT remains cryptographically valid. If the token was captured (e.g., via XSS in another component, network interception before HTTPS), it continues to work.

### Remediation
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

### Acceptance Criteria
- [ ] Logout endpoint implemented
- [ ] Endpoint revokes JWT token via `revoke_token()`
- [ ] Cookie cleared in response
- [ ] `get_url_logout()` returns logout endpoint URL
- [ ] Test added verifying token revocation on logout
- [ ] Documentation updated with logout instructions

### References
- ASVS 7.4.1: Users must be able to terminate their own sessions
- File: `airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py`

### Priority
**Medium** - Users cannot explicitly terminate sessions

---

## Issue: FINDING-011 - Direct Username/Password Credential Exchange Resembles Deprecated ROPC Grant Without Per-Client Grant Restriction
**Labels:** security, architecture, priority:medium
**Description:**
### Summary
The system uses direct credential exchange (username/password → JWT token), functionally equivalent to the deprecated Resource Owner Password Credentials (ROPC) grant type. There is no mechanism to restrict which grant types a specific client is allowed to use, and no client identification or registration.

### Details
The authentication flow:
1. Client submits username/password to `/auth/token`
2. Server returns JWT token directly
3. No authorization code flow
4. No client authentication (client_id/client_secret)
5. No distinction between confidential and public clients

**Context:**
The system's documented design is NOT a general-purpose OAuth2 authorization server—it's an application-specific authentication system. The project security guidance explicitly states: "JWT tokens for API authentication... auditors should focus on verifying token expiration, secure signing keys, and HTTPS enforcement."

The auth manager is pluggable, so production deployments with external auth managers (FAB, OIDC) may implement proper grant flows.

### Remediation
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

### Acceptance Criteria
- [ ] Documentation clarifies Simple Auth Manager is dev/test only
- [ ] Production auth manager guidance added recommending OAuth2 authorization code flow
- [ ] Example authorization code flow implementation provided for custom auth managers
- [ ] Grant type validation interface added to BaseAuthManager
- [ ] Test added for grant type restriction

### References
- ASVS 10.4.4: ROPC grant must no longer be used
- File: `airflow-core/docs/security/api.rst` (lines 37-48)

### Priority
**Medium** - Architectural pattern discouraged by modern OAuth2 guidance

---

## Issue: FINDING-012 - JWT Refresh Middleware Does Not Invalidate Previous Token After Issuing New Token
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The JWT refresh middleware issues new tokens during refresh but does not revoke the old token. An attacker who obtains a valid JWT cookie can replay it for the entire remaining token lifetime (up to 24 hours), even after the legitimate user has had their token refreshed.

### Details
The refresh flow:
1. User's token is near expiration
2. Middleware detects and issues new token
3. **Old token is NOT revoked**
4. Both old and new tokens are valid

**Attack Scenario:**
1. Attacker captures JWT token (XSS, network interception)
2. Legitimate user continues using application
3. Middleware refreshes user's token
4. Attacker's captured token still works (no revocation)
5. Attacker has up to 24 hours to use captured token

There is no token invalidation after refresh, no reuse detection, and no sender-constraining (no DPoP or mTLS binding to specific client). The browser is a public client, making this the exact scenario ASVS 10.4.5 addresses.

### Remediation
Implement refresh token rotation with invalidation:

```python
async def dispatch(self, request: Request, call_next):
    token = request.cookies.get(COOKIE_NAME_JWT_TOKEN)
    
    if token and self._should_refresh(token):
        # Generate new token
        new_token = self._generate_new_token(token)
        
        # Revoke old token
        try:
            jti = self._extract_jti(token)
            if jti:
                get_auth_manager().revoke_token(token)
        except Exception as e:
            log.error(f"Failed to revoke old token during refresh: {e}")
        
        # Set new token in response
        response = await call_next(request)
        response.set_cookie(COOKIE_NAME_JWT_TOKEN, new_token, ...)
        return response
    
    return await call_next(request)
```

Implement reuse detection by checking if a token has been revoked in `JWTValidator.avalidated_claims()`:

```python
async def avalidated_claims(self, token: str) -> dict:
    claims = jwt.decode(token, ...)
    
    jti = claims.get("jti")
    if jti and RevokedToken.is_revoked(jti):
        # Revoke ALL tokens for this user (replay detected)
        user_id = claims.get("sub")
        RevokedToken.revoke_all_for_user(user_id)
        raise jwt.InvalidTokenError('Token has been revoked (replay detected)')
    
    return claims
```

### Acceptance Criteria
- [ ] Old token revoked after refresh
- [ ] Reuse detection implemented
- [ ] All user tokens revoked on replay detection
- [ ] Test added for token rotation
- [ ] Test added for replay detection
- [ ] Documentation updated describing rotation behavior

### References
- ASVS 10.4.5: Refresh tokens must be invalidated after use (public clients)
- File: `airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py` (lines 50-66)

### Priority
**Medium** - Captured tokens remain valid after refresh

---

## Issue: FINDING-013 - No enforcement mechanism in base class ensures authorization is called at API entry points
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The BaseAuthManager defines authorization methods as abstract interfaces but provides no mechanism (decorator, middleware requirement, or dependency injection pattern) that FORCES API endpoints to call these methods. If any API endpoint omits the authorization check, function-level access control is bypassed.

### Details
The data flow is:
```
HTTP Request → FastAPI Router → Route Handler → ??? → is_authorized_*()
```

The connection between route handler and authorization check is not structurally enforced by the base class. The `get_fastapi_middlewares()` method returns an empty list by default, providing no middleware-level enforcement.

**Risk:**
If any API endpoint omits the authorization check, function-level access control is bypassed. Since there's no structural enforcement, every endpoint must be individually verified.

### Remediation
Consider providing a FastAPI dependency or decorator in the base auth framework that enforces authorization:

```python
from fastapi import Depends, HTTPException, status
from typing import Callable

def require_authorization(
    resource_type: str,
    method: str,
    details_extractor: Callable | None = None
):
    """
    FastAPI dependency that enforces authorization.
    
    Usage:
        @router.get(
            "/connections/{conn_id}",
            dependencies=[Depends(require_authorization("connection", "GET", lambda req: {"conn_id": req.path_params["conn_id"]}))]
        )
        def get_connection(conn_id: str):
            ...
    """
    async def check_authorization(request: Request, user: BaseUser = Depends(get_current_user)):
        auth_manager = get_auth_manager()
        details = details_extractor(request) if details_extractor else None
        
        is_authorized_method = getattr(auth_manager, f"is_authorized_{resource_type}")
        if not is_authorized_method(method=method, user=user, details=details):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"User not authorized to {method} {resource_type}"
            )
    
    return check_authorization
```

Additionally, conduct a comprehensive audit of all API endpoint handlers to verify that `is_authorized_*` methods are consistently called.

### Acceptance Criteria
- [ ] Authorization dependency helper implemented
- [ ] Example usage added to documentation
- [ ] Audit completed of all API endpoints
- [ ] Test added verifying authorization enforcement
- [ ] Endpoints missing authorization checks identified and fixed

### References
- ASVS 8.2.1: Authorization must be enforced at every API entry point
- File: `airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py`

### Priority
**Medium** - Structural gap that relies on developer discipline

---

## Issue: FINDING-014 - Optional details parameter allows authorization calls without data-specific context
**Labels:** bug, security, priority:medium
**Description:**
### Summary
All `is_authorized_*` methods accept `details` as an optional parameter defaulting to `None`. This means callers can invoke authorization checks without specifying which specific resource instance is being accessed, potentially creating BOLA vulnerabilities.

### Details
The method signature:
```python
def is_authorized_connection(
    self,
    *,
    method: str,
    user: BaseUser,
    details: ConnectionDetails | None = None,
) -> bool:
```

**Attack Scenario:**
1. API endpoint receives request for specific connection ID
2. Endpoint calls `is_authorized_connection(method="GET", user=user)` without details
3. Auth manager checks general permission (user can read *some* connections)
4. Access granted without validating user has permission to *this specific* connection
5. IDOR/BOLA vulnerability

**Data Flow:**
```
API endpoint receives request with resource ID
→ calls is_authorized_connection(method="GET", user=user) without details
→ Auth manager checks general permission
→ Access granted without data-specific validation
→ IDOR/BOLA
```

### Remediation
Consider splitting function-level and data-level authorization into separate method signatures:

```python
@abstractmethod
def is_authorized_connection_type(
    self,
    *,
    method: str,
    user: BaseUser,
) -> bool:
    """Check if user can access connections in general (function-level)."""
    ...

@abstractmethod
def is_authorized_connection_instance(
    self,
    *,
    method: str,
    user: BaseUser,
    details: ConnectionDetails,  # Required, not optional
) -> bool:
    """Check if user can access this specific connection (data-level)."""
    ...
```

Or use `@overload` to make the type checker flag calls without details when accessing specific instances.

### Acceptance Criteria
- [ ] Authorization methods split into type-level and instance-level variants
- [ ] Instance-level methods require details parameter
- [ ] API endpoints updated to use appropriate method
- [ ] Test added verifying data-specific authorization
- [ ] Documentation updated describing two-level authorization

### References
- ASVS 8.2.2: Data-level authorization required for all resource access
- CWE-639: Authorization Bypass Through User-Controlled Key
- File: `airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py` (lines 205-271)

### Priority
**Medium** - Design-level concern that could lead to BOLA vulnerabilities

---

## Issue: FINDING-015 - Incomplete Documentation of Input Validation Rules for DAG Trigger API
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The `trigger_dag` and `_trigger_dag` functions enforce several input validation rules implicitly in code (conf must be dict/null, logical_date must be localized and >= start_date, run_type must be in allowed_run_types), but these rules are not documented in a centralized specification.

### Details
The docstrings describe parameters functionally but do not define validation constraints or expected data formats:
- `dag_id`: expected pattern? max length?
- `run_id`: expected pattern? max length?
- `conf`: JSON object schema constraints per DAG?
- `logical_date`: ISO 8601 datetime with timezone?
- `note`: max length? allowed characters?
- `partition_key`: expected format?

Without documented validation rules:
- No specification to verify implementation against
- Developers maintaining or extending the API may not understand all constraints
- Security reviewers cannot confirm coverage without tracing every code path

### Remediation
Create a validation rules specification (e.g., in API schema documentation or an OpenAPI spec with `pattern`, `minLength`, `maxLength`, `format` constraints):

```yaml
# Example OpenAPI schema
TriggerDagRequest:
  type: object
  properties:
    dag_id:
      type: string
      pattern: '^[a-zA-Z0-9._-]+$'
      maxLength: 250
    run_id:
      type: string
      pattern: '^[a-zA-Z0-9._-]+$'
      maxLength: 250
    conf:
      type: object
      additionalProperties: true
      maxProperties: 100
    logical_date:
      type: string
      format: date-time
      description: ISO 8601 datetime with timezone
    note:
      type: string
      maxLength: 1000
```

Leverage FastAPI's Pydantic models to formally define constraints for API parameters. This simultaneously creates documentation (ASVS 2.1.1) and enforcement (ASVS 2.2.1).

### Acceptance Criteria
- [ ] Validation rules specification created
- [ ] Pydantic models defined with constraints
- [ ] OpenAPI schema generated with validation rules
- [ ] Documentation updated with validation requirements
- [ ] Test added verifying validation rules match specification

### References
- ASVS 2.1.1: Input validation rules must be documented
- File: `airflow-core/src/airflow/api/common/trigger_dag.py` (lines 40-200)

### Priority
**Medium** - Documentation gap that could lead to inconsistent validation

---

## Issue: FINDING-016 - Nginx reverse proxy example lacks HTTPS configuration with TLS protocol version enforcement
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The primary nginx reverse proxy example demonstrates an HTTP-only listener on port 80 without any corresponding HTTPS server block. This creates multiple security issues including no TLS protocol version configuration, no HTTPS listener, and no HTTP-to-HTTPS redirect.

### Details
The example configuration:
```nginx
server {
    listen 80;
    server_name lab.mycompany.com;
    
    location /myorg/airflow/ {
        proxy_pass http://localhost:8080;
        ...
    }
}
```

**Issues:**
1. No TLS protocol version configuration (e.g., `ssl_protocols TLSv1.2 TLSv1.3;`)
2. No HTTPS listener despite documentation referencing `https://lab.mycompany.com/myorg/airflow/`
3. No HTTP-to-HTTPS redirect

**Impact:**
- Deployments following this example will accept unencrypted HTTP traffic
- Authentication credentials and session tokens exposed to network interception
- If HTTPS is added without explicit protocol configuration, deprecated TLS versions may be enabled

### Remediation
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

### Acceptance Criteria
- [ ] HTTPS server block added to example
- [ ] TLS protocol version restriction documented
- [ ] HTTP-to-HTTPS redirect added
- [ ] Certificate configuration examples provided
- [ ] Security warning added for HTTP-only configurations

### References
- ASVS 12.1.1, 12.2.1, 4.4.1: TLS required with version restrictions
- File: `airflow-core/docs/howto/run-behind-proxy.rst` (lines 32-43)

### Priority
**Medium** - Documentation example teaches insecure deployment pattern

---

## Issue: FINDING-017 - Flower documentation lacks TLS configuration guidance
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The Flower documentation exclusively shows HTTP URLs and provides no guidance on configuring TLS for the Flower web interface. Flower exposes sensitive information about Celery task execution, and the basic authentication shown transmits credentials in base64 encoding without TLS encryption.

### Details
The documentation example:
```bash
airflow celery flower --basic-auth=user1:password1,user2:password2
```

**Issues:**
- Only HTTP URLs shown
- No TLS configuration guidance
- Basic authentication credentials sent in base64 without encryption
- Flower exposes sensitive task execution data

**Impact:**
- Flower deployments following this documentation will accept connections over HTTP
- Authentication credentials and monitoring data exposed to network interception
- Task arguments and potentially sensitive data visible to network attackers

### Remediation
Add TLS configuration guidance for Flower:

```rst
Flower Security Best Practices
-------------------------------

Flower should always be deployed behind a TLS-terminating reverse proxy
or configured with TLS directly. Basic authentication credentials are
transmitted in base64 encoding and MUST be protected by TLS encryption.

**Direct TLS Configuration:**

.. code-block:: bash

    airflow celery flower --basic-auth=user1:password1 \
        --certfile=/path/to/cert.pem --keyfile=/path/to/key.pem

**Reverse Proxy Configuration:**

Deploy Flower behind nginx or another reverse proxy with TLS termination
(see :doc:`/howto/run-behind-proxy` for examples).
```

### Acceptance Criteria
- [ ] TLS configuration section added to Flower documentation
- [ ] Certificate configuration examples provided
- [ ] Reverse proxy deployment guidance added
- [ ] Security warning added for HTTP-only configurations
- [ ] Link added to general reverse proxy documentation

### References
- ASVS 12.2.1: TLS required for all authenticated connections
- File: `airflow-core/docs/security/flower.rst` (lines 44-46)

### Priority
**Medium** - Documentation gap that could lead to insecure Flower deployments

---

## Issue: FINDING-018 - No Clear-Site-Data header implementation visible in middleware or response handling
**Labels:** enhancement, security, priority:medium
**Description:**
### Summary
The application initialization does not include any middleware or mechanism to set the `Clear-Site-Data` header on logout/session-termination responses. If client-side cleanup fails, authenticated data may persist in the browser after session termination.

### Details
The ASVS requirement states that authenticated data should be cleared from client storage when the session is terminated, and the `Clear-Site-Data` header is the recommended server-side mechanism for this.

The middleware stack includes `JWTRefreshMiddleware` for token management but no corresponding mechanism to instruct browsers to clear cached credentials, cookies, and storage when a session ends.

**Impact:**
If `Clear-Site-Data` is not set on logout responses and client-side cleanup fails (e.g., JavaScript error, network interruption), authenticated data (tokens, cached responses, cookies) may persist in the browser after session termination, potentially accessible to subsequent users on shared devices.

### Remediation
Add `Clear-Site-Data` header to logout and session-invalidation responses:

```python
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

### Acceptance Criteria
- [ ] Clear-Site-Data header added to logout endpoint
- [ ] Header added to session timeout responses
- [ ] Client-side cleanup implemented in UI
- [ ] Test added verifying header presence
- [ ] Documentation updated describing session cleanup

### References
- ASVS 14.3.1: Authenticated data must be cleared on session termination
- CWE-613: Insufficient Session Expiration
- File: `airflow-core/src/airflow/api_fastapi/core_api/app.py` (lines 163-180)

### Priority
**Medium** - Session data may persist after logout on shared devices

---

## Issue: FINDING-019 - Cookie path scoping function exists but no evidence of Secure attribute or __Host-/__Secure- prefix enforcement
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `get_cookie_path()` function provides path scoping for cookies but does not enforce the `Secure` attribute or cookie name prefixes (`__Host-` or `__Secure-`). The actual cookie-setting code is not present in the provided files, but the infrastructure for ensuring secure cookie attributes is not visible.

### Details
Observations:
- JWT refresh middleware exists (`JWTRefreshMiddleware`), suggesting tokens are stored in cookies
- `get_cookie_path()` utility exists for cookie scoping
- No Secure attribute enforcement visible
- No prefix validation visible
- No SameSite configuration visible

**Impact:**
- Without `Secure` attribute, cookies can be transmitted over unencrypted HTTP
- Without `__Host-` or `__Secure-` prefixes, cookies are vulnerable to domain/path override attacks from subdomains

### Remediation
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

### Acceptance Criteria
- [ ] Secure cookie helper function implemented
- [ ] All cookie-setting code audited
- [ ] Secure attribute enforced on all cookies
- [ ] Cookie prefixes implemented
- [ ] Test added verifying cookie security attributes
- [ ] Documentation updated with cookie security requirements

### References
- ASVS 3.3.1: Secure attribute and prefixes required for session cookies
- CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
- File: `airflow-core/src/airflow/api_fastapi/app.py` (lines 48-54)

### Priority
**Medium** - Cookies may be vulnerable to interception and override attacks

---

## Issue: FINDING-020 - No explicit CSRF token middleware or anti-forgery mechanism visible for state-changing operations
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application's CSRF protection strategy needs assessment. JWT-based authentication via cookies is inherently vulnerable to CSRF unless additional protections are in place. The middleware stack does not include explicit CSRF token generation/validation middleware.

### Details
CSRF protection assessment:
1. **JWT-based authentication via cookies:** The presence of JWTRefreshMiddleware and get_cookie_path() indicates JWT tokens are stored in cookies
2. **No explicit CSRF token middleware:** The middleware stack does not include CSRF token generation/validation
3. **CORS as partial protection:** CORS middleware provides protection for non-simple requests requiring preflight, but:
   - CORS is only configured when origins are explicitly set
   - Simple requests (form POSTs with application/x-www-form-urlencoded) don't trigger preflight
   - GET requests with side effects (if any) are not protected
4. **Potential mitigations not visible:** SameSite cookie attributes, custom header requirements, or token validation in request headers

**Attack Scenario:**
If JWT tokens are stored in cookies without SameSite=Strict and without CSRF tokens:
1. Victim is authenticated to Airflow
2. Victim visits attacker's site
3. Attacker's page submits state-changing requests (e.g., trigger DAG, modify connection)
4. Browser includes authentication cookies
5. Airflow processes request as legitimate

### Remediation
**Option 1:** Require non-CORS-safelisted header on all state-changing endpoints:

```python
class CSRFProtectionMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            # Require custom header for state-changing operations
            if not request.headers.get("x-requested-with"):
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"detail": "CSRF protection: x-requested-with header required"}
                )
        return await call_next(request)
```

**Option 2:** Ensure cookies use SameSite=Strict in cookie-setting code

**Option 3:** Validate Origin/Referer headers against expected values

### Acceptance Criteria
- [ ] CSRF protection mechanism implemented
- [ ] State-changing endpoints protected
- [ ] Test added for CSRF protection
- [ ] Documentation updated describing CSRF protection strategy
- [ ] SameSite cookie attribute verified

### References
- ASVS 3.5.1: CSRF protection required for state-changing operations
- CWE-352: Cross-Site Request Forgery
- File: `airflow-core/src/airflow/api_fastapi/core_api/app.py` (lines 172-189)

### Priority
**Medium** - Potential CSRF vulnerability if cookies lack SameSite attribute

---

## Issue: FINDING-021 - No Risk-Based Remediation Timeframes Defined in Documentation
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The application documentation does not define risk-based remediation timeframes for third-party component versions with known vulnerabilities, nor does it establish a general library update cadence.

### Details
The AGENTS.md file covers dependency management tooling (uv.lock, uv workspace) and includes a pattern for tracking deferred work, but does not define:
- Maximum acceptable timeframes for remediating critical CVEs (e.g., 24-72 hours)
- Timeframes for high-severity vulnerabilities (e.g., 7-14 days)
- Timeframes for medium/low-severity vulnerabilities (e.g., 30-90 days)
- Regular library update cadence (e.g., monthly dependency refresh)
- Criteria for determining component risk levels that trigger different timeframes
- Escalation procedures when timeframes are breached

### Remediation
Create a dedicated security documentation page (e.g., `airflow-core/docs/security/dependency_management.rst`) defining risk-based remediation timeframes:

```rst
Dependency Vulnerability Management
====================================

Risk-Based Remediation Timeframes
----------------------------------

**Critical (9.0-10.0 CVSS):** 72 hours
- Immediate patch or mitigation required
- Release blocker for all versions
- Emergency security release if necessary

**High (7.0-8.9):** 14 days
- Patch in next scheduled release
- Expedited release if actively exploited
- Workaround documented if patch unavailable

**Medium (4.0-6.9):** 30 days
- Include in next regular release cycle
- Monitor for exploitation activity

**Low (0.1-3.9):** 90 days
- Address during regular dependency updates
- May be deferred if risk is minimal

General Library Update Policy
------------------------------

- All direct dependencies reviewed monthly
- Provider packages must pin dependencies to versions receiving active security support
- Components classified as risky (poorly maintained, EOL, history of significant vulnerabilities) must be replaced or sandboxed within 90 days
- Transitive dependencies monitored via automated scanning in CI/CD pipelines
```

### Acceptance Criteria
- [ ] Security documentation page created
- [ ] Risk-based timeframes defined
- [ ] General update policy documented
- [ ] Escalation procedures defined
- [ ] Link added from main documentation

### References
- ASVS 15.1.1: Risk-based remediation timeframes required
- File: `AGENTS.md`

### Priority
**Medium** - Documentation gap for vulnerability management

---

## Issue: FINDING-022 - No Documented Mechanism to Verify Components Haven't Breached Update Timeframes
**Labels:** enhancement, security, priority:medium
**Description:**
### Summary
The application documentation does not describe a process or tooling to verify that included components have not exceeded their documented update and remediation timeframes. With 100+ provider packages and their transitive dependencies, vulnerable dependencies may persist indefinitely without automated verification.

### Details
The AGENTS.md references dependency management commands but only for development workflow. Since ASVS 15.1.1 timeframes are not defined (see FINDING-021), this requirement inherently cannot be met.

**Risk:**
With 100+ provider packages and their transitive dependencies, the attack surface for outdated components is substantial. Without automated verification that components are current, vulnerable dependencies may persist in production deployments indefinitely.

### Remediation
1. **Integrate automated dependency scanning into CI pipelines:**

```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on:
  pull_request:
  schedule:
    - cron: '0 0 * * *'  # Daily

jobs:
  dependency-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Scan dependencies
        run: |
          pip install pip-audit
          pip-audit --strict --requirement requirements.txt
```

2. **Document the verification process:**

```rst
Dependency Verification Process
================================

Automated Scanning
------------------

- Dependabot/Renovate for automated PRs with security-priority scheduling
- pip-audit in CI for every PR and nightly builds
- Monthly automated scans of all 100+ provider packages against NIST NVD

Compliance Dashboard
--------------------

- Automated tracking of component age vs. remediation deadlines
- Alerting when components approach or breach remediation timeframes
- Weekly security report to maintainers
```

3. **Define remediation timeframes** (Critical: 72h, High: 14d, Medium: 30d, Low: 90d)
4. **Create component inventory** classified by risk level
5. **Implement automated compliance dashboard** with alerting

### Acceptance Criteria
- [ ] Automated dependency scanning integrated into CI
- [ ] Verification process documented
- [ ] Compliance dashboard implemented
- [ ] Alerting configured for approaching deadlines
- [ ] Test added for scanning workflow

### References
- ASVS 15.2.1: Automated verification of component update compliance required
- File: `AGENTS.md`

### Priority
**Medium** - No mechanism to detect outdated vulnerable components

---

## Issue: FINDING-023 - No Account Lockout Mechanism in Simple Auth Manager Login Service
**Labels:** enhancement, security, priority:low
**Description:**
### Summary
The Simple Auth Manager login service does not implement any account lockout mechanism or failed attempt tracking. Repeated failed login attempts result in no tracking or lockout, creating unlimited brute force opportunity.

### Details
**Context:**
Low severity because the Simple Auth Manager is explicitly dev-only and rate limiting is intentionally a capability rather than enforced default. However, the absence of any lockout mechanism even as a reference implementation means custom auth managers have no framework-level template for implementing this control.

### Remediation
Consider adding an optional, configurable rate limit or failed-attempt counter in the BaseAuthManager interface as a reference for auth manager implementers:

```python
# In BaseAuthManager
def check_rate_limit(self, *, identifier: str) -> None:
    """Hook for rate limiting. Override to implement per-deployment policy."""
    pass
```

### Acceptance Criteria
- [ ] Optional rate limiting hook added to BaseAuthManager
- [ ] Example implementation provided in documentation
- [ ] Test added demonstrating rate limiting usage
- [ ] Documentation updated recommending rate limiting for production

### References
- ASVS 6.1.1: Account lockout or rate limiting required
- File: `airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py` (lines 24-63)

### Priority
**Low** - Dev-only component, but missing reference implementation

---

## Issue: FINDING-024 - Password Input Field Masking Cannot Be Verified From Available Source
**Labels:** verification-needed, security, priority:low
**Description:**
### Summary
The Simple Auth Manager serves a login UI via Jinja2 templates from the `ui/dev` or `ui/dist` directory. The actual `index.html` template and any associated JavaScript/form code that renders the password input field are not included in the audited source files, making it impossible to confirm whether password fields use `type="password"` for masking.

### Details
**Risk:**
If the password input field does not use `type="password"`, password entry would be visible to shoulder surfers or screen capture tools.

### Remediation
Verify that all password `<input>` elements in the login UI templates use `type="password"`:

```html
<input type="password" name="password" id="password" autocomplete="current-password" />
```

### Acceptance Criteria
- [ ] Login UI template source code reviewed
- [ ] Password input confirmed to use type="password"
- [ ] Test added verifying password field masking
- [ ] Documentation updated if changes needed

### References
- ASVS 6.2.6: Password fields must be masked
- File: `airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py` (lines 275-310)

### Priority
**Low** - Verification needed, UI code not in audit scope

---

## Issue: FINDING-025 - Documentation References Default "admin" and "viewer" Accounts in Development Tooling
**Labels:** documentation, security, priority:low
**Description:**
### Summary
The Breeze development environment pre-configures two accounts where the password equals the username (admin:admin, viewer:viewer). While this is explicitly a development tool configuration, developers may deploy with these credentials still active.

### Details
**Mitigating Context:**
- The Simple Auth Manager is documented as dev/test only
- The code itself reads users from configuration—no accounts are hardcoded
- Production would use a different auth manager entirely
- Password generation creates random 16-character passwords for non-Breeze environments

**Concern:**
1. Developers may deploy with these credentials still active
2. The `_looks_like_production()` heuristic only emits a warning—it does not prevent deployment
3. There is no forced password change for these well-known default credentials

### Remediation
1. The production detection heuristic could additionally check if any password matches the username and emit a CRITICAL warning

2. Add a startup check that refuses to serve if passwords match common defaults when the deployment appears production-like:

```python
if self._looks_like_production():
    passwords = self.get_passwords()
    users = self.get_users()
    for user in users:
        if passwords.get(user.username) == user.username:
            raise RuntimeError(
                f"Default credentials detected for user '{user.username}' in production-like "
                f"deployment. Change the password or use a production auth manager."
            )
```

### Acceptance Criteria
- [ ] Username==password check added to production detection
- [ ] Application refuses to start with default credentials in production
- [ ] Test added for default credential detection
- [ ] Documentation updated warning against default credentials

### References
- ASVS 6.3.2: Default credentials must not be present
- File: `airflow-core/docs/core-concepts/auth-manager/simple/index.rst`

### Priority
**Low** - Dev-only component with production detection heuristic

---

## Issue: FINDING-026 - System-Generated Initial Passwords Never Expire and Become Long-Term Credentials
**Labels:** enhancement, security, priority:low
**Description:**
### Summary
The system-generated initial passwords are securely randomly generated (16 characters, 52-char alphabet, ~91 bits entropy) but do NOT expire after a short period, do NOT require change after initial use, and ARE permitted to become the long-term password. Additionally, generated passwords are printed to stdout/logs on first generation, creating a credential exposure window.

### Details
**Issues:**
1. Generated passwords become permanent credentials with no expiration
2. No rotation mechanism enforced
3. Plaintext password file persists indefinitely
4. Passwords printed to logs on generation

### Remediation
1. Add a `created_at` timestamp per password entry in the JSON file
2. Add a configurable maximum age for generated passwords
3. After first login with a generated password, require password change
4. Consider suppressing password output to logs and instead directing users to the password file

Example:
```json
{
  "bob": {
    "password": "xK9mN2pQ...",
    "generated_at": "2024-01-01T00:00:00Z",
    "must_change": true
  }
}
```

### Acceptance Criteria
- [ ] Password metadata added to JSON file (created_at, must_change)
- [ ] Maximum age configuration option added
- [ ] First-login password change flow implemented
- [ ] Password logging suppressed or made optional
- [ ] Test added for password expiration
- [ ] Documentation updated describing password lifecycle

### References
- ASVS 6.4.1: Initial passwords must expire after short period
- File: `airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py` (lines 150-180)

### Priority
**Low** - Dev-only component, but teaches poor password management pattern

---

## Issue: FINDING-027 - JWT Revocation Check Is Conditional on JTI Presence—Tokens Without JTI Cannot Be Revoked
**Labels:** bug, security, priority:low
**Description:**
### Summary
Token validation short-circuits the revocation check if the `jti` claim is absent. If any code path generates a JWT without a `jti` claim, that token can never be revoked through the `revoke_token`/`RevokedToken` mechanism.

### Details
The validation logic:
```python
jti = payload.get("jti")
if jti and RevokedToken.is_revoked(jti):
    raise InvalidTokenError("Token has been revoked")
```

**Attack Scenario:**
1. Third-party auth manager integration generates JWT without `jti`
2. Token is issued to user
3. User's account is compromised
4. Administrator attempts to revoke token
5. Revocation fails silently (no `jti` to revoke)
6. Compromised token remains valid until expiration

The severity is LOW because the `JWTGenerator` likely includes `jti` by default. However, the defensive check pattern means the system tolerates tokens without `jti`, creating a potential bypass.

### Remediation
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

### Acceptance Criteria
- [ ] JTI presence check added to token validation
- [ ] Tokens without JTI rejected with clear error
- [ ] Test added for missing JTI rejection
- [ ] Documentation updated requiring JTI in all tokens

### References
- ASVS 7.4.1: All tokens must be revocable
- File: `airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py` (line 143)

### Priority
**Low** - Likely enforced by token generator, but validation should be explicit

---

## Issue: FINDING-028 - No OAuth2 Authorization Code Flow Implemented—Direct Credential Exchange Used Instead
**Labels:** architecture, security, priority:low
**Description:**
### Summary
The provided codebase does not implement an OAuth2 authorization code flow. The authentication mechanism uses direct credential exchange via the `/auth/token` endpoint, where clients submit username/password and receive a JWT access token directly.

### Details
The system bypasses the authorization code pattern entirely. The `/auth/token` endpoint directly exchanges credentials for a JWT token (similar to the deprecated Resource Owner Password Credentials flow).

**Context:**
Since there is no authorization code in this flow, the ASVS 10.4.3 requirement regarding authorization code lifetime cannot be directly evaluated. However, if any pluggable auth manager (e.g., FAB auth manager or external OIDC providers) implements authorization code flows internally, the lifetime enforcement would be delegated to those external systems and is not controlled by this codebase.

### Remediation
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

### Acceptance Criteria
- [ ] Authorization code flow support documented for custom auth managers
- [ ] Lifetime validation interface added to BaseAuthManager
- [ ] Example implementation provided
- [ ] Test added for authorization code expiration
- [ ] Documentation updated describing auth code flow support

### References
- ASVS 10.4.3: Authorization codes must expire within 10 minutes
- File: `airflow-core/docs/security/api.rst` (lines 37-48)

### Priority
**Low** - No authorization code flow in current implementation

---

## Issue: FINDING-029 - Token Revocation Infrastructure Exists But Is Not Integrated Into Refresh Flow
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `revoke_token()` method and the `RevokedToken` model provide the infrastructure to revoke tokens by jti. However, this method is NOT called anywhere in the JWTRefreshMiddleware when a new token replaces the old one. Additionally, there is no evidence that `avalidated_claims()` checks the revoked_token table during validation.

### Details
**Gap:**
The revocation mechanism is documented as being used for logout/explicit revocation, but not for rotation-based invalidation. This creates false confidence that token revocation provides replay protection when it is not wired into the refresh flow where it's most needed.

### Remediation
Integrate `revoke_token()` into the refresh flow and ensure `avalidated_claims()` checks the revocation table:

```python
# In avalidated_claims()
async def avalidated_claims(self, token: str) -> dict:
    claims = jwt.decode(token, ...)
    
    jti = claims.get('jti')
    if jti and RevokedToken.is_revoked(jti):
        raise jwt.InvalidTokenError('Token has been revoked')
    
    return claims

# In JWTRefreshMiddleware
async def dispatch(self, request: Request, call_next):
    token = request.cookies.get(COOKIE_NAME_JWT_TOKEN)
    
    if token and self._should_refresh(token):
        new_token = self._generate_new_token(token)
        
        # Revoke old token
        get_auth_manager().revoke_token(token)
        
        response = await call_next(request)
        response.set_cookie(COOKIE_NAME_JWT_TOKEN, new_token, ...)
        return response
```

### Acceptance Criteria
- [ ] Revocation check added to token validation
- [ ] Old token revoked during refresh
- [ ] Test added for revocation during refresh
- [ ] Test added for revoked token rejection
- [ ] Documentation updated describing revocation behavior

### References
- ASVS 10.4.5: Refresh tokens must be invalidated after use
- File: `airflow-core/src/airflow/api_fastapi/auth/tokens.py` (lines 302-309)

### Priority
**Low** - Infrastructure exists but not fully integrated

---

## Issue: FINDING-030 - No Explicit Rejection of 'None' Algorithm at Configuration Validation Time
**Labels:** bug, security, priority:low
**Description:**
### Summary
Configuration value `[api_auth] jwt_algorithm` flows through `_conf_list_factory` to `self.algorithm` and is passed to `jwt.decode(algorithms=...)` without sanitization of unsafe values. If a deployment manager configures `jwt_algorithm = none`, unsigned tokens would be accepted.

### Details
**Attack Scenario:**
1. Deployment misconfigured with `jwt_algorithm = none`
2. `self.algorithm = ["none"]`
3. `jwt.decode(..., algorithms=["none"])` accepts unsigned tokens
4. Attacker forges unsigned tokens with `alg=none` and no signature
5. Attacker gains unauthorized access as any user

**Risk Level:**
Requires deployment misconfiguration but the code should enforce the security invariant regardless.

### Remediation
Add explicit validation in `JWTValidator.__attrs_post_init__` to reject 'None' algorithm:

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

### Acceptance Criteria
- [ ] None algorithm validation added
- [ ] Application refuses to start with none algorithm configured
- [ ] Test added for none algorithm rejection
- [ ] Documentation updated warning against none algorithm

### References
- ASVS 9.1.2: None algorithm must be explicitly rejected
- File: `airflow-core/src/airflow/api_fastapi/auth/tokens.py` (line 232)

### Priority
**Low** - Requires misconfiguration, but validation should be explicit

---

## Issue: FINDING-031 - Authorization documentation does not explicitly define enforcement timing and pipeline position
**Labels:** documentation, security, priority:low
**Description:**
### Summary
The authorization documentation comprehensively defines WHAT authorization checks exist but does not explicitly document WHERE in the request processing pipeline authorization MUST be checked or the required call sequence.

### Details
The documentation defines:
- Resource types (connections, DAGs, pools, variables, assets, views)
- HTTP methods (GET/POST/PUT/DELETE)
- Authorization methods

But does NOT define:
- WHERE in the request processing pipeline authorization MUST be checked
- The required call sequence (authenticate → authorize → process → respond)
- Mandatory enforcement points (API endpoint layer, middleware layer)

**Risk:**
Custom auth manager implementers may inadvertently apply authorization checks at incorrect points in the request pipeline (e.g., after data is retrieved), creating a gap where the control is called but after the sensitive operation.

### Remediation
Add a section to the documentation explicitly stating:

```rst
Authorization Enforcement Requirements
---------------------------------------

All is_authorized_* methods MUST be called:

1. BEFORE any data access or mutation operation
2. At the API server layer (not in client-side code)
3. As early as possible after authentication completes
4. With the specific resource details when accessing a specific resource instance

The authorization decision MUST be evaluated before proceeding. If authorization
is denied, the request MUST be rejected with HTTP 403 Forbidden before any
resource access occurs.
```

### Acceptance Criteria
- [ ] Enforcement timing section added to documentation
- [ ] Call sequence documented
- [ ] Enforcement points clarified
- [ ] Example code provided showing correct placement
- [ ] Link added from auth manager implementation guide

### References
- ASVS 8.1.1: Authorization must be enforced at correct pipeline position
- File: `airflow-core/docs/core-concepts/auth-manager/index.rst`

### Priority
**Low** - Documentation clarification

---

## Issue: FINDING-032 - Documentation does not define handling of details=None authorization semantics for data-specific access
**Labels:** documentation, security, priority:low
**Description:**
### Summary
The documentation mentions 'Some details about the connection can be provided' but doesn't clearly distinguish between function-level check (details=None) and data-level check (details provided). This ambiguity could lead auth manager implementations to treat details=None as 'authorize access to ALL resources' rather than 'check general capability'.

### Details
The ambiguity:
- Function-level check: `is_authorized_connection(method='GET', user=user)` (details=None) — 'can user access connections at all?'
- Data-level check: `is_authorized_connection(method='GET', user=user, details=ConnectionDetails(conn_id='x'))` — 'can user access THIS connection?'

**Risk:**
Custom auth managers may incorrectly grant broad access when details=None is passed, creating IDOR/BOLA vulnerabilities.

### Remediation
Document the semantic difference explicitly:

```rst
Authorization Check Semantics
------------------------------

When ``details`` is ``None``, the check determines whether the user has the
capability to perform the action on the resource type in general. This is
typically used for listing operations.

When ``details`` is provided, it performs a data-specific check for that exact
resource instance.

Auth manager implementations MUST NOT treat ``details=None`` as granting access
to all instances of a resource type.
```

### Acceptance Criteria
- [ ] Semantic difference documented
- [ ] Examples provided for both cases
- [ ] Warning added about details=None handling
- [ ] Link added from auth manager implementation guide

### References
- ASVS 8.1.1: Authorization semantics must be clearly defined
- File: `airflow-core/docs/core-concepts/auth-manager/index.rst` (lines 99-155)

### Priority
**Low** - Documentation clarification

---

## Issue: FINDING-033 - Default filter_authorized_* implementations may allow timing-based inference attacks
**Labels:** security, performance, priority:low
**Description:**
### Summary
The default `filter_authorized_*` implementations iterate over all resource IDs and call individual authorization checks. This creates a potential timing side-channel: if the response time correlates with the number of resources checked, an attacker could infer the total number of resources in the system (even those they can't access).

### Details
**Risk:**
If response time correlates with resource count, attackers could infer:
- Total number of connections in system
- Total number of DAGs in system
- Total number of pools in system

**Mitigation:**
This is adequately addressed by the existing recommendation to override these methods for performance. Performance optimization also mitigates timing side-channels.

### Remediation
Consider adding a note that performance optimization also mitigates timing side-channels:

```rst
Performance and Security Note
------------------------------

The default filter_authorized_* implementations iterate over all resource IDs,
which has both performance and security implications. For large datasets:

1. **Performance:** O(n) authorization checks can be slow
2. **Timing side-channels:** Response time may leak information about total resource count

Override these methods to perform bulk authorization checks using database-level
filtering, which both improves performance and provides constant-time responses.
```

### Acceptance Criteria
- [ ] Note added to documentation about timing side-channels
- [ ] Example bulk authorization implementation provided
- [ ] Link added to security considerations

### References
- ASVS 8.2.2: Data-level authorization must not leak information
- CWE-208: Observable Timing Discrepancy
- File: `airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py` (lines 459-661)

### Priority
**Low** - Adequately addressed by existing performance recommendation

---

## Issue: FINDING-034 - SQL Injection Pattern in Documentation Example Code
**Labels:** documentation, security, priority:low
**Description:**
### Summary
The documentation file `cluster-policies.rst` contains example code that uses f-string interpolation to construct SQL statements. While this is not production code, it teaches an insecure pattern that users may copy and adapt.

### Details
The insecure pattern:
```python
dbapi_connection.execute(f"SET SESSION AUTHORIZATION '{token}'")
```

**Attack Scenario:**
If a token provider returns a value containing SQL metacharacters (e.g., single quotes), SQL injection becomes possible. For example, a token value of `foo'; DROP TABLE dag_run; --` would result in:
```sql
SET SESSION AUTHORIZATION 'foo'; DROP TABLE dag_run; --'
```

### Remediation
Update the documentation example to use parameterized execution:

```python
dbapi_connection.execute("SET SESSION AUTHORIZATION %s", [token])
```

Note: The exact parameterization syntax depends on the DBAPI driver. The documentation should provide driver-specific examples or recommend using SQLAlchemy's `text()` with bound parameters.

### Acceptance Criteria
- [ ] Documentation example updated to use parameterized queries
- [ ] Driver-specific examples provided
- [ ] Warning added about SQL injection risks
- [ ] Link added to secure coding guidelines

### References
- ASVS 1.2.4: Documentation must not contain insecure code examples
- CWE-89: SQL Injection
- File: `airflow-core/docs/administration-and-deployment/cluster-policies.rst` (lines 150-160)

### Priority
**Low** - Documentation example only, but teaches insecure pattern

---

## Issue: FINDING-035 - No Format Validation on dag_id Parameter
**Labels:** enhancement, security, priority:low
**Description:**
### Summary
The dag_id parameter accepts any string value without format or pattern validation. While the value is used safely in parameterized database queries (preventing injection) and validated by existence check against the database, there is no positive validation against an expected pattern before database lookup.

### Details
**Impact:**
Without format validation, the system performs unnecessary database queries for clearly invalid inputs (e.g., strings with special characters, extremely long strings), which could contribute to minor resource consumption.

### Remediation
Implement a regex pattern check for dag_id at the common API layer:

```python
import re

DAG_ID_PATTERN = re.compile(r"^[a-zA-Z0-9._-]{1,250}$")

def trigger_dag(dag_id: str, ...) -> DagRun | None:
    if not DAG_ID_PATTERN.match(dag_id):
        raise ValueError(f"Invalid dag_id format: {dag_id!r}")
    ...
```

### Acceptance Criteria
- [ ] DAG ID pattern validation implemented
- [ ] Invalid formats rejected before database lookup
- [ ] Test added for format validation
- [ ] Documentation updated with dag_id format requirements

### References
- ASVS 2.2.1: Input validation must use positive patterns
- File: `airflow-core/src/airflow/api/common/trigger_dag.py` (line 135)

### Priority
**Low** - Minor resource consumption issue

---

## Issue: FINDING-036 - No Schema Validation on DAG Run Configuration (conf)
**Labels:** enhancement, security, priority:low
**Description:**
### Summary
The conf parameter is validated only for type (must be dict or null). No size limits, depth limits, or structural schema validation is applied to the JSON content. Arbitrarily large or deeply nested configurations are accepted.

### Details
**Attack Scenario:**
An attacker with API access could submit extremely large or deeply nested configuration objects, consuming parsing time and database storage.

**Mitigation:**
This is likely mitigated by HTTP request size limits at the web server/reverse proxy layer.

### Remediation
Implement maximum size and depth checks on the JSON configuration:

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

### Acceptance Criteria
- [ ] Size limit validation implemented
- [ ] Depth limit validation implemented
- [ ] Test added for oversized configuration rejection
- [ ] Documentation updated with conf size limits

### References
- ASVS 2.2.1: Input validation must include size limits
- File: `airflow-core/src/airflow/api/common/trigger_dag.py` (line 35)

### Priority
**Low** - Likely mitigated by web server limits

---

## Issue: FINDING-037 - Potential TOCTOU in DAG Deletion Running-Task Check
**Labels:** bug, security, priority:low
**Description:**
### Summary
The function checks for running task instances and then proceeds to delete DAG data. Between the check and the deletion, there is a time window where a task instance could transition to RUNNING state (started by the scheduler).

### Details
While this is within the same database session/transaction, the initial check uses a non-locking `select` without `FOR UPDATE`.

**Risk Assessment:**
In practice, the deletion of the DagModel record would prevent new DagRuns from being scheduled, and the entire operation is within a single session transaction. The scheduler would also check for DagModel existence before scheduling. The risk is primarily theoretical—a task that was just started would be deleted mid-execution, but its state in the database would be cleaned up.

### Remediation
Consider using `SELECT ... FOR UPDATE` on the DagModel to prevent concurrent scheduling during deletion:

```python
dag = session.scalar(
    select(DagModel)
    .where(DagModel.dag_id == dag_id)
    .with_for_update()
    .limit(1)
)
```

### Acceptance Criteria
- [ ] FOR UPDATE added to DagModel query
- [ ] Test added for concurrent scheduling prevention
- [ ] Documentation updated describing deletion behavior

### References
- ASVS 2.3.1: Race conditions must be prevented in critical operations
- File: `airflow-core/src/airflow/api/common/delete_dag.py` (lines 55-62)

### Priority
**Low** - Theoretical race condition with minimal practical impact

---

## Issue: FINDING-038 - Helm chart ingress example missing TLS protocol version annotations
**Labels:** documentation, security, priority:low
**Description:**
### Summary
The Helm chart ingress example enables TLS but does not include annotations for enforcing minimum TLS protocol versions. While the Kubernetes Ingress controller may have reasonable defaults, explicitly documenting TLS version enforcement aligns with defense-in-depth.

### Details
**Risk:**
Low risk since many ingress controllers default to TLS 1.2+, but without explicit configuration, deployments on older or misconfigured ingress controllers may accept deprecated protocols.

### Remediation
Add TLS version annotation to the Helm ingress example:

```yaml
annotations:
  nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1.2 TLSv1.3"
```

### Acceptance Criteria
- [ ] TLS version annotation added to example
- [ ] Documentation updated with TLS configuration guidance
- [ ] Example provided for other ingress controllers (Traefik, AWS ALB)

### References
- ASVS 12.1.1: TLS version restrictions required
- File: `airflow-core/docs/howto/run-behind-proxy.rst` (lines 73-95)

### Priority
**Low** - Documentation enhancement for defense-in-depth

---

## Issue: FINDING-039 - Missing production TLS certificate configuration documentation
**Labels:** documentation, security, priority:low
**Description:**
### Summary
While the self-signed certificate documentation properly includes a caution that it is "not suitable for production use," there is no corresponding documentation providing equivalent detailed guidance for configuring publicly trusted certificates in production.

### Details
The documentation asymmetry means operators have step-by-step instructions for insecure certificate configuration but must discover production TLS setup on their own.

### Remediation
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

### Acceptance Criteria
- [ ] Production TLS documentation created or linked
- [ ] CA-signed certificate configuration examples provided
- [ ] Let's Encrypt integration guidance added
- [ ] Link added from self-signed certificate documentation

### References
- ASVS 12.2.2: Production TLS configuration must be documented
- File: `airflow-core/docs/howto/run-with-self-signed-certificate.rst`

### Priority
**Low** - Documentation gap for production deployments

---

## Issue: FINDING-040 - Excessive certificate validity period in development example
**Labels:** documentation, security, priority:low
**Description:**
### Summary
The certificate validity period of 3650 days (10 years) is excessive even for development environments. While the document is clearly marked for development use only, the long validity period sets a bad precedent and increases risk if the certificate is inadvertently used beyond its intended scope.

### Details
The example command:
```bash
-sha256 -days 3650 -nodes \
```

### Remediation
Reduce the example validity to a shorter period more appropriate for development/testing:

```bash
-sha256 -days 365 -nodes \
```

### Acceptance Criteria
- [ ] Example validity period reduced to 365 days
- [ ] Documentation updated explaining validity period choice
- [ ] Note added about certificate rotation best practices

### References
- ASVS 12.2.2: Certificate validity periods should be reasonable
- File: `airflow-core/docs/howto/run-with-self-signed-certificate.rst` (line 35)

### Priority
**Low** - Development example improvement

## Issue: FINDING-041 - Static file serving without Content-Disposition or Sec-Fetch validation
**Labels:** bug, security, priority:low
**Description:**
### Summary
Static files are served with `html=True` in the FastAPI application, allowing HTML file serving without Sec-Fetch-* header validation or Content-Disposition controls. While current risk is low (application-owned static files), this could enable content-type confusion attacks if user content reaches the static directory.

### Details
**File:** `airflow-core/src/airflow/api_fastapi/core_api/app.py` (lines 65-70)
**CWE:** CWE-16 (Configuration)
**ASVS:** 3.2.1 (L1)

The `StaticFiles` middleware is configured with `html=True`, permitting HTML content serving from the static directory. There is no validation of Sec-Fetch-* headers to ensure static resources are loaded only as sub-resources (not direct navigation targets). If any mechanism allows user-influenced content to be placed in the static directory, it could be served and executed as HTML without restriction.

### Remediation
1. Set `html=False` in `StaticFiles` configuration if HTML serving from static paths is not required
2. Implement Sec-Fetch-* header validation middleware to verify static resources are loaded only as sub-resources:
   - Check `Sec-Fetch-Dest` is not `document`
   - Verify `Sec-Fetch-Mode` is not `navigate`
3. Ensure security headers middleware (CSP, X-Content-Type-Options) covers static file responses
4. Add explicit Content-Disposition headers for downloadable content

### Acceptance Criteria
- [ ] Fixed: StaticFiles configured with `html=False` or Sec-Fetch validation added
- [ ] Test added: Verify HTML files in static directory cannot be navigated to directly
- [ ] Test added: Confirm static resources load correctly as sub-resources
- [ ] Documentation updated with static file security guidelines

### References
- ASVS 3.2.1: Context-aware output encoding
- CWE-16: Configuration

### Priority
Low - Current risk limited to application-owned static files, but defense-in-depth recommended

---

## Issue: FINDING-042 - Template rendering with dynamic context values — limited audit scope
**Labels:** bug, security, priority:low
**Description:**
### Summary
Server-side template rendering injects `request.base_url.path` into HTML templates. While Jinja2 auto-escaping mitigates server-side XSS, the React/TypeScript frontend code is outside audit scope, preventing assessment of client-side rendering safety.

### Details
**File:** `airflow-core/src/airflow/api_fastapi/core_api/app.py` (lines 104-112)
**CWE:** CWE-79 (Cross-site Scripting)
**ASVS:** 3.2.2 (L1)

The template context injects `request.base_url.path` (derived from Host header and application configuration) into HTML templates. Jinja2's default auto-escaping provides protection for server-side rendering. However, the React UI code in `airflow/ui/` was not included in the audit scope, preventing verification of:
- Use of safe React JSX interpolation vs. `dangerouslySetInnerHTML`
- Proper escaping of dynamic content in client-side rendering
- Sanitization of markdown/rich-text content

### Remediation
Conduct a comprehensive frontend security audit covering:
1. **React component review**: Verify all dynamic content uses JSX interpolation (auto-escaped)
2. **Dangerous patterns**: Search for `dangerouslySetInnerHTML` usage with user-controlled content
3. **Rich content rendering**: Ensure markdown/HTML rendering uses sanitization libraries (e.g., DOMPurify)
4. **DOM manipulation**: Verify use of `textContent`/`createTextNode` instead of `innerHTML` in vanilla JS
5. **Third-party components**: Audit any UI libraries for known XSS vulnerabilities

### Acceptance Criteria
- [ ] Fixed: Frontend code audit completed with findings addressed
- [ ] Test added: Automated tests for XSS vectors in React components
- [ ] Test added: CSP violation tests for inline scripts
- [ ] Documentation: Frontend security guidelines established

### References
- ASVS 3.2.2: Context-aware output encoding for clients
- CWE-79: Improper Neutralization of Input During Web Page Generation
- React Security Best Practices: https://react.dev/learn/writing-markup-with-jsx#the-rules-of-jsx

### Priority
Low - Server-side rendering is protected; client-side risk unknown due to scope limitation

---

## Issue: FINDING-043 - No middleware-level enforcement preventing GET requests to state-changing router endpoints
**Labels:** bug, security, priority:low
**Description:**
### Summary
The application lacks centralized middleware to prevent state-changing operations on safe HTTP methods (GET, HEAD, OPTIONS) or validate Sec-Fetch-* headers. While FastAPI provides route-level method restriction, there's no architectural safeguard against accidental exposure of state-changing logic via GET requests.

### Details
**File:** `airflow-core/src/airflow/api_fastapi/core_api/app.py` (lines 38-42)
**CWE:** CWE-650 (Trusting HTTP Permission Methods on the Server Side)
**ASVS:** 3.5.3 (L1)

The application registers `public_router` and `ui_router` without visible middleware-level guards that:
1. Audit or restrict HTTP methods for state-changing endpoints
2. Validate Sec-Fetch-* headers to ensure requests didn't originate from navigations
3. Prevent developers from accidentally registering state-changing logic on GET routes

Without centralized enforcement, state-changing operations could be triggered via simple navigation, image tags, or link prefetching.

### Remediation
Implement a `SecFetchValidationMiddleware` class:

```python
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

class SecFetchValidationMiddleware(BaseHTTPMiddleware):
    SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
    
    async def dispatch(self, request, call_next):
        # Skip validation for safe methods
        if request.method in self.SAFE_METHODS:
            return await call_next(request)
        
        # Validate Sec-Fetch-Site for state-changing requests
        sec_fetch_site = request.headers.get("sec-fetch-site")
        if sec_fetch_site not in {"same-origin", "same-site", "none"}:
            return JSONResponse(
                {"detail": "Cross-site request rejected"},
                status_code=403
            )
        
        return await call_next(request)
```

Add to application:
```python
app.add_middleware(SecFetchValidationMiddleware)
```

### Acceptance Criteria
- [ ] Fixed: SecFetchValidationMiddleware implemented and registered
- [ ] Test added: Verify cross-site POST/PUT/DELETE requests are rejected
- [ ] Test added: Confirm same-origin state-changing requests succeed
- [ ] Test added: Ensure safe methods (GET/HEAD/OPTIONS) bypass validation
- [ ] Documentation: HTTP method security guidelines added

### References
- ASVS 3.5.3: CSRF protection mechanisms
- CWE-650: Trusting HTTP Permission Methods on the Server Side
- Fetch Metadata: https://web.dev/fetch-metadata/

### Priority
Low - Defense-in-depth measure; primary CSRF protection should exist at route level

---

## Issue: FINDING-044 - Static file responses may lack charset parameter for text/* MIME types
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `StaticFiles` middleware uses Python's `mimetypes` module without ensuring `charset` parameters for `text/*` content types. This may cause encoding issues or enable charset-sniffing attacks in legacy browsers.

### Details
**File:** `airflow-core/src/airflow/api_fastapi/core_api/app.py` (lines 56-67)
**CWE:** CWE-436 (Interpretation Conflict)
**ASVS:** 4.1.1 (L1)

Starlette's `StaticFiles` determines Content-Type headers using Python's `mimetypes` module, which may not include charset parameters:
- `.css` → `text/css` (missing `; charset=utf-8`)
- `.js` → `application/javascript` or `text/javascript` (platform-dependent)

While modern browsers default to UTF-8, ASVS requires explicit charset specification for `text/*` responses. Without it, browsers in legacy/strict mode may fall back to platform-dependent encoding, potentially causing:
- Display issues with non-ASCII characters
- Charset-sniffing attacks in edge cases

### Remediation
Implement a `CharsetMiddleware` to add charset parameters:

```python
from starlette.middleware.base import BaseHTTPMiddleware

class CharsetMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        content_type = response.headers.get("content-type", "")
        
        # Add charset to text/* types if not present
        if content_type.startswith("text/") and "charset" not in content_type:
            response.headers["content-type"] = f"{content_type}; charset=utf-8"
        
        return response

# Register middleware
app.add_middleware(CharsetMiddleware)
```

### Acceptance Criteria
- [ ] Fixed: CharsetMiddleware implemented and registered
- [ ] Test added: Verify CSS files include `charset=utf-8`
- [ ] Test added: Verify JavaScript files include charset parameter
- [ ] Test added: Confirm non-text files unchanged
- [ ] Test added: Ensure existing charset parameters not duplicated

### References
- ASVS 4.1.1: Character set encoding
- CWE-436: Interpretation Conflict
- RFC 2046: MIME Media Types

### Priority
Low - Modern browsers handle UTF-8 by default; primarily affects legacy environments

---

## Issue: FINDING-045 - No Documentation of Source Control Metadata Exclusion in Deployment Guidance
**Labels:** bug, security, priority:low, documentation
**Description:**
### Summary
Deployment architecture documentation does not specify exclusion of source control metadata (`.git`, `.svn` folders) from production deployments, potentially exposing repository history, internal paths, and sensitive information to attackers.

### Details
**Files:** 
- `airflow-core/docs/core-concepts/overview.rst` (lines 67-80)
- `AGENTS.md`

**ASVS:** 13.4.1 (L1)

The deployment documentation discusses patterns and Helm charts but omits security hardening guidance for excluding source control metadata. If included in deployments, attackers could access:
- Complete repository history (including reverted secrets)
- Internal file paths and developer information
- Branch structure revealing development practices
- Commit messages with internal references

### Remediation
Add a "Deployment Security Hardening" section to documentation covering:

1. **Docker Images**
   - Create `.dockerignore` with `.git/`, `.svn/`, `.hg/`
   - Verify exclusion in build output

2. **DAG Synchronization**
   - Configure git-sync with `--depth 1` flag
   - Exclude `.git/` directory from volume mounts
   - Ensure DAG directories deny access to hidden folders

3. **Web Server Configuration**
   - Add location blocks denying access to `/.git`, `/.svn`, `/.hg`
   - Example nginx config:
     ```nginx
     location ~ /\.(git|svn|hg) {
         deny all;
         return 404;
     }
     ```

4. **Helm Chart Deployments**
   - Document verification that official Airflow images exclude metadata
   - Add validation step for custom images

5. **CI/CD Pipeline**
   - Add automated checks for source control metadata in artifacts
   - Fail builds if `.git/` detected in deployment packages

### Acceptance Criteria
- [ ] Fixed: Deployment security documentation created
- [ ] Documentation: `.dockerignore` template added to repository
- [ ] Documentation: Helm chart security checklist created
- [ ] Test added: CI/CD check for source control metadata in artifacts
- [ ] Documentation: Web server configuration examples added

### References
- ASVS 13.4.1: Source code and metadata exclusion
- OWASP: Information Leakage
- Docker documentation: .dockerignore

### Priority
Low - Preventative measure; risk depends on secrets in repository history