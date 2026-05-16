# Security Issues

## Issue: FINDING-002 - JWT Refresh Does Not Invalidate Previous Token, Enabling Replay Attacks
**Labels:** bug, security, priority:high
**Description:**
### Summary
The JWT refresh mechanism in `JWTRefreshMiddleware.dispatch()` generates new tokens but does not revoke or invalidate the old token. When a token is refreshed, both the old and new tokens remain valid for their full lifetime (default 24 hours).

### Details
This allows an attacker who has captured a valid JWT token to continue using it even after the legitimate user's session has been refreshed.

**Data flow:** 
current_token (cookie) → _refresh_user() → new JWT generated → old token remains valid

**Proof of concept:**
1. Attacker captures a valid JWT token from a user's browser
2. The legitimate user's token gets refreshed by JWTRefreshMiddleware with a new token issued
3. The attacker continues to use the captured old token which remains valid for up to 24 hours

**CWE:** CWE-613  
**ASVS:** 10.4.5, 7.2.4 (L1)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py:48-73`
- `airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py:57-60`

### Remediation
Implement token revocation during refresh by calling `revoke_token(current_token)` when a new token is successfully generated.

**Example implementation:**
```python
if new_user:
    new_token = get_auth_manager().generate_jwt(new_user)
    from airflow.api_fastapi.auth.tokens import get_sig_validation_args, JWTValidator
    validator = JWTValidator(**get_sig_validation_args(), audience=...)
    validator.revoke_token(current_token)
    set_response_cookie(new_token)
```

Alternatively, implement refresh token rotation with family tracking where:
- On refresh, the old token's jti is marked in the revoked_token table
- On validation, the jti is checked against the revoked_token table
- If a revoked token is presented, all tokens in the same family (jti chain) are revoked

### Acceptance Criteria
- [ ] Old tokens are revoked when new tokens are issued during refresh
- [ ] Test added for old token rejection after refresh
- [ ] Test added for new token acceptance after refresh
- [ ] Token family tracking implemented (if using family approach)

### References
- Related: FINDING-001, FINDING-003, FINDING-009
- ASVS 10.4.5, 7.2.4

### Priority
**HIGH** - Defeats the purpose of token rotation as a replay mitigation measure

---

## Issue: FINDING-003 - No Mechanism for Bulk Session Invalidation on Account Termination
**Labels:** bug, security, priority:high
**Description:**
### Summary
The JWTValidator class provides only `revoke_token(self, token: str)` which revokes a single known token by its JTI. There is no `revoke_all_user_tokens(user_id)` method, per-user 'not valid before' timestamp mechanism, per-user signing key rotation, or user-scoped token invalidation of any kind.

### Details
When an employee leaves the company and their account is disabled/deleted, any previously issued JWT tokens remain valid until their natural expiration (up to 24 hours for REST API tokens, 10 minutes for execution tokens).

The system has no way to invalidate all tokens for a specific user identity because:
1. The `revoke_token` method requires the actual token string (not available for all sessions)
2. There's no per-user invalidation timestamp in the JWT validation flow
3. Even if revocation worked, the validation doesn't check it (as noted in JWT-001)

This is a Type A gap - no control exists for bulk session termination on account disable/delete.

**CWE:** CWE-613  
**ASVS:** 7.4.2 (L1)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/tokens.py` (entire file)

### Remediation
Implement one of two options:

**Option A - Per-user 'not valid before' timestamp:**
In `JWTValidator.avalidated_claims()`, after `jwt.decode()`, check user-level invalidation:
```python
user_invalidation = UserSessionInvalidation.get_for_user(sub)
if user_invalidation and iat < user_invalidation.not_valid_before:
    raise jwt.InvalidTokenError(f'Token invalidated for user {sub}')
```

**Option B - Token issuance tracking:**
Create an `IssuedToken` model that tracks jti, user_id, and exp with user_id index:
```python
def disable_user(user_id):
    IssuedToken.revoke_all_for_user(user_id)
```

### Acceptance Criteria
- [ ] Per-user invalidation mechanism implemented
- [ ] Test added for token invalidation on user disable
- [ ] Test added for valid token acceptance for active users
- [ ] Administrative interface for bulk token revocation
- [ ] Documentation updated with user termination procedures

### References
- Related: FINDING-001, FINDING-002, FINDING-009
- ASVS 7.4.2

### Priority
**HIGH** - Critical for employee offboarding security

---

## Issue: FINDING-004 - Algorithm Blocklist Not Implemented, Allowing 'none' Algorithm Configuration
**Labels:** bug, security, priority:high
**Description:**
### Summary
The JWT validation code lacks an explicit blocklist of dangerous algorithms. There is no hardcoded check that prevents misconfiguration from introducing vulnerabilities by allowing algorithms like 'none', 'None', or 'NONE' which would disable signature validation entirely.

### Details
The code relies on 'safe defaults' (GUESS → HS512/RS256/EdDSA) but does not actively prevent configuration errors.

**Configuration data flow:** 
[api_auth] jwt_algorithm → _conf_list_factory → JWTValidator.algorithm → jwt.decode(algorithms=...)

If an administrator sets `jwt_algorithm = none` in airflow.cfg:
- The `JWTValidator.algorithm` becomes ['none']
- `jwt.decode()` is called with `algorithms=['none']`
- Tokens without any cryptographic signature would be accepted
- An attacker could forge arbitrary tokens

**CWE:** CWE-327  
**ASVS:** 10.4.5, 9.1.2 (L1)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/tokens.py:193-199`
- `airflow-core/src/airflow/api_fastapi/auth/tokens.py:322-331`

### Remediation
Add a hardcoded set of blocked algorithms that is checked in both `JWTValidator.__attrs_post_init__` and `JWTGenerator.__attrs_post_init__`:

```python
_BLOCKED_ALGORITHMS = frozenset({'none', 'None', 'NONE'})
_ALLOWED_ALGORITHMS = frozenset({
    'HS256', 'HS384', 'HS512', 
    'RS256', 'RS384', 'RS512', 
    'ES256', 'ES384', 'ES512', 
    'EdDSA', 'PS256', 'PS384', 'PS512'
})

def __attrs_post_init__(self):
    for alg in self.algorithm:
        if alg.lower() in _BLOCKED_ALGORITHMS:
            raise ValueError(f'Algorithm {alg} is not allowed')
        if alg not in _ALLOWED_ALGORITHMS:
            raise ValueError(f'Algorithm {alg} is not in the allowed set')
```

### Acceptance Criteria
- [ ] Algorithm blocklist implemented in both JWTValidator and JWTGenerator
- [ ] Test added for 'none' algorithm rejection
- [ ] Test added for other blocked algorithm variants
- [ ] Test added for valid algorithms acceptance
- [ ] Configuration validation at startup

### References
- Related: FINDING-033
- ASVS 10.4.5, 9.1.2

### Priority
**HIGH** - Prevents configuration errors from disabling signature validation

---

## Issue: FINDING-005 - No mechanism for users to change their passwords
**Labels:** bug, security, priority:high
**Description:**
### Summary
The Simple Auth Manager provides NO mechanism for users to change their passwords. The available endpoints are exclusively for authentication (token creation). There is no PUT/PATCH/POST endpoint for password modification.

### Details
The OpenAPI specification confirms only `/auth/token`, `/auth/token/login`, and `/auth/token/cli` endpoints exist.

**Data flow:**
User wants to change password → No endpoint exists → User cannot change password → Only option is admin manually editing password file or deleting it to trigger regeneration

There is no HTTP method or path combination that allows a user to submit a new password. The password file at `simple_auth_manager_passwords.json.generated` is only written during `init()` when a user doesn't already have a password.

**ASVS:** 6.2.2 (L1)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py` (entire file)
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/openapi/v2-simple-auth-manager-generated.yaml` (paths section)

### Remediation
Implement a password change endpoint:

```python
@login_router.post("/token/change-password", status_code=status.HTTP_200_OK)
async def change_password(
    body: ChangePasswordBody,
    current_user: User = Depends(get_current_user)
):
    # 1. Verify current password
    if not verify_current_password(current_user, body.current_password):
        raise HTTPException(status_code=401, detail="Invalid current password")
    
    # 2. Validate new password length (minimum 8 characters)
    if len(body.new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    
    # 3. Check against common passwords
    if is_common_password(body.new_password):
        raise HTTPException(status_code=400, detail="Password is too common")
    
    # 4. Update password in storage atomically with file locking
    update_password(current_user.username, body.new_password)
    
    return {"status": "password changed successfully"}
```

### Acceptance Criteria
- [ ] Password change endpoint implemented
- [ ] Current password verification added
- [ ] New password validation added (length, common passwords)
- [ ] Atomic file update with locking
- [ ] Test added for successful password change
- [ ] Test added for invalid current password rejection
- [ ] Test added for weak password rejection
- [ ] OpenAPI spec updated

### References
- ASVS 6.2.2
- NIST SP 800-63B §5.1.1.2

### Priority
**HIGH** - Users cannot respond to suspected credential compromise

---

## Issue: FINDING-006 - No password change functionality exists - current password verification requirement cannot be satisfied
**Labels:** bug, security, priority:high
**Description:**
### Summary
Since no password change functionality exists (per ASVS-622-HIGH-001), the requirement that password changes require both current and new password cannot be satisfied. There is no endpoint, service method, or data model that accepts a current password for verification alongside a new password.

### Details
If a password change mechanism is added later without this requirement, it could enable account takeover via CSRF or session hijacking (attacker with active session could change password without knowing the original).

Without current password verification, any bearer of a valid JWT could change any user's password.

**ASVS:** 6.2.3 (L1)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py` (entire file)
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py`

### Remediation
Implement alongside ASVS-622-HIGH-001 (FINDING-005) — ensure the `ChangePasswordBody` model requires both `current_password` and `new_password` fields, and that `current_password` is verified against stored credentials using constant-time comparison before allowing the change.

```python
class ChangePasswordBody(BaseModel):
    current_password: str
    new_password: str

def verify_current_password(user: User, current_password: str) -> bool:
    stored_hash = get_stored_password_hash(user.username)
    return secrets.compare_digest(
        hash_password(current_password),
        stored_hash
    )
```

### Acceptance Criteria
- [ ] ChangePasswordBody model created with both fields
- [ ] Current password verification implemented with constant-time comparison
- [ ] Test added for correct current password acceptance
- [ ] Test added for incorrect current password rejection
- [ ] Test added for timing attack resistance

### References
- Related: FINDING-005
- ASVS 6.2.3

### Priority
**HIGH** - Required security control for password change functionality

---

## Issue: FINDING-007 - Anonymous Admin Account Created Without Credentials in All-Admins Mode
**Labels:** bug, security, priority:high
**Description:**
### Summary
When `simple_auth_manager_all_admins` is set to `True`, a hardcoded "Anonymous" user with ADMIN role is accessible without any credentials via simple GET request. This is effectively a default admin account with no password.

### Details
While the SimpleAuthManager is documented as dev-only, the configuration flag lacks enforcement preventing production use beyond a log warning.

**Data flow:** 
Configuration flag `simple_auth_manager_all_admins=True` → `GET /auth/token` (no auth required) → `create_token_all_admins()` → `_create_anonymous_admin_user()` → Full ADMIN JWT token returned

**ASVS:** 6.3.2 (L1)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py:101-109`
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py:77`
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py:85`

### Remediation
Add hard guard against production-like environments in `_create_anonymous_admin_user()` method:

```python
def _create_anonymous_admin_user(self) -> User:
    if SimpleAuthManager._looks_like_production():
        raise HTTPException(
            status_code=403,
            detail="Anonymous admin access is not allowed in production environments"
        )
    # ... existing implementation
```

Additionally, the `simple_auth_manager_all_admins` configuration should be programmatically blocked when production indicators are detected, not just warned about. Require explicit opt-in flag (e.g., `simple_auth_manager_i_know_what_i_am_doing=True`) for production-like environments.

### Acceptance Criteria
- [ ] Production environment detection implemented
- [ ] Hard block added for anonymous admin in production
- [ ] Test added for production environment rejection
- [ ] Test added for dev environment acceptance
- [ ] Configuration validation at startup
- [ ] Documentation updated with security warnings

### References
- ASVS 6.3.2

### Priority
**HIGH** - Default admin account without credentials

---

## Issue: FINDING-008 - Generated Initial Passwords Never Expire and Become Long-Term Credentials
**Labels:** bug, security, priority:high
**Description:**
### Summary
System-generated passwords are stored permanently in a plaintext JSON file with no expiration timestamp, never require the user to change them after first use, are printed to stdout/logs on generation (visible in container logs, CI systems, etc.), and are the ONLY password mechanism with no 'change password' endpoint or flow.

### Details
This violates the requirement that initial secrets 'expire after a short period of time or after they are initially used' and 'must not be permitted to become the long term password.'

**ASVS:** 6.4.1 (L1)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:175-186`
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:481-484`

### Remediation
Store passwords with metadata including 'created_at' timestamp and 'must_change' flag:

```python
# Password storage format
{
    "username": {
        "password": "hashed_password",
        "created_at": "2024-01-01T00:00:00Z",
        "must_change": true
    }
}

# In create_token method
def create_token(body: LoginBody, ...) -> str:
    password_data = get_password_data(body.username)
    
    # Check must_change flag
    if password_data.get('must_change', False):
        raise HTTPException(
            status_code=403,
            detail="Password must be changed before first use"
        )
    
    # Check password age
    created_at = datetime.fromisoformat(password_data['created_at'])
    if datetime.now() - created_at > INITIAL_PASSWORD_TTL:
        raise HTTPException(
            status_code=401,
            detail="Initial password has expired"
        )
    
    # ... existing authentication logic
```

Implement a password change endpoint to allow users to set a new password after first use.

### Acceptance Criteria
- [ ] Password metadata storage implemented (created_at, must_change)
- [ ] Password expiration check added to authentication
- [ ] Must-change flag enforcement added
- [ ] Password change endpoint implemented (see FINDING-005)
- [ ] Test added for expired password rejection
- [ ] Test added for must-change enforcement
- [ ] Test added for successful password change

### References
- Related: FINDING-005
- ASVS 6.4.1

### Priority
**HIGH** - Initial credentials become permanent without expiration

---

## Issue: FINDING-009 - REST API Token Lifetime of 24 Hours is Excessive for Public Client Sessions
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The default REST API token lifetime is configured to 86400 seconds (24 hours) via the `[api_auth] jwt_expiration_time` setting. Combined with the lack of old-token invalidation during refresh (JWT-002), this 24-hour token lifetime means captured tokens have a very long replay window.

### Details
For public clients where refresh token rotation is meant to limit damage from token theft, a 24-hour window significantly reduces the security benefit of token rotation.

**CWE:** CWE-613  
**ASVS:** 10.4.5 (L1)

**Affected Files:**
- `airflow-core/docs/security/jwt_token_authentication.rst`

### Remediation
Reduce REST API token lifetime to 15-30 minutes for UI sessions. Rely on the refresh middleware to transparently issue new tokens. Implement proper rotation with old-token invalidation (see JWT-002).

Consider separate short-lived access tokens and longer-lived refresh tokens following the traditional OAuth pattern.

**Configuration change:**
```ini
[api_auth]
# Reduce from 24 hours to 1-2 hours for UI sessions
jwt_expiration_time = 3600  # 1 hour
```

### Acceptance Criteria
- [ ] Default token lifetime reduced to 1-2 hours
- [ ] Refresh middleware verified to work with shorter lifetime
- [ ] Test added for token expiration timing
- [ ] Documentation updated with new default
- [ ] Performance impact assessed

### References
- Related: FINDING-001, FINDING-002, FINDING-003
- ASVS 10.4.5

### Priority
**MEDIUM** - Long replay window for captured tokens

---

## Issue: FINDING-010 - Auto-Generated Signing Key Uses Only 128 Bits for HS512 Algorithm
**Labels:** bug, security, priority:medium
**Description:**
### Summary
While the token identifiers (jti) are UUID4 with 128 bits of entropy (meeting ASVS 7.2.3), the auto-generated signing key is only 128 bits. For HS512 (HMAC-SHA-512), NIST recommends the key be at least as long as the hash output (512 bits / 64 bytes).

### Details
A 128-bit key reduces the effective security below the algorithm's design strength, though it remains computationally infeasible to brute-force.

More critically, this ephemeral key differs across processes in multi-component deployments, causing authentication failures rather than a direct security bypass.

**Data flow:** 
Missing configuration → get_signing_key() → os.urandom(16) (128 bits) → used as HS512 signing key

**Proof of concept:**
Deploy multiple Airflow components (webserver, scheduler) without configuring `[api_auth] jwt_secret`. Each component generates a different random key, causing tokens from one to be rejected by the other.

**CWE:** CWE-326  
**ASVS:** 7.2.3 (L1)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/tokens.py:438-440`

### Remediation
Increase to 64 bytes (512 bits) to match HS512 algorithm strength:

```python
def get_signing_key() -> str:
    """Get or generate JWT signing key."""
    secret_key = conf.get("api_auth", "jwt_secret", fallback=None)
    if not secret_key:
        log.warning(
            "No jwt_secret configured. Generating ephemeral key. "
            "This will cause authentication failures in multi-component deployments."
        )
        secret_key = base64url_encode(os.urandom(64))  # 512 bits
    return secret_key
```

Additionally, ensure deployment documentation emphasizes that `jwt_secret` MUST be explicitly configured in production environments and shared across all components.

### Acceptance Criteria
- [ ] Signing key generation increased to 64 bytes
- [ ] Test added for key length validation
- [ ] Documentation updated with production configuration requirements
- [ ] Warning added for missing jwt_secret configuration
- [ ] Multi-component deployment guide updated

### References
- ASVS 7.2.3

### Priority
**MEDIUM** - Key strength below algorithm design, deployment issues

---

## Issue: FINDING-011 - No `Clear-Site-Data` header sent on logout/session termination
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Without the `Clear-Site-Data` header, the browser does not receive a server-authoritative instruction to clear cookies, cache, and storage associated with the session. While server-side token revocation prevents API access with the revoked token, cached API responses and residual authentication data in browser storage remain accessible.

### Details
On shared devices, this can expose sensitive information from cached responses.

**Data flow:** 
User initiates logout → `revoke_token()` revokes token server-side → `get_url_logout()` returns redirect URL (or None) → NO `Clear-Site-Data` header sent in response → client browser retains cookies, cache, and storage → stale token remains in browser cookie jar until expiration

**ASVS:** 14.3.1 (L1)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:168-176`
- `airflow-core/src/airflow/api_fastapi/core_api/app.py` (full file)

### Remediation
Add `Clear-Site-Data` header to logout responses:

```python
from fastapi import Response

@router.post("/logout")
async def logout(response: Response, token: str = Depends(get_current_token)):
    auth_manager.revoke_token(token)
    response.headers["Clear-Site-Data"] = '"cache", "cookies", "storage"'
    return {"status": "logged out"}
```

For the base auth manager, provide a helper method:
```python
@staticmethod
def get_logout_headers() -> dict[str, str]:
    """Return headers that should be included in logout responses."""
    return {"Clear-Site-Data": '"cache", "cookies", "storage"'}
```

### Acceptance Criteria
- [ ] Clear-Site-Data header added to logout endpoint
- [ ] Helper method added to base auth manager
- [ ] Test added for header presence in logout response
- [ ] Test added for browser cache/storage clearing
- [ ] Documentation updated with logout behavior

### References
- ASVS 14.3.1

### Priority
**MEDIUM** - Cached data persists after logout on shared devices

---

## Issue: FINDING-012 - Cookie name `_token` missing required `__Secure-` or `__Host-` prefix
**Labels:** bug, security, priority:medium
**Description:**
### Summary
JWT token generated by server → returned in `LoginResponse.access_token` → stored in cookie named `_token` → cookie lacks `__Secure-` prefix → no browser-level guarantee cookie was set/transmitted securely.

### Details
Without the `__Secure-` prefix, browsers do not enforce that the cookie was set over a secure (HTTPS) connection or has the Secure attribute. This weakens protections against cookie injection/fixation attacks where an attacker forces a known token value, potentially hijacking the session.

A network attacker performing a downgrade attack or injecting an HTTP response could set a cookie named `_token` for the same domain without the Secure flag. Browsers do not enforce that `_token` cookies must have been set over HTTPS, unlike `__Secure-` prefixed cookies.

**ASVS:** 3.3.1 (L1)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:113`
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/ui/src/login/Login.tsx:82`

### Remediation
In `base_auth_manager.py`:
```python
COOKIE_NAME_JWT_TOKEN = "__Secure-_token"
```

In `Login.tsx`:
```typescript
const [, setCookie, removeCookie] = useCookies(["__Secure-_token"]);
// ...
setCookie("__Secure-_token", data.access_token, { 
    path: cookiePath, 
    secure: true 
});
```

All server-side code that reads the cookie by name must also be updated to reference `__Secure-_token`.

### Acceptance Criteria
- [ ] Cookie name changed to `__Secure-_token` in all locations
- [ ] Client-side code updated to use new cookie name
- [ ] Server-side cookie reading updated
- [ ] Test added for cookie prefix presence
- [ ] Test added for Secure attribute enforcement
- [ ] Migration guide for existing deployments

### References
- ASVS 3.3.1

### Priority
**MEDIUM** - Weakens cookie injection/fixation protections

---

## Issue: FINDING-013 - Cookie `Secure` attribute is conditionally set based on client-side protocol detection
**Labels:** bug, security, priority:medium
**Description:**
### Summary
User authenticates → JWT token stored in cookie → `secure` flag determined by `globalThis.location.protocol` → if HTTP, cookie transmitted without Secure flag → susceptible to network interception.

### Details
If the application is deployed behind a reverse proxy that terminates TLS and forwards HTTP to the application (common in container deployments), or in any scenario where the browser loads the page over HTTP:

1. User navigates to `http://airflow.internal/login`
2. `globalThis.location.protocol` evaluates to `"http:"`
3. Cookie is set without Secure attribute: `_token=eyJ...`
4. All subsequent requests transmit the JWT token in cleartext
5. A network attacker captures the token and gains full API access

JWT tokens that grant full API access can be intercepted by network-level attackers when the Secure flag is not set. ASVS 3.3.1 requires the Secure attribute unconditionally.

**ASVS:** 3.3.1 (L1)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/ui/src/login/Login.tsx:83`

### Remediation
Change to:
```typescript
setCookie("__Secure-_token", data.access_token, { 
    path: cookiePath, 
    secure: true  // Always set Secure
});
```

Always set Secure - enforce HTTPS at deployment layer. If HTTP support is needed for local development only, use a separate configuration flag rather than runtime protocol detection, and ensure production builds always set `secure: true`.

### Acceptance Criteria
- [ ] Secure attribute always set to true
- [ ] Test added for Secure attribute presence
- [ ] Development environment guidance updated
- [ ] Production deployment checklist updated
- [ ] Warning added for HTTP deployments

### References
- ASVS 3.3.1

### Priority
**MEDIUM** - Allows token interception over HTTP

---

## Issue: FINDING-014 - Hardcoded `allow_credentials=True` without origin wildcard validation enables credential reflection to any origin if misconfigured
**Labels:** bug, security, priority:medium
**Description:**
### Summary
When `allow_origins` is configured as `*`, Starlette's CORSMiddleware with `allow_credentials=True` reflects the request's Origin header. This allows any website to: Read sensitive API responses including connection details, variables, DAG configurations; Perform state-changing actions (create/delete DAGs, connections) on behalf of authenticated users; Extract JWT tokens from response bodies.

### Details
Administrator sets `access_control_allow_origins = *` in configuration → `conf.getlist()` returns `["*"]` → passed to `CORSMiddleware(allow_origins=["*"], allow_credentials=True)` → Starlette reflects the incoming `Origin` header in `Access-Control-Allow-Origin` response (because `*` + credentials isn't valid per CORS spec, Starlette reflects instead) → Any website can make credentialed cross-origin requests.

This violates ASVS 3.4.2's requirement that the Origin be "validated against an allowlist of trusted origins" and that wildcard responses "do not include any sensitive information."

**ASVS:** 3.4.2 (L1)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/core_api/app.py:155-163`

### Remediation
Prevent dangerous misconfiguration by checking if "*" is in allow_origins:

**Option 1 - Disable credentials:**
```python
if "*" in allow_origins:
    log.warning(
        "CORS allow_origins contains '*'. Disabling allow_credentials "
        "to prevent credential reflection to arbitrary origins."
    )
    allow_credentials = False
else:
    allow_credentials = True
```

**Option 2 - Raise exception:**
```python
if "*" in allow_origins and allow_credentials:
    raise AirflowException(
        "CORS configuration error: 'access_control_allow_origins = *' "
        "cannot be used with credentialed requests. Specify explicit origins instead."
    )
```

### Acceptance Criteria
- [ ] Wildcard + credentials validation implemented
- [ ] Test added for wildcard rejection with credentials
- [ ] Test added for wildcard acceptance without credentials
- [ ] Test added for explicit origins with credentials
- [ ] Configuration validation at startup
- [ ] Documentation updated with CORS security guidance

### References
- ASVS 3.4.2

### Priority
**MEDIUM** - Allows credential reflection to arbitrary origins if misconfigured

---

## Issue: FINDING-015 - OAuth2 Resource Owner Password Credentials Flow Advertised and Used
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The code explicitly uses FastAPI's `OAuth2PasswordBearer` scheme, which advertises the OAuth2 Resource Owner Password Credentials flow in the generated OpenAPI specification. ASVS 10.4.4 explicitly states that the 'password' grant type must no longer be used.

### Details
The OpenAPI specification generated by FastAPI will advertise the OAuth2 password flow, directing API consumers and tooling (Swagger UI, code generators) to use the password flow by default. This direct credential exchange exposes user passwords to API clients rather than using redirect-based flows.

**ASVS:** 10.4.4 (L1)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/core_api/security.py:111`
- `airflow-core/src/airflow/api_fastapi/core_api/security.py:99-107`

### Remediation
Replace `OAuth2PasswordBearer` with a scheme that doesn't advertise the password flow.

**Option 1 (Recommended) - Use generic Bearer token scheme:**
```python
from fastapi.security import HTTPBearer

oauth2_scheme = HTTPBearer(
    description='JWT Bearer token obtained via authorization code flow or SSO redirect',
    auto_error=False
)
```

**Option 2 - Implement full Authorization Code Flow:**
```python
from fastapi.security import OAuth2AuthorizationCodeBearer

oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl="/auth/authorize",
    tokenUrl="/auth/token"
)
```

Update all references to `oauth2_scheme` throughout the codebase to use the new scheme.

### Acceptance Criteria
- [ ] OAuth2PasswordBearer replaced with HTTPBearer or OAuth2AuthorizationCodeBearer
- [ ] OpenAPI spec verified to not advertise password flow
- [ ] All references to oauth2_scheme updated
- [ ] Test added for token extraction
- [ ] Documentation updated with new authentication flow

### References
- ASVS 10.4.4

### Priority
**MEDIUM** - Advertises deprecated OAuth flow

---

## Issue: FINDING-016 - `is_safe_url` uses domain/path matching rather than exact string comparison against pre-registered allowlist
**Labels:** bug, security, priority:medium
**Description:**
### Summary
While `is_safe_url` provides protection against open redirects (same-domain validation), it does NOT implement OAuth redirect URI validation per ASVS 10.4.1 requirements: 1. No client-specific allowlist of pre-registered URIs; 2. No exact string comparison - uses scheme/netloc/path prefix matching; 3. Returns `True` (safe) when no base URLs are configured.

### Details
If this function is used for any OAuth-like redirect URI validation, it would allow any same-domain URL as a valid redirect target, which is insufficient for OAuth authorization servers.

However, based on the provided code, Airflow appears to be an API server (OAuth resource server / token issuer via password grant) rather than an OAuth authorization server with authorization code flows. The `oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")` indicates a Resource Owner Password Credentials flow, which doesn't involve redirect URIs.

This finding is MEDIUM rather than HIGH because the requirement may not be directly applicable to the observed architecture.

**ASVS:** 10.4.1 (L1)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/core_api/security.py:645-689`

### Remediation
If Airflow does implement or plans to implement OAuth authorization code flows:

```python
def validate_redirect_uri(client_id: str, redirect_uri: str) -> bool:
    """Validate redirect_uri using exact string comparison against pre-registered URIs."""
    registered_uris = get_registered_redirect_uris(client_id)
    return redirect_uri in registered_uris  # Exact string comparison
```

### Acceptance Criteria
- [ ] Determine if OAuth authorization code flow is implemented
- [ ] If yes, implement exact string comparison for redirect URIs
- [ ] If yes, implement client-specific URI registration
- [ ] Test added for exact URI matching
- [ ] Test added for rejection of similar but non-matching URIs
- [ ] Documentation clarified on OAuth flow support

### References
- ASVS 10.4.1

### Priority
**MEDIUM** - Insufficient redirect URI validation if OAuth authz code flow is used

---

## Issue: FINDING-017 - `requires_authenticated()` dependency provides authentication-only check without function-level authorization
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Any API endpoint that uses `requires_authenticated()` instead of a specific `requires_access_*` dependency will allow any authenticated user to invoke that function regardless of their assigned permissions.

### Details
Without seeing all route definitions, there's a risk of Type B gaps (control exists but wrong control applied). This function is intentionally designed for endpoints where any authenticated user should have access. The risk is if it's accidentally used on permission-sensitive endpoints.

**ASVS:** 8.2.1 (L1)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/core_api/security.py:605-614`

### Remediation
Consider adding a linter rule or architectural decision record that requires each endpoint to explicitly justify use of `requires_authenticated()` over a specific authorization dependency.

Add a decorator or annotation that marks endpoints as "public to all authenticated users" to make this intentional:

```python
@router.get("/public-endpoint")
@requires_authenticated()
@mark_public_to_authenticated  # Explicit marker
async def public_endpoint():
    """Endpoint accessible to all authenticated users."""
    pass
```

### Acceptance Criteria
- [ ] Code review checklist updated to verify authorization dependencies
- [ ] Linter rule added to flag requires_authenticated usage
- [ ] Documentation added explaining when to use requires_authenticated vs requires_access_*
- [ ] Audit of existing endpoints using requires_authenticated
- [ ] Explicit marker decorator added

### References
- ASVS 8.2.1

### Priority
**MEDIUM** - Risk of incorrect authorization control application

---

## Issue: FINDING-018 - No check against common/breached password list
**Labels:** bug, security, priority:medium
**Description:**
### Summary
There is no check against a list of common/breached passwords anywhere in the codebase. While the current system auto-generates passwords with high entropy (making collision with common passwords statistically negligible), the absence of a common password check means: 1. If a password change endpoint is added, it would have no blocklist infrastructure; 2. Manually-edited password files could contain common passwords without detection; 3. The system cannot reject weak passwords if the password generation mechanism is ever modified.

### Details
The login endpoint only validates that a password is non-empty, not that it meets minimum length.

**ASVS:** 6.2.4 (L1)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py`
- `services/login.py`

### Remediation
Implement a common password blocklist check:

```python
import os

COMMON_PASSWORDS_FILE = os.path.join(os.path.dirname(__file__), "common_passwords.txt")

def _load_common_passwords() -> set[str]:
    """Load at least top 3000 common passwords."""
    with open(COMMON_PASSWORDS_FILE) as f:
        return {line.strip().lower() for line in f if len(line.strip()) >= 8}

_COMMON_PASSWORDS = _load_common_passwords()

def is_common_password(password: str) -> bool:
    return password.lower() in _COMMON_PASSWORDS
```

Bundle a list of at least 3000 common passwords and check against this list during password changes and account creation.

### Acceptance Criteria
- [ ] Common password list file added (at least 3000 entries)
- [ ] is_common_password function implemented
- [ ] Check integrated into password validation
- [ ] Test added for common password rejection
- [ ] Test added for uncommon password acceptance
- [ ] Performance impact assessed

### References
- ASVS 6.2.4

### Priority
**MEDIUM** - No protection against common passwords if validation is added

---

## Issue: FINDING-019 - No Application-Level Account Lockout or Failed Login Tracking
**Labels:** bug, security, priority:medium
**Description:**
### Summary
An attacker can perform unlimited authentication attempts without any application-level detection or response. While rate limiting is delegated to the deployment layer (reverse proxy), the application provides no failed-login counter, progressive delays, account lockout, or audit trail for failed authentication attempts that would be necessary for credential stuffing detection regardless of network-level controls.

### Details
**ASVS:** 6.3.1 (L1)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py:33-85`

### Remediation
Implement application-level failed login tracking with lockout mechanism:

```python
from collections import defaultdict
import time

_failed_attempts: dict[str, list[float]] = defaultdict(list)
LOCKOUT_THRESHOLD = 5
LOCKOUT_WINDOW = 300  # 5 minutes

@staticmethod
def create_token(body: LoginBody, ...) -> str:
    key = body.username
    now = time.time()
    
    # Clean old attempts
    attempts = [t for t in _failed_attempts[key] if now - t < LOCKOUT_WINDOW]
    _failed_attempts[key] = attempts
    
    # Check lockout threshold
    if len(attempts) >= LOCKOUT_THRESHOLD:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts. Try again later.",
        )
    
    # ... existing authentication logic ...
    
    # Record failed attempt
    if len(found_users) == 0:
        _failed_attempts[key].append(now)
        raise HTTPException(...)
```

### Acceptance Criteria
- [ ] Failed login tracking implemented
- [ ] Lockout threshold configurable
- [ ] Lockout window configurable
- [ ] Test added for lockout after threshold
- [ ] Test added for lockout expiration
- [ ] Test added for successful login resetting counter
- [ ] Audit logging for failed attempts

### References
- ASVS 6.3.1

### Priority
**MEDIUM** - No application-level credential stuffing protection

---

## Issue: FINDING-020 - No TLS Version Enforcement or Configuration in Application Layer
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The FastAPI application is created without any TLS version configuration or enforcement at the application layer. While the domain context notes that 'The deployment manager is responsible for configuring reverse proxies (nginx, Apache) with proper TLS settings,' the application itself provides no validation that it's running behind a TLS-terminating proxy, no configuration options for minimum TLS version when running with an ASGI server, and no documentation or configuration references for TLS version requirements.

### Details
If deployed without proper reverse proxy configuration, the application will serve traffic over plaintext HTTP with no TLS version enforcement.

**ASVS:** 12.1.1, 12.2.2 (L1)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/app.py:84-116`
- `airflow-core/src/airflow/api_fastapi/core_api/app.py` (entire file)

### Remediation
Add certificate validation guidance to deployment documentation and consider adding a startup check:

```python
def validate_certificate_configuration():
    """Check database connection uses certificate validation."""
    conn_string = conf.get("database", "sql_alchemy_conn")
    if "postgresql" in conn_string:
        if "sslmode=verify-full" not in conn_string and "sslmode=verify-ca" not in conn_string:
            log.warning(
                "Database connection does not use certificate validation. "
                "Consider using sslmode=verify-full for production deployments."
            )
```

Additional recommendations:
1. Update database documentation to include TLS/SSL connection parameters
2. Add security configuration validation at startup
3. Add HSTS header middleware
4. Add optional HTTPSRedirectMiddleware
5. Create deployment security checklist
6. Implement TLS health check
7. Add database connection TLS validation
8. Consider mutual TLS (mTLS) for execution API

### Acceptance Criteria
- [ ] Database TLS validation check implemented
- [ ] Deployment documentation updated with TLS requirements
- [ ] HSTS middleware added
- [ ] HTTPSRedirectMiddleware implemented (optional)
- [ ] Security checklist created
- [ ] TLS health check added to /api/v2/monitor/health
- [ ] Test added for TLS configuration validation

### References
- ASVS 12.1.1, 12.2.2

### Priority
**MEDIUM** - No application-layer TLS enforcement or validation

---

*[Continuing with remaining 20 findings in next response due to length...]*

---

## Issue: FINDING-021 - No HTTPS Enforcement or HTTP-to-HTTPS Redirect in Application Code

**Labels:** bug, security, priority:medium

**Description:**

The application's middleware stack does not include any middleware that adds a `Strict-Transport-Security` header to responses. The complete middleware chain is visible and consists only of `JWTRefreshMiddleware`, auth manager middlewares, `GZipMiddleware`, and `HttpAccessLogMiddleware`. None of these set HSTS headers. Without HSTS, an attacker performing a man-in-the-middle attack can downgrade the connection from HTTPS to HTTP (SSL stripping attack), intercepting authentication tokens and session cookies. Users who initially connect via HTTP (e.g., typing `airflow.example.com` without `https://`) can have their connection intercepted before being redirected to HTTPS. This is particularly critical for an application handling authentication credentials, JWT tokens, and sensitive orchestration data.

**Remediation:** Add HTTPS enforcement middleware and HSTS headers:
python
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

def init_middlewares(app: FastAPI) -> None:
    from airflow.configuration import conf
    
    # Add HTTPS enforcement if configured
    if conf.getboolean("api", "force_https", fallback=False):
        app.add_middleware(HTTPSRedirectMiddleware)
    
    # Add HSTS middleware
    @app.middleware("http")
    async def add_hsts_header(request, call_next):
        response = await call_next(request)
        if conf.getboolean("api", "enable_hsts", fallback=True):
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response
    
    # ... existing middleware ...

**Priority:** Medium

---

## Issue: FINDING-022 - Database Connection Examples Permit Unencrypted Communication

**Labels:** bug, security, priority:medium

**Description:**

The database connection documentation: 1. Shows connection strings without SSL/TLS parameters, 2. Does not mention configuring pg_hba.conf to require SSL (hostssl instead of host), 3. Does not mention MySQL's require_secure_transport option, 4. The keepalives_idle example for managed databases mentions SSL errors but not proper SSL configuration. Database credentials (airflow_pass in examples) and all metadata query data (DAG definitions, connection secrets, variable values) transit the network unencrypted when following these setup instructions.

**Remediation:** Add a security section to the database documentation:
rst
Securing Database Connections with TLS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For production deployments, you MUST enable TLS for database connections.

**PostgreSQL:**

1. Configure ``pg_hba.conf`` to require SSL:

   .. code-block:: text

      hostssl  airflow_db  airflow_user  0.0.0.0/0  scram-sha-256

2. Use ``sslmode=verify-full`` in connection string:

   .. code-block:: text

      postgresql+psycopg2://airflow_user:airflow_pass@host/airflow_db?sslmode=verify-full&sslrootcert=/path/to/ca-cert.pem

**MySQL:**

1. Enable ``require_secure_transport=ON`` in MySQL configuration
2. Add SSL parameters to connection:

   .. code-block:: text

      mysql+mysqldb://airflow_user:airflow_pass@host/airflow_db?ssl_ca=/path/to/ca-cert.pem

**Priority:** Medium

---

## Issue: FINDING-023 - Audit Log Access Bypasses DAG-Level Access Controls — Potential Data Over-Exposure

**Labels:** bug, security, priority:medium

**Description:**

The documented behavior explicitly states that users with audit log read permission can access ALL entries regardless of DAG-specific access rights. This means a user restricted to only DAG_A but granted Audit Logs.can_read can see audit entries for DAG_B, DAG_C, etc. The extra field contains JSON-formatted additional context (parameters, error details, etc.) which may include connection names, variable values, or operational details from DAGs the user shouldn't access. This violates the principle of returning only the required subset of fields/records accessible to users.

**Remediation:** Consider implementing DAG-level filtering for audit log responses: Filter audit log results to only include entries for DAGs the user can access. Implementation should filter entries to return only those where dag_id is None (system events) or dag_id is in user's accessible DAGs.

**Priority:** Medium

---

## Issue: FINDING-024 - Audit Log extra Field Returns Unfiltered JSON Context — Potential Sensitive Data Over-Exposure

**Labels:** bug, security, priority:medium

**Description:**

The extra field is documented as containing arbitrary additional context in JSON format. For events like post_connection, patch_variable, or trigger_dag_run, this context may include connection parameters (hostnames, ports, schemas), variable values (which could contain secrets if the variable name doesn't match masking keywords), DAG trigger parameters (conf dict which may contain runtime secrets), and error messages that may leak sensitive information. The REST API endpoint /eventLogs appears to return all fields including extra without field-level filtering based on the user's permissions or the sensitivity of the content.

**Remediation:** Update the documentation example to include masking guidance using airflow.utils.log.secrets_masker.redact to ensure sensitive values are masked before storing in audit log. Provide example code showing proper sanitization of context data before insertion into the extra field.

**Priority:** Medium

---

## Issue: FINDING-025 - No Security Headers Middleware for Content Context Controls (X-Content-Type-Options, CSP)

**Labels:** bug, security, priority:medium

**Description:**

The middleware stack configured in `init_middlewares()` does not include any middleware that sets `X-Content-Type-Options: nosniff`, `Content-Security-Policy`, or validates `Sec-Fetch-*` request headers to prevent content rendering in incorrect contexts. Without `X-Content-Type-Options: nosniff`, browsers may MIME-sniff responses and render content in an unintended context. Without CSP headers, there's no defense-in-depth against injected scripts in rendered content. Without `Sec-Fetch-*` validation, there's no server-side mechanism to reject requests that arrive in inappropriate contexts (e.g., resource requests to API endpoints).

**Remediation:** Implement a SecurityHeadersMiddleware that adds X-Content-Type-Options: nosniff and Content-Security-Policy headers to all responses. Example implementation:
python
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "frame-ancestors 'self'"
        )
        return response

def init_middlewares(app: FastAPI) -> None:
    # ... existing middlewares ...
    app.add_middleware(SecurityHeadersMiddleware)


**Priority:** Medium

---

## Issue: FINDING-026 - Execution API Sub-Application Does Not Receive Middleware Stack

**Labels:** bug, security, priority:medium

**Description:**

The task execution API (`/execution`) is mounted before `init_middlewares()` is called, and `init_middlewares()` only adds middlewares to the core app. Even if an HSTS middleware were added, it would not automatically apply to the execution API sub-application. If security headers middleware is added to the core app, the execution API would still lack HSTS headers unless its sub-application is separately configured or a top-level middleware is used.

**Remediation:** Add security headers as top-level middleware on the root `app` object after all sub-apps are mounted, or ensure each sub-application receives its own security headers middleware. This ensures uniform security header coverage across all mounted applications including /execution, /auth, and plugin routes.

**Priority:** Medium

---

## Issue: FINDING-027 - No Visible Anti-Forgery Token or Custom Header Requirement for State-Changing Requests

**Labels:** bug, security, priority:medium

**Description:**

The middleware stack does not include any CSRF protection middleware (anti-forgery token validation or custom header requirement). The application uses JWT tokens via `JWTRefreshMiddleware` which implies cookie-based JWT storage. Without anti-forgery tokens or requiring non-CORS-safelisted headers, cross-origin form submissions could execute state-changing operations if cookies are automatically sent. The known false positive list indicates JWT tokens stored in HTTP-only cookies without explicit SameSite attributes is intentional because configuration at deployment time. However, the absence of ANY visible anti-forgery mechanism (CSRF tokens, Origin header validation, or custom header requirements) represents a gap that goes beyond cookie attribute configuration. If the deployment does not configure `SameSite=Strict/Lax`, there is no fallback defense. Without anti-forgery protection, an authenticated user visiting a malicious page could have state-changing operations (trigger DAG runs, pause/unpause DAGs, delete tasks) performed on their behalf.

**Remediation:** Option 1: Require custom header for API requests using CSRFProtectionMiddleware that checks for X-Requested-With header on POST, PUT, PATCH, DELETE methods and returns 403 if missing. Option 2: Validate Origin header using OriginValidationMiddleware that checks Origin header against allowed origins for state-changing methods and returns 403 for invalid origins.

**Priority:** Medium

---

## Issue: FINDING-028 - CORS Configuration Does Not Ensure Preflight is Triggered for Sensitive Requests

**Labels:** bug, security, priority:medium

**Description:**

The CORS middleware configuration does not enforce that sensitive requests trigger a CORS preflight. The allow_methods and allow_headers are fully configurable and could include only CORS-safelisted values. Without requiring a non-safelisted Content-Type (e.g., application/json) or custom header, simple cross-origin requests (POST with application/x-www-form-urlencoded) will bypass the CORS preflight mechanism entirely. FastAPI's CORSMiddleware does NOT block requests — it only controls response headers. A cross-origin simple request will be processed by the server even if the origin is not in allow_origins. The CORS policy only prevents the browser's JavaScript from reading the response. If the application relies on CORS preflight as a CSRF defense, simple requests bypass this entirely. State-changing operations (triggering DAG runs, modifying connections) could be executed by cross-origin requests without the user's consent.

**Remediation:** Implement server-side Content-Type validation middleware that rejects CORS-safelisted content types for state-changing API requests. Example: Create ContentTypeValidationMiddleware that validates Content-Type for POST/PUT/PATCH/DELETE requests, rejecting application/x-www-form-urlencoded, multipart/form-data, and text/plain for /api/ endpoints, requiring application/json Content-Type instead. Return 415 status code for unsupported media types. Additionally, consider requiring a non-CORS-safelisted custom header (e.g., X-Requested-With: XMLHttpRequest) for all state-changing API endpoints as an additional CSRF defense.

**Priority:** Medium

---

## Issue: FINDING-029 - Documentation Gap - No File Size Limits Documented for DAG Files

**Labels:** bug, security, priority:medium

**Description:**

The scheduler documentation extensively discusses performance tuning, resource management (CPU, memory, I/O), and configuration knobs for scheduling loops. However, there is no mention of any file size limit for DAG files placed in the DAG directory. Without documented or enforced file size limits on DAG files, a DAG author could submit excessively large DAG files that consume significant memory and CPU during parsing, potentially causing denial of service to the scheduler or DAG processor. The documentation mentions the scheduler 'collects Dag parsing results' once per minute but doesn't specify any safeguard against oversized files. This is a documentation gap finding only. The actual implementation may contain size limits not reflected in these docs. Per the domain context, DAG authors are treated as trusted users, which reduces the practical severity.

**Remediation:** Document and implement a configurable `max_dag_file_size` parameter in the `[scheduler]` configuration section, similar to other scheduler tunables already documented.

**Priority:** Medium

---

## Issue: FINDING-030 - No Runtime or Build-Time Mechanism to Enforce Component Remediation Compliance

**Labels:** bug, security, priority:medium

**Description:**

The application imports and depends on numerous third-party components without any visible reference to remediation SLA documentation. Third-party package ecosystem is imported at application startup with no documented SLA for vulnerability remediation visible in codebase artifacts. Without documented risk-based remediation timeframes: Critical vulnerabilities in dependencies (e.g., FastAPI, Jinja2, Pydantic) may persist without defined urgency for patching; The Airflow provider package ecosystem (many independently maintained packages) lacks a standardized vulnerability response timeline; Legacy Flask/FAB plugins maintained for backwards compatibility may carry unpatched vulnerabilities indefinitely; Deployment managers lack clear guidance on when component updates must be applied.

**Remediation:** Create and maintain a SECURITY_SLA.md or equivalent document (referenced from code comments or configuration) that defines risk-based SLA tiers: Critical (CVSS 9.0-10.0): 48 hours; High (CVSS 7.0-8.9): 7 days; Medium (CVSS 4.0-6.9): 30 days; Low (CVSS 0.1-3.9): 90 days/next release. Document component categories including Core Framework (FastAPI, SQLAlchemy, Pydantic) with update frequency within 14 days of security release; Provider Packages with update frequency within 30 days of security release; Legacy/Deprecated Components (Flask/FAB compatibility) with defined sunset timeline and security patches only policy.

**Priority:** Medium

---

## Issue: FINDING-031 - Deployment documentation lacks guidance on excluding source control metadata from production

**Labels:** bug, security, priority:medium

**Description:**

The deployment documentation describes multiple deployment architectures (basic, distributed, separate DAG processing) and provides detailed scheduler configuration guidance, but nowhere addresses the requirement to exclude `.git`, `.svn`, or other source control metadata from production deployments. The overview document describes DAG file synchronization between components but does not warn against synchronizing source control directories. If source control metadata is deployed with DAG files, the `.git` directory exposes full repository history including potentially deleted secrets, internal paths, developer emails, and commit messages. Attack surface increases if webserver or any externally-accessible component can serve these files. Chained with other vulnerabilities (directory traversal, misconfigured static file serving), this could lead to source code disclosure.

**Remediation:** Add explicit deployment hardening guidance to the administration documentation including a Deployment Hardening section with Source Control Metadata subsection. Ensure that production deployments do not include source control metadata directories (e.g., `.git`, `.svn`, `.hg`) in the DAG files folder or any other deployed component directory. Configure CI/CD pipeline to strip source control metadata before deploying, use `git archive` or equivalent to export DAG files without `.git` directories, verify that Helm chart DAG sync configuration excludes these directories, and if using git-sync sidecar, ensure the `.git` directory is not accessible to the webserver. Example: git archive --format=tar HEAD dags/ | tar -x -C /opt/airflow/dags/

**Priority:** Medium

---

## Issue: FINDING-032 - No documentation defining rate limiting, anti-automation, or adaptive response controls for authentication

**Labels:** bug, security, priority:medium

**Description:**

Neither the scheduler documentation nor the architecture overview documentation defines how rate limiting, anti-automation, or adaptive response controls protect against credential stuffing, password brute force, or malicious account lockout. The ASVS requirement specifically mandates that application documentation define these controls and explain their configuration. While the known false positive patterns acknowledge that 'No rate limiting at framework level for authentication endpoints is intentional because reverse proxies and auth manager implementations handle this,' ASVS 6.1.1 specifically requires documentation that defines how these controls are configured at the deployment layer. The absence of this documentation means operators may deploy Airflow without any rate limiting protection on authentication endpoints.

**Remediation:** Create or reference security documentation that explicitly covers: 1) Reverse Proxy Rate Limiting - Configure reverse proxy (nginx, HAProxy, cloud load balancer) to limit login attempts: Maximum 5 failed login attempts per IP per 5-minute window, Maximum 10 failed login attempts per account per 15-minute window, HTTP 429 response with Retry-After header. 2) Anti-Automation - Configure CAPTCHA after 3 failed login attempts, progressive delays between login attempts, or IP-based reputation scoring via WAF. 3) Adaptive Response - Configure account protection that temporarily locks accounts after threshold failures (recommended: 10 attempts / 30 minutes), notifies account owners of lockout events, does NOT permanently lock accounts to prevent denial-of-service, and provides administrative unlock capability. 4) Auth Manager Configuration - Document rate limiting for LDAP/AD, OAuth/OIDC, and password-based authentication methods.

**Priority:** Medium

---

## Issue: FINDING-034 - SimpleAllAdminMiddleware Bypasses Backend Verification for Simple Auth Manager

**Labels:** bug, security, priority:low

**Description:**

When the simple auth manager is active, every request is automatically granted admin-level access. The middleware generates an admin token and injects it into request headers, creating a circular trust model where the generated token passes through JWTValidator but the verification is meaningless because the middleware itself generates the token it then validates. This creates a situation where no actual authentication occurs. Data flow: Incoming request → middleware generates admin token → injects into request headers → downstream validation occurs on a self-generated token (circular trust). This is a Type C gap — a control (JWT validation) is called but the result is predetermined since the middleware always injects a valid token.

**Remediation:** Ensure deployment documentation clearly states that SimpleAuthManager MUST NOT be used in production. Consider adding a startup warning or configuration guard. Add deployment-mode guard for SimpleAllAdminMiddleware to prevent loading in production mode via environment variable or configuration check (e.g., if os.getenv('AIRFLOW_ENV') == 'production': raise RuntimeError('SimpleAuthManager cannot be used in production')).

**Priority:** Low

---

## Issue: FINDING-035 - No OAuth Authorization Code Flow Visible; Direct Credential-to-Token Exchange Used

**Labels:** bug, security, priority:low

**Description:**

The documentation describes a direct credential exchange flow (POST /auth/token with username/password → access_token), which is conceptually similar to the OAuth Resource Owner Password Credentials grant (deprecated in OAuth 2.1). No standard OAuth authorization code flow with short-lived codes is implemented in the provided code. If this system is intended to function as an OAuth Authorization Server, the absence of a proper authorization code flow means this requirement cannot be verified. However, based on the provided code and documentation, the system uses direct JWT issuance rather than OAuth authorization codes, making this requirement potentially not applicable to the current architecture.

**Remediation:** If there is an authorization code flow implemented elsewhere in the codebase (not provided for this audit), that code should be audited for compliance with the 10-minute maximum lifetime requirement. If OAuth authorization server functionality is intended, implement a proper authorization code flow with short-lived codes (maximum 10 minutes for L1/L2, 1 minute for L3).

**Priority:** Low

---

## Issue: FINDING-036 - No client-side fallback clearing mechanism for session termination without server connectivity

**Labels:** bug, security, priority:low

**Description:**

ASVS 14.3.1 states: "the client-side should also be able to clear up if the server connection is not available when the session is terminated." The Login component includes cookie management (`useCookies`, `removeCookie`) but only uses `removeCookie` during login flow (to clear stale root-path cookies). No visible logout handler, session timeout detection, or offline cleanup mechanism is present in the provided client-side code. While the logout implementation may exist in other components not provided for review, the audit scope shows no evidence of: a `beforeunload` or `visibilitychange` handler to detect session/tab closure, a service worker or client-side timer to detect session expiration and clear cookies, or an offline-capable logout flow. If the server is unreachable (network error, server crash) when a user's session expires or the user closes the browser tab, the JWT cookie persists until its expiration time. On shared devices, this leaves a valid (not yet expired) token accessible.

**Remediation:** Add client-side session expiration detection:
```typescript
// In a root App component or layout
useEffect(() => {
  const checkTokenExpiry = () => {
    const cookies = document.cookie.split(';');
    const tokenCookie = cookies.find(c => c.trim().startsWith('_token='));
    if (tokenCookie) {
      try {
        const token = tokenCookie.split('=')[1];
        const payload = JSON.parse(atob(token.split('.')[1]));
        if (payload.exp && payload.exp * 1000 < Date.now()) {
          // Token expired - clear client-side data
          removeCookie("_token", { path: cookiePath });
          localStorage.clear();
          sessionStorage.clear();
        }
      } catch { /* malformed token - clear anyway */ 
        removeCookie("_token", { path: cookiePath });
      }
    }
  };
  
  const interval = setInterval(checkTokenExpiry, 60000);
  return () => clearInterval(interval);
}, []);
```

**Priority:** Low

---

## Issue: FINDING-037 - No Per-Client Grant Type Restriction Mechanism

**Labels:** bug, security, priority:low

**Description:**

ASVS 10.4.4 requires that for a given client, the authorization server only allows the usage of grants that this client needs to use. The BaseAuthManager and security module contain no concept of OAuth client registration, client-specific grant type configuration, grant type validation per client identity, or client credential management. The authentication system treats all API consumers identically - any consumer with valid credentials can obtain a JWT token through the same mechanism. Impact is limited in Airflow's context because it doesn't function as a multi-client OAuth authorization server, but presents future risk if Airflow expands to support multiple client types with different security requirements.

**Remediation:** If Airflow needs to support multiple client types with different security requirements, implement a client configuration system including: ClientConfig dataclass with client_id, client_secret_hash, allowed_grant_types (excluding 'password' and 'implicit'), redirect_uris, and scopes. Create ClientRegistry class to manage registered OAuth clients with validate_grant_type method. Integrate validation into the token endpoint to ensure clients only use allowed grant types. Implement validate_grant_request to check client_id against allowed grant types before token generation.

**Priority:** Low

---

## Issue: FINDING-038 - Authorization documentation is code-embedded rather than standalone, lacking explicit mapping of consumer permissions to resource access rules

**Labels:** bug, security, priority:low

**Description:**

The authorization model is documented through code-level abstractions (abstract methods, enums, dataclasses) and a deprecation migration notice, but there is no dedicated authorization documentation that explicitly maps: Which consumer roles/groups have access to which functions; The data-specific access rules per resource type; The interaction between team-based access and individual permissions; The trust boundaries between different authorization layers. The deprecated_permissions.rst only documents migration from old to new permission model, not the actual access rules themselves.

**Remediation:** Create a standalone authorization documentation file that: 1. Enumerates all resource types and supported methods; 2. Defines the default permission model and how roles map to resource access; 3. Documents team-based isolation rules; 4. Specifies how batch authorization, filter-based authorization, and direct checks interact; 5. Maps each API endpoint to its required permissions

**Priority:** Low

---

## Issue: FINDING-039 - Wildcard DAG ID (`~`) bypasses specific-resource authorization in favor of general permission check

**Labels:** bug, security, priority:low

**Description:**

When `dag_id` is `~`, authorization is checked without a specific resource identifier, relying on the auth manager to correctly interpret `DagDetails(id=None)` as "check general access." The subsequent data-level filtering via `PermittedDagFilter` dependencies must be applied to ensure actual BOLA protection. Data flow: Request with `dag_id=~` → dag_id set to None → `DagDetails(id=None)` → general DAG authorization check (not resource-specific). This is by design - the `~` wildcard is Airflow's convention for "all resources," and the actual IDOR protection is enforced by the `PermittedDagFilter` applied to the database query. This is documented in the false positive patterns as "Batch authorization checks that may return partial results."

**Remediation:** No immediate remediation required as this is by design. Ensure that the `PermittedDagFilter` is consistently applied to all queries that use the wildcard DAG ID pattern to maintain BOLA protection at the data layer.

**Priority:** Low

---

## Issue: FINDING-040 - No password length validation on manually edited passwords

**Labels:** bug, security, priority:low

**Description:**

While system-generated passwords are 16 characters (meeting the requirement), there is no length validation enforced on passwords stored in the password file. If an administrator manually edits the password file (`simple_auth_manager_passwords.json.generated`) or if the file is corrupted, there is no validation at login time that rejects passwords below the minimum length. A manually-set weak password (e.g., "abc") would be accepted by the system without any rejection or warning. The login endpoint only validates that a password is non-empty, not that it meets minimum length.

**Remediation:** Add minimum password length validation:
```python
MIN_PASSWORD_LENGTH = 8

@staticmethod
def _generate_password() -> str:
    alphabet = "abcdefghkmnpqrstuvwxyzABCDEFGHKMNPQRSTUVWXYZ23456789"
    password = "".join(secrets.choice(alphabet) for _ in range(16))
    assert len(password) >= MIN_PASSWORD_LENGTH
    return password
```
Implement validation at login time to reject passwords below minimum length. Validate password length when loading from the password file.

**Priority:** Low

## Issue: FINDING-041 - Unable to verify password input field masking in UI template
**Labels:** bug, security, priority:low
**Description:**
### Summary
The login UI template is not included in the audit scope, making it impossible to verify that password input fields use proper masking (`type="password"`). Without verification, credentials could be visible on screen during entry if the template uses `type="text"`.

### Details
The login UI is served via Jinja2 templates from `{package_dir}/ui/dist` (or `ui/dev` in dev mode), but the actual HTML template content (`index.html`) is not included in the audit scope. 

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py` (lines 355-384)

**ASVS Reference:** 6.2.6 (Level 1)

### Remediation
Verify that the login form template at `airflow-core/src/airflow/api_fastapi/auth/managers/simple/ui/dist/index.html` contains:
```html
<input type="password" name="password" id="password" ... />
```
Optionally include a toggle button to temporarily reveal the password for user convenience.

### Acceptance Criteria
- [ ] Password input field verified to use `type="password"`
- [ ] Test added to verify password masking in rendered HTML
- [ ] Optional: Password reveal toggle implemented with proper accessibility

### References
- ASVS 6.2.6: Verify that password entry fields use type="password"
- Related: FINDING-042 (SimpleAuthManager production warnings)

### Priority
**Low** - Documentation/verification gap; standard HTML practice but unconfirmed

---

## Issue: FINDING-042 - Production Warning for SimpleAuthManager Is Advisory Only (No Enforcement)
**Labels:** security, enhancement, priority:low
**Description:**
### Summary
SimpleAuthManager's production detection only logs a warning but does not enforce restrictions. The system continues to operate with plaintext passwords and optional no-credential access in production environments, creating risk of accidental insecure deployments.

### Details
The `_looks_like_production()` method detects production indicators (non-sqlite backend, non-local API host, or distributed executor) but only produces a log warning. The system continues operating with insecure defaults.

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py` (lines 163-172)

**ASVS Reference:** 6.3.2 (Level 1)

### Remediation
Convert the warning into a hard failure to prevent accidental insecure production deployments. Options:
1. Raise an exception when production indicators are detected
2. Require explicit opt-in via configuration flag (e.g., `simple_auth_manager_allow_production=True`)

### Acceptance Criteria
- [ ] Exception raised when production environment detected without explicit opt-in
- [ ] Configuration flag added for explicit production override
- [ ] Clear error message guides users to proper auth manager
- [ ] Test added for production detection enforcement
- [ ] Documentation updated with migration guidance

### References
- ASVS 6.3.2: Verify authentication pathways are resistant to timing attacks
- Related: FINDING-041 (SimpleAuthManager password masking)

### Priority
**Low** - SimpleAuthManager is intended for development only, but enforcement adds defense-in-depth

---

## Issue: FINDING-043 - Database Connection Documentation Lacks TLS Configuration Guidance
**Labels:** documentation, security, priority:low
**Description:**
### Summary
Database setup documentation provides connection string examples without TLS parameters, potentially leading deployment managers to configure database connections without encryption, exposing credentials and query data in transit.

### Details
The documentation shows connection examples for PostgreSQL and MySQL without TLS configuration. While the domain context explicitly states "Database connections should also use TLS to protect credentials and query data in transit," the examples don't demonstrate this.

**Affected Files:**
- `airflow-core/docs/howto/set-up-database.rst` (lines 144-148, 210-213)

**ASVS Reference:** 12.1.1 (Level 1)

### Remediation
Add TLS configuration guidance to the documentation:

```rst
.. important::

   For production deployments, always enable TLS for database connections to protect
   credentials and data in transit.

   For PostgreSQL with TLS:

   .. code-block:: text

      postgresql+psycopg2://<user>:<password>@<host>/<db>?sslmode=verify-full&sslrootcert=/path/to/ca.crt

   For MySQL with TLS:

   .. code-block:: text

      mysql+mysqldb://<user>:<password>@<host>[:<port>]/<dbname>?ssl_ca=/path/to/ca.crt
```

### Acceptance Criteria
- [ ] Documentation updated with TLS configuration examples
- [ ] PostgreSQL sslmode options documented (require, verify-ca, verify-full)
- [ ] MySQL SSL options documented
- [ ] Warning added about production deployment requirements
- [ ] Examples include certificate verification paths

### References
- ASVS 12.1.1: Verify that secured TLS is used for all client connectivity
- PostgreSQL SSL documentation
- MySQL SSL/TLS documentation

### Priority
**Low** - Documentation gap; production deployments typically handle this at infrastructure level

---

## Issue: FINDING-044 - Pagination and Filter Parameters Lack Documented Validation Rules
**Labels:** documentation, enhancement, priority:low
**Description:**
### Summary
Pagination utility functions accept offset, limit, order_by, and filters without documented validation rules. This documentation gap may lead to inconsistent validation across API endpoints or omission of validation entirely.

### Details
The utility functions in `common.py` accept OrmClause objects but lack documentation specifying:
- Maximum allowed values for `limit` (DoS prevention)
- Valid ranges for `offset`
- Allowed sort fields/directions for `order_by`
- Permitted filter combinations and value ranges

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/common/db/common.py` (lines 67-167)

**ASVS Reference:** 2.1.1 (Level 1)

### Remediation
Define validation rules for pagination parameters in API documentation or inline docstrings:
- `offset` must be non-negative integer
- `limit` must be 1-100 (configurable maximum)
- `order_by` must reference allowed model columns
- `filters` must use parameterized values

Add enhanced docstring with validation rules section to utility functions.

### Acceptance Criteria
- [ ] Docstrings updated with validation requirements
- [ ] API documentation includes pagination limits
- [ ] Configuration option added for maximum limit value
- [ ] Examples added showing proper validation at endpoint level
- [ ] Test cases verify validation rule enforcement

### References
- ASVS 2.1.1: Verify that security controls are enforced server-side
- Related: FINDING-045 (Filter validation)

### Priority
**Low** - Documentation gap; FastAPI/Pydantic typically handle validation at endpoint level

---

## Issue: FINDING-045 - Filter Application Function Does Not Perform Validation of Filter Content
**Labels:** security, enhancement, priority:low
**Description:**
### Summary
The `apply_filters_to_select` function applies any OrmClause to a query without validation. Security depends entirely on upstream OrmClause construction. The function provides no defense-in-depth validation.

### Details
The function only checks for None values (null safety), but does not validate:
- Filter targets allowed columns
- Value ranges or data types
- Query complexity limits

If OrmClause objects are constructed from validated Pydantic models (typical FastAPI pattern), validation happens upstream. However, this represents a potential coverage gap.

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/common/db/common.py` (lines 48-56)

**ASVS Reference:** 2.2.1 (Level 1)

### Remediation
Add defensive assertions and type checking:

```python
def apply_filters_to_select(stmt, filters):
    if filters is None:
        return stmt
    for f in filters:
        if not isinstance(f, OrmClause):
            raise TypeError(f"Expected OrmClause, got {type(f)}")
        stmt = stmt.where(f.as_clause())
    return stmt
```

Additional steps:
1. Document pagination validation rules
2. Audit OrmClause implementations for injection risks
3. Implement query complexity limits

### Acceptance Criteria
- [ ] Type checking added to filter application
- [ ] Documentation added specifying allowed filter patterns
- [ ] Query complexity limits implemented
- [ ] Test cases for invalid filter types
- [ ] Audit completed of OrmClause implementations

### References
- ASVS 2.2.1: Verify that all input is validated using positive validation
- Related: FINDING-044 (Pagination validation documentation)

### Priority
**Low** - Design pattern observation; validation typically occurs upstream via Pydantic

---

## Issue: FINDING-046 - Documentation REST API Examples Lack Authentication Context
**Labels:** documentation, security, priority:low
**Description:**
### Summary
REST API documentation examples omit authentication headers entirely, potentially leading developers to implement insecure patterns (e.g., passing API keys as query parameters) when copying examples.

### Details
The audit logs REST API documentation shows curl examples without authentication:
```bash
curl -X GET "http://localhost:8080/api/v1/eventLogs"
```

While query parameters shown (event, dag_id, after, before, full_content) are non-sensitive filters, the lack of authentication context could lead developers to introduce insecure patterns.

**Affected Files:**
- `airflow-core/docs/security/audit_logs.rst` (lines 225-240)

**ASVS Reference:** 14.2.1 (Level 1)

### Remediation
Add authentication header examples to REST API documentation:

```rst
# Get all audit logs (with proper authentication in headers)
curl -X GET "http://localhost:8080/api/v1/eventLogs" \
  -H "Authorization: Bearer <token>"
```

**Immediate:** Review `/eventLogs` REST API implementation to verify response field filtering and secrets masking.

**Short-term:** Update REST API documentation examples to include authentication headers.

**Long-term:** Document data classification framework for audit log storage.

### Acceptance Criteria
- [ ] All REST API examples include authentication headers
- [ ] Documentation explicitly warns against credentials in URLs
- [ ] `/eventLogs` endpoint verified to mask secrets in responses
- [ ] Data classification guidance added for audit logs
- [ ] Test added verifying API rejects credentials in query params

### References
- ASVS 14.2.1: Verify that sensitive data is not passed in URL parameters
- Related: Audit logging and secrets management

### Priority
**Low** - Documentation gap; actual implementation likely correct

---

## Issue: FINDING-047 - Static File Serving with `html=True` Without Sec-Fetch Validation
**Labels:** security, enhancement, priority:low
**Description:**
### Summary
Static files are served with `html=True` enabling HTML rendering without `Sec-Fetch-Dest` or `Sec-Fetch-Mode` validation to ensure resources are loaded in the expected context. This violates defense-in-depth principles.

### Details
The `html=True` flag means any file in the directory will be rendered as HTML when accessed directly. While the directory contains application-owned UI assets (not user uploads), there's no validation that these resources are loaded in the expected context.

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/core_api/app.py` (lines 56-63)

**ASVS Reference:** 3.2.1 (Level 1)  
**CWE:** CWE-693 (Protection Mechanism Failure)

### Remediation
Consider setting `html=False` unless directory index serving is needed, and rely on explicit HTML response for the SPA entry point via the catch-all route.

Alternatively, implement Sec-Fetch header validation middleware to ensure static resources are loaded only in expected contexts.

### Acceptance Criteria
- [ ] `html=False` set for static file serving OR
- [ ] Sec-Fetch validation middleware implemented
- [ ] Test added verifying static files not rendered as HTML
- [ ] Documentation updated explaining static file security model
- [ ] Security review of all files in static directory

### References
- ASVS 3.2.1: Verify that all responses contain X-Content-Type-Options: nosniff
- CWE-693: Protection Mechanism Failure
- Related: FINDING-025, FINDING-026 (HTTP security headers)

### Priority
**Low** - Application-owned assets only; no user uploads in this directory

---

## Issue: FINDING-048 - Template Variable Injection Without Explicit Escaping Context
**Labels:** security, bug, priority:low
**Description:**
### Summary
The SPA catch-all route passes `backend_server_base_url` (derived from `request.base_url.path`) into a Jinja2 template context. If used within a JavaScript block in the template, it could bypass HTML escaping, potentially enabling injection attacks.

### Details
Data flow: `request.base_url.path` (derived from Host header or configured root_path) → template context variable → rendered in `index.html`.

While Jinja2 auto-escapes by default in HTML context, JavaScript context requires explicit escaping. Impact is low because `base_url.path` is typically controlled by server configuration, but if the Host header is not validated by a reverse proxy, path-based injection could occur.

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/core_api/app.py` (lines 88-93)

**ASVS Reference:** 3.2.2 (Level 1)  
**CWE:** CWE-79 (Cross-site Scripting)

### Remediation
Ensure the `index.html` template uses `{{ backend_server_base_url | tojson }}` if the value is placed in a JavaScript context, or verify that the reverse proxy normalizes the Host header.

### Acceptance Criteria
- [ ] Template reviewed for JavaScript context usage
- [ ] `tojson` filter applied if used in JavaScript blocks
- [ ] Reverse proxy Host header validation documented
- [ ] Test added for injection attempts via Host header
- [ ] Content Security Policy reviewed for inline script restrictions

### References
- ASVS 3.2.2: Verify that all responses contain correct Content-Type header
- CWE-79: Improper Neutralization of Input During Web Page Generation
- Jinja2 security documentation

### Priority
**Low** - Typically mitigated by reverse proxy configuration

---

## Issue: FINDING-049 - No Global HTTP Method Enforcement or Sec-Fetch-* Validation for Sensitive Operations
**Labels:** security, enhancement, priority:medium
**Description:**
### Summary
No global middleware validates Sec-Fetch-* headers or enforces that sensitive operations cannot be triggered via navigation requests or resource loads. While FastAPI routers should enforce method restrictions, there's no defense-in-depth at the middleware level.

### Details
Without Sec-Fetch-* validation, navigation requests (e.g., `<img src="https://airflow.example.com/api/v2/connections/delete/myconn">` if a GET-based delete existed) or cross-origin resource loads could trigger sensitive functionality.

Visible routes use appropriate methods (only GET for informational/UI endpoints), but actual sensitive API endpoints are not visible in the provided code.

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/core_api/app.py` (lines 32-93)

**ASVS Reference:** 3.5.3 (Level 1)  
**CWE:** CWE-352 (Cross-Site Request Forgery)

### Remediation
Implement SecFetchValidationMiddleware to validate Sec-Fetch-* headers for API endpoints:

```python
class SecFetchValidationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path.startswith("/api/"):
            sec_fetch_site = request.headers.get("Sec-Fetch-Site")
            sec_fetch_mode = request.headers.get("Sec-Fetch-Mode")
            if sec_fetch_site == "cross-site" and sec_fetch_mode == "navigate":
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Cross-site navigation to API not allowed"}
                )
        return await call_next(request)
```

### Acceptance Criteria
- [ ] SecFetchValidationMiddleware implemented
- [ ] Middleware applied to all API routes
- [ ] Cross-site navigation requests rejected with 403
- [ ] Tests added for Sec-Fetch validation
- [ ] Browser compatibility documented (graceful degradation for old browsers)
- [ ] CSRF protection verified for state-changing operations

### References
- ASVS 3.5.3: Verify that the application has defenses against HTTP parameter pollution
- CWE-352: Cross-Site Request Forgery
- Related: FINDING-027, FINDING-028 (CSRF protection)

### Priority
**Low** - FastAPI method enforcement provides primary protection; this adds defense-in-depth

---

## Issue: FINDING-050 - No Content-Type Enforcement for Plugin-Mounted Sub-Applications
**Labels:** security, enhancement, priority:low
**Description:**
### Summary
Plugin-mounted sub-applications are registered at arbitrary URL prefixes without middleware to enforce that Content-Type headers include proper charset parameters. If a plugin serves text content without proper Content-Type, browsers may perform content-type sniffing, potentially enabling XSS attacks.

### Details
The `init_plugins` function accepts arbitrary subapp objects (which may or may not be FastAPI apps) and mounts them directly. No middleware validates Content-Type headers on responses from these mounts.

Risk is mitigated by the fact that most plugins would use FastAPI's standard response classes, which include proper Content-Type headers.

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/app.py` (lines 184-228, 199-212)
- `airflow-core/src/airflow/api_fastapi/core_api/app.py` (line 145)

**ASVS Reference:** 4.1.1 (Level 1)  
**CWE:** CWE-430 (Deployment of Wrong Handler)

### Remediation
Add ContentTypeEnforcementMiddleware at the parent application level:

```python
class ContentTypeEnforcementMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        content_type = response.headers.get("content-type", "")
        if content_type.startswith("text/") and "charset" not in content_type:
            response.headers["content-type"] = f"{content_type}; charset=utf-8"
        response.headers["x-content-type-options"] = "nosniff"
        return response
```

Apply in `init_config()` which runs for all app configurations.

### Acceptance Criteria
- [ ] ContentTypeEnforcementMiddleware implemented
- [ ] Middleware applied in init_config()
- [ ] X-Content-Type-Options: nosniff header added
- [ ] Integration tests verify Content-Type + charset on all responses
- [ ] Error handler responses tested
- [ ] Plugin developer documentation updated with Content-Type requirements

### References
- ASVS 4.1.1: Verify that the application enforces access control rules on a trusted service layer
- CWE-430: Deployment of Wrong Handler
- MIME type sniffing documentation

### Priority
**Low** - Most plugins use FastAPI standard responses; defense-in-depth measure

---

## Issue: FINDING-051 - Dynamic Plugin Loading Extends Attack Surface Without Documented Component Risk Classification
**Labels:** security, documentation, priority:low
**Description:**
### Summary
Plugins are loaded dynamically without any visible mechanism to classify them as risky components or enforce that they meet remediation timeframe requirements. A plugin with known vulnerabilities could be loaded indefinitely.

### Details
The `init_plugins` function integrates FastAPI app, middlewares and UI plugins from `plugins_manager.get_fastapi_plugins()` and mounts them without risk classification, version validation, or maintenance status checks.

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/app.py` (lines 181-220)

**ASVS Reference:** 15.1.1 (Level 1)

### Remediation
Document plugin risk classification criteria and enforce version/maintenance requirements for loaded plugins:

1. Define minimum security standards for loaded plugins
2. Implement plugin metadata validation (version, maintenance status, security contact)
3. Add configuration to block plugins that don't meet security requirements
4. Create plugin security scorecard

### Acceptance Criteria
- [ ] Plugin risk classification framework documented
- [ ] Plugin metadata schema includes security information
- [ ] Configuration added to enforce minimum plugin standards
- [ ] Plugin loading logs security-relevant metadata
- [ ] Documentation added for plugin developers on security requirements
- [ ] Audit tool created to scan loaded plugins for known vulnerabilities

### References
- ASVS 15.1.1: Verify that all application components, libraries and modules are identified and known to be needed
- Plugin security best practices

### Priority
**Low** - Organizational control; typically managed via plugin approval process

---

## Issue: FINDING-052 - Legacy Flask/FAB Plugin Layer Maintains Potentially Outdated Dependencies Without Sunset Enforcement
**Labels:** technical-debt, security, priority:low
**Description:**
### Summary
The legacy Flask/FAB plugin compatibility layer may keep outdated dependencies (Flask-AppBuilder, older Flask versions) in the dependency tree indefinitely. While a deprecation warning is appropriate, there's no enforcement mechanism to prevent loading of Flask/FAB plugins after a defined sunset date.

### Details
The legacy compatibility layer continues to load Flask/FAB plugins without time-based restrictions. This may maintain vulnerable dependencies in the dependency tree even after migration paths are available.

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/core_api/app.py` (lines 94-119)

**ASVS Reference:** 15.2.1 (Level 1)

### Remediation
Implement a configuration-controlled sunset date after which Flask plugins are refused:

```python
from datetime import datetime
from airflow.configuration import conf

sunset_date_str = conf.get("api", "flask_plugin_sunset_date", fallback=None)
if sunset_date_str:
    sunset_date = datetime.fromisoformat(sunset_date_str)
    if datetime.now() > sunset_date:
        raise AirflowException(
            f"Flask/FAB plugins are no longer supported after {sunset_date_str}. "
            "Please migrate your plugins to the FastAPI plugin interface. "
            "See documentation: https://..."
        )
```

### Acceptance Criteria
- [ ] Configuration option added for Flask plugin sunset date
- [ ] Exception raised when sunset date exceeded
- [ ] Clear migration documentation provided
- [ ] Deprecation warnings updated with sunset date
- [ ] Release notes include sunset timeline
- [ ] Test added for sunset enforcement

### References
- ASVS 15.2.1: Verify that all components are up to date with proper security configuration
- Dependency management best practices
- Flask to FastAPI migration guide

### Priority
**Low** - Long-term technical debt; requires coordinated deprecation timeline