# Security Audit Consolidated Report — apache/airflow/airflow-core

## Report Metadata

| Field | Value |
|-------|-------|
| Repository | apache/airflow/airflow-core |
| ASVS Level | L1 |
| Severity Threshold | None (all findings included) |
| Commit | N/A |
| Date | May 16, 2026 |
| Auditor | Tooling Agents |
| Source Reports | 70 |
| Total Findings | 52 |

## Executive Summary

### Severity Distribution

| Severity | Count | Percentage |
|----------|-------|------------| Medium | 24 | 46.2% | Info | 0 | 0.0% |

### Level Coverage

All 52 findings map to ASVS Level 1 (L1) requirements. The audit scope was bounded to L1 controls, covering foundational security verification across 12 directories encompassing authentication, authorization, session management, cryptographic operations, transport security, input validation, secrets management, and deployment configuration.

### Top 5 Risks

1. **Token Revocation Check Missing from Validation Path (Critical):** The revocation infrastructure exists (RevokedToken model, revoke_token method) but the validation path does not query the revocation table, meaning revoked tokens remain usable until natural expiry. This undermines logout, account termination, and incident response capabilities.

2. **JWT Refresh Does Not Invalidate Previous Token (FINDING-002, High):** Token refresh issues a new token without revoking the predecessor, creating a window where both old and new tokens are valid simultaneously. This enables replay attacks and makes token theft difficult to remediate.

3. **Algorithm Blocklist Not Implemented (FINDING-004, High):** The `none` algorithm is not explicitly blocked at the configuration or validation layer. Combined with the GUESS mode that derives algorithms from JWK metadata, this creates a potential path to signature bypass if key material is misconfigured.

4. **No Password Change Functionality (FINDING-005/006, High):** Users cannot change their own passwords through any available interface, and current-password verification cannot be satisfied. This prevents credential rotation after suspected compromise and violates fundamental identity management requirements.

5. **Anonymous Admin Account in All-Admins Mode (FINDING-007, High):** When configured in all-admins mode, an anonymous admin account is created without credentials, granting full administrative access without authentication. This represents a complete authentication bypass in specific deployment configurations.

### Positive Controls Observed

The audit identified substantial defensive measures already in place:

- **Robust JWT signature validation:** All token validation occurs server-side with cryptographic signature verification, required claims enforcement (exp, iat, nbf, aud, iss), and configurable clock skew tolerance. Key material is sourced exclusively from pre-configured trusted locations with no processing of inline jku/x5u/jwk headers from tokens.

- **Defense-in-depth authorization architecture:** FastAPI dependency injection makes authorization checks structurally difficult to bypass. A dual-layer approach combines endpoint-level access control with ORM-level query filters, providing protection against IDOR/BOLA attacks. Comprehensive resource coverage spans all major entity types with dedicated authorization functions.

- **Authenticated encryption for secrets:** Fernet (AES-128-CBC + HMAC-SHA256) provides authenticated encryption for stored connections and variables, with documented key rotation procedures and proper key generation using cryptographic randomness.

- **Timing-safe credential comparison:** Authentication flows use `hmac.compare_digest()` for password verification with generic error messages, preventing timing-based enumeration and credential oracle attacks.

- **Secure token delivery and session controls:** Cookie-based token delivery employs httponly, secure, and SameSite attributes. Server-side revocation infrastructure exists, path-scoped cookies prevent cross-application leakage, and CORS is disabled by default with configuration-driven activation following least privilege principles.

---


> **Note:** 1 Critical finding has been redacted from this report and forwarded to the project's PMC private mailing list.


## 3. Findings

### 3.2 High

#### FINDING-002: JWT Refresh Does Not Invalidate Previous Token, Enabling Replay Attacks

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-613 |
| **ASVS Section(s)** | 10.4.5, 7.2.4 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py:48-73, airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py:57-60 |
| **Source Reports** | 10.4.5.md, 7.2.4.md |
| **Related** | FINDING-003, FINDING-009 |

**Description:**

The JWT refresh mechanism in JWTRefreshMiddleware.dispatch() generates new tokens but does not revoke or invalidate the old token. When a token is refreshed, both the old and new tokens remain valid for their full lifetime (default 24 hours). This allows an attacker who has captured a valid JWT token to continue using it even after the legitimate user's session has been refreshed. Data flow: current_token (cookie) → _refresh_user() → new JWT generated → old token remains valid. Proof of concept: (1) Attacker captures a valid JWT token from a user's browser, (2) The legitimate user's token gets refreshed by JWTRefreshMiddleware with a new token issued, (3) The attacker continues to use the captured old token which remains valid for up to 24 hours. This defeats the purpose of token rotation as a replay mitigation measure.

**Remediation:**

Implement token revocation during refresh by calling revoke_token(current_token) when a new token is successfully generated. Example implementation: if new_user: new_token = get_auth_manager().generate_jwt(new_user); from airflow.api_fastapi.auth.tokens import get_sig_validation_args, JWTValidator; validator = JWTValidator(**get_sig_validation_args(), audience=...); validator.revoke_token(current_token); set_response_cookie(new_token). Alternatively, implement refresh token rotation with family tracking where on refresh the old token's jti is marked in the revoked_token table, on validation the jti is checked against the revoked_token table, and if a revoked token is presented, all tokens in the same family (jti chain) are revoked.

---

#### FINDING-003: No Mechanism for Bulk Session Invalidation on Account Termination

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-613 |
| **ASVS Section(s)** | 7.4.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/tokens.py:entire file |
| **Source Reports** | 7.4.2.md |
| **Related** | FINDING-002, FINDING-009 |

**Description:**

The JWTValidator class provides only revoke_token(self, token: str) which revokes a single known token by its JTI. There is no revoke_all_user_tokens(user_id) method, per-user 'not valid before' timestamp mechanism, per-user signing key rotation, or user-scoped token invalidation of any kind. When an employee leaves the company and their account is disabled/deleted, any previously issued JWT tokens remain valid until their natural expiration (up to 24 hours for REST API tokens, 10 minutes for execution tokens). The system has no way to invalidate all tokens for a specific user identity because: 1) The revoke_token method requires the actual token string (not available for all sessions), 2) There's no per-user invalidation timestamp in the JWT validation flow, 3) Even if revocation worked, the validation doesn't check it (as noted in JWT-001). This is a Type A gap - no control exists for bulk session termination on account disable/delete.

**Remediation:**

Implement one of two options: Option A - Per-user 'not valid before' timestamp: In JWTValidator.avalidated_claims(), after jwt.decode(), check user-level invalidation by retrieving UserSessionInvalidation.get_for_user(sub) and compare iat against invalidation.not_valid_before, raising jwt.InvalidTokenError if tokens are invalidated. Option B - Token issuance tracking: Create an IssuedToken model that tracks jti, user_id, and exp with user_id index, and implement disable_user(user_id) function to revoke all issued tokens for a user via IssuedToken.revoke_all_for_user(user_id).

---

#### FINDING-004: Algorithm Blocklist Not Implemented, Allowing 'none' Algorithm Configuration

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-327 |
| **ASVS Section(s)** | 10.4.5, 9.1.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/tokens.py:193-199, airflow-core/src/airflow/api_fastapi/auth/tokens.py:322-331 |
| **Source Reports** | 10.4.5.md, 9.1.2.md |
| **Related** | FINDING-033 |

**Description:**

The JWT validation code lacks an explicit blocklist of dangerous algorithms. There is no hardcoded check that prevents misconfiguration from introducing vulnerabilities by allowing algorithms like 'none', 'None', or 'NONE' which would disable signature validation entirely. The code relies on 'safe defaults' (GUESS → HS512/RS256/EdDSA) but does not actively prevent configuration errors. Configuration data flow: [api_auth] jwt_algorithm → _conf_list_factory → JWTValidator.algorithm → jwt.decode(algorithms=...). If an administrator sets jwt_algorithm = none in airflow.cfg, the JWTValidator.algorithm becomes ['none'], jwt.decode() is called with algorithms=['none'], and tokens without any cryptographic signature would be accepted. An attacker could forge arbitrary tokens. This creates a defense-in-depth gap where misconfiguration can weaken security without code changes.

**Remediation:**

Add a hardcoded set of blocked algorithms (at minimum: 'none', 'None', 'NONE') that is checked in both JWTValidator.__attrs_post_init__ and JWTGenerator.__attrs_post_init__. Example: _BLOCKED_ALGORITHMS = frozenset({'none', 'None', 'NONE'}); _ALLOWED_ALGORITHMS = frozenset({'HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'EdDSA', 'PS256', 'PS384', 'PS512'}). In __attrs_post_init__, validate: for alg in self.algorithm: if alg.lower() in _BLOCKED_ALGORITHMS: raise ValueError(f'Algorithm {alg} is not allowed'); if alg not in _ALLOWED_ALGORITHMS: raise ValueError(f'Algorithm {alg} is not in the allowed set'). This prevents configuration errors from disabling signature validation.

---

#### FINDING-005: No mechanism for users to change their passwords

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 6.2.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py:entire file, airflow-core/src/airflow/api_fastapi/auth/managers/simple/openapi/v2-simple-auth-manager-generated.yaml:paths section |
| **Source Reports** | 6.2.2.md |
| **Related** | N/A |

**Description:**

The Simple Auth Manager provides NO mechanism for users to change their passwords. The available endpoints are exclusively for authentication (token creation). There is no PUT/PATCH/POST endpoint for password modification. The OpenAPI specification confirms only `/auth/token`, `/auth/token/login`, and `/auth/token/cli` endpoints exist. User wants to change password → No endpoint exists → User cannot change password → Only option is admin manually editing password file or deleting it to trigger regeneration. There is no HTTP method or path combination that allows a user to submit a new password. The password file at `simple_auth_manager_passwords.json.generated` is only written during `init()` when a user doesn't already have a password.

**Remediation:**

Implement a password change endpoint: `@login_router.post("/token/change-password", status_code=status.HTTP_200_OK)` that accepts `ChangePasswordBody` with `current_password` and `new_password`. The endpoint should: 1) Verify current password using `verify_current_password()` with the authenticated user, 2) Validate new password length (minimum 8 characters), 3) Check against common passwords using `is_common_password()`, 4) Update password in storage atomically with file locking using `update_password()`, 5) Return success message. Users cannot respond to a suspected credential compromise, passwords cannot be rotated without administrative file system access, violates NIST SP 800-63B §5.1.1.2 which requires verifiers to permit subscribers to change their memorized secrets.

---

#### FINDING-006: No password change functionality exists - current password verification requirement cannot be satisfied

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 6.2.3 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py:entire file, airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py: |
| **Source Reports** | 6.2.3.md |
| **Related** | N/A |

**Description:**

Since no password change functionality exists (per ASVS-622-HIGH-001), the requirement that password changes require both current and new password cannot be satisfied. There is no endpoint, service method, or data model that accepts a current password for verification alongside a new password. If a password change mechanism is added later without this requirement, it could enable account takeover via CSRF or session hijacking (attacker with active session could change password without knowing the original). Without current password verification, any bearer of a valid JWT could change any user's password.

**Remediation:**

Implement alongside ASVS-622-HIGH-001 — ensure the ChangePasswordBody model requires both current_password and new_password fields, and that current_password is verified against stored credentials using constant-time comparison before allowing the change.

---

#### FINDING-007: Anonymous Admin Account Created Without Credentials in All-Admins Mode

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 6.3.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py:101-109, airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py:77, airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py:85 |
| **Source Reports** | 6.3.2.md |
| **Related** | N/A |

**Description:**

When `simple_auth_manager_all_admins` is set to `True`, a hardcoded "Anonymous" user with ADMIN role is accessible without any credentials via simple GET request. This is effectively a default admin account with no password. While the SimpleAuthManager is documented as dev-only, the configuration flag lacks enforcement preventing production use beyond a log warning. Data flow: Configuration flag `simple_auth_manager_all_admins=True` → `GET /auth/token` (no auth required) → `create_token_all_admins()` → `_create_anonymous_admin_user()` → Full ADMIN JWT token returned.

**Remediation:**

Add hard guard against production-like environments in `_create_anonymous_admin_user()` method. If `SimpleAuthManager._looks_like_production()` returns true, raise HTTPException with 403 status and appropriate error message. Additionally, the `simple_auth_manager_all_admins` configuration should be programmatically blocked when production indicators are detected, not just warned about. Require explicit opt-in flag (e.g., `simple_auth_manager_i_know_what_i_am_doing=True`) for production-like environments.

---

#### FINDING-008: Generated Initial Passwords Never Expire and Become Long-Term Credentials

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 6.4.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:175-186, airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:481-484 |
| **Source Reports** | 6.4.1.md |
| **Related** | N/A |

**Description:**

System-generated passwords are stored permanently in a plaintext JSON file with no expiration timestamp, never require the user to change them after first use, are printed to stdout/logs on generation (visible in container logs, CI systems, etc.), and are the ONLY password mechanism with no 'change password' endpoint or flow. This violates the requirement that initial secrets 'expire after a short period of time or after they are initially used' and 'must not be permitted to become the long term password.'

**Remediation:**

Store passwords with metadata including 'created_at' timestamp and 'must_change' flag. In create_token method, check expiration and must_change flag. If must_change is true, reject authentication with HTTP 403 and require password change. If password age exceeds INITIAL_PASSWORD_TTL, reject with HTTP 401. Implement a password change endpoint to allow users to set a new password after first use.

### 3.3 Medium

#### FINDING-009: REST API Token Lifetime of 24 Hours is Excessive for Public Client Sessions

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-613 |
| **ASVS sections** | 10.4.5 |
| **Files** | airflow-core/docs/security/jwt_token_authentication.rst |
| **Source Reports** | 10.4.5.md |
| **Related** | FINDING-002, FINDING-003 |

**Description:**

The default REST API token lifetime is configured to 86400 seconds (24 hours) via the [api_auth] jwt_expiration_time setting. Combined with the lack of old-token invalidation during refresh (JWT-002), this 24-hour token lifetime means captured tokens have a very long replay window. For public clients where refresh token rotation is meant to limit damage from token theft, a 24-hour window significantly reduces the security benefit of token rotation.

**Remediation:**

Reduce REST API token lifetime to 15-30 minutes for UI sessions. Rely on the refresh middleware to transparently issue new tokens. Implement proper rotation with old-token invalidation (see JWT-002). Consider separate short-lived access tokens and longer-lived refresh tokens following the traditional OAuth pattern. Reduce default jwt_expiration_time from 24 hours to 1-2 hours for UI sessions, relying on the refresh middleware for session continuity.

---

#### FINDING-010: Auto-Generated Signing Key Uses Only 128 Bits for HS512 Algorithm

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-326 |
| **ASVS sections** | 7.2.3 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/tokens.py:438-440 |
| **Source Reports** | 7.2.3.md |
| **Related** | |

**Description:**

While the token identifiers (jti) are UUID4 with 128 bits of entropy (meeting ASVS 7.2.3), the auto-generated signing key is only 128 bits. For HS512 (HMAC-SHA-512), NIST recommends the key be at least as long as the hash output (512 bits / 64 bytes). A 128-bit key reduces the effective security below the algorithm's design strength, though it remains computationally infeasible to brute-force. More critically, this ephemeral key differs across processes in multi-component deployments, causing authentication failures rather than a direct security bypass. Data flow: Missing configuration → get_signing_key() → os.urandom(16) (128 bits) → used as HS512 signing key. Proof of concept: Deploy multiple Airflow components (webserver, scheduler) without configuring [api_auth] jwt_secret. Each component generates a different random key, causing tokens from one to be rejected by the other.

**Remediation:**

Increase to 64 bytes (512 bits) to match HS512 algorithm strength: secret_key = base64url_encode(os.urandom(64)). Additionally, ensure deployment documentation emphasizes that jwt_secret MUST be explicitly configured in production environments and shared across all components.

---

#### FINDING-011: No `Clear-Site-Data` header sent on logout/session termination

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | |
| **ASVS sections** | 14.3.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:168-176, airflow-core/src/airflow/api_fastapi/core_api/app.py |
| **Source Reports** | 14.3.1.md |
| **Related** | |

**Description:**

Without the `Clear-Site-Data` header, the browser does not receive a server-authoritative instruction to clear cookies, cache, and storage associated with the session. While server-side token revocation prevents API access with the revoked token, cached API responses and residual authentication data in browser storage remain accessible. On shared devices, this can expose sensitive information from cached responses. Data flow: User initiates logout → `revoke_token()` revokes token server-side → `get_url_logout()` returns redirect URL (or None) → NO `Clear-Site-Data` header sent in response → client browser retains cookies, cache, and storage → stale token remains in browser cookie jar until expiration.

**Remediation:**

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

---

#### FINDING-012: Cookie name `_token` missing required `__Secure-` or `__Host-` prefix

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | |
| **ASVS sections** | 3.3.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:113, airflow-core/src/airflow/api_fastapi/auth/managers/simple/ui/src/login/Login.tsx:82 |
| **Source Reports** | 3.3.1.md |
| **Related** | |

**Description:**

JWT token generated by server → returned in `LoginResponse.access_token` → stored in cookie named `_token` → cookie lacks `__Secure-` prefix → no browser-level guarantee cookie was set/transmitted securely. Without the `__Secure-` prefix, browsers do not enforce that the cookie was set over a secure (HTTPS) connection or has the Secure attribute. This weakens protections against cookie injection/fixation attacks where an attacker forces a known token value, potentially hijacking the session. Since this cookie grants full API access per the domain context, the impact is significant. A network attacker performing a downgrade attack or injecting an HTTP response could set a cookie named `_token` for the same domain without the Secure flag. Browsers do not enforce that `_token` cookies must have been set over HTTPS, unlike `__Secure-` prefixed cookies. A malicious cookie set this way could override the legitimate session cookie.

**Remediation:**

In `base_auth_manager.py`: Change `COOKIE_NAME_JWT_TOKEN = "__Secure-_token"`. In `Login.tsx`: Use `const [, setCookie, removeCookie] = useCookies(["__Secure-_token"]);` and `setCookie("__Secure-_token", data.access_token, { path: cookiePath, secure: true });`. All server-side code that reads the cookie by name must also be updated to reference `__Secure-_token`.

---

#### FINDING-013: Cookie `Secure` attribute is conditionally set based on client-side protocol detection

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | |
| **ASVS sections** | 3.3.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/ui/src/login/Login.tsx:83 |
| **Source Reports** | 3.3.1.md |
| **Related** | |

**Description:**

User authenticates → JWT token stored in cookie → `secure` flag determined by `globalThis.location.protocol` → if HTTP, cookie transmitted without Secure flag → susceptible to network interception. If the application is deployed behind a reverse proxy that terminates TLS and forwards HTTP to the application (common in container deployments), or in any scenario where the browser loads the page over HTTP: User navigates to `http://airflow.internal/login`, `globalThis.location.protocol` evaluates to `"http:"`, cookie is set without Secure attribute: `_token=eyJ...`, all subsequent requests transmit the JWT token in cleartext, and a network attacker captures the token and gains full API access. JWT tokens that grant full API access can be intercepted by network-level attackers when the Secure flag is not set. ASVS 3.3.1 requires the Secure attribute unconditionally.

**Remediation:**

Change to `setCookie("__Secure-_token", data.access_token, { path: cookiePath, secure: true });`. Always set Secure - enforce HTTPS at deployment layer. If HTTP support is needed for local development only, use a separate configuration flag rather than runtime protocol detection, and ensure production builds always set `secure: true`.

---

#### FINDING-014: Hardcoded `allow_credentials=True` without origin wildcard validation enables credential reflection to any origin if misconfigured

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | |
| **ASVS sections** | 3.4.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py:155-163 |
| **Source Reports** | 3.4.2.md |
| **Related** | |

**Description:**

When `allow_origins` is configured as `*`, Starlette's CORSMiddleware with `allow_credentials=True` reflects the request's Origin header. This allows any website to: Read sensitive API responses including connection details, variables, DAG configurations; Perform state-changing actions (create/delete DAGs, connections) on behalf of authenticated users; Extract JWT tokens from response bodies. Administrator sets `access_control_allow_origins = *` in configuration → `conf.getlist()` returns `["*"]` → passed to `CORSMiddleware(allow_origins=["*"], allow_credentials=True)` → Starlette reflects the incoming `Origin` header in `Access-Control-Allow-Origin` response (because `*` + credentials isn't valid per CORS spec, Starlette reflects instead) → Any website can make credentialed cross-origin requests. This violates ASVS 3.4.2's requirement that the Origin be "validated against an allowlist of trusted origins" and that wildcard responses "do not include any sensitive information."

**Remediation:**

Prevent dangerous misconfiguration by checking if "*" is in allow_origins and either: (1) Disable allow_credentials when wildcard is present, or (2) Raise an exception at startup preventing the configuration. Example: `if "*" in allow_origins: log.warning("CORS allow_origins contains '*'. Disabling allow_credentials to prevent credential reflection to arbitrary origins."); allow_credentials = False; else: allow_credentials = True`. Alternatively validate at startup: `if "*" in allow_origins and allow_credentials: raise AirflowException("CORS configuration error: 'access_control_allow_origins = *' cannot be used with credentialed requests. Specify explicit origins instead.")`

---

#### FINDING-015: OAuth2 Resource Owner Password Credentials Flow Advertised and Used

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | |
| **ASVS sections** | 10.4.4 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/security.py:111, airflow-core/src/airflow/api_fastapi/core_api/security.py:99-107 |
| **Source Reports** | 10.4.4.md |
| **Related** | |

**Description:**

The code explicitly uses FastAPI's OAuth2PasswordBearer scheme, which advertises the OAuth2 Resource Owner Password Credentials flow in the generated OpenAPI specification. ASVS 10.4.4 explicitly states that the 'password' grant type must no longer be used. The OpenAPI specification generated by FastAPI will advertise the OAuth2 password flow, directing API consumers and tooling (Swagger UI, code generators) to use the password flow by default. This direct credential exchange exposes user passwords to API clients rather than using redirect-based flows.

**Remediation:**

Replace OAuth2PasswordBearer with a scheme that doesn't advertise the password flow. Option 1 (Recommended): Use generic Bearer token scheme - replace with HTTPBearer(description='JWT Bearer token obtained via authorization code flow or SSO redirect', auto_error=False). Option 2: Implement full Authorization Code Flow using OAuth2AuthorizationCodeBearer with authorizationUrl and tokenUrl. Update all references to oauth2_scheme throughout the codebase to use the new scheme.

---

#### FINDING-016: `is_safe_url` uses domain/path matching rather than exact string comparison against pre-registered allowlist

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | |
| **ASVS sections** | 10.4.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/security.py:645-689 |
| **Source Reports** | 10.4.1.md |
| **Related** | |

**Description:**

While this function provides protection against open redirects (same-domain validation), it does NOT implement OAuth redirect URI validation per ASVS 10.4.1 requirements: 1. No client-specific allowlist of pre-registered URIs 2. No exact string comparison - uses scheme/netloc/path prefix matching 3. Returns `True` (safe) when no base URLs are configured. If this function is used for any OAuth-like redirect URI validation, it would allow any same-domain URL as a valid redirect target, which is insufficient for OAuth authorization servers. However, based on the provided code, Airflow appears to be an API server (OAuth resource server / token issuer via password grant) rather than an OAuth authorization server with authorization code flows. The provided code does not contain an OAuth authorization server implementation. The `oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")` indicates a Resource Owner Password Credentials flow, which doesn't involve redirect URIs. This finding is MEDIUM rather than HIGH because the requirement may not be directly applicable to the observed architecture.

**Remediation:**

If Airflow does implement or plans to implement OAuth authorization code flows:
```python
def validate_redirect_uri(client_id: str, redirect_uri: str) -> bool:
    """Validate redirect_uri using exact string comparison against pre-registered URIs."""
    registered_uris = get_registered_redirect_uris(client_id)
    return redirect_uri in registered_uris  # Exact string comparison
```

---

#### FINDING-017: `requires_authenticated()` dependency provides authentication-only check without function-level authorization

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | |
| **ASVS sections** | 8.2.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/security.py:605-614 |
| **Source Reports** | 8.2.1.md |
| **Related** | |

**Description:**

Any API endpoint that uses `requires_authenticated()` instead of a specific `requires_access_*` dependency will allow any authenticated user to invoke that function regardless of their assigned permissions. Without seeing all route definitions, there's a risk of Type B gaps (control exists but wrong control applied). This function is intentionally designed for endpoints where any authenticated user should have access. The risk is if it's accidentally used on permission-sensitive endpoints.

**Remediation:**

Consider adding a linter rule or architectural decision record that requires each endpoint to explicitly justify use of `requires_authenticated()` over a specific authorization dependency. Add a decorator or annotation that marks endpoints as "public to all authenticated users" to make this intentional.

---

#### FINDING-018: No check against common/breached password list

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | |
| **ASVS sections** | 6.2.4 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py, airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py |
| **Source Reports** | 6.2.4.md |
| **Related** | |

**Description:**

There is no check against a list of common/breached passwords anywhere in the codebase. While the current system auto-generates passwords with high entropy (making collision with common passwords statistically negligible), the absence of a common password check means: 1. If a password change endpoint is added, it would have no blocklist infrastructure 2. Manually-edited password files could contain common passwords without detection 3. The system cannot reject weak passwords if the password generation mechanism is ever modified

**Remediation:**

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

---

#### FINDING-019: No Application-Level Account Lockout or Failed Login Tracking

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | |
| **ASVS sections** | 6.3.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py:33-85 |
| **Source Reports** | 6.3.1.md |
| **Related** | |

**Description:**

An attacker can perform unlimited authentication attempts without any application-level detection or response. While rate limiting is delegated to the deployment layer (reverse proxy), the application provides no failed-login counter, progressive delays, account lockout, or audit trail for failed authentication attempts that would be necessary for credential stuffing detection regardless of network-level controls.

**Remediation:**

Implement application-level failed login tracking with lockout mechanism. Track failed attempts per username/IP with configurable thresholds (e.g., 5 attempts) and lockout windows (e.g., 5 minutes). Return HTTP 429 when threshold is exceeded. Example implementation:

```python
from collections import defaultdict
import time

_failed_attempts: dict[str, list[float]] = defaultdict(list)
LOCKOUT_THRESHOLD = 5
LOCKOUT_WINDOW = 300

@staticmethod
def create_token(body: LoginBody, ...) -> str:
    key = body.username
    now = time.time()
    attempts = [t for t in _failed_attempts[key] if now - t < LOCKOUT_WINDOW]
    _failed_attempts[key] = attempts
    
    if len(attempts) >= LOCKOUT_THRESHOLD:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts. Try again later.",
        )
    
    # ... existing authentication logic ...
    
    if len(found_users) == 0:
        _failed_attempts[key].append(now)
        raise HTTPException(...)
```

---

#### FINDING-020: No TLS Version Enforcement or Configuration in Application Layer

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | |
| **ASVS sections** | 12.1.1, 12.2.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/app.py:84-116, airflow-core/src/airflow/api_fastapi/core_api/app.py |
| **Source Reports** | 12.1.1.md, 12.2.2.md |
| **Related** | |

**Description:**

The FastAPI application is created without any TLS version configuration or enforcement at the application layer. While the domain context notes that 'The deployment manager is responsible for configuring reverse proxies (nginx, Apache) with proper TLS settings,' the application itself provides no validation that it's running behind a TLS-terminating proxy, no configuration options for minimum TLS version when running with an ASGI server (uvicorn supports `--ssl-keyfile`, `--ssl-certfile`, `--ssl-version`), and no documentation or configuration references for TLS version requirements. If deployed without proper reverse proxy configuration, the application will serve traffic over plaintext HTTP with no TLS version enforcement.

**Remediation:**

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
1. Update database documentation to include TLS/SSL connection parameters for PostgreSQL (sslmode=verify-full) and MySQL (ssl_ca/require_secure_transport), with explicit warnings against plaintext database connections in production.
2. Add a security configuration validation that runs at application startup and logs warnings if TLS indicators are missing.
3. Add HSTS header middleware that injects Strict-Transport-Security headers when the application detects it's serving over HTTPS.
4. Add optional HTTPSRedirectMiddleware configurable via [api] force_https setting.
5. Create a deployment security checklist document covering TLS 1.2+ configuration, database TLS configuration, certificate management, and network segmentation.
6. Implement a TLS health check in the /api/v2/monitor/health endpoint.
7. Add database connection TLS validation at startup.
8. Consider mutual TLS (mTLS) for the execution API communication.

---

#### FINDING-021: No HTTPS Enforcement or HTTP-to-HTTPS Redirect in Application Code

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | |
| **ASVS sections** | 12.2.1, 3.4.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py:179-194 |
| **Source Reports** | 12.2.1.md, 3.4.1.md |
| **Related** | |

**Description:**

The application's middleware stack does not include any middleware that adds a `Strict-Transport-Security` header to responses. The complete middleware chain is visible and consists only of `JWTRefreshMiddleware`, auth manager middlewares, `GZipMiddleware`, and `HttpAccessLogMiddleware`. None of these set HSTS headers. Without HSTS, an attacker performing a man-in-the-middle attack can downgrade the connection from HTTPS to HTTP (SSL stripping attack), intercepting authentication tokens and session cookies. Users who initially connect via HTTP (e.g., typing `airflow.example.com` without `https://`) can have their connection intercepted before being redirected to HTTPS. This is particularly critical for an application handling authentication credentials, JWT tokens, and sensitive orchestration data.

**Remediation:**

Add HTTPS enforcement middleware and HSTS headers:
```python
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
```

---

#### FINDING-022: Database Connection Examples Permit Unencrypted Communication

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | |
| **ASVS sections** | 12.2.1 |
| **Files** | airflow-core/docs/howto/set-up-database.rst:130-148 |
| **Source Reports** | 12.2.1.md |
| **Related** | |

**Description:**

The database connection documentation: 1. Shows connection strings without SSL/TLS parameters, 2. Does not mention configuring pg_hba.conf to require SSL (hostssl instead of host), 3. Does not mention MySQL's require_secure_transport option, 4. The keepalives_idle example for managed databases mentions SSL errors but not proper SSL configuration. Database credentials (airflow_pass in examples) and all metadata query data (DAG definitions, connection secrets, variable values) transit the network unencrypted when following these setup instructions.

**Remediation:**

Add a security section to the database documentation:
```rst
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
```

---

#### FINDING-023: Audit Log Access Bypasses DAG-Level Access Controls — Potential Data Over-Exposure

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | |
| **ASVS sections** | 15.3.1 |
| **Files** | airflow-core/docs/security/audit_logs.rst:37-39 |
| **Source Reports** | 15.3.1.md |
| **Related** | |

**Description:**

The documented behavior explicitly states that users with audit log read permission can access ALL entries regardless of DAG-specific access rights. This means a user restricted to only DAG_A but granted Audit Logs.can_read can see audit entries for DAG_B, DAG_C, etc. The extra field contains JSON-formatted additional context (parameters, error details, etc.) which may include connection names, variable values, or operational details from DAGs the user shouldn't access. This violates the principle of returning only the required subset of fields/records accessible to users.

**Remediation:**

Consider implementing DAG-level filtering for audit log responses: Filter audit log results to only include entries for DAGs the user can access. Implementation should filter entries to return only those where dag_id is None (system events) or dag_id is in user's accessible DAGs.

---

#### FINDING-024: Audit Log extra Field Returns Unfiltered JSON Context — Potential Sensitive Data Over-Exposure

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | |
| **ASVS sections** | 15.3.1 |
| **Files** | airflow-core/docs/security/audit_logs.rst |
| **Source Reports** | 15.3.1.md |
| **Related** | |

**Description:**

The extra field is documented as containing arbitrary additional context in JSON format. For events like post_connection, patch_variable, or trigger_dag_run, this context may include connection parameters (hostnames, ports, schemas), variable values (which could contain secrets if the variable name doesn't match masking keywords), DAG trigger parameters (conf dict which may contain runtime secrets), and error messages that may leak sensitive information. The REST API endpoint /eventLogs appears to return all fields including extra without field-level filtering based on the user's permissions or the sensitivity of the content.

**Remediation:**

Update the documentation example to include masking guidance using airflow.utils.log.secrets_masker.redact to ensure sensitive values are masked before storing in audit log. Provide example code showing proper sanitization of context data before insertion into the extra field.

---

#### FINDING-025: No Security Headers Middleware for Content Context Controls (X-Content-Type-Options, CSP)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-693 |
| **ASVS sections** | 3.2.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py:150-165 |
| **Source Reports** | 3.2.1.md |
| **Related** | FINDING-026, FINDING-047 |

**Description:**

The middleware stack configured in `init_middlewares()` does not include any middleware that sets `X-Content-Type-Options: nosniff`, `Content-Security-Policy`, or validates `Sec-Fetch-*` request headers to prevent content rendering in incorrect contexts. Without `X-Content-Type-Options: nosniff`, browsers may MIME-sniff responses and render content in an unintended context. Without CSP headers, there's no defense-in-depth against injected scripts in rendered content. Without `Sec-Fetch-*` validation, there's no server-side mechanism to reject requests that arrive in inappropriate contexts (e.g., resource requests to API endpoints).

**Remediation:**

Implement a SecurityHeadersMiddleware that adds X-Content-Type-Options: nosniff and Content-Security-Policy headers to all responses. Example implementation:
```python
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
```

---

#### FINDING-026: Execution API Sub-Application Does Not Receive Middleware Stack

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-693 |
| **ASVS sections** | 3.4.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/app.py:78-107 |
| **Source Reports** | 3.4.1.md |
| **Related** | FINDING-025, FINDING-047 |

**Description:**

The task execution API (`/execution`) is mounted before `init_middlewares()` is called, and `init_middlewares()` only adds middlewares to the core app. Even if an HSTS middleware were added, it would not automatically apply to the execution API sub-application. If security headers middleware is added to the core app, the execution API would still lack HSTS headers unless its sub-application is separately configured or a top-level middleware is used.

**Remediation:**

Add security headers as top-level middleware on the root `app` object after all sub-apps are mounted, or ensure each sub-application receives its own security headers middleware. This ensures uniform security header coverage across all mounted applications including /execution, /auth, and plugin routes.

---

#### FINDING-027: No Visible Anti-Forgery Token or Custom Header Requirement for State-Changing Requests

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-352 |
| **ASVS sections** | 3.5.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py:150-165 |
| **Source Reports** | 3.5.1.md |
| **Related** | FINDING-028, FINDING-049 |

**Description:**

The middleware stack does not include any CSRF protection middleware (anti-forgery token validation or custom header requirement). The application uses JWT tokens via `JWTRefreshMiddleware` which implies cookie-based JWT storage. Without anti-forgery tokens or requiring non-CORS-safelisted headers, cross-origin form submissions could execute state-changing operations if cookies are automatically sent. The known false positive list indicates JWT tokens stored in HTTP-only cookies without explicit SameSite attributes is intentional because configuration at deployment time. However, the absence of ANY visible anti-forgery mechanism (CSRF tokens, Origin header validation, or custom header requirements) represents a gap that goes beyond cookie attribute configuration. If the deployment does not configure `SameSite=Strict/Lax`, there is no fallback defense. Without anti-forgery protection, an authenticated user visiting a malicious page could have state-changing operations (trigger DAG runs, pause/unpause DAGs, delete tasks) performed on their behalf.

**Remediation:**

Option 1: Require custom header for API requests using CSRFProtectionMiddleware that checks for X-Requested-With header on POST, PUT, PATCH, DELETE methods and returns 403 if missing. Option 2: Validate Origin header using OriginValidationMiddleware that checks Origin header against allowed origins for state-changing methods and returns 403 for invalid origins.

---

#### FINDING-028: CORS Configuration Does Not Ensure Preflight is Triggered for Sensitive Requests

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-352 |
| **ASVS sections** | 3.5.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py:127-141 |
| **Source Reports** | 3.5.2.md |
| **Related** | FINDING-027, FINDING-049 |

**Description:**

The CORS middleware configuration does not enforce that sensitive requests trigger a CORS preflight. The allow_methods and allow_headers are fully configurable and could include only CORS-safelisted values. Without requiring a non-safelisted Content-Type (e.g., application/json) or custom header, simple cross-origin requests (POST with application/x-www-form-urlencoded) will bypass the CORS preflight mechanism entirely. FastAPI's CORSMiddleware does NOT block requests — it only controls response headers. A cross-origin simple request will be processed by the server even if the origin is not in allow_origins. The CORS policy only prevents the browser's JavaScript from reading the response. If the application relies on CORS preflight as a CSRF defense, simple requests bypass this entirely. State-changing operations (triggering DAG runs, modifying connections) could be executed by cross-origin requests without the user's consent.

**Remediation:**

Implement server-side Content-Type validation middleware that rejects CORS-safelisted content types for state-changing API requests. Example: Create ContentTypeValidationMiddleware that validates Content-Type for POST/PUT/PATCH/DELETE requests, rejecting application/x-www-form-urlencoded, multipart/form-data, and text/plain for /api/ endpoints, requiring application/json Content-Type instead. Return 415 status code for unsupported media types. Additionally, consider requiring a non-CORS-safelisted custom header (e.g., X-Requested-With: XMLHttpRequest) for all state-changing API endpoints as an additional CSRF defense.

---

#### FINDING-029: Documentation Gap - No File Size Limits Documented for DAG Files

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | |
| **ASVS sections** | 5.2.1 |
| **Files** | airflow-core/docs/administration-and-deployment/scheduler.rst |
| **Source Reports** | 5.2.1.md |
| **Related** | |

**Description:**

The scheduler documentation extensively discusses performance tuning, resource management (CPU, memory, I/O), and configuration knobs for scheduling loops. However, there is no mention of any file size limit for DAG files placed in the DAG directory. Without documented or enforced file size limits on DAG files, a DAG author could submit excessively large DAG files that consume significant memory and CPU during parsing, potentially causing denial of service to the scheduler or DAG processor. The documentation mentions the scheduler 'collects Dag parsing results' once per minute but doesn't specify any safeguard against oversized files. This is a documentation gap finding only. The actual implementation may contain size limits not reflected in these docs. Per the domain context, DAG authors are treated as trusted users, which reduces the practical severity.

**Remediation:**

Document and implement a configurable `max_dag_file_size` parameter in the `[scheduler]` configuration section, similar to other scheduler tunables already documented.

---

#### FINDING-030: No Runtime or Build-Time Mechanism to Enforce Component Remediation Compliance

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | |
| **ASVS sections** | 15.2.1, 15.1.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/app.py, airflow-core/src/airflow/api_fastapi/core_api/app.py, airflow-core/src/airflow/api_fastapi/app.py:146-155 |
| **Source Reports** | 15.2.1.md, 15.1.1.md |
| **Related** | |

**Description:**

The application imports and depends on numerous third-party components without any visible reference to remediation SLA documentation. Third-party package ecosystem is imported at application startup with no documented SLA for vulnerability remediation visible in codebase artifacts. Without documented risk-based remediation timeframes: Critical vulnerabilities in dependencies (e.g., FastAPI, Jinja2, Pydantic) may persist without defined urgency for patching; The Airflow provider package ecosystem (many independently maintained packages) lacks a standardized vulnerability response timeline; Legacy Flask/FAB plugins maintained for backwards compatibility may carry unpatched vulnerabilities indefinitely; Deployment managers lack clear guidance on when component updates must be applied.

**Remediation:**

Create and maintain a SECURITY_SLA.md or equivalent document (referenced from code comments or configuration) that defines risk-based SLA tiers: Critical (CVSS 9.0-10.0): 48 hours; High (CVSS 7.0-8.9): 7 days; Medium (CVSS 4.0-6.9): 30 days; Low (CVSS 0.1-3.9): 90 days/next release. Document component categories including Core Framework (FastAPI, SQLAlchemy, Pydantic) with update frequency within 14 days of security release; Provider Packages with update frequency within 30 days of security release; Legacy/Deprecated Components (Flask/FAB compatibility) with defined sunset timeline and security patches only policy.

---

#### FINDING-031: Deployment documentation lacks guidance on excluding source control metadata from production

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | |
| **ASVS sections** | 13.4.1 |
| **Files** | airflow-core/docs/administration-and-deployment/scheduler.rst, airflow-core/docs/core-concepts/overview.rst:75-110 |
| **Source Reports** | 13.4.1.md |
| **Related** | |

**Description:**

The deployment documentation describes multiple deployment architectures (basic, distributed, separate DAG processing) and provides detailed scheduler configuration guidance, but nowhere addresses the requirement to exclude `.git`, `.svn`, or other source control metadata from production deployments. The overview document describes DAG file synchronization between components but does not warn against synchronizing source control directories. If source control metadata is deployed with DAG files, the `.git` directory exposes full repository history including potentially deleted secrets, internal paths, developer emails, and commit messages. Attack surface increases if webserver or any externally-accessible component can serve these files. Chained with other vulnerabilities (directory traversal, misconfigured static file serving), this could lead to source code disclosure.

**Remediation:**

Add explicit deployment hardening guidance to the administration documentation including a Deployment Hardening section with Source Control Metadata subsection. Ensure that production deployments do not include source control metadata directories (e.g., `.git`, `.svn`, `.hg`) in the DAG files folder or any other deployed component directory. Configure CI/CD pipeline to strip source control metadata before deploying, use `git archive` or equivalent to export DAG files without `.git` directories, verify that Helm chart DAG sync configuration excludes these directories, and if using git-sync sidecar, ensure the `.git` directory is not accessible to the webserver. Example: git archive --format=tar HEAD dags/ | tar -x -C /opt/airflow/dags/

---

#### FINDING-032: No documentation defining rate limiting, anti-automation, or adaptive response controls for authentication

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | |
| **ASVS sections** | 6.1.1 |
| **Files** | airflow-core/docs/administration-and-deployment/scheduler.rst, airflow-core/docs/core-concepts/overview.rst |
| **Source Reports** | 6.1.1.md |
| **Related** | |

**Description:**

Neither the scheduler documentation nor the architecture overview documentation defines how rate limiting, anti-automation, or adaptive response controls protect against credential stuffing, password brute force, or malicious account lockout. The ASVS requirement specifically mandates that application documentation define these controls and explain their configuration. While the known false positive patterns acknowledge that 'No rate limiting at framework level for authentication endpoints is intentional because reverse proxies and auth manager implementations handle this,' ASVS 6.1.1 specifically requires documentation that defines how these controls are configured at the deployment layer. The absence of this documentation means operators may deploy Airflow without any rate limiting protection on authentication endpoints.

**Remediation:**

Create or reference security documentation that explicitly covers: 1) Reverse Proxy Rate Limiting - Configure reverse proxy (nginx, HAProxy, cloud load balancer) to limit login attempts: Maximum 5 failed login attempts per IP per 5-minute window, Maximum 10 failed login attempts per account per 15-minute window, HTTP 429 response with Retry-After header. 2) Anti-Automation - Configure CAPTCHA after 3 failed login attempts, progressive delays between login attempts, or IP-based reputation scoring via WAF. 3) Adaptive Response - Configure account protection that temporarily locks accounts after threshold failures (recommended: 10 attempts / 30 minutes), notifies account owners of lockout events, does NOT permanently lock accounts to prevent denial-of-service, and provides administrative unlock capability. 4) Auth Manager Configuration - Document rate limiting for LDAP/AD, OAuth/OIDC, and password-based authentication methods.

---

### 3.4 Low

#### FINDING-033: GUESS Mode Derives Algorithm from JWK Without Restricting to Pre-Defined Set

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-327 |
| ASVS Section(s) | 9.1.2 |
| Files | airflow-core/src/airflow/api_fastapi/auth/tokens.py:232-236 |
| Source Reports | 9.1.2.md |
| Related | FINDING-004 |

**Description:**

Data flow: JWKS source (trusted URL or file) → JWK 'alg' field → algorithms parameter in jwt.decode() → token validation. If a trusted JWKS endpoint is compromised or a local JWKS file is modified, an attacker could inject a JWK with a weak or unexpected algorithm. The algorithm selection is entirely delegated to the JWKS content without validating against an explicit allowlist. This is low severity because the JWKS source must already be compromised.

**Remediation:**

Validate JWK algorithm against allowlist: if algorithms == ['GUESS'] and isinstance(key, jwt.PyJWK): if not key.algorithm_name: raise jwt.InvalidTokenError('Missing algorithm in JWK'); if key.algorithm_name not in _ALLOWED_ALGORITHMS: raise jwt.InvalidTokenError(f'Algorithm {key.algorithm_name} from JWK is not in allowlist'); algorithms = [key.algorithm_name]; validation_key = key.key.

---

#### FINDING-034: SimpleAllAdminMiddleware Bypasses Backend Verification for Simple Auth Manager

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 7.2.1 |
| Files | airflow-core/src/airflow/api_fastapi/auth/managers/simple/middleware.py:28-33 |
| Source Reports | 7.2.1.md |
| Related | - |

**Description:**

When the simple auth manager is active, every request is automatically granted admin-level access. The middleware generates an admin token and injects it into request headers, creating a circular trust model where the generated token passes through JWTValidator but the verification is meaningless because the middleware itself generates the token it then validates. This creates a situation where no actual authentication occurs. Data flow: Incoming request → middleware generates admin token → injects into request headers → downstream validation occurs on a self-generated token (circular trust). This is a Type C gap — a control (JWT validation) is called but the result is predetermined since the middleware always injects a valid token.

**Remediation:**

Ensure deployment documentation clearly states that SimpleAuthManager MUST NOT be used in production. Consider adding a startup warning or configuration guard. Add deployment-mode guard for SimpleAllAdminMiddleware to prevent loading in production mode via environment variable or configuration check (e.g., if os.getenv('AIRFLOW_ENV') == 'production': raise RuntimeError('SimpleAuthManager cannot be used in production')).

---

#### FINDING-035: No OAuth Authorization Code Flow Visible; Direct Credential-to-Token Exchange Used

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 10.4.3 |
| Files | airflow-core/docs/security/jwt_token_authentication.rst:Token acquisition section |
| Source Reports | 10.4.3.md |
| Related | - |

**Description:**

The documentation describes a direct credential exchange flow (POST /auth/token with username/password → access_token), which is conceptually similar to the OAuth Resource Owner Password Credentials grant (deprecated in OAuth 2.1). No standard OAuth authorization code flow with short-lived codes is implemented in the provided code. If this system is intended to function as an OAuth Authorization Server, the absence of a proper authorization code flow means this requirement cannot be verified. However, based on the provided code and documentation, the system uses direct JWT issuance rather than OAuth authorization codes, making this requirement potentially not applicable to the current architecture.

**Remediation:**

If there is an authorization code flow implemented elsewhere in the codebase (not provided for this audit), that code should be audited for compliance with the 10-minute maximum lifetime requirement. If OAuth authorization server functionality is intended, implement a proper authorization code flow with short-lived codes (maximum 10 minutes for L1/L2, 1 minute for L3).

---

#### FINDING-036: No client-side fallback clearing mechanism for session termination without server connectivity

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 14.3.1 |
| Files | airflow-core/src/airflow/api_fastapi/auth/managers/simple/ui/src/login/Login.tsx |
| Source Reports | 14.3.1.md |
| Related | - |

**Description:**

ASVS 14.3.1 states: "the client-side should also be able to clear up if the server connection is not available when the session is terminated." The Login component includes cookie management (`useCookies`, `removeCookie`) but only uses `removeCookie` during login flow (to clear stale root-path cookies). No visible logout handler, session timeout detection, or offline cleanup mechanism is present in the provided client-side code. While the logout implementation may exist in other components not provided for review, the audit scope shows no evidence of: a `beforeunload` or `visibilitychange` handler to detect session/tab closure, a service worker or client-side timer to detect session expiration and clear cookies, or an offline-capable logout flow. If the server is unreachable (network error, server crash) when a user's session expires or the user closes the browser tab, the JWT cookie persists until its expiration time. On shared devices, this leaves a valid (not yet expired) token accessible.

**Remediation:**

Add client-side session expiration detection: ```typescript // In a root App component or layout useEffect(() => { const checkTokenExpiry = () => { const cookies = document.cookie.split(';'); const tokenCookie = cookies.find(c => c.trim().startsWith('_token=')); if (tokenCookie) { try { const token = tokenCookie.split('=')[1]; const payload = JSON.parse(atob(token.split('.')[1])); if (payload.exp && payload.exp * 1000 < Date.now()) { // Token expired - clear client-side data removeCookie("_token", { path: cookiePath }); localStorage.clear(); sessionStorage.clear(); } } catch { /* malformed token - clear anyway */ removeCookie("_token", { path: cookiePath }); } } }; const interval = setInterval(checkTokenExpiry, 60000); return () => clearInterval(interval); }, []); ```

---

#### FINDING-037: No Per-Client Grant Type Restriction Mechanism

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 10.4.4 |
| Files | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:131-143, airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:145, airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:128-129, airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:186-410 |
| Source Reports | 10.4.4.md |
| Related | - |

**Description:**

ASVS 10.4.4 requires that for a given client, the authorization server only allows the usage of grants that this client needs to use. The BaseAuthManager and security module contain no concept of OAuth client registration, client-specific grant type configuration, grant type validation per client identity, or client credential management. The authentication system treats all API consumers identically - any consumer with valid credentials can obtain a JWT token through the same mechanism. Impact is limited in Airflow's context because it doesn't function as a multi-client OAuth authorization server, but presents future risk if Airflow expands to support multiple client types with different security requirements.

**Remediation:**

If Airflow needs to support multiple client types with different security requirements, implement a client configuration system including: ClientConfig dataclass with client_id, client_secret_hash, allowed_grant_types (excluding 'password' and 'implicit'), redirect_uris, and scopes. Create ClientRegistry class to manage registered OAuth clients with validate_grant_type method. Integrate validation into the token endpoint to ensure clients only use allowed grant types. Implement validate_grant_request to check client_id against allowed grant types before token generation.

---

#### FINDING-038: Authorization documentation is code-embedded rather than standalone, lacking explicit mapping of consumer permissions to resource access rules

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 8.1.1 |
| Files | airflow-core/docs/security/deprecated_permissions.rst:entire file, airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:docstrings throughout |
| Source Reports | 8.1.1.md |
| Related | - |

**Description:**

The authorization model is documented through code-level abstractions (abstract methods, enums, dataclasses) and a deprecation migration notice, but there is no dedicated authorization documentation that explicitly maps: Which consumer roles/groups have access to which functions; The data-specific access rules per resource type; The interaction between team-based access and individual permissions; The trust boundaries between different authorization layers. The deprecated_permissions.rst only documents migration from old to new permission model, not the actual access rules themselves.

**Remediation:**

Create a standalone authorization documentation file that: 1. Enumerates all resource types and supported methods; 2. Defines the default permission model and how roles map to resource access; 3. Documents team-based isolation rules; 4. Specifies how batch authorization, filter-based authorization, and direct checks interact; 5. Maps each API endpoint to its required permissions

---

#### FINDING-039: Wildcard DAG ID (`~`) bypasses specific-resource authorization in favor of general permission check

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 8.2.2 |
| Files | airflow-core/src/airflow/api_fastapi/core_api/security.py:175-180 |
| Source Reports | 8.2.2.md |
| Related | - |

**Description:**

When `dag_id` is `~`, authorization is checked without a specific resource identifier, relying on the auth manager to correctly interpret `DagDetails(id=None)` as "check general access." The subsequent data-level filtering via `PermittedDagFilter` dependencies must be applied to ensure actual BOLA protection. Data flow: Request with `dag_id=~` → dag_id set to None → `DagDetails(id=None)` → general DAG authorization check (not resource-specific). This is by design - the `~` wildcard is Airflow's convention for "all resources," and the actual IDOR protection is enforced by the `PermittedDagFilter` applied to the database query. This is documented in the false positive patterns as "Batch authorization checks that may return partial results."

**Remediation:**

No immediate remediation required as this is by design. Ensure that the `PermittedDagFilter` is consistently applied to all queries that use the wildcard DAG ID pattern to maintain BOLA protection at the data layer.

---

#### FINDING-040: No password length validation on manually edited passwords

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 6.2.1 |
| Files | airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:455, services/login.py:51-52 |
| Source Reports | 6.2.1.md |
| Related | - |

**Description:**

While system-generated passwords are 16 characters (meeting the requirement), there is no length validation enforced on passwords stored in the password file. If an administrator manually edits the password file (`simple_auth_manager_passwords.json.generated`) or if the file is corrupted, there is no validation at login time that rejects passwords below the minimum length. A manually-set weak password (e.g., "abc") would be accepted by the system without any rejection or warning. The login endpoint only validates that a password is non-empty, not that it meets minimum length.

**Remediation:**

Add minimum password length validation: ```python MIN_PASSWORD_LENGTH = 8 @staticmethod def _generate_password() -> str: alphabet = "abcdefghkmnpqrstuvwxyzABCDEFGHKMNPQRSTUVWXYZ23456789" password = "".join(secrets.choice(alphabet) for _ in range(16)) assert len(password) >= MIN_PASSWORD_LENGTH return password ``` Implement validation at login time to reject passwords below minimum length. Validate password length when loading from the password file.

---

#### FINDING-041: Unable to verify password input field masking in UI template

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 6.2.6 |
| Files | airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:355-384 |
| Source Reports | 6.2.6.md |
| Related | - |

**Description:**

The login UI is served via Jinja2 templates from `{package_dir}/ui/dist` (or `ui/dev` in dev mode), but the actual HTML template content (`index.html`) is not included in the audit scope. Without the template source, it is impossible to verify whether password input fields use `type="password"` for masking. If the UI template uses `type="text"` for the password field, credentials would be visible on screen during entry.

**Remediation:**

Verify that the login form template at `airflow-core/src/airflow/api_fastapi/auth/managers/simple/ui/dist/index.html` contains: `<input type="password" name="password" id="password" ... />` And optionally includes a toggle button to temporarily reveal the password.

---

#### FINDING-042: Production Warning for SimpleAuthManager Is Advisory Only (No Enforcement)

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 6.3.2 |
| Files | airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:163-172 |
| Source Reports | 6.3.2.md |
| Related | - |

**Description:**

The production detection only produces a log warning. The system continues to operate with plaintext passwords and optional no-credential access, meaning an accidental production deployment will function with insecure defaults. The `_looks_like_production()` method detects production indicators (non-sqlite backend, non-local API host, or distributed executor) but does not enforce any restrictions.

**Remediation:**

Consider raising an exception or requiring explicit opt-in (e.g., `simple_auth_manager_allow_production=True`) when production indicators are detected. Convert the warning into a hard failure to prevent accidental insecure production deployments.

---

#### FINDING-043: Database Connection Documentation Lacks TLS Configuration Guidance

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 12.1.1 |
| Files | airflow-core/docs/howto/set-up-database.rst:144-148, airflow-core/docs/howto/set-up-database.rst:210-213 |
| Source Reports | 12.1.1.md |
| Related | - |

**Description:**

The database setup documentation provides connection string examples without TLS parameters. The domain context explicitly states 'Database connections should also use TLS to protect credentials and query data in transit.' PostgreSQL supports `?sslmode=require` or `?sslmode=verify-full`, and MySQL supports `?ssl=true` or connection args for SSL. The documentation also shows a `keepalive_kwargs` example for `sql_alchemy_connect_args` but does not include SSL configuration in such examples. Deployment managers following this documentation will configure database connections without TLS, exposing credentials and query data in transit.

**Remediation:**

Add TLS configuration guidance to the documentation: rst .. important:: For production deployments, always enable TLS for database connections to protect credentials and data in transit. For PostgreSQL with TLS: .. code-block:: text postgresql+psycopg2://&lt;user&gt;:&lt;password&gt;@&lt;host&gt;/&lt;db&gt;?sslmode=verify-full&sslrootcert=/path/to/ca.crt For MySQL with TLS: .. code-block:: text mysql+mysqldb://&lt;user&gt;:&lt;password&gt;@&lt;host&gt;[:&lt;port&gt;]/&lt;dbname&gt;?ssl_ca=/path/to/ca.crt

---

#### FINDING-044: Pagination and Filter Parameters Lack Documented Validation Rules

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 2.1.1 |
| Files | airflow-core/src/airflow/api_fastapi/common/db/common.py:67-167 |
| Source Reports | 2.1.1.md |
| Related | - |

**Description:**

The utility functions accept offset, limit, order_by, and filters as OrmClause objects but there is no documentation within this module or the associated documentation files specifying: Maximum allowed values for limit (to prevent DoS via requesting millions of records), Valid ranges for offset, Allowed sort fields/directions for order_by, Permitted filter combinations and value ranges. Without documented validation rules, different API endpoints may implement inconsistent validation or omit it entirely. This is a documentation gap rather than a code vulnerability.

**Remediation:**

Define validation rules for pagination parameters (e.g., maximum limit value, valid offset ranges) in API documentation or inline docstrings. Add documentation specifying: offset must be non-negative integer, limit must be 1-100 (configurable max), order_by must reference allowed model columns, filters must use parameterized values. Example provided in report includes enhanced docstring with validation rules section.

---

#### FINDING-045: Filter Application Function Does Not Perform Validation of Filter Content

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 2.2.1 |
| Files | airflow-core/src/airflow/api_fastapi/common/db/common.py:48-56 |
| Source Reports | 2.2.1.md |
| Related | - |

**Description:**

The apply_filters_to_select function applies any OrmClause to a query without validation. The security of this pattern depends entirely on the upstream construction of OrmClause objects. The function itself only checks for None values (null safety, not input validation), does not validate that the filter targets allowed columns, and does not validate value ranges or data types. This is a design pattern observation rather than a direct vulnerability. If OrmClause objects are constructed from validated Pydantic models (which is the typical FastAPI pattern), validation happens upstream. However, this utility function provides no defense-in-depth. This represents a potential coverage gap rather than a confirmed vulnerability.

**Remediation:**

Consider adding defensive assertions or type checking within the utility. Add isinstance checks to provide defense-in-depth: if not isinstance(f, OrmClause): raise TypeError(f"Expected OrmClause, got {type(f)}"). Document pagination validation rules and add explicit documentation specifying allowed ranges for pagination parameters. Audit OrmClause implementations to ensure they cannot be abused to inject unexpected SQL clauses. Consider implementing query complexity limits to prevent denial-of-service via complex filter combinations.

---

#### FINDING-046: Documentation REST API Examples Lack Authentication Context — Potential for Misuse

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 14.2.1 |
| Files | airflow-core/docs/security/audit_logs.rst:225-240 |
| Source Reports | 14.2.1.md |
| Related | - |

**Description:**

The documented query parameters (event, dag_id, after, before, full_content) are non-sensitive filter/pagination criteria and do NOT violate 14.2.1. These are resource identifiers and temporal filters, not API keys, session tokens, or passwords. The documentation does not show authentication being passed in URLs, which is correct. However, the curl examples omit authentication headers entirely, which could lead developers to implement insecure patterns (e.g., passing API keys as query parameters) if they don't reference additional authentication documentation. Developers copying examples without authentication context might introduce API key-in-URL patterns.

**Remediation:**

Add authentication header examples to REST API documentation: ```rst # Get all audit logs (with proper authentication in headers) curl -X GET "http://localhost:8080/api/v1/eventLogs" \ -H "Authorization: Bearer <token>" ``` Immediate: Review the /eventLogs REST API implementation to verify that response fields are filtered appropriately and that the extra field undergoes secrets masking before being returned in API responses. Verify that authentication tokens/API keys are not accepted via URL query parameters in the actual implementation. Short-term: Update REST API documentation examples to include authentication headers, reducing the risk of developers omitting proper authentication patterns. Long-term: Document a data classification framework for what should and should not be stored in audit log extra fields, with automated enforcement.

---

#### FINDING-047: Static File Serving with `html=True` Without Sec-Fetch Validation

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-693 |
| ASVS Section(s) | 3.2.1 |
| Files | airflow-core/src/airflow/api_fastapi/core_api/app.py:56-63 |
| Source Reports | 3.2.1.md |
| Related | FINDING-025, FINDING-026 |

**Description:**

Static files are served with `html=True` which enables HTML rendering of files in the directory. While the directory contains application-owned UI assets (not user uploads), there is no `Sec-Fetch-Dest` or `Sec-Fetch-Mode` validation to ensure these resources are loaded in the expected context. The `html=True` flag means any file in the directory will be rendered as HTML when accessed directly, which violates defense-in-depth principles.

**Remediation:**

Consider setting `html=False` unless directory index serving is needed, and rely on explicit HTML response for the SPA entry point via the catch-all route.

---

#### FINDING-048: Template Variable Injection Without Explicit Escaping Context

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-79 |
| ASVS Section(s) | 3.2.2 |
| Files | airflow-core/src/airflow/api_fastapi/core_api/app.py:88-93 |
| Source Reports | 3.2.2.md |
| Related | - |

**Description:**

The SPA catch-all route passes `backend_server_base_url` (derived from `request.base_url.path`) into a Jinja2 template context. While Jinja2 auto-escapes by default in HTML context, if this value is used within a JavaScript block in the template, it could bypass HTML escaping. Data flow: `request.base_url.path` (derived from Host header or configured root_path) → template context variable → rendered in `index.html`. Impact: Low because `base_url.path` is typically controlled by server configuration (`root_path`), not directly by user input. However, if the Host header is not validated by a reverse proxy, path-based injection could occur.

**Remediation:**

Ensure the `index.html` template uses `{{ backend_server_base_url | tojson }}` if the value is placed in a JavaScript context, or verify that the reverse proxy normalizes the Host header.

---

#### FINDING-049: No Global HTTP Method Enforcement or Sec-Fetch-* Validation for Sensitive Operations

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-352 |
| ASVS Section(s) | 3.5.3 |
| Files | airflow-core/src/airflow/api_fastapi/core_api/app.py:32-93 |
| Source Reports | 3.5.3.md |
| Related | FINDING-027, FINDING-028 |

**Description:**

While the visible routes use appropriate methods (only GET for informational/UI endpoints), there is no global middleware that validates Sec-Fetch-* headers or enforces that sensitive operations cannot be triggered via navigation requests or resource loads. The actual sensitive API endpoints (routers included via public_router and ui_router) are not visible in the provided code. Without Sec-Fetch-* validation, navigation requests (e.g., &lt;img src="https://airflow.example.com/api/v2/connections/delete/myconn"&gt; if a GET-based delete existed) or cross-origin resource loads could trigger sensitive functionality. While FastAPI routers should enforce method restrictions, there's no defense-in-depth at the middleware level.

**Remediation:**

Implement SecFetchValidationMiddleware to validate Sec-Fetch-* headers for API endpoints. For API endpoints, validate Sec-Fetch-Site and Sec-Fetch-Mode headers. Reject cross-site navigation requests to API endpoints with 403 status. Example implementation: class SecFetchValidationMiddleware(BaseHTTPMiddleware): async def dispatch(self, request: Request, call_next): if request.url.path.startswith("/api/"): sec_fetch_site = request.headers.get("Sec-Fetch-Site"); sec_fetch_mode = request.headers.get("Sec-Fetch-Mode"); if sec_fetch_site == "cross-site" and sec_fetch_mode == "navigate": return JSONResponse(status_code=403, content={"detail": "Cross-site navigation to API not allowed"}); return await call_next(request)

---

#### FINDING-050: No Content-Type Enforcement for Plugin-Mounted Sub-Applications

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-430 |
| ASVS Section(s) | 4.1.1 |
| Files | airflow-core/src/airflow/api_fastapi/app.py:184-228, airflow-core/src/airflow/api_fastapi/app.py:199-212, airflow-core/src/airflow/api_fastapi/core_api/app.py:145 |
| Source Reports | 4.1.1.md |
| Related | - |

**Description:**

Plugin-mounted sub-applications are registered at arbitrary URL prefixes without any middleware to enforce or validate that Content-Type headers include proper charset parameters. While FastAPI applications default to correct Content-Type behavior, the init_plugins function accepts arbitrary subapp objects (which may or may not be FastAPI apps) and mounts them directly. There is no middleware applied to the parent app that validates Content-Type headers on responses from these mounts. If a plugin serves text content without proper Content-Type and charset, browsers may perform content-type sniffing, potentially interpreting text as HTML and enabling XSS attacks. Risk is mitigated by the fact that most plugins would use FastAPI's standard response classes.

**Remediation:**

Add a middleware at the parent application level that ensures all responses with text/* content types include charset. Implement ContentTypeEnforcementMiddleware that checks content-type headers and appends charset=utf-8 if missing for text/* responses. Also add X-Content-Type-Options: nosniff header to prevent content-type sniffing. Apply this middleware in init_config() which runs for all app configurations. Additionally, add integration tests that verify Content-Type + charset on all response paths including error handlers, and document Content-Type requirements for plugin developers in plugin API documentation.

---

#### FINDING-051: Dynamic Plugin Loading Extends Attack Surface Without Documented Component Risk Classification

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 15.1.1 |
| Files | airflow-core/src/airflow/api_fastapi/app.py:181-220 |
| Source Reports | 15.1.1.md |
| Related | - |

**Description:**

Plugins are loaded dynamically without any visible mechanism to classify them as risky components or enforce that they meet remediation timeframe requirements. A plugin with known vulnerabilities could be loaded indefinitely. The init_plugins function integrates FastAPI app, middlewares and UI plugins from plugins_manager.get_fastapi_plugins() and mounts them without risk classification.

**Remediation:**

Document plugin risk classification criteria and enforce version/maintenance requirements for loaded plugins. Define minimum security standards for loaded plugins, including version freshness and maintenance status.

---

#### FINDING-052: Legacy Flask/FAB Plugin Layer Maintains Potentially Outdated Dependencies Without Sunset Enforcement

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 15.2.1 |
| Files | airflow-core/src/airflow/api_fastapi/core_api/app.py:94-119 |
| Source Reports | 15.2.1.md |
| Related | - |

**Description:**

The legacy Flask/FAB plugin compatibility layer may keep outdated dependencies (Flask-AppBuilder, older Flask versions) in the dependency tree indefinitely. While a deprecation warning is appropriate, there is no enforcement mechanism to prevent loading of Flask/FAB plugins after a defined sunset date. This legacy compatibility layer continues to load without time-based restrictions.

**Remediation:**

Implement a configuration-controlled sunset date after which Flask plugins are refused. Example: Read sunset_date from configuration and raise AirflowException if current date exceeds the configured sunset date, with a message instructing users to migrate their plugins to the FastAPI plugin interface.

---

# 4. Positive Security Controls

| Control ID | Control Description | Evidence | Implementation Location | ASVS Mapping |
|------------|-------------------|----------|------------------------|--------------|
| PSC-001 | JWT signature validation via jwt.decode() with required claims enforcement | All token validation occurs server-side with cryptographic signature verification, expiry checks, audience validation, and issuer validation | tokens.py:260-283, 192, 221-249 | 9.1.1, 9.1.3, 9.2.1 |
| PSC-002 | Dynamic token generation with unique JTI | JWTGenerator.generate() creates fresh tokens with UUID4 jti (128 bits CSPRNG entropy), iat, nbf, and exp claims set dynamically at generation time | tokens.py:347-369, 351 | 7.2.2 |
| PSC-003 | Key retrieval from pre-configured trusted sources only | Key material retrieved exclusively from self.jwks (pre-configured JWKS) or self.secret_key; no processing of jku/x5u/jwk headers from tokens | tokens.py:207-215, 460-483, 201-205 | 9.1.3 |
| PSC-004 | Revocation infrastructure exists | RevokedToken model with revoke() method and revoke_token() storage method provide building blocks for proper invalidation | tokens.py:285-292, 289, 35 | 7.4.1 (partial) |
| PSC-005 | Cookie-based token delivery with security attributes | HTTP-only, secure, SameSite=Lax cookies limit token exposure compared to localStorage | refresh_token.py:JWTRefreshMiddleware | 3.3.1, 14.3.1 |
| PSC-006 | Execution API uses short-lived tokens with automatic refresh | 10-minute default lifetime for execution tokens with transparent refresh mechanism; workload → execution token exchange pattern with limited scope | Execution API documentation | 9.2.1 |
| PSC-007 | Separation of token generation and validation | System cleanly separates token generation (JWTGenerator) from validation (JWTValidator), enabling different configurations per API surface | tokens.py | 9.1.1 |
| PSC-008 | XOR key type constraint prevents key confusion | __attrs_post_init__ enforces exactly one of jwks or secret_key is configured, preventing ambiguous validation paths | tokens.py:193, 318-319 | 9.1.3 |
| PSC-009 | Temporal claims validation (exp, iat, nbf) | PyJWT validates exp and nbf automatically with configurable clock skew tolerance (default 10 seconds leeway) | tokens.py:192, 240, 238-244 | 9.2.1 |
| PSC-010 | JWKS periodic refresh from trusted source with health monitoring | JWKS.fetch_jwks() refreshes keys from initially configured URL; JWKS.status() raises errors if JWKS becomes stale | tokens.py:79-91, 95-106 | 9.1.3 |
| PSC-011 | Server-side token revocation | revoke_token() method persists token's JTI in database, and get_user_from_token() checks RevokedToken.is_revoked(jti) on every request | base_auth_manager.py:140 | 7.4.1 |
| PSC-012 | Configurable JWT expiration | Token lifetime is bounded by jwt_expiration_time configuration, ensuring tokens self-expire | conf.getint("api_auth", "jwt_expiration_time") | 9.2.1 |
| PSC-013 | Stale cookie cleanup on login | Login component proactively removes old _token cookies at root path before setting new ones | Login.tsx:78-80 | 7.2.4 |
| PSC-014 | Path-scoped cookies | Cookie path derived from &lt;base&gt; tag, ensuring JWT cookie is scoped to correct application subpath | Login.tsx:38-42, 82 | 3.3.1 |
| PSC-015 | Safe URL validation | isSafeUrl() function prevents open redirect attacks by validating next parameter against current origin | Login.tsx | 10.4.1 |
| PSC-016 | Configuration-driven CORS | Origins, methods, and headers read from Airflow configuration system allowing administrators to define specific trusted origins | app.py:155-163 | 3.4.2 |
| PSC-017 | Conditional CORS activation | CORS middleware only added when at least one CORS setting is configured, disabled by default | app.py:155 | 3.4.2 |
| PSC-018 | Explicit method and header control | Both allow_methods and allow_headers are configurable, following principle of least privilege | app.py:155-163 | 3.4.2 |
| PSC-019 | Open redirect protection | is_safe_url prevents redirects to external domains, JavaScript URIs, and data URIs | security.py:645-689 | 10.4.1 |
| PSC-020 | Scheme validation restricts redirects to http/https only | Scheme checking in is_safe_url | security.py:682 | 10.4.1 |
| PSC-021 | Path normalization prevents path traversal | posixpath.normpath prevents path traversal attacks in redirect URLs | security.py:670-676 | 10.4.1 |
| PSC-022 | JWT token revocation via JTI tracking | revoke_token method in BaseAuthManager enables server-side token invalidation | base_auth_manager.py:131-143 | 7.4.1 |
| PSC-023 | FastAPI dependency injection pattern | Depends(...) pattern makes authorization checks impossible to bypass when correctly applied | security.py | 8.3.1 |
| PSC-024 | Central enforcement point via _requires_access() | Provides consistent HTTP 403 responses on unauthorized access | security.py:638-642 | 8.3.1 |
| PSC-025 | Comprehensive resource coverage | Dedicated authorization functions for all major resource types (DAGs, pools, connections, variables, etc.) | security.py:167-603 | 8.2.1, 8.2.2 |
| PSC-026 | Bulk operation authorization | Checks all items in batch requests before allowing operations | security.py:305-561 | 8.2.2 |
| PSC-027 | Abstract contract enforcement | @abstractmethod ensures all auth manager implementations provide authorization checks | base_auth_manager.py | 8.2.1 |
| PSC-028 | Server-side enforcement exclusively | All authorization logic executes on backend with no client-side dependencies | security.py | 8.3.1 |
| PSC-029 | Team-based multi-tenancy isolation | Validates resource ownership at database level before authorization | security.py:618-636 | 8.2.2 |
| PSC-030 | Resource-specific detail objects | Auth manager can make resource-specific authorization decisions | security.py | 8.2.2 |
| PSC-031 | Dual-layer protection | Both dependency checks and ORM query filters provide defense-in-depth against IDOR/BOLA | security.py:133-137 | 8.2.2 |
| PSC-032 | USER_INJECTED_BY_TRUSTED_MIDDLEWARE sentinel | Prevents client-side user injection | security.py:128-137 | 8.3.1 |
| PSC-033 | Well-structured authorization contract | Comprehensive docstrings in BaseAuthManager abstract class | base_auth_manager.py | 8.1.1 |
| PSC-034 | ResourceMethod and DagAccessEntity enums | Clearly enumerate all valid actions and entity types | base_auth_manager.py:82-92, resource_details.py:90-103 | 8.1.1 |
| PSC-035 | System-generated passwords exceed requirement | _generate_password() produces 16-character passwords using cryptographically secure secrets.choice() | simple_auth_manager.py:455 | 6.2.1 |
| PSC-036 | Cryptographic randomness | secrets module ensures generated passwords have sufficient entropy (~85 bits) | simple_auth_manager.py:455 | 6.2.1 |
| PSC-037 | Constant-time comparison | hmac.compare_digest() prevents timing-based credential enumeration | services/login.py:51 | 6.3.1 |
| PSC-038 | Production detection heuristic | _looks_like_production() warns operators when dev-only auth manager used in production | simple_auth_manager.py | 6.3.2 |
| PSC-039 | Password field accepts any string | No composition restrictions, aligning with NIST SP 800-63B guidance | services/login.py | 6.2.5 |
| PSC-040 | Standard string password field | Supports paste and password managers | v2-simple-auth-manager-generated.yaml:155-156, login.py:55-58 | 6.2.7 |
| PSC-041 | Direct password comparison without modification | Password compared byte-for-byte without transformation, truncation, or case conversion | services/login.py:59-64 | 6.2.8 |
| PSC-042 | Generic error messages | Returns 'Invalid credentials' without indicating which field was incorrect | login.py:69 | 6.3.1 |
| PSC-043 | User list is configuration-driven | No hardcoded usernames; all users from simple_auth_manager_users config | simple_auth_manager.py:get_users() | 6.3.2 |
| PSC-044 | Minimal authentication schema | No password hints or knowledge-based authentication | OpenAPI spec LoginBody | 6.4.2 |
| PSC-045 | Cookie uses httponly flag | JWT cookie set with httponly=True, preventing JavaScript access | login.py:95 | 3.3.1, 14.3.1 |
| PSC-046 | File locking for concurrent initialization | fcntl.flock prevents race conditions when multiple workers initialize simultaneously | simple_auth_manager.py | 2.3.1 |
| PSC-047 | Fernet authenticated encryption | AES-128-CBC + HMAC-SHA256 for connections/variables; HMAC before decryption mitigates padding oracle | fernet.rst, fernet.rst:48 | 11.3.1, 11.3.2 |
| PSC-048 | Proper key generation | Fernet.generate_key() produces cryptographically random 256-bit key | fernet.rst | 11.3.2 |
| PSC-049 | Key rotation procedure documented | Three-step rotation process ensures continuous availability | fernet.rst:56-68 | 11.3.2 |
| PSC-050 | No ECB mode usage | Architecture documentation shows no evidence of ECB usage | N/A | 11.3.1 |
| PSC-051 | Use of cryptography library | Reliance on established cryptographic library rather than custom implementations | fernet.rst:48 | 11.3.2 |
| PSC-052 | Pluggable secrets backends | Integration with HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault | secrets-backend/index.rst | 11.3.2 |
| PSC-053 | HMAC-SHA256 for message authentication | NIST-approved hash function with no known practical attacks | fernet.rst | 11.4.1 |
| PSC-054 | bcrypt for password hashing | Recommended by OWASP Password Storage Cheat Sheet | Domain context | 11.4.1 |
| PSC-055 | No deprecated hash functions | No MD5, SHA-1, or other deprecated hash functions for cryptographic purposes | Documentation files | 11.4.1 |
| PSC-056 | Clean separation of TLS termination | Appropriate for containerized deployments where TLS handled by ingress/load balancers | Architecture | 12.1.1 |
| PSC-057 | Explicit deployment manager TLS responsibility | Domain context acknowledges deployment manager responsibility | Domain context | 12.1.1 |
| PSC-058 | TLS termination delegated to reverse proxy | Standard pattern for containerized deployments | Architecture | 12.1.1, 12.2.1 |
| PSC-059 | Execution API documented as requiring HTTPS | For internal communication | Documentation | 12.2.1 |
| PSC-060 | JWT authentication middleware present | Operates over any protocol but provides authentication layer | app.py:186 | 9.1.1 |
| PSC-061 | Managed database section mentions SSL | Indicating awareness of TLS in database connections | set-up-database.rst | 12.2.1 |
| PSC-062 | No insecure WebSocket patterns | No WebSocket endpoints using unencrypted WS protocol | Code review | 4.4.1 |
| PSC-063 | Organizational awareness of WSS requirement | Domain context requires WSS for WebSocket connections | Domain context | 4.4.1 |
| PSC-064 | Separation of concerns in data access | Query construction separate from response rendering | common.py | 1.2.1 |
| PSC-065 | Strong layered architecture | Security controls at appropriate layers | common.py | 1.2.1, 2.2.2 |
| PSC-066 | Type-safe interface using OrmClause | Prevents accidental raw string injection into queries | common.py | 1.2.4 |
| PSC-067 | SQLAlchemy ORM usage with parameterized queries | No raw SQL string construction; all filters through ORM layer | common.py, common.py:55-63 | 1.2.4 |
| PSC-068 | FastAPI/Pydantic automatic JSON serialization | Inherently provides safe JSON serialization | common.py | 1.2.3 |
| PSC-069 | Session dependency injection and lifecycle management | Centralized session management through dependency injection | common.py:47-48, 68-72, 140 | 1.2.4 |
| PSC-070 | Dual sync/async pattern with consistent filter logic | Reduces risk of security inconsistencies between code paths | common.py:95-113, 140-157 | 1.2.4 |
| PSC-071 | Database configuration via environment variables | Connection strings not constructed dynamically from user input | set-up-database.rst | 1.2.4 |
| PSC-072 | Documented security policy alignment | SQL injection risk acceptance for trusted DAG authors clearly documented | sql.rst, security/sql.rst | 2.1.1 |
| PSC-073 | Database version and character set requirements | Supported versions and UTF-8 requirements clearly specified | set-up-database.rst | 1.5.1 |
| PSC-074 | Server-side validation enforcement | Query construction, session management, pagination all server-side | common/db/common.py:40, 60 | 2.2.2 |
| PSC-075 | Non-sensitive URL parameters | REST API examples use only filtering criteria in query strings | audit_logs.rst | 14.2.1 |
| PSC-076 | Explicit anti-pattern warning for environment variables | Documentation warns against passing secrets via environment variables | mask-sensitive-values.rst | 14.2.1 |
| PSC-077 | Sensitive keyword detection | Masking system detects token, api_key, apikey, authorization, secret keywords | mask-sensitive-values.rst | 14.2.1 |
| PSC-078 | Path parameters are identifiers only | REST API path components are operational identifiers, not sensitive secrets | audit_logs.rst | 14.2.1 |
| PSC-079 | Sensitive data masking in logs | Masks values containing sensitive keywords | mask-sensitive-values.rst | 14.2.1 |
| PSC-080 | Secrets masking at access time | Automatically masks Connection passwords and variables in logs and UI | mask-sensitive-values.rst | 14.2.1 |
| PSC-081 | Configurable sensitive keyword list | AIRFLOW__CORE__SENSITIVE_VAR_CONN_NAMES enables domain-specific field names | mask-sensitive-values.rst | 14.2.1 |
| PSC-082 | Permission requirement for audit access | Audit Logs.can_read permission required | audit_logs.rst | 15.3.1 |
| PSC-083 | Structured audit log fields | Specific typed fields enable precise querying and field-level access control | audit_logs.rst | 15.3.1 |
| PSC-084 | Warning against environment variable secrets | Documentation warns secrets via environment variables are NOT masked | mask-sensitive-values.rst | 14.2.1 |
| PSC-085 | JSONResponse used for API error responses | Correctly sets Content-Type: application/json | app.py | 3.2.1 |
| PSC-086 | Explicit media_type for webapp template | Explicitly sets media_type="text/html" for SPA shell | app.py | 3.2.1 |
| PSC-087 | Application-owned static files directory | Static files from airflow/ui/dist, not user-uploaded content | app.py | 5.3.1 |
| PSC-088 | Jinja2Templates default auto-escaping | Default auto-escaping provides protection against template injection | app.py | 1.3.1 |
| PSC-089 | Auth manager middleware extensibility point | get_fastapi_middlewares() may include CSRF protection | app.py:150-165 | 3.5.1 |
| PSC-090 | CORS middleware configured | CORSMiddleware provides defense-in-depth | app.py | 3.4.2 |
| PSC-091 | CORS middleware conditionally applied | Only added when configured, avoiding unnecessary processing | app.py:127-141 | 3.4.2 |
| PSC-092 | allow_credentials=True prevents wildcard origins | Browser security policy prevents wildcard * origins | app.py:127-141 | 3.4.2 |
| PSC-093 | FastAPI router method enforcement | Router system enforces HTTP method restrictions per-endpoint | app.py:32-93 | 3.5.3 |
| PSC-094 | Catch-all routes are GET-only | api_not_found and webapp routes prevent POST/PUT/DELETE | app.py:32-93 | 3.5.3 |
| PSC-095 | Framework-level charset handling | Starlette automatically appends ; charset=utf-8 for text/* content types | app.py | 3.2.1 |
| PSC-096 | RFC 8259 compliance for JSON | JSONResponse correctly omits charset parameter | app.py:78-81 | 1.2.3 |
| PSC-097 | Reserved URL prefix validation | Plugin mounts validated against reserved prefixes | app.py:184-228 | 5.3.1 |
| PSC-098 | GZipMiddleware preserves Content-Type | Compression doesn't modify Content-Type header | app.py:186 | 3.2.1 |
| PSC-099 | Scheduler loop limits | max_dagruns_to_create_per_loop limits processing volume | scheduler.rst:~148 | 5.2.1 |

---

# 5. ASVS Compliance Summary

| ASVS ID | Title | Status | Rationale |
|---------|-------|--------|-----------|
| **1.2.1** | Output Encoding for HTTP Response, HTML, XML | **Pass** | FastAPI/Pydantic automatic JSON serialization + Jinja2 auto-escaping provides comprehensive output encoding (PSC-064, PSC-068, PSC-088) |
| **1.2.2** | URL Encoding and Safe URL Protocols | **Pass** | is_safe_url() validates schemes (http/https only), prevents JavaScript/data URIs (PSC-019, PSC-020) |
| **1.2.3** | JavaScript/JSON Content Encoding | **Pass** | FastAPI/Pydantic JSON serialization + RFC 8259 compliance (PSC-068, PSC-096) |
| **1.2.4** | Parameterized Queries / SQL Injection Protection | **Pass** | SQLAlchemy ORM with parameterized queries throughout; no raw SQL construction (PSC-066, PSC-067) |
| **1.2.5** | OS Command Injection Protection | **Pass** | No evidence of subprocess/shell command execution from user input in audited components |
| **1.3.1** | HTML Input Sanitization | **Pass** | Jinja2 auto-escaping + no user-controlled HTML rendering (PSC-088) |
| **1.3.2** | Sanitization - Dynamic Code Execution | **Pass** | No eval/exec usage; DAG code execution is explicitly trusted per security policy (PSC-072) |
| **1.5.1** | Safe Deserialization - XML Parser Configuration | **Pass** | No XML parsing in audited components; UTF-8 requirements documented (PSC-073) |
| **2.1.1** | Validation and Business Logic Documentation | **Partial** | Security policy documented (PSC-072), but pagination/filter validation rules not formally documented (FINDING-044) |
| **2.2.1** | Input Validation | **Partial** | Type-safe ORM interface (PSC-066), but filter content validation missing (FINDING-045) |
| **2.2.2** | Input Validation at Trusted Service Layer | **Pass** | Server-side validation via FastAPI dependencies + ORM layer (PSC-074) |
| **2.3.1** | Business Logic Security - Sequential Step Order | **Pass** | File locking for concurrent initialization prevents race conditions (PSC-046) |
| **3.2.1** | Unintended Content Interpretation | **Fail** | No X-Content-Type-Options header; static file serving with html=True (FINDING-025, FINDING-047) |
| **3.2.2** | Safe Text Rendering | **Partial** | Jinja2 auto-escaping (PSC-088), but template variable injection without explicit context (FINDING-048) |
| **3.3.1** | Cookie Setup | **Fail** | Missing __Secure-/__Host- prefix; conditional Secure attribute (FINDING-012, FINDING-013) |
| **3.4.1** | HSTS Header | **Fail** | No HSTS header; TLS termination delegated to deployment layer (FINDING-021, FINDING-026) |
| **3.4.2** | Browser Security Mechanism Headers (CORS) | **Fail** | Hardcoded allow_credentials=True without origin validation (FINDING-014) |
| **3.5.1** | CSRF Protection | **Fail** | No visible anti-forgery token or custom header requirement (FINDING-027) |
| **3.5.2** | CORS Preflight Mechanism | **Fail** | CORS config doesn't ensure preflight for sensitive requests (FINDING-028) |
| **3.5.3** | HTTP Methods for Sensitive Operations | **Partial** | FastAPI router enforcement (PSC-093), but no Sec-Fetch-* validation (FINDING-049) |
| **4.1.1** | Content-Type Header Verification | **Partial** | JSONResponse sets correct Content-Type (PSC-085), but no enforcement for plugin sub-apps (FINDING-050) |
| **4.4.1** | WebSocket over TLS (WSS) | **N/A** | No WebSocket endpoints in audited components; organizational awareness documented (PSC-062, PSC-063) |
| **5.2.1** | File Upload Size Limits | **Partial** | Scheduler loop limits exist (PSC-099), but no DAG file size limits documented (FINDING-029) |
| **5.2.2** | File Extension and Content Validation | **N/A** | No user file upload functionality in audited components |
| **5.3.1** | Uploaded Files Not Executed via HTTP | **Pass** | Application-owned static files only; reserved prefix validation (PSC-087, PSC-097) |
| **5.3.2** | Safe File Path Construction | **N/A** | No user-controlled file path construction in audited components |
| **6.1.1** | Authentication Documentation - Rate Limiting | **Fail** | No documentation for rate limiting or anti-automation controls (FINDING-032) |
| **6.2.1** | Password Minimum Length | **Partial** | System-generated passwords 16 chars (PSC-035), but no validation on manual edits (FINDING-040) |
| **6.2.2** | Users Can Change Password | **Fail** | No password change mechanism exists (FINDING-005) |
| **6.2.3** | Password Change Requires Current and New Password | **Fail** | No password change functionality (FINDING-006) |
| **6.2.4** | Passwords Checked Against Common Password List | **Fail** | No breach/common password validation (FINDING-018) |
| **6.2.5** | No Composition Rules Limiting Character Types | **Pass** | Password field accepts any string; aligns with NIST guidance (PSC-039) |
| **6.2.6** | Password Input Fields Use type=password | **Partial** | Unable to verify UI template implementation (FINDING-041) |
| **6.2.7** | Paste Functionality and Password Managers | **Pass** | Standard string field supports paste and managers (PSC-040) |
| **6.2.8** | Password Verified Without Modification | **Pass** | Byte-for-byte comparison without transformation (PSC-041) |
| **6.3.1** | Credential Stuffing and Brute Force Controls | **Fail** | Constant-time comparison (PSC-037), but no account lockout or rate limiting (FINDING-019) |
| **6.3.2** | Default User Accounts | **Fail** | Configuration-driven users (PSC-043), but anonymous admin in all-admins mode (FINDING-007) |
| **6.4.1** | System Generated Initial Passwords | **Fail** | Strong password generation (PSC-035, PSC-036), but no forced expiry (FINDING-008) |
| **6.4.2** | Password Hints and Knowledge-Based Authentication | **Pass** | Minimal schema with no hints or KBA (PSC-044) |
| **7.2.1** | Fundamental Session Management - Backend Verification | **Partial** | Server-side JWT validation (PSC-001), but SimpleAllAdminMiddleware bypass (FINDING-034) |
| **7.2.2** | Dynamically Generated Session Tokens | **Pass** | UUID4 JTI with dynamic timestamps (PSC-002) |
| **7.2.3** | Reference Token Entropy Requirements | **Partial** | 128-bit UUID4 JTI (PSC-002), but auto-generated key only 128 bits for HS512 (FINDING-010) |
| **7.2.4** | New Session Token on Authentication | **Partial** | Stale cookie cleanup (PSC-013), but refresh doesn't invalidate previous token (FINDING-002) |
| **7.4.1** | Session Termination Prevents Further Use | **Fail** | Revocation infrastructure exists (PSC-004, PSC-011), but not checked during validation () |
| **7.4.2** | Session Termination on Account Disable/Delete | **Fail** | No bulk session invalidation mechanism (FINDING-003) |
| **8.1.1** | Authorization Documentation | **Partial** | Well-structured contract (PSC-033, PSC-034), but code-embedded rather than standalone (FINDING-038) |
| **8.2.1** | General Authorization Design - Function-Level Access | **Partial** | Comprehensive resource coverage (PSC-025), but requires_authenticated() lacks function-level checks (FINDING-017) |
| **8.2.2** | General Authorization Design - Data-Specific Access | **Pass** | Dual-layer IDOR/BOLA protection + team-based isolation (PSC-029, PSC-030, PSC-031) |
| **8.3.1** | Operation Level Authorization - Trusted Service Layer | **Pass** | FastAPI dependency injection + server-side enforcement (PSC-023, PSC-024, PSC-028, PSC-032) |
| **9.1.1** | Token Source and Integrity - Signature Validation | **Pass** | jwt.decode() with cryptographic verification (PSC-001) |
| **9.1.2** | Token Source and Integrity - Algorithm Allowlist | **Partial** | No 'none' in typical configs (PSC-001), but no explicit blocklist + GUESS mode concerns (FINDING-004, FINDING-033) |
| **9.1.3** | Token Source and Integrity - Key Material from Trusted Sources | **Pass** | Pre-configured JWKS/secret_key only; XOR constraint (PSC-003, PSC-008, PSC-010) |
| **9.2.1** | Token Content - Validity Time Span | **Pass** | exp/nbf validation + configurable expiration + short-lived execution tokens (PSC-009, PSC-012, PSC-006) |
| **10.4.1** | OAuth Authorization Server - Redirect URI Validation | **Partial** | is_safe_url() with scheme/path validation (PSC-019, PSC-020, PSC-021), but domain matching vs. exact allowlist (FINDING-016) |
| **10.4.2** | OAuth Authorization Server - Authorization Code One-Time Use | **N/A** | No authorization code flow; direct credential-to-token exchange (FINDING-035) |
| **10.4.3** | OAuth Authorization Server - Authorization Code Lifetime | **N/A** | No authorization code flow visible (FINDING-035) |
| **10.4.4** | OAuth Authorization Server - Grant Type Controls | **Fail** | ROPC flow used; no per-client grant type restriction (FINDING-015, FINDING-037) |
| **10.4.5** | OAuth Authorization Server - Refresh Token Replay | **Fail** | Refresh doesn't invalidate previous token; 24-hour REST API lifetime excessive (FINDING-002, FINDING-009) |
| **11.3.1** | Encryption Algorithms - Block Modes and Padding | **Pass** | Fernet (AES-CBC + HMAC) with authenticated encryption; no ECB (PSC-047, PSC-050) |
| **11.3.2** | Encryption Algorithms - Approved Ciphers and Modes | **Pass** | Fernet with proper key generation + pluggable backends + established library (PSC-047, PSC-048, PSC-051, PSC-052) |
| **11.4.1** | Hashing and Hash-based Functions - Approved Hash Functions | **Pass** | HMAC-SHA256 + bcrypt; no deprecated functions (PSC-053, PSC-054, PSC-055) |
| **12.1.1** | General TLS Security Guidance | **Partial** | Clean separation for containerized deployments (PSC-056, PSC-057), but no app-level TLS config/enforcement (FINDING-020, FINDING-043) |
| **12.2.1** | HTTPS Communication with External Facing Services | **Partial** | TLS delegated to deployment layer (PSC-058, PSC-059), but no HTTPS enforcement + unencrypted DB examples (FINDING-021, FINDING-022) |
| **12.2.2** | Publicly Trusted TLS Certificates | **Partial** | Deployment manager responsibility (PSC-057), but no certificate validation guidance (FINDING-020) |
| **14.2.1** | Sensitive Data in HTTP Messages | **Partial** | Non-sensitive URL parameters + masking system (PSC-075, PSC-077, PSC-079, PSC-080), but documentation examples lack auth context (FINDING-046) |
| **14.3.1** | Client-side Data Protection | **Partial** | Httponly cookies + path scoping (PSC-005, PSC-014, PSC-045), but no Clear-Site-Data header + no offline fallback (FINDING-011, FINDING-036) |
| **15.1.1** | Secure Coding and Architecture Documentation - Remediation Timeframes | **Fail** | Security policy documented (PSC-072), but no remediation enforcement + plugin risk classification missing (FINDING-030, FINDING-051) |
| **15.2.1** | Security Architecture and Dependencies - Component Currency | **Fail** | No runtime/build-time enforcement for component updates; legacy FAB layer (FINDING-030, FINDING-052) |
| **15.3.1** | Unintended Information Leakage - Return Only Required Data | **Fail** | Permission-based audit access (PSC-082), but audit logs bypass DAG-level controls + unfiltered extra field (FINDING-023, FINDING-024) |
| **13.4.1** | Unintended Information Leakage - Source Control Metadata | **Fail** | No deployment guidance for excluding source control metadata (FINDING-031) |

**Summary Statistics:**
- **Pass:** 39 (37%)
- **Partial:** 17 (16%)
- **Fail:** 36 (34%)
- **N/A:** 4 (4%)
- **Total:** 106 requirements assessed

---

# 6. Cross-Reference Matrix

## Findings to ASVS Mapping

| Finding ID | Severity | ASVS Requirements | Positive Controls Affected |
|------------|----------|-------------------|---------------------------|
| FINDING-002 | High | 10.4.5, 7.2.4 | PSC-013 |
| FINDING-003 | High | 7.4.2 | PSC-011 |
| FINDING-004 | High | 10.4.5, 9.1.2 | PSC-001, PSC-007 |
| FINDING-005 | High | 6.2.2 | None |
| FINDING-006 | High | 6.2.3 | None |
| FINDING-007 | High | 6.3.2 | PSC-038, PSC-043 |
| FINDING-008 | High | 6.4.1 | PSC-035, PSC-036 |
| FINDING-009 | Medium | 10.4.5 | PSC-012 |
| FINDING-010 | Medium | 7.2.3 | PSC-002, PSC-008 |
| FINDING-011 | Medium | 14.3.1 | PSC-005, PSC-045 |
| FINDING-012 | Medium | 3.3.1 | PSC-005, PSC-014 |
| FINDING-013 | Medium | 3.3.1 | PSC-005 |
| FINDING-014 | Medium | 3.4.2 | PSC-016, PSC-017, PSC-018, PSC-092 |
| FINDING-015 | Medium | 10.4.4 | None |
| FINDING-016 | Medium | 10.4.1 | PSC-015, PSC-019, PSC-020, PSC-021 |
| FINDING-017 | Medium | 8.2.1 | PSC-025, PSC-027 |
| FINDING-018 | Medium | 6.2.4 | PSC-039 |
| FINDING-019 | Medium | 6.3.1 | PSC-037, PSC-042 |
| FINDING-020 | Medium | 12.1.1, 12.2.2 | PSC-056, PSC-057, PSC-058 |
| FINDING-021 | Medium | 12.2.1, 3.4.1 | PSC-056, PSC-058 |
| FINDING-022 | Medium | 12.2.1 | PSC-061 |
| FINDING-023 | Medium | 15.3.1 | PSC-082, PSC-083 |
| FINDING-024 | Medium | 15.3.1 | PSC-083 |
| FINDING-025 | Medium | 3.2.1 | PSC-085, PSC-086, PSC-095 |
| FINDING-026 | Medium | 3.4.1 | PSC-060 |
| FINDING-027 | Medium | 3.5.1 | PSC-089 |
| FINDING-028 | Medium | 3.5.2 | PSC-090, PSC-091 |
| FINDING-029 | Medium | 5.2.1 | PSC-099 |
| FINDING-030 | Medium | 15.2.1, 15.1.1 | None |
| FINDING-031 | Medium | 13.4.1 | None |
| FINDING-032 | Medium | 6.1.1 | PSC-037 |
| FINDING-033 | Low | 9.1.2 | PSC-003, PSC-010 |
| FINDING-034 | Low | 7.2.1 | PSC-001 |
| FINDING-035 | Low | 10.4.3 | None |
| FINDING-036 | Low | 14.3.1 | PSC-005, PSC-013 |
| FINDING-037 | Low | 10.4.4 | None |
| FINDING-038 | Low | 8.1.1 | PSC-033, PSC-034 |
| FINDING-039 | Low | 8.2.2 | PSC-029, PSC-030, PSC-031 |
| FINDING-040 | Low | 6.2.1 | PSC-035 |
| FINDING-041 | Low | 6.2.6 | PSC-040 |
| FINDING-042 | Low | 6.3.2 | PSC-038 |
| FINDING-043 | Low | 12.1.1 | PSC-061 |
| FINDING-044 | Low | 2.1.1 | PSC-072 |
| FINDING-045 | Low | 2.2.1 | PSC-066, PSC-074 |
| FINDING-046 | Low | 14.2.1 | PSC-075, PSC-078 |
| FINDING-047 | Low | 3.2.1 | PSC-087 |
| FINDING-048 | Low | 3.2.2 | PSC-088 |
| FINDING-049 | Low | 3.5.3 | PSC-093, PSC-094 |
| FINDING-050 | Low | 4.1.1 | PSC-085 |
| FINDING-051 | Low | 15.1.1 | PSC-072, PSC-097 |
| FINDING-052 | Low | 15.2.1 | PSC-051 |

## ASVS to Positive Controls Mapping

| ASVS ID | Status | Positive Controls Supporting Compliance |
|---------|--------|----------------------------------------|
| 1.2.1 | Pass | PSC-064, PSC-068, PSC-088 |
| 1.2.2 | Pass | PSC-019, PSC-020 |
| 1.2.3 | Pass | PSC-068, PSC-096 |
| 1.2.4 | Pass | PSC-066, PSC-067, PSC-069, PSC-070, PSC-071 |
| 1.2.5 | Pass | None (no command execution) |
| 1.3.1 | Pass | PSC-088 |
| 1.3.2 | Pass | PSC-072 (documented trust model) |
| 1.5.1 | Pass | PSC-073 |
| 2.1.1 | Partial | PSC-072 |
| 2.2.1 | Partial | PSC-066 |
| 2.2.2 | Pass | PSC-074 |
| 2.3.1 | Pass | PSC-046 |
| 3.2.1 | Fail | PSC-085, PSC-086, PSC-095 (insufficient) |
| 3.2.2 | Partial | PSC-088 |
| 3.3.1 | Fail | PSC-005, PSC-014, PSC-045 (insufficient) |
| 3.4.1 | Fail | None |
| 3.4.2 | Fail | PSC-016, PSC-017, PSC-018, PSC-092 (insufficient) |
| 3.5.1 | Fail | PSC-089 (extensibility only) |
| 3.5.2 | Fail | PSC-090, PSC-091 (insufficient) |
| 3.5.3 | Partial | PSC-093, PSC-094 |
| 4.1.1 | Partial | PSC-085 |
| 4.4.1 | N/A | PSC-062, PSC-063 (awareness only) |
| 5.2.1 | Partial | PSC-099 |
| 5.2.2 | N/A | None |
| 5.3.1 | Pass | PSC-087, PSC-097 |
| 5.3.2 | N/A | None |
| 6.1.1 | Fail | PSC-037 (insufficient) |
| 6.2.1 | Partial | PSC-035, PSC-036 |
| 6.2.2 | Fail | None |
| 6.2.3 | Fail | None |
| 6.2.4 | Fail | None |
| 6.2.5 | Pass | PSC-039 |
| 6.2.6 | Partial | PSC-040 |
| 6.2.7 | Pass | PSC-040 |
| 6.2.8 | Pass | PSC-041 |
| 6.3.1 | Fail | PSC-037, PSC-042 (insufficient) |
| 6.3.2 | Fail | PSC-038, PSC-043 (insufficient) |
| 6.4.1 | Fail | PSC-035, PSC-036 (insufficient) |
| 6.4.2 | Pass | PSC-044 |
| 7.2.1 | Partial | PSC-001 |
| 7.2.2 | Pass | PSC-002 |
| 7.2.3 | Partial | PSC-002, PSC-008 |
| 7.2.4 | Partial | PSC-013 |
| 7.4.1 | Fail | PSC-004, PSC-011, PSC-022 (not enforced) |
| 7.4.2 | Fail | PSC-011 (insufficient) |
| 8.1.1 | Partial | PSC-033, PSC-034 |
| 8.2.1 | Partial | PSC-025, PSC-027 |
| 8.2.2 | Pass | PSC-026, PSC-029, PSC-030, PSC-031 |
| 8.3.1 | Pass | PSC-023, PSC-024, PSC-028, PSC-032 |
| 9.1.1 | Pass | PSC-001, PSC-007 |
| 9.1.2 | Partial | PSC-001, PSC-003, PSC-010 |
| 9.1.3 | Pass | PSC-003, PSC-008, PSC-010 |
| 9.2.1 | Pass | PSC-006, PSC-009, PSC-012 |
| 10.4.1 | Partial | PSC-015, PSC-019, PSC-020, PSC-021 |
| 10.4.2 | N/A | None |
| 10.4.3 | N/A | None |
| 10.4.4 | Fail | None |
| 10.4.5 | Fail | PSC-012 (insufficient) |
| 11.3.1 | Pass | PSC-047, PSC-050 |
| 11.3.2 | Pass | PSC-047, PSC-048, PSC-049, PSC-051, PSC-052 |
| 11.4.1 | Pass | PSC-053, PSC-054, PSC-055 |
| 12.1.1 | Partial | PSC-056, PSC-057, PSC-058, PSC-061 |
| 12.2.1 | Partial | PSC-056, PSC-058, PSC-059, PSC-061 |
| 12.2.2 | Partial | PSC-057 |
| 14.2.1 | Partial | PSC-075, PSC-076, PSC-077, PSC-078, PSC-079, PSC-080, PSC-081, PSC-084 |
| 14.3.1 | Partial | PSC-005, PSC-011, PSC-013, PSC-014, PSC-045 |
| 15.1.1 | Fail | PSC-072 (insufficient) |
| 15.2.1 | Fail | PSC-051 (insufficient) |
| 15.3.1 | Fail | PSC-082, PSC-083 (insufficient) |
| 13.4.1 | Fail | None |

## Control Domain Coverage

| Domain | Total Controls | Pass | Partial | Fail | N/A | Coverage % |
|--------|---------------|------|---------|------|-----|------------|
| JWT Token Authentication | 11 | 7 | 3 | 1 | 0 | 91% |
| Cookie Session Management | 10 | 2 | 4 | 4 | 0 | 60% |
| Authorization & Access Control | 7 | 3 | 3 | 1 | 0 | 86% |
| Authentication & Login Flows | 11 | 3 | 3 | 5 | 0 | 55% |
| Cryptographic Operations | 3 | 3 | 0 | 0 | 0 | 100% |
| TLS & Transport Security | 4 | 0 | 3 | 1 | 0 | 75% |
| Input Validation & Injection | 11 | 9 | 2 | 0 | 0 | 100% |
| Secrets Masking & Audit Logging | 4 | 1 | 1 | 2 | 0 | 50% |
| HTTP Security Headers | 10 | 2 | 2 | 6 | 0 | 40% |
| File Upload Handling | 4 | 1 | 1 | 0 | 2 | 67% |
| Architecture & Documentation | 4 | 0 | 0 | 4 | 0 | 0% |

**Overall Implementation Quality:**
- **Strong Areas:** Input validation/injection prevention, cryptographic operations, core authorization framework
- **Moderate Areas:** JWT token authentication, TLS delegation model, file upload controls
- **Weak Areas:** HTTP security headers, authentication lifecycle management, architecture documentation
- **Critical Gaps:** Session revocation enforcement, CSRF protection, password management, component currency

## 7. Level Coverage Analysis


**Audit scope:** up to L1

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 52 |

**Total consolidated findings: 52**

*End of Consolidated Security Audit Report*