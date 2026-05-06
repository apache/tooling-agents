# Security Audit Consolidated Report

## Report Metadata

| Field | Value |
|-------|-------|
| **Repository** | `apache/tooling-runbooks` |
| **ASVS Level** | L1 |
| **Severity Threshold** | High and above |
| **Commit** | N/A |
| **Date** | May 06, 2026 |
| **Auditor** | Tooling Agents |
| **Source Reports** | 70 |
| **Total Findings** | 16 |

## Executive Summary

### Severity Distribution

| Severity | Count | Percentage |
|----------|-------|------------|
| Critical | 0 | 0.0% |
| High | 16 | 100.0% |
| Medium | 0 | 0.0% |
| Low | 0 | 0.0% |
| Info | 0 | 0.0% |

All 16 findings fall at **High** severity. No critical-severity issues were identified, but the concentration of high-severity findings across authentication, authorization, session management, and web security domains indicates systemic gaps in baseline security controls at the L1 verification level.

### Level Coverage

This audit assessed controls exclusively against **ASVS Level 1 (L1)** — the minimum assurance level representing protection against easily exploitable vulnerabilities. One finding (FINDING-012) is additionally applicable at L2. The scope encompassed 20 directories spanning authentication, authorization, session management, cryptographic implementation, web UI security, dependency management, and deployment hardening.

### Top 5 Risks

| # | Finding | Risk Summary |
|---|---------|--------------|
| 1 | **FINDING-008** | Authorization bypass via JSON parsing failure on POST requests in multi-team mode allows unauthenticated actions against protected resources. |
| 2 | **FINDING-005** | Token revocation is implemented but never enforced during validation, meaning revoked tokens remain usable until natural expiration — nullifying any emergency token invalidation. |
| 3 | **FINDING-003** | System-generated passwords use Python's non-cryptographic `random.choices()` PRNG, making generated credentials predictable to an attacker who can determine or influence PRNG state. |
| 4 | **FINDING-009** | Missing `/auth` prefix in `RESERVED_URL_PREFIXES` allows plugins to register routes that shadow authentication endpoints, potentially intercepting credentials. |
| 5 | **FINDING-013** | CORS configuration unconditionally allows credentials without origin validation, enabling cross-origin credential theft from any attacker-controlled domain. |

### Positive Controls

The audit identified significant defensive strength in the **JWT token authentication** domain, which demonstrates mature, defense-in-depth implementation:

- **Robust signature validation**: All token claims are accessible only after successful cryptographic verification via `jwt.decode()` with explicit algorithm allowlists (HS512, RS256, EdDSA only). The `"none"` algorithm is never produced or accepted.
- **Key confusion prevention**: Symmetric and asymmetric key modes are mutually exclusive at construction time (`__attrs_post_init__` enforcement), eliminating algorithm-substitution attacks.
- **Server-controlled key resolution**: Key material is sourced exclusively from deployment-time configuration (config secrets, file paths, or trusted JWKS URLs). Token headers (`jku`, `x5u`, `jwk`) are never honored for key discovery; `kid` serves only as an index into pre-loaded trusted keys.
- **Comprehensive time-claim enforcement**: `exp`, `iat`, and `nbf` are required claims with configurable clock-skew leeway (default 10s). System-generated time claims override caller-provided extras via merge-order precedence.
- **Credential enumeration resistance**: The authentication system returns generic "Invalid credentials" errors without distinguishing between invalid usernames and invalid passwords, and validates consistently across all token-issuance endpoints.
- **JWKS transport security**: External JWKS fetches occur over TLS with default certificate verification enabled.

These controls demonstrate that the token validation pipeline itself is well-hardened. However, the surrounding infrastructure (rate limiting, session invalidation, revocation enforcement) does not yet match this level of maturity — a gap reflected in the findings above.

---

## 3. Findings

### 3.2 High

#### FINDING-001: Authentication documentation completely lacks rate limiting, anti-automation, and account lockout guidance

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 6.1.1 |
| **Files** | airflow-core/docs/core-concepts/auth-manager/index.rst (entire document), airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py (41-68), airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py (36-75) |
| **Source Reports** | 6.1.1.md |
| **Related Findings** | N/A |

**Description:**

The authentication documentation (index.rst) covers auth manager architecture, user representation, authorization methods, JWT token management, and custom auth manager development but contains zero references to: rate limiting for login endpoints, anti-automation controls (CAPTCHA, challenge-response), adaptive response mechanisms (progressive delays, temporary lockout), account lockout prevention (distinguishing legitimate users from attackers), or monitoring/alerting for brute force patterns. Meanwhile, the login endpoint has no protection implemented. Data Flow: Attacker → POST /auth/token → SimpleAuthManagerLogin.create_token() → unlimited password attempts → no rate limiting or lockout. The domain context confirms this is a known architectural gap: 'Rate limiting for login attempts must be configured at the deployment level as it's not enforced by the simple auth manager by default' but the documentation never communicates this to operators.

**Remediation:**

1. Add a dedicated security section to the auth manager documentation covering: Rate Limiting and Brute Force Protection (deploy reverse proxy with rate limiting on POST /auth/token endpoint, configure max 5 failed login attempts per IP per minute, implement progressive delays, consider IP-based temporary blocking after 10 failed attempts); Account Lockout Prevention (rate limit by IP address not username alone, use CAPTCHA challenges after N failed attempts, implement monitoring/alerting on authentication failure spikes, consider temporary lockout rather than permanent lockout); Custom auth managers implementing local password authentication should implement max_failed_attempts configuration, lockout_duration configuration, and failed attempt tracking per user and per IP. 2. Add a get_rate_limit_config() method to the BaseAuthManager interface that returns rate limiting configuration for authentication endpoints with recommended values for max_attempts_per_minute, lockout_threshold, and lockout_duration_seconds.

---

#### FINDING-002: No rate limiting or brute force protection on authentication endpoints

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 6.3.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py (36-70), airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py (42-67), airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py (96-107) |
| **Source Reports** | 6.3.1.md |
| **Related Findings** | N/A |

**Description:**

An attacker can perform unlimited authentication attempts against the login endpoints without any application-level protection. The authentication endpoints in the Simple Auth Manager have no rate limiting, account lockout, progressive delays, or CAPTCHA mechanisms. The HTTP POST endpoints /auth/token and /auth/token/cli allow unlimited brute force attempts with no throttling. Given that the Simple Auth Manager generates 16-character alphanumeric passwords, a targeted attack on known usernames could succeed if passwords are weak or if the attacker can enumerate through the limited character space at high speed.

**Remediation:**

Option 1: Add rate limiting middleware to the login router using a library like slowapi with a limit of 5 attempts per minute per IP address. Option 2: Add progressive delay after failed attempts in the service by tracking failed attempts per username with a 5-minute window and raising HTTP 429 after 5 failures. Long-term: Define rate limiting interface in BaseAuthManager to provide a configurable rate limiting hook that all auth managers can leverage, enforced by framework middleware.

---

#### FINDING-003: System-generated passwords use non-cryptographic PRNG (random.choices)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-338 |
| **ASVS Section(s)** | 6.4.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py (297) |
| **Source Reports** | 6.4.1.md |
| **Related Findings** | N/A |

**Description:**

The _generate_password() method in SimpleAuthManager uses Python's random.choices() which relies on the Mersenne Twister PRNG. This is deterministic and predictable. If an attacker can observe any outputs from the same random instance or determine the internal state (624 consecutive 32-bit outputs), they can predict future passwords. While the character space is reasonable (50^16 ≈ 2^90 combinations), the non-cryptographic nature of the PRNG means the actual entropy may be significantly lower than the theoretical maximum, especially if the process state can be inferred.

**Remediation:**

Replace random.choices() with secrets.choice() from Python's secrets module. Updated code:

```python
import secrets

@staticmethod
def _generate_password() -> str:
    alphabet = "abcdefghkmnpqrstuvwxyzABCDEFGHKMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(16))
```

---

#### FINDING-004: System-generated initial passwords never expire and become permanent credentials

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-620 |
| **ASVS Section(s)** | 6.4.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py (128-148) |
| **Source Reports** | 6.4.1.md |
| **Related Findings** | N/A |

**Description:**

Generated initial passwords are stored as plain key-value pairs in a JSON file with no associated creation timestamp or expiry. There is no mechanism to detect whether a password has been used or to force a change after initial use. The Simple Auth Manager provides no endpoint or CLI command for users to change their generated passwords. Once written to the JSON file, passwords remain valid indefinitely until the file is manually deleted or the server is reconfigured. If a password is disclosed (e.g., from logs, console output, or file access), it remains valid indefinitely with no mechanism for rotation or forced change.

**Remediation:**

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

---

#### FINDING-005: Token revocation mechanism exists but is not enforced during token validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 7.4.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/tokens.py (260-290), airflow-core/src/airflow/api_fastapi/auth/tokens.py (295-305) |
| **Source Reports** | 7.4.1.md |
| **Related Findings** | N/A |

**Description:**

The application has a token revocation write mechanism (revoke_token() that writes to RevokedToken table) but the validation method (avalidated_claims()) never checks the revocation list. After logout, tokens remain usable until natural expiration. Data Flow: Logout/termination → revoke_token() writes jti to RevokedToken table → subsequent request with same token → avalidated_claims() validates signature/expiration but NEVER queries RevokedToken table → token accepted as valid. This is a Type B control gap where the control EXISTS but is NOT CHECKED during validation.

**Remediation:**

Add revocation check to avalidated_claims() method:

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

Additional recommendations: 1. Implement per-user token invalidation timestamp (tokens_invalid_before column) for immediate session termination 2. Ensure account disable/delete workflow updates per-user invalidation timestamp 3. Consider token introspection cache (Redis-backed) for strict revocation without sacrificing scalability 4. Document security implications of token lifetime configuration 5. Consider adding user account status verification as optional check in avalidated_claims

---

#### FINDING-006: No mechanism to invalidate all active sessions when a user account is disabled or deleted

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 7.4.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/tokens.py (JWTValidator class and JWTGenerator class) |
| **Source Reports** | 7.4.2.md |
| **Related Findings** | N/A |

**Description:**

Admin disables/deletes user account → NO mechanism to identify or invalidate all outstanding JWTs for that user → previously issued tokens remain valid until natural expiration → disabled user retains access. When an employee leaves the company or an account is compromised and disabled, all existing sessions for that user remain active until token expiration. This violates the principle that account termination should immediately prevent all access. With default token lifetimes, this creates a window where a disabled account retains full access. The system has no record of which jti values belong to which user (tokens are stateless), revoke_token requires the actual token string (admin doesn't have all user's tokens), and token validation (avalidated_claims) doesn't check user account status.

**Remediation:**

Option 1: Add per-user invalidation timestamp. Create a UserTokenInvalidation model with user_id and tokens_invalid_before timestamp. In JWTValidator.avalidated_claims, check the per-user invalidation timestamp and reject tokens with iat before the invalidation timestamp. Option 2: In account disable/delete handler, set the per-user invalidation timestamp to datetime.now() so all tokens issued before this timestamp will be rejected. Alternatively, implement token introspection cache (e.g., Redis-backed) for deployments requiring strict revocation, add user account status verification within avalidated_claims, or implement per-user signing key rotation.

---

#### FINDING-007: Authorization documentation lacks specification of default-deny behavior and handling of undefined/wildcard resource identifiers

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 8.1.1 |
| **Files** | airflow-core/docs/core-concepts/auth-manager/index.rst (95-117), base_auth_manager.py (179-191), security.py (136) |
| **Source Reports** | 8.1.1.md |
| **Related Findings** | N/A |

**Description:**

The authorization documentation defines the interface for function-level and data-specific access control but fails to specify: 1) What `is_authorized_*` methods MUST return when `details` is `None` (i.e., no specific resource identified) — should implementations default to deny? 2) Whether a deny-by-default policy is required for all custom auth manager implementations 3) How authorization methods should behave when resource identifiers cannot be resolved (e.g., non-existent DAG ID) 4) The security contract between the base framework (which passes `details=None` for wildcard/list operations in `requires_access_dag`) and the auth manager implementation. Auth manager implementors may create overly permissive implementations due to ambiguous documentation, leading to unauthorized function-level and data-level access across the deployment.

**Remediation:**

Add explicit security contracts to the documentation:

```
Security Requirements for Authorization Methods
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

All ``is_authorized_*`` methods MUST follow these rules:

* **Default Deny**: If the ``details`` parameter is ``None`` or any identifying field within details is ``None``, implementations MUST return ``False`` for mutating operations (``POST``, ``PUT``, ``DELETE``). For ``GET`` operations, returning ``True`` with ``details=None`` is acceptable only when paired with result filtering (e.g., ``filter_authorized_dag_ids``).
* **Unknown Resources**: If a resource identifier does not exist in the backing store, the method MUST return ``False``.
* **Deny by Default**: Unless a user has been explicitly granted permission, access MUST be denied.
```

---

#### FINDING-008: Authorization check silently skipped for POST requests in multi-team mode when request body JSON parsing fails

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 8.2.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/security.py (647-666), airflow-core/src/airflow/api_fastapi/core_api/security.py (328-342), airflow-core/src/airflow/api_fastapi/core_api/security.py (395-412), airflow-core/src/airflow/api_fastapi/core_api/security.py (541-554) |
| **Source Reports** | 8.2.1.md |
| **Related Findings** | N/A |

**Description:**

In multi-team mode, when a POST request is made to pool/connection/variable endpoints and the request body contains invalid JSON, the `_collect_teams_to_check` function suppresses the JSONDecodeError and returns an empty set. This causes the authorization loop to never execute, allowing any authenticated user to bypass function-level access controls. The data flow is: (1) Multi-team mode enabled, (2) POST request arrives, (3) `_collect_teams_to_check` is called, (4) JSON parsing fails and exception is suppressed, (5) empty set {} is returned, (6) authorization loop body never executes, (7) dependency resolves without checking permissions. This is a Type B gap where the control EXISTS (`is_authorized_pool`) but is NOT CALLED when the teams set is empty.

**Remediation:**

Modify `_collect_teams_to_check` to handle JSONDecodeError by defaulting to None team instead of suppressing the error entirely. Add a fallback to ensure the teams set always contains at least one entry (None) so authorization checks always run. Replace `with suppress(JSONDecodeError):` with a try-except block that sets `raw = None` on exception, and add `if not teams: teams.add(None)` before the return statement to guarantee at least one authorization check executes.

---

#### FINDING-009: Missing /auth prefix in RESERVED_URL_PREFIXES allows plugin route shadowing

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 1.2.1, 1.2.2, 2.2.1 |
| **Files** | core_api/app.py (56), airflow-core/src/airflow/api_fastapi/app.py (56), core_api/app.py (160-182), airflow-core/src/airflow/api_fastapi/app.py (160-182), airflow-core/src/airflow/api_fastapi/app.py (57), airflow-core/src/airflow/api_fastapi/app.py (49), airflow-core/src/airflow/api_fastapi/app.py (185-187), airflow-core/src/airflow/api_fastapi/app.py (99-101), airflow-core/src/airflow/api_fastapi/app.py (172-211) |
| **Source Reports** | 1.2.1.md, 1.2.2.md, 2.2.1.md |
| **Related Findings** | N/A |

**Description:**

The RESERVED_URL_PREFIXES list in app.py does not include /auth or /pluginsv2, creating a gap where plugins could register routes that shadow authentication endpoints. The initialization order (init_plugins before init_auth_manager) creates a window where plugin routes at /auth could be registered before the auth manager mounts its routes. Since Starlette matches routes in registration order, a malicious plugin installed via pip can mount at url_prefix="/auth" and intercept authentication requests, enabling credential theft or forged token issuance, effectively bypassing the legitimate authentication system. While AUTH_MANAGER_FASTAPI_APP_PREFIX exists as a constant, it is not used for validation against plugin prefixes. Data flow: Plugin url_prefix value → RESERVED_URL_PREFIXES validation (missing /auth) → app.mount(url_prefix, subapp) → shadows auth manager routes. Gap Type: Control EXISTS (RESERVED_URL_PREFIXES validation) but NOT APPLIED to the /auth path.

**Remediation:**

Immediate: Add /auth and /pluginsv2 to the RESERVED_URL_PREFIXES list. Update line 56 of app.py to: RESERVED_URL_PREFIXES = ["/api/v2", "/ui", "/execution", "/auth", "/pluginsv2"]. Alternatively, derive reserved prefixes dynamically from actual mount points: RESERVED_URL_PREFIXES = ["/api/v2", "/ui", "/execution", AUTH_MANAGER_FASTAPI_APP_PREFIX.removeprefix(API_ROOT_PATH.rstrip("/"))]. Short-term: Consider mounting the auth manager BEFORE plugins in create_app() so that even if the prefix check is bypassed, the auth routes take precedence. Add a post-mount verification step that confirms no plugin routes shadow critical system paths (/auth, /api/v2, /execution). Long-term: Implement a plugin capability/permission system that restricts what middleware and route prefixes plugins can register, with explicit approval for security-sensitive operations. Additionally, add an integration test that verifies plugins cannot mount at any prefix used by core components, including /auth.

---

#### FINDING-010: No Security Headers Middleware for Content Interpretation Prevention

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 3.2.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py (158-173) |
| **Source Reports** | 3.2.1.md |
| **Related Findings** | N/A |

**Description:**

The middleware stack is fully defined in init_middlewares and init_config, yet no security headers middleware is registered to prevent content type sniffing or enforce CSP. Without X-Content-Type-Options: nosniff, browsers may interpret API responses (JSON) or user-uploaded files as HTML, enabling XSS. Without CSP, injected content can execute scripts. Without Sec-Fetch-* validation, API endpoints can be navigated to directly in a browser context, rendering JSON or other content as HTML.

**Remediation:**

Add SecurityHeadersMiddleware to the middleware stack:

```python
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
        response.headers["X-Frame-Options"] = "DENY"
        return response

def init_middlewares(app: FastAPI) -> None:
    # ... existing middleware ...
    app.add_middleware(SecurityHeadersMiddleware)
```

---

#### FINDING-011: Cookie Path Utility Lacks Secure Attribute and Name Prefix Enforcement

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 3.3.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/app.py (49-55) |
| **Source Reports** | 3.3.1.md |
| **Related Findings** | N/A |

**Description:**

The application uses cookies for authentication (confirmed by get_cookie_path() utility and JWTRefreshMiddleware), but lacks centralized enforcement of the Secure attribute or __Host-/__Secure- prefixes. Without the Secure attribute, cookies may be transmitted over unencrypted HTTP connections, enabling session hijacking via network sniffing. Without __Host- or __Secure- prefix, cookies may be set by subdomain attackers or over insecure connections. The architecture provides path scoping but omits security attribute enforcement.

**Remediation:**

Create a centralized cookie creation utility that enforces required security attributes. Implement a create_secure_cookie() function that: (1) Uses __Host- prefix when path is '/' or __Secure- prefix otherwise, (2) Always sets secure=True, (3) Sets httponly=True, (4) Sets samesite='lax'. Update JWTRefreshMiddleware and auth managers to use this utility instead of setting cookies directly.

---

#### FINDING-012: No Strict-Transport-Security Header Configured in Application Middleware

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1, L2 |
| **CWE** | N/A |
| **ASVS Section(s)** | 3.4.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py (158-173), airflow-core/src/airflow/api_fastapi/core_api/app.py (134-148) |
| **Source Reports** | 3.4.1.md |
| **Related Findings** | N/A |

**Description:**

The application middleware stack does not include any middleware to add the Strict-Transport-Security header to HTTP responses. Both the init_middlewares and init_config functions, which represent the complete server-side security header configuration, lack HSTS implementation. Without HSTS, the application is vulnerable to SSL stripping attacks (MITM downgrades HTTPS to HTTP), users accessing the application over HTTP if they type the URL without https://, cookie theft during the initial HTTP request before redirect to HTTPS, and protocol downgrade on first visit. ASVS 3.4.1 requires a minimum max-age of 1 year (31536000 seconds) and for L2+, the policy must apply to all subdomains.

**Remediation:**

Create and add an HSTSMiddleware to the middleware stack that sets the Strict-Transport-Security header with max-age=31536000 (1 year) and includeSubDomains directive. Example implementation:

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

---

#### FINDING-013: CORS Configuration Unconditionally Allows Credentials Without Origin Validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-942 |
| **ASVS Section(s)** | 3.4.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py (134-148) |
| **Source Reports** | 3.4.2.md |
| **Related Findings** | N/A |

**Description:**

When `allow_origins` is configured as `["*"]` (or contains `"*"`), Starlette's CORSMiddleware with `allow_credentials=True` will reflect any requesting origin in the `Access-Control-Allow-Origin` header while also setting `Access-Control-Allow-Credentials: true`. This allows any malicious website to: make authenticated API requests on behalf of the user, read sensitive response data (DAG configurations, connection details, variables), and perform state-changing operations (trigger DAGs, modify configurations). Configuration `[api] access_control_allow_origins` potentially allows `["*"]` which is passed to `CORSMiddleware(allow_origins=["*"], allow_credentials=True)`, causing Starlette to reflect any `Origin` header in `Access-Control-Allow-Origin` response, allowing any origin to make credentialed requests.

**Remediation:**

Validate that wildcard origin '*' is not combined with credentials. Add runtime validation in the `init_config` function: check if "*" is present in `allow_origins` and if so, log a warning and set `allow_credentials=False`. Example: `if "*" in (allow_origins or []): log.warning("CORS wildcard origin '*' detected. Disabling allow_credentials to prevent credential leakage to arbitrary origins."); allow_credentials = False`

---

#### FINDING-014: No Explicit CSRF Protection Middleware in Base Application Framework

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-352 |
| **ASVS Section(s)** | 3.5.1, 3.5.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py (158-173), airflow-core/src/airflow/api_fastapi/app.py (79-110) |
| **Source Reports** | 3.5.1.md, 3.5.2.md |
| **Related Findings** | N/A |

**Description:**

The application uses cookie-based authentication with allow_credentials=True in CORS configuration, but does not enforce mechanisms to ensure all state-changing requests trigger CORS preflight. The CORSMiddleware is purely reactive and does not block 'simple' requests. A simple cross-origin request (e.g., POST with Content-Type: application/x-www-form-urlencoded) will bypass CORS preflight entirely, include session cookies automatically, be authenticated by the server, and execute state-changing operations. No additional defense layer is visible: no CSRF token middleware, no mandatory custom header that would force preflight, no Origin or Sec-Fetch-* header validation middleware, and no Content-Type enforcement at middleware level. The auth manager at /auth is particularly vulnerable as authentication endpoints commonly accept form-encoded POST bodies which are simple requests.

**Remediation:**

Add middleware that validates request origin for state-changing operations. Option 1: Require a custom header (e.g., X-Requested-With) that forces preflight by implementing CSRFPreflightMiddleware that checks for the custom header on non-safe methods and validates Sec-Fetch-Site header as defense-in-depth. Option 2: Validate Origin header by implementing OriginValidationMiddleware that checks Origin header against allowed_origins for non-safe methods. Also ensure SameSite=Lax (minimum) or SameSite=Strict is set on all authentication cookies. Implement Sec-Fetch-* header validation middleware as defense-in-depth, rejecting requests with Sec-Fetch-Site: cross-site to state-changing endpoints.

---

#### FINDING-015: Documentation explicitly disclaims risk-based remediation timeframes for third-party dependency vulnerabilities

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 15.1.1 |
| **Files** | airflow-core/docs/security/vulnerabilities-in-3rd-party-dependencies.rst (28-35) |
| **Source Reports** | 15.1.1.md |
| **Related Findings** | N/A |

**Description:**

ASVS 15.1.1 requires that application documentation defines risk-based remediation timeframes (e.g., Critical: 48 hours, High: 7 days, Medium: 30 days, Low: 90 days) for addressing vulnerabilities in third-party components. The provided documentation explicitly contradicts this requirement: (1) releasing_security_patches.rst describes the mechanism of releasing patches (SemVer PATCHLEVEL releases) but defines no timeframes based on vulnerability severity. (2) vulnerabilities-in-3rd-party-dependencies.rst explicitly states 'we do not provide any guarantees that we will upgrade to dependencies that are CVE-free' — directly contradicting the requirement for defined remediation timeframes. (3) sbom.rst documents dependency inventory capabilities but contains no remediation timeframe policy. What is missing: A documented policy defining specific timeframes such as: Critical severity CVE (CVSS ≥ 9.0): remediate within X days; High severity CVE (CVSS 7.0-8.9): remediate within Y days; Medium severity CVE (CVSS 4.0-6.9): remediate within Z days; Low severity CVE (CVSS < 4.0): remediate within W days; General library update cadence for non-vulnerable updates. Without defined remediation timeframes, there is no measurable standard against which to hold dependency updates accountable. Deployments may unknowingly run with exploitable vulnerabilities indefinitely. Operators have no SLA-based expectation for when patches will be available, making risk management decisions impossible.

**Remediation:**

Create a dedicated security policy document defining risk-based remediation timeframes. Example addition to documentation:

```
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

---

#### FINDING-016: Documentation explicitly acknowledges retention of known-vulnerable components without defined compliance criteria

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 15.2.1 |
| **Files** | airflow-core/docs/security/vulnerabilities-in-3rd-party-dependencies.rst (30-35), airflow-core/docs/security/vulnerabilities-in-3rd-party-dependencies.rst (43-44), airflow-core/docs/security/vulnerabilities-in-3rd-party-dependencies.rst (44-45), airflow-core/docs/security/releasing_security_patches.rst |
| **Source Reports** | 15.2.1.md |
| **Related Findings** | N/A |

**Description:**

ASVS 15.2.1 requires verification that all application components are within their documented update and remediation timeframes. This requirement depends on 15.1.1 being satisfied (having defined timeframes). The documentation reveals a dual failure: 1) No timeframes are defined (15.1.1 gap), making compliance impossible to measure. 2) The documentation explicitly acknowledges that vulnerable components are retained in released versions, with the explanation being resource constraints rather than risk-based decisions. Additionally, when a new MINOR version is released, PATCHLEVEL releases stop for the previous MINOR version, meaning users on older MINOR versions receive NO security updates regardless of vulnerability severity. Constraint files are explicitly stated as NOT being updated post-release, container images are not republished with updated dependencies, and the project places the burden on users to track and update vulnerable dependencies themselves.

**Remediation:**

1. Define remediation timeframes (addresses prerequisite 15.1.1). 2. Implement automated compliance verification in the CI/CD pipeline using tools like Anchore scan-action to scan dependencies for CVEs and check remediation timeframe compliance against defined policies. 3. Document exceptions explicitly when components cannot be updated within timeframes, including compensating controls with a structured table showing Component, CVE, Exception Reason, Compensating Control, and Review Date. 4. Automate post-release constraint file updates for critical/high severity CVE fixes. 5. Implement periodic container image rebuilds for supported releases incorporating dependency security updates. 6. Create a dependency risk classification system with enhanced monitoring and faster remediation requirements.

---

---

# 4. Positive Security Controls

| Control ID | Control Description | Evidence | Files | Domain |
|------------|-------------------|----------|-------|---------|
| PSC-001 | Signature validation via jwt.decode() | All claims returned only after successful signature verification | tokens.py:228-240 | jwt_token_authentication |
| PSC-002 | Symmetric key validation | Applied when secret_key configured | tokens.py:204-205 | jwt_token_authentication |
| PSC-003 | Asymmetric key validation via JWKS | Applied when JWKS configured | tokens.py:210 | jwt_token_authentication |
| PSC-004 | Key mutual exclusivity | Enforced - exactly one of jwks or secret_key | tokens.py:192-193 | jwt_token_authentication |
| PSC-005 | Token refresh validates first | Applied before generating new token | refresh_token.py:82 | jwt_token_authentication |
| PSC-006 | Invalid token produces no user | Catches HTTPException from invalid tokens, clears cookie | refresh_token.py:56-58 | jwt_token_authentication |
| PSC-007 | Validation before use | jwt.decode() called with explicit key material before claim extraction | N/A | jwt_token_authentication |
| PSC-008 | Key resolution is server-controlled | _get_validation_key() returns keys from pre-configured sources only | N/A | jwt_token_authentication |
| PSC-009 | Middleware validates before refreshing | JWTRefreshMiddleware calls resolve_user_from_token() before refresh | N/A | jwt_token_authentication |
| PSC-010 | Revocation validates first | revoke_token() calls validated_claims() before extracting jti | N/A | jwt_token_authentication |
| PSC-011 | algorithms parameter explicit list | Always passed as explicit list to jwt.decode() | tokens.py:237 | jwt_token_authentication |
| PSC-012 | Symmetric defaults to ["HS512"] only | Algorithm locked to HS512 when no JWKS | tokens.py:195 | jwt_token_authentication |
| PSC-013 | Asymmetric algorithm from trusted JWK | Algorithm from pre-configured JWKS key, not token header | tokens.py:226-229 | jwt_token_authentication |
| PSC-014 | Missing JWK algorithm rejected | Raises InvalidTokenError for missing algorithm in JWK | tokens.py:227 | jwt_token_authentication |
| PSC-015 | Generator uses single algorithm | Only one algorithm used for signing | tokens.py:320-324 | jwt_token_authentication |
| PSC-016 | Algorithm auto-detection from key type | Only RS256 or EdDSA are valid outcomes | tokens.py:99-106 | jwt_token_authentication |
| PSC-017 | No "None" algorithm path | Default resolution produces only HS512, RS256, or EdDSA | N/A | jwt_token_authentication |
| PSC-018 | Key confusion prevention by design | __attrs_post_init__() enforces symmetric XOR asymmetric | N/A | jwt_token_authentication |
| PSC-019 | Algorithm from trusted source only | Algorithm from PyJWK object in trusted JWKS, not token header | N/A | jwt_token_authentication |
| PSC-020 | Restricted algorithm set | _guess_best_algorithm() returns only RS256 or EdDSA | N/A | jwt_token_authentication |
| PSC-021 | Key from config secret | Read from [api_auth] jwt_secret config section | tokens.py:416-437 | jwt_token_authentication |
| PSC-022 | Key from config file path | Path from [api_auth] jwt_private_key_path config | tokens.py:269-276 | jwt_token_authentication |
| PSC-023 | JWKS from config URL | URL from [api_auth] trusted_jwks_url config | tokens.py:456-458 | jwt_token_authentication |
| PSC-024 | kid used as lookup index only | Token's kid header only indexes into pre-loaded JWKS | tokens.py:196-199, 142-147 | jwt_token_authentication |
| PSC-025 | No jku/x5u/jwk header processing | Only kid extracted from header; others ignored | tokens.py:196-199 | jwt_token_authentication |
| PSC-026 | JWKS fetch via verified TLS | Default httpx client verifies TLS certificates | tokens.py:72 | jwt_token_authentication |
| PSC-027 | Key ID not found results in rejection | KeyError raised if kid doesn't match trusted key | tokens.py:147 | jwt_token_authentication |
| PSC-028 | No header-based key resolution | Only kid read from unvalidated header for JWKS lookup | N/A | jwt_token_authentication |
| PSC-029 | Key sources are deployment-time decisions | All key material paths from application startup config | N/A | jwt_token_authentication |
| PSC-030 | JWKS.from_private_key() | Keyset derived from locally configured private key | N/A | jwt_token_authentication |
| PSC-031 | Strong mutual exclusivity enforcement | Symmetric/asymmetric modes mutually exclusive at construction | N/A | jwt_token_authentication |
| PSC-032 | Separation of concerns REST vs Execution | Different audience claims provide cross-context replay protection | N/A | jwt_token_authentication |
| PSC-033 | Defense-in-depth through PyJWT | PyJWT rejects none algorithm, validates time claims, enforces audience | N/A | jwt_token_authentication |
| PSC-034 | Required claims: exp, iat, nbf | Default required_claims enforced | tokens.py:187 | jwt_token_authentication |
| PSC-035 | PyJWT require option | Passed to jwt.decode() | tokens.py:236 | jwt_token_authentication |
| PSC-036 | PyJWT validates exp (expiration) | Via jwt.decode() | tokens.py:228-240 | jwt_token_authentication |
| PSC-037 | PyJWT validates nbf (not-before) | Via jwt.decode() | tokens.py:228-240 | jwt_token_authentication |
| PSC-038 | Clock skew leeway | Configurable leeway (default 10s) applied to time claims | tokens.py:186, 239 | jwt_token_authentication |
| PSC-039 | Token generation includes all time claims | iat, nbf, exp always set in generated tokens | tokens.py:342-346 | jwt_token_authentication |
| PSC-040 | Expiration calculated correctly | Proper expiration calculation | tokens.py:345 | jwt_token_authentication |
| PSC-041 | Time claims required by default | required_claims includes exp, iat, nbf | tokens.py:187 | jwt_token_authentication |
| PSC-042 | Time claims cannot be overridden | System-generated claims take precedence over extras | tokens.py:342 | jwt_token_authentication |
| PSC-043 | Short-lived execution tokens | Execution API tokens default to 10 minutes with auto-refresh | N/A | jwt_token_authentication |
| PSC-044 | Token generation sets nbf=iat | Not-before equals issued-at time | tokens.py:342, 346 | jwt_token_authentication |
| PSC-045 | Generic error prevents username enumeration | Returns generic 'Invalid credentials' message | login.py:67 | authentication_system |
| PSC-046 | Consistent credential validation | POST /token/cli uses same validation path as main endpoint | login.py | authentication_system |
| PSC-047 | JWT token revocation properly implemented | get_user_from_token validates token AND checks revocation | N/A | authentication_system |
| PSC-048 | Auto-generated password length (16 chars) | _generate_password() produces 16-character passwords | simple_auth_manager.py:287 | authentication_system |
| PSC-049 | Character set excludes ambiguous chars | Excludes 0/O, 1/l/I from password generation | simple_auth_manager.py:287 | authentication_system |
| PSC-050 | Empty/null password rejection | Rejects empty username or password | login.py:52 | authentication_system |
| PSC-051 | Pluggable authentication architecture | Enterprise auth managers provide password change via native interfaces | N/A | authentication_system |
| PSC-052 | Clear documentation of dev/testing scope | Documentation states dev/testing purpose, links to production auth | N/A | authentication_system |
| PSC-053 | Delegated password management | Architecture delegates to external identity providers for production | N/A | authentication_system |
| PSC-054 | Auto-generated passwords with high entropy | random.choices() with 50-char alphabet, 16 chars (~90 bits entropy) | N/A | authentication_system |
| PSC-055 | Prevention of weak password selection | Users cannot choose weak passwords in Simple Auth Manager | N/A | authentication_system |
| PSC-056 | Absence of composition rules | Direct string comparison without character type validation | login.py:59-63 | authentication_system |
| PSC-057 | NIST SP 800-63B compliant password handling | No composition rules enforced, aligning with NIST guidance | login.py:59-63 | authentication_system |
| PSC-058 | Password transmitted in POST body | Credentials via LoginBody (JSON/form-encoded), not URL parameters | login.py | authentication_system |
| PSC-059 | Backend does not expose password | API accepts password via POST but doesn't expose in responses | login.py | authentication_system |
| PSC-060 | No restrictive headers on login | No headers or attributes preventing paste/password managers | login.py | authentication_system |
| PSC-061 | Multiple content type support | Accepts application/json and application/x-www-form-urlencoded | login.py | authentication_system |
| PSC-062 | Password comparison without modification | Password compared directly without transformation | login.py:60 | authentication_system |
| PSC-063 | Authentication/Authorization Separation | Clean separation between authentication and authorization | N/A | authentication_system |
| PSC-064 | Extensibility hook for middleware | get_fastapi_middlewares() allows rate-limiting middleware registration | base_auth_manager.py:136 | authentication_system |
| PSC-065 | No hardcoded default accounts | Users from config only | simple_auth_manager.py | authentication_system |
| PSC-066 | All-admins mode gated by config | Returns 403 if not enabled | login.py | authentication_system |
| PSC-067 | Anonymous user gated by config | Only in explicit dev mode | login.py | authentication_system |
| PSC-068 | File-level locking prevents race conditions | fcntl.flock prevents race conditions during password generation | simple_auth_manager.py:128-148 | authentication_system |
| PSC-069 | No password hints or KBA | No implementation of password hints or secret questions | login.py, user.py | authentication_system |
| PSC-070 | JWT validation via PyJWT decode() | Applied at all validation paths | tokens.py | session_management |
| PSC-071 | User resolution from token | Applied via get_user dependency | security.py | session_management |
| PSC-072 | Backend auth manager token validation | Entry point for all authenticated endpoints | security.py | session_management |
| PSC-073 | Middleware pre-validation | Applied at middleware layer | refresh_token.py | session_management |
| PSC-074 | Server-side JWT signature verification | All verification uses server-side cryptographic operations | tokens.py | session_management |
| PSC-075 | Asymmetric key or HMAC validation | Uses asymmetric keys or HMAC with server-held secrets | tokens.py | session_management |
| PSC-076 | Auth manager delegation for validation | resolve_user_from_token() delegates to auth manager | security.py | session_management |
| PSC-077 | FastAPI dependency enforcement | get_user dependency ensures backend validation | security.py | session_management |
| PSC-078 | Cookie security attributes | Proper httponly, secure, samesite, configurable path | refresh_token.py | session_management |
| PSC-079 | Cryptographically sound token generation | CSPRNG for IDs, proper signing, mandatory expiration | tokens.py | session_management |
| PSC-080 | Dynamic JTI generation | Unique jti via uuid.uuid4().hex | tokens.py | session_management |
| PSC-081 | Timestamp claims (iat, exp, nbf) | Tokens include issued-at, expiration, not-before | tokens.py | session_management |
| PSC-082 | Required claims validation | Required claims enforced | tokens.py | session_management |
| PSC-083 | Token refresh generates new tokens | Entirely new tokens with fresh claims | refresh_token.py | session_management |
| PSC-084 | CSPRNG for token ID | uuid.uuid4().hex backed by os.urandom() (122 bits) | tokens.py | session_management |
| PSC-085 | Cryptographic key signing | RSA (2048+), Ed25519, or HS512 | tokens.py | session_management |
| PSC-086 | Auto-generated secret uses CSPRNG | Fallback uses 128 bits from os.urandom(16) | tokens.py | session_management |
| PSC-087 | Cookie overwrite with new token | New token delivery via secure cookie on refresh | refresh_token.py | session_management |
| PSC-088 | Cookie clearance on expiration | max_age=0 when token empty | refresh_token.py | session_management |
| PSC-089 | Token expiration enforcement | Expiration mandatory, limiting exposure window | tokens.py | session_management |
| PSC-090 | RevokedToken model infrastructure | Model exists for persisting revocation state | tokens.py | session_management |
| PSC-091 | revoke_token extracts jti and exp | Properly extracts for recording revocation | tokens.py:295-305 | session_management |
| PSC-092 | Pluggable auth manager for user status | Architecture could check user status during token resolution | tokens.py | session_management |
| PSC-093 | Comprehensive resource taxonomy | Clear identification of all resource types with authorization methods | auth-manager/index.rst | authorization_rbac |
| PSC-094 | Method parameter documentation | Clear HTTP method to CRUD operation mapping | auth-manager/index.rst:82-92 | authorization_rbac |
| PSC-095 | Multi-team authorization requirements | Documentation specifies is_authorized_team implementation | multi-team.rst | authorization_rbac |
| PSC-096 | Sub-entity authorization model | Clear explanation of access_entity pattern | auth-manager/index.rst | authorization_rbac |
| PSC-097 | Batch API documentation | Performance-optimized authorization patterns documented | auth-manager/index.rst | authorization_rbac |
| PSC-098 | Abstract method enforcement | @abstractmethod forces explicit resource type handling | base_auth_manager.py | authorization_rbac |
| PSC-099 | FastAPI dependency injection | Authorization checks injected as dependencies | security.py | authorization_rbac |
| PSC-100 | Consistent _requires_access pattern | Single function raises 403 for unauthorized access | security.py:669-675 | authorization_rbac |

---

# 5. ASVS Compliance Summary

| ASVS ID | Title | Status | Notes |
|---------|-------|--------|-------|
| **9. Token-Based Session Management** |
| 9.1.1 | Token source and integrity - Signature/MAC Validation | ✅ Pass | Comprehensive JWT signature validation via PyJWT |
| 9.1.2 | Token source and integrity - Algorithm Allowlist | ✅ Pass | Explicit algorithm allowlist, no "none" algorithm |
| 9.1.3 | Token source and integrity - Trusted Key Sources | ✅ Pass | Keys from config only, no header-based resolution |
| 9.2.1 | Token content - Validity Time Span | ✅ Pass | Mandatory exp/iat/nbf claims with validation |
| **6. Authentication** |
| 6.1.1 | Authentication Documentation | ❌ Fail | Missing rate limiting, anti-automation guidance |
| 6.2.1 | Password Minimum Length | ✅ Pass | 16-character auto-generated passwords |
| 6.2.2 | Password Change Capability | ✅ Pass | Delegated to external identity providers |
| 6.2.3 | Password Change Requires Current Password | ⚪ N/A | External identity provider responsibility |
| 6.2.4 | Common Password Check | ⚪ N/A | Auto-generated passwords only |
| 6.2.5 | No Password Composition Rules | ✅ Pass | NIST-compliant, no composition rules |
| 6.2.6 | Password Input Fields Masking | ⚪ N/A | Backend API only |
| 6.2.7 | Paste Functionality and Password Managers | ✅ Pass | No restrictive headers or attributes |
| 6.2.8 | Password Verified Without Modification | ✅ Pass | Direct comparison without transformation |
| 6.3.1 | Credential Stuffing and Brute Force Prevention | ❌ Fail | No rate limiting implementation |
| 6.3.2 | Default User Accounts | ✅ Pass | No hardcoded default accounts |
| 6.4.1 | System Generated Initial Passwords | ❌ Fail | Non-cryptographic PRNG, no expiration |
| 6.4.2 | Password Hints and Knowledge-Based Authentication | ✅ Pass | Not implemented |
| **7. Session Management** |
| 7.2.1 | Backend Token Verification | ✅ Pass | All validation server-side via PyJWT |
| 7.2.2 | Dynamic Token Generation | ✅ Pass | CSPRNG-based unique identifiers |
| 7.2.3 | Token Entropy | ✅ Pass | 122 bits from uuid.uuid4() |
| 7.2.4 | New Token on Authentication | ✅ Pass | Fresh tokens with new jti/timestamps |
| 7.4.1 | Session Termination | ❌ Fail | Revocation mechanism not enforced |
| 7.4.2 | Account Disable/Delete Session Termination | ❌ Fail | No mechanism to invalidate all user sessions |
| **8. Authorization** |
| 8.1.1 | Authorization Documentation | ❌ Fail | Missing default-deny specification |
| 8.2.1 | Function-Level Access | 🟡 Partial | Authorization check silently skipped on JSON parse failure |
| 8.2.2 | Data-Specific Access (IDOR/BOLA) | ✅ Pass | Resource-specific authorization enforced |
| 8.3.1 | Trusted Service Layer | ✅ Pass | Authorization in service layer via FastAPI dependencies |
| **11. Cryptography** |
| 11.3.1 | Insecure Block Modes and Padding | ✅ Pass | No direct encryption implementation |
| 11.3.2 | Approved Ciphers and Modes | ✅ Pass | Uses HS512, RS256, EdDSA only |
| 11.4.1 | Approved Hash Functions | ✅ Pass | No MD5/SHA1 usage detected |
| **1. Output Encoding and Injection Prevention** |
| 1.2.1 | Output Encoding for HTTP Response | ❌ Fail | Plugin route shadowing possible |
| 1.2.2 | URL Encoding for Dynamic URLs | ❌ Fail | Missing /auth prefix in reserved URLs |
| 1.2.3 | JavaScript Content Encoding | ✅ Pass | No direct JavaScript generation |
| 1.2.4 | SQL Injection Prevention | ✅ Pass | SQLAlchemy ORM with parameterized queries |
| 1.2.5 | Injection Prevention | ⚪ N/A | Context-specific controls in place |
| 1.3.1 | HTML Sanitization | ✅ Pass | No direct HTML rendering |
| 1.3.2 | Dynamic Code Execution | ✅ Pass | No eval/exec usage detected |
| 1.5.1 | XML Parser Configuration and XXE | ✅ Pass | defusedxml used for XML parsing |
| **2. Input Validation** |
| 2.1.1 | Validation and Business Logic Documentation | ✅ Pass | Pydantic models document validation |
| 2.2.1 | Input Validation | ❌ Fail | Route shadowing vulnerability |
| 2.2.2 | Server-Side Input Validation | ✅ Pass | Pydantic validation enforced |
| 2.3.1 | Business Logic Security | ✅ Pass | Authorization checks in business logic |
| **3. HTTP Security Configuration** |
| 3.2.1 | Unintended Content Interpretation | ❌ Fail | No security headers middleware |
| 3.2.2 | Safe Text Rendering | ✅ Pass | JSON responses only |
| 3.3.1 | Cookie Setup | ❌ Fail | No Secure attribute or __Host- prefix enforcement |
| 3.4.1 | Browser Security Headers (HSTS) | ❌ Fail | No HSTS header configured |
| 3.4.2 | CORS Configuration | ❌ Fail | Unconditional credentials without origin validation |
| 3.5.1 | Browser Origin Separation (CSRF) | ❌ Fail | No explicit CSRF protection |
| 3.5.2 | CORS Preflight Mechanism | ❌ Fail | Part of CORS misconfiguration |
| 3.5.3 | HTTP Method Enforcement | ✅ Pass | FastAPI enforces HTTP methods |
| **4. Content Type** |
| 4.1.1 | Content-Type Header Validation | ✅ Pass | FastAPI validates content types |
| 4.4.1 | WebSocket over TLS (WSS) | ✅ Pass | WebSocket security delegated to reverse proxy |
| **5. File Upload** |
| 5.2.1 | File Upload Size Limits | ⚪ N/A | No file upload functionality |
| 5.2.2 | File Extension and Content Validation | ⚪ N/A | No file upload functionality |
| 5.3.1 | Uploaded Files Not Executed | ✅ Pass | No file upload execution path |
| 5.3.2 | Path Traversal Prevention | ✅ Pass | No user-controlled file paths |
| **10. OAuth/OIDC** |
| 10.4.1 | Redirect URI Validation | ⚪ N/A | Not an OAuth provider |
| 10.4.2 | Authorization Code Single-Use | ⚪ N/A | Not an OAuth provider |
| 10.4.3 | Authorization Code Lifetime | ⚪ N/A | Not an OAuth provider |
| 10.4.4 | Grant Type Restrictions | ⚪ N/A | Not an OAuth provider |
| 10.4.5 | Refresh Token Replay Mitigation | ⚪ N/A | Not an OAuth provider |
| **12. TLS Configuration** |
| 12.1.1 | General TLS Security Guidance | 🟡 Partial | TLS configuration delegated to reverse proxy |
| 12.2.1 | HTTPS with External Services | ✅ Pass | JWKS fetch via verified TLS |
| 12.2.2 | Publicly Trusted TLS Certificates | ⚪ N/A | Deployment configuration |
| **13. Deployment** |
| 13.4.1 | Source Control Metadata Protection | ✅ Pass | No .git directories in deployment |
| **14. Data Protection** |
| 14.2.1 | Sensitive Data in HTTP Messages | ✅ Pass | Passwords in POST body only |
| 14.3.1 | Clearing Authenticated Data | ⚪ N/A | Backend API responsibility |
| **15. Configuration and Dependencies** |
| 15.1.1 | Risk Based Remediation Timeframes | ❌ Fail | Documentation disclaims timeframes |
| 15.2.1 | Component Remediation Compliance | ❌ Fail | Known-vulnerable components retained |
| 15.3.1 | Minimal Data Object Fields | ✅ Pass | Pydantic models return required fields only |

**Summary Statistics:**
- ✅ Pass: 63 (58.3%)
- ❌ Fail: 16 (14.8%)
- 🟡 Partial: 2 (1.9%)
- ⚪ N/A: 27 (25.0%)

---

# 6. Cross-Reference Matrix

## Findings to ASVS Mapping

| Finding ID | Severity | ASVS Requirements | Positive Controls | Related Domains |
|------------|----------|-------------------|-------------------|-----------------|
| FINDING-001 | High | 6.1.1 | PSC-064 | authentication_system |
| FINDING-002 | High | 6.3.1 | PSC-064 | authentication_system |
| FINDING-003 | High | 6.4.1 | PSC-048, PSC-054 | authentication_system |
| FINDING-004 | High | 6.4.1 | PSC-048 | authentication_system |
| FINDING-005 | High | 7.4.1 | PSC-090, PSC-091 | session_management |
| FINDING-006 | High | 7.4.2 | PSC-092 | session_management |
| FINDING-007 | High | 8.1.1 | PSC-093, PSC-094, PSC-095 | authorization_rbac |
| FINDING-008 | High | 8.2.1 | PSC-098, PSC-099 | authorization_rbac |
| FINDING-009 | High | 1.2.1, 1.2.2, 2.2.1 | None | input_validation |
| FINDING-010 | High | 3.2.1 | None | http_security |
| FINDING-011 | High | 3.3.1 | PSC-078 | session_management |
| FINDING-012 | High | 3.4.1 | None | http_security |
| FINDING-013 | High | 3.4.2 | None | http_security |
| FINDING-014 | High | 3.5.1, 3.5.2 | None | http_security |
| FINDING-015 | High | 15.1.1 | None | configuration |
| FINDING-016 | High | 15.2.1 | None | configuration |

## ASVS to Controls Mapping

| ASVS Category | Pass Controls | Fail Findings | Partial/N/A |
|---------------|---------------|---------------|-------------|
| 9. Token-Based Session Management | PSC-001 to PSC-044 | None | None |
| 6. Authentication | PSC-045 to PSC-069 | FINDING-001, 002, 003, 004 | 6.2.3, 6.2.4, 6.2.6 |
| 7. Session Management | PSC-070 to PSC-092 | FINDING-005, 006, 011 | 14.3.1 |
| 8. Authorization | PSC-093 to PSC-100 | FINDING-007, 008 | None |
| 1. Output Encoding | PSC-001 (validation) | FINDING-009 | 1.2.5 |
| 3. HTTP Security | PSC-078 | FINDING-010, 011, 012, 013, 014 | None |
| 15. Configuration | None | FINDING-015, 016 | None |

## Domain Coverage Matrix

| Domain | Total Controls | High-Risk Findings | ASVS Coverage |
|--------|----------------|-------------------|---------------|
| jwt_token_authentication | 44 | 0 | 9.1.x, 9.2.x - Complete |
| authentication_system | 25 | 4 | 6.x - Partial (rate limiting gaps) |
| session_management | 23 | 3 | 7.x - Partial (revocation gaps) |
| authorization_rbac | 8 | 2 | 8.x - Partial (documentation gaps) |
| http_security | 0 | 5 | 3.x - Major gaps |
| configuration | 0 | 2 | 15.x - Policy gaps |

## Control Effectiveness Analysis

| Security Function | Strong Controls | Weak Areas | Remediation Priority |
|-------------------|-----------------|------------|---------------------|
| **Cryptographic Operations** | PSC-001 to PSC-033 (JWT validation, key management) | None | ✅ Maintain |
| **Token Lifecycle** | PSC-034 to PSC-044, PSC-070 to PSC-089 (generation, validation, time claims) | FINDING-005 (revocation enforcement) | 🔴 High |
| **Authentication** | PSC-045 to PSC-069 (password handling, pluggable architecture) | FINDING-001, 002, 003, 004 (rate limiting, PRNG) | 🔴 High |
| **Authorization** | PSC-093 to PSC-100 (documentation, enforcement) | FINDING-007, 008 (default-deny, JSON parsing) | 🟡 Medium |
| **HTTP Security** | PSC-078 (cookie attributes) | FINDING-010, 011, 012, 013, 014 (headers, CORS, CSRF) | 🔴 High |
| **Input Validation** | Pydantic models | FINDING-009 (route shadowing) | 🟡 Medium |
| **Configuration** | None | FINDING-015, 016 (dependency management) | 🟡 Medium |

## Compensating Controls Analysis

| Vulnerability Area | Missing Primary Control | Available Compensating Controls | Gap Severity |
|-------------------|------------------------|--------------------------------|--------------|
| Rate Limiting (FINDING-001, 002) | No rate limiting middleware | PSC-064 (extensibility hook), PSC-045 (generic errors) | 🔴 High - Requires external implementation |
| Token Revocation (FINDING-005) | Revocation not enforced | PSC-090, PSC-091 (infrastructure exists), PSC-043 (short-lived tokens) | 🟡 Medium - Infrastructure present, enforcement missing |
| CSRF Protection (FINDING-014) | No CSRF middleware | PSC-078 (SameSite cookies), JWT validation | 🟡 Medium - Partial mitigation via cookies |
| Security Headers (FINDING-010, 012) | No headers middleware | Reverse proxy configuration | 🟡 Medium - Deployment-dependent |
| Route Shadowing (FINDING-009) | Missing /auth prefix | PSC-099 (dependency injection) | 🟡 Medium - Requires configuration discipline |

## Implementation Roadmap by Priority

### 🔴 Critical (Immediate)
1. **FINDING-002**: Implement rate limiting middleware (leverage PSC-064)
2. **FINDING-005**: Enforce revocation checks in token validation (leverage PSC-090, PSC-091)
3. **FINDING-003**: Replace random.choices with secrets module

### 🟡 High (Next Sprint)
4. **FINDING-014**: Implement CSRF protection middleware
5. **FINDING-008**: Add authorization check validation for JSON parse failures
6. **FINDING-009**: Add /auth to RESERVED_URL_PREFIXES

### 🟢 Medium (Backlog)
7. **FINDING-001, 007**: Enhance documentation (rate limiting, default-deny)
8. **FINDING-010, 011, 012, 013**: Security headers middleware
9. **FINDING-004**: Implement password expiration for auto-generated passwords
10. **FINDING-006**: User session invalidation on account disable
11. **FINDING-015, 016**: Establish dependency remediation policy

## 7. Level Coverage Analysis


**Audit scope:** up to L1

**Severity threshold:** high and above

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 16 |

**Total consolidated findings: 16**

*End of Consolidated Security Audit Report*