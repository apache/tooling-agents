# Security Issues

## Issue: FINDING-001 - Bulk CREATE operations in multi-team mode skip team-level authorization for new resources
**Labels:** bug, security, priority:medium
**Description:**
### Summary
In multi-team mode, bulk CREATE operations for pools, connections, and variables do not extract team_name from the request body, passing team_name=None to the auth manager. This allows a user in one team to potentially create resources in another team's scope via bulk endpoints, while the non-bulk equivalents correctly use _collect_teams_to_check() to extract team context.

### Details
- **CWE:** CWE-863 (Incorrect Authorization)
- **ASVS:** 8.2.1 (Level L1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/core_api/security.py`
- **Domain:** Authorization and Access Control

The bulk CREATE endpoints (`requires_access_pool_bulk()`, `requires_access_connection_bulk()`, and `requires_access_variable_bulk()`) fail to extract team context from request bodies, creating an authorization bypass in multi-team deployments.

### Remediation
Update `requires_access_pool_bulk()`, `requires_access_connection_bulk()`, and `requires_access_variable_bulk()` to extract team_name from *Body objects for CREATE actions, matching the behavior of non-bulk equivalents via `_collect_teams_to_check()`.

### Acceptance Criteria
- [ ] Bulk CREATE operations extract team_name from request bodies
- [ ] Authorization checks in multi-team mode validate team context for bulk operations
- [ ] Test added covering multi-team bulk CREATE authorization
- [ ] Behavior matches non-bulk equivalents

### References
- Source Report: 8.2.1.md
- Related CWE: https://cwe.mitre.org/data/definitions/863.html
- ASVS 8.2.1

### Priority
**Medium** - Authorization bypass in multi-team deployments

---

## Issue: FINDING-002 - Hardcoded `allow_credentials=True` in CORS Without Origin Validation Against Wildcard
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application hardcodes `allow_credentials=True` in CORS configuration without validating that `allow_origins` does not contain '*'. This creates a footgun where a trusted-but-mistaken deployment manager could accidentally enable authenticated cross-origin access from any origin.

### Details
- **ASVS:** 3.4.2 (Level L1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/core_api/app.py`
- **Domain:** Web Security Headers and CORS

While CORS configuration is delegated to the Deployment Manager (a fully trusted role), the lack of validation creates a dangerous misconfiguration risk. A simple validation check would prevent accidental security vulnerabilities.

### Remediation
Add validation in `init_config` to log a warning and disable `allow_credentials` when `allow_origins` contains '*', or reject the configuration at startup entirely.

Example implementation:
```python
if '*' in allow_origins and allow_credentials:
    raise ValueError("Cannot use allow_credentials=True with wildcard origins")
```

### Acceptance Criteria
- [ ] Validation added to prevent `allow_credentials=True` with wildcard origins
- [ ] Configuration rejected at startup or credentials automatically disabled
- [ ] Warning logged when misconfiguration detected
- [ ] Test added for wildcard + credentials validation
- [ ] Documentation updated with secure CORS configuration examples

### References
- Source Report: 3.4.2.md
- ASVS 3.4.2

### Priority
**Medium** - Prevents dangerous misconfiguration by trusted administrators

---

## Issue: FINDING-003 - Previous JWT tokens are not revoked on new user authentication
**Labels:** bug, security, priority:low
**Description:**
### Summary
Previous JWT tokens are not revoked on new user authentication in SimpleAuthManager. When a user logs in again, old tokens remain valid, allowing potential session confusion or unauthorized access if old tokens are compromised.

### Details
- **CWE:** CWE-613 (Insufficient Session Expiration)
- **ASVS:** 7.2.4 (Level L1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py`
  - `airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py`
- **Domain:** Authentication and Session Management
- **Related Findings:** FINDING-004

**Note:** Downgraded from Medium severity because SimpleAuthManager is explicitly dev-only with production detection heuristics and loud warnings. Production deployments use external auth managers.

### Remediation
In the cookie-based login flow, read the existing cookie token and revoke it before issuing a new one using the existing `revoke_token()` infrastructure.

Example implementation:
```python
# Read existing token from cookie
existing_token = request.cookies.get(cookie_name)
if existing_token:
    revoke_token(existing_token)
# Issue new token
```

### Acceptance Criteria
- [ ] Existing tokens revoked before issuing new tokens on login
- [ ] Token revocation integrated into login flow
- [ ] Test added verifying old tokens are invalid after re-authentication
- [ ] Documentation updated describing token lifecycle

### References
- Source Report: 7.2.4.md
- Related CWE: https://cwe.mitre.org/data/definitions/613.html
- ASVS 7.2.4
- Related: FINDING-004

### Priority
**Low** - Affects dev-only SimpleAuthManager; production uses external auth

---

## Issue: FINDING-004 - No mechanism to terminate all active sessions when a user account is disabled or deleted
**Labels:** bug, security, priority:low
**Description:**
### Summary
No mechanism exists to terminate all active sessions when a user account is disabled or deleted in SimpleAuthManager. Disabled or deleted users can continue using valid tokens until natural expiration.

### Details
- **CWE:** CWE-613 (Insufficient Session Expiration)
- **ASVS:** 7.4.2 (Level L1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py`
  - `airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py`
- **Domain:** Authentication and Session Management
- **Related Findings:** FINDING-003

**Note:** Downgraded from Medium severity because SimpleAuthManager is explicitly dev-only with production detection heuristics. Production deployments use external auth managers that handle user lifecycle. The base_auth_manager lacks a user-existence check but this is only demonstrable via the dev-only SimpleAuthManager.

### Remediation
Add user existence/active-status check in `get_user_from_token()` or implement user-level token revocation via a `revoke_all_tokens_for_user(username)` method.

Example implementation:
```python
def get_user_from_token(self, token):
    user = self._decode_token(token)
    if not user or not self._is_user_active(user.username):
        raise AuthenticationError("User account disabled or deleted")
    return user
```

### Acceptance Criteria
- [ ] User active status checked during token validation
- [ ] Disabled/deleted users cannot authenticate with valid tokens
- [ ] Optional: Bulk token revocation method implemented
- [ ] Test added verifying disabled users cannot access resources
- [ ] Documentation updated describing user lifecycle management

### References
- Source Report: 7.4.2.md
- Related CWE: https://cwe.mitre.org/data/definitions/613.html
- ASVS 7.4.2
- Related: FINDING-003

### Priority
**Low** - Affects dev-only SimpleAuthManager; production uses external auth

---

## Issue: FINDING-005 - Default "GUESS" algorithm mode derives accepted algorithm from key material rather than explicit allowlist
**Labels:** bug, security, priority:low
**Description:**
### Summary
When configured with `trusted_jwks_url` but no explicit `jwt_algorithm`, the JWTValidator uses "GUESS" mode which derives the accepted algorithm from the JWKS key's algorithm_name at runtime rather than enforcing a static allowlist.

### Details
- **CWE:** CWE-757 (Selection of Less-Secure Algorithm During Negotiation)
- **ASVS:** 9.1.2 (Level L1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/auth/tokens.py`
- **Domain:** Authentication and Session Management

The "None" algorithm is implicitly excluded because PyJWK requires real key material, but no explicit blocklist/allowlist is enforced. This could allow weaker algorithms if they appear in the JWKS.

### Remediation
Add explicit algorithm allowlist validation in GUESS mode. Validate the resolved algorithm against a static allowlist of permitted algorithms and explicitly reject 'none'.

Example implementation:
```python
ALLOWED_ALGORITHMS = ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512']

def _validate_algorithm(self, algorithm):
    if algorithm.lower() == 'none':
        raise ValueError("Algorithm 'none' is not permitted")
    if algorithm not in ALLOWED_ALGORITHMS:
        raise ValueError(f"Algorithm {algorithm} not in allowlist")
```

### Acceptance Criteria
- [ ] Explicit algorithm allowlist defined
- [ ] GUESS mode validates resolved algorithm against allowlist
- [ ] 'none' algorithm explicitly rejected
- [ ] Test added for algorithm validation
- [ ] Configuration documentation updated with algorithm security guidance

### References
- Source Report: 9.1.2.md
- Related CWE: https://cwe.mitre.org/data/definitions/757.html
- ASVS 9.1.2

### Priority
**Low** - Implicit protection exists via PyJWK; explicit validation improves defense-in-depth

---

## Issue: FINDING-006 - Unvalidated `referer` header used for business logic decision
**Labels:** bug, security, priority:low
**Description:**
### Summary
HTTP Referer header is used without validation to determine `triggered_by` field stored in DagRun record. Any request with a Referer header is marked as UI-triggered, creating inaccurate audit trails.

### Details
- **CWE:** CWE-346 (Origin Validation Error)
- **ASVS:** 2.2.1 (Level L1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/core_api/routes/public/dag_run.py`
- **Domain:** API Input Validation and Injection Prevention

The Referer header is trivially spoofed by clients, making it unreliable for audit trail purposes. An attacker could falsely mark API-triggered runs as UI-triggered.

### Remediation
Validate the referer against known UI origins or use a more reliable mechanism such as a dedicated X-Triggered-By header set by the UI.

Example implementation:
```python
KNOWN_UI_ORIGINS = ['https://airflow.example.com']

def get_triggered_by(request):
    referer = request.headers.get('referer', '')
    if any(referer.startswith(origin) for origin in KNOWN_UI_ORIGINS):
        return DagRunTriggeredByType.UI
    return DagRunTriggeredByType.REST_API
```

### Acceptance Criteria
- [ ] Referer header validated against known UI origins
- [ ] Alternative mechanism (e.g., X-Triggered-By header) considered
- [ ] Invalid referers do not mark runs as UI-triggered
- [ ] Test added for referer validation
- [ ] Audit trail accuracy improved

### References
- Source Report: 2.2.1.md
- Related CWE: https://cwe.mitre.org/data/definitions/346.html
- ASVS 2.2.1

### Priority
**Low** - Affects audit trail accuracy, not security boundary

---

## Issue: FINDING-007 - `json.loads` in `_normalize_conf` lacks explicit error handling for malformed input
**Labels:** bug, security, priority:low
**Description:**
### Summary
In the non-API code path, `json.loads` can raise `JSONDecodeError` which is unhandled, resulting in a 500 response rather than a user-friendly 400 response. In the API path, Pydantic validates conf as dict|None before this function is called.

### Details
- **CWE:** CWE-252 (Unchecked Return Value)
- **ASVS:** 2.2.1 (Level L1)
- **Affected Files:**
  - `airflow-core/src/airflow/api/common/trigger_dag.py`
- **Domain:** API Input Validation and Injection Prevention

Unhandled JSON parsing errors create poor user experience and potentially expose stack traces in error responses.

### Remediation
Wrap `json.loads` in a try/except block catching `json.JSONDecodeError` and raising a `ValueError` with a descriptive message.

Example implementation:
```python
def _normalize_conf(conf):
    if isinstance(conf, str):
        try:
            return json.loads(conf)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in conf parameter: {e}")
    return conf
```

### Acceptance Criteria
- [ ] JSON parsing errors caught and handled
- [ ] User-friendly 400 error returned for malformed JSON
- [ ] No stack traces exposed in error responses
- [ ] Test added for malformed JSON input
- [ ] Error message provides actionable feedback

### References
- Source Report: 2.2.1.md
- Related CWE: https://cwe.mitre.org/data/definitions/252.html
- ASVS 2.2.1

### Priority
**Low** - User experience issue, not a security vulnerability

---

## Issue: FINDING-008 - No Sec-Fetch-* Header Validation or CSP Sandbox Directive in Application Code
**Labels:** bug, security, priority:low, documentation
**Description:**
### Summary
Security headers are delegated to reverse proxy per documented architecture. The application serves static files without application-level X-Content-Type-Options or Sec-Fetch-* validation. While proxy delegation is the documented pattern, incomplete proxy documentation creates a residual risk for deployments following only official docs.

### Details
- **ASVS:** 3.2.1 (Level L1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/core_api/app.py`
- **Domain:** Web Security Headers and CORS

**Note:** Downgraded from Medium severity because security headers are delegated to reverse proxy per documented architecture. This is primarily a documentation gap.

### Remediation
Expand `run-behind-proxy.rst` to include X-Content-Type-Options and other recommended security headers in the nginx example configuration.

Example nginx configuration:
```nginx
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Content-Security-Policy "default-src 'self'" always;
```

### Acceptance Criteria
- [ ] Documentation updated with comprehensive security headers examples
- [ ] Nginx, Apache, and other common proxy examples included
- [ ] X-Content-Type-Options explicitly documented
- [ ] Sec-Fetch-* validation guidance provided
- [ ] CSP examples included

### References
- Source Report: 3.2.1.md
- ASVS 3.2.1

### Priority
**Low** - Documentation improvement; security delegated to proxy layer

---

## Issue: FINDING-009 - Cookie Configuration Function Lacks Secure Attribute and Name Prefix Enforcement
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `get_cookie_path()` utility provides path scoping but no visible enforcement of Secure attribute or __Secure- prefix. The actual cookie-setting code was not in analyzed files so enforcement cannot be verified.

### Details
- **ASVS:** 3.3.1 (Level L1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/app.py`
- **Domain:** Web Security Headers and CORS

**Note:** Downgraded from Medium severity because TLS enforcement is delegated to proxy/deployment layer. Given TLS delegation to deployment manager, this is a defense-in-depth gap rather than a direct vulnerability.

### Remediation
Verify that all cookie-setting code sets `Secure=True`. Consider adding a centralized cookie utility that enforces security attributes.

Example implementation:
```python
def set_secure_cookie(response, name, value, **kwargs):
    if not name.startswith('__Secure-'):
        name = f'__Secure-{name}'
    kwargs.setdefault('secure', True)
    kwargs.setdefault('httponly', True)
    kwargs.setdefault('samesite', 'lax')
    response.set_cookie(name, value, **kwargs)
```

### Acceptance Criteria
- [ ] All cookie-setting code audited for Secure attribute
- [ ] Centralized cookie utility created (optional)
- [ ] __Secure- prefix enforced for HTTPS cookies
- [ ] Test added verifying cookie security attributes
- [ ] Documentation updated with secure cookie guidelines

### References
- Source Report: 3.3.1.md
- ASVS 3.3.1

### Priority
**Low** - Defense-in-depth improvement; TLS delegated to deployment layer

---

## Issue: FINDING-010 - No Explicit CSRF Token Mechanism for Cookie-Authenticated Core API Endpoints
**Labels:** bug, security, priority:low, documentation
**Description:**
### Summary
Starlette's CORSMiddleware does NOT reject simple (non-preflight) requests from disallowed origins. For requests that don't trigger preflight (e.g., POST with Content-Type: application/x-www-form-urlencoded), the middleware processes the request fully and only withholds Access-Control-Allow-Origin response headers.

### Details
- **ASVS:** 3.5.1, 3.5.2 (Level L1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/core_api/app.py`
- **Domain:** Web Security Headers and CORS

However, FastAPI endpoints require application/json (triggers preflight), JWT requires Authorization header (triggers preflight), and SameSite cookies prevent cross-origin cookie sending. This is a defense-in-depth gap, not exploitable in practice.

### Remediation
Document that CORS middleware alone is not the sole anti-forgery mechanism. Consider adding explicit Origin header validation middleware for any endpoints that accept cookie-based auth without JWT.

Example implementation:
```python
@app.middleware("http")
async def validate_origin(request: Request, call_next):
    if request.method in ["POST", "PUT", "DELETE", "PATCH"]:
        origin = request.headers.get("origin")
        if origin and origin not in ALLOWED_ORIGINS:
            return JSONResponse(
                status_code=403,
                content={"detail": "Origin not allowed"}
            )
    return await call_next(request)
```

### Acceptance Criteria
- [ ] Documentation clarifies CSRF protection mechanisms
- [ ] Origin validation middleware added (optional)
- [ ] Layered defense approach documented
- [ ] Test added for cross-origin request handling
- [ ] Security architecture documentation updated

### References
- Source Report: 3.5.1.md, 3.5.2.md
- ASVS 3.5.1, 3.5.2

### Priority
**Low** - Defense-in-depth gap; not exploitable due to existing protections