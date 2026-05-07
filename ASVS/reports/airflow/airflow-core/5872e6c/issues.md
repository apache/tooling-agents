# Security Issues

## Issue: FINDING-006 - No Password Change Functionality Exists
**Labels:** bug, security, priority:high
**Description:**
### Summary
The Simple Auth Manager provides no endpoint, service method, or mechanism for users to change their passwords, preventing password rotation after compromise.

### Details
The available endpoints are limited to login functionality only (token, token/login, token/cli). No PUT /password, POST /password/change, or similar endpoint exists. The SimpleAuthManager class has no change_password() method. Passwords are generated once during init() and stored permanently. Users cannot change compromised passwords. If a password is leaked (e.g., from console output during init, from the plain-text file, or via log exposure), there is no self-service mechanism to rotate it without restarting the Airflow instance and deleting the password file.

**CWE:** CWE-620  
**ASVS:** 6.2.2 (L1, L2, L3)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py` (entire file)
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py` (entire class)

**Related Findings:** FINDING-007

### Remediation
Add a new endpoint in routes/login.py or a new routes/password.py:
```python
@login_router.post("/password/change", status_code=status.HTTP_200_OK)
def change_password(
    body: PasswordChangeBody,  # contains current_password, new_password
    user: SimpleAuthManagerUser = Depends(get_current_user),
) -> dict:
    """Allow authenticated users to change their password."""
    SimpleAuthManagerLogin.change_password(
        username=user.username,
        current_password=body.current_password,
        new_password=body.new_password,
    )
    return {"message": "Password changed successfully"}
```

### Acceptance Criteria
- [ ] Password change endpoint implemented
- [ ] Current password verification required
- [ ] New password validation applied
- [ ] Test added verifying password change flow

### References
- Source: 6.2.2.md
- CWE-620: Unverified Password Change

### Priority
**High** - No mechanism to rotate compromised passwords

---

## Issue: FINDING-007 - Password Change Functionality Absent — Cannot Verify Current Password Requirement
**Labels:** bug, security, priority:high
**Description:**
### Summary
Since no password change functionality exists, the requirement that password changes must verify the current password before accepting a new one is inherently unmet, enabling potential session hijacking attacks if implemented incorrectly.

### Details
There is no PasswordChangeBody data model, no service method that validates the current password, and no endpoint that accepts both current and new passwords. If password change functionality is added in the future without proper design, it may omit current password verification, enabling session hijacking attacks where an attacker with a stolen session token can permanently take over an account by changing the password without knowing the original.

**CWE:** CWE-620  
**ASVS:** 6.2.3 (L1, L2, L3)

**Affected Files:**
- All files in scope

**Related Findings:** FINDING-006

### Remediation
When implementing password change per ASVS-6.2.2 remediation, ensure:
1. Create PasswordChangeBody data model with current_password and new_password fields
2. Implement change_password service method that verifies current password before allowing change (CRITICAL)
3. Add POST /password/change endpoint

Example:
```python
class PasswordChangeBody(BaseModel):
    current_password: str  # REQUIRED - prevents session-hijack takeover
    new_password: str

@staticmethod
def change_password(username: str, current_password: str, new_password: str) -> None:
    passwords = SimpleAuthManager.get_passwords()
    
    # CRITICAL: Verify current password before allowing change
    if passwords.get(username) != current_password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect",
        )
    
    validate_password(new_password)
    passwords[username] = new_password
    _write_passwords(passwords)
```

### Acceptance Criteria
- [ ] PasswordChangeBody model created with both fields
- [ ] Current password verification implemented
- [ ] HTTP 401 returned on incorrect current password
- [ ] Test added verifying current password requirement

### References
- Source: 6.2.3.md
- CWE-620: Unverified Password Change

### Priority
**High** - Design requirement for future implementation

---

## Issue: FINDING-008 - Timing-Attack Vulnerable Plain-Text Password Comparison
**Labels:** bug, security, priority:high
**Description:**
### Summary
The password comparison uses Python's == operator which short-circuits on first differing character, leaking password length/prefix information through timing analysis.

### Details
User-supplied body.password is compared against stored password using plain-text == string comparison. An attacker can use statistical timing analysis to iteratively determine password characters, reducing the effective brute-force search space significantly.

**CWE:** CWE-208  
**ASVS:** 6.3.1 (L1, L2, L3)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py:60`

### Remediation
Use constant-time comparison with hmac.compare_digest() instead of == operator:
```python
import hmac

stored_password = passwords.get(user.username, '')
if hmac.compare_digest(stored_password.encode(), body.password.encode()):
    # valid
```

### Acceptance Criteria
- [ ] hmac.compare_digest() used for password comparison
- [ ] Timing side-channel eliminated
- [ ] Test added verifying constant-time comparison

### References
- Source: 6.3.1.md
- CWE-208: Observable Timing Discrepancy

### Priority
**High** - Timing side-channel enables password enumeration

---

## Issue: FINDING-009 - Password generation uses non-cryptographic PRNG (random module)
**Labels:** bug, security, priority:high
**Description:**
### Summary
The password generation function uses Python's random module (Mersenne Twister PRNG) instead of a cryptographically secure random number generator, potentially allowing password prediction.

### Details
The random module is explicitly documented by Python as not suitable for security purposes. If an attacker can determine or estimate the PRNG state (e.g., by knowing the approximate startup time of Airflow workers, or by observing other random outputs), they can predict generated passwords. With multiple workers generating passwords near-simultaneously (as described in the file-locking logic), the entropy window is narrower.

**CWE:** CWE-338  
**ASVS:** 6.4.1, 11.4.2 (L1, L2, L3)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:302`

**Related Findings:** FINDING-142, FINDING-143

### Remediation
Replace the random module with the secrets module for cryptographically secure random generation:
```python
import secrets

@staticmethod
def _generate_password() -> str:
    alphabet = "abcdefghkmnpqrstuvwxyzABCDEFGHKMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(16))
```

### Acceptance Criteria
- [ ] secrets module used for password generation
- [ ] Cryptographically secure randomness ensured
- [ ] Test added verifying CSPRNG usage

### References
- Source: 6.4.1.md, 11.4.2.md
- CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator

### Priority
**High** - Predictable password generation

---

## Issue: FINDING-010 - Generated passwords never expire and cannot be changed
**Labels:** bug, security, priority:high
**Description:**
### Summary
ASVS 6.4.1 requires that system-generated initial passwords expire after a short period or after first use. The current implementation permanently stores generated passwords with no expiration mechanism, violating both requirements.

### Details
Generated passwords are stored in a JSON file indefinitely and used for all future authentications with no timestamp, no expiration check, and no first-use detection.

**CWE:** CWE-521  
**ASVS:** 6.4.1 (L1, L2, L3)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:126-155`

**Related Findings:** FINDING-035, FINDING-036, FINDING-037, FINDING-146

### Remediation
Implement password expiration and forced change on first use:
```python
# Store generation timestamp alongside password
passwords[user.username] = {
    "password": self._generate_password(),
    "generated_at": datetime.utcnow().isoformat(),
    "must_change": True
}

# In create_token(), check expiration and must_change:
if password_record["must_change"]:
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Password must be changed before first use",
        headers={"X-Password-Change-Required": "true"}
    )

generated_at = datetime.fromisoformat(password_record["generated_at"])
if datetime.utcnow() - generated_at > timedelta(hours=24):
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Initial password has expired"
    )
```

### Acceptance Criteria
- [ ] Password expiration timestamp stored
- [ ] Must-change flag enforced
- [ ] HTTP 403 returned when password change required
- [ ] Test added verifying expiration and first-use

### References
- Source: 6.4.1.md
- CWE-521: Weak Password Requirements

### Priority
**High** - Initial passwords never expire

---

## Issue: FINDING-011 - No multi-factor authentication mechanism available or enforceable
**Labels:** bug, security, priority:high
**Description:**
### Summary
The Simple Auth Manager provides only single-factor password authentication with no extension point for adding a second factor, making it insufficient for ASVS Level 2 deployments.

### Details
The authentication flow follows: POST /token → LoginBody(username, password) → single-factor validation → JWT issued. No TOTP, hardware key, push notification, or any second factor is requested, validated, or enforced. For ASVS Level 2 compliance, MFA is mandatory. If deployed in any environment requiring L2 assurance, authentication is insufficient against credential theft, phishing, or password reuse attacks.

**CWE:** CWE-308  
**ASVS:** 6.3.3 (L2, L3)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py:35-75`
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py` (all endpoints)

### Remediation
**Option 1:** Add TOTP support as second factor using pyotp library. After password validation, check if user has MFA enabled, require TOTP code in request body, verify TOTP code against user secret before issuing JWT.

**Option 2:** Document that production deployments MUST use a pluggable auth manager that supports MFA (e.g., OAuth2/OIDC provider with MFA enforcement).

**Mitigating Context:** This auth manager is explicitly for development/testing, and production deployments should use pluggable auth managers with enterprise SSO/OAuth that enforce MFA externally.

### Acceptance Criteria
- [ ] MFA support added OR production usage documented as prohibited
- [ ] TOTP verification implemented (if Option 1)
- [ ] Documentation updated with MFA requirements

### References
- Source: 6.3.3.md
- CWE-308: Use of Single-factor Authentication

### Priority
**High** - No MFA support for L2+ deployments

---

## Issue: FINDING-012 - No mechanism to terminate sessions after authentication factor change
**Labels:** bug, security, priority:high
**Description:**
### Summary
There is no mechanism to change passwords or terminate active sessions after credential changes, allowing old tokens to remain valid indefinitely after password changes.

### Details
There is no mechanism to change passwords (no password change endpoint exists), update MFA configuration (MFA is not implemented), or terminate other active sessions after any credential change. Even if passwords are manually changed in the password file, there is no mechanism to invalidate existing tokens issued with the old credentials. The system has no concept of a 'credentials changed at' timestamp that could be compared against token issuance time.

**CWE:** CWE-613  
**ASVS:** 7.4.3 (L2, L3)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/` (entire module scope)

**Related Findings:** FINDING-004, FINDING-005, FINDING-013, FINDING-041, FINDING-044

### Remediation
Add password change endpoint with session invalidation. The endpoint should:
1. Verify current password
2. Update password
3. Set per-user invalidation timestamp to invalidate all other sessions
4. Issue new token for current session

Example:
```python
# Add a POST /change-password endpoint that calls:
# - SimpleAuthManagerLogin.verify_credentials()
# - SimpleAuthManager.update_password()
# - set_user_invalidation_time()
# - generate_jwt() to return a new token with other_sessions_terminated flag
```

### Acceptance Criteria
- [ ] Password change endpoint implemented
- [ ] Per-user invalidation timestamp tracked
- [ ] Old tokens rejected after password change
- [ ] Test added verifying session termination

### References
- Source: 7.4.3.md
- CWE-613: Insufficient Session Expiration

### Priority
**High** - No session invalidation on credential change

---

## Issue: FINDING-013 - No logout endpoint or functionality defined
**Labels:** bug, security, priority:high
**Description:**
### Summary
No logout endpoint or functionality is defined anywhere in the provided codebase, preventing users from actively terminating their sessions.

### Details
The login_router contains only token creation endpoints. The FastAPI sub-application mounts the login router and serves UI templates but provides no server-side logout mechanism. Users cannot actively terminate their sessions, meaning: if a user walks away from an unlocked workstation, there's no way to end the session; shared computer scenarios have no mechanism for users to log out; and the session remains valid until natural JWT expiration.

**CWE:** CWE-613  
**ASVS:** 7.4.4, 7.5.2 (L2, L3)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py` (entire file)
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:280-320`

**Related Findings:** FINDING-004, FINDING-005, FINDING-012, FINDING-041, FINDING-044

### Remediation
Add a logout endpoint to the login_router that terminates the user session by clearing the JWT cookie and revoking the token:
```python
@login_router.post("/logout", status_code=status.HTTP_200_OK)
def logout(request: Request) -> Response:
    """Terminate the user session by clearing the JWT cookie and revoking the token."""
    response = Response(
        status_code=200,
        content='{"detail": "Logged out successfully"}'
    )
    response.delete_cookie(
        COOKIE_NAME_JWT_TOKEN,
        path=get_cookie_path(),
    )
    # If token revocation is implemented:
    # token = extract_token_from_request(request)
    # revoke_token(token)
    return response
```

Additionally, ensure the UI includes a visible logout button/link on all authenticated pages.

### Acceptance Criteria
- [ ] POST /logout endpoint implemented
- [ ] JWT cookie cleared on logout
- [ ] Token added to revocation list (if implemented)
- [ ] UI logout button added
- [ ] Test added verifying logout functionality

### References
- Source: 7.4.4.md, 7.5.2.md
- CWE-613: Insufficient Session Expiration

### Priority
**High** - No way to terminate active sessions

---

## Issue: FINDING-014 - No Capability to View Active Sessions
**Labels:** bug, security, priority:high
**Description:**
### Summary
The Simple Auth Manager provides no endpoint, service, or data model for users to view their currently active sessions, preventing detection of unauthorized access.

### Details
The architecture is entirely stateless JWT-based with no server-side session tracking, making it impossible for users to enumerate their active sessions across devices/browsers. Users have no visibility into whether their account has been compromised, and if credentials are stolen or tokens are leaked, the legitimate user cannot detect unauthorized active sessions.

**CWE:** CWE-778  
**ASVS:** 7.5.2 (L2, L3)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py` (N/A)
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:290-310`

### Remediation
Implement server-side session tracking with a SessionStore class that records session metadata (session_id, username, created_at, last_activity, ip_address, user_agent). Add a GET /sessions endpoint that returns all active sessions for the authenticated user. Include a 'jti' (JWT ID) claim in token generation using uuid.uuid4() to uniquely identify each session. Record sessions in the session store during token creation and provide session listing capability through the API endpoint.

### Acceptance Criteria
- [ ] SessionStore class implemented
- [ ] GET /sessions endpoint created
- [ ] JTI claim added to tokens
- [ ] Session metadata tracked (IP, user agent, timestamps)
- [ ] Test added verifying session listing

### References
- Source: 7.5.2.md
- CWE-778: Insufficient Logging

### Priority
**High** - No visibility into active sessions

---

## Issue: FINDING-015 - No Documentation of Field-Level Access Restrictions in the Authorization Model
**Labels:** bug, security, priority:high
**Description:**
### Summary
The authorization documentation and abstract interface define resource-level and method-level access controls but contain no provisions for field-level access restrictions (BOPLA protection).

### Details
There is no documentation or interface method that addresses: which fields within a resource require separate authorization; how field-level read restrictions should be implemented; how field-level write restrictions should work; state-dependent field access rules. Without field-level authorization: users authorized to read connections may see sensitive fields (passwords, extra configuration) they shouldn't access; users authorized to modify a resource may alter security-critical fields; state-dependent access patterns cannot be expressed.

**ASVS:** 8.1.2 (L2)

**Affected Files:**
- `airflow-core/docs/core-concepts/auth-manager/index.rst`
- `airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py`

### Remediation
Add field-level authorization to the auth manager interface by implementing a get_authorized_fields method that returns the set of fields the user is authorized to access. The method should accept resource_type, method, user, and details parameters, returning None if all fields are accessible or a set of field names the user may read/write based on the method. Document field-level rules in the authorization documentation, specifying which fields in resources like Connections (password, extra fields) and Variables require additional authorization beyond resource-level access.

### Acceptance Criteria
- [ ] get_authorized_fields method added to base interface
- [ ] Field-level authorization documented
- [ ] Sensitive field access rules defined
- [ ] Test added verifying field-level restrictions

### References
- Source: 8.1.2.md

### Priority
**High** - No field-level access control framework

---

## Issue: FINDING-016 - No Field-Level Authorization Mechanism Exists in the Auth Manager Framework
**Labels:** bug, security, priority:high
**Description:**
### Summary
The BaseAuthManager class provides no abstract methods, interfaces, or utilities for field-level authorization (BOPLA protection), allowing users with write access to modify security-critical fields.

### Details
Authorization decisions are binary (allow/deny) at the resource level. Once a user is authorized to access a resource, all fields of that resource are accessible for the authorized method. Specific BOPLA risk scenarios include: A user authorized to GET a connection can read the password field; A user authorized to PUT a DAG can modify its owners field; A user authorized to PUT a variable can modify its team_name field (potentially escalating team access).

**CWE:** CWE-639  
**ASVS:** 8.2.3 (L2)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:161-802`

### Remediation
Implement field-level authorization support in the base auth manager by adding methods get_writable_fields and get_readable_fields that return sets of field names the user can access, or None to indicate all fields are accessible (for backward compatibility). These methods should accept resource_type, user, and details parameters to enable context-aware field-level access control decisions.

### Acceptance Criteria
- [ ] get_writable_fields method added
- [ ] get_readable_fields method added
- [ ] Backward compatibility maintained (None = all fields)
- [ ] Test added verifying field-level filtering

### References
- Source: 8.2.3.md
- CWE-639: Authorization Bypass Through User-Controlled Key

### Priority
**High** - No protection against BOPLA attacks

---

## Issue: FINDING-017 - No step-up authentication for highly sensitive multi-team operations
**Labels:** bug, security, priority:high
**Description:**
### Summary
The multi-team documentation describes highly sensitive operations that can modify team boundaries and resource isolation without any mention of step-up authentication or re-verification.

### Details
Highly sensitive operations include: Team deletion (can destroy team isolation boundaries), DAG bundle to team association (can redirect all DAGs to a different team's execution context), Team-scoped executor configuration (can modify execution environments), Team-scoped secrets (can expose cross-team credentials). A compromised admin session (session hijacking, stolen token) can immediately perform destructive operations without additional verification.

**ASVS:** 7.5.3 (L3)

**Affected Files:**
- `airflow-core/docs/core-concepts/multi-team.rst:95-115`
- `airflow-core/docs/core-concepts/multi-team.rst:141-160`

### Remediation
Implement step-up authentication for sensitive multi-team operations. Before performing sensitive team operations, require fresh authentication for destructive operations (e.g., is_recently_authenticated with max_age_seconds=300), and require secondary factor (MFA verification) for team deletion and similar operations.

### Acceptance Criteria
- [ ] Step-up authentication framework implemented
- [ ] Recent authentication check added to sensitive operations
- [ ] MFA verification required for team deletion
- [ ] Test added verifying step-up requirements

### References
- Source: 7.5.3.md

### Priority
**High** - No additional verification for destructive operations

---

## Issue: FINDING-018 - Authorization resource model lacks environmental and contextual attributes for adaptive security controls
**Labels:** bug, security, priority:high
**Description:**
### Summary
The authorization resource model contains no provisions for environmental or contextual attributes, preventing implementation of adaptive security controls based on IP address, time, location, or device.

### Details
None of the resource detail dataclasses include fields for IP address, time of day, location, or device information. This indicates adaptive security controls are not part of the authorization decision framework. Without adaptive controls, the system cannot: detect and respond to compromised credentials used from unusual locations; enforce time-based access restrictions for sensitive operations; challenge suspicious access patterns with step-up authentication; restrict administrative operations to trusted networks/devices.

**ASVS:** 8.2.4, 8.4.2 (L3)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/managers/models/resource_details.py` (entire file)

### Remediation
Add an EnvironmentalContext dataclass that captures environmental attributes for adaptive security decisions including source_ip, user_agent, access_timestamp, geo_location, device_fingerprint, is_trusted_network, and session_start_time. Integrate this context into authorization checks by extending the BaseAuthManager methods to accept an optional EnvironmentalContext parameter.

Example:
```python
@dataclass
class EnvironmentalContext:
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    access_timestamp: Optional[datetime] = None
    geo_location: Optional[str] = None
    device_fingerprint: Optional[str] = None
    is_trusted_network: Optional[bool] = None
    session_start_time: Optional[datetime] = None

# Modify is_authorized_dag and similar methods:
def is_authorized_dag(
    self,
    method: str,
    user: BaseUser,
    details: DagDetails,
    context: Optional[EnvironmentalContext] = None
) -> bool:
    # Contextual evaluation logic
```

### Acceptance Criteria
- [ ] EnvironmentalContext dataclass created
- [ ] Authorization methods accept context parameter
- [ ] Documentation updated with adaptive control examples
- [ ] Test added verifying contextual authorization

### References
- Source: 8.2.4.md, 8.4.2.md

### Priority
**High** - No framework for adaptive security controls

---

## Issue: FINDING-019 - Missing Trusted Proxy Header Validation Middleware
**Labels:** bug, security, priority:high
**Description:**
### Summary
The middleware stack does not include any HTTPSRedirectMiddleware or equivalent logic to reject plaintext HTTP requests on API endpoints, potentially allowing unencrypted API traffic.

### Details
While the absence of automatic HTTP-to-HTTPS redirects at the application layer could be considered compliant (redirects should be at the infrastructure layer), there is no documentation or enforcement that API endpoints should NOT be auto-redirected. The webapp() catch-all route serves HTML over whatever protocol the request arrives on, and no Strict-Transport-Security header middleware is visible.

**CWE:** CWE-290  
**ASVS:** 4.1.3, 4.1.2, 4.2.5, 4.2.3, 4.2.4 (L2, L3)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/core_api/app.py:152-165`

### Remediation
Implement API-specific middleware to reject plaintext HTTP requests on API endpoints instead of redirecting:
```python
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

class APINoRedirectMiddleware(BaseHTTPMiddleware):
    """Reject plaintext HTTP on API endpoints instead of redirecting."""
    async def dispatch(self, request, call_next):
        if (request.url.scheme == "http" 
            and request.url.path.startswith("/api/")
            and request.headers.get("x-forwarded-proto") != "https"):
            return Response(
                content='{"error": "HTTPS required for API endpoints"}',
                status_code=421,
                media_type="application/json"
            )
        return await call_next(request)
```

Additionally, add deployment documentation specifying that reverse proxies must NOT perform transparent HTTP→HTTPS redirects for /api/v2/ paths.

### Acceptance Criteria
- [ ] APINoRedirectMiddleware implemented
- [ ] HTTP 421 returned for plaintext API requests
- [ ] Deployment documentation updated
- [ ] Test added verifying HTTPS enforcement

### References
- Source: 4.1.3.md, 4.1.2.md, 4.2.5.md, 4.2.3.md, 4.2.4.md
- CWE-290: Authentication Bypass by Spoofing

### Priority
**High** - API endpoints may accept plaintext traffic

---

## Issue: FINDING-020 - Authentication events (login success/failure) not documented in event catalog
**Labels:** bug, security, priority:high
**Description:**
### Summary
The comprehensive event catalog documents task events, DAG operations, and user management but critically does not include authentication events such as login success/failure, logout, or session management.

### Details
The following security-critical events are absent from the documented catalog: User login (successful), User login (failed/rejected), User logout, Session creation/destruction, Password change, Multi-factor authentication events, Token issuance/refresh/revocation, Authentication method/factor used, Account lockout events, OAuth/OIDC callback events. Without documented authentication logging, organizations cannot: detect brute-force attacks or credential stuffing, identify compromised accounts through unusual login patterns, meet compliance requirements for authentication audit trails, investigate unauthorized access incidents.

**ASVS:** 16.3.1, 16.3.3 (L2)

**Affected Files:**
- `airflow-core/docs/security/audit_logs.rst` (Event Catalog section)

### Remediation
Add an "Authentication Events" section to the Event Catalog documenting: login_success, login_failed, logout, session_created, session_expired, token_issued, token_refreshed, token_revoked, account_locked, account_unlocked, password_changed, mfa_challenge, mfa_success, mfa_failed. Each authentication event should include: User identity, Authentication method, Source IP, User agent, Result, Timestamp, Session ID (for successful authentications).

### Acceptance Criteria
- [ ] Authentication Events section added to documentation
- [ ] All critical auth events documented
- [ ] Required metadata fields specified
- [ ] Examples provided for each event type

### References
- Source: 16.3.1.md, 16.3.3.md

### Priority
**High** - Critical security events not documented

---

## Issue: FINDING-021 - No documented authorization failure events in the event catalog
**Labels:** bug, security, priority:high
**Description:**
### Summary
The comprehensive Event Catalog documents over 200 event types covering user actions and system events but does not define any events for authorization failures or access denials.

### Details
The catalog covers successful operations (e.g., trigger_dag_run, delete_variable, patch_connection) but does not define corresponding failure events when a user lacks permission to perform these operations. Authorization decisions happen at every API endpoint and UI action, but no logging event is defined for denied requests. Failed authorization attempts—a key indicator of privilege escalation attacks or misconfigured access controls—go undetected.

**ASVS:** 16.3.2 (L2)

**Affected Files:**
- `airflow-core/docs/security/audit_logs.rst:125-250`

### Remediation
Define and implement authorization failure events: authorization_denied (User attempted an action they lack permission for), resource_access_denied (User attempted to access a restricted resource), dag_access_denied (User attempted to access a DAG outside their scope). Each authorization denial log entry should include: User identification, Requested resource, Required permission, Timestamp.

### Acceptance Criteria
- [ ] Authorization failure events defined
- [ ] Required metadata fields specified
- [ ] Documentation updated with examples
- [ ] Implementation guidance provided

### References
- Source: 16.3.2.md

### Priority
**High** - Authorization failures not logged

---

## Issue: FINDING-022 - No documented events for security control bypass attempts
**Labels:** bug, security, priority:high
**Description:**
### Summary
The documentation defines the application's event catalog but does not include any events for detecting or logging attempts to bypass security controls.

### Details
Missing events include: Input validation failures (malformed API requests, injection attempts), Business logic bypasses (attempts to trigger paused DAGs, access past retention periods), Anti-automation violations (rate limit exceeded, excessive login attempts), Authentication failures (invalid credentials, expired tokens). An attacker conducting reconnaissance (probing APIs with invalid inputs, fuzzing parameters, attempting SQL injection) leaves no forensic trail.

**ASVS:** 16.3.3 (L2)

**Affected Files:**
- `airflow-core/docs/security/audit_logs.rst` (Event Catalog section)

### Remediation
Add a Security Events domain with the following events: authentication_failed, input_validation_failed, rate_limit_exceeded, csrf_validation_failed, session_hijack_detected, api_schema_violation, forbidden_parameter_detected.

### Acceptance Criteria
- [ ] Security Events domain added to catalog
- [ ] All bypass attempt events documented
- [ ] Required metadata fields specified
- [ ] Implementation guidance provided

### References
- Source: 16.3.3.md

### Priority
**High** - Attack reconnaissance not logged

---

## Issue: FINDING-023 - No documented events for security infrastructure failures
**Labels:** bug, security, priority:high
**Description:**
### Summary
The documentation does not define audit events for security infrastructure failures such as TLS connection failures, certificate validation errors, or secrets backend unavailability.

### Details
Missing events include: Backend TLS connection failures (to databases, external services, log systems), Certificate validation errors, LDAP/OAuth/SAML provider connectivity failures, Secrets backend unavailability, Encryption/decryption failures (Fernet key issues), Database connection pool exhaustion. If TLS connections to backends silently fail and the system falls back to unencrypted communication, or if the secrets backend becomes unavailable and cached credentials are used past their intended lifetime, no audit trail exists for forensic analysis.

**ASVS:** 16.3.4 (L2)

**Affected Files:**
- `airflow-core/docs/security/audit_logs.rst` (Event Catalog section)

### Remediation
Add Security Infrastructure Events to the event catalog including: tls_connection_failed, certificate_validation_error, auth_provider_unavailable, secrets_backend_error, encryption_failure, security_config_error.

### Acceptance Criteria
- [ ] Security Infrastructure Events section added
- [ ] All infrastructure failure events documented
- [ ] Required metadata fields specified
- [ ] Implementation guidance provided

### References
- Source: 16.3.4.md

### Priority
**High** - Security infrastructure failures not logged

---

## Issue: FINDING-024 - Missing Security Headers Middleware to Prevent Incorrect Content Rendering Context
**Labels:** bug, security, priority:high
**Description:**
### Summary
The middleware stack initialization adds JWT, auth, gzip, and access logging middlewares but includes NO security headers middleware, leaving responses without X-Content-Type-Options, Content-Disposition, or Content-Security-Policy headers.

### Details
There is no: X-Content-Type-Options: nosniff header to prevent MIME-type sniffing, Sec-Fetch-* request header validation to ensure correct request context, Content-Disposition: attachment for API responses that should not be rendered, Response-level Content-Security-Policy header. Data flow: HTTP request → FastAPI routing → Response served WITHOUT security headers.

**ASVS:** 3.2.1, 3.4.4 (L1, L2)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/core_api/app.py:168-183`

### Remediation
Add a security headers middleware to the application initialization:
```python
from starlette.middleware.base import BaseHTTPMiddleware

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

def init_middlewares(app: FastAPI) -> None:
    # ... existing middlewares ...
    app.add_middleware(SecurityHeadersMiddleware)
```

### Acceptance Criteria
- [ ] SecurityHeadersMiddleware implemented
- [ ] X-Content-Type-Options header added
- [ ] Content-Disposition configured for downloads
- [ ] Test added verifying headers

### References
- Source: 3.2.1.md, 3.4.4.md

### Priority
**High** - Missing security headers

---

## Issue: FINDING-025 - Missing Cookie Security Configuration and Documentation Advises Against HttpOnly
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application initialization code shows no configuration for cookie security attributes (Secure flag, __Host-/__Secure- prefix), and documentation explicitly advises proxies NOT to enforce HttpOnly.

### Details
There is no evidence in init_config, init_middlewares, or any other initialization function of setting: Secure flag on cookies, __Host- or __Secure- prefix for cookie names, or cookie configuration for session/auth tokens. The allow_credentials=True in CORS configuration indicates cookies ARE used for authentication, yet their security configuration is not visible. If cookies lack the Secure attribute, they can be transmitted over unencrypted HTTP connections, exposing session tokens.

**ASVS:** 3.3.1 (L1)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/core_api/app.py:144-158`
- `airflow-core/docs/howto/run-behind-proxy.rst:56`

### Remediation
Ensure cookie configuration in the auth system explicitly sets:
```python
response.set_cookie(
    key="__Host-session",
    value=token_value,
    secure=True,
    httponly=True,
    samesite="Lax",
    path="/"
)
```

If JavaScript cookie access is genuinely required, use a split-cookie approach: __Host-session (HttpOnly, Secure) for authentication and __Secure-csrf (non-HttpOnly, Secure) for CSRF token only.

### Acceptance Criteria
- [ ] Cookie Secure flag enforced
- [ ] __Host- prefix used for session cookies
- [ ] HttpOnly flag set (or split-cookie implemented)
- [ ] Documentation updated with cookie security requirements
- [ ] Test added verifying cookie attributes

### References
- Source: 3.3.1.md

### Priority
**High** - Insecure cookie configuration

---

## Issue: FINDING-026 - Missing Strict-Transport-Security (HSTS) Header on All Responses
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application initialization code configures multiple middleware layers but does NOT include any HSTS middleware or response header injection, leaving users vulnerable to SSL stripping attacks.

### Details
No Strict-Transport-Security header is added to responses. The init_config, init_middlewares, and init_views functions are the complete application setup, and none add HSTS. The proxy documentation also does not recommend adding HSTS headers at the application level or proxy level. Without HSTS, an attacker performing a MITM attack can downgrade HTTPS connections to HTTP, intercepting authentication tokens, session cookies, and sensitive workflow data.

**ASVS:** 3.4.1, 3.7.4 (L1, L2, L3)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/core_api/app.py:1-176`

### Remediation
Add HSTS middleware to the application:
```python
from starlette.middleware.base import BaseHTTPMiddleware

class HSTSMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        return response

def init_middlewares(app: FastAPI) -> None:
    # ... existing middleware ...
    app.add_middleware(HSTSMiddleware)
```

Alternatively, document HSTS configuration at the reverse proxy level in run-behind-proxy.rst:
```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

### Acceptance Criteria
- [ ] HSTS header added to responses
- [ ] max-age set to at least 31536000 (1 year)
- [ ] includeSubDomains directive included
- [ ] Documentation updated
- [ ] Test added verifying HSTS header

### References
- Source: 3.4.1.md, 3.7.4.md

### Priority
**High** - Vulnerable to SSL stripping attacks

---

## Issue: FINDING-027 - Missing Content-Security-Policy Response Header
**Labels:** bug, security, priority:high
**Description:**
### Summary
No CSP reporting configuration exists in either the application code or the documentation, preventing detection of XSS attempts, clickjacking, or unauthorized resource loading.

### Details
The only CSP example in the documentation (frame-ancestors 'self') does not include a report-uri or report-to directive. Without CSP violation reporting, the security team cannot detect attempts to inject unauthorized content (XSS probing), identify clickjacking attempts (frame-ancestors violations), detect mixed content or unauthorized resource loading, or monitor for policy regressions during development.

**ASVS:** 3.4.3, 3.4.6, 3.4.7 (L2, L3)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/core_api/app.py:1-176`

### Remediation
Add CSP middleware to the application:
```python
class CSPMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "object-src 'none'; "
            "base-uri 'none'; "
            "frame-ancestors 'self';"
        )
        return response
```

For Level 3, implement per-response nonces:
```python
import secrets

class CSPNonceMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        nonce = secrets.token_urlsafe(16)
        request.state.csp_nonce = nonce
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            f"default-src 'self'; "
            f"script-src 'self' 'nonce-{nonce}'; "
            f"object-src 'none'; "
            f"base-uri 'none';"
        )
        return response
```

### Acceptance Criteria
- [ ] CSP middleware implemented
- [ ] Default policy configured
- [ ] Nonce support added for L3
- [ ] Documentation updated
- [ ] Test added verifying CSP headers

### References
- Source: 3.4.3.md, 3.4.6.md, 3.4.7.md

### Priority
**High** - No CSP protection against XSS

---

## Issue: FINDING-028 - Primary nginx documentation example lacks TLS configuration
**Labels:** bug, security, priority:high
**Description:**
### Summary
The primary reverse proxy example in official documentation configures nginx to listen ONLY on port 80 (HTTP) with no HTTPS listener (port 443) and no HTTP-to-HTTPS redirect.

### Details
The documentation describes the target URL as https://lab.mycompany.com/myorg/airflow/ but the provided configuration does not implement TLS. There is no listen 443 ssl directive, no SSL certificate configuration, no TLS protocol version restrictions (ssl_protocols), and no redirect from HTTP to HTTPS. Users following this guide will deploy Airflow's web interface accessible over plaintext HTTP, exposing authentication credentials and operational data to network-level interception.

**ASVS:** 12.1.1, 12.2.1, 12.2.2 (L1)

**Affected Files:**
- `airflow-core/docs/howto/run-behind-proxy.rst:34-47`

### Remediation
Replace the nginx example with a secure configuration that includes:
1. HTTP to HTTPS redirect on port 80
2. HTTPS listener on port 443 with SSL certificate configuration
3. TLS protocols restricted to TLSv1.2 and TLSv1.3 using ssl_protocols directive
4. Strong cipher suite configuration with server preference enabled
5. HSTS header with max-age=63072000 and includeSubDomains
6. ssl_certificate and ssl_certificate_key directives pointing to publicly trusted certificates

### Acceptance Criteria
- [ ] Documentation example updated with TLS configuration
- [ ] HTTP to HTTPS redirect configured
- [ ] TLS 1.2+ enforced
- [ ] Strong cipher suites configured
- [ ] HSTS header added

### References
- Source: 12.1.1.md, 12.2.1.md, 12.2.2.md

### Priority
**High** - Documentation promotes insecure deployment

---

## Issue: FINDING-029 - No documentation of resource-management strategies including timeouts, retry logic, and backoff algorithms
**Labels:** bug, security, priority:high
**Description:**
### Summary
ASVS 13.1.3 requires documentation of resource-release procedures, timeout settings, failure handling, retry limits, delays, and back-off algorithms for every external system. Neither scheduler nor executor documentation provides this information.

### Details
Missing documentation includes: Database connections - no documented timeout settings, connection recycling (pool_recycle), or connection validation (pool_pre_ping); HTTP connections (to external APIs) - no documented short timeouts for synchronous operations; Retry logic - no documentation of retry limits, exponential backoff, or circuit breaker patterns; Resource release - no documented connection disposal or cleanup procedures; Thread/process management - no documentation of thread pool sizes or process limits for the scheduler.

**ASVS:** 13.1.3 (L3)

**Affected Files:**
- `airflow-core/docs/administration-and-deployment/scheduler.rst` (entire document)
- `airflow-core/docs/core-concepts/executor/index.rst` (entire document)

### Remediation
Create a 'Resource Management' documentation section covering:
1. **Database Connections** - document pool size (sql_alchemy_pool_size, default: 5), max overflow (sql_alchemy_max_overflow, default: 10), connection timeout (sql_alchemy_pool_timeout, default: 30s), connection recycling (sql_alchemy_pool_recycle, default: 1800s), pre-ping validation (sql_alchemy_pool_pre_ping, default: True), and retry logic
2. **HTTP Connections (External APIs)** - document default timeout (30s, configurable per hook), retry strategy (3 retries with exponential backoff: 1s, 2s, 4s), and circuit breaker status
3. **Message Broker (Celery)** - document connection timeout (broker_connection_timeout, default: 4s), retry on startup (broker_connection_retry_on_startup, default: True), and max retries

### Acceptance Criteria
- [ ] Resource Management section added to documentation
- [ ] All timeout values documented
- [ ] Retry strategies documented
- [ ] Connection pool settings documented
- [ ] Cleanup procedures documented

### References
- Source: 13.1.3.md

### Priority
**High** - Missing critical operational documentation

---

## Issue: FINDING-030 - No documentation of critical secrets or rotation schedules
**Labels:** bug, security, priority:high
**Description:**
### Summary
Neither scheduler nor executor documentation defines the secrets critical for security or provides a rotation schedule for any of Airflow's critical secrets.

### Details
Undocumented critical secrets include: Fernet key (fernet_key) — used to encrypt Connection passwords in the metadata database; JWT signing key — used for internal Execution API authentication; Database credentials — metadata database authentication; Broker credentials — message broker authentication; Webserver secret key (secret_key) — used for Flask session signing; LDAP/OAuth client secrets; Cloud provider credentials. Without documented secrets and rotation schedules: Compromised secrets may go unrotated indefinitely; Operators lack guidance on which secrets are most critical to protect; Compliance requirements cannot be met without documented rotation policies.

**ASVS:** 13.1.4 (L3)

**Affected Files:**
- `airflow-core/docs/administration-and-deployment/scheduler.rst` (entire document)
- `airflow-core/docs/core-concepts/executor/index.rst` (entire document)

### Remediation
Create a dedicated 'Secrets Management' documentation section with a table defining critical secrets including: fernet_key (Connection encryption, 90 days rotation, Multi-key rotation), webserver.secret_key (Session signing, 90 days rotation, Rolling restart), JWT signing key (Internal API auth, 30 days rotation, Key rotation API), Database password (Metadata DB access, 90 days rotation, Coordinated update), Broker password (Message queue auth, 90 days rotation, Coordinated update). Include a Rotation Procedures section documenting step-by-step rotation for each secret.

### Acceptance Criteria
- [ ] Secrets Management section added
- [ ] All critical secrets documented
- [ ] Rotation schedules defined
- [ ] Rotation procedures documented
- [ ] Multi-key rotation explained for Fernet

### References
- Source: 13.1.4.md

### Priority
**High** - No secrets rotation guidance

---

## Issue: FINDING-031 - Missing Sender-Constrained Access Token Verification (No mTLS or DPoP)
**Labels:** bug, security, priority:high
**Description:**
### Summary
The token validation process treats JWT tokens as bearer tokens with no sender-constraining mechanism, allowing stolen access tokens to be replayed by any party.

### Details
Specifically: No mTLS binding - no cnf (confirmation) claim verification to bind the token to a client certificate thumbprint; No DPoP verification - no DPoP proof header processing or jkt claim verification; Token generation does not embed any sender-constraining claims (cnf.x5t#S256 or cnf.jkt); No abstract method provided for subclasses to implement sender-constraining. A stolen JWT token can be replayed by any party that obtains it (e.g., via network interception, log exposure, or browser compromise).

**ASVS:** 10.3.5 (L3)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:140-155`
- `airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:743-770`

### Remediation
Implement sender-constrained token verification in the get_user_from_token method. Add parameters for client_cert_thumbprint and dpop_proof. Verify mTLS binding by checking the cnf.x5t#S256 claim against the presented client certificate thumbprint. Verify DPoP binding by checking the cnf.jkt claim and validating the DPoP proof header. Modify token generation in generate_jwt and _get_token_signer to embed sender-constraining claims.

### Acceptance Criteria
- [ ] mTLS binding verification implemented
- [ ] DPoP support added
- [ ] Sender-constraining claims embedded in tokens
- [ ] Documentation updated
- [ ] Test added verifying token binding

### References
- Source: 10.3.5.md

### Priority
**High** - No protection against token replay

---

## Issue: FINDING-032 - Auto-generated symmetric key undersized for HS512 algorithm per RFC 7518
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The auto-generated key has 128 bits of entropy (16 random bytes), but RFC 7518 Section 3.2 mandates a minimum of 512 bits (64 bytes) of key material for HS512.

### Details
When no [api_auth] jwt_secret is configured (common in initial deployments or development-to-production transitions), the auto-generated key violates the algorithm specification. While 128 bits prevents practical brute-force, the HMAC security proof requires key length ≥ hash output length for full security guarantees.

**CWE:** CWE-326  
**ASVS:** 11.6.1 (L2)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/tokens.py:467`

**Related Findings:** FINDING-142, FINDING-143

### Remediation
Generate 64 bytes (512 bits) to match HS512 requirements per RFC 7518:
```python
secret_key = base64url_encode(os.urandom(64))
```

### Acceptance Criteria
- [ ] Key generation changed to 64 bytes
- [ ] RFC 7518 compliance verified
- [ ] Test added verifying key size

### References
- Source: 11.6.1.md
- CWE-326: Inadequate Encryption Strength

### Priority
**Medium** - Key undersized per RFC spec

---

## Issue: FINDING-033 - No explicit token type claim prevents definitive type differentiation at the cryptographic layer
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Token generation does not include an explicit 'typ' or 'token_type' claim in standard claims, potentially allowing cross-service token acceptance when audience validation is disabled.

### Details
If the REST API audience is not configured (default is None per documentation), a token generated by the Execution API generator could potentially pass validation by the REST API validator. The 'audience' claim would be 'urn:airflow.apache.org:task' but if the REST API validator has 'audience=None', PyJWT skips audience validation entirely. The 'scope' claim is only enforced at the route level rather than at the JWTValidator core validation layer.

**CWE:** CWE-287  
**ASVS:** 9.2.2 (L2)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/tokens.py:382-398`

### Remediation
The JWTValidator should allow callers to specify required claims including token type at the validation layer. Add a 'required_scope' parameter to JWTValidator and validate it in the 'avalidated_claims' method. Additionally, ensure REST API tokens include an explicit scope/type claim when generating tokens. Set a default REST API audience to ensure audience validation is active by default. Add startup validation warning when 'jwt_audience' or 'jwt_issuer' is not configured.

### Acceptance Criteria
- [ ] Token type claim added to generation
- [ ] required_scope parameter added to validator
- [ ] Default audience configured
- [ ] Startup warning added for missing config
- [ ] Test added verifying type differentiation

### References
- Source: 9.2.2.md
- CWE-287: Improper Authentication

### Priority
**Medium** - Token type not cryptographically enforced

---

## Issue: FINDING-034 - REST API audience defaults to None, potentially allowing cross-service token acceptance
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The REST API audience defaults to None, and when unconfigured, tokens are issued without the aud claim entirely, potentially allowing cross-service token acceptance.

### Details
The documentation confirms both REST API and Execution API share the same signing key infrastructure. The Execution API sets a default audience (urn:airflow.apache.org:task), but the REST API audience defaults to None. If a deployment uses the same private key for both APIs without configuring [api_auth] jwt_audience, REST API tokens are generated without audience restriction. While the Execution API validator would reject tokens missing its expected audience, a misconfigured REST API validator could accept Execution API tokens cross-service.

**CWE:** CWE-346  
**ASVS:** 9.2.3, 9.2.4 (L2)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/tokens.py:227`
- `airflow-core/src/airflow/api_fastapi/auth/tokens.py:394-398`

**Related Findings:** FINDING-144

### Remediation
**Option 1** — Enforce non-empty audience at validator instantiation: Add an attrs validator to the JWTValidator.audience field that raises ValueError if the value is falsy.

**Option 2** — Provide a sensible default audience: Change the configuration default for jwt_audience from None to 'urn:airflow.apache.org:api'.

**Option 3** — Warn at startup when audience is unconfigured (minimum): In __attrs_post_init__, log a warning if self.audience is falsy.

### Acceptance Criteria
- [ ] Audience validation enforced or default set
- [ ] Startup warning added for missing config
- [ ] Documentation updated
- [ ] Test added verifying audience requirement

### References
- Source: 9.2.3.md, 9.2.4.md
- CWE-346: Origin Validation Error

### Priority
**Medium** - Cross-service token acceptance possible

---

## Issue: FINDING-035 - No Minimum Password Length Validation Mechanism Exists
**Labels:** bug, security, priority:medium
**Description:**
### Summary
While auto-generated passwords are 16 characters, there is no password length validation/enforcement mechanism anywhere in the codebase, allowing manually edited password files to contain passwords of any length.

### Details
The password file can be manually edited to contain passwords of any length, and the authentication flow only checks for non-empty passwords. If the password file is manually provisioned (e.g., via simple_auth_manager_passwords_file config pointing to a custom file), short passwords are silently accepted. The system provides no guardrail against weak passwords.

**CWE:** CWE-521  
**ASVS:** 6.2.1 (L1, L2, L3)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:313`
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py:50-54`

**Related Findings:** FINDING-010, FINDING-036, FINDING-037, FINDING-146

### Remediation
Implement password length validation utility:
```python
MIN_PASSWORD_LENGTH = 8  # ASVS minimum; 15 recommended

def validate_password_length(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters"
        )

@staticmethod
def _generate_password() -> str:
    password = "".join(random.choices(
        "abcdefghkmnpqrstuvwxyzABCDEFGHKMNPQRSTUVWXYZ23456789", k=16
    ))
    validate_password_length(password)  # Defense in depth
    return password
```

### Acceptance Criteria
- [ ] Password length validation function created
- [ ] Minimum length enforced (8+ characters)
- [ ] Validation applied to all password setting paths
- [ ] Test added verifying length requirement

### References
- Source: 6.2.1.md
- CWE-521: Weak Password Requirements

### Priority
**Medium** - No validation for manually set passwords

---

## Issue: FINDING-036 - No Context-Specific Word Checking Implemented for Password Validation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The system has no documented list of context-specific words and performs no validation against such a list, allowing administrators to manually set weak passwords like "airflow" or "admin123".

### Details
While auto-generated random passwords are unlikely to match context-specific terms, the system provides no defense if: The password file is manually edited with weak/contextual passwords, A password change mechanism is added in the future without this validation, or The generated password accidentally forms a dictionary word. An administrator can manually set a password in the JSON file (e.g., {"admin": "airflow"}) and the system will accept this without any warning or rejection.

**CWE:** CWE-521  
**ASVS:** 6.2.11 (L2, L3)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:312`

**Related Findings:** FINDING-010, FINDING-035, FINDING-037, FINDING-146

### Remediation
Implement a password validation function that checks against context-specific words:
```python
CONTEXT_SPECIFIC_WORDS = {
    "airflow", "apache", "admin", "password", 
    "workflow", "dag", "scheduler"
}

def _validate_password(password: str, username: str) -> bool:
    password_lower = password.lower()
    
    # Check username not in password
    if username.lower() in password_lower:
        return False
    
    # Check context-specific words
    for word in CONTEXT_SPECIFIC_WORDS:
        if word in password_lower:
            return False
    
    return True
```

### Acceptance Criteria
- [ ] Context-specific word list defined
- [ ] Password validation function created
- [ ] Username check included
- [ ] Test added verifying word blocking

### References
- Source: 6.2.11.md
- CWE-521: Weak Password Requirements

### Priority
**Medium** - No protection against contextual passwords

---

## Issue: FINDING-037 - No Breached Password Checking Implemented During Password Creation or Authentication
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The system never checks passwords against known breached password databases (e.g., Have I Been Pwned), preventing detection of compromised credentials.

### Details
While auto-generated random 16-character passwords have an astronomically low probability of appearing in breach databases, the architectural gap means: If a password is later discovered in a breach, the system cannot detect this; If the password file is manually populated with known-breached passwords, no warning is generated; No proactive monitoring of credential compromise exists.

**CWE:** CWE-521  
**ASVS:** 6.2.12, 6.2.4 (L2, L3, L1)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:312`
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py:36-78`

**Related Findings:** FINDING-010, FINDING-035, FINDING-036, FINDING-146

### Remediation
Implement breach checking using the k-anonymity approach (HIBP API):
```python
import hashlib
import aiohttp

async def check_password_breached(password: str) -> bool:
    """Check if password appears in known breaches using k-anonymity."""
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    
    async with aiohttp.ClientSession() as session:
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        async with session.get(url) as response:
            if response.status == 200:
                hashes = await response.text()
                return suffix in hashes
    return False
```

Apply during password generation in init() to regenerate passwords found in breach databases.

### Acceptance Criteria
- [ ] HIBP API integration implemented
- [ ] k-anonymity approach used
- [ ] Breached passwords rejected
- [ ] Test added verifying breach checking

### References
- Source: 6.2.12.md, 6.2.4.md
- CWE-521: Weak Password Requirements

### Priority
**Medium** - No breach database checking

---

## Issue: FINDING-038 - Built-in "Anonymous" Admin Account Active When simple_auth_manager_all_admins is Enabled
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Any network-reachable client can obtain full admin access without any authentication when the simple_auth_manager_all_admins configuration is enabled.

### Details
The _create_anonymous_admin_user() method creates a hardcoded user with username "Anonymous" and role "ADMIN" that grants JWT tokens with full admin privileges to any requester with NO credentials. While documented as a development feature, if this configuration is inadvertently deployed or left as default, it provides complete bypass of all authentication and authorization.

**CWE:** CWE-798  
**ASVS:** 6.3.2 (L1, L2, L3)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py:83-96`

### Remediation
1. Log a clear warning when this mode is active
2. Add a startup check that prevents this mode when not in DEBUG
3. Bind to localhost only when all_admins is enabled

Implementation:
```python
import warnings

if is_simple_auth_manager_all_admins:
    if not conf.getboolean("core", "unit_test_mode", fallback=False):
        warnings.warn(
            "simple_auth_manager_all_admins is enabled in a non-test environment. "
            "This provides unauthenticated admin access to all endpoints.",
            SecurityWarning,
            stacklevel=2,
        )
```

### Acceptance Criteria
- [ ] Startup warning added
- [ ] Production mode check implemented
- [ ] Documentation warning added
- [ ] Test added verifying warning

### References
- Source: 6.3.2.md
- CWE-798: Use of Hard-coded Credentials

### Priority
**Medium** - Dangerous development feature

---

## Issue: FINDING-039 - Generated passwords printed to stdout/logs in plaintext
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The SimpleAuthManager generates passwords and prints them to stdout/logs during initialization, and has no secure password reset/recovery mechanism.

### Details
The SimpleAuthManager: 1) Generates passwords and stores them in a JSON file in plaintext, 2) Prints passwords to stdout/logs during initialization, 3) Has no mechanism for password reset/recovery, 4) Has no identity verification for password changes (editing the file directly is the only recovery mechanism), 5) Uses random.choices() (non-cryptographic PRNG) for password generation. If a user loses their password, the only recovery is to directly edit the plaintext password file on the server filesystem with no identity proofing whatsoever.

**CWE:** CWE-532  
**ASVS:** 6.4.1, 6.4.4 (L1, L2, L3)

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:145-147`
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:305-313`

### Remediation
Since this is a dev/test auth manager, add a prominent warning and runtime safety check. Add a startup warning or configuration validation that flags simple_auth_manager_all_admins=True or SimpleAuthManager usage when the deployment appears to be production (e.g., multiple workers, non-localhost bind, database is PostgreSQL/MySQL). Add production safety check for SimpleAuthManager to prevent its use in production environments.

### Acceptance Criteria
- [ ] Startup warning added for production use
- [ ] Production detection implemented
- [ ] Documentation warning added
- [ ] Test added verifying warning

### References
- Source: 6.4.1.md, 6.4.4.md
- CWE-532: Insertion of Sensitive Information into Log File

### Priority
**Medium** - Development-only feature needs safeguards

---

## Issue: FINDING-040 - No password reset mechanism exists — users cannot recover access
**Labels:** bug, security, priority:medium
**Description:**
### Summary
No /forgot-password, /reset-password, or similar endpoint exists, leaving users who lose their password with no application-level recovery path.

### Details
Users who lose their password have no application-level recovery path. The only recovery is server-side manual intervention (editing the JSON password file or restarting Airflow to regenerate). For ASVS Level 2 compliance, a secure reset process that does not bypass MFA is required. Since neither a reset mechanism nor MFA exists, this requirement cannot be satisfied.

**CWE:** CWE-640  
**ASVS:** 6.4.3 (L2, L3)

**Affected Files:**
- `routes/login.py`
- `services/login.py`
- `simple_auth_manager.py`

### Remediation
Add a password reset flow:
```python
@login_router.post('/token/reset-password')
def reset_password(
    body: ResetPasswordBody,
    current_user: SimpleAuthManagerUser = Depends(get_current_user)
):
    if (not SimpleAuthManager._is_admin(current_user) 
        and body.username != current_user.username):
        raise HTTPException(status_code=403, detail='Insufficient privileges')
    
    new_password = secrets.token_urlsafe(16)
    store_password_with_expiry(
        body.username,
        new_password,
        expires_in=timedelta(hours=1)
    )
    
    return {
        'message': 'Password reset. New temporary password must be '
                  'changed on first login.'
    }
```

### Acceptance Criteria
- [ ] Password reset endpoint implemented
- [ ] Temporary password generation with expiry
- [ ] Admin or self-service reset supported
- [ ] Test added verifying reset flow

### References
- Source: 6.4.3.md
- CWE-640: Weak Password Recovery Mechanism for Forgotten Password

### Priority
**Medium** - No password recovery mechanism

## Issue: FINDING-041 - No Inactivity Timeout Mechanism — Only Absolute Token Expiration
**Labels:** bug, security, priority:medium
**Description:**
### Summary
User authenticates and receives a JWT issued with fixed exp claim. The token remains valid for the entire duration regardless of activity, with no server-side activity tracking. If a user authenticates and then walks away from their workstation, the session remains valid for the entire token lifetime (potentially hours) regardless of inactivity.

### Details
An attacker with physical or network access to the session can use it without triggering any re-authentication. This is a Type A gap where no inactivity timeout control exists. The only timeout is absolute expiration (jwt_expiration_time).

**CWE:** CWE-613  
**ASVS:** 7.3.1 (L2, L3)

### Remediation
Implement one of the following options:

**Option 1:** Short-lived access tokens with refresh token pattern
- Access token: 15 minutes
- Refresh token: checked against last-activity timestamp

**Option 2:** Server-side session activity tracking
```python
class SessionActivityTracker:
    def check_inactivity(self, user_id: str, max_idle_minutes: int = 30) -> bool:
        last_activity = self.get_last_activity(user_id)
        if datetime.utcnow() - last_activity > timedelta(minutes=max_idle_minutes):
            return False  # Session expired due to inactivity
        self.update_last_activity(user_id)
        return True
```

**Option 3:** Configurable in settings
```ini
[api_auth]
jwt_expiration_time = 900  # 15 min access token (short absolute timeout)
jwt_inactivity_timeout = 1800  # 30 min inactivity (if server-side tracking)
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py:35-100
- Related findings: FINDING-004, FINDING-005, FINDING-012, FINDING-013, FINDING-044

### Priority
Medium

---

## Issue: FINDING-042 - No re-authentication mechanism for sensitive account modifications
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The Simple Auth Manager does not implement any sensitive account modification endpoints and lacks any framework for requiring re-authentication before sensitive operations. There is no re-authentication endpoint or utility, no step-up authentication mechanism, no freshness check on tokens, and no `auth_time` claim in the JWT.

### Details
While the Simple Auth Manager is a development tool with limited account management features, the complete absence of re-authentication infrastructure means that if sensitive operations are added later, there's no mechanism to protect them. In the current state, the role and team claims in JWTs are immutable for the token lifetime — a user whose role is upgraded/downgraded will continue operating with the old role until token expiration.

**CWE:** CWE-306  
**ASVS:** 7.5.1 (L2, L3)

### Remediation
Add auth_time claim to tokens for freshness verification:
```python
def serialize_user(self, user: SimpleAuthManagerUser) -> dict[str, Any]:
    return {
        "sub": user.username, 
        "role": user.role, 
        "teams": user.teams,
        "auth_time": int(time.time()),
    }
```

Add re-authentication dependency for sensitive operations:
```python
def require_recent_auth(max_age_seconds: int = 300):
    """Require authentication within the last N seconds for sensitive operations."""
    def dependency(token: dict = Depends(get_current_token)):
        auth_time = token.get("auth_time", 0)
        if time.time() - auth_time > max_age_seconds:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Re-authentication required for this operation"
            )
    return Depends(dependency)
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- airflow-core/src/airflow/api_fastapi/auth/managers/simple/ (entire module scope)
- Related findings: FINDING-043

### Priority
Medium

---

## Issue: FINDING-043 - No Re-authentication Required for Security-Sensitive Operations
**Labels:** bug, security, priority:medium
**Description:**
### Summary
ASVS 7.5.2 explicitly requires that users authenticate again 'with at least one factor' before terminating sessions. The current codebase has no re-authentication mechanism or pattern that could be applied. There is no verify_password() or reauthenticate() method, no re-authentication dependency or middleware, and no endpoint that accepts current_password for verification before sensitive actions.

### Details
Without re-authentication before session termination, an attacker who has hijacked a session could terminate the legitimate user's other sessions, enabling lock-out attacks while maintaining their own hijacked access.

**CWE:** CWE-306  
**ASVS:** 7.5.2 (L2, L3)

### Remediation
Implement a verify_password() method in SimpleAuthManagerLogin class that validates username and password for re-authentication. Create a get_reauthenticated_user() dependency that requires users to provide their current password in addition to their valid JWT token before performing sensitive operations. Apply this dependency to session termination endpoints using FastAPI's Depends() mechanism. Add rate limiting (e.g., 5 attempts per minute) to prevent brute force attacks on re-authentication. Include a ReauthRequest Pydantic model to accept password in request body for re-authentication flows.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py
- airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py
- Related findings: FINDING-042

### Priority
Medium

---

## Issue: FINDING-044 - No Mechanism to Invalidate Previous Session Tokens on Re-Authentication
**Labels:** bug, security, priority:medium
**Description:**
### Summary
When a user re-authenticates (e.g., after password change, role change, or suspicious activity), previously issued tokens remain valid until their natural expiration. This creates a window where: 1) Compromised tokens cannot be revoked, 2) Multiple concurrent valid sessions exist without visibility, 3) Role/permission changes don't take immediate effect.

### Details
The authentication logic generates new JWTs but does not invalidate or revoke previously issued tokens, allowing them to remain valid until expiry.

**CWE:** CWE-613  
**ASVS:** 7.2.4 (L1, L2, L3)

### Remediation
Implement token revocation using one of two approaches:

**Option 1:** Implement a JTI (JWT ID) blacklist - Add unique JWT IDs to each token and maintain a server-side revocation list that invalidates all existing tokens for a user on re-authentication.

**Option 2:** Use very short-lived access tokens (≤15 minutes) with a refresh token mechanism and invalidate refresh tokens on re-authentication.

Add a function like invalidate_user_tokens() that is called before generating new tokens.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py:35-74
- Related findings: FINDING-004, FINDING-005, FINDING-012, FINDING-013, FINDING-041

### Priority
Medium

---

## Issue: FINDING-045 - Multiple Authentication Pathways Lack Consolidated Documentation of Security Strength Enforcement
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The documentation identifies multiple authentication pathways (JWT API token via POST /auth/token, cookie-based UI token exchange, pluggable auth manager login URLs, and token refresh via middleware) but does not provide a consolidated section that enumerates all authentication pathways in a single reference table, specifies the required authentication strength for each pathway, or documents how security controls are consistently enforced across them.

### Details
Without consolidated documentation, implementers of custom auth managers may not understand which security controls must be consistently applied across all pathways. This could lead to auth managers that have inconsistent security between pathways.

**ASVS:** 6.1.3 (L2)

### Remediation
Add a consolidated authentication pathways table to the documentation that includes: Pathway, Authentication Strength, and Required Controls columns. The table should document Login URL (UI), POST /auth/token (API), Cookie token exchange, and Token refresh pathways with their respective security controls (CSRF, rate limiting, account lockout, httponly, secure, path-scoped, absolute timeout check, revocation). Include a note that all pathways MUST enforce equivalent authentication strength and auth manager implementations MUST NOT allow a weaker pathway to bypass controls of a stronger one.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- airflow-core/docs/core-concepts/auth-manager/index.rst (entire file)

### Priority
Medium

---

## Issue: FINDING-046 - Insufficient Documentation of Session Lifetime Coordination with Federated Identity Providers
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The documentation references federated identity management (Keycloak SSO integration) and describes token refresh mechanics, but does not document how Airflow JWT session lifetimes should be coordinated with the external IdP session lifetime, what happens when the IdP session expires but the Airflow JWT is still valid, how session termination at the IdP level propagates to Airflow, or re-authentication conditions beyond simple token expiration.

### Details
Without documented requirements for session lifetime coordination, auth manager implementers may issue indefinitely-refreshable Airflow tokens without checking IdP session validity, user deactivation or session revocation at the IdP level may not propagate to Airflow in a timely manner, and no documented absolute session timeout means sessions could theoretically persist indefinitely through continuous refresh.

**ASVS:** 7.1.3 (L2)

### Remediation
Add federated session management documentation that requires auth manager implementations to document and enforce:
1. Absolute session timeout via jwt_absolute_timeout configuration (recommended 8-12 hours)
2. IdP session validation in refresh_user implementation via refresh token checking, IdP session cookie/state verification, or IdP userinfo/introspection endpoint calls
3. Session termination propagation by revoking outstanding Airflow tokens and denying token refresh requests when users are deactivated or IdP sessions are terminated
4. Re-authentication conditions including absolute session timeout exceeded, external IdP session expired/revoked, significant user permission changes, and security-sensitive operations

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- airflow-core/docs/core-concepts/auth-manager/index.rst (Token refresh section, lines referencing Keycloak)
- airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:231-240

### Priority
Medium

---

## Issue: FINDING-047 - No Documented Absolute Session Timeout Separate from JWT Expiration
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The BaseAuthManager uses jwt_expiration_time as the only session lifetime control. Combined with refresh_user (which can issue new tokens from expired ones), there is no documented or enforced absolute session timeout. The token generator does not include or enforce an iat (issued-at) based absolute timeout that persists across refreshes.

### Details
Without an absolute session timeout, sessions can be extended indefinitely through continuous refresh, compromised tokens maintain access until explicitly revoked, and federated SSO session invalidation may not propagate in bounded time.

**ASVS:** 7.1.3 (L2)

### Remediation
Document the requirement and provide implementation guidance by adding a session_start parameter to generate_jwt that tracks when original authentication occurred, including a session_start claim in the JWT token. Auth managers should check this claim during refresh to enforce absolute session timeouts. Add configuration documentation for jwt_absolute_session_timeout setting (default 28800 seconds/8 hours) to enforce maximum session duration regardless of refresh activity.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:212-216
- airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:779-791

### Priority
Medium

---

## Issue: FINDING-048 - Authorization Documentation Describes Mechanisms But Lacks Concrete Policy Rules
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The documentation provides an implementer's guide for the pluggable auth manager interface, describing available authorization methods and their parameters. However, it does not define concrete authorization policy rules that specify which consumer roles/types can access which functions, default-deny posture requirements for implementations, required minimum authorization granularity for each resource type, or mapping between the three-tier trust model (Deployment Managers, DAG Authors, Authenticated UI Users) and specific is_authorized_* outcomes.

### Details
Without defined policy rules, different auth manager implementations may apply inconsistent authorization decisions, potentially granting excessive access. Developers implementing custom auth managers have no authoritative reference for what access patterns should be allowed or denied for each trust tier.

**ASVS:** 8.1.1 (L1)

### Remediation
Create a security policy document (or section in this documentation) that explicitly maps: Each resource type to the trust tiers that should have access, Required granularity (e.g., DAGs must enforce per-DAG-ID access), Default posture (deny-by-default requirement), Method-level restrictions per trust tier. Example: Authorization Policy Rules section with a table mapping Resource types (Configuration, Connection, DAG, etc.) to trust tiers (Deployment Manager, DAG Author, Authenticated UI User) with explicit Allowed/Denied rules for each combination.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- airflow-core/docs/core-concepts/auth-manager/index.rst (Entire document)

### Priority
Medium

---

## Issue: FINDING-049 - Optional `details` Parameter Allows Resource-Type-Level Authorization Bypass Potential
**Labels:** bug, security, priority:medium
**Description:**
### Summary
All authorization methods accept `details` as an optional parameter with `None` as default. This design creates an ambiguity: a call with `details=None` asks "can the user access this resource type at all?" without specifying a specific resource. If API endpoints incorrectly use `details=None` where a specific resource check is needed, it could bypass data-specific authorization.

### Details
If an API endpoint that modifies a specific connection calls `is_authorized_connection(method="PUT", user=user)` without providing `details=ConnectionDetails(conn_id=target_id)`, the auth manager might approve access based on general permission without validating access to the specific resource.

**ASVS:** 8.2.1 (L1)

### Remediation
Document that `details=None` MUST NOT grant broader access than an explicit resource check, and consider adding runtime validation:

```python
def _validate_details_for_mutation(self, method: str, details: Any) -> None:
    """Ensure mutation operations always specify target resource details."""
    if method in ("PUT", "DELETE", "POST") and details is None:
        raise ValueError(
            f"Authorization check for method {method} must specify resource details"
        )
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:242-395

### Priority
Medium

---

## Issue: FINDING-050 - Missing Session Management Policy Documentation
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The multi-team documentation extensively covers resource isolation, executor configuration, and team management, but contains no documentation of session management policies including session inactivity timeout values, absolute maximum session lifetime, justification for any deviations from NIST SP 800-63B re-authentication requirements, how session policies vary between regular users and administrators, or how team-scoped access interacts with session lifetime.

### Details
Without documented session policies, implementations may use default values that are inappropriate for the security posture of multi-team deployments. There is no reference to NIST SP 800-63B compliance or justification for deviations.

**ASVS:** 7.1.1 (L2, L3)

### Remediation
Add a session management section to the multi-team documentation (or a separate session management document) that:
1. Documents inactivity timeout (e.g., 15 minutes for admin, 30 minutes for regular users)
2. Documents absolute session lifetime (e.g., 8 hours)
3. Justifies any deviations from NIST SP 800-63B (Section 7.2)
4. Documents how team membership changes affect active sessions
5. Documents interaction with SSO/IdP session policies (especially for Keycloak auth manager)

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- airflow-core/docs/core-concepts/multi-team.rst (entire file scope)

### Priority
Medium

---

## Issue: FINDING-051 - Missing Concurrent Session Policy Documentation
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The provided documentation does not define how many concurrent (parallel) sessions are allowed per account, whether concurrent session limits differ between regular users and administrators, what behavior occurs when the maximum number of sessions is reached, or how concurrent sessions interact with multi-team access.

### Details
Without documented concurrent session policies: Credential compromise may go undetected (attacker maintains parallel session); Resource contention from unlimited sessions could impact availability; Team isolation boundaries could be weakened if users maintain multiple sessions with different team contexts.

**ASVS:** 7.1.2 (L2, L3)

### Remediation
Document concurrent session policy including:
- Maximum concurrent sessions per user (e.g., 3)
- Behavior at maximum (e.g., oldest session is terminated with notification)
- Multi-team context handling (e.g., a single session covers all authorized teams; users do not need separate sessions per team)
- Admin account limits (e.g., limited to 1 concurrent session for security)

Example documentation: 'Concurrent Session Policy: Maximum concurrent sessions per user: 3; Behavior at maximum: Oldest session is terminated with notification; Multi-team context: A single session covers all authorized teams; users do not need separate sessions per team; Admin accounts: Limited to 1 concurrent session for security'

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- airflow-core/docs/core-concepts/multi-team.rst (entire file scope)

### Priority
Medium

---

## Issue: FINDING-052 - Session management not included in authorization resource model
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The resource details model does not include a session-related resource entity. The `AccessView` enum lists available views but does not include a `SESSIONS` or `USER_SESSIONS` view. The `DagAccessEntity` enum covers DAG-level entities but there is no equivalent enum for session management entities.

### Details
This suggests that session termination may not be modeled as an authorization-controlled operation in the resource model, which could mean: (1) No granular permission for "terminate other user's session" exists, (2) Admin session termination is not governed by the same RBAC framework as other operations.

**ASVS:** 7.4.5 (L2, L3)

### Remediation
Add session management to the resource model by:
1. Adding a `SESSIONS` entry to the `AccessView` enum
2. Creating a `SessionDetails` dataclass with fields for session_id, user_id, and team_name to represent session details for admin management

Example:
```python
SESSIONS = "SESSIONS"

@dataclass
class SessionDetails:
    session_id: str
    user_id: str
    team_name: str | None = None
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- airflow-core/src/airflow/api_fastapi/auth/managers/models/resource_details.py

### Priority
Medium

---

## Issue: FINDING-053 - Resource details model does not distinguish operation sensitivity levels
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The resource details model does not distinguish between read operations and highly sensitive write/delete operations at the model level. All team operations use the same TeamDetails dataclass regardless of whether the operation is a benign read or a destructive modification.

### Details
This means the authorization framework cannot easily enforce step-up authentication for specific operation types. Without sensitivity levels in the resource model, the auth manager cannot distinguish between operations requiring standard authentication versus those requiring step-up verification.

**ASVS:** 7.5.3 (L3)

### Remediation
Add operation sensitivity metadata to the TeamDetails dataclass, such as a requires_step_up boolean field that can be set by calling code for destructive operations to enable the auth manager to distinguish operations requiring standard authentication versus those requiring step-up verification.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- airflow-core/src/airflow/api_fastapi/auth/managers/models/resource_details.py

### Priority
Medium

---

## Issue: FINDING-054 - Missing documentation for federated session lifetime and re-authentication behavior
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The multi-team documentation references Keycloak as a compatible auth manager for federated authentication but does not document session lifetime behavior between Airflow (RP) and the IdP (Keycloak), re-authentication requirements when IdP session expires, maximum time between IdP authentication events, behavior when IdP session is terminated, or token refresh behavior for federated sessions.

### Details
Without documented federated session behavior: A user's IdP session may expire while their Airflow session remains active, violating the principle that IdP is the authority for authentication state, Users terminated from the IdP may retain active Airflow sessions, Team membership changes in the IdP may not be reflected in active Airflow sessions.

**ASVS:** 7.6.1 (L2, L3)

### Remediation
Document federated session behavior including:
- RP session lifetime bounded by [webserver] session_lifetime_minutes
- IdP re-authentication required every [auth] max_idp_session_age seconds (default: 3600)
- Airflow RP session invalidated via back-channel logout when IdP session terminates
- Team membership changes reflected at next token refresh (within [auth] token_refresh_interval)
- NIST SP 800-63C compliance with FAL2 - assertion freshness validated at each sensitive operation

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- airflow-core/docs/core-concepts/multi-team.rst:100-108

### Priority
Medium

---

## Issue: FINDING-055 - Authorization Documentation Missing Environmental/Contextual Attributes
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The application's authorization documentation does not define any environmental or contextual attributes (time of day, user location, IP address, device type, geolocation) that are used in security decisions pertaining to authentication and authorization.

### Details
Without documented environmental/contextual attributes, operators cannot consistently configure or verify adaptive security controls. Security decisions are limited to identity and role without environmental context, which is insufficient for Level 3 compliance.

**ASVS:** 8.1.3, 8.1.4 (L3)

### Remediation
Create a dedicated security architecture document that defines:

**Environmental and Contextual Security Attributes**

The following attributes are evaluated during authentication and authorization:

**Time-based Attributes**
- Time of day: Administrative operations restricted to business hours (configurable)
- Session duration: Absolute session timeout of [X] hours

**Network-based Attributes**
- Source IP address: Used for allow/deny list enforcement
- Network location: Internal vs. external network detection
- VPN status: Required for administrative access

**Device-based Attributes**
- Device trust level: Managed vs. unmanaged device detection
- Client certificate presence: For service-to-service authentication

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- airflow-core/docs/core-concepts/multi-team.rst (entire file)
- airflow-core/docs/security/deprecated_permissions.rst (entire file)

### Priority
Medium

---

## Issue: FINDING-056 - Undocumented Authorization Change Propagation in Multi-Team Environment
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The multi-team documentation does not describe what happens when authorization changes occur (team membership changes, resource reassignment, team deletion). There is no documentation or visible mechanism for immediate revocation of access when a user is removed from a team, immediate effect of resource reassignment between teams, session invalidation when permissions change, or alerting/reverting actions when stale authorization is used.

### Details
If authorization changes are not applied immediately, a user removed from a team could continue accessing team-scoped resources (Variables containing secrets, Connections containing credentials) until their session expires.

**ASVS:** 8.3.2 (L3)

### Remediation
Document and implement authorization change propagation:
1. Immediate enforcement - All subsequent API requests check current permissions from the metadata database (not cached)
2. Active session handling - Sessions are re-validated against current permissions on each request
3. Running tasks - Tasks already scheduled continue with original permissions but new scheduling uses updated permissions
4. Alerting - Changes that affect currently active users generate audit events

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- airflow-core/docs/core-concepts/multi-team.rst

### Priority
Medium

---

## Issue: FINDING-057 - Undocumented permission propagation through scheduler intermediary
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The multi-team architecture documentation describes a chain where the scheduler resolves team membership and selects executors on behalf of users, but does not clearly document how the originating subject's permissions are preserved through the execution chain. Specifically: 1) The scheduler acts as an intermediary between the user and task execution, 2) Tasks inherit team association through the chain (Task → Dag → Bundle → Team), 3) There's no documentation of how a task accessing secrets backends uses the originating user's permissions vs. the scheduler's service permissions.

### Details
Data Flow: User triggers DAG run → Scheduler (service account) resolves team → Executor runs task → Task accesses secrets backend → Authorization check uses ??? permissions. If access to team-scoped resources during task execution is based on the scheduler's service permissions rather than the originating user's permissions, it could allow unauthorized access to resources.

**ASVS:** 8.3.3 (L3)

### Remediation
Document the permission propagation model explicitly: When a task accesses team-scoped resources:
1. The task's team is determined by the DAG Bundle association (structural)
2. The task can access resources scoped to its team regardless of which user triggered the run
3. Access control for who can TRIGGER a DAG run is enforced at the API level using the originating user's permissions
4. The separation of concerns is: API layer: User's permissions determine what DAGs they can trigger; Execution layer: Task's team determines what resources it can access

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- airflow-core/docs/core-concepts/multi-team.rst

### Priority
Medium

---

## Issue: FINDING-058 - Incomplete Multi-Tenant Cross-Tenant Controls with Information Leakage Risk
**Labels:** bug, security, priority:medium
**Description:**
### Summary
While multi-team resource isolation is documented and the resource model includes team_name fields, the documentation explicitly acknowledges that this is an experimental feature with incomplete isolation. Several gaps in cross-tenant controls are identifiable: (1) Global uniqueness requirement creates information leakage risk - Dag IDs, Variable keys, and Connection IDs must be unique across the entire Airflow deployment, (2) Shared metadata database without documented database-level row security, (3) Incomplete coverage - documentation lists missing functionality, (4) Optional team_name field means authorization logic must consistently handle both None (global) and team-scoped scenarios.

### Details
Dag IDs, Variable keys, and Connection IDs must be unique across the entire Airflow deployment, meaning one team can determine what identifiers another team uses through naming conflicts. Cross-tenant data access relies entirely on application-layer enforcement.

**ASVS:** 8.4.1 (L2, L3)

### Remediation
1. For the namespace information leakage: Return generic 'already exists' without revealing owning team (e.g., raise ConflictError('Variable key already exists') NOT 'Variable key belongs to team_b')
2. For comprehensive coverage: Document and enforce cross-tenant control verification at every data access point including: All database queries for team-scoped resources include team_name filter, UI endpoints filter response data by team membership, API responses never include resources from other teams, Async operations (triggers, callbacks) inherit team from parent DAG

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- airflow-core/docs/core-concepts/multi-team.rst
- airflow-core/src/airflow/api_fastapi/auth/managers/models/resource_details.py

### Priority
Medium

---

## Issue: FINDING-059 - Administrative CLI operations lack multi-layered security controls
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The multi-team documentation describes administrative operations (team creation, deletion, resource assignment, executor configuration) that are managed via CLI and configuration files. The documentation does not describe any multi-layered security controls for these administrative interfaces beyond basic auth manager authorization.

### Details
There is no mention of: continuous identity verification during administrative sessions, device security posture assessment, contextual risk analysis (e.g., geographic location, time-of-day, behavioral patterns), or step-up authentication for destructive admin operations. Administrative operations that affect team isolation boundaries can be performed with only basic authentication.

**ASVS:** 8.4.2 (L3)

### Remediation
For Level 3 compliance, administrative interfaces should implement:
1. MFA/step-up authentication for administrative operations
2. Device posture checks (e.g., managed device verification)
3. Contextual risk scoring (unusual time, location, or behavior triggers additional verification)
4. Session binding to reduce session hijacking risk

Add admin operation verification in auth manager base with methods to verify session freshness, assess device posture, and calculate contextual risk scores.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- airflow-core/docs/core-concepts/multi-team.rst:95-115

### Priority
Medium

---

## Issue: FINDING-060 - Authorization Dependency Consumes Unvalidated Raw Body Input
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The authorization dependency reads `dag_id` directly from the raw JSON body without validating its type or format. The Pydantic validation in the actual endpoint handler runs as a parallel dependency, meaning the authorization check may operate on unvalidated data.

### Details
If `dag_id` is a non-string value (e.g., `null`, array, integer), the authorization check could produce incorrect results. Authorization decisions may be made with incorrect context when the raw body contains unexpected types, potentially allowing requests to pass authorization checks before Pydantic validation rejects them.

**CWE:** CWE-20  
**ASVS:** 2.2.2 (L1)

### Remediation
Add type validation before using team_name in authorization checks. Example:
```python
if raw is not None and not isinstance(raw, str):
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="team_name must be a string"
    )
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- airflow-core/src/airflow/api_fastapi/core_api/security.py:248-258

### Priority
Medium

---

## Issue: FINDING-061 - Flask Plugin Mount Bypasses FastAPI Trusted Service Layer
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The Flask application mounted via `WSGIMiddleware` creates a parallel trust boundary that bypasses all FastAPI-level security controls. The Flask/FAB application relies entirely on its own validation and authentication mechanisms, which may have different validation rules, different authentication schemes, or gaps in coverage compared to the primary FastAPI application.

### Details
Any legacy Airflow 2 plugin endpoints at `/pluginsv2/*` operate outside the FastAPI trusted service layer, creating an inconsistent security posture across the application.

**CWE:** CWE-1188  
**ASVS:** 2.2.2 (L1)

### Remediation
Add authentication middleware wrapper to verify authentication before routing to Flask, ensure Flask app has equivalent validation middleware, or document security responsibility boundary explicitly. Long-term: develop migration plan to eliminate Flask plugin mount and create FastAPI-native plugin system with unified validation.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- airflow-core/src/airflow/api_fastapi/core_api/app.py:98-125

### Priority
Medium

---

## Issue: FINDING-062 - No per-message digital signatures for highly sensitive operations
**Labels:** security, priority:medium
**Description:**
### Summary
There is no implementation of per-message digital signatures for highly sensitive operations. The application handles connection credentials, variable values, DAG trigger operations, and backfill operations. None of these operations implement request body signing.

### Details
The authentication relies solely on JWT bearer tokens, which authenticate the sender but do not provide non-repudiation for individual requests, integrity verification of request bodies, or protection against token replay with modified payloads. For Level 3 compliance, highly sensitive operations lack per-message integrity verification beyond transport-layer TLS.

**ASVS:** 4.1.5 (L3)

### Remediation
Implement HTTP Message Signatures (RFC 9421) or HMAC-based request signing for sensitive mutation endpoints. Example implementation:

```python
from fastapi import Header, HTTPException
import hmac
import hashlib

async def verify_request_signature(
    request: Request,
    x_signature: str = Header(None),
    x_signature_timestamp: str = Header(None),
):
    """Verify HMAC signature for sensitive operations."""
    if not x_signature or not x_signature_timestamp:
        raise HTTPException(400, "Missing request signature headers")
    
    body = await request.body()
    signing_input = f"{x_signature_timestamp}.{body.decode()}"
    expected = hmac.new(
        app.state.request_signing_key, 
        signing_input.encode(), 
        hashlib.sha256
    ).hexdigest()
    
    if not hmac.compare_digest(x_signature, expected):
        raise HTTPException(401, "Invalid request signature")
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- airflow-core/src/airflow/api_fastapi/core_api/security.py (entire file)
- airflow-core/src/airflow/api_fastapi/core_api/app.py

### Priority
Medium

---

## Issue: FINDING-063 - JWKS Endpoint Supports Unencrypted HTTP, Enabling Key Injection via MITM
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The Execution API is explicitly described as an internal, HTTP-based service used for communication between Airflow components. The documentation never mentions TLS as a requirement for this internal communication, describes the connection as "HTTP requests" without specifying HTTPS, provides no configuration for enforcing TLS on the Execution API server, and documents no mechanism to prevent fallback to unencrypted HTTP.

### Details
Without TLS enforcement, all internal communication between workers and the Execution API server—including JWT tokens, connection credentials, variables, and XCom data—could be transmitted in cleartext. This violates ASVS 12.3.3's requirement that all HTTP-based internal services use TLS.

**ASVS:** 12.3.1, 12.3.3 (L2)

### Remediation
Add explicit TLS configuration and enforcement documentation:

**Transport Security**

All Execution API communication between workers and the API server must use TLS. Configure the Execution API URL with an https:// scheme:

```ini
[execution_api]
url = https://scheduler.internal:8443
```

The server must be configured to reject unencrypted HTTP connections on the Execution API port. Use [execution_api] tls_cert_path and [execution_api] tls_key_path to configure the server certificate.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- airflow-core/docs/security/jwt_token_authentication.rst (Signing and Cryptography section)

### Priority
Medium

---

## Issue: FINDING-064 - No Certificate Validation Documented for Worker HTTP Client
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The Configuration Reference section documents all JWT-related configuration parameters but includes no parameters for: specifying trusted internal CA certificates for Execution API TLS connections, configuring certificate pinning for known internal services, restricting which CAs are trusted for internal service certificates, or specifying self-signed certificate trust stores.

### Details
Without these configurations, deployments must rely on system CA bundles or disable certificate verification entirely, neither of which satisfies ASVS 12.3.4's requirement to trust only specific internal CAs for internal service communication.

**ASVS:** 12.3.2, 12.3.4 (L2)

### Remediation
Document that the worker HTTP client must validate server certificates. Include configuration guidance for internal CA certificates:

The httpx.Client used by workers validates the Execution API server's TLS certificate against the system CA bundle by default. For deployments using internal CAs, configure [execution_api] ca_cert_path to point to the internal CA certificate bundle.

**Warning:** Never set verify=False in production. This disables all certificate validation and exposes tokens to interception.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- airflow-core/docs/security/jwt_token_authentication.rst (Token delivery to workers section)

### Priority
Medium

---

## Issue: FINDING-065 - No Application-Layer Allowlist for Outbound Communication Destinations
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The documentation describes the Execution API communication architecture comprehensively but does NOT describe any allowlist mechanism that restricts which hosts/endpoints workers are permitted to contact, which external resources the `trusted_jwks_url` parameter can reference, or which systems the application can make outbound requests to.

### Details
The `trusted_jwks_url` configuration accepts arbitrary URLs without URL validation, domain allowlisting, or SSRF protection. Without an application-layer allowlist for outbound communications: (1) A compromised worker could potentially communicate with arbitrary external systems for data exfiltration, (2) The `trusted_jwks_url` could be configured to point to an attacker-controlled JWKS endpoint if configuration injection is possible, (3) No defense-in-depth exists if network-level controls are misconfigured or absent.

**ASVS:** 13.2.4 (L2)

### Remediation
Implement an application-layer allowlist for outbound connections, particularly for:
1. The `trusted_jwks_url` parameter (validate against allowed URL patterns/domains)
2. Worker-to-API communication (restrict to known Execution API endpoints)

Example: URL allowlist validation for trusted_jwks_url using ALLOWED_JWKS_SCHEMES = {"https", "file"} and ALLOWED_JWKS_DOMAINS to validate parsed URLs before use.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- airflow-core/docs/security/jwt_token_authentication.rst

### Priority
Medium

---

## Issue: FINDING-066 - Cryptographic Operations Performed In-Process Without Isolated Security Module
**Labels:** security, priority:medium
**Description:**
### Summary
The Fernet encryption documentation describes cryptographic operations (encryption/decryption of connection passwords and variables) performed within the Airflow application process, with key material loaded directly into application memory. There is no documentation or support for performing these operations within an isolated security module (HSM, vault transit engine, or KMS).

### Details
Key material exists in application memory and is accessible to any code running in the same process (including DAG code, plugins, and any compromised libraries). For L3 deployments requiring hardware-backed solutions, this architecture does not meet the requirement. This is an L3 requirement acceptable for L2 if Fernet keys are properly protected, but there is no documented path to using transit encryption as an alternative.

**ASVS:** 13.3.3 (L3)

### Remediation
For L3 compliance, document and support a KMS-backed encryption mode:

**Hardware-Backed Encryption (L3)**

For deployments requiring hardware-backed cryptographic operations, configure Airflow to use a KMS-backed encryption backend instead of local Fernet:

- HashiCorp Vault Transit Engine
- AWS KMS with envelope encryption
- GCP Cloud KMS
- Azure Key Vault

This ensures key material never leaves the security boundary of the HSM/KMS.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- airflow-core/docs/security/secrets/fernet.rst

### Priority
Medium

---

## Issue: FINDING-067 - Database Connection Documentation Omits TLS/SSL Configuration for Sensitive Data in Transit
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The documentation for setting up production database backends does not include or require TLS/SSL configuration (sslmode=require for PostgreSQL, ssl=true/ssl_mode=REQUIRED for MySQL). While the Fernet documentation covers encryption at rest, the database setup documentation does not address encryption in transit as a required control for the protection level of sensitive metadata.

### Details
Deployments following this documentation may transmit encrypted-but-observable database traffic over unencrypted connections. Data flow: User follows documentation → configures database connection → connection string lacks sslmode=require or equivalent → sensitive metadata transmitted in plaintext over the network.

**ASVS:** 14.2.4 (L2)

### Remediation
Add explicit guidance about log access controls and sensitive data handling:

**WARNING:** SQLAlchemy echo=True logging may expose query parameters containing sensitive data. If enabled, ensure log access is restricted to authorized personnel, logs are stored in encrypted storage, and log retention follows your organization's data protection policy.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- airflow-core/docs/howto/set-up-database.rst:135-138
- airflow-core/docs/howto/set-up-database.rst:194-195

### Priority
Medium

---

## Issue: FINDING-068 - No Defined Automatic Retention Schedule for Sensitive Metadata
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The documentation acknowledges the existence of database cleanup tooling (airflow db clean and airflow.utils.db_cleanup) but does not define: 1) A data retention classification scheme for different types of sensitive data, 2) An automatic/scheduled cleanup mechanism (the tools require manual invocation), 3) Retention periods for different data categories, 4) Automatic expiration policies for encrypted credentials stored in the metadata database.

### Details
Without a defined retention classification and automatic deletion schedule, sensitive data (including encrypted connection credentials for decommissioned systems, historical task execution records containing sensitive parameters, and audit data) accumulates indefinitely in the metadata database. This increases the blast radius of a database compromise and violates the principle of data minimization.

**ASVS:** 14.2.7 (L3)

### Remediation
Document and implement a retention classification with policies based on sensitivity. Define retention periods for connection credentials (review quarterly), task instance records (retain for N days based on compliance), audit logs (minimum 1 year), and variables (periodic review with secrets backends with TTL preferred). Configure automatic cleanup using airflow db clean command in scheduler crontab or DAG with appropriate --clean-before-timestamp parameters.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- airflow-core/docs/howto/set-up-database.rst:253-259

### Priority
Medium

---

## Issue: FINDING-069 - Incomplete Data Sensitivity Classification Schema
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The documentation identifies sensitive data through keyword matching (access_token, api_key, password, etc.) but does not establish formal protection levels. The classification is binary — either a value matches a sensitive keyword or it doesn't. There is no documented tiering such as Level 1: PII, Level 2: Credentials, Level 3: Cryptographic material.

### Details
The masking scope table reveals that some data classified as sensitive receives inconsistent treatment. For example, a variable containing 'keyfile_dict' is only masked in the Variables UI — not in logs or rendered templates. Without formal protection levels, data that should receive the highest protection may receive inconsistent controls.

**ASVS:** 14.1.1 (L2)

### Remediation
Create a formal data classification document that:
1. Defines explicit protection levels (e.g., PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED)
2. Maps each sensitive keyword category to a protection level
3. Ensures all data at the same protection level receives identical masking scope

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- airflow-core/docs/security/secrets/mask-sensitive-values.rst:23-25
- airflow-core/docs/security/secrets/mask-sensitive-values.rst:42-53

### Priority
Medium

---

## Issue: FINDING-070 - No Documented Protection Requirements Per Sensitivity Level
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The documentation describes masking behavior but does not define protection requirements per sensitivity level as required by ASVS 14.1.2. Required elements absent include: encryption requirements, integrity verification, retention policies, logging requirements, database-level encryption, privacy-enhancing technologies, and access controls around sensitive data in logs.

### Details
Without documented protection requirements per level, implementation teams cannot verify whether the controls applied are sufficient. For example, a private_key value receives the same masking treatment as an api_key — there's no documented requirement that private keys should additionally be encrypted at rest or have restricted access.

**ASVS:** 14.1.2 (L2)

### Remediation
Create a protection requirements matrix with columns for Protection Level, Encryption, Masking, Log Retention, Access Control, and Integrity. Define levels such as:
- RESTRICTED (AES-256, Always masked, 7 days retention, Admin only access, HMAC integrity)
- CONFIDENTIAL (AES-256, Always masked, 30 days retention, Role-based access, Checksum integrity)
- INTERNAL (TLS only, Masked in logs, 90 days retention, Authenticated access, N/A integrity)
- PUBLIC (Optional encryption, Never masked, 1 year retention, Any access, N/A integrity)

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- airflow-core/docs/security/secrets/mask-sensitive-values.rst (entire document)

### Priority
Medium

---

## Issue: FINDING-071 - Documented Environment Variable Exposure to External Processes
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The documentation acknowledges that secrets passed via environment variables to external processes (like Kubernetes pods) are: (1) Not masked by Airflow's masking system, (2) Visible to anyone with process-level access, (3) Effectively sent to an external execution environment outside Airflow's control.

### Details
While this is documented as a warning, there is no technical control preventing users from passing secrets via environment variables to operators that spawn external processes. Data Flow: DAG author sets env var → Operator passes to external process → Secrets visible in process environment → No masking applied. Sensitive credentials could be exposed in Kubernetes pod specifications, container runtimes, or process listings.

**ASVS:** 14.2.3 (L2)

### Remediation
Beyond documentation:
1. Consider adding a linting rule or DAG validation check that warns when environment variables match sensitive keywords
2. Document in the protection requirements that secrets passed to external processes must use native secret management (K8s Secrets, vault injection)

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- airflow-core/docs/security/secrets/mask-sensitive-values.rst:95-102

### Priority
Medium

---

## Issue: FINDING-072 - Incomplete technology stack layer mapping in logging inventory
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
While the document provides a substantial inventory of logged events, it does not explicitly map logging at each discrete layer of the technology stack (e.g., web server/reverse proxy layer, application framework layer, ORM/database layer, infrastructure/OS layer).

### Details
The document distinguishes between "Audit Logs" (database) and "Event Logs" (files/external systems) but doesn't provide a layered architecture view showing what logging occurs at each technology boundary. The document lacks: Reverse proxy/load balancer logging documentation, Operating system audit logging, Database server query logging, Container/orchestrator layer logging, Network-level logging.

**ASVS:** 16.1.1 (L2)

### Remediation
Add a section explicitly mapping each technology layer in the deployment architecture to its logging configuration. Include a table with columns for Layer, Technology, Log Source, Events Captured, Storage, and Retention. Document logging for Reverse Proxy (Nginx/HAProxy), Application (Web and Audit), Database (PostgreSQL), and Operating System (Linux/auditd) layers with specific configurations and retention periods.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- airflow-core/docs/security/audit_logs.rst (entire document)

### Priority
Medium

---

## Issue: FINDING-073 - Missing "where" metadata in audit log schema - no source IP or component identifier
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The documented audit log schema includes "when" (dttm), "who" (owner), and "what" (event, dag_id, task_id, etc.), but lacks explicit "where" metadata. There is no documented field for: Source IP address of the request, Client/interface used (Web UI, REST API, CLI), Server/component that generated the log entry, or Session identifier for correlating multiple actions.

### Details
Without source IP and interface identification, forensic investigation cannot determine the origin of malicious actions. An attacker who compromises credentials cannot be traced to their network location. Timeline correlation across distributed systems is hindered without component identifiers.

**ASVS:** 16.2.1 (L2)

### Remediation
Add explicit "where" fields to the documented schema:
- source_ip: IP address from which the request originated for API/UI actions
- interface: The interface through which the action was performed (web_ui, rest_api, cli, system)
- component: The Airflow component that generated the log (webserver, scheduler, worker, triggerer)
- session_id: Session identifier for correlating multiple actions in a single session

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- airflow-core/docs/security/audit_logs.rst (Anatomy of an Audit Log Entry section)

### Priority
Medium

---

## Issue: FINDING-074 - No documentation of time synchronization requirements for logging components
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
While the document states that the `dttm` field uses "UTC timezone," there is no documentation of: Requirements for NTP synchronization across all Airflow components, How time synchronization is verified or enforced, What happens when distributed components have clock drift, or Configuration for ensuring consistent time sources.

### Details
For a distributed system with multiple components (scheduler, webserver, workers, triggerers, dag-processor), time synchronization is critical. Without documented time synchronization requirements, clock drift between components could make event timelines unreliable and hinder forensic investigations.

**ASVS:** 16.2.2 (L2)

### Remediation
Add a section on time synchronization:

**Time Synchronization Requirements**

All Airflow components (webserver, scheduler, workers, triggerer, dag-processor) MUST synchronize their system clocks using NTP or equivalent time synchronization protocol. Maximum acceptable clock drift between any two components is 1 second.

All audit log timestamps (`dttm`) are recorded in UTC. The application uses `datetime.now(timezone.utc)` for all audit log timestamp generation to ensure consistency regardless of the server's local timezone configuration.

For Kubernetes deployments, ensure that all pods use the cluster's time synchronization mechanism. For bare-metal/VM deployments, configure NTP pointing to reliable time sources.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- airflow-core/docs/security/audit_logs.rst (Anatomy of an Audit Log Entry section)

### Priority
Medium

---

## Issue: FINDING-075 - No documented mechanism to verify logs are only sent to inventoried destinations
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The document identifies where logs are stored (database `log` table, `$AIRFLOW_HOME/logs/`, external systems) but does not document: (1) A mechanism to enforce that logs are ONLY sent to approved destinations, (2) How to verify that no additional/unauthorized log sinks exist, (3) Configuration validation to prevent log exfiltration, (4) How custom logging configurations are audited against the inventory.

### Details
Without enforcement mechanisms, logs containing sensitive data (connection details, variable values, user actions) could be inadvertently or maliciously sent to unauthorized destinations, violating data protection requirements.

**ASVS:** 16.2.3 (L2)

### Remediation
Add documentation of destination control including: Log Destination Governance section that documents centrally managed logging configuration through airflow.cfg and logging_config_class setting, list of approved log destinations (Audit Logs in metadata database log table, Task Logs in configured remote logging backend or local filesystem, Component Logs in local filesystem or configured syslog forwarding), requirement that any modification to log destinations requires updating the inventory, verification process using 'airflow config list' command to verify active logging configuration matches documented inventory, and requirement that custom logging handlers added via logging_config_class must be reviewed and documented before deployment.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- airflow-core/docs/security/audit_logs.rst (throughout)

### Priority
Medium

---

## Issue: FINDING-076 - No documented common logging format standard or correlation mechanism
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The document describes audit log fields stored in a relational database but does not: reference a common logging format standard (CEF, OCSF, JSON Lines, W3C Extended Log Format); document how logs from different components can be correlated (no trace ID, request ID, or correlation ID); describe how the audit log format maps to the format expected by log processors (SIEM systems); or specify the format for event logs.

### Details
Without a common format and correlation mechanism, distributed Airflow deployments cannot effectively correlate events across components. A single user action may generate audit entries across webserver, scheduler, and worker components without a linking identifier.

**ASVS:** 16.2.4 (L2)

### Remediation
Document a log format and correlation mechanism. When exported via REST API, audit logs should use JSON format compatible with common SIEM systems with fields including timestamp, event_type, actor, resource, source_ip, correlation_id, and component. All API requests should generate a X-Request-ID header that is included in both audit and event logs, enabling correlation of a single user action across multiple log entries and components. Event logs should use a Python logging format that includes request_id for correlation.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- airflow-core/docs/security/audit_logs.rst (throughout)

### Priority
Medium

---

## Issue: FINDING-077 - No documentation of sensitive data access logging (L3 requirement)
**Labels:** bug, security, priority:medium
**Description:**
### Summary
For ASVS L3, all authorization decisions must be logged, including when sensitive data is accessed (without logging the sensitive data itself). The documentation shows get_* events like get_dag, get_pool, but does not document whether connection credential access, variable value retrieval, or Fernet key operations generate audit entries that note sensitive data was accessed without including the data.

### Details
The Event Catalog shows Variable operations (delete_variable, patch_variable, post_variable, bulk_variables) but no event like get_variable to log reads of potentially secret variables, and no documentation that the extra field excludes sensitive values. Sensitive data access goes unaudited; compliance with data governance frameworks (GDPR, SOC2) is incomplete.

**ASVS:** 16.3.2 (L3)

### Remediation
Document and implement sensitive data access logging events (e.g., get_variable for variable reads, get_connection_credentials for connection access) that capture when sensitive data is accessed without logging the sensitive data itself. Ensure the extra field explicitly excludes sensitive values and document this behavior.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- airflow-core/docs/security/audit_logs.rst (Event Catalog section)

### Priority
Medium

---

## Issue: FINDING-078 - Event logs vs audit logs distinction creates blind spots for security failures
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The documentation explicitly separates audit logs (stored in database) from event logs (stored in files/external systems) and states event logs have 'Short to medium-term (days to weeks)' retention. Security control failures that manifest as application errors would typically appear only in event logs, not audit logs, meaning they have short retention and may not be available for forensic analysis.

### Details
Security control failures logged only in event logs may be purged before an incident is detected, destroying forensic evidence.

**ASVS:** 16.3.4 (L2)

### Remediation
Document mandatory log transmission to a separate system for production deployments with TLS requirements. Ensure security control failures are captured in audit logs with long-term retention (months to years) rather than only in event logs. Document log retention policies aligned with compliance requirements specifying minimum retention periods.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- airflow-core/docs/security/audit_logs.rst (Audit Logs vs Event Logs section)

### Priority
Medium

---

## Issue: FINDING-079 - No documentation of log encoding or injection prevention measures
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The documentation describes how to create custom audit log entries and the structure of log entries but makes no mention of: Input sanitization before logging, Encoding of user-supplied values in log entries, Protection against log injection (newline injection, CRLF, format string attacks), or Safe handling of the `extra` field which accepts arbitrary content.

### Details
The custom event example shows direct insertion of user-supplied strings without sanitization guidance. Without documented encoding requirements, developers creating custom events or extending the logging system may introduce log injection vulnerabilities. Attackers could forge log entries, corrupt log analysis tools, or inject malicious content into SIEM systems.

**ASVS:** 16.4.1 (L2)

### Remediation
Add a "Log Security" section to the documentation that specifies: All data written to audit logs must be properly encoded; User-supplied values in `owner` and `extra` fields are automatically sanitized to prevent log injection attacks; Newline characters (`\n`, `\r`) are escaped in all log fields; The `extra` field is JSON-encoded, preventing format string attacks; HTML/XML special characters are escaped before transmission to external systems. Include guidance that when creating custom audit log entries, use the provided `Log` model which handles encoding automatically. Never construct log entries by string concatenation.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- airflow-core/docs/security/audit_logs.rst (Custom Events section, Anatomy section)

### Priority
Medium

---

## Issue: FINDING-080 - Event log file protection not documented
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Audit logs are stored in the `log` table within the same metadata database used by the Airflow application. The documentation notes the `Audit Logs.can_read` permission for UI access but does not address: Database-level access controls preventing the application from modifying existing log entries, Write-once/append-only constraints on the `log` table, Separation of log database from operational database, or Protection against administrators clearing the log table.

### Details
A user with database write access (which the Airflow application itself has) could `DELETE FROM log` or `UPDATE log SET event = 'success' WHERE event = 'failed'`. Log integrity cannot be guaranteed when stored in the same database the application has full write access to. A compromised Airflow component could silently alter its own audit trail.

**ASVS:** 16.4.2 (L2)

### Remediation
Implement database-level access controls preventing the application from modifying existing log entries, add write-once/append-only constraints on the `log` table, separate log database from operational database, add protection against administrators clearing the log table, and implement log integrity verification (checksums, hash chains, or digital signatures on log entries).

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- airflow-core/docs/security/audit_logs.rst (Querying Event Logs section)

### Priority
Medium

## Issue: FINDING-081 - External log transmission documented as optional without security requirements
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The documentation mentions external logging systems but presents them as optional integrations without any security requirements for transmission. The Elasticsearch example uses HTTP (not HTTPS), suggesting insecure transmission is acceptable. No documentation addresses requirement for TLS when transmitting logs externally, authentication to external log systems, ensuring audit logs (not just event logs) are transmitted, verifying log delivery (handling transmission failures), or that the default configuration stores logs locally (same system as application). Without mandatory secure transmission to a separate system, logs remain vulnerable to compromise if the Airflow deployment is breached.

### Details
- **CWE:** None specified
- **ASVS Sections:** 16.4.3
- **ASVS Levels:** L2
- **Affected Files:**
  - `airflow-core/docs/security/audit_logs.rst` (External Logging Systems section)

### Remediation
Production deployments MUST transmit audit logs to a logically separate system: All log transmission MUST use TLS 1.2 or higher; Authentication to the log collection system MUST be configured; Log delivery failures MUST be detected and alerted upon; The separate log system MUST NOT be accessible from the Airflow application with write/delete permissions. Recommended configurations: Syslog over TLS to a dedicated SIEM, Direct integration with cloud-native log services (CloudWatch, Cloud Logging) using IAM roles with append-only permissions, Kafka-based log streaming with TLS and authentication.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 16.4.3.md

### Priority
Medium

---

## Issue: FINDING-082 - Custom executor module loading without sanitization guidance
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The documentation explicitly describes and encourages loading arbitrary Python modules via configuration. User/admin configuration (airflow.cfg) allows specifying arbitrary Python module paths that are dynamically loaded and executed. The documentation does not describe any validation, allowlisting, or integrity checking of custom executor module paths before they are dynamically loaded. If the configuration file or the configuration source is compromisable, this becomes an arbitrary code execution vector.

### Details
- **CWE:** CWE-94
- **ASVS Sections:** 1.3.2
- **ASVS Levels:** L1
- **Affected Files:**
  - `airflow-core/docs/core-concepts/executor/index.rst` (lines 31-35)

### Remediation
Document that executor module paths should be restricted to a known allowlist in production deployments, and recommend filesystem integrity monitoring on airflow.cfg. Add security guidance to the 'Writing Your Own Executor' section regarding safe deserialization and input validation requirements. Implement executor module allowlisting at the configuration level, restricting dynamic imports to pre-approved packages.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 1.3.2.md

### Priority
Medium

---

## Issue: FINDING-083 - Pickle deserialization support documented without safety controls
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The documentation explicitly describes pickle deserialization support as an executor feature: 'supports_pickling: Whether or not the executor supports reading pickled Dags from the Database before execution (rather than reading the Dag definition from the file system)'. Python's pickle module is explicitly documented as insecure for untrusted data. The documentation describes this as an executor compatibility attribute without prescribing any safety controls such as allowlists of permitted object types during deserialization, integrity verification (signatures) of pickled data before deserialization, or use of safer serialization alternatives (JSON, Protocol Buffers).

### Details
- **CWE:** CWE-502
- **ASVS Sections:** 1.5.2
- **ASVS Levels:** L2
- **Affected Files:**
  - `airflow-core/docs/core-concepts/executor/index.rst` (within Compatibility Attributes section)

### Remediation
1. Document that pickle-based DAG loading should be disabled in production (supports_pickling = False). 2. If pickle support is retained, document required controls: database access restrictions, DAG integrity verification, and type allowlisting during deserialization. 3. Consider deprecating pickle support in favor of the serialized DAG representation already mentioned in the scheduler documentation.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 1.5.2.md

### Priority
Medium

---

## Issue: FINDING-084 - Missing Input Validation Rules Documentation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application's documentation does not define input validation rules for how to check the validity of data items against expected structures. Documentation files (scheduler.rst and executor/index.rst) are operational deployment and architecture documentation but do not define input validation rules for data items such as: DAG configuration parameter formats (e.g., cron expressions, schedule intervals), executor module path validation patterns, or configuration value format constraints (e.g., valid ranges for numeric settings).

### Details
- **CWE:** CWE-1059
- **ASVS Sections:** 2.1.1
- **ASVS Levels:** L1
- **Affected Files:**
  - `scheduler.rst`
  - `executor/index.rst` (line 108)
- **Related Findings:** FINDING-164, FINDING-165

### Remediation
Create dedicated input validation documentation that formally defines validation rules for: (1) DAG definition inputs (schedule expressions, task parameters, executor references), (2) Runtime parameters passed to DAGs, (3) Configuration values (acceptable ranges, format constraints, cross-parameter consistency rules), and (4) API inputs to the scheduler and executor interfaces. Formalize the implicit validation rules referenced in these documents (executor name validation, pool limit enforcement, configuration consistency) into a security design document that satisfies ASVS 2.1.1, 2.1.2, and 2.1.3.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 2.1.1.md

### Priority
Medium

---

## Issue: FINDING-085 - No documented or referenced allowlist mechanism for outbound connections from triggers and task execution
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The documentation describes an architecture where Triggers execute arbitrary async Python code within the triggerer process, capable of making unrestricted outbound network connections (e.g., polling APIs, connecting to databases), and Tasks run arbitrary Python code within worker processes with full network access. No allowlist mechanism is documented or referenced for restricting which external resources these components may contact. Without an allowlist of permitted outbound destinations, a malicious DAG author could use triggers or tasks to probe internal network services (SSRF), the triggerer process becomes a shared SSRF vector, and internal metadata services (cloud provider IMDSv1/v2, Kubernetes API) could be accessed from task/trigger code.

### Details
- **CWE:** CWE-918
- **ASVS Sections:** 13.2.5
- **ASVS Levels:** L2
- **Affected Files:**
  - `airflow-core/docs/authoring-and-scheduling/deferring.rst` (entire file)
  - `airflow-core/docs/core-concepts/executor/index.rst` (entire file)
  - `airflow-core/docs/security/workload.rst` (entire file)

### Remediation
The system should document and implement an outbound connection allowlist. Options include: 1) Network-level controls (recommended for production): Document that Deployment Managers must configure network policies (e.g., Kubernetes NetworkPolicy, firewall rules) to restrict egress from triggerer and worker pods/hosts. 2) Application-level allowlist: Implement a configurable allowlist in Airflow configuration with allowed_outbound_hosts, allowed_outbound_cidrs, and blocked_outbound_cidrs parameters. 3) Documentation gap: At minimum, the workload.rst security documentation should reference the need for egress controls and provide guidance for Deployment Managers. Additional recommendations include adding SSRF prevention guidance to workload.rst, documenting cloud metadata endpoint blocking (169.254.169.254), and creating backend connection configuration reference documentation.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 13.2.5.md

### Priority
Medium

---

## Issue: FINDING-086 - Context-Inappropriate Output Encoding for Template Variable in JavaScript Context
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `backend_server_base_url` template variable is passed to `index.html` from `request.base_url.path`. While Jinja2's auto-escaping handles HTML element/attribute contexts, if the template embeds this value within a `<script>` block (common for SPA configuration injection), HTML auto-escaping is semantically incorrect for a JavaScript context. The correct approach is JavaScript/JSON encoding via the `|tojson` filter, which escapes `</` to prevent script tag breakout, properly handles special characters for JavaScript string context, and produces valid JSON safe in both HTML and JS contexts.

### Details
- **CWE:** CWE-116
- **ASVS Sections:** 1.2.1, 1.2.3, 3.2.2
- **ASVS Levels:** L1
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/core_api/app.py` (lines 101-107)

### Remediation
In the template (index.html), use the tojson filter: `<script>window.__BASE_URL__ = {{ backend_server_base_url | tojson }};</script>`. Alternatively, pass pre-encoded JSON from the server side using `json.dumps(request.base_url.path)` and pass it as a separate context variable. Additionally, add server-side validation to ensure `request.base_url.path` matches expected path patterns (e.g., `^/[a-zA-Z0-9/_-]*$`) before passing to the template.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 1.2.1.md, 1.2.3.md, 3.2.2.md

### Priority
Medium

---

## Issue: FINDING-087 - Static Files Served with html=True Without Content-Type Enforcement
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The html=True parameter on StaticFiles enables serving index.html for directory requests and appending .html to paths. Combined with the absence of X-Content-Type-Options: nosniff, this increases the risk of content being interpreted in unintended contexts. Files in the static directory will be served with MIME types inferred from their extension, without additional security controls. If a file with ambiguous content ends up in the static directory (through build artifacts or plugin mechanisms), it could be rendered as HTML by browsers due to MIME-sniffing.

### Details
- **CWE:** None specified
- **ASVS Sections:** 3.2.1
- **ASVS Levels:** L1
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/core_api/app.py` (lines 62-69)

### Remediation
Remove html=True if not strictly needed, or ensure security headers middleware adds X-Content-Type-Options: nosniff to all responses from this mount.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 3.2.1.md

### Priority
Medium

---

## Issue: FINDING-088 - Missing SameSite Cookie Attribute Configuration
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application initialization code does not show any SameSite attribute configuration for cookies. Given that CORS is configured with `allow_credentials=True` (line 151), indicating cross-origin cookie usage, the application serves state-changing API endpoints (via `public_router`), and no CSRF middleware is visible in `init_middlewares`. The absence of explicit SameSite configuration means cookies may default to `SameSite=Lax` (modern browser default) or potentially `None` (if cross-origin usage is required). Without explicit configuration, the application relies on browser defaults which vary across implementations.

### Details
- **CWE:** None specified
- **ASVS Sections:** 3.3.2, 3.5.1, 3.5.2
- **ASVS Levels:** L2, L1
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/core_api/app.py` (entire file)

### Remediation
Implement a middleware that requires a custom header on state-changing requests to force CORS preflight. Example: from starlette.middleware.base import BaseHTTPMiddleware; from starlette.requests import Request; from starlette.responses import Response; class CORSPreflightEnforcementMiddleware(BaseHTTPMiddleware): SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}; async def dispatch(self, request: Request, call_next): if request.method not in self.SAFE_METHODS: if not request.headers.get("X-Requested-With"): return Response(status_code=403, content="Missing required header"); return await call_next(request)

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 3.3.2.md, 3.5.1.md, 3.5.2.md

### Priority
Medium

---

## Issue: FINDING-089 - Cookies Lack __Host- Prefix Enforcement
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application initialization code (app.py) registers JWTRefreshMiddleware which is responsible for setting session/auth cookies, but there is no evidence of __Host- prefix enforcement in the application's cookie configuration. Without the __Host- prefix, cookies are not guaranteed to have been set with Secure attribute, from the same host, and without a Path attribute other than /. This makes cookies susceptible to overwrite attacks from subdomains or insecure connections.

### Details
- **CWE:** None specified
- **ASVS Sections:** 3.3.3
- **ASVS Levels:** L2
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/core_api/app.py` (lines 161-176)
  - `airflow-core/docs/howto/run-behind-proxy.rst`

### Remediation
Configure all sensitive cookies (session tokens, refresh tokens) with the __Host- prefix. Example:
```python
response.set_cookie(
    key="__Host-airflow_session",
    value=token_value,
    secure=True,
    httponly=True,
    samesite="Lax",
    path="/"
)
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 3.3.3.md

### Priority
Medium

---

## Issue: FINDING-090 - CORS Wildcard Origin Allowed with Credentials Enabled
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The CORS configuration reads allowed origins from the Airflow configuration file (`api.access_control_allow_origins`) without any validation that the configured values are not wildcards when credentials are enabled. If an operator configures `access_control_allow_origins = *` (which is a valid list item), the `CORSMiddleware` with `allow_credentials=True` will reflect the requesting `Origin` header in the response (rather than returning literal `*`), effectively allowing any origin to make credentialed cross-origin requests. There is no code-level guardrail preventing this dangerous combination.

### Details
- **CWE:** None specified
- **ASVS Sections:** 3.4.2
- **ASVS Levels:** L1
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/core_api/app.py` (lines 138-152)

### Remediation
Add validation to reject wildcard origins when credentials are enabled:
```python
if "*" in allow_origins:
    log.warning("CORS wildcard origin '*' is configured with allow_credentials=True. This is insecure. Please specify explicit origins.")
    raise AirflowException("CORS wildcard origin '*' cannot be used with allow_credentials=True. Please configure explicit allowed origins.")
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 3.4.2.md

### Priority
Medium

---

## Issue: FINDING-091 - Incomplete CSP Documentation Guidance
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The documentation only mentions a minimal CSP header (frame-ancestors 'self'), and references HTTPS in passing through example URLs. It does NOT document: HSTS requirements (minimum max-age, includeSubDomains, preload), Full Content-Security-Policy directives (script-src, style-src, connect-src, etc.), X-Content-Type-Options requirements, Required browser minimum versions or feature support, How the application should behave when security features are unavailable (e.g., warning users, blocking access), Referrer-Policy requirements. The documentation actively advises AGAINST security controls: 'Please make sure your proxy does not enforce http-only status on the Set-Cookie headers.'

### Details
- **CWE:** None specified
- **ASVS Sections:** 3.4.3, 3.1.1
- **ASVS Levels:** L2, L3
- **Affected Files:**
  - `airflow-core/docs/howto/run-behind-proxy.rst` (lines 50-51)

### Remediation
Create a dedicated security documentation page that comprehensively covers:

Browser Security Requirements
=============================

Required HTTP Response Headers
------------------------------

The following headers MUST be configured in production deployments:

- ``Strict-Transport-Security: max-age=31536000; includeSubDomains``
- ``Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'self'``
- ``X-Content-Type-Options: nosniff``
- ``X-Frame-Options: SAMEORIGIN``
- ``Referrer-Policy: strict-origin-when-cross-origin``

Fallback Behavior
-----------------

If HTTPS is not available:
  - The application MUST NOT serve sensitive content over HTTP.
  - Cookies MUST NOT be transmitted.

If a browser does not support required features:
  - The application SHOULD display a warning banner.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 3.4.3.md, 3.1.1.md

### Priority
Medium

---

## Issue: FINDING-092 - Missing Referrer-Policy Header in Application Middleware
**Labels:** bug, security, priority:medium
**Description:**
### Summary
No Referrer-Policy header is set anywhere in the application middleware stack or route handlers. When a user clicks an external link from the Airflow UI (e.g., links in DAG documentation, rendered markdown, or plugin pages), the browser's default referrer behavior sends sensitive path information to third-party servers. Airflow URLs can contain sensitive information including DAG identifiers, task instance details, connection and variable names in admin URLs, and internal hostnames.

### Details
- **CWE:** None specified
- **ASVS Sections:** 3.4.5
- **ASVS Levels:** L2
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/core_api/app.py` (lines 162-178)

### Remediation
Implement a SecurityHeadersMiddleware that sets the Referrer-Policy header. For public applications use 'strict-origin-when-cross-origin'. For internal/non-public applications where even the hostname is sensitive, use 'same-origin'. Example implementation:
```python
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 3.4.5.md

### Priority
Medium

---

## Issue: FINDING-093 - Missing Cross-Origin-Opener-Policy header on HTML responses
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The webapp() catch-all route serves HTML document responses (media_type="text/html") without setting the Cross-Origin-Opener-Policy header. No middleware in the stack adds this header. Without COOP, if a user opens a link from the Airflow UI to an attacker-controlled page (e.g., from DAG documentation), the opened page retains a reference to the opener window (window.opener). This enables tabnabbing attacks where the attacker page navigates the opener (Airflow UI tab) to a phishing page, frame counting to enumerate internal Airflow state, and cross-window scripting attacks in same-origin scenarios.

### Details
- **CWE:** None specified
- **ASVS Sections:** 3.4.8
- **ASVS Levels:** L3
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/core_api/app.py` (lines 101-107)

### Remediation
Implement a SecurityHeadersMiddleware that adds the Cross-Origin-Opener-Policy header with value 'same-origin' for all text/html responses. Example implementation:

```python
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        content_type = response.headers.get("content-type", "")
        if "text/html" in content_type:
            response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        return response
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 3.4.8.md

### Priority
Medium

---

## Issue: FINDING-094 - Legacy Flask plugins mounted on same origin as main application
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The legacy Flask application (including third-party plugins) is mounted on the same hostname and origin as the main Airflow FastAPI application. This violates the same-origin separation principle: Cookies set by the main app are accessible by plugin code, XSS in a plugin affects the entire application, JavaScript from plugins can interact with the main app's resources, and there is no origin-based isolation between trusted core code and potentially untrusted plugin code. A vulnerability in any legacy Flask plugin (which may be third-party and less rigorously audited) can compromise the entire Airflow application since they share the same origin.

### Details
- **CWE:** None specified
- **ASVS Sections:** 3.5.4
- **ASVS Levels:** L2
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/core_api/app.py` (line 133)

### Remediation
Option 1: Host plugins on a separate subdomain (plugins.airflow.example.com instead of airflow.example.com/pluginsv2). Option 2: If same-host mounting is required, add iframe sandboxing and restrict cookie scope with path attributes. Option 3: Document in security guide that plugins should be vetted and deployed on separate hostnames for production environments.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 3.5.4.md

### Priority
Medium

---

## Issue: FINDING-095 - No Redirect Allowlist Mechanism Visible in Application Framework
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application framework does not implement a centralized redirect allowlist mechanism. While the provided code itself doesn't perform explicit redirects to external domains, there is no framework-level control to prevent other routes (registered via `public_router` or `ui_router`) from performing unvalidated redirects. The absence of such a control means any route added to the application could redirect users to arbitrary external hostnames without validation.

### Details
- **CWE:** None specified
- **ASVS Sections:** 3.7.2
- **ASVS Levels:** L2
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/core_api/app.py`

### Remediation
Implement a redirect validation middleware or utility function:
```python
from urllib.parse import urlparse

ALLOWED_REDIRECT_HOSTS = {"airflow.example.com"}

def validate_redirect_url(url: str, request: Request) -> str:
    parsed = urlparse(url)
    if parsed.netloc and parsed.netloc not in ALLOWED_REDIRECT_HOSTS:
        if parsed.netloc != request.url.hostname:
            return "/"  # Default to home
    return url
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 3.7.2.md

### Priority
Medium

---

## Issue: FINDING-096 - No External Redirect Notification Mechanism Implemented
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application does not implement any mechanism to notify users when they are being redirected to URLs outside of the application's control, nor does it provide an option to cancel such navigation. This is a Level 3 requirement that requires explicit user confirmation before navigating to external domains. Users could be silently redirected to phishing sites or malicious domains without awareness or ability to cancel the navigation.

### Details
- **CWE:** None specified
- **ASVS Sections:** 3.7.3
- **ASVS Levels:** L3
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/core_api/app.py`

### Remediation
Implement an interstitial redirect page:
```python
@app.get("/redirect", include_in_schema=False)
def external_redirect(request: Request, url: str):
    parsed = urlparse(url)
    if parsed.netloc and parsed.netloc != request.url.hostname:
        return templates.TemplateResponse(
            request,
            "/redirect_warning.html",
            {"target_url": url, "target_domain": parsed.netloc},
        )
    return RedirectResponse(url=url)
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 3.7.3.md

### Priority
Medium

---

## Issue: FINDING-097 - No Browser Security Feature Detection or Fallback Behavior
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application does not implement any mechanism to detect whether the browser supports expected security features (e.g., CSP, SameSite cookies, HSTS, modern TLS) and does not warn users or block access when security features are unavailable. The SPA catch-all route serves index.html to all browsers without any capability checking. No User-Agent analysis, feature detection, or minimum browser version requirements are enforced.

### Details
- **CWE:** None specified
- **ASVS Sections:** 3.7.5
- **ASVS Levels:** L3
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/core_api/app.py`

### Remediation
Implement browser compatibility checking: Server-side basic User-Agent check for known-insecure browsers (MSIE 6-10) with middleware that returns 403 status and unsupported browser message. Additionally, include client-side feature detection in the SPA JavaScript that warns users if required features are unavailable.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 3.7.5.md

### Priority
Medium

---

## Issue: FINDING-098 - No Refresh Token Replay Attack Mitigation for Public Clients
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The middleware issues new JWT tokens without invalidating the previously-issued JWT. When a browser-based (public) client's token is refreshed, the old JWT remains valid until its `exp` claim expires. There is no token rotation with invalidation logic, no DPoP binding, and no mTLS binding visible in this code. An attacker who obtains a JWT cookie can replay it even after the legitimate user has been issued a fresh token. The window of exposure equals the JWT's lifetime. For long-lived JWTs, this significantly extends the attack window.

### Details
- **CWE:** None specified
- **ASVS Sections:** 10.4.5
- **ASVS Levels:** L1, L2, L3
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py` (lines 45-95)
  - `airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py` (lines 97-100)

### Remediation
Implement one of: (1) Refresh token rotation with family tracking (L1/L2 minimum): Maintain a server-side token family. On refresh, invalidate the old token and if a used token is presented again, revoke the entire family. (2) Sender-constrained tokens (preferred for L3): Bind tokens to client proof-of-possession. Example implementation provided includes token rotation with jti tracking, checking if token has been consumed, marking tokens as consumed, and revoking entire token family on replay detection.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 10.4.5.md

### Priority
Medium

---

## Issue: FINDING-099 - JWT Refresh Token Lacks Absolute Expiration Enforcement
**Labels:** bug, security, priority:medium
**Description:**
### Summary
When setting the refreshed JWT cookie, max_age is set to None for valid tokens, creating a session cookie with no explicit expiration. Combined with the automatic refresh on every request, this allows sessions to persist indefinitely without any absolute expiration boundary enforced by this middleware. The JWT token itself may contain an exp claim, but the middleware's refresh mechanism generates a new JWT each time, effectively resetting the clock. There is no visible 'session started at' or 'absolute_expiry' claim being checked before issuing a new JWT.

### Details
- **CWE:** None specified
- **ASVS Sections:** 10.4.8
- **ASVS Levels:** L2, L3
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py` (line 75)

### Remediation
Add an absolute expiration check before allowing refresh. Implement a session_iat (session inception time) claim to JWTs that is preserved across refreshes, and enforce a maximum absolute session lifetime. Example: Check session_start against absolute_timeout before refreshing, and if exceeded, force re-authentication by setting new_token to empty string. Carry forward the original session_iat in new tokens. Configure session_absolute_timeout in configuration (e.g., 86400 seconds for 24 hours).

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 10.4.8.md

### Priority
Medium

---

## Issue: FINDING-100 - No Documentation of Multi-IdP User Identity Namespacing
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The documentation covers Kerberos as an authentication mechanism but does not document how user identities are namespaced when multiple identity providers are supported (e.g., Kerberos alongside LDAP, OAuth, or SAML). Airflow supports pluggable authentication managers, meaning multiple IdPs may coexist. If Airflow supports both Kerberos-authenticated users (for backend services) and another IdP (for web UI), there's no documented guidance on preventing identity collision where a user `airflow` from one IdP could be confused with user `airflow` from another IdP.

### Details
- **CWE:** None specified
- **ASVS Sections:** 6.8.1
- **ASVS Levels:** L2
- **Affected Files:**
  - `airflow-core/docs/security/kerberos.rst`

### Remediation
Documentation should clarify how user identities from Kerberos (realm-qualified principals like `user@REALM.COM`) are mapped to internal user records and how they're distinguished from users authenticated via other providers. Document multi-IdP identity mapping to clarify how Kerberos principals are mapped to internal user identities and how they're distinguished from users authenticated via other providers (OIDC, SAML, etc.). Provide a comprehensive federated identity guide covering how all supported IdPs (Kerberos, OIDC, SAML) interact, how identities are namespaced, and how assertions are validated across the system.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 6.8.1.md

### Priority
Medium

---

## Issue: FINDING-101 - Missing Cipher Suite Configuration in Reverse Proxy Documentation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The official reverse proxy deployment documentation contains no ssl_ciphers directive or guidance on selecting strong cipher suites. Neither the nginx nor Helm chart configuration examples include cipher suite configuration. For L3 compliance, only cipher suites providing forward secrecy should be permitted. Users following this guide will rely on system/nginx defaults for cipher selection, which may include non-forward-secrecy ciphers (e.g., RSA key exchange) and weak ciphers (e.g., 3DES, RC4 depending on nginx version).

### Details
- **CWE:** None specified
- **ASVS Sections:** 12.1.2
- **ASVS Levels:** L2, L3
- **Affected Files:**
  - `airflow-core/docs/howto/run-behind-proxy.rst` (lines 34-47)

### Remediation
Add cipher suite configuration to the nginx example: ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256'; ssl_prefer_server_ciphers on; For Helm with nginx ingress: annotations: nginx.ingress.kubernetes.io/ssl-ciphers: "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:..."

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 12.1.2.md

### Priority
Medium

---

## Issue: FINDING-102 - Missing mTLS Client Certificate Validation Guidance in Reverse Proxy Documentation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The deployment documentation provides no guidance on configuring mutual TLS (mTLS) for client certificate authentication at the reverse proxy layer. Given the domain context states 'mTLS client certificates must be validated before use' and 'Strong client authentication is required for sensitive intra-service communications,' the absence of mTLS guidance in the reverse proxy configuration is a documentation gap. Deployments following this guide will not implement client certificate verification at the proxy level, meaning services connecting to Airflow's external-facing API will not be authenticated via mTLS.

### Details
- **CWE:** None specified
- **ASVS Sections:** 12.1.3
- **ASVS Levels:** L2
- **Affected Files:**
  - `airflow-core/docs/howto/run-behind-proxy.rst` (entire file)

### Remediation
Add an mTLS section to the documentation with nginx configuration example including: ssl_client_certificate directive pointing to trusted CA certificate, ssl_verify_client set to 'on', ssl_verify_depth set appropriately (e.g., 2), and proxy headers to pass client certificate information to backend (X-Client-Cert with $ssl_client_s_dn and X-Client-Verify with $ssl_client_verify).

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 12.1.3.md

### Priority
Medium

---

## Issue: FINDING-103 - Wildcard FORWARDED_ALLOW_IPS allows header spoofing and weakens proxy authentication
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The documentation provides `FORWARDED_ALLOW_IPS: "*"` as the primary example for Helm deployments. This value allows ANY source to set forwarded headers (X-Forwarded-For, X-Forwarded-Proto). An attacker could send `X-Forwarded-Proto: https` to make the application believe the connection is encrypted when it is not, potentially bypassing HTTPS enforcement checks. In a Kubernetes environment where network policies are not perfectly configured, any pod could spoof forwarded headers to impersonate traffic from a trusted proxy, potentially bypassing IP-based access controls or logging.

### Details
- **CWE:** None specified
- **ASVS Sections:** 12.2.1, 12.3.5, 3.1.1
- **ASVS Levels:** L1, L3
- **Affected Files:**
  - `airflow-core/docs/howto/run-behind-proxy.rst` (lines 69-73)
  - `airflow-core/docs/howto/run-behind-proxy.rst` (lines 74-76)

### Remediation
Change the example to use restrictive IP ranges instead of wildcard. Replace `value: "*"` with `value: "10.0.0.0/8"` (adjusted to match actual proxy CIDR range or specific proxy service IP). Add a security warning explaining the risks of wildcard trust and emphasizing that production deployments must specify exact proxy IP ranges or CIDR blocks to prevent header spoofing and maintain service-to-service authentication integrity.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 12.2.1.md, 12.3.5.md, 3.1.1.md

### Priority
Medium

---

## Issue: FINDING-104 - Missing Secure cookie flag guidance
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The documentation advises AGAINST setting the `HttpOnly` flag on cookies due to frontend JavaScript requirements, but does not mention the `Secure` flag requirement. Without the `Secure` flag, cookies (including session tokens) could be transmitted over plaintext HTTP connections if TLS is not properly enforced at all layers. If a user deploys based on the port 80 nginx example and follows the cookie guidance, authentication cookies will be transmitted in plaintext and accessible to JavaScript (no HttpOnly), maximizing exposure to both network interception and XSS attacks.

### Details
- **CWE:** None specified
- **ASVS Sections:** 12.2.1
- **ASVS Levels:** L1
- **Affected Files:**
  - `airflow-core/docs/howto/run-behind-proxy.rst` (lines 52-53)

### Remediation
Add guidance that while HttpOnly may not be set on all cookies due to frontend requirements, the `Secure` flag MUST be set on all cookies to prevent transmission over HTTP. Update documentation to state: 'While HttpOnly cannot be enforced on all cookies (frontend JavaScript access required), ensure that the `Secure` flag IS set on all cookies to prevent transmission over HTTP. This requires TLS to be properly configured on the external-facing endpoint.'

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 12.2.1.md

### Priority
Medium

---

## Issue: FINDING-105 - No guidance on authenticated internal communications between proxy and backend
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The documentation demonstrates proxy-to-backend communication over plaintext HTTP without any form of service authentication. While localhost communication is lower risk, the documentation also addresses non-local proxy scenarios (line 60: "If your proxy server is not on the same host...") without providing guidance for securing that communication channel. For non-colocated deployments, the proxy-to-backend channel lacks: TLS encryption (proxy_pass uses http://), Mutual TLS (mTLS) client certificate authentication, any authentication mechanism between proxy and backend service, and network isolation guidance.

### Details
- **CWE:** None specified
- **ASVS Sections:** 12.3.5
- **ASVS Levels:** L3
- **Affected Files:**
  - `airflow-core/docs/howto/run-behind-proxy.rst` (lines 36-48)

### Remediation
Add a section for non-colocated deployments showing mTLS between proxy and backend with proxy_ssl_certificate, proxy_ssl_certificate_key, proxy_ssl_trusted_certificate, proxy_ssl_verify on, and proxy_ssl_protocols TLSv1.2 TLSv1.3 configuration. Also document Airflow API server configuration to require client certificates for non-localhost connections.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 12.3.5.md

### Priority
Medium

---

## Issue: FINDING-106 - Incomplete documentation of all communication needs for the application
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The scheduler documentation references communication with the metadata database and executors, and the executor documentation references communication with workers, databases, and external services (Kubernetes API, cloud providers, message brokers). However, neither document provides a comprehensive, consolidated list of ALL communication needs as required by ASVS 13.1.1. Missing documentation includes: No explicit enumeration of all external services (Redis/RabbitMQ for CeleryExecutor, Kubernetes API server, cloud APIs for ECS/Batch executors, Sentry, StatsD); No documentation of cases where end users (DAG authors) can provide external locations the application will connect to (e.g., Connections, HTTP operators targeting user-defined URLs, custom hooks); No network flow diagram or consolidated communication matrix; No documentation of the triggerer component's communication needs.

### Details
- **CWE:** None specified
- **ASVS Sections:** 13.1.1
- **ASVS Levels:** L2, L3
- **Affected Files:**
  - `airflow-core/docs/administration-and-deployment/scheduler.rst` (entire document)
  - `airflow-core/docs/core-concepts/executor/index.rst` (entire document)

### Remediation
Create a dedicated "Communication Architecture" document that: 1. Lists all internal component-to-component communication paths (scheduler↔DB, scheduler↔executor, webserver↔DB, triggerer↔DB, worker↔DB); 2. Lists all external service dependencies per executor type; 3. Documents that DAG authors can define arbitrary external connection targets via the Connections mechanism; 4. Provides a network flow matrix with protocols, ports, and direction

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 13.1.1.md

### Priority
Medium

---

## Issue: FINDING-107 - No documentation of maximum concurrent connection limits per service or behavior when limits are reached
**Labels:** bug, security, priority:medium
**Description:**
### Summary
While the scheduler documentation references pool limits and concurrency limits for task scheduling, it does not define the maximum number of concurrent connections to external services (database, message broker, Kubernetes API) or document what happens when those limits are reached. This acknowledges the problem but provides no: Defined maximum connection pool size, Documented behavior when the pool is exhausted, Fallback or recovery mechanisms, Connection queue behavior. The NOWAIT behavior is mentioned for row locks but there's no documentation of what happens when this fails (the fallback/recovery mechanism).

### Details
- **CWE:** None specified
- **ASVS Sections:** 13.1.2
- **ASVS Levels:** L3
- **Affected Files:**
  - `airflow-core/docs/administration-and-deployment/scheduler.rst`

### Remediation
Document for each service: 1. Default and configurable maximum connection pool sizes (e.g., sql_alchemy_pool_size, sql_alchemy_max_overflow), 2. Behavior when the pool is exhausted (queue, reject, timeout), 3. Recovery mechanisms (connection recycling, health checks), 4. Recommended monitoring thresholds

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 13.1.2.md

### Priority
Medium

---

## Issue: FINDING-108 - No documentation of executor queue depth limits or backpressure behavior
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The executor documentation describes queued/batch executors sending tasks to a central queue but does not document: Maximum queue depth, Behavior when the queue is full, Worker connection pool limits, Backpressure mechanisms. Without queue depth limits documentation, the system could experience unbounded queue growth leading to memory exhaustion or message broker instability.

### Details
- **CWE:** None specified
- **ASVS Sections:** 13.1.2
- **ASVS Levels:** L3
- **Affected Files:**
  - `airflow-core/docs/core-concepts/executor/index.rst`

### Remediation
For each executor type, document: Maximum concurrent workers/connections, Queue depth limits and overflow behavior, Backpressure signaling from executor to scheduler

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 13.1.2.md

### Priority
Medium

---

## Issue: FINDING-109 - Internal Architecture Documentation May Be Exposed in Production
**Labels:** bug, security, priority:medium
**Description:**
### Summary
This documentation file contains detailed internal architecture information that would aid an attacker if exposed in production. Key sensitive details include: supported PostgreSQL versions (13, 14, 15, 16, 17), MySQL versions (8.0, 8.4, Innovation), SQLite version (3.15.0+), connection string formats (postgresql+psycopg2://&lt;user&gt;:&lt;password&gt;@&lt;host&gt;/&lt;db&gt;, mysql+mysqldb://&lt;user&gt;:&lt;password&gt;@&lt;host&gt;[:&lt;port&gt;]/&lt;dbname&gt;), environment variable names (AIRFLOW__DATABASE__SQL_ALCHEMY_CONN, AIRFLOW__DATABASE__SQL_ALCHEMY_SCHEMA), and internal schema structure. If the docs/ directory is served by the application or accessible in deployment, an attacker gains knowledge of supported database backends and their versions (narrows attack surface), connection string formats (aids credential brute-forcing), internal schema structure and naming conventions, environment variable names that could be targeted for injection, and specific SQLAlchemy driver versions in use.

### Details
- **CWE:** None specified
- **ASVS Sections:** 13.4.5, 13.4.6, 13.4.7
- **ASVS Levels:** L2, L3
- **Affected Files:**
  - `airflow-core/docs/howto/set-up-database.rst` (entire file)

### Remediation
Ensure the docs/ directory is excluded from production deployments via Dockerfile exclusion (COPY --exclude=docs/ . /opt/airflow/) or .dockerignore (airflow-core/docs/). Verify deployment artifacts exclude docs/ directory in all production container images and deployment packages. Examine Dockerfiles and .dockerignore files. Add a production hardening section to this documentation that references ASVS 13.4.x requirements: disabling debug modes, removing documentation endpoints, disabling TRACE, and suppressing version headers. Add environment-aware defaults to SQLAlchemy engine configuration that automatically disable echo in production environments. Implement automated security scanning in CI/CD that verifies production container images do not contain documentation directories, .git metadata, or debug-enabling configurations. Create a dedicated security configuration guide that addresses all deployment hardening requirements in one location, referenced from this and other setup documentation.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 13.4.5.md, 13.4.6.md, 13.4.7.md

### Priority
Medium

---

## Issue: FINDING-110 - Documentation includes development-only configurations without clear production exclusion mechanism
**Labels:** bug, security, priority:medium
**Description:**
### Summary
While the documentation itself warns against using SQLite and echo=True in production, there is no programmatic enforcement. The presence of development-focused instructions (SQLite setup, echo=True logging, example credentials) alongside production setup guidance in a single file means this content could be included in production deployments where it is not needed and could guide operators toward insecure configurations. An operator deploying Airflow to production could: 1) Use the documented airflow_pass example credential literally, 2) Enable echo=True in production, logging all SQL queries including sensitive data, 3) Leave SQLite as the default backend without changing it.

### Details
- **CWE:** None specified
- **ASVS Sections:** 15.2.3
- **ASVS Levels:** L2
- **Affected Files:**
  - `airflow-core/docs/howto/set-up-database.rst` (lines 29-32)
  - `airflow-core/docs/howto/set-up-database.rst` (lines 261-266)

### Remediation
Ensure documentation is excluded from production deployment artifacts (Docker images, pip packages for runtime). Consider splitting development-only documentation into a separate file clearly marked as non-production. Add programmatic checks that warn/prevent SQLite usage in production mode. Example: Exclude docs/ directory from production Docker images.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 15.2.3.md

### Priority
Medium

---

## Issue: FINDING-111 - Dangerous Functionality in Auth Managers Not Explicitly Highlighted
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The auth manager architecture includes several patterns that constitute "dangerous functionality" per the ASVS definition (deserialization of untrusted data, dynamic code execution), but the documentation does not explicitly flag these as dangerous or describe the associated security controls: 1. JWT Deserialization (deserialize_user): Parses JWT token content to reconstruct user objects. Improper implementation could lead to injection or privilege escalation. 2. Dynamic Code Loading (lazy_load_command): CLI commands use lazy loading to dynamically import and execute Python modules. 3. Plugin Code Execution (get_fastapi_app): Auth managers can inject arbitrary FastAPI routes into the application server. 4. Token Cookie Handling: Auth managers set security-sensitive cookies that control authentication state.

### Details
- **CWE:** None specified
- **ASVS Sections:** 15.1.5
- **ASVS Levels:** L3
- **Affected Files:**
  - `airflow-core/docs/core-concepts/auth-manager/index.rst` (Throughout - particularly JWT handling, CLI commands, API extension)

### Remediation
Add a security considerations section that explicitly identifies dangerous functionality and required security controls. The section should cover: JWT Deserialization with strict schema validation and signature verification requirements; Dynamic Code Loading with trusted module path restrictions; API Extension with authentication and authorization requirements for injected routes; Cookie Management with httponly and secure flag requirements. Include cross-references to a dangerous-functionality-policy document.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 15.1.5.md

### Priority
Medium

---

## Issue: FINDING-112 - Batch Authorization Methods Lack Documented Size Constraints
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The documentation acknowledges that certain authorization operations are resource-intensive by providing batch optimization methods (batch_is_authorized_dag, filter_authorized_dag_ids, etc.) and warns about expensive module-level imports. However, it does not document: 1. What happens when batch authorization is called with very large lists (thousands of DAGs) 2. Timeout behavior if an external auth manager (e.g., Keycloak) becomes unresponsive 3. Rate limiting or queue-based approaches for authorization requests 4. How to prevent DoS through repeated authorization requests against expensive external identity providers. Custom auth manager implementations that make external API calls (to LDAP, OAuth providers, etc.) for each authorization check could cause: response timeouts exceeding consumer timeouts, resource exhaustion on the Airflow API server, and cascading failures when external identity providers are slow.

### Details
- **CWE:** None specified
- **ASVS Sections:** 15.2.2, 15.1.3
- **ASVS Levels:** L2
- **Affected Files:**
  - `airflow-core/docs/core-concepts/auth-manager/index.rst` (lines describing batch methods)

### Remediation
Add guidance on resource-demanding operations and mitigations: Add a section titled 'Performance and Availability Considerations' that documents: (1) Implement batch methods to override batch authorization methods to minimize round-trips to external services. (2) Set timeouts with explicit timeouts (e.g., 5 seconds) to prevent blocking the API server. (3) Cache results by caching authorization decisions with appropriate TTLs. (4) Handle unavailability by defining fallback behavior when external auth providers are unreachable (fail-closed recommended). (5) Limit parallel requests using connection pooling and limit concurrent requests to external identity providers.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 15.2.2.md, 15.1.3.md

### Priority
Medium

---

## Issue: FINDING-113 - Auth Manager Plugin System Lacks Sandboxing or Encapsulation for Arbitrary Code Execution
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The auth manager plugin architecture allows third-party code to: (1) Inject arbitrary FastAPI endpoints into the `/auth` path of the API server, (2) Register arbitrary CLI commands in the `airflow` namespace, (3) Register database managers that can modify database schema. All of these execute within the same process and security context as the core Airflow application. There is no documented sandboxing, network isolation, process isolation, or capability restriction for auth manager plugins. If a custom auth manager from a third-party provider is compromised or contains vulnerabilities, an attacker gains full access to the Airflow process (all DAGs, connections, variables, secrets), injected API endpoints run with the same privileges as core Airflow APIs, database managers could modify the metadata database schema, and CLI commands execute with the same filesystem/network access as Airflow.

### Details
- **CWE:** None specified
- **ASVS Sections:** 15.2.5
- **ASVS Levels:** L3
- **Affected Files:**
  - `airflow-core/docs/core-concepts/auth-manager/index.rst` (sections on get_fastapi_app, get_cli_commands, get_db_manager)

### Remediation
Document and implement at minimum: (1) Encapsulation: Auth manager endpoints mounted via get_fastapi_app() should have restricted middleware that limits their access to only auth-related database tables and APIs. (2) Capability restriction: Document recommended deployment patterns where custom auth managers are deployed in isolated containers with network access limited to the identity provider. (3) Interface boundary enforcement: Restrict what auth managers can import from airflow internals through a documented public interface boundary. Example implementation: Create an AuthManagerRouter class that validates auth_manager_app only uses allowed dependencies before mounting.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 15.2.5.md

### Priority
Medium

---

## Issue: FINDING-114 - Scheduler documentation lacks anti-automation controls for user-triggered DAG operations
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The scheduler documentation describes throughput optimization and performance tuning but does not document or reference any controls to enforce realistic human timing on user-initiated operations (e.g., manual DAG triggers, task state modifications, or API-driven DAG run submissions). Configuration parameters like `max_dagruns_to_create_per_loop` and `scheduler_idle_sleep_time` control internal scheduler behavior, not user-facing submission rates. The document explicitly states the scheduler is designed for "high throughput" and scheduling "tasks as soon as possible," but provides no guidance on preventing excessively rapid user-initiated transaction submissions through the API or UI.

### Details
- **CWE:** None specified
- **ASVS Sections:** 2.4.2
- **ASVS Levels:** L3
- **Affected Files:**
  - `airflow-core/docs/administration-and-deployment/scheduler.rst` (entire document)

### Remediation
Document minimum time intervals between user-initiated DAG triggers, include references to rate limiting middleware configuration, and describe how `max_active_runs_per_dag` and pool slot limits interact with anti-automation controls.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 2.4.2.md

### Priority
Medium

---

## Issue: FINDING-115 - Scheduler documentation does not reference authentication protection controls
**Labels:** bug, security, priority:medium
**Description:**
### Summary
This operational documentation file describes scheduler performance and configuration but makes no reference to how rate limiting, anti-automation, or adaptive response controls protect authentication endpoints from credential stuffing or brute force attacks. While this specific document focuses on scheduler operations, the scheduler interacts with authentication (e.g., the Internal Execution API uses JWT tokens), and the documentation does not cross-reference relevant security documentation. The document also does not explain how scheduler-level controls (pool limits, concurrency caps) prevent malicious account lockout scenarios when integrated with authentication systems.

### Details
- **CWE:** None specified
- **ASVS Sections:** 6.1.1
- **ASVS Levels:** L1
- **Affected Files:**
  - `airflow-core/docs/administration-and-deployment/scheduler.rst` (entire document)

### Remediation
Add a "Security Considerations" section or cross-reference to security documentation that describes: How rate limiting protects the webserver/API authentication endpoints; How adaptive lockout policies prevent brute force without enabling account lockout DoS; Configuration references for authentication-related rate limiting

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 6.1.1.md

### Priority
Medium

---

## Issue: FINDING-116 - No graceful degradation for template filesystem dependency in catch-all route
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `webapp` function serves as the catch-all route for the single-page application and depends on the filesystem being accessible. While `Path(directory).mkdir(exist_ok=True)` ensures the directory exists at startup, runtime filesystem failures (e.g., NFS mount loss, disk full, permission changes) would result in unhandled exceptions. There is no circuit breaker, cached response, or graceful degradation path. User request flows to `webapp()` then filesystem access to `index.html` template; if filesystem is unavailable (mounted volume gone, permissions changed, NFS failure), unhandled exception propagates. If the static filesystem becomes unavailable, ALL non-API requests will result in 500 errors.

### Details
- **CWE:** None specified
- **ASVS Sections:** 16.5.2
- **ASVS Levels:** L2, L3
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/core_api/app.py` (line 89)

### Remediation
Add try-catch block around template response to handle OSError and IOError exceptions. Return a 503 Service Unavailable response with a simple HTML maintenance page when filesystem is unavailable, including Retry-After header. Log the error server-side for operational visibility. Example: wrap templates.TemplateResponse in try block, catch (OSError, IOError), log error, and return HTMLResponse with status 503 and appropriate content indicating UI is temporarily unavailable but API endpoints may still be operational.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 16.5.2.md

### Priority
Medium

---

## Issue: FINDING-117 - Last-resort error handler coverage cannot be verified; potential gap in unhandled exception logging
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `init_error_handlers` function iterates over `ERROR_HANDLERS` and registers them. However, from this file alone, it is impossible to verify that: 1. A handler for the base `Exception` class exists (last-resort catch-all) 2. The catch-all handler properly logs the full exception with traceback to server-side logs 3. The catch-all handler returns a generic response to the client 4. `RuntimeError`, `SystemError`, or other unexpected exception types are covered. FastAPI's built-in server error handler returns `{"detail": "Internal Server Error"}` for uncaught exceptions, but it relies on the ASGI server (e.g., Uvicorn) for logging.

### Details
- **CWE:** None specified
- **ASVS Sections:** 16.5.4
- **ASVS Levels:** L3
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/core_api/app.py` (line 143)

### Remediation
Add an explicit last-resort exception handler in the `init_error_handlers` function:
```python
def init_error_handlers(app: FastAPI) -> None:
    from airflow.api_fastapi.common.exceptions import ERROR_HANDLERS

    for handler in ERROR_HANDLERS:
        app.add_exception_handler(handler.exception_cls, handler.exception_handler)

    # Last-resort handler for any unhandled exceptions
    @app.exception_handler(Exception)
    async def last_resort_exception_handler(request: Request, exc: Exception):
        log.exception(
            "Unhandled exception for %s %s",
            request.method,
            request.url.path,
            exc_info=exc,
        )
        return JSONResponse(
            status_code=500,
            content={"detail": "An unexpected error occurred. Please try again later."},
        )
```

Additionally: 1. Verify that `ERROR_HANDLERS` in `airflow.api_fastapi.common.exceptions` includes a handler for the base `Exception` class. 2. Document the expected content of `ERROR_HANDLERS` with explicit requirements (must include catch-all, must not expose internals, must log to Airflow's logging system). 3. Add integration tests that verify unhandled exception types (e.g., `RuntimeError`, `MemoryError`) result in generic error responses and proper server-side logging. 4. Consider adding structured error correlation IDs in generic error responses.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 16.5.4.md

### Priority
Medium

---

## Issue: FINDING-118 - Missing Comprehensive Key Management Policy Aligned with NIST SP 800-57
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The Fernet documentation provides operational guidance for key generation and rotation but does not constitute or reference a comprehensive key management policy aligned with NIST SP 800-57. The following key lifecycle phases are absent from documentation: Key destruction/revocation (no procedure for securely destroying old keys after rotation is complete), Key storage security requirements (no guidance on protecting the key at rest such as file permissions, secrets managers, HSMs), Key access control (no documentation on restricting which entities/services can access the Fernet key), Key sharing restrictions (no explicit statement limiting key sharing - the Fernet key is inherently shared across all Airflow components which may exceed the two entities for shared secrets guideline), Key expiration/rotation schedule (no defined rotation frequency or maximum key lifetime), and Cryptographic periods (no documentation of appropriate crypto-periods per NIST SP 800-57).

### Details
- **CWE:** None specified
- **ASVS Sections:** 11.1.1, 13.3.4
- **ASVS Levels:** L2, L3
- **Affected Files:**
  - `airflow-core/docs/security/secrets/fernet.rst` (entire document)

### Remediation
Add documented key rotation policy specifying that Fernet keys should be rotated at a minimum of every 90 days, or immediately upon suspected compromise. Configure automated rotation using secrets management system with cron jobs or scheduled tasks. Document connection and variable secrets rotation using external backend native rotation capabilities (HashiCorp Vault dynamic secrets with TTL-based expiration, AWS Secrets Manager automatic rotation with Lambda functions, GCP Secret Manager secret versions with scheduled rotation). Configure alerting when: Fernet key age exceeds the configured rotation period, connection credentials approach their expiration date, and rotation operations fail.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 11.1.1.md

### Priority
Medium

---

## Issue: FINDING-119 - Incomplete Cryptographic Inventory Documentation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The provided documentation covers only Fernet encryption for connection passwords and variables. Based on the domain context, Airflow uses multiple cryptographic mechanisms that are not inventoried in this document: JWT signing (for Execution API authentication) - algorithm and key not inventoried here; TLS/HTTPS certificates (for web server and API endpoints) - not documented; Password hashing (for user authentication) - algorithm not documented; Session tokens (for web UI sessions) - cryptographic basis not documented; OAuth/OIDC tokens (when using external auth providers) - not inventoried. The document also does not specify: Where the Fernet key cannot be used (only states connection passwords and variables); Classification of data types protected by Fernet; What data types require different cryptographic protection.

### Details
- **CWE:** None specified
- **ASVS Sections:** 11.1.2
- **ASVS Levels:** L2, L3
- **Affected Files:**
  - `airflow-core/docs/security/secrets/fernet.rst` (entire document scope)

### Remediation
Create a centralized cryptographic inventory document (e.g., docs/security/cryptographic-inventory.rst) that catalogs all cryptographic assets including: Fernet Key (AES-128-CBC + HMAC-SHA256, 256-bit split key, for connection passwords and variables, NOT for session tokens or user auth); JWT Signing Key (HS256/RS256, 256-bit/2048-bit, for internal API authentication, NOT for data encryption); TLS Certificate (RSA/ECDSA, ≥2048/≥256-bit, for transport security, NOT for data at rest). The inventory should document algorithm, key size, usage scope, and explicit restrictions for each cryptographic asset.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 11.1.2.md

### Priority
Medium

---

## Issue: FINDING-120 - No Cryptographic Discovery Mechanisms Implemented or Documented
**Labels:** bug, security, priority:medium
**Description:**
### Summary
No cryptographic discovery mechanisms are documented or referenced in the provided source material. There is no evidence of: Automated scanning tools to detect cryptographic usage in the codebase, Runtime detection of encryption, hashing, or signing operations, SBOM (Software Bill of Materials) integration documenting cryptographic dependencies, Static analysis rules targeting cryptographic API usage, Dependency scanning for cryptographic libraries. Without discovery mechanisms, new cryptographic usage introduced through code changes, dependency updates, or plugin installations may go undetected and unmanaged, potentially introducing weak or deprecated algorithms.

### Details
- **CWE:** None specified
- **ASVS Sections:** 11.1.3
- **ASVS Levels:** L3
- **Affected Files:** None specified

### Remediation
Implement cryptographic discovery through: 1. Static analysis: Configure SAST tools (e.g., Semgrep, CodeQL) with rules to detect imports from `cryptography`, `hashlib`, `hmac`, `jwt`, `ssl` modules. 2. Dependency scanning: Monitor `requirements.txt`/`pyproject.toml` for cryptographic library additions. 3. Runtime instrumentation: Log cryptographic operations with algorithm metadata for audit. 4. CI/CD integration: Add pipeline stages that flag new cryptographic usage for security review.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 11.1.3.md

### Priority
Medium

## Issue: FINDING-121 - No Post-Quantum Cryptography (PQC) Migration Plan Documented
**Labels:** security, priority:medium, documentation
**Description:**
### Summary
No post-quantum cryptography (PQC) migration plan or future-proofing strategy is documented for Airflow's cryptographic implementations. While Fernet's symmetric AES-128 encryption is less immediately threatened, asymmetric cryptography used elsewhere (JWT/RSA, TLS) faces higher quantum computing risks.

### Details
The Fernet documentation describes only current symmetric encryption without addressing:
- Quantum computing threats to cryptographic primitives in use
- Migration timeline or triggers for transitioning to PQC algorithms
- Crypto-agility assessment (ability to swap algorithms without code changes)
- Impact assessment of quantum threats on stored encrypted data (harvest-now-decrypt-later attacks)

Grover's algorithm reduces AES-128's effective security to 64 bits (below the 128-bit minimum), while HMAC-SHA256 authentication and asymmetric cryptography (JWT/RSA, TLS) are at higher risk from Shor's algorithm.

### Remediation
Document a PQC migration plan including:
1. **Current State Assessment**
   - Symmetric encryption Fernet/AES-128: Low immediate risk, consider AES-256
   - JWT signing HS256: Low immediate risk for symmetric variant
   - TLS certificates RSA/ECDSA: High risk - plan hybrid certificates
2. **Migration Triggers**
   - NIST PQC standard finalization for relevant use cases
   - Industry consensus on quantum computing timeline
3. **Migration Path**
   - Phase 1: Increase symmetric key sizes to 256-bit where possible
   - Phase 2: Adopt hybrid TLS with PQC key exchange (e.g., ML-KEM + X25519)
   - Phase 3: Transition JWT signing to PQC-safe algorithms when standardized
4. **Crypto-Agility Requirements**
   - Encryption module must support algorithm substitution via configuration
   - Key rotation procedures must support algorithm migration

### Acceptance Criteria
- [ ] PQC migration plan documented in security documentation
- [ ] Current cryptographic inventory assessed for quantum risk
- [ ] Migration phases and triggers defined
- [ ] Crypto-agility capabilities documented

### References
- ASVS 11.1.4
- airflow-core/docs/security/secrets/fernet.rst

### Priority
Medium - Strategic planning required but no immediate threat

---

## Issue: FINDING-122 - CORSMiddleware Does Not Protect WebSocket Connections
**Labels:** bug, security, priority:medium, websocket
**Description:**
### Summary
FastAPI/Starlette's CORSMiddleware only handles HTTP CORS preflight requests and does not validate the Origin header during WebSocket upgrade requests, creating a potential cross-site WebSocket hijacking vulnerability if WebSocket endpoints are added.

### Details
The CORSMiddleware configuration at lines 135-149 in `app.py` only processes HTTP OPTIONS requests with Access-Control-* headers. WebSocket connections (Connection: Upgrade) bypass this validation entirely.

If WebSocket endpoints are added to `public_router` or `ui_router`, they would not benefit from origin validation despite CORS configuration being present. A malicious website could initiate cross-site WebSocket hijacking attacks because the Origin header would not be validated during the WebSocket handshake.

This is a Type B gap: the control exists but is not applied to WebSocket connections.

### Remediation
If WebSocket endpoints are introduced, implement explicit Origin validation:

```python
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.websockets import WebSocket

class WebSocketOriginMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, allowed_origins: list[str]):
        super().__init__(app)
        self.allowed_origins = set(allowed_origins)
    
    async def dispatch(self, request, call_next):
        if request.scope["type"] == "websocket":
            origin = request.headers.get("origin")
            if origin not in self.allowed_origins:
                # Reject connection before handshake completes
                return Response(status_code=403)
        return await call_next(request)
```

### Acceptance Criteria
- [ ] WebSocketOriginMiddleware implemented if WebSocket endpoints exist
- [ ] Origin validation checks against allowed_origins list
- [ ] Connections from unauthorized origins rejected before handshake
- [ ] Tests added for WebSocket origin validation

### References
- ASVS 4.4.2 (L2)
- airflow-core/src/airflow/api_fastapi/core_api/app.py:135-149

### Priority
Medium - Preventive control for future WebSocket implementation

---

## Issue: FINDING-123 - Documented deadlock risk with MariaDB due to missing SKIP LOCKED/NOWAIT support
**Labels:** bug, security, priority:medium, database, concurrency
**Description:**
### Summary
The scheduler documentation acknowledges deadlock errors occur with unsupported MariaDB versions, but the system does not enforce database version requirements at startup, allowing silent deployment in deadlock-prone configurations.

### Details
From `scheduler.rst` lines 106-110, deadlock errors are documented as a known limitation without NOWAIT/SKIP LOCKED support. However:
- No startup validation verifies database supports required locking features
- Deployments on MariaDB < 10.6.0 can operate without warnings
- Multiple schedulers could experience deadlocks causing task scheduling stalls
- Potential denial of service in the scheduling pipeline

### Remediation
Add scheduler startup validation:

```python
def validate_database_locking_support():
    """Validate database supports required locking features for multi-scheduler setup."""
    if conf.getboolean('scheduler', 'use_row_level_locking'):
        # Check if multiple schedulers are expected
        if get_expected_scheduler_count() > 1:
            db_version = get_database_version()
            if is_mariadb(db_version) and db_version < (10, 6, 0):
                raise AirflowConfigException(
                    "MariaDB version >= 10.6.0 required for multiple schedulers "
                    "with row-level locking. Current version does not support "
                    "SKIP LOCKED/NOWAIT, which will cause deadlocks."
                )
```

### Acceptance Criteria
- [ ] Startup check validates database locking feature support
- [ ] AirflowConfigException raised for incompatible MariaDB versions
- [ ] Clear error message guides users to upgrade or use single scheduler
- [ ] Test added for version validation logic

### References
- ASVS 15.4.3 (L3)
- airflow-core/docs/administration-and-deployment/scheduler.rst:106-110

### Priority
Medium - Prevents production misconfigurations leading to service degradation

---

## Issue: FINDING-124 - mask_secret() API Lacks Documented Regex Metacharacter Escaping and ReDoS Protection
**Labels:** bug, security, priority:medium, regex, redos
**Description:**
### Summary
The `mask_secret()` API accepts arbitrary string values from DAG authors for pattern matching without documented regex metacharacter escaping or ReDoS protection, creating risks of over/under-masking and potential denial of service.

### Details
From `mask-sensitive-values.rst` lines 87-96, the documentation describes accepting arbitrary secret values but does not specify:
1. Whether regex metacharacters (e.g., `p@ss.w*rd+1`) are escaped
2. Protection against exponential backtracking (ReDoS)
3. Timeout or complexity limitations
4. Pattern validation

**Risk scenarios:**
- Unescaped metacharacters cause incorrect masking behavior
- Crafted secret values trigger exponential backtracking
- Task hangs or worker resource exhaustion
- No documented safety guarantees

CWE-1333: Regular Expression Denial of Service (ReDoS)

### Remediation
1. **Apply `re.escape()` to all user-supplied values:**
```python
def mask_secret(value: str) -> None:
    """Mask a secret value in logs by treating it as a literal string."""
    escaped_pattern = re.escape(str(value))
    # Register escaped pattern for masking
```

2. **Enforce safety limits:**
```python
MAX_PATTERNS = 100
MAX_PATTERN_LENGTH = 1024

if len(masked_patterns) >= MAX_PATTERNS:
    raise ValueError(f"Cannot register more than {MAX_PATTERNS} secret patterns")
if len(value) > MAX_PATTERN_LENGTH:
    raise ValueError(f"Secret value exceeds maximum length of {MAX_PATTERN_LENGTH}")
```

3. **Update documentation:**
```
Values passed to ``mask_secret()`` are automatically escaped for use in 
pattern matching. Special characters such as ``.``, ``*``, ``+``, ``(``, 
``)`` etc. are treated as literal characters, not as regex metacharacters.
Pattern matching includes safety limits to prevent performance degradation.
```

### Acceptance Criteria
- [ ] `re.escape()` applied to all values before regex compilation
- [ ] Maximum pattern count enforced (100)
- [ ] Maximum pattern length enforced (1024)
- [ ] Documentation updated with safety guarantees
- [ ] Tests added for special characters and limits

### References
- ASVS 1.2.9 (L2), 1.3.12 (L3)
- CWE-1333
- airflow-core/docs/security/secrets/mask-sensitive-values.rst:87-96

### Priority
Medium - Prevents ReDoS attacks and ensures correct masking behavior

---

## Issue: FINDING-125 - Authorization Decisions Do Not Incorporate Token-Level Claims (scope, authorization_details)
**Labels:** bug, security, priority:medium, oauth, authorization
**Description:**
### Summary
JWT validation extracts `scope` and `authorization_details` claims but authorization decisions ignore these token-specific constraints, granting full user permissions regardless of intended scope restrictions.

### Details
In `base_auth_manager.py` line 150-165, `get_user_from_token()` validates JWT and deserializes to user object, but:
- Token claims (`scope`, `authorization_details`) are not propagated to authorization
- `is_authorized_*` methods accept only `method` and `user`, not `token_claims`
- A token with limited scope (e.g., `scope=read:dags`) still grants full user permissions

**Type B gap:** JWT validation EXISTS and extracts claims, but scope/authorization_details are NOT USED in authorization decisions.

**Impact:** In delegated authorization scenarios (third-party applications accessing API on behalf of users), scope-limited access cannot be enforced. Any valid token grants full user permissions.

### Remediation
1. **Modify `get_user_from_token()` to return claims:**
```python
async def get_user_from_token(self, token: str) -> tuple[BaseUser, dict[str, Any]]:
    """Validate token and return user with token claims."""
    payload = await self._get_token_validator().validate(token)
    user = self.deserialize_user(payload)
    claims = {
        "scope": payload.get("scope"),
        "authorization_details": payload.get("authorization_details")
    }
    return user, claims
```

2. **Update authorization methods:**
```python
def is_authorized_connection(
    self, *, 
    method: str, 
    user: BaseUser, 
    details: ConnectionDetails | None = None,
    token_claims: dict[str, Any] | None = None
) -> bool:
    # Check both user permissions and scope authorization
    if token_claims and not self._check_scope(token_claims, "connections", method):
        return False
    return self._check_user_permission(user, "connections", method, details)
```

### Acceptance Criteria
- [ ] `get_user_from_token()` returns both user and token claims
- [ ] Authorization methods accept `token_claims` parameter
- [ ] Scope validation implemented for resource access
- [ ] Tests added for scope-limited tokens
- [ ] Documentation updated with scope enforcement behavior

### References
- ASVS 10.3.2 (L2)
- airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:150-165

### Priority
Medium - Required for proper delegated authorization and scope enforcement

---

## Issue: FINDING-126 - No Issuer (iss) Claim Validation in Token Validator
**Labels:** bug, security, priority:medium, jwt, oauth
**Description:**
### Summary
The `JWTValidator` is configured with `audience` but no `issuer` parameter, meaning tokens from different issuers sharing the same signing key could be accepted, creating token impersonation risk.

### Details
At line 835-843 in `base_auth_manager.py`, the `_get_token_validator()` method configures validation without issuer verification:
- Tokens sharing signing keys across services could be accepted
- User identification via `sub` alone may not be globally unique
- In federated deployments, `sub` collisions could occur

**Risks:**
- Compromised/shared signing keys enable cross-service token acceptance
- Multi-IdP deployments without issuer validation allow token confusion
- `sub` claim uniqueness not guaranteed without `iss` context

### Remediation
Add issuer validation to JWTValidator configuration:

```python
@classmethod
@cache
def _get_token_validator(cls) -> JWTValidator:
    return JWTValidator(
        **get_sig_validation_args(),
        leeway=conf.getint("api_auth", "jwt_leeway"),
        audience=conf.get("api_auth", "jwt_audience", fallback="apache-airflow"),
        issuer=conf.get("api_auth", "jwt_issuer", fallback=None),
    )

@classmethod
@cache
def _get_token_signer(cls, expiration_time_in_seconds: int = ...) -> JWTGenerator:
    return JWTGenerator(
        **get_signing_args(),
        valid_for=expiration_time_in_seconds,
        audience=conf.get("api_auth", "jwt_audience", fallback="apache-airflow"),
        issuer=conf.get("api_auth", "jwt_issuer", fallback="airflow"),
    )
```

Add configuration options:
```ini
[api_auth]
jwt_issuer = https://airflow.example.com
```

### Acceptance Criteria
- [ ] `jwt_issuer` configuration option added
- [ ] JWTValidator configured with issuer parameter
- [ ] JWTGenerator includes issuer in generated tokens
- [ ] Tokens with mismatched issuer rejected
- [ ] Tests added for issuer validation
- [ ] Documentation updated with issuer configuration

### References
- ASVS 10.3.3 (L2)
- airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:835-843

### Priority
Medium - Prevents token confusion in multi-issuer deployments

---

## Issue: FINDING-127 - Missing Authentication Strength, Method, and Recentness Verification
**Labels:** bug, security, priority:medium, oauth, authentication
**Description:**
### Summary
Token validation does not verify authentication context (`acr`), methods (`amr`), or recentness (`auth_time`) claims, preventing enforcement of elevated authentication requirements for sensitive operations.

### Details
In `base_auth_manager.py` lines 140-155, `get_user_from_token` validates signature, expiration, and revocation but not:
- `acr` (Authentication Context Class Reference) - authentication strength level
- `amr` (Authentication Methods References) - which methods were used
- `auth_time` - when user last authenticated

**Impacts:**
- Resources requiring elevated authentication (admin ops, sensitive data) cannot enforce appropriate strength
- No mechanism to require MFA for high-privilege operations
- Attacker with weak authentication factor gains same access as full MFA user
- No ability to require recent authentication for sensitive operations

### Remediation
Modify `get_user_from_token` to accept authentication constraints:

```python
async def get_user_from_token(
    self,
    token: str,
    required_acr: str | None = None,
    required_amr: list[str] | None = None,
    max_auth_age: int | None = None,
) -> BaseUser:
    """Validate token with optional authentication strength requirements."""
    payload = await self._get_token_validator().validate(token)
    
    # Verify authentication context class
    if required_acr and not self._acr_satisfies_requirement(
        payload.get("acr"), required_acr
    ):
        raise InvalidTokenError(
            f"Token ACR '{payload.get('acr')}' does not meet requirement '{required_acr}'"
        )
    
    # Verify authentication methods
    if required_amr:
        token_amr = payload.get("amr", [])
        if not all(method in token_amr for method in required_amr):
            raise InvalidTokenError(f"Token missing required authentication methods: {required_amr}")
    
    # Verify authentication recentness
    if max_auth_age:
        auth_time = payload.get("auth_time")
        if not auth_time or (time.time() - auth_time) > max_auth_age:
            raise InvalidTokenError("Authentication too old, re-authentication required")
    
    return self.deserialize_user(payload)

def _acr_satisfies_requirement(self, token_acr: str | None, required_acr: str) -> bool:
    """Compare authentication context class references according to policy."""
    # Implement organizational ACR hierarchy
    acr_levels = {"basic": 1, "mfa": 2, "hardware_mfa": 3}
    return acr_levels.get(token_acr, 0) >= acr_levels.get(required_acr, 0)
```

### Acceptance Criteria
- [ ] `get_user_from_token` accepts authentication constraint parameters
- [ ] `acr` claim validated against required strength
- [ ] `amr` claim validated for required methods
- [ ] `auth_time` claim validated for maximum age
- [ ] `_acr_satisfies_requirement` method implements policy hierarchy
- [ ] Tests added for authentication strength enforcement
- [ ] Documentation updated with authentication requirements

### References
- ASVS 10.3.4 (L2)
- airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:140-155

### Priority
Medium - Required for step-up authentication and sensitive operation protection

---

## Issue: FINDING-128 - Missing Redirect URI Validation in BaseAuthManager
**Labels:** bug, security, priority:medium, oauth, open-redirect
**Description:**
### Summary
The BaseAuthManager abstract base class provides no abstract method, utility, or guidance for redirect URI validation, enabling potential open redirect attacks in OAuth flows if implementations omit this critical check.

### Details
The `get_url_login(self, **kwargs)` method at line 169 accepts arbitrary kwargs which could include redirect parameters, but:
- No abstract method requires implementations to validate redirect URIs
- No utility method for exact string comparison against allowlists
- No client registration model with pre-registered redirect URIs
- No parameter validation contract defined

**Risk:** If concrete auth manager implementations act as OAuth authorization servers, they could omit redirect URI validation, enabling open redirect attacks.

### Remediation
Add utility method and documentation for redirect validation:

```python
@staticmethod
def validate_redirect_uri(redirect_uri: str, allowed_uris: list[str]) -> bool:
    """
    Validate redirect URI against allowlist using exact string comparison.
    
    This method should be used by auth manager implementations that handle
    OAuth/OIDC flows to prevent open redirect vulnerabilities.
    
    Args:
        redirect_uri: The redirect URI to validate
        allowed_uris: List of pre-registered allowed redirect URIs
    
    Returns:
        True if redirect_uri exactly matches an allowed URI
    
    Example:
        >>> allowed = ["https://app.example.com/callback"]
        >>> validate_redirect_uri("https://app.example.com/callback", allowed)
        True
        >>> validate_redirect_uri("https://evil.com", allowed)
        False
    """
    return redirect_uri in allowed_uris
```

Add documentation section:

```rst
Redirect URI Validation
^^^^^^^^^^^^^^^^^^^^^^^

Auth manager implementations that handle OAuth/OIDC authorization flows
MUST validate redirect URIs using exact string matching against a pre-registered
allowlist. Use the ``validate_redirect_uri()`` utility method to ensure
proper validation and prevent open redirect vulnerabilities.
```

### Acceptance Criteria
- [ ] `validate_redirect_uri()` static method added to BaseAuthManager
- [ ] Method uses exact string comparison (no pattern matching)
- [ ] Documentation added for OAuth redirect URI validation requirements
- [ ] Example implementation provided
- [ ] Tests added for redirect URI validation utility

### References
- ASVS 10.4.1 (L1)
- airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:169

### Priority
Medium - Prevents open redirect vulnerabilities in OAuth implementations

---

## Issue: FINDING-129 - JWT Access Tokens Lack Sender-Constraining Mechanisms
**Labels:** bug, security, priority:medium, jwt, oauth, token-binding
**Description:**
### Summary
JWT access tokens are generated without sender-constraining mechanisms (certificate binding or DPoP), making them vulnerable to token theft and replay attacks from any client/network location.

### Details
The base auth manager generates JWT access tokens without proof-of-possession binding:
- No `cnf` claim with `x5t#S256` thumbprint (RFC 8705 mTLS binding)
- No `jkt` claim or DPoP proof validation (RFC 9449 DPoP binding)
- `JWTGenerator` at line 743 instantiated with only signing args, validity, and audience

**Impact:** Tokens are bearer tokens vulnerable to:
- Token theft via interception
- Replay attacks from any location
- No client binding enforcement

### Remediation
Add support for certificate-bound and DPoP-bound tokens:

```python
def generate_jwt(
    self, user: T, *,
    expiration_time_in_seconds: int = conf.getint("api_auth", "jwt_expiration_time"),
    client_cert_thumbprint: str | None = None,
    dpop_jkt: str | None = None,
) -> str:
    """
    Generate JWT with optional sender-constraining mechanisms.
    
    Args:
        user: User to generate token for
        expiration_time_in_seconds: Token validity period
        client_cert_thumbprint: x5t#S256 thumbprint from mTLS client certificate
        dpop_jkt: JWK thumbprint from DPoP proof
    
    Returns:
        JWT access token with optional cnf claim
    """
    extra_claims = {}
    
    # Certificate-bound token (RFC 8705)
    if client_cert_thumbprint:
        extra_claims["cnf"] = {"x5t#S256": client_cert_thumbprint}
    # DPoP-bound token (RFC 9449)
    elif dpop_jkt:
        extra_claims["cnf"] = {"jkt": dpop_jkt}
    
    return self._get_token_signer(
        expiration_time_in_seconds=expiration_time_in_seconds
    ).generate({**self.serialize_user(user), **extra_claims})
```

Add validation in `get_user_from_token`:

```python
async def get_user_from_token(
    self, token: str, 
    client_cert_thumbprint: str | None = None,
    dpop_proof: str | None = None
) -> T:
    """Validate token with sender-constraining proof."""
    payload = await self._get_token_validator().validate(token)
    
    # Verify certificate binding
    if "cnf" in payload:
        if "x5t#S256" in payload["cnf"]:
            if not client_cert_thumbprint:
                raise InvalidTokenError("Certificate-bound token requires mTLS")
            if payload["cnf"]["x5t#S256"] != client_cert_thumbprint:
                raise InvalidTokenError("Certificate thumbprint mismatch")
        elif "jkt" in payload["cnf"]:
            if not dpop_proof:
                raise InvalidTokenError("DPoP-bound token requires DPoP proof")
            # Validate DPoP proof and extract jkt
            # Compare with payload["cnf"]["jkt"]
    
    return self.deserialize_user(payload)
```

### Acceptance Criteria
- [ ] `generate_jwt` accepts `client_cert_thumbprint` and `dpop_jkt` parameters
- [ ] `cnf` claim added to tokens when binding parameters provided
- [ ] `get_user_from_token` validates sender-constraining proofs
- [ ] mTLS certificate thumbprint validation implemented
- [ ] DPoP proof validation implemented
- [ ] Tests added for certificate-bound and DPoP-bound tokens
- [ ] Documentation updated with token binding options

### References
- ASVS 10.4.14 (L3), 10.7.3 (L2)
- RFC 8705 (OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens)
- RFC 9449 (OAuth 2.0 Demonstrating Proof of Possession)
- airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:743, 161

### Priority
Medium - Significantly improves token security for high-value deployments

---

## Issue: FINDING-130 - Missing Issuer Validation for OIDC ID Tokens
**Labels:** bug, security, priority:medium, oidc, jwt
**Description:**
### Summary
The `JWTValidator` is configured without explicit issuer validation, allowing tokens from malicious authorization servers with shared key material to be accepted in multi-IdP deployments.

### Details
At line 140 in `base_auth_manager.py`, `_get_token_validator()` does not pass an `issuer` parameter:
- Tokens signed with valid keys from different (malicious) authorization servers would be accepted
- Multiple IdPs sharing signing key infrastructure enable cross-IdP token confusion
- Audience validation provides partial protection but is not equivalent to issuer validation

**Impact in multi-IdP deployment:**
- Compromised authorization server can forge tokens accepted by Airflow
- Token issued for one IdP accepted as from another
- Unauthorized access through IdP impersonation

### Remediation
Add issuer validation to JWTValidator:

```python
@classmethod
@cache
def _get_token_validator(cls) -> JWTValidator:
    return JWTValidator(
        **get_sig_validation_args(),
        leeway=conf.getint("api_auth", "jwt_leeway"),
        audience=conf.get("api_auth", "jwt_audience", fallback="apache-airflow"),
        issuer=conf.get("api_auth", "jwt_issuer", fallback=None),
    )
```

Add validation in `get_user_from_token`:

```python
async def get_user_from_token(self, token: str) -> T:
    """Validate token including issuer claim verification."""
    payload = await self._get_token_validator().validate(token)
    
    # Additional issuer validation
    expected_issuer = conf.get("api_auth", "jwt_issuer", fallback=None)
    if expected_issuer and payload.get("iss") != expected_issuer:
        raise InvalidTokenError(
            f"Token issuer '{payload.get('iss')}' does not match "
            f"expected '{expected_issuer}'"
        )
    
    return self.deserialize_user(payload)
```

Add configuration:
```ini
[api_auth]
jwt_issuer = https://idp.example.com
```

### Acceptance Criteria
- [ ] `jwt_issuer` configuration option added
- [ ] JWTValidator configured with issuer parameter
- [ ] Explicit issuer claim validation in `get_user_from_token`
- [ ] Tokens with mismatched issuer rejected
- [ ] Tests added for issuer validation
- [ ] Documentation updated with issuer configuration requirements

### References
- ASVS 10.5.1 (L2), 10.5.3 (L3)
- airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:140

### Priority
Medium - Critical for multi-IdP deployments and federated authentication

---

## Issue: FINDING-131 - No Abstract Contract for OIDC ID Token Subject Identifier Usage
**Labels:** security, priority:medium, oidc, documentation
**Description:**
### Summary
The `deserialize_user` abstract method lacks guidance on using stable, non-reassignable identifiers (the `sub` claim), potentially enabling account takeover when identifiers like email addresses are reassigned.

### Details
The abstract `deserialize_user` method provides no enforcement or guidance about:
- Which claims must be used for unique user identification
- That identifiers must not be reassignable (email addresses can be reassigned)
- That `sub` should be combined with `iss` for cross-IdP uniqueness

The `is_authorized_hitl_task` method uses `user.get_id()` for identity comparison, but there's no guarantee this maps to the `sub` claim. If `get_id()` returns an email or username, account takeover could occur when identifiers are reassigned.

**Known limitation:** Auth manager system allowing custom implementations without certification is intentional, so this is a gap in the base class contract rather than a critical vulnerability.

### Remediation
Document OIDC requirements for implementers:

```python
@abstractmethod
def deserialize_user(self, payload: dict[str, Any]) -> T:
    """
    Deserialize user from JWT payload.
    
    OIDC Implementation Requirements:
    - Use the 'sub' claim as the primary user identifier
    - Combine 'sub' with 'iss' for globally unique identification
    - Do NOT use reassignable identifiers (email, username) as primary key
    - Ensure get_id() returns a stable, non-reassignable value
    
    Example:
        def deserialize_user(self, payload: dict[str, Any]) -> User:
            # Use sub + iss for unique identification
            unique_id = f"{payload['iss']}:{payload['sub']}"
            return User(
                id=unique_id,
                email=payload.get('email'),  # Secondary attribute only
                ...
            )
    """
```

Consider defining optional abstract methods or mixin classes:

```python
class OIDCClientMixin:
    """Mixin for OIDC-compliant auth manager implementations."""
    
    @abstractmethod
    def validate_id_token(self, id_token: str, nonce: str) -> dict[str, Any]:
        """Validate OIDC ID token including nonce verification."""
    
    @abstractmethod
    def handle_backchannel_logout(self, logout_token: str) -> bool:
        """Handle OIDC back-channel logout token."""
```

### Acceptance Criteria
- [ ] `deserialize_user` docstring updated with OIDC requirements
- [ ] Example implementation provided using `sub` + `iss`
- [ ] Optional `OIDCClientMixin` defined for OIDC-specific functionality
- [ ] Documentation added for secure OIDC implementation patterns
- [ ] Warning added that concrete OIDC implementations should be audited independently

### References
- ASVS 10.5.4 (L2), 10.5.2 (L3)
- airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py

### Priority
Medium - Guidance needed to prevent insecure OIDC implementations

---

## Issue: FINDING-132 - No Back-Channel Logout Interface or Validation Contract
**Labels:** security, priority:medium, oidc, logout
**Description:**
### Summary
The base class defines front-channel logout (`get_url_logout()`) but provides no interface or guidance for OIDC back-channel logout token validation, potentially leading to denial-of-service or cross-JWT confusion.

### Details
At line 172, `get_url_logout()` returns a URL for user redirection but does not handle incoming logout tokens from Identity Providers. The base class provides no abstract method or interface for:
- Receiving OIDC back-channel logout tokens
- Validating the `typ` header is `logout+jwt`
- Verifying the `event` claim contains correct member name
- Ensuring no `nonce` claim is present
- Enforcing short expiration on logout tokens

**Impact:** If concrete auth managers implement OIDC with back-channel logout support, there's no base class guidance for secure logout token validation, potentially enabling:
- Denial-of-service through forced logout
- Cross-JWT confusion attacks
- Improper session termination

### Remediation
Add optional interface for back-channel logout:

```python
def handle_backchannel_logout(self, logout_token: str) -> bool:
    """
    Handle OIDC back-channel logout token (optional).
    
    Implementations supporting OIDC back-channel logout MUST:
    1. Verify typ header is 'logout+jwt'
    2. Verify 'event' claim contains 'http://schemas.openid.net/event/backchannel-logout'
    3. Ensure NO 'nonce' claim is present
    4. Verify token expiration is short (recommended: 2 minutes)
    5. Validate signature and issuer as with ID tokens
    6. Terminate all sessions for the identified user
    
    Args:
        logout_token: The logout token JWT from the IdP
    
    Returns:
        True if logout was successfully processed
    
    Raises:
        InvalidTokenError: If logout token validation fails
    
    Example:
        def handle_backchannel_logout(self, logout_token: str) -> bool:
            # Parse JWT header
            header = jwt.get_unverified_header(logout_token)
            if header.get("typ") != "logout+jwt":
                raise InvalidTokenError("Invalid typ header")
            
            # Validate and decode
            payload = self._get_token_validator().validate(logout_token)
            
            # Verify event claim
            events = payload.get("events", {})
            if "http://schemas.openid.net/event/backchannel-logout" not in events:
                raise InvalidTokenError("Missing backchannel-logout event")
            
            # Ensure no nonce
            if "nonce" in payload:
                raise InvalidTokenError("Logout tokens must not contain nonce")
            
            # Verify short expiration
            if payload["exp"] - payload["iat"] > 120:
                raise InvalidTokenError("Logout token expiration too long")
            
            # Terminate sessions
            self._terminate_user_sessions(payload["sub"])
            return True
    """
    raise NotImplementedError(
        "Back-channel logout not supported by this auth manager"
    )
```

### Acceptance Criteria
- [ ] `handle_backchannel_logout` method added to BaseAuthManager
- [ ] Method includes comprehensive docstring with validation requirements
- [ ] Example implementation provided
- [ ] Default implementation raises NotImplementedError
- [ ] Documentation added for OIDC back-channel logout support
- [ ] Tests added for logout token validation

### References
- ASVS 10.5.5 (L2, L3)
- OpenID Connect Back-Channel Logout 1.0
- airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:172

### Priority
Medium - Required for complete OIDC logout support

---

## Issue: FINDING-133 - Middleware-based user injection bypasses JWT validation without framework-level guardrails
**Labels:** bug, security, priority:medium, authentication
**Description:**
### Summary
The `get_user()` dependency accepts pre-built user objects from `request.state.user` without validation, allowing arbitrary plugin middleware to bypass JWT signature validation, expiry checks, and token revocation checks.

### Details
In `security.py` lines 119-135, the `get_user()` function accepts `request.state.user` without validation. While legitimately used by `SimpleAllAdminMiddleware`, the `init_plugins()` function at `app.py` line 197 allows arbitrary plugins to register root-level middleware that could set `request.state.user`.

This creates an undocumented authentication pathway where any FastAPI plugin middleware can inject a user object, bypassing:
- JWT signature validation
- Token expiry checks
- Token revocation checks
- All standard authentication controls

**Risk:** Malicious or vulnerable plugins could inject arbitrary user objects with elevated privileges.

### Remediation
Add validation that middleware-injected users have a verifiable trust indicator:

```python
async def get_user(request: Request) -> User:
    """
    Get authenticated user from request.
    
    Supports two authentication pathways:
    1. Middleware-injected user (must have trust marker)
    2. JWT bearer token validation
    """
    # Check for middleware-injected user
    if hasattr(request.state, "user"):
        user = request.state.user
        
        # Verify the user was set by trusted middleware
        if not hasattr(request.state, "auth_middleware_trust_token"):
            raise HTTPException(
                status_code=401,
                detail="Middleware-injected user missing trust token"
            )
        
        # Verify trust token
        expected_token = _compute_trust_token(request)
        if request.state.auth_middleware_trust_token != expected_token:
            raise HTTPException(
                status_code=401,
                detail="Invalid middleware trust token"
            )
        
        return user
    
    # Fall through to JWT validation
    token = await get_token(request)
    return await get_auth_manager().get_user_from_token(token)

def _compute_trust_token(request: Request) -> str:
    """Compute trust token for middleware authentication."""
    # Use request-specific data + server secret
    data = f"{request.client.host}:{request.url.path}:{request.method}"
    secret = conf.get("api_auth", "middleware_trust_secret")
    return hmac.new(secret.encode(), data.encode(), "sha256").hexdigest()
```

Trusted middleware must set both user and trust token:

```python
class SimpleAllAdminMiddleware:
    async def __call__(self, request: Request, call_next):
        if self.enabled:
            request.state.user = SimpleUser(username="admin")
            request.state.auth_middleware_trust_token = _compute_trust_token(request)
        return await call_next(request)
```

### Acceptance Criteria
- [ ] Middleware-injected users require trust token
- [ ] Trust token computed from request-specific data + server secret
- [ ] `get_user()` validates trust token before accepting middleware user
- [ ] SimpleAllAdminMiddleware updated to set trust token
- [ ] Plugin registration validates middleware authentication contracts
- [ ] Tests added for trust token validation
- [ ] Documentation updated with secure middleware authentication patterns

### References
- ASVS 6.3.4 (L2, L3)
- airflow-core/src/airflow/api_fastapi/core_api/security.py:119-135
- airflow-core/src/airflow/api_fastapi/core_api/app.py:197

### Priority
Medium - Prevents authentication bypass through malicious plugins

---

## Issue: FINDING-134 - Inconsistent authentication strength between unauthenticated token generation endpoints and standard JWT-protected endpoints
**Labels:** bug, security, priority:medium, authentication, configuration
**Description:**
### Summary
When `simple_auth_manager_all_admins=True`, two endpoints issue ADMIN-level JWT tokens with ZERO authentication, with no runtime enforcement preventing this configuration in production environments.

### Details
In `login.py` lines 74-92, `GET /auth/token` and `GET /auth/token/login` issue admin tokens based solely on a boolean config check:
- No runtime enforcement prevents production deployment
- No environment detection
- No warning banner
- No audit log entry

While SimpleAuthManager is documented as "for development/testing," the code has no mechanism to prevent production use with `simple_auth_manager_all_admins=True`.

**Impact:**
- Production deployments could accidentally enable unauthenticated admin access
- Configuration error could expose entire system
- No defense-in-depth against misconfiguration

### Remediation
Add runtime safety checks:

```python
def _validate_simple_auth_config():
    """Validate Simple Auth Manager configuration safety."""
    if conf.getboolean("simple_auth_manager", "all_admins", fallback=False):
        # Check environment
        env = os.getenv("AIRFLOW_ENV", "production").lower()
        if env == "production":
            raise AirflowConfigException(
                "simple_auth_manager_all_admins=True is not allowed in production. "
                "This configuration grants unauthenticated admin access. "
                "Set AIRFLOW_ENV=development to use this feature."
            )
        
        # Log warning for non-production
        log.warning(
            "⚠️  SECURITY WARNING: simple_auth_manager_all_admins=True ⚠️\n"
            "Unauthenticated admin access is enabled. This configuration "
            "should ONLY be used in isolated development environments."
        )

@router.get("/token")
async def get_token(username: str = "admin") -> JSONResponse:
    """Issue token (DEVELOPMENT ONLY)."""
    _validate_simple_auth_config()
    
    # Audit log
    log.warning(
        f"Issuing unauthenticated admin token for user '{username}' "
        f"via Simple Auth Manager"
    )
    
    token = get_auth_manager().generate_jwt(SimpleUser(username=username))
    return JSONResponse({"access_token": token})
```

Add startup validation:

```python
# In app.py
def validate_auth_manager_config():
    """Validate auth manager configuration at startup."""
    auth_manager = get_auth_manager()
    if isinstance(auth_manager, SimpleAuthManager):
        _validate_simple_auth_config()
```

### Acceptance Criteria
- [ ] Runtime check prevents `simple_auth_manager_all_admins=True` in production
- [ ] Environment variable `AIRFLOW_ENV` controls enforcement
- [ ] Warning logged when issuing unauthenticated admin tokens
- [ ] Startup validation checks auth manager configuration
- [ ] Tests added for configuration validation
- [ ] Documentation updated with security warnings

### References
- ASVS 6.3.4 (L2, L3)
- airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py:74-92

### Priority
Medium - Prevents dangerous production misconfigurations

---

## Issue: FINDING-135 - Log serving authentication pathway lacks jti and sub claims, preventing token revocation and audit trailing
**Labels:** bug, security, priority:medium, jwt, logging
**Description:**
### Summary
Log serving JWT tokens lack `jti` (JWT ID) and `sub` (subject) claims, preventing individual token revocation and audit trailing when tokens are compromised.

### Details
From `test_serve_logs.py` lines 173-189 and `test_tokens.py`, log serving tokens only require:
- `aud` (audience)
- `iat` (issued at)
- `nbf` (not before)
- `exp` (expiration)
- `filename` (custom claim)

Missing claims:
- `jti` - Required for token revocation via `RevokedToken` mechanism
- `sub` - Required for audit identity

**Impact:**
- Compromised log tokens cannot be individually revoked
- Attacker can repeatedly access log files until token expires
- No audit trail of which user accessed logs
- Log access cannot be traced to specific identities

### Remediation
Update log token generation to include required claims:

```python
def generate_log_token(user: User, filename: str, expiration_seconds: int = 3600) -> str:
    """Generate JWT token for log file access with revocation support."""
    return get_auth_manager().generate_jwt(
        user,
        expiration_time_in_seconds=expiration_seconds,
        extra_claims={
            "filename": filename,
            "purpose": "log_access",
        }
    )
```

Ensure base `generate_jwt` includes `jti` and `sub`:

```python
def generate_jwt(self, user: T, *, extra_claims: dict | None = None, ...) -> str:
    """Generate JWT with required claims for revocation and audit."""
    claims = {
        "sub": user.get_id(),  # Subject identifier
        "jti": str(uuid.uuid4()),  # Unique token ID
        **self.serialize_user(user),
        **(extra_claims or {}),
    }
    return self._get_token_signer(...).generate(claims)
```

Update log serving endpoint to check revocation:

```python
async def serve_logs(token: str = Depends(get_token)):
    """Serve log file with revocation check."""
    # Validate token (includes revocation check)
    user = await get_auth_manager().get_user_from_token(token)
    
    # Extract and validate filename claim
    payload = jwt.decode(token, options={"verify_signature": False})
    filename = payload.get("filename")
    
    # Verify authorization for this specific log file
    if not get_auth_manager().is_authorized_log_access(
        user=user, filename=filename
    ):
        raise HTTPException(status_code=403)
    
    return FileResponse(filename)
```

### Acceptance Criteria
- [ ] Log serving tokens include `jti` claim
- [ ] Log serving tokens include `sub` claim
- [ ] Log serving endpoint checks `RevokedToken` table
- [ ] Token generation includes user identity in `sub`
- [ ] Tests added for log token revocation
- [ ] Audit logging added for log access with user identity
- [ ] Documentation updated with log token security

### References
- ASVS 6.3.4 (L2, L3)
- airflow-core/tests/unit/utils/test_serve_logs.py:173-189
- airflow-core/tests/unit/api_fastapi/auth/test_tokens.py

### Priority
Medium - Enables proper token lifecycle management for log access

---

## Issue: FINDING-136 - Undocumented Authentication Token Endpoint Referenced but Not Specified in API
**Labels:** security, priority:medium, documentation, openapi
**Description:**
### Summary
The OAuth2PasswordBearer security scheme references a `tokenUrl: /auth/token` endpoint that is not documented in the OpenAPI specification's paths section, preventing security review of authentication factors, rate limiting, and credential acceptance.

### Details
The OpenAPI specification defines `OAuth2PasswordBearer` with `tokenUrl: /auth/token`, but this endpoint is not documented in the `paths` section. Only `/api/v2/auth/login` and `/api/v2/auth/logout` are documented.

**Missing information:**
- What authentication factors are required
- Whether rate limiting or brute force protections are applied
- Whether the token endpoint enforces the same security policies
- What credential types are accepted (password, client credentials, etc.)

**Impact:**
- Security reviewers cannot verify authentication strength
- Penetration testers lack endpoint specification
- Compliance auditors cannot assess authentication controls
- Inconsistent documentation of authentication pathways

### Remediation
Add `/auth/token` endpoint to OpenAPI specification:

```yaml
paths:
  /auth/token:
    post:
      summary: Obtain access token
      description: |
        OAuth 2.0 token endpoint for obtaining access tokens.
        
        Supports the following grant types:
        - password: Resource Owner Password Credentials
        - client_credentials: Client Credentials (for service accounts)
        
        Rate limiting: 5 requests per minute per IP address
        Brute force protection: Account lockout after 5 failed attempts
      operationId: obtainToken
      tags:
        - Authentication
      requestBody:
        required: true
        content:
          application/x-www-form-urlencoded:
            schema:
              type: object
              required:
                - grant_type
              properties:
                grant_type:
                  type: string
                  enum: [password, client_credentials]
                username:
                  type: string
                  description: Required for password grant
                password:
                  type: string
                  format: password
                  description: Required for password grant
                client_id:
                  type: string
                  description: Required for client_credentials grant
                client_secret:
                  type: string
                  format: password
                  description: Required for client_credentials grant
                scope:
                  type: string
                  description: Optional space-separated list of scopes
      responses:
        '200':
          description: Access token issued successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  access_token:
                    type: string
                  token_type:
                    type: string
                    example: Bearer
                  expires_in:
                    type: integer
                    example: 3600
                  scope:
                    type: string
        '400':
          description: Invalid request
        '401':
          description: Authentication failed
        '429':
          description: Rate limit exceeded
      security: []  # No authentication required for token endpoint
```

### Acceptance Criteria
- [ ] `/auth/token` endpoint documented in OpenAPI specification
- [ ] Request body schema includes all supported grant types
- [ ] Response schemas documented for success and error cases
- [ ] Rate limiting policy documented
- [ ] Brute force protection documented
- [ ] Supported credential types clearly specified
- [ ] Security considerations section added

### References
- ASVS 6.3.4 (L2, L3)
- airflow-core/src/airflow/api_fastapi/core_api/openapi/v2-rest-api-generated.yaml

### Priority
Medium - Required for complete API security documentation

---

## Issue: FINDING-137 - BaseAuthManager framework provides no interface or enforcement for MFA during authentication factor recovery
**Labels:** security, priority:medium, mfa, authentication
**Description:**
### Summary
The BaseAuthManager abstract class defines no interface for multi-factor authentication enrollment, factor recovery, identity proofing during recovery, or factor lifecycle management, leaving MFA implementation entirely to concrete implementations without guidance.

### Details
The BaseAuthManager includes abstract methods for authentication (`get_url_login`, `deserialize_user`, `serialize_user`) and authorization (`is_authorized_*`), but provides NO interface for:
1. Multi-factor authentication enrollment
2. Authentication factor recovery/replacement
3. Identity proofing during factor recovery
4. Factor lifecycle management (expiration, rotation)

The documentation (`index.rst`) makes no mention of MFA requirements. As revealed by `EmptyAuthManager` in tests, there are no MFA-related abstract methods that must be implemented.

**Impact:**
- No framework-level MFA capability declaration
- Custom auth managers may omit MFA entirely
- No enforcement of identity proofing during factor recovery
- L2-compliant deployments cannot be verified

### Remediation
1. **Add MFA capability declaration:**

```python
class BaseAuthManager(ABC):
    def supports_mfa(self) -> bool:
        """
        Indicate whether this auth manager supports multi-factor authentication.
        
        L2-compliant deployments MUST use an auth manager that returns True.
        """
        return False
    
    def get_mfa_enforcement_level(self) -> str:
        """
        Get MFA enforcement level: 'none', 'optional', 'required', 'adaptive'.
        """
        return "none"
```

2. **Add CLI validation command:**

```python
@cli_utils.action_cli
def validate_auth_manager(args):
    """Validate auth manager meets ASVS requirements."""
    auth_manager = get_auth_manager()
    
    issues = []
    
    # Check MFA support for L2
    if not auth_manager.supports_mfa():
        issues.append(
            "⚠️  Auth manager does not support MFA (required for ASVS L2)"
        )
    
    # Check if Simple Auth Manager in production
    if isinstance(auth_manager, SimpleAuthManager):
        env = os.getenv("AIRFLOW_ENV", "production")
        if env == "production":
            issues.append(
                "❌ Simple Auth Manager should not be used in production"
            )
    
    if issues:
        print("Auth Manager Compliance Issues:")
        for issue in issues:
            print(f"  {issue}")
        sys.exit(1)
    else:
        print("✓ Auth manager meets ASVS L2 requirements")
```

3. **Add runtime configuration validation:**

```python
def validate_production_auth_config():
    """Validate auth manager configuration at startup."""
    auth_manager = get_auth_manager()
    
    if isinstance(auth_manager, SimpleAuthManager):
        env = os.getenv("AIRFLOW_ENV", "production").lower()
        if env == "production":
            log.error(
                "❌ Simple Auth Manager is configured in production environment. "
                "This auth manager does not support MFA and should only be used "
                "in development. Configure a production-ready auth manager."
            )
            raise AirflowConfigException(
                "Simple Auth Manager not allowed in production"
            )
```

4. **Document MFA requirements:**

```rst
Multi-Factor Authentication
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Auth manager implementations for production deployments SHOULD support
multi-factor authentication (MFA) to meet ASVS Level 2 requirements.

Implementing MFA Support
""""""""""""""""""""""""

To indicate MFA support, override the ``supports_mfa()`` method:

.. code-block:: python

    class MyAuthManager(BaseAuthManager):
        def supports_mfa(self) -> bool:
            return True
        
        def get_mfa_enforcement_level(self) -> str:
            return "required"  # or "optional", "adaptive"

Validating Auth Manager Compliance
""""""""""""""""""""""""""""""""""

Use the CLI to validate your auth manager configuration:

.. code-block:: bash

    airflow auth-manager validate
```

### Acceptance Criteria
- [ ] `supports_mfa()` method added to BaseAuthManager
- [ ] `get_mfa_enforcement_level()` method added
- [ ] CLI command `airflow auth-manager validate` implemented
- [ ] Runtime validation warns about Simple Auth Manager in production
- [ ] Documentation added for MFA requirements
- [ ] Tests added for MFA capability declaration

### References
- ASVS 6.4.4 (L2, L3)
- airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py

### Priority
Medium - Framework-level guidance needed for secure auth manager implementations

---

## Issue: FINDING-138 - No MFA Factor Recovery or Identity Re-proofing Mechanism Documented in API
**Labels:** security, priority:medium, mfa, api-documentation
**Description:**
### Summary
The API specification contains no endpoints for managing authentication factors (enrollment/removal), recovering lost factors, or performing identity re-proofing, making it impossible to verify ASVS L2 requirement that identity proofing at factor replacement matches enrollment level.

### Details
The API specification (`v2-rest-api-generated.yaml`) only includes:
- `/api/v2/auth/login` - Session initiation
- `/api/v2/auth/logout` - Session termination

Missing endpoints for:
- Managing authentication factors (enrolling/removing MFA devices)
- Recovering lost authentication factors
- Performing identity re-proofing when a factor is lost
- Password reset with identity verification

**Impact:**
- No verifiable mechanism for identity proofing during factor recovery
- Cannot demonstrate ASVS L2 compliance
- No documented MFA lifecycle management
- Unclear how users recover from lost MFA devices

### Remediation
Implement or document MFA recovery endpoints:

```yaml
paths:
  /api/v2/auth/factors:
    get:
      summary: List enrolled authentication factors
      description: Get list of MFA factors enrolled for the authenticated user
      operationId: listAuthFactors
      tags:
        - Authentication
      security:
        - BearerAuth: []
      responses:
        '200':
          description: List of enrolled factors
          content:
            application/json:
              schema:
                type: array
                items:
                  type: object
                  properties:
                    id:
                      type: string
                    type:
                      type: string
                      enum: [totp, webauthn, sms]
                    name:
                      type: string
                    enrolled_at:
                      type: string
                      format: date-time
  
  /api/v2/auth/factors/recovery:
    post:
      summary: Initiate MFA factor recovery
      description: |
        Initiate recovery process for lost MFA factor.
        
        For L2 applications, this requires identity proofing equivalent
        to enrollment:
        - Administrator approval, OR
        - Out-of-band identity verification
        
        This endpoint initiates the recovery process but does not
        immediately remove the factor. The user must complete identity
        proofing through the specified channel.
      operationId: initiateFactorRecovery
      tags:
        - Authentication
      security:
        - BearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required:
                - factor_id
                - recovery_method
              properties:
                factor_id:
                  type: string
                  description: ID of lost factor to recover
                recovery_method:
                  type: string
                  enum: [admin_approval, email_verification, phone_verification]
                  description: Identity proofing method
                contact_info:
                  type: string
                  description: Email or phone for out-of-band verification
      responses:
        '202':
          description: Recovery initiated, awaiting identity proofing
          content:
            application/json:
              schema:
                type: object
                properties:
                  recovery_id:
                    type: string
                  status:
                    type: string
                    example: pending_verification
                  next_steps:
                    type: string
                    example: "Check your email for verification link"
        '403':
          description: Not authorized to recover this factor
```

Add documentation section:

```rst
MFA Factor Recovery
^^^^^^^^^^^^^^^^^^^

When users lose access to an MFA factor (lost phone, broken hardware token),
they must complete an identity proofing process equivalent to initial enrollment.

Recovery Process
""""""""""""""""

1. User initiates recovery via ``POST /api/v2/auth/factors/recovery``
2. System requires identity proofing:
   
   - **Admin approval**: Administrator verifies identity and approves recovery
   - **Out-of-band verification**: Email or SMS verification to registered contact
   
3. After successful identity proofing, user can enroll a new factor
4. Old factor is removed only after new factor is successfully enrolled

This ensures continuous MFA protection and prevents attackers from
removing MFA by claiming factor loss.
```

### Acceptance Criteria
- [ ] `/api/v2/auth/factors` endpoint documented
- [ ] `/api/v2/auth/factors/recovery` endpoint documented
- [ ] Identity proofing methods specified
- [ ] Recovery process documented with security considerations
- [ ] Administrator approval workflow documented
- [ ] Out-of-band verification methods specified
- [ ] Tests added for factor recovery endpoints

### References
- ASVS 6.4.4 (L2, L3)
- airflow-core/src/airflow/api_fastapi/core_api/openapi/v2-rest-api-generated.yaml

### Priority
Medium - Required for L2 compliance and secure MFA lifecycle management

---

## Issue: FINDING-139 - No identity re-proofing mechanism visible for token revocation or session invalidation
**Labels:** security, priority:medium, authentication, token-revocation
**Description:**
### Summary
The token revocation mechanism does not require re-authentication or identity proofing before invalidating tokens, potentially allowing attackers with valid sessions to revoke tokens or trigger factor resets without proving identity.

### Details
From `test_tokens.py` lines 230-261, the token revocation data flow is:
1. User requests token revocation
2. `JWTValidator.revoke_token()` called
3. `jti` persisted in `RevokedToken` table
4. **No identity verification step visible**

**Risk:** If this mechanism is used for MFA factor loss (revoking tokens when user reports compromised authenticator), there's no evidence that identity is re-verified at the same level as during enrollment.

**Impact:**
- Attacker with valid session could revoke tokens
- Attacker could trigger factor resets without identity proof
- No protection against session hijacking leading to factor removal

### Remediation
Add identity verification requirement before token revocation:

```python
@router.post("/auth/tokens/revoke")
async def revoke_token(
    token_id: str,
    verification: IdentityVerification,
    current_user: User = Depends(get_user),
) -> JSONResponse:
    """
    Revoke a token with identity verification.
    
    Requires identity proofing equivalent to MFA enrollment to prevent
    attackers from revoking tokens after session compromise.
    """
    # Verify identity before allowing revocation
    if not await verify_identity_proofing(current_user, verification):
        raise HTTPException(
            status_code=403,
            detail="Identity verification required for token revocation"
        )
    
    # Revoke token
    await get_auth_manager().revoke_token(token_id)
    
    # Audit log
    log.warning(
        f"Token {token_id} revoked by user {current_user.get_id()} "
        f"after identity verification"
    )
    
    return JSONResponse({"status": "revoked"})

class IdentityVerification(BaseModel):
    """Identity verification for sensitive operations."""
    method: str  # 'password', 'mfa_code', 'admin_approval'
    credential: str  # Password, TOTP code, or approval token

async def verify_identity_proofing(
    user: User, 
    verification: IdentityVerification
) -> bool:
    """Verify user identity for sensitive operations."""
    if verification.method == "password":
        # Re-authenticate with password
        return await get_auth_manager().verify_password(
            user.username, verification.credential
        )
    elif verification.method == "mfa_code":
        # Verify current MFA code
        return await get_auth_manager().verify_mfa_code(
            user, verification.credential
        )
    elif verification.method == "admin_approval":
        # Verify admin approval token
        return await verify_admin_approval(verification.credential)
    return False
```

Update base auth manager interface:

```python
class BaseAuthManager(ABC):
    async def revoke_token(
        self, 
        token_id: str, 
        verification: IdentityVerification | None = None
    ) -> bool:
        """
        Revoke a token with optional identity verification.
        
        For sensitive operations (MFA factor recovery, account takeover
        response), identity verification SHOULD be required.
        """
        if verification:
            if not await self.verify_identity_proofing(verification):
                raise UnauthorizedError("Identity verification failed")
        
        # Proceed with revocation
        ...
```

### Acceptance Criteria
- [ ] Token revocation requires identity verification
- [ ] Multiple verification methods supported (password, MFA, admin approval)
- [ ] `verify_identity_proofing()` method added to BaseAuthManager
- [ ] Audit logging added for token revocations
- [ ] Tests added for identity verification before revocation
- [ ] Documentation updated with identity proofing requirements

### References
- ASVS 6.4.4 (L2, L3)
- airflow-core/tests/unit/api_fastapi/auth/test_tokens.py:230-261

### Priority
Medium - Prevents unauthorized token revocation and factor removal

---

## Issue: FINDING-140 - Auto-generated symmetric key lacks rotation mechanism
**Labels:** security, priority:low, key-management, rotation
**Description:**
### Summary
The auto-generated symmetric JWT signing key is per-process and ephemeral, providing no mechanism for key rotation without service restart and no graceful transition period where both old and new keys are accepted.

### Details
From `tokens.py` lines 564-582, the auto-generated key:
- Is fixed for the lifetime of the process
- Cannot be updated without restart
- Provides no multi-key support (unlike JWKS with multiple `kid` values)
- Requires immediate invalidation of all existing tokens on rotation
- Makes migration to post-quantum algorithms more disruptive

**Impact:**
- Key rotation requires service restart
- No graceful transition period
- All tokens immediately invalidated on rotation
- Difficult to respond to key compromise
- Challenging migration to new algorithms

CWE-320: Key Management Errors

### Remediation
Support multiple symmetric keys with `kid`-based selection:

```python
class MultiKeyJWTValidator:
    """JWT validator supporting multiple symmetric keys for rotation."""
    
    def __init__(self, secret_keys: dict[str, str], **kwargs):
        """
        Initialize validator with multiple keys.
        
        Args:
            secret_keys: Mapping of kid -> secret key
                Example: {
                    "2024-01": "current-secret-key",
                    "2023-12": "previous-secret-key"  # Still accepted during rotation
                }
        """
        self.secret_keys = secret_keys
        self.validators = {
            kid: JWTValidator(secret_key=key, **kwargs)
            for kid, key in secret_keys.items()
        }
        self.active_kid = max(secret_keys.keys())  # Most recent key
    
    async def validate(self, token: str) -> dict[str, Any]:
        """Validate token using appropriate key based on kid."""
        # Extract kid from header
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        
        if not kid or kid not in self.validators:
            raise InvalidTokenError(f"Unknown key ID: {kid}")
        
        # Validate with appropriate key
        return await self.validators[kid].validate(token)

class MultiKeyJWTGenerator:
    """JWT generator using active key with kid."""
    
    def __init__(self, secret_keys: dict[str, str], **kwargs):
        self.secret_keys = secret_keys
        self.active_kid = max(secret_keys.keys())
        self.generator = JWTGenerator(
            secret_key=secret_keys[self.active_kid],
            **kwargs
        )
    
    def generate(self, payload: dict[str, Any]) -> str:
        """Generate token with active kid in header."""
        # Add kid to header
        token = self.generator.generate(payload)
        # Modify header to include kid
        header, payload_part, signature = token.split(".")
        header_dict = json.loads(base64url_decode(header))
        header_dict["kid"] = self.active_kid
        new_header = base64url_encode(json.dumps(header_dict).encode())
        return f"{new_header}.{payload_part}.{signature}"
```

Configuration:

```ini
[api_auth]
jwt_secret_keys = {
    "2024-01": "current-secret-key-base64",
    "2023-12": "previous-secret-key-base64"
}
jwt_active_kid = 2024-01
```

Key rotation procedure:

```rst
Key Rotation
^^^^^^^^^^^^

To rotate symmetric JWT signing keys:

1. Generate new key: ``airflow auth generate-key --kid 2024-02``
2. Add new key to configuration while keeping old key
3. Set new key as active: ``jwt_active_kid = 2024-02``
4. Restart services (new tokens use new key, old tokens still valid)
5. Wait for old tokens to expire (default: 1 hour)
6. Remove old key from configuration
```

### Acceptance Criteria
- [ ] Multi-key support implemented for symmetric keys
- [ ] `kid` (key ID) included in JWT header
- [ ] Validator accepts tokens signed with any configured key
- [ ] Generator uses active key for new tokens
- [ ] Configuration supports multiple keys
- [ ] CLI command for key generation with kid
- [ ] Documentation added for key rotation procedure
- [ ] Tests added for multi-key validation

### References
- ASVS 11.2.2 (L2)
- CWE-320
- airflow-core/src/airflow/api_fastapi/auth/tokens.py:564-582

### Priority
Low - Enhancement for operational flexibility, not immediate security risk

---

*[Continued in next response due to length...]*

---

## Issue: FINDING-141 - Token identifier (jti) uses UUID4 which the ASVS explicitly identifies as not meeting 128-bit entropy requirement

**Labels:** bug, security, priority:low

**Description:**

The ASVS requirement explicitly states "Note that UUIDs do not respect this condition." UUID version 4 provides 122 random bits (6 bits are fixed for version and variant markers), sourced from CSPRNG (os.urandom in CPython). While practically very close to 128 bits, the specification does not technically meet the stated requirement. The jti is primarily used for uniqueness (token revocation tracking) rather than as a cryptographic secret. With 122 bits of randomness from CSPRNG, collision probability and guessability remain negligible. However, the implementation doesn't technically satisfy the ASVS requirement.

**Remediation:** Replace uuid.uuid4() with os.urandom(16) for full 128-bit entropy:

import os
from base64 import urlsafe_b64encode

def _generate_jti() -> str:
    """Generate a cryptographically random token identifier with 128 bits of entropy."""
    return urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode("ascii")

# In generate():
claims = {
    "jti": _generate_jti(),
    ...
}

**Priority:** Low

---

## Issue: FINDING-142 - No minimum key size validation for loaded asymmetric keys

**Labels:** bug, security, priority:low

**Description:**

When loading RSA keys from the configured file path, there is no validation that: RSA keys meet minimum 2048-bit size requirements, the public exponent is appropriate (e.g., not 3 which has known vulnerabilities), or the key isn't vulnerable to known factorization attacks. A deployment using a legacy 1024-bit RSA key (or even smaller) would function without any warning or error. Deployments could inadvertently use weak RSA keys (≤1024 bits are factorable with current resources), there is no defense-in-depth against misconfiguration, and tokens could be compromised if weak key is factored.

**Remediation:** Add validation in `_pem_to_key()` to check RSA key size is at least 2048 bits and public exponent is at least 65537. Raise ValueError with clear message if key does not meet minimum requirements.

**Priority:** Low

---

## Issue: FINDING-143 - `generate_private_key()` utility exported without minimum key size enforcement

**Labels:** bug, security, priority:low

**Description:**

The function is included in `__all__` (exported as public API) and accepts arbitrary `key_size` parameter without enforcing minimums. A caller could invoke `generate_private_key('RSA', key_size=512)` generating a trivially factorable key. While documented as 'for testing,' its presence in `__all__` makes it available for production use by other modules or plugins. The function's default (2048 bits) is appropriate, and the docstring indicates testing use. However, exporting it without minimum enforcement creates a hazard for downstream callers.

**Remediation:** Add validation: `if key_type == 'RSA' and key_size < 2048: raise ValueError(f'RSA key_size must be at least 2048 bits, got {key_size}')`

**Priority:** Low

---

## Issue: FINDING-144 - No validation that dynamically-provided audience values cannot impersonate other services

**Labels:** bug, security, priority:low

**Description:**

The `JWTGenerator` accepts the `audience` parameter without validating it against a registry of known audiences. While the current implementation uses static configuration values, the ASVS requirement states that if the audience identifier is dynamically provisioned, the token issuer must validate these audiences in order to make sure that they do not result in audience impersonation. If future code paths pass dynamically-derived audience values to `JWTGenerator`, there is no allowlist validation to prevent issuing tokens for audiences that could impersonate other services. Current risk is low since audiences are sourced from static configuration.

**Remediation:** Add audience validation when audience is set dynamically (not from static config). Define a registry of valid audiences: `VALID_AUDIENCES = frozenset({"urn:airflow.apache.org:task", "urn:airflow.apache.org:api"})`. In the `generate()` method, validate: `if audience_override and audience_override not in VALID_AUDIENCES: raise ValueError(f"Audience '{audience_override}' is not in the allowed audience registry")`. Consider implementing a dedicated audience registry that validates audience values against known services before token generation.

**Priority:** Low

---

## Issue: FINDING-145 - Cannot Verify Password Field Masking — Frontend Template Not in Audit Scope

**Labels:** bug, security, priority:low

**Description:**

The login UI is served via Jinja2 templates from a directory, but the actual HTML template (index.html) is not included in the audit scope. The template is served from ui/dev/ or ui/dist/ directories depending on DEV_MODE environment variable. Without access to the index.html file, it is impossible to verify whether password input fields use type="password" for masking. If the login form uses type="text" instead of type="password", passwords would be visible on screen during entry, enabling shoulder-surfing attacks.

**Remediation:** Verify that the frontend template contains: &lt;input type="password" name="password" id="password" autocomplete="current-password" /&gt; And optionally provides a show/hide toggle that temporarily switches to type="text".

**Priority:** Low

---

## Issue: FINDING-146 - Auto-Generated Passwords Limited to 16 Characters with No User-Facing Mechanism to Set Longer Passwords

**Labels:** bug, security, priority:low

**Description:**

While the system does not explicitly reject 64-character passwords (the string comparison at services/login.py line 60 has no length limitation), there is no user-facing mechanism to set a custom password of any length. Users cannot register or change their passwords through the application. Passwords are exclusively system-generated at 16 characters. This means the requirement is technically met at the storage/verification layer but not at the user interaction layer. If an administrator manually edits the password file to contain a 64-character password, the system will accept it during login. However, users have no self-service path to set such passwords.

**Remediation:** If password change functionality is added in the future, ensure no max_length constraint below 64 is applied. Example: class LoginBody(BaseModel): username: str; password: str = Field(..., max_length=128). Add a password change endpoint that demonstrates secure password change flows. Document minimum password length policy and ensure user-chosen passwords support at least 64 characters.

**Priority:** Low

---

## Issue: FINDING-147 - No Documentation of Minimum Authentication Strength Requirements for Production Auth Managers

**Labels:** bug, security, priority:low

**Description:**

While the documentation acknowledges that Simple Auth Manager is for development and lists available auth managers, it does not document minimum authentication strength requirements that production auth managers must meet. The abstract interface in base_auth_manager.py enforces structural contracts (abstract methods) but has no documentation of security strength requirements. Custom auth manager implementers have no guidance on minimum security requirements (e.g., password complexity, MFA support, brute-force protection) that should be consistently enforced regardless of the auth pathway.

**Remediation:** Add a 'Security Requirements for Auth Manager Implementations' section documenting minimum authentication strength expectations including password complexity, MFA support, brute-force protection, and credential storage requirements for production auth manager implementations.

**Priority:** Low

---

## Issue: FINDING-148 - Default Filter Implementations May Expose Resource Existence via Timing

**Labels:** bug, security, priority:low

**Description:**

The default `filter_authorized_*` implementations iterate through all resources and check authorization individually. This serial check pattern can reveal timing information about resource count, though this is primarily a performance concern. The actual security posture (checking each resource individually) is correct.

**Remediation:** Already addressed in documentation - implementations should override for performance.

**Priority:** Low

---

## Issue: FINDING-149 - ConfigurationDetails and AssetDetails Lack Team-Scoping

**Labels:** bug, security, priority:low

**Description:**

The ConfigurationDetails and AssetDetails dataclasses do not include a team_name field, while other resource types (Connections, DAGs, Pools, Variables) do. This inconsistency means configuration sections and assets cannot be team-scoped, potentially creating shared attack surfaces between teams. Teams share configuration and asset namespaces without isolation, meaning one team's configuration changes could affect another team's operations.

**Remediation:** Evaluate whether ConfigurationDetails and AssetDetails should include team_name for multi-team deployments, or document why these resources are intentionally global.

**Priority:** Low

---

## Issue: FINDING-150 - JSONResponse without explicit charset specification

**Labels:** bug, security, priority:low

**Description:**

The endpoints use JSONResponse without explicit charset. However, per RFC 8259, JSON text MUST be encoded as UTF-8 and the charset parameter has no meaning for application/json. Starlette's JSONResponse correctly sets Content-Type: application/json without charset, which is compliant with RFC 8259 Section 8.1. This is not a true vulnerability but worth documenting for completeness.

**Remediation:** No action needed for JSON responses. For the HTML template response, Starlette already appends ; charset=utf-8 to text/html responses automatically.

**Priority:** Low

---

## Issue: FINDING-151 - StaticFiles mount does not explicitly reject unsupported HTTP methods with 405

**Labels:** bug, security, priority:low

**Description:**

The `StaticFiles` mount in Starlette responds to GET and HEAD requests by default, which is appropriate. However, the mounted path `/static` will accept any HTTP method without returning 405 — Starlette's `StaticFiles` will return 404 for non-existent resources regardless of method but may not explicitly reject unsupported methods with a 405 response. However, FastAPI's router-based endpoints (defined with `@app.get(...)`) correctly return 405 Method Not Allowed for unsupported methods. This is a minor observation rather than a significant vulnerability.

**Remediation:** For Level 3 compliance, consider adding a method-filtering middleware:
python
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}

class AllowedMethodsMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if request.method not in ALLOWED_METHODS:
            return Response(status_code=405, headers={"Allow": ", ".join(ALLOWED_METHODS)})
        return await call_next(request)

**Priority:** Low

---

## Issue: FINDING-152 - Protocol Translation Boundary in WSGIMiddleware Creates Request Smuggling Risk

**Labels:** bug, security, priority:low

**Description:**

The `WSGIMiddleware` bridge converts ASGI (HTTP/1.1, HTTP/2) requests into WSGI format for legacy Flask plugins. This protocol conversion point introduces potential request smuggling risk because: 1) Protocol translation involves re-interpreting HTTP message boundaries. If the ASGI server and Flask/Werkzeug disagree on Content-Length vs. Transfer-Encoding handling, smuggling could occur. 2) Dual-stack parsing: The ASGI server (Uvicorn) parses the HTTP message first, then WSGIMiddleware reconstructs it for Flask/Werkzeug to re-parse. Discrepancies in how each layer handles malformed headers could enable smuggling. 3) No explicit Content-Length/Transfer-Encoding validation: The middleware stack doesn't include any validation that prevents conflicting Content-Length and Transfer-Encoding headers from reaching the Flask layer. However, this is mitigated by: Uvicorn uses `httptools` or `h11` for HTTP parsing, both of which reject conflicting CL/TE headers; The path is only `/pluginsv2` (limited scope); This is only active when legacy Airflow 2 plugins are present.

**Remediation:** Add middleware to reject requests with both Content-Length and Transfer-Encoding:
python
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

class AntiSmugglingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        has_cl = "content-length" in request.headers
        has_te = "transfer-encoding" in request.headers
        if has_cl and has_te:
            return Response(status_code=400, content="Ambiguous message framing")
        return await call_next(request)

Long-term: Plan migration path to eliminate the Flask plugin bridge (`WSGIMiddleware`), removing the protocol translation boundary that creates request smuggling risk.

**Priority:** Low

---

## Issue: FINDING-153 - InProcess Execution API Bypasses JWT Authentication Entirely

**Labels:** bug, security, priority:low

**Description:**

The DAG File Processor and Triggerer components do NOT use authenticated communication for their Execution API interactions when using in-process mode. The JWT bearer dependency is overridden to always return a synthetic TIToken with the 'execution' scope, effectively bypassing token validation. Per-resource access controls (connection, variable, and XCom access checks) are also overridden to always allow. This means malicious DAG code could exploit the bypassed authentication. However, this is explicitly documented and necessary for the in-process design, and is limited to in-process communication with no network exposure.

**Remediation:** This is an in-process communication limitation that is documented as a known security boundary issue. Mitigation should be addressed through deployment-level isolation as recommended in the documentation. The in-process API provides full unauthenticated access to connections, variables, and XComs, so ensure proper deployment isolation when malicious DAG code may be present.

**Priority:** Low

---

## Issue: FINDING-154 - InProcess API Grants Unrestricted Access Without Per-Resource Authorization

**Labels:** bug, security, priority:low

**Description:**

The InProcess Execution API overrides access controls to 'always allow,' meaning DAG code running in the DFP/Triggerer can access any connection, variable, or XCom regardless of ownership or team boundaries. This violates least-privilege for these components. Mitigating factors include: in-process communication only (no network exposure), multi-team isolation requires deployment-level separation (documented), and this is explicitly acknowledged as a known limitation.

**Remediation:** Implement per-resource access controls for DFP/Triggerer components, or provide deployment-level isolation guidance for multi-team environments to enforce resource boundaries at the infrastructure level.

**Priority:** Low

---

## Issue: FINDING-155 - Database Connection Credentials in Documentation Examples Without Security Warning

**Labels:** bug, security, priority:low

**Description:**

While these are clearly documentation examples (not source code), the use of weak example passwords (airflow_pass) without an accompanying security note about using strong, randomly generated passwords from a secrets manager could lead to operators copying patterns directly. Similar examples appear for MySQL. Operators may copy them directly for non-production environments that later get promoted.

**Remediation:** Add a security note after the SQL examples warning that the credentials above are for illustration only. In production, generate strong random passwords and store them in your secrets management solution. Never use predictable passwords like 'airflow_pass'.

**Priority:** Low

---

## Issue: FINDING-156 - No Documented Least Privilege Controls for Secrets Access

**Labels:** bug, security, priority:low

**Description:**

The secrets backend documentation describes a search path mechanism (secrets backend → environment variables → metastore) but does not document or enforce least-privilege access controls. Specifically: 1. No guidance on restricting which Airflow components can access which secrets 2. No role-based filtering of secrets access (all components with backend access can read all secrets) 3. The common.py database session creation does not incorporate any secrets-specific access controls 4. No documentation on configuring backend-level ACLs (e.g., Vault policies limiting access to specific paths). Any Airflow component that can access the secrets backend can potentially read any secret stored there. Without least-privilege documentation, operators may grant overly broad access.

**Remediation:** Add documentation section on configuring least-privilege access:

Least Privilege Configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When configuring secrets backends, follow the principle of least privilege:

1. **Backend-level ACLs**: Configure your secrets backend (e.g., Vault policies,
   AWS IAM policies) to restrict access to only the secrets each component needs.
2. **Worker isolation**: Use the worker-specific secrets backend configuration
   to limit worker access to only connection credentials, not administrative secrets.
3. **Path-based separation**: Organize secrets by component role
   (e.g., ``airflow/connections/``, ``airflow/variables/``, ``airflow/config/``)
   and apply separate access policies to each path.

**Priority:** Low

---

## Issue: FINDING-157 - Secrets Backend Documentation Lacks TTL/Expiration Guidance

**Labels:** bug, security, priority:low

**Description:**

The secrets backend documentation covers configuration and lookup order but does not address: secret expiration or time-to-live (TTL) policies, automatic rotation schedules, or classification of secrets by sensitivity level for differential retention. Organizations implementing secrets backends without TTL guidance may store secrets indefinitely, including credentials for decommissioned services or former employees' API tokens.

**Remediation:** Add a section on secret lifecycle management covering TTL/expiration policies for different secrets backends. Include guidance for AWS Secrets Manager rotation schedules with rotation_rules, HashiCorp Vault TTL configuration and dynamic secrets, and GCP Secret Manager expiration dates with IAM conditions. Ensure unused secrets are removed when associated connections are decommissioned.

**Priority:** Low

---

## Issue: FINDING-158 - XCom Side-Channel Not Classified in Sensitive Data Inventory

**Labels:** bug, security, priority:low

**Description:**

XCom values are acknowledged as a potential carrier of sensitive data, but XCom is not included in the data classification scheme. The documentation identifies this as a limitation but does not classify XCom-passed secrets as sensitive data requiring protection controls. The automatic masking is triggered by Connection or Variable access. This means that if you pass a sensitive value via XCom or any other side-channel it will not be masked when printed in the downstream task. Sensitive data transmitted via XCom bypasses all masking controls. Without classifying this channel in the data inventory, there's no requirement to address it.

**Remediation:** Document XCom as a sensitive data channel and either extend masking to XCom values containing sensitive keywords, or document the risk acceptance with compensating controls (e.g., restrict log access).

**Priority:** Low

---

## Issue: FINDING-159 - Masking Disable Option Lacks Risk Documentation

**Labels:** bug, security, priority:low

**Description:**

The documentation mentions that masking can be entirely disabled via configuration (config:core__hide_sensitive_var_conn_fields set to false), but provides no warning about the security implications or documented compensating controls that should be in place when masking is disabled. Administrators may disable masking for debugging purposes and forget to re-enable it, resulting in sensitive data exposure in logs without any protective controls.

**Remediation:** Add a security warning admonition and document compensating controls: 'WARNING: Disabling masking exposes all sensitive values in logs and UI. If disabled: (1) Ensure log access is restricted to authorized personnel only, (2) Enable audit logging for log access, (3) Re-enable masking immediately after debugging, (4) Consider using mask_secret() for critical values even when global masking is disabled.'

**Priority:** Low

---

## Issue: FINDING-160 - No Documentation of Cache Protection for Sensitive Data

**Labels:** bug, security, priority:low

**Description:**

The masking documentation describes protection of sensitive data in logs and UI displays but does not address caching mechanisms. Given that the masking system processes sensitive values in memory: (1) No mention of whether masked or unmasked values are subject to application-level caching, (2) No documentation of cache-control headers for UI endpoints displaying masked values, (3) No guidance on purging sensitive data from server-side caches after rendering. This is a documentation gap — the protection requirements for sensitive data should include cache handling.

**Remediation:** Add a section to the documentation addressing cache behavior:

Cache Behavior
"""""""""""""""

Masked values are not cached in their unmasked form by the Airflow web server.
Connection and Variable values are fetched fresh for each rendering request.
Ensure your deployment's reverse proxy does not cache pages containing masked values.

**Priority:** Low

## Issue: FINDING-161 - Log retention policy lacks specific enforceable durations
**Labels:** bug, security, priority:low
**Description:**
### Summary
The document states retention as vague ranges rather than specific, enforceable policies. The retention requirements are described as 'Long-term (months to years for compliance), if not purged from database' for audit logs and 'Short to medium-term (days to weeks)' for event logs. Without specific retention periods, organizations cannot verify compliance with regulatory requirements or implement automated log lifecycle management.

### Details
**CWE:** None specified  
**ASVS:** 16.1.1 (L2)  
**Affected Files:**
- `airflow-core/docs/security/audit_logs.rst` (Audit Logs vs Event Logs table)

Without specific retention periods, organizations cannot verify compliance with regulatory requirements or implement automated log lifecycle management.

### Remediation
Document specific default retention periods and configuration mechanisms. Add a 'Log Retention Configuration' section that specifies audit log retention is controlled by the [core] audit_log_retention_days configuration parameter with a default of 365 days. Document that event log retention defaults to 30 days and is controlled by [logging] event_log_retention_days. Explain that logs older than these thresholds are eligible for archival or deletion via the 'airflow db clean' command.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Report: 16.1.1.md
- Domain: audit_logging

### Priority
Low

---

## Issue: FINDING-162 - CLI event metadata lacks documented structure for execution context
**Labels:** bug, security, priority:low
**Description:**
### Summary
The document mentions CLI command entries include execution context but doesn't provide the actual field mapping. The claim that "environment variables" are logged raises both a security concern (potentially logging secrets in environment) and a metadata completeness question (how is this stored in the schema?). Unclear whether CLI metadata is actually stored in the documented schema fields or if this is aspirational documentation.

### Details
**CWE:** None specified  
**ASVS:** 16.2.1 (L2)  
**Affected Files:**
- `airflow-core/docs/security/audit_logs.rst` (CLI Events section end)

The claim about logging environment variables could expose secrets.

### Remediation
Clarify which schema fields map to CLI metadata and add warnings about sensitive data. Add documentation warning that CLI audit log entries store command details in the extra JSON field, environment variables are NOT logged to prevent secret exposure, and only the command line arguments (with sensitive values masked) are recorded.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Report: 16.2.1.md
- Domain: audit_logging

### Priority
Low

---

## Issue: FINDING-163 - Event log format not documented for machine readability
**Labels:** bug, security, priority:low
**Description:**
### Summary
While audit logs have a defined schema, event logs (scheduler, webserver, task logs) have no documented format specification. The document only shows access methods (tail, cat, REST API) without specifying what parsers should expect. Log processors cannot be reliably configured to parse Airflow event logs without reverse-engineering the format from actual output.

### Details
**CWE:** None specified  
**ASVS:** 16.2.4 (L2)  
**Affected Files:**
- `airflow-core/docs/security/audit_logs.rst` (Understanding Event Logs section)

### Remediation
Document the event log format with example output and parsing guidance. Specify the Python logging format string used and provide examples of actual log output that parsers should expect.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Report: 16.2.4.md
- Domain: audit_logging

### Priority
Low

---

## Issue: FINDING-164 - Configuration Security Context Not Documented
**Labels:** bug, security, priority:low
**Description:**
### Summary
The documentation describes several configuration parameters that, if manipulated, could affect system behavior (executor module paths accepting arbitrary Python classes, custom executor code execution). The documentation does not address validation of these configuration inputs from a security perspective. Configuration parameters with security implications if misconfigured (e.g., use_row_level_locking, custom executor module paths) lack security context documentation.

### Details
**CWE:** CWE-1059  
**ASVS:** 2.1.1 (L1)  
**Affected Files:**
- `executor/index.rst`
- `scheduler.rst`

**Related Findings:** FINDING-084, FINDING-165

### Remediation
Add security context to configuration parameter documentation, noting which parameters have security implications if misconfigured (e.g., use_row_level_locking, custom executor module paths). Consider documenting threat model for the scheduler/executor subsystem, particularly around DAG author trust boundaries and the implications of custom executor code execution.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Report: 2.1.1.md
- Domain: dag_input_validation

### Priority
Low

---

## Issue: FINDING-165 - Security Boundaries Not Explicitly Documented
**Labels:** bug, security, priority:low
**Description:**
### Summary
The scheduler documentation describes the critical section where task instances transition from scheduled to enqueued state, protected by database row-level locks. This is a trust-relevant architectural decision that is well-documented from an operational perspective but not explicitly framed as a security boundary. The documentation implicitly references several validation mechanisms without formally specifying them as security controls.

### Details
**CWE:** CWE-1059  
**ASVS:** 2.1.1 (L1)  
**Affected Files:**
- `scheduler.rst`

**Related Findings:** FINDING-084, FINDING-164

### Remediation
Document security boundaries explicitly in the scheduler architecture documentation, distinguishing between performance limits and security-enforced limits. Document the trust boundaries and security implications of the critical sections in the scheduler workflow.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Report: 2.1.1.md
- Domain: dag_input_validation

### Priority
Low

---

## Issue: FINDING-166 - Missing URL Validation for backend_server_base_url Template Context
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `backend_server_base_url` is passed to the SPA's `index.html` template from `request.base_url.path`. If the client-side JavaScript uses this value to construct API endpoint URLs, there is no server-side validation that the value does not contain protocol handlers (e.g., `javascript:`, `data:`), is properly URL-encoded, or is constrained to expected path formats.

### Details
**CWE:** None specified  
**ASVS:** 1.2.2 (L1)  
**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/core_api/app.py` (lines 101-107)

Impact: Low — requires proxy misconfiguration and non-standard behavior to exploit.

### Remediation
Add validation to ensure `request.base_url.path` matches expected path patterns before passing to the template. Example:
```python
import re

@app.get("/{rest_of_path:path}", response_class=HTMLResponse, include_in_schema=False)
def webapp(request: Request, rest_of_path: str):
    base_path = request.base_url.path
    # Validate that base_url.path is a legitimate path prefix
    if not re.match(r'^/[a-zA-Z0-9/_-]*$', base_path):
        base_path = "/"
    return templates.TemplateResponse(
        request,
        "/index.html",
        {"backend_server_base_url": base_path},
        media_type="text/html",
    )
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Report: 1.2.2.md
- Domain: web_ui_security

### Priority
Low

---

## Issue: FINDING-167 - Missing X-Content-Type-Options header in proxy configuration documentation
**Labels:** bug, security, priority:low
**Description:**
### Summary
The proxy configuration documentation provides an example CSP header but does not mention the X-Content-Type-Options: nosniff header. Operators following this guide would not configure this header at the proxy level either, leaving a defense-in-depth gap.

### Details
**CWE:** None specified  
**ASVS:** 3.4.4 (L2)  
**Affected Files:**
- `airflow-core/docs/howto/run-behind-proxy.rst`

### Remediation
Add X-Content-Type-Options: nosniff to the documented proxy configuration:

```
add_header X-Content-Type-Options "nosniff" always;
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Report: 3.4.4.md
- Domain: web_ui_security

### Priority
Low

---

## Issue: FINDING-168 - Missing Referrer-Policy Guidance in Reverse Proxy Documentation
**Labels:** bug, security, priority:low
**Description:**
### Summary
The reverse proxy documentation does not include guidance on setting a Referrer-Policy header, leaving operators without guidance on this control.

### Details
**CWE:** None specified  
**ASVS:** 3.4.5 (L2)  
**Affected Files:**
- `airflow-core/docs/howto/run-behind-proxy.rst`

### Remediation
Add to documented proxy configuration:

```
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Report: 3.4.5.md
- Domain: web_ui_security

### Priority
Low

---

## Issue: FINDING-169 - CSP frame-ancestors documented as optional proxy configuration rather than required application-level control
**Labels:** bug, security, priority:low
**Description:**
### Summary
The documentation correctly suggests frame-ancestors 'self' but presents it only as optional proxy configuration guidance rather than a required application-level default. If operators don't configure a reverse proxy or don't follow this specific documentation, the protection is absent. The requirement states this header must be present for every HTTP response.

### Details
**CWE:** None specified  
**ASVS:** 3.4.6 (L2)  
**Affected Files:**
- `airflow-core/docs/howto/run-behind-proxy.rst` (lines 47-49)

### Remediation
Implement frame-ancestors 'self' as a default at the application level (defense-in-depth), and document the proxy configuration as supplementary rather than the primary security control.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Report: 3.4.6.md
- Domain: web_ui_security

### Priority
Low

---

## Issue: FINDING-170 - Documentation Recommends Disabling HttpOnly Without CSRF Compensating Controls
**Labels:** bug, security, priority:low
**Description:**
### Summary
The official documentation explicitly instructs operators to NOT enforce HttpOnly on cookies, stating the frontend needs JavaScript access to cookies. This directly contradicts ASVS 3.3.4 which requires HttpOnly for cookies whose values (such as session tokens) should not be accessible to client-side scripts. If session tokens or refresh tokens are stored in cookies without HttpOnly, an XSS vulnerability would allow direct theft of authentication credentials.

### Details
**CWE:** CWE-1004  
**ASVS:** 3.5.1, 3.3.4 (L1, L2)  
**Affected Files:**
- `airflow-core/docs/howto/run-behind-proxy.rst` (lines 58-59)

Any XSS vulnerability becomes a full account takeover vector, as the attacker can steal the authentication token.

### Remediation
Separate cookie concerns: (1) Use HttpOnly cookies for session/refresh tokens (server-side only). (2) If the frontend needs state information, use a separate non-sensitive cookie or deliver that info via API response body. Example: Set session token with httponly=True, secure=True, samesite='Lax'. For UI preferences, use a separate cookie with httponly=False but containing only non-sensitive data.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Report: 3.5.1.md, 3.3.4.md
- Domain: web_ui_security

### Priority
Low

---

## Issue: FINDING-171 - Documentation recommends path-based rather than hostname-based separation
**Labels:** bug, security, priority:low
**Description:**
### Summary
The documentation guides users toward path-based deployment (/myorg/airflow/) on a shared hostname. If multiple applications are hosted on the same hostname at different paths, they share the same origin for JavaScript and cookie purposes. The documentation does not mention the security implications or recommend hostname-based separation.

### Details
**CWE:** None specified  
**ASVS:** 3.5.4 (L2)  
**Affected Files:**
- `airflow-core/docs/howto/run-behind-proxy.rst` (lines 28-33)

Deployers following this guide may co-host Airflow with other applications on the same hostname, weakening origin-based browser security boundaries.

### Remediation
Update documentation to recommend hostname-based separation as a security best practice for production deployments, especially when co-hosting with other applications. Include security implications of path-based deployment on shared hostnames.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Report: 3.5.4.md
- Domain: web_ui_security

### Priority
Low

---

## Issue: FINDING-172 - Static file serving without explicit authorization check or Cross-Origin-Resource-Policy header
**Labels:** bug, security, priority:low
**Description:**
### Summary
Static files are served directly from the filesystem without: 1. Any authentication/authorization middleware (StaticFiles bypasses route-level middleware in some configurations) 2. A `Cross-Origin-Resource-Policy` response header 3. Verification that sensitive data is not included in build artifacts. If build processes ever embed configuration, API keys, or user-specific data into JavaScript bundles, these would be accessible as script resources without authorization.

### Details
**CWE:** None specified  
**ASVS:** 3.5.7, 3.5.8 (L3)  
**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/core_api/app.py` (lines 62-69)

The `html=True` flag enables directory browsing fallback, and custom deployments could inadvertently expose sensitive files.

### Remediation
Implement SecFetchMiddleware to validate Sec-Fetch-* headers and set Cross-Origin-Resource-Policy header. For API endpoints, reject cross-origin non-navigate fetches by checking Sec-Fetch-Site and Sec-Fetch-Mode headers. Set Cross-Origin-Resource-Policy: same-origin header on all responses. Example implementation: Create SecFetchMiddleware class that validates sec_fetch_site in ("cross-site", "same-site") and sec_fetch_mode not in ("cors", "navigate") for /api/ paths, returning 403 if conditions are met. Add response.headers["Cross-Origin-Resource-Policy"] = "same-origin" to all responses. Add middleware via app.add_middleware(SecFetchMiddleware).

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Report: 3.5.7.md, 3.5.8.md
- Domain: web_ui_security

### Priority
Low

---

## Issue: FINDING-173 - Documentation Uses HTTP in Base URL Examples
**Labels:** bug, security, priority:low
**Description:**
### Summary
The documentation example for `base_url` uses `http://` which may lead operators to configure the application without TLS enforcement. Operators following documentation examples may not configure TLS, leaving the application vulnerable to eavesdropping.

### Details
**CWE:** None specified  
**ASVS:** 3.7.4 (L3)  
**Affected Files:**
- `airflow-core/docs/howto/run-behind-proxy.rst` (line 33)

### Remediation
Update documentation examples to use `https://` and add a note about mandatory TLS in production.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Report: 3.7.4.md
- Domain: web_ui_security

### Priority
Low

---

## Issue: FINDING-174 - No Explicit Token Revocation Check in JWT Refresh Middleware
**Labels:** bug, security, priority:low
**Description:**
### Summary
The middleware uses stateless JWTs without any server-side revocation check. There is no call to a token revocation store, blocklist, or validity check before accepting and refreshing a JWT. If a user revokes their session through a UI, the JWT remains valid until its exp claim expires unless additional infrastructure performs revocation checks.

### Details
**CWE:** None specified  
**ASVS:** 10.4.9 (L2, L3)  
**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py`

### Remediation
Add an explicit revocation check before accepting a token for refresh. Example implementation:

```python
@staticmethod
async def _refresh_user(current_token: str) -> tuple[BaseUser | None, BaseUser | None]:
    user = await resolve_user_from_token(current_token)
    
    # Check if token or session has been revoked
    token_jti = extract_jti(current_token)
    if await get_auth_manager().is_token_revoked(token_jti):
        raise HTTPException(status_code=401, detail="Token has been revoked")
    
    return get_auth_manager().refresh_user(user=user), user
```

Additionally, implement a server-side token tracking mechanism (e.g., Redis-backed store) that tracks issued JTIs to enable revocation checks. Ensure users can view active sessions and revoke individual tokens through the Airflow web UI.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Report: 10.4.9.md
- Domain: token_refresh_middleware

### Priority
Low

---

## Issue: FINDING-175 - Kerberos Credential Cache Stored in World-Accessible /tmp Directory
**Labels:** bug, security, priority:low
**Description:**
### Summary
The documentation reveals that the default credential cache (ccache) location is `/tmp/airflow_krb5_ccache`, which is a world-accessible directory on most Unix systems. While this is a documentation file, it documents the actual default configuration behavior. Other local users on the same system could potentially read or modify the Kerberos credential cache, leading to ticket theft or tampering.

### Details
**CWE:** None specified  
**ASVS:** 6.7.1 (L3)  
**Affected Files:**
- `airflow-core/docs/security/kerberos.rst` (lines 70-77)

While the keytab is documented with `chmod 600`, no equivalent file permission guidance is provided for the ccache file.

### Remediation
Documentation should recommend a non-world-accessible directory and explicit file permissions: `[kerberos] ccache = /run/airflow/krb5_ccache` (or a user-private directory) with guidance to set restrictive permissions on the parent directory.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Report: 6.7.1.md
- Domain: kerberos_integration

### Priority
Low

---

## Issue: FINDING-176 - No Documentation of Authentication Strength Enforcement for Kerberos-Authenticated Operations
**Labels:** bug, security, priority:low
**Description:**
### Summary
The documentation does not describe how the application verifies authentication strength, methods, or recentness when Kerberos is used as an identity provider. Specifically: 1. No guidance on verifying whether a Kerberos ticket was obtained via password, hardware token, or PKINIT; 2. No documentation of auth_time equivalent validation; 3. No step-up authentication mechanism documented for sensitive operations.

### Details
**CWE:** None specified  
**ASVS:** 6.8.4 (L2)  
**Affected Files:**
- `airflow-core/docs/security/kerberos.rst`

Without verifying authentication strength, the system cannot enforce that high-privilege operations require stronger authentication than lower-privilege operations.

### Remediation
Document a fallback approach as required by ASVS: if authentication strength cannot be determined from Kerberos, document the assumed minimum authentication level and any compensating controls (e.g., requiring re-authentication for sensitive operations).

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Report: 6.8.4.md
- Domain: kerberos_integration

### Priority
Low

---

## Issue: FINDING-177 - Missing OCSP Stapling Configuration in Deployment Documentation
**Labels:** bug, security, priority:low
**Description:**
### Summary
The deployment documentation provides no guidance on enabling OCSP stapling in the reverse proxy configuration. This is a Level 3 requirement, but given that the documentation is the primary deployment reference, the absence is notable. Deployments following this guide will not have certificate revocation checking enabled, meaning compromised or revoked certificates could still be trusted by clients.

### Details
**CWE:** None specified  
**ASVS:** 12.1.4 (L3)  
**Affected Files:**
- `airflow-core/docs/howto/run-behind-proxy.rst` (entire file)

### Remediation
Add OCSP stapling configuration to the nginx example:
```
ssl_stapling on;
ssl_stapling_verify on;
ssl_trusted_certificate /etc/nginx/ssl/chain.pem;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Report: 12.1.4.md
- Domain: tls_configuration

### Priority
Low

---

## Issue: FINDING-178 - No guidance on enabling Encrypted Client Hello (ECH) in deployment documentation
**Labels:** bug, security, priority:low
**Description:**
### Summary
The deployment documentation provides no guidance on enabling Encrypted Client Hello (ECH) to prevent SNI exposure during TLS handshakes. This is a Level 3 requirement. ECH is a relatively new feature and support varies by TLS stack. The Server Name Indication (SNI) field will be transmitted in plaintext during TLS handshakes, allowing network observers to determine which hostname the client is connecting to.

### Details
**CWE:** None specified  
**ASVS:** 12.1.5 (L3)  
**Affected Files:**
- `airflow-core/docs/howto/run-behind-proxy.rst` (entire file)

### Remediation
Add a section on ECH configuration. Note that ECH requires: 1. DNS HTTPS records with ECH configuration 2. Server-side support (nginx does not yet fully support ECH as of early 2024; solutions include Cloudflare proxy or custom builds). Example:
```
# ECH Configuration Note
# ECH requires DNS-level HTTPS records and server support.
# Consider deploying behind a CDN/proxy that supports ECH (e.g., Cloudflare)
# or use nginx builds with ECH support when available.
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Report: 12.1.5.md
- Domain: tls_configuration

### Priority
Low

---

## Issue: FINDING-179 - Incomplete documentation of connection configuration parameters for backend service interactions
**Labels:** bug, security, priority:low
**Description:**
### Summary
ASVS 13.2.6 requires that applications follow documented configuration for each backend connection including maximum parallel connections, behavior when maximum connections are reached, connection timeouts, and retry strategies. The provided documentation shows partial coverage. Without comprehensive documented connection configuration, resource exhaustion scenarios are harder to prevent, failure modes are unpredictable, and Deployment Managers cannot properly size infrastructure.

### Details
**CWE:** None specified  
**ASVS:** 13.2.6 (L3)  
**Affected Files:**
- `airflow-core/docs/authoring-and-scheduling/deferring.rst` (lines referencing capacity and heartbeat)
- `airflow-core/docs/core-concepts/executor/index.rst` (executor configuration)
- `airflow-core/docs/security/workload.rst` (no connection config referenced)

### Remediation
Document connection configuration for each backend service interaction including: Database Connections with sql_alchemy_pool_size, sql_alchemy_max_overflow, sql_alchemy_pool_recycle, sql_alchemy_pool_pre_ping, and sql_alchemy_connect_args parameters. For Triggerer-to-Database connections, document maximum connections, behavior at max, connection timeout, and retry strategy. For Executor-to-Worker Communication, document connection pool management, timeout settings, and retry strategy with exponential backoff.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Report: 13.2.6.md
- Domain: service_communication

### Priority
Low

---

## Issue: FINDING-180 - SQLAlchemy Debug Logging Lacks Programmatic Production Guard-rails
**Labels:** bug, security, priority:low
**Description:**
### Summary
The documentation describes enabling SQLAlchemy debug logging (echo=True) without providing a mechanism to ensure it is programmatically disabled in production deployments. If a deployment manager follows this guidance without reverting for production, all SQL statements (potentially including credential-related queries) are logged to application output. The documentation warns against production use but provides no guard-rails.

### Details
**CWE:** None specified  
**ASVS:** 13.4.2 (L2)  
**Affected Files:**
- `airflow-core/docs/howto/set-up-database.rst` (lines referencing SQLAlchemy logging section)

### Remediation
While not a code vulnerability, the documentation should recommend environment-aware configuration: In airflow_local_settings.py: `import os; sql_alchemy_engine_args = {"echo": os.environ.get("AIRFLOW_ENV") != "production"}`. Add environment-aware defaults to SQLAlchemy engine configuration that automatically disable echo in production environments. Add a production hardening section to this documentation that references ASVS 13.4.x requirements.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Report: 13.4.2.md
- Domain: deployment_configuration

### Priority
Low

---

## Issue: FINDING-181 - Documentation references external downloads without integrity verification guidance
**Labels:** bug, security, priority:low
**Description:**
### Summary
The documentation recommends specific Python drivers (psycopg2, mysqlclient) without specifying: expected PyPI package names (to prevent typosquatting confusion), expected repository source (PyPI, internal mirror), or expected package maintainers/checksums. This creates a theoretical dependency confusion risk if operators install packages from unverified sources or misspell package names.

### Details
**CWE:** None specified  
**ASVS:** 15.2.4 (L3)  
**Affected Files:**
- `airflow-core/docs/howto/set-up-database.rst` (lines 103-125)

### Remediation
Add integrity verification to the documented download process:
```rst
Download source from https://sqlite.org/, verify integrity, then make and install locally.

.. code-block:: bash

    wget https://www.sqlite.org/2024/sqlite-autoconf-3450000.tar.gz
    echo "expected_sha256_hash  sqlite-autoconf-3450000.tar.gz" | sha256sum -c -
    tar xzf sqlite-autoconf-3450000.tar.gz
    cd sqlite-autoconf-3450000/
    ...
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Report: 15.2.4.md
- Domain: deployment_configuration

### Priority
Low

---

## Issue: FINDING-182 - Auth Manager Documentation Does Not Reference Remediation Timeframes for Provider Dependencies
**Labels:** bug, security, priority:low
**Description:**
### Summary
This documentation describes a pluggable auth manager architecture where third-party provider packages are loaded as dependencies. The documentation does not reference or link to any policy defining risk-based remediation timeframes for vulnerabilities discovered in these third-party auth manager provider packages. Operators deploying custom or provider-based auth managers lack guidance on how quickly to update when vulnerabilities are disclosed.

### Details
**CWE:** None specified  
**ASVS:** 15.1.1 (L1)  
**Affected Files:**
- `airflow-core/docs/core-concepts/auth-manager/index.rst` (Throughout)

Since auth managers handle authentication and authorization (security-critical functionality), delays in patching could expose the entire Airflow deployment.

### Remediation
Add a section or cross-reference to a vulnerability remediation policy document that defines: Critical auth manager vulnerabilities: patch within 24-48 hours, High severity: patch within 7 days, Medium severity: patch within 30 days, Low severity: patch within 90 days. Example: Add a 'Security Updates for Auth Manager Providers' section that states 'Auth managers handle security-critical operations. When vulnerabilities are disclosed in auth manager provider packages, refer to the :doc:`/security/vulnerability-remediation-policy` for required remediation timeframes.'

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Report: 15.1.1.md
- Domain: dependency_management

### Priority
Low

---

## Issue: FINDING-183 - No SBOM Reference or Dependency Inventory for Auth Manager Provider Ecosystem
**Labels:** bug, security, priority:low
**Description:**
### Summary
The documentation references multiple external provider packages as auth manager implementations but does not reference an SBOM or dependency inventory tracking these components and their transitive dependencies. Auth managers are security-critical components that may introduce additional dependencies. Without SBOM tracking, vulnerabilities in nested dependencies may go undetected.

### Details
**CWE:** None specified  
**ASVS:** 15.1.2 (L2)  
**Affected Files:**
- `airflow-core/docs/core-concepts/auth-manager/index.rst` (lines 47-53)

### Remediation
Reference or link to SBOM generation processes:

```rst
Dependency Tracking
^^^^^^^^^^^^^^^^^^^

All auth manager provider packages and their transitive dependencies should be tracked
in the deployment's Software Bill of Materials (SBOM). See :doc:`/security/sbom` for
guidance on generating and maintaining SBOMs for Airflow deployments including providers.
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Report: 15.1.2.md
- Domain: dependency_management

### Priority
Low

---

## Issue: FINDING-184 - Token Refresh Middleware Resource Impact Not Documented
**Labels:** bug, security, priority:low
**Description:**
### Summary
The JWT refresh middleware intercepts every request to check token validity. The documentation does not describe the resource impact of this middleware or what happens when the refresh_user method involves expensive operations. If refresh_user involves network calls to external identity providers, concurrent token refreshes could overwhelm both the Airflow API server and the external provider.

### Details
**CWE:** None specified  
**ASVS:** 15.1.3 (L2)  
**Affected Files:**
- `airflow-core/docs/core-concepts/auth-manager/index.rst` (lines 139-146)

### Remediation
Document the resource implications and recommended patterns (e.g., token refresh should be fast, avoid expensive operations, consider refresh token pre-fetching).

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Report: 15.1.3.md
- Domain: dependency_management

### Priority
Low

---

## Issue: FINDING-185 - No Risk Classification of Auth Manager Provider Dependencies
**Labels:** bug, security, priority:low
**Description:**
### Summary
The documentation describes a system where any third-party package can serve as an auth manager (the most security-critical component in the system) but does not classify or identify which auth manager providers might be considered 'risky components' based on maintenance status, contributor count, vulnerability history, or security audit status. Operators may deploy auth managers from providers with poor security practices without being alerted to the associated risk.

### Details
**CWE:** None specified  
**ASVS:** 15.1.4 (L3)  
**Affected Files:**
- `airflow-core/docs/core-concepts/auth-manager/index.rst` (Throughout)

### Remediation
Add a risk classification section:

```rst
Security Considerations for Auth Manager Selection
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When selecting an auth manager provider, consider:

* **Maintenance status**: Is the provider actively maintained? Check recent commit activity.
* **Security track record**: Has the provider had security vulnerabilities? Were they patched promptly?
* **Community size**: Providers with few contributors have higher bus-factor risk.
* **Security audit status**: Has the provider undergone a security audit?

Providers classified as "risky" (unmaintained, history of vulnerabilities, or
limited contributor base) should be evaluated against :doc:`/security/risky-components-policy`.
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Report: 15.1.4.md
- Domain: dependency_management

### Priority
Low

---

## Issue: FINDING-186 - No Mechanism Documented to Verify Auth Manager Provider Versions Are Current
**Labels:** bug, security, priority:low
**Description:**
### Summary
The documentation describes loading auth managers from provider packages but does not reference any mechanism to verify that deployed provider versions comply with documented update timeframes. Without version verification mechanisms, deployments may continue using outdated auth manager providers with known vulnerabilities.

### Details
**CWE:** None specified  
**ASVS:** 15.2.1 (L1)  
**Affected Files:**
- `airflow-core/docs/core-concepts/auth-manager/index.rst` (Throughout)

### Remediation
Reference deployment-time and runtime version verification. Add a 'Keeping Auth Managers Updated' section documenting: Running pip-audit or equivalent tools in CI/CD to detect vulnerable dependencies, Monitoring provider release announcements and security advisories, Using constraint files to track approved provider versions, Setting up automated alerts when provider packages exceed their documented maximum age.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Report: 15.2.1.md
- Domain: dependency_management

### Priority
Low

---

## Issue: FINDING-187 - No Documented Resource Constraints for Custom Auth Manager Initialization
**Labels:** bug, security, priority:low
**Description:**
### Summary
While the documentation advises against expensive module-level imports for performance reasons, there is no enforcement mechanism or timeout documented for the init() method or for get_fastapi_app(). A custom auth manager's init() method could contain blocking operations that prevent the Airflow API server from starting, causing complete loss of availability.

### Details
**CWE:** None specified  
**ASVS:** 15.2.2 (L2)  
**Affected Files:**
- `airflow-core/docs/core-concepts/auth-manager/index.rst` (lines regarding init method and module-level imports)

### Remediation
Document and implement initialization timeouts for auth manager lifecycle methods. Add timeout wrappers around auth manager initialization in the core loader.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Report: 15.2.2.md
- Domain: dependency_management

### Priority
Low

---

## Issue: FINDING-188 - Potential information disclosure through unhandled template rendering errors
**Labels:** bug, security, priority:low
**Description:**
### Summary
If the template file (/index.html) is missing, corrupted, or contains a rendering error, a Jinja2TemplateNotFound or TemplateError exception will be raised. If not covered by error handlers, the ASGI server may log the error without the application having control over the response format, potentially leaking the technology stack.

### Details
**CWE:** None specified  
**ASVS:** 16.5.1 (L2, L3)  
**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/core_api/app.py` (line 89)

### Remediation
Add explicit error handling to the webapp catch-all route to gracefully handle template rendering errors:

```python
@app.get("/{rest_of_path:path}", response_class=HTMLResponse, include_in_schema=False)
def webapp(request: Request, rest_of_path: str):
    try:
        return templates.TemplateResponse(
            request,
            "/index.html",
            {"backend_server_base_url": request.base_url.path},
            media_type="text/html",
        )
    except Exception:
        log.exception("Failed to render webapp template")
        return HTMLResponse(content="<h1>Service Unavailable</h1>", status_code=503)
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Report: 16.5.1.md
- Domain: error_handling

### Priority
Low

---

## Issue: FINDING-189 - No graceful handling of auth manager middleware initialization failure
**Labels:** bug, security, priority:low
**Description:**
### Summary
If `get_auth_manager()` connects to an external identity provider or configuration store that is unavailable at startup, this will raise an unhandled exception, preventing the application from starting entirely. While failing to start without auth is the correct security posture (fail-closed), there's no explicit handling that distinguishes between 'auth provider temporarily unavailable' vs 'auth misconfigured.'

### Details
**CWE:** None specified  
**ASVS:** 16.5.2 (L2, L3)  
**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/core_api/app.py` (line 153)

### Remediation
Add explicit exception handling around auth manager initialization to distinguish between temporary availability issues and configuration errors. Provide clear error messages that aid operational troubleshooting while maintaining fail-closed behavior. Log specific error types to help operators determine whether the issue is transient (retry) or requires configuration changes.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Report: 16.5.2.md
- Domain: error_handling

### Priority
Low

---

## Issue: FINDING-190 - Plugin initialization may mask non-import errors during Flask app creation
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `create_app(enable_plugins=True)` call is outside the try/except block and could raise various exceptions (database errors, configuration issues, plugin initialization errors). If this call fails, the application startup fails completely. While this is the correct behavior (fail-closed), if `create_app` partially succeeds or if the WSGI mount happens with a partially-initialized Flask app, it could lead to inconsistent security state in the legacy plugin subsystem.

### Details
**CWE:** None specified  
**ASVS:** 16.5.3 (L2, L3)  
**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/core_api/app.py` (lines 107-122)

### Remediation
Add explicit error handling to the `create_app(enable_plugins=True)` call to ensure any exceptions during Flask app creation are properly caught and handled. Consider wrapping the WSGI mount operation in error handling to prevent mounting of a partially-initialized Flask app. Verify that `ERROR_HANDLERS` includes a handler for the base `Exception` class that both logs the full exception server-side and returns a generic message to clients.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Report: 16.5.3.md
- Domain: error_handling

### Priority
Low

---

## Issue: FINDING-191 - Key Rotation Procedure Missing Verification and Secure Disposal Steps
**Labels:** bug, security, priority:low
**Description:**
### Summary
The default behavior stores the master encryption key (which protects all connection passwords and variable values) in a plaintext configuration file. While environment variables are mentioned as an alternative, neither the Fernet documentation nor the secrets-backend documentation provides explicit guidance to store the Fernet key itself in a secrets management system for production deployments. If airflow.cfg is included in version control, container images, backups, or accessible to unauthorized users/processes, all encrypted credentials in the metadata database are compromised.

### Details
**CWE:** None specified  
**ASVS:** 11.1.1, 13.3.1 (L2, L3)  
**Affected Files:**
- `airflow-core/docs/security/secrets/fernet.rst` (lines 47-49)

### Remediation
The documentation should explicitly recommend and document how to store the Fernet key in an external secrets manager for production. Add a warning that for production deployments, the Fernet key MUST be stored in an external secrets management system and injected via environment variable at runtime. Never store the Fernet key in airflow.cfg or any file that may be committed to version control or included in container images. Provide example using AWS Secrets Manager with an entrypoint script.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Report: 11.1.1.md, 13.3.1.md
- Domain: cryptographic_inventory

### Priority
Low

---

## Issue: FINDING-192 - Cannot Verify Constant-Time Operation from Documentation Alone
**Labels:** bug, security, priority:low
**Description:**
### Summary
Cannot verify constant-time operation from documentation alone. The document references the `cryptography` library's Fernet implementation, which internally uses `hmac.compare_digest()` for constant-time comparison during token verification. However, this cannot be verified from the documentation file provided. If any Airflow code performs non-constant-time comparisons on cryptographic material (tokens, MACs, keys), timing side-channels could enable attacks.

### Details
**CWE:** None specified  
**ASVS:** 11.2.4 (L3)  
**Affected Files:**
- `airflow-core/docs/security/secrets/fernet.rst`

### Remediation
Verify in the actual implementation code that: 1. All MAC verification uses `hmac.compare_digest()` or equivalent 2. No early-return patterns exist in token comparison logic 3. Error handling does not leak timing information (e.g., different response times for 'invalid MAC' vs 'expired token')

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Report: 11.2.4.md
- Domain: cryptographic_inventory

### Priority
Low

---

## Issue: FINDING-193 - Documentation Gap for Key Exchange Mechanisms
**Labels:** bug, security, priority:low
**Description:**
### Summary
The security documentation covers symmetric encryption (Fernet) comprehensively but does not reference or document any key exchange mechanisms used within the Airflow ecosystem (beyond TLS, which ASVS 11.6.2 explicitly excludes from scope). A complete cryptographic inventory should document all cryptographic keys, algorithms, and their usage patterns, including key exchange mechanisms if they exist.

### Details
**CWE:** None specified  
**ASVS:** 11.6.2 (L3)  
**Affected Files:**
- `airflow-core/docs/security/secrets/fernet.rst` (entire file)

### Remediation
Expand the cryptographic documentation to explicitly address key exchange. Add a dedicated section that clarifies whether Airflow relies on TLS for all key exchange operations or if application-layer key exchange protocols exist. Document approved key exchange mechanisms including: For TLS - ECDHE with NIST P-256, P-384, P-521, or X25519 curves, and DHE with minimum 2048-bit group parameters. For custom integrations - use established libraries, ECDH with NIST P-256 or stronger curves only, and never implement custom key exchange protocols.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Report: 11.6.2.md
- Domain: cryptographic_inventory

### Priority
Low

---

## Issue: FINDING-194 - Documented priority inversion allowing low-priority tasks to execute before high-priority tasks
**Labels:** bug, security, priority:low
**Description:**
### Summary
The documentation explicitly states that task priority is not strictly enforced — low-priority tasks can be scheduled before high-priority tasks when pool slots are available. While this is documented as an intentional design decision for throughput optimization, it could lead to scenarios where critical high-priority tasks experience delayed execution during peak scheduling periods if they are in a later batch than lower-priority tasks.

### Details
**CWE:** None specified  
**ASVS:** 15.4.4 (L3)  
**Affected Files:**
- `airflow-core/docs/administration-and-deployment/scheduler.rst` (lines 56-62)

### Remediation
This is an acknowledged design trade-off. For deployments requiring strict priority enforcement: Use dedicated pools for high-priority tasks to ensure slot availability; Monitor scheduling latency by priority tier; Consider the max_dagruns_per_loop_to_schedule setting to control batch sizes. This finding is LOW severity because the behavior is documented and intentional.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Report: 15.4.4.md
- Domain: concurrency_safety

### Priority
Low

---

## Issue: FINDING-195 - Potential scheduler starvation when one scheduler acquires all DagRun locks
**Labels:** bug, security, priority:low
**Description:**
### Summary
The documentation acknowledges that misconfiguration of max_dagruns_per_loop_to_schedule can lead to one scheduler monopolizing DagRun processing, effectively starving other scheduler instances. While this is a configuration concern rather than a code defect, the system does not appear to have built-in fairness guarantees between scheduler instances.

### Details
**CWE:** None specified  
**ASVS:** 15.4.4 (L3)  
**Affected Files:**
- `airflow-core/docs/administration-and-deployment/scheduler.rst` (lines 155-162)

### Remediation
This is mitigated by proper configuration. The system could additionally implement: Dynamic adjustment of batch sizes based on detected peer scheduler activity; Randomized or round-robin DagRun acquisition to distribute work more evenly.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Report: 15.4.4.md
- Domain: concurrency_safety

### Priority
Low

---

## Issue: FINDING-196 - Base Auth Manager Framework Provides No PKCE/State Parameter Infrastructure for OAuth Code Flow
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `BaseAuthManager` abstract class defines `get_url_login(**kwargs) -> str` which suggests redirect-based authentication flows (e.g., OAuth authorization code flow). However, the base class provides no framework-level support for: PKCE generation or validation, `state` parameter generation, storage, or verification, or callback/redirect handling with anti-CSRF verification. Concrete auth manager implementations that utilize OAuth code flow may omit CSRF protection if developers don't implement it independently.

### Details
**CWE:** CWE-352  
**ASVS:** 10.2.1 (L2)  
**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py` (line 183)

### Remediation
Consider adding abstract or helper methods for PKCE/state parameter handling: (1) `generate_state_parameter()` to generate a cryptographically random state parameter using secrets.token_urlsafe(32), and (2) `validate_state_parameter(received_state, expected_state)` to validate the state parameter using hmac.compare_digest().

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Report: 10.2.1.md
- Domain: oauth_oidc_integration

### Priority
Low

---

## Issue: FINDING-197 - Audience Configuration Key Mismatch Between Token Signer and Validator
**Labels:** bug, security, priority:low
**Description:**
### Summary
The token signer and validator read audience configuration from different config sections, which could lead to a mismatch if operators configure one but not the other. Token signer uses `conf.get("api", "jwt_audience", fallback="apache-airflow")` while token validator uses `conf.get("api_auth", "jwt_audience", fallback="apache-airflow")`. If an operator sets one but not the other, tokens generated by this system would fail validation.

### Details
**CWE:** None specified  
**ASVS:** 10.3.1 (L2)  
**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py` (lines 821-843)

### Remediation
Unify the configuration source or add validation that both resolve to the same value. Use the same configuration section for both token signer and validator, preferably `api_auth` for consistency.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Report: 10.3.1.md
- Domain: oauth_oidc_integration

### Priority
Low

---

## Issue: FINDING-198 - `deserialize_user` Abstract Method Has No Contractual Requirement for `iss`+`sub` Identification
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `deserialize_user` abstract method accepts the full token payload but provides no enforcement or guidance that implementations must use `iss` + `sub` for unique user identification. Concrete implementations may use `email`, `preferred_username`, or other reassignable claims for user identification, leading to identity confusion if those claims change.

### Details
**CWE:** None specified  
**ASVS:** 10.3.3 (L2)  
**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py` (line 146)

### Remediation
Document the requirement and optionally enforce it:
```python
@abstractmethod
def deserialize_user(self, token: dict[str, Any]) -> T:
    """
    Create a user object from the validated JWT claims.
    
    Implementations MUST use the combination of 'iss' and 'sub' claims
    for unique user identification. Do not rely on mutable claims like
    'email' or 'preferred_username' for identity.
    
    :param token: validated JWT claims dictionary
    """
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Report: 10.3.3.md
- Domain: oauth_oidc_integration

### Priority
Low

---

## Issue: FINDING-199 - No PAR/JAR Infrastructure for Authorization Details Integrity
**Labels:** bug, security, priority:low
**Description:**
### Summary
The base auth manager does not implement OAuth authorization endpoint concepts such as: Pushed Authorization Requests (PAR) endpoint or enforcement, JWT-secured Authorization Request (JAR) validation, or authorization_details parameter handling (RFC 9396). If a derived class implements an OAuth AS flow with authorization_details, there is no base-class infrastructure to ensure these parameters originate from the client backend.

### Details
**CWE:** None specified  
**ASVS:** 10.4.15 (L3)  
**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py` (entire file)

### Remediation
If OAuth AS functionality is to be built on this base class, add abstract methods or interfaces for PAR/JAR support:
```python
@abstractmethod
def validate_authorization_request(self, request: AuthorizationRequest) -> bool:
    """Validate that authorization request parameters are integrity-protected (PAR/JAR)."""
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Report: 10.4.15.md
- Domain: oauth_oidc_integration

### Priority
Low

---

## Issue: FINDING-200 - No OAuth Client Authentication Mechanisms Implemented
**Labels:** bug, security, priority:low
**Description:**
### Summary
The base auth manager does not implement OAuth client authentication mechanisms. There is no support for: tls_client_auth (mutual TLS with PKI certificates), self_signed_tls_client_auth (mutual TLS with self-signed certificates), private_key_jwt (client assertion using private key), or client credential validation at token endpoints. The authentication flow in this base class is user-facing (JWT cookie-based), not client-to-server OAuth authentication.

### Details
**CWE:** None specified  
**ASVS:** 10.4.16 (L3)  
**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py` (entire file)

### Remediation
For deployments requiring OAuth AS functionality, either: 1. Use a dedicated OAuth AS (Keycloak, Hydra, etc.) alongside Airflow, or 2. Add client authentication interfaces to the base class with support for ClientAuthMethod enum (TLS_CLIENT_AUTH, SELF_SIGNED_TLS_CLIENT_AUTH, PRIVATE_KEY_JWT) and an abstract authenticate_client method that authenticates OAuth clients using strong methods (mTLS or private_key_jwt).

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Report: 10.4.16.md
- Domain: oauth_oidc_integration

### Priority
Low

## Issue: FINDING-201 - Execution API InProcessExecutionAPI completely bypasses all authentication and authorization controls
**Labels:** security, priority:low, authentication, authorization
**Description:**
### Summary
The InProcessExecutionAPI overrides all security dependencies with an `always_allow` function, creating a pathway where DAG author code running in the DFP or Triggerer has unrestricted access to all connections, variables, and XComs across all teams in multi-team deployments.

### Details
The InProcessExecutionAPI completely bypasses authentication and authorization by overriding ALL security dependencies (`_jwt_bearer`, `has_connection_access`, `has_variable_access`, `has_xcom_access`) with an `always_allow` function. While this is documented in `jwt_token_authentication.rst`, it creates a security concern in multi-team deployments where DAG author code from one team can access resources belonging to other teams when running via DFP or Triggerer.

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/execution_api/app.py` (lines 285-300)

**ASVS Reference:** 6.3.4 (L2, L3)

### Remediation
For multi-team deployments, implement one of the following:
1. Run separate DFP/Triggerer instances per team (currently recommended approach)
2. Implement team-scoped access controls within the InProcessExecutionAPI
3. Use a trusted internal service token with scoped permissions instead of completely disabling auth

### Acceptance Criteria
- [ ] Fixed: Team-scoped access controls implemented OR runtime validation added to enforce deployment topology
- [ ] Test added: Multi-team isolation tests for InProcessExecutionAPI
- [ ] Documentation updated with security implications and deployment recommendations

### References
- Source: `6.3.4.md`
- CWE: N/A

### Priority
**Low** - Documented behavior with workaround available, but creates security risk in multi-team deployments

---

## Issue: FINDING-202 - Token Revocation Conditional on JTI Claim Presence
**Labels:** security, priority:low, authentication, token-management
**Description:**
### Summary
Tokens issued without the `jti` claim cannot be revoked, creating an inconsistency in authentication strength across different token issuance pathways.

### Details
The `get_user_from_token` function skips the revocation check when the `jti` claim is absent. If a custom auth manager implementation or external identity provider issues tokens without the `jti` claim, those tokens cannot be revoked on logout or compromise. This creates an authentication strength inconsistency where some tokens are revocable and others are not.

**Affected Files:**
- `airflow-core/tests/unit/api_fastapi/auth/managers/test_base_auth_manager.py` (lines 195-215)

**ASVS Reference:** 6.3.4 (L2, L3)

### Remediation
Enforce `jti` claim requirement by:
1. Rejecting tokens without a `jti` claim in the `get_user_from_token` method
2. Ensuring all token issuance pathways include `jti` claim
3. Documenting the `jti` requirement for custom auth manager implementations

### Acceptance Criteria
- [ ] Fixed: `jti` claim validation enforced in `get_user_from_token`
- [ ] Test added: Token rejection test for missing `jti` claim
- [ ] Documentation updated: Custom auth manager requirements include mandatory `jti` claim

### References
- Source: `6.3.4.md`
- CWE: N/A

### Priority
**Low** - Affects edge cases with custom auth managers, but creates revocation gaps

---

## Issue: FINDING-203 - JWT refresh middleware does not validate token scope claim before refreshing user session
**Labels:** security, priority:low, authentication, token-validation
**Description:**
### Summary
The JWT refresh middleware lacks explicit scope validation, potentially allowing internal workload tokens to be used for user session creation if injected as cookies.

### Details
The JWT refresh middleware's `_refresh_user` function calls `resolve_user_from_token` without explicit scope validation. If different token scopes (workload, user, etc.) share the same signing key and audience, a token intended for internal scheduler-worker communication could potentially be injected as a cookie and trigger user session creation/refresh. While audience separation provides partial mitigation, the middleware has no explicit scope validation layer.

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py` (lines 67-70)

**ASVS Reference:** 6.3.4 (L2, L3)

### Remediation
Add explicit scope validation in the refresh middleware to:
1. Verify that tokens presented via cookies have the expected scope (e.g., not 'workload')
2. Reject tokens with inappropriate scopes before refreshing user sessions
3. Document the expected token scope for user session tokens

### Acceptance Criteria
- [ ] Fixed: Scope validation added to `_refresh_user` function
- [ ] Test added: Token rejection test for invalid scope in refresh flow
- [ ] Documentation updated: Token scope requirements documented

### References
- Source: `6.3.4.md`
- CWE: N/A

### Priority
**Low** - Partially mitigated by audience separation, but defense-in-depth improvement needed

---

## Issue: FINDING-204 - Multiple Authentication Schemes Configured as OR-Logic Without Documented Strength Equivalence
**Labels:** security, priority:low, authentication, documentation
**Description:**
### Summary
All secured API endpoints accept authentication via EITHER `OAuth2PasswordBearer` OR `HTTPBearer` without documentation clarifying that both pathways enforce equivalent authentication strength.

### Details
The OpenAPI specification configures multiple authentication schemes with OR-logic (array items are OR-ed). While both ultimately use bearer tokens, the specification does not document how tokens obtained through each pathway are equivalent in strength. Without documentation clarifying that `HTTPBearer` tokens are the SAME JWT tokens obtained via the OAuth2 flow (or an equivalent SSO/IdP flow), there is ambiguity about whether all pathways enforce equivalent authentication strength.

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/core_api/openapi/v2-rest-api-generated.yaml`

**ASVS Reference:** 6.3.4 (L2, L3)

### Remediation
Add documentation clarifying:
1. Both security schemes accept the same JWT tokens
2. No alternative token issuance mechanism exists with weaker controls
3. The authentication strength is equivalent regardless of scheme used
4. The purpose of having both schemes in the OpenAPI spec

### Acceptance Criteria
- [ ] Fixed: Documentation added to OpenAPI spec and authentication docs
- [ ] Test added: N/A (documentation issue)
- [ ] Documentation updated: Security scheme equivalence documented

### References
- Source: `6.3.4.md`
- CWE: N/A

### Priority
**Low** - Documentation clarity issue, no actual security vulnerability identified

---

## Issue: FINDING-205 - Simple auth manager provides no MFA factor lifecycle management
**Labels:** security, priority:low, authentication, mfa, production-safety
**Description:**
### Summary
The simple auth manager only supports single-factor authentication with no MFA enrollment or factor management, and lacks runtime guardrails preventing production use.

### Details
The simple auth manager only supports single-factor authentication (username/password) with no MFA enrollment, factor management, or factor recovery mechanism. While documented as for development/testing only, there is no runtime guardrail preventing its use in production environments. If deployed in production, single-factor authentication does not meet ASVS L2 requirements for MFA enforcement. The only safeguard is a dismissible banner warning.

**Affected Files:**
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/utils.py` (full file)
- `airflow-core/src/airflow/api_fastapi/auth/managers/simple/ui/src/login/Login.tsx` (entire file)

**ASVS Reference:** 6.4.4 (L2, L3)

### Remediation
Implement production safety checks:
1. Add runtime validation that prevents simple auth manager usage when deployment appears to be production (e.g., multiple workers, non-localhost bind, PostgreSQL/MySQL database)
2. Add startup warning or error when SimpleAuthManager is configured in production-like environments
3. Implement configuration validation to flag non-compliant auth manager usage

### Acceptance Criteria
- [ ] Fixed: Runtime production safety check implemented
- [ ] Test added: Production detection and rejection tests for SimpleAuthManager
- [ ] Documentation updated: Production safety guardrails documented

### References
- Source: `6.4.4.md`
- CWE: N/A

### Priority
**Low** - Documented limitation with known workaround, but lacks technical enforcement