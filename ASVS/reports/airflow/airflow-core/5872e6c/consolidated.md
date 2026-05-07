# Security Audit Consolidated Report

## Apache Tooling Runbooks — ASVS L3 Assessment

---


> **Note:** 5 Critical findings have been redacted from this report and forwarded to the project's PMC private mailing list.


## Report Metadata

| Field | Value |
|-------|-------|
| **Repository** | `apache/tooling-runbooks` |
| **ASVS Level** | L3 (Maximum) |
| **Severity Threshold** | None (all findings included) |
| **Commit** | N/A |
| **Date** | May 07, 2026 |
| **Auditor** | Tooling Agents |
| **Source Reports** | 345 |
| **Total Findings** | 205 |

---

## Executive Summary

This report consolidates the results of an automated security audit performed against 32 directories within the `apache/tooling-runbooks` repository, evaluated against the OWASP Application Security Verification Standard (ASVS) at Level 3 — the highest assurance tier intended for critical applications handling sensitive data and high-value transactions.

The audit identified **205 findings** across all severity levels, derived from **345 individual source reports**. The findings reveal systemic gaps in credential management, session lifecycle controls, and transport-layer hardening that collectively undermine the security posture of the platform.

### Severity Distribution

| Severity | Count | Percentage | Bar |
|----------|------:|:----------:|-----|
| **High** | 26 | 12.7% | 🟧🟧🟧🟧🟧🟧 |
| **Medium** | 108 | 52.7% | 🟨🟨🟨🟨🟨🟨🟨🟨🟨🟨🟨🟨🟨🟨🟨🟨🟨🟨🟨🟨🟨🟨🟨🟨🟨🟨 |
| **Low** | 66 | 32.2% | 🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩 |
| **Info** | 0 | 0.0% | — |

### ASVS Level Coverage

Findings span all three ASVS verification levels, indicating deficiencies from baseline controls through advanced assurance requirements:

| Level | Findings Applicable | Description |
|-------|-------------------:|-------------|
| **L1** (Baseline) | 68 | Fundamental security controls expected in all applications |
| **L2** (Standard) | 163 | Defense-in-depth controls for applications handling sensitive data |
| **L3** (Advanced) | 142 | Maximum assurance for critical infrastructure and high-value targets |

> *Note: Many findings are applicable to multiple levels simultaneously.*

### Top 2 Risks

#### 1. 🟠 Absent Multi-Factor Authentication and Credential Lifecycle (High)

**Findings:** FINDING-006, FINDING-007, FINDING-009, FINDING-010, FINDING-011, FINDING-040

No multi-factor authentication mechanism exists or can be enforced. Users cannot change their own passwords, no password reset flow exists, and auto-generated passwords use Python's non-cryptographic `random` module rather than `secrets`. The complete absence of credential lifecycle management means compromised passwords cannot be remediated by end users.

**ASVS References:** 6.2.2, 6.2.3, 6.3.3, 6.4.1, 6.4.3

#### 2. 🟠 Missing Transport Security and Security Headers (High)

**Findings:** FINDING-024, FINDING-025, FINDING-026, FINDING-027, FINDING-028

The application lacks HSTS headers, Content-Security-Policy, and essential cookie security attributes. The primary deployment documentation example omits TLS configuration entirely. Cookie documentation actively advises against `HttpOnly` without compensating CSRF controls. These gaps expose the application to session hijacking, content injection, and protocol downgrade attacks.

**ASVS References:** 3.2.1, 3.3.1, 3.4.1, 3.4.3, 12.1.1

### Positive Controls Identified

Despite the findings above, the audit identified several well-implemented security controls that demonstrate security awareness and provide a foundation for remediation:

| # | Control | Assessment |
|---|---------|------------|
| 1 | **Approved cryptographic algorithms only (HS512, RS256, EdDSA)** | Token signing restricts to NIST-approved algorithms with no deprecated options. Algorithm allowlisting in `jwt.decode()` prevents algorithm confusion attacks. |
| 2 | **CSPRNG for key generation** | Symmetric keys use `os.urandom(16)` and token identifiers use `uuid.uuid4().hex` backed by kernel CSPRNG, ensuring cryptographic-quality randomness for security-critical operations. |
| 3 | **Centralized token validation with required claims** | `JWTValidator` enforces `exp`, `iat`, and `nbf` as required claims. PyJWT performs automatic expiration and not-before validation with configurable clock skew tolerance. |
| 4 | **JWKS support with key rotation capability** | The JWKS infrastructure supports multiple keys per keyset with periodic background refresh (default 3600s), enabling zero-downtime key rotation for asymmetric deployments. |
| 5 | **No attacker-controlled key source processing** | Only `kid` is extracted from token headers — `jku`, `x5u`, and embedded `jwk` headers are not processed. JWKS URLs are exclusively sourced from server-side configuration. |
| 6 | **Pluggable auth manager architecture** | The `BaseAuthManager` abstract interface centralizes JWT generation, validation, and revocation tracking, ensuring structural consistency and allowing upgrade to MFA-capable implementations (OAuth2, SAML, OIDC). |
| 7 | **Execution API audience isolation** | Execution tokens default to `urn:airflow.apache.org:task` with route-level scope enforcement, preventing cross-service token acceptance. |
| 8 | **Generic authentication error messages** | Failed login returns `"Invalid credentials"` without distinguishing invalid username from invalid password, mitigating username enumeration. |
| 9 | **File locking for concurrent password generation** | `fcntl.flock()` prevents race conditions during multi-worker password file initialization. |
| 10 | **HTTP-only cookie storage with conditional Secure flag** | JWT cookies are set with `httponly=True` and the `Secure` flag is conditionally applied based on detected HTTPS configuration. |

### Risk Summary

The combination of plain-text password storage, absence of brute-force protection, and irrevocable sessions creates an **immediately exploitable attack chain**: an attacker can conduct unlimited login attempts against timing-vulnerable plain-text comparisons, and once successful, the resulting session cannot be terminated by administrators. This represents the highest-priority remediation target.

The Medium-severity findings (52.7% of total) predominantly cluster around missing documentation, incomplete session lifecycle management, and absent security headers — issues that reflect architectural gaps requiring design-level changes rather than simple code fixes.

---

## 3. Findings

## 3.2 High

#### FINDING-006: No Password Change Functionality Exists

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1, L2, L3 |
| **CWE** | CWE-620 |
| **ASVS sections** | 6.2.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py (entire file), airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py (entire class) |
| **Source Reports** | 6.2.2.md |
| **Related** | FINDING-007 |

**Description:**

The Simple Auth Manager provides no endpoint, service method, or mechanism for users to change their passwords. The available endpoints are limited to login functionality only (token, token/login, token/cli). No PUT /password, POST /password/change, or similar endpoint exists. The SimpleAuthManager class has no change_password() method. Passwords are generated once during init() and stored permanently. Users cannot change compromised passwords. If a password is leaked (e.g., from console output during init, from the plain-text file, or via log exposure), there is no self-service mechanism to rotate it without restarting the Airflow instance and deleting the password file.

**Remediation:**

Add a new endpoint in routes/login.py or a new routes/password.py:

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

---

#### FINDING-007: Password Change Functionality Absent — Cannot Verify Current Password Requirement

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1, L2, L3 |
| **CWE** | CWE-620 |
| **ASVS sections** | 6.2.3 |
| **Files** | All files in scope |
| **Source Reports** | 6.2.3.md |
| **Related** | FINDING-006 |

**Description:**

Since no password change functionality exists, the requirement that password changes must verify the current password before accepting a new one is inherently unmet. There is no PasswordChangeBody data model, no service method that validates the current password, and no endpoint that accepts both current and new passwords. If password change functionality is added in the future without proper design, it may omit current password verification, enabling session hijacking attacks where an attacker with a stolen session token can permanently take over an account by changing the password without knowing the original.

**Remediation:**

When implementing password change per ASVS-6.2.2 remediation, ensure:

1. Create PasswordChangeBody data model with current_password and new_password fields (datamodels/password.py)
2. Implement change_password service method that:
   - Verifies current password before allowing change (CRITICAL - prevents session-hijack takeover)
   - Returns HTTP 401 if current password is incorrect
   - Validates new password (length, common passwords, etc.)
   - Updates password only after all validations pass
3. Add POST /password/change endpoint

Example implementation:
```python
# datamodels/password.py
class PasswordChangeBody(BaseModel):
    current_password: str  # REQUIRED - prevents session-hijack takeover
    new_password: str

# services/login.py
@staticmethod
def change_password(username: str, current_password: str, new_password: str) -> None:
    passwords = SimpleAuthManager.get_passwords()
    
    # CRITICAL: Verify current password before allowing change
    if passwords.get(username) != current_password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect",
        )
    
    # Validate new password (length, common passwords, etc.)
    validate_password(new_password)
    
    # Update password
    passwords[username] = new_password
    _write_passwords(passwords)
```

---

#### FINDING-008: Timing-Attack Vulnerable Plain-Text Password Comparison

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1, L2, L3 |
| **CWE** | CWE-208 |
| **ASVS sections** | 6.3.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py (60) |
| **Source Reports** | 6.3.1.md |
| **Related** | |

**Description:**

The password comparison uses Python's == operator which short-circuits on first differing character, leaking password length/prefix information. User-supplied body.password is compared against stored password using plain-text == string comparison. An attacker can use statistical timing analysis to iteratively determine password characters, reducing the effective brute-force search space significantly.

**Remediation:**

Use constant-time comparison with hmac.compare_digest() instead of == operator. Example: stored_password = passwords.get(user.username, ''); if hmac.compare_digest(stored_password.encode(), body.password.encode()): # valid

---

#### FINDING-009: Password generation uses non-cryptographic PRNG (random module)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1, L2, L3 |
| **CWE** | CWE-338 |
| **ASVS sections** | 6.4.1, 11.4.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py (302) |
| **Source Reports** | 6.4.1.md, 11.4.2.md |
| **Related** | |

**Description:**

The password generation function uses Python's random module (Mersenne Twister PRNG) instead of a cryptographically secure random number generator. The random module is explicitly documented by Python as not suitable for security purposes. If an attacker can determine or estimate the PRNG state (e.g., by knowing the approximate startup time of Airflow workers, or by observing other random outputs), they can predict generated passwords. With multiple workers generating passwords near-simultaneously (as described in the file-locking logic), the entropy window is narrower.

**Remediation:**

Replace the random module with the secrets module for cryptographically secure random generation:

```python
import secrets

@staticmethod
def _generate_password() -> str:
    alphabet = "abcdefghkmnpqrstuvwxyzABCDEFGHKMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(16))
```

---

#### FINDING-010: Generated passwords never expire and cannot be changed

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1, L2, L3 |
| **CWE** | CWE-521 |
| **ASVS sections** | 6.4.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py (126-155) |
| **Source Reports** | 6.4.1.md |
| **Related** | FINDING-035, FINDING-036, FINDING-037, FINDING-146 |

**Description:**

ASVS 6.4.1 requires that system-generated initial passwords expire after a short period of time or after they are initially used and must not be permitted to become the long term password. The current implementation permanently stores generated passwords with no expiration mechanism, violating both requirements. Generated passwords are stored in a JSON file indefinitely and used for all future authentications with no timestamp, no expiration check, and no first-use detection.

**Remediation:**

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
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                       detail="Initial password has expired")
```

---

#### FINDING-011: No multi-factor authentication mechanism available or enforceable

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | CWE-308 |
| **ASVS sections** | 6.3.3 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py (35-75), airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py (all endpoints) |
| **Source Reports** | 6.3.3.md |
| **Related** | |

**Description:**

The Simple Auth Manager provides only single-factor password authentication with no extension point for adding a second factor. The authentication flow follows: POST /token → LoginBody(username, password) → single-factor validation → JWT issued. No TOTP, hardware key, push notification, or any second factor is requested, validated, or enforced. For ASVS Level 2 compliance, MFA is mandatory. If deployed in any environment requiring L2 assurance, authentication is insufficient against credential theft, phishing, or password reuse attacks.

**Remediation:**

Option 1: Add TOTP support as second factor using pyotp library. After password validation, check if user has MFA enabled, require TOTP code in request body, verify TOTP code against user secret before issuing JWT. Option 2: Document that production deployments MUST use a pluggable auth manager that supports MFA (e.g., OAuth2/OIDC provider with MFA enforcement). Mitigating Context: This auth manager is explicitly for development/testing, and production deployments should use pluggable auth managers with enterprise SSO/OAuth that enforce MFA externally.

---

#### FINDING-012: No mechanism to terminate sessions after authentication factor change

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | CWE-613 |
| **ASVS sections** | 7.4.3 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/ (entire module scope) |
| **Source Reports** | 7.4.3.md |
| **Related** | FINDING-013, FINDING-041, FINDING-044 |

**Description:**

There is no mechanism to change passwords (no password change endpoint exists), update MFA configuration (MFA is not implemented), or terminate other active sessions after any credential change. Even if passwords are manually changed in the password file, there is no mechanism to invalidate existing tokens issued with the old credentials. The system has no concept of a 'credentials changed at' timestamp that could be compared against token issuance time. If an administrator manually changes a user's password in the generated password file (the only way to change credentials), all previously issued tokens continue to work unchanged. There is no option for users or administrators to force termination of other sessions.

**Remediation:**

Add password change endpoint with session invalidation. The endpoint should: 1) Verify current password, 2) Update password, 3) Set per-user invalidation timestamp to invalidate all other sessions, 4) Issue new token for current session. Example implementation: Add a POST /change-password endpoint that calls SimpleAuthManagerLogin.verify_credentials(), SimpleAuthManager.update_password(), set_user_invalidation_time(), and generate_jwt() to return a new token with other_sessions_terminated flag.

---

#### FINDING-013: No logout endpoint or functionality defined

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | CWE-613 |
| **ASVS sections** | 7.4.4, 7.5.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py (entire file), airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py (280-320) |
| **Source Reports** | 7.4.4.md, 7.5.2.md |
| **Related** | FINDING-012, FINDING-041, FINDING-044 |

**Description:**

No logout endpoint or functionality is defined anywhere in the provided codebase. The login_router contains only token creation endpoints. The FastAPI sub-application mounts the login router and serves UI templates but provides no server-side logout mechanism. For pages requiring authentication, users have no accessible way to terminate their session. While the UI template (index.html) is not provided, the backend offers no API endpoint that a logout button could call. Users cannot actively terminate their sessions, meaning: if a user walks away from an unlocked workstation, there's no way to end the session; shared computer scenarios have no mechanism for users to log out; and the session remains valid until natural JWT expiration.

**Remediation:**

Add a logout endpoint to the login_router that terminates the user session by clearing the JWT cookie and revoking the token. Example implementation:

```python
@login_router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
)
def logout(request: Request) -> Response:
    """Terminate the user session by clearing the JWT cookie and revoking the token."""
    response = Response(status_code=200, content='{"detail": "Logged out successfully"}')
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

---

#### FINDING-014: No Capability to View Active Sessions

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | CWE-778 |
| **ASVS sections** | 7.5.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py (N/A), airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py (290-310) |
| **Source Reports** | 7.5.2.md |
| **Related** | |

**Description:**

The Simple Auth Manager provides no endpoint, service, or data model for users to view their currently active sessions. The architecture is entirely stateless JWT-based with no server-side session tracking, making it impossible for users to enumerate their active sessions across devices/browsers. Users have no visibility into whether their account has been compromised, and if credentials are stolen or tokens are leaked, the legitimate user cannot detect unauthorized active sessions.

**Remediation:**

Implement server-side session tracking with a SessionStore class that records session metadata (session_id, username, created_at, last_activity, ip_address, user_agent). Add a GET /sessions endpoint that returns all active sessions for the authenticated user. Include a 'jti' (JWT ID) claim in token generation using uuid.uuid4() to uniquely identify each session. Record sessions in the session store during token creation and provide session listing capability through the API endpoint.

---

#### FINDING-015: No Documentation of Field-Level Access Restrictions in the Authorization Model

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | |
| **ASVS sections** | 8.1.2 |
| **Files** | airflow-core/docs/core-concepts/auth-manager/index.rst, airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py |
| **Source Reports** | 8.1.2.md |
| **Related** | |

**Description:**

The authorization documentation and abstract interface define resource-level and method-level access controls but contain no provisions for field-level access restrictions. There is no documentation or interface method that addresses: Which fields within a resource (e.g., Connection password, DAG source code) require separate authorization; How field-level read restrictions should be implemented (e.g., masking sensitive fields based on user permissions); How field-level write restrictions should work (e.g., preventing certain users from modifying specific resource attributes); State-dependent field access rules (e.g., a DAG in "paused" state having different field editability). The authorization decision is binary (True/False) at the resource level. There's no mechanism to return partial access (e.g., "can read conn_id but not password") or to specify which fields the authorization applies to. Without field-level authorization: Users authorized to read connections may see sensitive fields (passwords, extra configuration) they shouldn't access; Users authorized to modify a resource may alter security-critical fields (e.g., changing connection types or credentials); State-dependent access patterns cannot be expressed (e.g., a "running" DAG having different modifiable fields than a "paused" DAG).

**Remediation:**

Add field-level authorization to the auth manager interface by implementing a get_authorized_fields method that returns the set of fields the user is authorized to access. The method should accept resource_type, method, user, and details parameters, returning None if all fields are accessible or a set of field names the user may read/write based on the method. Document field-level rules in the authorization documentation, specifying which fields in resources like Connections (password, extra fields) and Variables require additional authorization beyond resource-level access. Document state-dependent field access patterns where appropriate.

---

#### FINDING-016: No Field-Level Authorization Mechanism Exists in the Auth Manager Framework

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-639 |
| **ASVS sections** | 8.2.3 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py (161-802) |
| **Source Reports** | 8.2.3.md |
| **Related** | |

**Description:**

The BaseAuthManager class provides no abstract methods, interfaces, or utilities for field-level authorization (BOPLA protection). Authorization decisions are binary (allow/deny) at the resource level. Once a user is authorized to access a resource, all fields of that resource are accessible for the authorized method. Specific BOPLA risk scenarios include: A user authorized to GET a connection can read the password field; A user authorized to PUT a DAG can modify its owners field; A user authorized to PUT a variable can modify its team_name field (potentially escalating team access). Data flow: API request to modify resource → is_authorized_* returns True → ALL submitted fields are written to resource → no per-field filtering. Users with legitimate write access to a resource could modify security-critical fields they shouldn't be able to change, such as changing a resource's team_name to gain cross-team access, modifying connection credentials they should only be able to read, or setting DAG ownership attributes to escalate privileges.

**Remediation:**

Implement field-level authorization support in the base auth manager by adding methods get_writable_fields and get_readable_fields that return sets of field names the user can access, or None to indicate all fields are accessible (for backward compatibility). These methods should accept resource_type, user, and details parameters to enable context-aware field-level access control decisions.

---

#### FINDING-017: No step-up authentication for highly sensitive multi-team operations

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L3 |
| **CWE** | |
| **ASVS sections** | 7.5.3 |
| **Files** | airflow-core/docs/core-concepts/multi-team.rst (95-115), airflow-core/docs/core-concepts/multi-team.rst (141-160) |
| **Source Reports** | 7.5.3.md |
| **Related** | |

**Description:**

The multi-team documentation describes highly sensitive operations that can modify team boundaries and resource isolation without any mention of step-up authentication or re-verification: 1) Team deletion (airflow teams delete) - Can destroy team isolation boundaries, 2) Dag bundle to team association - Can redirect all DAGs to a different team's execution context, 3) Team-scoped executor configuration - Can modify execution environments, 4) Team-scoped secrets - Can expose cross-team credentials. These are highly sensitive operations that could compromise the security boundaries between teams. The documentation only mentions a --yes flag to skip confirmation prompts, not security re-verification. A compromised admin session (session hijacking, stolen token) can immediately perform destructive operations without additional verification. There is no documented requirement for re-authentication before operations that affect team isolation, credential access, or execution environments.

**Remediation:**

Implement step-up authentication for sensitive multi-team operations. Before performing sensitive team operations, require fresh authentication for destructive operations (e.g., is_recently_authenticated with max_age_seconds=300), and require secondary factor (MFA verification) for team deletion and similar operations.

---

#### FINDING-018: Authorization resource model lacks environmental and contextual attributes for adaptive security controls

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L3 |
| **CWE** | |
| **ASVS sections** | 8.2.4, 8.4.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/models/resource_details.py (entire file) |
| **Source Reports** | 8.2.4.md, 8.4.2.md |
| **Related** | |

**Description:**

The authorization resource model contains no provisions for environmental or contextual attributes. None of the resource detail dataclasses include fields for IP address, time of day, location, or device information. This indicates adaptive security controls are not part of the authorization decision framework and cannot be applied at session start or during an existing session. User request flows through Auth Manager and Resource details are checked (team/role only) with no environmental evaluation, resulting in access granted/denied purely on static identity. Without adaptive controls, the system cannot detect and respond to compromised credentials used from unusual locations, enforce time-based access restrictions for sensitive operations, challenge suspicious access patterns with step-up authentication, or restrict administrative operations to trusted networks/devices. This is particularly concerning for a system managing workflow orchestration credentials (connections containing database passwords, API keys, etc.).

**Remediation:**

Add an EnvironmentalContext dataclass that captures environmental attributes for adaptive security decisions including source_ip, user_agent, access_timestamp, geo_location, device_fingerprint, is_trusted_network, and session_start_time. Integrate this context into authorization checks by extending the BaseAuthManager methods to accept an optional EnvironmentalContext parameter. Example implementation: Create @dataclass EnvironmentalContext with Optional fields for all environmental attributes, then modify is_authorized_dag and similar methods to accept context: Optional[EnvironmentalContext] = None parameter for contextual evaluation.

---

#### FINDING-019: Missing Trusted Proxy Header Validation Middleware

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | CWE-290 |
| **ASVS sections** | 4.1.3, 4.1.2, 4.2.5, 4.2.3, 4.2.4 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py (152-165) |
| **Source Reports** | 4.1.3.md, 4.1.2.md, 4.2.5.md, 4.2.3.md, 4.2.4.md |
| **Related** | |

**Description:**

The middleware stack does not include any HTTPSRedirectMiddleware or equivalent redirect logic. While the absence of automatic HTTP-to-HTTPS redirects at the application layer could be considered compliant (redirects should be at the infrastructure layer), the concern is that: 1. There is no documentation or enforcement that API endpoints (non-browser) should NOT be auto-redirected. 2. The webapp() catch-all route (user-facing SPA) serves HTML over whatever protocol the request arrives on. 3. No Strict-Transport-Security header middleware is visible. If a load balancer or reverse proxy in front of this application performs blanket HTTP→HTTPS redirects for all paths (including /api/v2/), this would violate ASVS 4.1.2 because API clients sending unencrypted requests would be silently redirected rather than receiving an error.

**Remediation:**

Implement API-specific middleware to reject plaintext HTTP requests on API endpoints instead of redirecting. Example implementation:

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

---

#### FINDING-020: Authentication events (login success/failure) not documented in event catalog

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | |
| **ASVS sections** | 16.3.1, 16.3.3 |
| **Files** | airflow-core/docs/security/audit_logs.rst (Event Catalog section) |
| **Source Reports** | 16.3.1.md, 16.3.3.md |
| **Related** | |

**Description:**

The comprehensive event catalog documents task events, DAG operations, variable/connection/pool operations, user management, and CLI events, but critically does not include authentication events. The following security-critical events are absent from the documented catalog: User login (successful), User login (failed/rejected), User logout, Session creation/destruction, Password change, Multi-factor authentication challenge/success/failure, Token issuance/refresh/revocation, Authentication method/factor used, Account lockout events, OAuth/OIDC callback events. The "User and Role Management" subsection covers administrative CRUD operations on user objects but NOT the authentication process itself. Without documented authentication logging, organizations cannot: Detect brute-force attacks or credential stuffing, Identify compromised accounts through unusual login patterns, Meet compliance requirements for authentication audit trails, Investigate unauthorized access incidents, Determine which authentication method/factor was used. This is a critical gap for ASVS 16.3.1 which explicitly requires logging of "all authentication operations, including successful and unsuccessful attempts" with "metadata such as the type of authentication or factors used."

**Remediation:**

Add an "Authentication Events" section to the Event Catalog documenting: login_success (User successfully authenticated), login_failed (Authentication attempt rejected), logout (User session terminated), session_created (New session established after authentication), session_expired (Session expired due to timeout), token_issued (Authentication token/JWT issued), token_refreshed (Authentication token refreshed), token_revoked (Authentication token explicitly revoked), account_locked (Account locked after repeated failures), account_unlocked (Account unlocked by administrator), password_changed (User password was changed), mfa_challenge (Multi-factor authentication challenge issued), mfa_success (Multi-factor authentication succeeded), mfa_failed (Multi-factor authentication failed). Each authentication event should include: User identity (Username or identifier attempted), Authentication method (Password, OAuth, LDAP, SSO, API key, etc.), Source IP (IP address of the authentication request), User agent (Client application information), Result (Success or failure with reason code), Timestamp (When the attempt occurred in UTC), Session ID (For successful authentications, the resulting session identifier).

---

#### FINDING-021: No documented authorization failure events in the event catalog

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | |
| **ASVS sections** | 16.3.2 |
| **Files** | airflow-core/docs/security/audit_logs.rst (125-250) |
| **Source Reports** | 16.3.2.md |
| **Related** | |

**Description:**

The comprehensive Event Catalog documents over 200 event types covering user actions, system events, and CLI operations. However, there are zero events defined for authorization failures or access denials. The catalog covers successful operations (e.g., trigger_dag_run, delete_variable, patch_connection) but does not define corresponding failure events when a user lacks permission to perform these operations. Authorization decisions happen at every API endpoint and UI action, but no logging event is defined for denied requests. Failed authorization attempts—a key indicator of privilege escalation attacks or misconfigured access controls—go undetected. Security teams cannot identify users probing for unauthorized access.

**Remediation:**

Define and implement authorization failure events: authorization_denied (User attempted an action they lack permission for), resource_access_denied (User attempted to access a restricted resource), dag_access_denied (User attempted to access a DAG outside their scope). Each authorization denial log entry should include: User identification (Who attempted the action), Requested resource (What resource was targeted), Required permission (What permission was needed), Timestamp (When the attempt occurred).

---

#### FINDING-022: No documented events for security control bypass attempts

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | |
| **ASVS sections** | 16.3.3 |
| **Files** | airflow-core/docs/security/audit_logs.rst (Event Catalog section) |
| **Source Reports** | 16.3.3.md |
| **Related** | |

**Description:**

The documentation defines the application's event catalog but does not include any events for detecting or logging attempts to bypass security controls such as: Input validation failures (malformed API requests, injection attempts), Business logic bypasses (attempts to trigger paused DAGs, access past retention periods), Anti-automation violations (rate limit exceeded, excessive login attempts), Authentication failures (invalid credentials, expired tokens). An attacker conducting reconnaissance (probing APIs with invalid inputs, fuzzing parameters, attempting SQL injection) leaves no forensic trail. Security teams cannot correlate attack patterns or trigger alerts on suspicious behavior.

**Remediation:**

Add a Security Events domain with the following events: authentication_failed (Failed login attempt without logging credentials), input_validation_failed (Request rejected due to validation failure), rate_limit_exceeded (Client exceeded request rate limits), csrf_validation_failed (Cross-site request forgery check failed), session_hijack_detected (Session used from unexpected source), api_schema_violation (API request failed schema validation), forbidden_parameter_detected (Attempt to inject forbidden parameters)

---

#### FINDING-023: No documented events for security infrastructure failures

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | |
| **ASVS sections** | 16.3.4 |
| **Files** | airflow-core/docs/security/audit_logs.rst (Event Catalog section) |
| **Source Reports** | 16.3.4.md |
| **Related** | |

**Description:**

The documentation does not define audit events for security infrastructure failures such as: Backend TLS connection failures (to databases, external services, log systems), Certificate validation errors, LDAP/OAuth/SAML provider connectivity failures, Secrets backend unavailability, Encryption/decryption failures (Fernet key issues), Database connection pool exhaustion. The system monitoring events focus exclusively on task-level issues. These are operational events, not security control failures. If TLS connections to backends silently fail and the system falls back to unencrypted communication, or if the secrets backend becomes unavailable and cached credentials are used past their intended lifetime, no audit trail exists for forensic analysis.

**Remediation:**

Add Security Infrastructure Events to the event catalog including: tls_connection_failed (TLS handshake failed to backend service), certificate_validation_error (Certificate chain validation failed), auth_provider_unavailable (Authentication provider connection failed), secrets_backend_error (Secrets backend returned error or timeout), encryption_failure (Data encryption/decryption operation failed), security_config_error (Security configuration could not be applied)

---

#### FINDING-024: Missing Security Headers Middleware to Prevent Incorrect Content Rendering Context

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1, L2 |
| **CWE** | |
| **ASVS sections** | 3.2.1, 3.4.4 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py (168-183) |
| **Source Reports** | 3.2.1.md, 3.4.4.md |
| **Related** | |

**Description:**

The middleware stack initialization adds JWT, auth, gzip, and access logging middlewares but includes NO security headers middleware. There is no: X-Content-Type-Options: nosniff header to prevent MIME-type sniffing, Sec-Fetch-* request header validation to ensure correct request context, Content-Disposition: attachment for API responses that should not be rendered, Response-level Content-Security-Policy header. This is a Type A gap (entry point with NO control) — the init_middlewares function is the centralized location where all middlewares are registered, and security headers are entirely absent. Data flow: HTTP request → FastAPI routing → Response served WITHOUT X-Content-Type-Options, Content-Disposition, or Sec-Fetch-* validation headers.

**Remediation:**

Add a security headers middleware to the application initialization:

```python
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

def init_middlewares(app: FastAPI) -> None:
    # ... existing middlewares ...
    app.add_middleware(SecurityHeadersMiddleware)
```

---

#### FINDING-025: Missing Cookie Security Configuration and Documentation Advises Against HttpOnly

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | |
| **ASVS sections** | 3.3.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py (144-158), airflow-core/docs/howto/run-behind-proxy.rst (56) |
| **Source Reports** | 3.3.1.md |
| **Related** | |

**Description:**

The application initialization code shows no configuration for cookie security attributes. There is no evidence in `init_config`, `init_middlewares`, or any other initialization function of setting: Secure flag on cookies, __Host- or __Secure- prefix for cookie names, or cookie configuration for session/auth tokens. The `allow_credentials=True` in CORS configuration indicates cookies ARE used for authentication, yet their security configuration is not visible in the application setup code. While cookie settings may exist in the auth manager middleware loaded dynamically (`get_auth_manager().get_fastapi_middlewares()`), this cannot be verified from the provided code. Additionally, the documentation explicitly advises proxies NOT to enforce HttpOnly on cookies, suggesting cookies are designed to be JavaScript-accessible without mentioning the compensating requirement for `Secure` attribute. If cookies lack the `Secure` attribute, they can be transmitted over unencrypted HTTP connections, exposing session tokens or authentication credentials. Without `__Host-` or `__Secure-` prefix, cookies lack additional protections against subdomain attacks and scheme confusion.

**Remediation:**

Ensure cookie configuration in the auth system explicitly sets: response.set_cookie(key="__Host-session", value=token_value, secure=True, httponly=True, samesite="Lax", path="/"). If JavaScript cookie access is genuinely required, use a split-cookie approach: __Host-session (HttpOnly, Secure) for authentication and __Secure-csrf (non-HttpOnly, Secure) for CSRF token only.

---

#### FINDING-026: Missing Strict-Transport-Security (HSTS) Header on All Responses

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1, L2, L3 |
| **CWE** | |
| **ASVS sections** | 3.4.1, 3.7.4 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py (1-176) |
| **Source Reports** | 3.4.1.md, 3.7.4.md |
| **Related** | |

**Description:**

The application initialization code configures multiple middleware layers (CORS, GZip, JWT refresh, access logging, auth manager middlewares) but does NOT include any HSTS middleware or response header injection. No `Strict-Transport-Security` header is added to responses. The `init_config`, `init_middlewares`, and `init_views` functions are the complete application setup, and none add HSTS. The proxy documentation also does not recommend adding HSTS headers at the application level or proxy level. Without HSTS, users accessing the application are vulnerable to SSL stripping attacks. An attacker performing a MITM attack can downgrade HTTPS connections to HTTP, intercepting authentication tokens, session cookies, and sensitive workflow data. ASVS Level 1 requires `max-age` of at least 1 year; Level 2 requires `includeSubDomains`.

**Remediation:**

Add HSTS middleware to the application:
```python
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

class HSTSMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

def init_middlewares(app: FastAPI) -> None:
    # ... existing middleware ...
    app.add_middleware(HSTSMiddleware)
```

Alternatively, document HSTS configuration at the reverse proxy level in `run-behind-proxy.rst`:
```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

---

#### FINDING-027: Missing Content-Security-Policy Response Header

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | |
| **ASVS sections** | 3.4.3, 3.4.6, 3.4.7 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py (1-176) |
| **Source Reports** | 3.4.3.md, 3.4.6.md, 3.4.7.md |
| **Related** | |

**Description:**

No CSP reporting configuration exists in either the application code or the documentation. The only CSP example in the documentation (frame-ancestors 'self') does not include a report-uri or report-to directive. Without CSP violation reporting, the security team cannot detect attempts to inject unauthorized content (XSS probing), identify clickjacking attempts (frame-ancestors violations), detect mixed content or unauthorized resource loading, or monitor for policy regressions during development.

**Remediation:**

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

def init_middlewares(app: FastAPI) -> None:
    # ... existing middleware ...
    app.add_middleware(CSPMiddleware)
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

---

#### FINDING-028: Primary nginx documentation example lacks TLS configuration

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | |
| **ASVS sections** | 12.1.1, 12.2.1, 12.2.2 |
| **Files** | airflow-core/docs/howto/run-behind-proxy.rst (34-47) |
| **Source Reports** | 12.1.1.md, 12.2.1.md, 12.2.2.md |
| **Related** | |

**Description:**

The primary reverse proxy example in official documentation configures nginx to listen ONLY on port 80 (HTTP) with no HTTPS listener (port 443) and no HTTP-to-HTTPS redirect. The documentation describes the target URL as `https://lab.mycompany.com/myorg/airflow/` but the provided configuration does not implement TLS. There is no `listen 443 ssl` directive, no SSL certificate configuration, no TLS protocol version restrictions (ssl_protocols), and no redirect from HTTP to HTTPS. Users following this guide will deploy Airflow's web interface accessible over plaintext HTTP, exposing authentication credentials and operational data to network-level interception. This violates requirements for TLS enforcement, protocol version restrictions, and use of publicly trusted certificates for external-facing services.

**Remediation:**

Replace the nginx example with a secure configuration that includes: (1) HTTP to HTTPS redirect on port 80, (2) HTTPS listener on port 443 with SSL certificate configuration, (3) TLS protocols restricted to TLSv1.2 and TLSv1.3 using ssl_protocols directive, (4) Strong cipher suite configuration with server preference enabled, (5) HSTS header with max-age=63072000 and includeSubDomains, (6) ssl_certificate and ssl_certificate_key directives pointing to publicly trusted certificates.

---

#### FINDING-029: No documentation of resource-management strategies including timeouts, retry logic, and backoff algorithms for external services

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L3 |
| **CWE** | |
| **ASVS sections** | 13.1.3 |
| **Files** | airflow-core/docs/administration-and-deployment/scheduler.rst (entire document), airflow-core/docs/core-concepts/executor/index.rst (entire document) |
| **Source Reports** | 13.1.3.md |
| **Related** | |

**Description:**

ASVS 13.1.3 requires documentation of resource-release procedures, timeout settings, failure handling, retry limits, delays, and back-off algorithms for every external system. Neither document provides this information. Missing documentation includes: (1) Database connections - no documented timeout settings, connection recycling (pool_recycle), or connection validation (pool_pre_ping); (2) HTTP connections (to external APIs) - no documented short timeouts for synchronous operations; (3) Retry logic - no documentation of retry limits, exponential backoff, or circuit breaker patterns; (4) Resource release - no documented connection disposal or cleanup procedures; (5) Thread/process management - no documentation of thread pool sizes or process limits for the scheduler. Without documented resource management strategies, the system is vulnerable to cascading failures when downstream services become slow (no timeout documentation), resource exhaustion from unbounded retries (no retry limit documentation), connection leaks (no resource-release documentation), and thread/process starvation (no thread management documentation).

**Remediation:**

Create a 'Resource Management' documentation section covering: (1) Database Connections - document pool size (sql_alchemy_pool_size, default: 5), max overflow (sql_alchemy_max_overflow, default: 10), connection timeout (sql_alchemy_pool_timeout, default: 30s), connection recycling (sql_alchemy_pool_recycle, default: 1800s), pre-ping validation (sql_alchemy_pool_pre_ping, default: True), and retry logic (fail-fast for synchronous DB operations); (2) HTTP Connections (External APIs) - document default timeout (30s, configurable per hook), retry strategy (3 retries with exponential backoff: 1s, 2s, 4s), and circuit breaker status; (3) Message Broker (Celery) - document connection timeout (broker_connection_timeout, default: 4s), retry on startup (broker_connection_retry_on_startup, default: True), and max retries (broker_connection_max_retries, default: None/unlimited).

---

#### FINDING-030: No documentation of critical secrets or rotation schedules in provided documentation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L3 |
| **CWE** | |
| **ASVS sections** | 13.1.4 |
| **Files** | airflow-core/docs/administration-and-deployment/scheduler.rst (entire document), airflow-core/docs/core-concepts/executor/index.rst (entire document) |
| **Source Reports** | 13.1.4.md |
| **Related** | |

**Description:**

Neither document defines the secrets critical for security or provides a rotation schedule. Based on the domain context, Airflow has several critical secrets that require documentation: Undocumented critical secrets include: 1. Fernet key (fernet_key) — used to encrypt Connection passwords in the metadata database, 2. JWT signing key — used for internal Execution API authentication between scheduler and workers, 3. Database credentials — metadata database authentication, 4. Broker credentials — message broker authentication (Redis/RabbitMQ passwords), 5. Webserver secret key (secret_key) — used for Flask session signing, 6. LDAP/OAuth client secrets — if enterprise auth managers are configured, 7. Cloud provider credentials — for cloud-based executors (ECS, Batch, GKE). No rotation schedule is defined for any of these secrets. Impact: Without documented secrets and rotation schedules: Compromised secrets may go unrotated indefinitely, Operators lack guidance on which secrets are most critical to protect, Compliance requirements (SOC2, PCI-DSS) cannot be met without documented rotation policies, The Fernet key specifically supports rotation (multiple keys) but this is not documented in these files.

**Remediation:**

Create a dedicated 'Secrets Management' documentation section with a table defining critical secrets including: fernet_key (Connection encryption, 90 days rotation, Multi-key rotation), webserver.secret_key (Session signing, 90 days rotation, Rolling restart), JWT signing key (Internal API auth, 30 days rotation, Key rotation API), Database password (Metadata DB access, 90 days rotation, Coordinated update), Broker password (Message queue auth, 90 days rotation, Coordinated update). Include a Rotation Procedures section documenting step-by-step rotation for each secret.

---

#### FINDING-031: Missing Sender-Constrained Access Token Verification (No mTLS or DPoP)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L3 |
| **CWE** | |
| **ASVS sections** | 10.3.5 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py (140-155), airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py (743-770) |
| **Source Reports** | 10.3.5.md |
| **Related** | |

**Description:**

The token validation process treats JWT tokens as bearer tokens with no sender-constraining mechanism. The resource server does not prevent the use of stolen access tokens or replay of access tokens from unauthorized parties. Specifically: (1) No mTLS binding - no `cnf` (confirmation) claim verification to bind the token to a client certificate thumbprint, (2) No DPoP verification - no DPoP proof header processing or `jkt` claim verification, (3) Token generation does not embed any sender-constraining claims (`cnf.x5t#S256` or `cnf.jkt`), (4) No abstract method provided for subclasses to implement sender-constraining. A stolen JWT token can be replayed by any party that obtains it (e.g., via network interception, log exposure, or browser compromise).

**Remediation:**

Implement sender-constrained token verification in the `get_user_from_token` method. Add parameters for `client_cert_thumbprint` and `dpop_proof`. Verify mTLS binding by checking the `cnf.x5t#S256` claim against the presented client certificate thumbprint. Verify DPoP binding by checking the `cnf.jkt` claim and validating the DPoP proof header. Modify token generation in `generate_jwt` and `_get_token_signer` to embed sender-constraining claims. Provide abstract methods or configuration flags in the base class to allow subclasses to implement sender-constraining for external-facing APIs.

### 3.3 Medium

#### FINDING-032: Auto-generated symmetric key undersized for HS512 algorithm per RFC 7518

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-326 |
| **ASVS Sections** | 11.6.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/tokens.py:467 |
| **Source Reports** | 11.6.1.md |
| **Related** | FINDING-142, FINDING-143 |

**Description:**

The auto-generated key has 128 bits of entropy (16 random bytes). RFC 7518 Section 3.2 mandates: 'A key of the same size as the hash output (for instance, 256 bits for HS256) or larger MUST be used with this algorithm.' For HS512, this requires a minimum of 512 bits (64 bytes) of key material. When no `[api_auth] jwt_secret` is configured (common in initial deployments or development-to-production transitions), the auto-generated key violates the algorithm specification. While 128 bits prevents practical brute-force, the HMAC security proof requires key length ≥ hash output length for full security guarantees.

**Remediation:**

Generate 64 bytes (512 bits) to match HS512 requirements per RFC 7518: `secret_key = base64url_encode(os.urandom(64))`

---

#### FINDING-033: No explicit token type claim prevents definitive type differentiation at the cryptographic layer

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-287 |
| **ASVS Sections** | 9.2.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/tokens.py:382-398 |
| **Source Reports** | 9.2.2.md |
| **Related** | |

**Description:**

Token generation does not include an explicit 'typ' or 'token_type' claim in standard claims. If the REST API audience is not configured (default is None per documentation), a token generated by the Execution API generator could potentially pass validation by the REST API validator. The 'audience' claim would be 'urn:airflow.apache.org:task' but if the REST API validator has 'audience=None', PyJWT skips audience validation entirely. The 'scope' claim is only enforced at the route level (via 'require_auth' per documentation) rather than at the 'JWTValidator' core validation layer.

**Remediation:**

The JWTValidator should allow callers to specify required claims including token type at the validation layer. Add a 'required_scope' parameter to JWTValidator and validate it in the 'avalidated_claims' method. Additionally, ensure REST API tokens include an explicit scope/type claim when generating tokens. Set a default REST API audience to ensure audience validation is active by default. Add startup validation warning when 'jwt_audience' or 'jwt_issuer' is not configured. Long-term: separate signing keys per token type and add explicit 'typ' header to JWTs.

---

#### FINDING-034: REST API audience defaults to None, potentially allowing cross-service token acceptance when unconfigured

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-346 |
| **ASVS Sections** | 9.2.3, 9.2.4 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/tokens.py:227, airflow-core/src/airflow/api_fastapi/auth/tokens.py:394-398 |
| **Source Reports** | 9.2.3.md, 9.2.4.md |
| **Related** | FINDING-144 |

**Description:**

The documentation confirms both REST API and Execution API share the same signing key infrastructure (`[api_auth] jwt_secret` or `[api_auth] jwt_private_key_path`). The Execution API sets a default audience (`urn:airflow.apache.org:task`), but the REST API audience defaults to None. When the REST API audience is not configured, tokens are issued without the `aud` claim entirely. If a deployment uses the same private key for both APIs without configuring `[api_auth] jwt_audience`, REST API tokens are generated without audience restriction. While the Execution API validator would reject tokens missing its expected audience, a misconfigured REST API validator (or a third-party service trusting the same signing key) could accept Execution API tokens cross-service.

**Remediation:**

Option 1 — Enforce non-empty audience at validator instantiation: Add an attrs validator to the JWTValidator.audience field that raises ValueError if the value is falsy, requiring configuration of [api_auth] jwt_audience. Option 2 — Provide a sensible default audience: Change the configuration default for jwt_audience from None to 'urn:airflow.apache.org:api'. Option 3 — Warn at startup when audience is unconfigured (minimum): In __attrs_post_init__, log a warning if self.audience is falsy, alerting administrators that audience validation is disabled and cross-service token isolation is not active.

---

#### FINDING-035: No Minimum Password Length Validation Mechanism Exists

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1, L2, L3 |
| **CWE** | CWE-521 |
| **ASVS Sections** | 6.2.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:313, airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py:50-54 |
| **Source Reports** | 6.2.1.md |
| **Related** | FINDING-010, FINDING-036, FINDING-037, FINDING-146 |

**Description:**

While auto-generated passwords are 16 characters (meeting the requirement), there is no password length validation/enforcement mechanism anywhere in the codebase. The password file (simple_auth_manager_passwords.json.generated) can be manually edited to contain passwords of any length, and the authentication flow in services/login.py only checks for non-empty passwords. Password file (any length) → get_passwords() → stored as-is → create_token() accepts any match. Gap Type: Type A — No enforcement control exists for minimum length. Proof of Concept: 1. Stop Airflow 2. Edit simple_auth_manager_passwords.json.generated: {"admin": "ab"} 3. Restart Airflow — the 2-character password is accepted with no validation. Impact: If the password file is manually provisioned (e.g., via simple_auth_manager_passwords_file config pointing to a custom file), short passwords are silently accepted. The system provides no guardrail against weak passwords.

**Remediation:**

Implement password length validation utility:
```python
# In a new password validation utility
MIN_PASSWORD_LENGTH = 8  # ASVS minimum; 15 recommended

def validate_password_length(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")

# Apply in _generate_password and any future password-set flows
@staticmethod
def _generate_password() -> str:
    password = "".join(random.choices(
        "abcdefghkmnpqrstuvwxyzABCDEFGHKMNPQRSTUVWXYZ23456789", k=16
    ))
    validate_password_length(password)  # Defense in depth
    return password
```

---

#### FINDING-036: No Context-Specific Word Checking Implemented for Password Validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | CWE-521 |
| **ASVS Sections** | 6.2.11 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:312 |
| **Source Reports** | 6.2.11.md |
| **Related** | FINDING-010, FINDING-035, FINDING-037, FINDING-146 |

**Description:**

The system has no documented list of context-specific words and performs no validation against such a list. While auto-generated random passwords are unlikely to match context-specific terms, the system provides no defense if: (1) The password file is manually edited with weak/contextual passwords (e.g., "airflow", "admin123"), (2) A password change mechanism is added in the future without this validation, (3) The generated password accidentally forms a dictionary word (extremely unlikely but architecturally unprotected). An administrator can manually set a password in the JSON file (e.g., {"admin": "airflow"}) and the system will accept this without any warning or rejection.

**Remediation:**

Implement a password validation function that checks against context-specific words: CONTEXT_SPECIFIC_WORDS = {"airflow", "apache", "admin", "password", "workflow", "dag", "scheduler"}. Create a _validate_password(password: str, username: str) -> bool function that validates password against context-specific words by checking if any blocked words (including the username) appear in the password. Add password validation framework: Create a validate_password(password, username) function that can be applied when passwords are set (even if only via file). This provides the hook needed for context-specific word list checking and breached password database integration (k-anonymity HIBP API).

---

#### FINDING-037: No Breached Password Checking Implemented During Password Creation or Authentication

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3, L1 |
| **CWE** | CWE-521 |
| **ASVS Sections** | 6.2.12, 6.2.4 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:312, airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py:36-78 |
| **Source Reports** | 6.2.12.md, 6.2.4.md |
| **Related** | FINDING-010, FINDING-035, FINDING-036, FINDING-146 |

**Description:**

The system never checks passwords against known breached password databases (e.g., Have I Been Pwned). While auto-generated random 16-character passwords have an astronomically low probability of appearing in breach databases (~52^16 keyspace ≈ 2.8 × 10^27 combinations), the architectural gap means: If a password is later discovered in a breach, the system cannot detect this; If the password file is manually populated with known-breached passwords, no warning is generated; No proactive monitoring of credential compromise exists. An administrator could set a commonly breached password like 'P@ssw0rd123456!!' and the system would accept this without any check against breach databases.

**Remediation:**

Implement breach checking using the k-anonymity approach (HIBP API). Create an async function to check if password appears in known breaches using k-anonymity by hashing the password with SHA1, splitting into prefix and suffix, querying the pwnedpasswords.com API with the prefix, and checking if the suffix appears in the response. Apply during password generation in init() to regenerate passwords that are found in breach databases. Example implementation provided: async def check_password_breached(password: str) -> bool with SHA1 hashing and HIBP API integration.

---

#### FINDING-038: Built-in "Anonymous" Admin Account Active When simple_auth_manager_all_admins is Enabled

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1, L2, L3 |
| **CWE** | CWE-798 |
| **ASVS Sections** | 6.3.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py:83-96 |
| **Source Reports** | 6.3.2.md |
| **Related** | |

**Description:**

Any network-reachable client can obtain full admin access without any authentication when the `simple_auth_manager_all_admins` configuration is enabled. The `_create_anonymous_admin_user()` method creates a hardcoded user with username "Anonymous" and role "ADMIN" that grants JWT tokens with full admin privileges to any requester with NO credentials. While documented as a development feature, if this configuration is inadvertently deployed or left as default, it provides complete bypass of all authentication and authorization.

**Remediation:**

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

---

#### FINDING-039: Generated passwords printed to stdout/logs in plaintext

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1, L2, L3 |
| **CWE** | CWE-532 |
| **ASVS Sections** | 6.4.1, 6.4.4 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:145-147, airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:305-313 |
| **Source Reports** | 6.4.1.md, 6.4.4.md |
| **Related** | |

**Description:**

The SimpleAuthManager: 1) Generates passwords and stores them in a JSON file in plaintext, 2) Prints passwords to stdout/logs during initialization, 3) Has no mechanism for password reset/recovery, 4) Has no identity verification for password changes (editing the file directly is the only recovery mechanism), 5) Uses random.choices() (non-cryptographic PRNG) for password generation. If a user loses their password, the only recovery is to directly edit the plaintext password file on the server filesystem. This provides no identity proofing whatsoever. Per the known false positive patterns, the SimpleAuthManager is documented as for development/testing. This finding is LOW severity because it applies only to development environments.

**Remediation:**

Since this is a dev/test auth manager, add a prominent warning and runtime safety check. Add a startup warning or configuration validation that flags simple_auth_manager_all_admins=True or SimpleAuthManager usage when the deployment appears to be production (e.g., multiple workers, non-localhost bind, database is PostgreSQL/MySQL). Add production safety check for SimpleAuthManager to prevent its use in production environments.

---

#### FINDING-040: No password reset mechanism exists — users cannot recover access

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | CWE-640 |
| **ASVS Sections** | 6.4.3 |
| **Files** | routes/login.py, services/login.py, simple_auth_manager.py |
| **Source Reports** | 6.4.3.md |
| **Related** | |

**Description:**

No /forgot-password, /reset-password, or similar endpoint exists. Users who lose their password have no application-level recovery path. The only recovery is server-side manual intervention (editing the JSON password file or restarting Airflow to regenerate). For ASVS Level 2 compliance, a secure reset process that does not bypass MFA is required. Since neither a reset mechanism nor MFA exists, this requirement cannot be satisfied.

**Remediation:**

Add a password reset flow: 1. Authenticated admin can trigger reset for a user; 2. Reset generates a new temporary password with expiration; 3. If MFA were implemented, reset would not bypass it. Example implementation: @login_router.post('/token/reset-password') def reset_password(body: ResetPasswordBody, current_user: SimpleAuthManagerUser = Depends(get_current_user)): if not SimpleAuthManager._is_admin(current_user) and body.username != current_user.username: raise HTTPException(status_code=403, detail='Insufficient privileges'); new_password = secrets.token_urlsafe(16); store_password_with_expiry(body.username, new_password, expires_in=timedelta(hours=1)); return {'message': 'Password reset. New temporary password must be changed on first login.'}

---

#### FINDING-041: No Inactivity Timeout Mechanism — Only Absolute Token Expiration

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | CWE-613 |
| **ASVS Sections** | 7.3.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py:35-100 |
| **Source Reports** | 7.3.1.md |
| **Related** | FINDING-012, FINDING-013, FINDING-044 |

**Description:**

User authenticates and receives a JWT issued with fixed exp claim. The token remains valid for the entire duration regardless of activity, with no server-side activity tracking. If a user authenticates and then walks away from their workstation, the session remains valid for the entire token lifetime (potentially hours) regardless of inactivity. An attacker with physical or network access to the session can use it without triggering any re-authentication. This is a Type A gap where no inactivity timeout control exists. The only timeout is absolute expiration (jwt_expiration_time).

**Remediation:**

Implement one of the following options:

Option 1: Short-lived access tokens with refresh token pattern - Access token: 15 minutes, Refresh token: checked against last-activity timestamp

Option 2: Server-side session activity tracking
```python
class SessionActivityTracker:
    def check_inactivity(self, user_id: str, max_idle_minutes: int = 30) -> bool:
        last_activity = self.get_last_activity(user_id)
        if datetime.utcnow() - last_activity > timedelta(minutes=max_idle_minutes):
            return False  # Session expired due to inactivity
        self.update_last_activity(user_id)
        return True
```

Option 3: Configurable in settings
```
[api_auth]
jwt_expiration_time = 900  # 15 min access token (short absolute timeout)
jwt_inactivity_timeout = 1800  # 30 min inactivity (if server-side tracking)
```

---

#### FINDING-042: No re-authentication mechanism for sensitive account modifications

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | CWE-306 |
| **ASVS Sections** | 7.5.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/ (entire module scope) |
| **Source Reports** | 7.5.1.md |
| **Related** | FINDING-043 |

**Description:**

The Simple Auth Manager does not implement any sensitive account modification endpoints (no password change, no MFA configuration, no email/phone updates). However, the architecture also lacks any framework for requiring re-authentication before sensitive operations. There is: 1. No re-authentication endpoint or utility 2. No step-up authentication mechanism 3. No freshness check on tokens (no way to distinguish a freshly-authenticated session from an hours-old one) 4. No `auth_time` claim in the JWT that could be used to enforce re-authentication windows. While the Simple Auth Manager is a development tool with limited account management features, the complete absence of re-authentication infrastructure means that if sensitive operations are added later, there's no mechanism to protect them. In the current state, the role and team claims in JWTs are immutable for the token lifetime — a user whose role is upgraded/downgraded will continue operating with the old role until token expiration.

**Remediation:**

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

---

#### FINDING-043: No Re-authentication Required for Security-Sensitive Operations

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | CWE-306 |
| **ASVS Sections** | 7.5.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py (N/A), airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py (N/A) |
| **Source Reports** | 7.5.2.md |
| **Related** | FINDING-042 |

**Description:**

ASVS 7.5.2 explicitly requires that users authenticate again 'with at least one factor' before terminating sessions. The current codebase has no re-authentication mechanism or pattern that could be applied. There is no verify_password() or reauthenticate() method, no re-authentication dependency or middleware, and no endpoint that accepts current_password for verification before sensitive actions. Without re-authentication before session termination, an attacker who has hijacked a session could terminate the legitimate user's other sessions, enabling lock-out attacks while maintaining their own hijacked access.

**Remediation:**

Implement a verify_password() method in SimpleAuthManagerLogin class that validates username and password for re-authentication. Create a get_reauthenticated_user() dependency that requires users to provide their current password in addition to their valid JWT token before performing sensitive operations. Apply this dependency to session termination endpoints using FastAPI's Depends() mechanism. Add rate limiting (e.g., 5 attempts per minute) to prevent brute force attacks on re-authentication. Include a ReauthRequest Pydantic model to accept password in request body for re-authentication flows.

---

#### FINDING-044: No Mechanism to Invalidate Previous Session Tokens on Re-Authentication

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1, L2, L3 |
| **CWE** | CWE-613 |
| **ASVS Sections** | 7.2.4 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py:35-74 |
| **Source Reports** | 7.2.4.md |
| **Related** | FINDING-012, FINDING-013, FINDING-041 |

**Description:**

When a user re-authenticates (e.g., after password change, role change, or suspicious activity), previously issued tokens remain valid until their natural expiration. This creates a window where: 1) Compromised tokens cannot be revoked, 2) Multiple concurrent valid sessions exist without visibility, 3) Role/permission changes don't take immediate effect. The authentication logic generates new JWTs but does not invalidate or revoke previously issued tokens, allowing them to remain valid until expiry.

**Remediation:**

Implement token revocation using one of two approaches: Option 1: Implement a JTI (JWT ID) blacklist - Add unique JWT IDs to each token and maintain a server-side revocation list that invalidates all existing tokens for a user on re-authentication. Option 2: Use very short-lived access tokens (≤15 minutes) with a refresh token mechanism and invalidate refresh tokens on re-authentication. Add a function like invalidate_user_tokens() that is called before generating new tokens.

---

#### FINDING-045: Multiple Authentication Pathways Lack Consolidated Documentation of Security Strength Enforcement

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | |
| **ASVS Sections** | 6.1.3 |
| **Files** | airflow-core/docs/core-concepts/auth-manager/index.rst (entire file) |
| **Source Reports** | 6.1.3.md |
| **Related** | |

**Description:**

The documentation identifies multiple authentication pathways (JWT API token via POST /auth/token, cookie-based UI token exchange, pluggable auth manager login URLs, and token refresh via middleware) but does not provide a consolidated section that: 1) Enumerates all authentication pathways in a single reference table, 2) Specifies the required authentication strength for each pathway, 3) Documents how security controls are consistently enforced across them. The documentation describes pathways independently without cross-referencing their security properties. Without consolidated documentation, implementers of custom auth managers may not understand which security controls must be consistently applied across all pathways. This could lead to auth managers that have inconsistent security between pathways.

**Remediation:**

Add a consolidated authentication pathways table to the documentation that includes: Pathway, Authentication Strength, and Required Controls columns. The table should document Login URL (UI), POST /auth/token (API), Cookie token exchange, and Token refresh pathways with their respective security controls (CSRF, rate limiting, account lockout, httponly, secure, path-scoped, absolute timeout check, revocation). Include a note that all pathways MUST enforce equivalent authentication strength and auth manager implementations MUST NOT allow a weaker pathway to bypass controls of a stronger one.

---

#### FINDING-046: Insufficient Documentation of Session Lifetime Coordination with Federated Identity Providers

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | |
| **ASVS Sections** | 7.1.3 |
| **Files** | airflow-core/docs/core-concepts/auth-manager/index.rst (Token refresh section, lines referencing Keycloak), airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:231-240 |
| **Source Reports** | 7.1.3.md |
| **Related** | |

**Description:**

The documentation references federated identity management (Keycloak SSO integration) and describes token refresh mechanics, but does not document: 1. How Airflow JWT session lifetimes should be coordinated with the external IdP session lifetime, 2. What happens when the IdP session expires but the Airflow JWT is still valid, 3. How session termination at the IdP level propagates to Airflow, 4. Re-authentication conditions beyond simple token expiration. Without documented requirements for session lifetime coordination, auth manager implementers may issue indefinitely-refreshable Airflow tokens without checking IdP session validity, user deactivation or session revocation at the IdP level may not propagate to Airflow in a timely manner, and no documented absolute session timeout means sessions could theoretically persist indefinitely through continuous refresh.

**Remediation:**

Add federated session management documentation that requires auth manager implementations to document and enforce: 1. Absolute session timeout via jwt_absolute_timeout configuration (recommended 8-12 hours), 2. IdP session validation in refresh_user implementation via refresh token checking, IdP session cookie/state verification, or IdP userinfo/introspection endpoint calls, 3. Session termination propagation by revoking outstanding Airflow tokens and denying token refresh requests when users are deactivated or IdP sessions are terminated, 4. Re-authentication conditions including absolute session timeout exceeded, external IdP session expired/revoked, significant user permission changes, and security-sensitive operations.

---

#### FINDING-047: No Documented Absolute Session Timeout Separate from JWT Expiration

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | |
| **ASVS Sections** | 7.1.3 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:212-216, airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:779-791 |
| **Source Reports** | 7.1.3.md |
| **Related** | |

**Description:**

The BaseAuthManager uses jwt_expiration_time as the only session lifetime control. Combined with refresh_user (which can issue new tokens from expired ones), there is no documented or enforced absolute session timeout. The token generator does not include or enforce an iat (issued-at) based absolute timeout that persists across refreshes. Without an absolute session timeout, sessions can be extended indefinitely through continuous refresh, compromised tokens maintain access until explicitly revoked, and federated SSO session invalidation may not propagate in bounded time.

**Remediation:**

Document the requirement and provide implementation guidance by adding a session_start parameter to generate_jwt that tracks when original authentication occurred, including a session_start claim in the JWT token. Auth managers should check this claim during refresh to enforce absolute session timeouts. Add configuration documentation for jwt_absolute_session_timeout setting (default 28800 seconds/8 hours) to enforce maximum session duration regardless of refresh activity.

---

#### FINDING-048: Authorization Documentation Describes Mechanisms But Lacks Concrete Policy Rules

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | |
| **ASVS Sections** | 8.1.1 |
| **Files** | airflow-core/docs/core-concepts/auth-manager/index.rst (Entire document) |
| **Source Reports** | 8.1.1.md |
| **Related** | |

**Description:**

The documentation provides an implementer's guide for the pluggable auth manager interface, describing available authorization methods and their parameters. However, it does not define concrete authorization policy rules that specify: Which consumer roles/types can access which functions, Default-deny posture requirements for implementations, Required minimum authorization granularity for each resource type, Mapping between the three-tier trust model (Deployment Managers, DAG Authors, Authenticated UI Users) and specific is_authorized_* outcomes. The documentation describes WHAT authorization checks exist but not WHAT RULES they should enforce. Without defined policy rules, different auth manager implementations may apply inconsistent authorization decisions, potentially granting excessive access. Developers implementing custom auth managers have no authoritative reference for what access patterns should be allowed or denied for each trust tier.

**Remediation:**

Create a security policy document (or section in this documentation) that explicitly maps: Each resource type to the trust tiers that should have access, Required granularity (e.g., DAGs must enforce per-DAG-ID access), Default posture (deny-by-default requirement), Method-level restrictions per trust tier. Example: Authorization Policy Rules section with a table mapping Resource types (Configuration, Connection, DAG, etc.) to trust tiers (Deployment Manager, DAG Author, Authenticated UI User) with explicit Allowed/Denied rules for each combination.

---

#### FINDING-049: Optional `details` Parameter Allows Resource-Type-Level Authorization Bypass Potential

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | |
| **ASVS Sections** | 8.2.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:242-395 |
| **Source Reports** | 8.2.1.md |
| **Related** | |

**Description:**

All authorization methods accept `details` as an optional parameter with `None` as default. This design creates an ambiguity: a call with `details=None` asks "can the user access this resource type at all?" without specifying a specific resource. If API endpoints incorrectly use `details=None` where a specific resource check is needed, it could bypass data-specific authorization. While this is a design choice for listing operations (where you need to know if a user has ANY connection access before filtering), auth manager implementations that treat `details=None` as "access to all" would create a Type B gap (control exists but incorrectly applied). If an API endpoint that modifies a specific connection calls `is_authorized_connection(method="PUT", user=user)` without providing `details=ConnectionDetails(conn_id=target_id)`, the auth manager might approve access based on general permission without validating access to the specific resource.

**Remediation:**

Document that `details=None` MUST NOT grant broader access than an explicit resource check, and consider adding runtime validation:

```python
def _validate_details_for_mutation(self, method: str, details: Any) -> None:
    """Ensure mutation operations always specify target resource details."""
    if method in ("PUT", "DELETE", "POST") and details is None:
        raise ValueError(
            f"Authorization check for method {method} must specify resource details"
        )
```

---

#### FINDING-050: Missing Session Management Policy Documentation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | |
| **ASVS Sections** | 7.1.1 |
| **Files** | airflow-core/docs/core-concepts/multi-team.rst (entire file scope) |
| **Source Reports** | 7.1.1.md |
| **Related** | |

**Description:**

The multi-team documentation extensively covers resource isolation, executor configuration, and team management, but contains no documentation of session management policies including: Session inactivity timeout values, Absolute maximum session lifetime, Justification for any deviations from NIST SP 800-63B re-authentication requirements, How session policies vary between regular users and administrators, How team-scoped access interacts with session lifetime (e.g., whether changing team membership takes effect within active sessions). Given that the multi-team feature introduces elevated authorization complexity (team-scoped resources, team-specific executors), session management documentation is particularly important to ensure that: A user removed from a team loses access within the session, Team permission changes are reflected without requiring full re-login. Without documented session policies, implementations may use default values that are inappropriate for the security posture of multi-team deployments. There is no reference to NIST SP 800-63B compliance or justification for deviations.

**Remediation:**

Add a session management section to the multi-team documentation (or a separate session management document) that: 1. Documents inactivity timeout (e.g., 15 minutes for admin, 30 minutes for regular users) 2. Documents absolute session lifetime (e.g., 8 hours) 3. Justifies any deviations from NIST SP 800-63B (Section 7.2) 4. Documents how team membership changes affect active sessions 5. Documents interaction with SSO/IdP session policies (especially for Keycloak auth manager)

---

#### FINDING-051: Missing Concurrent Session Policy Documentation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | |
| **ASVS Sections** | 7.1.2 |
| **Files** | airflow-core/docs/core-concepts/multi-team.rst (entire file scope) |
| **Source Reports** | 7.1.2.md |
| **Related** | |

**Description:**

The provided documentation does not define: How many concurrent (parallel) sessions are allowed per account; Whether concurrent session limits differ between regular users and administrators; What behavior occurs when the maximum number of sessions is reached (oldest terminated, new login denied, etc.); How concurrent sessions interact with multi-team access (e.g., can a user have sessions in different team contexts simultaneously). This is particularly relevant in the multi-team context where a user may belong to multiple teams and could potentially maintain sessions with different team contexts active simultaneously. Without documented concurrent session policies: Credential compromise may go undetected (attacker maintains parallel session); Resource contention from unlimited sessions could impact availability; Team isolation boundaries could be weakened if users maintain multiple sessions with different team contexts.

**Remediation:**

Document concurrent session policy including: Maximum concurrent sessions per user (e.g., 3); Behavior at maximum (e.g., oldest session is terminated with notification); Multi-team context handling (e.g., a single session covers all authorized teams; users do not need separate sessions per team); Admin account limits (e.g., limited to 1 concurrent session for security). Example documentation: 'Concurrent Session Policy: Maximum concurrent sessions per user: 3; Behavior at maximum: Oldest session is terminated with notification; Multi-team context: A single session covers all authorized teams; users do not need separate sessions per team; Admin accounts: Limited to 1 concurrent session for security'

---

#### FINDING-052: Session management not included in authorization resource model

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | |
| **ASVS Sections** | 7.4.5 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/models/resource_details.py |
| **Source Reports** | 7.4.5.md |
| **Related** | |

**Description:**

The resource details model does not include a session-related resource entity. The `AccessView` enum lists available views (`CLUSTER_ACTIVITY`, `JOBS`, etc.) but does not include a `SESSIONS` or `USER_SESSIONS` view. The `DagAccessEntity` enum covers DAG-level entities but there is no equivalent enum for session management entities. This suggests that session termination may not be modeled as an authorization-controlled operation in the resource model, which could mean: (1) No granular permission for "terminate other user's session" exists, (2) Admin session termination is not governed by the same RBAC framework as other operations. Without a session management resource in the authorization model, it's unclear whether admins can terminate individual user sessions, terminate all active sessions (e.g., during security incident response), or if session termination permissions are governed by the same RBAC framework.

**Remediation:**

Add session management to the resource model by: (1) Adding a `SESSIONS` entry to the `AccessView` enum, (2) Creating a `SessionDetails` dataclass with fields for session_id, user_id, and team_name to represent session details for admin management. Example code provided in report shows adding `SESSIONS = "SESSIONS"` to the AccessView enum and creating a `@dataclass class SessionDetails` with appropriate fields.

---

#### FINDING-053: Resource details model does not distinguish operation sensitivity levels

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | |
| **ASVS Sections** | 7.5.3 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/models/resource_details.py |
| **Source Reports** | 7.5.3.md |
| **Related** | |

**Description:**

The resource details model does not distinguish between read operations and highly sensitive write/delete operations at the model level. All team operations use the same TeamDetails dataclass regardless of whether the operation is a benign read or a destructive modification. This means the authorization framework cannot easily enforce step-up authentication for specific operation types. Without sensitivity levels in the resource model, the auth manager cannot distinguish between operations requiring standard authentication versus those requiring step-up verification.

**Remediation:**

Add operation sensitivity metadata to the TeamDetails dataclass, such as a requires_step_up boolean field that can be set by calling code for destructive operations to enable the auth manager to distinguish operations requiring standard authentication versus those requiring step-up verification.

---

#### FINDING-054: Missing documentation for federated session lifetime and re-authentication behavior

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | |
| **ASVS Sections** | 7.6.1 |
| **Files** | airflow-core/docs/core-concepts/multi-team.rst:100-108 |
| **Source Reports** | 7.6.1.md |
| **Related** | |

**Description:**

The multi-team documentation references Keycloak as a compatible auth manager for federated authentication but does not document: Session lifetime behavior between Airflow (RP) and the IdP (Keycloak), Re-authentication requirements when IdP session expires, Maximum time between IdP authentication events, Behavior when IdP session is terminated (does Airflow session also terminate?), Token refresh behavior for federated sessions. Without documented federated session behavior: A user's IdP session may expire while their Airflow session remains active, violating the principle that IdP is the authority for authentication state, Users terminated from the IdP may retain active Airflow sessions, Team membership changes in the IdP may not be reflected in active Airflow sessions.

**Remediation:**

Document federated session behavior including: RP session lifetime bounded by [webserver] session_lifetime_minutes, IdP re-authentication required every [auth] max_idp_session_age seconds (default: 3600), Airflow RP session invalidated via back-channel logout when IdP session terminates, Team membership changes reflected at next token refresh (within [auth] token_refresh_interval), NIST SP 800-63C compliance with FAL2 - assertion freshness validated at each sensitive operation.

---

#### FINDING-055: Authorization Documentation Missing Environmental/Contextual Attributes

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | |
| **ASVS Sections** | 8.1.3, 8.1.4 |
| **Files** | airflow-core/docs/core-concepts/multi-team.rst (entire file), airflow-core/docs/security/deprecated_permissions.rst (entire file) |
| **Source Reports** | 8.1.3.md, 8.1.4.md |
| **Related** | |

**Description:**

The application's authorization documentation does not define any environmental or contextual attributes (time of day, user location, IP address, device type, geolocation) that are used in security decisions pertaining to authentication and authorization. Documentation gap → Developers/operators unaware of contextual security considerations → Inconsistent or missing contextual controls in deployment. Without documented environmental/contextual attributes, operators cannot consistently configure or verify adaptive security controls. Security decisions are limited to identity and role without environmental context, which is insufficient for Level 3 compliance.

**Remediation:**

Create a dedicated security architecture document that defines:

Environmental and Contextual Security Attributes
=================================================

The following attributes are evaluated during authentication and authorization:

Time-based Attributes
---------------------
- **Time of day**: Administrative operations restricted to business hours (configurable)
- **Session duration**: Absolute session timeout of [X] hours

Network-based Attributes  
-------------------------
- **Source IP address**: Used for allow/deny list enforcement
- **Network location**: Internal vs. external network detection
- **VPN status**: Required for administrative access

Device-based Attributes
------------------------
- **Device trust level**: Managed vs. unmanaged device detection
- **Client certificate presence**: For service-to-service authentication

---

#### FINDING-056: Undocumented Authorization Change Propagation in Multi-Team Environment

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | |
| **ASVS Sections** | 8.3.2 |
| **Files** | airflow-core/docs/core-concepts/multi-team.rst |
| **Source Reports** | 8.3.2.md |
| **Related** | |

**Description:**

The multi-team documentation does not describe what happens when authorization changes occur (team membership changes, resource reassignment, team deletion). There is no documentation or visible mechanism for: 1. Immediate revocation of access when a user is removed from a team, 2. Immediate effect of resource reassignment between teams, 3. Session invalidation when permissions change, 4. Alerting or reverting actions when stale authorization is used. If authorization changes are not applied immediately, a user removed from a team could continue accessing team-scoped resources (Variables containing secrets, Connections containing credentials) until their session expires.

**Remediation:**

Document and implement authorization change propagation: 1. Immediate enforcement - All subsequent API requests check current permissions from the metadata database (not cached). 2. Active session handling - Sessions are re-validated against current permissions on each request. 3. Running tasks - Tasks already scheduled continue with original permissions but new scheduling uses updated permissions. 4. Alerting - Changes that affect currently active users generate audit events.

---

#### FINDING-057: Undocumented permission propagation through scheduler intermediary

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | |
| **ASVS Sections** | 8.3.3 |
| **Files** | airflow-core/docs/core-concepts/multi-team.rst |
| **Source Reports** | 8.3.3.md |
| **Related** | |

**Description:**

The multi-team architecture documentation describes a chain where the scheduler resolves team membership and selects executors on behalf of users, but does not clearly document how the originating subject's permissions are preserved through the execution chain. Specifically: 1. The scheduler acts as an intermediary between the user and task execution 2. Tasks inherit team association through the chain (Task → Dag → Bundle → Team) 3. There's no documentation of how a task accessing secrets backends uses the originating user's permissions vs. the scheduler's service permissions. Data Flow: User triggers DAG run → Scheduler (service account) resolves team → Executor runs task → Task accesses secrets backend → Authorization check uses ??? permissions. If access to team-scoped resources (Variables, Connections) during task execution is based on the scheduler's service permissions rather than the originating user's permissions, it could allow unauthorized access to resources. A user who can trigger a DAG in a team bundle could potentially access resources they shouldn't if the team-based isolation relies on structural assignment rather than user-level authorization at runtime.

**Remediation:**

Document the permission propagation model explicitly: When a task accesses team-scoped resources: 1. The task's team is determined by the DAG Bundle association (structural). 2. The task can access resources scoped to its team regardless of which user triggered the run. 3. Access control for who can TRIGGER a DAG run is enforced at the API level using the originating user's permissions. 4. The separation of concerns is: API layer: User's permissions determine what DAGs they can trigger; Execution layer: Task's team determines what resources it can access.

---

#### FINDING-058: Incomplete Multi-Tenant Cross-Tenant Controls with Information Leakage Risk

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | |
| **ASVS Sections** | 8.4.1 |
| **Files** | airflow-core/docs/core-concepts/multi-team.rst, airflow-core/src/airflow/api_fastapi/auth/managers/models/resource_details.py |
| **Source Reports** | 8.4.1.md |
| **Related** | |

**Description:**

While multi-team resource isolation is documented and the resource model includes team_name fields, the documentation explicitly acknowledges that this is an experimental feature with incomplete isolation. Several gaps in cross-tenant controls are identifiable: (1) Global uniqueness requirement creates information leakage risk - Dag IDs, Variable keys, and Connection IDs must be unique across the entire Airflow deployment, meaning one team can determine what identifiers another team uses through naming conflicts. (2) Shared metadata database - All teams share the same Airflow infrastructure, scheduler, and metadata database without documented database-level row security, cross-tenant data access relies entirely on application-layer enforcement. (3) Incomplete coverage - The documentation lists missing functionality including 'Some UI elements may not be fully team-aware' and 'Async support (Triggers, Event Driven Scheduling, async Callbacks, etc)' which represent gaps in cross-tenant enforcement. (4) Optional team_name field means authorization logic must consistently handle both None (global) and team-scoped scenarios.

**Remediation:**

1. For the namespace information leakage: Return generic 'already exists' without revealing owning team (e.g., raise ConflictError('Variable key already exists') NOT 'Variable key belongs to team_b'). 2. For comprehensive coverage: Document and enforce cross-tenant control verification at every data access point including: All database queries for team-scoped resources include team_name filter, UI endpoints filter response data by team membership, API responses never include resources from other teams, Async operations (triggers, callbacks) inherit team from parent DAG.

---

#### FINDING-059: Administrative CLI operations lack multi-layered security controls

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | |
| **ASVS Sections** | 8.4.2 |
| **Files** | airflow-core/docs/core-concepts/multi-team.rst:95-115 |
| **Source Reports** | 8.4.2.md |
| **Related** | |

**Description:**

The multi-team documentation describes administrative operations (team creation, deletion, resource assignment, executor configuration) that are managed via CLI (`airflow teams create`, `airflow teams delete`) and configuration files. The documentation does not describe any multi-layered security controls for these administrative interfaces beyond basic auth manager authorization. There is no mention of: continuous identity verification during administrative sessions, device security posture assessment, contextual risk analysis (e.g., geographic location, time-of-day, behavioral patterns), or step-up authentication for destructive admin operations (e.g., `airflow teams delete`). Administrative operations that affect team isolation boundaries can be performed with only basic authentication, without additional layers such as device posture, contextual risk, or continuous verification. This could allow an attacker who compromises a single admin credential to modify team boundaries.

**Remediation:**

For Level 3 compliance, administrative interfaces should implement: (1) MFA/step-up authentication for administrative operations, (2) Device posture checks (e.g., managed device verification), (3) Contextual risk scoring (unusual time, location, or behavior triggers additional verification), (4) Session binding to reduce session hijacking risk. Add admin operation verification in auth manager base with methods to verify session freshness, assess device posture, and calculate contextual risk scores.

---

#### FINDING-060: Authorization Dependency Consumes Unvalidated Raw Body Input

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-20 |
| **ASVS Sections** | 2.2.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/security.py:248-258 |
| **Source Reports** | 2.2.2.md |
| **Related** | |

**Description:**

The authorization dependency reads `dag_id` directly from the raw JSON body without validating its type or format. The Pydantic validation in the actual endpoint handler runs as a parallel dependency, meaning the authorization check may operate on unvalidated data. If `dag_id` is a non-string value (e.g., `null`, array, integer), the authorization check could produce incorrect results. Authorization decisions may be made with incorrect context when the raw body contains unexpected types, potentially allowing requests to pass authorization checks before Pydantic validation rejects them.

**Remediation:**

Add type validation before using team_name in authorization checks. Example: `if raw is not None and not isinstance(raw, str): raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="team_name must be a string")` to ensure proper type enforcement before authorization decisions.

---

#### FINDING-061: Flask Plugin Mount Bypasses FastAPI Trusted Service Layer

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-1188 |
| **ASVS Sections** | 2.2.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py:98-125 |
| **Source Reports** | 2.2.2.md |
| **Related** | |

**Description:**

The Flask application mounted via `WSGIMiddleware` creates a parallel trust boundary that bypasses all FastAPI-level security controls. The Flask/FAB application relies entirely on its own validation and authentication mechanisms, which may have different validation rules, different authentication schemes, or gaps in coverage compared to the primary FastAPI application. Any legacy Airflow 2 plugin endpoints at `/pluginsv2/*` operate outside the FastAPI trusted service layer, creating an inconsistent security posture across the application.

**Remediation:**

Add authentication middleware wrapper to verify authentication before routing to Flask, ensure Flask app has equivalent validation middleware, or document security responsibility boundary explicitly. Long-term: develop migration plan to eliminate Flask plugin mount and create FastAPI-native plugin system with unified validation.

#### FINDING-062: No per-message digital signatures for highly sensitive operations

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS sections** | 4.1.5 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/security.py (entire file), airflow-core/src/airflow/api_fastapi/core_api/app.py |
| **Source Reports** | 4.1.5.md |
| **Related** | - |

**Description:**

There is no implementation of per-message digital signatures for highly sensitive operations. The application handles connection credentials (secrets), variable values (potentially sensitive), DAG trigger operations (state-changing), and backfill operations (resource-intensive). None of these operations implement request body signing (e.g., HTTP Message Signatures per RFC 9421, or custom HMAC-based signing). The authentication relies solely on JWT bearer tokens, which authenticate the sender but do not provide non-repudiation for individual requests, integrity verification of request bodies, or protection against token replay with modified payloads. For Level 3 compliance, highly sensitive operations (creating connections with credentials, triggering production DAGs, modifying variables containing secrets) lack per-message integrity verification beyond transport-layer TLS.

**Remediation:**

Implement HTTP Message Signatures (RFC 9421) or HMAC-based request signing for sensitive mutation endpoints. Example implementation:

python
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


This could be implemented as an optional security feature enabled via configuration for Level 3 compliance.

---

#### FINDING-063: JWKS Endpoint Supports Unencrypted HTTP, Enabling Key Injection via MITM

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS sections** | 12.3.1, 12.3.3 |
| **Files** | airflow-core/docs/security/jwt_token_authentication.rst (Signing and Cryptography section, lines referencing trusted_jwks_url) |
| **Source Reports** | 12.3.1.md, 12.3.3.md |
| **Related** | - |

**Description:**

The Execution API is explicitly described as an internal, HTTP-based service used for communication between Airflow components (workers, scheduler, triggerer, DAG processor). The documentation: 1. Never mentions TLS as a requirement for this internal communication 2. Describes the connection as "HTTP requests" without specifying HTTPS 3. Provides no configuration for enforcing TLS on the Execution API server 4. Documents no mechanism to prevent fallback to unencrypted HTTP. The httpx.Client is created with BearerAuth but no documented base_url scheme enforcement. Without TLS enforcement, all internal communication between workers and the Execution API server—including JWT tokens, connection credentials (fetched via the API), variables, and XCom data—could be transmitted in cleartext. This violates ASVS 12.3.3's requirement that all HTTP-based internal services use TLS.

**Remediation:**

Add explicit TLS configuration and enforcement documentation:

Transport Security
^^^^^^^^^^^^^^^^^^

All Execution API communication between workers and the API server must use TLS.
Configure the Execution API URL with an https:// scheme:

.. code-block:: ini

   [execution_api]
   url = https://scheduler.internal:8443

The server must be configured to reject unencrypted HTTP connections on the Execution
API port. Use [execution_api] tls_cert_path and [execution_api] tls_key_path
to configure the server certificate.

---

#### FINDING-064: No Certificate Validation Documented for Worker HTTP Client

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS sections** | 12.3.2, 12.3.4 |
| **Files** | airflow-core/docs/security/jwt_token_authentication.rst (Token delivery to workers section) |
| **Source Reports** | 12.3.2.md, 12.3.4.md |
| **Related** | - |

**Description:**

The Configuration Reference section documents all JWT-related configuration parameters but includes no parameters for: specifying trusted internal CA certificates for Execution API TLS connections, configuring certificate pinning for known internal services, restricting which CAs are trusted for internal service certificates, or specifying self-signed certificate trust stores. Without these configurations, deployments must rely on system CA bundles or disable certificate verification entirely, neither of which satisfies ASVS 12.3.4's requirement to trust only specific internal CAs for internal service communication.

**Remediation:**

Document that the worker HTTP client must validate server certificates. Include configuration guidance for internal CA certificates: The httpx.Client used by workers validates the Execution API server's TLS certificate against the system CA bundle by default. For deployments using internal CAs, configure [execution_api] ca_cert_path to point to the internal CA certificate bundle. Warning: Never set verify=False in production. This disables all certificate validation and exposes tokens to interception.

---

#### FINDING-065: No Application-Layer Allowlist for Outbound Communication Destinations

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS sections** | 13.2.4 |
| **Files** | airflow-core/docs/security/jwt_token_authentication.rst |
| **Source Reports** | 13.2.4.md |
| **Related** | - |

**Description:**

The documentation describes the Execution API communication architecture comprehensively but does NOT describe any allowlist mechanism that restricts: which hosts/endpoints workers are permitted to contact, which external resources the `trusted_jwks_url` parameter can reference (accepts any "local file or remote HTTP/HTTPS URL"), or which systems the application can make outbound requests to. The `trusted_jwks_url` configuration accepts arbitrary URLs without URL validation, domain allowlisting, or SSRF protection. Without an application-layer allowlist for outbound communications: (1) A compromised worker could potentially communicate with arbitrary external systems for data exfiltration. (2) The `trusted_jwks_url` could be configured to point to an attacker-controlled JWKS endpoint if configuration injection is possible. (3) No defense-in-depth exists if network-level controls (firewalls) are misconfigured or absent.

**Remediation:**

Implement an application-layer allowlist for outbound connections, particularly for: (1) The `trusted_jwks_url` parameter (validate against allowed URL patterns/domains), (2) Worker-to-API communication (restrict to known Execution API endpoints). Example: URL allowlist validation for trusted_jwks_url using ALLOWED_JWKS_SCHEMES = {"https", "file"} and ALLOWED_JWKS_DOMAINS to validate parsed URLs before use.

---

#### FINDING-066: Cryptographic Operations Performed In-Process Without Isolated Security Module

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS sections** | 13.3.3 |
| **Files** | airflow-core/docs/security/secrets/fernet.rst |
| **Source Reports** | 13.3.3.md |
| **Related** | - |

**Description:**

The Fernet encryption documentation describes cryptographic operations (encryption/decryption of connection passwords and variables) performed within the Airflow application process, with key material loaded directly into application memory. There is no documentation or support for performing these operations within an isolated security module (HSM, vault transit engine, or KMS). Key material exists in application memory and is accessible to any code running in the same process (including DAG code, plugins, and any compromised libraries). For L3 deployments requiring hardware-backed solutions, this architecture does not meet the requirement. This is an L3 requirement. The current architecture is acceptable for L2 if Fernet keys are properly protected. However, there is no documented path to using transit encryption (e.g., Vault Transit, AWS KMS Encrypt/Decrypt) as an alternative to local Fernet encryption.

**Remediation:**

For L3 compliance, document and support a KMS-backed encryption mode:

Hardware-Backed Encryption (L3)
''''''''''''''''''''''''''''''''

For deployments requiring hardware-backed cryptographic operations, configure
Airflow to use a KMS-backed encryption backend instead of local Fernet:

- HashiCorp Vault Transit Engine
- AWS KMS with envelope encryption
- GCP Cloud KMS
- Azure Key Vault

This ensures key material never leaves the security boundary of the HSM/KMS.

---

#### FINDING-067: Database Connection Documentation Omits TLS/SSL Configuration for Sensitive Data in Transit

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS sections** | 14.2.4 |
| **Files** | airflow-core/docs/howto/set-up-database.rst (135-138), airflow-core/docs/howto/set-up-database.rst (194-195) |
| **Source Reports** | 14.2.4.md |
| **Related** | - |

**Description:**

The documentation for setting up production database backends does not include or require TLS/SSL configuration (sslmode=require for PostgreSQL, ssl=true/ssl_mode=REQUIRED for MySQL). While the Fernet documentation covers encryption at rest, the database setup documentation does not address encryption in transit as a required control for the protection level of sensitive metadata. Deployments following this documentation may transmit encrypted-but-observable database traffic over unencrypted connections. Data flow: User follows documentation → configures database connection → connection string lacks sslmode=require or equivalent → sensitive metadata (encrypted passwords, variable values, DAG execution data) transmitted in plaintext over the network.

**Remediation:**

Add explicit guidance about log access controls and sensitive data handling:

WARNING: SQLAlchemy echo=True logging may expose query parameters containing sensitive data. If enabled, ensure log access is restricted to authorized personnel, logs are stored in encrypted storage, and log retention follows your organization's data protection policy.

---

#### FINDING-068: No Defined Automatic Retention Schedule for Sensitive Metadata

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS sections** | 14.2.7 |
| **Files** | airflow-core/docs/howto/set-up-database.rst (253-259) |
| **Source Reports** | 14.2.7.md |
| **Related** | - |

**Description:**

The documentation acknowledges the existence of database cleanup tooling (airflow db clean and airflow.utils.db_cleanup) but does not define: 1) A data retention classification scheme for different types of sensitive data, 2) An automatic/scheduled cleanup mechanism (the tools require manual invocation), 3) Retention periods for different data categories (task instance logs, connection audit records, variable history), 4) Automatic expiration policies for encrypted credentials stored in the metadata database. Without a defined retention classification and automatic deletion schedule, sensitive data (including encrypted connection credentials for decommissioned systems, historical task execution records containing sensitive parameters, and audit data) accumulates indefinitely in the metadata database. This increases the blast radius of a database compromise and violates the principle of data minimization.

**Remediation:**

Document and implement a retention classification with policies based on sensitivity. Define retention periods for connection credentials (review quarterly), task instance records (retain for N days based on compliance), audit logs (minimum 1 year), and variables (periodic review with secrets backends with TTL preferred). Configure automatic cleanup using airflow db clean command in scheduler crontab or DAG with appropriate --clean-before-timestamp parameters.

---

#### FINDING-069: Incomplete Data Sensitivity Classification Schema

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS sections** | 14.1.1 |
| **Files** | airflow-core/docs/security/secrets/mask-sensitive-values.rst (23-25), airflow-core/docs/security/secrets/mask-sensitive-values.rst (42-53) |
| **Source Reports** | 14.1.1.md |
| **Related** | - |

**Description:**

The documentation identifies sensitive data through keyword matching (access_token, api_key, password, etc.) but does not establish formal protection levels. The classification is binary — either a value matches a sensitive keyword or it doesn't. There is no documented tiering such as Level 1: PII (user emails, names), Level 2: Credentials (passwords, tokens), Level 3: Cryptographic material (private keys, signing keys). The masking scope table reveals that some data classified as sensitive receives inconsistent treatment. For example, a variable containing 'keyfile_dict' (which would typically contain cryptographic material) is only masked in the Variables UI — not in logs or rendered templates. This inconsistency suggests the classification lacks formal protection levels. Without formal protection levels, data that should receive the highest protection (e.g., private keys passed via Variables) may receive inconsistent controls. This makes compliance with regulations like GDPR (which requires documented data classification) difficult to demonstrate.

**Remediation:**

Create a formal data classification document that: 1. Defines explicit protection levels (e.g., PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED), 2. Maps each sensitive keyword category to a protection level, 3. Ensures all data at the same protection level receives identical masking scope

---

#### FINDING-070: No Documented Protection Requirements Per Sensitivity Level

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS sections** | 14.1.2 |
| **Files** | airflow-core/docs/security/secrets/mask-sensitive-values.rst (entire document) |
| **Source Reports** | 14.1.2.md |
| **Related** | - |

**Description:**

The documentation describes masking behavior but does not define protection requirements per sensitivity level as required by ASVS 14.1.2. Specifically, the following required elements are absent from this document: encryption requirements (no mention of encryption at rest/transit for different data levels), integrity verification (not addressed), retention policies (no mention of how long masked/unmasked logs are retained), logging requirements (describes what IS masked in logs, but not access control to logs), database-level encryption (not addressed), privacy-enhancing technologies (masking is one PET, but no comprehensive framework), and access controls around sensitive data in logs (not addressed). Without documented protection requirements per level, implementation teams cannot verify whether the controls applied are sufficient. For example, a private_key value (which should require the highest protection) receives the same masking treatment as an api_key — there's no documented requirement that private keys should additionally be encrypted at rest or have restricted access.

**Remediation:**

Create a protection requirements matrix with columns for Protection Level, Encryption, Masking, Log Retention, Access Control, and Integrity. Define levels such as: RESTRICTED (AES-256, Always masked, 7 days retention, Admin only access, HMAC integrity), CONFIDENTIAL (AES-256, Always masked, 30 days retention, Role-based access, Checksum integrity), INTERNAL (TLS only, Masked in logs, 90 days retention, Authenticated access, N/A integrity), PUBLIC (Optional encryption, Never masked, 1 year retention, Any access, N/A integrity).

---

#### FINDING-071: Documented Environment Variable Exposure to External Processes

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS sections** | 14.2.3 |
| **Files** | airflow-core/docs/security/secrets/mask-sensitive-values.rst (95-102) |
| **Source Reports** | 14.2.3.md |
| **Related** | - |

**Description:**

The documentation acknowledges that secrets passed via environment variables to external processes (like Kubernetes pods) are: (1) Not masked by Airflow's masking system, (2) Visible to anyone with process-level access, (3) Effectively sent to an external execution environment outside Airflow's control. While this is documented as a warning, there is no technical control preventing users from passing secrets via environment variables to operators that spawn external processes. The KubernetesPodOperator is called out specifically, but any operator that creates child processes or communicates with external systems could expose environment variables. Data Flow: DAG author sets env var → Operator passes to external process → Secrets visible in process environment → No masking applied. Sensitive credentials could be exposed in Kubernetes pod specifications, container runtimes, or process listings accessible to cluster administrators or monitoring tools that constitute 'untrusted parties' from the application's perspective.

**Remediation:**

Beyond documentation: (1) Consider adding a linting rule or DAG validation check that warns when environment variables match sensitive keywords, (2) Document in the protection requirements that secrets passed to external processes must use native secret management (K8s Secrets, vault injection)

---

#### FINDING-072: Incomplete technology stack layer mapping in logging inventory

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS sections** | 16.1.1 |
| **Files** | airflow-core/docs/security/audit_logs.rst (entire document) |
| **Source Reports** | 16.1.1.md |
| **Related** | - |

**Description:**

While the document provides a substantial inventory of logged events, it does not explicitly map logging at each discrete layer of the technology stack (e.g., web server/reverse proxy layer, application framework layer, ORM/database layer, infrastructure/OS layer). The document distinguishes between "Audit Logs" (database) and "Event Logs" (files/external systems) but doesn't provide a layered architecture view showing what logging occurs at each technology boundary. The document covers application-level logging comprehensively but lacks: Reverse proxy/load balancer logging documentation, Operating system audit logging (auditd/syslog integration), Database server query logging, Container/orchestrator layer logging (if applicable), Network-level logging.

**Remediation:**

Add a section explicitly mapping each technology layer in the deployment architecture to its logging configuration. Include a table with columns for Layer, Technology, Log Source, Events Captured, Storage, and Retention. Document logging for Reverse Proxy (Nginx/HAProxy), Application (Web and Audit), Database (PostgreSQL), and Operating System (Linux/auditd) layers with specific configurations and retention periods.

---

#### FINDING-073: Missing "where" metadata in audit log schema - no source IP or component identifier

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS sections** | 16.2.1 |
| **Files** | airflow-core/docs/security/audit_logs.rst (Anatomy of an Audit Log Entry section) |
| **Source Reports** | 16.2.1.md |
| **Related** | - |

**Description:**

The documented audit log schema includes "when" (dttm), "who" (owner), and "what" (event, dag_id, task_id, etc.), but lacks explicit "where" metadata. There is no documented field for: Source IP address of the request, Client/interface used (Web UI, REST API, CLI), Server/component that generated the log entry, Session identifier for correlating multiple actions. Without source IP and interface identification, forensic investigation cannot determine the origin of malicious actions. An attacker who compromises credentials cannot be traced to their network location. Timeline correlation across distributed systems is hindered without component identifiers.

**Remediation:**

Add explicit "where" fields to the documented schema: source_ip (IP address from which the request originated for API/UI actions), interface (The interface through which the action was performed: web_ui, rest_api, cli, system), component (The Airflow component that generated the log: webserver, scheduler, worker, triggerer), session_id (Session identifier for correlating multiple actions in a single session)

---

#### FINDING-074: No documentation of time synchronization requirements for logging components

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS sections** | 16.2.2 |
| **Files** | airflow-core/docs/security/audit_logs.rst (Anatomy of an Audit Log Entry section) |
| **Source Reports** | 16.2.2.md |
| **Related** | - |

**Description:**

While the document states that the `dttm` field uses "UTC timezone," there is no documentation of: Requirements for NTP synchronization across all Airflow components (webserver, scheduler, workers, triggerer); How time synchronization is verified or enforced; What happens when distributed components have clock drift; Configuration for ensuring consistent time sources. This is the only mention of time/timezone in the entire document. For a distributed system with multiple components (scheduler, webserver, workers, triggerers, dag-processor), time synchronization is critical. In distributed Airflow deployments (especially with Celery/Kubernetes executors), workers may run on different nodes. Without documented time synchronization requirements, clock drift between components could make event timelines unreliable and hinder forensic investigations.

**Remediation:**

Add a section on time synchronization:

Time Synchronization Requirements
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

All Airflow components (webserver, scheduler, workers, triggerer, dag-processor)
MUST synchronize their system clocks using NTP or equivalent time synchronization
protocol. Maximum acceptable clock drift between any two components is 1 second.

All audit log timestamps (``dttm``) are recorded in UTC. The application uses
``datetime.now(timezone.utc)`` for all audit log timestamp generation to ensure
consistency regardless of the server's local timezone configuration.

For Kubernetes deployments, ensure that all pods use the cluster's time
synchronization mechanism. For bare-metal/VM deployments, configure NTP
pointing to reliable time sources (e.g., pool.ntp.org or organization's NTP servers).

---

#### FINDING-075: No documented mechanism to verify logs are only sent to inventoried destinations

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS sections** | 16.2.3 |
| **Files** | airflow-core/docs/security/audit_logs.rst (throughout) |
| **Source Reports** | 16.2.3.md |
| **Related** | - |

**Description:**

The document identifies where logs are stored (database `log` table, `$AIRFLOW_HOME/logs/`, external systems) but does not document: (1) A mechanism to enforce that logs are ONLY sent to approved destinations, (2) How to verify that no additional/unauthorized log sinks exist, (3) Configuration validation to prevent log exfiltration, (4) How custom logging configurations are audited against the inventory. Without enforcement mechanisms, logs containing sensitive data (connection details, variable values, user actions) could be inadvertently or maliciously sent to unauthorized destinations, violating data protection requirements.

**Remediation:**

Add documentation of destination control including: Log Destination Governance section that documents centrally managed logging configuration through airflow.cfg and logging_config_class setting, list of approved log destinations (Audit Logs in metadata database log table, Task Logs in configured remote logging backend or local filesystem, Component Logs in local filesystem or configured syslog forwarding), requirement that any modification to log destinations requires updating the inventory, verification process using 'airflow config list' command to verify active logging configuration matches documented inventory, and requirement that custom logging handlers added via logging_config_class must be reviewed and documented before deployment.

---

#### FINDING-076: No documented common logging format standard or correlation mechanism

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS sections** | 16.2.4 |
| **Files** | airflow-core/docs/security/audit_logs.rst (throughout) |
| **Source Reports** | 16.2.4.md |
| **Related** | - |

**Description:**

The document describes audit log fields stored in a relational database but does not: reference a common logging format standard (CEF, OCSF, JSON Lines, W3C Extended Log Format); document how logs from different components can be correlated (no trace ID, request ID, or correlation ID); describe how the audit log format maps to the format expected by log processors (SIEM systems); specify the format for event logs (only audit logs are structurally defined). Without a common format and correlation mechanism, distributed Airflow deployments cannot effectively correlate events across components. A single user action may generate audit entries across webserver, scheduler, and worker components without a linking identifier.

**Remediation:**

Document a log format and correlation mechanism. When exported via REST API, audit logs should use JSON format compatible with common SIEM systems with fields including timestamp, event_type, actor, resource, source_ip, correlation_id, and component. All API requests should generate a X-Request-ID header that is included in both audit and event logs, enabling correlation of a single user action across multiple log entries and components. Event logs should use a Python logging format that includes request_id for correlation.

---

#### FINDING-077: No documentation of sensitive data access logging (L3 requirement)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS sections** | 16.3.2 |
| **Files** | airflow-core/docs/security/audit_logs.rst (Event Catalog section) |
| **Source Reports** | 16.3.2.md |
| **Related** | - |

**Description:**

For ASVS L3, all authorization decisions must be logged, including when sensitive data is accessed (without logging the sensitive data itself). The documentation shows get_* events like get_dag, get_pool, but does not document whether connection credential access, variable value retrieval (especially sensitive variables), or Fernet key operations generate audit entries that note sensitive data was accessed without including the data. The Event Catalog shows Variable operations (delete_variable, patch_variable, post_variable, bulk_variables) but no event like get_variable to log reads of potentially secret variables, and no documentation that the extra field excludes sensitive values. Sensitive data access goes unaudited; compliance with data governance frameworks (GDPR, SOC2) is incomplete.

**Remediation:**

Document and implement sensitive data access logging events (e.g., get_variable for variable reads, get_connection_credentials for connection access) that capture when sensitive data is accessed without logging the sensitive data itself. Ensure the extra field explicitly excludes sensitive values and document this behavior.

---

#### FINDING-078: Event logs vs audit logs distinction creates blind spots for security failures

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS sections** | 16.3.4 |
| **Files** | airflow-core/docs/security/audit_logs.rst (Audit Logs vs Event Logs section) |
| **Source Reports** | 16.3.4.md |
| **Related** | - |

**Description:**

The documentation explicitly separates audit logs (stored in database) from event logs (stored in files/external systems) and states event logs have 'Short to medium-term (days to weeks)' retention. Security control failures that manifest as application errors would typically appear only in event logs, not audit logs, meaning they have short retention and may not be available for forensic analysis of long-running security compromises. Security control failures logged only in event logs may be purged before an incident is detected, destroying forensic evidence.

**Remediation:**

Document mandatory log transmission to a separate system for production deployments with TLS requirements. Ensure security control failures are captured in audit logs with long-term retention (months to years) rather than only in event logs. Document log retention policies aligned with compliance requirements specifying minimum retention periods.

---

#### FINDING-079: No documentation of log encoding or injection prevention measures

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS sections** | 16.4.1 |
| **Files** | airflow-core/docs/security/audit_logs.rst (Custom Events section, Anatomy section) |
| **Source Reports** | 16.4.1.md |
| **Related** | - |

**Description:**

The documentation describes how to create custom audit log entries and the structure of log entries but makes no mention of: Input sanitization before logging, Encoding of user-supplied values in log entries, Protection against log injection (newline injection, CRLF, format string attacks), Safe handling of the `extra` field which accepts arbitrary content. The custom event example shows direct insertion of user-supplied strings without sanitization guidance. The `owner` field comes from the authenticated user's identity, and the `extra` field can contain arbitrary context. If these contain malicious characters (e.g., newlines for log forging, SQL for injection), the documentation provides no guidance on sanitization. Without documented encoding requirements, developers creating custom events or extending the logging system may introduce log injection vulnerabilities. Attackers could forge log entries, corrupt log analysis tools, or inject malicious content into SIEM systems.

**Remediation:**

Add a "Log Security" section to the documentation that specifies: All data written to audit logs must be properly encoded; User-supplied values in `owner` and `extra` fields are automatically sanitized to prevent log injection attacks; Newline characters (`\n`, `\r`) are escaped in all log fields; The `extra` field is JSON-encoded, preventing format string attacks; HTML/XML special characters are escaped before transmission to external systems. Include guidance that when creating custom audit log entries, use the provided `Log` model which handles encoding automatically. Never construct log entries by string concatenation.

---

#### FINDING-080: Event log file protection not documented

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS sections** | 16.4.2 |
| **Files** | airflow-core/docs/security/audit_logs.rst (Querying Event Logs section) |
| **Source Reports** | 16.4.2.md |
| **Related** | - |

**Description:**

Audit logs are stored in the `log` table within the same metadata database used by the Airflow application. The documentation notes the `Audit Logs.can_read` permission for UI access but does not address: Database-level access controls preventing the application from modifying existing log entries, Write-once/append-only constraints on the `log` table, Separation of log database from operational database, Protection against administrators clearing the log table. A user with database write access (which the Airflow application itself has) could `DELETE FROM log` or `UPDATE log SET event = 'success' WHERE event = 'failed'`. Log integrity cannot be guaranteed when stored in the same database the application has full write access to. A compromised Airflow component could silently alter its own audit trail.

**Remediation:**

Implement database-level access controls preventing the application from modifying existing log entries, add write-once/append-only constraints on the `log` table, separate log database from operational database, add protection against administrators clearing the log table, and implement log integrity verification (checksums, hash chains, or digital signatures on log entries).

---

#### FINDING-081: External log transmission documented as optional without security requirements

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS sections** | 16.4.3 |
| **Files** | airflow-core/docs/security/audit_logs.rst (External Logging Systems section) |
| **Source Reports** | 16.4.3.md |
| **Related** | - |

**Description:**

The documentation mentions external logging systems but presents them as optional integrations without any security requirements for transmission. The Elasticsearch example uses HTTP (not HTTPS), suggesting insecure transmission is acceptable. No documentation addresses: requirement for TLS when transmitting logs externally, authentication to external log systems, ensuring audit logs (not just event logs) are transmitted, verifying log delivery (handling transmission failures), or that the default configuration stores logs locally (same system as application). Without mandatory secure transmission to a separate system, logs remain vulnerable to compromise if the Airflow deployment is breached.

**Remediation:**

Production deployments MUST transmit audit logs to a logically separate system: All log transmission MUST use TLS 1.2 or higher; Authentication to the log collection system MUST be configured; Log delivery failures MUST be detected and alerted upon; The separate log system MUST NOT be accessible from the Airflow application with write/delete permissions. Recommended configurations: Syslog over TLS to a dedicated SIEM, Direct integration with cloud-native log services (CloudWatch, Cloud Logging) using IAM roles with append-only permissions, Kafka-based log streaming with TLS and authentication.

---

#### FINDING-082: Custom executor module loading without sanitization guidance

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-94 |
| **ASVS sections** | 1.3.2 |
| **Files** | airflow-core/docs/core-concepts/executor/index.rst (31-35) |
| **Source Reports** | 1.3.2.md |
| **Related** | - |

**Description:**

The documentation explicitly describes and encourages loading arbitrary Python modules via configuration. User/admin configuration (airflow.cfg) allows specifying arbitrary Python module paths that are dynamically loaded and executed. The documentation does not describe any validation, allowlisting, or integrity checking of custom executor module paths before they are dynamically loaded. If the configuration file or the configuration source is compromisable, this becomes an arbitrary code execution vector. While this is an intentional design feature, executor configuration is an infrastructure-level concern that should have stronger controls than DAG authoring.

**Remediation:**

Document that executor module paths should be restricted to a known allowlist in production deployments, and recommend filesystem integrity monitoring on airflow.cfg. Add security guidance to the 'Writing Your Own Executor' section regarding safe deserialization and input validation requirements. Implement executor module allowlisting at the configuration level, restricting dynamic imports to pre-approved packages.

---

#### FINDING-083: Pickle deserialization support documented without safety controls

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-502 |
| **ASVS sections** | 1.5.2 |
| **Files** | airflow-core/docs/core-concepts/executor/index.rst (within Compatibility Attributes section) |
| **Source Reports** | 1.5.2.md |
| **Related** | - |

**Description:**

The documentation explicitly describes pickle deserialization support as an executor feature: 'supports_pickling: Whether or not the executor supports reading pickled Dags from the Database before execution (rather than reading the Dag definition from the file system)'. Python's pickle module is explicitly documented as insecure for untrusted data. The documentation describes this as an executor compatibility attribute without prescribing any safety controls such as: allowlists of permitted object types during deserialization, integrity verification (signatures) of pickled data before deserialization, or use of safer serialization alternatives (JSON, Protocol Buffers). If a malicious or compromised DAG author can insert a crafted pickle payload into the metadata database, any executor with supports_pickling = True would execute arbitrary code during deserialization. This is an architectural observation from documentation. The actual pickle deserialization implementation and its safeguards must be audited in the Python source. However, the documentation normalizes pickle use without documenting required safety controls, which is concerning per ASVS 1.5.2's requirement that 'Deserialization mechanisms that are explicitly defined as insecure must not be used with untrusted input.'

**Remediation:**

1. Document that pickle-based DAG loading should be disabled in production (supports_pickling = False). 2. If pickle support is retained, document required controls: database access restrictions, DAG integrity verification, and type allowlisting during deserialization. 3. Consider deprecating pickle support in favor of the serialized DAG representation already mentioned in the scheduler documentation.

---

#### FINDING-084: Missing Input Validation Rules Documentation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-1059 |
| **ASVS sections** | 2.1.1 |
| **Files** | scheduler.rst, executor/index.rst (108) |
| **Source Reports** | 2.1.1.md |
| **Related** | FINDING-164, FINDING-165 |

**Description:**

The application's documentation does not define input validation rules for how to check the validity of data items against expected structures. Documentation files (scheduler.rst and executor/index.rst) are operational deployment and architecture documentation but do not define input validation rules for data items such as: DAG configuration parameter formats (e.g., cron expressions, schedule intervals), executor module path validation patterns, or configuration value format constraints (e.g., valid ranges for numeric settings). The executor documentation notes that 'If a Dag specifies a task to use an executor that is not configured, the Dag will fail to parse' which implicitly references a validation rule but does not formally document the expected input format or validation pattern.

**Remediation:**

Create dedicated input validation documentation that formally defines validation rules for: (1) DAG definition inputs (schedule expressions, task parameters, executor references), (2) Runtime parameters passed to DAGs, (3) Configuration values (acceptable ranges, format constraints, cross-parameter consistency rules), and (4) API inputs to the scheduler and executor interfaces. Formalize the implicit validation rules referenced in these documents (executor name validation, pool limit enforcement, configuration consistency) into a security design document that satisfies ASVS 2.1.1, 2.1.2, and 2.1.3.

---

#### FINDING-085: No documented or referenced allowlist mechanism for outbound connections from triggers and task execution

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-918 |
| **ASVS sections** | 13.2.5 |
| **Files** | airflow-core/docs/authoring-and-scheduling/deferring.rst (entire file), airflow-core/docs/core-concepts/executor/index.rst (entire file), airflow-core/docs/security/workload.rst (entire file) |
| **Source Reports** | 13.2.5.md |
| **Related** | - |

**Description:**

The documentation describes an architecture where Triggers execute arbitrary async Python code within the triggerer process, capable of making unrestricted outbound network connections (e.g., polling APIs, connecting to databases), and Tasks run arbitrary Python code within worker processes with full network access. No allowlist mechanism is documented or referenced for restricting which external resources these components may contact. The security documentation (workload.rst) discusses JWT authentication, memory protection, and impersonation but contains no mention of network-level egress controls or destination allowlisting for outbound requests. Without an allowlist of permitted outbound destinations, a malicious DAG author could use triggers or tasks to probe internal network services (SSRF), the triggerer process becomes a shared SSRF vector, and internal metadata services (cloud provider IMDSv1/v2, Kubernetes API) could be accessed from task/trigger code.

**Remediation:**

The system should document and implement an outbound connection allowlist. Options include: 1) Network-level controls (recommended for production): Document that Deployment Managers must configure network policies (e.g., Kubernetes NetworkPolicy, firewall rules) to restrict egress from triggerer and worker pods/hosts. 2) Application-level allowlist: Implement a configurable allowlist in Airflow configuration with allowed_outbound_hosts, allowed_outbound_cidrs, and blocked_outbound_cidrs parameters. 3) Documentation gap: At minimum, the workload.rst security documentation should reference the need for egress controls and provide guidance for Deployment Managers. Additional recommendations include adding SSRF prevention guidance to workload.rst, documenting cloud metadata endpoint blocking (169.254.169.254), and creating backend connection configuration reference documentation.

---

#### FINDING-086: Context-Inappropriate Output Encoding for Template Variable in JavaScript Context

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-116 |
| **ASVS sections** | 1.2.1, 1.2.3, 3.2.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py (101-107) |
| **Source Reports** | 1.2.1.md, 1.2.3.md, 3.2.2.md |
| **Related** | - |

**Description:**

The `backend_server_base_url` template variable is passed to `index.html` from `request.base_url.path`. While Jinja2's auto-escaping handles HTML element/attribute contexts, if the template embeds this value within a `<script>` block (common for SPA configuration injection), HTML auto-escaping is semantically incorrect for a JavaScript context. The correct approach is JavaScript/JSON encoding via the `|tojson` filter, which escapes `</` to prevent script tag breakout, properly handles special characters for JavaScript string context, and produces valid JSON safe in both HTML and JS contexts. HTML entities inside `<script>` tags are not decoded by browsers, which could lead to: 1) JavaScript errors from literal entity strings, 2) Incomplete protection if a `|safe` filter or `{% autoescape false %}` is used in the template. Exploitability requires either a misconfigured reverse proxy passing untrusted path prefixes or `FORWARDED_ALLOW_IPS=*` combined with a non-standard header-to-root-path middleware.

**Remediation:**

In the template (index.html), use the tojson filter: `<script>window.__BASE_URL__ = {{ backend_server_base_url | tojson }};</script>`. Alternatively, pass pre-encoded JSON from the server side using `json.dumps(request.base_url.path)` and pass it as a separate context variable. Additionally, add server-side validation to ensure `request.base_url.path` matches expected path patterns (e.g., `^/[a-zA-Z0-9/_-]*$`) before passing to the template.

---

#### FINDING-087: Static Files Served with html=True Without Content-Type Enforcement

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 3.2.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py (62-69) |
| **Source Reports** | 3.2.1.md |
| **Related** | - |

**Description:**

The html=True parameter on StaticFiles enables serving index.html for directory requests and appending .html to paths. Combined with the absence of X-Content-Type-Options: nosniff, this increases the risk of content being interpreted in unintended contexts. Files in the static directory will be served with MIME types inferred from their extension, without additional security controls. If a file with ambiguous content ends up in the static directory (through build artifacts or plugin mechanisms), it could be rendered as HTML by browsers due to MIME-sniffing.

**Remediation:**

Remove html=True if not strictly needed, or ensure security headers middleware adds X-Content-Type-Options: nosniff to all responses from this mount.

---

#### FINDING-088: Missing SameSite Cookie Attribute Configuration

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L1 |
| **CWE** | - |
| **ASVS sections** | 3.3.2, 3.5.1, 3.5.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py (entire file) |
| **Source Reports** | 3.3.2.md, 3.5.1.md, 3.5.2.md |
| **Related** | - |

**Description:**

The application initialization code does not show any SameSite attribute configuration for cookies. Given that: 1. CORS is configured with `allow_credentials=True` (line 151), indicating cross-origin cookie usage 2. The application serves state-changing API endpoints (via `public_router`) 3. No CSRF middleware is visible in `init_middlewares`. The absence of explicit SameSite configuration means cookies may default to `SameSite=Lax` (modern browser default) or potentially `None` (if cross-origin usage is required). The correct SameSite value depends on cookie purpose: Session cookies: `SameSite=Lax` (prevents CSRF for top-level navigations), API authentication cookies: `SameSite=Strict` or `Lax` depending on usage pattern, Cookies needed cross-origin: `SameSite=None; Secure` (requires explicit setting). Without explicit configuration, the application relies on browser defaults which vary across implementations. Impact: Inconsistent CSRF protection depending on browser behavior. If cookies require `SameSite=None` for cross-origin CORS requests but this isn't explicitly set, authentication may break in some contexts. Conversely, if SameSite should be `Strict` or `Lax` but isn't enforced, the application may be vulnerable to cross-site request forgery.

**Remediation:**

Implement a middleware that requires a custom header on state-changing requests to force CORS preflight. Example: from starlette.middleware.base import BaseHTTPMiddleware; from starlette.requests import Request; from starlette.responses import Response; class CORSPreflightEnforcementMiddleware(BaseHTTPMiddleware): SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}; async def dispatch(self, request: Request, call_next): if request.method not in self.SAFE_METHODS: if not request.headers.get("X-Requested-With"): return Response(status_code=403, content="Missing required header"); return await call_next(request)

---

#### FINDING-089: Cookies Lack __Host- Prefix Enforcement

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS sections** | 3.3.3 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py (161-176), airflow-core/docs/howto/run-behind-proxy.rst |
| **Source Reports** | 3.3.3.md |
| **Related** | - |

**Description:**

The application initialization code (app.py) registers JWTRefreshMiddleware which is responsible for setting session/auth cookies, but there is no evidence of __Host- prefix enforcement in the application's cookie configuration. The documentation discusses cookie handling in the proxy context but never mentions the __Host- prefix requirement. The init_config function sets up app.state.secret_key for token signing but does not configure cookie naming conventions. Without the __Host- prefix, cookies are not guaranteed to have been set with Secure attribute, from the same host, and without a Path attribute other than /. This makes cookies susceptible to overwrite attacks from subdomains or insecure connections.

**Remediation:**

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

---

#### FINDING-090: CORS Wildcard Origin Allowed with Credentials Enabled

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 3.4.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py (138-152) |
| **Source Reports** | 3.4.2.md |
| **Related** | - |

**Description:**

The CORS configuration reads allowed origins from the Airflow configuration file (`api.access_control_allow_origins`) without any validation that the configured values are not wildcards when credentials are enabled. If an operator configures `access_control_allow_origins = *` (which is a valid list item), the `CORSMiddleware` with `allow_credentials=True` will reflect the requesting `Origin` header in the response (rather than returning literal `*`), effectively allowing any origin to make credentialed cross-origin requests. There is no code-level guardrail preventing this dangerous combination. If misconfigured with wildcard origins, any website can make authenticated API requests on behalf of a logged-in user, accessing DAG configurations, triggering DAG runs, and extracting connection credentials.

**Remediation:**

Add validation to reject wildcard origins when credentials are enabled:
```python
if "*" in allow_origins:
    log.warning("CORS wildcard origin '*' is configured with allow_credentials=True. This is insecure. Please specify explicit origins.")
    raise AirflowException("CORS wildcard origin '*' cannot be used with allow_credentials=True. Please configure explicit allowed origins.")
```

---

#### FINDING-091: Incomplete CSP Documentation Guidance

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | - |
| **ASVS sections** | 3.4.3, 3.1.1 |
| **Files** | airflow-core/docs/howto/run-behind-proxy.rst (50-51) |
| **Source Reports** | 3.4.3.md, 3.1.1.md |
| **Related** | - |

**Description:**

The documentation only mentions a minimal CSP header (frame-ancestors 'self'), and references HTTPS in passing through example URLs. It does NOT document: HSTS requirements (minimum max-age, includeSubDomains, preload), Full Content-Security-Policy directives (script-src, style-src, connect-src, etc.), X-Content-Type-Options requirements, Required browser minimum versions or feature support, How the application should behave when security features are unavailable (e.g., warning users, blocking access), Referrer-Policy requirements. The documentation actively advises AGAINST security controls: 'Please make sure your proxy does not enforce http-only status on the Set-Cookie headers.' Administrators deploying Airflow behind reverse proxies will not implement comprehensive browser security headers, leaving the application vulnerable to XSS, clickjacking, MIME-sniffing, and protocol downgrade attacks. The absence of fallback behavior documentation means degraded security states go undetected.

**Remediation:**

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

#### FINDING-092: Missing Referrer-Policy Header in Application Middleware

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 3.4.5 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py:162-178 |
| **Source Reports** | 3.4.5.md |
| **Related Findings** | - |

**Description:**

No Referrer-Policy header is set anywhere in the application middleware stack or route handlers. When a user clicks an external link from the Airflow UI (e.g., links in DAG documentation, rendered markdown, or plugin pages), the browser's default referrer behavior sends sensitive path information to third-party servers. Airflow URLs can contain sensitive information including DAG identifiers, task instance details, connection and variable names in admin URLs, and internal hostnames.

**Remediation:**

Implement a SecurityHeadersMiddleware that sets the Referrer-Policy header. For public applications use 'strict-origin-when-cross-origin'. For internal/non-public applications where even the hostname is sensitive, use 'same-origin'. Example implementation:
```python
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response
```

---

#### FINDING-093: Missing Cross-Origin-Opener-Policy header on HTML responses

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 3.4.8 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py:101-107 |
| **Source Reports** | 3.4.8.md |
| **Related Findings** | - |

**Description:**

The webapp() catch-all route serves HTML document responses (media_type="text/html") without setting the Cross-Origin-Opener-Policy header. No middleware in the stack adds this header. Without COOP, if a user opens a link from the Airflow UI to an attacker-controlled page (e.g., from DAG documentation), the opened page retains a reference to the opener window (window.opener). This enables tabnabbing attacks where the attacker page navigates the opener (Airflow UI tab) to a phishing page, frame counting to enumerate internal Airflow state, and cross-window scripting attacks in same-origin scenarios.

**Remediation:**

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

---

#### FINDING-094: Legacy Flask plugins mounted on same origin as main application

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 3.5.4 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py:133 |
| **Source Reports** | 3.5.4.md |
| **Related Findings** | - |

**Description:**

The legacy Flask application (including third-party plugins) is mounted on the same hostname and origin as the main Airflow FastAPI application. This violates the same-origin separation principle: Cookies set by the main app are accessible by plugin code, XSS in a plugin affects the entire application, JavaScript from plugins can interact with the main app's resources, and there is no origin-based isolation between trusted core code and potentially untrusted plugin code. A vulnerability in any legacy Flask plugin (which may be third-party and less rigorously audited) can compromise the entire Airflow application since they share the same origin.

**Remediation:**

Option 1: Host plugins on a separate subdomain (plugins.airflow.example.com instead of airflow.example.com/pluginsv2). Option 2: If same-host mounting is required, add iframe sandboxing and restrict cookie scope with path attributes. Option 3: Document in security guide that plugins should be vetted and deployed on separate hostnames for production environments.

---

#### FINDING-095: No Redirect Allowlist Mechanism Visible in Application Framework

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 3.7.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py |
| **Source Reports** | 3.7.2.md |
| **Related Findings** | - |

**Description:**

The application framework does not implement a centralized redirect allowlist mechanism. While the provided code itself doesn't perform explicit redirects to external domains, there is no framework-level control to prevent other routes (registered via `public_router` or `ui_router`) from performing unvalidated redirects. The absence of such a control means any route added to the application could redirect users to arbitrary external hostnames without validation.

**Remediation:**

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

---

#### FINDING-096: No External Redirect Notification Mechanism Implemented

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 3.7.3 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py |
| **Source Reports** | 3.7.3.md |
| **Related Findings** | - |

**Description:**

The application does not implement any mechanism to notify users when they are being redirected to URLs outside of the application's control, nor does it provide an option to cancel such navigation. This is a Level 3 requirement that requires explicit user confirmation before navigating to external domains. Users could be silently redirected to phishing sites or malicious domains without awareness or ability to cancel the navigation.

**Remediation:**

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

---

#### FINDING-097: No Browser Security Feature Detection or Fallback Behavior

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 3.7.5 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py |
| **Source Reports** | 3.7.5.md |
| **Related Findings** | - |

**Description:**

The application does not implement any mechanism to detect whether the browser supports expected security features (e.g., CSP, SameSite cookies, HSTS, modern TLS) and does not warn users or block access when security features are unavailable. The SPA catch-all route serves index.html to all browsers without any capability checking. No User-Agent analysis, feature detection, or minimum browser version requirements are enforced.

**Remediation:**

Implement browser compatibility checking: Server-side basic User-Agent check for known-insecure browsers (MSIE 6-10) with middleware that returns 403 status and unsupported browser message. Additionally, include client-side feature detection in the SPA JavaScript that warns users if required features are unavailable.

---

#### FINDING-098: No Refresh Token Replay Attack Mitigation for Public Clients

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1, L2, L3 |
| **CWE** | - |
| **ASVS Sections** | 10.4.5 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py:45-95, airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py:97-100 |
| **Source Reports** | 10.4.5.md |
| **Related Findings** | - |

**Description:**

The middleware issues new JWT tokens without invalidating the previously-issued JWT. When a browser-based (public) client's token is refreshed, the old JWT remains valid until its `exp` claim expires. There is no token rotation with invalidation logic, no DPoP binding, and no mTLS binding visible in this code. An attacker who obtains a JWT cookie can replay it even after the legitimate user has been issued a fresh token. The window of exposure equals the JWT's lifetime. For long-lived JWTs, this significantly extends the attack window.

**Remediation:**

Implement one of: (1) Refresh token rotation with family tracking (L1/L2 minimum): Maintain a server-side token family. On refresh, invalidate the old token and if a used token is presented again, revoke the entire family. (2) Sender-constrained tokens (preferred for L3): Bind tokens to client proof-of-possession. Example implementation provided includes token rotation with jti tracking, checking if token has been consumed, marking tokens as consumed, and revoking entire token family on replay detection.

---

#### FINDING-099: JWT Refresh Token Lacks Absolute Expiration Enforcement

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | - |
| **ASVS Sections** | 10.4.8 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py:75 |
| **Source Reports** | 10.4.8.md |
| **Related Findings** | - |

**Description:**

When setting the refreshed JWT cookie, max_age is set to None for valid tokens, creating a session cookie with no explicit expiration. Combined with the automatic refresh on every request, this allows sessions to persist indefinitely without any absolute expiration boundary enforced by this middleware. The JWT token itself may contain an exp claim, but the middleware's refresh mechanism generates a new JWT each time, effectively resetting the clock. There is no visible 'session started at' or 'absolute_expiry' claim being checked before issuing a new JWT. Without an absolute expiration, a compromised session (via stolen cookie) remains active as long as the attacker maintains periodic requests.

**Remediation:**

Add an absolute expiration check before allowing refresh. Implement a session_iat (session inception time) claim to JWTs that is preserved across refreshes, and enforce a maximum absolute session lifetime. Example: Check session_start against absolute_timeout before refreshing, and if exceeded, force re-authentication by setting new_token to empty string. Carry forward the original session_iat in new tokens. Configure session_absolute_timeout in configuration (e.g., 86400 seconds for 24 hours).

---

#### FINDING-100: No Documentation of Multi-IdP User Identity Namespacing

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 6.8.1 |
| **Files** | airflow-core/docs/security/kerberos.rst |
| **Source Reports** | 6.8.1.md |
| **Related Findings** | - |

**Description:**

The documentation covers Kerberos as an authentication mechanism but does not document how user identities are namespaced when multiple identity providers are supported (e.g., Kerberos alongside LDAP, OAuth, or SAML). Airflow supports pluggable authentication managers, meaning multiple IdPs may coexist. The documentation states: 'it does not integrate Kerberos into the web interface and you will have to rely on network level security for now to make sure your service remains secure.' If Airflow supports both Kerberos-authenticated users (for backend services) and another IdP (for web UI), there's no documented guidance on preventing identity collision where a user `airflow` from one IdP could be confused with user `airflow` from another IdP. This is a documentation gap observation. The actual implementation in auth managers may handle this correctly - this finding is limited in confidence due to the scope of files provided.

**Remediation:**

Documentation should clarify how user identities from Kerberos (realm-qualified principals like `user@REALM.COM`) are mapped to internal user records and how they're distinguished from users authenticated via other providers. Document multi-IdP identity mapping to clarify how Kerberos principals are mapped to internal user identities and how they're distinguished from users authenticated via other providers (OIDC, SAML, etc.). Provide a comprehensive federated identity guide covering how all supported IdPs (Kerberos, OIDC, SAML) interact, how identities are namespaced, and how assertions are validated across the system.

---

#### FINDING-101: Missing Cipher Suite Configuration in Reverse Proxy Documentation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | - |
| **ASVS Sections** | 12.1.2 |
| **Files** | airflow-core/docs/howto/run-behind-proxy.rst:34-47 |
| **Source Reports** | 12.1.2.md |
| **Related Findings** | - |

**Description:**

The official reverse proxy deployment documentation contains no ssl_ciphers directive or guidance on selecting strong cipher suites. Neither the nginx nor Helm chart configuration examples include cipher suite configuration. For L3 compliance, only cipher suites providing forward secrecy should be permitted. Users following this guide will rely on system/nginx defaults for cipher selection, which may include non-forward-secrecy ciphers (e.g., RSA key exchange) and weak ciphers (e.g., 3DES, RC4 depending on nginx version).

**Remediation:**

Add cipher suite configuration to the nginx example: ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256'; ssl_prefer_server_ciphers on; For Helm with nginx ingress: annotations: nginx.ingress.kubernetes.io/ssl-ciphers: "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:..."

---

#### FINDING-102: Missing mTLS Client Certificate Validation Guidance in Reverse Proxy Documentation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 12.1.3 |
| **Files** | airflow-core/docs/howto/run-behind-proxy.rst |
| **Source Reports** | 12.1.3.md |
| **Related Findings** | - |

**Description:**

The deployment documentation provides no guidance on configuring mutual TLS (mTLS) for client certificate authentication at the reverse proxy layer. Given the domain context states 'mTLS client certificates must be validated before use' and 'Strong client authentication is required for sensitive intra-service communications,' the absence of mTLS guidance in the reverse proxy configuration is a documentation gap. Deployments following this guide will not implement client certificate verification at the proxy level, meaning services connecting to Airflow's external-facing API will not be authenticated via mTLS. If mTLS is later added, without explicit guidance on certificate trust validation, certificates may be accepted without proper CA chain verification.

**Remediation:**

Add an mTLS section to the documentation with nginx configuration example including: ssl_client_certificate directive pointing to trusted CA certificate, ssl_verify_client set to 'on', ssl_verify_depth set appropriately (e.g., 2), and proxy headers to pass client certificate information to backend (X-Client-Cert with $ssl_client_s_dn and X-Client-Verify with $ssl_client_verify).

---

#### FINDING-103: Wildcard FORWARDED_ALLOW_IPS allows header spoofing and weakens proxy authentication

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1, L3 |
| **CWE** | - |
| **ASVS Sections** | 12.2.1, 12.3.5, 3.1.1 |
| **Files** | airflow-core/docs/howto/run-behind-proxy.rst:69-73, airflow-core/docs/howto/run-behind-proxy.rst:74-76 |
| **Source Reports** | 12.2.1.md, 12.3.5.md, 3.1.1.md |
| **Related Findings** | - |

**Description:**

The documentation provides `FORWARDED_ALLOW_IPS: "*"` as the primary example for Helm deployments. This value allows ANY source to set forwarded headers (X-Forwarded-For, X-Forwarded-Proto). An attacker could send `X-Forwarded-Proto: https` to make the application believe the connection is encrypted when it is not, potentially bypassing HTTPS enforcement checks. In a Kubernetes environment where network policies are not perfectly configured, any pod could spoof forwarded headers to impersonate traffic from a trusted proxy, potentially bypassing IP-based access controls or logging. This undermines both TLS enforcement (12.2.1) and service-to-service authentication principles (12.3.5) by allowing any network endpoint to assert proxy identity and spoof protocol information.

**Remediation:**

Change the example to use restrictive IP ranges instead of wildcard. Replace `value: "*"` with `value: "10.0.0.0/8"` (adjusted to match actual proxy CIDR range or specific proxy service IP). Add a security warning explaining the risks of wildcard trust and emphasizing that production deployments must specify exact proxy IP ranges or CIDR blocks to prevent header spoofing and maintain service-to-service authentication integrity.

---

#### FINDING-104: Missing Secure cookie flag guidance

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 12.2.1 |
| **Files** | airflow-core/docs/howto/run-behind-proxy.rst:52-53 |
| **Source Reports** | 12.2.1.md |
| **Related Findings** | - |

**Description:**

The documentation advises AGAINST setting the `HttpOnly` flag on cookies due to frontend JavaScript requirements, but does not mention the `Secure` flag requirement. Without the `Secure` flag, cookies (including session tokens) could be transmitted over plaintext HTTP connections if TLS is not properly enforced at all layers. If a user deploys based on the port 80 nginx example and follows the cookie guidance, authentication cookies will be transmitted in plaintext and accessible to JavaScript (no HttpOnly), maximizing exposure to both network interception and XSS attacks.

**Remediation:**

Add guidance that while HttpOnly may not be set on all cookies due to frontend requirements, the `Secure` flag MUST be set on all cookies to prevent transmission over HTTP. Update documentation to state: 'While HttpOnly cannot be enforced on all cookies (frontend JavaScript access required), ensure that the `Secure` flag IS set on all cookies to prevent transmission over HTTP. This requires TLS to be properly configured on the external-facing endpoint.'

---

#### FINDING-105: No guidance on authenticated internal communications between proxy and backend

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 12.3.5 |
| **Files** | airflow-core/docs/howto/run-behind-proxy.rst:36-48 |
| **Source Reports** | 12.3.5.md |
| **Related Findings** | - |

**Description:**

The documentation demonstrates proxy-to-backend communication over plaintext HTTP without any form of service authentication. While localhost communication is lower risk, the documentation also addresses non-local proxy scenarios (line 60: "If your proxy server is not on the same host...") without providing guidance for securing that communication channel. For non-colocated deployments, the proxy-to-backend channel lacks: TLS encryption (proxy_pass uses http://), Mutual TLS (mTLS) client certificate authentication, any authentication mechanism between proxy and backend service, and network isolation guidance. In deployments where the reverse proxy is on a separate host from the Airflow backend (common in cloud/Kubernetes environments), intra-service traffic traverses the network unencrypted and unauthenticated. An attacker with network access could intercept credentials or impersonate the reverse proxy to bypass authentication.

**Remediation:**

Add a section for non-colocated deployments showing mTLS between proxy and backend with proxy_ssl_certificate, proxy_ssl_certificate_key, proxy_ssl_trusted_certificate, proxy_ssl_verify on, and proxy_ssl_protocols TLSv1.2 TLSv1.3 configuration. Also document Airflow API server configuration to require client certificates for non-localhost connections.

---

#### FINDING-106: Incomplete documentation of all communication needs for the application

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | - |
| **ASVS Sections** | 13.1.1 |
| **Files** | airflow-core/docs/administration-and-deployment/scheduler.rst, airflow-core/docs/core-concepts/executor/index.rst |
| **Source Reports** | 13.1.1.md |
| **Related Findings** | - |

**Description:**

The scheduler documentation references communication with the metadata database and executors, and the executor documentation references communication with workers, databases, and external services (Kubernetes API, cloud providers, message brokers). However, neither document provides a comprehensive, consolidated list of ALL communication needs as required by ASVS 13.1.1. Missing documentation includes: No explicit enumeration of all external services (Redis/RabbitMQ for CeleryExecutor, Kubernetes API server, cloud APIs for ECS/Batch executors, Sentry, StatsD); No documentation of cases where end users (DAG authors) can provide external locations the application will connect to (e.g., Connections, HTTP operators targeting user-defined URLs, custom hooks); No network flow diagram or consolidated communication matrix; No documentation of the triggerer component's communication needs (mentioned in domain context but absent from docs). Without a comprehensive communication inventory, operators cannot properly configure firewalls, network segmentation, or security monitoring. SSRF risks from user-defined connections remain undocumented.

**Remediation:**

Create a dedicated "Communication Architecture" document that: 1. Lists all internal component-to-component communication paths (scheduler↔DB, scheduler↔executor, webserver↔DB, triggerer↔DB, worker↔DB); 2. Lists all external service dependencies per executor type; 3. Documents that DAG authors can define arbitrary external connection targets via the Connections mechanism; 4. Provides a network flow matrix with protocols, ports, and direction

---

#### FINDING-107: No documentation of maximum concurrent connection limits per service or behavior when limits are reached

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 13.1.2 |
| **Files** | airflow-core/docs/administration-and-deployment/scheduler.rst |
| **Source Reports** | 13.1.2.md |
| **Related Findings** | - |

**Description:**

While the scheduler documentation references pool limits and concurrency limits for task scheduling, it does not define the maximum number of concurrent connections to external services (database, message broker, Kubernetes API) or document what happens when those limits are reached. This acknowledges the problem but provides no: Defined maximum connection pool size, Documented behavior when the pool is exhausted, Fallback or recovery mechanisms, Connection queue behavior. The NOWAIT behavior is mentioned for row locks but there's no documentation of what happens when this fails (the fallback/recovery mechanism).

**Remediation:**

Document for each service: 1. Default and configurable maximum connection pool sizes (e.g., sql_alchemy_pool_size, sql_alchemy_max_overflow), 2. Behavior when the pool is exhausted (queue, reject, timeout), 3. Recovery mechanisms (connection recycling, health checks), 4. Recommended monitoring thresholds

---

#### FINDING-108: No documentation of executor queue depth limits or backpressure behavior

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 13.1.2 |
| **Files** | airflow-core/docs/core-concepts/executor/index.rst |
| **Source Reports** | 13.1.2.md |
| **Related Findings** | - |

**Description:**

The executor documentation describes queued/batch executors sending tasks to a central queue but does not document: Maximum queue depth, Behavior when the queue is full, Worker connection pool limits, Backpressure mechanisms. Without queue depth limits documentation, the system could experience unbounded queue growth leading to memory exhaustion or message broker instability.

**Remediation:**

For each executor type, document: Maximum concurrent workers/connections, Queue depth limits and overflow behavior, Backpressure signaling from executor to scheduler

---

#### FINDING-109: Internal Architecture Documentation May Be Exposed in Production

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | - |
| **ASVS Sections** | 13.4.5, 13.4.6, 13.4.7 |
| **Files** | airflow-core/docs/howto/set-up-database.rst |
| **Source Reports** | 13.4.5.md, 13.4.6.md, 13.4.7.md |
| **Related Findings** | - |

**Description:**

This documentation file contains detailed internal architecture information that would aid an attacker if exposed in production. Key sensitive details include: supported PostgreSQL versions (13, 14, 15, 16, 17), MySQL versions (8.0, 8.4, Innovation), SQLite version (3.15.0+), connection string formats (postgresql+psycopg2://&lt;user&gt;:&lt;password&gt;@&lt;host&gt;/&lt;db&gt;, mysql+mysqldb://&lt;user&gt;:&lt;password&gt;@&lt;host&gt;[:&lt;port&gt;]/&lt;dbname&gt;), environment variable names (AIRFLOW__DATABASE__SQL_ALCHEMY_CONN, AIRFLOW__DATABASE__SQL_ALCHEMY_SCHEMA), and internal schema structure. If the docs/ directory is served by the application or accessible in deployment, an attacker gains knowledge of supported database backends and their versions (narrows attack surface), connection string formats (aids credential brute-forcing), internal schema structure and naming conventions, environment variable names that could be targeted for injection, and specific SQLAlchemy driver versions in use.

**Remediation:**

Ensure the docs/ directory is excluded from production deployments via Dockerfile exclusion (COPY --exclude=docs/ . /opt/airflow/) or .dockerignore (airflow-core/docs/). Verify deployment artifacts exclude docs/ directory in all production container images and deployment packages. Examine Dockerfiles and .dockerignore files. Add a production hardening section to this documentation that references ASVS 13.4.x requirements: disabling debug modes, removing documentation endpoints, disabling TRACE, and suppressing version headers. Add environment-aware defaults to SQLAlchemy engine configuration that automatically disable echo in production environments. Implement automated security scanning in CI/CD that verifies production container images do not contain documentation directories, .git metadata, or debug-enabling configurations. Create a dedicated security configuration guide that addresses all deployment hardening requirements in one location, referenced from this and other setup documentation.

---

#### FINDING-110: Documentation includes development-only configurations without clear production exclusion mechanism

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 15.2.3 |
| **Files** | airflow-core/docs/howto/set-up-database.rst:29-32, airflow-core/docs/howto/set-up-database.rst:261-266 |
| **Source Reports** | 15.2.3.md |
| **Related Findings** | - |

**Description:**

While the documentation itself warns against using SQLite and echo=True in production, there is no programmatic enforcement. The presence of development-focused instructions (SQLite setup, echo=True logging, example credentials) alongside production setup guidance in a single file means this content could be included in production deployments where it is not needed and could guide operators toward insecure configurations. An operator deploying Airflow to production could: 1) Use the documented airflow_pass example credential literally, 2) Enable echo=True in production, logging all SQL queries including sensitive data, 3) Leave SQLite as the default backend without changing it.

**Remediation:**

Ensure documentation is excluded from production deployment artifacts (Docker images, pip packages for runtime). Consider splitting development-only documentation into a separate file clearly marked as non-production. Add programmatic checks that warn/prevent SQLite usage in production mode. Example: Exclude docs/ directory from production Docker images.

---

#### FINDING-111: Dangerous Functionality in Auth Managers Not Explicitly Highlighted

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 15.1.5 |
| **Files** | airflow-core/docs/core-concepts/auth-manager/index.rst |
| **Source Reports** | 15.1.5.md |
| **Related Findings** | - |

**Description:**

The auth manager architecture includes several patterns that constitute "dangerous functionality" per the ASVS definition (deserialization of untrusted data, dynamic code execution), but the documentation does not explicitly flag these as dangerous or describe the associated security controls: 1. JWT Deserialization (deserialize_user): Parses JWT token content to reconstruct user objects. Improper implementation could lead to injection or privilege escalation. 2. Dynamic Code Loading (lazy_load_command): CLI commands use lazy loading to dynamically import and execute Python modules. 3. Plugin Code Execution (get_fastapi_app): Auth managers can inject arbitrary FastAPI routes into the application server. 4. Token Cookie Handling: Auth managers set security-sensitive cookies that control authentication state. Without explicitly identifying these as dangerous operations, auth manager implementers may not apply appropriate security controls (input validation on deserialized tokens, sandboxing of loaded modules, route authentication for injected endpoints).

**Remediation:**

Add a security considerations section that explicitly identifies dangerous functionality and required security controls. The section should cover: JWT Deserialization with strict schema validation and signature verification requirements; Dynamic Code Loading with trusted module path restrictions; API Extension with authentication and authorization requirements for injected routes; Cookie Management with httponly and secure flag requirements. Include cross-references to a dangerous-functionality-policy document.

---

#### FINDING-112: Batch Authorization Methods Lack Documented Size Constraints

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 15.2.2, 15.1.3 |
| **Files** | airflow-core/docs/core-concepts/auth-manager/index.rst |
| **Source Reports** | 15.2.2.md, 15.1.3.md |
| **Related Findings** | - |

**Description:**

The documentation acknowledges that certain authorization operations are resource-intensive by providing batch optimization methods (batch_is_authorized_dag, filter_authorized_dag_ids, etc.) and warns about expensive module-level imports. However, it does not document: 1. What happens when batch authorization is called with very large lists (thousands of DAGs) 2. Timeout behavior if an external auth manager (e.g., Keycloak) becomes unresponsive 3. Rate limiting or queue-based approaches for authorization requests 4. How to prevent DoS through repeated authorization requests against expensive external identity providers. Custom auth manager implementations that make external API calls (to LDAP, OAuth providers, etc.) for each authorization check could cause: response timeouts exceeding consumer timeouts, resource exhaustion on the Airflow API server, and cascading failures when external identity providers are slow.

**Remediation:**

Add guidance on resource-demanding operations and mitigations: Add a section titled 'Performance and Availability Considerations' that documents: (1) Implement batch methods to override batch authorization methods to minimize round-trips to external services. (2) Set timeouts with explicit timeouts (e.g., 5 seconds) to prevent blocking the API server. (3) Cache results by caching authorization decisions with appropriate TTLs. (4) Handle unavailability by defining fallback behavior when external auth providers are unreachable (fail-closed recommended). (5) Limit parallel requests using connection pooling and limit concurrent requests to external identity providers.

---

#### FINDING-113: Auth Manager Plugin System Lacks Sandboxing or Encapsulation for Arbitrary Code Execution

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 15.2.5 |
| **Files** | airflow-core/docs/core-concepts/auth-manager/index.rst |
| **Source Reports** | 15.2.5.md |
| **Related Findings** | - |

**Description:**

The auth manager plugin architecture allows third-party code to: (1) Inject arbitrary FastAPI endpoints into the `/auth` path of the API server, (2) Register arbitrary CLI commands in the `airflow` namespace, (3) Register database managers that can modify database schema. All of these execute within the same process and security context as the core Airflow application. There is no documented sandboxing, network isolation, process isolation, or capability restriction for auth manager plugins. If a custom auth manager from a third-party provider is compromised or contains vulnerabilities, an attacker gains full access to the Airflow process (all DAGs, connections, variables, secrets), injected API endpoints run with the same privileges as core Airflow APIs, database managers could modify the metadata database schema, and CLI commands execute with the same filesystem/network access as Airflow.

**Remediation:**

Document and implement at minimum: (1) Encapsulation: Auth manager endpoints mounted via get_fastapi_app() should have restricted middleware that limits their access to only auth-related database tables and APIs. (2) Capability restriction: Document recommended deployment patterns where custom auth managers are deployed in isolated containers with network access limited to the identity provider. (3) Interface boundary enforcement: Restrict what auth managers can import from airflow internals through a documented public interface boundary. Example implementation: Create an AuthManagerRouter class that validates auth_manager_app only uses allowed dependencies before mounting.

---

#### FINDING-114: Scheduler documentation lacks anti-automation controls for user-triggered DAG operations

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 2.4.2 |
| **Files** | airflow-core/docs/administration-and-deployment/scheduler.rst |
| **Source Reports** | 2.4.2.md |
| **Related Findings** | - |

**Description:**

The scheduler documentation describes throughput optimization and performance tuning but does not document or reference any controls to enforce realistic human timing on user-initiated operations (e.g., manual DAG triggers, task state modifications, or API-driven DAG run submissions). Configuration parameters like `max_dagruns_to_create_per_loop` and `scheduler_idle_sleep_time` control internal scheduler behavior, not user-facing submission rates. The document explicitly states the scheduler is designed for "high throughput" and scheduling "tasks as soon as possible," but provides no guidance on preventing excessively rapid user-initiated transaction submissions through the API or UI. Without documented human timing validation, automated tools could rapidly submit DAG runs or task operations, potentially causing resource exhaustion or abusing business logic that assumes human-speed interaction.

**Remediation:**

Document minimum time intervals between user-initiated DAG triggers, include references to rate limiting middleware configuration, and describe how `max_active_runs_per_dag` and pool slot limits interact with anti-automation controls.

---

#### FINDING-115: Scheduler documentation does not reference authentication protection controls

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 6.1.1 |
| **Files** | airflow-core/docs/administration-and-deployment/scheduler.rst |
| **Source Reports** | 6.1.1.md |
| **Related Findings** | - |

**Description:**

This operational documentation file describes scheduler performance and configuration but makes no reference to how rate limiting, anti-automation, or adaptive response controls protect authentication endpoints from credential stuffing or brute force attacks. While this specific document focuses on scheduler operations, the scheduler interacts with authentication (e.g., the Internal Execution API uses JWT tokens), and the documentation does not cross-reference relevant security documentation. The document also does not explain how scheduler-level controls (pool limits, concurrency caps) prevent malicious account lockout scenarios when integrated with authentication systems. Operators deploying based on this documentation may not be aware of authentication protection requirements or where to find relevant security configuration guidance.

**Remediation:**

Add a "Security Considerations" section or cross-reference to security documentation that describes: How rate limiting protects the webserver/API authentication endpoints; How adaptive lockout policies prevent brute force without enabling account lockout DoS; Configuration references for authentication-related rate limiting

---

#### FINDING-116: No graceful degradation for template filesystem dependency in catch-all route

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | - |
| **ASVS Sections** | 16.5.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py:89 |
| **Source Reports** | 16.5.2.md |
| **Related Findings** | - |

**Description:**

The `webapp` function serves as the catch-all route for the single-page application and depends on the filesystem being accessible. While `Path(directory).mkdir(exist_ok=True)` ensures the directory exists at startup, runtime filesystem failures (e.g., NFS mount loss, disk full, permission changes) would result in unhandled exceptions. There is no circuit breaker, cached response, or graceful degradation path. User request flows to `webapp()` then filesystem access to `index.html` template; if filesystem is unavailable (mounted volume gone, permissions changed, NFS failure), unhandled exception propagates. If the static filesystem becomes unavailable, ALL non-API requests will result in 500 errors. The application has no mechanism to serve a degraded response (e.g., cached HTML, maintenance page).

**Remediation:**

Add try-catch block around template response to handle OSError and IOError exceptions. Return a 503 Service Unavailable response with a simple HTML maintenance page when filesystem is unavailable, including Retry-After header. Log the error server-side for operational visibility. Example: wrap templates.TemplateResponse in try block, catch (OSError, IOError), log error, and return HTMLResponse with status 503 and appropriate content indicating UI is temporarily unavailable but API endpoints may still be operational.

---

#### FINDING-117: Last-resort error handler coverage cannot be verified; potential gap in unhandled exception logging

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 16.5.4 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py:143 |
| **Source Reports** | 16.5.4.md |
| **Related Findings** | - |

**Description:**

The `init_error_handlers` function iterates over `ERROR_HANDLERS` and registers them. However, from this file alone, it is impossible to verify that: 1. A handler for the base `Exception` class exists (last-resort catch-all) 2. The catch-all handler properly logs the full exception with traceback to server-side logs 3. The catch-all handler returns a generic response to the client 4. `RuntimeError`, `SystemError`, or other unexpected exception types are covered. FastAPI's built-in server error handler returns `{"detail": "Internal Server Error"}` for uncaught exceptions, but it relies on the ASGI server (e.g., Uvicorn) for logging. This means: Exception details may not reach Airflow's logging system, the error format may not match Airflow's expected error response schema, and process-level crashes (e.g., from C extensions) would not be caught. Without a verified last-resort handler: Unhandled exceptions may not be logged to Airflow's log files, losing debugging information; responses for unexpected errors may have inconsistent format; in extreme cases, an unhandled exception in an ASGI middleware could terminate the worker process.

**Remediation:**

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

---

#### FINDING-118: Missing Comprehensive Key Management Policy Aligned with NIST SP 800-57

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | - |
| **ASVS Sections** | 11.1.1, 13.3.4 |
| **Files** | airflow-core/docs/security/secrets/fernet.rst |
| **Source Reports** | 11.1.1.md, 13.3.4.md |
| **Related Findings** | - |

**Description:**

The Fernet documentation provides operational guidance for key generation and rotation but does not constitute or reference a comprehensive key management policy aligned with NIST SP 800-57. The following key lifecycle phases are absent from documentation: Key destruction/revocation (no procedure for securely destroying old keys after rotation is complete), Key storage security requirements (no guidance on protecting the key at rest such as file permissions, secrets managers, HSMs), Key access control (no documentation on restricting which entities/services can access the Fernet key), Key sharing restrictions (no explicit statement limiting key sharing - the Fernet key is inherently shared across all Airflow components which may exceed the two entities for shared secrets guideline), Key expiration/rotation schedule (no defined rotation frequency or maximum key lifetime), and Cryptographic periods (no documentation of appropriate crypto-periods per NIST SP 800-57).

**Remediation:**

Add documented key rotation policy specifying that Fernet keys should be rotated at a minimum of every 90 days, or immediately upon suspected compromise. Configure automated rotation using secrets management system with cron jobs or scheduled tasks. Document connection and variable secrets rotation using external backend native rotation capabilities (HashiCorp Vault dynamic secrets with TTL-based expiration, AWS Secrets Manager automatic rotation with Lambda functions, GCP Secret Manager secret versions with scheduled rotation). Configure alerting when: Fernet key age exceeds the configured rotation period, connection credentials approach their expiration date, and rotation operations fail.

---

#### FINDING-119: Incomplete Cryptographic Inventory Documentation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | - |
| **ASVS Sections** | 11.1.2 |
| **Files** | airflow-core/docs/security/secrets/fernet.rst |
| **Source Reports** | 11.1.2.md |
| **Related Findings** | - |

**Description:**

The provided documentation covers only Fernet encryption for connection passwords and variables. Based on the domain context, Airflow uses multiple cryptographic mechanisms that are not inventoried in this document: JWT signing (for Execution API authentication) - algorithm and key not inventoried here; TLS/HTTPS certificates (for web server and API endpoints) - not documented; Password hashing (for user authentication) - algorithm not documented; Session tokens (for web UI sessions) - cryptographic basis not documented; OAuth/OIDC tokens (when using external auth providers) - not inventoried. The document also does not specify: Where the Fernet key cannot be used (only states connection passwords and variables); Classification of data types protected by Fernet; What data types require different cryptographic protection. Without a comprehensive cryptographic inventory, the organization cannot effectively respond to algorithm deprecation, key compromise, or regulatory changes affecting specific cryptographic primitives.

**Remediation:**

Create a centralized cryptographic inventory document (e.g., docs/security/cryptographic-inventory.rst) that catalogs all cryptographic assets including: Fernet Key (AES-128-CBC + HMAC-SHA256, 256-bit split key, for connection passwords and variables, NOT for session tokens or user auth); JWT Signing Key (HS256/RS256, 256-bit/2048-bit, for internal API authentication, NOT for data encryption); TLS Certificate (RSA/ECDSA, ≥2048/≥256-bit, for transport security, NOT for data at rest). The inventory should document algorithm, key size, usage scope, and explicit restrictions for each cryptographic asset.

---

#### FINDING-120: No Cryptographic Discovery Mechanisms Implemented or Documented

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 11.1.3 |
| **Files** | - |
| **Source Reports** | 11.1.3.md |
| **Related Findings** | - |

**Description:**

No cryptographic discovery mechanisms are documented or referenced in the provided source material. There is no evidence of: Automated scanning tools to detect cryptographic usage in the codebase, Runtime detection of encryption, hashing, or signing operations, SBOM (Software Bill of Materials) integration documenting cryptographic dependencies, Static analysis rules targeting cryptographic API usage, Dependency scanning for cryptographic libraries. Without discovery mechanisms, new cryptographic usage introduced through code changes, dependency updates, or plugin installations may go undetected and unmanaged, potentially introducing weak or deprecated algorithms.

**Remediation:**

Implement cryptographic discovery through: 1. Static analysis: Configure SAST tools (e.g., Semgrep, CodeQL) with rules to detect imports from `cryptography`, `hashlib`, `hmac`, `jwt`, `ssl` modules. 2. Dependency scanning: Monitor `requirements.txt`/`pyproject.toml` for cryptographic library additions. 3. Runtime instrumentation: Log cryptographic operations with algorithm metadata for audit. 4. CI/CD integration: Add pipeline stages that flag new cryptographic usage for security review.

---

#### FINDING-121: No Post-Quantum Cryptography (PQC) Migration Plan Documented

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 11.1.4 |
| **Files** | airflow-core/docs/security/secrets/fernet.rst |
| **Source Reports** | 11.1.4.md |
| **Related Findings** | - |

**Description:**

No post-quantum cryptography (PQC) migration plan or future-proofing strategy is documented. The Fernet documentation describes only current symmetric encryption without addressing: Quantum computing threats to the cryptographic primitives in use; Migration timeline or triggers for transitioning to PQC algorithms; Crypto-agility assessment (ability to swap algorithms without code changes); Impact assessment of quantum threats on stored encrypted data (harvest-now-decrypt-later attacks). While Fernet's symmetric AES-128 encryption is less immediately threatened by quantum computing (Grover's algorithm reduces effective security to 64 bits, which is below the 128-bit minimum), the HMAC-SHA256 authentication and any asymmetric cryptography used elsewhere in Airflow (JWT/RSA, TLS) are at higher risk. Without a migration plan, the organization cannot proactively respond to quantum computing advances, potentially requiring emergency migrations under time pressure.

**Remediation:**

Document a PQC migration plan including: Post-Quantum Cryptography Migration Plan with Current State Assessment (Symmetric encryption Fernet/AES-128: Low immediate risk, but consider AES-256 for quantum resilience; JWT signing HS256: Low immediate risk for symmetric variant; TLS certificates RSA/ECDSA: High risk - plan hybrid certificates); Migration Triggers (NIST PQC standard finalization for relevant use cases; Industry consensus on quantum computing timeline reaching cryptographic relevance); Migration Path (Phase 1: Increase symmetric key sizes to 256-bit where possible; Phase 2: Adopt hybrid TLS with PQC key exchange e.g. ML-KEM + X25519; Phase 3: Transition JWT signing to PQC-safe algorithms when standardized); Crypto-Agility Requirements (Encryption module must support algorithm substitution via configuration; Key rotation procedures must support algorithm migration not just key refresh).

#### FINDING-122: CORSMiddleware Does Not Protect WebSocket Connections

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Section(s)** | 4.4.2 |
| **Affected File(s)** | airflow-core/src/airflow/api_fastapi/core_api/app.py:135-149 |
| **Source Report(s)** | 4.4.2.md |
| **Related Finding(s)** | None |

**Description:**

FastAPI/Starlette's CORSMiddleware only handles HTTP CORS preflight requests (OPTIONS method with Access-Control-* headers). It does not validate the Origin header during WebSocket upgrade requests (Connection: Upgrade). If WebSocket endpoints are added to public_router or ui_router, they would not benefit from origin validation despite the CORS configuration being present — creating a Type B gap (control exists but not applied to WebSocket). A malicious website could initiate cross-site WebSocket hijacking attacks because the Origin header would not be validated during the WebSocket handshake.

**Remediation:**

If WebSocket endpoints are introduced, add explicit Origin validation middleware for WebSocket connections using a custom WebSocketOriginMiddleware that checks the origin header against the allowed_origins list during WebSocket upgrade requests. The middleware should reject connections from origins not in the allowlist before the WebSocket handshake completes.

---

#### FINDING-123: Documented deadlock risk with MariaDB due to missing SKIP LOCKED/NOWAIT support

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Section(s)** | 15.4.3 |
| **Affected File(s)** | airflow-core/docs/administration-and-deployment/scheduler.rst:106-110 |
| **Source Report(s)** | 15.4.3.md |
| **Related Finding(s)** | None |

**Description:**

The documentation explicitly acknowledges that deadlock errors occur without NOWAIT/SKIP LOCKED support. While this is documented as a known limitation, the system does not appear to enforce database version requirements at startup — meaning a deployment on unsupported MariaDB versions could silently operate in a deadlock-prone configuration. If deployed on unsupported database versions, multiple schedulers could experience deadlocks, causing task scheduling to stall and potentially leading to denial of service in the scheduling pipeline.

**Remediation:**

The scheduler startup should validate that the database supports required locking features when use_row_level_locking is enabled and multiple schedulers are expected. Add a startup check that verifies database supports SKIP LOCKED/NOWAIT features, raising AirflowConfigException for MariaDB versions < 10.6.0 when attempting to run multiple schedulers.

---

#### FINDING-124: mask_secret() API Lacks Documented Regex Metacharacter Escaping and ReDoS Protection

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | CWE-1333 |
| **ASVS Section(s)** | 1.2.9, 1.3.12 |
| **Affected File(s)** | airflow-core/docs/security/secrets/mask-sensitive-values.rst:87-96 |
| **Source Report(s)** | 1.2.9.md, 1.3.12.md |
| **Related Finding(s)** | None |

**Description:**

The documentation describes a `mask_secret()` API that accepts arbitrary string values from DAG authors for pattern matching against all log output. The documentation does not specify whether regex metacharacters in secret values (e.g., `p@ss.w*rd+1`) are escaped, creating two related risks: (1) Unescaped metacharacters could cause over-masking or under-masking of log content, and (2) Without escaping, crafted secret values could cause exponential backtracking (ReDoS), leading to task hangs or worker resource exhaustion. No timeout, complexity limitation, or pattern validation is documented. While the system is designed for literal value matching (not user-defined regex patterns), the absence of documented safety guarantees leaves the implementation's behavior unclear and potentially vulnerable.

**Remediation:**

1. The implementation at `airflow.sdk.log.mask_secret()` must apply `re.escape()` to all user-supplied values before regex compilation to treat special characters as literals: `escaped_pattern = re.escape(str(value))`. 2. Enforce a timeout on regex matching operations using the regex module with timeout support or by limiting pattern count (MAX_PATTERNS = 100) and length (MAX_PATTERN_LENGTH = 1024). 3. Update documentation to explicitly state: 'Values passed to `mask_secret()` are automatically escaped for use in pattern matching. Special characters such as `.`, `*`, `+`, `(`, `)` etc. are treated as literal characters, not as regex metacharacters. Pattern matching includes safety limits to prevent performance degradation.'

---

#### FINDING-125: Authorization Decisions Do Not Incorporate Token-Level Claims (scope, authorization_details)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Section(s)** | 10.3.2 |
| **Affected File(s)** | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:150-165 |
| **Source Report(s)** | 10.3.2.md |
| **Related Finding(s)** | None |

**Description:**

The `get_user_from_token()` method validates the JWT and deserializes it into a user object, but subsequent authorization decisions (via `is_authorized_*` methods) are based solely on user identity, not on token-specific claims such as `scope` or `authorization_details`. The JWT payload contains potential `scope` and `authorization_details` claims, but these are not propagated to authorization decisions. The `is_authorized_*` methods accept `method` and `user` parameters but no `token_claims` or `scope` parameter. If a token were issued with limited scope (e.g., `scope=read:dags`), the authorization framework would still grant full user permissions because scope is not propagated to authorization decisions. This is a Type B gap: the JWT validation control EXISTS and extracts claims, but scope/authorization_details claims are NOT USED in authorization decisions. In a delegated authorization scenario (e.g., third-party application accessing API on behalf of a user with limited consent), the current architecture cannot enforce scope-limited access. Any valid token grants full user permissions regardless of intended scope restrictions.

**Remediation:**

Add scope/claims awareness to authorization methods. Modify `get_user_from_token()` to return both user and token claims: `async def get_user_from_token(self, token: str) -> tuple[BaseUser, dict[str, Any]]:` returning `user, {"scope": payload.get("scope"), "authorization_details": payload.get("authorization_details")}`. Update authorization methods to accept token claims: `def is_authorized_connection(self, *, method, user, details=None, token_claims=None) -> bool:` to check both user permissions and scope authorization.

---

#### FINDING-126: No Issuer (`iss`) Claim Validation in Token Validator

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Section(s)** | 10.3.3 |
| **Affected File(s)** | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:835-843 |
| **Source Report(s)** | 10.3.3.md |
| **Related Finding(s)** | None |

**Description:**

The `JWTValidator` is configured with `audience` but no `issuer` parameter. The token validation does not verify the `iss` claim, meaning tokens from different issuers (that share the same signing key or use a compromised key) could be accepted. If the signing key is shared or compromised across services, tokens issued for different purposes could be accepted by this resource server. User identification via `sub` alone (without `iss`) may not be globally unique if multiple token issuers exist in the infrastructure. In a federated deployment scenario, different Airflow instances sharing secrets could have `sub` collisions.

**Remediation:**

Add issuer validation to the JWTValidator configuration:
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

---

#### FINDING-127: Missing Authentication Strength, Method, and Recentness Verification

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Section(s)** | 10.3.4 |
| **Affected File(s)** | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:140-155 |
| **Source Report(s)** | 10.3.4.md |
| **Related Finding(s)** | None |

**Description:**

The `get_user_from_token` method validates the token's signature, expiration, and revocation status, but does not check the `acr` (Authentication Context Class Reference) claim to verify the authentication strength level, the `amr` (Authentication Methods References) claim to verify which authentication methods were used, or the `auth_time` claim to verify when the user last authenticated. There is no abstract method in the base class requiring subclasses to implement these checks, and no configuration mechanism to define required authentication strength per resource/endpoint. Resources requiring elevated authentication (e.g., admin operations, sensitive data access) cannot enforce that the user authenticated with an appropriate strength level. An attacker who compromises a weak authentication factor gains the same access as one with full MFA.

**Remediation:**

Modify the `get_user_from_token` method to accept optional parameters for required authentication constraints (`required_acr`, `required_amr`, `max_auth_age`). Implement verification logic that checks the `acr` claim against required authentication strength levels, validates that the `amr` claim includes all required authentication methods, and verifies that the `auth_time` claim is within acceptable age limits. Raise `InvalidTokenError` if any constraint is not satisfied. Provide a method `_acr_satisfies_requirement` to compare authentication context class references according to organizational policy.

---

#### FINDING-128: Missing Redirect URI Validation in BaseAuthManager

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 10.4.1 |
| **Affected File(s)** | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:169 |
| **Source Report(s)** | 10.4.1.md |
| **Related Finding(s)** | None |

**Description:**

The BaseAuthManager abstract base class does not include any abstract method, hook, or utility for redirect URI validation. There is no: 1. Abstract method requiring implementations to validate redirect URIs, 2. Utility method for exact string comparison of redirect URIs against allowlists, 3. Client registration model with pre-registered redirect URIs, 4. get_url_login(**kwargs) parameter validation for redirect targets. The get_url_login(self, **kwargs) method accepts arbitrary kwargs which could include redirect parameters, but no validation contract is defined. If a concrete auth manager implementation acts as an OAuth authorization server (or integrates with one), the base class provides no guidance or enforcement for redirect URI validation. Implementations could omit this critical check, enabling open redirect attacks in OAuth flows.

**Remediation:**

Add a utility method and documentation for redirect validation: @staticmethod def validate_redirect_uri(redirect_uri: str, allowed_uris: list[str]) -> bool: """Validate redirect URI against allowlist using exact string comparison.""" return redirect_uri in allowed_uris

---

#### FINDING-129: JWT Access Tokens Lack Sender-Constraining Mechanisms (Authorization Server Perspective)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3, L2 |
| **CWE** | N/A |
| **ASVS Section(s)** | 10.4.14, 10.7.3 |
| **Affected File(s)** | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:743, airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:161 |
| **Source Report(s)** | 10.4.14.md, 10.7.3.md |
| **Related Finding(s)** | None |

**Description:**

The base auth manager generates JWT access tokens without any sender-constraining mechanism. There is no infrastructure for certificate-bound access tokens (no `cnf` claim with `x5t#S256` thumbprint per RFC 8705) or DPoP-bound tokens (no `jkt` claim or DPoP proof validation per RFC 9449). The `JWTGenerator` is instantiated with only signing args, validity period, and audience — no proof-of-possession binding parameters are supported. If this auth manager is used in an OAuth AS capacity, tokens are bearer tokens vulnerable to token theft and replay. An attacker who intercepts a token can use it from any client/network location.

**Remediation:**

Add support for certificate-bound tokens (mTLS) and DPoP-bound tokens. Modify the `generate_jwt` method to accept optional `client_cert_thumbprint` (x5t#S256 from mTLS) or `dpop_jkt` (JWK thumbprint from DPoP proof) parameters and include them in the `cnf` claim of the generated JWT. Example implementation:
```python
def generate_jwt(
    self, user: T, *,
    expiration_time_in_seconds: int = conf.getint("api_auth", "jwt_expiration_time"),
    client_cert_thumbprint: str | None = None,
    dpop_jkt: str | None = None,
) -> str:
    extra_claims = {}
    if client_cert_thumbprint:
        extra_claims["cnf"] = {"x5t#S256": client_cert_thumbprint}
    elif dpop_jkt:
        extra_claims["cnf"] = {"jkt": dpop_jkt}
    
    return self._get_token_signer(expiration_time_in_seconds=expiration_time_in_seconds).generate(
        {**self.serialize_user(user), **extra_claims}
    )
```

---

#### FINDING-130: Missing Nonce Validation for ID Token Replay Prevention

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | N/A |
| **ASVS Section(s)** | 10.5.1, 10.5.3 |
| **Affected File(s)** | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:140 |
| **Source Report(s)** | 10.5.1.md, 10.5.3.md |
| **Related Finding(s)** | None |

**Description:**

The `JWTValidator` is configured with signature validation arguments and audience, but there is no explicit `issuer` parameter passed. When this auth manager validates tokens from external identity providers (OIDC IdPs), the absence of issuer validation means: 1. A token signed with a valid key but issued by a different (malicious) authorization server with the same key material would be accepted 2. If multiple IdPs are configured and share signing key infrastructure, tokens from one could be accepted as from another. The `audience` validation provides some protection (as different services typically use different audiences), but it's not equivalent to issuer validation. In a multi-IdP deployment, a compromised or malicious authorization server could forge tokens that would be accepted by the Airflow instance, potentially gaining unauthorized access.

**Remediation:**

Add issuer validation to the JWTValidator configuration by passing an issuer parameter from configuration. Update the _get_token_validator method to include: `issuer=conf.get("api_auth", "jwt_issuer", fallback=None)`. Additionally, in the get_user_from_token method, validate that the issuer claim in the payload matches the expected configuration: `expected_issuer = conf.get("api_auth", "jwt_issuer", fallback=None)` and `if expected_issuer and payload.get("iss") != expected_issuer: raise InvalidTokenError(f"Token issuer '{payload.get('iss')}' does not match expected '{expected_issuer}'")`

---

#### FINDING-131: No Abstract Contract for OIDC ID Token Audience Validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | N/A |
| **ASVS Section(s)** | 10.5.4, 10.5.2 |
| **Affected File(s)** | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:entire class scope |
| **Source Report(s)** | 10.5.4.md, 10.5.2.md |
| **Related Finding(s)** | None |

**Description:**

The `deserialize_user` method is abstract with no enforcement of using the `sub` claim (or any stable, non-reassignable identifier) for unique user identification. The docstring provides no guidance to implementers about: which claims must be used for unique identification, that the identifier must not be reassignable (e.g., email addresses can be reassigned), or that `sub` should be combined with `iss` for cross-IdP uniqueness. The `is_authorized_hitl_task` method demonstrates a pattern where `user.get_id()` is used for identity comparison, but there's no guarantee this maps to the `sub` claim. If `get_id()` returns an email or username rather than a stable subject identifier, account takeover could occur when identifiers are reassigned.

**Remediation:**

The known false positive pattern acknowledges that 'Auth manager system allowing custom implementations without certification is intentional' — so this is noted as a gap in the base class contract rather than a critical vulnerability. Concrete OIDC implementations should be audited independently. Document OIDC requirements for implementers and consider defining optional abstract methods or mixin classes for OIDC-specific functionality (e.g., OIDCClientMixin with validate_id_token(), handle_backchannel_logout()) to guide implementers toward secure patterns.

---

#### FINDING-132: No Back-Channel Logout Interface or Validation Contract

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | N/A |
| **ASVS Section(s)** | 10.5.5 |
| **Affected File(s)** | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:172 |
| **Source Report(s)** | 10.5.5.md |
| **Related Finding(s)** | None |

**Description:**

No OIDC back-channel logout implementation exists in this file. The base class defines `get_url_logout()` (line ~172) which returns a URL for user redirection on logout, but this is a front-channel concern and does not handle incoming logout tokens from an Identity Provider. The base class provides no abstract method or interface for: Receiving OIDC back-channel logout tokens, Validating the `typ` header is `logout+jwt`, Verifying the `event` claim contains the correct member name, Ensuring no `nonce` claim is present, Enforcing short expiration on logout tokens. If a concrete auth manager implements OIDC and the IdP supports back-channel logout, there's no base class guidance or enforcement for secure logout token validation, potentially leading to denial-of-service through forced logout or cross-JWT confusion.

**Remediation:**

Add an optional interface for back-channel logout handling: `def handle_backchannel_logout(self, logout_token: str) -> bool:` that implements verification of: typ header is 'logout+jwt', 'event' claim contains 'http://schemas.openid.net/event/backchannel-logout', No 'nonce' claim is present, Token expiration is short (recommended: 2 minutes).

---

#### FINDING-133: Middleware-based user injection bypasses JWT validation without framework-level guardrails

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | N/A |
| **ASVS Section(s)** | 6.3.4 |
| **Affected File(s)** | airflow-core/src/airflow/api_fastapi/core_api/security.py:119-135, airflow-core/src/airflow/api_fastapi/core_api/app.py:197 |
| **Source Report(s)** | 6.3.4.md |
| **Related Finding(s)** | None |

**Description:**

The `get_user()` function, which is the core authentication dependency for ALL Core API endpoints, accepts a pre-built user object from `request.state.user` without ANY validation. While this is used legitimately by `SimpleAllAdminMiddleware`, the `init_plugins()` function in `app.py` (line 197) allows arbitrary plugins to register root-level middleware that could set `request.state.user`. This creates an undocumented authentication pathway where any FastAPI plugin middleware can inject a user object, bypassing JWT signature validation, expiry checks, and token revocation checks.

**Remediation:**

Add validation that middleware-injected users have a verifiable trust indicator: verify the user was set by a trusted middleware using a trust token, and if not present, fall through to standard JWT validation.

---

#### FINDING-134: Inconsistent authentication strength between unauthenticated token generation endpoints and standard JWT-protected endpoints

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | N/A |
| **ASVS Section(s)** | 6.3.4 |
| **Affected File(s)** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py:74-92 |
| **Source Report(s)** | 6.3.4.md |
| **Related Finding(s)** | None |

**Description:**

When `simple_auth_manager_all_admins=True`, two endpoints (`GET /auth/token` and `GET /auth/token/login`) issue ADMIN-level JWT tokens with ZERO authentication. The only guard is a boolean config check. There is no runtime enforcement preventing this configuration in production - no environment detection, no warning banner, no audit log entry. While the SimpleAuthManager is documented as 'for development/testing,' the code itself has no mechanism to prevent production deployment with `simple_auth_manager_all_admins=True`.

**Remediation:**

Add a runtime safety check or at minimum, audit logging. Add explicit warning when issuing admin token without authentication. Implement environment detection to prevent this configuration in production.

---

#### FINDING-135: Log serving authentication pathway lacks `jti` and `sub` claims, preventing token revocation and audit trailing

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | N/A |
| **ASVS Section(s)** | 6.3.4 |
| **Affected File(s)** | airflow-core/tests/unit/utils/test_serve_logs.py:173-189, airflow-core/tests/unit/api_fastapi/auth/test_tokens.py |
| **Source Report(s)** | 6.3.4.md |
| **Related Finding(s)** | None |

**Description:**

The log serving JWT tokens only require `aud`, `iat`, `nbf`, `exp`, and `filename` claims. They lack the `jti` (JWT ID) claim that the main API requires for token revocation via the `RevokedToken` mechanism, and lack the `sub` claim for audit identity. If a log serving token is compromised (e.g., intercepted from a network capture within its validity window), it cannot be individually revoked through the `RevokedToken` system. The attacker can repeatedly access the log file until the token expires.

**Remediation:**

Include `jti` and `sub` claims in log serving tokens to enable revocation and audit. Update the log token generator to include these claims and ensure the log serving endpoint checks RevokedToken.

---

#### FINDING-136: Undocumented Authentication Token Endpoint Referenced but Not Specified in API

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | N/A |
| **ASVS Section(s)** | 6.3.4 |
| **Affected File(s)** | airflow-core/src/airflow/api_fastapi/core_api/openapi/v2-rest-api-generated.yaml |
| **Source Report(s)** | 6.3.4.md |
| **Related Finding(s)** | None |

**Description:**

The `OAuth2PasswordBearer` security scheme references a `tokenUrl: /auth/token` endpoint that is not documented in the `paths` section of the OpenAPI specification. The only documented authentication-adjacent endpoints are `/api/v2/auth/login` and `/api/v2/auth/logout`. The `/auth/token` endpoint represents an authentication pathway that exists in the system but is not formally specified alongside the other public API endpoints. Without formal documentation, security reviewers cannot verify what authentication factors are required, whether rate limiting or brute force protections are applied, whether the token endpoint enforces the same security policies as other pathways, and what credential types are accepted.

**Remediation:**

Document the `/auth/token` endpoint in the API specification with complete request/response schemas, security considerations, and applicable rate limiting.

---

#### FINDING-137: BaseAuthManager framework provides no interface or enforcement mechanism for identity proofing during authentication factor recovery

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | N/A |
| **ASVS Section(s)** | 6.4.4 |
| **Affected File(s)** | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:entire class definition |
| **Source Report(s)** | 6.4.4.md |
| **Related Finding(s)** | None |

**Description:**

The BaseAuthManager abstract class defines the contract that ALL auth manager implementations must follow. It includes abstract methods for authentication (get_url_login, deserialize_user, serialize_user) and authorization (is_authorized_* methods), but provides NO interface whatsoever for: 1) Multi-factor authentication enrollment, 2) Authentication factor recovery/replacement, 3) Identity proofing during factor recovery, 4) Factor lifecycle management (expiration, rotation). The auth manager documentation (index.rst) makes no mention of MFA requirements or factor recovery expectations for auth manager implementors. As revealed by EmptyAuthManager implementing all required abstract methods in tests, there are no MFA-related abstract methods that must be implemented.

**Remediation:**

Add MFA capability declaration to BaseAuthManager with methods like supports_mfa() -> bool and get_mfa_enforcement_level(). Document that L2-compliant deployments MUST use an auth manager that returns True from supports_mfa(). Implement a CLI command (airflow auth-manager validate) that checks the configured auth manager against ASVS L2 requirements and reports compliance gaps. Add runtime configuration validation that logs a WARNING or raises an error if Simple Auth Manager is configured in production.

---

#### FINDING-138: No MFA Factor Recovery or Identity Re-proofing Mechanism Documented in API

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | N/A |
| **ASVS Section(s)** | 6.4.4 |
| **Affected File(s)** | airflow-core/src/airflow/api_fastapi/core_api/openapi/v2-rest-api-generated.yaml:Entire API specification (absence of relevant endpoints) |
| **Source Report(s)** | 6.4.4.md |
| **Related Finding(s)** | None |

**Description:**

The API specification contains no endpoints for: managing authentication factors (enrolling/removing MFA devices), recovering lost authentication factors, performing identity re-proofing when a factor is lost, or password reset with identity verification. The only authentication-related endpoints are /api/v2/auth/login and /api/v2/auth/logout, which handle session initiation and termination but not factor lifecycle management. For an ASVS Level 2 application that requires MFA, the absence of documented recovery procedures means there is no verifiable mechanism to ensure that identity proofing at factor replacement matches the enrollment level.

**Remediation:**

Implement or document MFA recovery endpoints that enforce identity proofing equivalent to enrollment. Add endpoints such as /api/v2/auth/factors (GET to list enrolled factors) and /api/v2/auth/factors/recovery (POST to initiate factor recovery with identity proofing). For L2 applications, this requires administrator approval or equivalent out-of-band identity verification.

---

#### FINDING-139: No identity re-proofing mechanism visible for token revocation or session invalidation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | N/A |
| **ASVS Section(s)** | 6.4.4 |
| **Affected File(s)** | airflow-core/tests/unit/api_fastapi/auth/test_tokens.py:230-261 |
| **Source Report(s)** | 6.4.4.md |
| **Related Finding(s)** | None |

**Description:**

The token revocation mechanism does not require re-authentication or identity proofing before invalidating a token. The data flow is: User requests token revocation → JWTValidator.revoke_token() → persists jti in RevokedToken table → no identity verification step visible before revocation. If this mechanism is used as part of MFA factor loss (e.g., revoking tokens when a user reports a compromised authenticator), there is no evidence that identity is re-verified at the same level as during enrollment. An attacker who has a valid session could revoke tokens or trigger factor resets without proving their identity.

**Remediation:**

The base auth manager interface should define a recovery flow that requires identity proofing. Implement identity verification before allowing token revocation or factor reset operations. The pluggable auth manager architecture means that identity proofing for factor recovery may be delegated to external identity providers (e.g., enterprise SSO/OAuth), but the Airflow framework itself should enforce or validate that the auth manager performs identity proofing during recovery flows.

### 3.4 Low

#### FINDING-140: Auto-generated symmetric key lacks rotation mechanism

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-320 |
| ASVS sections | 11.2.2 |
| Files | airflow-core/src/airflow/api_fastapi/auth/tokens.py:564-582 |
| Source Reports | 11.2.2.md |
| Related | - |

**Description:**

The auto-generated key is per-process and ephemeral. While it prevents crashes, it provides no mechanism for key rotation — the key is fixed for the lifetime of the process and cannot be updated without restart. For symmetric keys in production, there's no multi-key support (unlike JWKS which can hold multiple keys with different `kid` values). In symmetric mode, key rotation requires service restart and immediate invalidation of all existing tokens. There's no graceful transition period where both old and new keys are accepted. This makes migration to post-quantum algorithms or response to key compromise more disruptive.

**Remediation:**

Consider supporting multiple symmetric keys with kid-based selection: Support key rotation by accepting multiple secret keys with active key for signing and all keys for validation. Implement a JWTValidator class with secret_keys dict mapping kid to secret, and an async _get_validation_key method that extracts kid from token header and returns the corresponding secret key.

---

#### FINDING-141: Token identifier (jti) uses UUID4 which the ASVS explicitly identifies as not meeting 128-bit entropy requirement

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS sections | 11.5.1 |
| Files | airflow-core/src/airflow/api_fastapi/auth/tokens.py:320 |
| Source Reports | 11.5.1.md |
| Related | - |

**Description:**

The ASVS requirement explicitly states "Note that UUIDs do not respect this condition." UUID version 4 provides 122 random bits (6 bits are fixed for version and variant markers), sourced from CSPRNG (os.urandom in CPython). While practically very close to 128 bits, the specification does not technically meet the stated requirement. The jti is primarily used for uniqueness (token revocation tracking) rather than as a cryptographic secret. With 122 bits of randomness from CSPRNG, collision probability and guessability remain negligible. However, the implementation doesn't technically satisfy the ASVS requirement.

**Remediation:**

Replace uuid.uuid4() with os.urandom(16) for full 128-bit entropy:

```python
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
```

---

#### FINDING-142: No minimum key size validation for loaded asymmetric keys

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-326 |
| ASVS sections | 11.6.1 |
| Files | airflow-core/src/airflow/api_fastapi/auth/tokens.py:301, airflow-core/src/airflow/api_fastapi/auth/tokens.py:311 |
| Source Reports | 11.6.1.md |
| Related | FINDING-032, FINDING-143 |

**Description:**

When loading RSA keys from the configured file path, there is no validation that: RSA keys meet minimum 2048-bit size requirements, the public exponent is appropriate (e.g., not 3 which has known vulnerabilities), or the key isn't vulnerable to known factorization attacks. A deployment using a legacy 1024-bit RSA key (or even smaller) would function without any warning or error. Deployments could inadvertently use weak RSA keys (≤1024 bits are factorable with current resources), there is no defense-in-depth against misconfiguration, and tokens could be compromised if weak key is factored.

**Remediation:**

Add validation in `_pem_to_key()` to check RSA key size is at least 2048 bits and public exponent is at least 65537. Raise ValueError with clear message if key does not meet minimum requirements.

---

#### FINDING-143: `generate_private_key()` utility exported without minimum key size enforcement

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-326 |
| ASVS sections | 11.6.1 |
| Files | airflow-core/src/airflow/api_fastapi/auth/tokens.py:400 |
| Source Reports | 11.6.1.md |
| Related | FINDING-032, FINDING-142 |

**Description:**

The function is included in `__all__` (exported as public API) and accepts arbitrary `key_size` parameter without enforcing minimums. A caller could invoke `generate_private_key('RSA', key_size=512)` generating a trivially factorable key. While documented as 'for testing,' its presence in `__all__` makes it available for production use by other modules or plugins. The function's default (2048 bits) is appropriate, and the docstring indicates testing use. However, exporting it without minimum enforcement creates a hazard for downstream callers.

**Remediation:**

Add validation: `if key_type == 'RSA' and key_size < 2048: raise ValueError(f'RSA key_size must be at least 2048 bits, got {key_size}')`

---

#### FINDING-144: No validation that dynamically-provided audience values cannot impersonate other services

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-346 |
| ASVS sections | 9.2.4 |
| Files | airflow-core/src/airflow/api_fastapi/auth/tokens.py |
| Source Reports | 9.2.4.md |
| Related | FINDING-034 |

**Description:**

The `JWTGenerator` accepts the `audience` parameter without validating it against a registry of known audiences. While the current implementation uses static configuration values, the ASVS requirement states that if the audience identifier is dynamically provisioned, the token issuer must validate these audiences in order to make sure that they do not result in audience impersonation. If future code paths pass dynamically-derived audience values to `JWTGenerator`, there is no allowlist validation to prevent issuing tokens for audiences that could impersonate other services. Current risk is low since audiences are sourced from static configuration.

**Remediation:**

Add audience validation when audience is set dynamically (not from static config). Define a registry of valid audiences: `VALID_AUDIENCES = frozenset({"urn:airflow.apache.org:task", "urn:airflow.apache.org:api"})`. In the `generate()` method, validate: `if audience_override and audience_override not in VALID_AUDIENCES: raise ValueError(f"Audience '{audience_override}' is not in the allowed audience registry")`. Consider implementing a dedicated audience registry that validates audience values against known services before token generation.

---

#### FINDING-145: Cannot Verify Password Field Masking — Frontend Template Not in Audit Scope

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1, L2, L3 |
| CWE | CWE-549 |
| ASVS sections | 6.2.6 |
| Files | airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:285-320 |
| Source Reports | 6.2.6.md |
| Related | - |

**Description:**

The login UI is served via Jinja2 templates from a directory, but the actual HTML template (index.html) is not included in the audit scope. The template is served from ui/dev/ or ui/dist/ directories depending on DEV_MODE environment variable. Without access to the index.html file, it is impossible to verify whether password input fields use type="password" for masking. If the login form uses type="text" instead of type="password", passwords would be visible on screen during entry, enabling shoulder-surfing attacks.

**Remediation:**

Verify that the frontend template contains: &lt;input type="password" name="password" id="password" autocomplete="current-password" /&gt; And optionally provides a show/hide toggle that temporarily switches to type="text".

---

#### FINDING-146: Auto-Generated Passwords Limited to 16 Characters with No User-Facing Mechanism to Set Longer Passwords

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2, L3 |
| CWE | CWE-521 |
| ASVS sections | 6.2.9 |
| Files | airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:312 |
| Source Reports | 6.2.9.md |
| Related | FINDING-010, FINDING-035, FINDING-036, FINDING-037 |

**Description:**

While the system does not explicitly reject 64-character passwords (the string comparison at services/login.py line 60 has no length limitation), there is no user-facing mechanism to set a custom password of any length. Users cannot register or change their passwords through the application. Passwords are exclusively system-generated at 16 characters. This means the requirement is technically met at the storage/verification layer but not at the user interaction layer. If an administrator manually edits the password file to contain a 64-character password, the system will accept it during login. However, users have no self-service path to set such passwords.

**Remediation:**

If password change functionality is added in the future, ensure no max_length constraint below 64 is applied. Example: class LoginBody(BaseModel): username: str; password: str = Field(..., max_length=128). Add a password change endpoint that demonstrates secure password change flows. Document minimum password length policy and ensure user-chosen passwords support at least 64 characters.

---

#### FINDING-147: No Documentation of Minimum Authentication Strength Requirements for Production Auth Managers

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS sections | 6.1.3 |
| Files | airflow-core/docs/core-concepts/auth-manager/index.rst:Lines referencing 'Writing your own auth manager' |
| Source Reports | 6.1.3.md |
| Related | - |

**Description:**

While the documentation acknowledges that Simple Auth Manager is for development and lists available auth managers, it does not document minimum authentication strength requirements that production auth managers must meet. The abstract interface in base_auth_manager.py enforces structural contracts (abstract methods) but has no documentation of security strength requirements. Custom auth manager implementers have no guidance on minimum security requirements (e.g., password complexity, MFA support, brute-force protection) that should be consistently enforced regardless of the auth pathway.

**Remediation:**

Add a 'Security Requirements for Auth Manager Implementations' section documenting minimum authentication strength expectations including password complexity, MFA support, brute-force protection, and credential storage requirements for production auth manager implementations.

---

#### FINDING-148: Default Filter Implementations May Expose Resource Existence via Timing

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 8.2.2 |
| Files | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:519-543 |
| Source Reports | 8.2.2.md |
| Related | - |

**Description:**

The default `filter_authorized_*` implementations iterate through all resources and check authorization individually. This serial check pattern can reveal timing information about resource count, though this is primarily a performance concern. The actual security posture (checking each resource individually) is correct.

**Remediation:**

Already addressed in documentation - implementations should override for performance.

---

#### FINDING-149: ConfigurationDetails and AssetDetails Lack Team-Scoping

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2, L3 |
| CWE | - |
| ASVS sections | 8.4.1 |
| Files | airflow-core/src/airflow/api_fastapi/auth/managers/models/resource_details.py:30-37 |
| Source Reports | 8.4.1.md |
| Related | - |

**Description:**

The ConfigurationDetails and AssetDetails dataclasses do not include a team_name field, while other resource types (Connections, DAGs, Pools, Variables) do. This inconsistency means configuration sections and assets cannot be team-scoped, potentially creating shared attack surfaces between teams. Teams share configuration and asset namespaces without isolation, meaning one team's configuration changes could affect another team's operations.

**Remediation:**

Evaluate whether ConfigurationDetails and AssetDetails should include team_name for multi-team deployments, or document why these resources are intentionally global.

---

#### FINDING-150: JSONResponse without explicit charset specification

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 4.1.1 |
| Files | airflow-core/src/airflow/api_fastapi/core_api/app.py:73-92 |
| Source Reports | 4.1.1.md |
| Related | - |

**Description:**

The endpoints use JSONResponse without explicit charset. However, per RFC 8259, JSON text MUST be encoded as UTF-8 and the charset parameter has no meaning for application/json. Starlette's JSONResponse correctly sets Content-Type: application/json without charset, which is compliant with RFC 8259 Section 8.1. This is not a true vulnerability but worth documenting for completeness.

**Remediation:**

No action needed for JSON responses. For the HTML template response, Starlette already appends ; charset=utf-8 to text/html responses automatically.

---

#### FINDING-151: StaticFiles mount does not explicitly reject unsupported HTTP methods with 405

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS sections | 4.1.4 |
| Files | airflow-core/src/airflow/api_fastapi/core_api/app.py:30-95 |
| Source Reports | 4.1.4.md |
| Related | - |

**Description:**

The `StaticFiles` mount in Starlette responds to GET and HEAD requests by default, which is appropriate. However, the mounted path `/static` will accept any HTTP method without returning 405 — Starlette's `StaticFiles` will return 404 for non-existent resources regardless of method but may not explicitly reject unsupported methods with a 405 response. However, FastAPI's router-based endpoints (defined with `@app.get(...)`) correctly return 405 Method Not Allowed for unsupported methods. This is a minor observation rather than a significant vulnerability.

**Remediation:**

For Level 3 compliance, consider adding a method-filtering middleware:

```python
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}

class AllowedMethodsMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if request.method not in ALLOWED_METHODS:
            return Response(status_code=405, headers={"Allow": ", ".join(ALLOWED_METHODS)})
        return await call_next(request)
```

---

#### FINDING-152: Protocol Translation Boundary in WSGIMiddleware Creates Request Smuggling Risk

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS sections | 4.2.1 |
| Files | airflow-core/src/airflow/api_fastapi/core_api/app.py:98-125 |
| Source Reports | 4.2.1.md |
| Related | - |

**Description:**

The `WSGIMiddleware` bridge converts ASGI (HTTP/1.1, HTTP/2) requests into WSGI format for legacy Flask plugins. This protocol conversion point introduces potential request smuggling risk because: 1) Protocol translation involves re-interpreting HTTP message boundaries. If the ASGI server and Flask/Werkzeug disagree on Content-Length vs. Transfer-Encoding handling, smuggling could occur. 2) Dual-stack parsing: The ASGI server (Uvicorn) parses the HTTP message first, then WSGIMiddleware reconstructs it for Flask/Werkzeug to re-parse. Discrepancies in how each layer handles malformed headers could enable smuggling. 3) No explicit Content-Length/Transfer-Encoding validation: The middleware stack doesn't include any validation that prevents conflicting Content-Length and Transfer-Encoding headers from reaching the Flask layer. However, this is mitigated by: Uvicorn uses `httptools` or `h11` for HTTP parsing, both of which reject conflicting CL/TE headers; The path is only `/pluginsv2` (limited scope); This is only active when legacy Airflow 2 plugins are present.

**Remediation:**

Add middleware to reject requests with both Content-Length and Transfer-Encoding:

```python
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

class AntiSmugglingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        has_cl = "content-length" in request.headers
        has_te = "transfer-encoding" in request.headers
        if has_cl and has_te:
            return Response(status_code=400, content="Ambiguous message framing")
        return await call_next(request)
```

Long-term: Plan migration path to eliminate the Flask plugin bridge (`WSGIMiddleware`), removing the protocol translation boundary that creates request smuggling risk.

---

#### FINDING-153: InProcess Execution API Bypasses JWT Authentication Entirely

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS sections | 13.2.1 |
| Files | airflow-core/docs/security/jwt_token_authentication.rst:Dag File Processor and Triggerer section |
| Source Reports | 13.2.1.md |
| Related | - |

**Description:**

The DAG File Processor and Triggerer components do NOT use authenticated communication for their Execution API interactions when using in-process mode. The JWT bearer dependency is overridden to always return a synthetic TIToken with the 'execution' scope, effectively bypassing token validation. Per-resource access controls (connection, variable, and XCom access checks) are also overridden to always allow. This means malicious DAG code could exploit the bypassed authentication. However, this is explicitly documented and necessary for the in-process design, and is limited to in-process communication with no network exposure.

**Remediation:**

This is an in-process communication limitation that is documented as a known security boundary issue. Mitigation should be addressed through deployment-level isolation as recommended in the documentation. The in-process API provides full unauthenticated access to connections, variables, and XComs, so ensure proper deployment isolation when malicious DAG code may be present.

---

#### FINDING-154: InProcess API Grants Unrestricted Access Without Per-Resource Authorization

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS sections | 13.2.2 |
| Files | airflow-core/docs/security/jwt_token_authentication.rst:Dag File Processor and Triggerer section |
| Source Reports | 13.2.2.md |
| Related | - |

**Description:**

The InProcess Execution API overrides access controls to 'always allow,' meaning DAG code running in the DFP/Triggerer can access any connection, variable, or XCom regardless of ownership or team boundaries. This violates least-privilege for these components. Mitigating factors include: in-process communication only (no network exposure), multi-team isolation requires deployment-level separation (documented), and this is explicitly acknowledged as a known limitation.

**Remediation:**

Implement per-resource access controls for DFP/Triggerer components, or provide deployment-level isolation guidance for multi-team environments to enforce resource boundaries at the infrastructure level.

---

#### FINDING-155: Database Connection Credentials in Documentation Examples Without Security Warning

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS sections | 13.3.1 |
| Files | airflow-core/docs/howto/set-up-database.rst:130-134, airflow-core/docs/howto/set-up-database.rst:194-196 |
| Source Reports | 13.3.1.md |
| Related | - |

**Description:**

While these are clearly documentation examples (not source code), the use of weak example passwords (airflow_pass) without an accompanying security note about using strong, randomly generated passwords from a secrets manager could lead to operators copying patterns directly. Similar examples appear for MySQL. Operators may copy them directly for non-production environments that later get promoted.

**Remediation:**

Add a security note after the SQL examples warning that the credentials above are for illustration only. In production, generate strong random passwords and store them in your secrets management solution. Never use predictable passwords like 'airflow_pass'.

---

#### FINDING-156: No Documented Least Privilege Controls for Secrets Access

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS sections | 13.3.2 |
| Files | airflow-core/docs/security/secrets/secrets-backend/index.rst |
| Source Reports | 13.3.2.md |
| Related | - |

**Description:**

The secrets backend documentation describes a search path mechanism (secrets backend → environment variables → metastore) but does not document or enforce least-privilege access controls. Specifically: 1. No guidance on restricting which Airflow components can access which secrets 2. No role-based filtering of secrets access (all components with backend access can read all secrets) 3. The common.py database session creation does not incorporate any secrets-specific access controls 4. No documentation on configuring backend-level ACLs (e.g., Vault policies limiting access to specific paths). Any Airflow component that can access the secrets backend can potentially read any secret stored there. Without least-privilege documentation, operators may grant overly broad access.

**Remediation:**

Add documentation section on configuring least-privilege access:

```
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
```

---

#### FINDING-157: Secrets Backend Documentation Lacks TTL/Expiration Guidance

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS sections | 14.2.7 |
| Files | airflow-core/docs/security/secrets/secrets-backend/index.rst |
| Source Reports | 14.2.7.md |
| Related | - |

**Description:**

The secrets backend documentation covers configuration and lookup order but does not address: secret expiration or time-to-live (TTL) policies, automatic rotation schedules, or classification of secrets by sensitivity level for differential retention. Organizations implementing secrets backends without TTL guidance may store secrets indefinitely, including credentials for decommissioned services or former employees' API tokens.

**Remediation:**

Add a section on secret lifecycle management covering TTL/expiration policies for different secrets backends. Include guidance for AWS Secrets Manager rotation schedules with rotation_rules, HashiCorp Vault TTL configuration and dynamic secrets, and GCP Secret Manager expiration dates with IAM conditions. Ensure unused secrets are removed when associated connections are decommissioned.

---

#### FINDING-158: XCom Side-Channel Not Classified in Sensitive Data Inventory

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS sections | 14.1.1 |
| Files | airflow-core/docs/security/secrets/mask-sensitive-values.rst:33-34 |
| Source Reports | 14.1.1.md |
| Related | - |

**Description:**

XCom values are acknowledged as a potential carrier of sensitive data, but XCom is not included in the data classification scheme. The documentation identifies this as a limitation but does not classify XCom-passed secrets as sensitive data requiring protection controls. The automatic masking is triggered by Connection or Variable access. This means that if you pass a sensitive value via XCom or any other side-channel it will not be masked when printed in the downstream task. Sensitive data transmitted via XCom bypasses all masking controls. Without classifying this channel in the data inventory, there's no requirement to address it.

**Remediation:**

Document XCom as a sensitive data channel and either extend masking to XCom values containing sensitive keywords, or document the risk acceptance with compensating controls (e.g., restrict log access).

---

#### FINDING-159: Masking Disable Option Lacks Risk Documentation

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS sections | 14.1.2 |
| Files | airflow-core/docs/security/secrets/mask-sensitive-values.rst:31 |
| Source Reports | 14.1.2.md |
| Related | - |

**Description:**

The documentation mentions that masking can be entirely disabled via configuration (config:core__hide_sensitive_var_conn_fields set to false), but provides no warning about the security implications or documented compensating controls that should be in place when masking is disabled. Administrators may disable masking for debugging purposes and forget to re-enable it, resulting in sensitive data exposure in logs without any protective controls.

**Remediation:**

Add a security warning admonition and document compensating controls: 'WARNING: Disabling masking exposes all sensitive values in logs and UI. If disabled: (1) Ensure log access is restricted to authorized personnel only, (2) Enable audit logging for log access, (3) Re-enable masking immediately after debugging, (4) Consider using mask_secret() for critical values even when global masking is disabled.'

---

#### FINDING-160: No Documentation of Cache Protection for Sensitive Data

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS sections | 14.2.2 |
| Files | airflow-core/docs/security/secrets/mask-sensitive-values.rst:entire document |
| Source Reports | 14.2.2.md |
| Related | - |

**Description:**

The masking documentation describes protection of sensitive data in logs and UI displays but does not address caching mechanisms. Given that the masking system processes sensitive values in memory: (1) No mention of whether masked or unmasked values are subject to application-level caching, (2) No documentation of cache-control headers for UI endpoints displaying masked values, (3) No guidance on purging sensitive data from server-side caches after rendering. This is a documentation gap — the protection requirements for sensitive data should include cache handling.

**Remediation:**

Add a section to the documentation addressing cache behavior:

```
Cache Behavior
""""""""""""""

Masked values are not cached in their unmasked form by the Airflow web server.
Connection and Variable values are fetched fresh for each rendering request.
Ensure your deployment's reverse proxy does not cache pages containing masked values.
```

---

#### FINDING-161: Log retention policy lacks specific enforceable durations

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS sections | 16.1.1 |
| Files | airflow-core/docs/security/audit_logs.rst:Audit Logs vs Event Logs table |
| Source Reports | 16.1.1.md |
| Related | - |

**Description:**

The document states retention as vague ranges rather than specific, enforceable policies. The retention requirements are described as 'Long-term (months to years for compliance), if not purged from database' for audit logs and 'Short to medium-term (days to weeks)' for event logs. Without specific retention periods, organizations cannot verify compliance with regulatory requirements or implement automated log lifecycle management.

**Remediation:**

Document specific default retention periods and configuration mechanisms. Add a 'Log Retention Configuration' section that specifies audit log retention is controlled by the [core] audit_log_retention_days configuration parameter with a default of 365 days. Document that event log retention defaults to 30 days and is controlled by [logging] event_log_retention_days. Explain that logs older than these thresholds are eligible for archival or deletion via the 'airflow db clean' command.

---

#### FINDING-162: CLI event metadata lacks documented structure for execution context

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS sections | 16.2.1 |
| Files | airflow-core/docs/security/audit_logs.rst:CLI Events section end |
| Source Reports | 16.2.1.md |
| Related | - |

**Description:**

The document mentions CLI command entries include execution context but doesn't provide the actual field mapping. The claim that "environment variables" are logged raises both a security concern (potentially logging secrets in environment) and a metadata completeness question (how is this stored in the schema?). Unclear whether CLI metadata is actually stored in the documented schema fields or if this is aspirational documentation. The claim about logging environment variables could expose secrets.

**Remediation:**

Clarify which schema fields map to CLI metadata and add warnings about sensitive data. Add documentation warning that CLI audit log entries store command details in the extra JSON field, environment variables are NOT logged to prevent secret exposure, and only the command line arguments (with sensitive values masked) are recorded.

---

#### FINDING-163: Event log format not documented for machine readability

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS sections | 16.2.4 |
| Files | airflow-core/docs/security/audit_logs.rst:Understanding Event Logs section |
| Source Reports | 16.2.4.md |
| Related | - |

**Description:**

While audit logs have a defined schema, event logs (scheduler, webserver, task logs) have no documented format specification. The document only shows access methods (tail, cat, REST API) without specifying what parsers should expect. Log processors cannot be reliably configured to parse Airflow event logs without reverse-engineering the format from actual output.

**Remediation:**

Document the event log format with example output and parsing guidance. Specify the Python logging format string used and provide examples of actual log output that parsers should expect.

---

#### FINDING-164: Configuration Security Context Not Documented

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-1059 |
| ASVS sections | 2.1.1 |
| Files | executor/index.rst, scheduler.rst |
| Source Reports | 2.1.1.md |
| Related | FINDING-084, FINDING-165 |

**Description:**

The documentation describes several configuration parameters that, if manipulated, could affect system behavior (executor module paths accepting arbitrary Python classes, custom executor code execution). The documentation does not address validation of these configuration inputs from a security perspective. Configuration parameters with security implications if misconfigured (e.g., use_row_level_locking, custom executor module paths) lack security context documentation.

**Remediation:**

Add security context to configuration parameter documentation, noting which parameters have security implications if misconfigured (e.g., use_row_level_locking, custom executor module paths). Consider documenting threat model for the scheduler/executor subsystem, particularly around DAG author trust boundaries and the implications of custom executor code execution.

---

#### FINDING-165: Security Boundaries Not Explicitly Documented

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-1059 |
| ASVS sections | 2.1.1 |
| Files | scheduler.rst |
| Source Reports | 2.1.1.md |
| Related | FINDING-084, FINDING-164 |

**Description:**

The scheduler documentation describes the critical section where task instances transition from scheduled to enqueued state, protected by database row-level locks. This is a trust-relevant architectural decision that is well-documented from an operational perspective but not explicitly framed as a security boundary. The documentation implicitly references several validation mechanisms (executor name validation, pool limit enforcement, configuration parsing) without formally specifying them as security controls, creating a gap between operational documentation and security documentation.

**Remediation:**

Document security boundaries explicitly in the scheduler architecture documentation, distinguishing between performance limits and security-enforced limits. Document the trust boundaries and security implications of the critical sections in the scheduler workflow.

---

#### FINDING-166: Missing URL Validation for backend_server_base_url Template Context

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 1.2.2 |
| Files | airflow-core/src/airflow/api_fastapi/core_api/app.py:101-107 |
| Source Reports | 1.2.2.md |
| Related | - |

**Description:**

The `backend_server_base_url` is passed to the SPA's `index.html` template from `request.base_url.path`. If the client-side JavaScript uses this value to construct API endpoint URLs (e.g., `fetch(baseUrl + "/api/v2/dags")`), there is no server-side validation that the value: 1. Does not contain protocol handlers (e.g., `javascript:`, `data:`), 2. Is properly URL-encoded for safe URL construction, 3. Is constrained to expected path formats. However, `request.base_url.path` in Starlette is constructed from the ASGI scope's `root_path`, which is typically a simple path string (e.g., `/`, `/airflow/`). The URL class in Starlette returns a parsed path component, making protocol injection via this specific vector unlikely. Impact: Low — requires proxy misconfiguration and non-standard behavior to exploit.

**Remediation:**

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

---

#### FINDING-167: Missing X-Content-Type-Options header in proxy configuration documentation

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS sections | 3.4.4 |
| Files | airflow-core/docs/howto/run-behind-proxy.rst |
| Source Reports | 3.4.4.md |
| Related | - |

**Description:**

The proxy configuration documentation provides an example CSP header but does not mention the X-Content-Type-Options: nosniff header. Operators following this guide would not configure this header at the proxy level either, leaving a defense-in-depth gap.

**Remediation:**

Add X-Content-Type-Options: nosniff to the documented proxy configuration:

```
add_header X-Content-Type-Options "nosniff" always;
```

---

#### FINDING-168: Missing Referrer-Policy Guidance in Reverse Proxy Documentation

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS sections | 3.4.5 |
| Files | airflow-core/docs/howto/run-behind-proxy.rst |
| Source Reports | 3.4.5.md |
| Related | - |

**Description:**

The reverse proxy documentation does not include guidance on setting a Referrer-Policy header, leaving operators without guidance on this control.

**Remediation:**

Add to documented proxy configuration:

```
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

---

#### FINDING-169: CSP frame-ancestors documented as optional proxy configuration rather than required application-level control

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS sections | 3.4.6 |
| Files | airflow-core/docs/howto/run-behind-proxy.rst:47-49 |
| Source Reports | 3.4.6.md |
| Related | - |

**Description:**

The documentation correctly suggests frame-ancestors 'self' but presents it only as optional proxy configuration guidance rather than a required application-level default. If operators don't configure a reverse proxy or don't follow this specific documentation, the protection is absent. The requirement states this header must be present for every HTTP response.

**Remediation:**

Implement frame-ancestors 'self' as a default at the application level (defense-in-depth), and document the proxy configuration as supplementary rather than the primary security control.

---

#### FINDING-170: Documentation Recommends Disabling HttpOnly Without CSRF Compensating Controls

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1, L2 |
| CWE | CWE-1004 |
| ASVS Sections | 3.5.1, 3.3.4 |
| Files | airflow-core/docs/howto/run-behind-proxy.rst:58-59 |
| Source Reports | 3.5.1.md, 3.3.4.md |
| Related | None |

**Description:**

The official documentation explicitly instructs operators to NOT enforce HttpOnly on cookies, stating the frontend needs JavaScript access to cookies. This directly contradicts ASVS 3.3.4 which requires HttpOnly for cookies whose values (such as session tokens) should not be accessible to client-side scripts. If session tokens or refresh tokens are stored in cookies without HttpOnly, an XSS vulnerability would allow direct theft of authentication credentials. Data flow: Server sets session/refresh token cookie → Cookie sent without HttpOnly → JavaScript can access cookie value → XSS attack can exfiltrate session token. Session tokens or JWT refresh tokens stored in cookies are directly accessible via JavaScript. Any XSS vulnerability becomes a full account takeover vector, as the attacker can steal the authentication token rather than just performing actions within the XSS context.

**Remediation:**

Separate cookie concerns: (1) Use HttpOnly cookies for session/refresh tokens (server-side only). (2) If the frontend needs state information, use a separate non-sensitive cookie or deliver that info via API response body. Example: Set session token with httponly=True, secure=True, samesite='Lax'. For UI preferences, use a separate cookie with httponly=False but containing only non-sensitive data.

---

#### FINDING-171: Documentation recommends path-based rather than hostname-based separation

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | None |
| ASVS Sections | 3.5.4 |
| Files | airflow-core/docs/howto/run-behind-proxy.rst:28-33 |
| Source Reports | 3.5.4.md |
| Related | None |

**Description:**

The documentation guides users toward path-based deployment (/myorg/airflow/) on a shared hostname. If multiple applications are hosted on the same hostname at different paths, they share the same origin for JavaScript and cookie purposes. The documentation does not mention the security implications or recommend hostname-based separation. Deployers following this guide may co-host Airflow with other applications on the same hostname, weakening origin-based browser security boundaries.

**Remediation:**

Update documentation to recommend hostname-based separation as a security best practice for production deployments, especially when co-hosting with other applications. Include security implications of path-based deployment on shared hostnames.

---

#### FINDING-172: Static file serving without explicit authorization check or Cross-Origin-Resource-Policy header

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | None |
| ASVS Sections | 3.5.7, 3.5.8 |
| Files | airflow-core/src/airflow/api_fastapi/core_api/app.py:62-69 |
| Source Reports | 3.5.7.md, 3.5.8.md |
| Related | None |

**Description:**

Static files are served directly from the filesystem without: 1. Any authentication/authorization middleware (StaticFiles bypasses route-level middleware in some configurations) 2. A `Cross-Origin-Resource-Policy` response header 3. Verification that sensitive data is not included in build artifacts. If build processes ever embed configuration, API keys, or user-specific data into JavaScript bundles (e.g., via environment variable injection at build time), these would be accessible as script resources without authorization. In the default configuration, the static directory contains pre-built frontend assets that typically don't contain per-user authorization data. However, the `html=True` flag enables directory browsing fallback, and custom deployments could inadvertently expose sensitive files.

**Remediation:**

Implement SecFetchMiddleware to validate Sec-Fetch-* headers and set Cross-Origin-Resource-Policy header. For API endpoints, reject cross-origin non-navigate fetches by checking Sec-Fetch-Site and Sec-Fetch-Mode headers. Set Cross-Origin-Resource-Policy: same-origin header on all responses. Example implementation: Create SecFetchMiddleware class that validates sec_fetch_site in ("cross-site", "same-site") and sec_fetch_mode not in ("cors", "navigate") for /api/ paths, returning 403 if conditions are met. Add response.headers["Cross-Origin-Resource-Policy"] = "same-origin" to all responses. Add middleware via app.add_middleware(SecFetchMiddleware).

---

#### FINDING-173: Documentation Uses HTTP in Base URL Examples

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | None |
| ASVS Sections | 3.7.4 |
| Files | airflow-core/docs/howto/run-behind-proxy.rst:33 |
| Source Reports | 3.7.4.md |
| Related | None |

**Description:**

The documentation example for `base_url` uses `http://` which may lead operators to configure the application without TLS enforcement. Operators following documentation examples may not configure TLS, leaving the application vulnerable to eavesdropping.

**Remediation:**

Update documentation examples to use `https://` and add a note about mandatory TLS in production.

---

#### FINDING-174: No Explicit Token Revocation Check in JWT Refresh Middleware

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2, L3 |
| CWE | None |
| ASVS Sections | 10.4.9 |
| Files | airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py |
| Source Reports | 10.4.9.md |
| Related | None |

**Description:**

The middleware uses stateless JWTs without any server-side revocation check. There is no call to a token revocation store, blocklist, or validity check before accepting and refreshing a JWT. If a user revokes their session through a UI, the JWT remains valid until its exp claim expires unless additional infrastructure (not visible here) performs revocation checks. The requirement specifically asks for a user-facing UI for revocation. This middleware is the enforcement point, and it should verify revocation status.

**Remediation:**

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

---

#### FINDING-175: Kerberos Credential Cache Stored in World-Accessible /tmp Directory

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | None |
| ASVS Sections | 6.7.1 |
| Files | airflow-core/docs/security/kerberos.rst:70-77 |
| Source Reports | 6.7.1.md |
| Related | None |

**Description:**

The documentation reveals that the default credential cache (ccache) location is `/tmp/airflow_krb5_ccache`, which is a world-accessible directory on most Unix systems. While this is a documentation file, it documents the actual default configuration behavior. Other local users on the same system could potentially read or modify the Kerberos credential cache, leading to ticket theft or tampering. While the keytab is documented with `chmod 600`, no equivalent file permission guidance is provided for the ccache file.

**Remediation:**

Documentation should recommend a non-world-accessible directory and explicit file permissions: `[kerberos] ccache = /run/airflow/krb5_ccache` (or a user-private directory) with guidance to set restrictive permissions on the parent directory.

---

#### FINDING-176: No Documentation of Authentication Strength Enforcement for Kerberos-Authenticated Operations

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | None |
| ASVS Sections | 6.8.4 |
| Files | airflow-core/docs/security/kerberos.rst |
| Source Reports | 6.8.4.md |
| Related | None |

**Description:**

The documentation does not describe how the application verifies authentication strength, methods, or recentness when Kerberos is used as an identity provider. Specifically: 1. No guidance on verifying whether a Kerberos ticket was obtained via password, hardware token, or PKINIT; 2. No documentation of auth_time equivalent validation (ticket issue time vs. current time); 3. No step-up authentication mechanism documented for sensitive operations. Without verifying authentication strength, the system cannot enforce that high-privilege operations (e.g., modifying DAGs, accessing sensitive connections) require stronger authentication than lower-privilege operations. Note: This is a documentation/architecture observation. Kerberos tickets don't inherently carry authentication method information in a way that's easily consumed by applications, making this a broader architectural challenge.

**Remediation:**

Document a fallback approach as required by ASVS: if authentication strength cannot be determined from Kerberos, document the assumed minimum authentication level and any compensating controls (e.g., requiring re-authentication for sensitive operations).

---

#### FINDING-177: Missing OCSP Stapling Configuration in Deployment Documentation

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | None |
| ASVS Sections | 12.1.4 |
| Files | airflow-core/docs/howto/run-behind-proxy.rst:entire file |
| Source Reports | 12.1.4.md |
| Related | None |

**Description:**

The deployment documentation provides no guidance on enabling OCSP stapling in the reverse proxy configuration. This is a Level 3 requirement, but given that the documentation is the primary deployment reference and the domain context states "Certificate revocation checking via OCSP stapling should be implemented," the absence is notable. Deployments following this guide will not have certificate revocation checking enabled, meaning compromised or revoked certificates could still be trusted by clients connecting to the service.

**Remediation:**

Add OCSP stapling configuration to the nginx example:
ssl_stapling on;
ssl_stapling_verify on;
ssl_trusted_certificate /etc/nginx/ssl/chain.pem;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;

---

#### FINDING-178: No guidance on enabling Encrypted Client Hello (ECH) in deployment documentation

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | None |
| ASVS Sections | 12.1.5 |
| Files | airflow-core/docs/howto/run-behind-proxy.rst:entire file |
| Source Reports | 12.1.5.md |
| Related | None |

**Description:**

The deployment documentation provides no guidance on enabling Encrypted Client Hello (ECH) to prevent SNI exposure during TLS handshakes. This is a Level 3 requirement. ECH is a relatively new feature and support varies by TLS stack, but given the domain context states 'Encrypted Client Hello (ECH) should be enabled to prevent hostname exposure,' documentation should at minimum acknowledge this requirement. The Server Name Indication (SNI) field will be transmitted in plaintext during TLS handshakes, allowing network observers to determine which hostname the client is connecting to even though the connection content is encrypted.

**Remediation:**

Add a section on ECH configuration. Note that ECH requires: 1. DNS HTTPS records with ECH configuration 2. Server-side support (nginx does not yet fully support ECH as of early 2024; solutions include Cloudflare proxy or custom builds). Example: # ECH Configuration Note # ECH requires DNS-level HTTPS records and server support. # Consider deploying behind a CDN/proxy that supports ECH (e.g., Cloudflare) # or use nginx builds with ECH support when available.

---

#### FINDING-179: Incomplete documentation of connection configuration parameters for backend service interactions

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | None |
| ASVS Sections | 13.2.6 |
| Files | airflow-core/docs/authoring-and-scheduling/deferring.rst:lines referencing capacity and heartbeat, airflow-core/docs/core-concepts/executor/index.rst:executor configuration, airflow-core/docs/security/workload.rst:no connection config referenced |
| Source Reports | 13.2.6.md |
| Related | None |

**Description:**

ASVS 13.2.6 requires that applications follow documented configuration for each backend connection including maximum parallel connections, behavior when maximum connections are reached, connection timeouts, and retry strategies. The provided documentation shows partial coverage. The triggerer documentation mentions capacity limits and heartbeat timeouts but does not document database connection pool settings, connection timeouts, or retry behavior for database connections. The executor documentation describes heartbeats and task queuing but does not document connection pool parameters for the scheduler-to-executor or executor-to-worker connections. Without comprehensive documented connection configuration, resource exhaustion scenarios are harder to prevent (e.g., triggerer opening unlimited database connections), failure modes are unpredictable when connection limits are reached, and Deployment Managers cannot properly size infrastructure or set appropriate limits.

**Remediation:**

Document connection configuration for each backend service interaction including: Database Connections with sql_alchemy_pool_size, sql_alchemy_max_overflow, sql_alchemy_pool_recycle, sql_alchemy_pool_pre_ping, and sql_alchemy_connect_args parameters. For Triggerer-to-Database connections, document maximum connections (sql_alchemy_pool_size + sql_alchemy_max_overflow), behavior at max (new requests wait up to pool_timeout before raising), connection timeout (configured via sql_alchemy_connect_args), and retry strategy (connections recycled after sql_alchemy_pool_recycle seconds). For Executor-to-Worker Communication, document CeleryExecutor connection pool managed by Celery broker configuration, KubernetesExecutor API server connection with configurable timeout, connection timeout settings, and retry strategy with exponential backoff.

---

#### FINDING-180: SQLAlchemy Debug Logging Lacks Programmatic Production Guard-rails

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | None |
| ASVS Sections | 13.4.2 |
| Files | airflow-core/docs/howto/set-up-database.rst:lines referencing SQLAlchemy logging section |
| Source Reports | 13.4.2.md |
| Related | None |

**Description:**

The documentation describes enabling SQLAlchemy debug logging (echo=True) without providing a mechanism to ensure it is programmatically disabled in production deployments. Data flow: Documentation guidance → Operator configures sql_alchemy_engine_args with echo=True → All SQL queries including those touching credentials tables are logged in plaintext. If a deployment manager follows this guidance without reverting for production, all SQL statements (potentially including credential-related queries) are logged to application output. The documentation warns against production use but provides no guard-rails.

**Remediation:**

While not a code vulnerability, the documentation should recommend environment-aware configuration: In airflow_local_settings.py: import os; sql_alchemy_engine_args = {"echo": os.environ.get("AIRFLOW_ENV") != "production"}. Add environment-aware defaults to SQLAlchemy engine configuration that automatically disable echo in production environments. Add a production hardening section to this documentation that references ASVS 13.4.x requirements: disabling debug modes, removing documentation endpoints, disabling TRACE, and suppressing version headers.

---

#### FINDING-181: Documentation references external downloads without integrity verification guidance

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | None |
| ASVS Sections | 15.2.4 |
| Files | airflow-core/docs/howto/set-up-database.rst:103-125 |
| Source Reports | 15.2.4.md |
| Related | None |

**Description:**

The documentation recommends specific Python drivers (psycopg2, mysqlclient) without specifying: expected PyPI package names (to prevent typosquatting confusion, e.g., psycopg2 vs psycopg2-binary vs malicious psycop2), expected repository source (PyPI, internal mirror), or expected package maintainers/checksums. This creates a theoretical dependency confusion risk if operators install packages from unverified sources or misspell package names. This is a documentation-level concern. The actual dependency management would be in requirements.txt, pyproject.toml, or similar files not provided here.

**Remediation:**

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

---

#### FINDING-182: Auth Manager Documentation Does Not Reference Remediation Timeframes for Provider Dependencies

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | None |
| ASVS Sections | 15.1.1 |
| Files | airflow-core/docs/core-concepts/auth-manager/index.rst:Throughout |
| Source Reports | 15.1.1.md |
| Related | None |

**Description:**

This documentation describes a pluggable auth manager architecture where third-party provider packages (e.g., `airflow.providers.fab.auth_manager.fab_auth_manager.FabAuthManager`, Keycloak auth manager) are loaded as dependencies. The documentation does not reference or link to any policy defining risk-based remediation timeframes for vulnerabilities discovered in these third-party auth manager provider packages. Operators deploying custom or provider-based auth managers lack guidance on how quickly to update when vulnerabilities are disclosed in those provider packages. Since auth managers handle authentication and authorization (security-critical functionality), delays in patching could expose the entire Airflow deployment.

**Remediation:**

Add a section or cross-reference to a vulnerability remediation policy document that defines: Critical auth manager vulnerabilities: patch within 24-48 hours, High severity: patch within 7 days, Medium severity: patch within 30 days, Low severity: patch within 90 days. Example: Add a 'Security Updates for Auth Manager Providers' section that states 'Auth managers handle security-critical operations. When vulnerabilities are disclosed in auth manager provider packages, refer to the :doc:`/security/vulnerability-remediation-policy` for required remediation timeframes.'

---

#### FINDING-183: No SBOM Reference or Dependency Inventory for Auth Manager Provider Ecosystem

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | None |
| ASVS Sections | 15.1.2 |
| Files | airflow-core/docs/core-concepts/auth-manager/index.rst:47-53 |
| Source Reports | 15.1.2.md |
| Related | None |

**Description:**

The documentation references multiple external provider packages as auth manager implementations but does not reference an SBOM or dependency inventory tracking these components and their transitive dependencies. Auth managers are security-critical components that may introduce additional dependencies (e.g., OAuth libraries, LDAP clients, SAML parsers). Without SBOM tracking of auth manager providers and their transitive dependencies, vulnerabilities in nested dependencies (e.g., a vulnerable `python-jose` library used by a JWT-based auth manager) may go undetected.

**Remediation:**

Reference or link to SBOM generation processes:

```rst
Dependency Tracking
^^^^^^^^^^^^^^^^^^^

All auth manager provider packages and their transitive dependencies should be tracked
in the deployment's Software Bill of Materials (SBOM). See :doc:`/security/sbom` for
guidance on generating and maintaining SBOMs for Airflow deployments including providers.
```

---

#### FINDING-184: Token Refresh Middleware Resource Impact Not Documented

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | None |
| ASVS Sections | 15.1.3 |
| Files | airflow-core/docs/core-concepts/auth-manager/index.rst:139-146 |
| Source Reports | 15.1.3.md |
| Related | None |

**Description:**

The JWT refresh middleware intercepts every request to check token validity. The documentation does not describe the resource impact of this middleware or what happens when the refresh_user method involves expensive operations (e.g., calling an external OAuth token endpoint). If refresh_user involves network calls to external identity providers, concurrent token refreshes could overwhelm both the Airflow API server and the external provider.

**Remediation:**

Document the resource implications and recommended patterns (e.g., token refresh should be fast, avoid expensive operations, consider refresh token pre-fetching).

---

#### FINDING-185: No Risk Classification of Auth Manager Provider Dependencies

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | None |
| ASVS Sections | 15.1.4 |
| Files | airflow-core/docs/core-concepts/auth-manager/index.rst:Throughout |
| Source Reports | 15.1.4.md |
| Related | None |

**Description:**

The documentation describes a system where any third-party package can serve as an auth manager (the most security-critical component in the system) but does not classify or identify which auth manager providers might be considered 'risky components' based on maintenance status, contributor count, vulnerability history, or security audit status. Operators may deploy auth managers from providers with poor security practices, few maintainers, or no security audits, without being alerted to the associated risk. Since auth managers control all authentication and authorization, a compromised or poorly maintained auth manager has maximum blast radius.

**Remediation:**

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

---

#### FINDING-186: No Mechanism Documented to Verify Auth Manager Provider Versions Are Current

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | None |
| ASVS Sections | 15.2.1 |
| Files | airflow-core/docs/core-concepts/auth-manager/index.rst:Throughout |
| Source Reports | 15.2.1.md |
| Related | None |

**Description:**

The documentation describes loading auth managers from provider packages but does not reference any mechanism to verify that deployed provider versions comply with documented update timeframes. There is no mention of: Version checking for auth manager providers, Warnings when providers are outdated, Integration with vulnerability scanning tools, or Automated update notifications. Without version verification mechanisms, deployments may continue using outdated auth manager providers with known vulnerabilities, exceeding any documented remediation timeframes.

**Remediation:**

Reference deployment-time and runtime version verification. Add a 'Keeping Auth Managers Updated' section documenting: Running pip-audit or equivalent tools in CI/CD to detect vulnerable dependencies, Monitoring provider release announcements and security advisories, Using constraint files to track approved provider versions, Setting up automated alerts when provider packages exceed their documented maximum age with reference to dependency-update-policy documentation.

---

#### FINDING-187: No Documented Resource Constraints for Custom Auth Manager Initialization

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | None |
| ASVS Sections | 15.2.2 |
| Files | airflow-core/docs/core-concepts/auth-manager/index.rst:lines regarding init method and module-level imports |
| Source Reports | 15.2.2.md |
| Related | None |

**Description:**

While the documentation advises against expensive module-level imports for performance reasons, there is no enforcement mechanism or timeout documented for the init() method or for get_fastapi_app(). A custom auth manager's init() method could contain blocking operations (e.g., waiting for an unresponsive external service) that prevent the Airflow API server from starting, causing complete loss of availability. A misbehaving or compromised auth manager could block Airflow startup indefinitely.

**Remediation:**

Document and implement initialization timeouts for auth manager lifecycle methods. Add timeout wrappers around auth manager initialization in the core loader.

---

#### FINDING-188: Potential information disclosure through unhandled template rendering errors

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2, L3 |
| CWE | None |
| ASVS Sections | 16.5.1 |
| Files | airflow-core/src/airflow/api_fastapi/core_api/app.py:89 |
| Source Reports | 16.5.1.md |
| Related | None |

**Description:**

If the template file (/index.html) is missing, corrupted, or contains a rendering error, a Jinja2TemplateNotFound or TemplateError exception will be raised. The response to the client depends entirely on whether the registered ERROR_HANDLERS (in init_error_handlers) cover Jinja2 exceptions. If not covered, FastAPI's built-in handler returns 'Internal Server Error' (generic), but the ASGI server (Uvicorn) may log the error without the application having control over the response format. FastAPI's default 500 handler typically does not expose stack traces in response bodies, but the response format may not be consistent with other error responses, potentially leaking the technology stack.

**Remediation:**

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

---

#### FINDING-189: No graceful handling of auth manager middleware initialization failure

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2, L3 |
| CWE | None |
| ASVS Sections | 16.5.2 |
| Files | airflow-core/src/airflow/api_fastapi/core_api/app.py:153 |
| Source Reports | 16.5.2.md |
| Related | None |

**Description:**

If `get_auth_manager()` connects to an external identity provider or configuration store that is unavailable at startup, this will raise an unhandled exception, preventing the application from starting entirely. While failing to start without auth is the correct security posture (fail-closed), there's no explicit handling that distinguishes between 'auth provider temporarily unavailable' vs 'auth misconfigured.' Failing to start without authentication is correct behavior (fail-closed), but lack of specific error messaging makes operational troubleshooting harder.

**Remediation:**

Add explicit exception handling around auth manager initialization to distinguish between temporary availability issues and configuration errors. Provide clear error messages that aid operational troubleshooting while maintaining fail-closed behavior. Log specific error types to help operators determine whether the issue is transient (retry) or requires configuration changes.

---

#### FINDING-190: Plugin initialization may mask non-import errors during Flask app creation

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2, L3 |
| CWE | None |
| ASVS Sections | 16.5.3 |
| Files | airflow-core/src/airflow/api_fastapi/core_api/app.py:107-122 |
| Source Reports | 16.5.3.md |
| Related | None |

**Description:**

The `create_app(enable_plugins=True)` call is outside the try/except block and could raise various exceptions (database errors, configuration issues, plugin initialization errors). If this call fails, the application startup fails completely. While this is the correct behavior (fail-closed), if `create_app` partially succeeds or if the WSGI mount happens with a partially-initialized Flask app, it could lead to inconsistent security state in the legacy plugin subsystem. The most likely failure mode is a complete startup failure (fail-closed), which is the correct security posture. The risk of a partially-initialized Flask app being mounted is theoretical.

**Remediation:**

Add explicit error handling to the `create_app(enable_plugins=True)` call to ensure any exceptions during Flask app creation are properly caught and handled. Consider wrapping the WSGI mount operation in error handling to prevent mounting of a partially-initialized Flask app. Verify that `ERROR_HANDLERS` in `airflow.api_fastapi.common.exceptions` includes a handler for the base `Exception` class that both logs the full exception server-side and returns a generic message to clients.

---

#### FINDING-191: Key Rotation Procedure Missing Verification and Secure Disposal Steps

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2, L3 |
| CWE | None |
| ASVS Sections | 11.1.1, 13.3.1 |
| Files | airflow-core/docs/security/secrets/fernet.rst:47-49 |
| Source Reports | 11.1.1.md, 13.3.1.md |
| Related | None |

**Description:**

The default behavior stores the master encryption key (which protects all connection passwords and variable values) in a plaintext configuration file. While environment variables are mentioned as an alternative, neither the Fernet documentation nor the secrets-backend documentation provides explicit guidance to store the Fernet key itself in a secrets management system (e.g., Vault, AWS Secrets Manager) for production deployments. The comment "keep it in secured place!" in the key generation example is insufficient operational guidance. The first time Airflow is started, the airflow.cfg file is generated with the default configuration and the unique Fernet key saved to option fernet_key of section [core]. If airflow.cfg is included in version control, container images, backups, or accessible to unauthorized users/processes, all encrypted credentials in the metadata database are compromised. The Fernet key is the single point of failure for data-at-rest encryption.

**Remediation:**

The documentation should explicitly recommend and document how to store the Fernet key in an external secrets manager for production. Add a warning that for production deployments, the Fernet key MUST be stored in an external secrets management system (e.g., HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager) and injected via environment variable at runtime. Never store the Fernet key in airflow.cfg or any file that may be committed to version control or included in container images. Provide example using AWS Secrets Manager with an entrypoint script to export AIRFLOW__CORE__FERNET_KEY from the secrets manager.

---

#### FINDING-192: Cannot Verify Constant-Time Operation from Documentation Alone

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | None |
| ASVS Sections | 11.2.4 |
| Files | airflow-core/docs/security/secrets/fernet.rst |
| Source Reports | 11.2.4.md |
| Related | None |

**Description:**

Cannot verify constant-time operation from documentation alone. The document references the `cryptography` library's Fernet implementation, which internally uses `hmac.compare_digest()` for constant-time comparison during token verification. However, this cannot be verified from the documentation file provided. This is an observation about audit scope limitation rather than a confirmed vulnerability. The `cryptography` Python library is well-audited and uses constant-time comparisons in its Fernet implementation. The risk would be in any custom code wrapping or using Fernet results (e.g., comparing decrypted values, token validation in custom code paths). If any Airflow code performs non-constant-time comparisons on cryptographic material (tokens, MACs, keys), timing side-channels could enable attacks.

**Remediation:**

Verify in the actual implementation code that: 1. All MAC verification uses `hmac.compare_digest()` or equivalent 2. No early-return patterns exist in token comparison logic 3. Error handling does not leak timing information (e.g., different response times for 'invalid MAC' vs 'expired token')

---

#### FINDING-193: Documentation Gap for Key Exchange Mechanisms

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | None |
| ASVS Sections | 11.6.2 |
| Files | airflow-core/docs/security/secrets/fernet.rst:entire file |
| Source Reports | 11.6.2.md |
| Related | None |

**Description:**

The security documentation covers symmetric encryption (Fernet) comprehensively but does not reference or document any key exchange mechanisms used within the Airflow ecosystem (beyond TLS, which ASVS 11.6.2 explicitly excludes from scope). A complete cryptographic inventory should document all cryptographic keys, algorithms, and their usage patterns, including key exchange mechanisms if they exist. The audit cannot determine if key exchange occurs in inter-component communication (scheduler ↔ worker, webserver ↔ database), custom protocol implementations, secrets backend handshakes, SSH integrations, or non-TLS encrypted channels.

**Remediation:**

Expand the cryptographic documentation to explicitly address key exchange. Add a dedicated section that clarifies whether Airflow relies on TLS for all key exchange operations or if application-layer key exchange protocols exist. Document approved key exchange mechanisms including: For TLS - ECDHE with NIST P-256, P-384, P-521, or X25519 curves, and DHE with minimum 2048-bit group parameters (3072-bit recommended). For custom integrations requiring key exchange - use established libraries (cryptography, OpenSSL), ECDH with NIST P-256 or stronger curves only, DH with minimum 2048-bit group parameters, and never implement custom key exchange protocols. Include a key exchange inventory table documenting components, mechanisms, parameters, and status for all key exchange operations in the system.

---

#### FINDING-194: Documented priority inversion allowing low-priority tasks to execute before high-priority tasks

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | None |
| ASVS Sections | 15.4.4 |
| Files | airflow-core/docs/administration-and-deployment/scheduler.rst:56-62 |
| Source Reports | 15.4.4.md |
| Related | None |

**Description:**

The documentation explicitly states that task priority is not strictly enforced — low-priority tasks can be scheduled before high-priority tasks when pool slots are available. While this is documented as an intentional design decision for throughput optimization, it could lead to scenarios where critical high-priority tasks experience delayed execution during peak scheduling periods if they are in a later batch than lower-priority tasks. In scenarios with high scheduling load, tasks with higher priority may experience unfair delays (a form of priority inversion/starvation), potentially affecting time-sensitive workflows.

**Remediation:**

This is an acknowledged design trade-off. For deployments requiring strict priority enforcement: Use dedicated pools for high-priority tasks to ensure slot availability; Monitor scheduling latency by priority tier; Consider the max_dagruns_per_loop_to_schedule setting to control batch sizes. This finding is LOW severity because the behavior is documented and intentional. It represents a design trade-off rather than a defect.

---

#### FINDING-195: Potential scheduler starvation when one scheduler acquires all DagRun locks

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | None |
| ASVS Sections | 15.4.4 |
| Files | airflow-core/docs/administration-and-deployment/scheduler.rst:155-162 |
| Source Reports | 15.4.4.md |
| Related | None |

**Description:**

The documentation acknowledges that misconfiguration of max_dagruns_per_loop_to_schedule can lead to one scheduler monopolizing DagRun processing, effectively starving other scheduler instances. While this is a configuration concern rather than a code defect, the system does not appear to have built-in fairness guarantees between scheduler instances. In a multi-scheduler deployment with high max_dagruns_per_loop_to_schedule values, one scheduler could dominate resource acquisition, reducing the effective throughput benefits of running multiple schedulers and potentially causing uneven load distribution.

**Remediation:**

This is mitigated by proper configuration. The system could additionally implement: Dynamic adjustment of batch sizes based on detected peer scheduler activity; Randomized or round-robin DagRun acquisition to distribute work more evenly.

---

#### FINDING-196: Base Auth Manager Framework Provides No PKCE/State Parameter Infrastructure for OAuth Code Flow

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-352 |
| ASVS Sections | 10.2.1 |
| Files | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:183 |
| Source Reports | 10.2.1.md |
| Related | None |

**Description:**

The `BaseAuthManager` abstract class defines `get_url_login(**kwargs) -> str` (line ~183) which suggests redirect-based authentication flows (e.g., OAuth authorization code flow). However, the base class provides no framework-level support for: PKCE (`code_verifier` / `code_challenge`) generation or validation, `state` parameter generation, storage, or verification, or callback/redirect handling with anti-CSRF verification. This is an abstract base class, and concrete OAuth implementations (subclasses) must implement their own CSRF protections. The absence of framework-level guidance or helper methods means every implementer must independently implement PKCE/state parameter protection. Concrete auth manager implementations that utilize OAuth code flow may omit CSRF protection if developers don't implement it independently, since the framework doesn't enforce or facilitate it.

**Remediation:**

Consider adding abstract or helper methods for PKCE/state parameter handling: (1) `generate_state_parameter()` to generate a cryptographically random state parameter for OAuth requests using secrets.token_urlsafe(32), and (2) `validate_state_parameter(received_state, expected_state)` to validate the state parameter returned from the authorization server using hmac.compare_digest().

---

#### FINDING-197: Audience Configuration Key Mismatch Between Token Signer and Validator

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | None |
| ASVS Sections | 10.3.1 |
| Files | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:821-843 |
| Source Reports | 10.3.1.md |
| Related | None |

**Description:**

The token signer and validator read audience configuration from different config sections, which could lead to a mismatch if operators configure one but not the other. Token signer uses `conf.get("api", "jwt_audience", fallback="apache-airflow")` while token validator uses `conf.get("api_auth", "jwt_audience", fallback="apache-airflow")`. If an operator sets `[api] jwt_audience = custom-audience` but doesn't also set `[api_auth] jwt_audience = custom-audience`, tokens generated by this system would fail validation by the same system. Conversely, misconfiguration could inadvertently accept tokens intended for different services. Since both have the same fallback value, the default behavior is correct.

**Remediation:**

Unify the configuration source or add validation that both resolve to the same value. Use the same configuration section for both token signer and validator, preferably `api_auth` for consistency.

---

#### FINDING-198: `deserialize_user` Abstract Method Has No Contractual Requirement for `iss`+`sub` Identification

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | None |
| ASVS Sections | 10.3.3 |
| Files | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:146 |
| Source Reports | 10.3.3.md |
| Related | None |

**Description:**

The `deserialize_user` abstract method accepts the full token payload but provides no enforcement or guidance that implementations must use `iss` + `sub` for unique user identification. Concrete implementations may use `email`, `preferred_username`, or other reassignable claims for user identification, leading to identity confusion if those claims change.

**Remediation:**

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

---

#### FINDING-199: No PAR/JAR Infrastructure for Authorization Details Integrity

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | None |
| ASVS Sections | 10.4.15 |
| Files | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:entire file |
| Source Reports | 10.4.15.md |
| Related | None |

**Description:**

The base auth manager does not implement OAuth authorization endpoint concepts such as: Pushed Authorization Requests (PAR) endpoint or enforcement, JWT-secured Authorization Request (JAR) validation, or authorization_details parameter handling (RFC 9396). The class is an abstract base for Airflow's internal authentication system, not a general-purpose OAuth authorization server. It does not expose an /authorize endpoint or process authorization requests with authorization_details parameters. If a derived class implements an OAuth AS flow with authorization_details, there is no base-class infrastructure to ensure these parameters originate from the client backend. However, this is an architectural gap rather than a direct vulnerability in the current code.

**Remediation:**

If OAuth AS functionality is to be built on this base class, add abstract methods or interfaces for PAR/JAR support:
```python
@abstractmethod
def validate_authorization_request(self, request: AuthorizationRequest) -> bool:
    """Validate that authorization request parameters are integrity-protected (PAR/JAR)."""
```

#### FINDING-200: No OAuth Client Authentication Mechanisms Implemented

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Section(s) | 10.4.16 |
| Files | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:entire file |
| Source Reports | 10.4.16.md |
| Related | - |

**Description:**

The base auth manager does not implement OAuth client authentication mechanisms. There is no support for: tls_client_auth (mutual TLS with PKI certificates), self_signed_tls_client_auth (mutual TLS with self-signed certificates per RFC 8705 §2.2), private_key_jwt (client assertion using private key), or client credential validation at token endpoints. The authentication flow in this base class is user-facing (JWT cookie-based), not client-to-server OAuth authentication.

**Remediation:**

For deployments requiring OAuth AS functionality, either: 1. Use a dedicated OAuth AS (Keycloak, Hydra, etc.) alongside Airflow, or 2. Add client authentication interfaces to the base class with support for ClientAuthMethod enum (TLS_CLIENT_AUTH, SELF_SIGNED_TLS_CLIENT_AUTH, PRIVATE_KEY_JWT) and an abstract authenticate_client method that authenticates OAuth clients using strong methods (mTLS or private_key_jwt).

---

#### FINDING-201: Execution API InProcessExecutionAPI completely bypasses all authentication and authorization controls

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2, L3 |
| CWE | - |
| ASVS Section(s) | 6.3.4 |
| Files | airflow-core/src/airflow/api_fastapi/execution_api/app.py:285-300 |
| Source Reports | 6.3.4.md |
| Related | - |

**Description:**

The InProcessExecutionAPI overrides ALL security dependencies (`_jwt_bearer`, `has_connection_access`, `has_variable_access`, `has_xcom_access`) with an `always_allow` function that always grants access. This is documented in `jwt_token_authentication.rst`, but it creates a pathway where DAG author code running in the DFP or Triggerer has unrestricted access to all connections, variables, and XComs across all teams. In multi-team deployments, DAG author code from one team can access connections, variables, and XComs belonging to other teams when running via DFP or Triggerer, since all access controls are bypassed.

**Remediation:**

This is documented and acknowledged. For multi-team deployments, the documentation recommends running separate DFP/Triggerer instances per team. Consider implementing team-scoped access controls within the InProcessExecutionAPI or using a trusted internal service token instead of completely disabling auth.

---

#### FINDING-202: Token Revocation Conditional on JTI Claim Presence

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2, L3 |
| CWE | - |
| ASVS Section(s) | 6.3.4 |
| Files | airflow-core/tests/unit/api_fastapi/auth/managers/test_base_auth_manager.py:195-215 |
| Source Reports | 6.3.4.md |
| Related | - |

**Description:**

If a custom auth manager implementation or external identity provider issues tokens without the `jti` claim, those tokens cannot be revoked (e.g., on logout). The `get_user_from_token` function skips the revocation check when the `jti` claim is absent. This creates an inconsistency in authentication strength across pathways that produce tokens with vs. without `jti`.

**Remediation:**

Enforce `jti` claim requirement by rejecting tokens without a `jti` claim in the `get_user_from_token` method, ensuring all tokens are revocable.

---

#### FINDING-203: JWT refresh middleware does not validate token `scope` claim before refreshing user session

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2, L3 |
| CWE | - |
| ASVS Section(s) | 6.3.4 |
| Files | airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py:67-70 |
| Source Reports | 6.3.4.md |
| Related | - |

**Description:**

The JWT refresh middleware's `_refresh_user` function calls `resolve_user_from_token` without explicit scope validation. If different token scopes (workload, user, etc.) share the same signing key and audience, a token intended for internal scheduler-worker communication could potentially be injected as a cookie and trigger user session creation/refresh. The audience separation mitigates this partially, but the middleware has no explicit scope validation.

**Remediation:**

Add explicit scope validation in the refresh middleware to verify that tokens presented via cookies have the expected scope (e.g., not 'workload') before refreshing user sessions.

---

#### FINDING-204: Multiple Authentication Schemes Configured as OR-Logic Without Documented Strength Equivalence

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2, L3 |
| CWE | - |
| ASVS Section(s) | 6.3.4 |
| Files | airflow-core/src/airflow/api_fastapi/core_api/openapi/v2-rest-api-generated.yaml |
| Source Reports | 6.3.4.md |
| Related | - |

**Description:**

All secured API endpoints accept authentication via EITHER `OAuth2PasswordBearer` OR `HTTPBearer` (OpenAPI 3.x `security` array items are OR-ed). While both ultimately use bearer tokens, the specification does not document how tokens obtained through each pathway are equivalent in strength. Without documentation clarifying that `HTTPBearer` tokens are the SAME JWT tokens obtained via the OAuth2 flow (or an equivalent SSO/IdP flow), there is ambiguity about whether all pathways enforce equivalent authentication strength.

**Remediation:**

Add documentation clarifying that both security schemes accept the same JWT tokens and that no alternative token issuance mechanism exists with weaker controls.

---

#### FINDING-205: Simple auth manager provides no MFA factor lifecycle management

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2, L3 |
| CWE | - |
| ASVS Section(s) | 6.4.4 |
| Files | airflow-core/src/airflow/api_fastapi/auth/managers/simple/utils.py:full file, airflow-core/src/airflow/api_fastapi/auth/managers/simple/ui/src/login/Login.tsx:entire file |
| Source Reports | 6.4.4.md |
| Related | - |

**Description:**

The simple auth manager only supports single-factor authentication (username/password). There is no MFA enrollment, factor management, or factor recovery mechanism. Per the ASVS requirement, L2 applications must force MFA. While the simple auth manager is documented as for development/testing only, there is no runtime guardrail preventing its use in production environments. If deployed in production without alternative auth manager, single-factor authentication with no recovery flow does not meet ASVS L2 requirements for MFA enforcement or factor lifecycle management. This is partially covered by the known false positive pattern (Simple Auth Manager using basic username/password authentication is intentional because it's explicitly documented as for development/testing). The finding is retained at LOW severity because the dismissible banner is the only safeguard.

**Remediation:**

Add a runtime warning or startup check that prevents simple auth manager usage in production. Add production safety check for SimpleAuthManager with validation that flags SimpleAuthManager usage when the deployment appears to be production (e.g., multiple workers, non-localhost bind, database is PostgreSQL/MySQL). Implement runtime configuration validation to prevent non-compliant auth manager usage in production environments.

---

# 4. Positive Security Controls

| Control | Evidence | Files/References |
|---------|----------|------------------|
| **JWT Token Authentication** |
| HTTP-only cookie for UI tokens | Stored in a secure, HTTP-only cookie (`_token`) with `SameSite=Lax` | Cookie configuration |
| Token scoping (workload vs execution) | Short-lived execution tokens replace long-lived workload tokens | Token generation logic |
| Unique token identifiers (jti) | Each generated token receives a unique jti claim via uuid.uuid4().hex, preventing replay and enabling revocation tracking | `JWTGenerator.generate()` |
| Token revocation tracking | The revoke_token() method stores jti values in the database, enabling detection of replayed/revoked tokens | `revoke_token()` |
| Python cryptography library usage | All key generation, serialization, and hashing operations use the cryptography library, which is backed by OpenSSL/BoringSSL | Core cryptographic operations |
| PyJWT for token operations | JWT encoding/decoding uses the pyjwt library, a widely-used, actively maintained implementation | Token handling |
| JWKS support with automatic refresh | The JWKS class supports multiple keys in a keyset with periodic background refresh (default 3600s) | Key rotation infrastructure |
| Kid (Key ID) in all asymmetric tokens | All tokens include a kid header, allowing validators to select the correct key from a keyset during rotation periods | Token headers |
| CSPRNG for key generation | The auto-generated symmetric secret key uses os.urandom(16), providing exactly 128 bits of entropy from the operating system's CSPRNG | `get_signing_key()` |
| uuid.uuid4().hex for token IDs | Used for jti claims in JWTGenerator.generate() method, backed by os.urandom() which uses kernel CSPRNG | `tokens.py:390` |
| RSA public exponent hardcoded to 65537 | generate_private_key() uses public_exponent=65537, preventing low-exponent attacks | `tokens.py:400` |
| Approved algorithms only | System restricts to NIST-approved algorithms (HS512, RS256, EdDSA), no deprecated algorithms used for signing | `tokens.py` |
| jwt.decode() with signature verification | Default PyJWT behavior verifies signature | `tokens.py:269` |
| algorithms parameter in jwt.decode() acts as allowlist | Explicit algorithm allowlist prevents algorithm confusion attacks | `tokens.py:269` |
| No jku/x5u/jwk header processing | Only kid extracted from headers, preventing header injection attacks | `tokens.py:239` |
| JWKS URL from server configuration only | The JWKS class URL comes from [api_auth] trusted_jwks_url in the Airflow configuration, which is admin-controlled | `tokens.py:492` |
| Required claims: exp, iat, nbf | JWTValidator class enforces required_claims = frozenset({"exp", "iat", "nbf"}) | `tokens.py:226` |
| exp validation by PyJWT | PyJWT auto-verifies exp claim during jwt.decode() | `tokens.py:269` |
| nbf validation by PyJWT | PyJWT auto-verifies nbf claim during jwt.decode() | `tokens.py:269` |
| Clock skew tolerance via leeway | JWTValidator.leeway configurable with default 10s for clock skew tolerance | `tokens.py:229` |
| Execution API scope enforcement documented | Documentation describes route-level token scope enforcement via 'require_auth' checking 'scope' against 'allowed_token_types' | Documentation |
| Execution API has strong audience default | The Execution API uses `urn:airflow.apache.org:task` as its audience by default | Configuration |
| PyJWT audience validation is used when configured | When a non-None audience is provided, `jwt.decode()` properly validates the `aud` claim | `tokens.py:270` |
| **Simple Auth Manager** |
| Password file uses exclusive file locking | fcntl.flock used during multi-worker initialization to prevent race conditions | `simple_auth_manager.py` |
| Generated passwords have reasonable entropy | 16-character alphanumeric passwords from 52-character alphabet provide ~95 bits of entropy | `simple_auth_manager.py:308` |
| Auto-generated passwords exceed minimum length | Password generation function creates 16-character passwords (exceeding 8-char minimum and 15-char recommended) | `simple_auth_manager.py:313` |
| Passwords persist indefinitely without forced rotation | The init() method only generates passwords for users that don't already have one | `simple_auth_manager.py:135` |
| No password composition rules enforced | Login accepts any string password without regex patterns or character class requirements | `services/login.py` |
| Direct password comparison without transformation | Password comparison uses direct equality without .lower(), .upper(), .strip(), or truncation | `services/login.py:60` |
| No max-length restriction on password verification | The direct equality comparison does not truncate or limit the compared string length | `services/login.py:60` |
| Generic error message on failed login | The service returns a generic 'Invalid credentials' message on failed login, avoiding username enumeration | `services/login.py:65` |
| No hardcoded default accounts | No hardcoded 'root', 'admin', or 'sa' accounts exist when simple_auth_manager_all_admins is False | `simple_auth_manager.py` |
| Configuration guard for all_admins mode | create_token_all_admins() raises HTTP 403 when all-admins configuration is not explicitly enabled | `services/login.py:77-82` |
| Absence of password hints and secret questions | LoginBody model accepts only username and password — no hint, secret question, or knowledge-based fields exist | Login model |
| Dynamic JWT generation per auth event | New token generated per login via create_token() | `services/login.py` |
| Configurable JWT expiration | jwt_expiration_time and jwt_cli_expiration_time configurations provide context-aware expiration | `services/login.py:38` |
| Self-contained JWT tokens | generate_jwt() via BaseAuthManager uses cryptographic signing (HS256) instead of reference tokens | Token generation |
| All token generation occurs exclusively on the backend | Backend-only JWT generation and verification via get_auth_manager().generate_jwt() | `services/login.py` |
| Secure flag detection for cookies | Checks scheme/SSL config before setting secure flag on cookies to ensure HTTPS-only transmission when applicable | `routes/login.py:91` |
| Pluggable BaseAuthManager architecture | BaseAuthManager interface supports OAuth2, SAML, OIDC providers with MFA capabilities | Architecture |
| Dynamic user list reading at login time | The get_users() method dynamically reads from configuration, meaning the user list is current at login time | `simple_auth_manager.py` |
| **Pluggable Auth System** |
| Unified abstract interface | BaseAuthManager enforces that all auth manager implementations must provide the same set of authentication and authorization methods | `base_auth_manager.py:178-395` |
| Centralized JWT handling | Token generation (generate_jwt) and validation (get_user_from_token) are centralized in the base class | `base_auth_manager.py:212-216, 190-204` |
| Cookie security guidance | The documentation explicitly instructs implementations to set httponly=True and conditionally set secure based on HTTPS | `index.rst` |
| Token revocation centralized | revoke_token and revocation checking are in the base class, ensuring all auth managers benefit from revocation support | `base_auth_manager.py:200` |
| Token refresh as explicit auth manager responsibility | Making refresh_user an overridable method on the auth manager allows federated implementations to validate IdP session state | `base_auth_manager.py:231-240` |
| JWT validation checks | Token validation includes signature verification, expiration, audience, and revocation status | `base_auth_manager.py:793-802` |
| Configurable JWT lifetime | The jwt_expiration_time configuration allows deployments to set appropriate token lifetimes | `base_auth_manager.py:213` |
| Abstract methods enforce implementation | All critical authorization methods are @abstractmethod, meaning no auth manager can be instantiated without implementing authorization logic | `base_auth_manager.py:242-395` |
| Keyword-only arguments | All authorization methods use * to force keyword-only arguments, preventing accidental parameter misuse | `base_auth_manager.py:242-395` |
| Fail-secure batch operations | batch_is_authorized_* methods use all(), meaning the entire batch fails if any single item is unauthorized | `base_auth_manager.py:421-494` |
| Data-specific details parameters | ConnectionDetails, DagDetails, PoolDetails, VariableDetails enable resource-specific checks | Resource details models |
| Server-side resource filtering | All get_authorized_* and filter_authorized_* methods execute on the server, retrieving from DB and filtering before returning | `base_auth_manager.py` |
| Team-based partitioning | Resources partitioned by team_name throughout with proper joins through team association tables | `base_auth_manager.py` |
| All authorization is server-side | Every is_authorized_* method runs in the Python backend (FastAPI application), not in client-side JavaScript | `base_auth_manager.py` |
| SQLAlchemy session management | Resource queries use @provide_session decorator, ensuring database operations execute on the server | `base_auth_manager.py` |
| **RBAC Permissions** |
| Multi-team documentation clearly documents the resource isolation model | Variables, Connections, Pools, DAGs isolation documented | `multi-team.rst` |
| Auth Manager interface requirements are well-defined | Specific methods needed (is_authorized_team, _get_teams) documented | `multi-team.rst` |
| Documentation explicitly warns about logical isolation limitations | States multi-team provides 'logical isolation' not complete isolation, setting appropriate expectations | `multi-team.rst` |
| Granular entity-level access control definitions | DagAccessEntity enum provides entity-level control for AUDIT_LOG, CODE, RUN, TASK_INSTANCE, TASK_LOGS, XCOM | `resource_details.py:93-108` |
| View-level access control definitions | AccessView enum defines view-level access | `resource_details.py:82-91` |
| Structured authorization model with inspectable context | Authorization model uses structured dataclasses with explicit fields, making the authorization context inspectable and auditable | `resource_details.py` |
| Team-based isolation with clear relationship chain | Team-based isolation documented with relationship chain (Task → Dag → Bundle → Team) | `multi-team.rst` |
| Team deletion guard | A team cannot be deleted if it has associated resources (Dag bundles, Variables, Connections, or Pools) | `multi-team.rst` |
| Database-stored team associations | The authorization model uses database-stored team associations (metadata DB), enabling real-time permission checks | `multi-team.rst` |
| Server-side authorization checks via Auth Manager | The architecture uses server-side authorization checks (Auth Manager) rather than purely client-side tokens | Architecture |
| Team-scoped resource scoping via structural relationships | The resource_details.py model includes team_name on multiple resource types | `resource_details.py` |
| Auth Manager user authorization checks at API layer | The Auth Manager interface requires is_authorized_team which checks the user's relationship to the team | `multi-team.rst` |
| Granular DAG access control | The DagAccessEntity enum provides granular control over what aspects of a DAG a user can access | `resource_details.py` |
| Team-scoped Variables, Connections, Pools, DAGs | Documented and modeled with team_name field or bundle association | Documentation and models |
| Team-scoped executor configuration | Provides compute isolation between teams | `multi-team.rst` |
| Team-scoped secrets backends | Prevent cross-team credential access at the task level | `multi-team.rst` |
| Explicit experimental warning | Documentation clearly marks multi-team as experimental, setting appropriate expectations | `multi-team.rst` |
| **FastAPI Core API** |
| SQLAlchemy ORM parameterized queries | All filter classes use SQLAlchemy ORM with proper parameterization | `security.py` |
| Type-safe parameter handling with int casting | backfill_id is int-cast before use in requires_access_backfill | `security.py:245` |
| No raw SQL construction | Zero instances of raw SQL string construction (text(), execute(f'...'), or string concatenation in queries) found | `security.py` |
| Server-Side Authentication Enforcement | Authentication is entirely server-side with no client-side token validation | `security.py:70-85` |
| Server-Side URL Validation | Comprehensive server-side URL validation preventing open redirects, protocol smuggling, and path traversal | `security.py:660-685` |
| Server-Side Authorization with Fail-Closed Default | Authorization defaults to deny. If the callback returns False or raises an exception, access is denied | `security.py:145-150` |
| FastAPI Framework-Level Input Validation | FastAPI with Pydantic models provides automatic server-side schema validation for all route parameters | `app.py` |
| Method-based authorization mapping | MAP_BULK_ACTION_TO_AUTH_METHOD dictionary correctly maps bulk actions to appropriate HTTP methods | `security.py` |

---

# 5. ASVS Compliance Summary

| ASVS ID | Requirement | Status | Notes |
|---------|-------------|--------|-------|
| **9. Token-Based Session Management** |
| 9.1.1 | Token source and integrity - Signature/MAC validation | ✅ Pass | PyJWT performs signature verification by default |
| 9.1.2 | Token source and integrity - Algorithm allowlist | ✅ Pass | Explicit algorithm allowlist prevents confusion attacks |
| 9.1.3 | Token source and integrity - Key material from trusted sources | ✅ Pass | JWKS URL from admin-controlled configuration only |
| 9.2.1 | Token content - Validity time span verification | ✅ Pass | exp, iat, nbf claims enforced |
| 9.2.2 | Token content - Token type validation | ⚠️ Partial | No explicit `typ` claim prevents definitive type differentiation |
| 9.2.3 | Token content - Audience validation | ⚠️ Partial | REST API audience defaults to None when unconfigured |
| 9.2.4 | Token Audience Restriction | ⚠️ Partial | Execution API has strong default, REST API does not |
| **10. OAuth and OIDC** |
| 10.1.1 | Tokens Only Sent to Components That Need Them | ✅ Pass | Token scoping architecture implemented |
| 10.1.2 | Client Validates Authorization Flow Values From Same Session | ⚠️ N/A | Not applicable - server-side token generation |
| 10.2.1 | OAuth Client CSRF Protection (PKCE/State) | ⚠️ Partial | No PKCE/State infrastructure in BaseAuthManager |
| 10.2.3 | OAuth Client Requests Only Required Scopes | ✅ Pass | Scope enforcement documented |
| 10.3.1 | Resource Server Validates Access Token Audience | ⚠️ Partial | Audience configuration key mismatch between signer and validator |
| 10.3.2 | Resource Server Enforces Claims-Based Authorization | ❌ Fail | Authorization decisions don't incorporate token-level claims |
| 10.3.3 | Resource Server Identifies Users from Non-Reassignable Claims | ⚠️ Partial | No contractual requirement for iss+sub identification |
| 10.3.4 | Authentication Strength Verification | ❌ Fail | No authentication strength, method, or recentness verification |
| 10.3.5 | Sender-Constrained Access Tokens | ❌ Fail | No mTLS or DPoP verification |
| 10.4.1 | Redirect URI Validation | ❌ Fail | Missing redirect URI validation in BaseAuthManager |
| 10.4.5 | Refresh Token Replay Attack Mitigation for Public Clients | ❌ Fail | No refresh token replay mitigation |
| 10.4.8 | Refresh Token Absolute Expiration | ❌ Fail | JWT refresh token lacks absolute expiration enforcement |
| 10.4.9 | Token Revocation by Authorized User | ⚠️ Partial | No explicit revocation check in JWT refresh middleware |
| 10.4.14 | Sender-Constrained Access Tokens | ❌ Fail | JWT access tokens lack sender-constraining mechanisms |
| 10.5.1 | ID Token Replay Mitigation (Nonce) | ⚠️ Partial | Missing nonce validation for ID token replay prevention |
| 10.5.3 | Issuer URL Validation | ❌ Fail | No issuer claim validation in token validator |
| 10.5.4 | OIDC Client - ID Token Audience Validation | ⚠️ Partial | No abstract contract for OIDC ID token audience validation |
| 10.5.5 | OIDC Client - Back-Channel Logout Token Validation | ❌ Fail | No back-channel logout interface or validation contract |
| 10.7.3 | Consent Management - User Review, Modification, and Revocation | ❌ Fail | No user-facing consent management interface |
| **11. Cryptography** |
| 11.2.1 | Industry-Validated Cryptographic Implementations | ✅ Pass | Uses Python cryptography library and PyJWT |
| 11.2.2 | Crypto Agility | ⚠️ Partial | Auto-generated symmetric key lacks rotation mechanism |
| 11.2.3 | Minimum 128-bit Security | ✅ Pass | All algorithms meet minimum security level |
| 11.2.4 | Constant-time Operations | ⚠️ Partial | Cannot verify constant-time operation from documentation alone |
| 11.4.2 | Password Hashing and Key Derivation Functions | ❌ Fail | Passwords stored in plain text without any hashing |
| 11.5.1 | CSPRNG with 128 Bits of Entropy | ⚠️ Partial | Token identifier (jti) uses UUID4 which doesn't meet 128-bit entropy requirement |
| 11.5.2 | Random Values | ✅ Pass | CSPRNG used for key generation (os.urandom) |
| 11.6.1 | Public Key Cryptography | ⚠️ Partial | No minimum key size validation for loaded asymmetric keys |
| 11.6.2 | Approved Cryptographic Algorithms for Key Exchange | ⚠️ Partial | Documentation gap for key exchange mechanisms |
| 11.1.1 | Cryptographic Key Management Policy | ⚠️ Partial | Missing comprehensive key management policy aligned with NIST SP 800-57 |
| 11.1.2 | Cryptographic Inventory | ⚠️ Partial | Incomplete cryptographic inventory documentation |
| 11.1.3 | Cryptographic Discovery Mechanisms | ❌ Fail | No cryptographic discovery mechanisms implemented |
| 11.1.4 | PQC Migration Plan | ❌ Fail | No post-quantum cryptography migration plan documented |
| **6. Authentication** |
| 6.2.1 | Password Minimum Length | ⚠️ Partial | No minimum password length validation mechanism exists |
| 6.2.2 | Users Can Change Their Password | ❌ Fail | No password change functionality exists |
| 6.2.3 | Password Change Requires Current and New Password | ❌ Fail | Password change functionality absent |
| 6.2.4 | Passwords Checked Against Common Password List | ❌ Fail | No breached password checking implemented |
| 6.2.5 | No Password Composition Rules | ✅ Pass | No password composition rules enforced |
| 6.2.6 | Password Input Fields Use type=password | ⚠️ Partial | Cannot verify - frontend template not in audit scope |
| 6.2.8 | Password Verified Without Modification | ✅ Pass | Direct password comparison without transformation |
| 6.2.9 | Passwords of at Least 64 Characters Permitted | ⚠️ Partial | Auto-generated passwords limited to 16 characters |
| 6.2.10 | No Periodic Credential Rotation Required | ✅ Pass | Passwords persist indefinitely without forced rotation |
| 6.2.11 | Context-Specific Word Checking | ❌ Fail | No context-specific word checking implemented |
| 6.2.12 | Breached Password Checking | ❌ Fail | No breached password checking implemented |
| 6.3.1 | Controls to prevent credential stuffing and password brute force | ❌ Fail | No rate limiting, account lockout, or brute force protection |
| 6.3.2 | Default user accounts | ⚠️ Partial | Built-in "Anonymous" admin account active when all_admins enabled |
| 6.3.3 | Multi-factor authentication | ❌ Fail | No multi-factor authentication mechanism available |
| 6.3.4 | Multiple Authentication Pathways | ❌ Fail | Multiple authentication pathways lack consolidated security strength enforcement |
| 6.4.1 | System generated initial passwords | ❌ Fail | Password generation uses non-cryptographic PRNG |
| 6.4.2 | Password hints or knowledge-based authentication | ✅ Pass | Absence of password hints and secret questions |
| 6.4.3 | Secure password reset process | ❌ Fail | No password reset mechanism exists |
| 6.4.4 | Authentication Factor Lifecycle and Recovery | ❌ Fail | No identity re-proofing mechanism for factor recovery |
| 6.1.3 | Authentication Documentation | ⚠️ Partial | Multiple authentication pathways lack consolidated documentation |
| 6.8.1 | Identity Provider Spoofing Prevention | ⚠️ Partial | No documentation of multi-IdP user identity namespacing |
| 6.8.4 | Authentication Strength Verification from IdP | ⚠️ Partial | No documentation of authentication strength enforcement for Kerberos |
| **7. Session Management** |
| 7.2.1 | Backend Session Token Verification | ✅ Pass | Server-side authentication enforcement |
| 7.2.2 | Dynamic Session Tokens | ✅ Pass | Dynamic JWT generation per auth event |
| 7.2.3 | Reference Token Entropy | ⚠️ N/A | Self-contained JWT tokens used instead of reference tokens |
| 7.2.4 | New Token on Authentication and Session Termination | ⚠️ Partial | No mechanism to invalidate previous session tokens on re-authentication |
| 7.3.1 | Inactivity Timeout | ❌ Fail | No inactivity timeout mechanism — only absolute token expiration |
| 7.3.2 | Session Timeout - Absolute Maximum Session Lifetime | ❌ Fail | No documented absolute session timeout separate from JWT expiration |
| 7.4.1 | Session Termination - Disallow Further Session Use | ❌ Fail | JWT tokens cannot be revoked - session termination impossible |
| 7.4.2 | Session Termination - Account Disable/Delete | ❌ Fail | Active sessions not terminated when user account is disabled or deleted |
| 7.4.3 | Session Termination - After Authentication Factor Change | ❌ Fail | No mechanism to terminate sessions after authentication factor change |
| 7.4.4 | Session Termination - Easy Access to Logout | ❌ Fail | No logout endpoint or functionality defined |
| 7.4.5 | Admin Session Termination | ❌ Fail | Session management not included in authorization resource model |
| 7.5.1 | Defenses Against Session Abuse - Re-authentication for Sensitive Changes | ⚠️ Partial | No re-authentication mechanism for sensitive account modifications |
| 7.5.2 | Defenses Against Session Abuse | ❌ Fail | No capability to view active sessions or re-authenticate for sensitive operations |
| 7.5.3 | Step-up Authentication for Sensitive Operations | ❌ Fail | No step-up authentication for highly sensitive multi-team operations |
| 7.6.1 | Federated Re-authentication | ❌ Fail | Missing documentation for federated session lifetime and re-authentication behavior |
| 7.6.2 | Session Creation Requires User Consent or Explicit Action | ✅ Pass | Session creation requires explicit login action |
| 7.1.1 | Session Inactivity Timeout and Maximum Lifetime Documentation | ❌ Fail | Missing session management policy documentation |
| 7.1.2 | Concurrent Session Documentation | ❌ Fail | Missing concurrent session policy documentation |
| 7.1.3 | Session Management Documentation for Federated Identity Management | ⚠️ Partial | Insufficient documentation of session lifetime coordination with federated identity providers |
| **8. Authorization** |
| 8.1.1 | Authorization Documentation | ⚠️ Partial | Authorization documentation describes mechanisms but lacks concrete policy rules |
| 8.1.2 | Authorization Documentation (Field-Level) | ❌ Fail | No documentation of field-level access restrictions |
| 8.1.3 | Authorization Documentation - Environmental/Contextual Attributes | ❌ Fail | Authorization documentation missing environmental/contextual attributes |
| 8.2.1 | General Authorization Design (Function-Level) | ⚠️ Partial | Optional `details` parameter allows resource-type-level authorization bypass potential |
| 8.2.2 | General Authorization Design (Data-Specific) | ✅ Pass | Data-specific details parameters enable resource-specific checks |
| 8.2.3 | General Authorization Design (Field-Level) | ❌ Fail | No field-level authorization mechanism exists in the Auth Manager framework |
| 8.2.4 | Adaptive Security Controls Implementation | ❌ Fail | Authorization resource model lacks environmental and contextual attributes |
| 8.3.1 | Operation Level Authorization | ✅ Pass | Server-side authorization checks via Auth Manager |
| 8.3.2 | Immediate Application of Authorization Changes | ⚠️ Partial | Undocumented authorization change propagation in multi-team environment |
| 8.3.3 | Access Based on Originating Subject's Permissions | ⚠️ Partial | Undocumented permission propagation through scheduler intermediary |
| 8.4.1 | Multi-Tenant Cross-Tenant Controls | ⚠️ Partial | Incomplete multi-tenant cross-tenant controls with information leakage risk |
| 8.4.2 | Administrative Interface Multi-Layer Security | ❌ Fail | Administrative CLI operations lack multi-layered security controls |
| **1. Architecture, Design and Threat Modeling** |
| 1.2.4 | Parameterized Queries / SQL Injection Prevention | ✅ Pass | SQLAlchemy ORM parameterized queries |
| 1.2.5 | Injection Prevention - OS Command Injection Protection | ⚠️ Partial | Custom executor module loading without sanitization guidance |
| 1.2.9 | Injection Prevention - Regex Metacharacter Escaping | ⚠️ Partial | mask_secret() API lacks documented regex metacharacter escaping |
| 1.3.2 | Sanitization — Dynamic Code Execution | ⚠️ Partial | Custom executor module loading without sanitization guidance |
| 1.3.7 | Sanitization — Template Injection | ✅ Pass | Jinja2 autoescape enabled by default |
| 1.3.12 | Sanitization - ReDoS Prevention | ⚠️ Partial | mask_secret() API lacks ReDoS protection documentation |
| 1.5.2 | Safe Deserialization | ❌ Fail | Pickle deserialization support documented without safety controls |
| 2.1.1 | Validation and Business Logic Documentation - Input Validation Rules | ❌ Fail | Missing input validation rules documentation |
| 2.1.2 | Validation and Business Logic Documentation - Contextual Consistency | ✅ Pass | Server-side URL validation |
| 2.1.3 | Validation and Business Logic Documentation - Business Logic Limits | ⚠️ Partial | Batch authorization methods lack documented size constraints |
| 2.2.2 | Server-Side Input Validation | ⚠️ Partial | Authorization dependency consumes unvalidated raw body input; Flask plugin bypasses FastAPI validation |
| 2.3.2 | Business Logic Limits | ✅ Pass | Fail-secure batch operations |
| 2.3.4 | Resource Locking for Limited Quantities | ✅ Pass | Password file uses exclusive file locking |
| 2.4.1 | Anti-automation Controls | ✅ Pass | Generic error message on failed login prevents username enumeration |
| 2.4.2 | Anti-automation - Realistic Human Timing | ⚠️ Partial | Scheduler documentation lacks anti-automation controls for user-triggered DAG operations |
| **3. Web Frontend Security** |
| 1.2.1 | Output Encoding for HTTP Response | ⚠️ Partial | Context-inappropriate output encoding for template variable in JavaScript context |
| 1.2.2 | URL Encoding for Dynamic URLs | ⚠️ Partial | Missing URL validation for backend_server_base_url template context |
| 1.2.3 | JavaScript Content Encoding | ⚠️ Partial | Context-inappropriate output encoding for template variable in JavaScript context |
| 3.1.1 | Web Frontend Security Documentation | ❌ Fail | Incomplete CSP documentation guidance |
| 3.2.1 | Unintended Content Interpretation | ❌ Fail | Missing security headers middleware; static files served with html=True without Content-Type enforcement |
| 3.2.2 | Safe Text Rendering (createTextNode/textContent) | ⚠️ Partial | Context-inappropriate output encoding for template variable in JavaScript context |
| 3.3.1 | Cookie Secure Attribute | ❌ Fail | Missing cookie security configuration |
| 3.3.2 | Cookie SameSite Attribute | ❌ Fail | Missing SameSite cookie attribute configuration |
| 3.3.3 | Cookie __Host- Prefix | ❌ Fail | Cookies lack __Host- prefix enforcement |
| 3.3.4 | Cookie HttpOnly Attribute | ❌ Fail | Documentation advises against HttpOnly |
| 3.4.1 | Strict-Transport-Security (HSTS) Header | ❌ Fail | Missing HSTS header on all responses |
| 3.4.2 | CORS Access-Control-Allow-Origin | ❌ Fail | CORS wildcard origin allowed with credentials enabled |
| 3.4.3 | Content-Security-Policy Header | ❌ Fail | Missing CSP response header |
| 3.4.4 | X-Content-Type-Options Header | ❌ Fail | Missing X-Content-Type-Options header |
| 3.4.5 | Referrer-Policy Header | ❌ Fail | Missing Referrer-Policy header |
| 3.4.6 | Content-Security-Policy frame-ancestors Directive | ❌ Fail | Missing CSP frame-ancestors directive |
| 3.4.7 | CSP Violation Reporting | ❌ Fail | Missing CSP violation reporting |
| 3.4.8 | Cross-Origin-Opener-Policy Header | ❌ Fail | Missing COOP header on HTML responses |
| 3.5.1 | Cross-Site Request Forgery (CSRF) Protection | ⚠️ Partial | Missing SameSite cookie attribute configuration |
| 3.5.2 | CORS Preflight Mechanism | ❌ Fail | Missing SameSite cookie attribute configuration |
| 3.5.3 | HTTP Methods for Sensitive Functionality | ✅ Pass | Method-based authorization mapping |
| 3.5.4 | Separate Applications on Different Hostnames | ❌ Fail | Legacy Flask plugins mounted on same origin as main application |
| 3.5.6 | JSONP Functionality Disabled | ✅ Pass | No JSONP functionality present |
| 3.5.7 | Authorization Data Not in Script Resources | ⚠️ Partial | Static file serving without explicit authorization check |
| 3.5.8 | Authenticated Resource Protection | ❌ Fail | Static file serving without explicit authorization check |
| 3.6.1 | External Resource Integrity | ✅ Pass | SRI attributes used for external resources |
| 3.7.1 | Supported Client-side Technologies | ✅ Pass | Modern browser technologies used |
| 3.7.2 | Redirect Allowlist | ❌ Fail | No redirect allowlist mechanism visible |
| 3.7.3 | Redirect Notification | ❌ Fail | No external redirect notification mechanism |
| 3.7.4 | HSTS Preload | ❌ Fail | Missing HSTS preload configuration |
| 3.7.5 | Browser Security Feature Detection | ❌ Fail | No browser security feature detection or fallback behavior |
| **4. HTTP Security** |
| 4.1.1 | Content-Type Header with Charset | ⚠️ Partial | JSONResponse without explicit charset specification |
| 4.1.2 | HTTP to HTTPS Redirect Behavior | ⚠️ Partial | Missing trusted proxy header validation middleware |
| 4.1.3 | Intermediary Header Override Protection | ❌ Fail | Missing trusted proxy header validation middleware |
| 4.1.4 | HTTP Method Restriction | ⚠️ Partial | StaticFiles mount does not explicitly reject unsupported HTTP methods with 405 |
| 4.1.5 | Per-Message Digital Signatures | ❌ Fail | No per-message digital signatures for highly sensitive operations |
| 4.2.1 | HTTP Request Smuggling Prevention | ⚠️ Partial | Protocol translation boundary in WSGIMiddleware creates request smuggling risk |
| 4.2.2 | Content-Length Header Validation | ✅ Pass | FastAPI framework validates Content-Length |
| 4.2.3 | Connection-Specific Headers in HTTP/2 and HTTP/3 | ⚠️ Partial | Missing trusted proxy header validation middleware |
| 4.2.4 | CRLF in HTTP/2 and HTTP/3 Headers | ⚠️ Partial | Missing trusted proxy header validation middleware |
| 4.2.5 | Overly Long URIs and Header Fields | ❌ Fail | Missing trusted proxy header validation middleware |
| 4.4.2 | Origin Header Validation During WebSocket Handshake | ⚠️ Partial | CORSMiddleware does not protect WebSocket connections |
| **12. TLS Configuration** |
| 12.1.1 | TLS Protocol Versions | ❌ Fail | Primary nginx documentation example lacks TLS configuration |
| 12.1.2 | Cipher Suite Configuration | ❌ Fail | Missing cipher suite configuration in reverse proxy documentation |
| 12.1.3 | mTLS Client Certificate Validation | ❌ Fail | Missing mTLS client certificate validation guidance |
| 12.1.4 | Certificate Revocation (OCSP Stapling) | ❌ Fail | Missing OCSP stapling configuration in deployment documentation |
| 12.1.5 | Encrypted Client Hello (ECH) | ❌ Fail | No guidance on enabling ECH in deployment documentation |
| 12.2.1 | TLS for All External-Facing HTTP Connectivity | ❌ Fail | Primary nginx documentation example lacks TLS configuration |
| 12.2.2 | HTTPS Communication with External Facing Services | ❌ Fail | Primary nginx documentation example lacks TLS configuration |
| 12.3.1 | Encrypted Protocol for All Connections | ❌ Fail | JWKS endpoint supports unencrypted HTTP |
| 12.3.2 | TLS Certificate Validation | ❌ Fail | No certificate validation documented for worker HTTP client |
| 12.3.3 | TLS for Internal HTTP Services | ❌ Fail | JWKS endpoint supports unencrypted HTTP |
| 12.3.4 | Trusted Certificates for Internal TLS | ❌ Fail | No certificate validation documented for worker HTTP client |
| 12.3.5 | General Service to Service Communication Security | ❌ Fail | No guidance on authenticated internal communications between proxy and backend |
| **13. Configuration and Deployment** |
| 13.1.1 | Configuration Documentation - Communication Needs | ❌ Fail | Incomplete documentation of all communication needs |
| 13.1.2 | Configuration Documentation - Connection Limits | ❌ Fail | No documentation of maximum concurrent connection limits or executor queue depth limits |
| 13.1.3 | Configuration Documentation - Resource Management Strategies | ❌ Fail | No documentation of resource-management strategies including timeouts and retry logic |
| 13.1.4 | Configuration Documentation - Secrets Definition and Rotation | ❌ Fail | No documentation of critical secrets or rotation schedules |
| 13.2.1 | Authenticated Backend Communication | ⚠️ Partial | InProcess Execution API bypasses JWT authentication entirely |
| 13.2.2 | Least Privilege for Backend Communications | ✅ Pass | Token scoping architecture (workload vs execution) |
| 13.2.3 | Backend Communication - No Default Credentials | ✅ Pass | No hardcoded default accounts when all_admins is False |
| 13.2.4 | Backend Communication - Outbound Communication Allowlist | ❌ Fail | No application-layer allowlist for outbound communication destinations |
| 13.2.5 | Backend Communication Allowlist Configuration | ❌ Fail | No documented allowlist mechanism for outbound connections from triggers and task execution |
| 13.2.6 | Backend Connection Configuration Documentation | ⚠️ Partial | Incomplete documentation of connection configuration parameters |
| 13.3.1 | Secrets Management Solution | ⚠️ Partial | Database connection credentials in documentation examples without security warning |
| 13.3.2 | Least Privilege Access to Secrets | ⚠️ Partial | No documented least privilege controls for secrets access |
| 13.3.3 | Isolated Security Module for Cryptographic Operations | ⚠️ Partial | Cryptographic operations performed in-process without isolated security module |
| 13.3.4 | Secrets Expiration and Rotation | ⚠️ Partial | Secrets backend documentation lacks TTL/expiration guidance |
| 13.4.2 | Debug Modes Disabled in Production | ⚠️ Partial | SQLAlchemy debug logging lacks programmatic production guard-rails |
| 13.4.5 | Documentation and Monitoring Endpoints Not Exposed | ⚠️ Partial | Internal architecture documentation may be exposed in production |
| 13.4.6 | Backend Component Version Information Not Exposed | ⚠️ Partial | Internal architecture documentation may be exposed in production |
| 13.4.7 | Unintended Information Leakage - File Extension Filtering | ⚠️ Partial | Internal architecture documentation may be exposed in production |
| **14. Data Protection** |
| 14.1.1 | Sensitive Data Identification and Classification | ⚠️ Partial | Incomplete data sensitivity classification schema; XCom side-channel not classified |
| 14.1.2 | Documented Protection Requirements per Sensitivity Level | ❌ Fail | No documented protection requirements per sensitivity level |
| 14.2.2 | Preventing Sensitive Data Caching | ⚠️ Partial | No documentation of cache protection for sensitive data |
| 14.2.3 | Sensitive Data Not Sent to Untrusted Parties | ⚠️ Partial | Documented environment variable exposure to external processes |
| 14.2.4 | General Data Protection - Sensitive Data Controls | ⚠️ Partial | Database connection documentation omits TLS/SSL configuration |
| 14.2.6 | General Data Protection - Minimum Sensitive Data | ✅ Pass | Structured authorization model with inspectable context |
| 14.2.7 | General Data Protection - Data Retention Classification | ⚠️ Partial | No defined automatic retention schedule for sensitive metadata |
| 16.2.5 | General Logging - Sensitive Data Logging Controls | ✅ Pass | Masking functionality for sensitive data in logs |
| **16. Logging and Monitoring** |
| 16.1.1 | Security Logging Documentation | ⚠️ Partial | Incomplete technology stack layer mapping in logging inventory; log retention policy lacks specific enforceable durations |
| 16.2.1 | General Logging - Metadata Requirements | ⚠️ Partial | Missing "where" metadata in audit log schema; CLI event metadata lacks documented structure |
| 16.2.2 | General Logging - Time Synchronization | ⚠️ Partial | No documentation of time synchronization requirements |
| 16.2.3 | General Logging - Log Destination Control | ⚠️ Partial | No documented mechanism to verify logs are only sent to inventoried destinations |
| 16.2.4 | General Logging - Common Format and Correlation | ⚠️ Partial | No documented common logging format standard or correlation mechanism; event log format not documented for machine readability |
| 16.3.1 | Security Events - Authentication Logging | ❌ Fail | Authentication events not documented in event catalog |
| 16.3.2 | Failed Authorization Attempts Logging | ❌ Fail | No documented authorization failure events; no documentation of sensitive data access logging |
| 16.3.3 | Security Event and Bypass Attempt Logging | ❌ Fail | No documented events for security control bypass attempts |
| 16.3.4 | Unexpected Error and Security Control Failure Logging | ❌ Fail | No documented events for security infrastructure failures; event logs vs audit logs distinction creates blind spots |
| 16.4.1 | Log Injection Prevention via Encoding | ⚠️ Partial | No documentation of log encoding or injection prevention measures |
| 16.4.2 | Log Protection from Unauthorized Access and Modification | ❌ Fail | Event log file protection not documented |
| 16.4.3 | Secure Log Transmission to Separate System | ❌ Fail | External log transmission documented as optional without security requirements |
| 16.5.1 | Error Handling - Generic Error Messages | ⚠️ Partial | Potential information disclosure through unhandled template rendering errors |
| 16.5.2 | Error Handling - Secure Operation When External Resources Fail | ⚠️ Partial | No graceful degradation for template filesystem dependency; no graceful handling of auth manager middleware initialization failure |
| 16.5.3 | Error Handling - Fail Gracefully and Securely | ✅ Pass | Fail-secure batch operations |
| 16.5.4 | Error Handling - Last Resort Error Handler | ⚠️ Partial | Last-resort error handler coverage cannot be verified |
| **15. Third-Party Components and Dependencies** |
| 15.1.1 | Risk-Based Remediation Timeframes for 3rd Party Components | ❌ Fail | Auth manager documentation does not reference remediation timeframes for provider dependencies |
| 15.1.2 | SBOM and Inventory Catalog of Third-Party Libraries | ⚠️ Partial | No SBOM reference or dependency inventory for auth manager provider ecosystem |
| 15.1.3 | Documentation of Resource-Demanding Functionality | ⚠️ Partial | Token refresh middleware resource impact not documented |
| 15.1.4 | Documentation Highlighting 'Risky Components' | ⚠️ Partial | No risk classification of auth manager provider dependencies |
| 15.1.5 | Documentation Highlighting Dangerous Functionality | ⚠️ Partial | Dangerous functionality in auth managers not explicitly highlighted |
| 15.2.1 | Components Within Documented Update Timeframes | ⚠️ Partial | No mechanism documented to verify auth manager provider versions are current |
| 15.2.2 | Defenses Against Loss of Availability Due to Resource-Demanding Functionality | ⚠️ Partial | Batch authorization methods lack documented size constraints; no documented resource constraints for custom auth manager initialization |
| 15.2.3 | Production Environment Functionality | ⚠️ Partial | Documentation includes development-only configurations without clear production exclusion mechanism |
| 15.2.4 | Dependency Confusion Prevention | ⚠️ Partial | Documentation references external downloads without integrity verification guidance |
| 15.2.5 | Additional Protections Around Dangerous Functionality and Risky Components | ⚠️ Partial | Auth manager plugin system lacks sandboxing or encapsulation |
| 15.4.2 | Safe Concurrency - TOCTOU Prevention via Atomic Operations | ⚠️ Partial | Password file uses exclusive file locking |
| 15.4.3 | Safe Concurrency - Consistent Lock Usage and Deadlock Prevention | ⚠️ Partial | Documented deadlock risk with MariaDB |
| 15.4.4 | Safe Concurrency - Fair Resource Allocation and Thread Starvation Prevention | ⚠️ Partial | Documented priority inversion and potential scheduler starvation |

**Legend:**
- ✅ **Pass**: Requirement is met with documented evidence
- ⚠️ **Partial**: Requirement is partially met or has gaps
- ❌ **Fail**: Requirement is not met
- ⚠️ **N/A**: Requirement is not applicable to this system

---

# 6. Cross-Reference Matrix

## Findings → ASVS Requirements

| Finding ID | Severity | ASVS Requirements |
|------------|----------|-------------------|
| FINDING-006 | High | 6.2.2 |
| FINDING-007 | High | 6.2.3 |
| FINDING-008 | High | 6.3.1 |
| FINDING-009 | High | 6.4.1, 11.4.2 |
| FINDING-010 | High | 6.4.1 |
| FINDING-011 | High | 6.3.3 |
| FINDING-012 | High | 7.4.3 |
| FINDING-013 | High | 7.4.4, 7.5.2 |
| FINDING-014 | High | 7.5.2 |
| FINDING-015 | High | 8.1.2 |
| FINDING-016 | High | 8.2.3 |
| FINDING-017 | High | 7.5.3 |
| FINDING-018 | High | 8.2.4, 8.4.2 |
| FINDING-019 | High | 4.1.3, 4.1.2, 4.2.5, 4.2.3, 4.2.4 |
| FINDING-020 | High | 16.3.1, 16.3.3 |
| FINDING-021 | High | 16.3.2 |
| FINDING-022 | High | 16.3.3 |
| FINDING-023 | High | 16.3.4 |
| FINDING-024 | High | 3.2.1, 3.4.4 |
| FINDING-025 | High | 3.3.1 |
| FINDING-026 | High | 3.4.1, 3.7.4 |
| FINDING-027 | High | 3.4.3, 3.4.6, 3.4.7 |
| FINDING-028 | High | 12.1.1, 12.2.1, 12.2.2 |
| FINDING-029 | High | 13.1.3 |
| FINDING-030 | High | 13.1.4 |
| FINDING-031 | High | 10.3.5 |
| FINDING-032 | Medium | 11.6.1 |
| FINDING-033 | Medium | 9.2.2 |
| FINDING-034 | Medium | 9.2.3, 9.2.4 |
| FINDING-035 | Medium | 6.2.1 |
| FINDING-036 | Medium | 6.2.11 |
| FINDING-037 | Medium | 6.2.12, 6.2.4 |
| FINDING-038 | Medium | 6.3.2 |
| FINDING-039 | Medium | 6.4.1, 6.4.4 |
| FINDING-040 | Medium | 6.4.3 |
| FINDING-041 | Medium | 7.3.1 |
| FINDING-042 | Medium | 7.5.1 |
| FINDING-043 | Medium | 7.5.2 |
| FINDING-044 | Medium | 7.2.4 |
| FINDING-045 | Medium | 6.1.3 |
| FINDING-046 | Medium | 7.1.3 |
| FINDING-047 | Medium | 7.1.3 |
| FINDING-048 | Medium | 8.1.1 |
| FINDING-049 | Medium | 8.2.1 |
| FINDING-050 | Medium | 7.1.1 |
| FINDING-051 | Medium | 7.1.2 |
| FINDING-052 | Medium | 7.4.5 |
| FINDING-053 | Medium | 7.5.3 |
| FINDING-054 | Medium | 7.6.1 |
| FINDING-055 | Medium | 8.1.3, 8.1.4 |
| FINDING-056 | Medium | 8.3.2 |
| FINDING-057 | Medium | 8.3.3 |
| FINDING-058 | Medium | 8.4.1 |
| FINDING-059 | Medium | 8.4.2 |
| FINDING-060 | Medium | 2.2.2 |
| FINDING-061 | Medium | 2.2.2 |
| FINDING-062 | Medium | 4.1.5 |
| FINDING-063 | Medium | 12.3.1, 12.3.3 |
| FINDING-064 | Medium | 12.3.2, 12.3.4 |
| FINDING-065 | Medium | 13.2.4 |
| FINDING-066 | Medium | 13.3.3 |
| FINDING-067 | Medium | 14.2.4 |
| FINDING-068 | Medium | 14.2.7 |
| FINDING-069 | Medium | 14.1.1 |
| FINDING-070 | Medium | 14.1.2 |
| FINDING-071 | Medium | 14.2.3 |
| FINDING-072 | Medium | 16.1.1 |
| FINDING-073 | Medium | 16.2.1 |
| FINDING-074 | Medium | 16.2.2 |
| FINDING-075 | Medium | 16.2.3 |
| FINDING-076 | Medium | 16.2.4 |
| FINDING-077 | Medium | 16.3.2 |
| FINDING-078 | Medium | 16.3.4 |
| FINDING-079 | Medium | 16.4.1 |
| FINDING-080 | Medium | 16.4.2 |
| FINDING-081 | Medium | 16.4.3 |
| FINDING-082 | Medium | 1.3.2 |
| FINDING-083 | Medium | 1.5.2 |
| FINDING-084 | Medium | 2.1.1 |
| FINDING-085 | Medium | 13.2.5 |
| FINDING-086 | Medium | 1.2.1, 1.2.3, 3.2.2 |
| FINDING-087 | Medium | 3.2.1 |
| FINDING-088 | Medium | 3.3.2, 3.5.1, 3.5.2 |
| FINDING-089 | Medium | 3.3.3 |
| FINDING-090 | Medium | 3.4.2 |
| FINDING-091 | Medium | 3.4.3, 3.1.1 |
| FINDING-092 | Medium | 3.4.5 |
| FINDING-093 | Medium | 3.4.8 |
| FINDING-094 | Medium | 3.5.4 |
| FINDING-095 | Medium | 3.7.2 |
| FINDING-096 | Medium | 3.7.3 |
| FINDING-097 | Medium | 3.7.5 |
| FINDING-098 | Medium | 10.4.5 |
| FINDING-099 | Medium | 10.4.8 |
| FINDING-100 | Medium | 6.8.1 |
| FINDING-101 | Medium | 12.1.2 |
| FINDING-102 | Medium | 12.1.3 |
| FINDING-103 | Medium | 12.2.1, 12.3.5, 3.1.1 |
| FINDING-104 | Medium | 12.2.1 |
| FINDING-105 | Medium | 12.3.5 |
| FINDING-106 | Medium | 13.1.1 |
| FINDING-107 | Medium | 13.1.2 |
| FINDING-108 | Medium | 13.1.2 |
| FINDING-109 | Medium | 13.4.5, 13.4.6, 13.4.7 |
| FINDING-110 | Medium | 15.2.3 |
| FINDING-111 | Medium | 15.1.5 |
| FINDING-112 | Medium | 15.2.2, 15.1.3 |
| FINDING-113 | Medium | 15.2.5 |
| FINDING-114 | Medium | 2.4.2 |
| FINDING-115 | Medium | 6.1.1 |
| FINDING-116 | Medium | 16.5.2 |
| FINDING-117 | Medium | 16.5.4 |
| FINDING-118 | Medium | 11.1.1, 13.3.4 |
| FINDING-119 | Medium | 11.1.2 |
| FINDING-120 | Medium | 11.1.3 |
| FINDING-121 | Medium | 11.1.4 |
| FINDING-122 | Medium | 4.4.2 |
| FINDING-123 | Medium | 15.4.3 |
| FINDING-124 | Medium | 1.2.9, 1.3.12 |
| FINDING-125 | Medium | 10.3.2 |
| FINDING-126 | Medium | 10.3.3 |
| FINDING-127 | Medium | 10.3.4 |
| FINDING-128 | Medium | 10.4.1 |
| FINDING-129 | Medium | 10.4.14, 10.7.3 |
| FINDING-130 | Medium | 10.5.1, 10.5.3 |
| FINDING-131 | Medium | 10.5.4, 10.5.2 |
| FINDING-132 | Medium | 10.5.5 |
| FINDING-133 | Medium | 6.3.4 |
| FINDING-134 | Medium | 6.3.4 |
| FINDING-135 | Medium | 6.3.4 |
| FINDING-136 | Medium | 6.3.4 |
| FINDING-137 | Medium | 6.4.4 |
| FINDING-138 | Medium | 6.4.4 |
| FINDING-139 | Medium | 6.4.4 |
| FINDING-140 | Low | 11.2.2 |
| FINDING-141 | Low | 11.5.1 |
| FINDING-142 | Low | 11.6.1 |
| FINDING-143 | Low | 11.6.1 |
| FINDING-144 | Low | 9.2.4 |
| FINDING-145 | Low | 6.2.6 |
| FINDING-146 | Low | 6.2.9 |
| FINDING-147 | Low | 6.1.3 |
| FINDING-148 | Low | 8.2.2 |
| FINDING-149 | Low | 8.4.1 |
| FINDING-150 | Low | 4.1.1 |
| FINDING-151 | Low | 4.1.4 |
| FINDING-152 | Low | 4.2.1 |
| FINDING-153 | Low | 13.2.1 |
| FINDING-154 | Low | 13.2.2 |
| FINDING-155 | Low | 13.3.1 |
| FINDING-156 | Low | 13.3.2 |
| FINDING-157 | Low | 14.2.7 |
| FINDING-158 | Low | 14.1.1 |
| FINDING-159 | Low | 14.1.2 |
| FINDING-160 | Low | 14.2.2 |
| FINDING-161 | Low | 16.1.1 |
| FINDING-162 | Low | 16.2.1 |
| FINDING-163 | Low | 16.2.4 |
| FINDING-164 | Low | 2.1.1 |
| FINDING-165 | Low | 2.1.1 |
| FINDING-166 | Low | 1.2.2 |
| FINDING-167 | Low | 3.4.4 |
| FINDING-168 | Low | 3.4.5 |
| FINDING-169 | Low | 3.4.6 |
| FINDING-170 | Low | 3.5.1, 3.3.4 |
| FINDING-171 | Low | 3.5.4 |
| FINDING-172 | Low | 3.5.7, 3.5.8 |
| FINDING-173 | Low | 3.7.4 |
| FINDING-174 | Low | 10.4.9 |
| FINDING-175 | Low | 6.7.1 |
| FINDING-176 | Low | 6.8.4 |
| FINDING-177 | Low | 12.1.4 |
| FINDING-178 | Low | 12.1.5 |
| FINDING-179 | Low | 13.2.6 |
| FINDING-180 | Low | 13.4.2 |
| FINDING-181 | Low | 15.2.4 |
| FINDING-182 | Low | 15.1.1 |
| FINDING-183 | Low | 15.1.2 |
| FINDING-184 | Low | 15.1.3 |
| FINDING-185 | Low | 15.1.4 |
| FINDING-186 | Low | 15.2.1 |
| FINDING-187 | Low | 15.2.2 |
| FINDING-188 | Low | 16.5.1 |
| FINDING-189 | Low | 16.5.2 |
| FINDING-190 | Low | 16.5.3 |
| FINDING-191 | Low | 11.1.1, 13.3.1 |
| FINDING-192 | Low | 11.2.4 |
| FINDING-193 | Low | 11.6.2 |
| FINDING-194 | Low | 15.4.4 |
| FINDING-195 | Low | 15.4.4 |
| FINDING-196 | Low | 10.2.1 |
| FINDING-197 | Low | 10.3.1 |
| FINDING-198 | Low | 10.3.3 |
| FINDING-199 | Low | 10.4.15 |
| FINDING-200 | Low | 10.4.16 |
| FINDING-201 | Low | 6.3.4 |
| FINDING-202 | Low | 6.3.4 |
| FINDING-203 | Low | 6.3.4 |
| FINDING-204 | Low | 6.3.4 |
| FINDING-205 | Low | 6.4.4 |

## ASVS Requirements → Findings

| ASVS ID | Requirement | Related Findings |
|---------|-------------|------------------|
| 11.4.2 | Password Hashing and Key Derivation Functions | FINDING-009 |
| 6.3.1 | Controls to prevent credential stuffing and password brute force | FINDING-008 |
| 7.4.1 | Session Termination - Disallow Further Session Use | |
| 7.4.2 | Session Termination - Account Disable/Delete | |
| 6.2.2 | Users Can Change Their Password | FINDING-006 |
| 6.2.3 | Password Change Requires Current and New Password | FINDING-007 |
| 6.4.1 | System generated initial passwords | FINDING-009, FINDING-010, FINDING-039 |
| 6.3.3 | Multi-factor authentication | FINDING-011 |
| 7.4.3 | Session Termination - After Authentication Factor Change | FINDING-012 |
| 7.4.4 | Session Termination - Easy Access to Logout | FINDING-013 |
| 7.5.2 | Defenses Against Session Abuse | FINDING-013, FINDING-014, FINDING-043 |
| 8.1.2 | Authorization Documentation (Field-Level) | FINDING-015 |
| 8.2.3 | General Authorization Design (Field-Level) | FINDING-016 |
| 7.5.3 | Step-up Authentication for Sensitive Operations | FINDING-017, FINDING-053 |
| 8.2.4 | Adaptive Security Controls Implementation | FINDING-018 |
| 8.4.2 | Administrative Interface Multi-Layer Security | FINDING-018, FINDING-059 |
| 4.1.3 | Intermediary Header Override Protection | FINDING-019 |
| 4.1.2 | HTTP to HTTPS Redirect Behavior | FINDING-019 |
| 4.2.5 | Overly Long URIs and Header Fields | FINDING-019 |
| 4.2.3 | Connection-Specific Headers in HTTP/2 and HTTP/3 | FINDING-019 |
| 4.2.4 | CRLF in HTTP/2 and HTTP/3 Headers | FINDING-019 |
| 16.3.1 | Security Events - Authentication Logging | FINDING-020 |
| 16.3.3 | Security Event and Bypass Attempt Logging | FINDING-020, FINDING-022 |
| 16.3.2 | Failed Authorization Attempts Logging | FINDING-021, FINDING-077 |
| 16.3.4 | Unexpected Error and Security Control Failure Logging | FINDING-023, FINDING-078 |
| 3.2.1 | Unintended Content Interpretation | FINDING-024, FINDING-087 |
| 3.4.4 | X-Content-Type-Options Header | FINDING-024, FINDING-167 |
| 3.3.1 | Cookie Secure Attribute | FINDING-025 |
| 3.4.1 | Strict-Transport-Security (HSTS) Header | FINDING-026 |
| 3.7.4 | HSTS Preload | FINDING-026, FINDING-173 |
| 3.4.3 | Content-Security-Policy Header | FINDING-027, FINDING-091 |
| 3.4.6 | Content-Security-Policy frame-ancestors Directive | FINDING-027, FINDING-169 |
| 3.4.7 | CSP Violation Reporting | FINDING-027 |
| 12.1.1 | TLS Protocol Versions | FINDING-028 |
| 12.2.1 | TLS for All External-Facing HTTP Connectivity | FINDING-028, FINDING-103, FINDING-104 |
| 12.2.2 | HTTPS Communication with External Facing Services | FINDING-028 |
| 13.1.3 | Configuration Documentation - Resource Management Strategies | FINDING-029 |
| 13.1.4 | Configuration Documentation - Secrets Definition and Rotation | FINDING-030 |
| 10.3.5 | Sender-Constrained Access Tokens | FINDING-031 |
| 11.6.1 | Public Key Cryptography | FINDING-032, FINDING-142, FINDING-143 |
| 9.2.2 | Token content - Token type validation | FINDING-033 |
| 9.2.3 | Token content - Audience validation | FINDING-034 |
| 9.2.4 | Token Audience Restriction | FINDING-034, FINDING-144 |
| 6.2.1 | Password Minimum Length | FINDING-035 |
| 6.2.11 | Context-Specific Word Checking | FINDING-036 |
| 6.2.12 | Breached Password Checking | FINDING-037 |
| 6.2.4 | Passwords Checked Against Common Password List | FINDING-037 |
| 6.3.2 | Default user accounts | FINDING-038 |
| 6.4.4 | Authentication Factor Lifecycle and Recovery | FINDING-039, FINDING-137, FINDING-138, FINDING-139, FINDING-205 |
| 6.4.3 | Secure password reset process | FINDING-040 |
| 7.3.1 | Inactivity Timeout | FINDING-041 |
| 7.5.1 | Defenses Against Session Abuse - Re-authentication for Sensitive Changes | FINDING-042 |
| 7.2.4 | New Token on Authentication and Session Termination | FINDING-044 |
| 6.1.3 | Authentication Documentation | FINDING-045, FINDING-147 |
| 7.1.3 | Session Management Documentation for Federated Identity Management | FINDING-046, FINDING-047 |
| 8.1.1 | Authorization Documentation | FINDING-048 |
| 8.2.1 | General Authorization Design (Function-Level) | FINDING-049 |
| 7.1.1 | Session Inactivity Timeout and Maximum Lifetime Documentation | FINDING-050 |
| 7.1.2 | Concurrent Session Documentation | FINDING-051 |
| 7.4.5 | Admin Session Termination | FINDING-052 |
| 7.6.1 | Federated Re-authentication | FINDING-054 |
| 8.1.3 | Authorization Documentation - Environmental/Contextual Attributes | FINDING-055 |
| 8.1.4 | Authorization Documentation - Environmental Factor Decision-Making | FINDING-055 |
| 8.3.2 | Immediate Application of Authorization Changes | FINDING-056 |
| 8.3.3 | Access Based on Originating Subject's Permissions | FINDING-057 |
| 8.4.1 | Multi-Tenant Cross-Tenant Controls | FINDING-058, FINDING-149 |
| 2.2.2 | Server-Side Input Validation | FINDING-060, FINDING-061 |
| 4.1.5 | Per-Message Digital Signatures | FINDING-062 |
| 12.3.1 | Encrypted Protocol for All Connections | FINDING-063 |
| 12.3.3 | TLS for Internal HTTP Services | FINDING-063 |
| 12.3.2 | TLS Certificate Validation | FINDING-064 |
| 12.3.4 | Trusted Certificates for Internal TLS | FINDING-064 |
| 13.2.4 | Backend Communication - Outbound Communication Allowlist | FINDING-065 |
| 13.3.3 | Isolated Security Module for Cryptographic Operations | FINDING-066 |
| 14.2.4 | General Data Protection - Sensitive Data Controls | FINDING-067 |
| 14.2.7 | General Data Protection - Data Retention Classification | FINDING-068, FINDING-157 |
| 14.1.1 | Sensitive Data Identification and Classification | FINDING-069, FINDING-158 |
| 14.1.2 | Documented Protection Requirements per Sensitivity Level | FINDING-070, FINDING-159 |
| 14.2.3 | Sensitive Data Not Sent to Untrusted Parties | FINDING-071 |
| 16.1.1 | Security Logging Documentation | FINDING-072, FINDING-161 |
| 16.2.1 | General Logging - Metadata Requirements | FINDING-073, FINDING-162 |
| 16.2.2 | General Logging - Time Synchronization | FINDING-074 |
| 16.2.3 | General Logging - Log Destination Control | FINDING-075 |
| 16.2.4 | General Logging - Common Format and Correlation | FINDING-076, FINDING-163 |
| 16.4.1 | Log Injection Prevention via Encoding | FINDING-079 |
| 16.4.2 | Log Protection from Unauthorized Access and Modification | FINDING-080 |
| 16.4.3 | Secure Log Transmission to Separate System | FINDING-081 |
| 1.3.2 | Sanitization — Dynamic Code Execution | FINDING-082 |
| 1.5.2 | Safe Deserialization | FINDING-083 |
| 2.1.1 | Validation and Business Logic Documentation - Input Validation Rules | FINDING-084, FINDING-164, FINDING-165 |
| 13.2.5 | Backend Communication Allowlist Configuration | FINDING-085 |
| 1.2.1 | Output Encoding for HTTP Response | FINDING-086 |
| 1.2.3 | JavaScript Content Encoding | FINDING-086 |
| 3.2.2 | Safe Text Rendering (createTextNode/textContent) | FINDING-086 |
| 3.3.2 | Cookie SameSite Attribute | FINDING-088 |
| 3.5.1 | Cross-Site Request Forgery (CSRF) Protection | FINDING-088, FINDING-170 |
| 3.5.2 | CORS Preflight Mechanism | FINDING-088 |
| 3.3.3 | Cookie __Host- Prefix | FINDING-089 |
| 3.4.2 | CORS Access-Control-Allow-Origin | FINDING-090 |
| 3.1.1 | Web Frontend Security Documentation | FINDING-091, FINDING-103 |
| 3.4.5 | Referrer-Policy Header | FINDING-092, FINDING-168 |
| 3.4.8 | Cross-Origin-Opener-Policy Header | FINDING-093 |
| 3.5.4 | Separate Applications on Different Hostnames | FINDING-094, FINDING-171 |
| 3.7.2 | Redirect Allowlist | FINDING-095 |
| 3.7.3 | Redirect Notification | FINDING-096 |
| 3.7.5 | Browser Security Feature Detection | FINDING-097 |
| 10.4.5 | Refresh Token Replay Attack Mitigation for Public Clients | FINDING-098 |
| 10.4.8 | Refresh Token Absolute Expiration | FINDING-099 |
| 6.8.1 | Identity Provider Spoofing Prevention | FINDING-100 |
| 12.1.2 | Cipher Suite Configuration | FINDING-101 |
| 12.1.3 | mTLS Client Certificate Validation | FINDING-102 |
| 12.3.5 | General Service to Service Communication Security | FINDING-103, FINDING-105 |
| 13.1.1 | Configuration Documentation - Communication Needs | FINDING-106 |
| 13.1.2 | Configuration Documentation - Connection Limits | FINDING-107, FINDING-108 |
| 13.4.5 | Documentation and Monitoring Endpoints Not Exposed | FINDING-109 |
| 13.4.6 | Backend Component Version Information Not Exposed | FINDING-109 |
| 13.4.7 | Unintended Information Leakage - File Extension Filtering | FINDING-109 |
| 15.2.3 | Production Environment Functionality | FINDING-110 |
| 15.1.5 | Documentation Highlighting Dangerous Functionality | FINDING-111 |
| 15.2.2 | Defenses Against Loss of Availability Due to Resource-Demanding Functionality | FINDING-112, FINDING-187 |
| 15.1.3 | Documentation of Resource-Demanding Functionality | FINDING-112, FINDING-184 |
| 15.2.5 | Additional Protections Around Dangerous Functionality and Risky Components | FINDING-113 |
| 2.4.2 | Anti-automation - Realistic Human Timing | FINDING-114 |
| 6.1.1 | Authentication Documentation - Rate Limiting and Anti-automation | FINDING-115 |
| 16.5.2 | Error Handling - Secure Operation When External Resources Fail | FINDING-116, FINDING-189 |
| 16.5.4 | Error Handling - Last Resort Error Handler | FINDING-117 |
| 11.1.1 | Cryptographic Key Management Policy | FINDING-118, FINDING-191 |
| 13.3.4 | Secrets Expiration and Rotation | FINDING-118 |
| 11.1.2 | Cryptographic Inventory | FINDING-119 |
| 11.1.3 | Cryptographic Discovery Mechanisms | FINDING-120 |
| 11.1.4 | PQC Migration Plan | FINDING-121 |
| 4.4.2 | Origin Header Validation During WebSocket Handshake | FINDING-122 |
| 15.4.3 | Safe Concurrency - Consistent Lock Usage and Deadlock Prevention | FINDING-123 |
| 1.2.9 | Injection Prevention - Regex Metacharacter Escaping | FINDING-124 |
| 1.3.12 | Sanitization - ReDoS Prevention | FINDING-124 |
| 10.3.2 | Resource Server Enforces Claims-Based Authorization | FINDING-125 |
| 10.3.3 | Resource Server Identifies Users from Non-Reassignable Claims | FINDING-126, FINDING-198 |
| 10.3.4 | Authentication Strength Verification | FINDING-127 |
| 10.4.1 | Redirect URI Validation | FINDING-128 |
| 10.4.14 | Sender-Constrained Access Tokens | FINDING-129 |
| 10.7.3 | Consent Management - User Review, Modification, and Revocation | FINDING-129 |
| 10.5.1 | ID Token Replay Mitigation (Nonce) | FINDING-130 |
| 10.5.3 | Issuer URL Validation | FINDING-130 |
| 10.5.4 | OIDC Client - ID Token Audience Validation | FINDING-131 |
| 10.5.2 | Unique User Identification from ID Token | FINDING-131 |
| 10.5.5 | OIDC Client - Back-Channel Logout Token Validation | FINDING-132 |
| 6.3.4 | Multiple Authentication Pathways | FINDING-133, FINDING-134, FINDING-135, FINDING-136, FINDING-201, FINDING-202, FINDING-203, FINDING-204 |
| 11.2.2 | Crypto Agility | FINDING-140 |
| 11.5.1 | CSPRNG with 128 Bits of Entropy | FINDING-141 |
| 6.2.6 | Password Input Fields Use type=password | FINDING-145 |
| 6.2.9 | Passwords of at Least 64 Characters Permitted | FINDING-146 |
| 8.2.2 | General Authorization Design (Data-Specific) | FINDING-148 |
| 4.1.1 | Content-Type Header with Charset | FINDING-150 |
| 4.1.4 | HTTP Method Restriction | FINDING-151 |
| 4.2.1 | HTTP Request Smuggling Prevention | FINDING-152 |
| 13.2.1 | Authenticated Backend Communication | FINDING-153 |
| 13.2.2 | Least Privilege for Backend Communications | FINDING-154 |
| 13.3.1 | Secrets Management Solution | FINDING-155, FINDING-191 |
| 13.3.2 | Least Privilege Access to Secrets | FINDING-156 |
| 14.2.2 | Preventing Sensitive Data Caching | FINDING-160 |
| 1.2.2 | URL Encoding for Dynamic URLs | FINDING-166 |
| 3.3.4 | Cookie HttpOnly Attribute | FINDING-170 |
| 3.5.7 | Authorization Data Not in Script Resources | FINDING-172 |
| 3.5.8 | Authenticated Resource Protection | FINDING-172 |
| 10.4.9 | Token Revocation by Authorized User | FINDING-174 |
| 6.7.1 | Certificate Storage Protection | FINDING-175 |
| 6.8.4 | Authentication Strength Verification from IdP | FINDING-176 |
| 12.1.4 | Certificate Revocation (OCSP Stapling) | FINDING-177 |
| 12.1.5 | Encrypted Client Hello (ECH) | FINDING-178 |
| 13.2.6 | Backend Connection Configuration Documentation | FINDING-179 |
| 13.4.2 | Debug Modes Disabled in Production | FINDING-180 |
| 15.2.4 | Dependency Confusion Prevention | FINDING-181 |
| 15.1.1 | Risk-Based Remediation Timeframes for 3rd Party Components | FINDING-182 |
| 15.1.2 | SBOM and Inventory Catalog of Third-Party Libraries | FINDING-183 |
| 15.1.4 | Documentation Highlighting 'Risky Components' | FINDING-185 |
| 15.2.1 | Components Within Documented Update Timeframes | FINDING-186 |
| 16.5.1 | Error Handling - Generic Error Messages | FINDING-188 |
| 16.5.3 | Error Handling - Fail Gracefully and Securely | FINDING-190 |
| 11.2.4 | Constant-time Operations | FINDING-192 |
| 11.6.2 | Approved Cryptographic Algorithms for Key Exchange | FINDING-193 |
| 15.4.4 | Safe Concurrency - Fair Resource Allocation and Thread Starvation Prevention | FINDING-194, FINDING-195 |
| 10.2.1 | OAuth Client CSRF Protection (PKCE/State) | FINDING-196 |
| 10.3.1 | Resource Server Validates Access Token Audience | FINDING-197 |
| 10.4.15 | Authorization Details Integrity (PAR/JAR) | FINDING-199 |
| 10.4.16 | Strong Client Authentication | FINDING-200 |

## 7. Level Coverage Analysis


**Audit scope:** up to L3

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 41 |
| L2 | 183 | 140 |
| L3 | 92 | 110 |

**Total consolidated findings: 205**

*End of Consolidated Security Audit Report*
