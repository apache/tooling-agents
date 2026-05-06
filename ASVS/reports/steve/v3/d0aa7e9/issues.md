# Security Issues

## Issue: FINDING-008 - No Crypto Agility - Algorithms Hardcoded Without Abstraction or Versioning
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application has no crypto-agility design. All crypto operations directly call specific implementations with hardcoded parameters. There's no configuration, registry, or strategy pattern that would allow swapping algorithms.

### Details
Specific issues: (1) No algorithm abstraction layer, (2) No algorithm versioning in stored data - the vote table stores ciphertext without any algorithm identifier, (3) No key versioning, (4) No re-encryption mechanism, (5) Fixed key lengths in schema - database CHECK constraints enforce exact lengths preventing algorithm changes without schema migration.

**ASVS:** 11.2.2 (L2)

**Affected Files:**
- `v3/steve/crypto.py` (entire file)
- `v3/schema.sql`

### Remediation
1. Add algorithm version to stored ciphertext:
```sql
CREATE TABLE vote (
    vid INTEGER PRIMARY KEY AUTOINCREMENT,
    vote_token BLOB NOT NULL,
    crypto_version INTEGER NOT NULL DEFAULT 1,
    ciphertext BLOB NOT NULL
) STRICT;
```

2. Implement a crypto abstraction layer with CRYPTO_VERSIONS dictionary mapping version numbers to algorithm configurations (kdf, hash, encrypt, key_stretch).

3. Modify create_vote() to return (version, ciphertext) tuple and decrypt_votestring() to accept version parameter.

4. Provide a re-encryption utility for migration.

### Acceptance Criteria
- [ ] Algorithm version field added to vote table
- [ ] Crypto abstraction layer implemented
- [ ] create_vote() returns version information
- [ ] decrypt_votestring() accepts version parameter
- [ ] Re-encryption utility created
- [ ] Test added for multi-version support

### References
- Source reports: 11.2.2.md

### Priority
**High** - Future algorithm changes will be difficult or impossible

---

## Issue: FINDING-009 - Non-constant-time Comparison in Tamper Check Allows Timing Oracle
**Labels:** bug, security, priority:high
**Description:**
### Summary
Python's != operator on bytes objects performs a short-circuit comparison that returns False as soon as the first differing byte is found. An attacker who can observe response timing could potentially determine how many leading bytes of the opened_key match, gradually reconstructing the stored key.

### Details
The opened_key is derived from election data and serves as the anti-tamper seal; leaking it could allow an attacker to forge tamper checks.

**ASVS:** 11.2.4 (L3)

**Affected Files:**
- `v3/steve/election.py:331`

### Remediation
Use hmac.compare_digest() for constant-time comparison. Replace `return opened_key != md.opened_key` with `return not hmac.compare_digest(opened_key, md.opened_key)`.

### Acceptance Criteria
- [ ] hmac.compare_digest() used for tamper check comparison
- [ ] Test added for tamper detection
- [ ] Test added for valid tamper check

### References
- Source reports: 11.2.4.md

### Priority
**High** - Timing oracle could leak tamper check key

---

## Issue: FINDING-010 - Authorization decisions do not consider delegated authorization claims
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application establishes sessions from OAuth tokens and then makes authorization decisions solely based on the `uid` extracted from the session and role memberships (committer, pmc_member). There is no evidence that OAuth scopes or `authorization_details` claims are evaluated during authorization decisions.

### Details
The session data structure only captures `uid`, `fullname`, and `email` — no scope or delegation information is preserved from the access token. If the OAuth client was granted limited scopes (e.g., read-only access), the resource server would not enforce those limitations. Any valid authenticated session grants full access within the role, regardless of what the resource owner actually delegated.

**ASVS:** 10.3.2 (L2)

**Affected Files:**
- `v3/server/pages.py:63-93`

### Remediation
Preserve OAuth token claims (scope, authorization_details) in the session during establishment. Modify basic_info() to include scope and authorization_details in the session data structure. Implement scope-based authorization decorators that verify required scopes before allowing access to endpoints.

Example: Create a require_scope() decorator that checks if the required scope is present in the user's token claims before executing the endpoint logic. Store scope as a space-separated string and authorization_details as a list in the session.

### Acceptance Criteria
- [ ] OAuth scope preserved in session
- [ ] authorization_details preserved in session
- [ ] Scope-based authorization decorator implemented
- [ ] Test added for scope enforcement
- [ ] Test added for insufficient scope rejection

### References
- Source reports: 10.3.2.md

### Priority
**High** - OAuth delegation claims not enforced

---

## Issue: FINDING-011 - Multiple endpoints have placeholder authorization checks - ownership not enforced
**Labels:** bug, security, priority:high
**Description:**
### Summary
Function-level authorization is NOT enforced for election management operations. The owner_pid and authz group checks are documented as required in the schema but are not implemented—all endpoints contain '### check authz' TODO comments but no actual authorization logic.

### Details
This is a Type B gap: the authorization model EXISTS in the schema/documentation (owner_pid and authz fields) but is NOT CALLED at any management endpoint. Any authenticated committer can view, open, close, add issues to, edit issues on, delete issues from, and modify dates on any election they don't own. This affects all 11 administrative endpoints that use the @load_election decorator.

**CWE:** CWE-862  
**ASVS:** 10.3.2, 8.2.1, 8.3.1, 8.4.2, 8.2.2, 2.3.2 (L1, L2, L3)

**Affected Files:**
- `v3/server/pages.py:487`
- `v3/server/pages.py:508`
- `v3/server/pages.py:420`
- `v3/server/pages.py:527`
- `v3/server/pages.py:552`
- `v3/server/pages.py:576`
- `v3/server/pages.py:467`
- `v3/server/pages.py:351`
- `v3/server/pages.py:193`

### Remediation
Implement check_election_authz() function to verify the current user is authorized to manage the election by checking owner_pid match or authz group membership via LDAP. Add this check to the load_election decorator before allowing access to management functions.

Example:
```python
async def check_election_authz(election, uid):
    md = election.get_metadata()
    if md.owner_pid == uid:
        return True
    if md.authz:
        if await check_ldap_group_membership(uid, md.authz):
            return True
    return False
```

Then in load_election decorator:
```python
if not await check_election_authz(e, result.uid):
    quart.abort(403)
```

### Acceptance Criteria
- [ ] check_election_authz() function implemented
- [ ] Authorization check added to load_election decorator
- [ ] LDAP group membership check implemented
- [ ] Test added for owner access
- [ ] Test added for authz group member access
- [ ] Test added for unauthorized access rejection

### References
- Source reports: 10.3.2.md, 8.2.1.md, 8.3.1.md, 8.4.2.md, 8.2.2.md, 2.3.2.md

### Priority
**High** - Complete absence of ownership-based authorization

---

## Issue: FINDING-012 - No PKCE Parameters in OAuth Authorization Request or Token Exchange
**Labels:** bug, security, priority:high
**Description:**
### Summary
The authorization URL template (OAUTH_URL_INIT) contains state and redirect_uri but no code_challenge or code_challenge_method parameters. The token exchange URL template (OAUTH_URL_CALLBACK) contains only code but no code_verifier parameter. There is no evidence of PKCE code verifier generation or storage anywhere in the codebase.

### Details
Even if the ASF OAuth server supports PKCE, the client is not sending the required parameters, which means PKCE protection is not active for this application. An attacker who intercepts the authorization code (e.g., via a malicious browser extension, open redirect, or referrer leakage) can exchange it directly at the token endpoint without needing to prove possession of the original code verifier.

**ASVS:** 10.4.6 (L2)

**Affected Files:**
- `v3/server/main.py:38-42`

### Remediation
Implement PKCE by generating a code verifier and code challenge. Update OAuth URL templates to include code_challenge and code_challenge_method=S256 in authorization requests, and code_verifier in token exchange requests.

Example: Generate code_verifier using `base64.urlsafe_b64encode(os.urandom(32))`, compute code_challenge using SHA256 hash of the verifier, and include these parameters in the OAuth URLs.

### Acceptance Criteria
- [ ] PKCE code verifier generation implemented
- [ ] code_challenge parameter added to authorization request
- [ ] code_verifier parameter added to token exchange
- [ ] Test added for PKCE flow
- [ ] Code verifier stored securely in session

### References
- Source reports: 10.4.6.md

### Priority
**High** - Authorization code interception vulnerability

---

## Issue: FINDING-013 - Missing nonce parameter in OIDC authorization request enables ID Token replay attacks
**Labels:** bug, security, priority:high
**Description:**
### Summary
The authorization request URL template includes only 'state' and 'redirect_uri' parameters. There is no 'nonce' parameter included in the authorization request.

### Details
Per the OIDC specification (Section 3.1.2.1), the 'nonce' value should be: 1) Generated as a cryptographically random value, 2) Sent in the authorization request, 3) Stored in the session, 4) Validated against the 'nonce' claim in the received ID Token. Without a nonce, the client cannot detect if an ID Token is being replayed from a previous authentication session. The 'state' parameter prevents CSRF but does NOT protect against ID Token replay.

**ASVS:** 10.5.1 (L2)

**Affected Files:**
- `v3/server/main.py:39-41`

### Remediation
Generate a cryptographically random nonce value using secrets.token_urlsafe(32), store it in the session, include it in the authorization request URL, and validate it against the nonce claim in the received ID Token during the callback handler.

Example:
```python
nonce = secrets.token_urlsafe(32)
session['oauth_nonce'] = nonce
asfquart.generics.OAUTH_URL_INIT = 'https://oauth.apache.org/auth?state=%s&redirect_uri=%s&nonce=%s'
```

In the callback handler:
```python
id_token_claims = decode_id_token(token_response)
if id_token_claims['nonce'] != session.pop('oauth_nonce'):
    abort(401, 'ID Token nonce mismatch - possible replay attack')
```

### Acceptance Criteria
- [ ] Nonce generation implemented
- [ ] Nonce stored in session
- [ ] Nonce included in authorization request
- [ ] Nonce validation implemented in callback
- [ ] Test added for nonce mismatch rejection

### References
- Source reports: 10.5.1.md

### Priority
**High** - ID Token replay attacks possible

---

## Issue: FINDING-014 - Missing Audience (aud) Claim Validation in ID Token
**Labels:** bug, security, priority:high
**Description:**
### Summary
There is no client_id configuration visible anywhere in the provided source code. For audience validation to work: 1) The application must know its own client_id, 2) The received ID Token's aud claim must be compared against the client_id, 3) If the aud doesn't match, the token must be rejected.

### Details
Without visible client_id configuration or audience validation logic, the application cannot verify that an ID Token was issued specifically for this client. An attacker who obtains an ID Token issued for a different client registered with the same authorization server could potentially use it to authenticate to this application.

**ASVS:** 10.5.4, 9.2.3 (L2)

**Affected Files:**
- `v3/server/main.py:39-42`
- `v3/server/pages.py:82-90`

### Remediation
Configure expected audience in create_app():
```python
app.config['TOKEN_AUDIENCE'] = 'steve'
app.config['TOKEN_ISSUER'] = 'https://oauth.apache.org'
```

Implement token validation function:
```python
def validate_token_claims(token_payload):
    if 'aud' in token_payload:
        aud = token_payload['aud']
        if isinstance(aud, list):
            if EXPECTED_AUDIENCE not in aud:
                raise ValueError
        elif aud != EXPECTED_AUDIENCE:
            raise ValueError
```

### Acceptance Criteria
- [ ] client_id configured
- [ ] Audience validation implemented
- [ ] Issuer validation implemented
- [ ] Test added for valid audience acceptance
- [ ] Test added for invalid audience rejection

### References
- Source reports: 10.5.4.md, 9.2.3.md

### Priority
**High** - Token audience not validated

---

## Issue: FINDING-015 - Inconsistent Security Controls Across Privileged Endpoints
**Labels:** bug, security, priority:high
**Description:**
### Summary
While a single authentication pathway (OAuth) exists, security controls after authentication are not enforced consistently. Election creation requires R.pmc_member, but election management (opening, closing, modifying issues) only requires R.committer without ownership verification.

### Details
This creates a horizontal privilege escalation where any committer can manage any election, contradicting the owner_pid model established at creation. Authorization control concept EXISTS (comments prove design intent) but is NOT CALLED at any management endpoint.

**ASVS:** 6.3.4 (L2)

**Affected Files:**
- `v3/server/pages.py:484-591`

### Remediation
Verify the authenticated user is the election owner before allowing management operations. Check metadata.owner_pid against result.uid and return 403 if they don't match. Alternatively, create a separate load_owned_election decorator that verifies ownership before allowing modification.

### Acceptance Criteria
- [ ] Ownership verification implemented
- [ ] Consistent authorization checks across all management endpoints
- [ ] Test added for owner access
- [ ] Test added for non-owner access rejection

### References
- Source reports: 6.3.4.md

### Priority
**High** - Inconsistent authorization controls

---

## Issue: FINDING-016 - Cannot verify signature validation on OAuth token responses
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application delegates OAuth token exchange and session establishment to the `asfquart` framework. The critical signature validation step — verifying that the authentication assertion (JWT, token response) from `oauth.apache.org` is properly signed and has not been tampered with — occurs within the `asfquart` framework code which is not provided for audit.

### Details
From the provided code, we can observe: 1. The OAuth callback URL pattern suggests a simple authorization code exchange (`code=%s`) 2. No explicit JWT signature validation logic is present in the application code 3. The session is consumed in `pages.py` without any additional integrity checks. The comment in `main.py` line 37 (`### is this really needed right now? # Avoid OIDC`) suggests the application deliberately avoids OIDC, which would typically provide standardized signature validation via ID tokens.

**ASVS:** 6.8.2 (L2)

**Affected Files:**
- `v3/server/main.py:39-42`

### Remediation
1. Audit the `asfquart` framework's OAuth callback handler to verify signature validation
2. If using plain OAuth 2.0 (not OIDC), ensure the token endpoint response is only accepted over verified TLS and the authorization code is single-use
3. Consider adopting OIDC with proper ID token signature validation using libraries like python-jose to decode and verify JWT signatures.

### Acceptance Criteria
- [ ] Framework signature validation audited and documented
- [ ] OIDC adoption evaluated
- [ ] JWT signature validation implemented if using OIDC
- [ ] Test added for invalid signature rejection

### References
- Source reports: 6.8.2.md

### Priority
**High** - Signature validation not verifiable

---

## Issue: FINDING-017 - No verification of authentication strength, method, or recentness from IdP
**Labels:** bug, security, priority:high
**Description:**
### Summary
The session only stores and checks uid, fullname, and email. There is no evidence that the application: 1. Validates acr (Authentication Context Class Reference) claims 2. Validates amr (Authentication Methods References) claims 3. Validates auth_time to ensure recent authentication 4. Has any documented fallback approach for unknown authentication strength.

### Details
Sensitive operations in this application include: Creating elections, Opening/closing elections, Voting, Managing election issues. None of these operations verify that the user authenticated with a specific strength mechanism. The comment in main.py line 37 (### is this really needed right now? # Avoid OIDC) further confirms that OIDC claims (where acr, amr, auth_time would typically be found) are not being processed.

**ASVS:** 6.8.4 (L2)

**Affected Files:**
- `v3/server/pages.py:82-91`

### Remediation
Implement authentication strength verification for sensitive operations. Check authentication time (require auth within last 15 minutes for sensitive ops), validate acr claim, and document fallback approach if no acr claim is present. Track 'auth_time' in the session and enforce maximum session age for sensitive operations.

### Acceptance Criteria
- [ ] auth_time tracking implemented
- [ ] acr claim validation implemented
- [ ] amr claim validation implemented
- [ ] Step-up authentication for sensitive operations
- [ ] Test added for authentication strength enforcement

### References
- Source reports: 6.8.4.md

### Priority
**High** - No authentication strength verification

---

## Issue: FINDING-018 - No session timeout configuration or documentation present
**Labels:** bug, security, priority:high
**Description:**
### Summary
The provided code contains: 1. No session inactivity timeout configuration — sessions are read and used without checking last activity time. 2. No absolute maximum session lifetime — no expiration timestamp is validated. 3. No documentation of session timeout decisions or justifications for deviations from NIST SP 800-63B. 4. No reference to NIST SP 800-63B re-authentication requirements.

### Details
NIST SP 800-63B Section 4.1.3 specifies: Session inactivity timeout of 30 minutes for AAL1, Re-authentication at least every 12 hours for AAL1, Shorter timeouts for higher assurance levels. For an election system handling sensitive operations, the lack of session timeouts means: A session could persist indefinitely after a user walks away from their computer, No forced re-authentication protects against session theft that occurred hours/days ago.

**ASVS:** 7.1.1 (L2)

**Affected Files:**
- `v3/server/pages.py:82`
- `v3/server/main.py`

### Remediation
1. Document session timeout decisions with a Session Management Policy including: Inactivity Timeout of 30 minutes for general operations (NIST SP 800-63B AAL1 compliant) and 15 minutes for election management operations; Absolute Maximum Lifetime of 12 hours maximum session duration with re-authentication required for election creation/opening/closing.

2. Implement session timeout enforcement in the basic_info() function to check absolute timeout (12 hours), inactivity timeout (30 minutes), and update last activity timestamp on each request. Destroy session and abort with 401 if either timeout is exceeded.

### Acceptance Criteria
- [ ] Session timeout policy documented
- [ ] Inactivity timeout implemented (30 minutes)
- [ ] Absolute timeout implemented (12 hours)
- [ ] Last activity timestamp tracking implemented
- [ ] Test added for timeout enforcement
- [ ] Test added for session refresh on activity

### References
- Source reports: 7.1.1.md

### Priority
**High** - No session timeout enforcement

---

## Issue: FINDING-019 - No inactivity timeout configuration exists
**Labels:** bug, security, priority:high
**Description:**
### Summary
No inactivity timeout configuration exists in the application code. The `asfquart` framework is used for session management, but no session idle timeout is configured at the application level. The `basic_info()` function reads session data without checking any timestamp for last activity.

### Details
User authenticates via OAuth → Session established → No timestamp tracking → Session remains valid indefinitely regardless of inactivity. An attacker who obtains a session cookie (e.g., via physical access to an unattended workstation) can reuse it hours or days later since no inactivity timeout forces re-authentication.

**ASVS:** 7.3.1 (L2)

**Affected Files:**
- `v3/server/pages.py` (entire file)
- `v3/server/main.py:44-48`

### Remediation
Configure session timeout in app configuration (main.py create_app()):
```python
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=30)
app.config['SESSION_REFRESH_EACH_REQUEST'] = True
```

Alternatively, implement custom middleware with @APP.before_request decorator to check session timeout by tracking 'last_active' timestamp in session data.

### Acceptance Criteria
- [ ] Inactivity timeout configured (30 minutes)
- [ ] Last activity timestamp tracking implemented
- [ ] Session refresh on activity implemented
- [ ] Test added for timeout enforcement

### References
- Source reports: 7.3.1.md

### Priority
**High** - Sessions persist indefinitely

---

## Issue: FINDING-020 - No absolute maximum session lifetime configured
**Labels:** bug, security, priority:high
**Description:**
### Summary
No absolute maximum session lifetime is configured anywhere in the application code. The create_app() function in main.py constructs the application without setting any session lifetime limits.

### Details
User authenticates → Session created with no creation timestamp or max lifetime → Session persists until browser closes (or indefinitely if persistent cookies are used). A session token obtained through any means (XSS, cookie theft, network interception) remains valid indefinitely. Even if the OAuth token expires at the identity provider, the local application session continues without re-authentication.

**ASVS:** 7.3.2 (L2)

**Affected Files:**
- `v3/server/pages.py` (entire file)
- `v3/server/main.py:44-48`

### Remediation
In main.py create_app():
```python
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(hours=8)
```

Or implement session creation timestamp check using @APP.before_request decorator to check session age and destroy sessions exceeding MAX_SESSION_LIFETIME (e.g., 28800 seconds for 8 hours).

### Acceptance Criteria
- [ ] Absolute session lifetime configured (8 hours)
- [ ] Session creation timestamp tracking implemented
- [ ] Session expiration enforcement implemented
- [ ] Test added for absolute timeout enforcement

### References
- Source reports: 7.3.2.md

### Priority
**High** - Sessions have no maximum lifetime

---

## Issue: FINDING-021 - Active sessions not terminated when user accounts are disabled or deleted
**Labels:** bug, security, priority:high
**Description:**
### Summary
The LDAP loading script (asf-load-ldap.py) performs a full synchronization of user data from LDAP into the local database, but contains no logic to detect removed accounts or terminate their active sessions.

### Details
The script only adds/updates persons. When a user is removed from the organization (removed from LDAP), their active sessions are not terminated. The person's record persists in the local database, and any active sessions remain valid. In an election system, this could allow former members to participate in votes they should no longer have access to.

**ASVS:** 7.4.2 (L1)

**Affected Files:**
- `v3/server/bin/asf-load-ldap.py:36-63`
- `v3/server/pages.py`

### Remediation
Modify the LDAP synchronization script to track current LDAP users, identify removed users by comparing existing database UIDs with current LDAP UIDs, disable removed accounts in the local database, and invalidate all active sessions for disabled users. Implement a disable_person method in the PersonDB class and a session invalidation mechanism.

### Acceptance Criteria
- [ ] Removed user detection implemented
- [ ] Account disabling mechanism implemented
- [ ] Session invalidation for disabled accounts implemented
- [ ] Test added for removed user session termination

### References
- Source reports: 7.4.2.md

### Priority
**High** - Former members retain access

---

## Issue: FINDING-022 - No logout endpoint defined in application
**Labels:** bug, security, priority:high
**Description:**
### Summary
No logout endpoint is defined in the application. Without a logout endpoint, it is impossible for templates to provide functional logout access, regardless of what the template HTML contains. The `basic_info()` function populates template data for authenticated pages but includes no logout URL.

### Details
User wants to logout → No logout URL provided to templates → No logout endpoint exists → User cannot terminate session. An authenticated user on any page (e.g., `/voter`, `/admin`, `/manage/<eid>`) has no way to terminate their session through the application interface.

**ASVS:** 7.4.4 (L2)

**Affected Files:**
- `v3/server/pages.py` (entire file)

### Remediation
1. Add logout endpoint at /logout that calls asfquart.session.destroy() and redirects to /.
2. Provide logout URL to all templates in basic_info() function.
3. Ensure navbar template includes visible logout button/link.

### Acceptance Criteria
- [ ] Logout endpoint implemented
- [ ] Session destruction logic implemented
- [ ] Logout URL provided to templates
- [ ] Logout link added to navbar
- [ ] Test added for logout functionality

### References
- Source reports: 7.4.4.md

### Priority
**High** - Users cannot log out

---

## Issue: FINDING-023 - No mechanism for users to view or terminate active sessions
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application provides no mechanism for users to view their active sessions or terminate them. The `/profile` page and `/settings` page only render basic templates without session management functionality. There is no session listing endpoint or session termination endpoint.

### Details
Users cannot detect if their account has been compromised by viewing concurrent sessions. If a session is hijacked (e.g., through cookie theft or XSS), users have no self-service mechanism to invalidate that session. In an election context, this could allow an attacker to maintain persistent access and vote on behalf of the user.

**ASVS:** 7.5.2 (L2)

**Affected Files:**
- `v3/server/pages.py:594`
- `v3/server/pages.py:603`

### Remediation
Implement session listing and termination endpoints. Add a `/sessions` GET endpoint that lists all active sessions for the current user. Add a `/sessions/terminate/<session_id>` POST endpoint that requires re-authentication before allowing session termination. The termination endpoint should verify the session belongs to the requesting user and call session invalidation server-side.

### Acceptance Criteria
- [ ] Session listing endpoint implemented
- [ ] Session termination endpoint implemented
- [ ] Re-authentication required for termination
- [ ] Ownership verification implemented
- [ ] Test added for session listing
- [ ] Test added for session termination

### References
- Source reports: 7.5.2.md

### Priority
**High** - No session management for users

---

## Issue: FINDING-024 - No Step-Up Authentication for Highly Sensitive Election Management Operations
**Labels:** bug, security, priority:high
**Description:**
### Summary
Highly sensitive election management operations (opening, closing, and creating elections) are performed without any additional authentication or secondary verification beyond the initial session. These are irreversible or highly impactful operations in an election system.

### Details
An attacker with a hijacked session cookie could open or close elections by simply issuing GET requests. Elections can be opened (making them available for voting), closed (ending voting periods), or created without any additional verification. In the context of organizational governance, premature opening or closing of elections could affect democratic outcomes.

**ASVS:** 7.5.3 (L3)

**Affected Files:**
- `v3/server/pages.py:484`
- `v3/server/pages.py:505`
- `v3/server/pages.py:462`

### Remediation
Implement step-up authentication for sensitive operations. Change do_open_endpoint and do_close_endpoint from GET to POST. Require re-authentication if last_auth_time exceeds 5 minutes. Verify ownership by checking metadata.owner_pid against result.uid.

### Acceptance Criteria
- [ ] Step-up authentication implemented
- [ ] Re-authentication required for sensitive operations
- [ ] HTTP method changed to POST for state-changing operations
- [ ] Ownership verification implemented
- [ ] Test added for step-up authentication enforcement

### References
- Source reports: 7.5.3.md

### Priority
**High** - Sensitive operations lack additional verification

---

## Issue: FINDING-025 - State-changing operations use HTTP GET instead of POST
**Labels:** bug, security, priority:high
**Description:**
### Summary
State-changing operations (opening and closing elections) use HTTP GET instead of POST, making them vulnerable to CSRF via image tags, link prefetching, browser prefetching, and other non-interactive GET request vectors.

### Details
If an authenticated user visits a malicious page, their browser will send GET requests that can open or close elections without their knowledge or consent. Web crawlers could accidentally trigger these operations. Combined with the missing authorization checks, any committer's browser visiting a malicious page containing `<img src='https://steve.apache.org/do-open/EID'>` triggers the action with no CSRF token validation.

**CWE:** CWE-352  
**ASVS:** 8.2.1, 8.3.1, 8.4.2, 6.3.4, 2.3.1 (L1, L2, L3)

**Affected Files:**
- `v3/server/pages.py:450-466`
- `v3/server/pages.py:470-486`
- `v3/server/pages.py:482`
- `v3/server/pages.py:503`
- `v3/server/pages.py:450-465`
- `v3/server/pages.py:470-485`

### Remediation
Change /do-open/&lt;eid&gt; and /do-close/&lt;eid&gt; from GET to POST methods (@APP.post). Implement CSRF token validation by calling validate_csrf_token(await quart.request.form) at the start of each endpoint. Add CSRF token validation to all state-changing endpoints. Ensure all forms submitting to these endpoints include the CSRF token.

Replace the placeholder csrf_token = 'placeholder' with:
```python
csrf_token = secrets.token_urlsafe(32)
```

Implement:
```python
async def validate_csrf_token(form_data):
    session_token = session.get('csrf_token')
    form_token = form_data.get('csrf_token')
    if not hmac.compare_digest(session_token, form_token):
        abort(403, 'CSRF token mismatch')
```

### Acceptance Criteria
- [ ] HTTP methods changed to POST
- [ ] CSRF token validation implemented
- [ ] Test added for CSRF protection
- [ ] Test added for valid CSRF token acceptance
- [ ] Test added for invalid CSRF token rejection

### References
- Related findings: FINDING-001, FINDING-113
- Source reports: 8.2.1.md, 8.3.1.md, 8.4.2.md, 6.3.4.md, 2.3.1.md

### Priority
**High** - CSRF vulnerability on state-changing operations

---

## Issue: FINDING-026 - Vote submission endpoint lacks explicit voter eligibility check
**Labels:** bug, security, priority:high
**Description:**
### Summary
The voting endpoint lacks an explicit authorization check before processing votes. While election.add_vote() will implicitly fail if the user has no mayvote entry (via AttributeError on None when accessing mayvote.salt), this is not a proper security control—it's an unhandled exception that may expose stack traces or cause inconsistent error handling.

### Details
Authorization relies on an implicit side-effect rather than an explicit check. This is a Type C gap where the control (mayvote lookup) is called but its result isn't explicitly validated. The pattern is fragile and a code refactor could silently remove the protection. The implicit failure may expose internal error details, provides a confusing error message, creates a timing side-channel, and relies on implementation accident rather than intentional security control.

**CWE:** CWE-285  
**ASVS:** 8.2.2, 8.3.1 (L1, L2, L3)

**Affected Files:**
- `v3/server/pages.py:407-430`
- `v3/steve/election.py:254`
- `v3/server/pages.py:410-456`
- `v3/steve/election.py:268`

### Remediation
Add explicit eligibility check in add_vote() method. Check if mayvote is None and raise a custom VoterNotEligible or NotEligibleToVote exception before attempting to access mayvote.salt. This provides intentional security control with proper error handling.

Example:
```python
if mayvote is None:
    raise NotEligibleToVote(f'User {pid} is not eligible to vote on issue {iid}')
```

### Acceptance Criteria
- [ ] Explicit eligibility check implemented
- [ ] Custom exception class created
- [ ] Test added for eligible voter
- [ ] Test added for ineligible voter rejection
- [ ] Error handling improved

### References
- Source reports: 8.2.2.md, 8.3.1.md

### Priority
**High** - Implicit authorization control

---

## Issue: FINDING-027 - Single shared database with no tenant-level data isolation
**Labels:** bug, security, priority:high
**Description:**
### Summary
All elections for all organizational groups share a single SQLite database (steve.db). The authz field provides logical tenancy, but there is no row-level security in SQLite and query methods like list_closed_election_ids return ALL elections without tenant filtering.

### Details
Administrative functions (like tallying via CLI) have access to ALL elections across all tenant boundaries. While CLI access is documented as intentional, the list_closed_election_ids method has no tenant parameter, meaning any code calling it gets cross-tenant data. This creates a risk of cross-tenant data leakage in administrative operations.

**CWE:** CWE-566  
**ASVS:** 8.4.1 (L2)

**Affected Files:**
- `v3/schema.sql`
- `v3/steve/election.py`

### Remediation
Add tenant filtering to list_closed_election_ids() and other cross-election queries.

Example:
```python
@classmethod
def list_closed_election_ids(cls, db_fname, authz_filter=None, include_open=False):
    db = cls.open_database(db_fname)
    if authz_filter:
        db.q_closed_election_ids_by_authz.perform(authz_filter)
        eids = [row.eid for row in db.q_closed_election_ids_by_authz.fetchall()]
    else:
        # Only for admin CLI with explicit authorization
        db.q_closed_election_ids.perform()
        eids = [row.eid for row in db.q_closed_election_ids.fetchall()]
    return eids
```

### Acceptance Criteria
- [ ] Tenant filtering added to list_closed_election_ids()
- [ ] Tenant filtering added to other cross-election queries
- [ ] Test added for tenant isolation
- [ ] Test added for cross-tenant access prevention

### References
- Source reports: 8.4.1.md

### Priority
**High** - Cross-tenant data leakage risk

---

## Issue: FINDING-028 - No continuous identity verification for sensitive administrative operations
**Labels:** bug, security, priority:high
**Description:**
### Summary
ASVS 8.4.2 requires 'continuous consumer identity verification' for administrative interfaces. The system performs identity verification only once at session creation. Critical operations such as opening an election (irreversible), closing an election (irreversible), and deleting issues are performed with the same session token as reading a profile page, with no additional verification.

### Details
No step-up authentication, no session age check, no re-authentication, and no verification that the session hasn't been hijacked since creation. This violates the requirement for multiple layers of security for administrative interfaces.

**CWE:** CWE-306  
**ASVS:** 8.4.2 (L3)

**Affected Files:**
- `v3/server/pages.py` (multiple)

### Remediation
Implement async def require_recent_auth(max_age_seconds=300) that checks the session's auth_time and requires re-authentication if the session is older than the specified threshold (e.g., 5 minutes for sensitive operations). Apply this check to all irreversible administrative operations including do_open_endpoint, do_close_endpoint, and do_delete_issue_endpoint. Store auth_time in session at login and validate it before critical operations.

### Acceptance Criteria
- [ ] require_recent_auth() function implemented
- [ ] auth_time tracking in session implemented
- [ ] Re-authentication check applied to sensitive operations
- [ ] Test added for recent authentication requirement
- [ ] Test added for stale authentication rejection

### References
- Source reports: 8.4.2.md

### Priority
**High** - No re-authentication for sensitive operations

---

## Issue: FINDING-029 - HTML Attribute Injection in doc: Filename Pattern
**Labels:** bug, security, priority:high
**Description:**
### Summary
The `rewrite_description()` function extracts filenames from issue descriptions using a regex pattern `doc:([^\s]+)` and constructs URL paths without sanitization. While filenames originate from authorized users (committers storing issue descriptions), a malicious committer could craft a description containing path traversal sequences in the `doc:` pattern.

### Details
A committer could store an issue description containing `doc:../../sensitive-file` which generates a link to `/docs/<iid>/../../sensitive-file`. When a voter clicks this link, it would be handled by `serve_doc()` where framework-level safe_join would prevent traversal, but the link itself could confuse users or be used in social engineering.

**CWE:** CWE-79  
**ASVS:** 1.2.1, 1.3.1, 1.2.2, 5.3.2, 5.4.2 (L1, L2)

**Affected Files:**
- `v3/server/pages.py:52-60`
- `v3/server/pages.py:66`

### Remediation
Validate extracted filenames against a safe pattern and HTML-encode them.

Example:
```python
def rewrite_description(issue):
    import re
    SAFE_DOCNAME_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*$')
    desc = issue.description
    def repl(match):
        filename = match.group(1)
        if not SAFE_DOCNAME_RE.match(filename):
            return f'[invalid doc reference]'
        from markupsafe import escape
        safe_filename = escape(filename)
        return f'<a href="/docs/{issue.iid}/{safe_filename}">{safe_filename}</a>'
    desc = re.sub(r'doc:([^\s]+)', repl, desc)
    issue.description = f'<pre>{desc}</pre>'
```

### Acceptance Criteria
- [ ] Filename validation implemented
- [ ] HTML encoding applied to filenames
- [ ] Test added for valid filenames
- [ ] Test added for invalid filename rejection
- [ ] Test added for path traversal prevention

### References
- Related findings: FINDING-004, FINDING-118, FINDING-119, FINDING-133
- Source reports: 1.2.1.md, 1.3.1.md, 1.2.2.md, 5.3.2.md, 5.4.2.md

### Priority
**High** - HTML attribute injection vulnerability

---

## Issue: FINDING-030 - Missing vote string validation before encryption and storage
**Labels:** bug, security, priority:high
**Description:**
### Summary
The comment '### validate VOTESTRING for ISSUE.TYPE voting' explicitly acknowledges that vote format validation is not implemented. For YNA issues, the votestring should be constrained to valid options (e.g., 'yes', 'no', 'abstain'). For STV issues, the votestring should be a valid ranking format. Without validation, arbitrary strings are encrypted and stored.

### Details
This is a fail-open condition — the validation logic is commented as TODO, meaning transactions proceed despite the absence of critical validation. Impact: Corrupted tally results if vtypes.tally() cannot handle invalid vote strings, Potential DoS if the tally function crashes on malformed votes, Election integrity compromised if invalid votes are counted.

**ASVS:** 1.3.3, 2.2.1, 2.3.2, 16.5.3 (L1, L2)

**Affected Files:**
- `v3/steve/election.py:243`

### Remediation
```python
def add_vote(self, pid: str, iid: str, votestring: str):
    md = self._all_metadata(self.S_OPEN)
    issue = self.q_get_issue.first_row(iid)
    if not issue:
        raise IssueNotFound(iid)
    m = vtypes.vtype_module(issue.type)
    if not m.validate_vote(votestring, self.json2kv(issue.kv)):
        raise InvalidVote(f'Invalid vote format for type {issue.type}')
    mayvote = self.q_get_mayvote.first_row(pid, iid)
    if not mayvote:
        raise VoterNotAuthorized(pid, iid)
    ...
```

### Acceptance Criteria
- [ ] Vote string validation implemented
- [ ] Validation for YNA vote types implemented
- [ ] Validation for STV vote types implemented
- [ ] Test added for valid vote acceptance
- [ ] Test added for invalid vote rejection
- [ ] Custom exception classes created

### References
- Source reports: 1.3.3.md, 2.2.1.md, 2.3.2.md, 16.5.3.md

### Priority
**High** - Vote integrity not validated

---

## Issue: FINDING-031 - User-supplied scriptable content not sanitized in issue descriptions
**Labels:** bug, security, priority:high
**Description:**
### Summary
The `doc:filename` pattern is a custom expression/template language within user content. The application processes this pattern to generate HTML links but: 1. Does not sanitize or disable other potentially dangerous patterns 2. Does not strip HTML/CSS/JavaScript from the description 3. The raw user content (minus `doc:` substitution) is rendered as HTML in the browser.

### Details
User-supplied content is rendered as active HTML, allowing CSS injection (visual manipulation, data exfiltration via CSS selectors), HTML injection (phishing content), and script injection (full XSS as covered in 1.3.1).

**ASVS:** 1.3.5 (L2)

**Affected Files:**
- `v3/server/pages.py:60-70`
- `v3/server/pages.py:299`

### Remediation
Implement HTML sanitization: First, escape ALL HTML in the description using html.escape(). Then safely process the doc: pattern on the escaped content. Ensure filenames are URL-encoded when placed in href attributes.

Example:
```python
import html
import re
import urllib.parse

def rewrite_description(issue):
    # First, escape ALL HTML in the description
    desc = html.escape(issue.description)
    
    # Now safely process the doc: pattern (on escaped content)
    def repl(match):
        filename = match.group(1)
        safe_filename = html.escape(filename)
        url_filename = urllib.parse.quote(filename, safe='')
        return f'<a href="/docs/{issue.iid}/{url_filename}">{safe_filename}</a>'
    desc = re.sub(r'doc:([^\s]+)', repl, desc)
    
    issue.description = f'<pre>{desc}</pre>'
```

### Acceptance Criteria
- [ ] HTML sanitization implemented
- [ ] URL encoding applied to filenames
- [ ] Test added for HTML injection prevention
- [ ] Test added for CSS injection prevention
- [ ] Test added for script injection prevention

### References
- Source reports: 1.3.5.md

### Priority
**High** - User content not sanitized

---

## Issue: FINDING-032 - Document filename relies solely on framework protection without explicit validation
**Labels:** bug, security, priority:high
**Description:**
### Summary
The endpoint serves files based on user-supplied `iid` and `docname` parameters. While `send_from_directory` provides framework-level path traversal protection, the code explicitly acknowledges missing validation with a TODO comment. The `iid` parameter constructs a directory path (`DOCSDIR / iid`) without validating that `iid` is actually a valid 10-char hex string.

### Details
Additionally, `docname` could contain special characters, encoded sequences, or be a symlink target if the filesystem allows. Depending on framework version and edge cases, this could lead to unauthorized file access outside the intended document directory.

**ASVS:** 2.2.1 (L1)

**Affected Files:**
- `v3/server/pages.py:560-574`

### Remediation
Implement explicit validation for `docname` using an allowlist pattern. Reject hidden files and directory traversal attempts.

Example:
```python
VALID_DOCNAME = re.compile(r'^[a-zA-Z0-9_\-][a-zA-Z0-9_\-\.]{0,254}$')
if not VALID_DOCNAME.match(docname):
    quart.abort(400)
if docname.startswith('.') or '..' in docname:
    quart.abort(400)
```

### Acceptance Criteria
- [ ] Filename validation implemented
- [ ] Hidden file rejection implemented
- [ ] Path traversal prevention implemented
- [ ] Test added for valid filenames
- [ ] Test added for invalid filename rejection

### References
- Source reports: 2.2.1.md

### Priority
**High** - Path traversal risk

---

## Issue: FINDING-033 - No validation that close_at is after open_at when setting dates
**Labels:** bug, security, priority:high
**Description:**
### Summary
When setting open_at or close_at dates, the application does not validate the logical relationship between them. Users can set close_at to Jan 1, 2024 and then set open_at to Feb 1, 2024, resulting in close_at < open_at which is logically inconsistent. The _set_election_date() function accepts date values independently without checking against the other date field.

**ASVS:** 2.2.3 (L2)

**Affected Files:**
- `v3/server/pages.py:88-110`
- `v3/steve/election.py`

### Remediation
Validate cross-field consistency by checking that open_at is before close_at when setting either field. Retrieve the existing date value for the other field and compare before allowing the update. Return a 400 error if the new date would create an invalid combination.

### Acceptance Criteria
- [ ] Date relationship validation implemented
- [ ] Test added for valid date combinations
- [ ] Test added for invalid date combination rejection
- [ ] Error message provides clear feedback

### References
- Source reports: 2.2.3.md

### Priority
**High** - Logical data inconsistency possible

---

## Issue: FINDING-034 - User-uploaded documents served inline without Content-Disposition header
**Labels:** bug, security, priority:high
**Description:**
### Summary
The serve_doc() endpoint accepts a user-submitted filename via the docname URL parameter and uses it directly to serve files. There is no validation or sanitization of this filename, and no explicit Content-Disposition header is set in the response to override the user-controlled filename.

### Details
The framework's default behavior uses the actual file's name for Content-Type inference, but the URL-visible filename remains user-controlled. Without explicit filename validation: 1) The Content-Type of the response is derived from the user-controlled filename extension, which could cause browser behavior differences, 2) If the response includes a Content-Disposition header, the user-controlled filename could contain injection characters, 3) The lack of explicit Content-Disposition means the browser uses the URL's filename segment for Save As operations.

**CWE:** CWE-646  
**ASVS:** 3.2.1, 5.4.1 (L1, L2)

**Affected Files:**
- `v3/server/pages.py:621-635`

### Remediation
Implement explicit filename validation using an allowlist regex (e.g., ^[a-zA-Z0-9][a-zA-Z0-9._-]*$) and reject requests with invalid filenames. Serve files with explicit Content-Disposition header using as_attachment=True in send_from_directory(). Add X-Content-Type-Options: nosniff header for defense-in-depth. Implement file extension allowlist to only serve known-safe extensions (.pdf, .txt, .md, etc.) and prevent serving executable or HTML content.

### Acceptance Criteria
- [ ] Filename validation implemented
- [ ] Content-Disposition header set
- [ ] X-Content-Type-Options header set
- [ ] File extension allowlist implemented
- [ ] Test added for safe file serving
- [ ] Test added for dangerous file rejection

### References
- Source reports: 3.2.1.md, 5.4.1.md

### Priority
**High** - Content-Type confusion attacks possible

---

## Issue: FINDING-035 - JavaScript String Injection in STV_CANDIDATES Object
**Labels:** bug, security, priority:high
**Description:**
### Summary
The template renders issue titles, candidate labels, and candidate names directly into JavaScript string literals WITHOUT using EZT's `[format "js,html"]` escape filter. If any of these values contain a double-quote, backslash, or newline, they break out of the string context. Database values (issue title, candidate label/name) flow through EZT template rendering without JS escaping into an inline &lt;script&gt; block, creating JavaScript string literal injection.

**ASVS:** 3.2.2 (L1)

**Affected Files:**
- `v3/server/templates/vote-on.ezt:280-295`

### Remediation
Replace innerHTML with DOM manipulation using textContent:

```javascript
function makeItem(candidate, rank) {
    const div = document.createElement('div');
    div.className = 'stv-item';
    div.dataset.label = candidate.label;
    if (rank) div.dataset.rank = rank;
    const handle = document.createElement('span');
    handle.className = 'drag-handle bi bi-grip-vertical';
    const nameSpan = document.createElement('span');
    nameSpan.className = 'cand-name';
    nameSpan.textContent = candidate.name;  // Safe text rendering
    div.appendChild(handle);
    div.appendChild(nameSpan);
    div.addEventListener('dblclick', () => moveItem(div));
    return div;
}
```

### Acceptance Criteria
- [ ] DOM manipulation replaces innerHTML
- [ ] textContent used for user data
- [ ] Test added for special character handling
- [ ] Test added for XSS payload rejection

### References
- Source reports: 3.2.2.md

### Priority
**High** - JavaScript injection vulnerability

---

## Issue: FINDING-036 - XSS via Unescaped Flash Messages
**Labels:** bug, security, priority:high
**Description:**
### Summary
User form input (election titles, issue titles) flows through flash_success() into session storage, then get_flashed_messages(), and is rendered via [flashes.message] in template without escaping as raw HTML. Multiple flash message sources in pages.py include user input without sanitization, including form.title and iid values.

**ASVS:** 3.2.2 (L1)

**Affected Files:**
- `v3/server/templates/flashes.ezt:1-6`
- `v3/server/pages.py:489`
- `v3/server/pages.py:547`
- `v3/server/pages.py:570`
- `v3/server/pages.py:589`
- `v3/server/pages.py:453`
- `v3/server/pages.py:465`

### Remediation
Either HTML-escape flash messages in the template:
```html
[for flashes]
<div class="alert alert-[flashes.category] alert-dismissible fade show" role="alert">
    [format "html"][flashes.message][end]
    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
</div>
[end]
```

Or sanitize input before passing to flash functions:
```python
from markupsafe import escape
await flash_success(f'Created election: {escape(form.title)}')
```

### Acceptance Criteria
- [ ] Flash message escaping implemented
- [ ] Test added for XSS payload in flash messages
- [ ] Test added for legitimate content rendering

### References
- Source reports: 3.2.2.md

### Priority
**High** - XSS via flash messages

---

## Issue: FINDING-037 - Missing Cookie Secure Attribute and Prefix Configuration
**Labels:** bug, security, priority:high
**Description:**
### Summary
No session cookie configuration is visible in the provided codebase. The application delegates session management to `asfquart.session`, but there is no evidence that cookies are configured with the `Secure` attribute or use the `__Host-` or `__Secure-` prefix.

### Details
Without the `Secure` attribute, session cookies could be transmitted over unencrypted HTTP connections (e.g., if a user accesses the site via HTTP before being redirected to HTTPS, or in a man-in-the-middle scenario). Without `__Host-` or `__Secure-` prefix, cookies lack additional protections against injection from subdomains.

**ASVS:** 3.3.1, 3.3.2 (L1, L2)

**Affected Files:**
- `v3/server/pages.py`
- `v3/server/main.py`

### Remediation
Configure session cookie security in the application initialization:

```python
def create_app():
    app = asfquart.construct('steve', app_dir=THIS_DIR, static_folder=None)
    
    # Configure session cookie security
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_NAME'] = '__Host-session'  # or '__Secure-session'
    
    import pages
    import api
    return app
```

### Acceptance Criteria
- [ ] Secure attribute configured
- [ ] HttpOnly attribute configured
- [ ] Cookie prefix configured (__Host- or __Secure-)
- [ ] Test added for secure cookie attributes

### References
- Source reports: 3.3.1.md, 3.3.2.md

### Priority
**High** - Session cookies lack security attributes

---

## Issue: FINDING-038 - No Strict-Transport-Security (HSTS) header configured
**Labels:** bug, security, priority:high
**Description:**
### Summary
No Strict-Transport-Security (HSTS) header is configured anywhere in the application. Despite TLS being configured in `config.yaml.example`, there is no `@APP.after_request` handler, middleware, or framework configuration that adds an HSTS header to responses. This is a Type A gap — the control is completely absent.

### Details
Without HSTS, SSL stripping attacks are possible on initial connections, users can be downgraded from HTTPS to HTTP by a network attacker, and this is especially critical for a voting application where ballot integrity and voter authentication depend on transport security. ASVS Level 2 requires `includeSubDomains` directive which is also missing.

**ASVS:** 3.4.1 (L1, L2)

**Affected Files:**
- `v3/server/main.py` (entire file)
- `v3/server/pages.py` (entire file)

### Remediation
Add after_request handler in pages.py or main.py:

```python
@APP.after_request
async def add_security_headers(response):
    # HSTS: 1 year minimum, include subdomains for L2
    response.headers['Strict-Transport-Security'] = (
        'max-age=31536000; includeSubDomains'
    )
    return response
```

### Acceptance Criteria
- [ ] HSTS header configured
- [ ] includeSubDomains directive included
- [ ] max-age set to at least 1 year
- [ ] Test added for HSTS header presence

### References
- Source reports: 3.4.1.md

### Priority
**High** - SSL stripping attacks possible

---

## Issue: FINDING-039 - No Content-Security-Policy header configured
**Labels:** bug, security, priority:high
**Description:**
### Summary
No Content-Security-Policy (CSP) header is configured anywhere in the application. This is a Type A gap — the control is completely absent. The application serves HTML pages with extensive inline JavaScript (in manage.ezt, manage-stv.ezt, vote-on.ezt, voter.ezt, admin.ezt) and loads external resources, but has no CSP to restrict script execution sources.

### Details
Without CSP, there is no defense-in-depth against XSS — any injection becomes script execution. The voting application handles sensitive election operations (vote casting, election management). The ASVS minimum requirement of object-src 'none'; base-uri 'none' is not met. For L2, allowlist or nonce-based script-src is required. Missing object-src 'none' allows Flash/Java plugin attacks. Missing base-uri 'none' allows base tag injection to hijack relative URLs.

**CWE:** CWE-1021  
**ASVS:** 3.4.3, 3.4.7 (L2, L3)

**Affected Files:**
- `v3/server/main.py` (entire file)
- `v3/server/pages.py` (entire file)
- `v3/server/templates/header.ezt` (entire file)
- `v3/server/templates/admin.ezt` (entire file)
- `v3/server/templates/manage.ezt` (entire file)
- `v3/server/templates/vote-on.ezt` (entire file)
- `v3/server/templates/voter.ezt` (entire file)
- `v3/server/templates/flashes.ezt` (entire file)

### Remediation
Add after_request handler to set CSP header with report-uri and report-to directives, and implement CSP violation report endpoint:

```python
@app.after_request
async def set_security_headers(response):
    csp = (
        "frame-ancestors 'none'; "
        "default-src 'self'; "
        "report-uri /csp-report; "
        "report-to csp-endpoint"
    )
    response.headers['Content-Security-Policy'] = csp
    response.headers['Reporting-Endpoints'] = 'csp-endpoint="/csp-report"'
    return response

@app.post('/csp-report')
async def csp_report():
    report = await quart.request.get_json(force=True)
    _LOGGER.warning(f'CSP violation: {report}')
    return '', 204
```

### Acceptance Criteria
- [ ] CSP header configured
- [ ] object-src 'none' directive included
- [ ] base-uri 'none' directive included
- [ ] CSP violation reporting endpoint implemented
- [ ] Test added for CSP header presence
- [ ] Test added for CSP violation reporting

### References
- Source reports: 3.4.3.md, 3.4.7.md

### Priority
**High** - No defense-in-depth against XSS

---

## Issue: FINDING-040 - Missing X-Content-Type-Options: nosniff header
**Labels:** bug, security, priority:high
**Description:**
### Summary
There is no middleware, after_request handler, or framework configuration in any of the provided source files that adds the X-Content-Type-Options: nosniff header to HTTP responses. This applies to all endpoints: HTML pages (home_page, voter_page, manage_page, etc.), static files served via serve_static(), and document files served via serve_doc().

### Details
Without this header, a browser may MIME-sniff the response body and interpret it as a different content type (e.g., treating a text file as executable JavaScript), enabling content-type confusion attacks. The /docs/&lt;iid&gt;/&lt;docname&gt; endpoint is particularly at risk as it serves user-uploaded documents.

**ASVS:** 3.4.4, 13.4.7 (L2, L3)

**Affected Files:**
- `v3/server/main.py` (application-wide)
- `v3/server/pages.py` (all route handlers)

### Remediation
Add after_request handler to set X-Content-Type-Options: nosniff header on all responses.

Example:
```python
@app.after_request
async def security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response
```

### Acceptance Criteria
- [ ] X-Content-Type-Options header configured
- [ ] Header applied to all responses
- [ ] Test added for header presence on HTML pages
- [ ] Test added for header presence on document downloads

### References
- Source reports: 3.4.4.md, 13.4.7.md

### Priority
**High** - MIME-sniffing attacks possible

## Issue: FINDING-041 - Missing Content-Security-Policy frame-ancestors directive enables clickjacking attacks
**Labels:** bug, security, priority:high
**Description:**
### Summary
No Content-Security-Policy header with a frame-ancestors directive is set on any HTTP response. There is also no X-Frame-Options header. This affects all page endpoints and enables clickjacking attacks where an attacker can embed any page from this application in an iframe on their malicious site.

### Details
All HTML-rendering routes (/, /voter, /admin, /manage/&lt;eid&gt;, /vote-on/&lt;eid&gt;, etc.) lack frame-ancestors protection. This is particularly critical for the voting interface (/vote-on/&lt;eid&gt;) where an attacker could overlay transparent iframes to trick users into submitting votes.

**Affected Files:**
- v3/server/main.py (application-wide)
- v3/server/pages.py (all HTML-rendering routes)

**CWE:** Not specified
**ASVS:** 3.4.6 (L2)

### Remediation
Add an after_request handler to set the Content-Security-Policy header with frame-ancestors directive:

```python
@app.after_request
async def set_security_headers(response):
    response.headers['Content-Security-Policy'] = "frame-ancestors 'none'"
    return response
```

### Acceptance Criteria
- [ ] Content-Security-Policy header with frame-ancestors 'none' added to all responses
- [ ] Test added to verify header presence on all endpoints
- [ ] Test added to verify clickjacking protection

### References
- Source: 3.4.6.md
- Related: BROWSER-XSS-025

### Priority
High

---

## Issue: FINDING-042 - Sensitive POST Endpoints Accept CORS-Safelisted Content Types Without Preflight Protection
**Labels:** bug, security, priority:high
**Description:**
### Summary
All sensitive POST endpoints consume application/x-www-form-urlencoded form data, which is a CORS-safelisted content type that does NOT trigger preflight checks. Combined with non-functional CSRF token validation, cross-origin requests to these endpoints will be processed by the server.

### Details
The application has no Origin header validation, custom header requirement, validated CSRF token, or Content-Type: application/json enforcement on form endpoints. An attacker can forge cross-origin requests to cast votes, create elections, add/edit/delete issues on behalf of an authenticated user who visits a malicious page.

**Affected Files:**
- v3/server/pages.py:405
- v3/server/pages.py:451
- v3/server/pages.py:507
- v3/server/pages.py:529
- v3/server/pages.py:551

**ASVS:** 3.5.2 (L1)

### Remediation
Implement Origin header validation to verify the Origin header matches the expected application origin. Alternatively, require a custom header that forces preflight (e.g., X-Requested-With). 

Example: Create a validate_origin() function that checks the Origin header against allowed_origins and aborts with 403 if invalid. Or use a before_request hook to check for custom headers on POST/PUT/DELETE/PATCH requests.

### Acceptance Criteria
- [ ] Origin header validation implemented for all state-changing endpoints
- [ ] Fixed CSRF token validation or custom header requirement added
- [ ] Test added to verify cross-origin requests are blocked
- [ ] Test added to verify same-origin requests succeed

### References
- Source: 3.5.2.md
- Related: BROWSER-XSS-2-005

### Priority
High

---

## Issue: FINDING-043 - No Cross-Origin-Resource-Policy Response Header on Any Endpoint
**Labels:** bug, security, priority:high
**Description:**
### Summary
No Cross-Origin-Resource-Policy (CORP) header is set on any response throughout the application. Without CORP headers, the browser cannot block cross-origin resource loads, allowing external pages to embed resources and probe application structure or authenticated state.

### Details
All endpoints including serve_static(), serve_doc(), and template-rendered responses lack this defensive header. External pages can embed resources like `<script src="https://steve.example.org/static/js/steve.js">` to probe application JavaScript structure, or use `<img>` tags to determine authenticated state via resource load timing.

**Affected Files:**
- v3/server/pages.py (all endpoints)

**ASVS:** 3.5.8 (L3)

### Remediation
Add an @APP.after_request handler to set security headers on all responses:

```python
@APP.after_request
async def security_headers(response):
    response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    return response
```

### Acceptance Criteria
- [ ] Cross-Origin-Resource-Policy: same-origin header added to all responses
- [ ] Cross-Origin-Opener-Policy: same-origin header added to all responses
- [ ] Test added to verify headers on static and dynamic resources
- [ ] Test added to verify cross-origin embedding is blocked

### References
- Source: 3.5.8.md
- Related: BROWSER-XSS-2-011

### Priority
High

---

## Issue: FINDING-044 - No Strict-Transport-Security Header Configuration and No HSTS Preload
**Labels:** bug, security, priority:high
**Description:**
### Summary
Client connects without Strict-Transport-Security header, browser does not enforce HTTPS, and domain is not on HSTS preload list. The first connection to the application can be intercepted via SSL stripping attacks. Configuration explicitly allows plain HTTP operation.

### Details
For a voting application handling ballot submissions, this could allow an attacker to intercept votes, session cookies, or serve a fraudulent voting page. The configuration explicitly allows plain HTTP operation (`leave these two fields blank for plain HTTP`).

**Affected Files:**
- v3/server/pages.py (entire file)
- v3/server/main.py (entire file)
- v3/server/config.yaml.example

**ASVS:** 3.7.4 (L3), 3.7.5 (L2)

### Remediation
Add HSTS header to all responses using @APP.after_request decorator with 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload'. Additionally:
1. Submit the domain to https://hstspreload.org for inclusion in browser preload lists
2. Remove the option for plain HTTP operation in production configurations
3. Add configuration validation that rejects missing TLS certificates in production mode

### Acceptance Criteria
- [ ] HSTS header with max-age=63072000 added to all responses
- [ ] includeSubDomains and preload directives included
- [ ] Plain HTTP operation disabled in production
- [ ] Configuration validation for TLS certificates implemented
- [ ] Test added to verify HSTS header presence
- [ ] Documentation updated for HSTS preload submission

### References
- Source: 3.7.4.md, 3.7.5.md
- Related: BROWSER-XSS-2-016

### Priority
High

---

## Issue: FINDING-045 - No Browser Feature Detection or User Warning
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application uses modern browser features critical for security and functionality but provides no detection mechanism or warning when these features are unavailable. An election system where some voters cannot participate due to browser incompatibility undermines democratic integrity.

### Details
Required features used without detection:
- JavaScript (ES6+) with arrow functions, template literals, const/let, destructuring
- Fetch API used in manage.ezt for AJAX date saving
- SortableJS/Drag-and-Drop critical for STV vote ranking in vote-on.ezt
- Bootstrap 5 JavaScript for modals, toasts, tabs

Users with JavaScript disabled see a non-functional page with no explanation. STV vote ranking requires SortableJS and Drag-and-Drop API - failure means votes cannot be cast.

**Affected Files:**
- v3/server/templates/header.ezt (all)
- v3/server/templates/footer.ezt (all)
- v3/server/templates/vote-on.ezt (all)
- v3/server/templates/manage.ezt (all)
- v3/server/pages.py (all)

**ASVS:** 3.7.5 (L3)

### Remediation
Add `<noscript>` block immediately after `<body>` in header.ezt with alert informing users that JavaScript is required and listing minimum browser versions (Chrome 80+, Firefox 78+, Safari 14+, Edge 80+). 

Implement feature detection script in `<head>` of header.ezt that checks for required features (fetch, Promise, Symbol, CSS Flexbox) and displays prominent warning when missing. 

Create DOMContentLoaded event handler that inserts warning div at top of page listing missing features and instructing users to update their browser.

### Acceptance Criteria
- [ ] `<noscript>` warning block added to header template
- [ ] Feature detection script implemented for critical features
- [ ] User-friendly warning message displayed for missing features
- [ ] Minimum browser version requirements documented
- [ ] Test added to verify warnings appear in unsupported browsers

### References
- Source: 3.7.5.md
- Related: BROWSER-XSS-2-018

### Priority
High

---

## Issue: FINDING-046 - Multi-Vote Submission Not Wrapped in Transaction — Partial Failure Leaves Inconsistent State
**Labels:** bug, security, priority:high
**Description:**
### Summary
User submits ballot with 10 issues → Loop processes votes one by one → Vote #5 fails → Votes #1-4 already committed → User told "error" but partial votes persist. Atomic ballot submission is not guaranteed. A voter's intent is a complete ballot, but partial submission creates an inconsistent state.

### Details
This violates the principle that business operations should succeed entirely or roll back. A voter's ballot is their complete intent, but the current implementation can leave partial votes persisted if any vote in the loop fails.

**Affected Files:**
- v3/server/pages.py:372

**CWE:** CWE-662
**ASVS:** 2.3.3 (L2)

### Remediation
Wrap all votes in a single transaction:

```python
election.db.conn.execute('BEGIN TRANSACTION')
try:
    for iid, votestring in votes.items():
        if iid not in issue_dict:
            election.db.conn.execute('ROLLBACK')
            await flash_danger(f'Invalid issue ID: {iid}')
            return quart.redirect(f'/vote-on/{election.eid}', code=303)
        election.add_vote(result.uid, iid, votestring)
    election.db.conn.execute('COMMIT')
except Exception as e:
    election.db.conn.execute('ROLLBACK')
    await flash_danger('Error submitting votes. No changes were saved.')
    return quart.redirect(f'/vote-on/{election.eid}', code=303)
```

### Acceptance Criteria
- [ ] All vote submissions wrapped in single transaction
- [ ] Rollback implemented on any failure
- [ ] Test added to verify partial submission is rolled back
- [ ] Test added to verify complete submission succeeds atomically
- [ ] User feedback updated to reflect transaction behavior

### References
- Source: 2.3.3.md
- Related: FINDING-047, FINDING-147

### Priority
High

---

## Issue: FINDING-047 - Election Open Operation Not Fully Atomic — Salt Addition and State Change in Separate Transactions
**Labels:** bug, security, priority:high
**Description:**
### Summary
The open() method executes add_salts() which commits its own transaction, then performs c_open.perform() in a separate auto-commit transaction. If an error occurs between these operations, the mayvote table has salts set but the election record still shows editable state.

### Details
Attempting to open again would regenerate salts, invalidating any votes that might have been cast in the interim. The election open operation is not atomic, leaving the database in an inconsistent state that cannot be trivially recovered.

**Affected Files:**
- v3/steve/election.py:70

**CWE:** CWE-662
**ASVS:** 2.3.3 (L2)

### Remediation
Wrap the entire open() operation in a single transaction:

```python
self.db.conn.execute('BEGIN TRANSACTION')
try:
    self.q_all_issues.perform(self.eid)
    for mayvote in self.q_all_issues.fetchall():
        salt = crypto.gen_salt()
        self.c_salt_mayvote.perform(salt, mayvote.rowid)
    edata = self.gather_election_data(pdb)
    salt = crypto.gen_salt()
    opened_key = crypto.gen_opened_key(edata, salt)
    self.c_open.perform(salt, opened_key, self.eid)
    self.db.conn.execute('COMMIT')
except Exception:
    self.db.conn.execute('ROLLBACK')
    raise
```

### Acceptance Criteria
- [ ] Election open operation wrapped in single transaction
- [ ] Rollback implemented on any failure
- [ ] Test added to verify partial open is rolled back
- [ ] Test added to verify complete open succeeds atomically
- [ ] Test added to verify salts are not regenerated on retry after failure

### References
- Source: 2.3.3.md
- Related: FINDING-046, FINDING-147

### Priority
High

---

## Issue: FINDING-048 - No Explicit Locking on Election State Transitions — Race Condition on Concurrent Open/Close
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application performs a check-then-act pattern without proper locking in the open() and close() methods. Request A checks is_editable() → True → begins add_salts(). Request B checks is_editable() → True (state not yet changed) → begins add_salts(). Both proceed to open the election with different salts/keys.

### Details
While SQLite's implicit write serialization may prevent actual data corruption in single-writer scenarios, the application logic does not handle the concurrency case explicitly. In multi-process deployments or with WAL mode, race conditions could lead to: double salt generation (overwriting previous salts), multiple opened_key values being computed, and inconsistent anti-tamper state.

**Affected Files:**
- v3/steve/election.py:70
- v3/steve/election.py:109

**CWE:** CWE-367
**ASVS:** 2.3.4 (L2)

### Remediation
Use a single transaction with an immediate lock. Re-check state inside the transaction (with lock held):

```python
self.db.conn.execute('BEGIN IMMEDIATE')
try:
    # Re-check state with lock held
    if not self.is_editable():
        self.db.conn.execute('ROLLBACK')
        raise ElectionStateError('Election is not in editable state')
    # Perform all operations atomically
    # ...
    self.db.conn.execute('COMMIT')
except Exception:
    self.db.conn.execute('ROLLBACK')
    raise
```

### Acceptance Criteria
- [ ] BEGIN IMMEDIATE used for state transition operations
- [ ] State re-checked after lock acquisition
- [ ] Test added to verify concurrent open/close is serialized
- [ ] Test added to verify second request fails appropriately
- [ ] Documentation updated regarding concurrency guarantees

### References
- Source: 2.3.4.md
- Related: BROWSER-XSS-2-008

### Priority
High

---

## Issue: FINDING-049 - TLS Protocol Version Not Explicitly Configured
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application starts with whatever TLS versions the underlying framework (Quart/Hypercorn) defaults to. Without explicit configuration, older TLS versions (TLS 1.0, TLS 1.1) may be negotiable depending on the runtime environment and library versions.

### Details
Config values are passed directly to app.runx() without any TLS protocol version constraints. An attacker can attempt handshake with deprecated TLS versions. If the underlying TLS library allows deprecated TLS versions, the application may be vulnerable to known protocol-level attacks (BEAST, POODLE, etc.). TLS 1.3 is not explicitly preferred.

**Affected Files:**
- v3/server/main.py:75-78

**ASVS:** 12.1.1 (L1)

### Remediation
Explicitly configure minimum TLS protocol version and prefer TLS 1.3. For Hypercorn, configure via hypercorn.toml or programmatically:

```python
import ssl
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.maximum_version = ssl.TLSVersion.TLSv1_3
ctx.load_cert_chain(certfile, keyfile)
```

For config.yaml, add `server.min_tls_version: "1.2"`

### Acceptance Criteria
- [ ] TLS minimum version set to 1.2
- [ ] TLS maximum version set to 1.3
- [ ] Configuration validation added
- [ ] Test added to verify TLS 1.0/1.1 are rejected
- [ ] Test added to verify TLS 1.2/1.3 are accepted
- [ ] Documentation updated with TLS requirements

### References
- Source: 12.1.1.md
- Related: TLS-1

### Priority
High

---

## Issue: FINDING-050 - No Cipher Suite Configuration - Weak Ciphers May Be Negotiated
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application has no control over which cipher suites are enabled. Without explicit cipher suite configuration, weak ciphers may be negotiated. For L3 compliance, the application MUST only support cipher suites providing forward secrecy (ECDHE/DHE key exchange).

### Details
Depending on the Python/OpenSSL version, this could allow:
- Non-forward-secrecy ciphers (e.g., RSA key exchange)
- Weak encryption algorithms (e.g., 3DES, RC4)
- Weak hash algorithms in cipher suites (e.g., SHA-1 based MACs)

**Affected Files:**
- v3/server/main.py:75-82

**ASVS:** 12.1.2 (L2, L3)

### Remediation
Create an SSL context with explicit cipher suite configuration:

```python
import ssl

def create_ssl_context(certfile, keyfile):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS:!RC4:!3DES')
    ctx.load_cert_chain(certfile, keyfile)
    return ctx
```

### Acceptance Criteria
- [ ] Explicit cipher suite configuration implemented
- [ ] Only forward secrecy ciphers enabled
- [ ] Weak ciphers (3DES, RC4, MD5) disabled
- [ ] Test added to verify cipher suite negotiation
- [ ] Test added to verify weak ciphers are rejected
- [ ] Documentation updated with supported cipher suites

### References
- Source: 12.1.2.md
- Related: TLS-2

### Priority
High

---

## Issue: FINDING-052 - No secrets management solution used; cryptographic keys stored directly in SQLite database
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application stores cryptographic secrets (election salts, opened_keys, mayvote salts, encrypted vote ciphertexts) directly in an unencrypted SQLite database file. There is no key vault or secrets management solution, HSM integration, encryption at rest for the database file, or access control beyond filesystem permissions.

### Details
If the SQLite database file is compromised (backup theft, file system access), all cryptographic material is exposed. The opened_key (32 bytes) is the master key for vote token derivation—its compromise allows vote de-anonymization. Election salts allow regeneration of vote tokens. No audit trail for secret access.

**Affected Files:**
- v3/steve/election.py
- v3/schema.sql:63-72

**ASVS:** 13.3.1 (L2)

### Remediation
Integrate a secrets management solution such as HashiCorp Vault, AWS KMS, or Azure Key Vault to store cryptographic keys separately from the database. Store sensitive key material in vault, not database. Store only references in database.

Example implementation:
```python
# Use VaultClient to write salt and opened_key to vault
vault_path = f'secret/elections/{eid}'
vault.write(vault_path, salt=salt, opened_key=opened_key)
# Store only reference in database
# Retrieve when needed rather than storing directly in SQLite
```

At minimum, enable SQLite encryption (SQLCipher) for the database file and add database encryption at rest.

### Acceptance Criteria
- [ ] Secrets management solution integrated (Vault/KMS/Key Vault)
- [ ] Cryptographic keys stored in vault, not database
- [ ] Database stores only references to keys
- [ ] Audit trail for key access implemented
- [ ] Test added to verify keys are not in database
- [ ] Test added to verify key retrieval from vault
- [ ] Documentation updated with key management procedures

### References
- Source: 13.3.1.md
- Related: SECRETS-13

### Priority
High

---

## Issue: FINDING-053 - Cryptographic key material generated and stored without isolated security module
**Labels:** bug, security, priority:high
**Description:**
### Summary
All cryptographic key material (election salts, opened_key, vote encryption keys) is generated, stored, and used entirely within the application process and a SQLite database file on disk. If the application server or database is compromised, all key material is immediately exposed. There is no hardware boundary protecting keys.

### Details
Data flow: Election data → gen_opened_key() in application process memory → stored as BLOB in SQLite election table → retrieved from SQLite for vote encryption/decryption operations. An attacker with read access to the SQLite file can extract opened_key and all mayvote.salt values, then recompute vote_token for any voter/issue pair and decrypt all votes.

**Affected Files:**
- v3/steve/crypto.py:43-95
- v3/steve/election.py:70-80
- v3/steve/election.py:231-243

**ASVS:** 13.3.3 (L3)

### Remediation
Integrate with a key management service (KMS) or HSM where cryptographic operations are performed within an isolated security boundary. Keys should never be exposed to application memory. Operations requiring keys should be delegated to the security module via API calls.

Example using HashiCorp Vault Transit secrets engine:
```python
# Encrypt operation delegated to Vault
vault.transit.encrypt(mount_point='transit', name='election-key', plaintext=vote_data)
# Decrypt operation delegated to Vault
vault.transit.decrypt(mount_point='transit', name='election-key', ciphertext=encrypted_vote)
```

### Acceptance Criteria
- [ ] KMS/HSM integration implemented
- [ ] Cryptographic operations delegated to security module
- [ ] Keys never exposed to application memory
- [ ] Test added to verify key isolation
- [ ] Test added to verify operations work via KMS/HSM
- [ ] Documentation updated with key management architecture
- [ ] Incident response plan updated for key compromise scenarios

### References
- Source: 13.3.3.md
- Related: SECRETS-17

### Priority
High

---

## Issue: FINDING-054 - Master election key loaded into application memory without process isolation
**Labels:** bug, security, priority:high
**Description:**
### Summary
The opened_key (the master election key material) is loaded into application memory in multiple request paths via the _all_metadata method. The SQLite database returns SALT and OPENED_KEY columns which flow through md object to multiple methods. The sensitive key material is only protected by an internal comment (not for public use) with no memory protection, access control at the data layer, or process isolation.

### Details
The key flows through: add_vote, tally_issue, has_voted_upon, and is_tampered methods. There is no memory protection, access control at the data layer, or process isolation for this critical key material.

**Affected Files:**
- v3/steve/election.py:144-158

**ASVS:** 13.3.3 (L3)

### Remediation
Integrate with a key management service (KMS) or HSM where the key never leaves the security boundary. Operations requiring the key should be delegated to the security module via API calls. Eliminate direct loading of key material into application memory.

### Acceptance Criteria
- [ ] Key material no longer loaded into application memory
- [ ] Operations requiring key delegated to KMS/HSM
- [ ] Test added to verify key is not accessible in memory dumps
- [ ] Test added to verify operations work via security module
- [ ] Code review to ensure no key material in logs or error messages
- [ ] Documentation updated with secure key handling procedures

### References
- Source: 13.3.3.md
- Related: SECRETS-18

### Priority
High

---

## Issue: FINDING-055 - Cryptographic keys and salts have no expiration or rotation mechanism
**Labels:** bug, security, priority:high
**Description:**
### Summary
Cryptographic keys and salts have no configured expiration or rotation mechanism. Once an election is closed, its key material remains in the database indefinitely, increasing the window for key compromise. Even mayvote.salt values persist forever.

### Details
The crypto.gen_salt() generates salt stored in election table that never expires or rotates. The crypto.gen_opened_key() generates opened_key stored in election table that persists through open to closed states indefinitely. If any key is compromised (e.g., through backup theft), there is no mechanism to detect staleness or force rotation. An attacker obtaining an old database backup can decrypt votes from elections that ended months or years ago.

**Affected Files:**
- v3/steve/election.py:70-80
- v3/schema.sql:48-56

**ASVS:** 13.3.4 (L3)

### Remediation
Add expiry tracking and rotation support to the Election class:

1. Implement KEY_EXPIRY_DAYS configuration (e.g., 90 days)
2. Add check_key_expiry() method to validate key age
3. Implement rotate_keys_post_close() method to zero out key material after tallying is complete and results are finalized
4. Add key_created_at and key_expires_at columns to the election table schema to track key lifecycle
5. After election finalization, remove or re-encrypt key material
6. Implement automated cleanup of secrets past their useful life

### Acceptance Criteria
- [ ] Key expiry configuration added
- [ ] key_created_at and key_expires_at columns added to schema
- [ ] Key rotation mechanism implemented
- [ ] Post-election key cleanup implemented
- [ ] Test added to verify key expiry detection
- [ ] Test added to verify key rotation
- [ ] Test added to verify post-election cleanup
- [ ] Documentation updated with key lifecycle procedures

### References
- Source: 13.3.4.md
- Related: SECRETS-19

### Priority
High

---

## Issue: FINDING-056 - No Cache-Control headers on pages serving sensitive election and voter data
**Labels:** bug, security, priority:high
**Description:**
### Summary
None of the route handlers set Cache-Control, Pragma, or Expires headers to prevent caching of sensitive pages. Pages containing voter eligibility status, election configuration, vote submission forms, and election documents could be cached by intermediate proxies, CDNs, load balancers, or browser caches.

### Details
Affected endpoints include:
- GET /voter (voter's elections, voting status)
- GET /vote-on/&lt;eid&gt; (election issues, candidate lists, voting form)
- GET /admin (owned elections list)
- GET /manage/&lt;eid&gt; (election metadata, issue list)
- GET /manage-stv/&lt;eid&gt;/&lt;iid&gt; (STV issue details)
- GET /docs/&lt;iid&gt;/&lt;docname&gt; (election documents)
- POST /do-vote/&lt;eid&gt; redirect response (flash message confirming vote)

Data flow: Server generates page with sensitive election data → Response sent without cache-control headers → Intermediate proxy/browser caches response → Cached sensitive data accessible to subsequent requests or shared computer users.

**Affected Files:**
- v3/server/pages.py (ALL route handlers returning sensitive data)

**ASVS:** 14.2.2 (L2), 14.3.2 (L3), 14.2.5 (L2), 14.3.3 (L3)

### Remediation
Add a middleware or decorator that sets anti-caching headers on all authenticated routes:

```python
@APP.after_request
async def no_cache(response):
    if quart.request.path not in ['/static/', '/public/']:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response
```

Alternatively, create a no_cache decorator for specific sensitive endpoints.

### Acceptance Criteria
- [ ] Cache-Control headers added to all authenticated routes
- [ ] Pragma: no-cache header added
- [ ] Expires: 0 header added
- [ ] Static resources excluded from anti-caching
- [ ] Test added to verify headers on sensitive endpoints
- [ ] Test added to verify browser/proxy does not cache pages
- [ ] Documentation updated with caching policy

### References
- Source: 14.2.2.md, 14.3.2.md, 14.2.5.md, 14.3.3.md
- Related: DPP-004, DPP-005, DPP-011, DPP-019, DPP-020

### Priority
High

---

## Issue: FINDING-057 - No documented risk-based remediation timeframes for third-party component vulnerabilities
**Labels:** bug, security, priority:high
**Description:**
### Summary
The codebase contains multiple third-party dependencies (cryptography, argon2-cffi, asfpy, easydict, Quart/asfquart, ezt) but no documentation defining risk-based remediation timeframes for addressing vulnerabilities or specifying update cadence for these libraries.

### Details
No SECURITY.md, DEPENDENCY_POLICY.md, or equivalent documentation is present that defines:
- Critical vulnerability remediation timeframe (e.g., 24-48 hours)
- High vulnerability remediation timeframe (e.g., 7 days)
- Medium/Low vulnerability remediation timeframe (e.g., 30-90 days)
- Routine update schedule for non-vulnerable components

**Affected Files:**
- v3/steve/crypto.py
- v3/steve/election.py
- v3/server/main.py

**ASVS:** 15.1.1 (L1)

### Remediation
Create a docs/DEPENDENCY_POLICY.md with explicit timeframes:

1. Define remediation windows for Critical (48 hours), High (7 days), Medium (30 days), and Low (90 days) severity vulnerabilities
2. Include routine update schedules:
   - Security-critical libraries (cryptography, argon2-cffi) monthly review
   - Framework libraries (Quart/asfquart) quarterly review
   - Utility libraries (easydict, asfpy) semi-annual review
3. Implement automated CVE monitoring via GitHub Dependabot/Safety/pip-audit
4. Manual review of security advisories for cryptography library

### Acceptance Criteria
- [ ] DEPENDENCY_POLICY.md created with remediation timeframes
- [ ] Routine update schedule documented
- [ ] Automated CVE monitoring configured
- [ ] Process for manual security advisory review documented
- [ ] Escalation procedures for critical vulnerabilities defined
- [ ] Test added to verify dependency scanning in CI/CD

### References
- Source: 15.1.1.md
- Related: DEPCOMP-001

### Priority
High

---

## Issue: FINDING-058 - No Software Bill of Materials (SBOM) or dependency manifest with pinned versions
**Labels:** bug, security, priority:high
**Description:**
### Summary
The codebase does not include a visible requirements.txt, pyproject.toml with pinned dependencies, Pipfile.lock, uv.lock, or any SBOM document (e.g., CycloneDX or SPDX format). While main.py uses a `uv run --script` shebang suggesting `uv` as the package manager, no lock file or dependency specification with version pins is provided.

### Details
Identified dependencies from code analysis: cryptography (Fernet, HKDF, hashes), argon2-cffi (low_level), asfpy (db, generics), easydict, asfquart (Quart wrapper), and ezt (templating). All versions are unknown.

Without a versioned inventory:
- Transitive dependencies are untracked (e.g., cryptography pulls in cffi, pycparser)
- Reproducible builds are not guaranteed
- Vulnerability scanning tools cannot accurately assess the dependency tree
- No verification that dependencies come from trusted repositories

**Affected Files:**
- Project-wide
- main.py
- crypto.py
- election.py

**ASVS:** 15.1.2 (L2)

### Remediation
1. Create a pyproject.toml with pinned dependencies including cryptography>=43.0.0, argon2-cffi>=23.1.0, asfpy>=0.45, easydict>=1.13, quart>=0.19.0, ezt>=1.2
2. Generate and maintain a lock file using `uv lock`
3. Generate SBOM in CycloneDX format using `cyclonedx-py environment -o sbom.json`
4. Configure automated SBOM generation in CI/CD pipeline

### Acceptance Criteria
- [ ] pyproject.toml created with all dependencies pinned
- [ ] Lock file generated and committed
- [ ] SBOM generated in CycloneDX format
- [ ] CI/CD pipeline updated to generate SBOM on each build
- [ ] Test added to verify all dependencies are pinned
- [ ] Documentation updated with dependency management procedures

### References
- Source: 15.1.2.md
- Related: DEPCOMP-003

### Priority
High

---

## Issue: FINDING-059 - Undocumented resource-intensive Argon2 operations with potential denial-of-service impact
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application contains several resource-demanding operations involving Argon2 key derivation that are not documented. Each Argon2 call allocates 64MB of memory. For an election with 1000 voters and 10 issues, tally_issue() requires 1000 Argon2 calls with potential 64GB aggregate memory demand.

### Details
Critical operations include:
1. _hash() function with memory_cost=65536 KiB (64MB per call)
2. tally_issue() which iterates over ALL eligible voters calling gen_vote_token() (which calls _hash()) for each voter
3. add_salts() which generates a salt for every person/issue combination in a single transaction
4. open() which calls both add_salts() and gen_opened_key()
5. add_vote() which requires gen_vote_token() (Argon2) plus Fernet encryption per vote submission

Without documentation and mitigation, a large election's tally_issue() could exceed request timeouts, concurrent vote submissions during peak periods could exhaust server memory, and operators have no guidance for capacity planning.

**Affected Files:**
- v3/steve/crypto.py:91-101
- v3/steve/election.py:265-324

**ASVS:** 15.1.3 (L2)

### Remediation
Create docs/RESOURCE_ANALYSIS.md documenting:

1. Argon2 Key Derivation - Memory: 64MB per operation, CPU: ~50ms per operation (2 iterations, 4 threads), Locations: Vote submission, tally computation, election opening
2. Tally Computation - Complexity: O(voters × issues) Argon2 operations, Mitigation: Performed offline via admin CLI (not web request), Timeout: Not applicable (CLI operation)
3. Vote Submission - Complexity: 1 Argon2 operation per vote, Mitigation: Single-instance deployment limits concurrency, Max concurrent: Limited by server memory (e.g., 16GB / 64MB = 250 concurrent)
4. Election Opening - Complexity: O(voters × issues) salt generations + 1 Argon2, Mitigation: Admin-only operation, performed once per election lifecycle
5. Defenses - Tally is an admin CLI operation not exposed to web requests, Vote submission is authenticated (prevents anonymous DoS), Single-instance architecture limits parallelism naturally

### Acceptance Criteria
- [ ] RESOURCE_ANALYSIS.md created with complete documentation
- [ ] Resource limits documented for each operation type
- [ ] Capacity planning guidelines provided
- [ ] Maximum election size guidelines documented
- [ ] Monitoring recommendations provided
- [ ] Test added to verify resource usage under load

### References
- Source: 15.1.3.md
- Related: DEPCOMP-005

### Priority
High

---

## Issue: FINDING-060 - Cannot verify component versions are within remediation timeframes due to missing version specifications
**Labels:** bug, security, priority:high
**Description:**
### Summary
Since no dependency manifest with pinned versions exists (ASVS-15.1.2), and no remediation policy exists (ASVS-15.1.1), it is impossible to verify that all components are within their documented update and remediation timeframes.

### Details
Specific concerns:
1. cryptography library has frequent security advisories and without pinned version cannot verify currency
2. Argon2 Type.D usage while OWASP recommends Type.ID for password hashing, with divergence between benchmark (Type.ID) and production (Type.D)
3. asfpy ASF-internal library with unknown release cadence and vulnerability tracking
4. HKDF info parameter mismatch (info=b'xchacha20_key') is misleading for current Fernet usage, suggesting code may be in transitional state beyond intended timeframe

**Affected Files:**
- v3/steve/crypto.py
- Project-wide

**ASVS:** 15.2.1 (L1)

### Remediation
1. Pin all dependency versions in pyproject.toml or equivalent
2. Implement automated vulnerability scanning using pip-audit --require-hashes --desc or uv pip audit in CI/CD pipeline
3. Create a dependency update log documenting Date, Component, From Version, To Version, and Reason for all updates

### Acceptance Criteria
- [ ] All dependencies pinned in pyproject.toml
- [ ] Automated vulnerability scanning configured in CI/CD
- [ ] Dependency update log created and maintained
- [ ] Test added to verify no unpinned dependencies
- [ ] Test added to verify vulnerability scanning runs
- [ ] Documentation updated with update procedures

### References
- Source: 15.2.1.md
- Related: DEPCOMP-008

### Priority
High

---

## Issue: FINDING-061 - No logging inventory or documentation exists for the application stack
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application uses Python's standard logging module across three layers (web pages, election library, CLI tools) but no logging inventory document exists defining what events are logged, log format specification, where logs are stored, how log access is controlled, log retention periods, and how logs are consumed for monitoring/alerting.

### Details
The logging.basicConfig(level=logging.INFO) in tally.py sends to stderr by default. The web layer (pages.py) relies on whatever the application framework configures, which is undocumented. The election.py library logs to a logger with no explicit handler configuration.

**Affected Files:**
- v3/server/bin/tally.py:165
- v3/server/pages.py:37
- v3/steve/election.py:27

**ASVS:** 16.1.1 (L2)

### Remediation
Create a LOGGING_INVENTORY.md or equivalent documentation covering all layers, components, logger names, events logged, format, destination, retention, and access control. Document each layer (Web/pages.py, Library/election.py, CLI/tally.py) with structured information including:
- JSON formatted logs
- Specific file destinations
- 90-day to 1-year retention periods
- Appropriate file permissions (root:adm 640)

### Acceptance Criteria
- [ ] LOGGING_INVENTORY.md created with complete documentation
- [ ] All logging layers documented
- [ ] Log format specification defined
- [ ] Log destinations documented
- [ ] Retention periods specified
- [ ] Access control requirements documented
- [ ] Monitoring/alerting procedures defined

### References
- Source: 16.1.1.md
- Related: LOG-001

### Priority
High

---

## Issue: FINDING-062 - Election library logging omits WHO (actor) metadata from security events
**Labels:** bug, security, priority:high
**Description:**
### Summary
The election.py library logs creation, update, and state-change events without recording WHO performed the action. While pages.py adds user context at the handler level, the library-level logs are missing the actor (PID/UID). If the library is invoked through a different path (e.g., tally.py, future APIs, or direct imports), the WHO metadata is entirely absent.

### Details
During incident investigation, it becomes impossible to correlate library-level events with the user who triggered them. This creates blind spots in the audit trail, especially for operations that bypass the web layer (CLI tools, scripts, direct database manipulation).

**Affected Files:**
- v3/steve/election.py:207
- v3/steve/election.py:219
- v3/steve/election.py:231
- v3/steve/election.py:430

**ASVS:** 16.2.1 (L2)

### Remediation
Option 1: Pass actor context to library methods:
```python
def add_issue(self, title, description, vtype, kv, actor_pid=None):
    ...
    _LOGGER.info(f'Actor[U:{actor_pid}] created issue[I:{iid}] in election[E:{self.eid}]')
```

Option 2: Use logging context (LoggerAdapter or contextvars):
```python
import contextvars
_actor_ctx = contextvars.ContextVar('actor_pid', default='system')

class Election:
    def add_issue(self, title, description, vtype, kv):
        ...
        _LOGGER.info(f'Actor[U:{_actor_ctx.get()}] created issue[I:{iid}] in election[E:{self.eid}]')
```

### Acceptance Criteria
- [ ] Actor context added to all library logging calls
- [ ] WHO metadata included in all security events
- [ ] Test added to verify actor context in logs
- [ ] Documentation updated with logging standards
- [ ] Code review to ensure consistent actor logging

### References
- Source: 16.2.1.md
- Related: LOG-003

### Priority
High

---

## Issue: FINDING-063 - Tally script performs security-critical operations without audit logging
**Labels:** bug, security, priority:high
**Description:**
### Summary
The tally script decrypts all votes for an election—one of the most sensitive operations in the system—without logging WHO (which administrator ran the tally), WHEN (timestamp of tally execution), WHERE (from which machine/terminal), or WHAT (which election was tallied, whether `--spy-on-open-elections` was used).

### Details
The `--spy-on-open-elections` flag is especially concerning as it enables viewing votes before an election closes, and its use is not logged at all. An administrator could spy on open election results without any audit trail. Tamper detection events are output via print() rather than formal security logging, meaning they may not reach monitoring systems.

**Affected Files:**
- v3/server/bin/tally.py:138-165

**ASVS:** 16.2.1 (L2), 16.4.3 (L2)

### Remediation
```python
def main(spy_on_open, election_id, issue_id, db_fname, output_format):
    import getpass
    import socket
    
    operator = getpass.getuser()
    hostname = socket.gethostname()
    
    _LOGGER.warning(
        f'TALLY_INITIATED operator={operator} host={hostname} '
        f'election_id={election_id} issue_id={issue_id} '
        f'spy_on_open={spy_on_open} db_path={db_fname}'
    )
    
    # ... existing logic ...
    
    if election.is_tampered(pdb):
        _LOGGER.critical(
            f'TAMPER_DETECTED operator={operator} election_id={election_id}'
        )
        sys.exit(1)
    
    _LOGGER.info(
        f'TALLY_COMPLETED operator={operator} election_id={election_id} '
        f'issues_tallied={len(issues)} voters_found={len(all_voters)}'
    )
```

### Acceptance Criteria
- [ ] Tally initiation logged with WHO, WHEN, WHERE, WHAT
- [ ] --spy-on-open-elections flag usage logged
- [ ] Tamper detection uses structured logging
- [ ] Tally completion logged with summary
- [ ] Test added to verify audit logging
- [ ] Documentation updated with tally audit requirements

### References
- Source: 16.2.1.md, 16.4.3.md
- Related: LOG-004, LOG-037

### Priority
High

---

## Issue: FINDING-064 - Debug print statements dump complete form data which may contain sensitive election configuration
**Labels:** bug, security, priority:high
**Description:**
### Summary
Complete form data is dumped to stdout without any filtering or redaction. While current form fields are title and description, the EasyDict wrapper captures ALL submitted form fields. If future forms include sensitive data (candidate names for confidential elections, authorization groups, etc.), this would log them without protection.

### Details
The print() call is a Type B gap—the _LOGGER system exists but is not used here, creating false confidence that logging is controlled. Any data submitted in these forms is broadcast to stdout without classification-based filtering. In containerized deployments, stdout is captured by orchestrators and may be accessible to operators without appropriate clearance.

**Affected Files:**
- v3/server/pages.py:427
- v3/server/pages.py:449

**ASVS:** 16.2.5 (L2)

### Remediation
Remove print statements entirely, or log only safe metadata:
```python
_LOGGER.debug(f'Issue form received: fields={list(form.keys())}')
```
Never log form values for election management operations.

### Acceptance Criteria
- [ ] Debug print statements removed or replaced with safe logging
- [ ] Form values never logged
- [ ] Only safe metadata (field names) logged if needed
- [ ] Test added to verify no sensitive data in logs
- [ ] Code review to find other print() statements
- [ ] Documentation updated with logging standards

### References
- Source: 16.2.5.md
- Related: LOG-013

### Priority
High

---

## Issue: FINDING-065 - No Authentication Event Logging in Application Code
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application relies on asfquart.auth.require decorators for authentication enforcement, but no logging occurs at the authentication boundary within this application code. There is no evidence of authentication success or failure being logged. Authentication successes and failures are invisible to security monitoring. Brute force attempts, credential stuffing, or unauthorized access patterns cannot be detected through application logs.

### Details
Authentication events are critical for security monitoring and incident response. The current implementation provides no visibility into authentication attempts, making it impossible to detect or respond to authentication-based attacks.

**Affected Files:**
- v3/server/pages.py (entire file)

**ASVS:** 16.3.1 (L2)

### Remediation
Add authentication event logging middleware or hook:
```python
@APP.before_request
async def log_authentication_event():
    """Log all authentication attempts with metadata."""
    s = await asfquart.session.read()
    if s:
        _LOGGER.info(
            'AUTH_SUCCESS: uid=%s, method=oauth, ip=%s, path=%s',
            sanitize_log(s['uid']),
            quart.request.remote_addr,
            quart.request.path,
        )
    elif quart.request.path not in PUBLIC_PATHS:
        _LOGGER.warning(
            'AUTH_FAILURE: ip=%s, path=%s, reason=no_session',
            quart.request.remote_addr,
            quart.request.path,
        )
```

### Acceptance Criteria
- [ ] Authentication success events logged
- [ ] Authentication failure events logged
- [ ] User ID, IP address, and path included in logs
- [ ] Test added to verify authentication logging
- [ ] Test added to verify failure logging
- [ ] Documentation updated with authentication logging requirements

### References
- Source: 16.3.1.md
- Related: LOG-016

### Priority
High

---

## Issue: FINDING-066 - Tampering Detection Does Not Use Logger
**Labels:** bug, security, priority:high
**Description:**
### Summary
The tamper detection check uses print() instead of the logging framework when tampering is detected—a critical security event. Tampering detected → print() to stdout → potentially lost if stdout is not captured → NO structured security log. Critical tampering events may not reach centralized logging systems.

### Details
A print() to stdout may be lost if the process output is not captured, and it lacks structured metadata (timestamp format, severity, correlation IDs). This is a critical security event that must be reliably captured and monitored.

**Affected Files:**
- v3/server/bin/tally.py:153-156

**ASVS:** 16.3.3 (L2), 16.3.4 (L2)

### Remediation
Replace print() with structured logging using _LOGGER.critical() for tamper detection events:
```python
if election.is_tampered(pdb):
    _LOGGER.critical(
        'TAMPER_DETECTED: election_id=%s, db_path=%s',
        election_id,
        str(db_fname),
    )
    print(f'Error: Election {election_id} has been tampered with. Cannot proceed.')
    sys.exit(1)
```

### Acceptance Criteria
- [ ] Tamper detection uses structured logging
- [ ] Critical severity level used
- [ ] Election ID and database path included
- [ ] User-facing error message still displayed
- [ ] Test added to verify tamper detection logging
- [ ] Documentation updated with security event logging requirements

### References
- Source: 16.3.3.md, 16.3.4.md
- Related: LOG-022, LOG-026

### Priority
High

---

## Issue: FINDING-067 - Input Validation Failures Not Logged
**Labels:** bug, security, priority:high
**Description:**
### Summary
Input validation failures (potential bypass attempts) are not logged. Malformed input → validation failure → 400 response → NO LOG. This affects multiple endpoints including _set_election_date, do_vote_endpoint (missing form data check), and do_vote_endpoint (invalid issue ID check). Injection attempts would be caught by validation but leave no audit trail.

### Details
Without logging validation failures, it's impossible to detect patterns of attack attempts, identify attackers probing for vulnerabilities, or correlate failed attempts with successful compromises.

**Affected Files:**
- v3/server/pages.py:95-102
- v3/server/pages.py:385
- v3/server/pages.py:393

**ASVS:** 16.3.3 (L2)

### Remediation
Add logging for all input validation failures:
```python
if not date_str:
    _LOGGER.warning(
        'INPUT_VALIDATION_FAILURE: uid=%s, endpoint=set_%s, reason=missing_date, election=%s',
        result.uid, field, election.eid,
    )
    quart.abort(400, 'Missing date')

try:
    dt = datetime.datetime.fromisoformat(date_str).date()
except ValueError:
    _LOGGER.warning(
        'INPUT_VALIDATION_FAILURE: uid=%s, endpoint=set_%s, reason=invalid_date_format, election=%s',
        result.uid, field, election.eid,
    )
    quart.abort(400, 'Invalid date format')
```

### Acceptance Criteria
- [ ] All input validation failures logged
- [ ] User ID, endpoint, and reason included in logs
- [ ] Test added to verify validation failure logging
- [ ] Test added to verify different failure types are logged
- [ ] Documentation updated with input validation logging requirements

### References
- Source: 16.3.3.md
- Related: LOG-023

### Priority
High

---

## Issue: FINDING-068 - No log transmission to a logically separate system
**Labels:** bug, security, priority:high
**Description:**
### Summary
The entire application uses Python's standard logging module with no configuration for transmitting logs to a logically separate system. If the application server is compromised, all security-relevant logs (authentication events, vote casting, election lifecycle changes, authorization failures) reside on the same system and can be modified or deleted by an attacker, destroying forensic evidence.

### Details
The tally.py CLI configures logging.basicConfig(level=logging.INFO) which outputs to stderr only. The web application (pages.py) relies on Quart's default logging configuration, which similarly only writes locally. There is no evidence of: Syslog forwarding configuration, Integration with centralized log management (ELK, Splunk, CloudWatch), Log shipping agents or sidecars configured, Remote logging handlers, or Any log output to files that could be shipped.

**Affected Files:**
- v3/server/pages.py:35
- v3/steve/election.py:7
- v3/server/bin/tally.py:34, 166

**ASVS:** 16.4.3 (L2)

### Remediation
Configure remote logging handlers to send logs to a logically separate system:
```python
import logging.handlers

# Configure SysLogHandler for remote logging
syslog_handler = logging.handlers.SysLogHandler(
    address=('logserver.internal.example.org', 514),
    facility=logging.handlers.SysLogHandler.LOG_AUTH
)
syslog_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(name)s %(levelname)s %(message)s'
))
_LOGGER.addHandler(syslog_handler)
```

### Acceptance Criteria
- [ ] Remote logging handler configured
- [ ] Logs transmitted to separate system
- [ ] Connection failure handling implemented
- [ ] Test added to verify remote log transmission
- [ ] Test added to verify local logs still work if remote fails
- [ ] Documentation updated with logging infrastructure requirements
- [ ] Log server configuration documented

### References
- Source: 16.4.3.md
- Related: LOG-036

### Priority
High

---

## Issue: FINDING-069 - No graceful degradation for database connectivity failures
**Labels:** bug, security, priority:high
**Description:**
### Summary
The load_election and load_election_issue decorators only catch ElectionNotFound exceptions. If the SQLite database file is locked, corrupted, or unavailable (disk full, permissions changed, etc.), an unhandled exception propagates to the framework's default error handler. There is no circuit breaker, retry logic, or graceful degradation pattern.

### Details
This affects ALL routes that use load_election or load_election_issue: GET /vote-on/&lt;eid&gt;, GET /manage/&lt;eid&gt;, GET /manage-stv/&lt;eid&gt;/&lt;iid&gt;, POST /do-set-open_at/&lt;eid&gt;, POST /do-set-close_at/&lt;eid&gt;, POST /do-vote/&lt;eid&gt;, GET /do-open/&lt;eid&gt;, GET /do-close/&lt;eid&gt;, POST /do-add-issue/&lt;eid&gt;, POST /do-edit-issue/&lt;eid&gt;/&lt;iid&gt;, POST /do-delete-issue/&lt;eid&gt;/&lt;iid&gt;.

Additionally affected without any decorator protection: GET /voter (directly calls Election.open_to_pid), GET /admin (directly calls Election.open_to_pid, Election.owned_elections).

Database lock contention, disk failures, or resource exhaustion causes unhandled exceptions across all endpoints, potentially exposing error details and causing service unavailability without informative user messaging.

**Affected Files:**
- v3/server/pages.py (all route handlers)
- v3/steve/election.py:38

**ASVS:** 16.5.2 (L2)

### Remediation
Add exception handling for database connectivity failures in the load_election decorator:
```python
def load_election(func):
    @functools.wraps(func)
    async def loader(eid):
        try:
            e = steve.election.Election(DB_FNAME, eid)
        except steve.election.ElectionNotFound:
            result = await basic_info()
            result.title = 'Unknown Election'
            result.eid = eid
            raise_404(T_BAD_EID, result)
        except (sqlite3.OperationalError, OSError) as e:
            _LOGGER.error(f'Database unavailable: {e}')
            quart.abort(503)  # Service Unavailable
        return await func(e)
    return loader
```

### Acceptance Criteria
- [ ] Database connectivity exceptions caught and handled
- [ ] 503 Service Unavailable returned for database failures
- [ ] Error logged with appropriate severity
- [ ] User-friendly error message displayed
- [ ] Test added to verify database failure handling
- [ ] Test added to verify appropriate HTTP status codes
- [ ] Documentation updated with error handling patterns

### References
- Source: 16.5.2.md
- Related: LOG-040

### Priority
High

---

## Issue: FINDING-070 - Implicit authorization failure via None dereference instead of explicit check in add_vote
**Labels:** bug, security, priority:high
**Description:**
### Summary
When a person is not authorized to vote on a specific issue (no mayvote entry exists), the query returns None. The code immediately accesses mayvote.salt without checking for None. This results in an AttributeError rather than a proper authorization denial. While the vote IS blocked (fail-closed), the error response is a generic 500 rather than a proper 403 Forbidden.

### Details
While this is technically fail-closed (the vote is not accepted), it represents a fragile security boundary that depends on an accidental crash rather than intentional enforcement. The 500 error also provides no useful feedback to the caller and may expose implementation details.

**Affected Files:**
- v3/steve/election.py:210-211

**ASVS:** 16.5.3 (L2)

### Remediation
```python
mayvote = self.q_get_mayvote.first_row(pid, iid)
if mayvote is None:
    raise VoterNotAuthorized(f'Person {pid} is not authorized to vote on issue {iid}')
vote_token = crypto.gen_vote_token(md.opened_key, pid, iid, mayvote.salt)
```

### Acceptance Criteria
- [ ] Explicit authorization check added before accessing mayvote.salt
- [ ] VoterNotAuthorized exception defined and raised
- [ ] 403 Forbidden status returned for authorization failures
- [ ] Test added to verify authorization check
- [ ] Test added to verify appropriate error response
- [ ] Documentation updated with authorization error handling

### References
- Source: 16.5.3.md
- Related: LOG-044

### Priority
High

---

## Issue: FINDING-071 - No global exception handler defined for the web application
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application defines no "last resort" error handler. There is no @APP.errorhandler(Exception), @APP.errorhandler(500), or equivalent catch-all that would log the full exception details for debugging, return a generic error page to the user, and prevent the application process from crashing on unexpected exceptions.

### Details
Only ElectionNotFound, IssueNotFound, and PersonNotFound are caught in specific locations. Any other exception type (e.g., sqlite3.OperationalError, TypeError, KeyError, json.JSONDecodeError) propagates to the framework default handler.

Quart's default behavior in production mode returns a 500 page, but there's no guarantee DEBUG mode isn't enabled, error details are not guaranteed to be logged by a custom handler, no alerting or escalation is triggered, and no consistent error response format exists.

Entry points without exception coverage include: all routes using load_election only catch ElectionNotFound, voter_page() calls Election.open_to_pid() with no error handling, admin_page() calls PersonDB.open() with no handling for DB errors, and serve_doc() uses send_from_directory() with no handling for OS errors.

**Affected Files:**
- v3/server/pages.py (entire file)

**ASVS:** 16.5.4 (L3)

### Remediation
Implement global exception handlers:
```python
@APP.errorhandler(Exception)
async def last_resort_handler(error):
    """Catch-all error handler to log details and return generic error."""
    _LOGGER.exception(f'Unhandled exception: {error}')
    return await quart.render_template('error_500.html'), 500

@APP.errorhandler(500)
async def internal_error(error):
    """Handle 500 Internal Server Errors."""
    _LOGGER.error(f'Internal server error: {error}')
    return await quart.render_template('error_500.html'), 500

@APP.errorhandler(503)
async def service_unavailable(error):
    """Handle service unavailability."""
    _LOGGER.warning(f'Service unavailable: {error}')
    return await quart.render_template('error_503.html'), 503
```

### Acceptance Criteria
- [ ] Global exception handler implemented for Exception
- [ ] Specific handlers for 500 and 503 status codes
- [ ] Error templates created (error_500.html, error_503.html)
- [ ] All exceptions logged with appropriate severity
- [ ] Generic error messages returned to users (no implementation details)
- [ ] Test added to verify exception handling
- [ ] Test added to verify no stack traces in responses
- [ ] Documentation updated with error handling patterns

### References
- Source: 16.5.4.md
- Related: LOG-046

### Priority
High

---

## Issue: FINDING-072 - No file size validation to prevent denial of service
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application serves documents via `/docs/<iid>/<docname>` but has no visible file upload endpoint with size validation. The mechanism by which documents are placed into `DOCSDIR` is not shown in the provided code, meaning there are no observable file size checks that would prevent a denial of service via excessively large files.

### Details
If files are uploaded through an undocumented mechanism, no size limits are enforced by the shown code. Additionally, the Quart application does not set `MAX_CONTENT_LENGTH` (or equivalent) to limit request body size globally, which would affect any file upload functionality added in the future.

**Affected Files:**
- v3/server/pages.py (entire application scope)

**ASVS:** 5.2.1 (L1)

### Remediation
Configure `APP.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024` to set a 10 MB max upload limit. In any file upload handler, implement explicit size checking:
```python
file.seek(0, os.SEEK_END)
size = file.tell()
file.seek(0)
if size > 10 * 1024 * 1024:  # 10 MB
    quart.abort(413, 'File too large')
```

### Acceptance Criteria
- [ ] MAX_CONTENT_LENGTH configured globally
- [ ] File size validation implemented in upload handlers
- [ ] 413 Payload Too Large returned for oversized files
- [ ] Test added to verify size limit enforcement
- [ ] Test added to verify acceptable files are processed
- [ ] Documentation updated with file size limits

### References
- Source: 5.2.1.md
- Related: FILE-2

### Priority
High

---

## Issue: FINDING-073 - Missing file extension and content validation in document serving endpoint
**Labels:** bug, security, priority:high
**Description:**
### Summary
The `serve_doc()` endpoint serves arbitrary files from the `DOCSDIR` directory. While no upload handler is visible in this codebase, the docs directory appears to be populated through external means. There is no validation that served files are non-executable content types.

### Details
If an attacker (or misconfigured process) places a file with a server-executable extension (e.g., `.py`, `.php`) in the docs directory, and if a reverse proxy or misconfigured server processes certain extensions, the file could be executed. With `send_from_directory`, Quart serves files as static content which mitigates direct Python execution, but upstream server configurations could still be vulnerable.

**Affected Files:**
- v3/server/pages.py:560-574

**ASVS:** 5.2.2 (L1), 5.3.1 (L2), 1.3.3 (L2)

### Remediation
Implement file extension allowlist validation and magic bytes content verification using python-magic library. Add security headers (X-Content-Type-Options: nosniff, Content-Disposition: attachment) to all file serve responses:
```python
import magic

ALLOWED_EXTENSIONS = {'.pdf', '.txt', '.png', '.jpg', '.jpeg'}
ALLOWED_MIMETYPES = {
    '.pdf': 'application/pdf',
    '.txt': 'text/plain',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
}

@APP.route('/docs/<iid>/<docname>')
async def serve_doc(iid, docname):
    ext = os.path.splitext(docname)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        quart.abort(403, 'File type not allowed')
    
    filepath = os.path.join(DOCSDIR, iid, docname)
    detected_mime = magic.from_file(filepath, mime=True)
    if detected_mime != ALLOWED_MIMETYPES[ext]:
        quart.abort(403, 'File content does not match extension')
    
    response = await quart.send_from_directory(os.path.join(DOCSDIR, iid), docname)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Disposition'] = 'attachment'
    return response
```

### Acceptance Criteria
- [ ] File extension allowlist implemented
- [ ] Magic bytes validation implemented using python-magic
- [ ] Security headers added to file responses
- [ ] 403 Forbidden returned for disallowed file types
- [ ] Test added to verify extension validation
- [ ] Test added to verify content validation
- [ ] Test added to verify security headers
- [ ] Documentation updated with allowed file types

### References
- Source: 5.2.2.md, 5.3.1.md, 1.3.3.md
- Related: FILE-3, FILE-4, FILE-8, INJ-011

### Priority
High

---

## Issue: FINDING-074 - No Token Audience Validation After OAuth Exchange
**Labels:** bug, security, priority:high
**Description:**
### Summary
The session data (uid, fullname, email) is consumed directly from asfquart.session.read() without any validation that the underlying token was issued specifically for the STeVe application. No aud claim is checked. No iss claim is verified against an expected value.

### Details
By explicitly avoiding OIDC (as noted in main.py line 29 comment), the application loses the standardized aud claim validation that OIDC ID tokens provide. OIDC requires that the ID token's aud claim contains the client_id of the relying party, which is exactly what ASVS 9.2.4 requires.

If the OAuth provider issues tokens that can be consumed by multiple services, the application has no defense against cross-service token confusion attacks. Any valid session from another ASF application sharing the same OAuth provider could potentially be used to access STeVe endpoints.

**Affected Files:**
- v3/server/pages.py:75-106

**ASVS:** 9.2.4 (L2)

### Remediation
Add audience and issuer validation:
```python
async def basic_info():
    """Return base-level EZT template data."""
    basic = edict()
    s = await asfquart.session.read()
    if s:
        # Validate audience claim matches this application
        expected_audience = APP.cfg.oauth.client_id  # e.g., 'steve-voting'
        token_audience = s.get('aud', s.get('audience'))
        if token_audience and expected_audience not in (
            token_audience if isinstance(token_audience, list) else [token_audience]
        ):
            _LOGGER.warning(f'Token audience mismatch: {token_audience} != {expected_audience}')
            basic.update(uid=None, name=None, email=None)
            return basic
            
        # Validate issuer
        expected_issuer = 'https://oauth.apache.org'
        if s.get('iss') and s.get('iss') != expected_issuer:
            _LOGGER.warning(f'Token issuer mismatch: {s.get("iss")}')
            basic.update(uid=None, name=None, email=None)
            return basic
            
        basic.update(uid=s['uid'], name=s['fullname'], email=s['email'])
```

### Acceptance Criteria
- [ ] Audience validation implemented
- [ ] Issuer validation implemented
- [ ] Expected audience configured
- [ ] Expected issuer configured
- [ ] Test added to verify audience validation
- [ ] Test added to verify issuer validation
- [ ] Test added to verify rejection of invalid tokens
- [ ] Documentation updated with token validation requirements

### References
- Source: 9.2.4.md
- Related: TOKEN-008

### Priority
High

---

## Issue: FINDING-075 - No Documented Cryptographic Key Management Policy or Key Lifecycle
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The codebase contains multiple cryptographic keys and secrets (election salt, opened_key, vote_token, vote encryption keys) but there is no documented key management policy conforming to NIST SP 800-57 or an equivalent standard. Without a documented key lifecycle, keys may persist beyond their intended use period, accumulate risk, and lack clear procedures for compromise response.

### Details
While schema.md provides some documentation of what keys exist, it does not constitute a key lifecycle policy addressing: Key generation procedures and responsibilities, Key storage and protection requirements, Key distribution controls, Key usage periods / expiration, Key revocation and destruction procedures, Key recovery mechanisms.

The opened_key persists in the database indefinitely after an election closes, with no documented destruction schedule.

**Affected Files:**
- v3/steve/crypto.py
- v3/docs/schema.md

**ASVS:** 11.1.1 (L2)

### Remediation
Create a formal cryptographic key management policy document covering:
1. Key types, purposes, and authorized users
2. Key generation procedures (already using secrets module)
3. Maximum key lifetime per key type
4. Key storage protection requirements
5. Key destruction procedures (e.g., zeroing opened_key after tally completion)
6. Incident response for key compromise

### Acceptance Criteria
- [ ] Cryptographic key management policy document created
- [ ] Key types and purposes documented
- [ ] Key lifecycle procedures defined
- [ ] Key destruction procedures documented
- [ ] Incident response procedures for key compromise defined
- [ ] Policy reviewed and approved
- [ ] Documentation published and accessible to team

### References
- Source: 11.1.1.md
- Related: VOTE-CRYPTO-001

### Priority
Medium

---

## Issue: FINDING-076 - Incomplete Cryptographic Inventory - Missing Algorithm and Key Usage Documentation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
While schema.md documents some cryptographic assets, it does not constitute a complete cryptographic inventory. Without a complete inventory, it's impossible to systematically assess cryptographic risk, plan migrations, or ensure all cryptographic assets are properly managed.

### Details
The following are not formally inventoried:
1. Algorithms not documented: BLAKE2b (64-byte digest, used as pre-hash for Argon2), HKDF-SHA256 (used for key stretching vote_token → vote_key), The specific Fernet composition (AES-128-CBC + HMAC-SHA256)
2. Key usage boundaries not documented: Where each key type CAN be used vs. CANNOT be used, What data types each key protects, Which components have access to which keys
3. No centralized inventory document: Crypto information is scattered across schema.md, crypto.py comments, and schema.sql comments

**Affected Files:**
- v3/steve/crypto.py:49, 61-66
- v3/docs/schema.md

**ASVS:** 11.1.2 (L2)

### Remediation
Create a dedicated CRYPTO_INVENTORY.md document containing a table with columns: Asset, Algorithm, Key Length, Purpose, Protected Data, Access Scope, Location. Include all cryptographic assets: election salt, opened key, mayvote salt, vote token, vote key, and ciphertext with their respective algorithms and parameters.

### Acceptance Criteria
- [ ] CRYPTO_INVENTORY.md created
- [ ] All cryptographic assets documented
- [ ] Algorithms and parameters specified
- [ ] Key usage boundaries defined
- [ ] Access scopes documented
- [ ] Inventory reviewed and approved
- [ ] Process defined for keeping inventory current

### References
- Source: 11.1.2.md
- Related: VOTE-CRYPTO-003

### Priority
Medium

---

## Issue: FINDING-077 - No Cryptographic Discovery Mechanisms Employed
**Labels:** bug, security, priority:medium
**Description:**
### Summary
There is no evidence of automated cryptographic discovery mechanisms being employed to identify all instances of cryptography in the system. No tooling, CI/CD pipeline steps, or scanning configurations are present to discover all cryptographic library usage, identify encryption, hashing, and signing operations, detect introduction of new cryptographic operations, or flag deprecated or weak algorithm usage.

### Details
The pyproject.toml defines development dependencies but includes no cryptographic scanning tools. No tools like cryptosense, crypto-detector, semgrep with crypto rules, or custom SAST rules for cryptographic operations are configured.

**Affected Files:**
- pyproject.toml
- v3/steve/pages.py:269

**ASVS:** 11.1.3 (L3)

### Remediation
1. Add a cryptographic linting step to CI/CD using tools like: semgrep with crypto-specific rules, custom ruff or pylint rules flagging hashlib, cryptography, hmac imports, SAST tools configured to flag crypto operations
2. Maintain a list of approved crypto imports/modules
3. Run periodic scans to detect drift from the inventory

### Acceptance Criteria
- [ ] Cryptographic scanning tool selected and configured
- [ ] CI/CD pipeline updated with crypto scanning step
- [ ] Approved crypto imports list created
- [ ] Scan results reviewed and baseline established
- [ ] Process defined for reviewing new crypto usage
- [ ] Documentation updated with crypto scanning procedures

### References
- Source: 11.1.3.md
- Related: VOTE-CRYPTO-004

### Priority
Medium

---

## Issue: FINDING-078 - No Documented Post-Quantum Cryptography Migration Plan
**Labels:** bug, security, priority:medium
**Description:**
### Summary
While the code acknowledges a planned transition from Fernet to XChaCha20-Poly1305, there is no documented migration plan addressing post-quantum cryptography threats. The current cryptographic primitives (AES-128, SHA-256, BLAKE2b) have varying levels of quantum resistance, and no formal assessment or migration roadmap exists.

### Details
Without a migration plan, the project cannot react efficiently to quantum computing advances. The planned Fernet → XChaCha20-Poly1305 migration doesn't address quantum threats (both are symmetric and similarly affected by Grover's algorithm). AES-128 specifically should be upgraded to AES-256 for quantum resistance.

**Affected Files:**
- v3/steve/crypto.py:63
- v3/docs/schema.md

**ASVS:** 11.1.4 (L3), 15.1.1 (L1)

### Remediation
Create a PQC_MIGRATION_PLAN.md documenting:
1. Current algorithm inventory with quantum risk assessment
2. Timeline for migrating AES-128 (Fernet) to AES-256 or authenticated encryption with 256-bit keys
3. Assessment of when PQC-resistant key exchange might be needed (if TLS/network crypto is added)
4. Crypto-agility requirements (see 11.2.2) to enable seamless future upgrades
5. Data re-encryption strategy for stored ciphertext

### Acceptance Criteria
- [ ] PQC_MIGRATION_PLAN.md created
- [ ] Current algorithms assessed for quantum resistance
- [ ] Migration timeline defined
- [ ] Crypto-agility requirements documented
- [ ] Data re-encryption strategy defined
- [ ] Plan reviewed and approved
- [ ] Monitoring plan for quantum computing advances defined

### References
- Source: 11.1.4.md, 15.1.1.md
- Related: VOTE-CRYPTO-005, DEPCOMP-002

### Priority
Medium

---

## Issue: FINDING-079 - Argon2d (Type.D) Used Instead of Recommended Argon2id (Type.ID)
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The production _hash() function uses Argon2d (data-dependent memory access), which is vulnerable to side-channel attacks (cache-timing attacks). RFC 9106 and OWASP recommend Argon2id for most applications, as it combines the side-channel resistance of Argon2i with the GPU/ASIC resistance of Argon2d.

### Details
The benchmark function at line 118 correctly uses Type.ID, suggesting awareness of the recommended variant, but the production code was not updated. In environments where an attacker can observe memory access patterns (shared hosting, VMs, certain cloud environments), Argon2d is vulnerable to side-channel extraction of the secret. This could enable extraction of opened_keys or vote_tokens.

**Affected Files:**
- v3/steve/crypto.py:89, 87, 84, 85-93

**ASVS:** 11.2.1 (L2), 11.2.4 (L3), 11.4.2 (L2), 11.4.4 (L3), 11.6.1 (L2), 15.2.1 (L1)

### Remediation
Change the type parameter in the _hash() function from argon2.low_level.Type.D to argon2.low_level.Type.ID (RFC 9106 recommended). 

**Note:** This will change all derived values, so must be coordinated with any existing deployed databases. Add a crypto_version column to the vote table to enable future algorithm transitions without data loss.

### Acceptance Criteria
- [ ] Argon2 type changed from Type.D to Type.ID
- [ ] crypto_version column added to vote table
- [ ] Migration plan created for existing databases
- [ ] Test added to verify Type.ID is used
- [ ] Test added to verify algorithm version tracking
- [ ] Documentation updated with Argon2 configuration
- [ ] Coordination plan for production deployment

### References
- Source: 11.2.1.md, 11.2.4.md, 11.4.2.md, 11.4.4.md, 11.6.1.md, 15.2.1.md
- Related: VOTE-CRYPTO-006, DEPCOMP-009

### Priority
Medium

---

## Issue: FINDING-081 - Unhandled Cryptographic Decryption Exceptions in Vote Tallying
**Labels:** bug, security, priority:high
**Description:**
### Summary
A single corrupted vote ciphertext causes the entire tally_issue() operation to fail with an unhandled cryptography.fernet.InvalidToken exception, creating a denial-of-service vector against the tallying function.

### Details
If any vote's ciphertext is corrupted (database corruption, malicious tampering with SQLite file), the entire tally operation fails. Data flow: ciphertext from database → Fernet.decrypt() → no exception handling → unhandled InvalidToken propagates → entire tally operation fails. While Fernet's encrypt-then-MAC construction prevents Padding Oracle attacks (HMAC verified before decryption), a single corrupted vote prevents ALL votes from being tallied.

**CWE:** None specified
**ASVS:** 11.2.5 (L3)
**Files:** v3/steve/election.py:283-290, v3/steve/crypto.py

### Remediation
Wrap the decryption call in a try/except block to handle InvalidToken exceptions gracefully. Log the failure generically without exposing details that could differentiate between HMAC failure vs decryption failure. Skip the corrupted vote and continue processing remaining votes rather than failing the entire tally operation.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 11.2.5.md
- Domain: vote_encryption_and_cryptography

### Priority
**Severity:** Medium

---

## Issue: FINDING-082 - Use of Fernet (AES-128-CBC) Instead of Approved AEAD Cipher
**Labels:** bug, security, priority:high
**Description:**
### Summary
The code uses Fernet (AES-128-CBC + HMAC-SHA256) instead of the acknowledged target of XChaCha20-Poly1305 AEAD cipher, wasting key material and using a legacy mode requiring careful composition.

### Details
While Fernet is secure, it's not a native AEAD mode. Modern ASVS standards prefer purpose-built AEAD ciphers (AES-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305). Key concerns: AES-CBC is legacy requiring careful MAC composition; Fernet's AES-128 provides only 128 bits of security vs the 256-bit key being derived; HKDF info parameter says b'xchacha20_key' but key is used for Fernet indicating incomplete migration; 32-byte HKDF output is base64-encoded and fed to Fernet, which splits it into 16 bytes signing + 16 bytes encryption (AES-128), not using full 256 bits.

**CWE:** None specified
**ASVS:** 11.3.2 (L1)
**Files:** v3/steve/crypto.py:72-82

### Remediation
Replace Fernet with ChaCha20-Poly1305 AEAD cipher. Use cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305 with 32-byte keys derived from HKDF. Generate 96-bit nonces using os.urandom(12) and prepend to ciphertext for decryption. Update HKDF info parameter to b'chacha20_poly1305_key' to match actual usage. This provides authenticated encryption with a single primitive and utilizes the full 256 bits of key material.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 11.3.2.md
- Domain: vote_encryption_and_cryptography

### Priority
**Severity:** Medium

---

## Issue: FINDING-083 - Sensitive Data Unprotected in Process Memory Without Memory Encryption
**Labels:** bug, security, priority:high
**Description:**
### Summary
Sensitive data including opened_key, vote_token, decrypted vote strings, and PIDs exist unprotected in process memory without memory encryption, allowing recovery via memory dumps or cold boot attacks.

### Details
Data flow: Encrypted ciphertext → decrypted votestrings → accumulated in votes list → passed to tally → returned from function, all without memory encryption. An attacker with memory access (via memory dump, cold boot attack, swap file analysis, or process inspection) could recover individual votes, compromising ballot secrecy.

**CWE:** None specified
**ASVS:** 11.7.1 (L3)
**Files:** v3/steve/crypto.py, v3/steve/election.py

### Remediation
Implement hardware-backed memory encryption using technologies such as: Intel TME (Total Memory Encryption) / MKTME, AMD SEV (Secure Encrypted Virtualization), or ARM CCA (Confidential Compute Architecture). At the application level, consider using memory-safe containers or encrypted memory regions via libraries like sodium with sodium_mlock() / sodium_munlock(). Additionally, consider using mlock() for memory pages containing decrypted votes during tally operations, and implement explicit memory clearing patterns.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 11.7.1.md
- Domain: vote_encryption_and_cryptography

### Priority
**Severity:** Medium

---

## Issue: FINDING-084 - OAuth/OIDC token handling mechanism not verifiable - session security cannot be confirmed
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application uses session-based authentication via asfquart.session.read(), but the OAuth/OIDC token handling is abstracted within the asfquart library which is not provided for review, preventing verification of token storage security.

### Details
Session data containing uid, fullname, and email is passed to EZT templates. The OAuth/OIDC token handling itself is abstracted within the asfquart library. The application does NOT appear to expose access tokens or refresh tokens to the browser. The backend appears to act as a BFF pattern where token handling is server-side only. However, if the session cookie itself contains embedded tokens (e.g., JWT session), or if the session store leaks token values, this cannot be verified from the provided code.

**CWE:** None specified
**ASVS:** 10.1.1 (L2)
**Files:** v3/server/pages.py:58-84

### Remediation
Verify that the asfquart session mechanism does not expose raw OAuth tokens in cookies or responses. Ensure session cookies are HttpOnly, Secure, and SameSite. Audit the asfquart library's OAuth implementation to verify token storage security (HttpOnly, Secure cookies) and session fixation protection. Add SameSite cookie attributes to ensure session cookies use SameSite=Lax or SameSite=Strict as an additional defense layer.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 10.1.1.md
- Domain: authentication_and_session_management

### Priority
**Severity:** Medium

---

## Issue: FINDING-085 - No visible audience claim validation for access tokens
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application acts as a resource server but there is no visible audience (aud) claim validation in the provided code, potentially allowing tokens meant for other services to be accepted.

### Details
Token/session validation is performed by asfquart.auth.require, but there is no visible audience (aud) claim validation. If another service in the ASF infrastructure issues tokens with the same authorization server but different intended audiences, a token meant for another service could potentially be used to access this application. The asfquart.auth.require decorator handles all authentication, but whether it validates the aud claim depends on the library's implementation, which is not provided.

**CWE:** None specified
**ASVS:** 10.3.1 (L2)
**Files:** v3/server/pages.py (all endpoints using @asfquart.auth.require)

### Remediation
Verify that the asfquart library validates the aud claim during token exchange or session creation. If using JWT access tokens directly, add audience validation. Example conceptual configuration: APP.config['OAUTH_AUDIENCE'] = 'steve-voting-system' and ensure asfquart validates this during token/session processing.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 10.3.1.md
- Domain: authentication_and_session_management

### Priority
**Severity:** Medium

---

## Issue: FINDING-086 - User identification relies on uid alone without verifiable iss + sub combination
**Labels:** bug, security, priority:high
**Description:**
### Summary
The session stores only uid without preserving the token issuer (iss), creating fragility if multiple OAuth providers are ever supported and potential for issuer confusion.

### Details
While the system currently uses a single identity provider (oauth.apache.org), the user identification does not include an issuer component. The asfquart framework likely handles token validation internally, but the application-level code only works with a flat uid string. There is no verification that the combination of issuer and subject is used as the unique identifier in the database (steve.persondb uses uid as the primary key). In the current single-issuer deployment, the risk is low. However, the architecture doesn't enforce the iss + sub combination pattern, making it fragile against future changes or issuer confusion if multiple OAuth providers are ever supported.

**CWE:** None specified
**ASVS:** 10.3.3 (L2)
**Files:** v3/server/pages.py:82-87, v3/server/main.py:39-42

### Remediation
In session establishment (within asfquart callback), store session data with both uid and iss: session_data = {'uid': token_claims['sub'], 'iss': token_claims['iss'], 'fullname': token_claims.get('name', ''), 'email': token_claims.get('email', '')}. In authorization checks, construct a unique user identifier from iss + sub: def get_unique_user_id(session): return f"{session['iss']}#{session['uid']}"

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 10.3.3.md
- Domain: authentication_and_session_management

### Priority
**Severity:** Medium

---

## Issue: FINDING-087 - No verification of authentication strength, methods, or recentness for sensitive operations
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application performs sensitive operations (opening/closing elections, creating elections, casting votes) without verifying authentication context (acr), methods (amr), or recentness (auth_time).

### Details
The session data (basic_info()) captures no authentication metadata beyond identity. Long-lived sessions could allow sensitive operations long after the original authentication event. A user who authenticated hours or days ago with a weak method (single factor) can perform highly sensitive operations (opening elections that affect organizational governance) without re-authentication or step-up verification. No checks for: (1) acr (Authentication Context Class Reference) — no check that the user authenticated with sufficient assurance level, (2) amr (Authentication Methods References) — no check that specific authentication methods (e.g., MFA) were used, (3) auth_time — no check that authentication occurred recently enough for the operation.

**CWE:** None specified
**ASVS:** 10.3.4 (L2)
**Files:** v3/server/pages.py (all sensitive endpoints)

### Remediation
Implement a decorator to require recent authentication for sensitive operations. Store auth_time in session and validate it before sensitive operations. Example: Create a require_recent_auth decorator that checks if time.time() - auth_time > SENSITIVE_OPS_MAX_AGE (e.g., 300 seconds), and if exceeded, redirect to re-authentication. Apply this decorator to sensitive endpoints like /do-open/&lt;eid&gt;, /do-create-election, and vote casting operations. Additionally, preserve OAuth token claims (acr, amr, auth_time) in the session when establishing it so they can be verified for sensitive operations.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 10.3.4.md
- Domain: authentication_and_session_management

### Priority
**Severity:** Medium

---

## Issue: FINDING-088 - No sender-constrained access token mechanisms (mTLS or DPoP) implemented
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application does not implement OAuth 2.0 Mutual TLS (RFC 8705) certificate-bound access tokens or DPoP (Demonstration of Proof of Possession) token binding, making tokens susceptible to theft and replay.

### Details
TLS configuration is standard server-side TLS only (certfile + keyfile for server certificate). Bearer tokens (or session cookies derived from them) are not bound to any client-specific cryptographic key. If an access token or session cookie is intercepted (e.g., via XSS, network compromise, or log exposure), it can be replayed from any client without detection. This is a Level 3 requirement, so it represents an advanced security control gap.

**CWE:** None specified
**ASVS:** 10.3.5, 10.4.14 (L3)
**Files:** v3/server/main.py:39-42, v3/server/main.py:76-79, v3/server/pages.py

### Remediation
Implement DPoP (Demonstration of Proof of Possession) token binding. Example implementation: Create a DPoP proof JWT using jwcrypto library with ES256 algorithm and P-256 curve. Generate a JWK key pair, create a JWT with 'dpop+jwt' type containing claims for jti (unique identifier), htm (HTTP method), htu (HTTP URI), iat (issued at time), and ath (access token hash when validating). Sign the proof with the private key and include the public key in the JWT header. Alternatively, implement OAuth 2.0 Mutual TLS (RFC 8705) certificate-bound access tokens by requiring client certificates and binding tokens to certificate fingerprints. At minimum, implement session binding to client characteristics with fingerprint verification.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 10.3.5.md, 10.4.14.md
- Domain: authentication_and_session_management

### Priority
**Severity:** Medium

---

## Issue: FINDING-090 - Authorization code grant flow does not use Pushed Authorization Requests (PAR)
**Labels:** bug, security, priority:high
**Description:**
### Summary
The authorization code grant flow does not use Pushed Authorization Requests (PAR), exposing authorization request parameters in the browser URL bar and making them susceptible to manipulation.

### Details
The authorization request parameters are passed directly in the URL to the authorization endpoint, rather than being pushed beforehand via a backchannel PAR request. Without PAR, authorization request parameters are exposed in the browser URL bar and browser history, can be manipulated by the user-agent or malicious browser extensions, and the redirect_uri is passed in the frontchannel, making it susceptible to parameter pollution attacks. The authorization server cannot verify the authenticity of the authorization request.

**CWE:** None specified
**ASVS:** 10.4.13, 10.4.15 (L3)
**Files:** v3/server/main.py:39-42

### Remediation
Implement PAR flow by pushing authorization request parameters via backchannel before redirecting the user. Create a function to push authorization request parameters to the PAR endpoint (https://oauth.apache.org/par) with client credentials, response_type, redirect_uri, state, and scope. Then redirect the user with only the client_id and the returned request_uri reference. Implementation depends on oauth.apache.org supporting the PAR endpoint (RFC 9126). The ASF OAuth infrastructure would need to be verified for PAR support.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 10.4.13.md, 10.4.15.md
- Domain: authentication_and_session_management

### Priority
**Severity:** Medium

---

## Issue: FINDING-091 - No Evidence of Refresh Token Handling or Sender-Constraining
**Labels:** bug, security, priority:high
**Description:**
### Summary
The codebase shows no evidence of refresh token storage, usage, DPoP proof generation, mTLS client certificate binding, or refresh token rotation handling on the client side, potentially allowing replay attacks if refresh tokens are used.

### Details
The session management uses asfquart.session.read() but the framework's internal handling of refresh tokens is not visible. If the framework handles refresh tokens internally without sender-constraining, replay attacks are possible. If the asfquart framework receives and stores refresh tokens from the ASF OAuth server, and neither DPoP nor mTLS is used, a stolen refresh token could be replayed by an attacker to obtain new access tokens.

**CWE:** None specified
**ASVS:** 10.4.5 (L2, L3)
**Files:** v3/server/main.py:38-42, v3/server/pages.py (entire file)

### Remediation
Verify that the asfquart framework either: 1. Does not use refresh tokens (session-only approach), OR 2. Implements DPoP or mTLS for sender-constraining, OR 3. Properly handles refresh token rotation (consuming old tokens). If using refresh tokens, ensure DPoP is configured: asfquart.generics.OAUTH_USE_DPOP = True or verify the framework's session management doesn't rely on refresh tokens.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 10.4.5.md
- Domain: authentication_and_session_management

### Priority
**Severity:** Medium

---

## Issue: FINDING-093 - Missing Issuer Validation in OAuth Token Response
**Labels:** bug, security, priority:high
**Description:**
### Summary
While the OAuth URLs are hardcoded to https://oauth.apache.org/, there is no visible validation that the token response actually came from oauth.apache.org or that the iss claim in any received ID Token matches the expected issuer URL.

### Details
The hardcoded URLs provide a form of issuer pinning for outbound requests, but the requirement specifically mandates validating the issuer in the received response/metadata. Without this validation, a man-in-the-middle or DNS hijack could cause the client to accept tokens from a malicious authorization server. Since the callback handler is in asfquart (not provided), we cannot confirm whether issuer validation occurs there. This represents a visibility gap.

**CWE:** None specified
**ASVS:** 10.5.3 (L2)
**Files:** v3/server/main.py:39-42

### Remediation
Configure expected issuer for validation: asfquart.generics.EXPECTED_ISSUER = 'https://oauth.apache.org'. In token validation: if decoded_token['iss'] != EXPECTED_ISSUER: raise SecurityError('Issuer mismatch - possible impersonation')

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 10.5.3.md
- Domain: authentication_and_session_management

### Priority
**Severity:** Medium

---

## Issue: FINDING-094 - No documented rate limiting, anti-automation, or adaptive response controls for authentication endpoints
**Labels:** bug, security, priority:high, documentation
**Description:**
### Summary
The application delegates authentication to ASF OAuth but provides no documentation describing rate limiting, anti-automation controls, or adaptive response mechanisms, preventing verification of brute force and credential stuffing protections.

### Details
There is no documentation anywhere in the provided code (comments, docstrings, or configuration) that describes: 1) How rate limiting is configured for the OAuth callback endpoint, 2) Whether the upstream ASF OAuth provider implements anti-automation controls, 3) What adaptive response mechanisms exist (e.g., progressive delays, CAPTCHA escalation), 4) How the system prevents malicious account lockout at the ASF OAuth layer, 5) Whether the application itself implements any secondary rate limiting on session-protected endpoints. The asfquart.auth.require decorator is used extensively across endpoints but no per-endpoint rate limiting is applied. Without documented rate limiting controls, there is no assurance that brute force or credential stuffing attacks against the OAuth flow are mitigated.

**CWE:** None specified
**ASVS:** 6.1.1, 6.3.1 (L1)
**Files:** v3/server/main.py:34-39, v3/server/pages.py (entire file)

### Remediation
Create authentication security documentation that specifies: 1) Rate Limiting - OAuth callback endpoint: Delegated to ASF OAuth (oauth.apache.org) with description of specific controls implemented by ASF OAuth and application-level controls (e.g., max 10 auth attempts per IP per minute via reverse proxy), 2) Anti-Automation - CAPTCHA integration and bot detection mechanisms, 3) Adaptive Response - Behavior after N failed attempts and account lockout prevention mechanisms including ASF account unlock procedures, 4) Reverse Proxy Configuration - Apache/nginx rate limit rules with references to config files

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 6.1.1.md, 6.3.1.md
- Domain: authentication_and_session_management

### Priority
**Severity:** Medium

---

## Issue: FINDING-095 - Multiple authentication pathways exist but are not documented together with security controls
**Labels:** bug, security, priority:high, documentation
**Description:**
### Summary
The application implements at least three distinct authentication/authorization pathways (bare session, committer level, PMC member level) but lacks comprehensive documentation defining what security controls apply at each level.

### Details
The application implements: 1) Bare session (@asfquart.auth.require): /profile, /settings, /docs/&lt;iid&gt;/&lt;docname&gt;, 2) Committer level (@asfquart.auth.require({R.committer})): /voter, /admin, /manage/&lt;eid&gt;, all voting and issue management endpoints, 3) PMC member level (@asfquart.auth.require({R.pmc_member})): /do-create-election. Additionally, the '### need general solution' comments throughout indicate that the authorization model is incomplete and evolving. There is no documentation that defines what security controls apply at each level, describes the authentication strength at each level, explains why certain endpoints use one level vs another, or documents the planned "general solution" mentioned in comments. The repeated '### check authz' comments indicate that fine-grained authorization checks are acknowledged as needed but not implemented.

**CWE:** None specified
**ASVS:** 6.1.3 (L2)
**Files:** v3/server/pages.py (multiple locations)

### Remediation
Create comprehensive authentication pathways documentation covering: 1) OAuth Flow (Primary - All Users) including provider (ASF OAuth), strength (single-factor), session management, and controls, 2) Authorization Levels for Level 0 (Public - No Authentication), Level 1 (Authenticated User - Valid Session), Level 2 (ASF Committer), and Level 3 (PMC Member), 3) Consistency Enforcement noting all pathways use the same ASF OAuth provider with identical authentication strength, with authorization differing by LDAP group membership. Document this in `docs/AUTHENTICATION.md` covering all three ASVS 6.1.x requirements.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 6.1.3.md
- Domain: authentication_and_session_management

### Priority
**Severity:** Medium

---

## Issue: FINDING-096 - No Mechanism for Suspicious Authentication Notifications
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application contains no code to detect or notify users about suspicious authentication attempts, preventing users from detecting unauthorized access attempts against their accounts.

### Details
The application lacks functionality to: (1) Detect authentication attempts from unusual locations or clients, (2) Identify partially successful authentication (one factor only), (3) Notice authentication after long inactivity periods, (4) Track successful authentication following multiple failures, (5) Send notifications to users about any of the above. Users have no visibility into unauthorized access attempts against their accounts. If a session is compromised or an attacker authenticates via stolen OAuth tokens, the legitimate user receives no notification.

**CWE:** None specified
**ASVS:** 6.3.5 (L3)
**Files:** v3/server/pages.py (entire file)

### Remediation
Implement a suspicious authentication detection and notification system that: (1) Tracks session attributes (IP address, user agent, last activity time) for comparison, (2) Detects anomalies such as new IP addresses, login after extended inactivity (e.g., 90+ days), or unusual client patterns, (3) Sends email notifications to users when suspicious activity is detected, (4) Records session information for future comparison.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 6.3.5.md
- Domain: authentication_and_session_management

### Priority
**Severity:** Medium

---

## Issue: FINDING-097 - No Notification Mechanism for Authentication Detail Changes
**Labels:** bug, security, priority:high
**Description:**
### Summary
A /settings page exists, but no notification mechanism exists for credential or profile changes, reducing the ability to detect account takeover.

### Details
While a /settings page exists, implying users can modify account details: 1. No notification mechanism exists anywhere in the codebase for credential or profile changes. 2. No email sending service is configured or imported. 3. Changes to LDAP-sourced data (username, email) happen externally but the application doesn't verify or notify when these change between sessions. If authentication details are modified at the ASF IdP level (credential reset, email change) or if the application later adds local settings, users will not be notified of changes.

**CWE:** None specified
**ASVS:** 6.3.7 (L3)
**Files:** v3/server/pages.py:603

### Remediation
Implement profile change detection and notification mechanism. Check stored profile against session data on each login, and if email or other critical attributes have changed, send notification to the old email address before updating.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 6.3.7.md
- Domain: authentication_and_session_management

### Priority
**Severity:** Medium

---

## Issue: FINDING-099 - User identity not explicitly namespaced with IdP identifier
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application uses a single uid field from the session as the user's identity throughout the system without IdP namespace, creating potential for cross-provider spoofing if multiple identity providers are ever supported.

### Details
While currently only one IdP is configured (ASF OAuth at oauth.apache.org), there is no IdP namespace stored alongside the user identifier. If the application were extended to support additional identity providers (or if the asfquart framework were configured to accept multiple providers), the uid field alone could be spoofed across providers. The OAuth configuration in main.py (lines 39-42) references only oauth.apache.org. Additionally, the LDAP load process in asf-load-ldap.py (line 54) stores users by uid alone. Mitigating Factor: Currently only one IdP is configured, which significantly reduces the actual exploitation risk.

**CWE:** None specified
**ASVS:** 6.8.1 (L2)
**Files:** v3/server/pages.py:82-93, main.py:39-42, asf-load-ldap.py:54

### Remediation
Store and validate a composite key of (idp_id, user_id) rather than user_id alone. Capture idp_id from session (defaulting to 'asf-oauth' for backward compatibility) and create a composite_id field in the format {idp_id}:{uid}. Update session handling in basic_info() to include idp, composite_id alongside existing uid, name, and email fields. Update PersonDB schema to namespace users with IdP identifier.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 6.8.1.md
- Domain: authentication_and_session_management

### Priority
**Severity:** Medium

---

## Issue: FINDING-100 - No documented fallback approach for authentication strength assumptions
**Labels:** bug, security, priority:high, documentation
**Description:**
### Summary
No documentation or implementation exists for a fallback approach when the IdP does not provide authentication strength information, violating ASVS requirement that the application must have a documented fallback assuming minimum strength authentication.

### Details
The ASVS requirement states: 'If the IdP does not provide this information, the application must have a documented fallback approach that assumes that the minimum strength authentication mechanism was used.' No such documentation or implementation exists in the codebase. The application treats all authenticated sessions equally regardless of authentication strength.

**CWE:** None specified
**ASVS:** 6.8.4 (L2)
**Files:** None

### Remediation
Document the authentication strength assumptions and implement appropriate controls. Example: When IdP does not provide acr/amr claims, assume single-factor authentication. Consequence: Election creation and management operations require re-authentication within 15 minutes. Vote submission allowed with standard session validity.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 6.8.4.md
- Domain: authentication_and_session_management

### Priority
**Severity:** Medium

---

## Issue: FINDING-101 - No concurrent session limit enforcement or documentation
**Labels:** bug, security, priority:high, documentation
**Description:**
### Summary
The application codebase contains no implementation, configuration, or documentation defining the maximum number of concurrent sessions allowed per account, allowing unlimited concurrent sessions and persistent attacker access even after credential changes.

### Details
The session management in pages.py reads sessions via asfquart.session.read() but never checks for or limits concurrent active sessions for the same user. User authenticates via OAuth → session is created → no check against existing active sessions for same uid → unlimited concurrent sessions permitted. An attacker who compromises a user's OAuth credentials could maintain persistent access even after the legitimate user changes credentials, as no mechanism detects or limits parallel sessions.

**CWE:** None specified
**ASVS:** 7.1.2 (L2)
**Files:** v3/server/pages.py:82-92, v3/server/main.py (entire file)

### Remediation
Document the session concurrency policy and implement enforcement. In session creation callback (within asfquart framework or custom middleware), check active sessions for the uid, and if the count exceeds MAX_CONCURRENT_SESSIONS (e.g., 3), terminate the oldest session and log the action.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 7.1.2.md
- Domain: authentication_and_session_management

### Priority
**Severity:** Medium

---

## Issue: FINDING-102 - No documented coordination between ASF OAuth SSO session lifetime and application session lifetime
**Labels:** bug, security, priority:high, documentation
**Description:**
### Summary
The application integrates with ASF's OAuth infrastructure but has no visible documentation or implementation of controls to coordinate session lifetimes between the ASF OAuth IdP and the local application session.

### Details
When the ASF OAuth session expires or is revoked, the local application session may remain valid indefinitely. User authenticates at ASF OAuth → token exchanged at callback → local session created → no periodic validation against OAuth provider → no session lifetime synchronization. There is no visible documentation or implementation of controls to coordinate session lifetimes between the ASF OAuth IdP and the local application session.

**CWE:** None specified
**ASVS:** 7.1.3 (L2)
**Files:** v3/server/main.py:39-42, v3/server/pages.py (entire file)

### Remediation
Document the federated session management strategy and implement periodic token validation. Configuration/documentation should include: SESSION_MANAGEMENT with sso_provider (ASF OAuth), local_session_max_lifetime (8 hours), idle_timeout (30 minutes), re_authentication_required_for (election creation, election open/close), token_refresh_interval (15 minutes), on_sso_revocation (terminate local session within refresh interval).

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 7.1.3.md
- Domain: authentication_and_session_management

### Priority
**Severity:** Medium

---

## Issue: FINDING-104 - No session termination mechanism after authentication factor changes
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application relies entirely on ASF's external OAuth/LDAP infrastructure for authentication with no mechanism to terminate existing sessions when credentials are changed at the ASF IdP level.

### Details
While the settings_page() endpoint exists, it contains no credential-related operations. Data flow: Authentication factor changes happen at ASF IdP → No callback/webhook from IdP to application → Application has no knowledge of credential changes → Other sessions remain active. If a user's credentials are changed at the ASF IdP (e.g., password reset after compromise), the application has no mechanism to terminate existing sessions.

**CWE:** None specified
**ASVS:** 7.4.3 (L2)
**Files:** v3/server/pages.py (full file)

### Remediation
Implement one or more of the following: 1. Short absolute session lifetimes (forces periodic re-auth via IdP), 2. Token refresh that validates against current IdP state, 3. Webhook endpoint for IdP credential change notifications that invalidates all sessions for the affected user. Create a POST /webhooks/credential-change endpoint that receives notifications from ASF IdP when credentials change and calls session_store.invalidate_all_for_user(uid).

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 7.4.3.md
- Domain: authentication_and_session_management

### Priority
**Severity:** Medium

---

## Issue: FINDING-105 - No re-authentication enforcement for sensitive account attribute changes
**Labels:** bug, security, priority:high
**Description:**
### Summary
The /settings and /profile pages exist but only render templates with no evidence of re-authentication enforcement for any attribute-changing operations within the application's scope.

### Details
While the application delegates account attribute management (email, MFA) to the ASF OAuth/LDAP infrastructure, there is no evidence of re-authentication enforcement for any attribute-changing operations within the application's scope. The architecture relies entirely on ASF's IdP for account attribute protection. If the settings page ever gains functionality for modifying sensitive attributes (or if it already has client-side forms posting to an API not shown in this audit), there's no re-authentication gate.

**CWE:** None specified
**ASVS:** 7.5.1 (L2)
**Files:** v3/server/pages.py:603, v3/server/pages.py:594

### Remediation
If any sensitive attribute modification is added, implement re-authentication flow. Check if user has recently authenticated via session flag. If not, redirect to re-authentication flow before proceeding with the update. Implement a POST endpoint that verifies recently_authenticated session flag and redirects to /reauth if not present.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 7.5.1.md
- Domain: authentication_and_session_management

### Priority
**Severity:** Medium

---

## Issue: FINDING-106 - No Additional Verification for Vote Submission
**Labels:** bug, security, priority:high
**Description:**
### Summary
Vote submission requires no additional verification beyond the existing session, allowing a session hijacker to cast or modify votes on behalf of the legitimate user without any additional verification.

### Details
Vote submission, while not election management, is a sensitive transaction where vote integrity is critical. No additional verification is required beyond the existing session. A session hijacker could cast or modify votes on behalf of the legitimate user without any additional verification. While re-voting is supported (making this reversible), the user may not notice the unauthorized vote submission.

**CWE:** None specified
**ASVS:** 7.5.3 (L3)
**Files:** v3/server/pages.py:417

### Remediation
Implement step-up authentication or additional verification mechanism for vote submission. Consider requiring re-authentication within a short time window (e.g., 5 minutes) before accepting votes, or implement a confirmation step with CSRF protection.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 7.5.3.md
- Domain: authentication_and_session_management

### Priority
**Severity:** Medium

---

## Issue: FINDING-107 - No session lifetime configuration or IdP authentication timestamp tracking
**Labels:** bug, security, priority:high
**Description:**
### Summary
No session lifetime configuration, maximum session duration, or IdP authentication timestamp tracking is visible in the codebase, potentially allowing sessions to remain valid indefinitely after initial OAuth authentication.

### Details
The OAuth configuration only defines URLs for authentication but no timeout or session freshness enforcement. There is no mechanism to require re-authentication when the maximum time between IdP authentication events is reached. Sessions may remain valid indefinitely after initial OAuth authentication. If the IdP revokes user access or the user's LDAP account is disabled, the application session remains valid. During long elections, sessions could persist without validation against the IdP, allowing access after authorization has been revoked.

**CWE:** None specified
**ASVS:** 7.6.1 (L2)
**Files:** v3/server/main.py:39-42, v3/server/pages.py:82

### Remediation
Implement session age checking against IdP maximum authentication time. Track 'auth_time' in the session and enforce maximum session age. Check session age in basic_info() function - if (time.time() - auth_time) > max_session_age, invalidate the session and redirect to login. Configure APP.cfg.session.max_age (e.g., 8 hours) and validate on each session read.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 7.6.1.md
- Domain: authentication_and_session_management

### Priority
**Severity:** Medium

---

## Issue: FINDING-108 - Issue KV data (candidate lists) exposed without granular field filtering
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The list_issues() method returns all KV data (candidate lists, seats, labelmap) without filtering based on the caller's context or role, potentially exposing operational data inappropriately.

### Details
There is no distinction between what fields a voter should see versus what a manager should see. The kv field contains operational data that may be appropriate for voters but the method has no field filtering mechanism based on the consumer's role or access level.

**CWE:** CWE-359
**ASVS:** 8.2.3 (L2)
**Files:** v3/steve/election.py:235-250

### Remediation
Add field-level access control to list_issues() method by introducing an include_management_fields parameter. When called from voter-facing contexts, filter the KV data to only include voter-visible fields (candidates, labelmap, seats). Example: def list_issues(self, include_management_fields=False) with conditional filtering of issue.kv based on the parameter.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 8.2.3.md
- Domain: election_authorization_and_access_control

### Priority
**Severity:** Medium

---

## Issue: FINDING-109 - No adaptive/contextual security controls implemented for authentication or authorization
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application does not implement any adaptive security controls based on IP address changes, geolocation anomalies, device fingerprint changes, time-of-day restrictions, concurrent session detection, or unusual access patterns.

### Details
This means a compromised session token can be used from any location, device, or context without triggering additional verification. Session cookie flows to asfquart.session.read() to establish identity with no environmental/contextual validation at session start or during operations.

**CWE:** None specified
**ASVS:** 8.2.4 (L3)
**Files:** v3/server/pages.py:67-93

### Remediation
Implement a validate_session_context() function that validates environmental context for the current request. This should include: IP-based session binding (validate request IP against stored session IP and require re-authentication on mismatch), device fingerprinting, time-based restrictions for sensitive operations (flag or require additional auth for off-hours access), geolocation validation, concurrent session detection, and step-up authentication for sensitive operations.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 8.2.4.md
- Domain: election_authorization_and_access_control

### Priority
**Severity:** Medium

---

## Issue: FINDING-111 - No mechanism to invalidate sessions or propagate authorization revocations immediately
**Labels:** bug, security, priority:high
**Description:**
### Summary
If a voter's eligibility is revoked (e.g., removed from mayvote during the editable phase, or LDAP group membership changes), there is no mechanism to immediately invalidate their active session or alert when they perform actions they're no longer authorized for.

### Details
Given that the authz LDAP group check is not implemented (AUTH-001), this is a compounding issue—even if authz were checked at login, there's no re-check during the session. Authorization changes are not applied immediately to active sessions.

**CWE:** None specified
**ASVS:** 8.3.2 (L3)
**Files:** v3/server/pages.py:67-93

### Remediation
Re-validate authorization on each request (or on sensitive operations). Check if user is still active in LDAP. If not, invalidate the session and abort with 401. Example: async def basic_info(): s = await asfquart.session.read(); if s: uid = s['uid']; if not await validate_user_still_active(uid): await asfquart.session.invalidate(); quart.abort(401, 'Session invalidated - user no longer authorized'). This ensures authorization changes are immediately effective.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 8.3.2.md
- Domain: election_authorization_and_access_control

### Priority
**Severity:** Medium

---

## Issue: FINDING-112 - No device security posture assessment or contextual risk analysis for administrative interfaces
**Labels:** bug, security, priority:high
**Description:**
### Summary
ASVS 8.4.2 explicitly requires 'device security posture assessment' and 'contextual risk analysis' for administrative interfaces. The system has no implementation of device fingerprinting, behavioral analysis, geographic/IP risk scoring, session binding to device characteristics, or anomaly detection for administrative operations.

### Details
Compromised credentials from any network location grant full administrative access with no detection of automated/scripted attacks or anomalous behavior patterns. The requirement states that network location or trusted endpoints should not be the sole factors, but the system has no factors at all.

**CWE:** CWE-778
**ASVS:** 8.4.2 (L3)
**Files:** v3/server/pages.py (system-wide)
**Related Findings:** FINDING-252

### Remediation
Implement async def assess_admin_risk(uid, operation) that calculates a risk score based on: (1) IP consistency with session, (2) rapid successive admin operations, (3) geographic anomalies, (4) time-of-day patterns. Log risk assessments and require step-up authentication when risk score exceeds threshold. Implement session binding to device characteristics and rate limiting on administrative endpoints. This provides the multiple layers of security required by ASVS 8.4.2.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 8.4.2.md
- Domain: election_authorization_and_access_control

### Priority
**Severity:** Medium

---

## Issue: FINDING-114 - Incomplete function-level access control documentation
**Labels:** bug, security, priority:high, documentation
**Description:**
### Summary
The authorization documentation partially defines access rules but lacks comprehensive function-level access control specification with a complete mapping of which functions/operations each role can perform.

### Details
Missing documentation includes: no explicit listing of all protected functions (open, close, add-issue, edit-issue, delete-issue, set-dates, vote, tally), no matrix mapping consumer permissions (owner, authz group member, eligible voter, committer, PMC member) to allowed operations, the authz field format is explicitly marked TBD indicating incomplete design, no documentation of the R.committer vs R.pmc_member distinction for election creation vs management, and no documentation of what committer status grants vs owner status. Without comprehensive function-level authorization documentation, developers cannot consistently implement checks, and testers cannot verify completeness. The current code has numerous 'check authz' TODO comments confirming that the lack of clear documentation has led to incomplete implementation.

**CWE:** None specified
**ASVS:** 8.1.1 (L1)
**Files:** v3/docs/schema.md (entire file)

### Remediation
Create an Authorization Matrix document specifying a complete mapping of operations to roles. The matrix should include: Operation, Owner, Authz Group, Eligible Voter, Any Committer, and PMC Member columns. Operations to document include: Create Election, View Management, Open Election, Close Election, Add Issue, Edit Issue, Delete Issue, Cast Vote, View Tally, and Set Dates. Each cell should clearly indicate Yes/No/- for whether that role can perform that operation.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 8.1.1.md
- Domain: election_authorization_and_access_control

### Priority
**Severity:** Medium

---

## Issue: FINDING-115 - Missing field-level access restriction documentation
**Labels:** bug, security, priority:high, documentation
**Description:**
### Summary
The authorization documentation does not define field-level access restrictions for read and write operations, with no documentation specifying which fields each consumer type can read or write, nor how access changes based on election state.

### Details
Missing documentation includes: which fields voters can read (e.g., can a voter see owner_pid? authz group?), which fields are writable based on election state (e.g., title writable only in EDITABLE state), specification that salt, opened_key, and vote_token are system-internal fields never exposed to consumers, and state-dependent field access rules (e.g., the trigger preventing open_at/close_at modification when closed is in SQL but not documented as a field-level policy).

**CWE:** None specified
**ASVS:** 8.1.2 (L2)
**Files:** v3/docs/schema.md, v3/steve/election.py:165, v3/steve/election.py:179

### Remediation
Create comprehensive field-level access control documentation with a table format showing Field, Owner (Read), Owner (Write), Voter (Read), Voter (Write), and State Dependency columns for all election fields including eid, title, owner_pid, authz, salt, opened_key, closed, open_at, and close_at.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 8.1.2.md
- Domain: election_authorization_and_access_control

### Priority
**Severity:** Medium

---

## Issue: FINDING-116 - Missing documentation of environmental and contextual security attributes
**Labels:** bug, security, priority:high, documentation
**Description:**
### Summary
The application's documentation does not define any environmental or contextual attributes used in security decisions, with no documentation of whether time of day, user location, IP address, device type, or other contextual factors influence authentication or authorization decisions.

### Details
The open_at and close_at fields exist in the schema, but the SQL comment explicitly states: 'These are purely advisory, for humans, and have no effect upon the actual Election operation.' No IP-based restrictions, geographic restrictions, or device/browser-based security decisions are documented. The @asfquart.auth.require decorator handles authentication but no documentation defines what contextual factors the authentication system evaluates.

**CWE:** None specified
**ASVS:** 8.1.3 (L3)
**Files:** v3/docs/schema.md (entire file), v3/server/pages.py (entire file)

### Remediation
Document all environmental/contextual attributes (or explicitly state none are used). Create documentation section titled "Environmental and Contextual Security Attributes" that explicitly lists attributes NOT used (time-of-day, IP address, device type, geographic location) with intentional design decisions, and attributes that ARE used (authentication session, LDAP group membership, election state).

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 8.1.3.md
- Domain: election_authorization_and_access_control

### Priority
**Severity:** Medium

---

## Issue: FINDING-117 - Missing documentation of environmental and contextual factors in authorization decision-making
**Labels:** bug, security, priority:high, documentation
**Description:**
### Summary
There is no documentation defining how environmental and contextual factors are used in authentication and authorization decision-making, including thresholds, risk levels, and actions taken.

### Details
Missing documentation includes: no risk scoring model, no step-up authentication triggers, no adaptive authentication rules, no documentation of when 'deny' vs 'challenge' applies, no documentation of how the ASF IdP session interacts with the application's authorization layer, and no documentation of what happens when LDAP group membership changes mid-session.

**CWE:** None specified
**ASVS:** 8.1.4 (L3)
**Files:** All documentation files

### Remediation
Create comprehensive decision-making framework documentation that includes: Authentication Decision Flow table showing Context, Evaluation, Threshold, and Action columns for valid session, expired session, and no session scenarios. Authorization Decision Flow table for election management, vote casting, and election creation. Factors NOT Evaluated section documenting design decisions about IP address changes, concurrent sessions, and rate limiting.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 8.1.4.md
- Domain: election_authorization_and_access_control

### Priority
**Severity:** Medium

---

## Issue: FINDING-118 - User-controlled data interpolated into flash messages without encoding
**Labels:** bug, security, priority:high
**Description:**
### Summary
User-controlled data is interpolated into flash messages without encoding. If EZT templates render flash messages as raw HTML, this constitutes output encoding NOT being performed as the final step.

### Details
Data flow: User form input (form.title, iid from form keys) → flash message stored in session → rendered in template on next page load. The encoding/escaping should happen at the point closest to the interpreter (the template), but if EZT templates render flash messages as raw HTML (which is typical for flash message systems that support HTML formatting), this creates a vulnerability.

**CWE:** CWE-79
**ASVS:** 1.1.2, 1.2.1, 16.4.1 (L1, L2)
**Files:** v3/server/pages.py:393, v3/server/pages.py:440, v3/server/pages.py:502, v3/server/pages.py:527, v3/server/pages.py:547
**Related Findings:** FINDING-004, FINDING-029, FINDING-119, FINDING-133

### Remediation
Implement a sanitization function that removes or encodes characters that could enable log injection (newlines, carriage returns, and other control characters). Replace f-string logging with parameterized logging using format strings.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 1.1.2.md, 16.4.1.md
- Domain: web_input_validation_and_injection

### Priority
**Severity:** Medium

---

## Issue: FINDING-119 - Potential reflected XSS in error page rendering via unencoded URL parameters
**Labels:** bug, security, priority:high
**Description:**
### Summary
The raise_404 function renders error templates with data from URL path parameters (eid and iid) without HTML encoding, potentially creating reflected XSS in error pages.

### Details
Data flows from URL path (/vote-on/&lt;eid&gt;) → Quart URL-decodes → eid assigned to result.eid → passed to EZT template → rendered as HTML. If the EZT error templates (e.g., e_bad_eid.ezt) render these values without HTML encoding, a malicious URL could inject HTML/JavaScript into the error page. Severity is dependent on template implementation which cannot be verified from provided code.

**CWE:** CWE-79
**ASVS:** 1.2.1 (L1)
**Files:** v3/server/pages.py:677-679
**Related Findings:** FINDING-004, FINDING-029, FINDING-118, FINDING-133

### Remediation
Apply HTML encoding to URL parameters before passing to error templates. Either: (1) Use html.escape(eid) and html.escape(iid) when assigning to result object before raise_404() call; or (2) Sanitize input by validating format (e.g., result.eid = eid if eid.isalnum() else 'invalid') to ensure only safe characters are passed to templates.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 1.2.1.md
- Domain: web_input_validation_and_injection

### Priority
**Severity:** Medium

---

## Issue: FINDING-120 - Path traversal risk due to missing canonicalization in serve_doc
**Labels:** bug, security, priority:high
**Description:**
### Summary
The serve_doc() function uses the user-supplied docname URL parameter directly in send_from_directory() without application-level validation. The developer explicitly acknowledged this gap with the comment "### verify the propriety of DOCNAME."

### Details
While Quart's send_from_directory() internally uses safe_join() to prevent path traversal, there is no defense-in-depth validation at the application layer. Relying solely on framework internals without application-level validation creates risk if: 1) The framework is upgraded and safe_join behavior changes, 2) A bypass is discovered in safe_join, 3) The code is refactored to use a different file-serving mechanism. The explicit TODO comment indicates the developer considers this incomplete.

**CWE:** CWE-22
**ASVS:** 1.1.1, 5.3.2 (L2, L1)
**Files:** v3/server/pages.py:584-600

### Remediation
Add an explicit allowlist regex (e.g., `^[a-zA-Z0-9][a-zA-Z0-9._-]*$`) and reject requests with invalid filenames. Validate docname using the regex pattern and reject any containing '..' or failing the pattern match before calling send_from_directory().

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 1.1.1.md, 5.3.2.md
- Domain: web_input_validation_and_injection

### Priority
**Severity:** Medium

## Issue: FINDING-121 - Missing SMTP Header Sanitization in Voter Email Data Retrieval
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `get_voters_for_email()` method retrieves voter names and email addresses without enforcing SMTP header sanitization, creating potential for SMTP header injection if person data contains CRLF sequences.

### Details
Person data originates from LDAP/external sources via `c_add_person` INSERT/UPSERT. Neither `get_voters_for_email()` nor the `person` table schema enforces sanitization of email addresses or names. If person names or email addresses contain CRLF sequences (`\r\n`) or SMTP protocol characters, and are used in email headers (To, From, Subject) without sanitization, an attacker who can influence LDAP data or the person import process could inject additional headers or recipients into outgoing emails.

**CWE:** CWE-93  
**ASVS:** 1.3.11 (L2)  
**Affected Files:**
- `v3/steve/election.py` (lines 514-520)

### Remediation
Implement sanitization to remove CRLF and other SMTP-dangerous characters from header values:
1. Add a `sanitize_email_field()` function that removes CR, LF, and NULL bytes using regex: `re.sub(r'[\r\n\x00]', '', value)`
2. Apply this sanitization to both name and email fields in the `get_voters_for_email()` method before returning the voter data
3. Example: `sanitize_email_field(row.name)` and `sanitize_email_field(row.email)`

### Acceptance Criteria
- [ ] Sanitization function implemented and tested
- [ ] Applied to all email header fields
- [ ] Test added for CRLF injection attempt
- [ ] Verified with malicious LDAP data input

### References
- Source Report: 1.3.11.md

### Priority
Medium

---

## Issue: FINDING-122 - No length or character validation on election titles
**Labels:** bug, security, priority:medium
**Description:**
### Summary
User-supplied text fields (election title, issue title, issue description) are passed directly to the database without validation, allowing extremely long titles, empty titles, or control characters.

### Details
Extremely long titles could cause display issues, memory exhaustion, or denial of service. Empty titles violate logical expectations (NOT NULL ≠ non-empty). No character set validation allows control characters or other problematic content. This affects the `gather_election_data()` anti-tamper hash — maliciously crafted titles could cause issues.

**ASVS:** 1.3.3 (L2), 2.2.1 (L1)  
**Affected Files:**
- `v3/server/pages.py` (line 463)

### Remediation
Implement server-side validation with:
- Maximum length limits (title: 200 characters, description: 10,000 characters)
- Strip whitespace and validate that titles are non-empty
- Example:
```python
title = form.get('title', '').strip()
if not title:
    await flash_danger('Election title is required.')
    return quart.redirect('/admin', code=303)
if len(title) > MAX_TITLE_LENGTH:
    await flash_danger(f'Title must be {MAX_TITLE_LENGTH} characters or less.')
    return quart.redirect('/admin', code=303)
```

### Acceptance Criteria
- [ ] Length validation implemented for all text fields
- [ ] Empty string validation added
- [ ] Tests added for boundary conditions
- [ ] Character set validation implemented

### References
- Source Reports: 1.3.3.md, 2.2.1.md
- Related: FINDING-129

### Priority
Medium

---

## Issue: FINDING-123 - Potential JavaScript injection via unescaped user-controlled data in templates
**Labels:** bug, security, priority:medium
**Description:**
### Summary
User-controlled data (election titles, issue titles, candidate names from labelmap) is passed to templates without verification of proper JavaScript escaping, potentially enabling JavaScript injection.

### Details
The application passes user-controlled data to templates, particularly the labelmap stored as JSON in the kv field containing candidate labels and names. If any EZT template embeds these values directly in `<script>` blocks or JavaScript event handlers without JSON serialization or JavaScript escaping, this enables JavaScript injection.

Data flow: `form.title/kv.labelmap → DB storage → list_issues() → template data → potential JavaScript context in template`

**ASVS:** 1.2.3 (L1)  
**Affected Files:**
- `v3/server/pages.py`

### Remediation
Ensure all data passed to JavaScript contexts uses `json.dumps()` for serialization:
```python
import json
result.issues_json = json.dumps([{
    'iid': i.iid,
    'title': i.title,
    'candidates': i.candidates
} for i in result.issues])
```

### Acceptance Criteria
- [ ] All JavaScript contexts use json.dumps()
- [ ] Template review completed
- [ ] XSS test cases added
- [ ] Verified with malicious input

### References
- Source Report: 1.2.3.md

### Priority
Medium

---

## Issue: FINDING-124 - Incomplete documentation of input validation rules for user-supplied text fields
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The documentation defines structural rules for internal identifiers but fails to document validation rules for user-supplied input data.

### Details
Missing documentation includes:
- Election title (max length, allowed characters, format)
- Issue title and description (max length, allowed characters)
- Vote string (votestring) format per vote type
- Person email format validation rules (RFC 5322 compliance)
- Person name (max length, allowed characters)
- Date inputs (expected format, range constraints)
- Authorization group (authz) allowed values/format

This leads to inconsistent validation and makes it difficult to verify correctness or identify gaps.

**ASVS:** 2.1.1 (L1)  
**Affected Files:**
- `v3/docs/schema.md`
- `v3/server/pages.py`

### Remediation
Create an `input-validation.md` document specifying validation rules for all user input fields:
- Election Title: String, Required, Max 200 chars, Unicode printable only
- Vote String for YNA: String, Required, Allowed values: yes/no/abstain, Case-insensitive
- Vote String for STV: String, Required, Format: Comma-separated candidate labels, Validation: Each label must exist in issue.kv.labelmap, no duplicates

### Acceptance Criteria
- [ ] input-validation.md created
- [ ] All user input fields documented
- [ ] Validation rules specified
- [ ] Examples provided

### References
- Source Report: 2.1.1.md

### Priority
Medium

---

## Issue: FINDING-125 - No documentation of temporal consistency rules for election dates
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The documentation does not define rules for validating logical consistency between `open_at` and `close_at` fields.

### Details
The code (`_set_election_date` in pages.py) sets each date independently without any documented cross-field consistency rule. Without documented consistency rules, dates can be set in illogical combinations (close before open), potentially confusing election administrators and voters.

**ASVS:** 2.1.2 (L2)  
**Affected Files:**
- `v3/docs/schema.md`
- `v3/server/pages.py`

### Remediation
Document the expected temporal relationships:
- `close_at` must be after `open_at` if both are set
- `open_at` should be in the future when the election is editable
- Neither date can be modified once the election is closed (enforced by trigger)

Add a Date Consistency Rules section to the documentation.

### Acceptance Criteria
- [ ] Temporal consistency rules documented
- [ ] Date validation rules specified
- [ ] State transition constraints documented

### References
- Source Report: 2.1.2.md

### Priority
Medium

---

## Issue: FINDING-126 - No documentation of election state consistency with voter/issue operations
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
While the code enforces state-based restrictions, these rules are not documented in the business logic documentation.

### Details
Missing documentation includes:
- Adding voters is only valid when `election.salt IS NULL` (editable state)
- Adding issues is only valid when `election.salt IS NULL`
- Voting is only valid when `election.salt IS NOT NULL AND closed != 1`
- Tallying is only valid when `closed = 1`
- Issue IID must belong to the election's EID when voting
- Voter PID must have a mayvote entry for the issue IID

Without documented consistency rules, it's unclear what invariants the system maintains.

**ASVS:** 2.1.2 (L2)  
**Affected Files:**
- `v3/docs/schema.md`

### Remediation
Add a State Transition Rules section documenting which operations are valid in which states and what cross-entity consistency is required.

### Acceptance Criteria
- [ ] State transition rules documented
- [ ] Operation validity by state documented
- [ ] Cross-entity consistency rules specified

### References
- Source Report: 2.1.2.md

### Priority
Medium

---

## Issue: FINDING-127 - No documentation of per-user or global business logic limits
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The application documentation does not define any limits on per-user operations or global limits, making the application vulnerable to resource exhaustion.

### Details
Missing limits include:
- Maximum elections a user can create
- Maximum issues per election
- Maximum voters per election/issue
- Rate limiting on vote submissions
- Maximum title/description field lengths
- Maximum number of STV candidates/seats
- Timeout for election operations

The `create-election.py` validates STV seats as positive integer but has no upper bound.

**ASVS:** 2.1.3 (L2)  
**Affected Files:**
- `schema.md`
- `TODO.md`
- `create-election.py` (line 67)
- `election.py` (line 169)

### Remediation
Create a business limits document including:
- Per-User limits: Max elections created: 50 (configurable), Max concurrent open elections: 10
- Per-Election limits: Max issues: 500, Max eligible voters: 10,000, Max STV candidates: 50, Max STV seats: candidates - 1
- Global limits: Election title max: 200 chars, Issue title max: 200 chars, Issue description max: 10,000 chars

### Acceptance Criteria
- [ ] Business limits document created
- [ ] Per-user limits specified
- [ ] Per-election limits specified
- [ ] Global limits specified

### References
- Source Report: 2.1.3.md

### Priority
Medium

---

## Issue: FINDING-128 - Date validation checks format but not logical business constraints
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The date validation in `_set_election_date()` only checks ISO format parsing, not business logic validity.

### Details
Elections can be set with nonsensical dates (past dates, close before open, far future dates), confusing administrators and potentially breaking UI display logic. No validation is performed to ensure dates are in the future, that `close_at` is after `open_at`, or that dates are within a reasonable range.

**ASVS:** 2.2.1 (L1)  
**Affected Files:**
- `v3/server/pages.py` (lines 88-110)

### Remediation
Add business logic validation for dates:
```python
if dt < today:
    quart.abort(400, 'Date cannot be in the past')

if field == 'close_at':
    md = election.get_metadata()
    if md.open_at:
        open_date = datetime.date.fromtimestamp(md.open_at)
        if dt <= open_date:
            quart.abort(400, 'Close date must be after open date')
```

### Acceptance Criteria
- [ ] Past date validation implemented
- [ ] Date ordering validation implemented
- [ ] Tests added for invalid dates
- [ ] Error messages user-friendly

### References
- Source Report: 2.2.1.md
- Related: FINDING-122

### Priority
Medium

---

## Issue: FINDING-129 - Client-side required field validation not replicated server-side
**Labels:** bug, security, priority:medium
**Description:**
### Summary
HTML form uses client-side `required` attribute and JavaScript validation, but server-side handler does NOT verify fields are non-empty.

### Details
The client-side validation can be easily bypassed by submitting a POST request directly with empty values. This is a Type A gap where server-side required-field validation is absent.

Proof of concept: `POST /do-add-issue/1a2b3c4d5e` with `title=&description=` bypasses client-side required attribute and creates an issue with empty title.

**ASVS:** 2.2.2 (L1)  
**Affected Files:**
- `v3/server/pages.py`
- `v3/server/templates/manage.ezt` (line 92)

### Remediation
Add server-side validation:
```python
async def do_add_issue_endpoint(election):
    form = edict(await quart.request.form)
    title = form.get('title', '').strip()
    if not title:
        await flash_danger('Issue title is required.')
        return quart.redirect(f'/manage/{election.eid}', code=303)
```

### Acceptance Criteria
- [ ] Server-side required validation implemented
- [ ] All form fields validated
- [ ] Tests added for empty submissions
- [ ] Verified bypass protection

### References
- Source Report: 2.2.2.md
- Related: FINDING-122

### Priority
Medium

---

## Issue: FINDING-130 - do_vote_endpoint does not verify voter eligibility for each specific issue
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `do_vote_endpoint` validates that the IID exists in the election's issue list, but does not explicitly verify that the authenticated user (PID) is eligible to vote on that specific issue before calling `add_vote`.

### Details
While `add_vote` does check mayvote, if the entry is None it results in an AttributeError rather than explicit authorization denial. This is accidental error handling rather than explicit validation.

**ASVS:** 2.2.3 (L2)  
**Affected Files:**
- `v3/server/pages.py` (lines 372-407)
- `v3/steve/election.py`

### Remediation
Add explicit mayvote NULL check in `add_vote()` method. If mayvote is None, raise a clear `VoterNotEligible` exception rather than allowing AttributeError. This provides clear error handling and distinguishes authorization failures from system errors in logs.

### Acceptance Criteria
- [ ] Explicit eligibility check added
- [ ] Custom exception created
- [ ] Test added for ineligible voter
- [ ] Error logging improved

### References
- Source Report: 2.2.3.md

### Priority
Medium

---

## Issue: FINDING-131 - No validation that STV vote rankings reference valid candidates from issue's labelmap
**Labels:** bug, security, priority:medium
**Description:**
### Summary
For STV issues, the votestring should contain a ranking of candidates whose labels exist in the issue's `kv.labelmap`, but this combined data consistency is not validated.

### Details
The `add_vote()` method does not check that:
- Votestring candidates are in `issue.kv.labelmap`
- Ranking count is valid
- There are no duplicate candidates in ranking

Invalid candidate references would corrupt STV tallying results or cause tally errors.

**ASVS:** 2.2.3 (L2)  
**Affected Files:**
- `v3/steve/election.py` (lines 231-244)

### Remediation
Validate that each ranked candidate label exists in the issue's `kv.labelmap` and there are no duplicates. Check that the ranking count does not exceed the number of candidates. Implement this validation before storing the encrypted vote.

### Acceptance Criteria
- [ ] Candidate label validation implemented
- [ ] Duplicate detection added
- [ ] Ranking count validation added
- [ ] Tests added for invalid rankings

### References
- Source Report: 2.2.3.md

### Priority
Medium

---

## Issue: FINDING-132 - Missing browser security feature documentation
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
No application documentation exists specifying the expected browser security features (HTTPS, HSTS, CSP, X-Content-Type-Options, etc.) or defining application behavior when these features are unavailable.

### Details
The `config.yaml.example` configures TLS certificates but there is no documentation or code that:
1. Specifies that browsers MUST support HTTPS
2. Defines HSTS requirements
3. Specifies Content-Security-Policy requirements
4. Defines behavior when security features are absent
5. Specifies minimum browser version requirements

The `header.ezt` template contains no `<meta>` CSP tags and no JavaScript feature detection.

**ASVS:** 3.1.1 (L3)  
**Affected Files:**
- Application-wide (no documentation file present)
- `config.yaml.example`
- `header.ezt`

### Remediation
1. Create a security documentation file (e.g., SECURITY.md) specifying:
   - Required: HTTPS, HSTS (max-age≥31536000), CSP with script-src restrictions
   - Required: X-Content-Type-Options: nosniff, X-Frame-Options or frame-ancestors
   - Behavior: HTTP requests must redirect to HTTPS; unsupported browsers receive a warning page
2. Implement corresponding middleware in the application

### Acceptance Criteria
- [ ] SECURITY.md created
- [ ] Browser requirements documented
- [ ] Fallback behavior specified
- [ ] Middleware implemented

### References
- Source Report: 3.1.1.md

### Priority
Medium

---

## Issue: FINDING-133 - DOM Clobbering via Global Scope Variables and Unsanitized HTML
**Labels:** bug, security, priority:medium
**Description:**
### Summary
JavaScript variables declared in global scope combined with unsanitized HTML in issue descriptions could enable DOM clobbering attacks.

### Details
The `manage.ezt` and `manage-stv.ezt` templates declare JavaScript variables in the global scope (not wrapped in an IIFE or module). Variables like `openModal`, `closeModal`, `csrfToken`, etc. are global. Additionally, `document.getElementById()` is used extensively, and issue descriptions (rendered as raw HTML) could potentially introduce elements with crafted `id` attributes.

Attack scenario: Admin creates issue with description containing `<form id="csrf-token"><input name="value" value="attacker-controlled"></form>`. When rendered, `document.getElementById('csrf-token')` would resolve to this injected element.

**CWE:** CWE-79  
**ASVS:** 3.2.3 (L3)  
**Affected Files:**
- `v3/server/templates/manage.ezt` (JavaScript blocks)
- `v3/server/templates/manage-stv.ezt` (JavaScript blocks)

### Remediation
1. Wrap all page-level JavaScript in IIFEs:
```javascript
(function() {
    'use strict';
    const csrfToken = document.getElementById('csrf-token').value;
    // ... rest of code
})();
```
2. Sanitize HTML in issue descriptions to prevent `id` and `name` attribute injection
3. Use more specific selectors: `const csrfToken = document.querySelector('input#csrf-token[type="hidden"]').value;`

### Acceptance Criteria
- [ ] All JavaScript wrapped in IIFEs
- [ ] HTML sanitization implemented
- [ ] Specific selectors used
- [ ] Tests added for DOM clobbering

### References
- Source Report: 3.2.3.md
- Related: FINDING-004, FINDING-029, FINDING-118, FINDING-119

### Priority
Medium

---

## Issue: FINDING-134 - Session cookies lack __Host- prefix
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application uses session cookies managed by the `asfquart` framework, but there is no visible configuration that sets the `__Host-` prefix for the session cookie name.

### Details
Without the `__Host-` prefix, the session cookie could potentially be:
- Set by a subdomain attacker (cookie tossing)
- Transmitted over unencrypted connections
- Scoped to a different path than intended

**ASVS:** 3.3.3 (L2)  
**Affected Files:**
- `v3/server/main.py` (line 38)
- `v3/server/pages.py` (line 72)

### Remediation
Configure the session cookie name with the `__Host-` prefix in app configuration:
```python
app.config['SESSION_COOKIE_NAME'] = '__Host-steve_session'
```

Note that `__Host-` prefix requires Secure=True, Path=/, and no Domain attribute, which are automatically enforced by compliant browsers.

### Acceptance Criteria
- [ ] Session cookie configured with __Host- prefix
- [ ] Secure attribute verified
- [ ] Path attribute verified
- [ ] Tests added

### References
- Source Report: 3.3.3.md

### Priority
Medium

---

## Issue: FINDING-135 - Session cookie HttpOnly attribute not explicitly configured
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The session cookie configuration is not visible in the provided code, and there is no explicit `SESSION_COOKIE_HTTPONLY = True` configuration.

### Details
The application stores sensitive session data (uid, fullname, email) via `asfquart.session`. While the framework may default to HttpOnly, the absence of explicit configuration cannot be verified.

Data flow: User authenticates via OAuth → session token stored in cookie → cookie potentially readable by client-side JavaScript if HttpOnly not set → XSS could steal session tokens.

Given the EZT template system lacks auto-escaping and the `flashes.ezt` template renders flash messages without explicit escaping, this is a heightened risk.

**ASVS:** 3.3.4 (L2)  
**Affected Files:**
- `v3/server/main.py` (line 38)
- `v3/server/pages.py` (lines 60-90)

### Remediation
Explicitly configure session cookie attributes in application configuration:
```python
# Explicit configuration in create_app() or app config
app.config['SESSION_COOKIE_HTTPONLY'] = True
# Or in Quart's response handling:
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)
```

### Acceptance Criteria
- [ ] HttpOnly attribute explicitly configured
- [ ] SameSite attribute configured
- [ ] Configuration verified
- [ ] Tests added

### References
- Source Report: 3.3.4.md

### Priority
Medium

---

## Issue: FINDING-136 - No CORS configuration is visible in the application code
**Labels:** bug, security, priority:medium
**Description:**
### Summary
No CORS configuration is visible in the application code. While this may be intentional, the ASVS requirement states that the CORS policy should be explicitly configured.

### Details
The absence of CORS headers means the browser's same-origin policy applies by default, which is the most restrictive setting. However, without explicit verification, we cannot confirm that no other middleware (e.g., `asfquart` internals or the reverse proxy) adds permissive CORS headers.

**ASVS:** 3.4.2 (L1)  
**Affected Files:**
- `v3/server/main.py` (entire file)
- `v3/server/pages.py` (entire file)

### Remediation
Add explicit CORS header configuration:
```python
@APP.after_request
async def add_cors_headers(response):
    # Explicitly deny cross-origin access (or allowlist trusted origins)
    # If CORS is not needed, ensure no Access-Control-Allow-Origin is set
    # If needed for specific endpoints:
    # response.headers['Access-Control-Allow-Origin'] = 'https://trusted.apache.org'
    
    # Remove any accidentally-set permissive CORS headers
    response.headers.pop('Access-Control-Allow-Origin', None)
    return response
```

### Acceptance Criteria
- [ ] CORS policy explicitly configured
- [ ] After_request handler added
- [ ] Tests verify no unintended CORS headers
- [ ] Documentation updated

### References
- Source Report: 3.4.2.md

### Priority
Medium

---

## Issue: FINDING-137 - Missing security response headers (CSP, HSTS, Referrer-Policy, etc.)
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application does not configure any HTTP security response headers, leaving browsers unable to enforce security features.

### Details
Missing headers include:
- Content-Security-Policy (restricts script execution, blocks inline scripts)
- Strict-Transport-Security (enforces HTTPS, prevents downgrade attacks)
- X-Content-Type-Options: nosniff (prevents MIME sniffing)
- Permissions-Policy (restricts browser APIs)
- Referrer-Policy (prevents sensitive URL leakage)
- Content-Security-Policy-Report-Only (monitors policy violations)

This results in no defense-in-depth via CSP for XSS prevention, no HSTS means browsers may downgrade to HTTP, and no visibility into browser security feature support.

**ASVS:** 3.4.5 (L2), 3.7.5 (L3)  
**Affected Files:**
- `v3/server/main.py` (application-wide)
- `v3/server/templates/header.ezt`
- `v3/server/templates/footer.ezt`
- `v3/server/templates/about.ezt`

### Remediation
Add after_request handler in `main.py` `create_app()` function to set security headers on all responses:
- Content-Security-Policy: `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' https://www.apache.org; frame-ancestors 'none'; report-uri /csp-report`
- Strict-Transport-Security: `max-age=31536000; includeSubDomains`
- X-Content-Type-Options: `nosniff`
- X-Frame-Options: `DENY`
- Permissions-Policy: `camera=(), microphone=(), geolocation=()`
- Referrer-Policy: `strict-origin-when-cross-origin`

### Acceptance Criteria
- [ ] After_request handler implemented
- [ ] All security headers configured
- [ ] CSP report endpoint created
- [ ] Tests verify headers present

### References
- Source Reports: 3.4.5.md, 3.7.5.md

### Priority
Medium

---

## Issue: FINDING-138 - Missing Cross-Origin-Opener-Policy header on HTML responses
**Labels:** bug, security, priority:medium
**Description:**
### Summary
No Cross-Origin-Opener-Policy header is set on any HTML response, leaving the application vulnerable to tabnabbing and frame counting attacks.

### Details
This leaves the application vulnerable to:
1. Tabnabbing - If a user opens a link in a new tab (e.g., external links in footer.ezt to apache.org), the opened page can manipulate `window.opener` to redirect the original page
2. Frame counting - Cross-origin pages can count the number of frames/windows, leaking information about application state

The footer template includes `target="_open_privacy_link"` which opens new windows, creating opener references.

**ASVS:** 3.4.8 (L3)  
**Affected Files:**
- `v3/server/main.py` (application-wide)
- `v3/server/pages.py` (all HTML-rendering routes)

### Remediation
Add an after_request handler to set the Cross-Origin-Opener-Policy header on all HTML responses:
```python
@app.after_request
async def set_security_headers(response):
    if 'text/html' in response.content_type:
        response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    return response
```

### Acceptance Criteria
- [ ] COOP header implemented
- [ ] Applied to all HTML responses
- [ ] Tests verify header present
- [ ] Verified external links don't break

### References
- Source Report: 3.4.8.md

### Priority
Medium

---

## Issue: FINDING-139 - JSON Endpoints Lack Content-Type Enforcement
**Labels:** bug, security, priority:medium
**Description:**
### Summary
While `get_json()` typically requires `Content-Type: application/json`, the server does not explicitly validate the Content-Type header, potentially allowing CORS preflight bypass.

### Details
If Quart's `get_json()` has a `force=True` option or falls back to parsing regardless of content-type, a request with `text/plain` (CORS-safelisted) could bypass preflight. Additionally, the client-side code sends CSRF token as custom header (X-CSRFToken), which WOULD trigger a CORS preflight, but the server never validates this header value.

**ASVS:** 3.5.2 (L1)  
**Affected Files:**
- `v3/server/pages.py` (line 88)

### Remediation
Explicitly verify Content-Type to ensure preflight was triggered:
```python
# In _set_election_date function
if request.content_type != 'application/json':
    quart.abort(415, 'Content-Type must be application/json')
```

This ensures the request format cannot be changed to bypass preflight checks.

### Acceptance Criteria
- [ ] Content-Type validation added
- [ ] Applied to all JSON endpoints
- [ ] Tests verify enforcement
- [ ] 415 error returned for invalid Content-Type

### References
- Source Report: 3.5.2.md

### Priority
Medium

---

## Issue: FINDING-140 - No Sec-Fetch-* Header Validation on Any Endpoint
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application does not validate Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, or Sec-Fetch-User headers on any endpoint, missing an opportunity for defense-in-depth.

### Details
Modern browsers send these headers automatically and they cannot be forged by JavaScript. Validating them provides an additional layer of cross-origin protection. All state-changing endpoints should reject requests where `Sec-Fetch-Site: cross-site` or `Sec-Fetch-Mode: no-cors`.

**ASVS:** 3.5.3 (L1)  
**Affected Files:**
- `v3/server/pages.py` (entire file)

### Remediation
Implement a before_request middleware to validate Sec-Fetch headers:
- Reject cross-origin requests to sensitive endpoints by checking if Sec-Fetch-Site is 'cross-site' or 'none' for POST/PUT/DELETE/PATCH methods
- For GET state-changing endpoints, reject requests where Sec-Fetch-Dest is 'image', 'script', or 'style' to prevent resource embedding attacks

### Acceptance Criteria
- [ ] Before_request middleware implemented
- [ ] Sec-Fetch header validation added
- [ ] Applied to all state-changing endpoints
- [ ] Tests verify rejection of cross-origin requests

### References
- Source Report: 3.5.3.md

### Priority
Medium

---

## Issue: FINDING-141 - External Image Resource Loaded Without Integrity Verification
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Browser loads SVG image from `https://www.apache.org` without integrity verification, creating dependency on unverified external resource.

### Details
Data flow: Browser loads page → fetches SVG from `https://www.apache.org` → no integrity verification → SVG rendered in page.

If the external Apache CDN is compromised or DNS is hijacked, a malicious SVG could be served. While `<img>`-loaded SVGs cannot execute scripts, a compromised or modified image could affect application trust perception. SRI is not supported on `<img>` tags by browsers.

**ASVS:** 3.6.1 (L3), 3.4.3 (L2)  
**Affected Files:**
- `v3/server/templates/header.ezt` (line 14)

### Remediation
**Option 1 (Recommended):** Self-host the image:
```html
<img src="/static/images/feather.svg" alt="Logo" width="30" height="30" class="d-inline-block align-text-top">
```

**Option 2:** Document the security decision for this specific resource, noting that img-loaded SVGs cannot execute scripts.

### Acceptance Criteria
- [ ] Image self-hosted OR security decision documented
- [ ] External dependency removed OR justified
- [ ] Tests verify image loads correctly

### References
- Source Reports: 3.6.1.md, 3.4.3.md

### Priority
Medium

---

## Issue: FINDING-142 - OAuth Redirect URI Pattern May Be Susceptible to Open Redirect
**Labels:** bug, security, priority:high
**Description:**
### Summary
The OAuth redirect pattern may allow open redirect attacks if the `login=` parameter value is used as a post-authentication redirect without validation against an allowlist.

### Details
Attack scenario: Attacker sends phishing link `https://steve.example.org/auth?login=https://evil.com/steal-session`. If the `login=` parameter value is used as a post-authentication redirect without validation, the user will be redirected to the attacker's site after authenticating.

The `/auth` endpoint implementation is in the asfquart framework (not provided). This finding is based on the observable pattern that login/logout parameters accept path values, and no allowlist validation is visible.

**ASVS:** 3.7.2 (L2)  
**Affected Files:**
- `v3/server/main.py` (lines 37-41)
- `v3/server/templates/header.ezt` (lines 28, 37)

### Remediation
In the auth handling (asfquart framework or custom middleware):
1. Add an ALLOWED_REDIRECT_PATHS allowlist containing safe internal paths like `{'/voter', '/admin', '/'}`
2. Implement a validate_redirect function that ensures redirect target is a safe internal path by parsing the URL and rejecting any with scheme or netloc, or that don't start with '/'
3. Return a default safe redirect '/' if validation fails

### Acceptance Criteria
- [ ] Redirect allowlist implemented
- [ ] Validation function added
- [ ] Tests for malicious redirects
- [ ] Default safe redirect configured

### References
- Source Report: 3.7.2.md

### Priority
High

---

## Issue: FINDING-143 - External Links Navigate Without User Notification or Cancellation Option
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Users are navigated away from the authenticated application without notification when clicking external links.

### Details
While these specific links go to trusted Apache-controlled domains, there is no architectural pattern in place to handle this for any future external links. This is a Level 3 requirement and the absence of the pattern means it cannot be verified.

Data flow: User clicks external link → browser immediately navigates to https://www.apache.org/... or https://steve.apache.org/ → no interstitial warning → no cancel option

**ASVS:** 3.7.3 (L3)  
**Affected Files:**
- `v3/server/templates/footer.ezt` (lines 8-12)
- `v3/server/templates/home.ezt` (lines 46-49)
- `v3/server/templates/about.ezt` (line 7)

### Remediation
Add an external redirect interstitial page with validation against allowlist of trusted domains:
1. Implement `/external-link` endpoint that validates target URLs against TRUSTED_DOMAINS allowlist
2. For untrusted domains, render an interstitial template with Continue and Cancel buttons
3. Create `external_redirect.ezt` template

### Acceptance Criteria
- [ ] External redirect endpoint implemented
- [ ] Trusted domains allowlist created
- [ ] Interstitial template created
- [ ] Tests for trusted/untrusted domains

### References
- Source Report: 3.7.3.md

### Priority
Medium

---

## Issue: FINDING-144 - Inline JavaScript Without CSP Nonce/Hash Strategy
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Every interactive template contains substantial inline JavaScript without CSP nonce/hash strategy, making it impossible to implement proper CSP-based browser security feature enforcement.

### Details
Templates with inline scripts include:
- `manage.ezt` (~120 lines inline JS)
- `manage-stv.ezt` (~100 lines inline JS)
- `vote-on.ezt` (~200 lines inline JS)
- `admin.ezt` (~20 lines inline JS)
- `voter.ezt` (~20 lines inline JS)

This prevents implementation of strict CSP without 'unsafe-inline', means browsers cannot enforce script source restrictions, gives XSS attacks full access to page context, and prevents CSP violation reporting for these scripts.

**ASVS:** 3.7.5 (L3)  
**Affected Files:**
- `v3/server/templates/manage.ezt`
- `v3/server/templates/admin.ezt`
- `v3/server/templates/vote-on.ezt`
- `v3/server/templates/manage-stv.ezt`
- `v3/server/templates/voter.ezt`
- `v3/server/pages.py`

### Remediation
**Option 1:** Generate a CSP nonce per request on the Python side:
```python
result.csp_nonce = secrets.token_hex(16)
```
Add nonce attribute to all inline script tags in templates:
```html
<script nonce="[csp_nonce]">
```
Update CSP header to include `script-src 'self' 'nonce-{csp_nonce}'`

**Option 2:** Refactor inline scripts into external .js files referenced by src attribute to eliminate need for nonces.

### Acceptance Criteria
- [ ] CSP nonce strategy implemented OR scripts externalized
- [ ] All inline scripts updated
- [ ] CSP header configured
- [ ] Tests verify CSP enforcement

### References
- Source Report: 3.7.5.md

### Priority
Medium

---

## Issue: FINDING-145 - No Prerequisite Validation Before Election Opening
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `open()` method does not validate that an election has the necessary prerequisites (issues and eligible voters) before allowing it to be opened.

### Details
An attacker can create an election and immediately open it without adding any issues or voters, resulting in a logically invalid and irreversible election state. This represents a skipped step in the business flow (configure → validate → open).

**CWE:** CWE-754  
**ASVS:** 2.3.1 (L1)  
**Affected Files:**
- `v3/steve/election.py` (line 70)
- `v3/server/pages.py` (line 431)

### Remediation
Add prerequisite validation in the `open()` method:
```python
# Verify at least one issue exists
issues = self.list_issues()
if not issues:
    raise ValueError('Cannot open election with no issues')

# Verify at least one eligible voter
self.q_voting_persons.perform(self.eid)
voters = self.q_voting_persons.fetchall()
if not voters:
    raise ValueError('Cannot open election with no eligible voters')
```

### Acceptance Criteria
- [ ] Prerequisite validation implemented
- [ ] Issue count validation added
- [ ] Voter count validation added
- [ ] Tests for invalid states
- [ ] User-friendly error messages

### References
- Source Report: 2.3.1.md

### Priority
Medium

---

## Issue: FINDING-146 - No Logical Constraint Validation on Election Dates
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `_set_election_date()` function validates date format but does not perform logical validation on election dates.

### Details
It accepts dates in the past and does not verify that `close_at` is after `open_at`. This could result in confusing or misleading date information displayed to voters and could be used to manipulate voter behavior, such as showing a close date has passed to discourage voting while the election is still open.

**CWE:** CWE-20  
**ASVS:** 2.3.2 (L2)  
**Affected Files:**
- `v3/server/pages.py` (line 88)

### Remediation
Add logical date validation to ensure `close_at` is after `open_at` and that dates are not set to unreasonable values in the past. Implement business logic constraints that enforce sensible date ranges for elections.

### Acceptance Criteria
- [ ] Logical date validation implemented
- [ ] Past date rejection added
- [ ] Date ordering validation added
- [ ] Tests for invalid date combinations

### References
- Source Report: 2.3.2.md
- Related: FINDING-128

### Priority
Medium

---

## Issue: FINDING-147 - Election Creation Script Has Transaction Code Commented Out
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `create-election.py` script has transaction wrapping code (BEGIN TRANSACTION, COMMIT, ROLLBACK) commented out with a TODO note.

### Details
If voter addition fails partway through (e.g., PID not found), the election is left with some but not all eligible voters. No rollback occurs, leaving the election in a partially configured state.

**CWE:** CWE-662  
**ASVS:** 2.3.3 (L2)  
**Affected Files:**
- `v3/server/bin/create-election.py` (lines 83, 109)

### Remediation
Re-enable the transaction wrapping code by uncommenting the BEGIN TRANSACTION, COMMIT, and ROLLBACK statements. Ensure database setup allows for proper transaction support.

### Acceptance Criteria
- [ ] Transaction code uncommented
- [ ] Database transactions verified working
- [ ] Tests for partial failure scenarios
- [ ] Rollback behavior verified

### References
- Source Report: 2.3.3.md
- Related: FINDING-046, FINDING-047

### Priority
Medium

---

## Issue: FINDING-148 - Vote Table Allows Unlimited Re-Votes Without Locking or Rate Control
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Each call to `add_vote()` performs a pure INSERT into the vote table with no limit on how many rows a single vote_token can accumulate.

### Details
Repeatedly POSTing to `/do-vote/<eid>` with the same ballot adds a new row for each issue on each submission. After 1000 submissions, there are 1000 rows per vote_token, consuming storage and making tally queries slower.

While re-voting is an intended feature (only the latest vote counts), there's no limit on how many times a voter can re-vote, potentially exhausting storage or degrading tally performance.

**CWE:** CWE-770  
**ASVS:** 2.3.4 (L2)  
**Affected Files:**
- `v3/steve/election.py` (line 231)
- `v3/queries.yaml` (line 44)

### Remediation
Consider either:
1. An UPDATE pattern (replacing the existing vote)
2. Limiting re-votes per voter per issue
3. Add rate limiting on the `/do-vote/<eid>` endpoint
4. Implement vote garbage collection to periodically remove superseded vote rows

### Acceptance Criteria
- [ ] Vote limit strategy implemented
- [ ] Rate limiting added
- [ ] Garbage collection implemented OR update pattern used
- [ ] Tests for excessive re-voting

### References
- Source Report: 2.3.4.md
- Related: FINDING-006

### Priority
Medium

---

## Issue: FINDING-149 - Irreversible Election State Changes Require Only Single-User Action
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Opening and closing elections trigger irreversible operations but require only single-user action without oversight.

### Details
Opening an election triggers irreversible cryptographic operations (salt generation, opened_key computation). Closing an election permanently ends voting. Both actions have significant organizational impact — voters may be disenfranchised by premature closure, or an improperly configured election may be opened without review.

A single user (or compromised account) can irreversibly alter election state without oversight. For an organization like the ASF where elections determine governance, this represents a high-value operation that should require multi-party approval.

**CWE:** CWE-863  
**ASVS:** 2.3.5 (L3)  
**Affected Files:**
- `v3/server/pages.py` (lines 431, 451)

### Remediation
Add approval workflow:
1. Create endpoints for requesting state changes (`/do-request-open/<eid>`) that record the request and notify approvers
2. Create approval endpoints (`/do-approve-open/<eid>`) that:
   - Verify the approver is different from the requester
   - Verify approver has authority
   - Execute the state change only after approval

### Acceptance Criteria
- [ ] Approval workflow implemented
- [ ] Request endpoints created
- [ ] Approval endpoints created
- [ ] Notification system integrated
- [ ] Tests for approval flow

### References
- Source Report: 2.3.5.md
- Related: FINDING-251

### Priority
Medium

---

## Issue: FINDING-150 - No Minimum Time Enforcement in add_vote() Business Logic
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The business logic layer for vote submission has no concept of vote timing, providing zero defense-in-depth against automated vote submission.

### Details
There is no tracking of when a voter last submitted a vote, no minimum interval enforcement between re-votes, and no defense-in-depth against automated vote submission. The vote table lacks a timestamp column that could enable retroactive timing analysis.

Combined with the handler-level lack of rate limiting, there is zero defense-in-depth against automated vote submission.

**CWE:** CWE-799  
**ASVS:** 2.4.2 (L3)  
**Affected Files:**
- `v3/steve/election.py` (line 231)

### Remediation
1. Add timestamp tracking to the vote submission logic
2. Check time since last vote by the same vote_token
3. Raise VoteTooRapid exception if submitted within minimum revote interval
4. Implement query to retrieve last vote time and enforce minimum interval at business logic layer

### Acceptance Criteria
- [ ] Timestamp column added to vote table
- [ ] Minimum interval check implemented
- [ ] VoteTooRapid exception created
- [ ] Tests for rapid re-voting

### References
- Source Report: 2.4.2.md

### Priority
Medium

---

## Issue: FINDING-151 - Configuration Template Missing TLS Version Controls
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The configuration template provides no guidance or fields for specifying TLS protocol versions.

### Details
Administrators deploying this application have no documented mechanism to enforce TLS 1.2+ or prefer TLS 1.3.

**ASVS:** 12.1.1 (L1)  
**Affected Files:**
- `v3/server/config.yaml.example` (lines 6-12)

### Remediation
Add TLS version configuration to the example config:
```yaml
server:
  certfile: /path/to/cert.pem
  keyfile: /path/to/key.pem
  min_tls_version: "1.2"  # Minimum TLS version 1.2 or 1.3
```

### Acceptance Criteria
- [ ] TLS version config added to example
- [ ] Documentation updated
- [ ] Deployment guide includes TLS configuration

### References
- Source Report: 12.1.1.md

### Priority
Medium

---

## Issue: FINDING-152 - OCSP Stapling Not Configured for TLS Server
**Labels:** bug, security, priority:medium
**Description:**
### Summary
No OCSP stapling is configured for the TLS server, meaning clients will not be efficiently informed of certificate revocation status.

### Details
Without OCSP stapling:
- Clients must perform their own OCSP lookups (slower, privacy-leaking)
- Many clients soft-fail OCSP checks meaning revoked certificates may still be accepted
- The development configuration uses self-signed certificates (where OCSP is not applicable), but production deployments need this

**ASVS:** 12.1.4 (L3)  
**Affected Files:**
- `v3/server/main.py` (lines 75-82)
- `v3/server/config.yaml.example`

### Remediation
For production deployment with Hypercorn:
1. Configure OCSP stapling in the SSL context by creating an SSL context with minimum TLS version 1.2
2. Load the certificate chain and enable OCSP stapling if response is available
3. For Hypercorn-based deployment, add ssl configuration to `hypercorn.toml` with certfile and keyfile paths
4. Configure a reverse proxy (nginx/Apache) with OCSP stapling enabled

Note that full OCSP stapling requires periodic refresh of the OCSP response.

### Acceptance Criteria
- [ ] OCSP stapling configured
- [ ] SSL context updated
- [ ] Documentation for reverse proxy setup
- [ ] Tests verify OCSP response

### References
- Source Report: 12.1.4.md

### Priority
Medium

---

## Issue: FINDING-153 - Self-Signed Certificates Used with No Pathway to Publicly Trusted Certificates
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The example configuration and documentation exclusively reference self-signed certificates with no production configuration example using publicly trusted certificates.

### Details
There is:
1. No production configuration example with publicly trusted certificates
2. No documentation on deploying with publicly trusted TLS certs
3. No validation that configured certificates are publicly trusted
4. The certs/ directory structure implies certificate storage alongside code

External-facing clients would encounter certificate warnings or be vulnerable to MITM attacks if self-signed certificates are used in production.

**ASVS:** 12.2.2 (L1)  
**Affected Files:**
- `v3/server/config.yaml.example` (lines 25-31)
- `v3/docs/quickstart.md` (lines 49-53)

### Remediation
1. Provide a production configuration example using Let's Encrypt or other CA-signed certificates
2. Add deployment documentation requiring publicly trusted certificates for production
3. Consider integrating ACME (Let's Encrypt) certificate provisioning

Example production config:
```yaml
server:
  port: 443
  certfile: /etc/letsencrypt/live/voting.example.org/fullchain.pem
  keyfile: /etc/letsencrypt/live/voting.example.org/privkey.pem
```

### Acceptance Criteria
- [ ] Production config example added
- [ ] Let's Encrypt documentation created
- [ ] Certificate validation guidance added
- [ ] Deployment checklist includes certificate verification

### References
- Source Report: 12.2.2.md

### Priority
Medium

---

## Issue: FINDING-154 - No TLS Enforcement in ASGI Deployment Mode
**Labels:** bug, security, priority:medium
**Description:**
### Summary
When running in ASGI mode (production deployment via Hypercorn), TLS configuration is entirely delegated to the external ASGI server with no validation or enforcement within the application.

### Details
The application code does not:
- Verify that the ASGI server has TLS configured
- Set any TLS-related response headers (HSTS)
- Reject non-HTTPS requests
- Check X-Forwarded-Proto when behind a proxy

**ASVS:** 12.2.1 (L1)  
**Affected Files:**
- `v3/server/main.py` (lines 88-108)

### Remediation
Add middleware to enforce HTTPS in ASGI mode:
```python
@APP.before_request
async def enforce_https():
    if not quart.request.is_secure and \
       quart.request.headers.get('X-Forwarded-Proto') != 'https':
        quart.abort(403, 'HTTPS required')
```

Document required TLS configuration for Hypercorn and proxy deployments.

### Acceptance Criteria
- [ ] HTTPS enforcement middleware added
- [ ] X-Forwarded-Proto check implemented
- [ ] Hypercorn TLS documentation created
- [ ] Tests verify HTTPS enforcement

### References
- Source Report: 12.2.1.md

### Priority
Medium

---

## Issue: FINDING-155 - No Visible TLS Certificate Validation for Outbound OAuth Connections
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application makes outbound HTTPS connections to oauth.apache.org for authentication, but there is no visible code confirming TLS certificate validation is enabled.

### Details
The actual HTTP client implementation is within asfquart (not provided), and there is no visible code confirming:
1. TLS certificate validation is enabled (not verify=False)
2. Certificate chain is validated against system trust store
3. Hostname verification is performed

If certificate validation is disabled or improperly configured in the asfquart OAuth client, the application would be vulnerable to MITM attacks during the OAuth flow, potentially allowing token theft or session hijacking.

**ASVS:** 12.3.2 (L2)  
**Affected Files:**
- `v3/server/main.py` (lines 44-49)

### Remediation
Verify that the asfquart library's HTTP client has certificate validation enabled. Add explicit configuration to enforce certificate verification:
```python
import httpx
async with httpx.AsyncClient(verify=True) as client:
    response = await client.get(oauth_url)
```

### Acceptance Criteria
- [ ] Certificate validation verified in asfquart
- [ ] Explicit verify=True configuration added
- [ ] Tests verify certificate validation
- [ ] Documentation updated

### References
- Source Report: 12.3.2.md

### Priority
Medium

---

## Issue: FINDING-156 - Self-Signed Certificates for Internal/Development Use with No Trust Management
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The system uses self-signed certificates but there is no internal CA configuration, trust store management, or certificate pinning for internal connections.

### Details
There is no:
1. Internal CA configuration or documentation
2. Trust store management for consuming services
3. Certificate pinning for internal connections
4. Guidance on which specific self-signed certificates should be trusted by clients/proxies

A consuming service (reverse proxy) configured to trust "any" self-signed certificate or to skip validation when connecting to this backend would be vulnerable to MITM attacks on the internal network.

**ASVS:** 12.3.4 (L2)  
**Affected Files:**
- `v3/docs/quickstart.md` (lines 49-53)
- `v3/server/config.yaml.example` (lines 25-31)

### Remediation
1. Establish an internal CA and document certificate provisioning
2. Configure the reverse proxy to pin the specific backend certificate or trust only the internal CA

Example nginx proxy configuration:
```nginx
upstream backend {
    server localhost:58383;
}

server {
    location / {
        proxy_pass https://backend;
        proxy_ssl_trusted_certificate /etc/nginx/internal-ca.pem;
        proxy_ssl_verify on;
    }
}
```

### Acceptance Criteria
- [ ] Internal CA established OR certificate pinning implemented
- [ ] Trust store configuration documented
- [ ] Reverse proxy configuration example provided
- [ ] Tests verify certificate validation

### References
- Source Report: 12.3.4.md

### Priority
Medium

---

## Issue: FINDING-157 - Incomplete documentation of application communication needs
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The application communicates with multiple external services, but there is no comprehensive communication inventory document.

### Details
The following communication channels were identified through code analysis but are not formally documented:
1. ASF OAuth Service (external authentication) at oauth.apache.org
2. SMTP/Email Service (voter notification)
3. SQLite Database (local persistence)
4. LDAP Service (authorization, referenced but not implemented)
5. End-user-provided document filenames (potential SSRF vector)

Without comprehensive communication documentation, security teams cannot perform complete threat modeling, firewall rule validation, or network segmentation reviews.

**ASVS:** 13.1.1 (L2)  
**Affected Files:**
- `v3/ARCHITECTURE.md`
- `v3/docs/schema.md`
- `v3/server/config.yaml.example`
- `v3/server/main.py` (lines 36-40)
- `v3/server/bin/mail-voters.py` (lines 67-73)
- `v3/steve/election.py` (line 37)
- `v3/server/pages.py` (lines 560-574)

### Remediation
Create a dedicated COMMUNICATIONS.md document that inventories:
- All external service endpoints (OAuth, SMTP, LDAP)
- Protocol, port, and authentication method for each
- Direction of communication (inbound/outbound)
- User-controllable endpoints or file references
- Network security requirements (TLS versions, cipher suites)

### Acceptance Criteria
- [ ] COMMUNICATIONS.md created
- [ ] All external services documented
- [ ] Network requirements specified
- [ ] Threat model updated

### References
- Source Report: 13.1.1.md

### Priority
Medium

---

## Issue: FINDING-158 - No documentation of concurrent connection limits or fallback mechanisms
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The application interacts with multiple services (SQLite, OAuth, SMTP) but there is no documentation defining maximum concurrent connections, connection pool limits, or behavior when those limits are reached.

### Details
Database connections are opened per-operation without pooling. Each `Election()` instantiation opens a new database connection. Web handlers create new Election/PersonDB instances per request without connection management.

No documentation exists for:
- Maximum concurrent SQLite connections
- OAuth service connection timeouts/limits
- SMTP connection pooling or rate limits
- Fallback behavior if any service becomes unavailable

Under high load, the application may exhaust file descriptors, memory, or other resources.

**ASVS:** 13.1.2 (L3)  
**Affected Files:**
- `v3/ARCHITECTURE.md`
- `v3/steve/election.py` (lines 35-44)
- `v3/server/pages.py` (lines 165-186, 297)

### Remediation
Document for each service:
- Connection pool size or maximum concurrent connections
- Queue/backpressure behavior when limits are reached
- Circuit breaker or fallback patterns

Example configuration:
```yaml
database:
  max_connections: 10
  connection_timeout_ms: 5000
  behavior_at_limit: queue  # or reject

oauth:
  max_concurrent_requests: 5
  timeout_ms: 10000
  fallback: deny_login

smtp:
  max_concurrent_sends: 3
  retry_on_failure: false
```

### Acceptance Criteria
- [ ] Connection limits documented for all services
- [ ] Fallback behavior specified
- [ ] Configuration examples provided
- [ ] Load testing performed

### References
- Source Report: 13.1.2.md

### Priority
Medium

---

## Issue: FINDING-159 - No documented resource-management strategies, timeout settings, or retry logic
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The application documentation does not define resource-management strategies for any external system.

### Details
Gaps identified:
1. No timeout settings for database operations
2. No resource-release procedures documented (connections are closed in some cases but not others)
3. Email sending has no retry or timeout configuration
4. OAuth callback has no documented timeout
5. No retry limits, delays, or back-off algorithms documented

Without defined resource management strategies:
- Database locks could cause indefinite hangs
- Failed email sends could silently drop voter notifications
- OAuth service outages could leave requests hanging
- Resource leaks from unclosed connections could degrade availability

**ASVS:** 13.1.3 (L3)  
**Affected Files:**
- `v3/ARCHITECTURE.md`
- `v3/steve/election.py`
- `v3/server/main.py` (lines 37-40)
- `v3/server/bin/mail-voters.py` (lines 67-73)
- `v3/server/pages.py` (lines 165-186)

### Remediation
Create a resource management section in documentation covering:

**SQLite Database:**
- Timeout: 30 seconds via sqlite3 timeout parameter
- Release: Connections closed after each request via context manager
- Failure handling: Return 503 if database is locked beyond timeout
- Retry: No retries for synchronous operations

**OAuth/ASF OAuth:**
- Timeout: 10 seconds for token exchange
- Retry: None - redirect user to retry login
- Failure handling: Display error page with retry option

**SMTP/Email:**
- Timeout: 30 seconds per message
- Retry: Up to 2 retries with 5-second delay
- Failure handling: Log error, continue to next recipient

### Acceptance Criteria
- [ ] Resource management documentation created
- [ ] Timeout settings specified for all services
- [ ] Retry logic documented
- [ ] Failure handling procedures specified

### References
- Source Report: 13.1.3.md

### Priority
Medium

---

## Issue: FINDING-160 - No secrets rotation schedule or lifecycle management documentation
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
While the application documents what secrets exist and how they are generated, there is no documentation defining a rotation schedule or lifecycle management for any secret.

### Details
Secrets identified in the system:
1. Election salts (16 bytes) generated once, never rotated
2. Mayvote salts (16 bytes) generated once, never rotated
3. Opened keys (32 bytes) derived once for tamper detection
4. TLS certificate private keys with path documented but no rotation
5. Session secrets managed by asfquart, not documented
6. OAuth client credentials referenced but not documented
7. CSRF tokens currently placeholder ('placeholder'), not a real secret

What's missing:
- Rotation schedule for TLS certificates
- Rotation procedures if election salts are compromised
- Session secret rotation policy
- OAuth credential rotation
- Impact assessment if any secret is compromised
- Classification of secrets by criticality

**ASVS:** 13.1.4 (L3)  
**Affected Files:**
- `v3/docs/schema.md`
- `v3/steve/crypto.py` (lines 27-29, 32-41)
- `v3/server/config.yaml.example`
- `v3/server/pages.py` (line 83)

### Remediation
Create a secrets management document with:

**Secrets Inventory and Rotation Schedule:**
| Secret | Criticality | Rotation Schedule | Rotation Procedure |
|--------|-------------|-------------------|-------------------|
| TLS private key | Critical | Annual or on compromise | Re-issue certificate, deploy, restart |
| Session signing key | High | Monthly | Update config, restart server |
| OAuth client secret | High | Annual | Coordinate with ASF OAuth team |
| Election salts | Medium | N/A (single-use) | Cannot rotate once election opened |
| CSRF tokens | High | Per-session | Automatically generated per session |

**Compromise Response:**
- If TLS key compromised: Revoke certificate immediately, re-issue
- If session key compromised: Rotate key, invalidate all sessions
- If election salt compromised: Election integrity may be violated; re-run if possible

### Acceptance Criteria
- [ ] Secrets management document created
- [ ] Rotation schedule specified for each secret
- [ ] Compromise response procedures documented
- [ ] Secret criticality classification defined

### References
- Source Report: 13.1.4.md

### Priority
Medium

## Issue: FINDING-161 - All application components use identical full-privilege database access

**Labels:** security, priority:high, database, privilege-separation

**Description:**

### Summary
All application modules (web handlers, business logic, command-line tools) access the SQLite database with identical full read/write permissions, violating the principle of least privilege. Components that only require read access maintain full write capabilities, expanding the attack surface.

### Details
- Web request handlers, Election model, PersonDB, and CLI tools all use identical database access patterns with full permissions
- The `mail-voters.py` script only needs READ access to election metadata and voter emails, but has full write access to the database
- Voter-facing endpoints (e.g., `/vote-on/<eid>`) can technically invoke any database operation (create elections, delete data) since the same Election class is used
- No OS-level service account separation between the web server and CLI tools
- If any component is compromised (e.g., through a web vulnerability), the attacker gains full database access including ability to modify election results, delete elections, or alter voter records

**Affected files:**
- `v3/steve/election.py:35-37`
- `v3/steve/persondb.py:25-26`
- `v3/server/bin/create-election.py:31`
- `v3/server/bin/mail-voters.py:28`
- `v3/server/pages.py:40`

### Remediation
1. For SQLite: Implement application-level privilege separation by using different database wrapper classes with restricted query sets
   - Example: Create VoterDB class with read-only access and ALLOWED_QUERIES whitelist
2. For CLI tools, use read-only database connections where write access is not needed
   - Example: `mail-voters.py` should use `sqlite3.connect(db_path, uri=True, mode='ro')`
3. Document the principle of least privilege for each component and its required access level

### Acceptance Criteria
- [ ] Database wrapper classes implement privilege separation
- [ ] Read-only connections used for read-only operations
- [ ] Documentation added for component access requirements
- [ ] Test added verifying privilege restrictions

### References
- ASVS 13.2.2
- CWE: Not specified

### Priority
High - Violates defense in depth and increases blast radius of potential compromises

---

## Issue: FINDING-162 - No allowlist defined for outbound resource access or file system access patterns

**Labels:** security, priority:medium, input-validation, file-access

**Description:**

### Summary
User-supplied `docname` URL parameter is passed to `quart.send_from_directory()` for file system access with no allowlist of permitted file types or names. While `send_from_directory` typically prevents path traversal, there is no allowlist of permitted document types/names.

### Details
- The comment `### verify the propriety of DOCNAME.` explicitly acknowledges this gap
- Without an allowlist of permitted document types/names, any file placed in the `DOCSDIR/iid/` directory could be served
- The intent of the developer (per the TODO comment) was clearly to restrict this further
- Potential for serving unintended file types if placed in the document directory

**Affected files:**
- `v3/server/pages.py:560-574`

### Remediation
1. Implement an allowlist of permitted document extensions
   ```python
   ALLOWED_DOC_EXTENSIONS = {'.pdf', '.txt', '.md', '.html'}
   ```
2. Validate `docname` against this allowlist by checking the file extension
3. Ensure no path separators (`/`, `\`, `..`) are present in `docname`
   ```python
   import os
   _, ext = os.path.splitext(docname)
   if ext.lower() not in ALLOWED_DOC_EXTENSIONS:
       quart.abort(400)
   if any(sep in docname for sep in ['/', '\\', '..']):
       quart.abort(400)
   ```

### Acceptance Criteria
- [ ] Document extension allowlist implemented
- [ ] Path separator validation added
- [ ] Test added for rejected file types
- [ ] Test added for path traversal attempts

### References
- ASVS 13.2.4

### Priority
Medium - Defense in depth measure for file serving

---

## Issue: FINDING-163 - Database connections opened without documented configuration for timeouts, connection limits, or retry strategies

**Labels:** security, priority:medium, database, reliability

**Description:**

### Summary
Multiple call sites open database connections through `asfpy.db.DB()` without timeout, pool limit, or retry configuration. This could lead to indefinite hangs, file handle exhaustion, or transient failure cascades.

### Details
- No connection timeout means requests could hang indefinitely if the database file becomes locked
- No maximum connection limit means concurrent requests could exhaust file handles
- No retry strategy means transient failures (e.g., WAL checkpoint) cause immediate errors
- Database connections are opened per-request without pooling

**Affected files:**
- `v3/steve/election.py:36`
- `v3/steve/persondb.py:27`
- `v3/server/pages.py:567`

### Remediation
1. Implement configuration constants:
   ```python
   DB_TIMEOUT = 30  # seconds
   DB_MAX_CONNECTIONS = 10
   DB_RETRY_ATTEMPTS = 3
   DB_RETRY_DELAY = 0.5  # seconds
   ```
2. Set PRAGMA busy_timeout on connections:
   ```python
   db.conn.execute('PRAGMA busy_timeout = 30000')
   ```
3. Enable WAL mode for better concurrency:
   ```python
   db.conn.execute('PRAGMA journal_mode = WAL')
   ```

### Acceptance Criteria
- [ ] Database timeout configuration implemented
- [ ] Connection pooling or limits added
- [ ] Retry strategy implemented for transient failures
- [ ] Test added for database contention scenarios

### References
- ASVS 13.2.6

### Priority
Medium - Affects reliability and availability under load

---

## Issue: FINDING-164 - Internal _all_metadata() method exposes SALT and OPENED_KEY to any code with Election object access

**Labels:** security, priority:medium, cryptography, access-control

**Description:**

### Summary
The `_all_metadata()` method is marked as 'INTERNAL ONLY' by convention (leading underscore and comment), but Python does not enforce access control. Any code with access to an Election instance can call `election._all_metadata()` to retrieve the salt and opened_key.

### Details
- The `__getattr__` proxy method (line 48) means that query cursors like `q_metadata` are directly accessible on the Election object
- If authorization gaps exist (and they do — multiple `### check authz` placeholders), any authenticated user who obtains an Election object could access sensitive cryptographic material through the internal API
- Exposure of salt and opened_key could compromise election integrity verification

**Affected files:**
- `v3/steve/election.py:130`

### Remediation
Return a wrapper object that prevents serialization of sensitive fields:
```python
class _InternalMetadata:
    __slots__ = ('title', 'owner_pid', 'monitors', 'state', 'start', 'end')
    
    def __init__(self, row):
        self.title = row['title']
        self.owner_pid = row['owner_pid']
        # ... other non-sensitive fields
        # Explicitly exclude: salt, opened_key
    
    def __repr__(self):
        return f'<Metadata title={self.title!r} state={self.state}>'
```

### Acceptance Criteria
- [ ] Wrapper class prevents exposure of sensitive fields
- [ ] __repr__ redacts sensitive information
- [ ] Test added verifying salt/opened_key not accessible
- [ ] Documentation updated on internal API usage

### References
- ASVS 13.3.2

### Priority
Medium - Reduces risk of accidental cryptographic material exposure

---

## Issue: FINDING-165 - Per-voter-per-issue salt values have no expiration or rotation mechanism

**Labels:** security, priority:medium, cryptography, key-management

**Description:**

### Summary
Per-voter-per-issue salt values in the `mayvote` table have no expiration or rotation mechanism. These salts are critical for deriving vote_token and encryption keys and persist indefinitely with no lifecycle management.

### Details
- Salt values (16 bytes) stored in `mayvote` table persist for the lifetime of the database
- Once set during `add_salts()`, they remain unchanged
- No documented key lifecycle policy
- No cleanup mechanism after election finalization

**Affected files:**
- `v3/schema.sql:130-139`
- `v3/steve/election.py`

### Remediation
Implement a key lifecycle policy that:
1. Documents expected lifetimes for all secret material
2. Removes or re-encrypts key material after election finalization
3. Implements automated cleanup of secrets past their useful life
4. Considers secret rotation for long-running elections or maximum election duration policy

Example:
```python
def finalize_election(self):
    """Finalize election and clean up cryptographic material."""
    # Archive results
    # Remove salts and keys
    self.c_cleanup_secrets.perform(self.eid)
    self.db.conn.commit()
```

### Acceptance Criteria
- [ ] Key lifecycle policy documented
- [ ] Cleanup mechanism implemented for finalized elections
- [ ] Test added for secret removal after finalization
- [ ] Maximum election duration policy considered

### References
- ASVS 13.3.4

### Priority
Medium - Reduces long-term exposure of cryptographic material

---

## Issue: FINDING-166 - Static file endpoint serves source control metadata

**Labels:** security, priority:medium, information-disclosure, file-access

**Description:**

### Summary
The `/static/<path:filename>` endpoint accepts paths with subdirectories (e.g., `.git/config`, `.svn/entries`). If a `.git` or `.svn` folder exists within `STATICDIR`, it would be served to clients.

### Details
- While `send_from_directory` should prevent path traversal above the root, it will serve any file within the directory tree including source control metadata
- Could occur from development/deployment practices
- Exposes repository history, configuration, and potentially sensitive information

**Affected files:**
- `v3/server/pages.py:577-578`

### Remediation
Add explicit blocking of source control metadata paths:
```python
import re

BLOCKED_PATTERNS = re.compile(r'(^|/)(\.|)(git|svn|hg|bzr)(/|$)', re.IGNORECASE)

@APP.route('/static/<path:filename>')
async def serve_static(filename: str):
    if BLOCKED_PATTERNS.search(filename):
        quart.abort(404)
    return await quart.send_from_directory(STATICDIR, filename)
```

### Acceptance Criteria
- [ ] Source control directory blocking implemented
- [ ] Test added for .git path rejection
- [ ] Test added for .svn path rejection
- [ ] Documentation updated on static file serving restrictions

### References
- ASVS 13.4.1

### Priority
Medium - Prevents information disclosure of repository metadata

---

## Issue: FINDING-167 - Debug print() statements expose form data to stdout in production

**Labels:** bug, security, priority:medium, logging, information-disclosure

**Description:**

### Summary
Two endpoint handlers dump complete form data to stdout via `print()` statements. This creates an undocumented log channel that bypasses the `_LOGGER` system and its configured handlers, potentially exposing sensitive election configuration details.

### Details
- Form data containing election titles, descriptions, and potentially sensitive organizational information is broadcast to an uncontrolled output stream
- In containerized environments, stdout is typically captured and may be accessible to operators who should not see election configuration details
- Bypasses any logging framework configuration (formatters, handlers, filters, destinations)
- Not subject to any log access controls
- Not mentioned in any logging inventory

**Affected files:**
- `v3/server/pages.py:476`
- `v3/server/pages.py:497`

### Remediation
Remove debug print statements and use structured logging:
```python
# Remove: print('FORM:', form)
# Replace with:
_LOGGER.debug(f'Adding issue to election[E:{election.eid}]')
# Do NOT log form content
```

### Acceptance Criteria
- [ ] All print() statements removed from production code
- [ ] Proper logging calls added where needed
- [ ] Test added verifying no stdout output in production
- [ ] Logging documentation updated

### References
- ASVS 13.4.2, 16.2.3, 16.5.1, 14.2.4

### Priority
Medium - Information disclosure through uncontrolled logging channel

---

## Issue: FINDING-168 - No Server/Framework Version Header Suppression Configured

**Labels:** security, priority:low, information-disclosure, hardening

**Description:**

### Summary
Hypercorn (used in ASGI mode) and the underlying framework typically include a `Server` header (e.g., `Server: hypercorn-h11`) in HTTP responses by default. This reveals the specific server technology, enabling targeted attacks against known vulnerabilities in that version.

### Details
- No configuration is present to suppress or override this header
- HTTP request → Hypercorn/asfquart server → HTTP response with default Server header → client receives version info
- Enables reconnaissance for targeted attacks

**Affected files:**
- `v3/server/main.py:52`
- `v3/server/main.py:94`

### Remediation
For Hypercorn, configure in `hypercorn.toml` or programmatically:
```toml
server_names = [""]
```

Or add middleware to strip version headers:
```python
@app.after_request
async def remove_version_headers(response):
    response.headers.pop('Server', None)
    response.headers.pop('X-Powered-By', None)
    return response
```

### Acceptance Criteria
- [ ] Server header suppression configured
- [ ] Test added verifying header removal
- [ ] Documentation updated on security headers

### References
- ASVS 13.4.6

### Priority
Low - Defense in depth measure against reconnaissance

---

## Issue: FINDING-169 - Sensitive Files Co-located With Application Without Explicit Web Tier File Extension Filtering

**Labels:** security, priority:medium, configuration, information-disclosure

**Description:**

### Summary
The application directory contains sensitive files including `config.yaml`, `steve.db`, `certs/*.pem`, and `*.py` source code. If the proxy is misconfigured to serve files from the application directory, all these sensitive files become accessible.

### Details
- config.yaml contains database path and TLS configuration
- steve.db contains all election data
- certs/*.pem contains TLS private keys
- *.py contains source code
- The config comment states 'a proxy sits in front of this server' but no proxy configuration with file extension allowlisting is provided

**Affected files:**
- `v3/server/config.yaml.example`
- `v3/server/main.py:27-28`

### Remediation
Provide and enforce proxy configuration with explicit file extension allowlisting. Example nginx configuration:
```nginx
location / {
    # Block direct file access
    location ~* \.(yaml|yml|db|sqlite|pem|key|py|pyc|cfg|ini|env|git|log)$ {
        deny all;
    }
    
    # Only allow specific static asset extensions
    location ~* \.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2)$ {
        # Serve static assets
    }
    
    # Proxy application requests
    proxy_pass http://localhost:8000;
}
```

### Acceptance Criteria
- [ ] Proxy configuration template provided
- [ ] File extension blocklist documented
- [ ] Deployment documentation updated
- [ ] Test added verifying sensitive file blocking

### References
- ASVS 13.4.7

### Priority
Medium - Prevents information disclosure through misconfiguration

---

## Issue: FINDING-170 - Incomplete formal data classification with protection levels

**Labels:** security, priority:medium, data-protection, compliance

**Description:**

### Summary
The schema documentation describes individual fields and their cryptographic properties, but does not formally classify data into distinct protection levels. Without formal classification, developers cannot consistently apply appropriate protection controls.

### Details
Sensitive data items described but not formally classified:
- Per-voter salts (mayvote.salt)
- Election salts (election.salt)
- Opened keys (election.opened_key)
- Vote ciphertext (vote.ciphertext)
- Vote tokens (vote.vote_token)
- Voter identities (mayvote.pid linking to person.pid)
- Person emails (person.email)

Impact:
- Data requiring highest protection may be treated identically to lower-sensitivity data
- Compliance with privacy regulations (GDPR, etc.) requires documented data classification

**Affected files:**
- `v3/docs/schema.md` (entire document)

### Remediation
Create a formal data classification document that:
1. Defines protection levels (e.g., Public, Internal, Confidential, Restricted)
2. Maps each data element to a protection level
3. References applicable regulatory requirements

Example classification table:
| Data Element | Protection Level | Basis | Controls |
|--------------|------------------|-------|----------|
| vote.ciphertext | RESTRICTED | Ballot secrecy laws | Encryption at rest |
| mayvote.salt | RESTRICTED | Cryptographic material | Never logged or transmitted |
| election.opened_key | CONFIDENTIAL | Integrity verification | Never exposed via API |
| person.email | INTERNAL | GDPR/Privacy | Encryption at rest |
| election.title | PUBLIC | General information | Standard web protections |

### Acceptance Criteria
- [ ] Data classification document created
- [ ] All data elements mapped to protection levels
- [ ] Regulatory requirements documented
- [ ] Protection controls specified per level

### References
- ASVS 14.1.1

### Priority
Medium - Required for compliance and consistent protection

---

## Issue: FINDING-171 - No documented protection requirements per data sensitivity level

**Labels:** security, priority:medium, data-protection, documentation

**Description:**

### Summary
While the schema documentation describes what cryptographic mechanisms are used, it does not document the required set of protection controls for each sensitivity level, including encryption, integrity verification, retention, logging controls, access controls for sensitive data in logs, database-level encryption, and privacy-enhancing technologies.

### Details
Missing documentation areas:
- Data retention: No policy for closed elections, old votes, or person data
- Logging requirements: No specification of what can/cannot be logged
- Access controls for logs: No mention of log protection
- Database-level encryption: No requirement for filesystem/disk encryption
- Privacy-enhancing technologies: Vote shuffling mentioned in code but not in docs

### Remediation
Create a protection requirements document for each data level.

For RESTRICTED data (votes, salts, opened_keys):
- Encryption: AES-256 equivalent (currently Fernet, migrating to XChaCha20-Poly1305)
- Integrity: Argon2-based tamper detection via opened_key comparison
- Retention: Encrypted votes until election results certified + 90 days, then purged
- Logging: NEVER log plaintext votes, salts, or decryption keys; log only vote_token existence
- Log access: Restricted to ops team for server logs containing election operations
- Database encryption: SQLite database file on encrypted filesystem (LUKS/dm-crypt)
- Privacy: Per-voter salts to prevent vote correlation; votes shuffled before tallying

For CONFIDENTIAL data (voter identities, emails, voter-issue linkages):
- Encryption: Protected by TLS in transit, filesystem encryption at rest
- Retention: Person records while active in LDAP, removed 1 year after LDAP removal
- Logging: PIDs may be logged for audit but emails MUST NOT be logged
- Access: Voter-issue linkages accessible only to election owner during open state

### Acceptance Criteria
- [ ] Protection requirements documented per data level
- [ ] Retention policies defined
- [ ] Logging controls specified
- [ ] Database encryption requirements documented

### References
- ASVS 14.1.2

### Priority
Medium - Essential for consistent data protection implementation

---

## Issue: FINDING-172 - Exception objects logged in error handler may contain sensitive cryptographic context

**Labels:** security, priority:medium, logging, information-disclosure

**Description:**

### Summary
If `election.add_vote()` fails during cryptographic operations, the exception object may contain partial key material, salt values, internal state of cryptographic primitives, or database query parameters including vote_tokens. This violates the requirement that sensitive data access in logs must be controlled.

### Details
Data flow: Cryptographic operation failure → Exception message (may contain key material, salt values, or internal state) → `_LOGGER.error()` → server logs

Exception messages could include:
- Partial key material in error context
- Salt values referenced in the traceback
- Internal state of cryptographic primitives
- Database query parameters including vote_tokens

**Affected files:**
- `v3/server/pages.py` (do_vote_endpoint)

### Remediation
Log only sanitized error information:
```python
# Replace:
_LOGGER.error(f'Error adding vote for user[U:{result.uid}] on issue[I:{iid}]: {e}')

# With:
_LOGGER.error(f'Error adding vote for user[U:{result.uid}] on issue[I:{iid}]: {type(e).__name__}')
# Optionally:
_LOGGER.debug(f'Vote error details: {e}')  # DEBUG level only, never in production
```

### Acceptance Criteria
- [ ] Exception logging sanitized
- [ ] Sensitive details only in DEBUG level
- [ ] Test added for exception handling
- [ ] Logging documentation updated

### References
- ASVS 14.2.4

### Priority
Medium - Prevents cryptographic material disclosure in logs

---

## Issue: FINDING-173 - Authenticated document serving endpoint lacks cache-control headers and content-type validation

**Labels:** security, priority:medium, caching, input-validation

**Description:**

### Summary
The `serve_doc()` endpoint serves sensitive election documents to authenticated users but does not set cache-control headers or validate content types. If a caching layer sits in front of the application, authenticated responses could be cached and served to unauthorized users.

### Details
- If a caching layer (CDN, reverse proxy) sits in front of the application, authenticated responses could be cached
- Lack of Content-Type validation means responses may be cached under unexpected content types
- The `docname` parameter is not validated, potentially allowing path manipulation
- Voter confusion about partial vote state if caching occurs

**Affected files:**
- `v3/server/pages.py:605-620`

### Remediation
1. Validate `docname` parameter to only allow safe filenames using regex pattern
2. Set Cache-Control headers:
```python
response = await quart.send_from_directory(DOCSDIR / iid, docname)
response.headers['Cache-Control'] = 'no-store'
response.headers['X-Content-Type-Options'] = 'nosniff'
return response
```

### Acceptance Criteria
- [ ] Docname validation implemented
- [ ] Cache-Control headers set
- [ ] X-Content-Type-Options header set
- [ ] Test added for caching behavior

### References
- ASVS 14.2.5
- CWE-524

### Priority
Medium - Prevents unauthorized access via caching

---

## Issue: FINDING-174 - tally_issue() returns full voter PIDs instead of minimum required data

**Labels:** security, priority:low, data-minimization, privacy

**Description:**

### Summary
The `tally_issue()` function returns the complete set of voter PIDs (identities) alongside tally results. While knowing who voted (not how they voted) may be acceptable for election monitoring, returning full PIDs exceeds the minimum required data. A count of voters would suffice for most UI purposes.

### Details
- Per the domain context, voter identities (mayvote.who) are sensitive data
- Full PIDs returned when a count would suffice
- Violates data minimization principle

**Affected files:**
- `v3/steve/election.py:241-270`

### Remediation
Return voter count instead of full voter identities for general use:
```python
def tally_issue(self, iid: str):
    # ... existing tally logic ...
    return {
        'votes': votes,
        'voter_count': len(voters),  # Instead of full voter list
        # ... other tally data ...
    }
```

Create a separate privileged method for admin use:
```python
def tally_issue_with_voters(self, iid: str):
    """Admin-only method that includes full voter identities."""
    # Requires additional authorization check
    # Returns full voter list
```

### Acceptance Criteria
- [ ] Voter count returned instead of full PIDs
- [ ] Separate admin method created for full voter list
- [ ] Test added for data minimization
- [ ] Documentation updated on data access patterns

### References
- ASVS 14.2.6

### Priority
Low - Privacy enhancement through data minimization

---

## Issue: FINDING-175 - get_voters_for_email() returns all voter identities in bulk

**Labels:** security, priority:low, data-minimization, privacy

**Description:**

### Summary
The `get_voters_for_email()` function returns all voter identities (PID, name, email) for an entire election. While this may be needed for sending ballot links, it exposes sensitive voter identity data. If this data is ever exposed through a page template or API response, it would violate minimum data principles.

### Details
- Returns all voter identities in bulk
- Per domain context, voter identities are sensitive and should be minimized
- Risk of exposure through templates or API responses

**Affected files:**
- `v3/steve/election.py:433-438`

### Remediation
1. Ensure this function is only called in strictly necessary contexts (e.g., email sending)
2. Never return in page templates or API responses
3. Consider returning only the fields needed for the specific use case:
```python
def get_voter_emails_for_notification(self, iid: str = None):
    """Return only email addresses needed for notification."""
    # Returns only email field, not full identity records
```

### Acceptance Criteria
- [ ] Usage restricted to email sending contexts
- [ ] Documented as internal-only method
- [ ] Alternative method created for email-only access
- [ ] Test added verifying no template exposure

### References
- ASVS 14.2.6

### Priority
Low - Data minimization for bulk operations

---

## Issue: FINDING-176 - Authenticated user data persists in browser DOM without cleanup mechanism

**Labels:** security, priority:medium, session-management, client-side

**Description:**

### Summary
Authenticated user data (uid, name, email) is injected into every page's DOM through template rendering via the `basic_info()` function. Without a client-side mechanism to clear the DOM or browser cache on session termination, this data persists in browser history, back-forward cache, and potentially in browser developer tools.

### Details
- User data injected into DOM on every page render
- No cleanup mechanism on session termination
- Data persists in browser history and back-forward cache
- Accessible through browser developer tools

**Affected files:**
- `v3/server/pages.py:61-87`

### Remediation
Add session timeout headers and client-side cleanup using after_request middleware:
```python
@APP.after_request
async def add_security_headers(response):
    s = await asfquart.session.read()
    if s:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response
```

### Acceptance Criteria
- [ ] Cache-Control headers added
- [ ] Session cleanup mechanism implemented
- [ ] Test added for header presence
- [ ] Documentation updated on session handling

### References
- ASVS 14.3.1

### Priority
Medium - Prevents data persistence after session termination

---

## Issue: FINDING-177 - No verification mechanism for dependency source integrity

**Labels:** security, priority:medium, supply-chain, dependencies

**Description:**

### Summary
There is no evidence of hash verification for downloaded packages (e.g., `--require-hashes` in pip, or hash entries in a lock file). While dependencies should come from PyPI (a trusted source), there is no cryptographic verification that installed packages match expected artifacts.

### Details
- No hash verification for downloaded packages
- Supply chain attacks via package repository compromise or typosquatting would not be detected during installation
- No cryptographic verification of package integrity

**Affected files:**
- Project-wide

### Remediation
Use `uv lock` with hash verification or pip's `--require-hashes`:
```bash
# Generate lock file with hashes
uv lock

# Or use pip with hashes
cryptography==43.0.0 --hash=sha256:abc123...
```

### Acceptance Criteria
- [ ] Lock file with hashes generated
- [ ] CI/CD updated to use hash verification
- [ ] Documentation updated on dependency installation
- [ ] Test added for hash verification in CI

### References
- ASVS 15.1.2

### Priority
Medium - Protects against supply chain attacks

---

## Issue: FINDING-178 - No documentation highlighting risky third-party components despite known risks

**Labels:** security, priority:medium, dependencies, documentation

**Description:**

### Summary
The domain context explicitly notes that "`ezt` is not widely used, which may be a risk factor," yet no formal documentation exists that classifies this or other components according to their risk profile. Components that warrant documented risk assessment include `ezt`, `easydict`, `asfpy`, and `argon2-cffi`.

### Details
Risky components identified:
- `ezt`: Not widely used, small maintainer base, niche templating engine
- `easydict`: Simple utility, low activity repository
- `asfpy`: ASF-internal library, limited community review
- `argon2-cffi`: Well-maintained but wraps C library via cffi

Without documented risk assessment, teams cannot make informed decisions about:
- Whether additional sandboxing is needed for risky components
- Whether alternatives should be evaluated
- What additional testing is required
- Appropriate monitoring for vulnerability disclosures

**Affected files:**
- Project-wide
- `election.py`

### Remediation
Create `docs/RISKY_COMPONENTS.md` documenting each risky component:

| Component | Risk Level | Risk Factors | Mitigation | Review Frequency | Alternatives |
|-----------|------------|--------------|------------|------------------|--------------|
| ezt | Medium | Limited community adoption, small maintainer pool | Restrict to rendering pre-validated data only | Quarterly | Jinja2 (more maintained) |
| easydict | Low | Infrequent updates | None required | Annual | dataclasses |
| asfpy | Low-Medium | Internal ASF library, limited external security review | Trust boundary at organizational level | Quarterly | N/A (ASF-specific) |
| argon2-cffi | Low | Wraps C library | Use high-level API only | Annual | N/A (industry standard) |

### Acceptance Criteria
- [ ] RISKY_COMPONENTS.md created
- [ ] Each component documented with risk assessment
- [ ] Mitigation strategies defined
- [ ] Review schedule established

### References
- ASVS 15.1.4

### Priority
Medium - Enables informed risk management decisions

---

## Issue: FINDING-179 - No documentation highlighting dangerous functionality used in the application

**Labels:** security, priority:medium, cryptography, documentation

**Description:**

### Summary
The application contains several instances of "dangerous functionality" as defined by ASVS (deserialization, dynamic code execution, raw data parsing, direct memory manipulation) that are not documented with their risks and mitigations.

### Details
Dangerous functionality identified:
1. Deserialization of data (`json.loads`) in `json2kv` method
2. Low-level cryptographic operations (`argon2.low_level`)
3. Symmetric encryption/decryption with key material handling
4. Dynamic module imports
5. HKDF key derivation with hardcoded info parameter

Without documentation, developers and auditors cannot quickly identify:
- Where the most security-sensitive code resides
- What additional review/testing these areas require
- What the acceptable input constraints are for dangerous operations
- What the blast radius is if a vulnerability is found

**Affected files:**
- `v3/steve/election.py:410`
- `v3/steve/crypto.py:91-101`
- `v3/steve/crypto.py:75-88`
- `v3/server/main.py:40-41`
- `v3/steve/crypto.py:63-70`

### Remediation
Create `docs/DANGEROUS_FUNCTIONALITY.md`:

**Cryptographic Key Derivation (crypto.py)**
- Type: Direct memory manipulation (Argon2 low-level), key material handling
- Location: `v3/steve/crypto.py:_hash(), _b64_vote_key(), gen_opened_key()`
- Risk: Incorrect parameters could weaken vote encryption
- Mitigation: Parameters benchmarked, unit tested, review required for changes
- Input Trust: All inputs are system-generated (salts, tokens) — not user-controlled

**Vote Encryption/Decryption (crypto.py)**
- Type: Symmetric encryption with derived keys
- Location: `v3/steve/crypto.py:create_vote(), decrypt_votestring()`
- Risk: Key leakage exposes all votes for an election
- Mitigation: Keys derived per-voter-per-issue, never stored in plaintext

**Data Deserialization (election.py)**
- Type: JSON deserialization
- Location: `v3/steve/election.py:json2kv()`
- Risk: Low (JSON parser, data sourced from database)
- Mitigation: Data written by application's own `kv2json()`; no untrusted input

### Acceptance Criteria
- [ ] DANGEROUS_FUNCTIONALITY.md created
- [ ] All dangerous operations documented
- [ ] Risks and mitigations specified
- [ ] Input trust boundaries documented

### References
- ASVS 15.1.5

### Priority
Medium - Enables focused security review and testing

---

## Issue: FINDING-180 - Default group configuration includes all dependency groups

**Labels:** bug, security, priority:medium, dependencies, configuration

**Description:**

### Summary
The `default-groups = "all"` setting instructs `uv` to install ALL dependency groups by default, including development and linting tools. If a production deployment uses `uv install` or `uv sync` without explicitly overriding this setting, development dependencies will be installed in the production environment.

### Details
Development tools that would be present in production:
- `faker` (test data generation, could expose test utilities)
- `python-ldap` (if only needed for dev/testing LDAP scenarios)
- `coverage` (code coverage tool)
- `ruff`/`mypy` (code analysis tools)

Impact:
- Development tools in production expand the attack surface
- `faker` could be imported to generate fake data
- `coverage` can instrument code for information disclosure
- Unnecessary packages increase the supply chain attack surface

**Affected files:**
- `v3/pyproject.toml:36`

### Remediation
Change the default to only include production groups, or remove the `default-groups` directive entirely:
```toml
# Remove or change:
# default-groups = "all"

# For production deployments:
uv sync --no-group dev --no-group lint
```

### Acceptance Criteria
- [ ] default-groups configuration updated
- [ ] Production deployment script updated
- [ ] Test added verifying dev dependencies not installed
- [ ] Documentation updated on dependency installation

### References
- ASVS 15.2.3

### Priority
Medium - Reduces production attack surface

---

## Issue: FINDING-181 - ASF-internal packages without explicit repository pinning

**Labels:** security, priority:medium, supply-chain, dependencies

**Description:**

### Summary
The packages `asfpy` and `asfquart` are Apache Software Foundation internal packages. While they are published on PyPI, there is no explicit configuration pinning these packages to a specific index URL or verifying their integrity via hashes.

### Details
Key concerns:
1. No lock file visible with hashes
2. No index URL restriction
3. No integrity verification via `[tool.uv.sources]`

Impact:
- If an attacker publishes a higher-versioned malicious package with the same name on PyPI, it could be installed
- Dependency confusion attack possible if organization uses internal registry alongside PyPI
- No cryptographic verification of package integrity

**Affected files:**
- `v3/pyproject.toml:11-12`

### Remediation
1. Maintain a lock file with integrity hashes:
```bash
uv lock  # Generate uv.lock with cryptographic hashes
```

2. Consider explicit source configuration:
```toml
[tool.uv.sources]
asfpy = { index = "https://pypi.org/simple" }
asfquart = { index = "https://pypi.org/simple" }
```

3. Use `--require-hashes` in CI/CD deployment

### Acceptance Criteria
- [ ] Lock file with hashes generated
- [ ] Source configuration added if needed
- [ ] CI/CD updated to enforce hash verification
- [ ] Documentation updated on dependency management

### References
- ASVS 15.2.4

### Priority
Medium - Protects against dependency confusion attacks

---

## Issue: FINDING-182 - EasyDict Dependency Enables Attribute-style Mass Assignment Patterns

**Labels:** security, priority:medium, input-validation, dependencies

**Description:**

### Summary
The `easydict` library converts dictionary keys to object attributes, which can facilitate mass assignment when user-controlled input dictionaries are passed directly to such objects. Without explicit field whitelisting at the controller/action level, this dependency introduces an architectural pattern that could enable mass assignment.

### Details
- The domain context explicitly states: 'Mass assignment risks exist in form handling—input should be explicitly mapped to model fields'
- An attacker could potentially inject or modify fields not intended for user modification (e.g., `owner_pid`, `is_admin`, election state fields)
- Risk confirmed but mitigation cannot be verified from available code

**Affected files:**
- `v3/pyproject.toml:14`

### Remediation
Use explicit field extraction instead of passing request data directly to EasyDict objects:
```python
ALLOWED_FIELDS = {"title", "description", "start_date", "end_date"}

form_data = await request.form
election_data = {k: form_data[k] for k in ALLOWED_FIELDS if k in form_data}

# Use election_data instead of passing form directly
```

Implement explicit field whitelisting at every state-changing endpoint. Add input schema validation (e.g., using `pydantic` or manual whitelists).

### Acceptance Criteria
- [ ] Field whitelisting implemented for all form handlers
- [ ] Input schema validation added
- [ ] Test added for mass assignment prevention
- [ ] Documentation updated on safe form handling

### References
- ASVS 15.3.3

### Priority
Medium - Prevents unauthorized field modification

---

## Issue: FINDING-183 - SQLite Shared Database Access Without Explicit Synchronization in Async Context

**Labels:** security, priority:high, concurrency, database

**Description:**

### Summary
The domain context confirms: "No explicit locking mechanisms are visible for the database" and "Thread safety should be considered for shared resources." In an async Quart application, multiple coroutines can attempt database writes concurrently, potentially resulting in "database is locked" errors, race conditions, and TOCTOU vulnerabilities.

### Details
SQLite concurrency constraints:
- Only one writer at a time (default journal mode)
- Concurrent reads are allowed
- In WAL mode, one writer + multiple readers are allowed

Without explicit synchronization:
- "database is locked" errors possible
- Race conditions in read-modify-write patterns
- TOCTOU vulnerabilities (check if voter has voted → insert vote)

**Affected files:**
- `v3/pyproject.toml`

### Remediation
Implement an encapsulated database access layer with explicit locking:
```python
import asyncio

class DatabaseManager:
    def __init__(self, db_path):
        self._write_lock = asyncio.Lock()
        self._db_path = db_path
        
    async def atomic_write(self, timeout=5.0):
        """Context manager for atomic write operations."""
        async with asyncio.timeout(timeout):
            async with self._write_lock:
                conn = sqlite3.connect(self._db_path)
                conn.execute('PRAGMA busy_timeout = 5000')
                conn.execute('PRAGMA journal_mode = WAL')
                try:
                    yield conn
                    conn.commit()
                except:
                    conn.rollback()
                    raise
                finally:
                    conn.close()
```

Consider using `aiosqlite` for async-compatible SQLite access.

### Acceptance Criteria
- [ ] Database manager with locking implemented
- [ ] WAL mode enabled
- [ ] Atomic transaction wrappers added
- [ ] Test added for concurrent access scenarios

### References
- ASVS 15.4.1, 15.4.3

### Priority
High - Critical for data integrity under concurrent load

---

## Issue: FINDING-184 - Insufficient Evidence of Atomic Operations for Vote State Checks

**Labels:** security, priority:high, concurrency, race-condition

**Description:**

### Summary
The domain context explicitly states 'No explicit locking mechanisms are visible for the database'. In a voting system, critical TOCTOU-susceptible operations include checking voter eligibility before recording a vote, checking election state before accepting a vote, and checking if a voter has already voted before allowing re-vote. Without atomic operations, race conditions could allow votes to be recorded after an election closes or by unauthorized voters.

### Details
TOCTOU-susceptible operations:
- Checking voter eligibility (mayvote) before recording a vote
- Checking election state (open/closed) before accepting a vote
- Checking if a voter has already voted before allowing re-vote

Without atomic operations:
- Race condition could allow votes after election closes
- Unauthorized voters could vote during brief window
- Double-voting possible under contention

**Affected files:**
- Application-wide (source code needed for verification)

### Remediation
Ensure all state-check-then-act patterns are wrapped in SQLite transactions:
```python
async with db_manager.atomic_write() as conn:
    # BEGIN IMMEDIATE to acquire write lock immediately
    conn.execute('BEGIN IMMEDIATE')
    
    # Check eligibility
    cursor = conn.execute(
        'SELECT 1 FROM mayvote WHERE pid=? AND iid=? AND eid=?',
        (pid, iid, eid)
    )
    if not cursor.fetchone():
        raise NotEligible()
    
    # Insert vote within same transaction
    conn.execute(
        'INSERT INTO vote (eid, iid, vote_token, ciphertext) VALUES (?, ?, ?, ?)',
        (eid, iid, vote_token, ciphertext)
    )
    # COMMIT handled by context manager
```

Configure SQLite:
```python
conn.execute('PRAGMA busy_timeout = 5000')
conn.execute('PRAGMA journal_mode = WAL')
```

### Acceptance Criteria
- [ ] All state-check-then-act patterns use transactions
- [ ] BEGIN IMMEDIATE used for write operations
- [ ] SQLite busy_timeout configured
- [ ] WAL mode enabled
- [ ] Test added for concurrent vote submissions

### References
- ASVS 15.4.2

### Priority
High - Prevents race conditions in vote recording

---

## Issue: FINDING-185 - Mixed logging mechanisms (print vs logger) create undocumented output channels

**Labels:** bug, security, priority:medium, logging

**Description:**

### Summary
Multiple code paths use `print()` statements alongside the formal `_LOGGER` system. These bypass any logging framework configuration and output to stdout directly, creating undocumented log channels that cannot be inventoried.

### Details
- Security-relevant information (form submissions, tamper detection alerts) exits through channels not covered by any logging policy
- Bypasses logging framework configuration (formatters, handlers, filters, destinations)
- Potentially lost or logged without proper access controls

**Affected files:**
- `v3/server/pages.py:427`
- `v3/server/pages.py:449`
- `v3/server/bin/tally.py:127`
- `v3/server/bin/tally.py:152`
- `v3/server/bin/tally.py:157`

### Remediation
Replace all print statements with proper logging calls:
```python
# For form data:
_LOGGER.debug(f'Form data received for issue creation in election[E:{election.eid}]')

# For security events:
_LOGGER.critical(f'TAMPER DETECTED: Election[E:{election_id}] integrity check failed')
```

### Acceptance Criteria
- [ ] All print() statements replaced with logging
- [ ] Appropriate log levels used
- [ ] Test added verifying logging behavior
- [ ] Logging documentation updated

### References
- ASVS 16.1.1

### Priority
Medium - Ensures consistent logging infrastructure

---

## Issue: FINDING-186 - Authorization failure events lack structured metadata

**Labels:** security, priority:medium, logging, authorization

**Description:**

### Summary
When a user attempts to access an election they are not authorized to vote in, the application returns a 404 but does not log this authorization failure. This is a security event that should include WHO tried, WHAT they tried to access, WHEN, and the outcome.

### Details
- Authorization failures are invisible to security monitoring
- Repeated attempts to access unauthorized elections cannot be detected or alerted upon
- No audit trail of access control violations

**Affected files:**
- `v3/server/pages.py:199-201`

### Remediation
```python
election.q_find_issues.perform(result.uid, election.eid)
if not election.q_find_issues.fetchall():
    _LOGGER.warning(
        f'AUTHZ_DENIED user=U:{result.uid} resource=election[E:{election.eid}] '
        f'action=vote_access reason=not_in_mayvote'
    )
    result = await basic_info()
    result.title = 'Access Denied'
    result.eid = election.eid
    raise_404(T_BAD_EID, result)
```

### Acceptance Criteria
- [ ] Authorization failures logged
- [ ] Structured metadata included (user, resource, action, reason)
- [ ] Test added for authorization logging
- [ ] Security monitoring updated

### References
- ASVS 16.2.1

### Priority
Medium - Enables detection of unauthorized access attempts

---

## Issue: FINDING-187 - Election state change operations in election.py lack logging

**Labels:** security, priority:medium, logging, audit

**Description:**

### Summary
Critical election lifecycle operations (`close()`, `add_salts()`, `delete()`) do not emit log entries at the library level. While `pages.py` logs the close event when invoked via the web interface, direct library usage (e.g., from `tally.py` or future integration paths) leaves no trace.

### Details
- State changes occur without audit trails when library used outside web context
- No logging for critical operations: close(), add_salts(), delete()
- Inconsistent logging between web and library usage

**Affected files:**
- `v3/steve/election.py:110-115`
- `v3/steve/election.py:117-137`

### Remediation
```python
def close(self):
    """Close an election."""
    assert self.is_open()
    self.c_close.perform(self.eid)
    _LOGGER.info(f'Election[E:{self.eid}] state changed to CLOSED')
```

Add similar logging to `add_salts()` and `delete()`.

### Acceptance Criteria
- [ ] Logging added to all state change operations
- [ ] Consistent logging across all usage contexts
- [ ] Test added for library-level logging
- [ ] Documentation updated

### References
- ASVS 16.2.1

### Priority
Medium - Ensures complete audit trail

---

## Issue: FINDING-188 - No logging format configuration enforces UTC timestamps

**Labels:** bug, security, priority:medium, logging, time-management

**Description:**

### Summary
The application does not configure a logging format that ensures timestamps are present in every log entry, use UTC, and include explicit timezone offset. The default format in `tally.py` does NOT include a timestamp at all.

### Details
- `logging.basicConfig(level=logging.INFO)` uses default format without timestamps
- Default format: `%(levelname)s:%(name)s:%(message)s`
- Web server logging uses framework defaults (typically local time without timezone)
- `datetime.datetime.now()` and `datetime.datetime.fromtimestamp()` used without timezone awareness

**Affected files:**
- `v3/server/bin/tally.py:165`
- `v3/server/pages.py`

### Remediation
Configure UTC timestamps globally:
```python
import logging
import time

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S.%fZ',
)
logging.Formatter.converter = time.gmtime  # Force UTC
```

Or use JSON formatter for structured logging:
```python
import json_log_formatter

formatter = json_log_formatter.JSONFormatter()
handler = logging.StreamHandler()
handler.setFormatter(formatter)
# Timestamps will be ISO 8601 with timezone
```

### Acceptance Criteria
- [ ] UTC timestamp format configured
- [ ] All log entries include timestamps
- [ ] Timezone explicitly included
- [ ] Test added for timestamp format

### References
- ASVS 16.2.2

### Priority
Medium - Essential for log correlation and forensics

---

## Issue: FINDING-189 - No structured logging format enables machine parsing and correlation

**Labels:** security, priority:medium, logging, monitoring

**Description:**

### Summary
The application uses unstructured f-string log messages that vary in format between modules. While the `[U:xxx]`, `[E:xxx]`, `[I:xxx]` convention is helpful, the overall format is not machine-parseable without custom regex patterns.

### Details
Issues:
1. No common structured format (JSON, CEF, CLF) is used
2. Inconsistent field ordering
3. No correlation ID (request ID or trace ID)
4. Mixed separators (semicolons, commas, natural language)
5. No event type field

Impact:
- Log processors require custom parsing rules for each message variant
- Automated alerting on patterns becomes difficult
- Cannot filter by event category without text matching

**Affected files:**
- `v3/server/pages.py` (all logging calls)
- `v3/steve/election.py` (all logging calls)

### Remediation
Implement structured logging using `structlog` or `python-json-logger`:
```python
import structlog

logger = structlog.get_logger()

logger.info(
    "election.vote_cast",
    actor_uid=result.uid,
    election_id=election.eid,
    issue_id=iid,
    event_type="security",
    action="vote_cast"
)

# Output:
# {"event": "election.vote_cast", "actor_uid": "jdoe", "election_id": "a1b2c3d4e5", ...}
```

### Acceptance Criteria
- [ ] Structured logging library integrated
- [ ] All log calls converted to structured format
- [ ] Correlation ID added to requests
- [ ] Test added for log parsing

### References
- ASVS 16.2.4

### Priority
Medium - Enables automated log analysis and alerting

---

## Issue: FINDING-190 - Tally output includes full voter identity list without classification controls

**Labels:** security, priority:medium, logging, privacy

**Description:**

### Summary
The JSON output format includes a complete sorted list of voter PIDs. This reveals which specific individuals voted on each issue, which could be considered sensitive in some election contexts.

### Details
- Voter list output without any masking or classification-based control
- While knowing WHO voted doesn't reveal HOW they voted (votes are shuffled), participation patterns could be sensitive
- Sorted output enables easy diff-ing between multiple tallies to identify new voters

**Affected files:**
- `v3/server/bin/tally.py:129-132`

### Remediation
Option 1: Hash voter identities in output
```python
import hashlib

voters_hashed = [hashlib.sha256(v.encode()).hexdigest()[:12] for v in all_voters]
```

Option 2: Only include voter count, not identities
```python
# Default output
'voter_count': len(all_voters)

# Verbose flag for full list
if args.verbose:
    'voters': sorted(all_voters)
```

### Acceptance Criteria
- [ ] Voter identities hashed or count-only in default output
- [ ] Verbose flag added for full voter list
- [ ] Test added for output format
- [ ] Documentation updated on tally output

### References
- ASVS 16.2.5

### Priority
Medium - Protects voter participation privacy

---

## Issue: FINDING-191 - Exception details potentially leak sensitive information into error logs

**Labels:** security, priority:medium, logging, information-disclosure

**Description:**

### Summary
The catch-all `Exception` handler logs the full exception message. Depending on the failure mode, this could include cryptographic operation details, database state information, internal path information, or partial sensitive data that caused the error.

### Details
Exception messages could include:
- Cryptographic operation details (key derivation failures, Fernet errors)
- Database state information (SQLite error messages with table/column names)
- Internal path information
- Partial sensitive data that caused the error

Impact:
- Exception messages could leak internal implementation details
- Information disclosure risk if logs accessible to broader audience

**Affected files:**
- `v3/server/pages.py:356`

### Remediation
Sanitize exception logging:
```python
_LOGGER.error(
    f'Vote submission failed for user[U:{result.uid}] on issue[I:{iid}] '
    f'in election[E:{election.eid}]: {type(e).__name__}',
    exc_info=True  # Full traceback only in DEBUG
)
```

### Acceptance Criteria
- [ ] Exception logging sanitized
- [ ] Only exception type in ERROR level
- [ ] Full details in DEBUG level only
- [ ] Test added for exception handling

### References
- ASVS 16.2.5

### Priority
Medium - Prevents information disclosure through error messages

---

## Issue: FINDING-192 - No Authentication Metadata Captured in Existing Logs

**Labels:** security, priority:medium, logging, authentication

**Description:**

### Summary
The existing log messages record user actions but do not include authentication metadata (authentication type, factors used, session age, IP address). There's insufficient metadata to correlate events with authentication context.

### Details
Missing metadata:
- Authentication type (OAuth provider)
- MFA status
- Source IP address
- Session age
- Session ID

**Affected files:**
- `v3/server/pages.py:106-108`
- `v3/server/pages.py:404-407`
- `v3/server/pages.py:440-443`

### Remediation
Include authentication metadata in log messages:
```python
_LOGGER.info(
    'ELECTION_DATE_SET: uid=%s, election=%s, field=%s, value=%s, '
    'auth_method=oauth, ip=%s, session_id=%s',
    sanitize_log(result.uid),
    sanitize_log(election.eid),
    field,
    date_str,
    quart.request.remote_addr,
    session_id_hash,
)
```

### Acceptance Criteria
- [ ] Authentication metadata added to logs
- [ ] IP address captured
- [ ] Session ID (hashed) included
- [ ] Test added for metadata presence

### References
- ASVS 16.3.1

### Priority
Medium - Enables security event correlation

---

## Issue: FINDING-193 - Election State Assertion Failures Not Logged

**Labels:** security, priority:high, logging, business-logic

**Description:**

### Summary
State validation uses Python `assert` statements which raise `AssertionError` without logging. Attempts to bypass election state controls produce no audit trail. These are business logic bypass attempts that should be logged. Assertions are also disabled when Python runs with optimization (-O flag).

### Details
Affected functions:
- delete, open, close, add_issue, edit_issue, delete_issue, add_voter, add_vote

Impact:
- No audit trail of bypass attempts
- Security control failures produce unstructured stack traces
- Checks completely disabled with -O flag

**Affected files:**
- `v3/steve/election.py` (multiple locations)

### Remediation
Replace assert statements with explicit conditional checks:
```python
def add_vote(self, pid: str, iid: str, votestring: str):
    if not self.is_open():
        _LOGGER.warning(
            'BUSINESS_LOGIC_BYPASS: attempt to vote on non-open election, '
            'election=%s, state=%s, pid=%s, iid=%s',
            self.eid, self.get_state(), pid, iid,
        )
        raise ElectionBadState(self.eid, self.get_state(), self.S_OPEN)
```

### Acceptance Criteria
- [ ] All assert statements replaced with conditional checks
- [ ] Business logic violations logged
- [ ] Custom exceptions raised
- [ ] Test added for state violation logging

### References
- ASVS 16.3.3

### Priority
High - Critical for detecting bypass attempts

---

## Issue: FINDING-194 - Assertion Errors Not Caught or Logged at Application Level

**Labels:** security, priority:high, logging, error-handling

**Description:**

### Summary
Multiple critical operations use `assert` for state validation. If assertions fail, no structured logging occurs. Security control failures produce unstructured stack traces rather than structured security event logs. When running with -O, these checks are completely disabled.

### Details
Affected locations with assert statements:
- `v3/steve/election.py:48` (election state validation)
- `v3/steve/election.py:69` (voter eligibility)
- `v3/steve/election.py:115` (election open state)
- `v3/steve/election.py:178` (issue state)
- `v3/steve/election.py:197` (edit permissions)
- `v3/steve/election.py:211` (delete permissions)
- `v3/steve/election.py:238` (tally permissions)

Impact:
- Security control failures not logged
- Checks disabled with Python -O flag
- No structured error handling

**Affected files:**
- `v3/steve/election.py` (multiple lines)

### Remediation
Replace assert statements with proper conditional checks that log security events before raising exceptions. See FINDING-193 for example implementation.

### Acceptance Criteria
- [ ] All assertions replaced with conditional checks
- [ ] Security control failures logged
- [ ] Structured exceptions raised
- [ ] Test added for control failure logging

### References
- ASVS 16.3.4

### Priority
High - Critical security control failures must be logged

---

## Issue: FINDING-195 - Database Connectivity Failures Not Explicitly Logged

**Labels:** security, priority:medium, logging, infrastructure

**Description:**

### Summary
Database connection failures would produce SQLite exceptions without application-level logging. Backend infrastructure failures (database unavailability, file system issues) would not be captured as structured security events.

### Details
- No explicit error handling for database connection failures
- Infrastructure failures not logged as security events
- Difficult to diagnose availability issues

**Affected files:**
- `v3/steve/election.py:28`

### Remediation
Wrap database connection logic with try-except block:
```python
try:
    db = asfpy.db.DB(DB_FNAME)
except (sqlite3.OperationalError, OSError) as e:
    _LOGGER.error(
        'Database connection failed: path=%s, error=%s',
        DB_FNAME,
        type(e).__name__,
        exc_info=True
    )
    raise
```

### Acceptance Criteria
- [ ] Database connection failures logged
- [ ] Structured error information captured
- [ ] Test added for connection failure logging
- [ ] Monitoring alerts configured

### References
- ASVS 16.3.4

### Priority
Medium - Enables infrastructure failure detection

---

## Issue: FINDING-196 - No Log Protection Configuration

**Labels:** security, priority:medium, logging, audit

**Description:**

### Summary
The logging configuration uses `basicConfig` with no file protection, access control, or integrity measures. Logs are written to stdout/stderr with no write-once/append-only guarantees, file permissions configuration, log rotation with integrity verification, transmission to a protected centralized system, or digital signatures.

### Details
Missing protections:
- No write-once/append-only guarantees
- No file permissions configuration
- No log rotation with integrity verification
- No transmission to protected centralized system
- No digital signatures or checksums on log entries

**Affected files:**
- `v3/server/bin/tally.py:163`

### Remediation
Implement separate output handling for sensitive audit data. Ensure voter lists and other sensitive information are written to protected storage with appropriate access controls rather than stdout. Consider implementing:
1. Data classification and handling policies for different types of output
2. Centralized log shipping with integrity verification
3. Log forwarding to a protected centralized system
4. Separate log storage from application server
5. Explicit log protection configuration in application code

### Acceptance Criteria
- [ ] Protected log storage configured
- [ ] Access controls implemented
- [ ] Centralized logging configured
- [ ] Test added for log protection

### References
- ASVS 16.4.2

### Priority
Medium - Protects audit trail integrity

---

## Issue: FINDING-197 - No Centralized Logging Configuration in Web Application

**Labels:** security, priority:medium, logging, infrastructure

**Description:**

### Summary
The web application uses Python's logging module but there is no evidence of log forwarding to a centralized system, log file protection configuration, separate log storage from application server, or log integrity verification.

### Details
Missing configurations:
- No log forwarding to centralized system
- No log file protection configuration
- No separate log storage from application server
- No log integrity verification

While infrastructure may provide these protections, application code shows no explicit configuration.

**Affected files:**
- `v3/server/pages.py`

### Remediation
Configure centralized log shipping with integrity verification:
1. Implement log forwarding to a protected centralized system
2. Configure separate log storage from the application server with appropriate access controls
3. Add explicit log protection configuration in application code rather than relying solely on infrastructure

Example:
```python
import logging.handlers

# Syslog handler for centralized logging
syslog_handler = logging.handlers.SysLogHandler(address=('logserver', 514))
syslog_handler.setFormatter(json_formatter)
logger.addHandler(syslog_handler)
```

### Acceptance Criteria
- [ ] Centralized logging configured
- [ ] Log forwarding implemented
- [ ] Separate log storage configured
- [ ] Test added for log shipping

### References
- ASVS 16.4.2

### Priority
Medium - Ensures log availability and protection

---

## Issue: FINDING-198 - HTTP 400 responses expose specific validation failure reasons

**Labels:** security, priority:low, information-disclosure, error-handling

**Description:**

### Summary
The `quart.abort()` calls include descriptive messages ('Missing date', 'Invalid date format', 'Invalid field') that are passed to the default Quart error handler, which may render them in the HTTP response body. While these specific messages are not highly sensitive, the pattern establishes a practice that could lead to information disclosure if applied to more sensitive contexts.

### Details
- Descriptive error messages in HTTP responses
- Pattern could lead to information disclosure
- Violates principle of minimal error information

**Affected files:**
- `v3/server/pages.py:103-110`

### Remediation
Return generic validation error:
```python
# Instead of:
quart.abort(400, 'Missing date')

# Use:
quart.abort(400)  # Let global error handler provide generic message
```

### Acceptance Criteria
- [ ] Generic error messages used
- [ ] Detailed errors only in logs
- [ ] Test added for error response format
- [ ] Global error handler configured

### References
- ASVS 16.5.1

### Priority
Low - Reduces information disclosure through error messages

---

## Issue: FINDING-199 - PersonDB failures not handled in admin endpoints

**Labels:** bug, security, priority:medium, error-handling, availability

**Description:**

### Summary
While `PersonNotFound` is handled gracefully, the `PersonDB.open()` call itself has no error handling for database connectivity failures. If the database is unavailable, the error propagates unhandled, making the admin page completely unavailable with no graceful degradation or retry.

### Details
- No error handling for database connectivity failures
- Admin page becomes completely unavailable if database has issues
- No graceful degradation or retry mechanism

**Affected files:**
- `v3/server/pages.py:286-287`

### Remediation
Add exception handling for `PersonDB.open()` failures:
```python
try:
    pdb = steve.persondb.PersonDB.open(DB_FNAME)
    me = pdb.get_person(result.uid)
except steve.persondb.PersonNotFound:
    raise_404(T_BAD_PID, result)
except (sqlite3.OperationalError, OSError) as e:
    _LOGGER.error(f'PersonDB unavailable: {e}')
    await flash_danger('Service temporarily unavailable. Please try again.')
    return quart.redirect('/', code=303)
```

### Acceptance Criteria
- [ ] Database failure handling added
- [ ] Graceful degradation implemented
- [ ] User-friendly error message shown
- [ ] Test added for database failure scenario

### References
- ASVS 16.5.2

### Priority
Medium - Improves availability and user experience

---

## Issue: FINDING-200 - Partial vote submission without transaction wrapping

**Labels:** bug, security, priority:medium, transactions, data-integrity

**Description:**

### Summary
When a voter submits votes for multiple issues simultaneously, each vote is processed individually. If an error occurs on the Nth vote, the first N-1 votes have already been committed to the database. There is no transaction wrapping the entire batch.

### Details
- No transaction wrapping for batch vote submission
- Partial votes committed on error
- User receives error message that doesn't clarify which votes succeeded
- Voter confusion about partial vote state
- Potential for inconsistent ballot if voter doesn't retry

While re-voting is supported (mitigating data loss), the user experience is poor.

**Affected files:**
- `v3/server/pages.py:400-422`

### Remediation
Wrap batch vote submission in transaction:
```python
election.db.conn.execute('BEGIN TRANSACTION')
try:
    for iid, votestring in votes.items():
        election.add_vote(result.uid, iid, votestring)
    election.db.conn.execute('COMMIT')
except Exception as e:
    election.db.conn.execute('ROLLBACK')
    _LOGGER.error(f'Vote batch failed: {e}')
    await flash_danger('Error submitting votes. Please try again.')
    return quart.redirect(f'/vote-on/{election.eid}', code=303)
```

### Acceptance Criteria
- [ ] Transaction wrapping implemented for batch votes
- [ ] All-or-nothing vote submission
- [ ] Clear error message on failure
- [ ] Test added for partial failure scenario

### References
- ASVS 16.5.3

### Priority
Medium - Ensures data integrity and better user experience

## Issue: FINDING-201 - CLI tally script has no top-level exception handler
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The main() function and entry point in the CLI tally script lack a top-level try/except block, causing unexpected exceptions to print full stack traces to stderr and exit ungracefully.

### Details
While the function handles is_tampered() and calls sys.exit(1), unexpected exceptions (database corruption, permission denied, memory errors) will print full stack traces to stderr and exit ungracefully. Within tally_election, the raise after catching an exception intentionally fails hard but doesn't ensure the error is logged through the logging system (only print()). Full stack traces with file paths and variable values are printed to stderr; error details may be lost if not captured by a process manager; no structured error logging for operational monitoring exists.

**Affected Files:**
- v3/server/bin/tally.py (lines 166-180)

**CWE:** None specified
**ASVS:** 16.5.4 (L3)

### Remediation
Add top-level exception handler to CLI entry point:

```python
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    try:
        # ... argument parsing and main() call ...
        main(args.spy_on_open_elections, args.election_id, args.issue_id, args.db_path, args.output)
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:
        _LOGGER.critical(f'Fatal error: {e}', exc_info=True)
        sys.exit(2)
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 16.5.4.md
- Global ID: FINDING-201

### Priority
Medium

---

## Issue: FINDING-202 - No evidence of header trust boundary enforcement for intermediary headers
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application exposes APP from asfquart without visible configuration to strip or reject user-supplied intermediary headers (e.g., X-Forwarded-For, X-Real-IP, X-User-ID).

### Details
While the asfquart framework may handle this internally, there is no visible control in the auditable codebase to confirm that end-users cannot inject headers that would be trusted as if set by intermediaries. Data flow: External HTTP request → X-Forwarded-For header → APP request handling → potential trust of user-supplied value as intermediary-set value. If asfquart or downstream handlers trust these headers without validation, an attacker could spoof their IP address or identity for access control bypass or audit log pollution.

**Affected Files:**
- v3/server/api.py (lines 1-21)

**CWE:** None specified
**ASVS:** 4.1.3 (L2)

### Remediation
Configure the application or its framework to explicitly define trusted proxy sources and strip/ignore intermediary headers from untrusted origins. Example: Configure trusted proxies using APP.config['FORWARDED_ALLOW_IPS'] = '127.0.0.1,10.0.0.0/8' or use middleware to strip untrusted headers. Verify that asfquart or the reverse proxy configuration strips/overwrites X-Forwarded-* and similar headers from untrusted sources.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 4.1.3.md
- Global ID: FINDING-202

### Priority
Medium

---

## Issue: FINDING-203 - No visible HTTP message boundary validation or Transfer-Encoding/Content-Length conflict handling
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application provides no configuration related to HTTP/1.1 request smuggling prevention.

### Details
There is no visible: rejection of requests with both Transfer-Encoding and Content-Length headers, HTTP/2 DATA frame length validation against Content-Length, or configuration ensuring the application server and reverse proxy agree on message boundaries. If the reverse proxy and Quart/Hypercorn disagree on how to parse the request boundary (e.g., one uses Content-Length while the other uses Transfer-Encoding), an attacker could smuggle a second request that bypasses authentication or access controls.

**Affected Files:**
- v3/server/api.py (lines 1-21)

**CWE:** None specified
**ASVS:** 4.2.1 (L2)

### Remediation
1. Configure the reverse proxy to normalize requests (reject ambiguous requests with both TE and CL)
2. Configure the ASGI server (Hypercorn) to reject malformed requests
3. Add application-level validation using a before_request handler to reject requests with both Transfer-Encoding and Content-Length headers by returning a 400 error

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 4.2.1.md
- Global ID: FINDING-203

### Priority
Medium

---

## Issue: FINDING-204 - Missing File Handling Documentation
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The application serves documents but lacks documentation defining permitted file types, extensions, maximum file size, and malicious file handling procedures.

### Details
The application serves documents from DOCSDIR/&lt;iid&gt;/ via the /docs/&lt;iid&gt;/&lt;docname&gt; endpoint, and issue descriptions can reference documents via doc:filename syntax. However, there is no documentation defining: permitted file types, expected file extensions, maximum file size (or maximum unpacked size), or how the application handles malicious files detected during download/processing. Without documented policies on accepted file types, extensions, and sizes, developers cannot implement consistent file validation. End users downloading served documents have no assurance that files have been vetted for malware or unsafe content.

**Affected Files:**
- v3/server/pages.py (lines 560-574)
- v3/docs/schema.md

**CWE:** None specified
**ASVS:** 5.1.1 (L2)

### Remediation
Create explicit documentation specifying:
- Permitted File Types for Issue Documents (PDF, plain text, PNG images with MIME types)
- Maximum File Size (Individual file: 10 MB, Per-issue total: 50 MB)
- Malicious File Handling (Files are scanned with ClamAV on upload, Files failing validation are rejected with HTTP 415 and logged, Served files include Content-Disposition: attachment header, X-Content-Type-Options: nosniff is set on all responses)

Implement file extension allowlist in serve_doc, add security headers, add symlink check before serving files, implement documented file upload handler with MAX_CONTENT_LENGTH, extension validation, magic bytes verification, and maximum file size enforcement.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 5.1.1.md
- Global ID: FINDING-204

### Priority
Medium

---

## Issue: FINDING-205 - Missing compressed file validation against size and count limits
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application has a document serving mechanism but no visible handling or validation of compressed files (zip, gz, docx, odt, etc.).

### Details
There is no code that: (1) Detects if a served or uploaded file is a compressed archive, (2) Checks the maximum uncompressed size before extraction, (3) Limits the maximum number of files within an archive, (4) Prevents zip bomb attacks. Since the upload mechanism is not shown in the provided code, it is impossible to verify that compressed file protections exist upstream. If compressed files (e.g., zip bombs) are placed in DOCSDIR through any mechanism, they could be served to users or potentially processed server-side without decompression limits, leading to denial of service.

**Affected Files:**
- v3/server/pages.py (entire application scope)

**CWE:** None specified
**ASVS:** 5.2.3 (L2)

### Remediation
Implement compressed file validation using a function that checks:
1. Whether the file is a compressed archive (using zipfile.is_zipfile or similar)
2. Total uncompressed size against MAX_UNCOMPRESSED_SIZE (e.g., 100 MB)
3. Number of files in archive against MAX_FILES_IN_ARCHIVE (e.g., 100)
4. Compression ratio to detect zip bombs (reject if ratio > 100)

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 5.2.3.md
- Global ID: FINDING-205

### Priority
Medium

---

## Issue: FINDING-206 - No per-user file quota or maximum file count enforcement
**Labels:** bug, security, priority:medium
**Description:**
### Summary
There is no per-user file quota or maximum file count enforcement anywhere in the provided code or database schema.

### Details
The database schema contains tables for elections, issues, persons, mayvotes, and votes — but nothing tracking file storage per user. Documents are served from DOCSDIR/&lt;iid&gt;/ but there is no: (1) Database table or column tracking per-user storage consumption, (2) Check limiting the total number of files a user can upload, (3) Check limiting total storage bytes per user, (4) Any quota enforcement mechanism. A single user (or compromised account) could fill available storage by uploading an unlimited number of files or excessively large files, causing denial of service for all users.

**Affected Files:**
- v3/server/pages.py
- v3/schema.sql

**CWE:** None specified
**ASVS:** 5.2.4 (L3)

### Remediation
Add file tracking table to database schema and implement quota checking function with MAX_FILES_PER_USER = 50 and MAX_STORAGE_PER_USER = 500 MB. Create queries to check user file count and total storage before allowing new file uploads.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 5.2.4.md
- Global ID: FINDING-206

### Priority
Medium

---

## Issue: FINDING-207 - No Symlink Detection or Prevention in Compressed Files
**Labels:** bug, security, priority:medium
**Description:**
### Summary
There is no handling of compressed files visible in the provided code, and consequently no symlink detection or prevention.

### Details
If documents placed in DOCSDIR originated from extracted archives, symbolic links within those archives could allow access to sensitive files outside the intended directory. While send_from_directory provides some protection against traversal, symlinks resolved at the filesystem level could bypass this. If an attacker can place a compressed file containing symlinks (e.g., pointing to /etc/passwd or the database file) and it gets extracted into DOCSDIR, the serve_doc endpoint could serve sensitive system files to authorized users.

**Affected Files:**
- v3/server/pages.py (entire application scope)

**CWE:** None specified
**ASVS:** 5.2.5 (L3)

### Remediation
Implement symlink validation for compressed files using validate_no_symlinks and safe_extract functions. Add symlink checking before serving files with filepath.is_symlink() check in serve_doc. Mount DOCSDIR filesystem with nosymfollow or equivalent to prevent symlink resolution at the OS level.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 5.2.5.md
- Global ID: FINDING-207

### Priority
Medium

---

## Issue: FINDING-208 - Missing RFC 6266 Content-Disposition encoding in file serving endpoint
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The serve_doc() endpoint serves files without explicitly setting a properly-encoded Content-Disposition header per RFC 6266.

### Details
The user-controlled docname parameter is not sanitized before being reflected in the response. If the filename on disk contains non-ASCII characters or special characters, the response header may not be properly encoded. Data flow: User-controlled docname → no sanitization → send_from_directory() → response headers potentially reflecting unsanitized filename. If filenames in the docs directory contain special characters (quotes, newlines, non-ASCII), the response headers may be malformed, potentially enabling: (1) Header injection via CRLF sequences in filename, (2) Content-Disposition header parsing issues in browsers, (3) Filename display issues or spoofing in download dialogs.

**Affected Files:**
- v3/server/pages.py (lines 560-574)

**CWE:** None specified
**ASVS:** 5.4.2 (L2)

### Remediation
Sanitize the filename using secure_filename() and explicitly set Content-Disposition with properly encoded filenames. Use as_attachment=True and attachment_filename parameters in send_from_directory(). Add an explicit allowlist regex for docname validation. Set X-Content-Type-Options: nosniff header.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 5.4.2.md
- Global ID: FINDING-208

### Priority
Medium

---

## Issue: FINDING-209 - No Antivirus Scanning for Documents Served to Users
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Files placed in the docs directory are served directly to authenticated users without malware scanning.

### Details
While the code does not show an explicit upload mechanism, the infrastructure for serving per-issue documents exists, and the application converts doc:filename patterns in issue descriptions into download links. Files placed in the docs directory (whether by admin CLI scripts, manual upload, or an upload mechanism not shown) are served directly to authenticated users without malware scanning. A malicious document (e.g., a PDF with embedded exploit, a malware-laden Office document, or an HTML file with scripts) placed in the docs directory would be served to all voters authorized for that issue. Given the election context, a compromised admin or supply-chain attack on candidate documents could distribute malware to all eligible voters.

**Affected Files:**
- v3/server/pages.py (lines 598-614)
- v3/server/pages.py (lines 50-57)

**CWE:** None specified
**ASVS:** 5.4.3 (L2)

### Remediation
Implement antivirus scanning using ClamAV/clamdscan either at serving time or at ingestion time. Option 1: Scan at serving time by adding a scan_file() async function that runs clamdscan before send_from_directory, with fail-closed behavior if scanner is unavailable. Validate filename extensions against an allowed whitelist (e.g., .pdf, .txt, .md, .html). Option 2: Scan at ingestion time by implementing a place_document() function that scans files before copying them to the DOCSDIR. Both options should include proper logging and error handling with fail-closed security posture.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 5.4.3.md
- Global ID: FINDING-209

### Priority
Medium

---

## Issue: FINDING-210 - No Visible Token Signature Validation in Application Code
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Token/session validation is entirely delegated to the asfquart framework with no application-level verification.

### Details
The application code contains zero explicit signature validation, and no configuration parameters for signature verification keys are provided. If asfquart fails to validate, the application has no defense-in-depth. The application's trust model assumes asfquart.session.read() returns fully validated, trustworthy data. Every endpoint reads session data and uses uid directly for authorization decisions (database queries, ownership checks, logging) without any additional verification layer.

**Affected Files:**
- v3/server/pages.py (lines 75-106)
- v3/server/main.py (lines 27-42)

**CWE:** None specified
**ASVS:** 9.1.1 (L1)

### Remediation
Option 1: Add explicit verification that the framework is configured for signature validation (assert signing_key and verify_signatures are configured).

Option 2: If JWTs are used, add application-level verification using jwt.decode with signature verification.

Additional recommendations:
1. Audit asfquart framework for compliance with ASVS 9.x requirements
2. Configure audience validation with explicit audience ('steve')
3. Reconsider OIDC avoidance
4. Document algorithm allowlist
5. Add issuer validation
6. Implement defense-in-depth for sessions
7. Implement or verify JWKS endpoint caching and rotation handling
8. Implement explicit token type checking

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 9.1.1.md
- Global ID: FINDING-210

### Priority
Medium

---

## Issue: FINDING-211 - No Algorithm Restriction Configuration Visible
**Labels:** bug, security, priority:medium
**Description:**
### Summary
No algorithm allowlist is configured anywhere in the provided application code.

### Details
If the asfquart framework or any JWT library processes self-contained tokens, there is no explicit restriction to approved algorithms (e.g., RS256, ES256) and no explicit prohibition of the 'None' algorithm. The audit context specifies that only approved algorithms (RS256, ES256) are allowed (not HS256 with shared secrets), but no such restriction is implemented or configured in the visible code. If the underlying framework uses a JWT library that accepts the alg: none header or allows algorithm confusion attacks (e.g., treating an RSA public key as an HMAC secret with HS256), an attacker could forge valid-looking tokens.

**Affected Files:**
- v3/server/main.py (lines 27-42)

**CWE:** None specified
**ASVS:** 9.1.2 (L1)

### Remediation
In create_app() or configuration, explicitly set allowed algorithms. Configure algorithm allowlist for token validation: app.config['TOKEN_ALGORITHMS'] = ['RS256', 'ES256'] (No 'none', no HS256) and app.config['TOKEN_REJECT_NONE_ALG'] = True. If using PyJWT directly, use: ALLOWED_ALGORITHMS = ['RS256', 'ES256'] and jwt.decode(token, key, algorithms=ALLOWED_ALGORITHMS) (Never pass algorithms=None).

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 9.1.2.md
- Global ID: FINDING-211

### Priority
Medium

---

## Issue: FINDING-212 - No Key Material Source Validation Configured
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application does not configure trusted key sources, JKU/x5u/JWK header allowlists, or pinned public keys for the OAuth issuer.

### Details
If self-contained tokens (JWTs) are used with headers like jku (JSON Web Key URL), an attacker could potentially craft a token pointing to their own key server, causing the application to validate the forged token against attacker-controlled keys. OAuth provider issues tokens → Token may contain jku/x5u/jwk headers → Application/framework processes token → No visible restriction on key source headers.

**Affected Files:**
- v3/server/main.py (lines 27-42)

**CWE:** None specified
**ASVS:** 9.1.3 (L1)

### Remediation
Configure trusted key sources: TRUSTED_JWKS_URLS = ['https://oauth.apache.org/.well-known/jwks.json'] and TRUSTED_ISSUERS = ['https://oauth.apache.org']. In token validation, reject tokens with jku/x5u/jwk headers unless they match the allowlist. Implement validation function to check token headers and raise errors for untrusted jku URLs, x5u headers, and embedded jwk headers. Use pre-configured keys instead of allowing embedded keys.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 9.1.3.md
- Global ID: FINDING-212

### Priority
Medium

---

## Issue: FINDING-213 - No Token Expiry Verification in Application Code
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application reads session data and checks only for presence (if s:), not for temporal validity.

### Details
No exp, nbf, or iat claim verification is visible. If asfquart.session.read() does not internally verify token expiration, expired sessions would be accepted indefinitely. Data flow: asfquart.session.read() returns session dict, application checks only if s: (truthy), accepts claims without time validation. If session tokens or OAuth tokens don't have expiry enforcement, a stolen/leaked token could be used indefinitely, even after a user's access should have been revoked.

**Affected Files:**
- v3/server/pages.py (lines 75-106)

**CWE:** None specified
**ASVS:** 9.2.1 (L1)

### Remediation
Verify session hasn't expired at application level. If 'exp' claim exists in session, check if current time exceeds exp value and reject expired sessions. If 'nbf' claim exists, check if current time is before nbf value and reject not-yet-valid sessions. Example: if 'exp' in s: import time; if time.time() > s['exp']: treat as unauthenticated. Similarly check 'nbf' claim if present.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 9.2.1.md
- Global ID: FINDING-213

### Priority
Medium

---

## Issue: FINDING-214 - No Token Type Differentiation or Verification
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application explicitly avoids OIDC and does not distinguish between token types.

### Details
The plain OAuth flow used does not distinguish between token types. No typ or token_use claim is checked before accepting token contents for authentication decisions. Without token type verification, there is a risk of token misuse. For example, if different token types are issued for different purposes (API access vs. user identity), the absence of type checking could allow an access token to be used where an ID token is expected, potentially granting unintended access.

**Affected Files:**
- v3/server/pages.py (lines 75-106)
- v3/server/main.py (lines 27-42)

**CWE:** None specified
**ASVS:** 9.2.2 (L2)

### Remediation
If using OIDC (recommended over plain OAuth), the framework should validate that ID tokens are used for authentication and access tokens for API calls. At the application level, implement token type checking to verify this is an identity-purpose session/token and reject non-identity tokens.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 9.2.2.md
- Global ID: FINDING-214

### Priority
Medium

---

## Issue: FINDING-215 - OIDC Explicitly Bypassed Removing Standard Audience Protection
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The code explicitly overrides the asfquart framework's default OAuth/OIDC configuration with a comment 'Avoid OIDC'.

### Details
The uncertain 'is this really needed right now?' suggests this was done as a quick workaround rather than a deliberate security decision. OIDC provides built-in audience restriction via: ID Token aud claim (MUST contain client_id per spec), Token endpoint client authentication, and Standardized token validation procedures. By bypassing OIDC, the application loses these protections that directly satisfy ASVS 9.2.4. The application deliberately disables a framework-level control that would provide audience restriction, creating a false sense of security since the asfquart.auth.require decorator appears to work but doesn't validate audience claims.

**Affected Files:**
- v3/server/main.py (lines 29-35)

**CWE:** None specified
**ASVS:** 9.2.4 (L2)

### Remediation
Use standard OIDC flow which provides audience validation. Configure client_id for audience restriction. If custom OAuth is needed, ensure audience is configured with OAUTH_CLIENT_ID, OAUTH_EXPECTED_AUDIENCE, and OAUTH_EXPECTED_ISSUER.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 9.2.4.md
- Global ID: FINDING-215

### Priority
Medium

---

## Issue: FINDING-216 - Key Sharing Scope Not Formally Documented
**Labels:** documentation, security, priority:low
**Description:**
### Summary
The opened_key in each election effectively acts as a shared secret used by the system to derive per-voter vote tokens, but sharing boundaries are not formally documented.

### Details
While the key is only accessible to the application server (single entity), the sharing boundaries are not formally documented. The key derivation chain (opened_key → vote_token → vote_key) means compromise of the opened_key enables decryption of all votes in that election. Without formal documentation of key sharing boundaries, there's risk of architectural changes inadvertently exposing keys to additional entities.

**Affected Files:**
- v3/steve/crypto.py
- v3/steve/election.py

**CWE:** None specified
**ASVS:** 11.1.1 (L2)

### Remediation
Formally document key sharing boundaries and access scope for all cryptographic keys, particularly the opened_key. Include this in the overall key management policy document.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 11.1.1.md
- Global ID: FINDING-216

### Priority
Low

---

## Issue: FINDING-217 - Misleading HKDF Info Parameter Suggests Incomplete Migration
**Labels:** bug, security, priority:low
**Description:**
### Summary
The HKDF info parameter is set to b'xchacha20_key' but the actual encryption uses Fernet (AES-128-CBC).

### Details
This is a domain separation label that typically identifies the intended key usage. When the migration to XChaCha20-Poly1305 occurs, this info value must NOT change (or old ciphertext becomes undecryptable), creating a confusing situation where the info label is correct for new data but was technically wrong for historical data.

**Affected Files:**
- v3/steve/crypto.py (lines 63-67)
- v3/steve/crypto.py (lines 60-67)

**CWE:** None specified
**ASVS:** 11.2.2, 11.3.4 (L2, L3)

### Remediation
Either use a generic info value like b'vote_encryption_key_v1' or document that the current info value was chosen proactively for the planned migration. Plan migration path for Fernet → XChaCha20-Poly1305 to ensure the HKDF info parameter changes during migration to prevent key reuse across algorithms.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 11.2.2.md, 11.3.4.md
- Global ID: FINDING-217

### Priority
Low

---

## Issue: FINDING-218 - BLAKE2b Usage Not NIST FIPS Approved
**Labels:** compliance, security, priority:low
**Description:**
### Summary
BLAKE2b is a modern, secure hash function (RFC 7693) with a 512-bit output, but it is not listed in NIST FIPS 180-4 (SHA-2) or FIPS 202 (SHA-3) as an 'approved' hash function.

### Details
Depending on organizational compliance requirements, this could be a concern. In practice, BLAKE2b is used within Argon2 itself (which is NIST-recognized via SP 800-63B), making this a very low-risk finding.

**Affected Files:**
- v3/steve/crypto.py (line 45)

**CWE:** None specified
**ASVS:** 11.4.1 (L1)

### Remediation
If strict NIST compliance is required, replace with SHA-512: import hashlib; digest = hashlib.sha512(edata).digest()  # 64 bytes, NIST-approved

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 11.4.1.md
- Global ID: FINDING-218

### Priority
Low

---

## Issue: FINDING-219 - HKDF Usage Lacks Documentation Clarifying Security Model
**Labels:** documentation, security, priority:low
**Description:**
### Summary
HKDF is not a key-stretching function and provides no computational cost against brute-force.

### Details
However, since the input (vote_token) is already the 32-byte output of Argon2 (which provides the key stretching), HKDF is being used appropriately as a key derivation function to transform already-stretched material into an encryption key. This is acceptable architecture but worth documenting that the stretching occurs upstream.

**Affected Files:**
- v3/steve/crypto.py (lines 60-67)

**CWE:** None specified
**ASVS:** 11.4.4 (L2)

### Remediation
Add a comment clarifying the security model in the _b64_vote_key function documentation explaining that key stretching is provided by Argon2 in gen_vote_token() and HKDF here only transforms the already-stretched token into a key suitable for the encryption algorithm.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 11.4.4.md
- Global ID: FINDING-219

### Priority
Low

---

## Issue: FINDING-220 - All Votes Decrypted and Held Simultaneously in Memory During Tally
**Labels:** bug, security, priority:low
**Description:**
### Summary
The entire set of decrypted votes exists in cleartext memory simultaneously in the tally_issue() function.

### Details
All votes for an issue are decrypted simultaneously, stored in a votes list, and remain in memory until garbage collected. For elections with many voters, this creates a larger window where all vote data is exposed. There is no explicit clearing of sensitive variables after use.

**Affected Files:**
- v3/steve/election.py (lines 248-294)

**CWE:** None specified
**ASVS:** 11.7.2 (L3)

### Remediation
Process votes through streaming tally where possible. For STV (which requires all votes), minimize exposure window by implementing explicit clearing of sensitive data in a finally block. Clear the votes list by setting each element to None and calling clear(). While Python doesn't guarantee memory zeroing, this reduces the exposure window.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 11.7.2.md
- Global ID: FINDING-220

### Priority
Low

---

## Issue: FINDING-221 - Voter Identity Data Accumulated in Cleartext Memory During Election Data Gathering
**Labels:** bug, security, priority:low
**Description:**
### Summary
In gather_election_data(), all voter PIDs and emails are assembled in a cleartext string, encoded to bytes, and passed to a hash function, but the original strings remain in memory until garbage collected.

### Details
Voter identity data (PIDs and email addresses) exists in unencrypted memory longer than necessary. The assembled string is only needed for hashing but persists until garbage collected.

**Affected Files:**
- v3/steve/election.py (lines 82-107)

**CWE:** None specified
**ASVS:** 11.7.2 (L3)

### Remediation
Use incremental hashing to avoid accumulating all data in a single string. Create a hash object and update it incrementally as each piece of data is retrieved from the database, encoding each piece before updating the hash. Return the final digest without accumulating all voter data in memory simultaneously.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 11.7.2.md
- Global ID: FINDING-221

### Priority
Low

---

## Issue: FINDING-222 - Redirect URI handling delegates validation entirely to external authorization server with no client-side verification
**Labels:** bug, security, priority:low
**Description:**
### Summary
This application is an OAuth CLIENT, not an authorization server. The actual redirect URI validation is the responsibility of oauth.apache.org.

### Details
The code configures the OAuth initiation URL with a redirect_uri parameter (populated via %s), but: 1. We cannot verify from this codebase how the redirect_uri value is constructed by asfquart 2. The authorization server at oauth.apache.org is responsible for exact string comparison validation 3. The asfquart.generics module (not provided) handles the actual redirect_uri construction. If the asfquart framework constructs the redirect_uri dynamically from request parameters without validation, it could enable open redirect attacks, but this cannot be confirmed from the available code.

**Affected Files:**
- v3/server/main.py (lines 39-42)

**CWE:** None specified
**ASVS:** 10.4.1, 6.5.1 (L1, L2)

### Remediation
Ensure redirect_uri is a hardcoded constant, not derived from user input. Example: OAUTH_REDIRECT_URI = 'https://steve.apache.org/oauth/callback' and use it in the OAuth URL construction as: asfquart.generics.OAUTH_URL_INIT = (f'https://oauth.apache.org/auth?state=%s&redirect_uri={OAUTH_REDIRECT_URI}')

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 10.4.1.md, 6.5.1.md
- Global ID: FINDING-222

### Priority
Low

---

## Issue: FINDING-223 - OAuth authorization request does not include explicit scope parameter
**Labels:** bug, security, priority:low
**Description:**
### Summary
The OAuth authorization URL (OAUTH_URL_INIT) does not include a client_id parameter.

### Details
In standard OAuth 2.0 (RFC 6749 §4.1.1), the client_id is REQUIRED in the authorization request and is the mechanism by which the authorization server can scope the issued token to a specific audience. Without client_id: 1) The OAuth server cannot issue audience-restricted tokens, 2) If the same OAuth provider's private key signs tokens for multiple relying parties, any token is valid everywhere, 3) A token obtained by visiting another ASF application (sharing the same OAuth server) could be replayed against STeVe. This enables cross-service token replay where a token issued for a less-sensitive ASF service could be used to authenticate to STeVe (the voting system), which has higher security requirements due to election integrity concerns.

**Affected Files:**
- v3/server/main.py (lines 39-40)

**CWE:** None specified
**ASVS:** 10.4.11, 9.2.4 (L2)

### Remediation
Include client_id in OAuth requests with CLIENT_ID from configuration and use it in both OAUTH_URL_INIT and OAUTH_URL_CALLBACK.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 10.4.11.md, 9.2.4.md
- Global ID: FINDING-223

### Priority
Low

---

## Issue: FINDING-224 - Missing response_mode parameter in OAuth authorization request
**Labels:** bug, security, priority:low
**Description:**
### Summary
The OAuth authorization request does not specify a response_mode parameter.

### Details
There is no enforcement that the authorization server will only use the expected response mode (query for code flow). Without PAR or JAR, the authorization server relies on its own configuration to restrict response modes. Without explicit response_mode specification, an attacker modifying the authorization request (e.g., through open redirector or parameter injection) could potentially force the authorization server to return tokens in fragment mode, making them accessible to client-side code. This is a Level 3 requirement and lower risk given the code grant type in use.

**Affected Files:**
- v3/server/main.py (lines 39-40)

**CWE:** None specified
**ASVS:** 10.4.12 (L3)

### Remediation
Explicitly set response_mode for the code flow: asfquart.generics.OAUTH_URL_INIT = ('https://oauth.apache.org/auth?state=%s&redirect_uri=%s&response_type=code&response_mode=query'). Note: This is a Level 3 requirement. The ASF OAuth server should be configured to only allow appropriate response modes for this client. The finding reflects that no client-side enforcement or specification exists.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 10.4.12.md
- Global ID: FINDING-224

### Priority
Low

---

## Issue: FINDING-225 - Authorization code replay protection is delegated to external authorization server without client-side verification
**Labels:** bug, security, priority:low
**Description:**
### Summary
This application is an OAuth CLIENT, not an authorization server. The enforcement of single-use authorization codes is the responsibility of the authorization server at oauth.apache.org.

### Details
From the client side: 1. The code exchanges an authorization code for a token via the callback URL 2. The asfquart framework handles the actual token exchange 3. The authorization server should reject reused codes and revoke associated tokens. The code format 'https://oauth.apache.org/token?code=%s' passes the code as a query parameter in a GET-style URL format, which could lead to code exposure in server logs. If oauth.apache.org does not enforce single-use codes, an intercepted code could be replayed. This is outside the control of this codebase.

**Affected Files:**
- v3/server/main.py (lines 41-42)

**CWE:** None specified
**ASVS:** 10.4.2, 6.8.3 (L1, L2)

### Remediation
Use POST for token exchange to avoid code in URL/logs. The token endpoint should accept code in the request body, not query string. Change from: asfquart.generics.OAUTH_URL_CALLBACK = 'https://oauth.apache.org/token?code=%s' to: asfquart.generics.OAUTH_URL_CALLBACK = 'https://oauth.apache.org/token' with code sent as POST body parameter.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 10.4.2.md, 6.8.3.md
- Global ID: FINDING-225

### Priority
Low

---

## Issue: FINDING-226 - No Visible Refresh Token Expiration Enforcement on Client Side
**Labels:** bug, security, priority:low
**Description:**
### Summary
The application uses asfquart.session and asfquart.auth for authentication, operating as an OIDC Relying Party, but there is no back-channel logout endpoint or logout token processing visible in the codebase.

### Details
The application has no route matching /backchannel-logout, /logout, or similar patterns. No JWT parsing of logout tokens, no verification of the event claim, no check for absence of nonce claim, no expiration validation on logout tokens. Sessions authenticated via asfquart.session.read() would persist indefinitely after an IdP-initiated logout. If the upstream identity provider terminates a user's session, the voting application would continue to honor the stale session. This creates a denial-of-service vector through forced logout attacks, and sessions cannot be revoked remotely. A compromised account cannot be quickly invalidated across all relying parties.

**Affected Files:**
- v3/server/pages.py (lines 82-91)

**CWE:** None specified
**ASVS:** 10.4.8, 10.5.5, 6.3.3 (L2)

### Remediation
Implement a /backchannel-logout endpoint that: (1) Validates typ: logout+jwt in the JWT header, (2) Verifies the events claim contains http://schemas.openid.net/event/backchannel-logout, (3) Rejects tokens containing a nonce claim, (4) Enforces a maximum 2-minute token lifetime (exp - iat ≤ 120s), (5) Invalidates all sessions for the identified subject (sub) or session (sid). Additionally, implement session revocation infrastructure with a session store or blacklist mechanism, implement RP-initiated logout for user-facing logout, register the back-channel logout URI with the IdP, configure session timeouts aligned with IdP token lifetimes, and implement jti-based replay detection cache for logout tokens.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 10.4.8.md, 10.5.5.md, 6.3.3.md
- Global ID: FINDING-226

### Priority
Low

---

## Issue: FINDING-227 - Cannot verify ID Token sub claim mapping to session uid
**Labels:** bug, security, priority:low
**Description:**
### Summary
The application uses s['uid'] from the session as the unique user identifier throughout the codebase, but we cannot verify from the provided code that the session uid originates from a validated sub claim in an ID Token.

### Details
This maps to the LDAP uid attribute. The uid in ASF LDAP is a stable, non-reassignable identifier (Apache ID), which satisfies the spirit of the requirement. However, we cannot verify from the provided code: 1) That the session uid originates from a validated sub claim in an ID Token (the OAuth callback handler is in asfquart), 2) That the mapping between OAuth identity and LDAP uid is tamper-proof. The architectural pattern is sound — using a stable LDAP identifier — but verification of the token-to-session binding is not possible from the visible code.

**Affected Files:**
- v3/server/pages.py (lines 82-90)

**CWE:** None specified
**ASVS:** 10.5.2 (L2)

### Remediation
Verify that the asfquart framework properly validates the ID Token and maps the sub claim to the session uid. Audit the asfquart library OAuth callback handler to ensure: 1) The sub claim from the ID Token is extracted after proper token validation, 2) The mapping between OAuth sub claim and LDAP uid is secure and tamper-proof, 3) The session uid cannot be manipulated by the client. Document this mapping and validation process.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 10.5.2.md
- Global ID: FINDING-227

### Priority
Low

---

## Issue: FINDING-228 - No documented context-specific password deny list for the delegated authentication system
**Labels:** documentation, security, priority:low
**Description:**
### Summary
The application delegates password management entirely to ASF OAuth, but ASVS 6.1.2 requires that a list of context-specific words be documented to prevent their use in passwords.

### Details
For this application, such a list would include: Organization: "apache", "asf", "foundation"; Product: "steve", "voter", "election", "ballot"; System identifiers: Any election IDs, database names; Project codenames: "steve3", "STeVe"; Roles: "committer", "pmc", "member", "admin". Even though password enforcement is delegated, the documentation requirement still applies. The application should document either: 1. That ASF OAuth maintains such a deny list (with reference), OR 2. The recommended deny list for the ASF OAuth system to implement. Impact: Low severity because authentication is fully delegated to ASF OAuth, which likely has its own password policies. However, without documentation, there's no verification that context-specific words are prevented.

**Affected Files:**
- v3/server/main.py (entire file)
- v3/server/pages.py (entire file)

**CWE:** None specified
**ASVS:** 6.1.2 (L2)

### Remediation
Create documentation for context-specific password deny list including organization names (apache, asf, foundation, software), product/system names (steve, voter, voting, election, ballot), role names (committer, pmc, member, admin, owner), and project identifiers (steve3, STeVe, apache-steve). Document delegation notice that password policies are enforced by ASF OAuth with link to ASF password policy documentation and date last verified.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 6.1.2.md
- Global ID: FINDING-228

### Priority
Low

---

## Issue: FINDING-229 - LDAP bulk import does not filter or flag privileged/default account names
**Labels:** bug, security, priority:low
**Description:**
### Summary
The LDAP search filter uid=* imports every LDAP entry without filtering.

### Details
If the ASF LDAP directory contains service accounts, test accounts, or accounts with default-like names (e.g., root, admin, test), they would be imported into the person database and potentially eligible for election participation. The application does not validate imported accounts against a blocklist of default/service account names. This is a low severity finding because: 1) ASF LDAP is the authoritative source and likely manages its own account hygiene, 2) The imported accounts still need to pass mayvote authorization checks before voting, 3) No evidence that ASF LDAP contains standard default accounts like 'root' or 'sa'.

**Affected Files:**
- v3/server/bin/asf-load-ldap.py (lines 46-57)

**CWE:** None specified
**ASVS:** 6.3.2 (L1)

### Remediation
Add filtering for known service/default accounts: BLOCKED_UIDS = {'root', 'admin', 'sa', 'test', 'nobody', 'daemon'}. During LDAP import, skip any uid that matches the blocklist and log a warning.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 6.3.2.md
- Global ID: FINDING-229

### Priority
Low

---

## Issue: FINDING-230 - No re-authentication for sensitive election management operations
**Labels:** bug, security, priority:low
**Description:**
### Summary
Critical operations like opening and closing elections have no step-up authentication or re-authentication requirement.

### Details
With single-factor auth as the only mechanism, these high-impact operations proceed with the same assurance level as viewing a profile page. If a session is hijacked, the attacker can perform irreversible election management actions (open/close elections) without additional verification.

**Affected Files:**
- v3/server/pages.py (lines 484-520)

**CWE:** None specified
**ASVS:** 6.3.3 (L2)

### Remediation
Implement a re-authentication prompt before critical operations with require_recent_auth(max_age_seconds=300) that checks session.last_auth_at and redirects to /reauth if the session is too old.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 6.3.3.md
- Global ID: FINDING-230

### Priority
Low

---

## Issue: FINDING-231 - PersonDB Lookup Reveals User Existence to Authenticated Users
**Labels:** bug, security, priority:low
**Description:**
### Summary
When an authenticated committer accesses /admin and is NOT found in the PersonDB, they receive a distinct T_BAD_PID 404 error page.

### Details
This differentiates between "user exists in PersonDB" vs. "user doesn't exist in PersonDB." However, this only reveals information to the authenticated user about their OWN account status, the user is already authenticated via OAuth (so their identity is known), and no endpoint allows querying OTHER users' existence. Impact is minimal as the information leak is about the user's own status in an internal database, visible only to authenticated users. This does not enable enumeration of other users' accounts.

**Affected Files:**
- v3/server/pages.py (lines 303-344)

**CWE:** None specified
**ASVS:** 6.3.8 (L3)

### Remediation
While the impact is minimal due to mitigating factors (authentication is external via ASF OAuth, no login form exists to enumerate against, no registration or forgot-password functionality exists, and the differentiated response is only visible to the authenticated user about themselves), consider returning a generic error message that does not differentiate between user existence states in PersonDB.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 6.3.8.md
- Global ID: FINDING-231

### Priority
Low

---

## Issue: FINDING-232 - No session/token expiration renewal notifications
**Labels:** enhancement, security, priority:low
**Description:**
### Summary
While authentication mechanism expiry is managed by the external ASF IdP, the application's own session mechanism does not appear to implement any renewal warning.

### Details
If sessions have a fixed lifetime (configured in the asfquart framework), users receive no advance notice before their session expires during an active voting period. Session expiration occurs without warning, and users discover expired sessions only upon their next action. During time-sensitive elections, a voter or administrator could lose their session mid-operation without advance warning.

**Affected Files:**
- v3/server/pages.py (lines 63-93)

**CWE:** None specified
**ASVS:** 6.4.5 (L3)

### Remediation
If session timeouts are enforced, consider implementing a client-side warning (e.g., JavaScript timer) or server-side check that alerts users when their session is approaching expiration, particularly during active voting operations.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 6.4.5.md
- Global ID: FINDING-232

### Priority
Low

---

## Issue: FINDING-233 - Non-cryptographic random module used for candidate shuffling
**Labels:** bug, security, priority:low
**Description:**
### Summary
The random module (non-CSPRNG) is imported and used for shuffling candidate display order.

### Details
While this is NOT generating lookup secrets, OOB codes, or TOTP seeds (and therefore not a direct violation of 6.5.3), it establishes a pattern of using non-cryptographic randomness. If this module were ever extended to generate authentication-related secrets, the existing import random would likely be mistakenly reused. The Mersenne Twister's state can be reconstructed from 624 consecutive outputs, theoretically allowing prediction of shuffle order — but this only affects candidate display bias, not authentication security.

**Affected Files:**
- v3/server/pages.py (line 33)
- v3/server/pages.py (line 290)

**CWE:** None specified
**ASVS:** 6.5.3 (L2)

### Remediation
Replace random module usage with secrets or random.SystemRandom() for shuffling operations. While not an authentication vulnerability, using cryptographically secure randomness for candidate shuffling prevents any potential bias exploitation and establishes better security patterns.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 6.5.3.md
- Global ID: FINDING-233

### Priority
Low

---

## Issue: FINDING-234 - No re-authentication requirement for sensitive election management operations (federated context)
**Labels:** bug, security, priority:low
**Description:**
### Summary
Sensitive operations such as opening elections (do_open_endpoint) and closing elections (do_close_endpoint) do not require re-authentication.

### Details
In a federated identity system, re-authentication for high-privilege operations ensures the current operator is still the authenticated principal. A stolen session token could be used to open or close elections without any step-up authentication challenge.

**Affected Files:**
- v3/server/pages.py (lines 484-520)

**CWE:** None specified
**ASVS:** 7.1.3 (L2)

### Remediation
Implement re-authentication requirement for sensitive operations (election open/close/create) as a step-up authentication mechanism.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 7.1.3.md
- Global ID: FINDING-234

### Priority
Low

---

## Issue: FINDING-235 - Session token generation cannot be verified from provided code — delegated to asfquart framework
**Labels:** bug, security, priority:low
**Description:**
### Summary
Session token generation is fully delegated to the asfquart framework, which is not included in the audited codebase.

### Details
It is not possible to verify from the provided source files whether session tokens meet the 128-bit entropy requirement or are generated using a CSPRNG. The asfquart.session module handles all token creation internally. If the framework uses insufficient entropy (e.g., predictable tokens, < 128 bits), session tokens could be brute-forced or predicted, leading to session hijacking in the voting system.

**Affected Files:**
- v3/server/pages.py (line 82)
- v3/server/main.py (line 45)

**CWE:** None specified
**ASVS:** 7.2.3 (L1)

### Remediation
Verify the asfquart framework's session token generation: 1. Audit asfquart.session module for CSPRNG usage (e.g., secrets.token_hex(16) or equivalent) 2. Verify token length provides ≥ 128 bits of entropy 3. Document the verification in security architecture documentation.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 7.2.3.md
- Global ID: FINDING-235

### Priority
Low

---

## Issue: FINDING-236 - No logout functionality visible in audited code
**Labels:** bug, security, priority:low
**Description:**
### Summary
The provided pages.py file defines no logout endpoint or session termination route.

### Details
While this may exist in the asfquart framework or in the imported but not provided api.py module, the absence means we cannot verify that session tokens are properly terminated on logout. The file defines routes for /, /voter, /admin, /manage/&lt;eid&gt;, /profile, /settings, /about, and various /do-* action endpoints, but no /logout or /do-logout endpoint.

**Affected Files:**
- v3/server/pages.py (entire file)

**CWE:** None specified
**ASVS:** 7.2.4 (L1)

### Remediation
Implement or verify logout functionality that terminates the session token server-side. Add explicit logout endpoint (e.g., /logout or /do-logout) that destroys the session and invalidates the session token to prevent session theft after logout.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 7.2.4.md
- Global ID: FINDING-236

### Priority
Low

---

## Issue: FINDING-237 - OAuth callback session creation handler not visible for verification
**Labels:** bug, security, priority:low
**Description:**
### Summary
The OAuth flow configuration is present, but the actual callback handler that creates the session is not visible in the audited code (it's likely in the asfquart framework).

### Details
The OAuth flow inherently requires user interaction (browser redirect to OAuth provider, user approves). However, without seeing the callback handler, it's impossible to verify that: 1. Silent re-authentication doesn't create new sessions without user interaction 2. The callback validates that the user actively initiated the flow (state parameter). If the asfquart framework's OAuth callback creates sessions without proper state validation, it could be possible to forge session creation. However, the state=%s parameter in the OAuth URL suggests state parameter usage, which is a positive indicator.

**Affected Files:**
- v3/server/main.py (lines 39-42)

**CWE:** None specified
**ASVS:** 7.6.2 (L2)

### Remediation
Audit the asfquart framework OAuth callback handler to verify: 1. State parameter is properly validated to prevent CSRF attacks and ensure user-initiated flow 2. Silent re-authentication does not create new sessions without explicit user interaction 3. Callback validates that the user actively initiated the OAuth flow. Document the session creation logic and ensure it aligns with ASVS 7.6.2 requirements.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 7.6.2.md
- Global ID: FINDING-237

### Priority
Low

---

## Issue: FINDING-238 - Election state changes are immediately effective but no notification mechanism exists
**Labels:** enhancement, security, priority:low
**Description:**
### Summary
When an election is closed, any voter with the voting page already loaded can still submit their form, which will fail with a state error.

### Details
The authorization change (election closed = no more voting) IS applied immediately in the database (add_vote checks self.S_OPEN), but there's no mitigating control to alert voters mid-session. This is partially mitigated by _all_metadata(self.S_OPEN) in add_vote which validates state on every vote submission.

**Affected Files:**
- v3/steve/election.py

**CWE:** None specified
**ASVS:** 8.3.2 (L3)

### Remediation
Implement a real-time notification mechanism to alert active voters when an election state changes (e.g., when an election closes). Consider using WebSockets or polling to notify users that voting is no longer possible.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 8.3.2.md
- Global ID: FINDING-238

### Priority
Low

---

## Issue: FINDING-239 - No evidence of token propagation architecture, but session identity is correctly used for all operations
**Labels:** documentation, security, priority:low
**Description:**
### Summary
The application is a monolithic server with direct database access. There are no service-to-service calls, no intermediary services, and no token forwarding patterns.

### Details
All operations use result.uid (from the authenticated session) directly. No findings detected for this requirement in the current architecture. The application correctly uses the originating subject's identity for all permission decisions.

**Affected Files:**
- v3/server/pages.py
- v3/steve/election.py

**CWE:** None specified
**ASVS:** 8.3.3 (L3)

### Remediation
No remediation required. The application correctly uses the originating subject's identity for all permission decisions. Continue to maintain this pattern as the architecture evolves.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 8.3.3.md
- Global ID: FINDING-239

### Priority
Low

---

## Issue: FINDING-240 - User-controlled values in flash messages and log entries via f-strings
**Labels:** bug, security, priority:low
**Description:**
### Summary
User-controlled values are included in flash messages and log entries via f-strings.

### Details
While f-strings themselves are safe from format string attacks, the user data (election titles, issue IDs) flows into contexts that could be misinterpreted in future refactoring. Data flow: User form input (form.title, iid from form keys) → f-string evaluation → flash message stored in session → rendered in template. Impact is minimal for format string attacks specifically (f-strings prevent this). The concern is defensive: if logging or flash code were refactored to use deferred formatting (e.g., logging.info with %s or Python's .format() on a template variable), the lack of explicit sanitization could introduce vulnerabilities. Current code is safe.

**Affected Files:**
- v3/server/pages.py (line 423)
- v3/server/pages.py (line 490)
- v3/server/pages.py (line 399)

**CWE:** None specified
**ASVS:** 1.3.10 (L2)

### Remediation
No immediate action needed. Document as secure-by-convention and add input validation (length limits, character restrictions) for election titles as defense-in-depth.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 1.3.10.md
- Global ID: FINDING-240

### Priority
Low

## Issue: FINDING-241 - SVG files served without script execution prevention
**Labels:** bug, security, priority:low
**Description:**
### Summary
The serve_doc endpoint serves arbitrary files from the docs directory without file-type restrictions. SVG files with embedded JavaScript could be served to voters if placed by compromised administrators.

### Details
If SVG files are placed in the docs directory (by trusted administrators), they would be served with their native image/svg+xml Content-Type, potentially containing embedded scripts. If a compromised or malicious election administrator places an SVG file with embedded JavaScript, it would be served to voters who click links generated by rewrite_description(). Mitigating factors include: files are placed by trusted administrators (filesystem access required), not directly uploadable through the web interface, and the user writing doc:filename in a description cannot create the actual file.

**CWE:** N/A  
**ASVS:** 1.3.4 (L2)  
**File:** v3/server/pages.py:586

### Remediation
Add Content-Disposition header to force download for non-safe types. Create a SAFE_INLINE_TYPES allowlist containing only safe extensions like .pdf, .txt, .png, .jpg, .jpeg, .gif. For files not in the allowlist, set Content-Disposition to attachment. Additionally, add Content-Security-Policy header with script-src 'none' to prevent SVG script execution even if served inline.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 1.3.4.md
- Related: None

### Priority
Low

---

## Issue: FINDING-242 - Deserialized JSON `kv` data lacks schema validation before use in vote tallying
**Labels:** bug, security, priority:low
**Description:**
### Summary
Database `issue.kv` column (TEXT) is deserialized via `json.loads()` and passed directly to `vtypes` module `tally()` function without structural validation.

### Details
While `json.loads()` is inherently safe from code execution (only produces basic Python types: dict, list, str, int, float, bool, None), the deserialized structure is passed to vote-type-specific modules without validation against an expected schema. If the `kv` data were corrupted or maliciously set (e.g., via an authorization bypass — the code inventory notes multiple `### check authz` placeholders are unimplemented), unexpected data structures could cause logic errors in tallying. Mitigating factors include: data originates from authorized election administrators (write path is `add_issue`/`edit_issue` which assert `is_editable()`), `json.loads()` cannot instantiate arbitrary objects, `issue.type` is validated against `vtypes.TYPES` at creation time.

**CWE:** N/A  
**ASVS:** 1.5.2 (L2)  
**Files:** v3/steve/election.py:292, v3/steve/election.py:368

### Remediation
Add schema validation to the `json2kv()` function to ensure the deserialized result is a dict (expected schema). Additionally, each `vtypes` module should validate the `kv` structure it receives in its `tally()` function. Example implementation:
```python
@staticmethod
def json2kv(j):
    if not j:
        return None
    parsed = json.loads(j)
    if not isinstance(parsed, dict):
        raise ValueError(f"Expected dict for kv, got {type(parsed).__name__}")
    return parsed
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 1.5.2.md
- Related: None

### Priority
Low

---

## Issue: FINDING-243 - Vote type enumeration not documented outside of code
**Labels:** bug, security, priority:low
**Description:**
### Summary
The schema documentation mentions yna and stv as vote types but does not document the complete set of valid values, how they are validated, or their expected input/output formats.

### Details
The schema.md states that type column supports yna (Yes/No/Abstain voting) and stv (Single Transferable Vote) with additional types potentially added in the future, but the validation rules for each type's vote data are not documented. The enumeration exists partially in documentation and is enforced in code (vtypes.TYPES), but the validation rules for each type's vote input format are not documented.

**CWE:** N/A  
**ASVS:** 2.1.1 (L1)  
**File:** v3/docs/schema.md

### Remediation
Document the expected vote input format for each type and the validation rules that apply. Include complete enumeration of valid vote types, input format specifications, and validation criteria for each type's vote data.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 2.1.1.md
- Related: None

### Priority
Low

---

## Issue: FINDING-244 - Server can operate without TLS with no documentation or warning
**Labels:** bug, security, priority:low
**Description:**
### Summary
The server can be configured without TLS (blank certfile/keyfile fields in config.yaml), serving plain HTTP with no documentation stating this is only acceptable for development.

### Details
The application silently falls back to plain HTTP if TLS is not configured, with no warning or documentation about security implications. This could lead to production deployments without encryption.

**CWE:** N/A  
**ASVS:** 3.1.1 (L3)  
**File:** v3/server/main.py:53-90

### Remediation
Add explicit warning logging when TLS is not configured, and document that production deployments MUST use TLS (either directly or via reverse proxy).

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 3.1.1.md
- Related: None

### Priority
Low

---

## Issue: FINDING-245 - Global Scope Functions Without Namespace Isolation or Type Checking
**Labels:** bug, security, priority:low
**Description:**
### Summary
Functions are defined in global scope without namespace isolation in `admin.ezt`. The `showModal`, `validateRequiredField`, and `submitFormWithLoading` functions are also global with no strict type checking on DOM element retrieval results.

### Details
Low risk since this page requires admin authentication and doesn't render user-controlled HTML. However, it represents a pattern that could become exploitable if combined with other vulnerabilities.

**CWE:** N/A  
**ASVS:** 3.2.3 (L3)  
**File:** v3/server/templates/admin.ezt (JavaScript block)

### Remediation
Move to module pattern or IIFE with explicit null checks:
```javascript
(function() { 
  'use strict'; 
  window.openCreateElectionModal = function() { 
    const el = document.getElementById('electionTitle'); 
    if (!(el instanceof HTMLInputElement)) return; 
    el.value = ''; 
    el.classList.remove('is-invalid'); 
    showModal('createElectionModal'); 
  }; 
})();
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 3.2.3.md
- Related: None

### Priority
Low

---

## Issue: FINDING-246 - CSRF token embedded in HTML body rather than Set-Cookie header
**Labels:** bug, security, priority:low
**Description:**
### Summary
The CSRF token (currently a placeholder `'placeholder'`) is embedded in template output as a hidden form field value rather than exclusively via `Set-Cookie`.

### Details
While CSRF tokens are by definition meant to be used by client-side forms, this is an architectural note rather than a vulnerability. The real risk is that this token is never validated (acknowledged in known false positives as work-in-progress).

**CWE:** N/A  
**ASVS:** 3.3.4 (L2)  
**File:** v3/server/pages.py:87

### Remediation
CSRF tokens are typically embedded in page HTML by design. The primary remediation is to implement actual CSRF token validation rather than changing the transmission mechanism.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 3.3.4.md
- Related: None

### Priority
Low

---

## Issue: FINDING-247 - No validation that session cookie size stays within 4096 bytes
**Labels:** bug, security, priority:low
**Description:**
### Summary
The application stores flash messages in the session (which is cookie-based in Quart by default). There is no validation that the total session/cookie size stays within 4096 bytes.

### Details
Flash messages accumulate in the session until displayed. If cookie exceeds 4096 bytes, browser silently drops cookie and user loses session. Low practical risk as flash messages are cleared on page load, and the session data (uid, fullname, email) is typically short.

**CWE:** N/A  
**ASVS:** 3.3.5 (L3)  
**File:** v3/server/pages.py:60-90

### Remediation
Add middleware to validate cookie size before setting:
```python
@APP.after_request
async def check_cookie_size(response):
    for header_name, header_value in response.headers:
        if header_name.lower() == 'set-cookie':
            cookie_content = header_value.split(';')[0]
            if len(cookie_content.encode('utf-8')) > 4096:
                _LOGGER.warning(f'Cookie exceeds 4096 bytes: {len(cookie_content)} bytes')
    return response
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 3.3.5.md
- Related: None

### Priority
Low

---

## Issue: FINDING-248 - Single Hostname Configuration With No Evidence of Multi-Application Separation
**Labels:** bug, security, priority:low
**Description:**
### Summary
The configuration shows a single server on a single port with TLS certificates for a single hostname. While no multi-application hosting is evident, there is no explicit configuration or documentation that would prevent deployment on a shared hostname with other applications.

### Details
The application serves dynamic pages (elections, voting), static files (/static/), document files (/docs/), and authentication flows (/auth) all under a single origin. If co-hosted with other ASF applications on the same hostname, the Same-Origin Policy would not provide separation.

**CWE:** N/A  
**ASVS:** 3.5.4 (L2)  
**File:** v3/server/config.yaml.example

### Remediation
Ensure deployment configuration uses a dedicated hostname (e.g., steve.apache.org) rather than a path-based virtual host. Document this requirement.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 3.5.4.md
- Related: None

### Priority
Low

---

## Issue: FINDING-249 - Candidate Data Embedded in Inline Script Within Authenticated HTML Page
**Labels:** bug, security, priority:low
**Description:**
### Summary
Election data (candidate names, issue titles, seat counts, issue IDs) is embedded in an inline &lt;script&gt; block within the HTML response of an authenticated page.

### Details
This is NOT a XSSI vulnerability because: (1) The data is in the HTML page itself, not in a separate script resource; (2) The page requires authentication; (3) Cross-origin script loading would not include session cookies; (4) Quart does not set Access-Control-Allow-Origin headers that would permit cross-origin reading. However, if any separate .js endpoint were added in the future that serves this data dynamically, it could become exploitable.

**CWE:** N/A  
**ASVS:** 3.5.7 (L3)  
**File:** v3/server/templates/vote-on.ezt (JavaScript section)

### Remediation
No immediate action required. As a defense-in-depth measure, add X-Content-Type-Options to prevent MIME sniffing: `@APP.after_request async def security_headers(response): response.headers['X-Content-Type-Options'] = 'nosniff'; return response`

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 3.5.7.md
- Related: None

### Priority
Low

---

## Issue: FINDING-250 - SRI Integrity Attributes Incomplete
**Labels:** bug, security, priority:low
**Description:**
### Summary
SRI (Subresource Integrity) is applied to Bootstrap CSS and JS, and to SortableJS, but NOT to the application's own scripts and stylesheets.

### Details
Missing integrity attributes on bootstrap-icons.css, steve.css, and steve.js mean no integrity verification on application resources. If SRI check fails on resources that do have integrity attributes, the browser blocks loading but the application provides no user-visible explanation. There is no fallback behavior documented or implemented when critical scripts fail to load.

**CWE:** N/A  
**ASVS:** 3.7.5, 3.6.1 (L3)  
**Files:** v3/server/templates/header.ezt:7, v3/server/templates/footer.ezt:14

### Remediation
Add integrity attributes to all script and style resources including steve.css and steve.js with computed SHA-384 hashes. Implement a global error event handler that listens for error events on SCRIPT and LINK elements, and when detected, replaces document.body.innerHTML with a user-friendly error message stating 'A required resource failed integrity verification. This may indicate a security issue. Please reload the page or contact support.'

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 3.7.5.md, 3.6.1.md
- Related: None

### Priority
Low

---

## Issue: FINDING-251 - Election Creation Has No Secondary Approval
**Labels:** bug, security, priority:low
**Description:**
### Summary
While creation itself is not destructive, it's the entry point for the entire election lifecycle. A PMC member could create elections without organizational awareness.

### Details
This is lower severity as elections must still be opened and closed, and the `R.pmc_member` requirement provides some gatekeeping. However, lack of multi-user approval workflow could allow unauthorized election creation.

**CWE:** CWE-863  
**ASVS:** 2.3.5 (L3)  
**File:** v3/server/pages.py:410

### Remediation
Implement multi-user approval workflow for election creation to ensure organizational awareness and oversight before elections enter the lifecycle.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 2.3.5.md
- Related: FINDING-149

### Priority
Low

---

## Issue: FINDING-252 - Vote Table Schema Lacks Timestamp for Timing Analysis
**Labels:** bug, security, priority:low
**Description:**
### Summary
The vote table schema lacks a timestamp column, preventing any timing-based analysis or enforcement.

### Details
This makes it impossible to retroactively detect automated voting patterns or implement minimum interval checks at the database level. The AUTOINCREMENT VID provides ordering but not timing information. Audit logs may have timing info, but it's separated from the vote data.

**CWE:** CWE-778  
**ASVS:** 2.4.2 (L3)  
**File:** v3/docs/schema.md:148

### Remediation
Add created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')) column to vote table. Create database trigger to prevent rapid re-voting by checking if vote_token has voted within last 10 seconds and raising ABORT if so.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 2.4.2.md
- Related: FINDING-112

### Priority
Low

---

## Issue: FINDING-253 - Encrypted Client Hello (ECH) Not Configured
**Labels:** bug, security, priority:low
**Description:**
### Summary
No ECH (Encrypted Client Hello) configuration exists anywhere in the codebase. Without ECH, the Server Name Indication (SNI) field in the TLS ClientHello is transmitted in plaintext.

### Details
This allows network observers (ISPs, network administrators, or attackers performing passive surveillance) to determine which hostname the client is connecting to, even though the payload is encrypted. This is a metadata privacy issue. ECH is a TLS 1.3 extension (RFC 9578, formerly ESNI) that is still relatively new and requires DNS infrastructure support, server-side TLS library support, and Python's ssl module does not natively support ECH configuration as of Python 3.12.

**CWE:** N/A  
**ASVS:** 12.1.5 (L3)  
**Files:** v3/server/main.py, v3/server/config.yaml.example

### Remediation
This is a Level 3 requirement. Implementation requires: 1. Deploy behind a reverse proxy that supports ECH (e.g., Cloudflare, nginx with ECH patches) 2. Publish ECH keys via DNS HTTPS records 3. Document ECH configuration in deployment guides. Example DNS record for ECH support: `_443._https.steve.apache.org. IN HTTPS 1 . ech="<base64-encoded ECH config>"`

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 12.1.5.md
- Related: None

### Priority
Low

---

## Issue: FINDING-254 - LDAP Connection Security Not Verified in Architecture
**Labels:** bug, security, priority:low
**Description:**
### Summary
The system connects to an LDAP server for user data loading via the asf-load-ldap.py script. There is no documentation indicating whether LDAPS or StartTLS is used, certificate validation is performed, or credentials are transmitted securely.

### Details
If LDAP connections use plaintext LDAP (port 389) without StartTLS, credentials and user data are transmitted unencrypted.

**CWE:** N/A  
**ASVS:** 12.3.1 (L2)  
**Files:** v3/docs/quickstart.md:38-44, v3/ARCHITECTURE.md

### Remediation
Ensure the LDAP loading script uses LDAPS (port 636) or StartTLS with certificate validation enabled. Document this requirement in the deployment and quickstart guides. Verify the asf-load-ldap.py script implementation to confirm secure LDAP connection configuration.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 12.3.1.md
- Related: None

### Priority
Low

---

## Issue: FINDING-255 - No Documented Enforcement of TLS Between Application and Reverse Proxy
**Labels:** bug, security, priority:low
**Description:**
### Summary
The architecture is primarily a monolithic application (Quart web server + SQLite file database) with minimal service-to-service communication. However, there are identifiable communication paths without mutual TLS.

### Details
The system does not implement: TLS client certificate authentication, Service mesh, API keys or tokens for service-to-service authentication, or Replay attack prevention for internal calls. At Level 3, the absence of mutual TLS means internal services cannot cryptographically verify each other's identity. However, given the monolithic architecture with SQLite (no network database), the attack surface is limited.

**CWE:** N/A  
**ASVS:** 12.3.3, 12.3.5 (L2, L3)  
**Files:** v3/ARCHITECTURE.md, v3/server/config.yaml.example:22

### Remediation
For a Level 3 deployment, add mTLS support in main.py or consider a service mesh (e.g., Istio, Linkerd) if the architecture evolves to microservices.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 12.3.3.md, 12.3.5.md
- Related: None

### Priority
Low

---

## Issue: FINDING-256 - SQLite database access lacks authentication mechanism
**Labels:** bug, security, priority:low
**Description:**
### Summary
Communications between application components and the SQLite database do not use any authentication mechanism. The database is accessed via file path with no credentials.

### Details
SQLite is a file-based database and does not natively support user authentication. Access control depends entirely on file system permissions. If the file system permissions are misconfigured, any process on the same host could read or modify election data, cryptographic salts, and encrypted votes.

**CWE:** N/A  
**ASVS:** 13.2.1 (L2)  
**Files:** v3/steve/election.py:35-37, v3/steve/persondb.py:25-26

### Remediation
For SQLite specifically: Document that file system permissions serve as the authentication mechanism; Ensure the database file has restrictive permissions (e.g., 0600, owned by the application service account); Consider SQLite encryption extensions (e.g., SQLCipher) for data-at-rest protection; If migrating to a networked database, implement service account authentication with short-term credentials

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 13.2.1.md
- Related: None

### Priority
Low

---

## Issue: FINDING-257 - Email service communication lacks documented authentication configuration
**Labels:** bug, security, priority:low
**Description:**
### Summary
The email sending function does not show explicit SMTP authentication. The comment '# Add other parameters as needed (e.g., auth, headers)' suggests authentication is not yet configured.

### Details
The asfpy.messaging library may handle this internally, but it is not documented or visible in this codebase. If SMTP authentication is not configured, the application may be relying on network-level trust which could be spoofed or abused.

**CWE:** N/A  
**ASVS:** 13.2.1 (L2)  
**File:** v3/server/bin/mail-voters.py:67-73

### Remediation
Document SMTP authentication method and ensure it uses short-term tokens or certificate-based authentication rather than static passwords.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 13.2.1.md
- Related: None

### Priority
Low

---

## Issue: FINDING-258 - CLI scripts run without documented privilege requirements
**Labels:** bug, security, priority:low
**Description:**
### Summary
Command-line utilities that directly modify the database or send emails have no documented OS-level privilege requirements or access controls.

### Details
create-election.py can create elections and add voters, while mail-voters.py can read voter emails and send messages. These scripts have the same database privileges as the web server but no authentication or authorization layer. Anyone with shell access to the server can create elections, modify voter rolls, or send emails to voters without audit trail beyond system-level logging.

**CWE:** N/A  
**ASVS:** 13.2.2 (L2)  
**Files:** v3/server/bin/create-election.py, v3/server/bin/mail-voters.py

### Remediation
Document required OS permissions and consider adding authentication checks or restricted execution contexts for CLI tools.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 13.2.2.md
- Related: None

### Priority
Low

---

## Issue: FINDING-259 - No evidence of server-level allowlist configuration for outbound requests or file access
**Labels:** bug, security, priority:low
**Description:**
### Summary
The codebase does not contain any server-level configuration defining which resources or systems the server can send requests to or load data from.

### Details
While the application primarily uses local SQLite databases and local file system access, there is no evidence of web server configuration restricting outbound connections, application-level configuration restricting file system access paths, or network-level allowlist documentation. If the application is extended to make outbound requests, there would be no allowlist to prevent SSRF or unauthorized outbound communication.

**CWE:** N/A  
**ASVS:** 13.2.5 (L2)  
**Files:** Application-wide (configuration gap), election.py:445

### Remediation
In application configuration, define ALLOWED_FILE_PATHS dictionary containing 'database', 'templates', 'static', and 'docs' paths. At server-level, configure reverse proxy (e.g., nginx) to restrict outbound connections. Add iptables/firewall rules to whitelist only necessary outbound destinations.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 13.2.5.md
- Related: None

### Priority
Low

---

## Issue: FINDING-260 - Ad-hoc database connections opened in request handlers without connection lifecycle management
**Labels:** bug, security, priority:low
**Description:**
### Summary
Multiple database connections are opened per request without explicit closing or connection pooling. Comments in the code acknowledge this issue with '### should open/keep a PersonDB instance in the APP'.

### Details
Connections are opened at lines 233, 295, 435, and 567 in pages.py without proper lifecycle management.

**CWE:** N/A  
**ASVS:** 13.2.6 (L3)  
**Files:** v3/server/pages.py:233, v3/server/pages.py:295, v3/server/pages.py:435, v3/server/pages.py:567

### Remediation
Implement a connection pool or application-level singleton for database access with proper lifecycle management. Replace ad-hoc open_database() calls with an application-level connection pool with documented configuration for timeouts, max connections, and retry behavior.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 13.2.6.md
- Related: None

### Priority
Low

---

## Issue: FINDING-261 - Commented-out debug print statements expose critical key material if uncommented
**Labels:** bug, security, priority:low
**Description:**
### Summary
While these debug print statements are currently commented out, their presence indicates a pattern of uncommenting for debugging. If accidentally uncommented in production, they would expose critical key material (salt, opened_key, election data) to stdout/logs.

### Details
The presence of commented-out debug statements creates a risk of accidental exposure in production environments.

**CWE:** N/A  
**ASVS:** 13.4.2 (L2)  
**Files:** v3/steve/election.py:79, v3/steve/election.py:83

### Remediation
Remove all commented-out debug print statements. Use structured logging with appropriate log levels that can be configured per environment.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 13.4.2.md
- Related: None

### Priority
Low

---

## Issue: FINDING-262 - Directory Listing Protection Depends on Deployment Configuration
**Labels:** bug, security, priority:low
**Description:**
### Summary
While Quart's send_from_directory() does NOT generate directory listings by default, the application does not explicitly configure or document that directory listing is disabled at the web server level if deployed behind a reverse proxy.

### Details
If the application is deployed behind a web server that has autoindex enabled, directories could be listed. This is a LOW finding because Quart/Flask's send_from_directory does not serve directory listings, and the actual risk depends on the deployment infrastructure.

**CWE:** N/A  
**ASVS:** 13.4.3 (L2)  
**Files:** v3/server/pages.py:560-574, v3/server/pages.py:577-578

### Remediation
Document deployment requirements to ensure directory listing is disabled at all levels. Add explicit handling for directory access attempts with a 404 error handler, or add middleware to reject requests ending in / for static and docs paths.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 13.4.3.md
- Related: None

### Priority
Low

---

## Issue: FINDING-263 - No Explicit HTTP TRACE Method Blocking
**Labels:** bug, security, priority:low
**Description:**
### Summary
The application uses Quart framework route decorators which only respond to explicitly specified HTTP methods. There is no explicit TRACE handler defined, and Quart will respond with 405 Method Not Allowed for unsupported methods.

### Details
However, there is no explicit middleware or configuration to block TRACE at the application level. If deployed behind a reverse proxy that passes TRACE through, or if future framework changes alter default behavior, TRACE could become available. The risk is LOW because the framework's default behavior is correct.

**CWE:** N/A  
**ASVS:** 13.4.4 (L2)  
**File:** v3/server/pages.py:125-583

### Remediation
Add explicit TRACE blocking for defense-in-depth: Add a before_request handler to block TRACE method explicitly or configure at the reverse proxy level (preferred) using nginx configuration: `if ($request_method = TRACE) { return 405; }`

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 13.4.4.md
- Related: None

### Priority
Low

---

## Issue: FINDING-264 - No Explicit Framework Endpoint Restriction Visible for asfquart Built-in Routes
**Labels:** bug, security, priority:low
**Description:**
### Summary
Application startup sets root logger and app logger to DEBUG level in all modes, including production ASGI. Debug-level logging in production ASGI mode may expose internal state, request parameters, framework internals, and cryptographic operation details to log collectors.

### Details
While not an endpoint per se, log aggregation systems (ELK, Splunk, CloudWatch) often expose search interfaces that become de facto monitoring endpoints. Any request processed by the server will generate DEBUG-level log entries containing internal processing details, framework routing decisions, and potentially session data.

**CWE:** N/A  
**ASVS:** 13.4.5 (L2)  
**File:** v3/server/main.py:34

### Remediation
After app construction, explicitly verify registered routes and remove any unintended ones. If framework exposes introspection: `app.config['EXPLAIN_TEMPLATE_LOADING'] = False`; Remove any health/status endpoints not intended for public access. Audit asfquart framework for any built-in documentation, debugging, or monitoring endpoints that may be registered by default.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 13.4.5.md
- Related: None

### Priority
Low

---

## Issue: FINDING-265 - Internal Code Comments Reveal Migration Plans and Technology Stack
**Labels:** bug, security, priority:low
**Description:**
### Summary
Source code comments explicitly state the current encryption scheme (Fernet), planned future scheme (XChaCha20-Poly1305), and that it hasn't been migrated yet.

### Details
If source code is inadvertently exposed, this provides cryptographic implementation intelligence. The info=b'xchacha20_key' parameter is also a technology indicator embedded in the ciphertext derivation chain. This is LOW severity because it requires source code exposure first, which is addressed by other controls.

**CWE:** N/A  
**ASVS:** 13.4.6 (L3)  
**File:** v3/steve/crypto.py:58-69

### Remediation
Ensure deployment processes strip comments and that no source files are accessible via the web tier. Review whether info=b'xchacha20_key' should be updated to a non-descriptive value like b'vote_key_v1'.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 13.4.6.md
- Related: None

### Priority
Low

---

## Issue: FINDING-266 - State-changing operations using GET requests expose operation context in URL history
**Labels:** bug, security, priority:low
**Description:**
### Summary
While EIDs are not themselves highly sensitive data, performing state-changing operations via GET means the operation URL appears in browser history, proxy/CDN logs record the action with the EID, and browser prefetching or link scanners could inadvertently trigger the operation.

### Details
The EIDs themselves are 40-bit entropy identifiers protected by authorization, so the actual data exposure risk is low. However, using GET for state-changing operations is architecturally inappropriate.

**CWE:** N/A  
**ASVS:** 14.2.1 (L1)  
**Files:** v3/server/pages.py (do_open_endpoint, do_close_endpoint)

### Remediation
Convert to POST requests:
```python
@APP.post('/do-open/<eid>')
@asfquart.auth.require({R.committer})
@load_election
async def do_open_endpoint(election):
    ...
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 14.2.1.md
- Related: None

### Priority
Low

---

## Issue: FINDING-267 - Non-cryptographic PRNG used for candidate ordering in voting interface
**Labels:** bug, security, priority:low
**Description:**
### Summary
The application uses `random.shuffle()` (Mersenne Twister, predictable) instead of the available cryptographically secure `crypto.shuffle()` function for shuffling candidates in the voting interface.

### Details
While candidate names are public information, the ordering presented to voters can influence voting behavior (primacy/recency effects). Using a predictable PRNG means an attacker who knows the random seed could predict candidate ordering. The tally code uses `crypto.shuffle()` but the presentation code uses `random.shuffle()`.

**CWE:** N/A  
**ASVS:** 14.2.4 (L2)  
**File:** v3/server/pages.py (vote_on_page)

### Remediation
Replace `random.shuffle(issue.candidates)` with `steve.crypto.shuffle(issue.candidates)`

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 14.2.4.md
- Related: None

### Priority
Low

---

## Issue: FINDING-268 - No data retention controls implemented for closed elections
**Labels:** bug, security, priority:low
**Description:**
### Summary
There is no mechanism to enforce data retention policies for closed elections and their associated votes, superseded votes, person records for individuals no longer in LDAP, or decrypted vote data after tallying.

### Details
The schema documentation states 'Older votes are retained for auditing' but provides no retention limit or purge mechanism. Without retention controls: encrypted vote data persists indefinitely, increasing the risk window for future cryptographic breaks; per-voter salts persist indefinitely, maintaining the ability to link voters to votes; the database grows unboundedly; compliance with privacy regulations requiring data minimization cannot be demonstrated.

**CWE:** N/A  
**ASVS:** 14.2.4, 14.2.7 (L2, L3)  
**Files:** v3/steve/election.py, v3/schema.sql, v3/docs/schema.md

### Remediation
Implement retention lifecycle with methods such as `purge_old_votes()` to remove superseded votes (keep only latest per vote_token), and `archive_and_purge(retention_days=90)` to archive and purge closed election data after retention period, including removing salts and vote_tokens. Additionally, document retention policy in schema.md covering superseded votes, election salts and keys, closed election data, and person records.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 14.2.4.md, 14.2.7.md
- Related: None

### Priority
Low

---

## Issue: FINDING-269 - User email included in every page template context
**Labels:** bug, security, priority:low
**Description:**
### Summary
User's email is included in every page's template context via basic_info() which is called for every page. If templates render this data, it appears on every page even where not needed.

### Details
This is a minor over-exposure of personal data.

**CWE:** N/A  
**ASVS:** 14.2.6 (L3)  
**File:** v3/server/pages.py:87

### Remediation
Only include email in template context where it's specifically needed (e.g., profile page). Remove email from the basic_info() function and add it selectively to page contexts that require it.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 14.2.6.md
- Related: None

### Priority
Low

---

## Issue: FINDING-270 - No Data Lifecycle Management Function for Closed Elections
**Labels:** bug, security, priority:low
**Description:**
### Summary
While the function list_closed_election_ids() exists to list closed elections, there is no corresponding deletion or archival function.

### Details
The function supports identifying elections but provides no lifecycle management capability to enforce data retention schedules.

**CWE:** N/A  
**ASVS:** 14.2.7 (L3)  
**File:** v3/steve/election.py:441-451

### Remediation
Implement a companion function for data lifecycle management:
```python
@classmethod
def archive_old_elections(cls, db_fname, max_age_days=365):
    """Archive and delete elections older than max_age_days after closing."""
    # Export to archive, then delete
    pass
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 14.2.7.md
- Related: None

### Priority
Low

---

## Issue: FINDING-271 - Documents Served Without Metadata Stripping
**Labels:** bug, security, priority:low
**Description:**
### Summary
Documents served from DOCSDIR are returned without any metadata stripping. If these documents were originally submitted by users, they may contain EXIF data, Office document metadata, or PDF metadata.

### Details
However, the provided code does not show a file upload mechanism—documents appear to be admin-placed. If there is a separate upload mechanism not shown here, this is more critical.

**CWE:** N/A  
**ASVS:** 14.2.8 (L3)  
**File:** v3/server/pages.py:605-620

### Remediation
Implement metadata stripping for uploaded files before storing. Use exiftool or similar libraries to remove metadata from images, PDFs, and office documents. Example: Use subprocess to call exiftool with '-all=' flag for JPG, PNG, GIF, TIFF, and PDF files. Add handlers for other file types as needed. Additionally, implement user consent mechanism for metadata storage if metadata needs to be retained.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 14.2.8.md
- Related: None

### Priority
Low

---

## Issue: FINDING-272 - Flash Messages in Session Cookie May Expose Election Titles
**Labels:** bug, security, priority:low
**Description:**
### Summary
Flash messages containing election and issue titles are stored in the session, which in Quart/Flask typically means they are stored in client-side session cookies.

### Details
While election titles are not strictly sensitive data, they could reveal information about private or confidential elections. Flash messages include election creation, opening, closing, and issue management operations.

**CWE:** N/A  
**ASVS:** 14.3.3 (L2)  
**Files:** v3/server/pages.py:443, v3/server/pages.py:466, v3/server/pages.py:485, v3/server/pages.py:510, v3/server/pages.py:534, v3/server/pages.py:554

### Remediation
Replace flash messages containing election/issue titles with generic success messages that do not include potentially sensitive details. For example, use 'Election created successfully.' instead of 'Created election: {form.title}'.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 14.3.3.md
- Related: None

### Priority
Low

---

## Issue: FINDING-273 - No resource management or resilience dependencies declared
**Labels:** bug, security, priority:low
**Description:**
### Summary
The dependency list contains no libraries providing resource management controls such as async task timeouts, connection pooling with limits, circuit breakers, or request size limiting middleware.

### Details
The cryptography library and argon2-cffi are CPU-intensive by design. Without documented resource constraints at the application level, repeated invocation of these operations could degrade availability. Per the known false positive patterns, lack of rate limiting on vote submission is intentional since voters are authenticated ASF committers.

**CWE:** N/A  
**ASVS:** 15.2.2 (L2)  
**File:** v3/pyproject.toml:10-17

### Remediation
Document the security decision regarding resource-demanding functionality (Argon2 hashing, Fernet encryption/decryption). If not already present, consider adding application-level timeouts using asyncio.timeout to wrap resource-intensive operations with a 5-second timeout or similar appropriate limit.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 15.2.2.md
- Related: None

### Priority
Low

---

## Issue: FINDING-274 - Version constraints allow wide range of acceptable versions
**Labels:** bug, security, priority:low
**Description:**
### Summary
Four of six dependencies (`asfpy`, `asfquart`, `ezt`, `easydict`) have no upper version bound. While this is common practice, it means a future major version with breaking changes or a compromised release could be automatically pulled.

### Details
The security-critical packages (`cryptography`, `argon2-cffi`) are properly bounded, which is a positive pattern. Impact: Low — primarily a supply chain management concern. A lock file (if maintained outside this audit scope) would mitigate this.

**CWE:** N/A  
**ASVS:** 15.2.4 (L3)  
**File:** v3/pyproject.toml:10-17

### Remediation
Add upper bounds to all dependencies or ensure a lock file is maintained and committed. Example: `asfpy>=0.56,<1`, `asfquart>=0.1.12,<1`, `ezt>=1.1,<2`, `easydict>=1.13,<2`.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 15.2.4.md
- Related: None

### Priority
Low

---

## Issue: FINDING-275 - No evidence of isolation mechanisms for cryptographic operations
**Labels:** bug, security, priority:low
**Description:**
### Summary
From the pyproject.toml alone, there is no evidence of containerization configuration, sandboxing libraries, network isolation configuration, or process isolation for cryptographic operations.

### Details
The application uses cryptography (Fernet encryption) and argon2-cffi (hashing) which are critical security components. Per ASVS 15.2.5, these should be isolated to limit blast radius if compromised. If a vulnerability is discovered in a dependency, there are no visible architectural barriers preventing lateral movement within the application.

**CWE:** N/A  
**ASVS:** 15.2.5 (L3)  
**File:** v3/pyproject.toml

### Remediation
Document the security architecture decisions regarding component isolation. Consider: 1. Running cryptographic operations in a separate process/service, 2. Adding a Dockerfile with minimal base image and non-root user, 3. Documenting network isolation in deployment configuration

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 15.2.5.md
- Related: None

### Priority
Low

---

## Issue: FINDING-276 - Potential use of requests library without explicit redirect prevention configuration
**Labels:** bug, security, priority:low
**Description:**
### Summary
The presence of `types-requests>=2.32.4,<3` in the lint dependency group strongly suggests that the `requests` library is used in the codebase. The `requests` library follows redirects by default.

### Details
Without source code review, it cannot be confirmed whether: 1. The application makes backend calls to external URLs 2. Whether `allow_redirects=False` is set on such calls 3. Whether the `asfpy`/`asfquart` libraries handle OAuth callbacks with redirect following. If backend HTTP calls exist without `allow_redirects=False`, an attacker could exploit open redirects to reach internal services.

**CWE:** N/A  
**ASVS:** 15.3.2 (L2)  
**File:** v3/pyproject.toml

### Remediation
If the application makes backend HTTP calls, ensure redirects are disabled:
```python
import requests
response = requests.get(url, allow_redirects=False, timeout=10)
```
Or use a session with redirect disabled:
```python
session = requests.Session()
session.max_redirects = 0
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 15.3.2.md
- Related: None

### Priority
Low

---

## Issue: FINDING-277 - EasyDict May Suppress Type Errors Through Permissive Attribute Access
**Labels:** bug, security, priority:low
**Description:**
### Summary
EasyDict converts dictionaries to objects with attribute access. This can mask type issues when user input (always strings from HTTP forms) is compared against expected types without explicit conversion/validation.

### Details
In Python, type juggling risks exist when: String values from forms are compared to integers (e.g., "1" == 1 is False in Python, but int("1") == 1 is True — inconsistent handling); Boolean coercion is relied upon (e.g., empty string vs. None vs. False). Without seeing the actual application logic, this is a dependency-level risk indicator only.

**CWE:** N/A  
**ASVS:** 15.3.5 (L2)  
**File:** v3/pyproject.toml:14

### Remediation
Implement explicit type validation at input boundaries. Example:
```python
from typing import TypedDict

class VoteInput(TypedDict):
    election_id: str
    candidate_id: str

def validate_vote_input(form_data: dict) -> VoteInput:
    if not isinstance(form_data.get("election_id"), str):
        raise ValueError("election_id must be a string")
    if not isinstance(form_data.get("candidate_id"), str):
        raise ValueError("candidate_id must be a string")
    return VoteInput(election_id=form_data["election_id"], candidate_id=form_data["candidate_id"])
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 15.3.5.md
- Related: None

### Priority
Low

---

## Issue: FINDING-278 - Quart/Werkzeug Multi-Value Parameter Handling Not Verifiably Constrained
**Labels:** bug, security, priority:low
**Description:**
### Summary
Quart (built on Werkzeug) uses MultiDict for query parameters and form data, meaning duplicate parameter keys result in multi-valued entries. If the application code inconsistently uses .get() vs .getlist() or passes raw parameter dictionaries to downstream functions, HTTP Parameter Pollution could occur.

### Details
By default: request.args.get("key") returns the first value and request.args.getlist("key") returns all values. Additionally, if request.values (which merges query string and form body) is used, parameters from different sources could conflict. Without the actual route handler code, the specific exposure cannot be confirmed.

**CWE:** N/A  
**ASVS:** 15.3.7 (L2)  
**File:** v3/pyproject.toml:12

### Remediation
Always use explicit parameter source. Use request.form or request.args specifically, never request.values. Reject duplicate parameters explicitly by checking if len(request.form.getlist("parameter_name")) > 1 and returning a 400 error. Example:
```python
from quart import request

@app.route("/vote", methods=["POST"])
async def submit_vote():
    election_id = request.form.get("election_id", type=str)
    if len(request.form.getlist("election_id")) > 1:
        return "Duplicate parameter not allowed", 400
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 15.3.7.md
- Related: None

### Priority
Low

---

## Issue: FINDING-279 - No Thread Pool or Fair Scheduling Configuration Visible
**Labels:** bug, security, priority:low
**Description:**
### Summary
The project configuration does not reference any thread pool management, worker configuration, or fair scheduling mechanisms.

### Details
The application relies on Quart's default async event loop (single-threaded by default) and SQLite's built-in locking. Without explicit configuration of sqlite3 busy timeout, thread pool executor for blocking SQLite operations, or worker/request queue fairness policies, lower-priority or later-arriving requests could starve if SQLite's lock is held by a long-running operation. During election tallying (which involves decryption of all votes), write locks could block new vote submissions indefinitely.

**CWE:** N/A  
**ASVS:** 15.4.4 (L3)  
**File:** v3/pyproject.toml

### Remediation
Configure SQLite busy timeout to prevent indefinite waiting (e.g., conn.execute('PRAGMA busy_timeout = 5000')). Enable WAL mode for concurrent read access (conn.execute('PRAGMA journal_mode = WAL')). For longer operations like tallying, use a dedicated ThreadPoolExecutor with max_workers=2 to run CPU-intensive operations without blocking the event loop. Implement async wrapper:
```python
async def tally_votes(election_id):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(_executor, _sync_tally, election_id)
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 15.4.4.md
- Related: None

### Priority
Low

---

## Issue: FINDING-280 - Date/time operations use naive datetimes without timezone awareness
**Labels:** bug, security, priority:low
**Description:**
### Summary
All datetime operations use naive (timezone-unaware) datetime objects. While not directly a logging issue, this indicates that the application lacks UTC discipline, making it likely that log timestamps (when configured) would also use local time.

### Details
This creates potential for confusion in multi-timezone deployments and makes log correlation difficult.

**CWE:** N/A  
**ASVS:** 16.2.2 (L2)  
**Files:** v3/server/pages.py:86, v3/server/pages.py:571, v3/server/bin/tally.py:86

### Remediation
```python
from datetime import datetime, timezone

# Use UTC-aware datetimes
datetime.now(timezone.utc)
datetime.fromtimestamp(ts, tz=timezone.utc)
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 16.2.2.md
- Related: None

### Priority
Low

## Issue: FINDING-281 - Tally script outputs decrypted vote results to stdout without log governance
**Labels:** bug, security, priority:low
**Description:**
### Summary
The tally script outputs sensitive decrypted election results (voter identities and vote tallies) directly to stdout without any audit logging or governance controls. This creates a risk that sensitive voting data could be inadvertently captured in shell history, piped to insecure files, or logged by terminal multiplexers.

### Details
**File:** `v3/server/bin/tally.py` (lines 129-135)

The tally CLI tool outputs election results to stdout as its primary function, but there is no logging of:
- Who executed the tally operation
- Where the output was directed
- What data was exposed

Without documentation of how tally outputs should be secured, results containing sensitive voter information could be:
- Captured in shell history files
- Redirected to world-readable files
- Logged by terminal multiplexers (tmux, screen)
- Captured by system logging daemons

This violates ASVS 16.2.3 (Level 2) requirements for security event logging.

### Remediation
1. Add audit logging when results are output:
```python
_LOGGER.info(f'TALLY_OUTPUT election_id={election.eid} format={output_format} issues={len(results)} voters={len(all_voters)}')
```

2. Document in the logging inventory that:
   - Tally output goes to stdout
   - Must be handled per data classification policy
   - Recommend secure output practices (e.g., direct to encrypted files, secure terminals only)

3. Consider adding a `--secure-output` flag that writes to a protected file instead of stdout

### Acceptance Criteria
- [ ] Audit logging added to tally.py before results output
- [ ] Logging includes: election_id, timestamp, user (if available), output format, record counts
- [ ] Documentation added describing secure tally output handling procedures
- [ ] Test added to verify audit log entry is created during tally operations

### References
- ASVS 16.2.3: Security logging requirements
- CWE: Not applicable
- Domain: Logging and Monitoring

### Priority
Low - While this is sensitive data, it requires privileged access to execute tally operations. The risk is operational rather than exploitable by external attackers.

---

## Issue: FINDING-282 - No request/correlation ID for tracing multi-step operations
**Labels:** bug, security, priority:low
**Description:**
### Summary
Multi-issue vote submissions generate separate log entries without a shared correlation ID, making it difficult to trace all operations belonging to a single HTTP request. This complicates forensic investigation and log analysis for voting sessions.

### Details
**File:** `v3/server/pages.py` (all endpoint handlers)

When a user submits votes for multiple issues in a single request, each vote generates an independent log entry:
```
User[U:123] voted on issue[I:1] in election[E:5]
User[U:123] voted on issue[I:2] in election[E:5]
User[U:123] voted on issue[I:3] in election[E:5]
```

Without a correlation ID, log processors cannot definitively determine these entries are from the same HTTP request without relying on temporal proximity heuristics. This creates challenges for:
- Forensic investigation of specific voting sessions
- Detecting partial failures in multi-vote submissions
- Correlating votes with authentication events
- Performance analysis of request processing

This violates ASVS 16.2.4 (Level 2) requirements for time source correlation.

### Remediation
**Option 1 (Quick fix):**
```python
request_id = str(uuid.uuid4())[:8]
for iid, votestring in votes.items():
    _LOGGER.info(f'request_id={request_id} User[U:{result.uid}] voted on issue[I:{iid}] in election[E:{election.eid}]')
```

**Option 2 (Recommended):**
Use Quart middleware to generate per-request correlation IDs and propagate via contextvars:
```python
from contextvars import ContextVar
request_id_var = ContextVar('request_id', default=None)

@app.before_request
async def set_request_id():
    request_id_var.set(str(uuid.uuid4())[:8])
```

### Acceptance Criteria
- [ ] Correlation ID generation implemented (middleware or per-endpoint)
- [ ] All log entries within a request include the correlation ID
- [ ] Correlation ID format documented (UUID4 substring recommended)
- [ ] Test added verifying multi-vote submission logs share correlation ID

### References
- ASVS 16.2.4: Time source correlation requirements
- CWE: Not applicable
- Domain: Logging and Monitoring

### Priority
Low - This is a logging quality issue that affects operational analysis but doesn't directly expose vulnerabilities.

---

## Issue: FINDING-283 - PersonDB Lookup Failure Handling
**Labels:** bug, security, priority:low
**Description:**
### Summary
When a `PersonNotFound` exception occurs for an authenticated user, the application returns a 404 response but doesn't log this anomalous condition. An authenticated user not being found in PersonDB indicates a potential configuration issue or data integrity problem that should be tracked.

### Details
**File:** `v3/server/pages.py` (lines 303-313)

The exception handler silently catches `PersonNotFound`:
```python
except PersonNotFound:
    return await render_template("error.html", ...), 404
```

This is problematic because:
- The user successfully authenticated (has valid credentials)
- But doesn't exist in the PersonDB (authorization database)
- This mismatch indicates data synchronization issues between authentication and authorization systems
- No log entry is created to track this anomaly

Without logging, administrators cannot:
- Detect authentication/authorization database drift
- Identify patterns of missing user records
- Investigate potential account provisioning failures
- Track the frequency of this error condition

This violates ASVS 16.3.4 (Level 2) requirements for logging of security-relevant failures.

### Remediation
Add warning-level logging when PersonNotFound occurs for authenticated users:
```python
except PersonNotFound:
    _LOGGER.warning(
        f"Authenticated user not found in PersonDB: "
        f"uid={session.get('uid', 'unknown')} "
        f"endpoint={request.endpoint} "
        f"auth_method={session.get('auth_method', 'unknown')}"
    )
    return await render_template("error.html", ...), 404
```

### Acceptance Criteria
- [ ] Warning log added to PersonNotFound exception handler
- [ ] Log includes: uid, endpoint, authentication method, timestamp
- [ ] Log level set to WARNING (not ERROR, as this is handled gracefully)
- [ ] Test added to verify log entry created when PersonNotFound occurs for authenticated user
- [ ] Documentation updated describing this error condition and monitoring recommendations

### References
- ASVS 16.3.4: Security failure logging requirements
- CWE: Not applicable
- Domain: Logging and Monitoring

### Priority
Low - This is a monitoring gap rather than an exploitable vulnerability. The condition is handled safely (404 response), but tracking it would improve operational visibility.

---

## Issue: FINDING-284 - No explicit HTTP method restrictions visible
**Labels:** bug, security, priority:low
**Description:**
### Summary
The application does not have visible global HTTP method restrictions to reject unexpected methods (TRACE, TRACK, DELETE, etc.) on endpoints that shouldn't support them. While the Quart framework likely provides default 405 responses, there's no explicit enforcement or documentation of allowed methods.

### Details
**File:** `v3/server/api.py` (lines 1-21)

The API module defines no routes and contains no method restriction configuration. Potential concerns:
- No visible global rejection of dangerous methods (TRACE for XST attacks)
- No catch-all handler to ensure 405 for undefined methods
- Reliance on framework defaults without explicit verification
- TRACK method (proprietary, deprecated) not explicitly blocked

While Quart (like Flask) typically returns 405 automatically for methods not registered on a route, this behavior should be:
1. Explicitly verified and documented
2. Tested to ensure TRACE/TRACK are blocked
3. Enforced at the application layer, not just framework defaults

This relates to ASVS 4.1.4 (Level 3) requirements for access control enforcement.

### Remediation
Add explicit global method restriction to ensure only safe methods are allowed:

```python
ALLOWED_METHODS = {'GET', 'POST', 'OPTIONS', 'HEAD'}

@APP.before_request
async def enforce_http_methods():
    if request.method not in ALLOWED_METHODS:
        return jsonify({"error": "Method not allowed"}), 405
```

Additionally, configure the web server (Apache/nginx) to block TRACE/TRACK:
```apache
TraceEnable off
```

### Acceptance Criteria
- [ ] Global HTTP method whitelist implemented in before_request handler
- [ ] TRACE and TRACK methods explicitly blocked and tested
- [ ] Web server configuration updated to disable TRACE at infrastructure level
- [ ] Tests added verifying 405 responses for: TRACE, TRACK, DELETE, PUT, PATCH on voting endpoints
- [ ] Documentation updated listing allowed HTTP methods per endpoint type

### References
- ASVS 4.1.4: Access control enforcement requirements (Level 3)
- CWE: Not applicable
- OWASP: HTTP Verb Tampering, Cross-Site Tracing (XST)
- Domain: HTTP Protocol and API Security

### Priority
Low - Quart likely handles this correctly by default, but explicit enforcement provides defense in depth and clear documentation of security boundaries.

---

## Issue: FINDING-285 - No per-message digital signature mechanism observed for highly sensitive transactions
**Labels:** bug, security, priority:low
**Description:**
### Summary
The voting application lacks per-message digital signatures for highly sensitive transactions (vote casting, election management). Without message-level integrity protection beyond TLS, vote submissions could theoretically be tampered with if TLS is terminated at a proxy or if internal traffic is unencrypted.

### Details
**File:** `v3/server/api.py` (lines 1-21)

Currently, the application relies solely on TLS for transport security. This creates integrity risks in scenarios where:
- TLS is terminated at a load balancer/reverse proxy
- Internal traffic between components is unencrypted
- Intermediary systems exist between client and application
- Defense-in-depth is required for critical voting operations

For a voting system handling ballot submissions and election state changes, message integrity cannot be independently verified if TLS is compromised or bypassed. This means:
- Vote submissions could be modified between TLS termination and application processing
- Election configuration changes could be tampered with in internal networks
- No cryptographic proof of message integrity exists at the application layer

While this is a Level 3 (advanced) requirement per ASVS 4.1.5, voting systems may warrant this additional protection given the sensitivity of the data.

### Remediation
Implement request signing for highly sensitive operations using HMAC or digital signatures:

**Option 1: HMAC-based signing**
```python
import hmac
import hashlib

@APP.before_request
async def verify_signature():
    if request.endpoint in ['vote_submission', 'election_update']:
        signature = request.headers.get('X-Signature')
        if not signature:
            return jsonify({"error": "Signature required"}), 401
        
        body = await request.get_data()
        expected = hmac.new(
            SIGNING_KEY.encode(),
            body,
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(signature, expected):
            return jsonify({"error": "Invalid signature"}), 401
```

**Option 2: HTTP Message Signatures (RFC 9421)**
Consider implementing the HTTP Message Signatures standard for standardized request signing.

### Acceptance Criteria
- [ ] Request signing mechanism selected (HMAC, JWS, or RFC 9421)
- [ ] Signing implemented for: vote submission, election state changes, tally operations
- [ ] Signing key management documented (rotation, storage, distribution)
- [ ] Client libraries/documentation updated to include signature generation
- [ ] Tests added verifying: valid signatures accepted, invalid signatures rejected, missing signatures rejected
- [ ] Performance impact assessed (signing/verification overhead)

### References
- ASVS 4.1.5: Per-message digital signature requirements (Level 3)
- RFC 9421: HTTP Message Signatures
- CWE: Not applicable
- Domain: HTTP Protocol and API Security

### Priority
Low - This is a Level 3 (advanced) control. While valuable for defense-in-depth in a voting system, it requires significant implementation effort. Prioritize if: (1) TLS termination occurs at proxies, (2) internal network security is a concern, or (3) regulatory requirements mandate message-level integrity.