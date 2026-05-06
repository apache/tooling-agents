# Security Issues

## Issue: FINDING-010 - No Crypto Agility - Algorithms Hardcoded Without Abstraction or Versioning
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application has no crypto-agility design. All crypto operations directly call specific implementations with hardcoded parameters. There's no configuration, registry, or strategy pattern that would allow swapping algorithms.

### Details
Specific issues:
1. No algorithm abstraction layer
2. No algorithm versioning in stored data: The vote table stores ciphertext without any algorithm identifier
3. No key versioning
4. No re-encryption mechanism
5. Fixed key lengths in schema: Database CHECK constraints enforce exact lengths preventing algorithm changes without schema migration

**ASVS:** 11.2.2 (L2)

**Affected Files:**
- v3/steve/crypto.py (entire file)
- v3/schema.sql

### Remediation
1. Add algorithm version to stored ciphertext: `CREATE TABLE vote (vid INTEGER PRIMARY KEY AUTOINCREMENT, vote_token BLOB NOT NULL, crypto_version INTEGER NOT NULL DEFAULT 1, ciphertext BLOB NOT NULL) STRICT;`
2. Implement a crypto abstraction layer with CRYPTO_VERSIONS dictionary mapping version numbers to algorithm configurations
3. Update create_vote() and decrypt_votestring() functions to accept and use version parameters
4. Provide a re-encryption utility for migration

### Acceptance Criteria
- [ ] crypto_version column added to vote table
- [ ] CRYPTO_VERSIONS abstraction layer implemented
- [ ] create_vote() updated to use versioned algorithms
- [ ] decrypt_votestring() updated to handle multiple versions
- [ ] Re-encryption utility created
- [ ] Test added for multi-version support
- [ ] Migration documentation created

### References
- Source Reports: 11.2.2.md

### Priority
**High** - Lack of crypto agility prevents algorithm upgrades

---

## Issue: FINDING-011 - Non-constant-time comparison in tamper check allows timing oracle
**Labels:** bug, security, priority:high
**Description:**
### Summary
Python's `!=` operator on `bytes` objects performs a short-circuit comparison that returns `False` as soon as the first differing byte is found. An attacker who can observe response timing could potentially determine how many leading bytes of the `opened_key` match, gradually reconstructing the stored key.

### Details
The `opened_key` is derived from election data and serves as the anti-tamper seal; leaking it could allow an attacker to forge tamper checks.

**ASVS:** 11.2.4 (L3)

**Affected Files:**
- v3/steve/election.py:331

### Remediation
Replace the `!=` comparison with `hmac.compare_digest()` to ensure constant-time comparison. Change `return opened_key != md.opened_key` to `return not hmac.compare_digest(opened_key, md.opened_key)` after importing `hmac`.

### Acceptance Criteria
- [ ] hmac.compare_digest() used for key comparison
- [ ] Test added to verify constant-time behavior
- [ ] Documentation updated

### References
- Source Reports: 11.2.4.md

### Priority
**High** - Timing oracle could leak tamper detection keys

---

## Issue: FINDING-012 - No Secrets Management Solution (Key Vault) Integration
**Labels:** bug, security, priority:high
**Description:**
### Summary
All cryptographic operations (key derivation, encryption, decryption, hashing) are performed directly in the application process. Key material is derived in application memory, exists as Python bytes objects on the heap, and is accessible to any code running in the same process (or an attacker who achieves memory read access).

### Details
There is no isolation boundary — no HSM, no separate vault process, no TEE, and no software enclave protecting key material during use. For an L3 application, this is particularly concerning as ASVS 13.3.3 requires an isolated security module to prevent key exposure. Data flow: vote_token + salt → _b64_vote_key() → derived key in Python heap → Fernet object → encryption/decryption in same process.

**ASVS:** 13.3.1, 13.3.3 (L2, L3)

**Affected Files:**
- v3/steve/crypto.py (entire module)
- v3/steve/election.py:75-85
- v3/schema.sql (election table)

### Remediation
Integrate a secrets management solution such as HashiCorp Vault, AWS KMS, or Azure Key Vault to store election salts and opened_keys outside the application database. Example implementation using HashiCorp Vault with KV secrets engine and AppRole authentication. At minimum, use Vault's KV secrets engine for secret storage with ACL policies per election. Add key lifecycle metadata with key_created_at and key_version columns to enable future rotation and audit capabilities. Implement secret destruction for closed elections by adding an archive_election() method that zeros out cryptographic material after a defined retention period. For L3 ASVS compliance, integrate a hardware security module (PKCS#11 interface or cloud HSM) for key generation and cryptographic operations.

### Acceptance Criteria
- [ ] Secrets management solution integrated
- [ ] Election salts stored in vault
- [ ] opened_keys stored in vault
- [ ] Key lifecycle metadata added
- [ ] Secret destruction implemented for closed elections
- [ ] HSM integration for L3 compliance (optional)
- [ ] Test added for vault integration
- [ ] Documentation added for secrets management

### References
- Source Reports: 13.3.1.md, 13.3.3.md

### Priority
**High** - Cryptographic keys stored in application memory without isolation

---

## Issue: FINDING-013 - Single Database File Provides Unrestricted Access to All Secrets
**Labels:** bug, security, priority:high
**Description:**
### Summary
The SQLite architecture stores all cryptographic secrets (election salts, opened_keys, per-voter salts) in the same database file as non-sensitive metadata (titles, person names, emails). Any process or user with read access to the database file can extract all secrets.

### Details
There is no row-level or column-level access control, and no separation between the secret store and the application data store. Any code path with db_fname can obtain full read/write access to election.salt, election.opened_key, mayvote.salt, and vote.ciphertext. The tally_issue method demonstrates that any caller who reaches it can decrypt ALL votes for an issue without additional per-secret access control.

**ASVS:** 13.3.2 (L2)

**Affected Files:**
- v3/steve/election.py:40
- v3/schema.sql

### Remediation
1. Separate secret material into a distinct storage mechanism with independent access controls
2. Implement application-level access control that verifies the caller's authorization before exposing per-voter salts
3. Consider encrypting the salt columns with a master key managed by a vault
4. Implement a SecretAccessLayer class that mediates access to cryptographic secrets with least privilege, restricting access to election keys to admin/tally roles only and voter salts to the specific voter or tally role

### Acceptance Criteria
- [ ] Secret storage separated from application data
- [ ] Application-level access control implemented
- [ ] SecretAccessLayer class created
- [ ] Least privilege access enforced
- [ ] Test added for access control enforcement
- [ ] Documentation added for secret access controls

### References
- Source Reports: 13.3.2.md

### Priority
**High** - All secrets accessible to anyone with database file access

---

## Issue: FINDING-014 - No Expiration or Rotation Mechanism for Cryptographic Secrets
**Labels:** bug, security, priority:high
**Description:**
### Summary
Once generated, cryptographic secrets (election salts, opened_keys, per-voter salts) persist indefinitely in the database with no expiration timestamp or TTL, key versioning mechanism, rotation procedure, or scheduled re-keying.

### Details
For long-running elections or elections that remain in storage after closure, cryptographic material ages without replacement. If a key is compromised, there is no rotation mechanism to limit exposure.

**ASVS:** 13.3.4 (L3)

**Affected Files:**
- v3/schema.sql (election and mayvote tables)
- v3/steve/election.py:75-140

### Remediation
Add expiration and versioning to schema by extending the election table with key_version, key_created_at, and key_expires_at columns. Implement a rotate_encryption_keys() method that rotates election keys if expired and re-encrypts all votes with new key material, updating key metadata including version, created_at, and expires_at timestamps.

### Acceptance Criteria
- [ ] key_version column added to election table
- [ ] key_created_at column added
- [ ] key_expires_at column added
- [ ] rotate_encryption_keys() method implemented
- [ ] Vote re-encryption logic implemented
- [ ] Key metadata updated on rotation
- [ ] Test added for key rotation
- [ ] Test added for expired key detection
- [ ] Documentation added for key lifecycle

### References
- Source Reports: 13.3.4.md

### Priority
**High** - Cryptographic keys persist indefinitely without rotation

---

## Issue: FINDING-015 - No data retention mechanism — opened/closed elections cannot be deleted
**Labels:** bug, security, priority:high
**Description:**
### Summary
Once an election is opened, it can NEVER be deleted through the application. The `assert self.is_editable()` check prevents deletion of opened or closed elections. This means all voter eligibility data, encrypted votes, and person records persist indefinitely.

### Details
There is no automated cleanup, TTL, or scheduled purge mechanism. For elections containing sensitive data (voter identities, participation records), indefinite retention without a defined schedule violates data minimization principles and potentially GDPR/privacy regulations requiring time-bounded retention. After an election is closed and tallied, calling `Election(db, eid).delete()` raises `AssertionError` — the data is permanently locked in the database.

**ASVS:** 14.2.7 (L3)

**Affected Files:**
- v3/steve/election.py:60-77

### Remediation
Implement a purge method that allows deletion of closed elections after a retention period. The method should check that the election is closed, verify the retention period has expired, and then delete votes, mayvote records, issues, and the election record in a transaction. Example implementation: `def purge(self, retention_days=None)` that asserts the election is closed, checks the retention period against close_at timestamp, and performs cascading deletes of all related data.

### Acceptance Criteria
- [ ] purge() method implemented
- [ ] Retention period checking implemented
- [ ] Cascading deletion of all related data
- [ ] Transaction safety ensured
- [ ] Test added for successful purge
- [ ] Test added for retention period enforcement
- [ ] Test added for closed election requirement
- [ ] Documentation added for data retention policy

### References
- Source Reports: 14.2.7.md

### Priority
**High** - Indefinite data retention violates privacy principles

---

## Issue: FINDING-016 - Missing Strong Client Authentication for OAuth Token Endpoint
**Labels:** bug, security, priority:high
**Description:**
### Summary
The token endpoint callback URL format 'https://oauth.apache.org/token?code=%s' only passes the authorization code via query parameter. There is no evidence of client_assertion parameter, client_assertion_type parameter, Mutual TLS configuration, or any client_id or client_secret being injected into the token request.

### Details
While the asfquart framework may inject credentials internally, the URL format token?code=%s with a single format specifier suggests only the code is passed. Without strong client authentication (mutual TLS or private_key_jwt), the client cannot be verified as confidential. This weakens the security of the authorization code exchange, potentially allowing code injection or replay by unauthorized parties.

**ASVS:** 10.4.10, 10.4.16 (L2, L3)

**Affected Files:**
- v3/server/main.py:39-42

### Remediation
Configure client authentication using private_key_jwt or mTLS. For private_key_jwt: Create a client assertion function that generates a JWT signed with the client's private key, including claims for iss, sub, aud, iat, exp, and jti. For mTLS: Configure the HTTP client with client certificate using `ssl_context.load_cert_chain(certfile='client.pem', keyfile='client_key.pem')`. Ensure the asfquart framework sends client credentials with token requests. Example using client_secret_post: Set OAUTH_URL_CALLBACK to 'https://oauth.apache.org/token' and include in the token request body: `code=<code>&client_id=<id>&client_secret=<secret>&grant_type=authorization_code`. Preferably, use private_key_jwt or mTLS for client authentication.

### Acceptance Criteria
- [ ] Client authentication method selected (private_key_jwt or mTLS)
- [ ] Client assertion generation implemented (if using private_key_jwt)
- [ ] Client certificate configured (if using mTLS)
- [ ] Token request updated to include client credentials
- [ ] Test added for client authentication
- [ ] Documentation added for authentication method

### References
- Source Reports: 10.4.10.md, 10.4.16.md

### Priority
**High** - Weak client authentication for OAuth token exchange

---

## Issue: FINDING-017 - Missing ID Token Audience (aud) Claim Validation
**Labels:** bug, security, priority:high
**Description:**
### Summary
The code explicitly overrides the asfquart framework's default OAuth/OIDC configuration (which presumably includes proper OIDC flows with audience validation). The comment 'Avoid OIDC' and the uncertain 'is this really needed right now?' suggest this was done as a quick workaround rather than a deliberate security decision.

### Details
OIDC provides built-in audience restriction via ID Token aud claim (MUST contain client_id per spec), token endpoint client authentication, and standardized token validation procedures. By bypassing OIDC, the application loses these protections that directly satisfy ASVS 9.2.4, creating a false sense of security since the asfquart.auth.require decorator appears to work but doesn't validate audience claims.

**CWE:** CWE-345  
**ASVS:** 10.5.4, 9.2.4 (L2)

**Affected Files:**
- v3/server/main.py:35-49

### Remediation
Configure client_id for audience validation and ensure token validation checks audience. Example implementation:
```python
def create_app():
    import asfquart.generics
    CLIENT_ID = 'steve-voting-app'
    asfquart.generics.OAUTH_URL_INIT = (
        f'https://oauth.apache.org/auth?client_id={CLIENT_ID}&state=%s&redirect_uri=%s'
    )
    asfquart.generics.OAUTH_URL_CALLBACK = 'https://oauth.apache.org/token?code=%s'
    app = asfquart.construct('steve', app_dir=THIS_DIR, static_folder=None)
    app.config['OAUTH_CLIENT_ID'] = CLIENT_ID
    # In token validation callback:
    assert id_token['aud'] == CLIENT_ID
```

### Acceptance Criteria
- [ ] client_id configured
- [ ] Audience validation implemented in token validation
- [ ] OIDC flow restored or audience validation added to custom flow
- [ ] Test added for audience validation
- [ ] Test added for invalid audience rejection
- [ ] Documentation updated to explain authentication flow

### References
- Source Reports: 10.5.4.md, 9.2.4.md

### Priority
**High** - Missing audience validation allows token reuse across applications

---

## Issue: FINDING-018 - Inconsistent Authentication Strength Between Election Creation and Management
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application enforces a higher privilege level (R.pmc_member) for creating elections than for managing them (R.committer). This inconsistency means a lower-privileged user (committer, not PMC member) can perform more impactful operations such as opening/closing elections and modifying issues.

### Details
This is a gap in authentication pathway consistency where different pathways to affect election state have different strength requirements.

**CWE:** CWE-863  
**ASVS:** 6.3.4 (L2)

**Affected Files:**
- v3/server/pages.py

### Remediation
Ensure management operations require at least the same privilege level as creation, or implement proper owner-based authorization checking. Management operations should either require R.pmc_member status or implement the owner/authz checks to ensure consistent security controls.

### Acceptance Criteria
- [ ] Privilege requirements aligned between creation and management
- [ ] Owner-based authorization implemented (if applicable)
- [ ] Test added for privilege enforcement
- [ ] Documentation updated for access control model

### References
- Source Reports: 6.3.4.md

### Priority
**High** - Inconsistent privilege requirements allow lower-privileged users to perform high-impact operations

---

## Issue: FINDING-019 - State-Changing Operations Use GET Method, Bypassing CSRF and Browser Security Mechanisms
**Labels:** bug, security, priority:high
**Description:**
### Summary
The do-open and do-close endpoints use GET methods for state-changing operations. This allows these operations to be triggered by any cross-origin reference such as img tags, link prefetch, or other browser mechanisms.

### Details
Combined with the lack of authorization checks, this creates an undocumented pathway where elections can be manipulated without the user even visiting the application, simply by loading a malicious image or link.

**CWE:** CWE-352  
**ASVS:** 6.3.4 (L2)

**Affected Files:**
- v3/server/pages.py

### Remediation
Change state-modifying operations to POST methods and implement proper CSRF protection. Example:
```python
@APP.post('/do-open/<eid>')
@asfquart.auth.require({R.committer})
@load_election
async def do_open_endpoint(election):
    await verify_csrf_token()
    await check_election_authz(election, (await basic_info()).uid)
    election.open(pdb)
    ...
```

### Acceptance Criteria
- [ ] do-open endpoint converted to POST
- [ ] do-close endpoint converted to POST
- [ ] CSRF protection implemented
- [ ] Authorization checks added
- [ ] Test added for POST requirement
- [ ] Test added for CSRF protection
- [ ] Client-side code updated to use POST

### References
- Source Reports: 6.3.4.md
- Related: FINDING-002, FINDING-005, FINDING-138

### Priority
**High** - GET methods for state-changing operations enable trivial CSRF attacks

---

## Issue: FINDING-020 - Vote Submission Lacks Explicit Voter Eligibility Check
**Labels:** bug, security, priority:high
**Description:**
### Summary
The do_vote_endpoint function lacks an explicit voter eligibility check before processing votes. Authorization relies on an implicit side-effect where add_vote() throws an AttributeError when accessing mayvote.salt if mayvote is None.

### Details
This is a Type C gap where the control (mayvote lookup) is called but its result isn't explicitly validated before use. The pattern is fragile and could be silently broken by code refactoring (e.g., adding a default value to mayvote.salt). While the generic error message prevents information leakage, the lack of explicit authorization checking violates secure coding principles.

**CWE:** CWE-285  
**ASVS:** 8.2.2, 8.3.1, 2.2.3 (L1, L2)

**Affected Files:**
- v3/server/pages.py:407-430
- v3/steve/election.py:254-268

### Remediation
In the add_vote() method in election.py, add explicit eligibility check immediately after q_get_mayvote.first_row(pid, iid): `if mayvote is None: raise NotEligibleToVote(f'User {pid} not eligible to vote on issue {iid}')`. Define custom NotEligibleToVote exception class. This makes the authorization check explicit and intentional rather than relying on implicit AttributeError. Update do_vote_endpoint to catch NotEligibleToVote and return appropriate 403 response with clear error message.

### Acceptance Criteria
- [ ] NotEligibleToVote exception class defined
- [ ] Explicit eligibility check added to add_vote()
- [ ] do_vote_endpoint updated to handle exception
- [ ] Test added for eligible voter acceptance
- [ ] Test added for ineligible voter rejection
- [ ] Error messages reviewed for information leakage

### References
- Source Reports: 8.2.2.md, 8.3.1.md, 2.2.3.md

### Priority
**High** - Implicit authorization check is fragile and could be bypassed

---

*[Continuing with remaining 20 findings in next response due to length...]*

---

## Issue: FINDING-021 - Management Endpoints Expose Sensitive Election Metadata Without Authorization

**Labels:** bug, security, priority:high

**Description:**

The manage_page endpoint exposes sensitive election metadata fields (owner_pid, authz LDAP group, issue kv data including STV candidate lists and seat counts) to any authenticated committer without verifying ownership or authorization. Any authenticated committer can view election configuration for any election by knowing or guessing the 10-character hex EID. This results in unauthorized field-level data exposure including: authz LDAP group name (reveals organizational structure), owner_pid (reveals election administrator identity), issue kv data (reveals STV candidate lists, seat counts before election opens), and full issue titles and descriptions (potentially confidential ballot topics). This violates field-level access control requirements (BOPLA).

**Remediation:** Add await check_election_authz(election, result.uid) to manage_page and manage_stv_page immediately after basic_info() call and before displaying any election data. Implement is_authorized_manager() function that validates user's uid against md.owner_pid and md.authz LDAP group membership. Return 403 Forbidden if not authorized. This ensures backend authorization enforcement matches UI-level filtering and prevents information disclosure through direct URL navigation.

**Priority:** High

---

## Issue: FINDING-022 - Shared Database Without Tenant-Level Data Isolation

**Labels:** bug, security, priority:high

**Description:**

All elections for all organizational groups (tenants) share a single SQLite database (steve.db) with no row-level security. The authz field provides logical tenancy, but query methods like list_closed_election_ids() return ALL elections without tenant filtering. The method has no tenant parameter, meaning any code calling it gets cross-tenant data. While CLI access to all elections is documented as intentional for administrative purposes, the lack of tenant filtering in query methods means administrative functions have access to ALL elections across all tenant boundaries without explicit authorization checks or audit trails.

**Remediation:** Add tenant filtering to list_closed_election_ids() method by adding an authz_filter parameter. When authz_filter is provided, use a query that filters by the authz group (e.g., q_closed_election_ids_by_authz = 'SELECT eid FROM election WHERE state = ? AND authz = ? ORDER BY close_at DESC'). Only allow unfiltered access for admin CLI operations with explicit authorization and audit logging. Apply similar tenant filtering to any other cross-election queries used by the web interface. Document which functions are intentionally cross-tenant for administrative purposes.

**Priority:** High

---

## Issue: FINDING-023 - No Absolute Maximum Session Lifetime Enforced

**Labels:** bug, security, priority:high

**Description:**

The application code contains no absolute session lifetime limit, no session creation timestamp stored in session data, no validation of session age before granting access, and no documented security decision regarding maximum session lifetime. User authenticates, session is created with no creation timestamp, session is used over days/weeks/months, no absolute expiration is enforced, and session remains valid permanently as long as it exists. For an election system where elections have defined open/close periods, a session that outlives an election's lifecycle could allow unintended access patterns. A compromised session token could be used indefinitely by an attacker. Even if a user changes their password or credentials are rotated, the existing session may remain valid. This is particularly concerning for election management operations where election states are time-sensitive.

**Remediation:** Implement absolute session lifetime enforcement: 1) Add SESSION_MAX_LIFETIME configuration (e.g., 8 hours), 2) Store session creation timestamp in session data (session['created_at'] = time.time()), 3) Validate session age in basic_info() or middleware before granting access, 4) Destroy session and return 401 if session exceeds maximum lifetime, 5) Document security decision regarding chosen lifetime value based on risk analysis.

**Priority:** High

---

## Issue: FINDING-024 - No logout endpoint exists - users cannot terminate sessions

**Labels:** bug, security, priority:high

**Description:**

The application defines 21 routes across GET and POST methods, but NONE of them implement session termination functionality. There is no /logout endpoint, no session destruction call (asfquart.session.destroy() or equivalent), and no mechanism to invalidate sessions on expiration. Users cannot actively terminate their sessions. If a user accesses the system from a shared computer, the next user can access election management features. Combined with the absence of timeouts (7.3.1, 7.3.2), sessions effectively persist indefinitely. This is a Type A gap — the entry point (logout) does not exist at all.

**Remediation:** Implement a logout endpoint that destroys the session on the backend and clears the session cookie:

python
@APP.get('/logout')
@APP.post('/logout')
async def logout():
    """Terminate the user's session."""
    # Destroy the session on the backend
    await asfquart.session.destroy()
    
    # Clear session cookie
    response = quart.redirect('/', code=303)
    response.delete_cookie('session')
    
    _LOGGER.info(f'User logged out')
    return response


**Priority:** High

---

## Issue: FINDING-025 - No session termination when user account is deleted or disabled

**Labels:** bug, security, priority:high

**Description:**

The system has a c_delete_person SQL query defined in queries.yaml but no application-level code that terminates sessions when a person is deleted. There is no session store indexed by person ID (PID) for bulk invalidation, no mechanism to link active sessions to person records, and no disabled flag in the person table schema for soft-disabling accounts. When a person's account is deleted (e.g., they leave the organization), their active sessions continue to work, allowing them to continue to vote, manage elections, or access sensitive election data until their session naturally expires.

**Remediation:** Implement delete_person function that first terminates all active sessions for the user (via terminate_all_sessions_for_user) before deleting the person record. Add session-to-user mapping in session store to enable bulk invalidation by user ID. For server-side sessions, use DELETE FROM sessions WHERE user_id = ?. For JWTs, add PID to revocation list or update per-user invalidation timestamp. Log all person deletions and session terminations.

**Priority:** High

---

## Issue: FINDING-026 - No administrative capability to terminate active sessions

**Labels:** bug, security, priority:high

**Description:**

There is no administrative capability to terminate active sessions for individual users or all users. The `/admin` page (line 279) only shows election management functionality. No session management endpoints exist anywhere in the application code. If a user account is compromised or a user leaves the organization, administrators cannot force session invalidation. Active compromised sessions persist until natural expiration, extending the window for unauthorized access to election data and voting.

**Remediation:** Implement an admin session management interface with endpoints for viewing active sessions, terminating sessions for individual users, and terminating all sessions. Add proper admin role definition and implement session store with termination API. Example implementation includes: `/admin/sessions` GET endpoint to list all active sessions, `/admin/sessions/terminate/<uid>` POST endpoint to terminate sessions for a specific user, and `/admin/sessions/terminate-all` POST endpoint to invalidate all active sessions. All endpoints should require proper admin role authorization and log administrative actions.

**Priority:** High

---

## Issue: FINDING-027 - Missing User Session Viewing and Termination Functionality

**Labels:** bug, security, priority:high

**Description:**

There is no functionality for users to view their currently active sessions or terminate specific sessions. The /profile and /settings pages do not include any session management capabilities. No endpoints exist for listing or invalidating user sessions. Users cannot detect if their account is being used from unauthorized locations/devices. If a session is compromised, the legitimate user has no mechanism to revoke it other than the single "Sign Out" link (which only terminates their current session). This is especially critical for a voting system where unauthorized session use could result in fraudulent votes.

**Remediation:** Implement three new endpoints: (1) GET /sessions - Display all active sessions for the authenticated user with metadata (device, time, location), marking the current session. (2) POST /sessions/terminate/&lt;session_id&gt; - Allow termination of a specific session after re-authentication with at least one factor. (3) POST /sessions/terminate-all - Terminate all sessions except the current one, also requiring re-authentication. All termination operations must verify user identity through re-authentication before execution. Add session listing data to the profile template and create a new sessions.ezt template for the session management interface.

**Priority:** High

---

## Issue: FINDING-028 - Voting operation lacks step-up authentication or secondary verification

**Labels:** bug, security, priority:high

**Description:**

Voting — a highly sensitive operation in an election system — does not require step-up authentication or secondary verification. Once a user has an active session, they can cast votes with no additional verification. An attacker with a hijacked session (via XSS exploitation facilitated by the placeholder CSRF token) can cast votes on behalf of the victim without any additional authentication challenge. In a voting system, casting votes is the most sensitive operation. Without step-up authentication, a compromised session directly leads to election manipulation. Combined with the non-functional CSRF protection (line 83: basic.csrf_token = 'placeholder'), this creates a critical attack surface for vote manipulation via session hijacking or CSRF.

**Remediation:** Implement step-up authentication that requires recent re-authentication for sensitive operations. Example implementation: Create a require_step_up_auth function that checks if the last step-up authentication occurred within a validity window (e.g., 5 minutes). If not, redirect to a step-up authentication page before allowing the vote operation to proceed. Store the last_step_up_auth timestamp in the session and validate it before processing votes.

**Priority:** High

---

## Issue: FINDING-029 - State-Changing GET Endpoints Enable Session Creation + Action Without User Interaction

**Labels:** bug, security, priority:high

**Description:**

State-changing operations (opening/closing elections) are exposed as GET endpoints with authentication decorators. This creates a compound violation where silent session creation can be immediately followed by sensitive state changes without explicit user interaction. When a user has an expired RP session but active IdP session, an attacker can craft a link that triggers OAuth flow, creates a new session at the RP, and immediately executes a state-changing operation (election opened/closed). The data flow: User has expired RP session but active IdP session → Attacker crafts link to /do-open/abc1234567 → User clicks link → Auth decorator triggers OAuth flow with silent re-auth at IdP → New session created at RP → State-changing operation executes. An attacker who can induce a user to click a link or load an image can trigger election state changes without the user's knowledge or explicit consent.

**Remediation:** Convert state-changing operations from GET to POST and require CSRF token validation. Change @APP.get to @APP.post for do_open_endpoint and do_close_endpoint functions. Implement and validate CSRF tokens (not placeholder) in these endpoints before executing state changes. This prevents link-triggered session creation combined with immediate state changes.

**Priority:** High

---

## Issue: FINDING-036 - Authenticated Document Endpoint Serves Resources Without Cross-Origin-Resource-Policy or Sec-Fetch-* Validation

**Labels:** bug, security, priority:high

**Description:**

The serve_doc endpoint serves authenticated election documents without Cross-Origin-Resource-Policy headers or Sec-Fetch-* validation. Authenticated election documents (images, diagrams, PDFs) can be loaded on attacker pages via cross-origin img/video/object/embed tags, leaking confidential election materials. This creates a timing/existence oracle where attackers can determine whether a user has mayvote access to specific elections by checking load success/failure. With permissive CORS or browser bugs, pixel-level data extraction from images is possible.

**Remediation:** 1. Validate Sec-Fetch-Site and Sec-Fetch-Dest headers, only allowing 'same-origin', 'none' (direct navigation), or empty string. Reject all other values with 403. 2. Add 'Cross-Origin-Resource-Policy: same-origin' response header to all document responses to prevent cross-origin embedding at the browser level.

**Priority:** High

---

## Issue: FINDING-037 - Missing Comprehensive Session Cookie Security Configuration

**Labels:** bug, security, priority:high

**Description:**

The application does not explicitly configure critical security attributes for session cookies including: Secure attribute, __Host-/__Secure- prefix, HttpOnly attribute, and SameSite attribute. While the asfquart framework may provide some defaults internally, no explicit cookie security configuration exists in the application code. This creates dependency on undocumented framework behavior and leaves session cookies vulnerable to: (1) interception via network sniffing if transmitted over unencrypted connections, (2) cross-site request forgery attacks due to missing SameSite protection, (3) JavaScript access via XSS due to unverified HttpOnly enforcement, and (4) subdomain cookie injection attacks due to missing __Host- prefix. The session cookie is created by the framework without explicit security hardening in v3/server/main.py.

**Remediation:** Explicitly configure all session cookie security attributes in the create_app() function:

app.config.update(
    SESSION_COOKIE_NAME='__Host-steve_session',
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict',
    SESSION_COOKIE_PATH='/',
)

This ensures: (1) Secure attribute prevents transmission over HTTP, (2) __Host- prefix binds cookie to exact host and enforces Secure/Path requirements, (3) HttpOnly prevents JavaScript access, (4) SameSite=Strict prevents cross-site request inclusion.

**Priority:** High

---

## Issue: FINDING-038 - No Content-Security-Policy Header Defined in Any HTTP Response

**Labels:** bug, security, priority:high

**Description:**

The application does not set a Content-Security-Policy header on any HTTP response. Without CSP, the application has no defense-in-depth against cross-site scripting (XSS) attacks, data exfiltration via injected &lt;object&gt;, &lt;embed&gt;, or &lt;base&gt; tags, and clickjacking via embedded frames. The ASVS requirement mandates at minimum: object-src 'none', base-uri 'none', plus either an allowlist or nonces/hashes for script sources. Client requests flow through route handlers to template rendering and HTTP responses without any CSP header being set. An XSS payload would execute without CSP restrictions. Additionally, no CSP violation reporting endpoint is configured (report-uri/report-to directives), meaning XSS exploitation attempts and policy misconfigurations go undetected.

**Remediation:** Implement a global after_request handler in main.py that sets CSP headers on every response:

@app.after_request
async def set_security_headers(response):
    csp = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "frame-ancestors 'self'; "
        "report-uri /csp-report; "
        "report-to csp-endpoint"
    )
    response.headers['Content-Security-Policy'] = csp
    response.headers['Report-To'] = '{"group":"csp-endpoint","max_age":86400,"endpoints":[{"url":"/csp-report"}]}'
    return response

Add CSP violation reporting endpoint:

@APP.post('/csp-report')
async def csp_report():
    report = await quart.request.get_json(force=True)
    _LOGGER.warning(f'CSP Violation: {report}')
    return '', 204

Deploy Content-Security-Policy-Report-Only initially to identify policy violations before enforcement.

**Priority:** High

---

## Issue: FINDING-039 - No frame-ancestors CSP Directive Prevents Clickjacking

**Labels:** bug, security, priority:high

**Description:**

The web application does not set the frame-ancestors directive in the Content-Security-Policy header for any HTTP response. This allows the application to be embedded in iframes on malicious sites, enabling clickjacking attacks. All page handlers return responses without framing protection. The /do-open/&lt;eid&gt; and /do-close/&lt;eid&gt; endpoints use GET methods and perform state-changing operations, making them particularly vulnerable to clickjacking combined with the lack of framing protection. An attacker can create a malicious page with an iframe embedding the application and trick authenticated users into performing unintended actions.

**Remediation:** Implement a global after_request handler that sets the frame-ancestors directive in the Content-Security-Policy header for every response:

@app.after_request
async def set_security_headers(response):
    csp = response.headers.get('Content-Security-Policy', '')
    if 'frame-ancestors' not in csp:
        if csp:
            csp += "; frame-ancestors 'self'"
        else:
            csp = "frame-ancestors 'self'"
    response.headers['Content-Security-Policy'] = csp
    return response

Additionally, convert /do-open/&lt;eid&gt; and /do-close/&lt;eid&gt; from GET to POST methods to reduce clickjacking and CSRF attack surface.

**Priority:** High

---

## Issue: FINDING-040 - Missing Cross-Origin-Opener-Policy Header on HTML Responses

**Labels:** bug, security, priority:high

**Description:**

The application does not set the `Cross-Origin-Opener-Policy` (COOP) header on any HTTP responses that render HTML documents. There is no `after_request` handler, middleware, or framework configuration that adds this header. All template-rendered endpoints (using `@APP.use_template()`) return HTML responses without COOP protection. Without COOP, cross-origin pages that open or are opened by the application can retain references to the `Window` object. This enables tabnabbing attacks (where a malicious page opened via `target=_blank` replaces the opener with a phishing page) and frame-counting side-channel attacks.

**Remediation:** Implement an `after_request` handler to set the COOP header on all HTML responses:

@APP.after_request
async def set_security_headers(response):
    content_type = response.content_type or ''
    if 'text/html' in content_type:
        response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    return response

**Priority:** High

## Issue: FINDING-041 - No TLS Protocol Version Enforcement
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application starts with default TLS versions from Quart/Hypercorn without explicit configuration, potentially allowing negotiation of deprecated TLS 1.0/1.1 protocols depending on runtime environment.

### Details
Config values for certfile and keyfile are passed directly to `app.run()` in `v3/server/main.py` (lines 75-78) without any TLS protocol version constraints. An attacker can attempt handshake with deprecated TLS versions using `openssl s_client -connect localhost:58383 -tls1_1`. Without explicit configuration, older TLS versions may be negotiable depending on Python/OpenSSL library versions.

**ASVS:** 12.1.1 (L1)  
**CWE:** Not specified  
**Affected Files:** v3/server/main.py:75-78

### Remediation
Explicitly configure minimum TLS protocol version to TLS 1.2 and prefer TLS 1.3. For Hypercorn, create an SSL context programmatically:
```python
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.maximum_version = ssl.TLSVersion.TLSv1_3
ctx.load_cert_chain(certfile, keyfile)
```
Add `server.min_tls_version: '1.2'` to config.yaml.

### Acceptance Criteria
- [ ] SSL context configured with minimum TLS 1.2
- [ ] Configuration option added to config.yaml
- [ ] Test added verifying TLS 1.0/1.1 are rejected
- [ ] Test added verifying TLS 1.2/1.3 are accepted

### References
- Source: 12.1.1.md
- Related: FINDING-042, FINDING-043

### Priority
High - Allows deprecated protocol versions that could be exploited

---

## Issue: FINDING-042 - No Cipher Suite Configuration - Weak Ciphers May Be Negotiated
**Labels:** bug, security, priority:high
**Description:**
### Summary
Application has no control over cipher suites, potentially allowing weak ciphers without forward secrecy (RC4, 3DES, RSA key exchange) to be negotiated.

### Details
Without explicit cipher suite configuration in `v3/server/main.py` (lines 75-82), weak ciphers may be negotiated depending on Python/OpenSSL version. This could allow non-forward-secrecy ciphers (RSA key exchange), weak encryption (3DES, RC4), or weak hash algorithms (SHA-1 MACs). For L3 compliance, MUST only support cipher suites providing forward secrecy (ECDHE/DHE key exchange).

**ASVS:** 12.1.2 (L2, L3)  
**CWE:** Not specified  
**Affected Files:** v3/server/main.py:75-82

### Remediation
Create SSL context with explicit cipher suite configuration:
```python
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS:!RC4:!3DES')
ctx.load_cert_chain(certfile, keyfile)
```

### Acceptance Criteria
- [ ] Cipher suite configuration implemented
- [ ] Only forward-secrecy ciphers enabled
- [ ] Test added verifying weak ciphers are rejected
- [ ] Test added verifying strong ciphers are accepted

### References
- Source: 12.1.2.md
- Related: FINDING-041, FINDING-043

### Priority
High - Weak ciphers compromise confidentiality and integrity

---

## Issue: FINDING-043 - TLS Configuration is Optional - Application Allows Plain HTTP
**Labels:** bug, security, priority:high
**Description:**
### Summary
Configuration explicitly documents TLS can be disabled by leaving certfile/keyfile blank, allowing session cookies, OAuth tokens, credentials, and vote data to be transmitted in cleartext.

### Details
When running without TLS, session hijacking is possible, OAuth tokens/credentials are exposed, vote data transmitted unencrypted, and no HSTS enforcement exists. No mechanism redirects HTTP to HTTPS. This is a voting application handling sensitive election data—running without TLS completely undermines confidentiality and integrity.

**ASVS:** 12.2.1, 12.3.1, 12.2.2 (L1, L2)  
**CWE:** Not specified  
**Affected Files:** v3/server/config.yaml.example:6-12, v3/server/main.py:72-82

### Remediation
Enforce TLS at startup by requiring certificates:
```python
if not app.cfg.server.certfile or not app.cfg.server.keyfile:
    _LOGGER.critical('TLS certificates MUST be configured. Set server.certfile and server.keyfile in config.yaml')
    sys.exit(1)

kwargs['certfile'] = CERTS_DIR / app.cfg.server.certfile
kwargs['keyfile'] = CERTS_DIR / app.cfg.server.keyfile
```

### Acceptance Criteria
- [ ] Application fails to start without TLS certificates
- [ ] Clear error message displayed when certificates missing
- [ ] Configuration documentation updated to require TLS
- [ ] Test added verifying startup failure without certificates

### References
- Source: 12.2.1.md, 12.3.1.md, 12.2.2.md
- Related: FINDING-041, FINDING-042

### Priority
High - Plaintext transmission of sensitive voting data

---

## Issue: FINDING-044 - Election Title and Issue Title/Description Have No Server-Side Length or Content Validation
**Labels:** bug, security, priority:high
**Description:**
### Summary
User-supplied text fields (election title, issue title, issue description) passed directly to database without validation in create/add/edit operations, allowing extremely long titles, empty values, or control characters.

### Details
Affects `do_create_endpoint()`, `do_add_issue_endpoint()`, and `do_edit_issue_endpoint()` in `v3/server/pages.py` (lines 410-425, 469-490, 493-515). Extremely long titles could cause display issues, memory exhaustion, or DoS. Empty titles violate logical expectations. No character set validation allows control characters. Affects `gather_election_data()` anti-tamper hash.

**ASVS:** 2.2.1 (L1)  
**CWE:** Not specified  
**Affected Files:** v3/server/pages.py:410-425, 469-490, 493-515

### Remediation
Add server-side validation:
```python
def validate_title(title: str, max_length: int = 200) -> str:
    title = title.strip()
    if not title:
        raise ValueError("Title cannot be empty")
    if len(title) > max_length:
        raise ValueError(f"Title exceeds maximum length of {max_length}")
    return title
```
Return errors via `flash_danger` and redirect on validation failure. Consider database CHECK constraints.

### Acceptance Criteria
- [ ] Title validation implemented (max 200 chars)
- [ ] Description validation implemented (max 10,000 chars)
- [ ] Empty value validation added
- [ ] Tests added for validation edge cases
- [ ] Error messages displayed to users

### References
- Source: 2.2.1.md

### Priority
High - Could cause DoS or data integrity issues

---

## Issue: FINDING-045 - Document Filename (docname) Relies Solely on Framework Protection Without Explicit Validation
**Labels:** bug, security, priority:high
**Description:**
### Summary
`serve_doc()` endpoint serves files based on user-supplied `iid` and `docname` parameters with only framework-level path traversal protection and no explicit validation (acknowledged by TODO comment).

### Details
In `v3/server/pages.py` (lines 560-574), `docname` parameter could contain special characters, encoded sequences, or reference symlinks. `iid` parameter constructs directory path without validating it's a valid 10-char hex string. Depending on framework version and edge cases, could lead to unauthorized file access outside intended document directory.

**ASVS:** 2.2.1 (L1)  
**CWE:** Not specified  
**Affected Files:** v3/server/pages.py:560-574

### Remediation
Implement explicit validation:
```python
import re
DOCNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_\-][a-zA-Z0-9_\-\.]{0,254}$')

if not DOCNAME_PATTERN.match(docname) or '..' in docname or docname.startswith('.'):
    return quart.abort(400, "Invalid filename")
```
Return HTTP 400 for invalid filenames before calling `send_from_directory`.

### Acceptance Criteria
- [ ] Regex validation for docname implemented
- [ ] Validation for iid format added
- [ ] Dot-file and path traversal checks added
- [ ] Tests added for malicious filename patterns
- [ ] TODO comment resolved

### References
- Source: 2.2.1.md
- Related: FINDING-050

### Priority
High - Potential unauthorized file access

---

## Issue: FINDING-046 - Multi-Vote Submission Not Wrapped in Transaction — Partial Failure Leaves Inconsistent State
**Labels:** bug, security, priority:high
**Description:**
### Summary
User ballot submission with multiple issues processes votes one-by-one without transaction, allowing partial submission where some votes succeed and others fail, leaving inconsistent state.

### Details
In `v3/server/pages.py` (line 372), if user submits ballot with 10 issues and vote #5 fails, votes #1-4 are already committed while user sees "error". Atomic ballot submission not guaranteed. Voter's intent is complete ballot, but partial submission creates inconsistent state violating principle that business operations should succeed entirely or roll back.

**ASVS:** 2.3.3, 16.5.3 (L2)  
**CWE:** Not specified  
**Affected Files:** v3/server/pages.py:372

### Remediation
Wrap all votes in transaction:
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
- [ ] Transaction wrapping implemented
- [ ] Rollback on any vote failure
- [ ] Error logging added
- [ ] User feedback for failures
- [ ] Tests for partial failure scenarios

### References
- Source: 2.3.3.md, 16.5.3.md

### Priority
High - Data integrity violation in voting system

---

## Issue: FINDING-047 - Election Open Operation Not Fully Atomic — Salt Addition and State Change in Separate Transactions
**Labels:** bug, security, priority:high
**Description:**
### Summary
`open()` method performs non-atomic sequence (check editable, write salts, change state) without transaction wrapper, allowing concurrent administrators to create inconsistent opened_key and salts.

### Details
In `v3/steve/election.py` (line 70), concurrent `open()` calls can both pass `is_editable()` check, then interleave operations: Admin A's `add_salts()` runs, Admin B's `add_salts()` OVERWRITES salts with different values, Admin A's `c_open.perform()` runs with opened_key based on original salts, Admin B's `c_open.perform()` overwrites opened_key. Result: opened_key and salts inconsistent, breaking tamper detection and preventing proper tallying.

**ASVS:** 2.3.3, 15.4.2 (L2, L3)  
**CWE:** Not specified  
**Affected Files:** v3/steve/election.py:70

### Remediation
Wrap entire `open()` operation in BEGIN IMMEDIATE transaction. Re-check election state within transaction using `_all_metadata()`. If state not editable, rollback and raise `ElectionBadState`. Integrate `add_salts()` operations into same transaction. Include proper exception handling with ROLLBACK on error and COMMIT on success.

### Acceptance Criteria
- [ ] BEGIN IMMEDIATE transaction wrapper added
- [ ] State re-check within transaction
- [ ] add_salts() integrated into transaction
- [ ] Exception handling with rollback
- [ ] Tests for concurrent open() attempts

### References
- Source: 2.3.3.md, 15.4.2.md
- Related: FINDING-074, FINDING-075

### Priority
High - Election integrity violation through race condition

---

## Issue: FINDING-048 - No Validation That close_at Is After open_at When Setting Dates
**Labels:** bug, security, priority:high
**Description:**
### Summary
No cross-field validation ensures `close_at` is after `open_at` when setting dates, allowing logically inconsistent election schedules.

### Details
In `v3/server/pages.py` (lines 88-110), user can set close_at to Jan 1, 2024 then set open_at to Feb 1, 2024, resulting in close_at < open_at which is logically inconsistent. Type A gap where no cross-field consistency validation exists.

**ASVS:** 2.2.3 (L2)  
**CWE:** Not specified  
**Affected Files:** v3/server/pages.py:88-110, v3/steve/election.py

### Remediation
Add validation in `_set_election_date()`:
```python
def _set_election_date(election, field, value):
    if field == 'open_at':
        close_at = election.get_metadata().get('close_at')
        if close_at and value >= close_at:
            return quart.abort(400, "open_at must be before close_at")
    elif field == 'close_at':
        open_at = election.get_metadata().get('open_at')
        if open_at and value <= open_at:
            return quart.abort(400, "close_at must be after open_at")
```

### Acceptance Criteria
- [ ] Cross-field validation implemented
- [ ] Validation for both open_at and close_at
- [ ] Descriptive error messages
- [ ] Tests for invalid date combinations

### References
- Source: 2.2.3.md

### Priority
High - Logical data integrity violation

---

## Issue: FINDING-049 - No file size validation or upload limits enforced
**Labels:** bug, security, priority:high
**Description:**
### Summary
Application serves documents via `/docs/<iid>/<docname>` but has no visible file upload endpoint with size validation, and no global request body size limit configured.

### Details
Mechanism for placing documents into `DOCSDIR` not shown in code, meaning no observable file size checks preventing DoS via excessively large files. Quart application doesn't set `MAX_CONTENT_LENGTH` to limit request body size globally, affecting any future file upload functionality.

**ASVS:** 5.2.1 (L1)  
**CWE:** Not specified  
**Affected Files:** v3/server/pages.py (entire application scope)

### Remediation
1. Configure `APP.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024` (10 MB)
2. In file upload handler:
```python
MAX_FILE_SIZE = 10 * 1024 * 1024
file.seek(0, 2)  # Seek to end
size = file.tell()
file.seek(0)  # Reset
if size > MAX_FILE_SIZE:
    return quart.abort(413, "File too large")
```

### Acceptance Criteria
- [ ] MAX_CONTENT_LENGTH configured
- [ ] File size validation in upload handler
- [ ] HTTP 413 returned for oversized files
- [ ] Tests for size limit enforcement

### References
- Source: 5.2.1.md

### Priority
High - DoS vulnerability through resource exhaustion

---

## Issue: FINDING-050 - Missing file extension and content validation in document serving endpoint
**Labels:** bug, security, priority:high
**Description:**
### Summary
`serve_doc` endpoint serves files without validating file extension against allowlist or verifying content matches extension, potentially serving polyglot files, HTML/SVG with embedded scripts, or files masquerading as safe types.

### Details
In `v3/server/pages.py` (lines 560-574), `docname` parameter passed directly to `send_from_directory` with no check that: (1) file extension matches allowlist, (2) file content (magic bytes) matches extension, (3) file is safe to download. Comment explicitly acknowledges gap. Could lead to stored XSS or serving malicious files.

**ASVS:** 5.2.2, 5.3.1 (L1)  
**CWE:** Not specified  
**Affected Files:** v3/server/pages.py:560-574

### Remediation
```python
import magic
ALLOWED_EXTENSIONS = {'.pdf', '.txt', '.png', '.jpg', '.jpeg'}
ALLOWED_MIMES = {'application/pdf', 'text/plain', 'image/png', 'image/jpeg'}

ext = Path(docname).suffix.lower()
if ext not in ALLOWED_EXTENSIONS:
    return quart.abort(400, "File type not allowed")

file_path = DOCSDIR / iid / docname
mime = magic.from_file(str(file_path), mime=True)
if mime not in ALLOWED_MIMES:
    return quart.abort(400, "File content validation failed")

response.headers['X-Content-Type-Options'] = 'nosniff'
response.headers['Content-Disposition'] = 'attachment'
```

### Acceptance Criteria
- [ ] Extension allowlist implemented
- [ ] Magic byte validation added
- [ ] Security headers set
- [ ] Symlink check added
- [ ] Tests for malicious file types

### References
- Source: 5.2.2.md, 5.3.1.md
- Related: FINDING-045

### Priority
High - XSS and malicious file serving risk

---

## Issue: FINDING-051 - No logging inventory or documentation exists for the application stack
**Labels:** bug, security, priority:high
**Description:**
### Summary
Application uses Python's logging across three layers (web, election library, CLI) but no logging inventory document exists defining what events are logged, format, storage, access control, or retention.

### Details
`logging.basicConfig(level=logging.INFO)` in tally.py sends to stderr by default. Web layer relies on undocumented framework configuration. Election.py library logs with no explicit handler configuration. No documentation of: what events logged at each layer, log format specification, storage location, access controls, retention periods, monitoring/alerting consumption.

**ASVS:** 16.1.1 (L2)  
**CWE:** Not specified  
**Affected Files:** v3/server/bin/tally.py:165, v3/server/pages.py:37, v3/steve/election.py:27

### Remediation
Create `LOGGING_INVENTORY.md`:
```markdown
| Layer | Component | Logger | Events | Format | Destination | Retention | Access |
|-------|-----------|--------|--------|--------|-------------|-----------|--------|
| Web | pages.py | _LOGGER | Auth, votes, admin | JSON | /var/log/steve/, SIEM | 90d | root:adm 640 |
| Library | election.py | _LOGGER | State changes, crypto | JSON | /var/log/steve/, SIEM | 1y | root:adm 640 |
| CLI | tally.py | _LOGGER | Tally operations | JSON | /var/log/steve/, SIEM | 1y | root:adm 640 |
```

### Acceptance Criteria
- [ ] LOGGING_INVENTORY.md created
- [ ] All layers documented
- [ ] Format specifications defined
- [ ] Retention policies documented
- [ ] Access controls specified

### References
- Source: 16.1.1.md

### Priority
High - Foundational security monitoring requirement

---

## Issue: FINDING-052 - Election library logging omits WHO (actor) metadata from security events
**Labels:** bug, security, priority:high
**Description:**
### Summary
Election.py library logs creation, update, and state-change events without recording WHO performed the action, creating blind spots in audit trail especially for CLI/API operations bypassing web layer.

### Details
In `v3/steve/election.py` (lines 207, 219, 231, 430), while pages.py adds user context at handler level, library-level logs missing actor (PID/UID). If library invoked through different path (tally.py, future APIs, direct imports), WHO metadata entirely absent. During incident investigation, impossible to correlate library-level events with triggering user.

**ASVS:** 16.2.1 (L2)  
**CWE:** Not specified  
**Affected Files:** v3/steve/election.py:207, 219, 231, 430

### Remediation
Option 1: Pass actor context to library methods:
```python
def add_issue(self, title, description, vtype, kv, actor_pid=None):
    _LOGGER.info(f'Actor[U:{actor_pid}] added issue to election[E:{self.eid}]')
```
Option 2: Use LoggerAdapter or contextvars to propagate actor identity from web handlers.

### Acceptance Criteria
- [ ] Actor context added to library methods
- [ ] All security events include WHO
- [ ] Tests verify actor logging
- [ ] Documentation updated

### References
- Source: 16.2.1.md
- Related: FINDING-053, FINDING-054

### Priority
High - Critical audit trail gap

---

## Issue: FINDING-053 - Tally script performs security-critical operations without audit logging
**Labels:** bug, security, priority:high
**Description:**
### Summary
Tally script decrypts all votes without logging WHO ran tally, WHEN, WHERE, or WHAT election was tallied. `--spy-on-open-elections` flag use not logged at all, enabling undetected spying on open elections.

### Details
In `v3/server/bin/tally.py` (lines 138-165), administrator could spy on open election results without audit trail. Tamper detection events output via `print()` rather than formal security logging, may not reach monitoring systems. No logging of which administrator ran tally, timestamp, machine/terminal, election tallied, or spy flag usage.

**ASVS:** 16.2.1, 16.4.3 (L2)  
**CWE:** Not specified  
**Affected Files:** v3/server/bin/tally.py:138-165

### Remediation
Add audit logging before outputting results:
```python
_LOGGER.info(
    f'TALLY_OPERATION: user={os.getenv("USER")}, election={election.eid}, '
    f'issues={len(results)}, voters={len(all_voters)}, '
    f'spy_mode={args.spy_on_open_elections}'
)
```

### Acceptance Criteria
- [ ] Audit logging added for tally operations
- [ ] WHO, WHEN, WHERE, WHAT logged
- [ ] Spy flag usage logged
- [ ] Tamper detection uses _LOGGER
- [ ] Tests verify logging

### References
- Source: 16.2.1.md, 16.4.3.md
- Related: FINDING-052, FINDING-058

### Priority
High - Undetectable sensitive operation abuse

---

## Issue: FINDING-054 - Debug print statements dump complete form data which may contain sensitive election configuration
**Labels:** bug, security, priority:high
**Description:**
### Summary
Complete form data dumped to stdout without filtering via `print()` statements. While current forms contain title/description, EasyDict wrapper captures ALL submitted fields including potential future sensitive data.

### Details
In `v3/server/pages.py` (lines 427, 449), `print()` call creates Type B gap—`_LOGGER` system exists but not used here. Any data submitted in forms broadcast to stdout without classification-based filtering. In containerized deployments, stdout captured by orchestrators and may be accessible to operators without appropriate clearance. If future forms include sensitive data (candidate names for confidential elections, authorization groups), would be logged without protection.

**ASVS:** 16.2.5 (L2)  
**CWE:** Not specified  
**Affected Files:** v3/server/pages.py:427, 449

### Remediation
Remove print statements or log only safe metadata:
```python
_LOGGER.debug(f'Issue form received: fields={list(form.keys())}')
# Never log form values for election management operations
```

### Acceptance Criteria
- [ ] Print statements removed or replaced
- [ ] Only safe metadata logged
- [ ] No form values in logs
- [ ] Tests verify no sensitive data logged

### References
- Source: 16.2.5.md

### Priority
High - Sensitive data exposure through logs

---

## Issue: FINDING-055 - No Authentication Event Logging in Application Code
**Labels:** bug, security, priority:high
**Description:**
### Summary
Application relies on `asfquart.auth.require` decorators for authentication but no logging occurs at authentication boundary within application code. No evidence of authentication success or failure logging.

### Details
In `v3/server/pages.py` (entire file), authentication successes and failures invisible to security monitoring. Brute force attempts, credential stuffing, or unauthorized access patterns cannot be detected through application logs.

**ASVS:** 16.3.1 (L2)  
**CWE:** Not specified  
**Affected Files:** v3/server/pages.py (entire file)

### Remediation
Add authentication event logging middleware:
```python
@APP.before_request
async def log_authentication():
    result = asfquart.session.read(APP.cfg.server.cookie_name)
    if result and result.uid:
        _LOGGER.info(
            f'AUTH_SUCCESS: uid={result.uid}, method=oauth, '
            f'ip={quart.request.remote_addr}, path={quart.request.path}'
        )
    elif quart.request.endpoint and quart.request.endpoint != 'index':
        _LOGGER.warning(
            f'AUTH_FAILURE: ip={quart.request.remote_addr}, '
            f'path={quart.request.path}'
        )
```

### Acceptance Criteria
- [ ] Authentication success logging added
- [ ] Authentication failure logging added
- [ ] Metadata includes uid, method, ip, path
- [ ] Tests verify logging

### References
- Source: 16.3.1.md
- Related: FINDING-056, FINDING-057

### Priority
High - No visibility into authentication events

---

## Issue: FINDING-056 - Document Access Authorization Failure Not Logged
**Labels:** bug, security, priority:high
**Description:**
### Summary
Authorization checked for document access but failures not logged. `serve_doc` checks mayvote authorization before serving election documents, but when check fails, returns 404 without logging unauthorized access attempt.

### Details
In `v3/server/pages.py` (lines 596-602), unauthorized attempts to access election documents (potentially sensitive nomination documents) invisible to security monitoring.

**ASVS:** 16.3.2 (L2, L3)  
**CWE:** Not specified  
**Affected Files:** v3/server/pages.py:596-602

### Remediation
Add logging when authorization fails:
```python
if not election.mayvote(result.uid, issue.iid):
    _LOGGER.warning(
        f'AUTHZ_FAILURE: uid={result.uid}, action=document_access, '
        f'election={election.eid}, issue={issue.iid}, doc={docname}, '
        f'ip={quart.request.remote_addr}'
    )
    return quart.abort(404)
```

### Acceptance Criteria
- [ ] Authorization failure logging added
- [ ] Metadata includes uid, document, issue, ip
- [ ] Tests verify logging

### References
- Source: 16.3.2.md
- Related: FINDING-055, FINDING-057

### Priority
High - Unauthorized access attempts invisible

---

## Issue: FINDING-057 - Missing Authorization Logging in State-Changing Operations
**Labels:** bug, security, priority:high
**Description:**
### Summary
Multiple state-changing operations (open, close, set dates, add/edit/delete issues) have comments indicating authorization checks not implemented. Any authenticated committer can modify any election. No logging of whether user is actually election owner.

### Details
In `v3/server/pages.py` (lines 449-470, 472-489), beyond missing authorization, no logging whether user performing action is election owner. Unauthorized modifications logged as successful actions without flagging lack of ownership.

**ASVS:** 16.3.2 (L2, L3)  
**CWE:** Not specified  
**Affected Files:** v3/server/pages.py:449-470, 472-489

### Remediation
Implement ownership-based authorization checks:
```python
owner_pid = election.get_metadata().get('owner_pid')
if result.uid != owner_pid:
    _LOGGER.warning(
        f'AUTHZ_FAILURE: uid={result.uid}, action={action}, '
        f'election={election.eid}, owner={owner_pid}, '
        f'ip={quart.request.remote_addr}'
    )
    return quart.abort(403, "Only election owner can perform this action")

_LOGGER.info(
    f'AUTHZ_SUCCESS: uid={result.uid}, action={action}, '
    f'election={election.eid}'
)
```

### Acceptance Criteria
- [ ] Ownership authorization checks implemented
- [ ] Success and failure logging added
- [ ] All state-changing operations protected
- [ ] Tests verify authorization and logging

### References
- Source: 16.3.2.md
- Related: FINDING-055, FINDING-056

### Priority
High - Unauthorized election modifications possible

---

## Issue: FINDING-058 - Tampering Detection Does Not Use Logger
**Labels:** bug, security, priority:high
**Description:**
### Summary
Tamper detection check uses `print()` instead of logging framework when tampering detected—a critical security event. Print to stdout potentially lost if not captured, lacks structured metadata.

### Details
In `v3/server/bin/tally.py` (lines 153-156), critical tampering events may not reach centralized logging systems. Print to stdout may be lost if process output not captured, lacks structured metadata (timestamp format, severity, correlation IDs).

**ASVS:** 16.3.3, 16.3.4 (L2)  
**CWE:** Not specified  
**Affected Files:** v3/server/bin/tally.py:153-156

### Remediation
Replace `print()` with structured logging:
```python
_LOGGER.error(
    'TALLY_ERROR: election=%s, issue=%s, error_type=%s, error=%s',
    election.eid, issue.iid, type(e).__name__, str(e),
    exc_info=True
)
```

### Acceptance Criteria
- [ ] Print statements replaced with _LOGGER
- [ ] exc_info=True for full exception context
- [ ] Structured format with metadata
- [ ] Tests verify logging

### References
- Source: 16.3.3.md, 16.3.4.md
- Related: FINDING-053, FINDING-059

### Priority
High - Critical security events may be lost

---

## Issue: FINDING-059 - Input Validation Failures Not Logged
**Labels:** bug, security, priority:high
**Description:**
### Summary
Input validation failures (potential bypass attempts) not logged. Malformed input results in validation failure and 400 response with no log entry. Injection attempts caught by validation leave no audit trail.

### Details
In `v3/server/pages.py` (lines 95-102, 385, 393), missing form data check, invalid issue ID check, and date parsing failures have no logging. Prevents detection of attack patterns.

**ASVS:** 16.3.3 (L2)  
**CWE:** Not specified  
**Affected Files:** v3/server/pages.py:95-102, 385, 393

### Remediation
Add logging before validation failures:
```python
_LOGGER.warning(
    'INPUT_VALIDATION_FAILURE: uid=%s, endpoint=%s, reason=%s, '
    'election=%s, ip=%s',
    result.uid, endpoint, reason, election.eid, quart.request.remote_addr
)
return quart.abort(400, reason)
```

### Acceptance Criteria
- [ ] Logging added for all validation failures
- [ ] Metadata includes uid, endpoint, reason, ip
- [ ] Tests verify logging

### References
- Source: 16.3.3.md
- Related: FINDING-058

### Priority
High - Attack attempts invisible to monitoring

---

## Issue: FINDING-060 - User-Controlled Input in Log Messages Without Encoding
**Labels:** bug, security, priority:high
**Description:**
### Summary
Form title value interpolated into log messages without sanitization. While Python f-strings not vulnerable to format string attacks, form.title could contain log injection characters (newlines, ANSI escape sequences) to forge log entries or obscure audit trails.

### Details
In `v3/server/pages.py` (lines 440-443), attacker could inject newlines to create fake log entries or use ANSI codes to manipulate log appearance.

**ASVS:** 16.4.1, 1.3.10 (L2)  
**CWE:** CWE-117  
**Affected Files:** v3/server/pages.py:440-443

### Remediation
Add sanitization utility:
```python
import re

def sanitize_for_log(value: str) -> str:
    """Remove control characters that could enable log injection."""
    return re.sub(r'[\x00-\x1f\x7f]', '', value)

_LOGGER.info(
    f'User[U:{result.uid}] created election[E:{election.eid}]; '
    f'title: "{sanitize_for_log(form.title)}"'
)
```

### Acceptance Criteria
- [ ] Sanitization function implemented
- [ ] Applied to all user input in logs
- [ ] Tests for newline/control character injection
- [ ] Tests verify sanitized output

### References
- Source: 16.4.1.md, 1.3.10.md
- Related: FINDING-187

### Priority
High - Log injection enables audit trail manipulation

---

## Issue: FINDING-061 - No log transmission to a logically separate system
**Labels:** bug, security, priority:high
**Description:**
### Summary
Entire application uses Python's logging with no configuration for transmitting logs to logically separate system. If application server compromised, all security-relevant logs reside on same system and can be modified/deleted by attacker.

### Details
In `v3/server/pages.py:35`, `v3/steve/election.py:7`, `v3/server/bin/tally.py:34,166`, no evidence of: syslog forwarding configuration, centralized log management integration (ELK, Splunk, CloudWatch), log shipping agents/sidecars, remote logging handlers (SocketHandler, HTTPHandler), or file output that could be shipped. All logs written locally only.

**ASVS:** 16.4.3 (L2)  
**CWE:** Not specified  
**Affected Files:** v3/server/pages.py:35, v3/steve/election.py:7, v3/server/bin/tally.py:34,166

### Remediation
Configure remote log transmission:
```python
import logging.handlers

syslog_handler = logging.handlers.SysLogHandler(
    address=('logserver.internal.example.org', 514),
    facility=logging.handlers.SysLogHandler.LOG_AUTH
)
syslog_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(name)s %(levelname)s %(message)s'
))
logging.getLogger().addHandler(syslog_handler)
```

### Acceptance Criteria
- [ ] Remote syslog handler configured
- [ ] Logs transmitted to separate system
- [ ] Configuration documented
- [ ] Tests verify remote transmission

### References
- Source: 16.4.3.md
- Related: FINDING-051

### Priority
High - Logs can be destroyed by attacker

---

## Issue: FINDING-062 - No graceful degradation for database connectivity failures
**Labels:** bug, security, priority:high
**Description:**
### Summary
`load_election` and `load_election_issue` decorators only catch `ElectionNotFound` exceptions. If SQLite database file locked, corrupted, or unavailable, unhandled exception propagates to framework's default error handler. No circuit breaker, retry logic, or graceful degradation.

### Details
Affects ALL routes using `load_election` or `load_election_issue` in `v3/server/pages.py`. Database lock contention, disk failures, or resource exhaustion causes unhandled exceptions across all endpoints, potentially exposing error details and causing service unavailability without informative user messaging.

**ASVS:** 16.5.2 (L2)  
**CWE:** Not specified  
**Affected Files:** v3/server/pages.py (all route handlers), v3/steve/election.py:38

### Remediation
Wrap Election initialization with exception handling:
```python
try:
    election = Election(eid)
except (sqlite3.OperationalError, OSError) as e:
    _LOGGER.error(f'Database unavailable for election {eid}: {e}')
    return quart.Response(
        'Service temporarily unavailable. Please try again later.',
        status=503
    )
```

### Acceptance Criteria
- [ ] Exception handling for database errors
- [ ] HTTP 503 for unavailability
- [ ] Error logging
- [ ] User-friendly error messages
- [ ] Tests for database failure scenarios

### References
- Source: 16.5.2.md

### Priority
High - Unhandled exceptions cause service failures

---

## Issue: FINDING-063 - Implicit authorization failure via None dereference instead of explicit check in add_vote
**Labels:** bug, security, priority:high
**Description:**
### Summary
When person not authorized to vote on specific issue (no mayvote entry), query returns None. Code immediately accesses `mayvote.salt` without checking for None, resulting in AttributeError rather than proper authorization denial.

### Details
In `v3/steve/election.py` (lines 210-211), while vote IS blocked (fail-closed), error response is generic 500 rather than proper 403 Forbidden, and exception may expose details. Represents fragile security boundary depending on accidental crash rather than intentional enforcement.

**ASVS:** 16.5.3 (L2)  
**CWE:** Not specified  
**Affected Files:** v3/steve/election.py:210-211

### Remediation
Add explicit None check:
```python
mayvote = self.q_get_mayvote.first_row(pid, iid)
if mayvote is None:
    raise VoterNotAuthorized(
        f'Person {pid} is not authorized to vote on issue {iid}'
    )
vote_token = crypto.gen_vote_token(md.opened_key, pid, iid, mayvote.salt)
```

### Acceptance Criteria
- [ ] Explicit None check added
- [ ] Custom VoterNotAuthorized exception
- [ ] HTTP 403 returned for unauthorized
- [ ] Tests for unauthorized vote attempts

### References
- Source: 16.5.3.md
- Related: FINDING-046

### Priority
High - Security boundary relies on crash rather than check

---

## Issue: FINDING-064 - No global exception handler defined for the web application
**Labels:** bug, security, priority:high
**Description:**
### Summary
Application defines no "last resort" error handler. No `@APP.errorhandler(Exception)`, `@APP.errorhandler(500)`, or equivalent catch-all to log exceptions, return generic error page, or prevent process crashes.

### Details
In `v3/server/pages.py` (entire file), only `ElectionNotFound`, `IssueNotFound`, and `PersonNotFound` caught in specific locations. Any other exception type (sqlite3.OperationalError, TypeError, KeyError, json.JSONDecodeError) propagates to framework default handler. No guarantee DEBUG mode isn't enabled, error details not logged by custom handler, no alerting/escalation triggered, no consistent error response format.

**ASVS:** 16.5.4 (L3)  
**CWE:** Not specified  
**Affected Files:** v3/server/pages.py (entire file)

### Remediation
Implement global exception handlers:
```python
@APP.errorhandler(Exception)
async def handle_exception(e):
    _LOGGER.error(f'Unhandled exception: {e}', exc_info=True)
    return quart.Response(
        'An unexpected error occurred. Please try again later.',
        status=500
    )

@APP.errorhandler(500)
async def handle_500(e):
    _LOGGER.error(f'Internal server error: {e}')
    return await quart.render_template('error.html', code=500)

@APP.errorhandler(503)
async def handle_503(e):
    return await quart.render_template('error.html', code=503)
```

### Acceptance Criteria
- [ ] Global exception handlers implemented
- [ ] All exceptions logged with full context
- [ ] Generic error pages returned
- [ ] Tests for unhandled exception types

### References
- Source: 16.5.4.md
- Related: FINDING-062

### Priority
High - Unhandled exceptions may expose sensitive details

---

## Issue: FINDING-065 - Unconditional DEBUG logging level in all execution modes
**Labels:** bug, security, priority:high
**Description:**
### Summary
Both execution modes unconditionally set root logging level to DEBUG with no environment-based differentiation. No configuration option to control this in config.yaml.example. DEBUG-level logging can capture sensitive data.

### Details
In `v3/server/main.py` (lines 62-67, 101-106), DEBUG-level logging can capture session tokens, database queries, request payloads that could be exposed through log aggregation systems, error handlers, or inadvertent log exposure.

**ASVS:** 13.4.2, 15.2.3 (L2)  
**CWE:** Not specified  
**Affected Files:** v3/server/main.py:62-67, 101-106

### Remediation
Add environment-aware logging configuration:
```python
# In config.yaml.example:
debug: false
log_level: WARNING

# In main.py:
log_level = getattr(logging, app.cfg.server.get('log_level', 'WARNING').upper())
logging.basicConfig(level=log_level)

if app.cfg.server.get('debug', False):
    _LOGGER.warning('DEBUG MODE ENABLED - Not for production use')
```

### Acceptance Criteria
- [ ] debug and log_level config options added
- [ ] Production-safe defaults (WARNING)
- [ ] Warning logged if debug enabled
- [ ] Tests for different log levels

### References
- Source: 13.4.2.md, 15.2.3.md

### Priority
High - Sensitive data exposure through debug logs

---

## Issue: FINDING-066 - No documented risk-based remediation timeframes for third-party component vulnerabilities
**Labels:** bug, security, priority:high
**Description:**
### Summary
Codebase contains multiple third-party dependencies (cryptography, argon2-cffi, asfpy, easydict, Quart/asfquart, ezt) but no documentation defining risk-based remediation timeframes for addressing vulnerabilities or update cadence.

### Details
No SECURITY.md, DEPENDENCY_POLICY.md, or equivalent documentation defining: Critical vulnerability remediation timeframe (e.g., 24-48 hours), High vulnerability remediation timeframe (e.g., 7 days), Medium/Low vulnerability remediation timeframe (e.g., 30-90 days), or routine update schedule for non-vulnerable components.

**ASVS:** 15.1.1 (L1)  
**CWE:** Not specified  
**Affected Files:** Project-wide (no documentation file found)

### Remediation
Create `docs/DEPENDENCY_POLICY.md`:
```markdown
# Dependency Security Policy

## Remediation Timeframes
- Critical (CVSS ≥ 9.0): 48 hours
- High (CVSS 7.0-8.9): 7 days
- Medium (CVSS 4.0-6.9): 30 days
- Low (CVSS < 4.0): 90 days

## Routine Update Schedules
- Security-critical libraries (cryptography, argon2-cffi): Monthly review
- Framework libraries (Quart/asfquart): Quarterly review
- Utility libraries (easydict, asfpy): Semi-annual review

## Monitoring
- GitHub Dependabot enabled
- pip-audit in CI/CD pipeline
- Manual review of cryptography security advisories
```

### Acceptance Criteria
- [ ] DEPENDENCY_POLICY.md created
- [ ] Remediation timeframes defined
- [ ] Update schedules documented
- [ ] Monitoring procedures specified

### References
- Source: 15.1.1.md
- Related: FINDING-067, FINDING-069

### Priority
High - Foundational dependency security requirement

---

## Issue: FINDING-067 - No Software Bill of Materials (SBOM) or dependency manifest with pinned versions
**Labels:** bug, security, priority:high
**Description:**
### Summary
Codebase doesn't include visible requirements.txt, pyproject.toml with pinned dependencies, Pipfile.lock, uv.lock, or SBOM document. All dependency versions unknown. Without versioned inventory, transitive dependencies untracked, reproducible builds not guaranteed, vulnerability scanning cannot accurately assess dependency tree.

### Details
Identified dependencies from code analysis: cryptography, argon2-cffi, asfpy, easydict, asfquart, ezt - all versions unknown. No verification dependencies come from trusted repositories.

**ASVS:** 15.1.2, 15.2.4 (L2, L3)  
**CWE:** Not specified  
**Affected Files:** Project-wide

### Remediation
1. Create `pyproject.toml`:
```toml
[project]
dependencies = [
    "cryptography>=43.0.0",
    "argon2-cffi>=23.1.0",
    "asfpy>=0.45",
    "easydict>=1.13",
    "quart>=0.19.0",
    "ezt>=1.2",
]
```
2. Generate lock file: `uv lock --generate-hashes`
3. Generate SBOM: `cyclonedx-py environment -o sbom.json`
4. Configure automated SBOM generation in CI/CD

### Acceptance Criteria
- [ ] pyproject.toml with pinned versions
- [ ] Lock file with hash verification
- [ ] SBOM generated in CycloneDX format
- [ ] CI/CD integration for SBOM generation

### References
- Source: 15.1.2.md, 15.2.4.md
- Related: FINDING-066, FINDING-069

### Priority
High - Cannot verify dependency security without version info

---

## Issue: FINDING-068 - Undocumented resource-intensive Argon2 operations with potential denial-of-service impact
**Labels:** bug, security, priority:high
**Description:**
### Summary
Application contains several resource-intensive operations not documented: Argon2 key derivation allocating 64MB per call, tally operations iterating over all voters. For election with 1000 voters and 10 issues, tally_issue() requires 1000 Argon2 calls with potential 64GB aggregate memory demand.

### Details
In `v3/steve/crypto.py` (lines 91-101) and `v3/steve/election.py` (lines 265-324), concurrent vote submissions during peak periods could exhaust server memory. No documentation of resource demands, rate limiting strategy, consumer timeout guidance, or maximum supported election size.

**ASVS:** 15.1.3 (L2)  
**CWE:** Not specified  
**Affected Files:** v3/steve/crypto.py:91-101, v3/steve/election.py:265-324

### Remediation
Create `docs/RESOURCE_ANALYSIS.md`:
```markdown
# Resource Analysis

## Argon2 Key Derivation
- Memory: 64MB per operation
- CPU: ~50ms per operation
- Occurs at: vote submission, tally computation, election opening

## Tally Computation
- Complexity: O(voters × issues) Argon2 operations
- Mitigation: Performed offline via admin CLI

## Vote Submission
- Complexity: 1 Argon2 operation per vote
- Max concurrent: Limited by server memory

## Defense Mechanisms
- CLI-based tally operations
- Authenticated vote submission
- Single-instance architecture limiting parallelism
```

### Acceptance Criteria
- [ ] RESOURCE_ANALYSIS.md created
- [ ] All resource-intensive operations documented
- [ ] Complexity analysis included
- [ ] Mitigation strategies documented

### References
- Source: 15.1.3.md
- Related: FINDING-070, FINDING-076

### Priority
High - DoS risk through resource exhaustion

---

## Issue: FINDING-069 - Cannot verify component versions are within remediation timeframes due to missing version specifications
**Labels:** bug, security, priority:high
**Description:**
### Summary
Since no dependency manifest with pinned versions exists and no remediation policy exists, impossible to verify all components within documented update and remediation timeframes. Known CVEs in dependencies may be present but undetected.

### Details
Specific concerns: (1) cryptography library has frequent security advisories without pinned version, (2) Argon2 Type.D usage in production vs Type.ID in benchmark (OWASP recommends Type.ID), (3) asfpy ASF-internal library with unknown release cadence, (4) HKDF info parameter mismatch suggesting transitional code state.

**ASVS:** 15.2.1 (L1)  
**CWE:** Not specified  
**Affected Files:** v3/steve/crypto.py, Project-wide

### Remediation
1. Pin all dependency versions in pyproject.toml
2. Implement automated vulnerability scanning:
```bash
pip-audit --require-hashes --desc
# or
uv pip audit
```
3. Create dependency update log:
```markdown
| Date | Component | From | To | Reason |
|------|-----------|------|----|----- --|
```

### Acceptance Criteria
- [ ] All versions pinned
- [ ] Automated vulnerability scanning in CI/CD
- [ ] Dependency update log created
- [ ] Initial audit completed

### References
- Source: 15.2.1.md
- Related: FINDING-066, FINDING-067

### Priority
High - Cannot verify security posture of dependencies

---

## Issue: FINDING-070 - Unbounded Argon2 Computation in Tally Operation Without Resource Controls
**Labels:** bug, security, priority:high
**Description:**
### Summary
`tally_issue()` function performs unbounded Argon2 computations (64MB per call) for each eligible voter without resource controls. Election with 1000 eligible voters triggers 1000 sequential Argon2 computations, consuming ~64GB peak memory throughput.

### Details
In `v3/steve/election.py` (lines 245-305), attacker with admin access or exploiting state manipulation bug could trigger repeatedly, causing DoS through memory and CPU exhaustion. `has_voted_upon()` function performs similar unbounded Argon2 iteration proportional to number of issues.

**ASVS:** 15.2.2 (L2)  
**CWE:** Not specified  
**Affected Files:** v3/steve/election.py:245-305

### Remediation
Implement concurrent operation limits:
```python
import asyncio
from concurrent.futures import ThreadPoolExecutor

_argon2_semaphore = asyncio.Semaphore(4)  # Max 4 concurrent operations

async def tally_issue_bounded(self, iid):
    eligible_voters = list(self.q_get_eligible_voters.all_rows(iid))
    
    async def process_voter_batch(batch):
        async with _argon2_semaphore:
            return [self._compute_vote_token(v) for v in batch]
    
    # Process in batches of 50
    for i in range(0, len(eligible_voters), 50):
        batch = eligible_voters[i:i+50]
        await process_voter_batch(batch)
```

### Acceptance Criteria
- [ ] Semaphore-based concurrency limiting
- [ ] Batch processing implemented
- [ ] Memory usage bounded
- [ ] Tests for large elections

### References
- Source: 15.2.2.md
- Related: FINDING-068, FINDING-076

### Priority
High - DoS through unbounded resource consumption

---

## Issue: FINDING-071 - Internal ASF Packages (asfquart, asfpy) Potentially Vulnerable to Dependency Confusion
**Labels:** bug, security, priority:high
**Description:**
### Summary
Both asfquart and asfpy appear to be ASF-internal packages. Without explicit index URLs, version pinning with hash verification, attacker could register packages on public PyPI with higher version number, causing dependency confusion during installation.

### Details
In `v3/server/main.py` (lines 30-31) and `v3/steve/election.py` (line 24), no visible evidence of: pyproject.toml with explicit index URLs, pip.conf/uv configuration pointing to internal package index, version pinning with hash verification, or lock file. Package manager resolution could resolve from public PyPI instead of ASF internal repository.

**ASVS:** 15.2.4 (L3)  
**CWE:** Not specified  
**Affected Files:** v3/server/main.py:30-31, v3/steve/election.py:24

### Remediation
Configure explicit index URLs and pin versions:
```toml
[tool.uv]
index-url = "https://pypi.org/simple/"

[tool.uv.sources]
asfpy = { version = "==X.Y.Z", hash = "sha256:..." }
asfquart = { version = "==X.Y.Z", hash = "sha256:..." }
```

### Acceptance Criteria
- [ ] Index URLs configured
- [ ] Versions pinned with hashes
- [ ] Lock file generated
- [ ] Tests verify correct package sources

### References
- Source: 15.2.4.md
- Related: FINDING-067

### Priority
High - Supply chain attack vector

---

## Issue: FINDING-072 - No Trusted Proxy Configuration for IP Address Handling
**Labels:** bug, security, priority:high
**Description:**
### Summary
Application has no proxy trust configuration (no ProxyFix middleware, no Quart proxy settings), no IP address extraction for logging, no X-Forwarded-For header processing. If deployed behind reverse proxy, cannot distinguish original client IP.

### Details
In `v3/server/pages.py` (entire file), without proper proxy configuration, rate limiting could be bypassed by spoofing X-Forwarded-For headers. Security logs lack client IP context. If session compromised, attacker cannot be distinguished by IP.

**ASVS:** 15.3.4 (L2)  
**CWE:** Not specified  
**Affected Files:** v3/server/pages.py (entire file)

### Remediation
Configure trusted proxy:
```python
from werkzeug.middleware.proxy_fix import ProxyFix

# In application initialization:
app.config['PROXY_FIX_X_FOR'] = 1
app.config['PROXY_FIX_X_PROTO'] = 1

# Or use middleware:
app = ProxyFix(app, x_for=1, x_proto=1)

# Add IP to security logs:
_LOGGER.info(
    f'Security event: uid={uid}, ip={quart.request.remote_addr}, ...'
)
```

### Acceptance Criteria
- [ ] Proxy trust configuration added
- [ ] IP address logged in security events
- [ ] Configuration documented
- [ ] Tests verify IP extraction

### References
- Source: 15.3.4.md

### Priority
High - Rate limiting bypass and forensic analysis limitations

---

## Issue: FINDING-073 - Vote Insertion Uses Non-Thread-Safe Multi-Step Database Access Without Synchronization
**Labels:** bug, security, priority:high
**Description:**
### Summary
`add_vote()` method performs multiple unsynchronized database operations (read metadata, query mayvote, insert vote) without transaction or lock protection. Concurrent HTTP requests create separate Election instances with separate DB connections, leading to potential interleaved database state.

### Details
In `v3/steve/election.py` (lines 242-251), under concurrent voting, autoincrement IDs in vote table reveal insertion order, which combined with authentication logs could correlate voters to votes. Multi-step read-compute-write pattern not atomic, even though SQLite serializes actual writes.

**ASVS:** 15.4.1 (L3)  
**CWE:** Not specified  
**Affected Files:** v3/steve/election.py:242-251

### Remediation
Wrap with asyncio.Lock and add random delay:
```python
import asyncio
import random

_vote_lock = asyncio.Lock()

async def add_vote(self, pid, iid, votestring):
    async with _vote_lock:
        # Perform all operations
        md = self._all_metadata(self.S_OPEN)
        mayvote = self.q_get_mayvote.first_row(pid, iid)
        # ... rest of operations
        
        # Random delay to decorrelate insertion order
        await asyncio.sleep(random.uniform(0, 0.1))
        
        self.c_add_vote.perform(...)
```

### Acceptance Criteria
- [ ] asyncio.Lock wrapping implemented
- [ ] Random delay added
- [ ] Method converted to async
- [ ] Tests for concurrent voting

### References
- Source: 15.4.1.md
- Related: FINDING-074, FINDING-075

### Priority
High - Potential voter-vote correlation

---

## Issue: FINDING-074 - Non-Atomic Check-Then-Use in Vote Recording Allows Voting on Closed Elections
**Labels:** bug, security, priority:high
**Description:**
### Summary
`add_vote()` method performs non-atomic check-then-use operation: checks if election open, then later inserts vote. Between operations, concurrent `close()` call can change election state, allowing votes to be inserted into closed election.

### Details
In `v3/steve/election.py` (lines 242-251), timeline: T1: Voter A calls add_vote(), passes state check (OPEN); T2: Admin calls close(), election state changes to CLOSED; T3: Voter A's c_add_vote.perform() executes, inserting vote into CLOSED election. Violates election integrity.

**ASVS:** 15.4.2, 2.3.4 (L3, L2)  
**CWE:** CWE-367  
**Affected Files:** v3/steve/election.py:242-251

### Remediation
Use single transaction with immediate lock:
```python
def add_vote(self, pid, iid, votestring):
    self.db.conn.execute('BEGIN IMMEDIATE')
    try:
        md = self._all_metadata()
        if self._compute_state(md) != self.S_OPEN:
            raise ElectionBadState('Election is not open for voting')
        
        # Perform all operations within transaction
        mayvote = self.q_get_mayvote.first_row(pid, iid)
        # ... rest of operations
        
        self.db.conn.execute('COMMIT')
    except Exception:
        self.db.conn.execute('ROLLBACK')
        raise
```

### Acceptance Criteria
- [ ] BEGIN IMMEDIATE transaction wrapper
- [ ] State re-check within transaction
- [ ] Rollback on error
- [ ] Tests for concurrent close during vote

### References
- Source: 15.4.2.md, 2.3.4.md
- Related: FINDING-047, FINDING-073, FINDING-075, FINDING-219, FINDING-220

### Priority
High - Election integrity violation through TOCTOU

---

## Issue: FINDING-075 - Inconsistent Transaction Usage — Some Multi-Step Operations Are Transactional, Others Are Not
**Labels:** bug, security, priority:high
**Description:**
### Summary
Inconsistent transaction usage across codebase. `delete` and `add_salts` methods use transactions, but `add_vote` and `open` do not, despite being equally critical for election integrity. Type B gap: control EXISTS but NOT CONSISTENTLY CALLED.

### Details
In `v3/steve/election.py` (multiple methods), inconsistency means code reviewers may incorrectly assume all multi-step operations are safe. Creates maintenance risk and false security confidence.

**ASVS:** 15.4.3 (L3)  
**CWE:** Not specified  
**Affected Files:** v3/steve/election.py (multiple methods)

### Remediation
Wrap `add_vote` in BEGIN IMMEDIATE transaction:
```python
def add_vote(self, pid, iid, votestring):
    self.db.conn.execute('BEGIN IMMEDIATE')
    try:
        # All operations
        self.db.conn.execute('COMMIT')
    except Exception:
        self.db.conn.execute('ROLLBACK')
        raise
```
Apply same pattern to `open()` method and all multi-step operations.

### Acceptance Criteria
- [ ] All multi-step operations use transactions
- [ ] Consistent transaction pattern across codebase
- [ ] Documentation of transaction policy
- [ ] Tests for all transactional operations

### References
- Source: 15.4.3.md
- Related: FINDING-073, FINDING-074

### Priority
High - Inconsistent security controls create vulnerabilities

---

## Issue: FINDING-076 - No Rate Limiting on Vote Submission or Election Creation Enables Resource Exhaustion
**Labels:** bug, security, priority:high
**Description:**
### Summary
Vote submission endpoint has no rate limiting. Authenticated user can submit votes as rapidly as network allows. While system's re-voting design means only last vote counts, rapid automated submission creates race conditions and violates principle that voting systems should enforce realistic human timing.

### Details
In `v3/server/pages.py` (lines 385-425), with 100,000 iterations, table grows by 100,000 rows per issue. Since only latest vote counts, all but last are dead weight consuming storage and slowing tally operations. No rate limiting on election creation either.

**ASVS:** 15.4.4, 2.4.1, 2.4.2, 6.3.1 (L3, L2, L1)  
**CWE:** Not specified  
**Affected Files:** v3/server/pages.py:385-425, v3/steve/election.py

### Remediation
Implement per-user rate limiting:
```python
from quart_rate_limiter import rate_limit
from datetime import timedelta

@APP.route('/do-vote/<eid>', methods=['POST'])
@rate_limit(10, timedelta(minutes=1))  # 10 votes per minute
async def do_vote_endpoint(eid):
    # Track last vote timestamp
    last_vote = get_last_vote_timestamp(result.uid, eid)
    if last_vote and (time.time() - last_vote) < MINIMUM_VOTE_INTERVAL:
        return quart.abort(429, "Please wait before voting again")
    
    # Process vote
    set_last_vote_timestamp(result.uid, eid, time.time())
```

### Acceptance Criteria
- [ ] Rate limiting implemented (10 votes/minute)
- [ ] Minimum interval between votes enforced
- [ ] HTTP 429 returned for rate limit violations
- [ ] Tests for rate limit enforcement

### References
- Source: 15.4.4.md, 2.4.1.md, 2.4.2.md, 6.3.1.md
- Related: FINDING-068, FINDING-070

### Priority
High - DoS and resource exhaustion vulnerability

---

## Issue: FINDING-077 - OAuth Configuration Lacks Audience/Client Identification
**Labels:** bug, security, priority:high
**Description:**
### Summary
OAuth authorization URL (OAUTH_URL_INIT) doesn't include client_id parameter. Without client_id, OAuth server cannot issue audience-restricted tokens. Token obtained by visiting another ASF application could be replayed against STeVe.

### Details
In `v3/server/main.py` (lines 31-35), standard OAuth 2.0 (RFC 6749 §4.1.1) requires client_id in authorization request. Token exchange URL (OAUTH_URL_CALLBACK) only passes authorization code without client credentials. If same OAuth provider signs tokens for multiple relying parties, any token valid everywhere.

**ASVS:** 9.2.4 (L2)  
**CWE:** Not specified  
**Affected Files:** v3/server/main.py:31-35

### Remediation
Include client_id in OAuth requests:
```python
CLIENT_ID = app.cfg.oauth.client_id
OAUTH_URL_INIT = (
    'https://oauth.apache.org/auth?client_id=%s&state=%s&redirect_uri=%s'
)
OAUTH_URL_CALLBACK = (
    'https://oauth.apache.org/token?code=%s&client_id=%s&client_secret=%s'
)
```

### Acceptance Criteria
- [ ] client_id added to authorization URL
- [ ] client_id and client_secret in token exchange
- [ ] Configuration for CLIENT_ID added
- [ ] Tests verify client_id in requests

### References
- Source: 9.2.4.md
- Related: FINDING-078

### Priority
High - Token replay attack across applications

---

## Issue: FINDING-078 - No Token Audience Validation After OAuth Exchange
**Labels:** bug, security, priority:high
**Description:**
### Summary
Session data (uid, fullname, email) consumed directly from `asfquart.session.read()` without validating token issued specifically for STeVe application. No aud claim checked, no iss claim verified. If OAuth provider issues tokens consumable by multiple services, no defense against cross-service token confusion attacks.

### Details
In `v3/server/pages.py` (lines 75-106), by explicitly avoiding OIDC (main.py line 29), application loses standardized aud claim validation that OIDC ID tokens provide. OIDC requires ID token's aud claim contains client_id of relying party.

**ASVS:** 9.2.4 (L2)  
**CWE:** Not specified  
**Affected Files:** v3/server/pages.py:75-106

### Remediation
Add audience and issuer validation:
```python
async def basic_info():
    result = asfquart.session.read(APP.cfg.server.cookie_name)
    
    if result and result.uid:
        # Validate audience
        expected_audience = APP.cfg.oauth.client_id
        token_audience = result.get('aud')
        
        if isinstance(token_audience, list):
            if expected_audience not in token_audience:
                _LOGGER.warning(f'Token audience mismatch: {token_audience}')
                return EasyDict(uid=None, name=None, email=None)
        elif token_audience != expected_audience:
            _LOGGER.warning(f'Token audience mismatch: {token_audience}')
            return EasyDict(uid=None, name=None, email=None)
        
        # Validate issuer
        if result.get('iss') != 'https://oauth.apache.org':
            _LOGGER.warning(f'Token issuer mismatch: {result.get("iss")}')
            return EasyDict(uid=None, name=None, email=None)
    
    return result
```

### Acceptance Criteria
- [ ] Audience validation implemented
- [ ] Issuer validation implemented
- [ ] Handles both string and list audience
- [ ] Tests for token validation

### References
- Source: 9.2.4.md
- Related: FINDING-077

### Priority
High - Cross-service token confusion attack

---

## Issue: FINDING-079 - No Anti-caching Headers Set for Sensitive Election Data Responses
**Labels:** bug, security, priority:high
**Description:**
### Summary
Election module returns highly sensitive data through multiple methods that would be served as HTTP responses, but no cache-control mechanism defined anywhere in codebase. Browser caching of sensitive pages could expose ballot secrecy violations, voter PII, election integrity data.

### Details
Methods requiring Cache-Control: no-store: `get_metadata()` (owner_pid, authz groups), `has_voted_upon()` (per-voter voting status), `tally_issue()` (decrypted vote tallies), `list_issues()`, `get_voters_for_email()` (voter PII), `open_to_pid()`. Data Flow: Database → election.py methods → web framework response → browser cache (uncontrolled). Cached pages on shared computers could reveal voting participation, voter PII, tally results, enabling voter-vote correlation.

**ASVS:** 14.3.2 (L2)  
**CWE:** Not specified  
**Affected Files:** v3/steve/election.py (all data-returning methods)

### Remediation
Apply anti-caching headers at Quart framework layer:
```python
@app.after_request
async def set_security_headers(response):
    response.headers['Cache-Control'] = (
        'no-store, no-cache, must-revalidate, max-age=0'
    )
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response
```

### Acceptance Criteria
- [ ] Anti-caching headers applied globally
- [ ] All authenticated endpoints protected
- [ ] Tests verify headers present
- [ ] Documentation of caching policy

### References
- Source: 14.3.2.md

### Priority
High - Ballot secrecy and voter privacy violation

---

## Issue: FINDING-080 - No Documented Cryptographic Key Management Policy or Key Lifecycle
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Codebase contains multiple cryptographic keys and secrets (election salt, opened_key, vote_token, vote encryption keys) but no documented key management policy conforming to NIST SP 800-57 or equivalent. No documented key lifecycle, generation procedures, storage requirements, distribution controls, expiration, revocation, destruction, or recovery mechanisms.

### Details
While schema.md provides documentation of what keys exist, it doesn't constitute key lifecycle policy. Without documented key lifecycle, keys may persist beyond intended use period, accumulate risk, lack clear procedures for compromise response. The opened_key persists in database indefinitely after election closes, with no documented destruction schedule.

**ASVS:** 11.1.1 (L2)  
**CWE:** Not specified  
**Affected Files:** v3/steve/crypto.py, v3/docs/schema.md

### Remediation
Create formal cryptographic key management policy document covering:
1. Key types, purposes, and authorized users
2. Key generation procedures (already using secrets module)
3. Maximum key lifetime per key type
4. Key storage protection requirements
5. Key destruction procedures (e.g., zeroing opened_key after tally completion)
6. Incident response for key compromise

Example structure in `docs/KEY_MANAGEMENT_POLICY.md`

### Acceptance Criteria
- [ ] KEY_MANAGEMENT_POLICY.md created
- [ ] All key types documented
- [ ] Lifecycle procedures defined
- [ ] Destruction procedures specified
- [ ] Incident response procedures included

### References
- Source: 11.1.1.md

### Priority
Medium - Key management policy gap

## Issue: FINDING-081 - Incomplete Cryptographic Inventory - Missing Algorithm and Key Usage Documentation
**Labels:** security, priority:medium, cryptography, documentation
**Description:**
### Summary
The cryptographic inventory is incomplete, with algorithms, key usage boundaries, and centralized documentation missing. Crypto information is scattered across multiple files without a systematic assessment framework.

### Details
While `schema.md` documents some cryptographic assets, critical gaps exist:
1. **Undocumented algorithms**: BLAKE2b (64-byte digest for Argon2 pre-hash), HKDF-SHA256 (vote_token → vote_key stretching), Fernet composition (AES-128-CBC + HMAC-SHA256)
2. **Missing key usage boundaries**: No documentation of where each key CAN/CANNOT be used, what data types each key protects, or which components access which keys
3. **No centralized inventory**: Information scattered across `schema.md`, `crypto.py` comments, and `schema.sql` comments

Without complete inventory, systematic cryptographic risk assessment, migration planning, and proper asset management are impossible.

### Remediation
Create `CRYPTO_INVENTORY.md` with comprehensive table including:
- **Election salt**: N/A random, 128 bits, Argon2 input, Server-only, `election.salt`
- **Opened key**: Argon2d(BLAKE2b(edata)), 256 bits, Tamper detection + vote token derivation, Server-only, `election.opened_key`
- **Mayvote salt**: N/A random, 128 bits, Per-voter differentiation, Server-only, `mayvote.salt`
- **Vote token**: Argon2d(opened_key‖pid‖iid, salt), 256 bits, Voter identification + key derivation, Server-only, `vote.vote_token`
- **Vote key**: HKDF-SHA256(vote_token, salt), 256 bits, Vote encryption, Ephemeral, Derived in memory
- **Ciphertext**: Fernet (AES-128-CBC + HMAC-SHA256), N/A, Vote confidentiality, Stored, `vote.ciphertext`

### Acceptance Criteria
- [ ] CRYPTO_INVENTORY.md created with all cryptographic assets documented
- [ ] Algorithm details (name, key length, purpose) specified for each asset
- [ ] Key usage boundaries and access scope clearly defined
- [ ] Protected data types mapped to each cryptographic asset
- [ ] Storage locations documented

### References
- ASVS 11.1.2 (L2)
- Files: `crypto.py:49`, `crypto.py:61-66`, `schema.md`

### Priority
Medium

---

## Issue: FINDING-082 - No Cryptographic Discovery Mechanisms Employed
**Labels:** security, priority:medium, cryptography, ci-cd, tooling
**Description:**
### Summary
No automated cryptographic discovery mechanisms exist to identify all cryptography instances in the system, detect new cryptographic operations, or flag deprecated/weak algorithms.

### Details
The codebase lacks:
- Cryptographic library usage discovery tools
- Encryption/hashing/signing operation identification
- Detection of newly introduced cryptographic operations
- Deprecated/weak algorithm flagging

`pyproject.toml` defines development dependencies but includes no cryptographic scanning tools (cryptosense, crypto-detector, semgrep with crypto rules, or custom SAST rules).

### Remediation
1. Add cryptographic linting to CI/CD using:
   - Semgrep with crypto-specific rules
   - Custom ruff/pylint rules flagging `hashlib`, `cryptography`, `hmac` imports
   - SAST tools configured for crypto operations
2. Maintain approved crypto imports/modules list
3. Run periodic scans to detect inventory drift

### Acceptance Criteria
- [ ] Cryptographic scanning tool integrated into CI/CD pipeline
- [ ] Approved cryptographic imports list created and maintained
- [ ] Automated detection of unapproved crypto usage implemented
- [ ] Periodic scanning scheduled and documented
- [ ] Test added to verify scanning functionality

### References
- ASVS 11.1.3 (L3)
- Files: `pyproject.toml`, `pages.py:269`

### Priority
Medium

---

## Issue: FINDING-083 - No Documented Post-Quantum Cryptography Migration Plan
**Labels:** security, priority:medium, cryptography, future-proofing, documentation
**Description:**
### Summary
No documented migration plan addresses post-quantum cryptography threats. Current primitives (AES-128, SHA-256, BLAKE2b) have varying quantum resistance levels without formal assessment or migration roadmap.

### Details
While code acknowledges planned Fernet → XChaCha20-Poly1305 transition, this doesn't address quantum threats:
- Both are symmetric and similarly affected by Grover's algorithm
- AES-128 specifically should upgrade to AES-256 for quantum resistance
- No formal PQC assessment exists
- No migration timeline defined

Without a plan, the project cannot react efficiently to quantum computing advances.

### Remediation
Create `PQC_MIGRATION_PLAN.md` documenting:
1. Current algorithm inventory with quantum risk assessment
2. Timeline for migrating AES-128 (Fernet) to AES-256 or 256-bit authenticated encryption
3. Assessment of when PQC-resistant key exchange might be needed (if TLS/network crypto added)
4. Crypto-agility requirements (see ASVS 11.2.2) for seamless future upgrades
5. Data re-encryption strategy for stored ciphertext

### Acceptance Criteria
- [ ] PQC_MIGRATION_PLAN.md created
- [ ] Quantum risk assessment completed for all current algorithms
- [ ] Migration timeline defined with milestones
- [ ] Crypto-agility requirements specified
- [ ] Re-encryption strategy documented

### References
- ASVS 11.1.4 (L3)
- Files: `v3/steve/crypto.py:63`, `v3/docs/schema.md`

### Priority
Medium

---

## Issue: FINDING-084 - Argon2d (Type.D) Used Instead of Recommended Argon2id (Type.ID)
**Labels:** bug, security, priority:medium, cryptography, side-channel
**Description:**
### Summary
Production code uses Argon2d (Type.D) vulnerable to side-channel attacks, while OWASP and NIST recommend Argon2id (Type.ID). The benchmark function correctly uses Type.ID, indicating developer awareness but incorrect production implementation.

### Details
**Vulnerability**: Argon2d's data-dependent memory accesses enable timing attacks. Attackers with physical/VM co-location could observe memory access patterns during vote token generation to recover secret data.

**Affected operations**:
- Password storage (ASVS 11.4.2)
- Key stretching (ASVS 11.4.4)
- Suboptimal algorithm choice (ASVS 11.6.1)

**Evidence of awareness**: Benchmark at line 116 uses correct Type.ID variant.

### Remediation
Change `_hash()` function from `argon2.low_level.Type.D` to `argon2.low_level.Type.ID` per RFC 9106.

**Migration considerations**:
- This changes all derived values
- Must coordinate with existing deployed databases
- Add `crypto_version` column to `vote` table for future algorithm transitions

### Acceptance Criteria
- [ ] Argon2 type changed from Type.D to Type.ID in production code
- [ ] crypto_version column added to vote table
- [ ] Migration plan documented for existing deployments
- [ ] Test added verifying Type.ID usage
- [ ] Benchmark function consistency verified

### References
- ASVS 11.2.1, 11.2.4, 11.4.2, 11.4.4, 11.6.1, 15.2.1 (L1-L3)
- Files: `v3/steve/crypto.py:89`, `v3/steve/crypto.py:87`
- RFC 9106

### Priority
Medium

---

## Issue: FINDING-085 - ID Generation Uses Insufficient Entropy (40 bits vs Required 128 bits)
**Labels:** security, priority:medium, cryptography, entropy
**Description:**
### Summary
`create_id()` generates only 5 bytes (40 bits) of entropy for election/issue IDs. While adequate for resource identifiers, session token entropy requirements (128+ bits) cannot be verified in external `asfquart.session` dependency.

### Details
**Resource IDs**: 40-bit space (~1 trillion values) provides unpredictability for URL-based resource identifiers as intended ("URLs for Elections cannot be deduced").

**Session tokens**: Managed by external `asfquart.session` - entropy cannot be verified from provided source.

**Awareness evidence**: `crypto.py` demonstrates `secrets.token_bytes(16)` (128 bits) for salts, showing understanding of appropriate entropy levels.

### Remediation
1. Verify `asfquart.session` generates session tokens with ≥128 bits entropy using CSPRNG
2. Document session token generation mechanism:
```python
# Session Token Specification:
# - Generated by asfquart.session using [specific mechanism]
# - Token length: [N] bytes ([M] bits of entropy)
# - Source: [e.g., os.urandom / secrets module]
# - Verified to meet ASVS 7.2.3 (128+ bits, CSPRNG)
```

### Acceptance Criteria
- [ ] asfquart.session token generation verified (≥128 bits, CSPRNG)
- [ ] Session token specification documented
- [ ] Entropy source confirmed cryptographically secure
- [ ] Documentation added to security architecture docs

### References
- ASVS 11.2.3, 11.5.1, 7.2.3 (L1-L2)
- Files: `v3/steve/crypto.py:100`

### Priority
Medium

---

## Issue: FINDING-086 - Unhandled Cryptographic Decryption Exceptions in Vote Tallying
**Labels:** bug, security, priority:medium, error-handling, availability
**Description:**
### Summary
`tally_issue()` doesn't handle exceptions from `crypto.decrypt_votestring()`. A single corrupted vote ciphertext causes entire tally operation to fail with unhandled `cryptography.fernet.InvalidToken` exception, creating a denial-of-service vector.

### Details
**Impact**:
- Single corrupted vote prevents ALL votes from being tallied
- Exception type/message could potentially differentiate between HMAC failure and other issues

**Mitigation note**: Fernet's encrypt-then-MAC construction prevents Padding Oracle attacks (HMAC verified before decryption).

### Remediation
Wrap `decrypt_votestring()` in try/except block:
```python
try:
    votestring = crypto.decrypt_votestring(vote_token, mayvote.salt, row.ciphertext)
    votes.append(votestring)
except Exception:
    _LOGGER.error(f'Failed to decrypt vote for issue {iid} - vote skipped')
    continue
```

**Requirements**:
- Log failures without exposing HMAC vs decryption failure details
- Skip corrupted vote and continue processing
- Generic exception handling to prevent information leakage

### Acceptance Criteria
- [ ] Exception handling added to decrypt_votestring() calls
- [ ] Corrupted votes skipped without failing entire tally
- [ ] Logging implemented without exposing cryptographic details
- [ ] Test added for corrupted vote handling
- [ ] Tally continues processing remaining valid votes

### References
- ASVS 11.2.5 (L3)
- Files: `v3/steve/election.py:283-290`, `v3/steve/crypto.py`

### Priority
Medium

---

## Issue: FINDING-087 - Use of Fernet (AES-128-CBC) Instead of Approved AEAD Cipher
**Labels:** bug, security, priority:medium, cryptography, modernization
**Description:**
### Summary
Code uses Fernet (AES-128-CBC + HMAC-SHA256) instead of acknowledged target XChaCha20-Poly1305 AEAD cipher. While Fernet is secure, modern standards prefer purpose-built AEAD ciphers with formal security proofs.

### Details
**Key concerns**:
- AES-CBC is legacy mode requiring careful MAC composition
- Fernet's AES-128 provides only 128-bit security vs 256-bit derived key (wasted key material)
- HKDF info parameter says 'xchacha20_key' but key used for Fernet (incomplete migration)
- 32-byte HKDF output base64-encoded for Fernet, which splits into 16 bytes signing + 16 bytes encryption (AES-128), not using full 256 bits

### Remediation
Replace Fernet with ChaCha20-Poly1305 AEAD:
1. Derive 32-byte key using HKDF with info='chacha20_poly1305_key'
2. Generate 96-bit nonce using `os.urandom(12)` per encryption
3. Use `ChaCha20Poly1305` class from `cryptography.hazmat.primitives.ciphers.aead`
4. Prepend nonce to ciphertext for storage/transmission
5. Update `decrypt_votestring` to extract nonce from first 12 bytes and decrypt remainder

### Acceptance Criteria
- [ ] Fernet replaced with ChaCha20-Poly1305
- [ ] 32-byte key derivation implemented with correct info parameter
- [ ] Nonce generation (96-bit) implemented per encryption
- [ ] Nonce prepended to ciphertext in storage format
- [ ] decrypt_votestring updated for new format
- [ ] Migration plan for existing encrypted votes documented
- [ ] Tests added for new encryption/decryption

### References
- ASVS 11.3.2 (L1)
- Files: `v3/steve/crypto.py:72-82`

### Priority
Medium

---

## Issue: FINDING-088 - TLS Private Key Path Stored in Configuration File
**Labels:** security, priority:medium, secrets-management, configuration
**Description:**
### Summary
TLS private key filesystem paths stored in YAML configuration file that may be committed to source control or included in build artifacts. Private key material resides on filesystem without vault-based access control.

### Details
**Configuration pattern**:
```yaml
certfile: localhost.apache.org+3.pem
keyfile: localhost.apache.org+3-key.pem
```

While this is an example file, the pattern encourages insecure key management practices.

### Remediation
Reference TLS material via secrets manager or environment variables:
```yaml
certfile: ${VAULT_TLS_CERT_PATH}
keyfile: ${VAULT_TLS_KEY_PATH}
```

Store TLS private keys in vault solution with access control rather than filesystem.

### Acceptance Criteria
- [ ] Configuration updated to use secrets manager references
- [ ] Example configuration shows secure pattern
- [ ] Documentation added for secrets manager integration
- [ ] Filesystem key access removed from examples
- [ ] Vault/secrets manager setup documented

### References
- ASVS 13.3.1 (L2)
- Files: `v3/server/config.yaml.example:30-31`

### Priority
Medium

---

## Issue: FINDING-089 - Argon2 Key Derivation Exposes Intermediate Key Material
**Labels:** security, priority:medium, cryptography, architecture
**Description:**
### Summary
`opened_key` (election master secret) passed as parameter and concatenated with voter identifiers in application memory. In isolated security module architecture, master key would never leave secure boundary—only derived tokens would be exported.

### Details
**Exposure points**:
- `gen_opened_key` creates 64-byte digest in memory and returns 32-byte key to caller
- Master key passed as parameter throughout derivation process
- Concatenation operations expose intermediate key material in application memory

**Security module principle**: Master keys should remain within security module boundary with only derived tokens exported to application.

### Remediation
Restructure so `opened_key` is a reference to key stored within security module, with derivation happening inside module boundary:
- Master key never passed as parameter or concatenated in application memory
- Implement key derivation operations within isolated security module (vault/HSM)
- Only derived tokens exported to application

### Acceptance Criteria
- [ ] Key derivation refactored to use key references instead of key material
- [ ] Master key operations isolated within security boundary
- [ ] Application receives only derived tokens, never master key
- [ ] Security module integration documented
- [ ] Tests verify key material never exposed to application layer

### References
- ASVS 13.3.3 (L3)
- Files: `v3/steve/crypto.py:39-55`

### Priority
Medium

---

## Issue: FINDING-090 - Closed Elections Retain Cryptographic Material Indefinitely
**Labels:** security, priority:medium, data-retention, cryptography
**Description:**
### Summary
After election closure and tally completion, cryptographic key material (salt, opened_key, per-voter salt values) remains in database indefinitely. No procedure exists to destroy secrets after they're no longer needed (post-tally verification period).

### Details
Violates principle that secrets should have defined lifetimes. Retained indefinitely:
- Election salt
- opened_key
- Per-voter salt values
- Encrypted votes

### Remediation
Implement `archive_election()` method that after retention period (e.g., 90 days):
1. Verifies retention period elapsed
2. Zeros out cryptographic material:
   - Set `salt` and `opened_key` to NULL for election records
   - Set `salt` to NULL for all mayvote records
   - Delete encrypted votes

### Acceptance Criteria
- [ ] archive_election() method implemented
- [ ] Retention period configuration added (default 90 days)
- [ ] Cryptographic material destruction verified
- [ ] Audit log entry created for archival
- [ ] Tests verify proper cleanup after retention period
- [ ] Documentation updated with retention policy

### References
- ASVS 13.3.4 (L3)
- Files: `v3/steve/election.py:116-121`, `v3/schema.sql`

### Priority
Medium

---

## Issue: FINDING-091 - Lack of Full Memory Encryption for Sensitive Data In-Use
**Labels:** security, priority:medium, cryptography, infrastructure
**Description:**
### Summary
Sensitive data (opened_key, vote_token, decrypted vote strings, PIDs) exists unprotected in process memory. Attacker with memory access (memory dump, cold boot attack, swap file analysis, process inspection) could recover individual votes, compromising ballot secrecy.

### Details
**Unprotected data flow**:
Encrypted ciphertext → decrypted votestrings → accumulated in votes list → passed to tally → returned from function

All stages lack memory encryption protection.

### Remediation
**Long-term**: Implement hardware-backed memory encryption:
- Intel TME (Total Memory Encryption) / MKTME
- AMD SEV (Secure Encrypted Virtualization)
- ARM CCA (Confidential Compute Architecture)

**Application-level**:
- Use memory-safe containers or encrypted memory regions via libraries like sodium
- Implement `sodium_mlock()` / `sodium_munlock()`
- Use `mlock()` for memory pages containing decrypted votes during tally
- Implement explicit memory clearing patterns
- Implement incremental hashing in `gather_election_data()` for streaming hash computation instead of accumulating all voter data in memory

### Acceptance Criteria
- [ ] Memory encryption strategy selected and documented
- [ ] Sensitive memory pages locked (mlock) during operations
- [ ] Explicit memory clearing implemented
- [ ] Streaming operations implemented where possible
- [ ] Documentation updated with memory security approach

### References
- ASVS 11.7.1 (L3)
- Files: `v3/steve/crypto.py`, `v3/steve/election.py`

### Priority
Medium

---

## Issue: FINDING-092 - Incomplete Formal Data Classification into Protection Levels
**Labels:** security, priority:medium, documentation, data-classification
**Description:**
### Summary
Documentation describes cryptographic mechanisms but doesn't define comprehensive protection requirements for each data sensitivity level. Missing formal encryption standards, integrity verification requirements, retention policies, logging requirements, access controls, database-level encryption, privacy requirements, and key management documentation.

### Details
**Missing documentation**:
- Formal encryption standards (Fernet mentioned, XChaCha20 planned but no formal requirement)
- Integrity verification requirements (Argon2 opened_key described but no formal requirement)
- Data retention policy (older votes retained for auditing but no retention period/purge schedule)
- Logging requirements (no policy on what can/cannot be logged)
- Formal access controls (owner_pid and authz mentioned but no formal RBAC documentation)
- Database-level encryption (no mention of SQLite encryption at rest)
- Privacy requirements (vote anonymity implied but not formally specified)
- Key management (no documentation on key rotation, backup, or destruction)

**Consequences**:
- Data retention may grow indefinitely
- Key management procedures undefined
- Logging of sensitive data has no enforceable policy
- Database file encryption status undocumented

### Remediation
Add "Data Protection Requirements" section to schema.md including:

**Encryption requirements**:
- All vote ciphertext MUST use authenticated encryption
- Database file MUST be readable only by application user with chmod 600
- Cryptographic salts MUST be generated using secrets.token_bytes()

**Integrity requirements**:
- Election tampering MUST be detectable via opened_key verification using Argon2
- Foreign key constraints MUST be enforced at runtime

**Retention requirements**:
- Closed election data MUST be retained for [X] months for audit purposes
- Vote re-voting history MUST be purged after tallying
- Person records MUST be reviewed annually for GDPR/privacy compliance

**Logging requirements**:
- Encrypted vote content/ciphertext MUST NEVER appear in logs
- Salt values MUST NEVER appear in logs
- opened_key MUST NEVER appear in logs
- Election IDs and issue IDs MAY be logged for operational purposes

**Access Control requirements**:
- Only election owner and authz group may modify elections
- Administrative decryption requires CLI access with encryption keys
- Database file access restricted to application service account

### Acceptance Criteria
- [ ] Data Protection Requirements section added to schema.md
- [ ] All protection requirements formally specified
- [ ] Encryption standards documented
- [ ] Retention policies defined with specific timeframes
- [ ] Logging requirements specified
- [ ] Access control requirements documented

### References
- ASVS 14.1.1, 14.1.2 (L2)
- Files: `v3/docs/schema.md`

### Priority
Medium

---

## Issue: FINDING-093 - Integrity Verification Does Not Cover Authorization-Critical Fields
**Labels:** bug, security, priority:medium, integrity, authorization
**Description:**
### Summary
`gather_election_data()` only includes `eid` and `title` in integrity hash, omitting `owner_pid` and `authz` fields. Modifications to authorization fields after election opening won't trigger tamper detection via `is_tampered()`.

### Details
**Vulnerability**: Attacker with database write access could reassign election ownership without triggering integrity alerts.

**Current hash input**: `md.eid + md.title`

**Missing from hash**: `owner_pid`, `authz`

### Remediation
Include all integrity-critical fields in `gather_election_data()`:
```python
mdata = md.eid + md.title + md.owner_pid + (md.authz or '')
```

### Acceptance Criteria
- [ ] owner_pid included in integrity hash
- [ ] authz included in integrity hash (with null handling)
- [ ] Test added verifying tamper detection for authorization field changes
- [ ] Existing elections re-hashed if needed
- [ ] Documentation updated

### References
- ASVS 14.2.4 (L2)
- Files: `v3/steve/election.py:90-110`

### Priority
Medium

---

## Issue: FINDING-094 - Tamper Detection Not Automatically Invoked During Critical Operations
**Labels:** bug, security, priority:medium, integrity
**Description:**
### Summary
`is_tampered()` method exists but isn't automatically called in critical operations like `add_vote()` or `tally_issue()`. If election data is tampered with after opening, votes can still be cast and tallied without integrity check being triggered.

### Details
**Current state**: Method must be called externally by web layer—no enforcement that it has been called before `add_vote()` proceeds.

**Risk**: Tampering with election data after opening goes undetected during vote casting and tallying.

### Remediation
Add integrity verification before accepting votes:
```python
if pdb and self.is_tampered(pdb):
    raise ElectionTampered(self.eid)
```

**Options**:
1. Call `is_tampered()` within `add_vote()` automatically, OR
2. Add decorator ensuring web layer performed check before method executes

### Acceptance Criteria
- [ ] Tamper detection automatically invoked before vote casting
- [ ] Tamper detection automatically invoked before tallying
- [ ] ElectionTampered exception raised when tampering detected
- [ ] Tests verify automatic invocation
- [ ] Documentation updated

### References
- ASVS 14.2.4 (L2)
- Files: `v3/steve/election.py:260-273`

### Priority
Medium

---

## Issue: FINDING-095 - Superseded Votes Retained Indefinitely Without Purge Mechanism
**Labels:** security, priority:medium, data-retention, privacy
**Description:**
### Summary
When voter re-votes, all previous encrypted votes remain in database. While only latest vote (MAX(vid)) used for tallying, old ciphertexts represent historical sensitive data with no defined retention period, potential attack surface if encryption keys compromised, and storage of data serving no ongoing operational purpose.

### Details
**Missing**:
- No query in `queries.yaml` to delete superseded votes
- No scheduled cleanup
- No retention policy documentation

**Risk**: If attacker compromises encryption keys later, historical votes become vulnerable.

### Remediation
Add queries to `queries.yaml`:
- `c_purge_old_votes`: Delete superseded votes for given vote_token (keeping only MAX(vid))
- `c_purge_election_votes`: Delete all votes for specific closed election

Implement cleanup mechanism running after tallying or on scheduled basis to remove superseded votes no longer needed for operational purposes.

### Acceptance Criteria
- [ ] c_purge_old_votes query added
- [ ] c_purge_election_votes query added
- [ ] Cleanup mechanism implemented
- [ ] Retention policy documented
- [ ] Scheduled cleanup configured
- [ ] Tests verify proper vote purging

### References
- ASVS 14.2.7 (L3)
- Files: `v3/docs/schema.md`, `v3/schema.sql`

### Priority
Medium

---

## Issue: FINDING-096 - Person Records Have No Lifecycle Management or Cleanup
**Labels:** security, priority:medium, data-retention, privacy, gdpr
**Description:**
### Summary
Person records (PID, name, email) accumulate indefinitely. While `c_delete_person` exists, `ON DELETE RESTRICT` constraints on `mayvote` and `election.owner_pid` prevent deletion as long as any election references the person. Since opened elections cannot be deleted, person records become effectively permanent, resulting in indefinite PII retention.

### Details
**Issue**: No defined retention schedule or cleanup mechanism for PII.

**Constraint**: Database foreign keys prevent deletion while elections exist.

### Remediation
Implement data anonymization mechanism for persons in completed elections:
```python
def anonymize_person_in_closed_elections(self, pid):
    # Replace PII with anonymized values after retention period expires
    # Preserves referential integrity while removing sensitive information
```

This allows person records to remain for database consistency while removing sensitive personal information.

### Acceptance Criteria
- [ ] Anonymization function implemented
- [ ] Retention period defined (e.g., 90 days after election closure)
- [ ] PII (name, email) replaced with anonymized values
- [ ] Referential integrity preserved
- [ ] GDPR compliance verified
- [ ] Tests added for anonymization process
- [ ] Documentation updated

### References
- ASVS 14.2.7 (L3)
- Files: `v3/queries.yaml`, `v3/schema.sql`

### Priority
Medium

---

## Issue: FINDING-097 - Missing PKCE (Proof Key for Code Exchange) in OAuth Flow
**Labels:** bug, security, priority:medium, oauth, authentication
**Description:**
### Summary
OAuth authorization URL template includes `state` parameter but lacks PKCE (Proof Key for Code Exchange) parameters. While `state` provides CSRF protection, PKCE provides additional protection against authorization code interception attacks.

### Details
**Missing from URL template**:
- `code_challenge` parameter
- `code_challenge_method` parameter
- `code_verifier` generation/binding logic

**Current protection**: Relies solely on `state` and code confidentiality.

**Risk**: Authorization code interception attacks (especially relevant where callback URI could be intercepted).

### Remediation
Modify OAuth URL template to include PKCE:
```python
asfquart.generics.OAUTH_URL_INIT = (
    'https://oauth.apache.org/auth?state=%s&redirect_uri=%s'
    '&code_challenge=%s&code_challenge_method=S256'
)
```

**Framework must**:
1. Generate code_verifier (43-128 chars, cryptographically random)
2. Compute code_challenge = BASE64URL(SHA256(code_verifier))
3. Store code_verifier in session
4. Send it with token exchange request

**Example**:
```python
code_verifier = base64.urlsafe_b64encode(
    secrets.token_bytes(32)
).rstrip(b'=').decode()

code_challenge = base64.urlsafe_b64encode(
    hashlib.sha256(code_verifier.encode()).digest()
).rstrip(b'=').decode()
```

### Acceptance Criteria
- [ ] PKCE parameters added to OAuth URL template
- [ ] code_verifier generation implemented
- [ ] code_challenge computation implemented (S256 method)
- [ ] code_verifier stored in session
- [ ] code_verifier sent with token exchange
- [ ] Tests verify PKCE flow
- [ ] Documentation updated

### References
- ASVS 10.1.2, 10.2.1, 10.4.6, 10.4.4 (L1-L2)
- Files: `v3/server/main.py:39-42`
- RFC 7636 (PKCE)

### Priority
Medium

---

## Issue: FINDING-098 - Missing Fine-Grained Authorization Based on Election Ownership and LDAP Group Claims
**Labels:** bug, security, priority:high, authorization, bola
**Description:**
### Summary
Application verifies 'committer' role but doesn't enforce fine-grained authorization based on election ownership (`owner_pid`) or LDAP group membership (`authz` field). Systematic '### check authz' comments at 9+ locations indicate conceptualized but never implemented authorization control (Type B gap). ANY authenticated committer can manage any election.

### Details
**Unauthorized operations possible**:
- Open/close any election
- Add/edit/delete issues in any election
- Set dates on any election

**Evidence**: Domain model includes `owner_pid` and `authz` fields, but these are never checked before management operations.

**Comment locations** (9+ instances):
- pages.py:488, 509, 527, 553, 577, 421, 99, 195, 224

### Remediation
Implement election ownership authorization checks in `load_election` and `load_election_issue` decorators:

1. Retrieve election metadata including `owner_pid` and `authz` fields
2. Compare authenticated user's `uid` with `owner_pid`
3. If not owner, check if user is member of LDAP group specified in `authz` using `PersonDB.is_member_of_group()`
4. Return 403 Forbidden if neither condition met

**Example**:
```python
if result.uid != metadata.owner_pid:
    if metadata.authz:
        if not pdb.is_member_of_group(result.uid, metadata.authz):
            quart.abort(403, 'Not authorized to manage this election')
    else:
        quart.abort(403, 'Not authorized to manage this election')
```

Apply check in `load_election` decorator so all endpoints inherit protection.

### Acceptance Criteria
- [ ] Authorization check implemented in load_election decorator
- [ ] Authorization check implemented in load_election_issue decorator
- [ ] owner_pid comparison implemented
- [ ] LDAP group membership check implemented
- [ ] 403 Forbidden returned for unauthorized access
- [ ] All 9+ endpoints with '### check authz' comments protected
- [ ] Tests verify authorization enforcement
- [ ] Tests verify owner access allowed
- [ ] Tests verify authz group member access allowed
- [ ] Tests verify non-authorized access denied

### References
- ASVS 10.3.2 (L2)
- Files: `v3/server/pages.py` (multiple lines)
- Related: FINDING-021, FINDING-022

### Priority
High

---

## Issue: FINDING-099 - User Identification Does Not Verify iss+sub Combination from Token Claims
**Labels:** security, priority:medium, oauth, authentication
**Description:**
### Summary
Application identifies users solely by `uid` extracted from session, without validating user identity derived from `iss` (issuer) + `sub` (subject) claims combination that cannot be reassigned. No verification that token was issued by expected issuer or that `sub` maps uniquely across all possible issuers.

### Details
**Current state**: Relies entirely on `asfquart` framework to map OAuth token claims to `uid`, with no explicit issuer verification.

**Risk**: If framework has misconfiguration or second OAuth provider added, user identity could be confused. Attacker at different IdP could potentially obtain token with same `uid`/`sub` mapping to different user.

### Remediation
Verify session established from expected issuer and use iss+sub combination as canonical user identifier:

```python
async def basic_info():
    s = await asfquart.session.read()
    if s:
        expected_issuer = 'https://oauth.apache.org'
        if s.get('iss') != expected_issuer:
            _LOGGER.warning(f'Unexpected issuer in session: {s.get("iss")}')
            return basic
        
        canonical_id = f"{s['iss']}:{s['sub']}"
        basic.update(
            uid=s['uid'],
            canonical_user_id=canonical_id,
            name=s['fullname'],
            email=s['email']
        )
```

### Acceptance Criteria
- [ ] Issuer claim validation implemented
- [ ] Expected issuer configured and verified
- [ ] Canonical user ID (iss:sub) generated and stored
- [ ] Warning logged for unexpected issuers
- [ ] Tests verify issuer validation
- [ ] Tests verify canonical ID generation
- [ ] Documentation updated

### References
- ASVS 10.3.3 (L2)
- Files: `v3/server/pages.py:82-89`

### Priority
Medium

---

## Issue: FINDING-100 - No Verification of Authentication Strength, Methods, or Recentness for Sensitive Operations
**Labels:** security, priority:medium, authentication, step-up-auth
**Description:**
### Summary
Application uses different authorization levels (R.committer, R.pmc_member) but never verifies authentication strength or method used by IdP. No OIDC claims (acr, amr, auth_time) inspected. Sensitive operations (opening/closing elections, casting votes) could benefit from step-up authentication verification, but no mechanism exists to differentiate between password-only vs MFA authentication.

### Details
**Missing verification**:
- Authentication Context Class Reference (acr)
- Authentication Methods References (amr)
- Authentication time (auth_time)

**Risk**: User authenticated with weak method (compromised password without MFA) has same access as one authenticated with strong authentication.

### Remediation
Implement authentication strength verification before sensitive operations:

```python
def verify_auth_strength(session, max_age_seconds=300):
    """Verify authentication strength for sensitive operations."""
    # 1. Check authentication recentness
    auth_time = session.get('auth_time')
    if not auth_time or (time.time() - auth_time) > max_age_seconds:
        # Redirect to re-authentication
        quart.abort(401, 'Re-authentication required')
    
    # 2. Check authentication context class (acr)
    acr = session.get('acr')
    if acr not in ['urn:mace:incommon:iap:silver', 'urn:mace:incommon:iap:gold']:
        quart.abort(403, 'Insufficient authentication assurance level')
    
    # 3. Check authentication methods (amr)
    amr = session.get('amr', [])
    if 'mfa' not in amr:
        quart.abort(403, 'Multi-factor authentication required')
```

**Apply to sensitive endpoints**:
- do-vote
- do-open
- do-close
- do-create-election
- do-delete-issue

Store `auth_time` in session during initial OAuth authentication.

### Acceptance Criteria
- [ ] verify_auth_strength function implemented
- [ ] auth_time validation implemented with configurable max age
- [ ] acr claim validation implemented
- [ ] amr claim validation implemented
- [ ] Verification applied to all sensitive endpoints
- [ ] auth_time stored in session during OAuth authentication
- [ ] Re-authentication redirect implemented
- [ ] Tests verify strength checking
- [ ] Tests verify re-authentication requirement
- [ ] Documentation updated

### References
- ASVS 10.3.4, 6.8.4, 8.4.2 (L2-L3)
- Files: `v3/server/pages.py:484`

### Priority
Medium

---

## Issue: FINDING-101 - No Sender-Constrained Access Token Mechanism (mTLS or DPoP)
**Labels:** security, priority:medium, oauth, token-binding
**Description:**
### Summary
Application uses standard OAuth 2.0 bearer tokens without sender-constraining mechanism. No implementation of Mutual TLS (mTLS) for OAuth 2 (RFC 8705) with client certificate binding, nor DPoP (Demonstration of Proof-of-Possession) (RFC 9449). TLS configuration is server-side only. Stolen access token or session cookie can be used from any network location by any party.

### Details
**Level 3 requirement**: Sender-constrained tokens.

**Current state**: Server-side TLS only (main.py:76-79).

**Risk**: Token theft enables use from any location without proof of possession.

### Remediation
Implement one of the following:

**Option 1: DPoP**
```python
# Configure DPoP requirement
app.config['REQUIRE_DPOP'] = True

# Generate DPoP key pair per-session
# Create DPoP proof JWTs with:
# - Headers: typ: dpop+jwt, alg: ES256, jwk
# - Payload: htm (HTTP method), htu (HTTP URI), iat, jti, ath (hash of access token)
# Include DPoP proof in token requests via DPoP header
```

**Option 2: Session binding with client fingerprinting**
- Bind session to TLS connection attributes

**Option 3: mTLS**
- Configure client certificate verification
- Bind tokens to certificate thumbprint (cnf.x5t#S256)

### Acceptance Criteria
- [ ] Sender-constraining mechanism selected and implemented
- [ ] DPoP OR mTLS OR session binding implemented
- [ ] Token binding verified on each request
- [ ] Tests verify token binding enforcement
- [ ] Tests verify stolen token rejection
- [ ] Documentation updated

### References
- ASVS 10.3.5, 10.4.14 (L3)
- Files: `v3/server/main.py:39-42`, `v3/server/main.py:76-79`, `v3/server/pages.py:82-88`
- RFC 8705 (mTLS), RFC 9449 (DPoP)

### Priority
Medium

---

## Issue: FINDING-102 - Authorization Code Grant Not Used with Pushed Authorization Requests (PAR)
**Labels:** security, priority:medium, oauth, par
**Description:**
### Summary
Application uses authorization code grant without Pushed Authorization Requests (PAR). Authorization request constructed as direct redirect with parameters in URL. Without PAR: parameters exposed in browser address bar and referrer headers, redirect_uri and state can be manipulated before reaching authorization server, and authorization request is not authenticated.

### Details
**Level 3 requirement**: Authorization code flow should use PAR.

**Current flow**: Direct redirect with URL parameters (state=%s, redirect_uri=%s).

**Security benefits of PAR**:
- Authenticates authorization request
- Prevents parameter manipulation in browser
- Returns request_uri instead of raw parameters

### Remediation
Implement PAR:

**Step 1: Push Authorization Request (authenticated)**
```python
response = httpx.post(
    'https://oauth.apache.org/par',
    data={
        'client_id': client_id,
        'client_secret': client_secret,
        'redirect_uri': redirect_uri,
        'state': state,
        'response_type': 'code',
        'scope': scope,
        'authorization_details': authorization_details  # if applicable
    }
)
request_uri = response.json()['request_uri']
```

**Step 2: Redirect user with only client_id and request_uri**
```python
redirect_url = (
    f'https://oauth.apache.org/authorize'
    f'?client_id={client_id}&request_uri={request_uri}'
)
```

With PAR, authorization_details pushed server-to-server, ensuring parameters originate from authenticated client backend and are tamper-proof.

### Acceptance Criteria
- [ ] PAR endpoint integration implemented
- [ ] Authorization request pushed to AS before user redirect
- [ ] request_uri obtained and used in redirect
- [ ] Client authentication in PAR request implemented
- [ ] User redirect simplified to client_id + request_uri
- [ ] Tests verify PAR flow
- [ ] Documentation updated

### References
- ASVS 10.4.13, 10.4.15 (L3)
- Files: `v3/server/main.py:39-42`
- RFC 9126 (PAR)

### Priority
Medium

---

## Issue: FINDING-103 - No Replay Detection Mechanism in Session Claim Consumption
**Labels:** security, priority:medium, oauth, replay-attack
**Description:**
### Summary
Session read and user identity values (uid, fullname, email) consumed directly without mechanism to detect if underlying token has been replayed. No timestamp comparison, no nonce validation, no binding to current session. If session data originates from replayed token, application will trust it unconditionally.

### Details
**Missing protections**:
- Timestamp comparison
- Nonce validation
- Session binding

**Risk**: Replayed tokens accepted without detection.

### Remediation
Implement token replay detection mechanisms:

1. **Nonce validation** (see OAUTH-LDAP-002 for details)
2. **Timestamp-based validation** to ensure tokens not reused beyond intended lifetime
3. **Session binding** to specific authentication requests

```python
async def validate_session_freshness(session):
    """Validate session is not from replayed token."""
    # Check nonce hasn't been seen before
    nonce = session.get('nonce')
    if nonce and await nonce_store.has_been_used(nonce):
        raise ReplayDetected('Nonce already used')
    
    # Check timestamp within acceptable window
    iat = session.get('iat')
    if not iat or (time.time() - iat) > MAX_TOKEN_AGE:
        raise TokenExpired('Token too old')
    
    # Bind to authentication request
    if session.get('auth_request_id') != current_request_id:
        raise SessionMismatch('Session not bound to this request')
```

### Acceptance Criteria
- [ ] Nonce validation implemented
- [ ] Nonce storage and tracking implemented
- [ ] Timestamp validation implemented
- [ ] Session binding to authentication request implemented
- [ ] Replay detection enforced on session read
- [ ] Tests verify replay detection
- [ ] Documentation updated

### References
- ASVS 10.5.1 (L2)
- Files: `v3/server/pages.py:82-91`
- CWE-294

### Priority
Medium

---

## Issue: FINDING-104 - No MFA Enforcement or Verification at Application Level
**Labels:** security, priority:high, authentication, mfa
**Description:**
### Summary
Application accepts any valid OAuth token from oauth.apache.org without verifying authentication included second factor. If ASF OAuth allows single-factor authentication for some users, application would grant access without MFA. For election/voting application, this represents significant risk of account takeover leading to vote manipulation.

### Details
**Flow**: User → ASF OAuth (unknown MFA policy) → OAuth token → Application session → Access granted without MFA verification

**Risk**: Users could authenticate with only password if external OAuth provider doesn't universally enforce MFA or if policy changes.

### Remediation
Application should:

1. **Verify MFA claims in OAuth token/response** (e.g., acr or amr claims in OIDC)
2. **Implement second authentication factor within application**
3. **Document that ASF OAuth universally enforces MFA** and that this is a dependency

**Example**:
```python
async def verify_mfa_in_session(session):
    """Verify that the OAuth authentication included MFA."""
    amr = session.get('amr', [])
    if len(amr) < 2 or 'mfa' not in amr:
        quart.abort(403, 'Multi-factor authentication required')
```

### Acceptance Criteria
- [ ] MFA claim verification implemented (acr or amr)
- [ ] Application enforces MFA requirement for all authenticated users
- [ ] OR: Documentation confirms ASF OAuth universally enforces MFA
- [ ] Tests verify MFA enforcement
- [ ] Tests verify single-factor authentication rejected
- [ ] Documentation updated with MFA policy

### References
- ASVS 6.3.3 (L2)
- Files: `v3/server/main.py:38-42`, `v3/server/pages.py` (all @asfquart.auth.require decorators)
- CWE-308

### Priority
High

---

## Issue: FINDING-105 - JWT/Token Signature Validation Not Visible at Application Layer
**Labels:** security, priority:high, authentication, jwt
**Description:**
### Summary
Actual token validation logic encapsulated within asfquart library (not provided for review). No visible code in application layer validates JWT signatures on ID tokens or access tokens, verifies token issuer (iss) claims, checks token audience (aud) claims, or validates token expiration (exp). If asfquart library doesn't properly validate token signatures, attacker could forge authentication assertions.

### Details
**Trust dependency**: Entirely placed in library implementation.

**Missing visibility**:
- JWT signature validation
- Issuer (iss) claim verification
- Audience (aud) claim verification
- Expiration (exp) validation

**Callback pattern**: Suggests simple token exchange without explicit signature verification at application layer.

### Remediation
1. **Verify asfquart library validates JWT/token signatures**
2. **Document signature validation approach**
3. **Consider application-level assertion validation** using library like python-jose:

```python
from jose import jwt, JWTError

async def validate_id_token(token, expected_issuer, expected_audience):
    """Explicitly validate ID token signatures and claims."""
    try:
        # Get signing keys from JWKS endpoint
        jwks = await get_jwks(f'{expected_issuer}/.well-known/jwks.json')
        
        # Validate signature and claims
        claims = jwt.decode(
            token,
            jwks,
            algorithms=['RS256'],  # Only allow expected algorithms
            issuer=expected_issuer,
            audience=expected_audience
        )
        
        # Reject unsigned tokens
        if claims.get('alg') == 'none':
            raise JWTError('Unsigned tokens not allowed')
        
        return claims
    except JWTError as e:
        _LOGGER.error(f'Token validation failed: {e}')
        raise
```

### Acceptance Criteria
- [ ] asfquart library signature validation verified and documented
- [ ] OR: Application-level signature validation implemented
- [ ] Issuer claim verification documented/implemented
- [ ] Audience claim verification documented/implemented
- [ ] Unsigned token rejection verified
- [ ] Only expected algorithms allowed (RS256, ES256)
- [ ] Tests verify signature validation
- [ ] Tests verify forged token rejection
- [ ] Documentation updated

### References
- ASVS 6.8.2 (L2)
- Files: `v3/server/main.py:40-43`
- CWE-347

### Priority
High

---

## Issue: FINDING-106 - No User Notification When LDAP Profile Data Is Updated
**Labels:** security, priority:medium, notification, ldap
**Description:**
### Summary
When LDAP synchronization script updates user profile information (display name or email address), user is not notified. If attacker compromises ASF account and changes associated email in LDAP, synchronized data would change silently in voting system without legitimate user receiving notification.

### Details
**Risk**: Missed signal of account takeover when profile modified.

**Affected data**: Email address, display name

**Related**: FINDING-107 (suspicious authentication notification)

### Remediation
Implement change detection and notification in LDAP sync:

```python
for r in results:
    entry = edict(r[1])
    uid = entry.uid[0].decode('utf-8')
    visname = entry.cn[0].decode('utf-8')
    email = entry['asf-committer-email'][0].decode('utf-8')
    
    # Detect changes before overwriting
    try:
        existing = pdb.get_person(uid)
        if existing[1] != email:
            notify_user_profile_change(uid, 'email', existing[1], email)
        if existing[0] != visname:
            notify_user_profile_change(uid, 'name', existing[0], visname)
    except steve.persondb.PersonNotFound:
        pass
    
    pdb.add_person(uid, visname, email)
```

### Acceptance Criteria
- [ ] Change detection implemented in LDAP sync
- [ ] notify_user_profile_change function implemented
- [ ] Email notifications sent for email address changes
- [ ] Email notifications sent for display name changes
- [ ] Notifications include old and new values
- [ ] Tests verify notification on profile changes
- [ ] Documentation updated

### References
- ASVS 6.3.7 (L3)
- Files: `v3/server/bin/asf-load-ldap.py:45-62`
- CWE-778
- Related: FINDING-107

### Priority
Medium

---

## Issue: FINDING-107 - No Suspicious Authentication Notification System
**Labels:** security, priority:medium, notification, monitoring
**Description:**
### Summary
Application doesn't implement mechanism to detect or notify users about suspicious authentication attempts. No unusual location detection, unusual client detection, failed attempt tracking, inactivity-based alerts, or successful-after-failed notification. Application delegates authentication to ASF OAuth but doesn't receive or process signals about authentication anomalies.

### Details
**Missing detection mechanisms**:
1. No unusual location detection (IP geolocation)
2. No unusual client detection (user-agent/device fingerprinting)
3. No failed attempt tracking per user
4. No inactivity-based alerts (authentication after long dormancy)
5. No successful-after-failed notification

**Related**: FINDING-106 (profile change notification)

### Remediation
Implement authentication event monitoring and notification:

```python
async def check_suspicious_auth(session, request):
    uid = session['uid']
    current_ip = request.remote_addr
    current_ua = request.headers.get('User-Agent', '')
    
    last_auth = await get_last_auth_record(uid)
    suspicious = False
    
    if last_auth:
        if last_auth.ip != current_ip:
            suspicious = True
        if last_auth.user_agent != current_ua:
            suspicious = True
        if (datetime.now() - last_auth.timestamp).days > 90:
            suspicious = True
    
    if suspicious:
        await send_notification(
            uid,
            'Suspicious login detected',
            details
        )
    
    await record_auth_event(uid, current_ip, current_ua)
```

### Acceptance Criteria
- [ ] Authentication event recording implemented
- [ ] IP address change detection implemented
- [ ] User-agent change detection implemented
- [ ] Inactivity period detection implemented (>90 days)
- [ ] Notification system implemented
- [ ] Email notifications sent for suspicious authentications
- [ ] Tests verify detection mechanisms
- [ ] Tests verify notification sending
- [ ] Documentation updated

### References
- ASVS 6.3.5 (L3)
- Files: All files in scope
- CWE-778
- Related: FINDING-106

### Priority
Medium

---

## Issue: FINDING-108 - Inconsistent Privilege Requirements Create Privilege Escalation Path
**Labels:** bug, security, priority:medium, authorization, privilege-escalation
**Description:**
### Summary
Election creation requires R.pmc_member (PMC member privilege) while all other election operations only require R.committer (committer privilege). This creates privilege escalation path where committer cannot create elections but can fully manage (including opening, closing, deleting issues from) elections created by PMC members.

### Details
**Inconsistency**: Higher-privilege requirement for creation provides no security benefit when lower-privileged committer can fully manage all existing elections.

**Impact**: Undermines privilege model and creates confusion about intended access controls.

### Remediation
Apply consistent authorization at all management endpoints by implementing ownership and authz group checks described in FINDING-098.

**Ensures**: Only authorized users (owners or authz group members) can manage elections, regardless of whether they are PMC members or committers.

**Note**: R.pmc_member requirement for creation can remain as separate organizational policy control, but all subsequent management must verify election-specific authorization.

### Acceptance Criteria
- [ ] Ownership checks implemented for all management operations
- [ ] authz group checks implemented for all management operations
- [ ] Consistent authorization enforced across all endpoints
- [ ] Tests verify committers cannot manage elections they don't own
- [ ] Tests verify authz group members can manage elections
- [ ] Documentation clarifies privilege model

### References
- ASVS 8.2.1 (L1)
- Files: `v3/server/pages.py:435`
- Related: FINDING-098

### Priority
Medium

---

## Issue: FINDING-109 - Missing Authorization Check in Election Date Modification Helper
**Labels:** bug, security, priority:medium, authorization, bola
**Description:**
### Summary
`_set_election_date` helper function contains '# check authz' comment but performs NO authorization check. Any committer can set open_at or close_at dates on any election. This is specific instance of BOLA vulnerability (FINDING-098) applied to date modification helper function.

### Details
**Current state**: Function proceeds to modify election dates without verifying authenticated user has permission to manage that election.

**Note**: While dates marked as 'purely advisory' in SQL comments, unauthorized modification still represents security control failure.

**Related**: FINDING-021, FINDING-022, FINDING-110

### Remediation
Implement authorization check in `_set_election_date` function:

```python
def _set_election_date(md, uid, field, value):
    # Check authorization
    if md.owner_pid != uid:
        if md.authz:
            if not pdb.is_member_of_group(uid, md.authz):
                quart.abort(403, 'Not authorized to modify election dates')
        else:
            quart.abort(403, 'Not authorized to modify election dates')
    
    # Proceed with date modification
    # ...
```

Follow same pattern as `check_election_authz()` function recommended in FINDING-098.

### Acceptance Criteria
- [ ] Authorization check implemented in _set_election_date
- [ ] owner_pid comparison implemented
- [ ] authz group membership check implemented
- [ ] 403 Forbidden returned for unauthorized access
- [ ] Tests verify owner can set dates
- [ ] Tests verify authz group member can set dates
- [ ] Tests verify non-authorized user cannot set dates

### References
- ASVS 8.2.2 (L1)
- Files: `v3/server/pages.py:75-95`
- CWE-639
- Related: FINDING-021, FINDING-022, FINDING-110

### Priority
Medium

---

## Issue: FINDING-110 - Issue KV Data Exposed Without Role-Based Field Filtering
**Labels:** security, priority:medium, authorization, information-disclosure
**Description:**
### Summary
`list_issues()` method returns all KV data including operational configuration fields without filtering based on caller's role or context. No distinction between what fields voter should see (ballot data like candidates and labelmap) versus what manager should see (full configuration including internal settings).

### Details
**Current state**: Any caller (management page OR voting page) receives full kv field without differentiation, potentially exposing management-specific configuration data to voters.

**Risk**: Management-specific configuration data exposed to voters without need-to-know.

**Related**: FINDING-021, FINDING-022, FINDING-109

### Remediation
Add `include_management_fields` parameter (default False) to `list_issues()` method:

```python
def list_issues(self, include_management_fields=False):
    """List issues with role-based field filtering."""
    # ...query issues...
    
    for row in rows:
        kv = json.loads(row.kv)
        
        if not include_management_fields:
            # Filter to voter-visible fields only
            filtered_kv = {
                k: v for k, v in kv.items()
                if k in ['candidates', 'labelmap', 'seats']
            }
            row.kv = json.dumps(filtered_kv)
        
        issues.append(row)
    
    return issues
```

**Usage**:
- Management interfaces: `list_issues(include_management_fields=True)`
- Voting interfaces: `list_issues(include_management_fields=False)` (default)

### Acceptance Criteria
- [ ] include_management_fields parameter added to list_issues()
- [ ] Field filtering implemented for voter context
- [ ] Full KV data returned for management context
- [ ] Voter-visible fields defined and documented
- [ ] Tests verify filtering for voters
- [ ] Tests verify full data for managers
- [ ] Callers updated to specify appropriate filtering level

### References
- ASVS 8.2.3 (L2)
- Files: `v3/steve/election.py:235-250`
- CWE-639
- Related: FINDING-021, FINDING-022, FINDING-109

### Priority
Medium

---

## Issue: FINDING-111 - No Session Invalidation Mechanism for Authorization Revocations
**Labels:** security, priority:medium, session-management, authorization
**Description:**
### Summary
If voter's eligibility is revoked (removed from mayvote during editable phase, or LDAP group membership changes), no mechanism exists to: immediately invalidate active session, alert when they perform unauthorized actions, or revert changes made after authorization was revoked.

### Details
**Current state**: Authorization changes only effective on next database query, but cached session data may allow continued access.

**Compounding issue**: Since authz LDAP group check not implemented (FINDING-098), even if authz were checked at login, there's no re-check during session.

### Remediation
Implement authorization re-validation on each request for sensitive operations:

```python
async def validate_user_still_active(uid):
    """Check if user is still active in LDAP and has required group memberships."""
    # Check LDAP user still exists and is active
    # Check required group memberships still valid
    # Return True if authorized, False otherwise
    pass

# In basic_info() or middleware layer
async def basic_info():
    s = await asfquart.session.read()
    if s:
        uid = s['uid']
        if not await validate_user_still_active(uid):
            await asfquart.session.invalidate()
            quart.abort(401, 'Session invalidated - user no longer authorized')
```

**Optimization**: Add session metadata tracking (`last_authz_check` timestamp) to avoid checking on every request while ensuring reasonable freshness (e.g., check every 5 minutes).

### Acceptance Criteria
- [ ] validate_user_still_active function implemented
- [ ] LDAP user status check implemented
- [ ] Group membership re-validation implemented
- [ ] Session invalidation on authorization revocation implemented
- [ ] last_authz_check timestamp tracking implemented
- [ ] Configurable re-check interval implemented
- [ ] Tests verify session invalidation on revocation
- [ ] Tests verify re-check interval respected
- [ ] Documentation updated

### References
- ASVS 8.3.2 (L3)
- Files: `v3/server/pages.py:67-93`
- Related: FINDING-098

### Priority
Medium

---

## Issue: FINDING-112 - No Device Security Posture Assessment or Contextual Risk Analysis
**Labels:** security, priority:medium, authentication, risk-analysis
**Description:**
### Summary
ASVS 8.4.2 explicitly requires 'device security posture assessment' and 'contextual risk analysis' for administrative interfaces. System has no implementation of device fingerprinting, behavioral analysis, geographic/IP risk scoring, session binding to device characteristics, or anomaly detection for administrative operations.

### Details
**Missing capabilities**:
- Device fingerprinting
- Behavioral analysis (rapid successive operations, unusual access patterns)
- Geographic/IP risk scoring
- Session binding to device characteristics
- Anomaly detection for administrative operations

**Risk**: Compromised credentials from any network location grant full administrative access with no contextual awareness.

**No adaptive controls** based on:
- IP address changes
- Time-of-day patterns
- Concurrent sessions
- Device changes

### Remediation
Implement `assess_admin_risk(uid, operation)` function calculating risk score based on:

```python
async def assess_admin_risk(uid, operation):
    """Calculate risk score for administrative operation."""
    risk_score = 0
    
    # 1. IP address consistency
    session_ip = session.get('last_ip')
    current_ip = request.remote_addr
    if session_ip and session_ip != current_ip:
        risk_score += 30
    
    # 2. Rapid successive admin operations
    last_admin = session.get('last_admin_timestamp', 0)
    if (time.time() - last_admin) < 5:  # < 5 seconds
        risk_score += 25
    
    # 3. User-Agent consistency
    session_ua = session.get('user_agent')
    current_ua = request.headers.get('User-Agent')
    if session_ua and session_ua != current_ua:
        risk_score += 20
    
    # 4. Time-of-day patterns
    hour = datetime.now().hour
    if hour < 6 or hour > 22:  # Outside business hours
        risk_score += 15
    
    # Log risk assessment
    _LOGGER.info(f'Admin risk assessment: User[U:{uid}] Operation[{operation}] Score[{risk_score}]')
    
    # Require step-up authentication if high risk
    if risk_score >= 50:
        require_step_up_authentication()
    
    # Update session context
    session['last_ip'] = current_ip
    session['last_admin_timestamp'] = time.time()
    session['user_agent'] = current_ua
    
    return risk_score
```

Apply to all administrative endpoints (lines 450-486).

### Acceptance Criteria
- [ ] assess_admin_risk function implemented
- [ ] IP consistency check implemented
- [ ] Rapid operation detection implemented
- [ ] User-Agent consistency check implemented
- [ ] Time-of-day analysis implemented
- [ ] Risk score calculation implemented
- [ ] Step-up authentication trigger implemented (score >= 50)
- [ ] Session context storage implemented
- [ ] Structured logging implemented
- [ ] Applied to all administrative endpoints
- [ ] Tests verify risk assessment
- [ ] Tests verify step-up authentication trigger
- [ ] Documentation updated

### References
- ASVS 8.4.2 (L3)
- Files: `v3/server/pages.py:450-486`
- CWE-306

### Priority
Medium

---

## Issue: FINDING-113 - No Adaptive Security Controls Based on Environmental/Contextual Attributes
**Labels:** security, priority:medium, session-management, adaptive-security
**Description:**
### Summary
Application doesn't implement adaptive security controls based on environmental or contextual attributes such as IP address changes during session, geolocation anomalies, device fingerprint changes, time-of-day restrictions, concurrent session detection, or unusual access patterns. Compromised session token can be used from any location, device, or context without triggering additional verification.

### Details
**Current state**: Uses server-side session validation but no contextual risk assessment or adaptive response.

**Missing controls**:
- IP address change detection
- Geolocation anomaly detection
- Device fingerprint change detection
- Time-of-day restrictions
- Concurrent session detection
- Unusual access pattern detection (e.g., managing elections outside business hours)

### Remediation
Implement session context validation:

```python
class ContextViolation(Exception):
    """Raised when session context validation fails."""
    pass

async def validate_session_context(session):
    """Validate session context and trigger adaptive controls."""
    
    # 1. IP-based session binding
    request_ip = quart.request.remote_addr
    stored_ip = session.get('bound_ip')
    if stored_ip and request_ip != stored_ip:
        raise ContextViolation('IP address changed')
    
    # 2. Device fingerprinting
    current_ua = quart.request.headers.get('User-Agent')
    stored_ua = session.get('user_agent')
    if stored_ua and current_ua != stored_ua:
        _LOGGER.warning(f'User-Agent changed for session {session.id}')
        # Consider requiring re-authentication
    
    # 3. Time-of-day restrictions for sensitive operations
    hour = datetime.now().hour
    if hour < 6 or hour > 22:  # Outside 6 AM - 10 PM
        if is_sensitive_operation():
            require_step_up_authentication()
    
    # 4. Geolocation validation (if IP geolocation service available)
    current_geo = await get_geolocation(request_ip)
    stored_geo = session.get('geolocation')
    if stored_geo and current_geo.country != stored_geo.country:
        _LOGGER.warning(f'Geographic location changed: {stored_geo.country} -> {current_geo.country}')
        require_step_up_authentication()
    
    # 5. Concurrent session detection
    active_sessions = await get_active_sessions(session['uid'])
    if len(active_sessions) > MAX_CONCURRENT_SESSIONS:
        _LOGGER.warning(f'User {session["uid"]} has {len(active_sessions)} concurrent sessions')
        # Alert user or require re-authentication
```

Apply validation before sensitive operations.

### Acceptance Criteria
- [ ] IP-based session binding implemented
- [ ] Device fingerprinting implemented
- [ ] Time-of-day restrictions implemented
- [ ] Geolocation validation implemented (if service available)
- [ ] Concurrent session detection implemented
- [ ] Step-up authentication triggers implemented
- [ ] Context violation handling implemented
- [ ] Applied before sensitive operations
- [ ] Tests verify context validation
- [ ] Tests verify step-up authentication triggers
- [ ] Configurable thresholds documented
- [ ] Documentation updated

### References
- ASVS 8.2.4 (L3)
- Files: `v3/server/pages.py:67-93`

### Priority
Medium

---

## Issue: FINDING-114 - Incomplete Function-Level Authorization Documentation
**Labels:** security, priority:medium, documentation, authorization
**Description:**
### Summary
Authorization documentation partially defines access rules but lacks comprehensive function-level access control specification. While documentation mentions ownership (owner_pid) and LDAP group authorization (authz), it doesn't provide complete mapping of which functions/operations each role can perform.

### Details
**Missing documentation**:
- No explicit listing of all protected functions (open, close, add-issue, edit-issue, delete-issue, set-dates, vote, tally)
- No matrix mapping consumer permissions (owner, authz group member, eligible voter, committer, PMC member) to allowed operations
- authz field format explicitly marked 'TBD' (incomplete design)
- No documentation of R.committer vs R.pmc_member distinction for election creation vs management
- No documentation of 'committer' status grants vs 'owner' status

### Remediation
Create comprehensive field-level access control documentation:

**Field-Level Access Control Matrix**:

| Field | Owner (Read) | Owner (Write) | Voter (Read) | Voter (Write) | State Dependency | Notes |
|-------|-------------|---------------|-------------|---------------|------------------|-------|
| eid | Yes | Never | Yes | Never | - | System-generated ID |
| title | Yes | EDITABLE only | Yes | Never | - | Election title |
| owner_pid | Yes | Never | No | Never | - | Ownership field |
| authz | Yes | EDITABLE only | No | Never | - | LDAP group authorization |
| salt | Never | Never | Never | Never | - | System-only cryptographic material |
| opened_key | Never | Never | Never | Never | - | System-only cryptographic material |
| open_at | Yes | Yes | Yes | Never | - | Advisory date |
| close_at | Yes | Yes | Yes | Never | - | Advisory date |
| state | Yes | Never | Yes | Never | - | State machine managed |

**Function-Level Access Control Matrix**:

| Operation | Owner | Authz Group Member | Eligible Voter | Committer | PMC Member |
|-----------|-------|-------------------|----------------|-----------|------------|
| create-election | No | No | No | No | Yes |
| open-election | Yes | Yes | No | No | No |
| close-election | Yes | Yes | No | No | No |
| add-issue | Yes | Yes | No | No | No |
| edit-issue | Yes | Yes | No | No | No |
| delete-issue | Yes | Yes | No | No | No |
| set-dates | Yes | Yes | No | No | No |
| vote | No | No | Yes | No | No |
| tally | Yes | Yes | No | No | No |

### Acceptance Criteria
- [ ] Field-level access control matrix created
- [ ] Function-level access control matrix created
- [ ] State dependencies documented
- [ ] System-only fields identified
- [ ] Role definitions clarified
- [ ] authz field format finalized (not 'TBD')
- [ ] Documentation added to schema.md or separate ACCESS_CONTROL.md

### References
- ASVS 8.1.1, 8.1.2 (L1-L2)
- Files: `v3/docs/schema.md`

### Priority
Medium

---

## Issue: FINDING-115 - Missing Documentation of Environmental and Contextual Security Attributes
**Labels:** security, priority:medium, documentation, contextual-security
**Description:**
### Summary
Application documentation doesn't define environmental or contextual attributes used in security decisions. No documentation of whether time of day, user location, IP address, device type, or other contextual factors influence authentication or authorization decisions.

### Details
**Existing but undocumented**:
- open_at and close_at fields exist but SQL comment states: "These are purely advisory, for humans, and have no effect upon the actual Election operation."

**Missing documentation**:
- No IP-based restrictions documented
- No geographic restrictions documented
- No device/browser-based security decisions documented
- @asfquart.auth.require decorator handles authentication but no documentation defines what contextual factors authentication system evaluates

### Remediation
Document all environmental/contextual attributes (or explicitly state none are used):

**Environmental and Contextual Attributes Documentation**:

**Attributes NOT Used** (with intentional design decisions):
- **Time-of-day restrictions**: NOT USED (intentional - ASF is global organization with contributors in all time zones)
- **IP address restrictions**: NOT USED (intentional - contributors work from various locations)
- **Device type restrictions**: NOT USED (intentional - support for diverse platforms)
- **Geographic location**: NOT USED (intentional - global contributor base)

**Attributes that ARE Used**:
- **Authentication session**: OAuth via ASF IdP, session timeout per ASF IdP configuration
- **LDAP group membership**: Evaluated at request time
- **Election state**: Managed through explicit state transitions, not time-based

**Rationale**:
ASF is a global organization with contributors working from diverse locations, devices, and time zones. Contextual restrictions based on location or time would impede legitimate use. Security relies on strong authentication (OAuth + MFA) and explicit authorization (ownership + LDAP groups) rather than environmental heuristics.

### Acceptance Criteria
- [ ] Environmental attributes documentation created
- [ ] Attributes NOT used explicitly documented with rationale
- [ ] Attributes that ARE used documented
- [ ] Design decisions explained
- [ ] Documentation added to schema.md or SECURITY.md

### References
- ASVS 8.1.3 (L3)
- Files: `v3/docs/schema.md`, `v3/server/pages.py`

### Priority
Medium

---

## Issue: FINDING-116 - Missing Documentation of Environmental Factors in Authorization Decision-Making
**Labels:** security, priority:medium, documentation, authorization
**Description:**
### Summary
No documentation defining how environmental and contextual factors are used in authentication and authorization decision-making, including thresholds, risk levels, and actions taken. Since no environmental/contextual attributes documented (FINDING-115), there's no documentation of decision logic, evaluated attributes, risk thresholds, or resulting actions (allow/challenge/deny/step-up).

### Details
**Missing documentation**:
- No risk scoring model
- No step-up authentication triggers
- No adaptive authentication rules
- No documentation of when 'deny' vs 'challenge' applies
- No documentation of how ASF IdP session interacts with application's authorization layer
- No documentation of what happens when LDAP group membership changes mid-session

### Remediation
Create comprehensive decision-making framework documentation:

**Authentication Decision Flow**:

| Context | Evaluation | Threshold | Action |
|---------|-----------|-----------|--------|
| Valid session | Session exists in store AND not expired | N/A | Allow - proceed with request |
| Expired session | Session exists but expired | Session timeout (per ASF IdP) | Deny - redirect to login (HTTP 401) |
| No session | No session in store | N/A | Deny - redirect to login (HTTP 401) |

**Authorization Decision Flow**:

| Operation | Evaluation | Threshold | Action |
|-----------|-----------|-----------|--------|
| Election management | User is owner OR member of authz LDAP group | Exact match required | Allow if authorized, Deny (HTTP 403) if not |
| Vote casting | User in mayvote table for this election | Exact match required | Allow if eligible, Deny (HTTP 403) if not |
| Election creation | User has R.pmc_member role | Role membership required | Allow if PMC member, Deny (HTTP 403) if not |

**Factors NOT Evaluated** (design decisions):
- **IP address changes during session**: Not evaluated (global user base with legitimate IP changes)
- **Concurrent sessions**: Not restricted (users may legitimately access from multiple devices)
- **Rate limiting**: Delegated to reverse proxy layer (not application responsibility)

**Session-IdP Interaction**:
- Application session lifetime MUST NOT exceed IdP session lifetime
- Session invalidation triggered by IdP backchannel logout (if implemented)
- LDAP group membership changes effective on next authorization check (no mid-session re-validation unless FINDING-111 implemented)

### Acceptance Criteria
- [ ] Authentication decision flow documented
- [ ] Authorization decision flow documented
- [ ] Factors NOT evaluated documented with rationale
- [ ] Session-IdP interaction documented
- [ ] Risk thresholds defined (if applicable)
- [ ] Actions (Allow/Deny/Challenge/Step-up) specified
- [ ] HTTP status codes documented
- [ ] Documentation added to AUTHORIZATION.md or SECURITY.md

### References
- ASVS 8.1.4 (L3)
- Files: All documentation files
- Related: FINDING-115

### Priority
Medium

---

## Issue: FINDING-117 - No Session Inactivity Timeout or Absolute Session Lifetime Documentation/Configuration
**Labels:** security, priority:medium, session-management, timeout
**Description:**
### Summary
No session inactivity timeout configured anywhere in codebase. No absolute maximum session lifetime defined. asfquart.session.read() called without visible timeout parameters. No documentation addresses session timeout decisions or deviations from NIST SP 800-63B. Sessions could persist indefinitely, increasing risk of session hijacking on shared/public workstations.

### Details
**NIST SP 800-63B §7.2 recommendations**:
- Re-authentication after 30 minutes of inactivity at AAL1
- Re-authentication after 15 minutes at AAL2

**Missing**:
- No timeout configuration
- No documentation
- No security review of timeout appropriateness for risk level

### Remediation
Implement session inactivity timeout mechanism:

```python
SESSION_INACTIVITY_TIMEOUT = 30 * 60  # 30 minutes

async def basic_info():
    s = await asfquart.session.read()
    if s:
        last_activity = s.get('last_activity', 0)
        now = time.time()
        
        if now - last_activity > SESSION_INACTIVITY_TIMEOUT:
            await asfquart.session.destroy()
            quart.abort(401, 'Session expired due to inactivity')
        
        s['last_activity'] = now
        await asfquart.session.save(s)
```

**Configuration**:
1. Add SESSION_INACTIVITY_TIMEOUT configuration (e.g., 30 minutes)
2. Store last_activity timestamp in session data
3. Implement middleware or modify basic_info() to check elapsed time
4. Update last_activity timestamp on each request
5. Destroy session and return 401 if timeout exceeded

### Acceptance Criteria
- [ ] SESSION_INACTIVITY_TIMEOUT configuration added
- [ ] last_activity timestamp tracking implemented
- [ ] Timeout check implemented on each request
- [ ] Session destruction on timeout implemented
- [ ] 401 response on timeout implemented
- [ ] Timeout value documented with NIST justification
- [ ] Tests verify timeout enforcement
- [ ] Documentation updated

### References
- ASVS 7.1.1, 7.3.1 (L2)
- Files: `v3/server/pages.py:58-84`
- NIST SP 800-63B §7.2

### Priority
Medium

---

## Issue: FINDING-118 - No Concurrent Session Policy Documentation or Enforcement
**Labels:** security, priority:medium, session-management, policy
**Description:**
### Summary
No documentation defines how many concurrent sessions permitted per account. No session counting or session listing mechanism exists. No behavior defined for when maximum sessions reached (deny new login, terminate oldest, or alert user). Election system allows voting operations—if attacker establishes parallel session after stealing credentials, there's no detection or limitation mechanism.

### Details
**Missing**:
- Concurrent session limit documentation
- Session counting mechanism
- Session listing mechanism
- Behavior on limit reached
- Detection of parallel sessions

**Risk**: Stolen credentials can establish parallel session without detection.

### Remediation
Document concurrent session policy and implement controls:

**Documentation** (session-management-policy.md):
- **Maximum concurrent sessions per account**: 3
- **When maximum reached**: Oldest session is invalidated
- **Justification**: Allows legitimate use across desktop/mobile while detecting credential sharing or compromise
- **Notification**: Users notified on login if other active sessions exist

**Implementation**:
```python
async def enforce_session_limits(uid):
    active_sessions = await session_store.get_active_sessions(uid)
    MAX_CONCURRENT = 3
    
    if len(active_sessions) >= MAX_CONCURRENT:
        oldest = min(active_sessions, key=lambda s: s.created_at)
        await session_store.invalidate(oldest.session_id)
        _LOGGER.warning(
            f'User[U:{uid}] exceeded max sessions; terminated oldest'
        )
```

### Acceptance Criteria
- [ ] Concurrent session policy documented
- [ ] Maximum session limit defined (recommend 3)
- [ ] Session counting implemented
- [ ] Session listing implemented
- [ ] Oldest session termination implemented
- [ ] User notification on login implemented
- [ ] Tests verify session limit enforcement
- [ ] Tests verify oldest session termination
- [ ] Documentation added to session-management-policy.md

### References
- ASVS 7.1.2 (L2)
- Files: `v3/server/pages.py`

### Priority
Medium

---

## Issue: FINDING-119 - Federated Identity System (ASF SSO) Interaction Undocumented
**Labels:** security, priority:medium, documentation, sso, federation
**Description:**
### Summary
Application uses asfquart.auth and asfquart.session integrating with ASF identity management ecosystem (LDAP and OAuth/SSO). No documentation details: how ASF SSO session coordinates with application session, what happens when SSO session expires but local session persists, how session termination propagates between systems, conditions requiring re-authentication, or session lifetime coordination between IdP and application.

### Details
**Missing documentation**:
- SSO-application session coordination
- SSO session expiration handling
- Session termination propagation
- Re-authentication requirements (sensitive operations)
- Session lifetime coordination

**Risk without documentation**:
- Orphaned local sessions after SSO logout
- Inconsistent session lifetimes between IdP and application
- Missing re-authentication for high-privilege operations
- No coordinated session termination in incident response

### Remediation
Create federated session management documentation:

**Systems in Ecosystem**:
- ASF OAuth/SSO Identity Provider
- STeVe Application
- LDAP Directory

**Session Coordination**:
- Local session MUST NOT exceed IdP session lifetime
- Application checks IdP token validity on sensitive operations
- Logout from IdP triggers backchannel logout notification

**Re-authentication Requirements**:
Operations requiring re-verification of IdP session:
- Opening an election
- Closing an election
- Tallying votes

**Session Termination**:
- **User-initiated logout**: Invalidates both local and IdP sessions
- **IdP-initiated revocation**: Must invalidate local session within 5 minutes
- **Administrative session revocation**: Propagates immediately

### Acceptance Criteria
- [ ] Federated session management documentation created
- [ ] Systems in ecosystem documented
- [ ] Session coordination documented
- [ ] Re-authentication requirements specified
- [ ] Session termination procedures documented
- [ ] Session lifetime coordination specified
- [ ] Backchannel logout documented (if applicable)
- [ ] Documentation added to FEDERATION.md or SECURITY.md

### References
- ASVS 7.1.3 (L2)
- Files: `v3/server/pages.py:1-36`

### Priority
Medium

---

## Issue: FINDING-120 - No Visible Session Token Regeneration on Authentication
**Labels:** security, priority:high, session-management, session-fixation
**Description:**
### Summary
Application code doesn't contain explicit login endpoint or authentication handler where session token regeneration could occur. Authentication entirely delegated to asfquart.auth framework via decorators. No evidence that new session token generated upon successful authentication, old session token invalidated upon re-authentication, or session fixation protections implemented at application level.

### Details
**Current state**: asfquart.session.read() only reads existing session data—doesn't create or rotate sessions.

**Risk**: If underlying asfquart framework doesn't regenerate session tokens on authentication, application is vulnerable to session fixation attacks. Attacker who sets or knows user's session ID before login could hijack session after user authenticates.

### Remediation
After successful authentication, framework or application should:

1. **Invalidate old session**:
   ```python
   await asfquart.session.destroy()
   ```

2. **Create new session with fresh token**:
   ```python
   new_session = await asfquart.session.create()
   ```

3. **Populate new session with user data**:
   ```python
   new_session.update({
       'uid': uid,
       'fullname': fullname,
       'email': email
   })
   ```

4. **Save the new session**:
   ```python
   await asfquart.session.save(new_session)
   ```

**Note**: This may be handled by asfquart framework outside visible code scope. Verification with framework documentation required.

### Acceptance Criteria
- [ ] Session token regeneration verified in asfquart framework OR implemented in application
- [ ] Old session invalidated on authentication
- [ ] New session created with fresh token
- [ ] User data populated in new session
- [ ] Session fixation attack prevented
- [ ] Tests verify session token changes on authentication
- [ ] Tests verify old session token invalid after authentication
- [ ] Documentation updated

### References
- ASVS 7.2.4 (L1)
- Files: `v3/server/pages.py:58-85`

### Priority
High

## Issue: FINDING-121 - No option to terminate other sessions after authentication factor change
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Users cannot terminate other active sessions after credential changes, allowing compromised sessions to remain valid indefinitely.

### Details
The application provides `/profile` and `/settings` pages but lacks functionality to manage active sessions. There is no password change endpoint, MFA configuration, session listing, or session termination feature. If a user's credentials are compromised and changed through an external identity provider, all existing sessions (including attacker sessions) remain valid with no user-controlled invalidation mechanism.

**Affected Files:**
- `v3/server/pages.py:535-549`

**CWE:** Not specified
**ASVS:** 7.4.3 (L2)

### Remediation
Implement a session termination endpoint:
1. Add POST endpoint `/do-terminate-other-sessions`
2. Retrieve current session ID
3. Invalidate all other sessions via `session_store.invalidate_all_except(result.uid, current_session_id)`
4. Log the action and redirect to settings
5. Implement session-to-user mapping for PID-based session lookup
6. Add active session listing to `/settings` page

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 7.4.3.md
- Related: ASVS-743-MED-001

### Priority
Medium

---

## Issue: FINDING-122 - No re-authentication enforced before sensitive account modifications
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Sensitive account modifications can be performed with only an existing session, without requiring recent re-authentication.

### Details
The `/profile` and `/settings` pages require authentication but do not enforce re-authentication before modifications. If an attacker gains access to an active session (XSS, session fixation, physical access), they can modify sensitive attributes without credential verification. The CSRF token is currently a placeholder (`basic.csrf_token = 'placeholder'` at line 83).

**Affected Files:**
- `v3/server/pages.py:535-548`
- `v3/server/pages.py:83`

**CWE:** Not specified
**ASVS:** 7.5.1 (L2)

### Remediation
Implement re-authentication middleware:
```python
async def require_reauthentication():
    """Check if user has recently re-authenticated (within last 5 minutes)."""
    s = await asfquart.session.read()
    reauth_time = s.get('last_reauth')
    if not reauth_time or (time.time() - reauth_time) > 300:
        return quart.redirect(f'/auth/reauth?return_to={quart.request.path}')
    return None

@APP.post('/do-update-profile')
@asfquart.auth.require
async def do_update_profile():
    redirect = await require_reauthentication()
    if redirect:
        return redirect
    # ... proceed with attribute changes
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 7.5.1.md
- Related: ASVS-751-MED-001

### Priority
Medium

---

## Issue: FINDING-123 - Creating elections lacks step-up authentication
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Election creation, a privileged operation, requires only basic session authentication without additional verification.

### Details
The `do_create_endpoint` function processes election creation with only `R.pmc_member` session authentication. No recent re-authentication or secondary verification is required for this sensitive operation that affects organizational governance.

**Affected Files:**
- `v3/server/pages.py:410-427`

**CWE:** Not specified
**ASVS:** 7.5.3 (L3)

### Remediation
Implement step-up authentication:
1. Create `require_step_up_auth` function
2. Require recent authentication (within 5 minutes)
3. Apply to election creation endpoint before processing

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 7.5.3.md
- Related: ASVS-753-MED-001

### Priority
Medium

---

## Issue: FINDING-124 - No validation of session freshness or maximum time between IdP authentication events
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Application does not validate IdP session freshness, allowing local sessions to persist after IdP session expiration or revocation.

### Details
The application reads session data from SSO provider without validating when the user last authenticated at the IdP level. If the IdP session expires or is revoked, the application's local session may remain valid, creating a disconnect. Users removed from PMC/committer groups at the IdP level may retain voting access.

**Affected Files:**
- `v3/server/pages.py:68-84`

**CWE:** Not specified
**ASVS:** 7.6.1 (L2)

### Remediation
Implement IdP authentication freshness checking:
1. Validate `auth_time` claims from IdP
2. Check if `idp_auth_time` exists in session
3. Compare `(time.time() - idp_auth_time)` against `MAX_IDP_AUTH_AGE` (e.g., 3600 seconds)
4. If exceeded, redirect to `/auth?login=` to force re-authentication

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 7.6.1.md
- Related: ASVS-761-MED-001

### Priority
Medium

---

## Issue: FINDING-125 - Silent Session Creation via Federated Re-authentication Without User Consent
**Labels:** bug, security, priority:medium
**Description:**
### Summary
OAuth flow lacks `prompt` parameter, allowing silent session creation without explicit user consent when IdP session is active.

### Details
The OAuth initialization URL does not include a `prompt` parameter (such as `prompt=login` or `prompt=consent`). When a user has an active IdP session but no RP session, accessing protected pages triggers silent re-authentication and session creation without user interaction. An attacker could trigger silent session creation by embedding hidden requests to protected pages.

**Affected Files:**
- `v3/server/main.py:36-40`

**CWE:** Not specified
**ASVS:** 7.6.2 (L2)

### Remediation
Two options:
1. Add `prompt=consent` or `prompt=login` to OAuth URL: Change `OAUTH_URL_INIT` to include `&prompt=consent`
2. Implement login interstitial page with explicit 'Continue to login' button as sole OAuth entry point

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 7.6.2.md
- Related: ASVS-762-MED-001

### Priority
Medium

---

## Issue: FINDING-126 - Flash messages embed user-controlled input without encoding
**Labels:** bug, security, priority:medium
**Description:**
### Summary
User-controlled input in flash messages is not HTML-encoded at creation, deferring encoding responsibility to templates and creating potential XSS vulnerability.

### Details
User input (e.g., `form.title`) is embedded in flash messages without HTML encoding at the point of creation. Encoding responsibility is split between server code and templates with no guarantee the template applies it. If the `flashes.ezt` template outputs without HTML encoding, this creates a reflected XSS vulnerability.

**Affected Files:**
- `v3/server/pages.py:430`
- `v3/server/pages.py:491`
- `v3/server/pages.py:513`
- `v3/server/pages.py:531`

**CWE:** CWE-79
**ASVS:** 1.1.2 (L2)

### Remediation
HTML-encode at flash message creation:
```python
import html
await flash_success(f'Created election: {html.escape(form.title)}')
```
Or ensure flashes template uses `[format "html"]`.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 1.1.2.md
- Related: ASVS-112-MED-001, FINDING-003, FINDING-004, FINDING-030-035, FINDING-127-128

### Priority
Medium

---

## Issue: FINDING-127 - Election titles and user names output without HTML encoding across multiple templates
**Labels:** bug, security, priority:medium
**Description:**
### Summary
User-controlled data including election titles and person names are output in multiple templates without HTML encoding.

### Details
Election titles (set by PMC members) and names (from PersonDB/LDAP) are output in multiple templates (`header.ezt`, `admin.ezt`, `voter.ezt`, `manage.ezt`, `vote-on.ezt`) without `[format "html"]` encoding. An attacker with PMC member or LDAP write access could inject HTML/JavaScript rendering for all users viewing affected elections.

**Affected Files:**
- `v3/server/templates/header.ezt`
- `v3/server/templates/admin.ezt`
- `v3/server/templates/voter.ezt`
- `v3/server/templates/manage.ezt`
- `v3/server/templates/vote-on.ezt`

**CWE:** CWE-79
**ASVS:** 3.2.2 (L1)

### Remediation
Apply `[format "html"]` to ALL user-controlled template variables:
```
<title>Apache STeVe: [format "html"][title][end]</title>
<h5 class="card-title">[format "html"][owned.title][end]</h5>
<strong>[format "html"][issues.title][end]</strong>
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 3.2.2.md
- Related: ASVS-322-MED-001, FINDING-003, FINDING-004, FINDING-030-035, FINDING-126, FINDING-128

### Priority
Medium

---

## Issue: FINDING-128 - Missing JavaScript Encoding in HTML Attributes with Template Variables
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Template variables embedded in onclick attributes and DOM element IDs lack proper JavaScript encoding, creating defense-in-depth gap.

### Details
Template variables (e.g., `issues.iid`) are embedded in onclick attribute strings without `[format "js,html"]` applied. While IIDs are cryptographically generated and currently safe, the pattern is architecturally wrong. If ID generation changes or different data sources are used, this becomes exploitable.

**Affected Files:**
- `v3/server/templates/vote-on.ezt` (throughout `<script>` block)

**CWE:** CWE-79
**ASVS:** 1.2.3 (L1)

### Remediation
Apply `[format "js,html"]` to all template variables in HTML attributes containing JavaScript:
```
<span onclick="toggleDescription('[format "js,html"][issues.iid][end]')">
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 1.2.3.md
- Related: ASVS-123-MED-001, FINDING-003, FINDING-004, FINDING-030-035, FINDING-126-127

### Priority
Medium

---

## Issue: FINDING-129 - voter.ezt tab activation script embeds server value without JS encoding
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `voter.ezt` template embeds the `active_tab` value into JavaScript without proper encoding.

### Details
JavaScript code embeds server value without encoding: `var active = "[active_tab]";`. Currently uses fixed string values ('open', 'upcoming', 'past'), so impact is low in practice. However, the pattern is unsafe and could become exploitable if logic changes to accept user input or during refactoring.

**Affected Files:**
- `v3/server/templates/voter.ezt`

**CWE:** CWE-79
**ASVS:** 3.2.2 (L1)

### Remediation
Apply `[format "js"]` encoding:
```
var active = "[format "js"][active_tab][end]";
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 3.2.2.md
- Related: ASVS-322-MED-002, FINDING-003, FINDING-004, FINDING-030-035, FINDING-126-127

### Priority
Medium

---

## Issue: FINDING-130 - Missing URL encoding and HTML escaping in document link construction
**Labels:** bug, security, priority:high
**Description:**
### Summary
The `rewrite_description()` function constructs document links without proper URL encoding and HTML escaping, enabling XSS via attribute injection.

### Details
Function extracts filenames from 'doc:' patterns using regex `([^\s]+)` and directly injects into href attributes and tag bodies. Example exploit: `doc:"onmouseover="alert(1)"x="` results in `<a href="/docs/iid/"onmouseover="alert(1)"x="">...</a>`, creating XSS via event handler injection.

**Affected Files:**
- `v3/server/pages.py:54-56`

**CWE:** CWE-79
**ASVS:** 1.2.2, 1.3.1, 1.3.3 (L1, L2)

### Remediation
Apply URL encoding and HTML escaping:
```python
from urllib.parse import quote
import html

safe_href = quote(filename, safe='')
safe_display = html.escape(filename)
return f'<a href="/docs/{issue.iid}/{safe_href}">{safe_display}</a>'
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 1.2.2.md, 1.3.1.md, 1.3.3.md
- Related: ASVS-122-MED-001, INJ-002, FINDING-003, FINDING-004, FINDING-030-035, FINDING-126-127

### Priority
High

---

## Issue: FINDING-131 - Missing explicit canonicalization validation in document serving endpoint
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Document serving endpoint lacks explicit canonicalization validation for path parameters, relying solely on implicit protections.

### Details
While Quart performs URL decoding once and `send_from_directory` provides path traversal protection, there is no verification that `docname` or `iid` don't contain encoded sequences. The comment `### verify the propriety of DOCNAME.` acknowledges missing validation. IID is used to construct directory path before being passed to `send_from_directory`, validated only implicitly via database lookup.

**Affected Files:**
- `v3/server/pages.py:559-576`

**CWE:** Not specified
**ASVS:** 1.1.1 (L2)

### Remediation
Validate canonical form before processing:
```python
if '/' in docname or '\\' in docname or docname.startswith('.'):
    quart.abort(400)
if not iid.isalnum():
    quart.abort(400)
```
Perform validation before database lookup and path construction.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 1.1.1.md
- Related: ASVS-111-MED-001

### Priority
Medium

---

## Issue: FINDING-132 - No Content-Security-Policy headers on HTML responses
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Server generates HTML responses without CSP headers, removing defense-in-depth layer against XSS attacks.

### Details
No CSP header or meta tag restricts resource loading. If XSS occurs, attacker has full browser capability with unrestricted access to inline scripts, eval(), and cross-origin resource loading. CSP would serve as defense-in-depth against content rendering in unintended contexts.

**Affected Files:**
- `v3/server/templates/header.ezt`

**CWE:** Not specified
**ASVS:** 3.2.1 (L1)

### Remediation
Add CSP via middleware or response headers using `@after_request` decorator:
```python
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' https://www.apache.org; frame-ancestors 'none'
X-Content-Type-Options: nosniff
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 3.2.1.md
- Related: ASVS-321-MED-001

### Priority
Medium

---

## Issue: FINDING-133 - No Sec-Fetch-* header validation on API endpoints serving sensitive data
**Labels:** bug, security, priority:medium
**Description:**
### Summary
API endpoints lack Sec-Fetch-* header validation, reducing defense-in-depth against CSRF and resource misuse attacks.

### Details
Endpoints `do_set_open_at_endpoint`, `do_set_close_at_endpoint`, and `serve_doc` do not validate Sec-Fetch-* headers. Without validation, the application cannot distinguish between same-origin navigation requests and cross-origin or embed attempts.

**Affected Files:**
- `v3/server/pages.py` (multiple endpoints)

**CWE:** Not specified
**ASVS:** 3.2.1 (L1)

### Remediation
Create `validate_sec_fetch` decorator:
```python
def validate_sec_fetch(func):
    async def wrapper(*args, **kwargs):
        sec_fetch_site = quart.request.headers.get('Sec-Fetch-Site')
        if sec_fetch_site not in ('same-origin', 'none', None):
            quart.abort(403, 'Cross-origin request rejected')
        return await func(*args, **kwargs)
    return wrapper
```
Apply to sensitive endpoints.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 3.2.1.md
- Related: ASVS-321-MED-002

### Priority
Medium

---

## Issue: FINDING-134 - Form-Based POST Endpoints Accept CORS-Safelisted Content Types Without Origin Validation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Endpoints accepting `application/x-www-form-urlencoded` lack Origin validation, bypassing CORS preflight protection.

### Details
Requests with Content-Type `application/x-www-form-urlencoded` are CORS-safelisted and do NOT trigger preflight OPTIONS. Without CSRF token validation, Origin header validation, or non-safelisted header requirements, cross-origin form submissions can reach sensitive functionality without CORS preflight checks.

**Affected Files:**
- `v3/server/pages.py` (multiple POST endpoints)

**CWE:** Not specified
**ASVS:** 3.5.2 (L1)

### Remediation
Implement Origin header validation decorator:
```python
def validate_origin(func):
    async def wrapper(*args, **kwargs):
        origin = quart.request.headers.get('Origin')
        if origin and origin not in ALLOWED_ORIGINS:
            quart.abort(403, 'Invalid origin')
        return await func(*args, **kwargs)
    return wrapper
```
Additionally implement CSRF token validation and Content-Type validation.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 3.5.2.md
- Related: ASVS-352-MED-001

### Priority
Medium

---

## Issue: FINDING-135 - Authenticated Document Endpoint Serves Files Without XSSI Protections
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Document serving endpoint lacks browser-level origin separation controls, enabling cross-origin data extraction via script inclusion.

### Details
The `/docs/<iid>/<docname>` endpoint serves files to authenticated users after authorization checks but lacks origin separation controls. If JavaScript files are stored as election documents, an attacker can embed them via `<script src>` tags and extract authorized data. Browser sends cookies with cross-origin request, server authorizes it, but response is delivered to attacker's origin context for JavaScript parsing.

**Affected Files:**
- `v3/server/pages.py:651-666`

**CWE:** Not specified
**ASVS:** 3.5.7 (L3)

### Remediation
Add headers to `serve_doc` endpoint:
```python
response = await quart.send_from_directory(DOCSDIR / iid, docname)
response.headers['X-Content-Type-Options'] = 'nosniff'
response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
return response
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 3.5.7.md
- Related: ASVS-357-MED-001

### Priority
Medium

---

## Issue: FINDING-136 - No Cross-Origin-Resource-Policy Header on Any Authenticated Endpoint
**Labels:** bug, security, priority:medium
**Description:**
### Summary
No Cross-Origin-Resource-Policy response header is set anywhere in the application, removing critical defense-in-depth layer.

### Details
No CORP headers are set and no after-request middleware adds them. Without CORP headers, browsers rely solely on other mechanisms (SameSite cookies, CORS) to prevent cross-origin resource loading. Authenticated pages and resources can potentially be loaded in cross-origin contexts.

**Affected Files:**
- `v3/server/pages.py` (application-wide)

**CWE:** Not specified
**ASVS:** 3.5.8 (L3)

### Remediation
Implement `after_request` handler adding CORP headers:
- 'cross-origin' for public resources (static files, favicon)
- 'same-site' for landing/about pages
- 'same-origin' for all authenticated resources

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 3.5.8.md
- Related: ASVS-358-MED-001

### Priority
Medium

---

## Issue: FINDING-137 - Template Triggers State-Changing GET Requests via JavaScript Navigation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `manage.ezt` template uses `window.location.href` to trigger state changes via GET requests, inherently vulnerable to cross-origin exploitation.

### Details
Client-side code uses navigational JavaScript (`window.location.href`) for state-changing operations (open/close election) rather than POST form submissions. This reinforces server-side vulnerability by using navigational JavaScript exploitable via links, redirects, and top-level navigations.

**Affected Files:**
- `v3/server/templates/manage.ezt`

**CWE:** Not specified
**ASVS:** 3.5.8 (L3)

### Remediation
Replace `window.location.href` navigations with POST form submissions:
1. Create forms dynamically in JavaScript
2. Add CSRF token as hidden input
3. Append to document body
4. Submit programmatically

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 3.5.8.md
- Related: ASVS-358-MED-002

### Priority
Medium

---

## Issue: FINDING-138 - State-Changing Operations Using GET Method Without SameSite Protection
**Labels:** bug, security, priority:medium
**Description:**
### Summary
State-changing operations (open/close election) use GET method, trivially exploitable via image tags or link preloading.

### Details
Endpoints `/do-open/<eid>` and `/do-close/<eid>` use GET for state-changing operations. Without SameSite cookie protection, these are exploitable via `<img>` tags. Even with SameSite=Lax, GET-based operations remain vulnerable since Lax allows top-level navigation. Only SameSite=Strict would fully protect, but POST methods should be used regardless.

**Affected Files:**
- `v3/server/pages.py:468`
- `v3/server/pages.py:490`

**CWE:** CWE-352
**ASVS:** 3.3.2 (L2)

### Remediation
Change to POST methods with CSRF protection:
```python
@APP.post('/do-open/<eid>')
@asfquart.auth.require({R.committer})
@load_election
async def do_open_endpoint(election):
    # Validate CSRF token
    ...
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 3.3.2.md
- Related: ASVS-332-MED-001, FINDING-002, FINDING-005, FINDING-019

### Priority
Medium

---

## Issue: FINDING-139 - No CORS Configuration Visible in Application Code
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Application contains no visible CORS configuration, risking either failed legitimate API access or exposure to unauthorized origins.

### Details
No Access-Control-Allow-Origin header is set, no CORS middleware is registered, and no `@app.after_request` handler manages CORS headers. The api module is imported but not provided for review. If underlying framework doesn't provide CORS protection by default, application may either not serve cross-origin requests or expose sensitive data if CORS library is added later without proper configuration.

**Affected Files:**
- `v3/server/main.py:32-45`
- `v3/server/pages.py` (application-wide)

**CWE:** CWE-942
**ASVS:** 3.4.2 (L1)

### Remediation
Implement CORS configuration in `create_app()` or via middleware:
```python
ALLOWED_ORIGINS = {'https://whimsy.apache.org', 'https://www.apache.org'}

@app.after_request
async def set_cors_headers(response):
    origin = request.headers.get('Origin')
    if origin in ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Vary'] = 'Origin'
    return response
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 3.4.2.md
- Related: ASVS-342-MED-001

### Priority
Medium

---

## Issue: FINDING-140 - No X-Content-Type-Options: nosniff Header Set on HTTP Responses
**Labels:** bug, security, priority:medium
**Description:**
### Summary
All HTTP responses lack 'X-Content-Type-Options: nosniff' header, enabling MIME sniffing attacks.

### Details
Responses from `/static/<path:filename>` and `/docs/<iid>/<docname>` lack this header. If documents with ambiguous content types are served (e.g., uploaded file mistyped as `text/plain` containing HTML/JavaScript), browser MIME sniffing could interpret as executable content. This can lead to XSS via uploaded documents and weakens Cross-Origin Read Blocking (CORB) protection.

**Affected Files:**
- `v3/server/main.py` (application-wide)
- `v3/server/pages.py` (application-wide)

**CWE:** CWE-430
**ASVS:** 3.4.4 (L2)

### Remediation
Implement global after_request handler:
```python
@app.after_request
async def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 3.4.4.md
- Related: ASVS-344-MED-001

### Priority
Medium

---

## Issue: FINDING-141 - No Referrer-Policy Header Set on HTTP Responses
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Application does not set Referrer-Policy header, leaking sensitive election IDs and URL structure to third-party services.

### Details
When users navigate from pages containing election IDs (e.g., `/vote-on/<eid>`) to external links, browser sends full URL including sensitive election IDs in Referer header. This leaks election IDs (10-char hex), internal URL structure, and potentially sensitive hostname information for internal deployments.

**Affected Files:**
- `v3/server/main.py` (application-wide)
- `v3/server/pages.py` (application-wide)

**CWE:** CWE-200
**ASVS:** 3.4.5 (L2)

### Remediation
Implement global after_request handler:
```python
@app.after_request
async def set_security_headers(response):
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 3.4.5.md
- Related: ASVS-345-MED-001

### Priority
Medium

---

## Issue: FINDING-142 - Missing Redirect Allowlist and Validation Mechanism
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Application lacks centralized redirect validation control, risking future introduction of open redirects.

### Details
While current redirects are to internal paths, there is no defensive mechanism (allowlist, redirect validator, middleware) preventing future code changes from introducing open redirects. OAuth flow hardcodes external redirects to oauth.apache.org without validation framework. Domain context requires 'any redirects to external domains show user warnings' — this control is absent.

**Affected Files:**
- `v3/server/pages.py:353, 420, 437`
- `v3/server/main.py:37`

**CWE:** CWE-601
**ASVS:** 3.7.2 (L2)

### Remediation
Implement `safe_redirect()` utility with allowlist:
```python
ALLOWED_EXTERNAL_DOMAINS = {'oauth.apache.org'}

def safe_redirect(url, code=303):
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme and parsed.netloc:
        if parsed.netloc not in ALLOWED_EXTERNAL_DOMAINS:
            raise ValueError(f"Redirect to unauthorized domain: {parsed.netloc}")
    return quart.redirect(url, code=code)
```
Replace all `quart.redirect()` calls.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 3.7.2.md
- Related: ASVS-372-MED-001, FINDING-143

### Priority
Medium

---

## Issue: FINDING-143 - No User Notification When Redirecting to External OAuth Domain
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Application does not implement user notification or interstitial page when redirecting to external OAuth domain.

### Details
OAuth flow redirects users to `oauth.apache.org` without notification they are leaving the application. Domain context explicitly requires: 'any redirects to external domains show user warnings.' OAuth authentication (managed by `asfquart.generics`) redirects to `https://oauth.apache.org/auth?state=%s&redirect_uri=%s` without interstitial page.

**Affected Files:**
- `v3/server/main.py:37`
- `v3/server/pages.py` (application-wide)

**CWE:** CWE-601
**ASVS:** 3.7.3 (L3)

### Remediation
Implement interstitial page:
1. Create `/leaving` endpoint accepting `target` parameter
2. Validate target against `ALLOWED_EXTERNAL_DOMAINS`
3. Render template `leaving.ezt` showing destination domain
4. Provide proceed/cancel options

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 3.7.3.md
- Related: ASVS-373-MED-001, FINDING-142

### Priority
Medium

---

## Issue: FINDING-144 - No Browser Security Feature Detection or Warning Mechanism
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Application does not detect browser security feature support or warn users with outdated browsers.

### Details
No mechanism to detect whether user's browser supports expected security features (CSP, COOP, CORS, SameSite cookies). No client-side JavaScript feature detection, User-Agent analysis, or server-side checks identify outdated browsers. Users with outdated browsers (IE11, older mobile browsers) lacking modern security features would not be warned their session may be vulnerable.

**Affected Files:**
- `v3/server/pages.py` (application-wide)

**CWE:** CWE-1104
**ASVS:** 3.7.5 (L3)

### Remediation
Implement feature detection:
1. Create `static/js/browser-check.js` with feature detection (window.crypto, window.crypto.subtle, crossOriginIsolated)
2. Add `@APP.before_request` handler checking User-Agent for known-insecure browsers (MSIE, Trident/, Edge/12, Edge/13)
3. Display warnings using flash message infrastructure
4. Return 400 for insecure browser patterns

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 3.7.5.md
- Related: ASVS-375-MED-001

### Priority
Medium

---

## Issue: FINDING-145 - No TLS Version Configuration in Config Template
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Configuration template provides no guidance for specifying TLS protocol versions.

### Details
The `config.yaml.example` only includes certfile and keyfile fields without TLS protocol version settings. Administrators have no documented mechanism to enforce TLS 1.2+ or prefer TLS 1.3.

**Affected Files:**
- `v3/server/config.yaml.example:6-12`

**CWE:** Not specified
**ASVS:** 12.1.1 (L1)

### Remediation
Add TLS version configuration to example config:
```yaml
server:
  certfile: path/to/cert.pem
  keyfile: path/to/key.pem
  min_tls_version: '1.2'  # Minimum TLS version (1.2 or 1.3)
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 12.1.1.md
- Related: ASVS-1211-MED-001

### Priority
Medium

---

## Issue: FINDING-146 - OCSP Stapling Not Configured for TLS Server
**Labels:** bug, security, priority:medium
**Description:**
### Summary
No OCSP stapling is configured, preventing efficient client notification of certificate revocation.

### Details
Without OCSP stapling: clients must perform their own OCSP lookups (slower, privacy-leaking), many clients soft-fail OCSP checks meaning revoked certificates may still be accepted. Development configuration uses self-signed certificates (where OCSP not applicable), but production deployments need this.

**Affected Files:**
- `v3/server/main.py:75-82`
- `v3/server/config.yaml.example`

**CWE:** Not specified
**ASVS:** 12.1.4 (L3)

### Remediation
For production deployment:
1. Configure OCSP stapling in SSL context using `ssl.SSLContext` with `set_ocsp_client_callback`
2. For Hypercorn, add ssl configuration to `hypercorn.toml` with certfile and keyfile
3. Configure reverse proxy (nginx/Apache) with OCSP stapling enabled
4. Implement periodic refresh of OCSP response

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 12.1.4.md
- Related: ASVS-1214-MED-001

### Priority
Medium

---

## Issue: FINDING-147 - Self-Signed Certificates Used with No Pathway to Publicly Trusted Certificates
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Example configuration and documentation exclusively reference self-signed certificates without production guidance for publicly trusted certificates.

### Details
No production configuration example with publicly trusted certificates, no deployment documentation for publicly trusted TLS certs, no validation that configured certificates are publicly trusted. The `certs/` directory structure implies certificate storage alongside code. External-facing clients would encounter certificate warnings or be vulnerable to MITM attacks.

**Affected Files:**
- `v3/server/config.yaml.example:25-31`
- `v3/docs/quickstart.md:49-53`

**CWE:** Not specified
**ASVS:** 12.2.2 (L1)

### Remediation
Provide production configuration example:
```yaml
server:
  port: 443
  certfile: /etc/letsencrypt/live/voting.example.org/fullchain.pem
  keyfile: /etc/letsencrypt/live/voting.example.org/privkey.pem
```
Add deployment documentation requiring publicly trusted certificates. Consider integrating ACME (Let's Encrypt) provisioning.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 12.2.2.md
- Related: ASVS-1222-MED-001

### Priority
Medium

---

## Issue: FINDING-148 - No Visible TLS Certificate Validation for Outbound OAuth Connections
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Outbound HTTPS connections to oauth.apache.org lack visible certificate validation configuration.

### Details
Application makes outbound connections to oauth.apache.org for authentication. The HTTP client implementation is within asfquart (not provided), with no visible code confirming: TLS certificate validation is enabled (not verify=False), certificate chain is validated against system trust store, hostname verification is performed. While Python defaults to validating certificates, custom HTTP clients or misconfiguration could disable this.

**Affected Files:**
- `v3/server/main.py:44-49`

**CWE:** Not specified
**ASVS:** 12.3.2 (L2)

### Remediation
Verify asfquart library's HTTP client has certificate validation enabled. Add explicit configuration:
```python
import httpx
async with httpx.AsyncClient(verify=True) as client:
    response = await client.get(oauth_url)
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 12.3.2.md
- Related: ASVS-1232-MED-001

### Priority
Medium

---

## Issue: FINDING-149 - Self-Signed Certificates for Internal Use with No Trust Management
**Labels:** bug, security, priority:medium
**Description:**
### Summary
System uses self-signed certificates without internal CA configuration, trust store management, or certificate pinning.

### Details
No internal CA configuration or documentation, no trust store management for consuming services, no certificate pinning for internal connections, no guidance on which specific self-signed certificates should be trusted. If reverse proxy connects to this backend without proper trust configuration, it creates MITM risk on internal network.

**Affected Files:**
- `v3/docs/quickstart.md:49-53`
- `v3/server/config.yaml.example:25-31`

**CWE:** Not specified
**ASVS:** 12.3.4 (L2)

### Remediation
Establish internal CA and document certificate provisioning. Configure reverse proxy to pin specific backend certificate or trust only internal CA. Example nginx configuration:
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
- [ ] Fixed
- [ ] Test added

### References
- Source: 12.3.4.md
- Related: ASVS-1234-MED-001

### Priority
Medium

---

## Issue: FINDING-150 - Incomplete Documentation of Input Validation Rules
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Documentation defines structural rules for internal identifiers but fails to document validation rules for user-supplied input data.

### Details
Documentation (schema.md) lacks validation rules for: Election title (max length, allowed characters), Issue title/description, Vote string format per type, Person email format validation, Person name constraints, Date inputs format/range, Authorization group allowed values. Developers have no reference for valid input, leading to inconsistent validation.

**Affected Files:**
- `v3/docs/schema.md`
- `v3/server/pages.py`

**CWE:** Not specified
**ASVS:** 2.1.1 (L1)

### Remediation
Create `input-validation.md` document specifying validation rules. Example entries:
- Election Title: Type String, Required Yes, Max length 200 characters, Allowed Unicode printable no control characters
- Vote String (YNA): Type String, Required Yes, Allowed values yes/no/abstain, Case-insensitive
- Vote String (STV): Format Comma-separated candidate labels from issue's labelmap, Validation Each label must exist, no duplicates

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 2.1.1.md
- Related: ASVS-211-MED-001

### Priority
Medium

---

## Issue: FINDING-151 - No Documentation of Temporal Consistency Rules for Election Dates
**Labels:** bug, security, priority:medium
**Description:**
### Summary
State-based restrictions are enforced in code but not documented in business logic documentation.

### Details
Missing documentation for: Adding voters only valid when election.salt IS NULL (editable state), Adding issues only valid when editable, Voting only valid when election.salt IS NOT NULL AND closed != 1, Tallying only valid when closed = 1, Issue IID must belong to election's EID, Voter PID must have mayvote entry. Expected temporal relationships also undocumented: close_at must be after open_at if both set, open_at should be future when editable, neither date modifiable once closed.

**Affected Files:**
- `v3/docs/schema.md`
- `v3/server/pages.py`

**CWE:** Not specified
**ASVS:** 2.1.2 (L2)

### Remediation
Document expected temporal relationships and state-based restrictions in business logic documentation.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 2.1.2.md
- Related: ASVS-212-MED-001, IVBL-017

### Priority
Medium

---

## Issue: FINDING-152 - No Documentation of Per-User or Global Business Logic Limits
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Application documentation does not define limits on per-user or global operations, risking resource exhaustion.

### Details
No documented limits for: maximum elections per user, maximum issues per election, maximum voters per election/issue, rate limiting on vote submissions/election creation, maximum concurrent open elections, maximum title/description field lengths, maximum STV candidates/seats, timeout for operations. Without documented limits, application vulnerable to resource exhaustion.

**Affected Files:**
- `schema.md`
- `TODO.md`
- `create-election.py:67`
- `election.py:169`

**CWE:** Not specified
**ASVS:** 2.1.3 (L2)

### Remediation
Create business limits document specifying:
- Per-User limits: Max elections created 50 (configurable), Max concurrent open elections owned 10
- Per-Election limits: Max issues 500, Max eligible voters 10,000, Max STV candidates per issue 50, Max STV seats candidates - 1
- Global limits: Election title max length 200 characters, Issue title max length 200, Issue description max length 10,000

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 2.1.3.md
- Related: ASVS-213-MED-001

### Priority
Medium

---

## Issue: FINDING-153 - Date Validation Checks Format But Not Logical Business Constraints
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `_set_election_date()` function validates ISO date format but does not enforce business logic constraints.

### Details
Elections can be set with nonsensical dates: past dates, close dates before open dates, dates in far future. Validation only checks `datetime.fromisoformat()` success without verifying logical sense. Example: `{"date": "2020-01-01"}` accepted for close_at with no validation. Impact: Confusing/misleading date information, potential voter behavior manipulation.

**Affected Files:**
- `v3/server/pages.py:88-110`

**CWE:** Not specified
**ASVS:** 2.2.1, 2.3.2 (L1, L2)

### Remediation
Add business logic validation after format checking:
1. Reject dates in past (compare against `datetime.date.today()`)
2. Ensure close_at > open_at when both set
3. Add reasonable range limits (e.g., not more than 5 years future)
4. Return HTTP 400 with descriptive error messages

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 2.2.1.md, 2.3.2.md
- Related: ASVS-221-MED-001, ASVS-232-MED-001

### Priority
Medium

---

## Issue: FINDING-154 - Client-Side Required Field Validation Not Replicated Server-Side
**Labels:** bug, security, priority:medium
**Description:**
### Summary
HTML form uses client-side 'required' attribute but server-side handler does not verify field is non-empty.

### Details
The `do_add_issue_endpoint` does not check if `form.title` is empty or contains only whitespace. This allows bypassing client-side validation by sending direct HTTP request with empty title and description fields, creating issues with empty titles.

**Affected Files:**
- `v3/server/pages.py`
- `v3/server/templates/manage.ezt:92`

**CWE:** Not specified
**ASVS:** 2.2.2 (L1)

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
- [ ] Fixed
- [ ] Test added

### References
- Source: 2.2.2.md
- Related: ASVS-222-MED-001

### Priority
Medium

---

## Issue: FINDING-155 - No Validation That STV Vote Rankings Reference Valid Candidates
**Labels:** bug, security, priority:medium
**Description:**
### Summary
For STV issues, votestring should contain ranking of candidates from issue's labelmap, but this is not validated.

### Details
The `add_vote()` method stores votestring without checking that candidate labels match issue's labelmap, ranking count is valid, or there are no duplicate candidates. Combined data consistency (vote references valid candidates from issue metadata) is not validated.

**Affected Files:**
- `v3/steve/election.py:231-244`

**CWE:** Not specified
**ASVS:** 2.2.3 (L2)

### Remediation
Validate STV votes:
1. Each ranked candidate label exists in issue's kv.labelmap
2. No duplicate candidates
3. Ranking count does not exceed number of candidates in labelmap
4. Reject votes with non-existent candidates or duplicates

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 2.2.3.md
- Related: ASVS-223-MED-002

### Priority
Medium

---

## Issue: FINDING-156 - No Prerequisite Validation Before Election Opening
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Election can be opened without any issues or eligible voters, representing skipped step in business flow.

### Details
The `open()` method does not verify election has been properly configured with issues and voters before allowing state transition. Calling `/do-open/<eid>` immediately after creation succeeds but creates useless and irreversible election.

**Affected Files:**
- `v3/steve/election.py:70`
- `v3/server/pages.py:431`

**CWE:** Not specified
**ASVS:** 2.3.1 (L1)

### Remediation
Add prerequisite validation in `open()` method:
```python
issues = self.list_issues()
if not issues:
    raise ValueError('Cannot open election with no issues')
self.q_voting_persons.perform(self.eid)
voters = self.q_voting_persons.fetchall()
if not voters:
    raise ValueError('Cannot open election with no eligible voters')
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 2.3.1.md
- Related: ASVS-231-MED-001

### Priority
Medium

---

## Issue: FINDING-157 - Election Creation Script Has Transaction Code Commented Out
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `create-election.py` script has transaction wrapping code commented out, risking inconsistent state on partial failure.

### Details
Transaction code (BEGIN TRANSACTION, COMMIT, ROLLBACK) is commented out with TODO note. If voter addition fails partway through (e.g., PID not found), election is left with some but not all eligible voters without rollback.

**Affected Files:**
- `v3/server/bin/create-election.py:83-87`
- `v3/server/bin/create-election.py:109-112`

**CWE:** Not specified
**ASVS:** 2.3.3 (L2)

### Remediation
Re-enable transaction wrapping by uncommenting:
1. BEGIN TRANSACTION at start of try block
2. COMMIT/ROLLBACK statements in success and exception paths

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 2.3.3.md
- Related: ASVS-233-MED-001

### Priority
Medium

---

## Issue: FINDING-158 - Vote Table Allows Unlimited Re-Votes Without Locking or Rate Control
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Each call to `add_vote()` performs pure INSERT without limit on re-votes, potentially exhausting storage or degrading performance.

### Details
Every submission creates new row with no UPDATE or UPSERT pattern. No limit on rows per vote_token. Repeatedly POSTing to `/do-vote/<eid>` adds new row for each issue. After 1000 submissions, 1000 rows exist per vote_token, consuming storage and making tally queries slower.

**Affected Files:**
- `v3/steve/election.py:231`
- `v3/queries.yaml:44`

**CWE:** Not specified
**ASVS:** 2.3.4 (L2)

### Remediation
Consider either:
1. UPDATE pattern (replacing existing vote)
2. Limiting re-votes per voter per issue
3. Rate limiting on `/do-vote/<eid>` endpoint
4. Vote garbage collection to periodically remove superseded vote rows

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 2.3.4.md
- Related: ASVS-234-MED-001

### Priority
Medium

---

## Issue: FINDING-159 - Irreversible Election State Changes Require Only Single-User Action
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Opening/closing elections triggers irreversible operations requiring only single-user action without oversight.

### Details
Opening triggers irreversible cryptographic operations (salt generation, opened_key computation). Closing permanently ends voting. Both have significant organizational impact — voters may be disenfranchised by premature closure, or improperly configured election may be opened without review. Single user (or compromised account) can irreversibly alter election state.

**Affected Files:**
- `v3/server/pages.py:431`
- `v3/server/pages.py:451`

**CWE:** Not specified
**ASVS:** 2.3.5 (L3)

### Remediation
Add approval workflow with separate request and approval endpoints:
1. `/do-request-open/<eid>` to record request and notify approvers
2. `/do-approve-open/<eid>` to verify approver is different from requester, verify approver authority, and execute state change

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 2.3.5.md
- Related: ASVS-235-MED-001

### Priority
Medium

---

## Issue: FINDING-160 - No Rate Limiting on Authentication-Gated Page Views
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Authentication-gated page views lack rate limiting, allowing high-frequency requests to cause denial of service via query overload.

### Details
Pages `/voter`, `/admin`, and vote pages have no rate limiting. Each page view triggers multiple database queries with JOINs across mayvote, issue, election, and person tables. High-frequency requests from authenticated user could cause DoS via SQLite database query overload.

**Affected Files:**
- `v3/server/pages.py:133`
- `v3/server/pages.py:279`
- `v3/server/pages.py:221`

**CWE:** Not specified
**ASVS:** 2.4.1 (L2)

### Remediation
Apply general rate limiting at application or reverse-proxy level for all authenticated page views.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source: 2.4.1.md
- Related: ASVS-241-MED-001

### Priority
Medium

## Issue: FINDING-161 - No Minimum Time Enforcement in add_vote() Business Logic
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The business logic layer's add_vote() function has no concept of vote timing. There is no tracking of when a voter last submitted a vote, no minimum interval enforcement between re-votes, and the vote table lacks a timestamp column that could enable retroactive timing analysis. Combined with the handler-level lack of rate limiting, there is zero defense-in-depth against automated vote submission.

### Details
**Affected Files:**
- `v3/steve/election.py` (lines 180-194)

**CWE:** None specified
**ASVS:** 2.4.2 (Level L3)

The add_vote() function processes votes without any temporal validation. This creates multiple security gaps:
- No tracking of vote submission timestamps
- No minimum interval enforcement between successive votes
- Database schema lacks timestamp column for votes
- Zero defense-in-depth against automated voting attacks

### Remediation
Implement vote timing tracking in the add_vote() business logic by checking time since last vote by the same vote_token and raising a VoteTooRapid exception if the vote is submitted within MINIMUM_REVOTE_INTERVAL seconds.

### Acceptance Criteria
- [ ] Add timestamp column to votes table
- [ ] Implement vote timing tracking in add_vote()
- [ ] Create VoteTooRapid exception class
- [ ] Add MINIMUM_REVOTE_INTERVAL configuration
- [ ] Test added for rapid re-vote rejection
- [ ] Test added for legitimate re-vote acceptance

### References
- Source: 2.4.2.md
- Domain: input_validation_and_business_logic

### Priority
Medium

---

## Issue: FINDING-162 - Flash messages include unsanitized issue ID from form field names
**Labels:** bug, security, priority:medium, xss
**Description:**
### Summary
The do_vote_endpoint() function extracts issue ID from form field names using key.split('-', 1)[1] and includes it in flash messages without HTML escaping. This creates reflected XSS if the flash template renders message content without escaping.

### Details
**Affected Files:**
- `v3/server/pages.py` (line 443)

**CWE:** CWE-79 (Cross-site Scripting)
**ASVS:** 1.3.3 (Level L2)

Form field names in POST body (attacker-controlled) are processed by splitting on '-' and extracting everything after 'vote-', then passed to flash_danger() message which may be rendered in template as raw HTML. Example payload: `vote-<img src=x onerror=alert(1)>=yes`

**Related Findings:** FINDING-003, FINDING-004, FINDING-030, FINDING-031, FINDING-032, FINDING-033, FINDING-034, FINDING-035, FINDING-126, FINDING-127

### Remediation
Apply html.escape() to all user-controlled data included in flash messages: `import html; await flash_danger(f'Invalid issue ID: {html.escape(iid)}')`. Consider creating a wrapper function for safe flash messages.

### Acceptance Criteria
- [ ] Import html module in pages.py
- [ ] Apply html.escape() to all user-controlled flash message content
- [ ] Create safe_flash() wrapper functions
- [ ] Test added for XSS payload rejection
- [ ] Review all flash message calls for similar issues

### References
- Source: 1.3.3.md
- Domain: injection_prevention

### Priority
Medium

---

## Issue: FINDING-163 - Email Infrastructure Exists Without Visible Sanitization
**Labels:** bug, security, priority:medium, injection
**Description:**
### Summary
The method `get_voters_for_email()` retrieves voter data (name and email) from the database for email purposes. The `name` field originates from LDAP `cn` attribute and could theoretically contain SMTP header injection characters (`\r\n`) if LDAP data is malformed.

### Details
**Affected Files:**
- `v3/steve/election.py` (lines 335-342)

**CWE:** CWE-93 (SMTP Header Injection)
**ASVS:** 1.3.11 (Level L2)

Data flow: LDAP `cn` field → `pdb.add_person(uid, visname, email)` → database → `get_voters_for_email()` → email system. When used in email headers (To, From, Subject), malformed data could inject additional headers (BCC, CC) or alter message content. The email-sending code itself is not in the provided files, so sanitization at the send boundary cannot be verified.

### Remediation
Implement sanitization at the boundary where email is sent. Add a utility function to remove SMTP header injection characters:

```python
def sanitize_email_header(value: str) -> str:
    """Remove characters that could enable SMTP header injection."""
    return value.replace('\r', '').replace('\n', '').replace('\x00', '')

# When constructing email:
recipient_name = sanitize_email_header(voter.name)
recipient_email = sanitize_email_header(voter.email)
```

### Acceptance Criteria
- [ ] Create sanitize_email_header() utility function
- [ ] Apply sanitization to all email header fields
- [ ] Test added for CRLF injection attempts
- [ ] Document email sanitization requirements
- [ ] Review LDAP data validation

### References
- Source: 1.3.11.md
- Domain: injection_prevention

### Priority
Medium

---

## Issue: FINDING-164 - LDAP Operations Lack Defensive Coding for Future Extension
**Labels:** bug, security, priority:medium, future-risk
**Description:**
### Summary
The current LDAP search filter is hardcoded and safe. However, the application stores an 'authz' field in elections (LDAP group names), and the code contains multiple '### check authz' placeholders. When authorization checks are implemented, they will likely need to query LDAP with the authz value without a sanitization framework.

### Details
**Affected Files:**
- `v3/server/bin/asf-load-ldap.py` (line 48)

**CWE:** None specified
**ASVS:** 1.3.8 (Level L2)

Data flow: form.authz → Election.create() → stored in DB → (future) LDAP query → potential injection. Impact: Low currently (hardcoded filter), but when '### check authz' is implemented, LDAP special characters (*, (, ), \, NUL) in group names could enable LDAP injection if not escaped.

### Remediation
Implement LDAP filter escaping using ldap.filter.escape_filter_chars() before constructing LDAP filters with user-controlled values. Example:

```python
import ldap.filter

def safe_ldap_filter(group_name):
    """Escape LDAP special characters for filter construction."""
    escaped = ldap.filter.escape_filter_chars(group_name)
    return f'(cn={escaped})'
```

Integrate this as a mandatory step before implementing the '### check authz' functionality.

### Acceptance Criteria
- [ ] Create safe_ldap_filter() utility function
- [ ] Document LDAP injection prevention requirements
- [ ] Add test cases for LDAP special characters
- [ ] Review all '### check authz' placeholders
- [ ] Integrate sanitization before implementing authz checks

### References
- Source: 1.3.8.md
- Domain: injection_prevention

### Priority
Medium

---

## Issue: FINDING-165 - Missing File Handling Documentation for Issue Documents
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The application serves documents from `DOCSDIR/<iid>/` via the `/docs/<iid>/<docname>` endpoint, but there is no documentation defining: permitted file types, expected file extensions, maximum file size, or how the application handles malicious files detected during download/processing.

### Details
**Affected Files:**
- `v3/server/pages.py` (lines 560-574)
- `v3/docs/schema.md` (N/A)

**CWE:** None specified
**ASVS:** 5.1.1 (Level L2)

Without documented policies on accepted file types, extensions, and sizes, developers cannot implement consistent file validation. End users downloading served documents have no assurance that files have been vetted for malware or unsafe content (e.g., polyglot files, malicious macros).

### Remediation
Create explicit documentation specifying:
- Permitted file types for issue documents (e.g., PDF (.pdf) - application/pdf, Plain text (.txt) - text/plain, PNG images (.png) - image/png)
- Maximum file size (e.g., individual file: 10 MB, per-issue total: 50 MB)
- Malicious file handling procedures (e.g., files are scanned with ClamAV on upload, files failing validation are rejected with HTTP 415 and logged, served files include `Content-Disposition: attachment` header, X-Content-Type-Options: nosniff is set on all responses)

### Acceptance Criteria
- [ ] Create FILE_HANDLING.md documentation
- [ ] Define permitted file types and extensions
- [ ] Document file size limits
- [ ] Document malicious file handling procedures
- [ ] Document Content-Security-Policy for file serving

### References
- Source: 5.1.1.md
- Domain: file_upload_and_handling

### Priority
Medium

---

## Issue: FINDING-166 - No compressed file validation against uncompressed size and file count limits
**Labels:** bug, security, priority:medium, dos
**Description:**
### Summary
The application has a document serving mechanism but no visible handling or validation of compressed files (zip, gz, docx, odt, etc.). There is no code that detects compressed archives, checks maximum uncompressed size before extraction, limits maximum number of files within an archive, or prevents zip bomb attacks.

### Details
**Affected Files:**
- `v3/server/pages.py` (entire application scope)

**CWE:** None specified
**ASVS:** 5.2.3 (Level L2)

If compressed files (e.g., zip bombs) are placed in `DOCSDIR` through any mechanism, they could be served to users or potentially processed server-side without decompression limits, leading to denial of service.

### Remediation
Implement compressed file validation that checks:
1. If file is a compressed archive using zipfile.is_zipfile() or similar
2. Total number of files in archive against MAX_FILES_IN_ARCHIVE (e.g., 100)
3. Total uncompressed size against MAX_UNCOMPRESSED_SIZE (e.g., 100 MB)
4. Compression ratio to detect zip bombs (e.g., reject if ratio > 100)

Reject files failing any check with appropriate error messages.

### Acceptance Criteria
- [ ] Implement compressed file detection
- [ ] Add MAX_FILES_IN_ARCHIVE configuration
- [ ] Add MAX_UNCOMPRESSED_SIZE configuration
- [ ] Implement compression ratio validation
- [ ] Test added for zip bomb detection
- [ ] Document compressed file handling policy

### References
- Source: 5.2.3.md
- Domain: file_upload_and_handling

### Priority
Medium

---

## Issue: FINDING-167 - No per-user file quota or maximum file count enforcement
**Labels:** bug, security, priority:medium, dos
**Description:**
### Summary
There is no per-user file quota or maximum file count enforcement anywhere in the provided code or database schema. A single user (or compromised account) could fill available storage by uploading an unlimited number of files or excessively large files, causing denial of service for all users.

### Details
**Affected Files:**
- `v3/server/pages.py` (entire application scope)
- `v3/schema.sql` (database schema)

**CWE:** None specified
**ASVS:** 5.2.4 (Level L3)

The database schema contains tables for elections, issues, persons, mayvotes, and votes — but nothing tracking file storage per user. Documents are served from DOCSDIR/&lt;iid&gt;/ but there is no tracking of per-user storage consumption, maximum file count limits, or quota enforcement mechanism.

### Remediation
Add file tracking table to database schema with columns for file_id, pid, iid, filename, file_size, and uploaded_at. Implement quota checking function that validates against MAX_FILES_PER_USER (e.g., 50) and MAX_STORAGE_PER_USER (e.g., 500 MB) before accepting file uploads. Query user's current file count and total storage, rejecting uploads that would exceed limits.

### Acceptance Criteria
- [ ] Create file_tracking table in schema
- [ ] Add MAX_FILES_PER_USER configuration
- [ ] Add MAX_STORAGE_PER_USER configuration
- [ ] Implement quota checking function
- [ ] Test added for quota enforcement
- [ ] Document quota policy

### References
- Source: 5.2.4.md
- Domain: file_upload_and_handling

### Priority
Medium

---

## Issue: FINDING-168 - No symlink detection or prevention in compressed file handling
**Labels:** bug, security, priority:medium, path-traversal
**Description:**
### Summary
There is no handling of compressed files visible in the provided code, and consequently no symlink detection or prevention. If documents placed in DOCSDIR originated from extracted archives, symbolic links within those archives could allow access to sensitive files outside the intended directory.

### Details
**Affected Files:**
- `v3/server/pages.py` (entire application scope)

**CWE:** None specified
**ASVS:** 5.2.5 (Level L3)

While send_from_directory provides some protection against traversal, symlinks resolved at the filesystem level could bypass this. If an attacker can place a compressed file containing symlinks (e.g., pointing to /etc/passwd or the database file) and it gets extracted into DOCSDIR, the serve_doc endpoint could serve sensitive system files to authorized users.

### Remediation
Implement validation functions to detect and reject symlinks in archives before extraction. Use validate_no_symlinks() to check archive contents for symlink attributes. Implement safe_extract() to prevent both symlinks and path traversal during extraction. Add symlink check in serve_doc endpoint using filepath.is_symlink() and abort with 403 if detected. Consider mounting DOCSDIR filesystem with nosymfollow option to prevent symlink resolution at OS level.

### Acceptance Criteria
- [ ] Implement validate_no_symlinks() function
- [ ] Implement safe_extract() function
- [ ] Add symlink detection in serve_doc endpoint
- [ ] Test added for symlink rejection
- [ ] Document symlink prevention policy
- [ ] Consider nosymfollow mount option

### References
- Source: 5.2.5.md
- Domain: file_upload_and_handling

### Priority
Medium

---

## Issue: FINDING-169 - Missing application-level validation for user-supplied docname parameter in serve_doc()
**Labels:** bug, security, priority:medium, path-traversal
**Description:**
### Summary
The serve_doc() function uses the user-supplied docname URL parameter directly in send_from_directory() without application-level validation. The developer explicitly acknowledged this gap with the comment '### verify the propriety of DOCNAME.' While Quart's send_from_directory() internally uses safe_join() to prevent path traversal, there is no defense-in-depth validation at the application layer.

### Details
**Affected Files:**
- `v3/server/pages.py` (lines 560-574)

**CWE:** CWE-22 (Path Traversal)
**ASVS:** 5.3.2 (Level L1)

**Related Findings:** FINDING-279

Relying solely on framework internals without application-level validation creates risk if: 1) The framework is upgraded and safe_join behavior changes, 2) A bypass is discovered in safe_join, 3) The code is refactored to use a different file-serving mechanism.

### Remediation
Add an explicit allowlist regex (e.g., ^[a-zA-Z0-9][a-zA-Z0-9._-]*$) to validate docname and reject requests with invalid filenames including path traversal sequences. Validate before passing to send_from_directory() and abort with 400 for invalid filenames.

### Acceptance Criteria
- [ ] Define ALLOWED_FILENAME_PATTERN regex
- [ ] Add docname validation before send_from_directory()
- [ ] Return 400 for invalid filenames
- [ ] Test added for path traversal attempts
- [ ] Test added for valid filename acceptance
- [ ] Remove ### verify comment

### References
- Source: 5.3.2.md
- Domain: file_upload_and_handling

### Priority
Medium

---

## Issue: FINDING-170 - Missing filename validation and Content-Disposition header in document download endpoint
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The serve_doc() endpoint accepts a user-submitted filename via the docname URL parameter and uses it directly to serve files. There is no validation or sanitization of this filename, and no explicit Content-Disposition header is set in the response to override the user-controlled filename.

### Details
**Affected Files:**
- `v3/server/pages.py` (lines 560-574)

**CWE:** None specified
**ASVS:** 5.4.1, 5.4.2 (Level L2)

Without explicit filename validation: 1. The Content-Type of the response is derived from the user-controlled filename extension, which could cause browser behavior differences. 2. If the response includes a Content-Disposition header, the user-controlled filename could contain injection characters. 3. The lack of explicit Content-Disposition means the browser uses the URL's filename segment for Save As operations.

### Remediation
Implement filename validation using an allowlist regex (e.g., ^[a-zA-Z0-9][a-zA-Z0-9._-]*$) and reject requests with invalid filenames. Sanitize the filename using secure_filename() from werkzeug.utils. Serve files with explicit Content-Disposition header using as_attachment=True in send_from_directory(). Add X-Content-Type-Options: nosniff header for defense-in-depth. Implement file extension allowlist to only serve known-safe extensions (.pdf, .txt, .md, etc.).

### Acceptance Criteria
- [ ] Add filename validation with allowlist regex
- [ ] Import and use secure_filename()
- [ ] Set Content-Disposition: attachment header
- [ ] Add X-Content-Type-Options: nosniff header
- [ ] Implement file extension allowlist
- [ ] Test added for invalid filename rejection

### References
- Source: 5.4.1.md, 5.4.2.md
- Domain: file_upload_and_handling

### Priority
Medium

---

## Issue: FINDING-171 - No Antivirus Scanning for Documents Served to Users
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application serves per-issue documents directly to authenticated users without any antivirus or malware scanning. A malicious document (e.g., a PDF with embedded exploit, a malware-laden Office document, or an HTML file with scripts) placed in the docs directory would be served to all voters authorized for that issue.

### Details
**Affected Files:**
- `v3/server/pages.py` (lines 598-614, 50-57)

**CWE:** None specified
**ASVS:** 5.4.3 (Level L2)

Files are served from the DOCSDIR/{iid}/ directory structure and referenced in issue descriptions using the doc:filename syntax, which is converted into clickable download links. Files placed in the docs directory (whether by admin CLI scripts, manual upload, or an upload mechanism not shown) are served directly to authenticated users without malware scanning.

### Remediation
Implement antivirus scanning using ClamAV at serving time or at ingestion time. For serving time, integrate clamdscan to scan files before delivery with fail-closed behavior if scanner is unavailable. Add file extension whitelisting to restrict allowed document types (e.g., .pdf, .txt, .md, .html). Implement periodic background scanning of the docs directory to catch files that may have been clean at upload but later identified as malicious. Add a quarantine mechanism for suspicious files and log all scan results for security monitoring.

### Acceptance Criteria
- [ ] Integrate ClamAV scanning
- [ ] Implement fail-closed behavior if scanner unavailable
- [ ] Add file extension whitelist
- [ ] Implement periodic background scanning
- [ ] Create quarantine mechanism
- [ ] Log all scan results
- [ ] Document antivirus policy

### References
- Source: 5.4.3.md
- Domain: file_upload_and_handling

### Priority
Medium

---

## Issue: FINDING-172 - No evidence of header trust boundary enforcement
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The file imports and exposes `APP` from `asfquart` without any visible configuration to strip or reject user-supplied intermediary headers (e.g., `X-Forwarded-For`, `X-Real-IP`, `X-User-ID`). If `asfquart` or downstream handlers trust these headers without validation, an attacker could spoof their IP address or identity for access control bypass or audit log pollution.

### Details
**Affected Files:**
- `v3/server/api.py` (lines 1-21)

**CWE:** None specified
**ASVS:** 4.1.3 (Level L2, L3)

Data flow: External HTTP request → `X-Forwarded-For` header → `APP` request handling → potential trust of user-supplied value as intermediary-set value. While the `asfquart` framework may handle this internally, there is no visible control in the auditable codebase to confirm that end-users cannot inject headers that would be trusted as if set by intermediaries.

### Remediation
Configure the application or its framework to explicitly define trusted proxy sources and strip/ignore intermediary headers from untrusted origins. Example: Configure trusted proxies using APP.config['FORWARDED_ALLOW_IPS'] = '127.0.0.1,10.0.0.0/8' or use middleware to strip untrusted headers. This finding is classified as MEDIUM rather than CRITICAL because the control may exist in `asfquart` but cannot be verified from the provided source.

### Acceptance Criteria
- [ ] Configure FORWARDED_ALLOW_IPS in application config
- [ ] Implement middleware to strip untrusted headers
- [ ] Document trusted proxy configuration
- [ ] Test header injection attempts
- [ ] Verify asfquart header handling behavior

### References
- Source: 4.1.3.md
- Domain: api_endpoints

### Priority
Medium

---

## Issue: FINDING-173 - No visible HTTP message boundary validation or Transfer-Encoding/Content-Length conflict handling
**Labels:** bug, security, priority:medium, request-smuggling
**Description:**
### Summary
The file provides no configuration related to HTTP/1.1 request smuggling prevention. There is no visible rejection of requests with both Transfer-Encoding and Content-Length headers, HTTP/2 DATA frame length validation against Content-Length, or configuration ensuring the application server and reverse proxy agree on message boundaries.

### Details
**Affected Files:**
- `v3/server/api.py` (lines 1-21)

**CWE:** None specified
**ASVS:** 4.2.1 (Level L2, L3)

If the reverse proxy and Quart/Hypercorn disagree on how to parse the request boundary (e.g., one uses Content-Length while the other uses Transfer-Encoding), an attacker could smuggle a second request that bypasses authentication or access controls.

### Remediation
1. Configure the reverse proxy to normalize requests (reject ambiguous requests with both TE and CL)
2. Configure the ASGI server (Hypercorn) to reject malformed requests
3. Add application-level validation using @APP.before_request to reject requests with both Transfer-Encoding and Content-Length headers by aborting with 400 status and 'Ambiguous message framing' message

### Acceptance Criteria
- [ ] Configure reverse proxy to reject ambiguous requests
- [ ] Configure Hypercorn to reject malformed requests
- [ ] Add @APP.before_request validation
- [ ] Test request smuggling scenarios
- [ ] Document HTTP message boundary policy

### References
- Source: 4.2.1.md
- Domain: api_endpoints

### Priority
Medium

---

## Issue: FINDING-174 - Mixed logging mechanisms (print vs logger) create undocumented output channels
**Labels:** bug, security, priority:medium, logging
**Description:**
### Summary
Multiple code paths use print() statements alongside the formal _LOGGER system. These bypass any logging framework configuration (formatters, handlers, filters, destinations) and output to stdout directly, creating undocumented log channels that cannot be inventoried. Security-relevant information (form submissions, tamper detection alerts) exits through channels not covered by any logging policy.

### Details
**Affected Files:**
- `v3/server/pages.py` (lines 427, 449)
- `v3/server/bin/tally.py` (lines 127, 152, 157)

**CWE:** None specified
**ASVS:** 16.1.1, 16.2.3 (Level L2)

Security-relevant information exits through channels not covered by any logging policy, potentially being lost or logged without proper access controls.

### Remediation
Replace print statements with proper logging. For form data, use _LOGGER.debug() with structured identifiers. For security events like tamper detection, use _LOGGER.critical() with clear event descriptions. Example: _LOGGER.critical(f'TAMPER DETECTED: Election[E:{election_id}] integrity check failed')

### Acceptance Criteria
- [ ] Replace all print() calls with _LOGGER calls
- [ ] Use appropriate log levels (debug, info, warning, critical)
- [ ] Add structured identifiers to log messages
- [ ] Test log output consistency
- [ ] Document logging standards

### References
- Source: 16.1.1.md, 16.2.3.md
- Domain: logging_and_monitoring

### Priority
Medium

---

## Issue: FINDING-175 - Authorization failure events lack structured metadata
**Labels:** bug, security, priority:medium, logging
**Description:**
### Summary
When a user attempts to access an election they are not authorized to vote in, the application returns a 404 but does not log this authorization failure. This is a security event (potential enumeration or unauthorized access attempt) that should include WHO tried, WHAT they tried to access, WHEN, and the outcome. Repeated attempts to access unauthorized elections cannot be detected or alerted upon.

### Details
**Affected Files:**
- `v3/server/pages.py` (lines 199-201)

**CWE:** None specified
**ASVS:** 16.2.1 (Level L2)

Authorization failures are invisible to security monitoring. Repeated attempts to access unauthorized elections cannot be detected or alerted upon.

### Remediation
Add _LOGGER.warning() call when authorization check fails in vote_on_page, capturing user=U:{result.uid}, resource=election[E:{election.eid}], action=vote_access, and reason=not_in_mayvote before returning 404.

### Acceptance Criteria
- [ ] Add _LOGGER.warning() for authorization failures
- [ ] Include user ID, election ID, action, and reason
- [ ] Test authorization failure logging
- [ ] Document authorization event format

### References
- Source: 16.2.1.md
- Domain: logging_and_monitoring

### Priority
Medium

---

## Issue: FINDING-176 - Election state change operations in election.py lack logging
**Labels:** bug, security, priority:medium, logging
**Description:**
### Summary
Critical election lifecycle operations (close(), add_salts(), delete()) do not emit log entries at the library level. While pages.py logs the close event when invoked via the web interface, direct library usage (e.g., from tally.py or future integration paths) leaves no trace. If the library is used outside the web context, security-critical state changes occur without audit trails.

### Details
**Affected Files:**
- `v3/steve/election.py` (lines 110-115, 117-137)

**CWE:** None specified
**ASVS:** 16.2.1 (Level L2)

If the library is used outside the web context, security-critical state changes occur without audit trails.

### Remediation
Add _LOGGER.info() calls to close(), add_salts(), and delete() methods in election.py to log state changes at the library level, including Election[E:{self.eid}] identifier and the action performed.

### Acceptance Criteria
- [ ] Add logging to close() method
- [ ] Add logging to add_salts() method
- [ ] Add logging to delete() method
- [ ] Include election ID in all log messages
- [ ] Test library-level logging

### References
- Source: 16.2.1.md
- Domain: logging_and_monitoring

### Priority
Medium

---

## Issue: FINDING-177 - No logging format configuration enforces UTC timestamps
**Labels:** bug, security, priority:medium, logging
**Description:**
### Summary
The application does not configure a logging format that ensures: 1. Timestamps are present in every log entry 2. Timestamps use UTC (or include explicit timezone offset) 3. Time sources are synchronized across components. The logging.basicConfig(level=logging.INFO) in tally.py uses the default format which does NOT include a timestamp at all.

### Details
**Affected Files:**
- `v3/server/bin/tally.py` (line 165)
- `v3/server/pages.py` (entire file)

**CWE:** None specified
**ASVS:** 16.2.2 (Level L2)

The default format is %(levelname)s:%(name)s:%(message)s. The web server's logging configuration is not shown but relies on framework defaults which typically use local time without timezone. Additionally, pages.py uses datetime.datetime.now() and datetime.datetime.fromtimestamp() without timezone awareness.

### Remediation
Configure UTC timestamps globally using logging.basicConfig with format='%(asctime)s %(levelname)s %(name)s %(message)s', datefmt='%Y-%m-%dT%H:%M:%S.%fZ', and set logging.Formatter.converter = time.gmtime to force UTC. Alternatively, use a JSON formatter for structured logging with ISO 8601 timestamps that include timezone information.

### Acceptance Criteria
- [ ] Configure logging.basicConfig with UTC timestamps
- [ ] Set logging.Formatter.converter = time.gmtime
- [ ] Use timezone-aware datetime objects
- [ ] Test timestamp format consistency
- [ ] Document logging timestamp requirements

### References
- Source: 16.2.2.md
- Domain: logging_and_monitoring

### Priority
Medium

---

## Issue: FINDING-178 - No structured logging format enables machine parsing and correlation
**Labels:** bug, security, priority:medium, logging
**Description:**
### Summary
The application uses unstructured f-string log messages that vary in format between modules. While the `[U:xxx]`, `[E:xxx]`, `[I:xxx]` convention is helpful, the overall format is not machine-parseable without custom regex patterns. Log processors (ELK, Splunk, CloudWatch) would require custom parsing rules for each message variant.

### Details
**Affected Files:**
- `v3/server/pages.py` (all logging calls)
- `v3/steve/election.py` (all logging calls)

**CWE:** None specified
**ASVS:** 16.2.4 (Level L2)

Issues include: 1. No common structured format (JSON, CEF, CLF) is used, 2. Inconsistent field ordering, 3. No correlation ID: No request ID or trace ID to correlate multiple log entries from the same request, 4. Mixed separators, 5. No event type field. Automated alerting on patterns like "3 failed access attempts in 5 minutes" becomes difficult without structured fields.

### Remediation
Implement structured logging using structlog or similar library. Example: import structlog; logger = structlog.get_logger(); logger.info("election.vote_cast", actor_uid=result.uid, election_id=election.eid, issue_id=iid, event_type="security", action="vote_cast"). Output should be JSON format with consistent fields.

### Acceptance Criteria
- [ ] Implement structlog or equivalent
- [ ] Convert all logging calls to structured format
- [ ] Add correlation IDs to requests
- [ ] Add event_type field to all logs
- [ ] Output JSON format
- [ ] Test log parsing with common tools

### References
- Source: 16.2.4.md
- Domain: logging_and_monitoring

### Priority
Medium

---

## Issue: FINDING-179 - Tally output includes full voter identity list without classification controls
**Labels:** bug, security, priority:medium, privacy
**Description:**
### Summary
The JSON output format includes a complete sorted list of voter PIDs (`voters=sorted(all_voters)`). This reveals which specific individuals voted on each issue, which could be considered sensitive in some election contexts. The voter list is output without any masking or classification-based control.

### Details
**Affected Files:**
- `v3/server/bin/tally.py` (lines 129-132)

**CWE:** None specified
**ASVS:** 16.2.5 (Level L2)

While knowing WHO voted doesn't reveal HOW they voted (votes are shuffled), participation patterns could be sensitive. The sorted output also enables easy diff-ing between multiple tallies to identify new voters.

### Remediation
Option 1: Hash voter identities in output using hashlib.sha256(v.encode()).hexdigest()[:12]. Option 2: Only include voter count, not identities, with voters list available only with --verbose flag.

### Acceptance Criteria
- [ ] Implement voter identity hashing OR count-only output
- [ ] Add --verbose flag for full voter list (if count-only chosen)
- [ ] Test tally output format
- [ ] Document voter privacy policy

### References
- Source: 16.2.5.md
- Domain: logging_and_monitoring

### Priority
Medium

---

## Issue: FINDING-180 - Exception details potentially leak sensitive information into error logs
**Labels:** bug, security, priority:medium, logging
**Description:**
### Summary
The catch-all `Exception` handler logs the full exception message (`{e}`). Depending on the failure mode, this could include: cryptographic operation details, database state information, internal path information, or partial sensitive data that caused the error. The error message is not sanitized before logging.

### Details
**Affected Files:**
- `v3/server/pages.py` (line 356)

**CWE:** None specified
**ASVS:** 16.2.5 (Level L2)

Exception messages could leak internal implementation details into logs. If logs are accessible to a broader audience than the application code, this creates an information disclosure risk.

### Remediation
Log only exception type name in standard logs: _LOGGER.error(f'Vote submission failed for user[U:{result.uid}] on issue[I:{iid}] in election[E:{election.eid}]: {type(e).__name__}', exc_info=True). Full traceback only at configured log level.

### Acceptance Criteria
- [ ] Log exception type instead of full message
- [ ] Use exc_info=True for traceback at debug level
- [ ] Review all exception logging
- [ ] Test exception logging output
- [ ] Document exception logging policy

### References
- Source: 16.2.5.md
- Domain: logging_and_monitoring

### Priority
Medium

---

## Issue: FINDING-181 - No Authentication Metadata Captured in Existing Logs
**Labels:** bug, security, priority:medium, logging
**Description:**
### Summary
The existing log messages record user actions but do not include authentication metadata (authentication type, factors used, session age, IP address). Even where actions are logged, there's insufficient metadata to correlate events with authentication context (OAuth provider, MFA status, source IP).

### Details
**Affected Files:**
- `v3/server/pages.py` (lines 106-108, 404-407, 440-443)

**CWE:** None specified
**ASVS:** 16.3.1 (Level L2)

Lack of authentication metadata prevents correlation of security events with authentication context.

### Remediation
Include authentication metadata in log messages: auth_method=oauth, ip address, session_id hash, and other relevant authentication context for all user actions.

### Acceptance Criteria
- [ ] Add auth_method to log messages
- [ ] Add IP address to log messages
- [ ] Add session_id hash to log messages
- [ ] Add MFA status if applicable
- [ ] Test authentication metadata logging

### References
- Source: 16.3.1.md
- Domain: logging_and_monitoring

### Priority
Medium

---

## Issue: FINDING-182 - No Authorization Logging in Vote Submission
**Labels:** bug, security, priority:medium, logging
**Description:**
### Summary
The vote endpoint has a comment indicating incomplete authorization implementation and does not log authorization decisions. While add_vote in election.py checks mayvote internally, no explicit authorization decision is logged, preventing audit trail of who attempted to vote and whether they were authorized.

### Details
**Affected Files:**
- `v3/server/pages.py` (lines 380-422)

**CWE:** None specified
**ASVS:** 16.3.2 (Level L2, L3)

Authorization decisions are not logged, preventing security monitoring of vote access attempts.

### Remediation
Implement explicit authorization check for vote submission and log both successful and failed authorization attempts. Include user ID, election ID, timestamp, and IP address in authorization logs.

### Acceptance Criteria
- [ ] Add explicit authorization check
- [ ] Log successful authorization attempts
- [ ] Log failed authorization attempts
- [ ] Include user ID, election ID, timestamp, IP
- [ ] Test authorization logging

### References
- Source: 16.3.2.md
- Domain: logging_and_monitoring

### Priority
Medium

---

## Issue: FINDING-183 - Election State Assertion Failures Not Logged
**Labels:** bug, security, priority:medium, logging
**Description:**
### Summary
State validation uses Python assert statements which raise AssertionError without logging. Attempts to bypass election state controls (e.g., voting in a closed election, modifying an open election) produce no audit trail. These are business logic bypass attempts that should be logged per ASVS 16.3.3. Assertions are also disabled when Python runs with optimization (-O flag), making this a potential security bypass.

### Details
**Affected Files:**
- `v3/steve/election.py` (multiple)

**CWE:** None specified
**ASVS:** 16.3.3 (Level L2)

Assertions produce no audit trail and are disabled with -O flag.

### Remediation
Replace assertions with explicit checks and logging: if not self.is_open(): _LOGGER.warning('BUSINESS_LOGIC_BYPASS: attempt to vote on non-open election, election=%s, state=%s, pid=%s, iid=%s', self.eid, self.get_state(), pid, iid); raise ElectionBadState(...)

### Acceptance Criteria
- [ ] Replace all assert statements with explicit checks
- [ ] Add logging before raising exceptions
- [ ] Create ElectionBadState exception class
- [ ] Test state validation logging
- [ ] Document state validation requirements

### References
- Source: 16.3.3.md
- Domain: logging_and_monitoring

### Priority
Medium

---

## Issue: FINDING-184 - No Logging of Anti-Automation or Rate Limiting Events
**Labels:** bug, security, priority:medium, logging
**Description:**
### Summary
There is no evidence of rate limiting, anti-automation controls, or logging of potential automated abuse: No request rate tracking, No logging of rapid successive requests, No CAPTCHA or similar controls, No detection of automated voting attempts. Automated attacks against authentication, voting, or election management endpoints cannot be detected through application logs.

### Details
**Affected Files:**
- `v3/server/pages.py` (entire file)

**CWE:** None specified
**ASVS:** 16.3.3 (Level L2)

Automated attacks cannot be detected through application logs.

### Remediation
Implement rate-limit event logging—Implement request rate tracking and log anomalous patterns. Add anti-automation detection and logging mechanisms for authentication, voting, and election management endpoints.

### Acceptance Criteria
- [ ] Implement request rate tracking
- [ ] Log rapid successive requests
- [ ] Add anti-automation detection
- [ ] Log automated voting attempts
- [ ] Test rate limit logging
- [ ] Document anti-automation policy

### References
- Source: 16.3.3.md
- Domain: logging_and_monitoring

### Priority
Medium

---

## Issue: FINDING-185 - Assertion Errors Not Caught or Logged at Application Level
**Labels:** bug, security, priority:medium, logging
**Description:**
### Summary
Multiple critical operations use assert for state validation. If assertions fail (indicating an unexpected state or security control failure), no structured logging occurs. Security control failures (election in wrong state) produce unstructured stack traces rather than structured security event logs. When running with -O (optimized mode), these checks are completely disabled.

### Details
**Affected Files:**
- `v3/steve/election.py` (lines 48, 69, 115, 178, 197, 211, 238)

**CWE:** None specified
**ASVS:** 16.3.4 (Level L2)

Assertions produce unstructured stack traces and are disabled with -O flag.

### Remediation
Replace assert statements with proper conditional checks that log security events before raising exceptions. Use explicit if statements with structured logging to capture state validation failures as security events.

### Acceptance Criteria
- [ ] Replace all assert statements
- [ ] Add structured logging before exceptions
- [ ] Test security event logging
- [ ] Verify behavior with -O flag
- [ ] Document state validation logging

### References
- Source: 16.3.4.md
- Domain: logging_and_monitoring

### Priority
Medium

---

## Issue: FINDING-186 - Database Connectivity Failures Not Explicitly Logged
**Labels:** bug, security, priority:medium, logging
**Description:**
### Summary
Database connection failures would produce SQLite exceptions without application-level logging. Backend infrastructure failures (database unavailability, file system issues) would not be captured as structured security events.

### Details
**Affected Files:**
- `v3/steve/election.py` (line 28)

**CWE:** None specified
**ASVS:** 16.3.4 (Level L2)

Backend infrastructure failures are not captured as structured security events.

### Remediation
Wrap database connection attempts in try-except blocks with explicit logging of connection failures, including database path and error details, before re-raising or handling the exception.

### Acceptance Criteria
- [ ] Add try-except for database connections
- [ ] Log connection failures with details
- [ ] Include database path in logs
- [ ] Test connection failure logging
- [ ] Document database error handling

### References
- Source: 16.3.4.md
- Domain: logging_and_monitoring

### Priority
Medium

---

## Issue: FINDING-187 - Debug Print Statements with Unsanitized User Input
**Labels:** bug, security, priority:medium, logging, log-injection
**Description:**
### Summary
Debug `print()` statements output raw form data including user-controlled input. If stdout is captured to log files (common in containerized deployments), unsanitized user input flows into logs, enabling log injection attacks through the stdout capture mechanism.

### Details
**Affected Files:**
- `v3/server/pages.py` (lines 500, 523)

**CWE:** CWE-117 (Log Injection)
**ASVS:** 16.4.1 (Level L2)

**Related Findings:** FINDING-060

Unsanitized user input in print() statements can enable log injection attacks.

### Remediation
Replace debug print() statements with proper logging using _LOGGER. Apply sanitization to any user-controlled data before logging. If debug output is necessary, use _LOGGER.debug() with sanitized values instead of print() statements.

### Acceptance Criteria
- [ ] Replace print() with _LOGGER.debug()
- [ ] Sanitize user-controlled data before logging
- [ ] Test log injection prevention
- [ ] Document logging sanitization policy

### References
- Source: 16.4.1.md
- Domain: logging_and_monitoring

### Priority
Medium

---

## Issue: FINDING-188 - No Log Protection Configuration
**Labels:** bug, security, priority:medium, logging
**Description:**
### Summary
The logging configuration uses `basicConfig` with no file protection, access control, or integrity measures. Logs are written to stdout/stderr with no write-once/append-only guarantees, file permissions configuration, log rotation with integrity verification, transmission to a protected centralized system, or digital signatures or checksums on log entries.

### Details
**Affected Files:**
- `v3/server/bin/tally.py` (line 163)

**CWE:** None specified
**ASVS:** 16.4.2 (Level L2)

Logs lack protection, access control, and integrity verification.

### Remediation
Configure structured logging with proper handlers for centralized log collection. Implement log integrity protection using append-only log files or use a log shipping agent with integrity verification. Configure appropriate file permissions for log files and ensure logs are transmitted to a protected centralized system.

### Acceptance Criteria
- [ ] Configure centralized log collection
- [ ] Implement log integrity protection
- [ ] Configure file permissions for logs
- [ ] Set up log shipping with verification
- [ ] Test log protection mechanisms
- [ ] Document log protection policy

### References
- Source: 16.4.2.md
- Domain: logging_and_monitoring

### Priority
Medium

---

## Issue: FINDING-189 - No Centralized Logging Configuration in Web Application
**Labels:** bug, security, priority:medium, logging
**Description:**
### Summary
The web application uses Python's `logging` module but there is no evidence of log forwarding to a centralized system, log file protection configuration, separate log storage from application server, or log integrity verification. While the infrastructure may provide these protections, the application code shows no explicit configuration ensuring log protection.

### Details
**Affected Files:**
- `v3/server/pages.py`

**CWE:** None specified
**ASVS:** 16.4.2 (Level L2)

Application code lacks explicit centralized logging configuration.

### Remediation
Configure centralized logging with log forwarding to a protected system. Implement log file protection configuration including appropriate file permissions, separate log storage from the application server, and log integrity verification mechanisms.

### Acceptance Criteria
- [ ] Configure log forwarding
- [ ] Implement log file protection
- [ ] Separate log storage from app server
- [ ] Add log integrity verification
- [ ] Test centralized logging
- [ ] Document logging infrastructure

### References
- Source: 16.4.2.md
- Domain: logging_and_monitoring

### Priority
Medium

---

## Issue: FINDING-190 - HTTP 400 responses expose specific validation failure reasons
**Labels:** bug, security, priority:medium, information-disclosure
**Description:**
### Summary
The `quart.abort()` calls include descriptive messages ('Missing date', 'Invalid date format', 'Invalid field') that are passed to the default Quart error handler, which may render them in the HTTP response body. While these specific messages are not highly sensitive, the pattern establishes a practice that could lead to information disclosure if applied to more sensitive contexts.

### Details
**Affected Files:**
- `v3/server/pages.py` (lines 103-110)

**CWE:** None specified
**ASVS:** 16.5.1 (Level L2)

Descriptive error messages in HTTP responses may leak implementation details.

### Remediation
Return generic validation error: `quart.abort(400)` and let global error handler provide generic message

### Acceptance Criteria
- [ ] Remove descriptive messages from abort() calls
- [ ] Implement generic error handler
- [ ] Log detailed errors server-side
- [ ] Test error response format
- [ ] Document error handling policy

### References
- Source: 16.5.1.md
- Domain: logging_and_monitoring

### Priority
Medium

---

## Issue: FINDING-191 - PersonDB failures not handled in admin endpoints
**Labels:** bug, security, priority:medium, error-handling
**Description:**
### Summary
While PersonNotFound is handled gracefully, the PersonDB.open() call itself has no error handling for database connectivity failures. If the database is unavailable, the error propagates unhandled. The admin page becomes completely unavailable if database has connectivity issues, with no graceful degradation or retry.

### Details
**Affected Files:**
- `v3/server/pages.py` (lines 286-287)

**CWE:** None specified
**ASVS:** 16.5.2 (Level L2)

Database connectivity failures are not handled, causing complete unavailability.

### Remediation
Wrap PersonDB.open() and subsequent operations in a try/except block to handle sqlite3.OperationalError and OSError. Log the error, flash a user-friendly message, and redirect to a safe page.

### Acceptance Criteria
- [ ] Add try-except for PersonDB.open()
- [ ] Handle sqlite3.OperationalError
- [ ] Handle OSError
- [ ] Log database errors
- [ ] Flash user-friendly message
- [ ] Test database failure scenarios

### References
- Source: 16.5.2.md
- Domain: logging_and_monitoring

### Priority
Medium

---

## Issue: FINDING-192 - CLI tally script has no top-level exception handler
**Labels:** bug, security, priority:medium, error-handling
**Description:**
### Summary
The main() function and entry point have no top-level try/except block. While the function handles is_tampered() and calls sys.exit(1), unexpected exceptions (database corruption, permission denied, memory errors) will print full stack traces to stderr and exit ungracefully. Full stack traces with file paths and variable values printed to stderr; error details may be lost if not captured by a process manager.

### Details
**Affected Files:**
- `v3/server/bin/tally.py` (lines 166-180)

**CWE:** None specified
**ASVS:** 16.5.4 (Level L3)

Unexpected exceptions print full stack traces without structured logging.

### Remediation
Add top-level exception handler to CLI entry point wrapping main() call with try/except to catch KeyboardInterrupt and Exception, logging critical errors before exiting with appropriate exit codes.

### Acceptance Criteria
- [ ] Add top-level try-except to main()
- [ ] Handle KeyboardInterrupt separately
- [ ] Log critical errors before exit
- [ ] Use appropriate exit codes
- [ ] Test exception handling
- [ ] Document CLI error handling

### References
- Source: 16.5.4.md
- Domain: logging_and_monitoring

### Priority
Medium

---

## Issue: FINDING-193 - Incomplete documentation of application communication needs
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The application communicates with multiple external services, but there is no comprehensive communication inventory document. Without comprehensive communication documentation, security teams cannot perform complete threat modeling, firewall rule validation, or network segmentation reviews. Undocumented external dependencies may introduce unmonitored attack surfaces.

### Details
**Affected Files:**
- `v3/ARCHITECTURE.md`
- `v3/docs/schema.md`
- `v3/server/config.yaml.example`
- `v3/server/main.py` (lines 36-40)
- `v3/server/bin/mail-voters.py` (lines 67-73)
- `v3/steve/election.py` (line 37)
- `v3/server/pages.py` (lines 560-574)

**CWE:** None specified
**ASVS:** 13.1.1 (Level L2, L3)

Communication channels identified: 1) ASF OAuth Service, 2) SMTP/Email Service, 3) SQLite Database, 4) LDAP Service, 5) End-user-provided document filenames.

### Remediation
Create a dedicated COMMUNICATIONS.md or equivalent document that inventories: All external service endpoints (OAuth, SMTP, LDAP), Protocol, port, and authentication method for each, Direction of communication (inbound/outbound), User-controllable endpoints or file references, Network security requirements (TLS versions, cipher suites)

### Acceptance Criteria
- [ ] Create COMMUNICATIONS.md document
- [ ] Document all external service endpoints
- [ ] Document protocols, ports, authentication
- [ ] Document communication direction
- [ ] Document network security requirements
- [ ] Review with security team

### References
- Source: 13.1.1.md
- Domain: secrets_and_configuration_management

### Priority
Medium

---

## Issue: FINDING-194 - No documented resource-management strategies, timeout settings, or retry logic for external services
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The application interacts with multiple services (SQLite, OAuth, SMTP) but there is no documentation defining maximum concurrent connections, connection pool limits, or behavior when those limits are reached. Without defined limits and fallback mechanisms, a denial-of-service condition could result from legitimate traffic spikes or upstream service degradation.

### Details
**Affected Files:**
- `v3/ARCHITECTURE.md`
- `v3/steve/election.py` (lines 35-37, 39-44)
- `v3/server/pages.py` (lines 165-186, 297)

**CWE:** None specified
**ASVS:** 13.1.2 (Level L3)

No documentation exists for maximum concurrent connections, connection timeouts/limits, connection pooling, or fallback behavior.

### Remediation
Document for each service: connection pool size or maximum concurrent connections, queue/backpressure behavior when limits are reached, circuit breaker or fallback patterns. Example configuration: database: max_connections: 10, connection_timeout_ms: 5000, behavior_at_limit: queue; oauth: max_concurrent_requests: 5, timeout_ms: 10000, fallback: deny_login; smtp: max_concurrent_sends: 3, retry_on_failure: false

### Acceptance Criteria
- [ ] Document connection limits for each service
- [ ] Document timeout settings
- [ ] Document fallback behavior
- [ ] Document circuit breaker patterns
- [ ] Test resource limit scenarios
- [ ] Review with operations team

### References
- Source: 13.1.2.md
- Domain: secrets_and_configuration_management

### Priority
Medium

---

## Issue: FINDING-195 - No documented resource-management strategies, timeout settings, or retry logic for external services
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The application documentation does not define resource-management strategies for any external system. Without defined resource management strategies: database locks could cause indefinite hangs under concurrent access, failed email sends could silently drop voter notifications, OAuth service outages could leave requests hanging, and resource leaks from unclosed connections could degrade availability over time.

### Details
**Affected Files:**
- `v3/ARCHITECTURE.md`
- `v3/steve/election.py`
- `v3/server/main.py` (lines 37-40)
- `v3/server/bin/mail-voters.py` (lines 67-73)
- `v3/server/pages.py` (lines 165-186)

**CWE:** None specified
**ASVS:** 13.1.3 (Level L3)

No timeout settings, retry limits, or resource-release procedures documented.

### Remediation
Create a resource management section in documentation covering: SQLite Database - Timeout: 30 seconds, Release: Connections closed after each request via context manager, Failure handling: Return 503 if database is locked beyond timeout, Retry: No retries for synchronous operations. OAuth (ASF OAuth) - Timeout: 10 seconds for token exchange, Retry: None, Failure handling: Display error page with retry option. SMTP (Email) - Timeout: 30 seconds per message, Retry: Up to 2 retries with 5-second delay, Failure handling: Log error, continue to next recipient.

### Acceptance Criteria
- [ ] Document timeout settings for each service
- [ ] Document retry logic
- [ ] Document resource release procedures
- [ ] Document failure handling
- [ ] Test resource management
- [ ] Review with operations team

### References
- Source: 13.1.3.md
- Domain: secrets_and_configuration_management

### Priority
Medium

---

## Issue: FINDING-196 - No secrets rotation schedule or lifecycle management documentation
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
While the application documents what secrets exist and how they are generated, there is no documentation defining a rotation schedule or lifecycle management for any secret. Without a defined rotation schedule, compromised secrets may remain in use indefinitely. The placeholder CSRF token represents a complete absence of this security control.

### Details
**Affected Files:**
- `v3/docs/schema.md`
- `v3/steve/crypto.py` (lines 27-29, 32-41)
- `v3/server/config.yaml.example`
- `v3/server/pages.py` (line 83)

**CWE:** None specified
**ASVS:** 13.1.4 (Level L3)

Secrets identified: Election salts, Mayvote salts, Opened keys, TLS certificate private keys, Session secrets, OAuth client credentials, CSRF tokens (currently placeholder).

### Remediation
Create a secrets management document with rotation schedule table containing: Secret, Criticality, Rotation Schedule, and Rotation Procedure. Include entries for: TLS private key (Critical, Annual or on compromise), Session signing key (High, Monthly), OAuth client secret (High, Annual), Election salts (Medium, N/A single-use per election), CSRF tokens (High, Per-session). Add Compromise Response section detailing procedures for each secret type.

### Acceptance Criteria
- [ ] Create secrets management document
- [ ] Document rotation schedule for each secret
- [ ] Document rotation procedures
- [ ] Document compromise response procedures
- [ ] Implement real CSRF tokens
- [ ] Review with security team

### References
- Source: 13.1.4.md
- Domain: secrets_and_configuration_management

### Priority
Medium

---

## Issue: FINDING-197 - All application components use identical full-privilege database access
**Labels:** bug, security, priority:medium, privilege-separation
**Description:**
### Summary
All application modules — web handlers, business logic, command-line tools — access the SQLite database with the same full read/write permissions. There is no privilege separation. If any component is compromised (e.g., through a web vulnerability), the attacker gains full database access including ability to modify election results, delete elections, or alter voter records.

### Details
**Affected Files:**
- `v3/steve/election.py` (lines 35-37)
- `v3/steve/persondb.py` (lines 25-26)
- `v3/server/bin/create-election.py` (line 31)
- `v3/server/bin/mail-voters.py` (line 28)
- `v3/server/pages.py` (line 40)

**CWE:** None specified
**ASVS:** 13.2.2 (Level L2, L3)

The mail-voters.py script only needs READ access but has full write access. Voter-facing endpoints can technically invoke any database operation.

### Remediation
1. For SQLite: Implement application-level privilege separation by using different database wrapper classes with restricted query sets (e.g., VoterDB with read-only access and ALLOWED_QUERIES). 2. For CLI tools, use read-only database connections where write access is not needed (e.g., mail-voters.py should use sqlite3.connect with mode=ro). 3. Document the principle of least privilege for each component and its required access level.

### Acceptance Criteria
- [ ] Create read-only database wrapper classes
- [ ] Update mail-voters.py to use read-only connection
- [ ] Implement query allowlists for different roles
- [ ] Test privilege separation
- [ ] Document privilege requirements per component

### References
- Source: 13.2.2.md
- Domain: secrets_and_configuration_management

### Priority
Medium

---

## Issue: FINDING-198 - No allowlist of permitted external resources defined in application configuration
**Labels:** bug, security, priority:medium, ssrf
**Description:**
### Summary
The configuration schema defines server listening parameters and database location but contains no allowlist section defining permitted OAuth/authentication endpoints, permitted LDAP server addresses, permitted external API endpoints, or blocked internal network ranges (SSRF prevention). Without an application-layer allowlist, if any code path allows user-influenced URLs, there is no defense-in-depth against SSRF or unauthorized outbound communication.

### Details
**Affected Files:**
- `v3/server/config.yaml.example` (entire file scope)

**CWE:** None specified
**ASVS:** 13.2.4 (Level L2, L3)

The domain context confirms communication with ASF OAuth and LDAP, but no configuration mechanism restricts which external systems the application may contact.

### Remediation
Add an explicit allowlist section to the configuration:
```yaml
allowed_backends:
  oauth:
    url: "https://oauth.apache.org"
  ldap:
    host: "ldaps://ldap.apache.org"
    port: 636
denied_networks:
  - "169.254.0.0/16"   # Link-local
  - "10.0.0.0/8"        # Private
  - "172.16.0.0/12"     # Private
  - "192.168.0.0/16"    # Private
  - "127.0.0.0/8"       # Loopback
```

### Acceptance Criteria
- [ ] Add allowed_backends to config schema
- [ ] Add denied_networks to config schema
- [ ] Implement allowlist validation
- [ ] Test SSRF prevention
- [ ] Document external resource policy

### References
- Source: 13.2.4.md
- Domain: secrets_and_configuration_management

### Priority
Medium

---

## Issue: FINDING-199 - Web server configuration lacks allowlist for permitted outbound request targets
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The server configuration only specifies listening parameters (port, TLS certificates) and database location. There is no configuration for allowed outbound request destinations at the web server level, file access restrictions beyond the database path, permitted data load sources, or egress filtering rules. The application server itself has no configured restrictions on what resources it may fetch or what systems it may contact.

### Details
**Affected Files:**
- `v3/server/config.yaml.example` (entire file scope)

**CWE:** None specified
**ASVS:** 13.2.5 (Level L2, L3)

The comment 'Typical usage is that a proxy sits in front of this server' suggests a reverse proxy architecture, but the proxy configuration for egress filtering is not documented or enforced at the application level.

### Remediation
Add server-level egress configuration:
```yaml
server:
    port: 58383
    certfile: localhost.apache.org+3.pem
    keyfile: localhost.apache.org+3-key.pem
    allowed_outbound:
      - host: "oauth.apache.org"
        port: 443
        protocol: "https"
      - host: "ldap.apache.org"
        port: 636
        protocol: "ldaps"
    allowed_file_paths:
      - "/opt/steve/data/"
      - "/opt/steve/certs/"
```
Additionally, document the expected proxy/firewall-level egress controls in a deployment guide.

### Acceptance Criteria
- [ ] Add allowed_outbound to config schema
- [ ] Add allowed_file_paths to config schema
- [ ] Implement egress validation
- [ ] Document proxy/firewall requirements
- [ ] Test egress restrictions

### References
- Source: 13.2.5.md
- Domain: secrets_and_configuration_management

### Priority
Medium

---

## Issue: FINDING-200 - Auto-reload capability enabled in standalone mode
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The standalone mode uses extra_files for auto-reload capability, which is typically a development/debug feature. While the hot-reload behavior depends on the asfquart.runx() implementation, passing extra_files implies file-watching and automatic restart on changes. Auto-reload in production can cause service disruptions and may expose timing information about server state.

### Details
**Affected Files:**
- `v3/server/main.py` (lines 84-91)

**CWE:** None specified
**ASVS:** 13.4.2 (Level L2)

Auto-reload in production can cause service disruptions and may expose timing information.

### Remediation
Conditionally enable extra_files only when debug mode is explicitly enabled. Remove or disable file-watching capabilities in production deployments.

### Acceptance Criteria
- [ ] Add debug mode configuration flag
- [ ] Conditionally enable extra_files based on debug mode
- [ ] Document production deployment requirements
- [ ] Test with debug mode disabled
- [ ] Verify no auto-reload in production

### References
- Source: 13.4.2.md
- Domain: deployment_and_configuration_hardening

### Priority
Medium

## Issue: FINDING-201 - Missing debug configuration in example config file
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The example configuration file lacks a debug setting with a production-safe default (i.e., debug: false). Without this, operators may not realize debug mode controls are needed.

### Details
**Affected Files:**
- `v3/server/config.yaml.example`

**ASVS Reference:** 13.4.2 (Level L2)

The example configuration file does not include explicit debug mode or log level settings. This creates a risk that production deployments may inadvertently run with debug mode enabled, potentially exposing sensitive information through verbose error messages, stack traces, or debug endpoints.

### Remediation
Add production-safe defaults to `config.yaml.example` including `debug: false` and `log_level: WARNING` with comments indicating these MUST be false/WARNING in production.

Example configuration:
```yaml
# Security: MUST be false in production
debug: false

# Logging: Use WARNING or ERROR in production
log_level: WARNING
```

### Acceptance Criteria
- [ ] Added `debug: false` to config.yaml.example
- [ ] Added `log_level: WARNING` to config.yaml.example
- [ ] Added comments warning about production requirements
- [ ] Test added to verify config parsing accepts these values

### References
- CWE: None specified
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-202 - HTTP TRACE method not explicitly disabled
**Labels:** bug, security, priority:medium
**Description:**
### Summary
There is no explicit configuration or middleware to disable the HTTP TRACE method, creating potential Cross-Site Tracing (XST) vulnerability risk.

### Details
**Affected Files:**
- `v3/server/main.py` (entire file)
- `v3/server/config.yaml.example`

**ASVS Reference:** 13.4.4 (Level L2)

Neither the application code nor the configuration file addresses TRACE method handling. While Quart/Hypercorn may not support TRACE by default (as it typically only routes methods explicitly defined in decorators), there is no explicit rejection mechanism documented or configured. The reliance on framework defaults without verification creates a gap. If TRACE is supported, an attacker could use it in conjunction with XSS (Cross-Site Tracing) to extract HTTP-only cookies or authentication headers.

### Remediation
Add explicit TRACE method rejection middleware:

```python
@app.before_request
async def reject_trace():
    from quart import request, abort
    if request.method == 'TRACE':
        abort(405)
```

Or configure at the reverse proxy level:
```apache
# Apache
TraceEnable off
```

### Acceptance Criteria
- [ ] TRACE method rejection implemented in application or proxy
- [ ] Configuration documented in deployment guide
- [ ] Test added to verify TRACE requests return 405

### References
- CWE: None specified
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-203 - Server version headers exposed in HTTP responses
**Labels:** bug, security, priority:medium
**Description:**
### Summary
There is no configuration to suppress server version headers. Hypercorn by default includes a `server: hypercorn-h11` or similar header in responses, and Quart may expose its version in error pages.

### Details
**Affected Files:**
- `v3/server/main.py` (entire file)

**ASVS Reference:** 13.4.6 (Level L3)

No middleware or configuration is present to strip server version headers. Detailed version information of the ASGI server allows attackers to identify specific vulnerabilities in that version, reducing the effort needed for targeted attacks.

### Remediation
Configure Hypercorn to suppress the server header and add an after-request hook to strip version information:

```python
# In create_app() or via Hypercorn config
@app.after_request
async def strip_server_header(response):
    response.headers.pop('Server', None)
    response.headers.pop('X-Powered-By', None)
    return response
```

For Hypercorn configuration:
```toml
# hypercorn.toml
include_server_header = false
```

### Acceptance Criteria
- [ ] Server header suppression implemented
- [ ] X-Powered-By header removed
- [ ] Hypercorn configuration updated
- [ ] Test added to verify headers are not present in responses

### References
- CWE: None specified
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-204 - No Application-Level File Extension Allowlist as Defense-in-Depth
**Labels:** bug, security, priority:medium
**Description:**
### Summary
While `static_folder=None` disables default static file serving, there is no application-level middleware or response filter that would enforce a file extension allowlist if any route serves files dynamically.

### Details
**Affected Files:**
- `v3/server/main.py:48`

**ASVS Reference:** 13.4.7 (Level L3)

This means there is no secondary control to prevent serving of `.py`, `.yaml`, `.db`, `.pem`, `.git`, or other sensitive extensions if a file-serving endpoint is introduced.

### Remediation
Add a response middleware that validates served content types, or add an after_request hook that enforces allowed extensions. 

Example: Create an after_request handler that checks file extensions against an allowlist (e.g., `.html`, `.css`, `.js`, `.png`, `.jpg`, `.svg`, `.ico`, `.woff2`) and returns 404 for unexpected extensions.

```python
ALLOWED_EXTENSIONS = {'.html', '.css', '.js', '.png', '.jpg', '.svg', '.ico', '.woff2'}

@app.after_request
async def validate_file_extension(response):
    if response.status_code == 200:
        # Check Content-Disposition or request path for file extensions
        # Return 404 if extension not in allowlist
        pass
    return response
```

### Acceptance Criteria
- [ ] File extension validation middleware implemented
- [ ] Allowlist of safe extensions defined
- [ ] Test added to verify blocked extensions return 404
- [ ] Test added to verify allowed extensions are served

### References
- CWE: None specified
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-205 - No Reverse Proxy Hardening Configuration for File Extension Filtering
**Labels:** bug, security, documentation, priority:medium
**Description:**
### Summary
The domain context confirms deployment behind reverse proxies (Apache/nginx). However, no example reverse proxy configuration is provided that restricts which file extensions may be served.

### Details
**Affected Files:**
- `v3/server/config.yaml.example`

**ASVS Reference:** 13.4.7 (Level L3)

ASVS 13.4.7 specifically targets web tier configuration, which in a proxy-fronted architecture means the reverse proxy must enforce extension restrictions. Without proxy-level restrictions, requests for `.git/`, `.env`, `config.yaml`, `*.db`, `*.pem`, and source files could potentially reach the application layer if any misconfiguration occurs.

### Remediation
Provide example reverse proxy configurations that deny access to sensitive file extensions. 

For nginx:
```nginx
# Block sensitive file extensions
location ~* \.(py|yaml|yml|db|pem|key|sqlite|git|env|cfg|ini|log)$ {
    deny all;
    return 404;
}

# Block hidden files and directories
location ~ /\. {
    deny all;
    return 404;
}
```

For Apache:
```apache
<FilesMatch "\.(py|yaml|yml|db|pem|key|sqlite|env|cfg|ini|log)$">
    Require all denied
</FilesMatch>

<DirectoryMatch "^\.|/\.">
    Require all denied
</DirectoryMatch>
```

### Acceptance Criteria
- [ ] Example nginx configuration created in docs/
- [ ] Example Apache configuration created in docs/
- [ ] Deployment guide updated to reference configurations
- [ ] Test procedure documented for verifying proxy restrictions

### References
- CWE: None specified
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-206 - Comment indicates known pending migration without documented timeline
**Labels:** technical-debt, security, priority:medium
**Description:**
### Summary
The code contains a TODO-style comment indicating a planned migration from Fernet (AES-128-CBC) to XChaCha20-Poly1305, with HKDF parameters already configured for the target algorithm. However, there is no documented timeline for this migration.

### Details
**Affected Files:**
- `v3/steve/crypto.py:63-64`

**ASVS Reference:** 15.1.1 (Level L1)

There is no documented assessment of whether the current Fernet implementation has any specific vulnerability requiring urgent migration. Without a documented timeline, this technical debt may persist indefinitely, and stakeholders cannot assess whether the current cryptographic approach meets the application's risk profile.

### Remediation
Document the migration plan with a target date and risk assessment of the current implementation. Either migrate to XChaCha20-Poly1305 or update the HKDF info parameter to accurately reflect current Fernet usage.

Create `docs/CRYPTO_MIGRATION.md`:
```markdown
## Cryptographic Algorithm Migration Plan

### Current State
- Algorithm: Fernet (AES-128-CBC + HMAC)
- Risk Assessment: [Low/Medium/High]
- Known Issues: [None/List issues]

### Target State
- Algorithm: XChaCha20-Poly1305
- Benefits: [Larger nonce space, AEAD construction]

### Timeline
- Assessment completion: [Date]
- Migration start: [Date]
- Migration completion target: [Date]
```

### Acceptance Criteria
- [ ] Migration plan documented with timeline
- [ ] Risk assessment of current implementation completed
- [ ] HKDF info parameter updated to match current algorithm or migration completed
- [ ] Stakeholder approval obtained for timeline

### References
- CWE: None specified
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-207 - No documentation highlighting risky third-party components despite known risks
**Labels:** documentation, security, dependency, priority:medium
**Description:**
### Summary
The domain context explicitly notes that 'ezt' is not widely used, which may be a risk factor, yet no formal documentation exists that classifies this or other components according to their risk profile.

### Details
**Affected Files:**
- Project-wide
- `election.py`

**ASVS Reference:** 15.1.4 (Level L3)

Based on the ASVS definition of 'risky components' (poorly maintained, unsupported, end-of-life, or history of significant vulnerabilities), the following components warrant documented risk assessment:
- **ezt** - not widely used, small maintainer base, niche templating engine
- **easydict** - simple utility, low activity repository
- **asfpy** - ASF-internal library, limited community review
- **argon2-cffi** - well-maintained but wraps C library via cffi

Without documented risk assessment, teams cannot make informed decisions about additional sandboxing, alternative evaluation, testing requirements, and vulnerability monitoring.

### Remediation
Create `docs/RISKY_COMPONENTS.md` documenting risk assessment for each component:

```markdown
## Risky Components Assessment

### ezt
- **Risk Level:** Medium
- **Risk Factors:** Limited community adoption, small maintainer pool
- **Mitigation:** Restrict to rendering pre-validated data only
- **Review Frequency:** Quarterly
- **Alternative Considered:** Jinja2

### easydict
- **Risk Level:** Low
- **Risk Factors:** Infrequent updates
- **Mitigation:** Frozen version, could be replaced with dataclasses
- **Review Frequency:** Annual

### asfpy
- **Risk Level:** Low-Medium
- **Risk Factors:** Limited external security review
- **Mitigation:** ASF infrastructure team maintains with organizational trust boundary
- **Review Frequency:** Tied to ASF infrastructure releases
```

### Acceptance Criteria
- [ ] RISKY_COMPONENTS.md created with all dependencies assessed
- [ ] Risk levels assigned and documented
- [ ] Mitigation strategies documented
- [ ] Review schedule established
- [ ] Document added to security review checklist

### References
- CWE: None specified
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-208 - No documentation highlighting dangerous functionality used in the application
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The application contains several instances of "dangerous functionality" as defined by ASVS (deserialization, dynamic code execution, raw data parsing, direct memory manipulation) that are not documented with their risks and mitigations.

### Details
**Affected Files:**
- `v3/steve/election.py:410`
- `v3/steve/crypto.py:91-101`
- `v3/steve/crypto.py:75-88`
- `v3/server/main.py:40-41`
- `v3/steve/crypto.py:63-70`

**ASVS Reference:** 15.1.5 (Level L3)

Dangerous functionality instances:
1. Deserialization of data (json.loads) in json2kv function
2. Low-level cryptographic operations (argon2.low_level)
3. Symmetric encryption/decryption with key material handling
4. Dynamic module imports
5. HKDF key derivation with hardcoded info parameter

Without documentation, developers and auditors cannot quickly identify where the most security-sensitive code resides, what additional review/testing these areas require, acceptable input constraints, and blast radius of potential vulnerabilities.

### Remediation
Create `docs/DANGEROUS_FUNCTIONALITY.md`:

```markdown
## Dangerous Functionality Documentation

### Cryptographic Key Derivation (crypto.py)
- **Type:** Direct memory manipulation (Argon2 low-level), key material handling
- **Location:** v3/steve/crypto.py:_hash(), _b64_vote_key(), gen_opened_key()
- **Risk:** Incorrect parameters could weaken vote encryption
- **Mitigation:** Parameters benchmarked, unit tested, review required for changes
- **Input Trust:** All inputs are system-generated (salts, tokens) — not user-controlled

### Vote Encryption/Decryption (crypto.py)
- **Type:** Symmetric encryption with derived keys
- **Location:** v3/steve/crypto.py:create_vote(), decrypt_votestring()
- **Risk:** Key leakage exposes all votes for an election
- **Mitigation:** Keys derived per-voter-per-issue, never stored in plaintext

### Data Deserialization (election.py)
- **Type:** JSON deserialization
- **Location:** v3/steve/election.py:json2kv()
- **Risk:** Low (JSON parser, data sourced from database)
- **Mitigation:** Data written by application's own kv2json(); no untrusted input

### Dynamic Module Loading (main.py)
- **Type:** Dynamic imports at startup
- **Location:** v3/server/main.py:create_app()
- **Risk:** Module injection if filesystem compromised
- **Mitigation:** Imports are hardcoded module names, not user-controlled strings
```

### Acceptance Criteria
- [ ] DANGEROUS_FUNCTIONALITY.md created
- [ ] All dangerous operations documented
- [ ] Risk assessments completed
- [ ] Mitigations documented
- [ ] Document added to onboarding materials

### References
- CWE: None specified
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-209 - Repeated Argon2 Calls in has_voted_upon() Without Throttling
**Labels:** bug, security, performance, priority:medium
**Description:**
### Summary
The `has_voted_upon()` function is callable by any authenticated voter and triggers Argon2 computation for each issue in an election without throttling.

### Details
**Affected Files:**
- `v3/steve/election.py:307-333`

**ASVS Reference:** 15.2.2 (Level L2)

An election with many issues (e.g., 50+ candidates as individual issues) would require 50+ Argon2 computations per page load, consuming ~3.2GB+ of memory throughput per request. This creates a resource consumption vector proportional to election size that can be triggered by any authenticated user.

### Remediation
Implement per-user rate limiting and cap the number of concurrent Argon2 operations system-wide to prevent resource exhaustion from repeated calls to this endpoint.

```python
from quart_rate_limiter import rate_limit

@rate_limit(50, timedelta(minutes=1))
async def has_voted_upon_endpoint():
    # existing logic
    pass

# Add global Argon2 semaphore
ARGON2_SEMAPHORE = asyncio.Semaphore(10)  # Max 10 concurrent operations

async def _hash_with_limit(*args, **kwargs):
    async with ARGON2_SEMAPHORE:
        return _hash(*args, **kwargs)
```

### Acceptance Criteria
- [ ] Per-user rate limiting implemented
- [ ] Global Argon2 operation semaphore added
- [ ] Configuration parameter for max concurrent operations
- [ ] Test added to verify rate limiting behavior
- [ ] Monitoring added for Argon2 operation queue depth

### References
- CWE: None specified
- Related Findings: FINDING-210

### Priority
Medium

---

## Issue: FINDING-210 - No Visible Rate Limiting or Request Timeout Configuration
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application has no visible rate limiting at the application layer and no evidence of middleware or framework-level controls for request throttling or timeouts.

### Details
**Affected Files:**
- `v3/server/main.py`

**ASVS Reference:** 15.2.2 (Level L2)

Without these controls, unlimited HTTP requests can trigger resource-intensive operations (Argon2, database) with no backpressure mechanism. The application relies entirely on external infrastructure (reverse proxy) for DoS protection, which is undocumented and may not be implemented in all deployment environments.

### Remediation
Implement application-level rate limiting using quart_rate_limiter with default limits (e.g., 50 requests per minute). Add request timeout configuration and document deployment requirements for external DoS protection infrastructure.

```python
from quart_rate_limiter import RateLimiter, rate_limit

app = Quart(__name__)
rate_limiter = RateLimiter(app)

# Global default
app.config['RATELIMIT_DEFAULT'] = '50/minute'

# Request timeout
app.config['REQUEST_TIMEOUT'] = 30  # seconds

@app.before_request
async def check_timeout():
    request.timeout = app.config['REQUEST_TIMEOUT']
```

### Acceptance Criteria
- [ ] quart_rate_limiter integrated
- [ ] Default rate limits configured
- [ ] Request timeout configuration added
- [ ] Deployment documentation updated with infrastructure requirements
- [ ] Test added to verify rate limiting behavior

### References
- CWE: None specified
- Related Findings: FINDING-209

### Priority
Medium

---

## Issue: FINDING-211 - Benchmarking Function Included in Production Crypto Module
**Labels:** bug, security, code-quality, priority:medium
**Description:**
### Summary
The `benchmark_argon2()` function exists in the production crypto module (`crypto.py`), increasing attack surface and containing code patterns unsuitable for production.

### Details
**Affected Files:**
- `v3/steve/crypto.py:125-158`

**ASVS Reference:** 15.2.3 (Level L2)

While not directly exploitable via HTTP (requires `__main__` execution or explicit import), this function:
1. Exists in production deployment, increasing attack surface
2. Uses hardcoded salt (`b'16_byte_salt_123'`) which could mislead developers
3. Imports time module solely for this function
4. Uses Argon2.Type.ID while production uses Type.D, potentially confusing security audits
5. Contains informational output via print() rather than logging

### Remediation
Move `benchmark_argon2()` to a separate development/testing module not included in production deployments:

```
Move to: v3/tools/benchmark_argon2.py (excluded from production)

# In setup.py or equivalent
packages=find_packages(exclude=['tools', 'tests'])
```

### Acceptance Criteria
- [ ] benchmark_argon2() moved to v3/tools/benchmark_argon2.py
- [ ] tools/ directory excluded from production packaging
- [ ] Import removed from crypto.py
- [ ] Documentation added for running benchmarks in development
- [ ] Test added to verify tools/ not in production package

### References
- CWE: None specified
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-212 - easydict Package Used Without Verification — Low-Maintenance Dependency
**Labels:** dependency, security, priority:medium
**Description:**
### Summary
`easydict` is a convenience package with minimal maintenance activity. It's used throughout `election.py` for dictionary attribute access. Being a low-download, simple utility package, it's a higher-risk target for supply chain attacks.

### Details
**Affected Files:**
- `v3/steve/election.py:25`

**ASVS Reference:** 15.2.4 (Level L3)

The domain context notes that `ezt` is "not widely used" as a risk factor — the same applies to `easydict`. This creates supply chain risk through typosquatting or maintainer account takeover.

### Remediation
Consider replacing with Python's built-in `types.SimpleNamespace` or `dataclasses`, eliminating the third-party dependency entirely:

```python
from types import SimpleNamespace

# Replace edict(...) with SimpleNamespace(...)
# Or use dataclasses for structured data

from dataclasses import dataclass

@dataclass
class ElectionMetadata:
    eid: str
    title: str
    owner_pid: str
    # ... other fields
```

### Acceptance Criteria
- [ ] easydict dependency removed from requirements
- [ ] All edict() calls replaced with SimpleNamespace or dataclasses
- [ ] Tests updated and passing
- [ ] Performance impact assessed (if any)
- [ ] Documentation updated

### References
- CWE: None specified
- Related Findings: FINDING-207

### Priority
Medium

---

## Issue: FINDING-213 - No Architectural Isolation Between Administrative and User-Facing Operations
**Labels:** architecture, security, priority:medium
**Description:**
### Summary
Administrative operations (election deletion, tallying with decryption, opening/closing elections) execute in the same process space as user-facing operations. A vulnerability in a user-facing endpoint could be leveraged to access administrative functionality.

### Details
**Affected Files:**
- `v3/server/main.py`
- `v3/steve/election.py`

**ASVS Reference:** 15.2.5 (Level L3)

There is no evidence of:
- Separate admin service/process
- Network-level isolation between admin and voter paths
- Container boundaries between operations
- Privilege separation at the OS level

### Remediation
**Option 1:** Separate admin into its own service
```
admin_service/
  main.py  # Runs on different port/network
  admin_api.py
```

**Option 2:** Containerization with network policies
```yaml
# docker-compose.yml
services:
  voter-app:
    networks:
      - frontend
  admin-app:
    networks:
      - backend  # Not accessible from internet
```

### Acceptance Criteria
- [ ] Architecture decision documented
- [ ] Admin operations isolated (service or container)
- [ ] Network policies implemented
- [ ] Deployment guide updated
- [ ] Test added to verify isolation

### References
- CWE: None specified
- Related Findings: FINDING-214

### Priority
Medium

---

## Issue: FINDING-214 - Cryptographic Operations Execute Without Sandboxing or Memory Isolation
**Labels:** security, architecture, priority:medium
**Description:**
### Summary
The `argon2.low_level` API directly calls into a C library (argon2-cffi-bindings wrapping the reference C implementation). This executes native code that could be exploited if the library has a memory corruption vulnerability.

### Details
**Affected Files:**
- `v3/steve/crypto.py:88-99`

**ASVS Reference:** 15.2.5 (Level L3)

This:
1. Allocates 64MB of memory per call within the application process
2. Executes native code that could be exploited
3. Shares the same memory space as all application data (encryption keys, vote content)

A memory corruption vulnerability in the native Argon2 library could expose the `opened_key` or vote tokens stored in the same process memory.

### Remediation
Run crypto operations in a sandboxed subprocess using `subprocess.run` with resource limits via ulimit or seccomp. Alternatively, deploy with container-level memory limits and seccomp profiles.

```python
import subprocess
import json

def argon2_sandboxed(password, salt, **params):
    """Run Argon2 in sandboxed subprocess"""
    cmd = ['python', '-m', 'crypto_worker', 
           json.dumps({'password': password, 'salt': salt, **params})]
    
    result = subprocess.run(
        cmd,
        capture_output=True,
        timeout=10,
        # Resource limits
        preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_AS, (128*1024*1024, 128*1024*1024))
    )
    return json.loads(result.stdout)
```

Or use container-level controls:
```yaml
# docker-compose.yml
services:
  app:
    security_opt:
      - seccomp:default.json
    mem_limit: 256m
```

### Acceptance Criteria
- [ ] Sandboxing mechanism implemented (subprocess or container)
- [ ] Resource limits configured
- [ ] Security profile (seccomp) applied
- [ ] Performance impact assessed
- [ ] Test added to verify sandboxing

### References
- CWE: None specified
- Related Findings: FINDING-213

### Priority
Medium

---

## Issue: FINDING-215 - Raw Database Rows Returned Without Python-Level Field Filtering
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The methods `open_to_pid()` and `upcoming_to_pid()` in `election.py` return raw database rows without explicit Python-level field filtering. If the underlying SQL queries select from the metadata table without column restrictions, sensitive fields (`salt`, `opened_key`) could leak.

### Details
**Affected Files:**
- `v3/steve/election.py:374`
- `v3/steve/election.py:399`

**ASVS Reference:** 15.3.1 (Level L1)

This is inconsistent with the control pattern used in `owned_elections()`, which explicitly excludes sensitive columns with a comment acknowledging the need to prevent exposure of `salt` and `opened_key`. The severity is mitigated if the queries in `queries.yaml` select only specific columns, but this cannot be verified from the provided code.

### Remediation
Apply explicit Python-level field filtering to `open_to_pid()` and `upcoming_to_pid()` methods, matching the pattern used in `get_metadata()` and `owned_elections()`. 

```python
def open_to_pid(self, pid):
    """Return open elections for a PID with safe fields only"""
    rows = self.queries.q_get_open.fetch(pid)
    # Explicit safe field extraction
    return [
        edict({
            'eid': row['eid'],
            'title': row['title'],
            'owner_pid': row['owner_pid'],
            'closed': row['closed'],
            'open_at': row['open_at'],
            'close_at': row['close_at'],
            'issue_count': row['issue_count']
        })
        for row in rows
    ]
```

### Acceptance Criteria
- [ ] Explicit field filtering added to open_to_pid()
- [ ] Explicit field filtering added to upcoming_to_pid()
- [ ] Test added to verify sensitive fields not returned
- [ ] Code review confirms consistency with owned_elections()

### References
- CWE: None specified
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-216 - Election Creation Accepts Unrestricted Form Data Pattern
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `do_create_endpoint()` function loads ALL form data into an edict without a whitelist, creating risk of future mass assignment.

### Details
**Affected Files:**
- `v3/server/pages.py:439`

**ASVS Reference:** 15.3.3 (Level L2)

While currently only `form.title` is passed to `Election.create()`, the pattern lacks an explicit allowlist meaning code review is the only protection. The `create()` method accepts additional parameters (`authz`, `open_at`, `close_at`) that could be exploited if a developer later extracts them from the form. If `authz` were controllable, an attacker could modify LDAP group authorization for elections they create. If `open_at`/`close_at` were controllable, dates could be manipulated.

### Remediation
Replace the edict pattern with explicit field extraction using `form.get('title', '').strip()`. Add validation to ensure title is not empty. Only accept whitelisted fields and perform type checking before passing to `Election.create()`.

```python
async def do_create_endpoint():
    form = await request.form
    
    # Explicit allowlist
    title = form.get('title', '').strip()
    
    # Validation
    if not title:
        abort(400, "Title is required")
    if len(title) > 200:
        abort(400, "Title too long")
    
    # Only pass validated, whitelisted fields
    election = Election.create(title=title)
    return redirect(f'/manage/{election.eid}')
```

### Acceptance Criteria
- [ ] Explicit field extraction implemented
- [ ] Input validation added
- [ ] Test added for empty title
- [ ] Test added for title length validation
- [ ] Test added to verify additional form fields are ignored

### References
- CWE: None specified
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-217 - Incomplete Exception Handling for Type Errors in Date Parsing
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `data.get('date')` could return any JSON type (array, object, number, boolean). The `if not date_str` check would pass for non-empty arrays/objects (truthy values). When passed to `datetime.datetime.fromisoformat()`, a non-string type raises `TypeError`, not `ValueError`.

### Details
**Affected Files:**
- `v3/server/pages.py:91`

**ASVS Reference:** 15.3.5 (Level L2)

Only `ValueError` is caught. This results in unhandled 500 error instead of a clean 400 response, potentially causing information leakage via stack traces if debug mode is enabled.

### Remediation
Add explicit type validation using `isinstance(date_str, str)` before the truthy check. Catch both `ValueError` and `TypeError` in the exception handler.

```python
async def _set_election_date(election, field):
    data = await quart.request.get_json()
    date_str = data.get('date')
    
    # Explicit type check
    if not isinstance(date_str, str) or not date_str:
        quart.abort(400, 'Missing or invalid date')

    try:
        dt = datetime.datetime.fromisoformat(date_str).date()
    except (ValueError, TypeError):
        quart.abort(400, 'Invalid date format')
    
    # Set the date...
```

### Acceptance Criteria
- [ ] Type validation added before truthy check
- [ ] TypeError caught in exception handler
- [ ] Test added for non-string date values (array, object, number)
- [ ] Test added for invalid date format strings
- [ ] Verify 400 response instead of 500 for all invalid inputs

### References
- CWE: None specified
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-218 - Database Connections Created Per-Instance Without Connection Lifecycle Management
**Labels:** bug, security, performance, priority:medium
**Description:**
### Summary
Each concurrent request creates a new Election instance which opens a new `asfpy.db.DB` connection to the same SQLite file through `Election.__init__()` and `open_database()`. There is no connection pooling, no maximum connection limit, and no timeout configuration.

### Details
**Affected Files:**
- `v3/steve/election.py`

**ASVS Reference:** 15.4.1 (Level L3)

Under high concurrency (e.g., many voters submitting simultaneously during election close), this could exhaust file descriptors or cause SQLite SQLITE_BUSY errors without proper retry logic.

### Remediation
Implement connection pooling with bounded concurrency using an `asyncio.Semaphore` to limit simultaneous database connections (e.g., max 10 concurrent connections).

```python
import asyncio

class ElectionDB:
    _connection_semaphore = asyncio.Semaphore(10)  # Max 10 concurrent connections
    
    @classmethod
    async def get_connection(cls):
        """Acquire a database connection with concurrency control"""
        async with cls._connection_semaphore:
            db = open_database()
            try:
                yield db
            finally:
                db.close()

# Usage
async with ElectionDB.get_connection() as db:
    # Perform database operations
    pass
```

### Acceptance Criteria
- [ ] Connection pooling implemented with semaphore
- [ ] Maximum connection limit configured
- [ ] Connection timeout configured
- [ ] Test added for high concurrency scenarios
- [ ] Monitoring added for connection pool metrics

### References
- CWE: None specified
- Related Findings: FINDING-222

### Priority
Medium

---

## Issue: FINDING-219 - Non-Atomic State Check and Close Operation
**Labels:** bug, security, concurrency, priority:medium
**Description:**
### Summary
The `close()` method performs a non-atomic check-then-use operation where it first checks if the election is open (`is_open()`) and then closes it (`c_close.perform()`). Between these operations, a concurrent close could execute.

### Details
**Affected Files:**
- `v3/steve/election.py:111-116`

**ASVS Reference:** 15.4.2 (Level L3)
**CWE:** CWE-367 (Time-of-check Time-of-use Race Condition)

While double-close is less severe than double-open since closing is idempotent at the database level (setting `closed=1` twice has the same effect), it still represents a TOCTOU pattern that could produce misleading log entries or confusing user feedback.

### Remediation
Wrap the `close()` operation in a BEGIN IMMEDIATE transaction with state re-verification. Re-check the election state within the transaction to ensure it is still open before performing the close operation.

```python
def close(self):
    """Close election with atomic state verification"""
    self.db.conn.execute('BEGIN IMMEDIATE')
    try:
        # Re-verify state within transaction
        if not self.is_open():
            self.db.conn.execute('ROLLBACK')
            raise ValueError("Election is not open")
        
        # Perform close
        self.queries.c_close.perform(self.eid)
        self.db.conn.execute('COMMIT')
    except Exception:
        self.db.conn.execute('ROLLBACK')
        raise
```

### Acceptance Criteria
- [ ] Transaction wrapper added to close()
- [ ] State re-verification within transaction
- [ ] ROLLBACK on error implemented
- [ ] Test added for concurrent close attempts
- [ ] Test added to verify transaction behavior

### References
- CWE: CWE-367
- Related Findings: FINDING-074, FINDING-220

### Priority
Medium

---

## Issue: FINDING-220 - TOCTOU Between Authorization Check and File Serving
**Labels:** bug, security, concurrency, priority:medium
**Description:**
### Summary
The `serve_doc()` endpoint performs a non-atomic authorization check followed by file serving. It first checks if the user has permission by querying `q_get_mayvote.first_row(result.uid, iid)`, then serves the file using `send_from_directory()`.

### Details
**Affected Files:**
- `v3/server/pages.py:585-599`

**ASVS Reference:** 15.4.2 (Level L3)
**CWE:** CWE-367 (Time-of-check Time-of-use Race Condition)

Between the check and use, the mayvote entry could be deleted (e.g., if the election is reset), allowing a file to be served to a user whose permission was just revoked. While the window is small and the consequence is limited, this is a textbook TOCTOU pattern.

### Remediation
Perform the authorization check and file serving within a transaction, or re-verify the authorization immediately before serving the file. Consider caching the authorization decision with a short TTL.

```python
@APP.route('/docs/<iid>/<docname>')
@asfquart.auth.require
async def serve_doc(iid, docname):
    result = await asfquart.session.read(request)
    
    # Start transaction for atomic check
    db = open_database()
    db.conn.execute('BEGIN IMMEDIATE')
    try:
        # Authorization check within transaction
        mayvote = queries.q_get_mayvote.first_row(result.uid, iid)
        if not mayvote:
            db.conn.execute('ROLLBACK')
            quart.abort(403, 'You are not authorized to view this document')
        
        # Serve file while transaction is active
        response = await send_from_directory(docs_dir, docname)
        db.conn.execute('COMMIT')
        return response
    except Exception:
        db.conn.execute('ROLLBACK')
        raise
```

### Acceptance Criteria
- [ ] Authorization check made atomic with file serving
- [ ] Transaction or re-verification implemented
- [ ] Test added for concurrent permission revocation
- [ ] Test added to verify transaction behavior

### References
- CWE: CWE-367
- Related Findings: FINDING-074, FINDING-219

### Priority
Medium

---

## Issue: FINDING-221 - Transaction Blocks Lack Error Handling — No ROLLBACK on Failure
**Labels:** bug, security, database, priority:medium
**Description:**
### Summary
If any operation within the transaction raises an exception, the transaction remains open (not committed, not rolled back). The SQLite connection would hold a write lock until the connection is garbage-collected or explicitly closed.

### Details
**Affected Files:**
- `v3/steve/election.py:56-67`
- `v3/steve/election.py:118-135`

**ASVS Reference:** 15.4.3 (Level L3)

In a concurrent environment, this could deadlock other database operations waiting for the write lock.

### Remediation
Add try/except/ROLLBACK blocks to all transaction code. Wrap transaction operations in try blocks, catch exceptions, execute ROLLBACK, and re-raise the exception to ensure locks are properly released on failure.

```python
def open(self):
    """Open election with proper transaction error handling"""
    self.db.conn.execute('BEGIN IMMEDIATE')
    try:
        # Verify state
        if self.is_open():
            raise ValueError("Election is already open")
        
        # Generate and store opened_key
        opened_key = gen_opened_key()
        self.queries.c_set_opened_key.perform(opened_key, self.eid)
        
        # Mark as open
        self.queries.c_open.perform(self.eid)
        
        self.db.conn.execute('COMMIT')
    except Exception:
        self.db.conn.execute('ROLLBACK')
        raise
```

### Acceptance Criteria
- [ ] Try/except/ROLLBACK added to all transaction blocks
- [ ] Test added for transaction failure scenarios
- [ ] Test added to verify locks are released on error
- [ ] Test added for concurrent access during failure

### References
- CWE: None specified
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-222 - No SQLite Busy Timeout Configuration — Concurrent Requests Can Fail Immediately
**Labels:** bug, performance, database, priority:medium
**Description:**
### Summary
Concurrent requests → multiple `open_database()` calls → multiple SQLite connections → no `busy_timeout` set → SQLITE_BUSY error returned immediately to lower-priority threads.

### Details
**Affected Files:**
- `v3/steve/election.py:40`

**ASVS Reference:** 15.4.4 (Level L3)

When multiple concurrent requests contend for the SQLite write lock, requests that cannot immediately acquire the lock receive an SQLITE_BUSY error without retrying. This effectively starves lower-priority requests (those that arrive slightly later) by failing them immediately rather than allowing them to wait a reasonable time. SQLite's default busy timeout is 0 (fail immediately), which causes thread starvation under any write contention.

### Remediation
Configure SQLite busy timeout in `open_database()`:

```python
def open_database():
    """Open database with proper busy timeout configuration"""
    db = asfpy.db.DB(DB_FILE)
    
    # Configure 5-second busy timeout
    db.conn.execute('PRAGMA busy_timeout = 5000')
    
    return db
```

### Acceptance Criteria
- [ ] busy_timeout configured in open_database()
- [ ] Timeout value made configurable (default 5000ms)
- [ ] Test added for concurrent write scenarios
- [ ] Test added to verify timeout behavior
- [ ] Monitoring added for SQLITE_BUSY occurrences

### References
- CWE: None specified
- Related Findings: FINDING-218

### Priority
Medium

---

## Issue: FINDING-223 - Unbounded Iteration Over User-Supplied Form Keys Without Limiting Candidate Count
**Labels:** bug, security, performance, priority:medium
**Description:**
### Summary
User-controlled form data (potentially thousands of vote-xxx keys) → iteration → `add_vote()` call per key → database query + crypto operations per iteration → CPU/IO exhaustion.

### Details
**Affected Files:**
- `v3/server/pages.py:399-420`

**ASVS Reference:** 15.4.4 (Level L3)

A single authenticated request with many fabricated vote- parameters forces the server to iterate through all of them. While invalid IIDs are caught early, the iteration itself and the `issue_dict` lookups consume resources proportional to attacker input size.

### Remediation
Implement a maximum vote count per request (e.g., MAX_VOTES_PER_REQUEST = 100). Check `len(votes)` during iteration and return an error if the limit is exceeded before processing further.

```python
MAX_VOTES_PER_REQUEST = 100

async def do_vote_endpoint(eid):
    form = await request.form
    
    # Extract vote keys
    votes = [(k, v) for k, v in form.items() if k.startswith('vote-')]
    
    # Enforce limit
    if len(votes) > MAX_VOTES_PER_REQUEST:
        quart.abort(400, f'Too many votes in single request (max {MAX_VOTES_PER_REQUEST})')
    
    # Process votes...
    for key, value in votes:
        # existing logic
        pass
```

### Acceptance Criteria
- [ ] MAX_VOTES_PER_REQUEST limit implemented
- [ ] Configuration parameter for limit
- [ ] Test added for exceeding vote limit
- [ ] Test added for valid vote count at limit
- [ ] Error message provides clear feedback

### References
- CWE: None specified
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-224 - No documented rate limiting, anti-automation, or adaptive response controls for authentication endpoints
**Labels:** documentation, security, authentication, priority:medium
**Description:**
### Summary
The application delegates authentication to ASF OAuth (oauth.apache.org). However, there is no documentation anywhere in the provided code that describes how rate limiting, anti-automation controls, or adaptive response mechanisms are configured.

### Details
**Affected Files:**
- `v3/server/main.py:34-39`
- `v3/server/pages.py`

**ASVS Reference:** 6.1.1 (Level L1)

Without documented rate limiting controls, there is no assurance that brute force or credential stuffing attacks against the OAuth flow are mitigated. Operational staff cannot verify correct configuration without documentation. The `asfquart.auth.require` decorator is used extensively but no per-endpoint rate limiting is applied.

### Remediation
Create authentication security documentation that specifies:

```markdown
# docs/AUTHENTICATION_SECURITY.md

## Rate Limiting

### OAuth Callback Endpoint
- **Provider:** Delegated to ASF OAuth (oauth.apache.org)
- **Controls:** [Describe ASF OAuth rate limiting]
- **Application Layer:** Max N attempts per IP per minute via reverse proxy

## Anti-Automation
- **CAPTCHA Integration:** [Describe mechanism]
- **Bot Detection:** [Describe detection methods]

## Adaptive Response
- **Failed Attempts:** [Behavior after N failures]
- **Account Lockout Prevention:** [Unlock mechanism for ASF accounts]

## Reverse Proxy Configuration
- **Apache/nginx Rules:** [Reference to config files]
- **Rate Limit Implementation:** [Specific rules]
```

### Acceptance Criteria
- [ ] AUTHENTICATION_SECURITY.md created
- [ ] Rate limiting mechanisms documented
- [ ] Anti-automation controls documented
- [ ] Adaptive response behavior documented
- [ ] Reverse proxy configuration referenced
- [ ] Document reviewed by security team

### References
- CWE: None specified
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-225 - Multiple authentication pathways exist but are not documented together with security controls
**Labels:** documentation, security, authentication, priority:medium
**Description:**
### Summary
The application implements at least three distinct authentication/authorization pathways but lacks comprehensive documentation of security controls at each level.

### Details
**Affected Files:**
- `v3/server/pages.py` (multiple locations)

**ASVS Reference:** 6.1.3 (Level L2)

Authentication pathways:
1. Bare session (`@asfquart.auth.require`) for /profile, /settings, /docs
2. Committer level (`@asfquart.auth.require({R.committer})`) for /voter, /admin, /manage
3. PMC member level (`@asfquart.auth.require({R.pmc_member})`) for /do-create-election

The '### need general solution' comments throughout indicate that the authorization model is incomplete and evolving. There is no documentation defining what security controls apply at each level or describing the authentication strength.

### Remediation
Create comprehensive authentication pathways documentation:

```markdown
# docs/AUTHENTICATION.md

## OAuth Flow
- **Provider:** ASF OAuth (oauth.apache.org)
- **Authentication Strength:** Single-factor ASF credentials
- **Session Management:** [Describe mechanism]
- **Security Controls:** [List controls]

## Authorization Levels

### Level 0: Public/No Authentication
- **Endpoints:** /
- **Controls:** None

### Level 1: Authenticated User
- **Endpoints:** /profile, /settings
- **Requirement:** Valid session
- **Controls:** Session validation

### Level 2: ASF Committer
- **Endpoints:** /voter, /admin, /manage/<eid>
- **Requirement:** Committer status (LDAP group)
- **Controls:** Group membership verification

### Level 3: PMC Member
- **Endpoints:** /do-create-election
- **Requirement:** PMC member status
- **Controls:** PMC group membership verification

## Consistency Enforcement
All pathways use the same ASF OAuth provider with identical authentication strength. Authorization differs by LDAP group membership.

## Known Gaps
- Fine-grained authorization checks (marked with ### check authz)
- Planned remediation: [Describe plan]
```

### Acceptance Criteria
- [ ] AUTHENTICATION.md created with all pathways documented
- [ ] Security controls documented for each level
- [ ] Known gaps acknowledged and remediation planned
- [ ] Document reviewed by security and development teams

### References
- CWE: None specified
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-226 - No Visible Token Signature Validation in Application Code
**Labels:** bug, security, authentication, priority:medium
**Description:**
### Summary
Token/session validation is entirely delegated to the `asfquart` framework. The application code contains zero explicit signature validation, and no configuration parameters for signature verification keys are provided.

### Details
**Affected Files:**
- `v3/server/pages.py:75-106`
- `v3/server/main.py:27-42`

**ASVS Reference:** 9.1.1 (Level L1)

If `asfquart` fails to validate, the application has no defense-in-depth. The application's trust model assumes `asfquart.session.read()` returns fully validated, trustworthy data. Every endpoint reads session data and uses `uid` directly for authorization decisions without any additional verification layer.

### Remediation
**Option 1:** Add explicit verification that the framework is configured for signature validation:

```python
app = asfquart.construct('steve', app_dir=THIS_DIR, static_folder=None)
assert app.cfg.session.signing_key, "Session signing key must be configured"
assert app.cfg.session.verify_signatures is True, "Signature verification must be enabled"
```

**Option 2:** If JWTs are used, add application-level verification:

```python
import jwt

def verify_token(token, public_key, algorithms=['RS256', 'ES256']):
    return jwt.decode(token, public_key, algorithms=algorithms,
                      options={"verify_signature": True})
```

Additional recommendations:
1. Audit `asfquart` framework for ASVS 9.x compliance
2. Configure audience validation
3. Implement defense-in-depth with application-level validation

### Acceptance Criteria
- [ ] Framework signature validation verified
- [ ] Application-level verification added (if applicable)
- [ ] Configuration assertions added
- [ ] Algorithm allowlist configured
- [ ] Test added to verify signature validation

### References
- CWE: None specified
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-227 - No Algorithm Restriction Configuration Visible
**Labels:** bug, security, authentication, priority:medium
**Description:**
### Summary
No algorithm allowlist is configured anywhere in the provided application code. If the asfquart framework or any JWT library processes self-contained tokens, there is no explicit restriction to approved algorithms.

### Details
**Affected Files:**
- `v3/server/main.py:27-42`

**ASVS Reference:** 9.1.2 (Level L1)

If the underlying framework uses a JWT library that accepts the `alg: none` header or allows algorithm confusion attacks (e.g., treating an RSA public key as an HMAC secret with HS256), an attacker could forge valid-looking tokens. The audit context specifies only approved algorithms (RS256, ES256) are allowed — no such restriction is implemented.

### Remediation
In `create_app()` or configuration, explicitly set allowed algorithms:

```python
# Configure algorithm allowlist for token validation
app.config['TOKEN_ALGORITHMS'] = ['RS256', 'ES256']  # No 'none', no HS256
app.config['TOKEN_REJECT_NONE_ALG'] = True

# If using PyJWT directly:
ALLOWED_ALGORITHMS = ['RS256', 'ES256']

def decode_token(token, key):
    return jwt.decode(token, key, algorithms=ALLOWED_ALGORITHMS)
    # Never pass algorithms=None
```

### Acceptance Criteria
- [ ] Algorithm allowlist configured
- [ ] 'none' algorithm explicitly rejected
- [ ] HS256 excluded from allowed algorithms
- [ ] Test added to verify algorithm enforcement
- [ ] Test added to reject 'none' algorithm

### References
- CWE: None specified
- Related Findings: FINDING-226

### Priority
Medium

---

## Issue: FINDING-228 - No Key Material Source Validation Configured
**Labels:** bug, security, authentication, priority:medium
**Description:**
### Summary
No configuration of trusted key sources, no JKU/x5u/JWK header allowlists, and no pinned public keys for the OAuth issuer (oauth.apache.org) are visible in the application code.

### Details
**Affected Files:**
- `v3/server/main.py:27-42`

**ASVS Reference:** 9.1.3 (Level L1)

If self-contained tokens (JWTs) are used with headers like `jku` (JSON Web Key URL), an attacker could potentially craft a token pointing to their own key server, causing the application to validate the forged token against attacker-controlled keys.

### Remediation
Configure trusted key sources:

```python
# In create_app() or config
TRUSTED_JWKS_URLS = ['https://oauth.apache.org/.well-known/jwks.json']
TRUSTED_ISSUERS = ['https://oauth.apache.org']

app.config['TRUSTED_JWKS_URLS'] = TRUSTED_JWKS_URLS
app.config['TRUSTED_ISSUERS'] = TRUSTED_ISSUERS

# In token validation
def validate_token_headers(token):
    """Reject tokens with untrusted key sources"""
    header = jwt.get_unverified_header(token)
    
    if 'jku' in header and header['jku'] not in TRUSTED_JWKS_URLS:
        raise ValueError("Untrusted JKU header")
    
    if 'x5u' in header:
        raise ValueError("x5u header not allowed")
    
    if 'jwk' in header:
        raise ValueError("Embedded JWK not allowed")
```

### Acceptance Criteria
- [ ] Trusted key sources configured
- [ ] JKU allowlist implemented
- [ ] x5u and jwk headers rejected
- [ ] Test added to verify trusted sources
- [ ] Test added to reject untrusted sources

### References
- CWE: None specified
- Related Findings: FINDING-226, FINDING-227

### Priority
Medium

---

## Issue: FINDING-229 - No Token Expiry Verification in Application Code
**Labels:** bug, security, authentication, priority:medium
**Description:**
### Summary
The application reads session data and checks only for presence (`if s:`), not for temporal validity. No `exp`, `nbf`, or `iat` claim verification is visible.

### Details
**Affected Files:**
- `v3/server/pages.py:75-106`

**ASVS Reference:** 9.2.1 (Level L1)

If `asfquart.session.read()` does not internally verify token expiration, expired sessions would be accepted indefinitely. The application's trust model assumes the framework returns fully validated data without additional verification.

### Remediation
Verify session hasn't expired at the application layer even if framework handles this:

```python
import time

async def get_session_with_validation(request):
    """Get session with explicit expiry validation"""
    s = await asfquart.session.read(request)
    
    if not s:
        return None
    
    # Check expiry
    if 'exp' in s and time.time() > s['exp']:
        # Session expired
        return None
    
    # Check not-before
    if 'nbf' in s and time.time() < s['nbf']:
        # Session not yet valid
        return None
    
    return s
```

### Acceptance Criteria
- [ ] Expiry validation added to session reading
- [ ] nbf (not-before) validation added
- [ ] Test added for expired sessions
- [ ] Test added for not-yet-valid sessions
- [ ] Proper error responses for invalid sessions

### References
- CWE: None specified
- Related Findings: FINDING-226

### Priority
Medium

---

## Issue: FINDING-230 - No Token Type Differentiation or Verification
**Labels:** bug, security, authentication, priority:medium
**Description:**
### Summary
The application explicitly avoids OIDC (which provides standard ID tokens with `typ` claims and clear access/identity token separation). The plain OAuth flow used does not distinguish between token types.

### Details
**Affected Files:**
- `v3/server/pages.py:75-106`
- `v3/server/main.py:27-42`

**ASVS Reference:** 9.2.2 (Level L2)

No `typ` or `token_use` claim is checked before accepting token contents for authentication decisions. Without token type verification, there is a risk of token misuse where different token types issued for different purposes could be used interchangeably.

### Remediation
If using OIDC (recommended over plain OAuth), the framework should validate that ID tokens are used for authentication and access tokens for API calls. At the application level, implement token type checking:

```python
def validate_token_type(session):
    """Verify token type is appropriate for authentication"""
    token_type = session.get('token_type') or session.get('typ')
    
    if token_type not in ['id_token', 'session']:
        raise ValueError(f"Invalid token type for authentication: {token_type}")
    
    return True

async def get_session_with_type_check(request):
    s = await asfquart.session.read(request)
    if s:
        validate_token_type(s)
    return s
```

### Acceptance Criteria
- [ ] Token type validation implemented
- [ ] Expected token types documented
- [ ] Test added for correct token types
- [ ] Test added to reject wrong token types
- [ ] Consider migration to OIDC for standard token types

### References
- CWE: None specified
- Related Findings: FINDING-226

### Priority
Medium

---

## Issue: FINDING-231 - No Audience Claim Validation Configured
**Labels:** bug, security, authentication, priority:medium
**Description:**
### Summary
No audience (`aud`) claim validation is configured or performed anywhere in the visible application code. The application identifier 'steve' is used for app construction but not configured as an expected audience for token validation.

### Details
**Affected Files:**
- `v3/server/main.py:27-42`
- `v3/server/pages.py:75-106`

**ASVS Reference:** 9.2.3 (Level L2)

If oauth.apache.org issues tokens for multiple applications (which is likely given it's a shared OAuth provider for all ASF services), a token intended for another ASF application could potentially be replayed against this STeVe application. Without audience validation, cross-application token reuse is possible.

### Remediation
Configure expected audience in `create_app()`:

```python
# Configuration
app.config['TOKEN_AUDIENCE'] = 'steve'
app.config['TOKEN_ISSUER'] = 'https://oauth.apache.org'

# Validation function
def validate_token_claims(session):
    """Validate audience and issuer claims"""
    EXPECTED_AUDIENCE = app.config['TOKEN_AUDIENCE']
    EXPECTED_ISSUER = app.config['TOKEN_ISSUER']
    
    # Check audience (can be string or list)
    aud = session.get('aud')
    if isinstance(aud, str):
        if aud != EXPECTED_AUDIENCE:
            raise ValueError(f"Invalid audience: {aud}")
    elif isinstance(aud, list):
        if EXPECTED_AUDIENCE not in aud:
            raise ValueError(f"Audience not in list: {aud}")
    else:
        raise ValueError("Missing audience claim")
    
    # Check issuer
    iss = session.get('iss')
    if iss != EXPECTED_ISSUER:
        raise ValueError(f"Invalid issuer: {iss}")
```

### Acceptance Criteria
- [ ] Audience validation configured
- [ ] Issuer validation configured
- [ ] Validation function implemented
- [ ] Test added for correct audience
- [ ] Test added to reject wrong audience
- [ ] Test added for audience list handling

### References
- CWE: None specified
- Related Findings: FINDING-226

### Priority
Medium

---

## Issue: FINDING-232 - No Clear-Site-Data Header or Client-side Storage Cleanup Mechanism Present
**Labels:** bug, security, privacy, priority:medium
**Description:**
### Summary
The provided code constitutes the data access layer of an election system that handles highly sensitive data. Without a Clear-Site-Data header sent on session termination/logout, sensitive election data may persist in browser caches after the user's session ends.

### Details
**Affected Files:**
- `v3/steve/election.py`
- `v3/schema.sql`
- `v3/docs/schema.md`

**ASVS Reference:** 14.3.1 (Level L1)

Given the core security requirement of ballot secrecy, residual data showing which issues a voter has voted upon could persist on shared or compromised devices. The web framework layer (Quart) is not included in the audit scope, but no evidence of a logout handler sending Clear-Site-Data header is present.

### Remediation
In the Quart web layer (not provided), implement a logout endpoint:

```python
@app.route('/logout')
async def logout():
    # Invalidate server-side session
    await asfquart.session.delete(request)
    
    # Clear client-side data
    response = redirect('/')
    response.headers['Clear-Site-Data'] = '"cache", "cookies", "storage"'
    return response
```

Additionally, implement client-side cleanup:

```javascript
// Client-side cleanup for offline scenarios
window.addEventListener('beforeunload', function() {
    if (sessionExpired()) {
        localStorage.clear();
        sessionStorage.clear();
    }
});
```

### Acceptance Criteria
- [ ] Logout endpoint implemented with Clear-Site-Data header
- [ ] Client-side cleanup script added
- [ ] Test added to verify header is sent
- [ ] Test added to verify storage is cleared
- [ ] Documentation updated with logout flow

### References
- CWE: None specified
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-233 - Data Access Layer Returns Sensitive Data Without Browser Storage Restrictions
**Labels:** bug, security, privacy, priority:medium
**Description:**
### Summary
The election module's API surface returns data that must not be persisted in client-side browser storage (localStorage, sessionStorage, IndexedDB). The `has_voted_upon` method creates a voter-to-issue-participation mapping that could violate ballot secrecy if stored.

### Details
**Affected Files:**
- `v3/steve/election.py` (has_voted_upon method)
- `v3/steve/election.py` (get_voters_for_email method)

**ASVS Reference:** 14.3.3 (Level L2)

If any client-side JavaScript stores `has_voted_upon` results, it directly links voter identity (PID) to voting participation per issue, violating ballot secrecy. No Content-Security-Policy or JavaScript controls preventing storage are present.

### Remediation
1. At the web framework layer, implement CSP headers:

```python
@app.after_request
async def set_csp_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
    return response
```

2. In client-side JavaScript, explicitly avoid storing sensitive API responses:

```javascript
// Keep sensitive data only in memory
let votingStatus = null;

async function loadVotingStatus() {
    const response = await fetch('/api/has-voted');
    votingStatus = await response.json();
    // DO NOT: localStorage.setItem('votingStatus', JSON.stringify(votingStatus));
    // Data exists only in memory and is garbage-collected on page navigation
}
```

3. Add security comment to data access layer:

```python
def has_voted_upon(self, pid):
    """
    Return voting status for a voter.
    
    SECURITY: Results contain voter-specific data that MUST NOT be 
    persisted in client-side storage (localStorage, sessionStorage, IndexedDB).
    Keep in memory only.
    """
```

### Acceptance Criteria
- [ ] CSP headers implemented restricting script capabilities
- [ ] Client-side code audited to ensure no sensitive data storage
- [ ] Security comments added to sensitive methods
- [ ] Test added to verify CSP headers
- [ ] Developer documentation updated with storage restrictions

### References
- CWE: None specified
- Related Findings: FINDING-232

### Priority
Medium

---

## Issue: FINDING-234 - No HTTP Security Headers Configuration or Documentation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application does not configure or document any browser security features. There is no evidence of HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, or Permissions-Policy headers.

### Details
**Affected Files:**
- `v3/server/pages.py` (entire file)

**ASVS Reference:** 3.1.1 (Level L3)

Without documented browser security requirements and enforced headers:
1. No HSTS means connections may be downgraded to HTTP
2. No CSP means the application is more vulnerable to XSS exploitation
3. No documentation means deployment teams cannot verify correct security configuration
4. Browsers with insufficient security features will access the application without warning

### Remediation
Add security headers middleware:

```python
@APP.after_request
async def set_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response
```

Additionally, create `docs/SECURITY.md`:

```markdown
## Browser Security Requirements

### Required Browser Features
- TLS 1.2 or higher
- JavaScript enabled
- Secure cookie support

### Expected Headers
- Strict-Transport-Security (from reverse proxy or application)
- Content-Security-Policy
- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy

### Behavior When Security Features Unavailable
- [Describe graceful degradation or blocking strategy]
```

### Acceptance Criteria
- [ ] Security headers middleware implemented
- [ ] SECURITY.md documentation created
- [ ] Headers configuration made configurable
- [ ] Test added to verify all headers present
- [ ] Deployment guide updated with header requirements

### References
- CWE: None specified
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-235 - Key Sharing Scope Not Formally Documented
**Labels:** documentation, security, cryptography, priority:low
**Description:**
### Summary
The `opened_key` in each election effectively acts as a shared secret used by the system to derive per-voter vote tokens. While the key is only accessible to the application server (single entity), the sharing boundaries are not formally documented.

### Details
**Affected Files:**
- `v3/steve/crypto.py`
- `v3/steve/election.py`

**ASVS Reference:** 11.1.1 (Level L2)

The key derivation chain (opened_key → vote_token → vote_key) means compromise of the opened_key enables decryption of all votes in that election. Without formal documentation of key sharing boundaries, there's risk of architectural changes inadvertently exposing keys to additional entities.

### Remediation
Formally document key sharing boundaries and access control policies:

```markdown
# docs/KEY_MANAGEMENT.md

## Key Sharing Boundaries

### opened_key
- **Scope:** Single election
- **Shared Between:** Application server processes only (not shared across entities)
- **Access Control:** 
  - Database-level: Stored in metadata table
  - Application-level: Only election.py module accesses
  - Network-level: Never transmitted off-server
- **Compromise Impact:** All votes in the election can be decrypted
- **Rotation:** Cannot be rotated (election-lifetime key)

## Key Derivation Chain
1. opened_key (election-level, stored encrypted)
2. → vote_token (per-voter-per-issue, derived via Argon2)
3. → vote_key (per-voter-per-issue, derived via HKDF)
4. → vote ciphertext (per-voter-per-issue, encrypted)

## Architectural Constraints
- opened_key MUST NOT be shared across network boundaries
- opened_key MUST NOT be accessible to client code
- Any architectural change that exposes opened_key requires security review
```

### Acceptance Criteria
- [ ] KEY_MANAGEMENT.md created
- [ ] Key sharing boundaries documented
- [ ] Key derivation chain documented
- [ ] Compromise impact assessed
- [ ] Architectural constraints documented

### References
- CWE: None specified
- Related Findings: None

### Priority
Low

---

## Issue: FINDING-236 - Misleading HKDF Info Parameter Suggests Incomplete Migration
**Labels:** bug, security, cryptography, priority:low
**Description:**
### Summary
The HKDF `info` parameter is set to `b'xchacha20_key'` while the system currently uses Fernet for encryption. When the system migrates to XChaCha20-Poly1305, this `info` value will remain the same, violating the principle that a single key should not be used across different algorithm/data-element pairs.

### Details
**Affected Files:**
- `v3/steve/crypto.py:63-67`

**ASVS Reference:** 11.2.2, 11.3.4 (Level L2, L3)

If old ciphertexts coexist with new ciphertexts during migration, keys derived for Fernet would be identical to keys derived for XChaCha20-Poly1305, lacking proper domain separation.

### Remediation
Use `info=b'fernet_vote_key'` now, and switch to `info=b'xchacha20_vote_key'` during migration to ensure domain separation.

```python
def _b64_vote_key(opened_key, vote_token):
    """Derive a base64-encoded vote key using HKDF"""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'fernet_vote_key',  # Change to b'xchacha20_vote_key' when algorithm changes
    )
    key = hkdf.derive(opened_key + vote_token)
    return base64.urlsafe_b64encode(key)
```

### Acceptance Criteria
- [ ] HKDF info parameter updated to reflect current algorithm
- [ ] Comment added explaining migration plan
- [ ] Migration documentation updated with info parameter change
- [ ] Test added to verify different keys for different algorithms

### References
- CWE: None specified
- Related Findings: FINDING-206

### Priority
Low

---

## Issue: FINDING-237 - BLAKE2b usage may not meet strict NIST compliance requirements
**Labels:** documentation, security, cryptography, compliance, priority:low
**Description:**
### Summary
BLAKE2b is a modern, secure hash function (RFC 7693) with a 512-bit output, providing strong collision resistance. However, it is not listed in NIST FIPS 180-4 (SHA-2) or FIPS 202 (SHA-3) as an "approved" hash function.

### Details
**Affected Files:**
- `v3/steve/crypto.py:45`

**ASVS Reference:** 11.4.1 (Level L1)

Depending on organizational compliance requirements, this could be a concern. In practice, BLAKE2b is used within Argon2 itself (which is NIST-recognized via SP 800-63B), making this a very low-risk finding.

### Remediation
If strict NIST compliance is required, replace with SHA-512:

```python
def _hash(edata):
    """Hash election data for verification"""
    digest = hashlib.sha512(edata).digest()  # 64 bytes, NIST-approved
    return base64.urlsafe_b64encode(digest).decode('ascii').rstrip('=')
```

Otherwise, document the rationale for BLAKE2b usage:

```python
def _hash(edata):
    """
    Hash election data for verification using BLAKE2b.
    
    Note: BLAKE2b (RFC 7693) is not NIST FIPS-approved but provides
    equivalent security to SHA-512. It is used here for performance.
    If strict NIST compliance is required, replace with SHA-512.
    """
```

### Acceptance Criteria
- [ ] Compliance requirements assessed
- [ ] Either replace with SHA-512 or document rationale
- [ ] If keeping BLAKE2b, add comment explaining choice
- [ ] Compliance documentation updated

### References
- CWE: None specified
- Related Findings: None

### Priority
Low

---

## Issue: FINDING-238 - HKDF usage documentation needed to clarify key stretching architecture
**Labels:** documentation, security, cryptography, priority:low
**Description:**
### Summary
HKDF is not a key-stretching function and provides no computational cost against brute-force. However, since the input (vote_token) is already the 32-byte output of Argon2 (which provides the key stretching), HKDF is being used appropriately as a key derivation function.

### Details
**Affected Files:**
- `v3/steve/crypto.py:60-67`

**ASVS Reference:** 11.4.4 (Level L2)

This is acceptable architecture but worth documenting that the stretching occurs upstream.

### Remediation
Add a comment clarifying the security model:

```python
def _b64_vote_key(opened_key, vote_token):
    """
    Derive a base64-encoded vote key using HKDF.
    
    Note: Key stretching is provided by Argon2 in gen_vote_token().
    HKDF here only transforms the already-stretched token into a key
    suitable for the encryption algorithm.
    
    Security Model:
    - vote_token is 32 bytes from Argon2 (computationally expensive)
    - HKDF provides domain separation and algorithm-specific derivation
    - HKDF is NOT used for key stretching (that's Argon2's role)
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'xchacha20_key',  # TODO: Update when migrating from Fernet
    )
    key = hkdf.derive(opened_key + vote_token)
    return base64.urlsafe_b64encode(key)
```

### Acceptance Criteria
- [ ] Comment added explaining security model
- [ ] Key stretching architecture documented
- [ ] Clarification that HKDF is not for stretching
- [ ] Reference to Argon2 as the stretching mechanism

### References
- CWE: None specified
- Related Findings: None

### Priority
Low

---

## Issue: FINDING-239 - All votes decrypted and held simultaneously in memory during tally
**Labels:** security, performance, cryptography, priority:low
**Description:**
### Summary
The entire set of decrypted votes exists in cleartext memory simultaneously. For elections with many voters, this creates a larger window where all vote data is exposed. There is no explicit clearing of sensitive variables after use.

### Details
**Affected Files:**
- `v3/steve/election.py:248-294`

**ASVS Reference:** 11.7.2 (Level L3)

Data flow: All votes for an issue are decrypted simultaneously → stored in `votes` list → remain in memory until garbage collected.

### Remediation
Process votes through streaming tally where possible. For STV (requires all votes), minimize exposure window by explicitly clearing sensitive data in a finally block.

```python
def tally_issue(self, iid):
    """Tally votes with explicit memory cleanup"""
    votes = []
    try:
        # Decrypt all votes
        for row in self.queries.q_get_votes.fetch(iid):
            votestring = decrypt_votestring(self.opened_key, row['voter'], iid, row['vote'])
            votes.append(votestring)
        
        # Perform tally
        result = self._run_tally_algorithm(votes)
        return result
    
    finally:
        # Explicit cleanup (Python doesn't guarantee zeroing, but reduces window)
        if votes:
            for i in range(len(votes)):
                votes[i] = None
            votes.clear()
```

### Acceptance Criteria
- [ ] Explicit memory cleanup added to tally operations
- [ ] Finally block ensures cleanup even on exception
- [ ] Documentation added explaining memory exposure window
- [ ] Consider streaming tally for non-STV methods

### References
- CWE: None specified
- Related Findings: FINDING-240

### Priority
Low

---

## Issue: FINDING-240 - Voter identity data accumulated in cleartext memory during election data gathering
**Labels:** security, privacy, cryptography, priority:low
**Description:**
### Summary
Voter identity data (PIDs and email addresses) exists in unencrypted memory longer than necessary. The assembled string is only needed for hashing but persists until garbage collected.

### Details
**Affected Files:**
- `v3/steve/election.py:82-107`

**ASVS Reference:** 11.7.2 (Level L3)

Data flow: All voter PIDs and emails assembled in cleartext string → encoded to bytes → passed to hash function → original strings remain in memory.

### Remediation
Use incremental hashing to avoid accumulating all data in a single string:

```python
def get_hash(self):
    """Generate election hash using incremental hashing"""
    import hashlib
    
    # Create hash object for incremental updates
    hasher = hashlib.blake2b()
    
    # Add metadata incrementally
    meta = self.get_metadata()
    hasher.update(f"eid={meta.eid}\n".encode('utf-8'))
    hasher.update(f"title={meta.title}\n".encode('utf-8'))
    # ... other metadata fields
    
    # Add issues incrementally
    for issue in self.get_issues():
        hasher.update(f"issue={issue.iid}:{issue.title}\n".encode('utf-8'))
    
    # Add voters incrementally (never accumulate in single string)
    for voter in self.queries.q_get_voters.fetch(self.eid):
        hasher.update(f"voter={voter['pid']}:{voter['email']}\n".encode('utf-8'))
    
    # Return final digest
    digest = hasher.digest()
    return base64.urlsafe_b64encode(digest).decode('ascii').rstrip('=')
```

### Acceptance Criteria
- [ ] Incremental hashing implemented
- [ ] No accumulation of sensitive data in single string
- [ ] Test added to verify hash consistency
- [ ] Memory usage reduced for large elections

### References
- CWE: None specified
- Related Findings: FINDING-239

### Priority
Low

## Issue: FINDING-241 - No Evidence of Cache-Control Mechanisms for Sensitive Data Responses
**Labels:** bug, security, priority:low
**Description:**
### Summary
The data access layer returns sensitive data objects including voter PII (email, name) and election metadata (salt, opened_key) without visible HTTP cache-control headers or cache purging mechanisms. Without explicit cache controls at the HTTP layer, sensitive voter data could be cached in reverse proxies, application-level caches, or browser caches.

### Details
The data access layer in `election.py` returns sensitive data objects but no cache prevention controls are visible in the provided code. The web layer (Quart framework) is not in scope for this audit. Without explicit cache controls:
- Voter email addresses could be cached in reverse proxies
- Election metadata with sensitive fields could persist in application-level caches
- Browser caches could store sensitive responses

**Affected Files:**
- `v3/steve/election.py` (entire module)

**CWE:** None specified
**ASVS:** 14.2.2 (L2)

### Remediation
In the Quart web handlers (not provided), add appropriate headers for endpoints returning sensitive data:
1. Implement an `after_request` handler to add `Cache-Control: no-store, no-cache, must-revalidate, private` headers
2. Add `Pragma: no-cache` and `Expires: 0` headers for paths like `/election/` and `/vote/`
3. Apply these headers specifically to endpoints serving voter PII and election metadata

Example implementation:
```python
@app.after_request
async def add_cache_headers(response):
    if request.path.startswith(('/election/', '/vote/')):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response
```

### Acceptance Criteria
- [ ] Cache-Control headers implemented for sensitive endpoints
- [ ] Test added to verify headers are present on sensitive responses
- [ ] Documentation updated with cache control policy

### References
- ASVS 14.2.2
- Source: 14.2.2.md

### Priority
Low

---

## Issue: FINDING-242 - No programmatic enforcement of database file permissions
**Labels:** bug, security, priority:low
**Description:**
### Summary
The domain context states 'database file permissions restrict access to the application user only' but there is no verification of file permissions when the database is opened. If the database file is created with overly permissive modes (e.g., 0644 instead of 0600), sensitive data including encrypted votes and cryptographic salts would be accessible to other system users.

### Details
The `open_database()` function does not check or enforce database file permissions. This creates a risk where:
- Database files could be created with world-readable permissions
- Sensitive data (encrypted votes, cryptographic salts, voter PII) would be accessible to unauthorized system users
- No runtime validation ensures the security posture matches documentation

**Affected Files:**
- `v3/steve/election.py:38`

**CWE:** None specified
**ASVS:** 14.2.4 (L2)

### Remediation
Check and enforce database file permissions in `open_database()`:

```python
import os
import stat

def open_database(db_path):
    # For existing files, verify permissions
    if os.path.exists(db_path):
        current_mode = os.stat(db_path).st_mode
        if current_mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH):
            raise SecurityError(f"Database file {db_path} has insecure permissions")
    
    # Open database
    conn = sqlite3.connect(db_path)
    
    # Set secure permissions on newly created files
    if os.path.exists(db_path):
        os.chmod(db_path, 0o600)
    
    return conn
```

### Acceptance Criteria
- [ ] Permission validation added to `open_database()`
- [ ] Newly created database files set to mode 0600
- [ ] Test added to verify permission enforcement
- [ ] Error raised for existing files with insecure permissions

### References
- ASVS 14.2.4
- Source: 14.2.4.md

### Priority
Low

---

## Issue: FINDING-243 - tally_issue returns full set of voter PIDs alongside tally results
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `tally_issue()` method returns the full set of voter PIDs (identities of who voted) alongside tally results. While knowing *who* voted (not *how*) may be legitimate for participation tracking, returning a full identity set to the caller provides more data than may be needed for simply displaying results and could reveal voting participation patterns if exposed to unauthorized users.

### Details
The method returns both tally results and the complete set of voter PIDs. While votes remain anonymous (shuffled and unlinkable to specific PIDs), the full voter identity list may be excessive for display purposes. This could enable:
- Voting participation pattern analysis
- Identification of non-voters through absence
- Unnecessary data exposure if web layer authorization is insufficient

**Affected Files:**
- `v3/steve/election.py:280-320`

**CWE:** None specified
**ASVS:** 14.2.6 (L3)

### Remediation
Implement two separate methods to support different use cases:

```python
def tally_issue(self, iid):
    """Return tally results with voter count only (for display)"""
    issue, votes, voters = self._all_votes(iid)
    return {
        'tally': m.tally(votes, self.json2kv(issue.kv)),
        'voter_count': len(voters)
    }

def tally_issue_with_voters(self, iid, requesting_uid):
    """Return tally results with full voter list (for authorized audit only)"""
    # Verify requesting_uid has audit permissions
    if not self._has_audit_permission(requesting_uid):
        raise PermissionError("Audit access required")
    
    issue, votes, voters = self._all_votes(iid)
    return {
        'tally': m.tally(votes, self.json2kv(issue.kv)),
        'voters': voters
    }
```

### Acceptance Criteria
- [ ] Separate methods implemented for display vs audit access
- [ ] Authorization check added for voter list access
- [ ] Web layer updated to use appropriate method
- [ ] Tests added for both access patterns

### References
- ASVS 14.2.6
- Source: 14.2.6.md

### Priority
Low

---

## Issue: FINDING-244 - Token Handling Cannot Be Fully Verified Without asfquart Library Inspection
**Labels:** bug, security, priority:low
**Description:**
### Summary
The OAuth authorization code flow is configured with server-side token exchange, which is the correct pattern. However, without visibility into the `asfquart` library's token handling, full compliance with ASVS 10.1.1 cannot be confirmed. Specifically, it's unclear whether access/refresh tokens are ever sent to the browser via cookies or response bodies, or whether the session cookie contains tokens or only a session identifier.

### Details
The architectural pattern appears correct based on available code:
- Authorization code flow is used
- `OAUTH_URL_CALLBACK` URL format suggests server-side exchange
- However, verification gaps exist:
  1. The `asfquart` library's token handling is not visible
  2. Whether access/refresh tokens are sent to browser cannot be confirmed
  3. Whether session cookie contains tokens or only session ID is unclear

**Affected Files:**
- `v3/server/main.py:40-43`

**CWE:** None specified
**ASVS:** 10.1.1 (L2)

### Remediation
Verify token confinement in `asfquart` library:

1. **Audit asfquart token handling:**
   - Confirm session cookie contains only session identifier
   - Verify access/refresh tokens are stored server-side only
   - Ensure no tokens are transmitted to browser in any form

2. **Document findings:**
   ```python
   # Add configuration documentation
   # Token Storage: All OAuth tokens (access, refresh) are stored server-side
   # Session Cookie: Contains only session identifier, no embedded tokens
   # Token Exchange: Performed entirely server-side via asfquart framework
   ```

3. **Add runtime verification (if possible):**
   ```python
   @app.after_request
   async def verify_no_token_leakage(response):
       # Verify no OAuth tokens in response
       if 'access_token' in response.get_data(as_text=True):
           logger.error("SECURITY: Access token detected in response body")
       return response
   ```

### Acceptance Criteria
- [ ] asfquart library token handling audited and documented
- [ ] Confirmation that session cookie contains only session ID
- [ ] Verification that tokens are never sent to browser
- [ ] Documentation added to security architecture

### References
- ASVS 10.1.1
- Source: 10.1.1.md

### Priority
Low

---

## Issue: FINDING-245 - Missing nonce Parameter for OpenID Connect
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The authentication request URL template includes `state` and `redirect_uri` parameters but does NOT include a `nonce` parameter. Per OIDC Core Section 3.1.2.1, the nonce parameter should be included in authentication requests and validated in the returned ID token to mitigate replay attacks. The comment `# Avoid OIDC` indicates the application is intentionally bypassing OIDC standard protections.

### Details
Without nonce binding, an attacker who captures an ID token could replay it:
1. Attacker captures ID token (e.g., from browser history, logs, or XSS)
2. Attacker presents captured token to application
3. Application accepts it as valid (no nonce to tie token to specific request)
4. Attacker gains unauthorized access using victim's identity

The application intentionally avoids OIDC, meaning OIDC-standard protections like nonce validation are not implemented.

**Affected Files:**
- `v3/server/main.py:39-42`

**CWE:** None specified
**ASVS:** 10.1.2, 10.5.1 (L2)

### Remediation
Implement nonce parameter for OIDC compliance:

```python
import secrets

# In authorization request handler
nonce = secrets.token_urlsafe(32)
session['oauth_nonce'] = nonce

OAUTH_URL_INIT = (
    'https://oauth.apache.org/auth'
    f'?state=%s&redirect_uri=%s&nonce={nonce}'
)

# In token validation callback
@app.route('/oauth/callback')
async def oauth_callback():
    # ... existing code ...
    
    # Validate nonce
    expected_nonce = session.get('oauth_nonce')
    if not expected_nonce:
        raise SecurityError("Missing nonce in session")
    
    received_nonce = id_token_claims.get('nonce')
    if received_nonce != expected_nonce:
        raise SecurityError("Nonce mismatch - potential replay attack")
    
    # Delete nonce after single use
    del session['oauth_nonce']
    
    # ... continue with authentication ...
```

### Acceptance Criteria
- [ ] Nonce generation implemented with cryptographically secure random
- [ ] Nonce stored in session for validation
- [ ] Nonce included in authorization request URL
- [ ] Nonce validation added to callback handler
- [ ] Nonce deleted after single use
- [ ] Tests added for nonce validation and mismatch scenarios

### References
- ASVS 10.1.2, 10.5.1
- OIDC Core Section 3.1.2.1
- Source: 10.1.2.md, 10.5.1.md

### Priority
Low (Medium if ID tokens are actually used)

---

## Issue: FINDING-246 - OAuth authorization URL does not include explicit scope parameter
**Labels:** bug, security, priority:low
**Description:**
### Summary
The OAuth authorization URL template does not include a `scope` parameter. This means either default scopes are applied (potentially broader than needed), the `asfquart` framework appends scopes elsewhere, or the ASF OAuth system doesn't use scopes. If the authorization server grants broader permissions than necessary by default, any token theft would grant the attacker more access than the application requires, violating the principle of least privilege.

### Details
Based on the application's session usage (`basic_info()` reads `uid`, `fullname`, `email`), the application only needs identity information. Without explicit scope restriction:
- Authorization server may grant default scopes broader than needed
- Token theft would provide attacker with unnecessary permissions
- No explicit mapping between OAuth scopes and application permissions
- Violates principle of least privilege

**Affected Files:**
- `v3/server/main.py:40`

**CWE:** None specified
**ASVS:** 10.2.3 (L3), 10.4.11 (L2)

### Remediation
Add explicit scope parameter to OAuth authorization URL:

```python
# In main.py OAuth configuration
asfquart.generics.OAUTH_URL_INIT = (
    'https://oauth.apache.org/auth'
    '?state=%s'
    '&redirect_uri=%s'
    '&scope=openid+profile+email'  # Request only needed scopes
)

# Or if ASF OAuth uses custom scopes:
asfquart.generics.OAUTH_URL_INIT = (
    'https://oauth.apache.org/auth'
    '?state=%s'
    '&redirect_uri=%s'
    '&scope=asf:identity'  # Minimal scope for identity only
)
```

Document scope-to-permission mapping:
```python
# OAuth Scope Mapping
# --------------------
# openid: Required for authentication
# profile: Provides uid, fullname
# email: Provides email address
# 
# Application does NOT require:
# - Write access to ASF services
# - Access to other user data
# - Administrative permissions
```

### Acceptance Criteria
- [ ] Explicit scope parameter added to authorization URL
- [ ] Scope limited to minimum required (identity information only)
- [ ] Scope-to-permission mapping documented
- [ ] Verification that authorization server respects scope restriction
- [ ] Tests added to verify scope is included in requests

### References
- ASVS 10.2.3, 10.4.11
- Source: 10.2.3.md, 10.4.11.md

### Priority
Low

---

## Issue: FINDING-247 - OAuth scope to application permission mapping not explicit
**Labels:** bug, security, priority:low
**Description:**
### Summary
The application uses role-based access control (R.committer, R.pmc_member) but these roles appear to be derived from session/token data, not from OAuth scopes. The mapping between OAuth scopes and application-level permissions is not explicit in the provided code. If the authorization server grants overly broad scopes, the application's internal RBAC may be the only control preventing scope abuse.

### Details
Current implementation:
- Application has internal RBAC (R.committer, R.pmc_member)
- Roles derived from session/token data
- No explicit mapping from OAuth scopes to application permissions
- Authorization server scope grants not validated against application needs

Defense-in-depth principle suggests scopes should be constrained at both:
1. OAuth authorization server level
2. Application permission enforcement level

**Affected Files:**
- `v3/server/pages.py` (multiple locations)

**CWE:** None specified
**ASVS:** 10.4.11 (L2)

### Remediation
Document and enforce explicit scope-to-permission mapping:

```python
# In configuration or documentation
OAUTH_SCOPE_MAPPING = {
    'openid': 'authenticated_user',
    'profile': 'basic_profile_access',
    'email': 'email_access',
    'asf:committer': 'R.committer',
    'asf:pmc': 'R.pmc_member',
}

# Add scope validation in session establishment
async def validate_token_scopes(token_scopes, required_permission):
    """Validate that token scopes support required permission"""
    allowed_permissions = set()
    for scope in token_scopes:
        if scope in OAUTH_SCOPE_MAPPING:
            allowed_permissions.add(OAUTH_SCOPE_MAPPING[scope])
    
    if required_permission not in allowed_permissions:
        raise PermissionError(
            f"Token scopes {token_scopes} do not grant {required_permission}"
        )
```

Add documentation:
```markdown
# OAuth Scope to Permission Mapping

## Scope Requirements by Role
- **Voter**: openid, profile, email
- **Committer** (R.committer): openid, profile, email, asf:committer
- **PMC Member** (R.pmc_member): openid, profile, email, asf:pmc

## Enforcement
1. Authorization server grants scopes based on user's ASF status
2. Application validates scopes during session establishment
3. Application RBAC provides secondary enforcement layer
```

### Acceptance Criteria
- [ ] Scope-to-permission mapping documented
- [ ] Scope validation added during session establishment
- [ ] Authorization server scope configuration verified
- [ ] Tests added for scope validation
- [ ] Documentation updated with scope requirements

### References
- ASVS 10.4.11
- Source: 10.4.11.md

### Priority
Low

---

## Issue: FINDING-248 - Token Audience Validation Not Verifiable in OAuth Callback
**Labels:** bug, security, priority:low
**Description:**
### Summary
The application does not appear to function as a traditional OAuth resource server that accepts bearer tokens. Instead, it uses session-based authentication established through an OAuth login flow. However, the initial token received from the authorization server during the OAuth callback should ideally have its audience validated by the `asfquart` framework before establishing the session. If the `asfquart` framework does not validate the audience, a token intended for a different ASF application could potentially be used to establish a session (token confusion attack).

### Details
Current architecture:
- Application uses session-based authentication (not bearer tokens)
- Protected endpoints use `@asfquart.auth.require` decorators (check session, not tokens)
- OAuth callback receives token and establishes session
- Audience validation during callback not visible in provided code

Risk: Token intended for different ASF application could establish session in this application if audience is not validated.

**Affected Files:**
- `v3/server/pages.py` (multiple endpoints)

**CWE:** None specified
**ASVS:** 10.3.1 (L2)

### Remediation
Verify and document audience validation in OAuth callback:

1. **Audit asfquart framework:**
   - Confirm `aud` claim validation occurs during token processing
   - Verify expected audience value matches this application's identifier

2. **Add explicit validation if not present:**
```python
# In OAuth callback handler (or asfquart configuration)
EXPECTED_AUDIENCE = 'steve.apache.org'  # This application's identifier

async def validate_oauth_callback(token):
    """Validate token before establishing session"""
    # Decode token (asfquart should do this)
    claims = decode_token(token)
    
    # Validate audience
    token_audience = claims.get('aud')
    if token_audience != EXPECTED_AUDIENCE:
        raise SecurityError(
            f"Token audience mismatch: expected {EXPECTED_AUDIENCE}, "
            f"got {token_audience}"
        )
    
    # Continue with session establishment
    return claims
```

3. **Document audience validation:**
```python
# OAuth Token Audience Validation
# --------------------------------
# Expected audience: steve.apache.org
# Validated by: asfquart framework during callback processing
# Prevents: Token confusion attacks from other ASF applications
```

### Acceptance Criteria
- [ ] Audience validation confirmed in asfquart framework
- [ ] Expected audience value documented
- [ ] Explicit validation added if not present in framework
- [ ] Tests added for audience mismatch scenarios
- [ ] Documentation updated with validation approach

### References
- ASVS 10.3.1
- Source: 10.3.1.md

### Priority
Low

---

## Issue: FINDING-249 - Cannot verify redirect URI validation with exact string comparison on external authorization server
**Labels:** bug, security, priority:low
**Description:**
### Summary
The application delegates authorization to `oauth.apache.org`, which is responsible for validating redirect URIs. From the client perspective, the `redirect_uri` is passed as `%s` in the template URL, with the actual value determined by the `asfquart` framework. Without verification of the authorization server's validation and the framework's URI construction, we cannot confirm protection against redirect URI manipulation attacks.

### Details
Verification gaps:
1. Whether authorization server validates redirect URIs with exact string matching (not wildcards)
2. What redirect URI value the `asfquart` framework substitutes
3. Whether client's registered redirect URIs are restricted to specific paths
4. Whether `asfquart` dynamically constructs redirect_uri from request Host header (open redirect risk)

If authorization server doesn't perform exact string comparison, attacker could redirect authorization response to malicious endpoint. If `asfquart` constructs URI from Host header, Host header injection could enable open redirect.

**Affected Files:**
- `v3/server/main.py:39-42`

**CWE:** None specified
**ASVS:** 10.4.1 (L1)

### Remediation
Explicitly set fixed redirect URI and verify server-side validation:

```python
# In create_app()
FIXED_REDIRECT_URI = 'https://steve.apache.org/oauth/callback'

asfquart.generics.OAUTH_URL_INIT = (
    'https://oauth.apache.org/auth'
    f'?state=%s&redirect_uri={FIXED_REDIRECT_URI}'
)

# Verify in callback that received redirect_uri matches expected
@app.route('/oauth/callback')
async def oauth_callback():
    received_redirect = request.args.get('redirect_uri')
    if received_redirect and received_redirect != FIXED_REDIRECT_URI:
        raise SecurityError("Redirect URI mismatch")
    # ... continue with callback processing ...
```

Verification checklist for ASF OAuth team:
- [ ] Redirect URIs validated with exact string comparison (no wildcards)
- [ ] No pattern matching or regex used for redirect URI validation
- [ ] Client registration includes only specific callback URL
- [ ] Multiple redirect URIs not allowed for this client
- [ ] Redirect URI cannot be overridden at request time

### Acceptance Criteria
- [ ] Fixed redirect URI configured in application
- [ ] No dynamic construction from request headers
- [ ] ASF OAuth server validation confirmed with OAuth team
- [ ] Documentation updated with redirect URI security
- [ ] Tests added for redirect URI validation

### References
- ASVS 10.4.1
- Source: 10.4.1.md

### Priority
Low

---

## Issue: FINDING-250 - response_mode parameter not explicitly specified in authorization request
**Labels:** bug, security, priority:low
**Description:**
### Summary
The authorization request does not specify a `response_mode` parameter. The default for authorization code flow is `query` (code returned as query parameter), which is acceptable for this server-side confidential client. However, if the authorization server allows the client to use `response_mode=fragment`, an attacker could craft requests that deliver the code via the fragment, which would not be sent to the server and could be intercepted by client-side scripts.

### Details
Current state:
- No `response_mode` parameter specified
- Default is `response_mode=query` (acceptable for server-side client)
- Authorization server configuration unknown

Risk: If authorization server allows `response_mode=fragment`:
- Attacker could craft authorization requests with fragment mode
- Authorization code delivered via URL fragment
- Fragment not sent to server (client-side only)
- Client-side scripts could intercept code

**Affected Files:**
- `v3/server/main.py:39`

**CWE:** None specified
**ASVS:** 10.4.12 (L3)

### Remediation
Explicitly specify `response_mode=query` to make intent clear:

```python
# In main.py OAuth configuration
asfquart.generics.OAUTH_URL_INIT = (
    'https://oauth.apache.org/auth'
    '?state=%s'
    '&redirect_uri=%s'
    '&response_mode=query'  # Explicit server-side code delivery
)
```

Verify with ASF OAuth team:
- [ ] Authorization server rejects `response_mode=fragment` for this client
- [ ] Only `response_mode=query` is allowed
- [ ] Client cannot override response_mode at request time

Add validation in callback:
```python
@app.route('/oauth/callback')
async def oauth_callback():
    # Code must be in query parameters, not fragment
    code = request.args.get('code')
    if not code:
        raise SecurityError("Authorization code not received in query parameters")
    # ... continue processing ...
```

### Acceptance Criteria
- [ ] response_mode=query explicitly specified
- [ ] ASF OAuth server configuration verified
- [ ] Callback validation added for code in query params
- [ ] Documentation updated with response_mode security
- [ ] Tests added for response_mode validation

### References
- ASVS 10.4.12
- Source: 10.4.12.md

### Priority
Low

---

## Issue: FINDING-251 - Authorization Code Lifetime and One-Time Use Cannot Be Verified from Client Code
**Labels:** bug, security, priority:low
**Description:**
### Summary
Authorization code lifetime and one-time use enforcement are entirely controlled by the external authorization server (`oauth.apache.org`). From the client perspective, the application correctly exchanges codes immediately, but we cannot verify that the authorization server enforces: (1) single-use codes, (2) maximum lifetime of 10 minutes (L1/L2) or 1 minute (L3). Without these server-side controls, the window for code interception and replay attacks increases.

### Details
Client-side behavior (appropriate):
- Application receives authorization code in callback
- Code immediately exchanged via token endpoint
- No client-side code storage or delayed use
- `asfquart` framework processes callback in same request flow

Server-side requirements (unverified):
- Codes must be single-use (revoke tokens if reused)
- Codes must expire within 10 minutes (L1/L2) or 1 minute (L3)
- Authorization server must enforce these constraints

**Affected Files:**
- `v3/server/main.py:42`

**CWE:** None specified
**ASVS:** 10.4.2, 10.4.3 (L1)

### Remediation
1. **Verify with ASF OAuth team:**
   - [ ] Authorization server enforces single-use codes
   - [ ] Tokens revoked if code is reused
   - [ ] Code lifetime ≤ 10 minutes (L1/L2) or ≤ 1 minute (L3)
   - [ ] Code cannot be replayed after first use

2. **Ensure asfquart doesn't cache/retry:**
```python
# Verify in asfquart configuration or callback handler
# that code exchange is never retried
async def exchange_code_once(code):
    """Exchange authorization code exactly once"""
    if hasattr(exchange_code_once, '_used_codes'):
        if code in exchange_code_once._used_codes:
            raise SecurityError("Code already exchanged (client-side detection)")
    else:
        exchange_code_once._used_codes = set()
    
    # Exchange code
    tokens = await oauth_client.exchange_code(code)
    
    # Mark as used
    exchange_code_once._used_codes.add(code)
    
    return tokens
```

3. **Consider implementing PKCE (RFC 7636):**
```python
import secrets
import hashlib
import base64

# In authorization request
code_verifier = secrets.token_urlsafe(32)
session['pkce_verifier'] = code_verifier

code_challenge = base64.urlsafe_b64encode(
    hashlib.sha256(code_verifier.encode()).digest()
).decode().rstrip('=')

auth_url = (
    f'https://oauth.apache.org/auth'
    f'?state={state}'
    f'&redirect_uri={redirect_uri}'
    f'&code_challenge={code_challenge}'
    f'&code_challenge_method=S256'
)

# In callback
code_verifier = session.pop('pkce_verifier')
# Include code_verifier in token exchange
```

### Acceptance Criteria
- [ ] Authorization server code lifetime and reuse policy verified
- [ ] asfquart framework code exchange behavior confirmed
- [ ] PKCE implementation considered/implemented
- [ ] Documentation updated with code security measures
- [ ] No client-side code caching or retry logic

### References
- ASVS 10.4.2, 10.4.3
- RFC 7636 (PKCE)
- Source: 10.4.2.md, 10.4.3.md

### Priority
Low

---

## Issue: FINDING-252 - No user-facing interface for revoking OAuth tokens or active sessions
**Labels:** bug, security, priority:low
**Description:**
### Summary
The application provides no user-facing interface for revoking OAuth tokens or active sessions. While `/profile` and `/settings` pages exist, neither offers session/token revocation capabilities. If a user's session or tokens are compromised, they have no way to revoke those tokens through the application's interface and must go directly to `oauth.apache.org`.

### Details
Current state:
- `/profile` and `/settings` pages exist
- No session management or revocation UI
- No "sign out of all sessions" capability
- No link to IdP's token management interface

Impact:
- Users cannot revoke compromised tokens via application
- No visibility into active sessions
- No emergency session termination capability
- Must use external IdP interface for token management

**Affected Files:**
- `v3/server/pages.py` (Application-wide)

**CWE:** CWE-613 (Insufficient Session Expiration)
**ASVS:** 10.4.9 (L2)

### Remediation
Add session management page with revocation capabilities:

```python
@APP.route('/account/sessions')
@asfquart.auth.require
async def session_management_page(result):
    """Display active sessions and provide revocation"""
    uid = result.uid
    
    # Get active sessions (implementation depends on session storage)
    active_sessions = await get_user_sessions(uid)
    
    return await render_template(
        'sessions.ezt',
        sessions=active_sessions,
        current_session_id=session.get('session_id')
    )

@APP.route('/account/sessions/revoke-all', methods=['POST'])
@asfquart.auth.require
async def revoke_all_sessions(result):
    """Revoke all sessions for current user"""
    uid = result.uid
    current_session_id = session.get('session_id')
    
    # Invalidate all sessions except current
    await invalidate_user_sessions(uid, except_session=current_session_id)
    
    # Optionally call ASF OAuth revocation endpoint
    if ASF_OAUTH_REVOCATION_ENDPOINT:
        await revoke_oauth_tokens(uid)
    
    await flash_success('All other sessions have been revoked')
    return quart.redirect('/account/sessions', code=303)
```

Add to settings page:
```html
<!-- In settings.ezt or profile.ezt -->
<div class="session-management">
    <h3>Active Sessions</h3>
    <p>Manage your active login sessions</p>
    <a href="/account/sessions" class="btn">View Sessions</a>
    <form action="/account/sessions/revoke-all" method="post">
        <button type="submit" class="btn btn-danger">
            Sign Out All Other Sessions
        </button>
    </form>
</div>
```

### Acceptance Criteria
- [ ] Session management page created
- [ ] List of active sessions displayed
- [ ] "Revoke all sessions" action implemented
- [ ] Link to IdP token management provided
- [ ] Current session excluded from bulk revocation
- [ ] Tests added for session revocation
- [ ] Documentation updated with session management

### References
- ASVS 10.4.9
- CWE-613
- Source: 10.4.9.md

### Priority
Low

---

## Issue: FINDING-253 - User identification may not explicitly map to OIDC sub claim
**Labels:** bug, security, priority:low
**Description:**
### Summary
The application identifies users via `s['uid']` from the session, which is the ASF username (Apache ID) mapping to LDAP 'uid' attribute. While this uses a stable identifier, it's not clear whether this maps to the OIDC 'sub' claim specifically. The comment "Avoid OIDC" suggests the application may be receiving a custom user identifier that may not have the same non-reassignment guarantees as an OIDC 'sub' claim.

### Details
Current implementation:
- User identified by `s['uid']` (ASF username/Apache ID)
- Maps to LDAP 'uid' attribute
- Used consistently for all authorization decisions
- Comment "Avoid OIDC" suggests custom OAuth flow

Risk: If ASF ever changes OAuth to return reassignable identifiers, application would not detect the difference.

Mitigation: ASF UIDs are non-reassignable by ASF policy, so this is low severity.

**Affected Files:**
- `v3/server/pages.py:82-91`

**CWE:** CWE-287 (Improper Authentication)
**ASVS:** 10.5.2 (L2)

**Related:** FINDING-255

### Remediation
Explicitly document user identification strategy and add issuer scoping:

```python
async def basic_info():
    """Get basic user information from session
    
    User Identification:
    - Users identified by ASF UID (Apache ID)
    - Equivalent to OIDC 'sub' claim
    - ASF UIDs are non-reassignable per ASF policy
    - Scoped to issuer 'https://oauth.apache.org'
    """
    basic = {}
    s = await asfquart.session.read()
    if s:
        basic.update(
            uid=s['uid'],  # Non-reassignable ASF username
            issuer='https://oauth.apache.org',  # Explicit issuer scoping
            name=s['fullname'],
            email=s['email']
        )
    return basic

# Add validation in session establishment
async def validate_user_identifier(uid, issuer):
    """Validate that user identifier is stable and non-reassignable"""
    if issuer != 'https://oauth.apache.org':
        raise SecurityError(f"Unexpected issuer: {issuer}")
    
    # ASF UIDs are non-reassignable by policy
    # Document this assumption explicitly
    logger.info(f"User authenticated: {uid}@{issuer}")
```

Add configuration documentation:
```python
# User Identification Policy
# ---------------------------
# Identifier: ASF UID (Apache ID)
# Source: LDAP 'uid' attribute via ASF OAuth
# Issuer: https://oauth.apache.org
# Reassignment: Not allowed per ASF policy
# Equivalent to: OIDC 'sub' claim
#
# If ASF OAuth changes to provide OIDC 'sub' claim,
# update to use 'sub' instead of 'uid'
```

### Acceptance Criteria
- [ ] User identification strategy documented
- [ ] Issuer scoping added to user identity
- [ ] Validation added for expected issuer
- [ ] ASF UID non-reassignment policy documented
- [ ] Tests added for issuer validation
- [ ] Documentation updated with identification approach

### References
- ASVS 10.5.2
- CWE-287
- Source: 10.5.2.md
- Related: FINDING-255

### Priority
Low

---

## Issue: FINDING-254 - No Documented Fallback for Missing Authentication Strength Information
**Labels:** bug, security, priority:low
**Description:**
### Summary
No documented fallback approach exists for when the IdP doesn't provide authentication strength information. Per ASVS 6.8.4, if the IdP does not provide this information, the application must have a documented fallback approach that assumes the minimum strength authentication mechanism was used. The '### need general solution' comments on auth decorators suggest this is a known gap.

### Details
Current state:
- No authentication strength (acr/amr) claims validated
- No documentation of fallback approach
- Comments indicate awareness of gap: "### need general solution"
- No clear security posture regarding authentication strength

Without documented fallback:
- Unclear what authentication strength is assumed
- No basis for risk assessment
- Cannot verify appropriate controls for authentication level

**Affected Files:**
- `v3/server/pages.py`

**CWE:** CWE-1008 (Architectural Security Tactic)
**ASVS:** 6.8.4 (L2)

### Remediation
Create explicit documentation and implement fallback policy:

```python
# Authentication Strength Policy
# -------------------------------
# ASF OAuth does not provide acr (Authentication Context Class Reference)
# or amr (Authentication Methods Reference) claims.
#
# Fallback Assumption:
# - Minimum authentication strength: Single-factor (password only)
# - No MFA guarantee unless explicitly verified through other means
#
# Risk Acceptance:
# - Application assumes single-factor authentication for all users
# - Higher-risk operations should implement additional verification
# - Consider requiring step-up authentication for sensitive operations

# Configuration
ASSUMED_AUTH_STRENGTH = 'single-factor'
REQUIRES_MFA_OPERATIONS = [
    'close_election',
    'delete_election',
    'modify_voter_eligibility'
]

async def validate_auth_strength(operation):
    """Validate authentication strength for operation"""
    s = await asfquart.session.read()
    
    # Check if IdP provided authentication strength
    auth_strength = s.get('acr') or s.get('amr')
    
    if not auth_strength:
        # Fallback: assume minimum strength
        auth_strength = ASSUMED_AUTH_STRENGTH
        logger.warning(
            f"No authentication strength provided by IdP, "
            f"assuming {ASSUMED_AUTH_STRENGTH}"
        )
    
    # Check if operation requires higher strength
    if operation in REQUIRES_MFA_OPERATIONS:
        if auth_strength == 'single-factor':
            raise SecurityError(
                f"Operation {operation} requires multi-factor authentication. "
                f"Please re-authenticate with MFA."
            )
    
    return auth_strength
```

Add to security documentation:
```markdown
# Authentication Strength

## Current State
- ASF OAuth does not provide authentication strength claims (acr/amr)
- Application cannot verify if user authenticated with MFA

## Fallback Policy
- **Assumption**: All authentications are single-factor (password only)
- **Rationale**: Without acr/amr claims, cannot verify MFA usage
- **Risk**: Higher-risk operations may be performed with only password authentication

## Mitigation
- Document operations that should require MFA
- Consider implementing step-up authentication for sensitive operations
- Request ASF OAuth team add acr/amr claims to tokens
```

### Acceptance Criteria
- [ ] Authentication strength fallback policy documented
- [ ] Assumption of minimum strength clearly stated
- [ ] High-risk operations identified
- [ ] Consider step-up authentication for sensitive operations
- [ ] Documentation added to security architecture
- [ ] Request acr/amr claims from ASF OAuth team

### References
- ASVS 6.8.4
- CWE-1008
- Source: 6.8.4.md

### Priority
Low

---

## Issue: FINDING-255 - Potential Multi-IdP Identity Spoofing Risk if Additional IdPs Added
**Labels:** bug, security, priority:low
**Description:**
### Summary
The application uses a single IdP (ASF OAuth at https://oauth.apache.org/), so multi-IdP identity spoofing doesn't currently apply. The `uid` from session is used consistently as the user identifier. However, if additional IdPs were added in the future without namespacing user IDs (e.g., prefixing with IdP identifier), this would become a critical vulnerability.

### Details
Current architecture (secure):
- Single IdP configured (ASF OAuth)
- `uid` used consistently across all operations
- No cross-IdP spoofing risk by design

Future risk if multiple IdPs added:
- User "alice" from IdP A could be confused with "alice" from IdP B
- Without namespacing, authorization decisions could grant wrong user's permissions
- Critical vulnerability if IdPs are added without identity scoping

**Affected Files:**
- `v3/server/pages.py:86-95`
- `v3/server/main.py:40-43`

**CWE:** CWE-287 (Improper Authentication)
**ASVS:** 6.8.1 (L2)

**Related:** FINDING-253

### Remediation
Document current single-IdP architecture and add safeguards for future:

```python
# Identity Scoping Policy
# -----------------------
# Current: Single IdP (https://oauth.apache.org)
# User identifier: ASF UID (non-namespaced)
#
# IMPORTANT: If additional IdPs are added, MUST implement
# namespaced identifiers to prevent identity spoofing

# Configuration
ALLOWED_IDPS = {
    'https://oauth.apache.org': {
        'name': 'ASF OAuth',
        'uid_prefix': 'asf-oauth',
        'enabled': True
    }
    # Future IdPs must be added here with unique prefixes
}

def get_namespaced_uid(uid, issuer):
    """Get namespaced user identifier to prevent cross-IdP spoofing"""
    if issuer not in ALLOWED_IDPS:
        raise SecurityError(f"Unknown issuer: {issuer}")
    
    idp_config = ALLOWED_IDPS[issuer]
    if not idp_config['enabled']:
        raise SecurityError(f"IdP disabled: {issuer}")
    
    # Namespace the UID with IdP prefix
    prefix = idp_config['uid_prefix']
    namespaced_uid = f"{prefix}:{uid}"
    
    logger.info(f"Namespaced identity: {namespaced_uid}")
    return namespaced_uid

async def basic_info():
    """Get basic user information with namespaced identity"""
    basic = {}
    s = await asfquart.session.read()
    if s:
        issuer = s.get('issuer', 'https://oauth.apache.org')
        uid = s['uid']
        
        # Get namespaced UID for future multi-IdP support
        namespaced_uid = get_namespaced_uid(uid, issuer)
        
        basic.update(
            uid=namespaced_uid,  # Namespaced to prevent spoofing
            raw_uid=uid,  # Keep original for backward compatibility
            issuer=issuer,
            name=s['fullname'],
            email=s['email']
        )
    return basic
```

Add migration guide for multi-IdP:
```markdown
# Multi-IdP Migration Guide

## Current State
- Single IdP: ASF OAuth (https://oauth.apache.org)
- User IDs: Non-namespaced ASF UIDs

## Before Adding Additional IdPs

1. **Implement Namespaced Identifiers**
   - Format: `{idp-prefix}:{uid}`
   - Example: `asf-oauth:alice`, `github:alice`

2. **Update Database Schema**
   - Add `issuer` column to user-related tables
   - Migrate existing UIDs to namespaced format
   - Add unique constraint on (uid, issuer)

3. **Update Authorization Logic**
   - Use namespaced UIDs in all authorization checks
   - Validate issuer in all identity comparisons

4. **Test Cross-IdP Scenarios**
   - Verify users with same UID from different IdPs are distinct
   - Ensure authorization decisions respect IdP boundaries
```

### Acceptance Criteria
- [ ] Single-IdP architecture documented
- [ ] Namespacing strategy designed for future multi-IdP
- [ ] Safeguards added to prevent accidental multi-IdP without namespacing
- [ ] Migration guide created for multi-IdP scenarios
- [ ] Tests added for identity namespacing logic
- [ ] Documentation updated with IdP identity policy

### References
- ASVS 6.8.1
- CWE-287
- Source: 6.8.1.md
- Related: FINDING-253

### Priority
Low

---

*Continuing with remaining findings in next response...*

---

## Issue: FINDING-256 - Self-disclosure of PersonDB synchronization status

**Labels:** bug, security, priority:low

**Description:**

The admin_page() function reveals whether an authenticated user's OAuth identity has been synchronized into the local PersonDB through a distinct error response ('Unknown Person'). While this only affects the currently authenticated user viewing their own status, it creates a distinguishable response pattern. The application delegates authentication entirely to ASF OAuth, so traditional login/registration/forgot-password enumeration vectors are not present. This finding is informational rather than exploitable for user enumeration since it only shows the user their own synchronization status.

**Remediation:** No immediate action required. The distinct error only reveals the user's own synchronization status to themselves. This is a self-disclosure pattern with minimal security impact.

**Priority:** Low

---

## Issue: FINDING-257 - Incomplete Data-Specific Access Rules Documentation

**Labels:** bug, security, priority:low

**Description:**

Data-specific access rules for election isolation are partially documented. The documentation explains that elections use unique EIDs and that mayvote restricts voting access, but does not explicitly document that access to one election's data must not grant access to another election's data, nor does it specify the complete set of data-specific restrictions. Missing is an explicit statement that election management operations are restricted to the specific election's owner_pid or authz group members, and that data from different elections is isolated.

**Remediation:** Add explicit data-level access documentation stating isolation requirements per election. Document that: (1) election management operations are restricted to the specific election's owner_pid or authz group members, (2) data from different elections is isolated (queries are scoped by EID), (3) access to one election's data does not grant access to another election's data, (4) the mayvote table enforces voter eligibility on a per-election, per-issue basis. Include this in a dedicated 'Data Isolation' section in schema.md.

**Priority:** Low

---

## Issue: FINDING-258 - No Real-Time Notification for Election State Changes

**Labels:** bug, security, priority:low

**Description:**

When an election is closed, any voter with the voting page already loaded can still submit their form, which will fail with a state error. The authorization change (election closed = no more voting) IS applied immediately in the database (add_vote checks self.S_OPEN), but there's no mitigating control to alert voters mid-session that the election state has changed. This is partially mitigated by _all_metadata(self.S_OPEN) in add_vote which validates state on every vote submission, ensuring closed elections immediately reject votes. However, the user experience is poor as voters may spend time filling out ballots only to have submission fail.

**Remediation:** Implement a real-time notification mechanism to alert active voters when election state changes occur. Options include: (1) WebSocket connection to push state change notifications to active voting pages, (2) periodic AJAX polling to check election state and display warning banner if state changed, (3) optimistic UI validation before form submission to check current state and warn user before they invest time in ballot completion. This improves user experience and prevents wasted effort on ballots that will be rejected due to state changes.

**Priority:** Low

---

## Issue: FINDING-259 - Session Identity Correctly Used - No Intermediary Permission Escalation

**Labels:** bug, security, priority:low

**Description:**

The application is a monolithic server with direct database access. There are no service-to-service calls, no intermediary services, and no token forwarding patterns. All operations use result.uid (from the authenticated session) directly. The application correctly uses the originating subject's identity for all permission decisions. No findings detected for this requirement in the current architecture. This is documented as a positive finding to confirm compliance with ASVS 8.3.3.

**Remediation:** No remediation required. The application correctly uses the originating subject's identity for all permission decisions. Continue to maintain direct identity propagation from session to data layer. If the architecture evolves to include service-to-service calls or intermediary services, ensure that the originating subject's identity is propagated and used for all authorization decisions rather than the intermediary's permissions.

**Priority:** Low

---

## Issue: FINDING-260 - Logout functionality nested in dropdown menu reduces visibility

**Labels:** bug, security, priority:low

**Description:**

The logout functionality exists but is nested within a dropdown menu that requires two clicks to access (click username dropdown, then click "Sign Out"). While this is a common UI pattern, it reduces visibility. The requirement states "easy and visible access" — a nested dropdown partially meets this but may fail strict interpretation. Users under session-hijacking attack may not quickly find the logout option.

**Remediation:** While the current implementation follows common web patterns (similar to GitHub, GitLab), consider adding a visible logout icon/button directly in the navbar for higher visibility. Add a dedicated logout link with an icon directly in the navbar navigation items for immediate visibility without requiring dropdown interaction.

**Priority:** Low

---

## Issue: FINDING-261 - No documentation of expected session lifetime behavior between RP and IdP

**Labels:** bug, security, priority:low

**Description:**

There is no documentation of the expected session lifetime behavior between this application (RP) and the ASF SSO provider (IdP). The login (/auth?login=/) and logout (/auth?logout=/) endpoints delegate to asfquart but session lifetime policies are not explicitly configured or documented in the application code. Without documented session behavior, it's impossible to verify correct implementation. Operations teams cannot validate that session termination at the IdP properly propagates to this application, and vice versa.

**Remediation:** Document and configure session behavior explicitly in application configuration. Define SESSION_LIFETIME (max session duration), IDP_REAUTH_INTERVAL (re-verify with IdP interval), IDLE_TIMEOUT, and document that logout at /auth?logout=/ terminates both RP session and IdP session (single logout). Example: APP.config.update(SESSION_LIFETIME=3600, IDP_REAUTH_INTERVAL=1800, IDLE_TIMEOUT=900).

**Priority:** Low

---

## Issue: FINDING-262 - No Session Creation Notification to User

**Labels:** bug, security, priority:low

**Description:**

After OAuth callback creates a new session, there is no mechanism to notify users or provide visibility into session creation events. Per ASVS 7.6.2's intent (derived from NIST 800-63C), users should be aware when sessions are created on their behalf. The data flow: OAuth callback completes successfully → New session created in asfquart framework → User redirected to protected page → No indication that new session was created → User may be unaware of active session state. Users lack awareness of when sessions are created, making it difficult to detect unauthorized session creation. This reduces user ability to identify potential security issues and does not align with the principle of informed consent for session establishment.

**Remediation:** Implement session creation notifications in the OAuth callback handler. After successful session creation, display a flash message indicating 'New session created. If you did not initiate login, please contact support.' Store session creation timestamp in session data. Add a session management page at /account/sessions that displays active sessions and creation timestamps, allowing users to view and manage their sessions.

**Priority:** Low

---

## Issue: FINDING-263 - Missing URL encoding in JavaScript form action construction

**Labels:** bug, security, priority:low

**Description:**

The issueId JavaScript variable (passed from server-rendered onclick attributes) is concatenated directly into a URL path without encoding in manage.ezt template. While IIDs are cryptographically generated and thus safe in practice, the pattern doesn't apply URL encoding to untrusted data used in URL construction. Impact is low because IIDs are server-generated alphanumeric values with no user control over their format.

**Remediation:** Apply encodeURIComponent to all URL path parameters: form.action = `/do-edit-issue/[eid]/${encodeURIComponent(issueId)}`;

**Priority:** Low

---

## Issue: FINDING-264 - Global window function assignments could be overridden via DOM clobbering

**Labels:** bug, security, priority:low

**Description:**

Multiple functions are assigned to the window object (openSTVModal, saveSTVRanking, clearSTVRanking, bulkVote, clearYNAVotes, toggleDescription, toggleAllDescriptions, submitVotes). If unescaped HTML content contains named elements like `<a id="submitVotes" href="https://evil.com">`, and JavaScript code later accesses `window.submitVotes` without type checking, the element reference could shadow the function. Impact is Low because modern browsers resolve `window.X` to function assignments over named elements when both exist. However, if the function assignment fails (e.g., due to a syntax error caused by XSS in `STV_CANDIDATES`), the named element would be accessible via `window.X`.

**Remediation:** Add type checking before invocation: `const submitFn = window.submitVotes; if (typeof submitFn !== 'function') { console.error('submitVotes has been overridden'); return; }`

**Priority:** Low

---

## Issue: FINDING-265 - JSON Endpoints Use Content-Type That Triggers Preflight But Lack Explicit CORS Policy

**Labels:** bug, security, priority:low

**Description:**

The client sends Content-Type: application/json (from manage.ezt line 251), which is non-safelisted and would trigger a CORS preflight. However, without explicit CORS configuration visible in the code, it is unclear whether the server properly rejects unauthorized origins during the OPTIONS preflight. If a permissive CORS policy were added in the future (e.g., Access-Control-Allow-Origin: *), these endpoints would become vulnerable. Protection is implicit rather than explicit.

**Remediation:** Add explicit CORS policy configuration that restricts allowed origins, and validate Content-Type server-side. Explicitly verify Content-Type is application/json and reject with 415 if not. Example: if quart.request.content_type != 'application/json': quart.abort(415, 'Content-Type must be application/json')

**Priority:** Low

---

## Issue: FINDING-266 - Unable to Verify Hostname Separation — Single Application Serves All Functionality

**Labels:** bug, security, priority:low

**Description:**

The application serves administrative functions (/admin, /manage), voter functions (/voter, /vote-on), static files (/static), and document files (/docs) all from the same application instance. There is no evidence of: separate hostnames for admin vs. voter functionality, separate origins for static content, or domain-based cookie scoping. The code uses a single APP instance with all routes registered in one file, suggesting a single-origin deployment. If a vulnerability (e.g., XSS) exists in one area of the application, it can access cookies and data from all other areas since they share the same origin. Administrative session cookies are accessible from voter-facing pages and vice versa.

**Remediation:** Consider separating administrative and voter functionality onto different subdomains: admin.steve.example.com — Election management, vote.steve.example.com — Voter interface, static.steve.example.com — Static assets (with restrictive CSP).

**Priority:** Low

---

## Issue: FINDING-267 - No Global X-Content-Type-Options: nosniff Header to Prevent Content-Type Sniffing

**Labels:** bug, security, priority:low

**Description:**

The application does not set the X-Content-Type-Options: nosniff header on any response. No after-request handler or middleware adds this header globally. Without this header, browsers may MIME-sniff responses and interpret non-JavaScript content as executable scripts, creating potential XSSI exploitation vectors for non-script responses. This is primarily a defense-in-depth gap since authenticated HTML pages won't parse as valid JavaScript, but it represents a missing security control that could prevent certain attack variants.

**Remediation:** Add a global after-request handler to set the X-Content-Type-Options: nosniff header on all responses:

@APP.after_request
async def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

**Priority:** Low

---

## Issue: FINDING-268 - No Cookie Size Validation Before Writing Cookies

**Labels:** bug, security, priority:low

**Description:**

The application does not explicitly validate that cookie name and value length combined do not exceed 4096 bytes before writing cookies. While unlikely in normal operation (flash messages are consumed on next page load and session data is minimal), a rapid sequence of operations or very long election titles in flash messages could theoretically push the cookie size near the limit. If cookie exceeds 4096 bytes, the browser silently drops the cookie and the user loses their session.

**Remediation:** Add middleware to check cookie size before sending:

@app.after_request
async def check_cookie_size(response):
    for header_name, header_value in response.headers:
        if header_name.lower() == 'set-cookie':
            cookie_content = header_value.split(';')[0]
            if len(cookie_content.encode('utf-8')) > 4096:
                _LOGGER.warning(f'Cookie exceeds 4096 bytes: {len(cookie_content)} bytes')
                # Handle gracefully - truncate flash messages or use server-side sessions
    return response

**Priority:** Low

---

## Issue: FINDING-269 - Encrypted Client Hello (ECH) Not Configured

**Labels:** bug, security, priority:low

**Description:**

No ECH (Encrypted Client Hello) configuration exists anywhere in the codebase. Without ECH, the Server Name Indication (SNI) field in the TLS ClientHello is transmitted in plaintext. This allows network observers (ISPs, network administrators, or attackers performing passive surveillance) to determine which hostname the client is connecting to, even though the payload is encrypted. This is a metadata privacy issue. ECH is a TLS 1.3 extension (RFC 9578, formerly ESNI) that is still relatively new and requires DNS infrastructure support (HTTPS/SVCB DNS records with ECH configuration), server-side TLS library support (OpenSSL 3.x+ with ECH patches, or BoringSSL). Python's ssl module does not natively support ECH configuration as of Python 3.12.

**Remediation:** This is a Level 3 requirement. Implementation requires: 1. Deploy behind a reverse proxy that supports ECH (e.g., Cloudflare, nginx with ECH patches) 2. Publish ECH keys via DNS HTTPS records 3. Document ECH configuration in deployment guides. Example DNS record for ECH support: _443._https.steve.apache.org. IN HTTPS 1 . ech="&lt;base64-encoded ECH config&gt;"

**Priority:** Low

---

## Issue: FINDING-270 - LDAP Connection Security Not Verified in Architecture

**Labels:** bug, security, priority:low

**Description:**

The system connects to an LDAP server for user data loading via the asf-load-ldap.py script. There is no documentation indicating whether: 1) LDAPS (LDAP over TLS) or StartTLS is used, 2) Certificate validation is performed, 3) Credentials in bind.txt are transmitted securely. If LDAP connections use plaintext LDAP (port 389) without StartTLS, credentials and user data are transmitted unencrypted.

**Remediation:** Ensure the LDAP loading script uses LDAPS (port 636) or StartTLS with certificate validation, and document this requirement. Verify OAuth Client TLS by auditing the asfquart library to confirm certificate validation is enabled and cannot be accidentally disabled. Add certificate validation for LDAP in asf-load-ldap.py.

**Priority:** Low

---

## Issue: FINDING-271 - No Documented Enforcement of TLS Between Application and Reverse Proxy

**Labels:** bug, security, priority:low

**Description:**

The architecture states a proxy sits in front of the application server. The communication between the proxy and the application backend is not explicitly configured to use TLS. If the TLS configuration is left blank (as the config allows), the proxy-to-application link would be unencrypted. In a typical deployment: External client → Proxy (TLS terminated) → Application server (plain HTTP on port 58383). This internal hop may be unencrypted if the application's certfile/keyfile are not set. If the proxy and application are on different hosts or cross a network boundary, internal traffic between them could be intercepted. This is a lower severity concern if both are on the same host/container.

**Remediation:** Document that TLS must be configured on the application even when behind a proxy (unless on the same localhost). Or enforce TLS between proxy and backend by requiring certfile and keyfile in production configuration: server: port: 58383, certfile: internal-service.pem (Required even behind proxy), keyfile: internal-service-key.pem

**Priority:** Low

---

## Issue: FINDING-272 - No Mutual TLS (mTLS) or Strong Service Authentication for Internal Communications

**Labels:** bug, security, priority:low

**Description:**

The architecture is primarily a monolithic application (Quart web server + SQLite file database) with minimal service-to-service communication. However, there are identifiable communication paths: 1. Reverse proxy → Application server: No mutual TLS; the proxy authenticates to the backend only via network connectivity (no client certificate) 2. Application → OAuth provider (oauth.apache.org): Standard TLS, no client certificate authentication 3. Application → LDAP server: Authentication via bind credentials in bind.txt, no evidence of mTLS. The system does not implement: TLS client certificate authentication, Service mesh, API keys or tokens for service-to-service authentication, or Replay attack prevention for internal calls. At Level 3, the absence of mutual TLS means internal services cannot cryptographically verify each other's identity. An attacker with network access could potentially impersonate internal services. However, given the monolithic architecture with SQLite (no network database), the attack surface is limited.

**Remediation:** For a Level 3 deployment, add mTLS support in main.py by creating an SSL context with client certificate authentication enabled. Load server certificate chain and internal CA certificate, set verify_mode to ssl.CERT_REQUIRED to require client certificates, and apply this context when running the app. Alternatively, consider implementing a service mesh (e.g., Istio, Linkerd) if the architecture evolves to microservices.

**Priority:** Low

---

## Issue: FINDING-273 - Vote Type Enumeration Not Documented Outside of Code

**Labels:** bug, security, priority:low

**Description:**

The schema documentation mentions yna and stv as vote types but does not document the complete set of valid values, how they are validated, or their expected input/output formats. The schema.md states: type (TEXT, NOT NULL): The voting mechanism. Currently supports: yna: Yes/No/Abstain voting, stv: Single Transferable Vote. Additional types may be added in the future. The enumeration exists partially in documentation and is enforced in code (vtypes.TYPES), but the validation rules for each type's vote data are not documented.

**Remediation:** Document the expected vote input format for each type and the validation rules that apply.

**Priority:** Low

---

## Issue: FINDING-274 - Election Creation Has No Secondary Approval

**Labels:** bug, security, priority:low

**Description:**

While creation itself is not destructive, it's the entry point for the entire election lifecycle. A PMC member could create elections without organizational awareness. This is lower severity as elections must still be opened and closed, and the R.pmc_member requirement provides some gatekeeping.

**Remediation:** Consider implementing a secondary approval workflow for election creation to ensure organizational awareness and oversight, particularly for high-impact elections.

**Priority:** Low

---

## Issue: FINDING-275 - Vote Table Schema Lacks Timestamp for Timing Analysis

**Labels:** bug, security, priority:low

**Description:**

The vote table schema lacks a created_at timestamp column, preventing timing-based analysis or enforcement at the database level. This means the application cannot retroactively detect automated voting patterns, cannot implement minimum interval checks at the database level, and audit capabilities are limited.

**Remediation:** Add a created_at INTEGER column with DEFAULT (strftime('%s', 'now')) to the vote table and implement a database trigger prevent_rapid_revote to enforce minimum time intervals between votes at the database level.

**Priority:** Low

---

## Issue: FINDING-276 - Regex Applied to User-Controlled Content Without Input Length Limit

**Labels:** bug, security, priority:low

**Description:**

The rewrite_description() function applies a regex pattern r'doc:([^\s]+)' to issue.description content without a documented length limit on the description field. While the regex itself is not vulnerable to ReDoS (it uses a simple non-overlapping character class with linear O(n) complexity and no nested quantifiers or ambiguous matching), an extremely long description (megabytes) could cause momentary CPU usage during the linear scan. This is a standard DoS concern rather than exponential backtracking. The description field is admin-provided content (election managers create issues via do_add_issue_endpoint() and do_edit_issue_endpoint()), not arbitrary external users.

**Remediation:** Implement maximum length constraints on description and title fields in do_add_issue_endpoint() and do_edit_issue_endpoint() to prevent resource exhaustion. As the application grows, consider integrating a static analysis tool (e.g., regexploit) into CI/CD to catch ReDoS-vulnerable patterns in new code.

**Priority:** Low

---

## Issue: FINDING-277 - Election title used in flash messages and logs without length restriction

**Labels:** bug, security, priority:low

**Description:**

The election creation endpoint accepts form.title without length validation and uses it in logs and flash messages. No length validation on form.title allows arbitrarily long strings to be stored and rendered. While not directly exploitable for code injection (SQL is parameterized), extremely long values could cause display issues or log flooding.

**Remediation:** Add input length validation with a reasonable maximum (e.g., 200 characters): MAX_TITLE_LENGTH = 200; if not form.title or len(form.title) > MAX_TITLE_LENGTH: await flash_danger('Title is required and must be under 200 characters.'); return quart.redirect('/admin', code=303).

**Priority:** Low

---

## Issue: FINDING-278 - User-controlled data passed to EZT template variables without explicit escaping (mitigated by EZT design)

**Labels:** bug, security, priority:low

**Description:**

User-controlled data like eid from URL parameters is passed to EZT template variables without explicit escaping. EZT (EaZyTemplate) is a restricted template engine that substitutes variable values as literal strings without re-interpreting template syntax. Unlike Jinja2 or Mako, EZT's [varname] directives do not evaluate expressions—they output the string value directly. Therefore, even if eid contained [include /etc/passwd], EZT would output it as literal text. Template injection is not achievable via EZT variable substitution. However, the lack of explicit HTML escaping means this is an XSS concern rather than a template injection concern.

**Remediation:** While template injection is mitigated by EZT's design, documenting this architectural decision and ensuring templates are never loaded from user-controlled paths provides defense-in-depth. Ensure all templates are loaded from the TEMPLATES directory only and never construct template content from user input: assert template_path.resolve().is_relative_to(TEMPLATES)

**Priority:** Low

---

## Issue: FINDING-279 - Unsanitized filenames extracted from issue descriptions in rewrite_description()

**Labels:** bug, security, priority:low

**Description:**

The rewrite_description() function extracts filenames from issue descriptions using a regex pattern 'doc:([^\s]+)' and constructs URL paths without sanitization. While filenames originate from authorized users (committers storing issue descriptions), a malicious committer could craft a description containing path traversal sequences in the doc: pattern. A committer could store an issue description containing 'doc:../../sensitive-file' which generates a link to '/docs/&lt;iid&gt;/../../sensitive-file'. When a voter clicks this link, it would be handled by serve_doc() where framework-level safe_join would prevent traversal, but the link itself could confuse users or be used in social engineering.

**Remediation:** Validate extracted filenames against a safe pattern (e.g., ^[a-zA-Z0-9][a-zA-Z0-9._-]*$) and HTML-encode output. Replace invalid references with placeholder text like '[invalid doc reference]'. Use markupsafe.escape() for safe HTML rendering.

**Priority:** Low

---

## Issue: FINDING-280 - Unencoded filenames in HTML output breaking document structure

**Labels:** bug, security, priority:low

**Description:**

The `rewrite_description()` function constructs HTML `<a>` tags with filenames extracted from issue descriptions without HTML encoding. If a filename contains HTML special characters (`"`, `<`, `>`, `&`), it could break the document structure of the rendered page. If an issue description (set by a committer) contains `doc:file"onmouseover="alert(1)`, the resulting HTML would inject event handlers, breaking the HTML attribute context. Exploitation requires a malicious committer.

**Remediation:** Use `markupsafe.escape()` for display text and `urllib.parse.quote()` for href attributes. Example: `safe_display = escape(filename)` and `safe_href = urllib.parse.quote(filename, safe='')` then construct link as `f'<a href="/docs/{issue.iid}/{safe_href}">{safe_display}</a>'`

**Priority:** Low

## Issue: FINDING-281 - No File Content-Type Validation on Document Serving
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `send_from_directory` function serves files without content-type validation or forced download disposition, allowing arbitrary file types including HTML/SVG with embedded JavaScript to be rendered inline by browsers, creating stored XSS risk.

### Details
At `v3/server/pages.py:614`, documents are served using `send_from_directory` which infers MIME type from file extension without:
- Restricting allowed file types via whitelist
- Forcing `Content-Disposition: attachment` to prevent inline rendering
- Setting security headers like `X-Content-Type-Options: nosniff`

A malicious file named `exploit.html` or `malicious.svg` containing JavaScript could execute in voters' browser contexts when viewed.

### Remediation
1. Add `as_attachment=True` parameter to `send_from_directory`
2. Implement whitelist of allowed extensions (`.pdf`, `.txt`, `.md`)
3. Add security headers: `X-Content-Type-Options: nosniff` and `Content-Security-Policy: default-src 'none'`
4. Consider serving documents from separate domain for isolation

### Acceptance Criteria
- [ ] File serving forces download disposition
- [ ] Extension whitelist implemented and enforced
- [ ] Security headers added to document responses
- [ ] Test added verifying HTML/SVG files cannot execute inline

### References
- ASVS 5.4.3 (L2)
- CWE: Not specified
- Source: 5.4.3.md

### Priority
Medium (Low severity but affects core voting document functionality)

---

## Issue: FINDING-282 - No Explicit HTTP Method Restrictions Visible
**Labels:** security, priority:low
**Description:**
### Summary
No global HTTP method restrictions are visible in the API configuration, potentially allowing unsupported methods like TRACE, TRACK, or DELETE on endpoints that shouldn't support them.

### Details
In `v3/server/api.py:1-21`, there is no visible global rejection of unexpected HTTP methods or catch-all handler to return 405 for undefined methods. While the framework likely provides method-specific routing, unused methods may be accessible if defaults are permissive.

### Remediation
Add global method restriction handler:
```python
@APP.before_request
async def check_method():
    allowed = {'GET', 'POST', 'OPTIONS', 'HEAD'}
    if request.method not in allowed:
        abort(405)
```
Ensure TRACE and TRACK are blocked at server level.

### Acceptance Criteria
- [ ] Global method restriction handler implemented
- [ ] TRACE/TRACK methods explicitly blocked
- [ ] Test added verifying 405 response for unsupported methods
- [ ] Documentation updated with allowed methods per endpoint

### References
- ASVS 4.1.4 (L3)
- Source: 4.1.4.md

### Priority
Low (L3 requirement, framework likely handles this)

---

## Issue: FINDING-283 - No Per-Message Digital Signature Mechanism
**Labels:** security, enhancement, priority:low
**Description:**
### Summary
For a voting application handling sensitive transactions, there is no per-message digital signature implementation (e.g., HTTP Message Signatures RFC 9421, JWS, HMAC) to provide integrity assurance beyond TLS.

### Details
In `v3/server/api.py:1-21`, no request signing mechanism is visible. If TLS terminates at a proxy and internal traffic is unencrypted, or if intermediary systems exist, message integrity cannot be independently verified. Vote submissions could theoretically be tampered with between internal components.

### Remediation
For sensitive operations (vote submission, election state changes), implement request signing:
```python
@APP.before_request
async def verify_signature():
    if request.path in SENSITIVE_PATHS:
        signature = request.headers.get('X-Signature')
        expected = hmac.new(SECRET_KEY, request.get_data(), 'sha256').hexdigest()
        if not hmac.compare_digest(signature or '', expected):
            abort(401)
```

### Acceptance Criteria
- [ ] HMAC-based request signing implemented for vote submissions
- [ ] Signature verification uses timing-safe comparison
- [ ] Election state change operations protected
- [ ] Test coverage for signature validation

### References
- ASVS 4.1.5 (L3)
- Source: 4.1.5.md

### Priority
Low (L3 requirement, requires infrastructure changes)

---

## Issue: FINDING-284 - Date/Time Operations Use Naive Datetimes
**Labels:** bug, priority:low
**Description:**
### Summary
All datetime operations use naive (timezone-unaware) datetime objects, making log timestamps unreliable and potentially causing timezone-related bugs in election scheduling.

### Details
Affected operations:
- `v3/server/pages.py:571` - `datetime.datetime.now().timestamp()`
- `v3/server/pages.py:86` - `datetime.datetime.fromtimestamp(election.close_at)`
- `v3/server/pages.py:97` - `datetime.datetime.fromisoformat(date_str)`
- `v3/server/bin/tally.py:86` - Similar timestamp operations

### Remediation
Use timezone-aware datetime objects:
```python
from datetime import datetime, timezone
datetime.now(timezone.utc)
datetime.fromtimestamp(ts, tz=timezone.utc)
```

### Acceptance Criteria
- [ ] All datetime operations use timezone-aware objects
- [ ] UTC timezone explicitly set throughout codebase
- [ ] Test added verifying timezone awareness
- [ ] Election close time calculations verified

### References
- ASVS 16.2.2 (L2)
- Source: 16.2.2.md

### Priority
Low (correctness issue, not immediate security risk)

---

## Issue: FINDING-285 - Tally Script Outputs to Stdout Without Log Governance
**Labels:** security, documentation, priority:low
**Description:**
### Summary
The tally script outputs decrypted election results (including voter identities and vote tallies) to stdout without audit logging or documentation of output handling requirements.

### Details
At `v3/server/bin/tally.py:129-135`, sensitive results are output to stdout without:
- Logging of where output is captured
- Documentation of secure handling requirements
- Audit trail of result access

Results could be captured in shell history, piped to insecure files, or logged by terminal multiplexers.

### Remediation
Add audit logging:
```python
_LOGGER.info(f'TALLY_OUTPUT election_id={election.eid} format={output_format} '
             f'issues={len(results)} voters={len(all_voters)}')
```
Document that tally output must be handled per data classification policy.

### Acceptance Criteria
- [ ] Audit logging added for tally output operations
- [ ] Documentation created for secure tally output handling
- [ ] Logging inventory updated to include stdout channel
- [ ] Operational procedures documented

### References
- ASVS 16.2.3, 16.4.2 (L2)
- Source: 16.2.3.md, 16.4.2.md

### Priority
Low (operational security concern)

---

## Issue: FINDING-286 - No Request/Correlation ID for Multi-Step Operations
**Labels:** enhancement, observability, priority:low
**Description:**
### Summary
When users submit votes for multiple issues in a single request, each vote generates a separate log entry with no shared correlation ID, complicating forensic investigation.

### Details
In `v3/server/pages.py` endpoint handlers, multiple vote submissions in one request cannot be correlated without temporal proximity heuristics. This impacts incident response and audit capabilities.

### Remediation
Generate request-scoped correlation ID:
```python
import uuid
request_id = str(uuid.uuid4())[:8]
for iid, votestring in votes.items():
    _LOGGER.info(f'request_id={request_id} User[U:{result.uid}] '
                 f'voted on issue[I:{iid}] in election[E:{election.eid}]')
```

### Acceptance Criteria
- [ ] Request correlation IDs implemented
- [ ] All multi-step operations include correlation ID in logs
- [ ] Test added verifying correlation across log entries
- [ ] Log parsing documentation updated

### References
- ASVS 16.2.4 (L2)
- Source: 16.2.4.md

### Priority
Low (observability improvement)

---

## Issue: FINDING-287 - PersonDB Lookup Failure Not Logged
**Labels:** bug, observability, priority:low
**Description:**
### Summary
When `PersonNotFound` exception occurs for an authenticated user, the handler returns 404 without logging this anomalous condition that could indicate configuration or data integrity issues.

### Details
At `v3/server/pages.py:303-313`, authenticated users not found in PersonDB represent an unexpected state but generate no log entry. This could mask:
- Configuration issues
- Data synchronization problems
- Potential security issues

### Remediation
Add structured logging for PersonNotFound:
```python
except PersonNotFound:
    _LOGGER.warning(f'PersonDB lookup failed for authenticated user uid={result.uid} '
                    f'context={request.path} timestamp={datetime.now(timezone.utc)}')
    return quart.abort(404)
```

### Acceptance Criteria
- [ ] PersonNotFound exceptions logged with context
- [ ] Log includes authenticated UID and request context
- [ ] Test added verifying logging behavior
- [ ] Alerting configured for repeated occurrences

### References
- ASVS 16.3.4 (L2)
- Source: 16.3.4.md

### Priority
Low (observability improvement)

---

## Issue: FINDING-288 - Debug Print Statements Expose Form Data
**Labels:** bug, security, priority:low
**Description:**
### Summary
Debug `print()` statements output raw form data to stdout, potentially exposing sensitive information if stdout is captured by logging systems.

### Details
At `v3/server/pages.py:499` and `v3/server/pages.py:524`, debug print statements output form data including:
- Issue titles and descriptions
- User-supplied content
- Potentially sensitive election data

If stdout is captured by process managers or logging systems, this data could be exposed to unauthorized parties.

### Remediation
Replace print statements with appropriate log levels:
```python
_LOGGER.debug(f'Form data received for issue creation: keys={list(form.keys())}')
```
Or remove entirely if not needed.

### Acceptance Criteria
- [ ] All print() statements removed or replaced with logging
- [ ] Debug logging uses appropriate log levels
- [ ] Test added verifying no stdout output in production mode
- [ ] Code review process updated to catch debug statements

### References
- ASVS 16.5.1 (L2)
- Source: 16.5.1.md

### Priority
Low (development artifact, limited exposure)

---

## Issue: FINDING-289 - SQLite Database Access Lacks Authentication
**Labels:** security, architecture, priority:low
**Description:**
### Summary
SQLite database access relies solely on file system permissions rather than cryptographic authentication, creating single-point-of-failure risk.

### Details
At `v3/steve/election.py:35-37` and `v3/steve/persondb.py:25-26`, database access uses file paths with no authentication layer. While SQLite is embedded and this is architecturally normal, ASVS 13.2.1 requires authentication for data layer communications.

Current data flow: Application process → file system → steve.db (no authentication layer)

### Remediation
For SQLite specifically:
1. Document that file system permissions serve as authentication
2. Ensure database file has restrictive permissions (0600)
3. Consider SQLCipher for data-at-rest encryption
4. If migrating to networked database, implement service account authentication

### Acceptance Criteria
- [ ] Database file permissions documented and enforced (0600)
- [ ] File ownership restricted to application service account
- [ ] Security documentation updated with authentication model
- [ ] Migration path to authenticated database documented

### References
- ASVS 13.2.1 (L2, L3)
- Source: 13.2.1.md

### Priority
Low (architectural limitation of SQLite)

---

## Issue: FINDING-290 - Email Service Authentication Not Documented
**Labels:** security, documentation, priority:low
**Description:**
### Summary
SMTP authentication configuration is not visible or documented. Comment suggests authentication is not yet configured, potentially relying on network-level trust.

### Details
At `v3/server/bin/mail-voters.py:67-73`, the email sending function includes comment "Add other parameters as needed (e.g., auth, headers)" suggesting authentication is not configured. The `asfpy.messaging` library may handle this internally, but it's not documented.

If SMTP auth is not configured, the application may rely on network-level trust which could be spoofed or abused.

### Remediation
1. Document SMTP authentication method
2. Ensure use of short-term tokens or certificate-based auth (not static passwords)
3. Verify asfpy.messaging library authentication configuration
4. Add configuration validation on startup

### Acceptance Criteria
- [ ] SMTP authentication method documented
- [ ] Configuration includes authentication parameters
- [ ] Startup validation ensures auth is configured
- [ ] Test added verifying authentication is used

### References
- ASVS 13.2.1 (L2, L3)
- Source: 13.2.1.md

### Priority
Low (may be handled by library)

---

## Issue: FINDING-291 - CLI Scripts Lack Privilege Requirements Documentation
**Labels:** security, documentation, priority:low
**Description:**
### Summary
Command-line utilities that modify databases or send emails have no documented OS-level privilege requirements or access controls, allowing any shell user to perform administrative actions.

### Details
Scripts `create-election.py` and `mail-voters.py` can:
- Create elections and modify voter rolls
- Read voter emails and send messages
- Modify database directly with same privileges as web server

Anyone with shell access can perform these actions without authentication or authorization beyond system-level logging.

### Remediation
1. Document required OS permissions for CLI tools
2. Consider adding authentication checks (e.g., require specific user/group)
3. Implement restricted execution contexts
4. Add audit logging within scripts

Example:
```python
import os
if os.geteuid() != 0 and os.getegid() not in ADMIN_GROUPS:
    raise PermissionError("This script requires admin privileges")
```

### Acceptance Criteria
- [ ] OS permission requirements documented
- [ ] Scripts validate execution privileges
- [ ] Audit logging added to CLI operations
- [ ] Operational procedures updated

### References
- ASVS 13.2.2 (L2, L3)
- Source: 13.2.2.md

### Priority
Low (operational security concern)

---

## Issue: FINDING-292 - No Connection Management Configuration
**Labels:** enhancement, reliability, priority:low
**Description:**
### Summary
Configuration schema lacks connection management parameters (timeouts, retries, max connections) for backend services, potentially causing cascading failures and resource exhaustion.

### Details
`v3/server/config.yaml.example` does not define:
- SQLite connection parameters (busy timeout, journal mode)
- OAuth timeout and retry configuration
- LDAP connection pooling and timeouts

Without explicit configuration:
- Slow external services could cause request handler timeouts
- Connection leaks could exhaust file descriptors
- No circuit-breaker behavior when backends unavailable
- Default retry strategies may cause thundering herd

### Remediation
Extend config.yaml schema:
```yaml
connections:
  database:
    path: steve.db
    busy_timeout_ms: 5000
    journal_mode: WAL
    max_connections: 5
  oauth:
    base_url: "https://oauth.apache.org"
    connect_timeout_s: 5
    read_timeout_s: 10
    max_retries: 3
    retry_backoff: "exponential"
  ldap:
    host: "ldaps://ldap.apache.org"
    connect_timeout_s: 5
    pool_size: 5
```

### Acceptance Criteria
- [ ] Connection configuration schema defined
- [ ] Timeouts implemented for all backend connections
- [ ] Retry logic with exponential backoff implemented
- [ ] Health checks added for backend connectivity
- [ ] Test coverage for timeout scenarios

### References
- ASVS 13.2.6 (L3)
- Source: 13.2.6.md

### Priority
Low (L3 requirement, reliability improvement)

---

## Issue: FINDING-293 - No Source Control Metadata Exclusion
**Labels:** security, deployment, priority:low
**Description:**
### Summary
No deployment configuration explicitly excludes `.git`, `.svn`, or other source control metadata from production deployments, potentially exposing source code history and credentials.

### Details
At `main.py:49`, `static_folder=None` prevents serving arbitrary files, but no `.dockerignore`, deployment script, or reverse proxy rules explicitly exclude source control directories. If deployment pipeline doesn't strip `.git` and reverse proxy doesn't block access, exposure is possible.

### Remediation
Add deployment exclusions:
```dockerfile
# .dockerignore
.git
.svn
.hg
*.pyc
__pycache__
```

Or reverse proxy rules:
```apache
<DirectoryMatch "^\.(git|svn|hg)">
    Require all denied
</DirectoryMatch>
```

### Acceptance Criteria
- [ ] .dockerignore file created with source control exclusions
- [ ] Deployment script validates exclusions
- [ ] Reverse proxy rules added
- [ ] Test added verifying .git is not accessible

### References
- ASVS 13.4.1 (L1)
- Source: 13.4.1.md

### Priority
Low (defense-in-depth)

---

## Issue: FINDING-294 - Documentation/Monitoring Endpoints Not Verified
**Labels:** security, documentation, priority:low
**Description:**
### Summary
Cannot verify whether documentation endpoints (Swagger/OpenAPI) or monitoring endpoints are exposed without access control due to missing module visibility.

### Details
At `v3/server/main.py:52-53`, `pages` and `api` modules are imported but not available for audit. If these modules expose auto-generated documentation or monitoring endpoints without authentication, internal API structure and system health could be disclosed.

### Remediation
Ensure documentation/monitoring endpoints are:
1. Protected by authentication/authorization
2. Disabled in production via configuration
3. Bound only to internal network interfaces

Example conditional loading:
```python
if not app.cfg.server.get('production', True):
    import api_docs
```

### Acceptance Criteria
- [ ] Audit pages.py and api.py for documentation endpoints
- [ ] Authentication added to any monitoring endpoints
- [ ] Production configuration disables documentation
- [ ] Test added verifying endpoints are protected

### References
- ASVS 13.4.5 (L2)
- Source: 13.4.5.md

### Priority
Low (requires module audit)

---

## Issue: FINDING-295 - Example Configuration Reveals Development Tooling
**Labels:** security, documentation, priority:low
**Description:**
### Summary
Example configuration file uses specific certificate filenames (`localhost.apache.org+3.pem`) that reveal the use of `mkcert` development tool.

### Details
In `v3/server/config.yaml.example`, certificate filenames reveal development tooling choices. While minimal impact, this is information leakage that violates defense-in-depth principles.

### Remediation
Use generic filenames in example configuration:
```yaml
certfile: server.pem
keyfile: server-key.pem
```

### Acceptance Criteria
- [ ] Example configuration updated with generic filenames
- [ ] Documentation notes to replace with production certificates
- [ ] Review other configuration examples for information leakage

### References
- ASVS 13.4.6 (L3)
- Source: 13.4.6.md

### Priority
Low (minimal impact)

---

## Issue: FINDING-296 - Sensitive Files Co-Located in Application Directory
**Labels:** security, architecture, priority:low
**Description:**
### Summary
Configuration files, database, TLS keys, and source code are co-located in the application directory, creating single-point-of-failure risk where misconfiguration could expose all sensitive files.

### Details
Application directory contains:
- config.yaml (credentials, configuration)
- steve.db (database with encrypted votes)
- certs/*.pem and certs/*-key.pem (TLS private keys)
- *.py (source code)

While `static_folder=None` prevents serving via framework, a single misconfiguration (e.g., accidentally setting `static_folder='.'`) could expose everything.

### Remediation
Separate sensitive files by function:
```
/var/lib/steve/steve.db          # Database
/etc/ssl/private/steve/          # Certificates
/etc/steve/config.yaml           # Configuration
/opt/steve/                      # Application code
```

Update path resolution in main.py and add deployment documentation.

### Acceptance Criteria
- [ ] File separation architecture documented
- [ ] Path resolution updated for separated files
- [ ] Deployment script implements separation
- [ ] Test added verifying file isolation

### References
- ASVS 13.4.7 (L3)
- Source: 13.4.7.md

### Priority
Low (defense-in-depth, requires deployment changes)

---

## Issue: FINDING-297 - Database Operations Not Isolated From Web Process
**Labels:** security, architecture, priority:low
**Description:**
### Summary
SQLite database access occurs directly in the web-serving process, meaning the database file (containing encrypted votes and keys) is accessible to the same process handling untrusted HTTP input.

### Details
At `v3/steve/election.py:43`, database operations occur in the web process. A path traversal or file inclusion vulnerability could potentially compromise the database directly without additional privilege escalation.

### Remediation
Consider architectural change to dedicated database access layer:
- Microservice or separate process mediating database operations
- Web process makes API calls instead of direct file access
- Reduces blast radius of web application vulnerabilities

This is a significant architectural change appropriate for future versions.

### Acceptance Criteria
- [ ] Architecture documented for database isolation
- [ ] API interface designed for database operations
- [ ] Migration path documented
- [ ] Security benefits quantified

### References
- ASVS 15.2.5 (L3)
- Source: 15.2.5.md

### Priority
Low (architectural enhancement for future consideration)

---

## Issue: FINDING-298 - Election Owner PID Exposed to Non-Owner Voters
**Labels:** security, data-minimization, priority:low
**Description:**
### Summary
The `vote_on_page()` function passes election object including `owner_pid` and `authz` fields to templates, exposing administrative information to voters who don't need it.

### Details
At `v3/server/pages.py:235`, `result.election` passed to template includes administrative fields like `owner_pid` (election owner's person ID) and `authz` (LDAP group). While `get_metadata()` excludes `salt` and `opened_key`, these administrative fields violate data minimization.

### Remediation
Create voter-specific view of election metadata:
```python
def get_voter_metadata(self):
    """Return election metadata appropriate for voters."""
    return {
        'eid': self.eid,
        'title': self.title,
        'open_at': self.open_at,
        'close_at': self.close_at,
        # Exclude: owner_pid, authz, administrative fields
    }
```

### Acceptance Criteria
- [ ] Voter-specific metadata method implemented
- [ ] Field-level access control added based on user role
- [ ] Template updated to use filtered metadata
- [ ] Test added verifying field filtering

### References
- ASVS 15.3.1 (L1)
- Source: 15.3.1.md

### Priority
Low (data minimization principle)

---

## Issue: FINDING-299 - Vote Endpoint Accepts Arbitrary Issue IDs
**Labels:** security, input-validation, priority:low
**Description:**
### Summary
The `do_vote_endpoint()` function extracts any form key prefixed with 'vote-' without validating the issue ID exists in the current election before processing.

### Details
At `v3/server/pages.py:390`, form keys starting with 'vote-' are processed with the suffix used as issue ID. While downstream `add_vote()` validates authorization via `q_get_mayvote.first_row(pid, iid)`, the endpoint doesn't fail fast for non-existent issues, potentially triggering unnecessary database queries.

### Remediation
Add upfront validation:
```python
votes = {}
for key, votestring in form.items():
    if key.startswith("vote-"):
        iid = key[5:]
        if iid not in issue_dict:
            flash(f"Invalid issue ID: {iid}", "danger")
            return quart.redirect(f"/election/{election.eid}/vote")
        votes[iid] = votestring
```

### Acceptance Criteria
- [ ] Issue ID validation added before processing
- [ ] Invalid issue IDs rejected with error message
- [ ] Test added for non-existent issue IDs
- [ ] Test added for cross-election issue ID injection attempt

### References
- ASVS 15.3.3 (L2)
- Source: 15.3.3.md

### Priority
Low (defense-in-depth, mitigated by downstream checks)

---

## Issue: FINDING-300 - No Type Validation on Form Fields
**Labels:** bug, input-validation, priority:low
**Description:**
### Summary
Functions using `edict(await quart.request.form)` pattern lack explicit type validation, creating potential for unexpected behavior if Content-Type headers are manipulated.

### Details
In `v3/server/pages.py`, functions `do_add_issue_endpoint()`, `do_edit_issue_endpoint()`, and `do_create_endpoint()` use `edict(await quart.request.form)` without type checking. While Quart's form parser returns strings, the conversion to `edict` and direct attribute access without validation creates fragility.

### Remediation
Replace `edict` pattern with explicit field extraction:
```python
form = await quart.request.form
title = form.get('title', '')
if not isinstance(title, str) or not title:
    quart.abort(400, 'Invalid title')
description = form.get('description', '')
if not isinstance(description, str):
    quart.abort(400, 'Invalid description')
```

### Acceptance Criteria
- [ ] All form field extractions use explicit get() with type checking
- [ ] Type validation added for all user inputs
- [ ] Test added for type validation edge cases
- [ ] edict usage removed from form processing

### References
- ASVS 15.3.5 (L2)
- Source: 15.3.5.md

### Priority
Low (framework provides some protection)

---

## Issue: FINDING-301 - EasyDict Usage May Allow Attribute Shadowing
**Labels:** security, code-quality, priority:low
**Description:**
### Summary
EasyDict converts dictionary keys to object attributes. If user input contains keys like `__class__`, `items`, or `keys`, it could shadow built-in methods causing TypeError in downstream code.

### Details
At `v3/server/pages.py:401, 447, 518`, `edict(await quart.request.form)` converts user-controlled form data to attribute-accessible objects. If a form field named `items` is submitted, calling `form.items()` later would return the stored value instead of the method, causing TypeError.

While not as dangerous as JavaScript prototype pollution, this can cause denial of service.

### Remediation
Replace edict usage with explicit field extraction:
```python
form_data = await quart.request.form
title = form_data.get('title', '').strip()
description = form_data.get('description', '').strip()
# Explicit extraction prevents attribute shadowing
```

### Acceptance Criteria
- [ ] All edict usage removed from form processing
- [ ] Explicit field extraction implemented
- [ ] Test added for reserved attribute name submission
- [ ] Code review checklist updated to flag edict usage

### References
- ASVS 15.3.6 (L2)
- Source: 15.3.6.md

### Priority
Low (denial of service risk only)

---

## Issue: FINDING-302 - Implicit Parameter Deduplication Without HPP Defense
**Labels:** security, input-validation, priority:low
**Description:**
### Summary
HTTP form body MultiDict is converted to dict via `edict()`, silently dropping duplicate parameters without explicit HTTP Parameter Pollution (HPP) defense.

### Details
At `v3/server/pages.py:397`, `edict(await quart.request.form)` converts MultiDict to dict, silently keeping first value when duplicates exist. This behavior is framework-dependent and undocumented. While subsequent validation (`if iid not in issue_dict`) and vote re-submission model mitigate impact, the implicit deduplication is fragile.

### Remediation
Implement explicit duplicate detection:
```python
raw_form = await quart.request.form
for key in raw_form.keys():
    if key.startswith('vote-'):
        values = raw_form.getlist(key)
        if len(values) > 1:
            flash(f'Duplicate vote parameter detected for {key}', 'danger')
            return quart.redirect(f'/election/{eid}/vote')
```

### Acceptance Criteria
- [ ] Explicit duplicate parameter detection implemented
- [ ] Requests with duplicate parameters rejected
- [ ] Test added for HPP attack scenarios
- [ ] Behavior documented

### References
- ASVS 15.3.7 (L2)
- Source: 15.3.7.md

### Priority
Low (mitigated by downstream validation)

---

## Issue: FINDING-303 - State-Changing GET Endpoints Enable Session Replay
**Labels:** security, priority:medium
**Description:**
### Summary
State-changing operations `/do-open/<eid>` and `/do-close/<eid>` use HTTP GET method, enabling session replay attacks, accidental triggering via link prefetching, and bypass of POST-specific protections.

### Details
At `v3/server/pages.py` (do_open_endpoint, do_close_endpoint), GET requests for state-changing operations:
- Can be cached/logged by proxies and browsers
- Triggered via `<img>` tags or link prefetching
- Replayed from browser history
- May bypass WAF POST-specific protections

### Remediation
Change to POST method:
```python
@APP.post('/do-open/<eid>')
async def do_open_endpoint(eid):
    # ... existing code
```

Update templates to use forms instead of links for these actions.

### Acceptance Criteria
- [ ] State-changing endpoints converted to POST
- [ ] CSRF protection added (separate finding)
- [ ] Templates updated with forms instead of links
- [ ] Test added verifying GET requests rejected

### References
- ASVS 6.1.1 (L1), 6.3.1 (L1)
- Source: 6.1.1.md, 6.3.1.md

### Priority
Medium (violates HTTP semantics, enables attacks)

---

## Issue: FINDING-304 - No Context-Specific Password Deny List Documented
**Labels:** documentation, security, priority:low
**Description:**
### Summary
While authentication is delegated to ASF OAuth, ASVS 6.1.2 requires documentation of context-specific words that should be prevented in passwords (e.g., "apache", "steve", "voter").

### Details
The application delegates password management to ASF OAuth but lacks documentation of context-specific password deny list. Even with delegation, the requirement to document such a list applies to verify the authentication provider implements appropriate controls.

Context-specific words for this application:
- Organization: apache, asf, foundation
- Product: steve, voter, election, ballot
- Roles: committer, pmc, member, admin

### Remediation
Create documentation:
```markdown
# Context-Specific Password Deny List

## Delegation Notice
Password policies enforced by ASF OAuth (oauth.apache.org).

## Recommended Deny List
- Organization: apache, asf, foundation, software
- Product: steve, voter, voting, election, ballot
- Roles: committer, pmc, member, admin, owner
- Project: steve3, STeVe, apache-steve

## Verification
[Link to ASF password policy]
[Last verified: YYYY-MM-DD]
```

### Acceptance Criteria
- [ ] Password deny list documented
- [ ] ASF OAuth policy verified to include context-specific words
- [ ] Documentation includes verification date
- [ ] Link to ASF password policy included

### References
- ASVS 6.1.2 (L2)
- Source: 6.1.2.md

### Priority
Low (documentation requirement)

---

## Issue: FINDING-305 - OAuth State Parameter Binding Not Verifiable
**Labels:** security, authentication, priority:low
**Description:**
### Summary
OAuth state parameter generation and validation logic resides in asfquart framework (not provided for review), making it impossible to verify proper state binding to prevent CSRF and session fixation.

### Details
At `v3/server/main.py:33-37`, OAuth configuration uses `%s` format string for state parameter but actual generation/validation is in asfquart framework. Cannot verify:
- State contains sufficient entropy (≥128 bits)
- State is bound to user's session
- State is validated on callback
- State is single-use

### Remediation
Document reliance on framework and verify during integration testing:
1. State generated with CSPRNG (≥128 bits entropy)
2. State stored in server-side session before redirect
3. State verified on callback and consumed (single-use)
4. State includes timestamp and expires

Add integration test verifying state validation:
```python
def test_oauth_state_binding():
    # Attempt to reuse state parameter
    # Attempt to use state from different session
    # Verify both are rejected
```

### Acceptance Criteria
- [ ] Framework OAuth state handling documented
- [ ] Integration test added for state validation
- [ ] State entropy verified (≥128 bits)
- [ ] Single-use consumption verified

### References
- ASVS 6.6.2 (L2)
- Source: 6.6.2.md

### Priority
Low (framework responsibility)

---

## Issue: FINDING-306 - TLS Certificate Storage Lacks Integrity Protection
**Labels:** security, deployment, priority:low
**Description:**
### Summary
TLS certificates stored on filesystem lack explicit integrity protection mechanisms (file permissions enforcement, checksums, read-only mounting), creating risk if filesystem is compromised.

### Details
At `v3/server/main.py:6, 71-73`, TLS certificates loaded from filesystem without:
- File permission verification
- Integrity verification (checksums/signatures)
- Read-only filesystem mounting

If attacker gains filesystem write access to `certs/` directory, they could replace certificates enabling MITM attacks. This requires prior server compromise but represents defense-in-depth gap.

### Remediation
Add certificate file permission verification:
```python
import os, stat

cert_path = CERTS_DIR / app.cfg.server.certfile
cert_stat = os.stat(cert_path)
if cert_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
    raise RuntimeError(f"Certificate {cert_path} has unsafe permissions")
```

Document required permissions (0600, owned by service account).

### Acceptance Criteria
- [ ] Certificate file permission verification added
- [ ] Startup fails if permissions are unsafe
- [ ] Documentation updated with required permissions
- [ ] Deployment script sets correct permissions

### References
- ASVS 6.7.1 (L3)
- Source: 6.7.1.md

### Priority
Low (infrastructure concern, requires prior compromise)

---

## Issue: FINDING-307 - Session Token Storage Mechanism Not Defined
**Labels:** security, documentation, priority:low
**Description:**
### Summary
Session management mechanism not visible in provided code. Cannot verify whether session cookies are marked HttpOnly, Secure, and SameSite, or whether session data beyond token ID is stored client-side.

### Details
No session management configuration visible in provided files. Quart framework typically uses signed cookies for sessions, but configuration cannot be verified. Per ASVS 14.3.3, session tokens are the only exception allowed for browser storage, but must be properly secured.

### Remediation
Ensure Quart session configuration includes:
```python
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour
```

Document session management approach and security controls.

### Acceptance Criteria
- [ ] Session cookie configuration verified
- [ ] HttpOnly, Secure, SameSite flags confirmed
- [ ] Session lifetime configured appropriately
- [ ] Documentation updated with session security controls

### References
- ASVS 14.3.3 (L2)
- Source: 14.3.3.md

### Priority
Low (likely handled by framework)

---

## Issue: FINDING-309 - Deserialized JSON KV Data Lacks Schema Validation
**Labels:** security, data-validation, priority:low
**Description:**
### Summary
Database `issue.kv` column deserialized via `json.loads()` and passed to vote tallying functions without structural validation, potentially causing logic errors if data is corrupted or maliciously set.

### Details
At `v3/steve/election.py:292, 368`, `json.loads()` deserializes `kv` data passed directly to `vtypes` module `tally()` functions without schema validation. While `json.loads()` is safe from code execution, unexpected data structures could cause tallying errors.

Mitigating factors:
- Data originates from authorized administrators
- `issue.type` validated against `vtypes.TYPES` at creation
- Exploitation requires bypassing multiple controls

### Remediation
Implement schema validation in `json2kv()`:
```python
@staticmethod
def json2kv(j):
    """Convert KV JSON string back to structured value."""
    if not j:
        return None
    parsed = json.loads(j)
    if not isinstance(parsed, dict):
        raise ValueError(f"Expected dict for kv, got {type(parsed).__name__}")
    return parsed
```

Each `vtypes` module should also validate `kv` structure in `tally()`.

### Acceptance Criteria
- [ ] Schema validation added to json2kv()
- [ ] Type checking added for deserialized data
- [ ] Each vtypes module validates kv structure
- [ ] Test added for invalid kv data structures

### References
- ASVS 1.5.2 (L2)
- Source: 1.5.2.md

### Priority
Low (multiple mitigating controls exist)

---

## Issue: FINDING-310 - Cannot Verify SRI Compliance - Templates Not Available
**Labels:** security, audit-required, priority:low
**Description:**
### Summary
HTML templates (.ezt files) not available for audit. Cannot verify whether external CDN resources are loaded with Subresource Integrity (SRI) attributes to prevent CDN compromise attacks.

### Details
At `v3/server/pages.py:40-41`, application uses templates from TEMPLATES directory (not provided). These may reference external resources (JavaScript libraries, CSS frameworks, fonts) without SRI. If external resources loaded without SRI, CDN compromise could inject malicious JavaScript.

Application references Bootstrap (in flash message categories), suggesting external CSS/JS may be used.

### Remediation
1. Audit all .ezt templates for external resource references
2. Add `integrity` and `crossorigin` attributes to external resources:
```html
<script src="https://cdn.example.com/lib.min.js" 
        integrity="sha384-{hash}" 
        crossorigin="anonymous"></script>
```
3. Preferably host all assets locally via `serve_static()` handler
4. Document external resource dependencies and SRI hashes

### Acceptance Criteria
- [ ] All .ezt templates audited for external resources
- [ ] SRI attributes added to external resources
- [ ] Or all assets migrated to local hosting
- [ ] External resource inventory documented

### References
- ASVS 3.6.1 (L3)
- Source: 3.6.1.md

### Priority
Low (requires template audit, L3 requirement)

---

## Issue: FINDING-308 - Session Token Storage Mechanism Not Defined

**Labels:** bug, security, priority:low

**Description:**

Per ASVS 14.3.3, session tokens are the only exception allowed for browser storage. However, no session management mechanism is visible in the provided code. The domain context mentions the application uses Quart (async Flask-like framework), which typically uses signed cookies for sessions. Without seeing the session configuration, it's unclear whether session cookies are marked HttpOnly, Secure, and SameSite, or whether session data beyond the token ID is stored client-side. Session management not visible in provided code. This is likely handled by the Quart framework's session management, but cannot be verified from the provided files.

**Remediation:** Ensure Quart session configuration includes: app.config['SESSION_COOKIE_HTTPONLY'] = True, app.config['SESSION_COOKIE_SECURE'] = True, app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'.

**Priority:** Low