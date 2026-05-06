# Security Audit Consolidated Report

## Apache STeVe Election System — ASVS L3 Assessment

---


> **Note:** 7 Critical findings have been redacted from this report and forwarded to the project's PMC private mailing list.


## Report Metadata

| Field | Value |
|-------|-------|
| **Repository** | `apache/tooling-runbooks` |
| **ASVS Level** | L3 |
| **Severity Threshold** | None (all findings included) |
| **Commit** | N/A |
| **Date** | May 06, 2026 |
| **Auditor** | Tooling Agents |
| **Source Reports** | 345 |
| **Total Findings** | 286 |

---

## Executive Summary

This report consolidates the results of a comprehensive ASVS Level 3 security audit across 15 security domains of the Apache STeVe election management system. The assessment evaluated source code, configuration, architecture, and deployment artifacts against the OWASP Application Security Verification Standard at its most rigorous level.

### Severity Distribution

| Severity | Count | Percentage |
|----------|------:|:----------:|
| 🟠 High | 67 | 23.4% |
| 🟡 Medium | 141 | 49.3% |
| 🔵 Low | 70 | 24.5% |
| ⚪ Informational | 1 | 0.3% |
| **Total** | **279** | **100%** |

The finding distribution reveals a system with **fundamental architectural security gaps** at the Critical and High tiers, compounded by extensive control incompleteness at the Medium tier. The concentration of 74 findings (25.9%) at Critical or High severity indicates systemic deficiencies in authentication, authorization, session management, and transport security that require immediate remediation.

### ASVS Level Coverage

| Level | Findings Triggered | Assessment |
|-------|-------------------:|------------|
| **L1** (Baseline) | 89 | Significant gaps in foundational controls including input validation, XSS prevention, TLS enforcement, and basic session management |
| **L2** (Standard) | 198 | Widespread deficiencies in OAuth/OIDC security, logging, cryptographic management, header security, and business logic validation |
| **L3** (Advanced) | 83 | Expected gaps in hardware security modules, post-quantum readiness, memory protection, and advanced isolation — but also missing controls expected at this tier such as step-up authentication and continuous verification |

> **Note:** Many findings span multiple levels, indicating controls that are absent from the most basic tier upward.

### Top 5 Risks

| # | Finding | Severity | Risk Summary |
|---|---------|----------|--------------|
| 4 | **FINDING-051**: TLS Configuration is Optional — Application Allows Plaintext HTTP | 🟠 High | The application can operate over unencrypted HTTP with no enforcement mechanism. Combined with the absence of HSTS (FINDING-038/044), session tokens, OAuth credentials, and vote data may transit in cleartext. |

**Compounding Factor:** These top risks interact synergistically. The BOLA vulnerability () combined with the CSRF bypass () means an unauthenticated attacker could potentially manipulate elections by forging requests from any authenticated user's browser. The absence of security event logging (FINDING-065) means such attacks would leave no audit trail.

### Positive Controls Identified

Despite the significant findings, the audit identified several well-designed security controls demonstrating architectural security awareness:

| Category | Controls | Assessment |
|----------|----------|------------|
| **Cryptographic Architecture** | Centralized crypto module; CSPRNG via `secrets.token_bytes()`; multi-level key derivation (BLAKE2b → Argon2 → opened_key); per-voter-per-issue salts; immediate vote encryption; Fernet encrypt-then-MAC preventing padding oracle attacks; random IV per encryption; vote shuffling before output | **Strong.** The cryptographic design demonstrates expert-level understanding of vote secrecy requirements. No homebrew primitives; all operations use peer-reviewed libraries. |
| **Credential Protection** | `get_metadata()` explicitly excludes `salt` and `opened_key`; SQL queries for external data select only safe columns; no tokens in template variables; server-side-only token handling | **Strong.** Defense-in-depth approach to preventing cryptographic material leakage to clients. |
| **Authorization Architecture** | `@asfquart.auth.require` decorator on all protected endpoints; role differentiation (committer vs. pmc_member); per-endpoint authorization declarations; voter eligibility verification; per-document access control | **Partial.** The framework provides authentication enforcement, but object-level authorization within endpoints remains incomplete (see FINDING-011). |
| **OAuth/Session Design** | Authorization code flow (not implicit); server-side backchannel token exchange; state parameter for CSRF protection; HTTPS for all OAuth communication; session-based architecture with cookie constraints | **Adequate foundation.** Core OAuth flow is correctly structured, though missing PKCE, nonce, and audience validation at the application layer. |
| **Database Schema Constraints** | CHECK constraints enforce key lengths (16-byte salt, 32-byte opened_key, 32-byte vote_token); library version pinning with upper bounds | **Good.** Schema-level enforcement provides defense-in-depth for cryptographic material integrity. |

**Summary Assessment:** The application demonstrates strong cryptographic engineering for vote secrecy but has critical gaps in web application security fundamentals (CSRF, XSS, authorization, session management, TLS enforcement, and security logging). The security posture suggests a development focus on election integrity mathematics without equivalent attention to the web security envelope protecting those operations.

---

## 3. Findings

### 3.2 High

#### FINDING-008: No Crypto Agility - Algorithms Hardcoded Without Abstraction or Versioning

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 11.2.2 |
| **Files** | v3/steve/crypto.py (entire file), v3/schema.sql (N/A) |
| **Source Reports** | 11.2.2.md |
| **Related Findings** | None |

**Description:**

The application has no crypto-agility design. Specific issues: (1) No algorithm abstraction layer - all crypto operations directly call specific implementations with hardcoded parameters. There's no configuration, registry, or strategy pattern that would allow swapping algorithms. (2) No algorithm versioning in stored data - the vote table stores ciphertext without any algorithm identifier. When transitioning from Fernet to XChaCha20-Poly1305, there will be no way to determine which algorithm was used for existing ciphertext without external tracking. (3) No key versioning - if keys need to be rotated or algorithms changed, there's no version field to indicate which key/algorithm generated a given ciphertext. (4) No re-encryption mechanism - no tooling exists to decrypt existing votes with the old algorithm and re-encrypt with a new one. (5) Fixed key lengths in schema - database CHECK constraints enforce exact lengths (length(vote_token) = 32, length(opened_key) = 32, length(salt) = 16), preventing algorithm changes that require different sizes without schema migration.

**Remediation:**

1. Add algorithm version to stored ciphertext: CREATE TABLE vote (vid INTEGER PRIMARY KEY AUTOINCREMENT, vote_token BLOB NOT NULL, crypto_version INTEGER NOT NULL DEFAULT 1, ciphertext BLOB NOT NULL) STRICT; 2. Implement a crypto abstraction layer with CRYPTO_VERSIONS dictionary mapping version numbers to algorithm configurations (kdf, hash, encrypt, key_stretch). 3. Modify create_vote() to return (version, ciphertext) tuple and decrypt_votestring() to accept version parameter. 4. Provide a re-encryption utility for migration.

---

#### FINDING-009: Non-constant-time Comparison in Tamper Check Allows Timing Oracle

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Sections** | 11.2.4 |
| **Files** | v3/steve/election.py:331 |
| **Source Reports** | 11.2.4.md |
| **Related Findings** | None |

**Description:**

Python's != operator on bytes objects performs a short-circuit comparison that returns False as soon as the first differing byte is found. An attacker who can observe response timing could potentially determine how many leading bytes of the opened_key match, gradually reconstructing the stored key. The opened_key is derived from election data and serves as the anti-tamper seal; leaking it could allow an attacker to forge tamper checks.

**Remediation:**

Use hmac.compare_digest() for constant-time comparison. Replace return opened_key != md.opened_key with return not hmac.compare_digest(opened_key, md.opened_key).

---

#### FINDING-010: Authorization decisions do not consider delegated authorization claims (scope, authorization_details)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 10.3.2 |
| **Files** | v3/server/pages.py:63-93 |
| **Source Reports** | 10.3.2.md |
| **Related Findings** | None |

**Description:**

The application establishes sessions from OAuth tokens and then makes authorization decisions solely based on the `uid` extracted from the session and role memberships (committer, pmc_member). There is no evidence that OAuth scopes or `authorization_details` claims are evaluated during authorization decisions. The session data structure only captures `uid`, `fullname`, and `email` — no scope or delegation information is preserved from the access token. If the OAuth client was granted limited scopes (e.g., read-only access), the resource server would not enforce those limitations. Any valid authenticated session grants full access within the role, regardless of what the resource owner actually delegated.

**Remediation:**

Preserve OAuth token claims (scope, authorization_details) in the session during establishment. Modify basic_info() to include scope and authorization_details in the session data structure. Implement scope-based authorization decorators that verify required scopes before allowing access to endpoints. Example: Create a require_scope() decorator that checks if the required scope is present in the user's token claims before executing the endpoint logic. Store scope as a space-separated string and authorization_details as a list in the session.

---

#### FINDING-011: Multiple endpoints have placeholder authorization checks - ownership not enforced

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1, L2, L3 |
| **CWE** | CWE-862 |
| **ASVS Sections** | 10.3.2, 8.2.1, 8.3.1, 8.4.2, 8.2.2, 2.3.2 |
| **Files** | v3/server/pages.py:487, v3/server/pages.py:508, v3/server/pages.py:420, v3/server/pages.py:527, v3/server/pages.py:552, v3/server/pages.py:576, v3/server/pages.py:467, v3/server/pages.py:351, v3/server/pages.py:193 |
| **Source Reports** | 10.3.2.md, 8.2.1.md, 8.3.1.md, 8.4.2.md, 8.2.2.md, 2.3.2.md |
| **Related Findings** | None |

**Description:**

Function-level authorization is NOT enforced for election management operations. The owner_pid and authz group checks are documented as required in the schema but are not implemented—all endpoints contain '### check authz' TODO comments but no actual authorization logic. This is a Type B gap: the authorization model EXISTS in the schema/documentation (owner_pid and authz fields) but is NOT CALLED at any management endpoint. Any authenticated committer can view, open, close, add issues to, edit issues on, delete issues from, and modify dates on any election they don't own. This affects all 11 administrative endpoints that use the @load_election decorator. The authz field format is explicitly marked TBD indicating incomplete design.

**Remediation:**

Implement check_election_authz() function to verify the current user is authorized to manage the election by checking owner_pid match or authz group membership via LDAP. Add this check to the load_election decorator before allowing access to management functions. Example: async def check_election_authz(election, uid): md = election.get_metadata(); if md.owner_pid == uid: return True; if md.authz: if await check_ldap_group_membership(uid, md.authz): return True; return False. Then in load_election decorator: if not await check_election_authz(e, result.uid): quart.abort(403). Apply to all administrative endpoints including do_open_endpoint, do_close_endpoint, do_add_issue_endpoint, do_edit_issue_endpoint, do_delete_issue_endpoint, do_set_open_at_endpoint, do_set_close_at_endpoint, manage_page, and manage_stv_page.

---

#### FINDING-012: No PKCE Parameters in OAuth Authorization Request or Token Exchange

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 10.4.6 |
| **Files** | v3/server/main.py:38-42 |
| **Source Reports** | 10.4.6.md |
| **Related Findings** | None |

**Description:**

The authorization URL template (OAUTH_URL_INIT) contains state and redirect_uri but no code_challenge or code_challenge_method parameters. The token exchange URL template (OAUTH_URL_CALLBACK) contains only code but no code_verifier parameter. There is no evidence of PKCE code verifier generation or storage anywhere in the codebase. Even if the ASF OAuth server supports PKCE, the client is not sending the required parameters, which means PKCE protection is not active for this application. An attacker who intercepts the authorization code (e.g., via a malicious browser extension, open redirect, or referrer leakage) can exchange it directly at the token endpoint without needing to prove possession of the original code verifier, since no code verifier was bound to the authorization request.

**Remediation:**

Implement PKCE by generating a code verifier and code challenge. Update OAuth URL templates to include code_challenge and code_challenge_method=S256 in authorization requests, and code_verifier in token exchange requests. Example: Generate code_verifier using base64.urlsafe_b64encode(os.urandom(32)), compute code_challenge using SHA256 hash of the verifier, and include these parameters in the OAuth URLs. This requires the asfquart framework to support PKCE parameter injection, or the OAuth URL construction must be overridden.

---

#### FINDING-013: Missing nonce parameter in OIDC authorization request enables ID Token replay attacks

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 10.5.1 |
| **Files** | v3/server/main.py:39-41 |
| **Source Reports** | 10.5.1.md |
| **Related Findings** | None |

**Description:**

The authorization request URL template includes only 'state' and 'redirect_uri' parameters. There is no 'nonce' parameter included in the authorization request. Per the OIDC specification (Section 3.1.2.1), the 'nonce' value should be: 1) Generated as a cryptographically random value, 2) Sent in the authorization request, 3) Stored in the session, 4) Validated against the 'nonce' claim in the received ID Token. Without a nonce, the client cannot detect if an ID Token is being replayed from a previous authentication session. The 'state' parameter prevents CSRF but does NOT protect against ID Token replay. An attacker who obtains a valid ID Token can replay it to authenticate as the victim user, potentially gaining access to election management or voting capabilities.

**Remediation:**

Generate a cryptographically random nonce value using secrets.token_urlsafe(32), store it in the session, include it in the authorization request URL, and validate it against the nonce claim in the received ID Token during the callback handler. Example: nonce = secrets.token_urlsafe(32); session['oauth_nonce'] = nonce; asfquart.generics.OAUTH_URL_INIT = 'https://oauth.apache.org/auth?state=%s&redirect_uri=%s&nonce=%s'. In the callback handler: id_token_claims = decode_id_token(token_response); if id_token_claims['nonce'] != session.pop('oauth_nonce'): abort(401, 'ID Token nonce mismatch - possible replay attack')

---

#### FINDING-014: Missing Audience (aud) Claim Validation in ID Token

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 10.5.4, 9.2.3 |
| **Files** | v3/server/main.py:39-42, v3/server/pages.py:82-90 |
| **Source Reports** | 10.5.4.md, 9.2.3.md |
| **Related Findings** | None |

**Description:**

There is no client_id configuration visible anywhere in the provided source code. For audience validation to work: 1) The application must know its own client_id, 2) The received ID Token's aud claim must be compared against the client_id, 3) If the aud doesn't match, the token must be rejected. Without visible client_id configuration or audience validation logic, the application cannot verify that an ID Token was issued specifically for this client. An attacker who obtains an ID Token issued for a different client registered with the same authorization server could potentially use it to authenticate to this application. The asfquart framework likely handles this internally, but it's not configurable or visible in this codebase, making it impossible to verify compliance.

**Remediation:**

Configure expected audience in create_app(): app.config['TOKEN_AUDIENCE'] = 'steve' and app.config['TOKEN_ISSUER'] = 'https://oauth.apache.org'. Implement token validation function that validates the aud claim against the expected audience (handling both string and list formats) and validates the iss claim against the expected issuer. Example: def validate_token_claims(token_payload): if 'aud' in token_payload: aud = token_payload['aud']; if isinstance(aud, list): if EXPECTED_AUDIENCE not in aud: raise ValueError; elif aud != EXPECTED_AUDIENCE: raise ValueError. Also validate issuer claim similarly.

---

#### FINDING-015: Inconsistent Security Controls Across Privileged Endpoints

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 6.3.4 |
| **Files** | v3/server/pages.py:484-591 |
| **Source Reports** | 6.3.4.md |
| **Related Findings** | None |

**Description:**

While a single authentication pathway (OAuth) exists, security controls after authentication are not enforced consistently. Election creation requires R.pmc_member, but election management (opening, closing, modifying issues) only requires R.committer without ownership verification. This creates a horizontal privilege escalation where any committer can manage any election, contradicting the owner_pid model established at creation. Authorization control concept EXISTS (comments prove design intent) but is NOT CALLED at any management endpoint.

**Remediation:**

Verify the authenticated user is the election owner before allowing management operations. Check metadata.owner_pid against result.uid and return 403 if they don't match. Alternatively, create a separate load_owned_election decorator that verifies ownership before allowing modification.

---

#### FINDING-016: Cannot verify signature validation on OAuth token responses — implementation not visible

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 6.8.2 |
| **Files** | v3/server/main.py:39-42 |
| **Source Reports** | 6.8.2.md |
| **Related Findings** | None |

**Description:**

The application delegates OAuth token exchange and session establishment to the `asfquart` framework. The critical signature validation step — verifying that the authentication assertion (JWT, token response) from `oauth.apache.org` is properly signed and has not been tampered with — occurs within the `asfquart` framework code which is not provided for audit. From the provided code, we can observe: 1. The OAuth callback URL pattern suggests a simple authorization code exchange (`code=%s`) 2. No explicit JWT signature validation logic is present in the application code 3. The session is consumed in `pages.py` without any additional integrity checks. The comment in `main.py` line 37 (`### is this really needed right now? # Avoid OIDC`) suggests the application deliberately avoids OIDC, which would typically provide standardized signature validation via ID tokens. Using a custom OAuth flow without OIDC increases the risk that signature validation may not be properly implemented.

**Remediation:**

1. Audit the `asfquart` framework's OAuth callback handler to verify signature validation 2. If using plain OAuth 2.0 (not OIDC), ensure the token endpoint response is only accepted over verified TLS and the authorization code is single-use 3. Consider adopting OIDC with proper ID token signature validation using libraries like python-jose to decode and verify JWT signatures.

---

#### FINDING-017: No verification of authentication strength, method, or recentness from IdP

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 6.8.4 |
| **Files** | v3/server/pages.py:82-91 |
| **Source Reports** | 6.8.4.md |
| **Related Findings** | None |

**Description:**

The session only stores and checks uid, fullname, and email. There is no evidence that the application: 1. Validates acr (Authentication Context Class Reference) claims 2. Validates amr (Authentication Methods References) claims 3. Validates auth_time to ensure recent authentication 4. Has any documented fallback approach for unknown authentication strength. Sensitive operations in this application include: Creating elections, Opening/closing elections, Voting, Managing election issues. None of these operations verify that the user authenticated with a specific strength mechanism. The comment in main.py line 37 (### is this really needed right now? # Avoid OIDC) further confirms that OIDC claims (where acr, amr, auth_time would typically be found) are not being processed.

**Remediation:**

Implement authentication strength verification for sensitive operations. Check authentication time (require auth within last 15 minutes for sensitive ops), validate acr claim, and document fallback approach if no acr claim is present. Track 'auth_time' in the session and enforce maximum session age for sensitive operations.

---

#### FINDING-018: No session timeout configuration or documentation present in application code

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 7.1.1 |
| **Files** | v3/server/pages.py:82, v3/server/main.py:null |
| **Source Reports** | 7.1.1.md |
| **Related Findings** | None |

**Description:**

The provided code contains: 1. No session inactivity timeout configuration — sessions are read and used without checking last activity time. 2. No absolute maximum session lifetime — no expiration timestamp is validated. 3. No documentation of session timeout decisions or justifications for deviations from NIST SP 800-63B. 4. No reference to NIST SP 800-63B re-authentication requirements. NIST SP 800-63B Section 4.1.3 specifies: Session inactivity timeout of 30 minutes for AAL1, Re-authentication at least every 12 hours for AAL1, Shorter timeouts for higher assurance levels. For an election system handling sensitive operations, the lack of session timeouts means: A session could persist indefinitely after a user walks away from their computer, No forced re-authentication protects against session theft that occurred hours/days ago, There's no documented risk analysis justifying this design.

**Remediation:**

1. Document session timeout decisions with a Session Management Policy including: Inactivity Timeout of 30 minutes for general operations (NIST SP 800-63B AAL1 compliant) and 15 minutes for election management operations; Absolute Maximum Lifetime of 12 hours maximum session duration with re-authentication required for election creation/opening/closing. 2. Implement session timeout enforcement in the basic_info() function to check absolute timeout (12 hours), inactivity timeout (30 minutes), and update last activity timestamp on each request. Destroy session and abort with 401 if either timeout is exceeded.

---

#### FINDING-019: No inactivity timeout configuration exists in the application

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 7.3.1 |
| **Files** | v3/server/pages.py:entire file, v3/server/main.py:44-48 |
| **Source Reports** | 7.3.1.md |
| **Related Findings** | None |

**Description:**

No inactivity timeout configuration exists in the application code. The `asfquart` framework is used for session management, but no session idle timeout is configured at the application level. The `basic_info()` function reads session data without checking any timestamp for last activity. User authenticates via OAuth → Session established → No timestamp tracking → Session remains valid indefinitely regardless of inactivity. An attacker who obtains a session cookie (e.g., via physical access to an unattended workstation) can reuse it hours or days later since no inactivity timeout forces re-authentication.

**Remediation:**

Configure session timeout in app configuration (main.py create_app()): app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=30) and app.config['SESSION_REFRESH_EACH_REQUEST'] = True. Alternatively, implement custom middleware with @APP.before_request decorator to check session timeout by tracking 'last_active' timestamp in session data.

---

#### FINDING-020: No absolute maximum session lifetime configured

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 7.3.2 |
| **Files** | v3/server/pages.py:entire file, v3/server/main.py:44-48 |
| **Source Reports** | 7.3.2.md |
| **Related Findings** | None |

**Description:**

No absolute maximum session lifetime is configured anywhere in the application code. The create_app() function in main.py constructs the application without setting any session lifetime limits. User authenticates → Session created with no creation timestamp or max lifetime → Session persists until browser closes (or indefinitely if persistent cookies are used). A session token obtained through any means (XSS, cookie theft, network interception) remains valid indefinitely. Even if the OAuth token expires at the identity provider, the local application session continues without re-authentication.

**Remediation:**

In main.py create_app(): Set absolute maximum session lifetime (e.g., 8 hours) using app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(hours=8). Or implement session creation timestamp check using @APP.before_request decorator to check session age and destroy sessions exceeding MAX_SESSION_LIFETIME (e.g., 28800 seconds for 8 hours).

---

#### FINDING-021: Active sessions not terminated when user accounts are disabled or deleted

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 7.4.2 |
| **Files** | v3/server/bin/asf-load-ldap.py:36-63, v3/server/pages.py:null |
| **Source Reports** | 7.4.2.md |
| **Related Findings** | None |

**Description:**

The LDAP loading script (asf-load-ldap.py) performs a full synchronization of user data from LDAP into the local database, but contains no logic to detect removed accounts or terminate their active sessions. The script only adds/updates persons. When a user is removed from the organization (removed from LDAP), their active sessions are not terminated. The person's record persists in the local database, and any active sessions remain valid. In an election system, this could allow former members to participate in votes they should no longer have access to.

**Remediation:**

Modify the LDAP synchronization script to track current LDAP users, identify removed users by comparing existing database UIDs with current LDAP UIDs, disable removed accounts in the local database, and invalidate all active sessions for disabled users. Implement a disable_person method in the PersonDB class and a session invalidation mechanism to terminate all sessions when an account is disabled or deleted.

---

#### FINDING-022: No logout endpoint defined in application

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 7.4.4 |
| **Files** | v3/server/pages.py:entire file |
| **Source Reports** | 7.4.4.md |
| **Related Findings** | None |

**Description:**

No logout endpoint is defined in the application. Without a logout endpoint, it is impossible for templates to provide functional logout access, regardless of what the template HTML contains. The `basic_info()` function populates template data for authenticated pages but includes no logout URL. User wants to logout → No logout URL provided to templates → No logout endpoint exists → User cannot terminate session. An authenticated user on any page (e.g., `/voter`, `/admin`, `/manage/<eid>`) has no way to terminate their session through the application interface.

**Remediation:**

1. Add logout endpoint at /logout that calls asfquart.session.destroy() and redirects to /. 2. Provide logout URL to all templates in basic_info() function. 3. Ensure navbar template includes visible logout button/link.

---

#### FINDING-023: No mechanism for users to view or terminate active sessions

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 7.5.2 |
| **Files** | v3/server/pages.py:594, v3/server/pages.py:603 |
| **Source Reports** | 7.5.2.md |
| **Related Findings** | None |

**Description:**

The application provides no mechanism for users to view their active sessions or terminate them. The `/profile` page and `/settings` page only render basic templates without session management functionality. There is no session listing endpoint or session termination endpoint. Users cannot detect if their account has been compromised by viewing concurrent sessions. If a session is hijacked (e.g., through cookie theft or XSS), users have no self-service mechanism to invalidate that session. In an election context, this could allow an attacker to maintain persistent access and vote on behalf of the user.

**Remediation:**

Implement session listing and termination endpoints. Add a `/sessions` GET endpoint that lists all active sessions for the current user. Add a `/sessions/terminate/<session_id>` POST endpoint that requires re-authentication before allowing session termination. The termination endpoint should verify the session belongs to the requesting user and call session invalidation server-side.

---

#### FINDING-024: No Step-Up Authentication for Highly Sensitive Election Management Operations

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Sections** | 7.5.3 |
| **Files** | v3/server/pages.py:484, v3/server/pages.py:505, v3/server/pages.py:462 |
| **Source Reports** | 7.5.3.md |
| **Related Findings** | None |

**Description:**

Highly sensitive election management operations (opening, closing, and creating elections) are performed without any additional authentication or secondary verification beyond the initial session. These are irreversible or highly impactful operations in an election system. An attacker with a hijacked session cookie could open or close elections by simply issuing GET requests. Elections can be opened (making them available for voting), closed (ending voting periods), or created without any additional verification. In the context of organizational governance, premature opening or closing of elections could affect democratic outcomes.

**Remediation:**

Implement step-up authentication for sensitive operations. Change do_open_endpoint and do_close_endpoint from GET to POST. Require re-authentication if last_auth_time exceeds 5 minutes. Verify ownership by checking metadata.owner_pid against result.uid.

---

#### FINDING-025: State-changing operations use HTTP GET instead of POST, enabling CSRF attacks

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1, L2, L3 |
| **CWE** | CWE-352 |
| **ASVS Sections** | 8.2.1, 8.3.1, 8.4.2, 6.3.4, 2.3.1 |
| **Files** | v3/server/pages.py:450-466, v3/server/pages.py:470-486, v3/server/pages.py:482, v3/server/pages.py:503, v3/server/pages.py:450-465, v3/server/pages.py:470-485 |
| **Source Reports** | 8.2.1.md, 8.3.1.md, 8.4.2.md, 6.3.4.md, 2.3.1.md |
| **Related Findings** | FINDING-113 |

**Description:**

State-changing operations (opening and closing elections) use HTTP GET instead of POST, making them vulnerable to CSRF via image tags, link prefetching, browser prefetching, and other non-interactive GET request vectors. If an authenticated user visits a malicious page, their browser will send GET requests that can open or close elections without their knowledge or consent. Web crawlers could accidentally trigger these operations. Combined with the missing authorization checks, any committer's browser visiting a malicious page containing &lt;img src='https://steve.apache.org/do-open/EID'&gt; triggers the action with no CSRF token validation.

**Remediation:**

Change /do-open/&lt;eid&gt; and /do-close/&lt;eid&gt; from GET to POST methods (@APP.post). Implement CSRF token validation by calling validate_csrf_token(await quart.request.form) at the start of each endpoint. Add CSRF token validation to all state-changing endpoints. Ensure all forms submitting to these endpoints include the CSRF token. Replace the placeholder csrf_token = 'placeholder' with cryptographic CSRF token generation using secrets.token_urlsafe(32) and store it in the session. Implement async def validate_csrf_token(form_data) that uses hmac.compare_digest to validate the token from form submissions against the session token.

---

#### FINDING-026: Vote submission endpoint lacks explicit voter eligibility check before processing

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1, L2, L3 |
| **CWE** | CWE-285 |
| **ASVS Sections** | 8.2.2, 8.3.1 |
| **Files** | v3/server/pages.py:407-430, v3/steve/election.py:254, v3/server/pages.py:410-456, v3/steve/election.py:268 |
| **Source Reports** | 8.2.2.md, 8.3.1.md |
| **Related Findings** | None |

**Description:**

The voting endpoint lacks an explicit authorization check before processing votes. While election.add_vote() will implicitly fail if the user has no mayvote entry (via AttributeError on None when accessing mayvote.salt), this is not a proper security control—it's an unhandled exception that may expose stack traces or cause inconsistent error handling. Authorization relies on an implicit side-effect rather than an explicit check. This is a Type C gap where the control (mayvote lookup) is called but its result isn't explicitly validated. The pattern is fragile and a code refactor could silently remove the protection. The implicit failure may expose internal error details, provides a confusing error message, creates a timing side-channel, and relies on implementation accident rather than intentional security control.

**Remediation:**

Add explicit eligibility check in add_vote() method. Check if mayvote is None and raise a custom VoterNotEligible or NotEligibleToVote exception before attempting to access mayvote.salt. This provides intentional security control with proper error handling. Example: if mayvote is None: raise NotEligibleToVote(f'User {pid} is not eligible to vote on issue {iid}').

---

#### FINDING-027: Single shared database with no tenant-level data isolation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-566 |
| **ASVS Sections** | 8.4.1 |
| **Files** | v3/schema.sql:, v3/steve/election.py: |
| **Source Reports** | 8.4.1.md |
| **Related Findings** | None |

**Description:**

All elections for all organizational groups share a single SQLite database (steve.db). The authz field provides logical tenancy, but there is no row-level security in SQLite and query methods like list_closed_election_ids return ALL elections without tenant filtering. Administrative functions (like tallying via CLI) have access to ALL elections across all tenant boundaries. While CLI access is documented as intentional, the list_closed_election_ids method has no tenant parameter, meaning any code calling it gets cross-tenant data. This creates a risk of cross-tenant data leakage in administrative operations.

**Remediation:**

Add tenant filtering to list_closed_election_ids() and other cross-election queries. Example: @classmethod def list_closed_election_ids(cls, db_fname, authz_filter=None, include_open=False): db = cls.open_database(db_fname); if authz_filter: db.q_closed_election_ids_by_authz.perform(authz_filter); eids = [row.eid for row in db.q_closed_election_ids_by_authz.fetchall()]; else: # Only for admin CLI with explicit authorization; db.q_closed_election_ids.perform(); eids = [row.eid for row in db.q_closed_election_ids.fetchall()]; return eids. Implement tenant filtering in election queries used by the web interface.

---

#### FINDING-028: No continuous identity verification or re-authentication for sensitive administrative operations

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L3 |
| **CWE** | CWE-306 |
| **ASVS Sections** | 8.4.2 |
| **Files** | v3/server/pages.py:multiple |
| **Source Reports** | 8.4.2.md |
| **Related Findings** | None |

**Description:**

ASVS 8.4.2 requires 'continuous consumer identity verification' for administrative interfaces. The system performs identity verification only once at session creation. Critical operations such as opening an election (irreversible), closing an election (irreversible), and deleting issues are performed with the same session token as reading a profile page, with no additional verification. No step-up authentication, no session age check, no re-authentication, and no verification that the session hasn't been hijacked since creation. This violates the requirement for multiple layers of security for administrative interfaces.

**Remediation:**

Implement async def require_recent_auth(max_age_seconds=300) that checks the session's auth_time and requires re-authentication if the session is older than the specified threshold (e.g., 5 minutes for sensitive operations). Apply this check to all irreversible administrative operations including do_open_endpoint, do_close_endpoint, and do_delete_issue_endpoint. Store auth_time in session at login and validate it before critical operations.

---

#### FINDING-029: HTML Attribute Injection in doc: Filename Pattern

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1, L2 |
| **CWE** | CWE-79 |
| **ASVS Sections** | 1.2.1, 1.3.1, 1.2.2, 5.3.2, 5.4.2 |
| **Files** | v3/server/pages.py:52-60, v3/server/pages.py:66 |
| **Source Reports** | 1.2.1.md, 1.3.1.md, 1.2.2.md, 5.3.2.md, 5.4.2.md |
| **Related Findings** | FINDING-118, FINDING-119, FINDING-133 |

**Description:**

The `rewrite_description()` function extracts filenames from issue descriptions using a regex pattern `doc:([^\s]+)` and constructs URL paths without sanitization. While filenames originate from authorized users (committers storing issue descriptions), a malicious committer could craft a description containing path traversal sequences in the `doc:` pattern. A committer could store an issue description containing `doc:../../sensitive-file` which generates a link to `/docs/<iid>/../../sensitive-file`. When a voter clicks this link, it would be handled by `serve_doc()` where framework-level safe_join would prevent traversal, but the link itself could confuse users or be used in social engineering.

**Remediation:**

Validate extracted filenames against a safe pattern and HTML-encode them. Example implementation: python
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
        return f'&lt;a href="/docs/{issue.iid}/{safe_filename}"&gt;{safe_filename}&lt;/a&gt;'
    desc = re.sub(r'doc:([^\s]+)', repl, desc)
    issue.description = f'&lt;pre&gt;{desc}&lt;/pre&gt;'

---

#### FINDING-030: Missing vote string validation before encryption and storage

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1, L2 |
| **CWE** | N/A |
| **ASVS Sections** | 1.3.3, 2.2.1, 2.3.2, 16.5.3 |
| **Files** | v3/steve/election.py:243 |
| **Source Reports** | 1.3.3.md, 2.2.1.md, 2.3.2.md, 16.5.3.md |
| **Related Findings** | None |

**Description:**

The comment '### validate VOTESTRING for ISSUE.TYPE voting' explicitly acknowledges that vote format validation is not implemented. For YNA issues, the votestring should be constrained to valid options (e.g., 'yes', 'no', 'abstain'). For STV issues, the votestring should be a valid ranking format. Without validation, arbitrary strings are encrypted and stored. This is a fail-open condition — the validation logic is commented as TODO, meaning transactions proceed despite the absence of critical validation. Impact: Corrupted tally results if vtypes.tally() cannot handle invalid vote strings, Potential DoS if the tally function crashes on malformed votes, Election integrity compromised if invalid votes are counted.

**Remediation:**

def add_vote(self, pid: str, iid: str, votestring: str): md = self._all_metadata(self.S_OPEN); issue = self.q_get_issue.first_row(iid); if not issue: raise IssueNotFound(iid); m = vtypes.vtype_module(issue.type); if not m.validate_vote(votestring, self.json2kv(issue.kv)): raise InvalidVote(f'Invalid vote format for type {issue.type}'); mayvote = self.q_get_mayvote.first_row(pid, iid); if not mayvote: raise VoterNotAuthorized(pid, iid); ...

---

#### FINDING-031: User-supplied scriptable content not sanitized in issue descriptions

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 1.3.5 |
| **Files** | v3/server/pages.py:60-70, v3/server/pages.py:299 |
| **Source Reports** | 1.3.5.md |
| **Related Findings** | None |

**Description:**

The `doc:filename` pattern is a custom expression/template language within user content. The application processes this pattern to generate HTML links but: 1. Does not sanitize or disable other potentially dangerous patterns 2. Does not strip HTML/CSS/JavaScript from the description 3. The raw user content (minus `doc:` substitution) is rendered as HTML in the browser. User-supplied content is rendered as active HTML, allowing CSS injection (visual manipulation, data exfiltration via CSS selectors), HTML injection (phishing content), and script injection (full XSS as covered in 1.3.1).

**Remediation:**

Implement HTML sanitization: First, escape ALL HTML in the description using html.escape(). Then safely process the doc: pattern on the escaped content. Ensure filenames are URL-encoded when placed in href attributes. Example: python
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
        return f'&lt;a href="/docs/{issue.iid}/{url_filename}"&gt;{safe_filename}&lt;/a&gt;'
    desc = re.sub(r'doc:([^\s]+)', repl, desc)
    
    issue.description = f'&lt;pre&gt;{desc}&lt;/pre&gt;'

---

#### FINDING-032: Document filename (docname) relies solely on framework protection without explicit validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 2.2.1 |
| **Files** | v3/server/pages.py:560-574 |
| **Source Reports** | 2.2.1.md |
| **Related Findings** | None |

**Description:**

The endpoint serves files based on user-supplied `iid` and `docname` parameters. While `send_from_directory` provides framework-level path traversal protection, the code explicitly acknowledges missing validation with a TODO comment. The `iid` parameter constructs a directory path (`DOCSDIR / iid`) without validating that `iid` is actually a valid 10-char hex string. Additionally, `docname` could contain special characters, encoded sequences, or be a symlink target if the filesystem allows. Depending on framework version and edge cases, this could lead to unauthorized file access outside the intended document directory.

**Remediation:**

Implement explicit validation for `docname` using an allowlist pattern. Reject hidden files and directory traversal attempts. Example: `VALID_DOCNAME = re.compile(r'^[a-zA-Z0-9_\-][a-zA-Z0-9_\-\.]{0,254}$'); if not VALID_DOCNAME.match(docname): quart.abort(400); if docname.startswith('.') or '..' in docname: quart.abort(400)`

---

#### FINDING-033: No validation that close_at is after open_at when setting dates

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 2.2.3 |
| **Files** | v3/server/pages.py:88-110, v3/steve/election.py:null |
| **Source Reports** | 2.2.3.md |
| **Related Findings** | None |

**Description:**

When setting open_at or close_at dates, the application does not validate the logical relationship between them. Users can set close_at to Jan 1, 2024 and then set open_at to Feb 1, 2024, resulting in close_at < open_at which is logically inconsistent. The _set_election_date() function accepts date values independently without checking against the other date field.

**Remediation:**

Validate cross-field consistency by checking that open_at is before close_at when setting either field. Retrieve the existing date value for the other field and compare before allowing the update. Return a 400 error if the new date would create an invalid combination.

---

#### FINDING-034: User-uploaded documents served inline without Content-Disposition header

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1, L2 |
| **CWE** | CWE-646 |
| **ASVS Sections** | 3.2.1, 5.4.1 |
| **Files** | v3/server/pages.py:621-635 |
| **Source Reports** | 3.2.1.md, 5.4.1.md |
| **Related Findings** | None |

**Description:**

The serve_doc() endpoint accepts a user-submitted filename via the docname URL parameter and uses it directly to serve files. There is no validation or sanitization of this filename, and no explicit Content-Disposition header is set in the response to override the user-controlled filename. The framework's default behavior uses the actual file's name for Content-Type inference, but the URL-visible filename remains user-controlled. Without explicit filename validation: 1) The Content-Type of the response is derived from the user-controlled filename extension, which could cause browser behavior differences, 2) If the response includes a Content-Disposition header, the user-controlled filename could contain injection characters, 3) The lack of explicit Content-Disposition means the browser uses the URL's filename segment for Save As operations.

**Remediation:**

Implement explicit filename validation using an allowlist regex (e.g., ^[a-zA-Z0-9][a-zA-Z0-9._-]*$) and reject requests with invalid filenames. Serve files with explicit Content-Disposition header using as_attachment=True in send_from_directory(). Add X-Content-Type-Options: nosniff header for defense-in-depth. Implement file extension allowlist to only serve known-safe extensions (.pdf, .txt, .md, etc.) and prevent serving executable or HTML content.

---

#### FINDING-035: JavaScript String Injection in STV_CANDIDATES Object

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 3.2.2 |
| **Files** | v3/server/templates/vote-on.ezt:280-295 |
| **Source Reports** | 3.2.2.md |
| **Related Findings** | None |

**Description:**

The template renders issue titles, candidate labels, and candidate names directly into JavaScript string literals WITHOUT using EZT's `[format "js,html"]` escape filter. If any of these values contain a double-quote, backslash, or newline, they break out of the string context. Database values (issue title, candidate label/name) flow through EZT template rendering without JS escaping into an inline &lt;script&gt; block, creating JavaScript string literal injection.

**Remediation:**

Replace innerHTML with DOM manipulation using textContent: `function makeItem(candidate, rank) { const div = document.createElement('div'); div.className = 'stv-item'; div.dataset.label = candidate.label; if (rank) div.dataset.rank = rank; const handle = document.createElement('span'); handle.className = 'drag-handle bi bi-grip-vertical'; const nameSpan = document.createElement('span'); nameSpan.className = 'cand-name'; nameSpan.textContent = candidate.name;  // Safe text rendering div.appendChild(handle); div.appendChild(nameSpan); div.addEventListener('dblclick', () => moveItem(div)); return div; }`

---

#### FINDING-036: XSS via Unescaped Flash Messages

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 3.2.2 |
| **Files** | v3/server/templates/flashes.ezt:1-6, v3/server/pages.py:489, v3/server/pages.py:547, v3/server/pages.py:570, v3/server/pages.py:589, v3/server/pages.py:453, v3/server/pages.py:465 |
| **Source Reports** | 3.2.2.md |
| **Related Findings** | None |

**Description:**

User form input (election titles, issue titles) flows through flash_success() into session storage, then get_flashed_messages(), and is rendered via [flashes.message] in template without escaping as raw HTML. Multiple flash message sources in pages.py include user input without sanitization, including form.title and iid values.

**Remediation:**

Either HTML-escape flash messages in the template: `[for flashes] <div class="alert alert-[flashes.category] alert-dismissible fade show" role="alert"> [format "html"][flashes.message][end] <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button> </div> [end]` Or sanitize input before passing to flash functions: `from markupsafe import escape; await flash_success(f'Created election: {escape(form.title)}')`

---

#### FINDING-037: Missing Cookie Secure Attribute and Prefix Configuration

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1, L2 |
| **CWE** | N/A |
| **ASVS Sections** | 3.3.1, 3.3.2 |
| **Files** | v3/server/pages.py:null, v3/server/main.py:null |
| **Source Reports** | 3.3.1.md, 3.3.2.md |
| **Related Findings** | None |

**Description:**

No session cookie configuration is visible in the provided codebase. The application delegates session management to `asfquart.session`, but there is no evidence that cookies are configured with the `Secure` attribute or use the `__Host-` or `__Secure-` prefix. Without the `Secure` attribute, session cookies could be transmitted over unencrypted HTTP connections (e.g., if a user accesses the site via HTTP before being redirected to HTTPS, or in a man-in-the-middle scenario). Without `__Host-` or `__Secure-` prefix, cookies lack additional protections against injection from subdomains.

**Remediation:**

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

Note: If `asfquart` handles this internally with secure defaults, verify the framework configuration. Given the critical nature of session cookies for a voting system, explicit configuration is recommended.

#### FINDING-038: No Strict-Transport-Security (HSTS) header configured

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L1, L2 |
| CWE | - |
| ASVS Sections | 3.4.1 |
| Files | v3/server/main.py (entire file), v3/server/pages.py (entire file) |
| Source Reports | 3.4.1.md |
| Related Findings | - |

**Description:**

No Strict-Transport-Security (HSTS) header is configured anywhere in the application. Despite TLS being configured in `config.yaml.example`, there is no `@APP.after_request` handler, middleware, or framework configuration that adds an HSTS header to responses. This is a Type A gap — the control is completely absent. Without HSTS, SSL stripping attacks are possible on initial connections, users can be downgraded from HTTPS to HTTP by a network attacker, and this is especially critical for a voting application where ballot integrity and voter authentication depend on transport security. ASVS Level 2 requires `includeSubDomains` directive which is also missing.

**Remediation:**

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

---

#### FINDING-039: No Content-Security-Policy header configured

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2, L3 |
| CWE | CWE-1021 |
| ASVS Sections | 3.4.3, 3.4.7 |
| Files | v3/server/main.py (entire file), v3/server/pages.py (entire file), v3/server/templates/header.ezt (entire file), v3/server/templates/admin.ezt (entire file), v3/server/templates/manage.ezt (entire file), v3/server/templates/vote-on.ezt (entire file), v3/server/templates/voter.ezt (entire file), v3/server/templates/flashes.ezt (entire file) |
| Source Reports | 3.4.3.md, 3.4.7.md |
| Related Findings | - |

**Description:**

No Content-Security-Policy (CSP) header is configured anywhere in the application. This is a Type A gap — the control is completely absent. The application serves HTML pages with extensive inline JavaScript (in manage.ezt, manage-stv.ezt, vote-on.ezt, voter.ezt, admin.ezt) and loads external resources, but has no CSP to restrict script execution sources. Without CSP, there is no defense-in-depth against XSS — any injection becomes script execution. The voting application handles sensitive election operations (vote casting, election management). The ASVS minimum requirement of object-src 'none'; base-uri 'none' is not met. For L2, allowlist or nonce-based script-src is required. Missing object-src 'none' allows Flash/Java plugin attacks. Missing base-uri 'none' allows base tag injection to hijack relative URLs.

**Remediation:**

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

---

#### FINDING-040: Missing X-Content-Type-Options: nosniff header on all HTTP responses

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2, L3 |
| CWE | - |
| ASVS Sections | 3.4.4, 13.4.7 |
| Files | v3/server/main.py (application-wide), v3/server/pages.py (all route handlers) |
| Source Reports | 3.4.4.md, 13.4.7.md |
| Related Findings | - |

**Description:**

There is no middleware, after_request handler, or framework configuration in any of the provided source files that adds the X-Content-Type-Options: nosniff header to HTTP responses. This applies to all endpoints: HTML pages (home_page, voter_page, manage_page, etc.), static files served via serve_static(), and document files served via serve_doc(). Without this header, a browser may MIME-sniff the response body and interpret it as a different content type (e.g., treating a text file as executable JavaScript), enabling content-type confusion attacks. The /docs/&lt;iid&gt;/&lt;docname&gt; endpoint is particularly at risk as it serves user-uploaded documents.

**Remediation:**

Add after_request handler to set X-Content-Type-Options: nosniff header on all responses. Example: @app.after_request async def security_headers(response): response.headers['X-Content-Type-Options'] = 'nosniff'; return response

---

#### FINDING-041: Missing Content-Security-Policy frame-ancestors directive enables clickjacking attacks

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 3.4.6 |
| Files | v3/server/main.py (application-wide), v3/server/pages.py (all HTML-rendering routes) |
| Source Reports | 3.4.6.md |
| Related Findings | - |

**Description:**

No Content-Security-Policy header with a frame-ancestors directive is set on any HTTP response. There is also no X-Frame-Options header (which is noted as obsolete in the requirement but would provide backward compatibility). This affects all page endpoints: /, /voter, /admin, /manage/&lt;eid&gt;, /vote-on/&lt;eid&gt;, etc. An attacker can embed any page from this application in an iframe on their malicious site, enabling clickjacking attacks. This is particularly critical for the voting interface (/vote-on/&lt;eid&gt;) where an attacker could overlay transparent iframes to trick users into submitting votes.

**Remediation:**

Add an after_request handler to set the Content-Security-Policy header with frame-ancestors directive:

```python
@app.after_request
async def set_security_headers(response):
    response.headers['Content-Security-Policy'] = "frame-ancestors 'none'"
    return response
```

---

#### FINDING-042: Sensitive POST Endpoints Accept CORS-Safelisted Content Types Without Preflight Protection

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Sections | 3.5.2 |
| Files | v3/server/pages.py (405), v3/server/pages.py (451), v3/server/pages.py (507), v3/server/pages.py (529), v3/server/pages.py (551) |
| Source Reports | 3.5.2.md |
| Related Findings | - |

**Description:**

All sensitive POST endpoints consume application/x-www-form-urlencoded form data, which is a CORS-safelisted content type. Requests with this content type do NOT trigger a CORS preflight check. Combined with the non-functional CSRF token (basic.csrf_token = 'placeholder' with no server-side validation), cross-origin requests to these endpoints will be processed by the server. The application has no Origin header validation, custom header requirement, validated CSRF token, or Content-Type: application/json enforcement on form endpoints. An attacker can forge cross-origin requests to cast votes, create elections, add/edit/delete issues on behalf of an authenticated user who visits a malicious page.

**Remediation:**

Implement Origin header validation to verify the Origin header matches the expected application origin. Alternatively, require a custom header that forces preflight (e.g., X-Requested-With). Example: Create a validate_origin() function that checks the Origin header against allowed_origins and aborts with 403 if invalid. Or use a before_request hook to check for custom headers on POST/PUT/DELETE/PATCH requests.

---

#### FINDING-043: No Cross-Origin-Resource-Policy Response Header on Any Endpoint

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 3.5.8 |
| Files | v3/server/pages.py |
| Source Reports | 3.5.8.md |
| Related Findings | - |

**Description:**

No Cross-Origin-Resource-Policy (CORP) header is set on any response throughout the application. All endpoints including serve_static(), serve_doc(), and template-rendered responses lack this defensive header. Without CORP headers, the browser cannot block cross-origin resource loads. External pages can embed resources like &lt;script src="https://steve.example.org/static/js/steve.js"&gt; to probe application JavaScript structure, or use &lt;img&gt; tags to determine authenticated state via resource load timing. Static resources expose application structure; authenticated resources expose sensitive data.

**Remediation:**

Add an @APP.after_request handler to set security headers on all responses. Set Cross-Origin-Resource-Policy: same-origin to restrict resources to same-origin only. Also add Cross-Origin-Opener-Policy: same-origin to block cross-origin opener/embedder access. Example: create security_headers() function decorated with @APP.after_request that adds response.headers['Cross-Origin-Resource-Policy'] = 'same-origin' and response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'.

---

#### FINDING-044: No Strict-Transport-Security Header Configuration and No HSTS Preload

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L3, L2 |
| CWE | - |
| ASVS Sections | 3.7.4, 3.7.5 |
| Files | v3/server/pages.py (entire file), v3/server/main.py (entire file), v3/server/config.yaml.example |
| Source Reports | 3.7.4.md, 3.7.5.md |
| Related Findings | - |

**Description:**

Client connects → server responds without `Strict-Transport-Security` header → browser does not enforce HTTPS → domain not on HSTS preload list → first-connection vulnerable to downgrade. Without HSTS preload, the very first connection to the application can be intercepted via SSL stripping attacks. For a voting application handling ballot submissions, this could allow an attacker to intercept votes, session cookies, or serve a fraudulent voting page. The configuration explicitly allows plain HTTP operation (`leave these two fields blank for plain HTTP`).

**Remediation:**

Add HSTS header to all responses using @APP.after_request decorator with 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload'. Additionally: (1) Submit the domain to https://hstspreload.org for inclusion in browser preload lists, (2) Remove the option for plain HTTP operation in production configurations, (3) Add configuration validation that rejects missing TLS certificates in production mode.

---

#### FINDING-045: No Browser Feature Detection or User Warning

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 3.7.5 |
| Files | v3/server/templates/header.ezt (all), v3/server/templates/footer.ezt (all), v3/server/templates/vote-on.ezt (all), v3/server/templates/manage.ezt (all), v3/server/pages.py (all) |
| Source Reports | 3.7.5.md |
| Related Findings | - |

**Description:**

The application uses modern browser features that are critical for its security and functionality but provides no detection mechanism or warning when these features are unavailable. Required browser features used without detection include: JavaScript (ES6+) with arrow functions, template literals, const/let, destructuring, Set, Array.from(); Fetch API used in manage.ezt for AJAX date saving; SortableJS/Drag-and-Drop critical for STV vote ranking in vote-on.ezt; and Bootstrap 5 JavaScript for modals, toasts, tabs required for all user interactions. Users with JavaScript disabled see a non-functional page with no explanation. Browsers lacking Fetch API will fail silently on date operations. STV vote ranking requires SortableJS and Drag-and-Drop API - failure means votes cannot be cast. An election system where some voters cannot participate due to browser incompatibility undermines democratic integrity.

**Remediation:**

Add &lt;noscript&gt; block immediately after &lt;body&gt; in header.ezt with alert informing users that JavaScript is required and listing minimum browser versions (Chrome 80+, Firefox 78+, Safari 14+, Edge 80+). Implement feature detection script in &lt;head&gt; of header.ezt that checks for required features (fetch, Promise, Symbol, CSS Flexbox) and displays prominent warning when missing. Create DOMContentLoaded event handler that inserts warning div at top of page listing missing features and instructing users to update their browser.

---

#### FINDING-046: Multi-Vote Submission Not Wrapped in Transaction — Partial Failure Leaves Inconsistent State

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2 |
| CWE | CWE-662 |
| ASVS Sections | 2.3.3 |
| Files | v3/server/pages.py (372) |
| Source Reports | 2.3.3.md |
| Related Findings | FINDING-047, FINDING-147 |

**Description:**

User submits ballot with 10 issues → Loop processes votes one by one → Vote #5 fails → Votes #1-4 already committed → User told "error" but partial votes persist. Atomic ballot submission is not guaranteed. A voter's intent is a complete ballot, but partial submission creates an inconsistent state where some issues have new votes and others retain old votes. This violates the principle that business operations should succeed entirely or roll back.

**Remediation:**

Wrap all votes in a single transaction. Use BEGIN TRANSACTION before the loop, COMMIT after successful completion, and ROLLBACK on any exception. Example: election.db.conn.execute('BEGIN TRANSACTION') try: for iid, votestring in votes.items(): if iid not in issue_dict: election.db.conn.execute('ROLLBACK') await flash_danger(f'Invalid issue ID: {iid}') return quart.redirect(f'/vote-on/{election.eid}', code=303) election.add_vote(result.uid, iid, votestring) election.db.conn.execute('COMMIT') except Exception as e: election.db.conn.execute('ROLLBACK') await flash_danger('Error submitting votes. No changes were saved.') return quart.redirect(f'/vote-on/{election.eid}', code=303)

---

#### FINDING-047: Election Open Operation Not Fully Atomic — Salt Addition and State Change in Separate Transactions

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2 |
| CWE | CWE-662 |
| ASVS Sections | 2.3.3 |
| Files | v3/steve/election.py (70) |
| Source Reports | 2.3.3.md |
| Related Findings | FINDING-046, FINDING-147 |

**Description:**

The open() method executes add_salts() which commits its own transaction, then performs c_open.perform() in a separate auto-commit transaction. If an error occurs between add_salts() completing and c_open.perform() succeeding (e.g., disk full, power loss, exception in gather_election_data), the mayvote table has salts set (indicating an opened election) but the election record still shows editable state. Attempting to open again would regenerate salts, invalidating any votes that might have been cast in the interim. The election open operation is not atomic, leaving the database in an inconsistent state that cannot be trivially recovered.

**Remediation:**

Wrap the entire open() operation in a single transaction: self.db.conn.execute('BEGIN TRANSACTION') try: self.q_all_issues.perform(self.eid) for mayvote in self.q_all_issues.fetchall(): salt = crypto.gen_salt() self.c_salt_mayvote.perform(salt, mayvote.rowid) edata = self.gather_election_data(pdb) salt = crypto.gen_salt() opened_key = crypto.gen_opened_key(edata, salt) self.c_open.perform(salt, opened_key, self.eid) self.db.conn.execute('COMMIT') except Exception: self.db.conn.execute('ROLLBACK') raise

---

#### FINDING-048: No Explicit Locking on Election State Transitions — Race Condition on Concurrent Open/Close

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2 |
| CWE | CWE-367 |
| ASVS Sections | 2.3.4 |
| Files | v3/steve/election.py (70), v3/steve/election.py (109) |
| Source Reports | 2.3.4.md |
| Related Findings | - |

**Description:**

The application performs a check-then-act pattern without proper locking in the open() and close() methods. Request A checks is_editable() → True → begins add_salts(). Request B checks is_editable() → True (state not yet changed) → begins add_salts(). Both proceed to open the election with different salts/keys. While SQLite's implicit write serialization may prevent actual data corruption in single-writer scenarios, the application logic does not handle the concurrency case explicitly. In multi-process deployments or with WAL mode, race conditions could lead to: double salt generation (overwriting previous salts), multiple opened_key values being computed, and inconsistent anti-tamper state.

**Remediation:**

Use a single transaction with an immediate lock. Re-check state inside the transaction (with lock held). Wrap all operations in BEGIN IMMEDIATE...COMMIT with proper rollback handling. Example: self.db.conn.execute('BEGIN IMMEDIATE'); re-check state; perform all operations atomically; self.db.conn.execute('COMMIT').

---

#### FINDING-049: TLS Protocol Version Not Explicitly Configured

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Sections | 12.1.1 |
| Files | v3/server/main.py (75-78) |
| Source Reports | 12.1.1.md |
| Related Findings | - |

**Description:**

The application starts with whatever TLS versions the underlying framework (Quart/Hypercorn) defaults to. Without explicit configuration, older TLS versions (TLS 1.0, TLS 1.1) may be negotiable depending on the runtime environment and library versions. Config values are passed directly to app.runx() without any TLS protocol version constraints. An attacker can attempt handshake with deprecated TLS versions using openssl s_client -connect localhost:58383 -tls1_1. If the underlying TLS library allows deprecated TLS versions, the application may be vulnerable to known protocol-level attacks (BEAST, POODLE, etc.). Without explicit minimum version enforcement, there is no guarantee that only TLS 1.2+ is used. TLS 1.3 is not explicitly preferred.

**Remediation:**

Explicitly configure minimum TLS protocol version and prefer TLS 1.3. For Hypercorn (the ASGI server used in run_asgi()), configure via hypercorn.toml or programmatically: Create an SSL context with ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER), ctx.minimum_version = ssl.TLSVersion.TLSv1_2, ctx.maximum_version = ssl.TLSVersion.TLSv1_3, ctx.load_cert_chain(certfile, keyfile). For config.yaml, add server.min_tls_version: "1.2"

---

#### FINDING-050: No Cipher Suite Configuration - Weak Ciphers May Be Negotiated

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2, L3 |
| CWE | - |
| ASVS Sections | 12.1.2 |
| Files | v3/server/main.py (75-82) |
| Source Reports | 12.1.2.md |
| Related Findings | - |

**Description:**

The application has no control over which cipher suites are enabled. Without explicit cipher suite configuration, weak ciphers may be negotiated. Depending on the Python/OpenSSL version, this could allow: Non-forward-secrecy ciphers (e.g., RSA key exchange), Weak encryption algorithms (e.g., 3DES, RC4), Weak hash algorithms in cipher suites (e.g., SHA-1 based MACs). For L3 compliance, the application MUST only support cipher suites providing forward secrecy (ECDHE/DHE key exchange).

**Remediation:**

Create an SSL context with explicit cipher suite configuration: import ssl; def create_ssl_context(certfile, keyfile): ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.minimum_version = ssl.TLSVersion.TLSv1_2; ctx.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS:!RC4:!3DES'); ctx.load_cert_chain(certfile, keyfile); return ctx

---

#### FINDING-051: TLS Configuration is Optional - Application Allows Plaintext HTTP Communication

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L1, L2, L3 |
| CWE | - |
| ASVS Sections | 12.2.1, 12.2.2, 12.3.1, 3.7.4 |
| Files | v3/server/config.yaml.example (6-12), v3/server/config.yaml.example (25-31), v3/server/main.py (72-82), v3/server/main.py (80-84) |
| Source Reports | 12.2.1.md, 12.2.2.md, 12.3.1.md, 3.7.4.md |
| Related Findings | - |

**Description:**

The configuration explicitly documents that TLS can be disabled by leaving certfile and keyfile fields blank. When running without TLS, session cookies are transmitted in cleartext enabling session hijacking, OAuth tokens and credentials are exposed, vote data is transmitted unencrypted, and no mechanism exists to redirect HTTP to HTTPS. No HSTS header enforcement is visible in the code. This is a voting application handling sensitive election data—running without TLS completely undermines confidentiality and integrity.

**Remediation:**

Enforce TLS as mandatory by refusing to start the server without certificates. Implement HTTP-to-HTTPS redirect and HSTS headers. Example: Check if app.cfg.server.certfile or app.cfg.server.keyfile are missing and exit with error. Add @APP.before_request middleware to enforce HTTPS and @APP.after_request middleware to add Strict-Transport-Security header with max-age=31536000 and includeSubDomains. Enforce TLS at startup and fail loudly if certificates are unavailable with critical logging and sys.exit(1).

---

#### FINDING-052: No secrets management solution used; cryptographic keys stored directly in SQLite database

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 13.3.1 |
| Files | v3/steve/election.py, v3/schema.sql (63-72) |
| Source Reports | 13.3.1.md |
| Related Findings | - |

**Description:**

The application stores cryptographic secrets (election salts, opened_keys, mayvote salts, encrypted vote ciphertexts) directly in an unencrypted SQLite database file. There is no key vault or secrets management solution (e.g., HashiCorp Vault, AWS KMS, Azure Key Vault), Hardware Security Module (HSM) integration, encryption at rest for the database file, or access control beyond filesystem permissions on the SQLite file. If the SQLite database file is compromised (backup theft, file system access), all cryptographic material is exposed. The opened_key (32 bytes) is the master key for vote token derivation — its compromise allows vote de-anonymization. Election salts allow regeneration of vote tokens. No audit trail for secret access.

**Remediation:**

Integrate a secrets management solution such as HashiCorp Vault, AWS KMS, or Azure Key Vault to store cryptographic keys separately from the database. Store sensitive key material in vault, not database. Store only references in database. Example implementation: use VaultClient to write salt and opened_key to vault at path 'secret/elections/{eid}' and retrieve them when needed rather than storing directly in SQLite. At minimum, enable SQLite encryption (SQLCipher) for the database file and add database encryption at rest.

---

#### FINDING-053: Cryptographic key material generated and stored without isolated security module

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 13.3.3 |
| Files | v3/steve/crypto.py (43-95), v3/steve/election.py (70-80), v3/steve/election.py (231-243) |
| Source Reports | 13.3.3.md |
| Related Findings | - |

**Description:**

All cryptographic key material (election salts, opened_key, vote encryption keys) is generated, stored, and used entirely within the application process and a SQLite database file on disk. If the application server or database is compromised, all key material is immediately exposed. There is no hardware boundary protecting keys from memory dumps, side-channel attacks, or direct file access. Data flow: Election data → gen_opened_key() in application process memory → stored as BLOB in SQLite election table → retrieved from SQLite for vote encryption/decryption operations. An attacker with read access to the SQLite file can extract opened_key and all mayvote.salt values, then recompute vote_token for any voter/issue pair and decrypt all votes.

**Remediation:**

Integrate with a key management service (KMS) or HSM where cryptographic operations are performed within an isolated security boundary. Example implementation using HashiCorp Vault Transit secrets engine provided in report. Keys should never be exposed to application memory. Operations requiring keys should be delegated to the security module via API calls.

---

#### FINDING-054: Master election key loaded into application memory without process isolation

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 13.3.3 |
| Files | v3/steve/election.py (144-158) |
| Source Reports | 13.3.3.md |
| Related Findings | - |

**Description:**

The opened_key (the master election key material) is loaded into application memory in multiple request paths via the _all_metadata method. The SQLite database returns SALT and OPENED_KEY columns which flow through md object to multiple methods including add_vote, tally_issue, has_voted_upon, and is_tampered. The sensitive key material is only protected by an internal comment (not for public use) with no memory protection, access control at the data layer, or process isolation.

**Remediation:**

Integrate with a key management service (KMS) or HSM where the key never leaves the security boundary. Operations requiring the key should be delegated to the security module via API calls. Eliminate direct loading of key material into application memory.

---

#### FINDING-055: Cryptographic keys and salts have no expiration or rotation mechanism

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 13.3.4 |
| Files | v3/steve/election.py (70-80), v3/schema.sql (48-56) |
| Source Reports | 13.3.4.md |
| Related Findings | - |

**Description:**

Cryptographic keys and salts have no configured expiration or rotation mechanism. Once an election is closed, its key material remains in the database indefinitely, increasing the window for key compromise. The crypto.gen_salt() generates salt stored in election table that never expires or rotates. The crypto.gen_opened_key() generates opened_key stored in election table that persists through open to closed states indefinitely. Even the mayvote.salt values persist forever. If any key is compromised (e.g., through backup theft), there is no mechanism to detect staleness or force rotation. An attacker obtaining an old database backup can decrypt votes from elections that ended months or years ago, since no keys have been rotated or marked expired.

**Remediation:**

Add expiry tracking and rotation support to the Election class. Implement KEY_EXPIRY_DAYS configuration (e.g., 90 days) and check_key_expiry() method to validate key age. Implement rotate_keys_post_close() method to zero out key material after tallying is complete and results are finalized. Add key_created_at and key_expires_at columns to the election table schema to track key lifecycle. After election finalization, remove or re-encrypt key material. Implement automated cleanup of secrets past their useful life.

---

#### FINDING-056: No Cache-Control headers on pages serving sensitive election and voter data

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2, L3 |
| CWE | - |
| ASVS Sections | 14.2.2, 14.3.2, 14.2.5, 14.3.3 |
| Files | v3/server/pages.py (ALL route handlers returning sensitive data) |
| Source Reports | 14.2.2.md, 14.3.2.md, 14.2.5.md, 14.3.3.md |
| Related Findings | - |

**Description:**

None of the route handlers set Cache-Control, Pragma, or Expires headers to prevent caching of sensitive pages. Pages containing voter eligibility status, election configuration, vote submission forms, and election documents could be cached by intermediate proxies, CDNs, load balancers, or browser caches. Affected endpoints include GET /voter (voter's elections, voting status), GET /vote-on/&lt;eid&gt; (election issues, candidate lists, voting form), GET /admin (owned elections list), GET /manage/&lt;eid&gt; (election metadata, issue list), GET /manage-stv/&lt;eid&gt;/&lt;iid&gt; (STV issue details), GET /docs/&lt;iid&gt;/&lt;docname&gt; (election documents), and POST /do-vote/&lt;eid&gt; redirect response (flash message confirming vote). Data flow: Server generates page with sensitive election data → Response sent without cache-control headers → Intermediate proxy/browser caches response → Cached sensitive data accessible to subsequent requests or shared computer users.

**Remediation:**

Add a middleware or decorator that sets anti-caching headers on all authenticated routes. Use @APP.after_request to add Cache-Control: no-store, no-cache, must-revalidate, max-age=0, Pragma: no-cache, and Expires: 0 headers to all non-static responses. Alternatively, create a no_cache decorator for specific sensitive endpoints that sets Cache-Control: no-store and Pragma: no-cache headers on responses.

---

#### FINDING-057: No documented risk-based remediation timeframes for third-party component vulnerabilities

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Sections | 15.1.1 |
| Files | v3/steve/crypto.py, v3/steve/election.py, v3/server/main.py |
| Source Reports | 15.1.1.md |
| Related Findings | - |

**Description:**

The provided codebase contains multiple third-party dependencies (cryptography, argon2-cffi, asfpy, easydict, Quart/asfquart, ezt) but no documentation defining risk-based remediation timeframes for addressing vulnerabilities or specifying update cadence for these libraries. No SECURITY.md, DEPENDENCY_POLICY.md, or equivalent documentation is present that defines: Critical vulnerability remediation timeframe (e.g., 24-48 hours), High vulnerability remediation timeframe (e.g., 7 days), Medium/Low vulnerability remediation timeframe (e.g., 30-90 days), or Routine update schedule for non-vulnerable components.

**Remediation:**

Create a docs/DEPENDENCY_POLICY.md with explicit timeframes defining remediation windows for Critical (48 hours), High (7 days), Medium (30 days), and Low (90 days) severity vulnerabilities. Include routine update schedules: Security-critical libraries (cryptography, argon2-cffi) monthly review, Framework libraries (Quart/asfquart) quarterly review, Utility libraries (easydict, asfpy) semi-annual review. Implement automated CVE monitoring via GitHub Dependabot/Safety/pip-audit and manual review of security advisories for cryptography library.

---

#### FINDING-058: No Software Bill of Materials (SBOM) or dependency manifest with pinned versions

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 15.1.2 |
| Files | Project-wide, main.py, crypto.py, election.py |
| Source Reports | 15.1.2.md |
| Related Findings | - |

**Description:**

The provided codebase does not include a visible `requirements.txt`, `pyproject.toml` with pinned dependencies, `Pipfile.lock`, `uv.lock`, or any SBOM document (e.g., CycloneDX or SPDX format). While `main.py` uses a `uv run --script` shebang suggesting `uv` as the package manager, no lock file or dependency specification with version pins is provided. Identified dependencies from code analysis: `cryptography` (Fernet, HKDF, hashes) from `crypto.py`, `argon2-cffi` (low_level) from `crypto.py`, `asfpy` (db, generics) from `election.py` and `main.py`, `easydict` from `election.py`, `asfquart` (Quart wrapper) from `main.py`, and `ezt` (templating) from domain context. All versions are unknown. Without a versioned inventory: transitive dependencies are untracked (e.g., `cryptography` pulls in `cffi`, `pycparser`), reproducible builds are not guaranteed, vulnerability scanning tools cannot accurately assess the dependency tree, and there is no verification that dependencies come from trusted repositories.

**Remediation:**

1. Create a `pyproject.toml` with pinned dependencies including cryptography>=43.0.0, argon2-cffi>=23.1.0, asfpy>=0.45, easydict>=1.13, quart>=0.19.0, ezt>=1.2. 2. Generate and maintain a lock file using `uv lock`. 3. Generate SBOM in CycloneDX format using `cyclonedx-py environment -o sbom.json`. 4. Configure automated SBOM generation in CI/CD pipeline.

---

#### FINDING-059: Undocumented resource-intensive Argon2 operations with potential denial-of-service impact

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 15.1.3 |
| Files | v3/steve/crypto.py (91-101), v3/steve/election.py (265-324) |
| Source Reports | 15.1.3.md |
| Related Findings | - |

**Description:**

The application contains several resource-demanding operations involving Argon2 key derivation that are not documented. Each Argon2 call allocates 64MB of memory. Critical operations include: (1) _hash() function with memory_cost=65536 KiB (64MB per call), (2) tally_issue() which iterates over ALL eligible voters calling gen_vote_token() (which calls _hash()) for each voter, (3) add_salts() which generates a salt for every person/issue combination in a single transaction, (4) open() which calls both add_salts() and gen_opened_key(), and (5) add_vote() which requires gen_vote_token() (Argon2) plus Fernet encryption per vote submission. For an election with 1000 voters and 10 issues, tally_issue() requires 1000 Argon2 calls with potential 64GB aggregate memory demand, add_salts() requires 10,000 salt generations, and concurrent vote submissions each require 64MB memory. There is no documentation of these resource demands, no documented rate limiting or queuing strategy, no consumer timeout guidance, and no documentation of maximum supported election size. Without documentation and mitigation, a large election's tally_issue() could exceed request timeouts, concurrent vote submissions during peak periods could exhaust server memory, and operators have no guidance for capacity planning.

**Remediation:**

Create docs/RESOURCE_ANALYSIS.md documenting: (1) Argon2 Key Derivation - Memory: 64MB per operation, CPU: ~50ms per operation (2 iterations, 4 threads), Locations: Vote submission, tally computation, election opening; (2) Tally Computation - Complexity: O(voters × issues) Argon2 operations, Mitigation: Performed offline via admin CLI (not web request), Timeout: Not applicable (CLI operation); (3) Vote Submission - Complexity: 1 Argon2 operation per vote, Mitigation: Single-instance deployment limits concurrency, Max concurrent: Limited by server memory (e.g., 16GB / 64MB = 250 concurrent); (4) Election Opening - Complexity: O(voters × issues) salt generations + 1 Argon2, Mitigation: Admin-only operation, performed once per election lifecycle; (5) Defenses - Tally is an admin CLI operation not exposed to web requests, Vote submission is authenticated (prevents anonymous DoS), Single-instance architecture limits parallelism naturally.

---

#### FINDING-060: Cannot verify component versions are within remediation timeframes due to missing version specifications

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Sections | 15.2.1 |
| Files | v3/steve/crypto.py, Project-wide |
| Source Reports | 15.2.1.md |
| Related Findings | - |

**Description:**

Since no dependency manifest with pinned versions exists (as identified in ASVS-15.1.2), and no remediation policy exists (as identified in ASVS-15.1.1), it is impossible to verify that all components are within their documented update and remediation timeframes. Specific concerns: 1) cryptography library has frequent security advisories and without pinned version cannot verify currency; 2) Argon2 Type.D usage while OWASP recommends Type.ID for password hashing, with divergence between benchmark (Type.ID) and production (Type.D); 3) asfpy ASF-internal library with unknown release cadence and vulnerability tracking; 4) HKDF info parameter mismatch (info=b'xchacha20_key') is misleading for current Fernet usage, suggesting code may be in transitional state beyond intended timeframe.

**Remediation:**

1. Pin all dependency versions in pyproject.toml or equivalent. 2. Implement automated vulnerability scanning using pip-audit --require-hashes --desc or uv pip audit in CI/CD pipeline. 3. Create a dependency update log documenting Date, Component, From Version, To Version, and Reason for all updates.

---

#### FINDING-061: No logging inventory or documentation exists for the application stack

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 16.1.1 |
| Files | v3/server/bin/tally.py (165), v3/server/pages.py (37), v3/steve/election.py (27) |
| Source Reports | 16.1.1.md |
| Related Findings | - |

**Description:**

The application uses Python's standard `logging` module across three layers (web pages, election library, CLI tools) but no logging inventory document exists defining: What events are logged at each layer, the log format specification, where logs are stored (file, syslog, SIEM), how log access is controlled, log retention periods, and how logs are consumed for monitoring/alerting. The `logging.basicConfig(level=logging.INFO)` in `tally.py` sends to stderr by default. The web layer (`pages.py`) relies on whatever the application framework configures, which is undocumented. The `election.py` library logs to a logger with no explicit handler configuration.

**Remediation:**

Create a `LOGGING_INVENTORY.md` or equivalent documentation covering all layers, components, logger names, events logged, format, destination, retention, and access control. Document each layer (Web/pages.py, Library/election.py, CLI/tally.py) with structured information including JSON formatted logs, specific file destinations, 90-day to 1-year retention periods, and appropriate file permissions (root:adm 640).

---

#### FINDING-062: Election library logging omits WHO (actor) metadata from security events

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 16.2.1 |
| Files | v3/steve/election.py (207), v3/steve/election.py (219), v3/steve/election.py (231), v3/steve/election.py (430) |
| Source Reports | 16.2.1.md |
| Related Findings | - |

**Description:**

The `election.py` library logs creation, update, and state-change events without recording WHO performed the action. While `pages.py` adds user context at the handler level, the library-level logs are missing the actor (PID/UID). If the library is invoked through a different path (e.g., `tally.py`, future APIs, or direct imports), the WHO metadata is entirely absent. During incident investigation, it becomes impossible to correlate library-level events with the user who triggered them. This creates blind spots in the audit trail, especially for operations that bypass the web layer (CLI tools, scripts, direct database manipulation).

**Remediation:**

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

---

#### FINDING-063: Tally script performs security-critical operations without audit logging

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 16.2.1, 16.4.3 |
| Files | v3/server/bin/tally.py (138-165) |
| Source Reports | 16.2.1.md, 16.4.3.md |
| Related Findings | - |

**Description:**

The tally script decrypts all votes for an election—one of the most sensitive operations in the system—without logging WHO (which administrator ran the tally), WHEN (timestamp of tally execution), WHERE (from which machine/terminal), or WHAT (which election was tallied, whether `--spy-on-open-elections` was used). The `--spy-on-open-elections` flag is especially concerning as it enables viewing votes before an election closes, and its use is not logged at all. An administrator could spy on open election results without any audit trail. Tamper detection events are output via `print()` rather than formal security logging, meaning they may not reach monitoring systems.

**Remediation:**

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

---

#### FINDING-064: Debug print statements dump complete form data which may contain sensitive election configuration

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 16.2.5 |
| Files | v3/server/pages.py (427), v3/server/pages.py (449) |
| Source Reports | 16.2.5.md |
| Related Findings | - |

**Description:**

Complete form data is dumped to stdout without any filtering or redaction. While current form fields are `title` and `description`, the EasyDict wrapper captures ALL submitted form fields. If future forms include sensitive data (candidate names for confidential elections, authorization groups, etc.), this would log them without protection. The `print()` call is a Type B gap—the `_LOGGER` system exists but is not used here, creating false confidence that logging is controlled. Any data submitted in these forms is broadcast to stdout without classification-based filtering. In containerized deployments, stdout is captured by orchestrators and may be accessible to operators without appropriate clearance.

**Remediation:**

Remove print statements entirely, or log only safe metadata: `_LOGGER.debug(f'Issue form received: fields={list(form.keys())}')`. Never log form values for election management operations.

---

#### FINDING-065: No Authentication Event Logging in Application Code

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 16.3.1 |
| Files | v3/server/pages.py (entire file) |
| Source Reports | 16.3.1.md |
| Related Findings | - |

**Description:**

The application relies on `asfquart.auth.require` decorators for authentication enforcement, but no logging occurs at the authentication boundary within this application code. There is no evidence of authentication success or failure being logged. Authentication successes and failures are invisible to security monitoring. Brute force attempts, credential stuffing, or unauthorized access patterns cannot be detected through application logs.

**Remediation:**

Add authentication event logging middleware or hook:
```python
# Add authentication event logging middleware or hook
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

---

#### FINDING-066: Tampering Detection Does Not Use Logger

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 16.3.3, 16.3.4 |
| Files | v3/server/bin/tally.py (153-156) |
| Source Reports | 16.3.3.md, 16.3.4.md |
| Related Findings | - |

**Description:**

The tamper detection check uses print() instead of the logging framework when tampering is detected — a critical security event. Tampering detected → print() to stdout → potentially lost if stdout is not captured → NO structured security log. Critical tampering events may not reach centralized logging systems. A print() to stdout may be lost if the process output is not captured, and it lacks structured metadata (timestamp format, severity, correlation IDs).

**Remediation:**

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

---

#### FINDING-067: Input Validation Failures Not Logged

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 16.3.3 |
| Files | v3/server/pages.py (95-102), v3/server/pages.py (385), v3/server/pages.py (393) |
| Source Reports | 16.3.3.md |
| Related Findings | - |

**Description:**

Input validation failures (potential bypass attempts) are not logged. Malformed input → validation failure → 400 response → NO LOG. This affects multiple endpoints including _set_election_date (lines 95-102), do_vote_endpoint (line 385: missing form data check), and do_vote_endpoint (line 393: invalid issue ID check). Injection attempts would be caught by validation but leave no audit trail.

**Remediation:**

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

#### FINDING-068: No log transmission to a logically separate system

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Section(s)** | 16.4.3 |
| **Files** | v3/server/pages.py:35, v3/steve/election.py:7, v3/server/bin/tally.py:34, v3/server/bin/tally.py:166 |
| **Source Reports** | 16.4.3.md |
| **Related** | - |

**Description:**

The entire application uses Python's standard logging module with no configuration for transmitting logs to a logically separate system. The tally.py CLI configures logging.basicConfig(level=logging.INFO) which outputs to stderr only. The web application (pages.py) relies on Quart's default logging configuration, which similarly only writes locally. There is no evidence of: Syslog forwarding configuration (e.g., SysLogHandler), Integration with centralized log management (ELK, Splunk, CloudWatch), Log shipping agents or sidecars configured, Remote logging handlers (SocketHandler, HTTPHandler), Any log output to files that could be shipped. If the application server is compromised, all security-relevant logs (authentication events, vote casting, election lifecycle changes, authorization failures) reside on the same system and can be modified or deleted by an attacker, destroying forensic evidence.

**Remediation:**

Configure remote logging handlers to send logs to a logically separate system. Example implementation: import logging.handlers and configure SysLogHandler to send to remote syslog/log aggregator at address ('logserver.internal.example.org', 514) with facility LOG_AUTH. Set appropriate formatter with timestamp, name, levelname, and message fields.

---

#### FINDING-069: No graceful degradation for database connectivity failures

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Section(s)** | 16.5.2 |
| **Files** | v3/server/pages.py:all route handlers, v3/steve/election.py:38 |
| **Source Reports** | 16.5.2.md |
| **Related** | - |

**Description:**

The load_election and load_election_issue decorators only catch ElectionNotFound exceptions. If the SQLite database file is locked, corrupted, or unavailable (disk full, permissions changed, etc.), an unhandled exception propagates to the framework's default error handler. There is no circuit breaker, retry logic, or graceful degradation pattern. This affects ALL routes that use load_election or load_election_issue: GET /vote-on/&lt;eid&gt;, GET /manage/&lt;eid&gt;, GET /manage-stv/&lt;eid&gt;/&lt;iid&gt;, POST /do-set-open_at/&lt;eid&gt;, POST /do-set-close_at/&lt;eid&gt;, POST /do-vote/&lt;eid&gt;, GET /do-open/&lt;eid&gt;, GET /do-close/&lt;eid&gt;, POST /do-add-issue/&lt;eid&gt;, POST /do-edit-issue/&lt;eid&gt;/&lt;iid&gt;, POST /do-delete-issue/&lt;eid&gt;/&lt;iid&gt;. Additionally affected without any decorator protection: GET /voter (directly calls Election.open_to_pid), GET /admin (directly calls Election.open_to_pid, Election.owned_elections). Database lock contention, disk failures, or resource exhaustion causes unhandled exceptions across all endpoints, potentially exposing error details and causing service unavailability without informative user messaging.

**Remediation:**

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

---

#### FINDING-070: Implicit authorization failure via None dereference instead of explicit check in add_vote

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Section(s)** | 16.5.3 |
| **Files** | v3/steve/election.py:210-211 |
| **Source Reports** | 16.5.3.md |
| **Related** | - |

**Description:**

When a person is not authorized to vote on a specific issue (no mayvote entry exists), the query returns None. The code immediately accesses mayvote.salt without checking for None. This results in an AttributeError rather than a proper authorization denial. While the vote IS blocked (fail-closed), the error response is a generic 500 rather than a proper 403 Forbidden, and the exception may expose details. While this is technically fail-closed (the vote is not accepted), it represents a fragile security boundary that depends on an accidental crash rather than intentional enforcement. The 500 error also provides no useful feedback to the caller.

**Remediation:**

```python
mayvote = self.q_get_mayvote.first_row(pid, iid)
if mayvote is None:
    raise VoterNotAuthorized(f'Person {pid} is not authorized to vote on issue {iid}')
vote_token = crypto.gen_vote_token(md.opened_key, pid, iid, mayvote.salt)
```

---

#### FINDING-071: No global exception handler defined for the web application

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Section(s)** | 16.5.4 |
| **Files** | v3/server/pages.py:entire file |
| **Source Reports** | 16.5.4.md |
| **Related** | - |

**Description:**

The application defines no "last resort" error handler. There is no @APP.errorhandler(Exception), @APP.errorhandler(500), or equivalent catch-all that would: 1. Log the full exception details for debugging, 2. Return a generic error page to the user, 3. Prevent the application process from crashing on unexpected exceptions. Only ElectionNotFound, IssueNotFound, and PersonNotFound are caught in specific locations. Any other exception type (e.g., sqlite3.OperationalError, TypeError, KeyError, json.JSONDecodeError) propagates to the framework default handler. Quart's default behavior in production mode returns a 500 page, but there's no guarantee DEBUG mode isn't enabled, error details are not guaranteed to be logged by a custom handler, no alerting or escalation is triggered, and no consistent error response format exists. Entry points without exception coverage include: all routes using load_election only catch ElectionNotFound, voter_page() calls Election.open_to_pid() with no error handling, admin_page() calls PersonDB.open() with no handling for DB errors, and serve_doc() uses send_from_directory() with no handling for OS errors.

**Remediation:**

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

---

#### FINDING-072: No file size validation to prevent denial of service

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 5.2.1 |
| **Files** | v3/server/pages.py:entire application scope |
| **Source Reports** | 5.2.1.md |
| **Related** | - |

**Description:**

The application serves documents via `/docs/<iid>/<docname>` but has no visible file upload endpoint with size validation. The mechanism by which documents are placed into `DOCSDIR` is not shown in the provided code, meaning there are no observable file size checks that would prevent a denial of service via excessively large files. If files are uploaded through an undocumented mechanism, no size limits are enforced by the shown code. Additionally, the Quart application does not set `MAX_CONTENT_LENGTH` (or equivalent) to limit request body size globally, which would affect any file upload functionality added in the future.

**Remediation:**

Configure `APP.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024` to set a 10 MB max upload limit. In any file upload handler, implement explicit size checking by seeking to the end of the file, checking the size, and rejecting files that exceed the maximum allowed size (e.g., 10 MB) with a 413 status code.

---

#### FINDING-073: Missing file extension and content validation in document serving endpoint

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1, L2 |
| **CWE** | - |
| **ASVS Section(s)** | 5.2.2, 5.3.1, 1.3.3 |
| **Files** | v3/server/pages.py:560-574 |
| **Source Reports** | 5.2.2.md, 5.3.1.md, 1.3.3.md |
| **Related** | - |

**Description:**

The `serve_doc()` endpoint serves arbitrary files from the `DOCSDIR` directory. While no upload handler is visible in this codebase, the docs directory appears to be populated through external means (files are referenced via `doc:filename` patterns in issue descriptions). There is no validation that served files are non-executable content types. If an attacker (or misconfigured process) places a file with a server-executable extension (e.g., `.py`, `.php`) in the docs directory, and if a reverse proxy or misconfigured server processes certain extensions, the file could be executed. With `send_from_directory`, Quart serves files as static content which mitigates direct Python execution, but upstream server configurations could still be vulnerable.

**Remediation:**

Implement file extension allowlist validation and magic bytes content verification using python-magic library. Add security headers (X-Content-Type-Options: nosniff, Content-Disposition: attachment) to all file serve responses. Verify the file extension matches an allowed list (e.g., .pdf, .txt, .png, .jpg, .jpeg), then validate that the detected MIME type matches the expected MIME type for that extension. Reject requests for files that fail either check.

---

#### FINDING-074: No Token Audience Validation After OAuth Exchange

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Section(s)** | 9.2.4 |
| **Files** | v3/server/pages.py:75-106 |
| **Source Reports** | 9.2.4.md |
| **Related** | - |

**Description:**

The session data (uid, fullname, email) is consumed directly from asfquart.session.read() without any validation that the underlying token was issued specifically for the STeVe application. No aud claim is checked. No iss claim is verified against an expected value. By explicitly avoiding OIDC (as noted in main.py line 29 comment), the application loses the standardized aud claim validation that OIDC ID tokens provide. OIDC requires that the ID token's aud claim contains the client_id of the relying party, which is exactly what ASVS 9.2.4 requires. If the OAuth provider issues tokens that can be consumed by multiple services, the application has no defense against cross-service token confusion attacks. Any valid session from another ASF application sharing the same OAuth provider could potentially be used to access STeVe endpoints.

**Remediation:**

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

### 3.3 Medium

#### FINDING-075: No Documented Cryptographic Key Management Policy or Key Lifecycle

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 11.1.1 |
| **Files** | v3/steve/crypto.py, v3/docs/schema.md |
| **Source Reports** | 11.1.1.md |
| **Related Findings** | None |

**Description:**

The codebase contains multiple cryptographic keys and secrets (election salt, opened_key, vote_token, vote encryption keys) but there is no documented key management policy conforming to NIST SP 800-57 or an equivalent standard. While schema.md provides some documentation of what keys exist, it does not constitute a key lifecycle policy addressing: Key generation procedures and responsibilities, Key storage and protection requirements, Key distribution controls, Key usage periods / expiration, Key revocation and destruction procedures, Key recovery mechanisms. Without a documented key lifecycle, keys may persist beyond their intended use period, accumulate risk, and lack clear procedures for compromise response. The opened_key persists in the database indefinitely after an election closes, with no documented destruction schedule.

**Remediation:**

Create a formal cryptographic key management policy document covering: 1. Key types, purposes, and authorized users 2. Key generation procedures (already using secrets module) 3. Maximum key lifetime per key type 4. Key storage protection requirements 5. Key destruction procedures (e.g., zeroing opened_key after tally completion) 6. Incident response for key compromise

---

#### FINDING-076: Incomplete Cryptographic Inventory - Missing Algorithm and Key Usage Documentation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 11.1.2 |
| **Files** | v3/steve/crypto.py:49, v3/steve/crypto.py:61-66, v3/docs/schema.md |
| **Source Reports** | 11.1.2.md |
| **Related Findings** | None |

**Description:**

While schema.md documents some cryptographic assets, it does not constitute a complete cryptographic inventory. The following are not formally inventoried: 1) Algorithms not documented: BLAKE2b (64-byte digest, used as pre-hash for Argon2), HKDF-SHA256 (used for key stretching vote_token → vote_key), The specific Fernet composition (AES-128-CBC + HMAC-SHA256). 2) Key usage boundaries not documented: Where each key type CAN be used vs. CANNOT be used, What data types each key protects, Which components have access to which keys. 3) No centralized inventory document: Crypto information is scattered across schema.md, crypto.py comments, and schema.sql comments. Without a complete inventory, it's impossible to systematically assess cryptographic risk, plan migrations, or ensure all cryptographic assets are properly managed.

**Remediation:**

Create a dedicated CRYPTO_INVENTORY.md document containing a table with columns: Asset, Algorithm, Key Length, Purpose, Protected Data, Access Scope, Location. Include all cryptographic assets: election salt, opened key, mayvote salt, vote token, vote key, and ciphertext with their respective algorithms and parameters.

---

#### FINDING-077: No Cryptographic Discovery Mechanisms Employed

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Sections** | 11.1.3 |
| **Files** | pyproject.toml, v3/steve/pages.py:269 |
| **Source Reports** | 11.1.3.md |
| **Related Findings** | None |

**Description:**

There is no evidence of automated cryptographic discovery mechanisms being employed to identify all instances of cryptography in the system. No tooling, CI/CD pipeline steps, or scanning configurations are present to: discover all cryptographic library usage, identify encryption, hashing, and signing operations, detect introduction of new cryptographic operations, or flag deprecated or weak algorithm usage. The pyproject.toml defines development dependencies but includes no cryptographic scanning tools. No tools like cryptosense, crypto-detector, semgrep with crypto rules, or custom SAST rules for cryptographic operations are configured.

**Remediation:**

1. Add a cryptographic linting step to CI/CD using tools like: semgrep with crypto-specific rules, custom ruff or pylint rules flagging hashlib, cryptography, hmac imports, SAST tools configured to flag crypto operations. 2. Maintain a list of approved crypto imports/modules. 3. Run periodic scans to detect drift from the inventory.

---

#### FINDING-078: No Documented Post-Quantum Cryptography Migration Plan

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3, L1 |
| **CWE** | N/A |
| **ASVS Sections** | 11.1.4, 15.1.1 |
| **Files** | v3/steve/crypto.py:63, v3/docs/schema.md |
| **Source Reports** | 11.1.4.md, 15.1.1.md |
| **Related Findings** | None |

**Description:**

While the code acknowledges a planned transition from Fernet to XChaCha20-Poly1305, there is no documented migration plan addressing post-quantum cryptography threats. The current cryptographic primitives (AES-128, SHA-256, BLAKE2b) have varying levels of quantum resistance, and no formal assessment or migration roadmap exists. Without a migration plan, the project cannot react efficiently to quantum computing advances. The planned Fernet → XChaCha20-Poly1305 migration doesn't address quantum threats (both are symmetric and similarly affected by Grover's algorithm). AES-128 specifically should be upgraded to AES-256 for quantum resistance.

**Remediation:**

Create a PQC_MIGRATION_PLAN.md documenting: 1. Current algorithm inventory with quantum risk assessment 2. Timeline for migrating AES-128 (Fernet) to AES-256 or authenticated encryption with 256-bit keys 3. Assessment of when PQC-resistant key exchange might be needed (if TLS/network crypto is added) 4. Crypto-agility requirements (see 11.2.2) to enable seamless future upgrades 5. Data re-encryption strategy for stored ciphertext

---

#### FINDING-079: Argon2d (Type.D) Used Instead of Recommended Argon2id (Type.ID)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3, L1 |
| **CWE** | N/A |
| **ASVS Sections** | 11.2.1, 11.2.4, 11.4.2, 11.4.4, 11.6.1, 15.2.1 |
| **Files** | v3/steve/crypto.py:89, v3/steve/crypto.py:87, v3/steve/crypto.py:84, v3/steve/crypto.py:85-93 |
| **Source Reports** | 11.2.1.md, 11.2.4.md, 11.4.2.md, 11.4.4.md, 11.6.1.md, 15.2.1.md |
| **Related Findings** | None |

**Description:**

The production _hash() function uses Argon2d (data-dependent memory access), which is vulnerable to side-channel attacks (cache-timing attacks). RFC 9106 and OWASP recommend Argon2id for most applications, as it combines the side-channel resistance of Argon2i with the GPU/ASIC resistance of Argon2d. The benchmark function at line 118 correctly uses Type.ID, suggesting awareness of the recommended variant, but the production code was not updated. In environments where an attacker can observe memory access patterns (shared hosting, VMs, certain cloud environments), Argon2d is vulnerable to side-channel extraction of the secret. This could enable extraction of opened_keys or vote_tokens.

**Remediation:**

Change the type parameter in the _hash() function from argon2.low_level.Type.D to argon2.low_level.Type.ID (RFC 9106 recommended). Note: this will change all derived values, so must be coordinated with any existing deployed databases. Add a crypto_version column to the vote table to enable future algorithm transitions without data loss.

---

#### FINDING-080: ID Generation Uses Insufficient Entropy (40 bits)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-330 |
| **ASVS Sections** | 11.2.3, 11.5.1 |
| **Files** | v3/steve/crypto.py:100, v3/steve/crypto.py:101, v3/steve/election.py:171, v3/steve/election.py:379 |
| **Source Reports** | 11.2.3.md, 11.5.1.md |
| **Related Findings** | None |

**Description:**

The create_id() function generates identifiers using only 5 bytes (40 bits of entropy), significantly below the 128-bit threshold recommended for cryptographic security parameters. While create_id() is not a traditional cryptographic primitive, it provides the security property of preventing URL/identifier guessing for election IDs and issue IDs. With only 40 bits of entropy (~10^12 possibilities), an attacker with sustained access could enumerate valid election IDs or issue IDs. With ~1 trillion possible values and only a small subset being valid, this is mitigated by the online attack constraint (rate limiting, network latency). However, for a voting system where ballot secrecy is paramount, the margin is thin.

**Remediation:**

Use secrets.token_hex(16) to generate 16 bytes (128 bits) encoded as 32 hex characters. This requires schema changes to accommodate 32-character IDs and updating CHECK constraints in schema.sql. Example code: def create_id(): return secrets.token_hex(16)  # 16 bytes = 128 bits

---

#### FINDING-081: Unhandled Cryptographic Decryption Exceptions in Vote Tallying

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Sections** | 11.2.5 |
| **Files** | v3/steve/election.py:283-290, v3/steve/crypto.py |
| **Source Reports** | 11.2.5.md |
| **Related Findings** | None |

**Description:**

If any single vote's ciphertext is corrupted (database corruption, malicious tampering with the SQLite file), the entire tally_issue() operation will fail with an unhandled cryptography.fernet.InvalidToken exception. This is a denial-of-service vector against the tallying function. While Fernet's encrypt-then-MAC construction prevents Padding Oracle attacks specifically (HMAC is verified before decryption), the lack of error handling means: 1) A single corrupted vote prevents ALL votes from being tallied, 2) The exception type/message could potentially differentiate between HMAC failure and other issues in some library versions. Data flow: ciphertext from database → Fernet.decrypt() → no exception handling → unhandled InvalidToken propagates → entire tally operation fails.

**Remediation:**

Wrap the decryption call in a try/except block to handle InvalidToken exceptions gracefully. Log the failure generically without exposing details that could differentiate between HMAC failure vs decryption failure. Skip the corrupted vote and continue processing remaining votes rather than failing the entire tally operation.

---

#### FINDING-082: Use of Fernet (AES-128-CBC) Instead of Approved AEAD Cipher

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 11.3.2 |
| **Files** | v3/steve/crypto.py:72-82 |
| **Source Reports** | 11.3.2.md |
| **Related Findings** | None |

**Description:**

The code explicitly acknowledges it should be using XChaCha20-Poly1305 (an AEAD cipher) but is currently using Fernet (AES-128-CBC + HMAC-SHA256). While Fernet is a secure authenticated encryption construction, it is not a native AEAD mode. Modern ASVS standards prefer purpose-built AEAD ciphers (AES-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305) which provide authenticated encryption in a single primitive with formal security proofs. Key concerns: AES-CBC is a legacy mode that requires careful composition with MAC; Fernet's AES-128 provides only 128 bits of security vs the 256-bit key being derived (waste of key material); The HKDF info parameter says b'xchacha20_key' but the key is used for Fernet indicating incomplete migration; The 32-byte HKDF output is base64-encoded and fed to Fernet, which internally splits it into 16 bytes signing + 16 bytes encryption (AES-128), not using the full 256 bits.

**Remediation:**

Replace Fernet with ChaCha20-Poly1305 AEAD cipher. Use cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305 with 32-byte keys derived from HKDF. Generate 96-bit nonces using os.urandom(12) and prepend to ciphertext for decryption. Update HKDF info parameter to b'chacha20_poly1305_key' to match actual usage. This provides authenticated encryption with a single primitive and utilizes the full 256 bits of key material.

---

#### FINDING-083: Sensitive Data Unprotected in Process Memory Without Memory Encryption

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Sections** | 11.7.1 |
| **Files** | v3/steve/crypto.py, v3/steve/election.py |
| **Source Reports** | 11.7.1.md |
| **Related Findings** | None |

**Description:**

Sensitive data including opened_key, vote_token, decrypted vote strings, and PIDs exist unprotected in process memory. The data flow shows: Encrypted ciphertext → decrypted votestrings → accumulated in votes list → passed to tally → returned from function, all without memory encryption. An attacker with memory access (via memory dump, cold boot attack, swap file analysis, or process inspection) could recover individual votes, compromising ballot secrecy.

**Remediation:**

Implement hardware-backed memory encryption using technologies such as: Intel TME (Total Memory Encryption) / MKTME, AMD SEV (Secure Encrypted Virtualization), or ARM CCA (Confidential Compute Architecture). At the application level, consider using memory-safe containers or encrypted memory regions via libraries like sodium with sodium_mlock() / sodium_munlock(). Additionally, consider using mlock() for memory pages containing decrypted votes during tally operations, and implement explicit memory clearing patterns.

---

#### FINDING-084: OAuth/OIDC token handling mechanism not verifiable - session security cannot be confirmed

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 10.1.1 |
| **Files** | v3/server/pages.py:58-84 |
| **Source Reports** | 10.1.1.md |
| **Related Findings** | None |

**Description:**

The application uses session-based authentication via `asfquart.session.read()`. Session data containing `uid`, `fullname`, and `email` is passed to EZT templates for rendering. However, the OAuth/OIDC token handling itself is abstracted within the `asfquart` library, which is not provided for review. The application does NOT appear to expose access tokens or refresh tokens to the browser. The session is read server-side and only user-facing attributes (uid, name, email) are passed to templates. The templates do not reference any OAuth tokens. The backend appears to act as a BFF pattern where token handling is server-side only. The `asfquart` session mechanism is not inspectable in this code. If the session cookie itself contains embedded tokens (e.g., JWT session), or if the session store leaks token values, this cannot be verified from the provided code.

**Remediation:**

Verify that the `asfquart` session mechanism does not expose raw OAuth tokens in cookies or responses. Ensure session cookies are `HttpOnly`, `Secure`, and `SameSite`. Audit the `asfquart` library's OAuth implementation to verify token storage security (HttpOnly, Secure cookies) and session fixation protection. Add SameSite cookie attributes to ensure session cookies use `SameSite=Lax` or `SameSite=Strict` as an additional defense layer.

---

#### FINDING-085: No visible audience claim validation for access tokens

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 10.3.1 |
| **Files** | v3/server/pages.py (all endpoints using @asfquart.auth.require) |
| **Source Reports** | 10.3.1.md |
| **Related Findings** | None |

**Description:**

The application acts as a resource server (protected API/web application). Token/session validation is performed by `asfquart.auth.require`, but there is no visible audience (`aud`) claim validation in the provided code. If the authentication mechanism uses structured access tokens (JWTs), the application should verify that tokens are intended for this specific service. If another service in the ASF infrastructure issues tokens with the same authorization server but different intended audiences, a token meant for another service could potentially be used to access this application. The `asfquart.auth.require` decorator handles all authentication, but whether it validates the `aud` claim depends on the library's implementation, which is not provided.

**Remediation:**

Verify that the `asfquart` library validates the `aud` claim during token exchange or session creation. If using JWT access tokens directly, add audience validation. Example conceptual configuration: APP.config['OAUTH_AUDIENCE'] = 'steve-voting-system' and ensure asfquart validates this during token/session processing.

---

#### FINDING-086: User identification relies on `uid` alone without verifiable `iss` + `sub` combination

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 10.3.3 |
| **Files** | v3/server/pages.py:82-87, v3/server/main.py:39-42 |
| **Source Reports** | 10.3.3.md |
| **Related Findings** | None |

**Description:**

The session stores only `uid` without preserving the token issuer (`iss`). While the system currently uses a single identity provider (oauth.apache.org), the user identification does not include an issuer component. If the system were ever configured to accept tokens from multiple issuers, or if session data could be manipulated, a `uid` from one issuer could be confused with the same `uid` from another. The `asfquart` framework likely handles token validation internally, but the application-level code only works with a flat `uid` string. There is no verification that the combination of issuer and subject is used as the unique identifier in the database (`steve.persondb` uses `uid` as the primary key). In the current single-issuer deployment, the risk is low. However, the architecture doesn't enforce the `iss` + `sub` combination pattern, making it fragile against future changes or issuer confusion if multiple OAuth providers are ever supported.

**Remediation:**

In session establishment (within asfquart callback), store session data with both `uid` and `iss`: session_data = {'uid': token_claims['sub'], 'iss': token_claims['iss'], 'fullname': token_claims.get('name', ''), 'email': token_claims.get('email', '')}. In authorization checks, construct a unique user identifier from iss + sub: def get_unique_user_id(session): return f"{session['iss']}#{session['uid']}"

---

#### FINDING-087: No verification of authentication strength, methods, or recentness for sensitive operations

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 10.3.4 |
| **Files** | v3/server/pages.py (all sensitive endpoints) |
| **Source Reports** | 10.3.4.md |
| **Related Findings** | None |

**Description:**

The application performs sensitive operations (opening/closing elections, creating elections, casting votes) without verifying: (1) acr (Authentication Context Class Reference) — no check that the user authenticated with sufficient assurance level, (2) amr (Authentication Methods References) — no check that specific authentication methods (e.g., MFA) were used, (3) auth_time — no check that authentication occurred recently enough for the operation. The session data (basic_info()) captures no authentication metadata beyond identity. Long-lived sessions could allow sensitive operations long after the original authentication event. A user who authenticated hours or days ago with a weak method (single factor) can perform highly sensitive operations (opening elections that affect organizational governance) without re-authentication or step-up verification.

**Remediation:**

Implement a decorator to require recent authentication for sensitive operations. Store auth_time in session and validate it before sensitive operations. Example: Create a require_recent_auth decorator that checks if time.time() - auth_time > SENSITIVE_OPS_MAX_AGE (e.g., 300 seconds), and if exceeded, redirect to re-authentication. Apply this decorator to sensitive endpoints like /do-open/&lt;eid&gt;, /do-create-election, and vote casting operations. Additionally, preserve OAuth token claims (acr, amr, auth_time) in the session when establishing it so they can be verified for sensitive operations.

---

#### FINDING-088: No sender-constrained access token mechanisms (mTLS or DPoP) implemented

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Sections** | 10.3.5, 10.4.14 |
| **Files** | v3/server/main.py:39-42, v3/server/main.py:76-79, v3/server/pages.py |
| **Source Reports** | 10.3.5.md, 10.4.14.md |
| **Related Findings** | None |

**Description:**

The application does not implement OAuth 2.0 Mutual TLS (RFC 8705) certificate-bound access tokens or DPoP (Demonstration of Proof of Possession) token binding. TLS configuration is standard server-side TLS only (certfile + keyfile for server certificate). The OAuth token exchange URL format shows no DPoP proof parameter. Bearer tokens (or session cookies derived from them) are not bound to any client-specific cryptographic key, making them susceptible to theft and replay. If an access token or session cookie is intercepted (e.g., via XSS, network compromise, or log exposure), it can be replayed from any client without detection. This is a Level 3 requirement, so it represents an advanced security control gap.

**Remediation:**

Implement DPoP (Demonstration of Proof of Possession) token binding. Example implementation: Create a DPoP proof JWT using jwcrypto library with ES256 algorithm and P-256 curve. Generate a JWK key pair, create a JWT with 'dpop+jwt' type containing claims for jti (unique identifier), htm (HTTP method), htu (HTTP URI), iat (issued at time), and ath (access token hash when validating). Sign the proof with the private key and include the public key in the JWT header. Alternatively, implement OAuth 2.0 Mutual TLS (RFC 8705) certificate-bound access tokens by requiring client certificates and binding tokens to certificate fingerprints. At minimum, implement session binding to client characteristics with fingerprint verification.

---

#### FINDING-089: OAuth token exchange callback URL does not visibly include client authentication parameters

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | N/A |
| **ASVS Sections** | 10.4.10, 10.4.16 |
| **Files** | v3/server/main.py:39-42 |
| **Source Reports** | 10.4.10.md, 10.4.16.md |
| **Related Findings** | None |

**Description:**

The token exchange URL pattern `https://oauth.apache.org/token?code=%s` passes only the authorization code as a query parameter. There is no evidence of strong client authentication methods being configured: (1) No mutual TLS (`tls_client_auth` / `self_signed_tls_client_auth`) - While the server has TLS certificate configuration, there is no client certificate configuration for outbound connections to the authorization server. (2) No `private_key_jwt` - No JWT signing key configuration is visible for client assertion authentication. (3) No visible `client_secret` - Even basic client_secret_post/client_secret_basic is not configured in the visible code. The `OAUTH_URL_CALLBACK` format suggests the code is passed as a URL query parameter rather than in a POST body with client credentials, which is inconsistent with confidential client behavior. Without strong client authentication, the authorization server cannot reliably verify that token requests originate from the legitimate client. This enables authorization code injection and token theft attacks.

**Remediation:**

Configure mutual TLS for client authentication: asfquart.generics.OAUTH_CLIENT_CERT = '/path/to/client_cert.pem'; asfquart.generics.OAUTH_CLIENT_KEY = '/path/to/client_key.pem'; asfquart.generics.TOKEN_ENDPOINT_AUTH_METHOD = 'tls_client_auth'. Or configure private_key_jwt: asfquart.generics.TOKEN_ENDPOINT_AUTH_METHOD = 'private_key_jwt'; asfquart.generics.CLIENT_ASSERTION_KEY = '/path/to/private_key.pem'; asfquart.generics.CLIENT_ID = 'steve-voting-app'.

---

#### FINDING-090: Authorization code grant flow does not use Pushed Authorization Requests (PAR)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Sections** | 10.4.13, 10.4.15 |
| **Files** | v3/server/main.py:39-42 |
| **Source Reports** | 10.4.13.md, 10.4.15.md |
| **Related Findings** | None |

**Description:**

The authorization code grant flow does not use Pushed Authorization Requests (PAR). The authorization request parameters are passed directly in the URL to the authorization endpoint, rather than being pushed beforehand via a backchannel PAR request. Without PAR, authorization request parameters are exposed in the browser URL bar and browser history, can be manipulated by the user-agent or malicious browser extensions, and the redirect_uri is passed in the frontchannel, making it susceptible to parameter pollution attacks. The authorization server cannot verify the authenticity of the authorization request. For an election system, this could theoretically allow manipulation of the OAuth flow to impersonate voters, though the state parameter provides some protection.

**Remediation:**

Implement PAR flow by pushing authorization request parameters via backchannel before redirecting the user. Create a function to push authorization request parameters to the PAR endpoint (https://oauth.apache.org/par) with client credentials, response_type, redirect_uri, state, and scope. Then redirect the user with only the client_id and the returned request_uri reference. Implementation depends on oauth.apache.org supporting the PAR endpoint (RFC 9126). The ASF OAuth infrastructure would need to be verified for PAR support.

---

#### FINDING-091: No Evidence of Refresh Token Handling or Sender-Constraining

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | N/A |
| **ASVS Sections** | 10.4.5 |
| **Files** | v3/server/main.py:38-42, v3/server/pages.py (entire file) |
| **Source Reports** | 10.4.5.md |
| **Related Findings** | None |

**Description:**

The codebase shows no evidence of refresh token storage or usage, DPoP proof generation, mTLS client certificate binding, or refresh token rotation handling on the client side. The session management uses asfquart.session.read() but the framework's internal handling of refresh tokens is not visible. If the framework handles refresh tokens internally without sender-constraining, replay attacks are possible. If the asfquart framework receives and stores refresh tokens from the ASF OAuth server, and neither DPoP nor mTLS is used, a stolen refresh token could be replayed by an attacker to obtain new access tokens.

**Remediation:**

Verify that the asfquart framework either: 1. Does not use refresh tokens (session-only approach), OR 2. Implements DPoP or mTLS for sender-constraining, OR 3. Properly handles refresh token rotation (consuming old tokens). If using refresh tokens, ensure DPoP is configured: asfquart.generics.OAUTH_USE_DPOP = True or verify the framework's session management doesn't rely on refresh tokens.

---

#### FINDING-092: No token/session revocation endpoint or UI present

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L1 |
| **CWE** | N/A |
| **ASVS Sections** | 10.4.9, 6.1.1, 7.4.5, 14.3.1 |
| **Files** | v3/server/pages.py (entire file scope) |
| **Source Reports** | 10.4.9.md, 6.1.1.md, 7.4.5.md, 14.3.1.md |
| **Related Findings** | None |

**Description:**

There is no visible logout endpoint in the provided code. Without a logout mechanism: 1) No Clear-Site-Data header can be sent on session termination, 2) Authenticated session data (cookies, any client-side cached data) persists in the browser indefinitely, 3) If a user walks away from a shared computer, their session remains active, 4) Flash messages (stored in session) containing sensitive election information persist until consumed. The absence of any session termination mechanism violates ASVS 14.3.1 which requires authenticated data to be cleared from client storage after the client or session is terminated.

**Remediation:**

Implement session logout and revocation endpoints. Add a /logout endpoint that destroys the current session and a /revoke-all-sessions endpoint that revokes all sessions for the current user. Example implementation: @APP.get('/logout') @asfquart.auth.require async def logout_page(): session = await asfquart.session.read(); if session: await asfquart.session.destroy(); return quart.redirect('/', code=303). @APP.post('/revoke-all-sessions') @asfquart.auth.require async def revoke_all_sessions(): session = await asfquart.session.read(); if session: await asfquart.session.destroy_all(session['uid']); return quart.redirect('/', code=303)

---

#### FINDING-093: Missing Issuer Validation in OAuth Token Response

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 10.5.3 |
| **Files** | v3/server/main.py:39-42 |
| **Source Reports** | 10.5.3.md |
| **Related Findings** | None |

**Description:**

While the OAuth URLs are hardcoded to `https://oauth.apache.org/`, there is no visible validation that: 1) The token response actually came from `oauth.apache.org`, 2) The `iss` claim in any received ID Token matches the expected issuer URL, 3) Authorization server metadata (if fetched) is validated against the pre-configured issuer. The hardcoded URLs provide a form of issuer pinning for outbound requests, but the requirement specifically mandates validating the issuer in the received response/metadata. Without this validation, a man-in-the-middle or DNS hijack could cause the client to accept tokens from a malicious authorization server. Since the callback handler is in `asfquart` (not provided), we cannot confirm whether issuer validation occurs there. This represents a visibility gap.

**Remediation:**

Configure expected issuer for validation: asfquart.generics.EXPECTED_ISSUER = 'https://oauth.apache.org'. In token validation: if decoded_token['iss'] != EXPECTED_ISSUER: raise SecurityError('Issuer mismatch - possible impersonation')

---

#### FINDING-094: No documented rate limiting, anti-automation, or adaptive response controls for authentication endpoints

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 6.1.1, 6.3.1 |
| **Files** | v3/server/main.py:34-39, v3/server/pages.py (entire file) |
| **Source Reports** | 6.1.1.md, 6.3.1.md |
| **Related Findings** | None |

**Description:**

The application delegates authentication to ASF OAuth (oauth.apache.org). However, there is no documentation anywhere in the provided code (comments, docstrings, or configuration) that describes: 1) How rate limiting is configured for the OAuth callback endpoint, 2) Whether the upstream ASF OAuth provider implements anti-automation controls, 3) What adaptive response mechanisms exist (e.g., progressive delays, CAPTCHA escalation), 4) How the system prevents malicious account lockout at the ASF OAuth layer, 5) Whether the application itself implements any secondary rate limiting on session-protected endpoints. The asfquart.auth.require decorator is used extensively across endpoints (with {R.committer}, {R.pmc_member}, or bare), but no per-endpoint rate limiting is applied. Without documented rate limiting controls, there is no assurance that brute force or credential stuffing attacks against the OAuth flow are mitigated. Operational staff cannot verify correct configuration without documentation.

**Remediation:**

Create authentication security documentation that specifies: 1) Rate Limiting - OAuth callback endpoint: Delegated to ASF OAuth (oauth.apache.org) with description of specific controls implemented by ASF OAuth and application-level controls (e.g., max 10 auth attempts per IP per minute via reverse proxy), 2) Anti-Automation - CAPTCHA integration and bot detection mechanisms, 3) Adaptive Response - Behavior after N failed attempts and account lockout prevention mechanisms including ASF account unlock procedures, 4) Reverse Proxy Configuration - Apache/nginx rate limit rules with references to config files

---

#### FINDING-095: Multiple authentication pathways exist but are not documented together with security controls

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 6.1.3 |
| **Files** | v3/server/pages.py (multiple locations) |
| **Source Reports** | 6.1.3.md |
| **Related Findings** | None |

**Description:**

The application implements at least three distinct authentication/authorization pathways: 1) Bare session (`@asfquart.auth.require`): `/profile`, `/settings`, `/docs/<iid>/<docname>`, 2) Committer level (`@asfquart.auth.require({R.committer})`): `/voter`, `/admin`, `/manage/<eid>`, all voting and issue management endpoints, 3) PMC member level (`@asfquart.auth.require({R.pmc_member})`): `/do-create-election`. Additionally, the `### need general solution` comments throughout indicate that the authorization model is incomplete and evolving. There is no documentation that defines what security controls apply at each level, describes the authentication strength at each level (all use the same OAuth flow), explains why certain endpoints use one level vs another, or documents the planned "general solution" mentioned in comments. The repeated `### check authz` comments indicate that fine-grained authorization checks are acknowledged as needed but not implemented.

**Remediation:**

Create comprehensive authentication pathways documentation covering: 1) OAuth Flow (Primary - All Users) including provider (ASF OAuth), strength (single-factor), session management, and controls, 2) Authorization Levels for Level 0 (Public - No Authentication), Level 1 (Authenticated User - Valid Session), Level 2 (ASF Committer), and Level 3 (PMC Member), 3) Consistency Enforcement noting all pathways use the same ASF OAuth provider with identical authentication strength, with authorization differing by LDAP group membership. Document this in `docs/AUTHENTICATION.md` covering all three ASVS 6.1.x requirements.

---

#### FINDING-096: No Mechanism for Suspicious Authentication Notifications

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Sections** | 6.3.5 |
| **Files** | v3/server/pages.py (entire file) |
| **Source Reports** | 6.3.5.md |
| **Related Findings** | None |

**Description:**

The application contains no code to detect or notify users about suspicious authentication attempts. Specifically, it lacks functionality to: (1) Detect authentication attempts from unusual locations or clients, (2) Identify partially successful authentication (one factor only), (3) Notice authentication after long inactivity periods, (4) Track successful authentication following multiple failures, (5) Send notifications to users about any of the above. Users have no visibility into unauthorized access attempts against their accounts. If a session is compromised or an attacker authenticates via stolen OAuth tokens, the legitimate user receives no notification.

**Remediation:**

Implement a suspicious authentication detection and notification system that: (1) Tracks session attributes (IP address, user agent, last activity time) for comparison, (2) Detects anomalies such as new IP addresses, login after extended inactivity (e.g., 90+ days), or unusual client patterns, (3) Sends email notifications to users when suspicious activity is detected, (4) Records session information for future comparison.

---

#### FINDING-097: No Notification Mechanism for Authentication Detail Changes

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Sections** | 6.3.7 |
| **Files** | v3/server/pages.py:603 |
| **Source Reports** | 6.3.7.md |
| **Related Findings** | None |

**Description:**

A `/settings` page exists, implying users can modify account details. However: 1. No notification mechanism exists anywhere in the codebase for credential or profile changes. 2. No email sending service is configured or imported. 3. Changes to LDAP-sourced data (username, email) happen externally but the application doesn't verify or notify when these change between sessions. If authentication details are modified at the ASF IdP level (credential reset, email change) or if the application later adds local settings, users will not be notified of changes. This reduces the ability to detect account takeover.

**Remediation:**

Implement profile change detection and notification mechanism. Check stored profile against session data on each login, and if email or other critical attributes have changed, send notification to the old email address before updating.

---

#### FINDING-098: No mechanism for revoking authentication sessions or invalidating user access

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Sections** | 6.5.6 |
| **Files** | v3/server/pages.py (entire authentication architecture) |
| **Source Reports** | 6.5.6.md |
| **Related Findings** | None |

**Description:**

The audited codebase provides no mechanism for revoking authentication sessions or invalidating a user's access independent of the external IdP. While authentication factor management (passwords, TOTP devices, etc.) is delegated to ASF's IdP, the application-level session established after OAuth callback has no visible revocation mechanism in the provided code: (1) No logout endpoint is visible in pages.py, (2) No session invalidation mechanism is exposed to administrators, (3) No 'revoke all sessions' capability for compromised accounts, (4) If an ASF account is compromised, there's no evidence the application can immediately invalidate active sessions. The asfquart.session module handles session management but its implementation is not provided for review.

**Remediation:**

Implement logout endpoint and admin session revocation capability. Add /logout endpoint that invalidates current session using asfquart.session.invalidate(). Add /admin/revoke-sessions/&lt;uid&gt; endpoint for administrators to revoke all sessions for a user.

---

#### FINDING-099: User identity not explicitly namespaced with IdP identifier

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 6.8.1 |
| **Files** | v3/server/pages.py:82-93, main.py:39-42, asf-load-ldap.py:54 |
| **Source Reports** | 6.8.1.md |
| **Related Findings** | None |

**Description:**

The application uses a single `uid` field from the session as the user's identity throughout the system. While currently only one IdP is configured (ASF OAuth at `oauth.apache.org`), there is no IdP namespace stored alongside the user identifier. If the application were extended to support additional identity providers (or if the `asfquart` framework were configured to accept multiple providers), the `uid` field alone could be spoofed across providers. The OAuth configuration in `main.py` (lines 39-42) references only `oauth.apache.org`. Additionally, the LDAP load process in `asf-load-ldap.py` (line 54) stores users by `uid` alone. Mitigating Factor: Currently only one IdP is configured, which significantly reduces the actual exploitation risk.

**Remediation:**

Store and validate a composite key of `(idp_id, user_id)` rather than `user_id` alone. Capture `idp_id` from session (defaulting to 'asf-oauth' for backward compatibility) and create a `composite_id` field in the format `{idp_id}:{uid}`. Update session handling in `basic_info()` to include `idp`, `composite_id` alongside existing `uid`, `name`, and `email` fields. Update PersonDB schema to namespace users with IdP identifier.

---

#### FINDING-100: No documented fallback approach for authentication strength assumptions

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 6.8.4 |
| **Files** | N/A |
| **Source Reports** | 6.8.4.md |
| **Related Findings** | None |

**Description:**

The ASVS requirement states: 'If the IdP does not provide this information, the application must have a documented fallback approach that assumes that the minimum strength authentication mechanism was used.' No such documentation or implementation exists in the codebase. The application treats all authenticated sessions equally regardless of authentication strength.

**Remediation:**

Document the authentication strength assumptions and implement appropriate controls. Example: When IdP does not provide acr/amr claims, assume single-factor authentication. Consequence: Election creation and management operations require re-authentication within 15 minutes. Vote submission allowed with standard session validity.

---

#### FINDING-101: No concurrent session limit enforcement or documentation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 7.1.2 |
| **Files** | v3/server/pages.py:82-92, v3/server/main.py (entire file) |
| **Source Reports** | 7.1.2.md |
| **Related Findings** | None |

**Description:**

The application codebase contains no implementation, configuration, or documentation defining the maximum number of concurrent sessions allowed per account, nor any behavior when a limit would be reached. The session management in `pages.py` reads sessions via `asfquart.session.read()` but never checks for or limits concurrent active sessions for the same user. User authenticates via OAuth → session is created → no check against existing active sessions for same `uid` → unlimited concurrent sessions permitted. An attacker who compromises a user's OAuth credentials could maintain persistent access even after the legitimate user changes credentials, as no mechanism detects or limits parallel sessions.

**Remediation:**

Document the session concurrency policy and implement enforcement. In session creation callback (within asfquart framework or custom middleware), check active sessions for the uid, and if the count exceeds MAX_CONCURRENT_SESSIONS (e.g., 3), terminate the oldest session and log the action.

---

#### FINDING-102: No documented coordination between ASF OAuth SSO session lifetime and application session lifetime

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 7.1.3 |
| **Files** | v3/server/main.py:39-42, v3/server/pages.py (entire file) |
| **Source Reports** | 7.1.3.md |
| **Related Findings** | None |

**Description:**

The application integrates with ASF's OAuth infrastructure as a federated identity source, but there is no visible documentation or implementation of controls to coordinate session lifetimes between the ASF OAuth IdP and the local application session. When the ASF OAuth session expires or is revoked, the local application session may remain valid indefinitely. User authenticates at ASF OAuth → token exchanged at callback → local session created → no periodic validation against OAuth provider → no session lifetime synchronization.

**Remediation:**

Document the federated session management strategy and implement periodic token validation. Configuration/documentation should include: SESSION_MANAGEMENT with sso_provider (ASF OAuth), local_session_max_lifetime (8 hours), idle_timeout (30 minutes), re_authentication_required_for (election creation, election open/close), token_refresh_interval (15 minutes), on_sso_revocation (terminate local session within refresh interval).

---

#### FINDING-103: No visible session regeneration on authentication — cannot verify session fixation protection

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 7.2.4 |
| **Files** | v3/server/pages.py (entire file), v3/server/main.py:39-42 |
| **Source Reports** | 7.2.4.md |
| **Related Findings** | None |

**Description:**

The provided codebase does not contain any explicit session token regeneration logic during the OAuth authentication callback. While the `asfquart` framework likely handles the OAuth callback and session creation, there is no code in the audited files that demonstrates: 1. A new session token being generated upon successful OAuth authentication 2. The previous (unauthenticated) session token being invalidated/terminated 3. Session regeneration on any form of re-authentication. The OAuth callback handling is entirely within the `asfquart` framework. Without visibility into that code, session fixation protection cannot be confirmed.

**Remediation:**

Verify the `asfquart` framework regenerates session tokens on authentication. If not, add explicit regeneration in OAuth callback handler: terminate old session using await asfquart.session.destroy(), then create new session token using await asfquart.session.create() with user info (uid, fullname, email). Log session regeneration events including old and new session IDs.

---

#### FINDING-104: No session termination mechanism after authentication factor changes

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 7.4.3 |
| **Files** | v3/server/pages.py (full file) |
| **Source Reports** | 7.4.3.md |
| **Related Findings** | None |

**Description:**

The application relies entirely on ASF's external OAuth/LDAP infrastructure for authentication. There is no password change, MFA settings update, or credential management functionality within the application. While the settings_page() endpoint exists, it contains no credential-related operations. Data flow: Authentication factor changes happen at ASF IdP → No callback/webhook from IdP to application → Application has no knowledge of credential changes → Other sessions remain active. If a user's credentials are changed at the ASF IdP (e.g., password reset after compromise), the application has no mechanism to terminate existing sessions.

**Remediation:**

Implement one or more of the following: 1. Short absolute session lifetimes (forces periodic re-auth via IdP), 2. Token refresh that validates against current IdP state, 3. Webhook endpoint for IdP credential change notifications that invalidates all sessions for the affected user. Create a POST /webhooks/credential-change endpoint that receives notifications from ASF IdP when credentials change and calls session_store.invalidate_all_for_user(uid).

#### FINDING-105: No re-authentication enforcement for sensitive account attribute changes

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 7.5.1 |
| **Files** | v3/server/pages.py:603, v3/server/pages.py:594 |
| **Source Reports** | 7.5.1.md |
| **Related Findings** | - |

**Description:**

The `/settings` and `/profile` pages exist but only render templates. While the application delegates account attribute management (email, MFA) to the ASF OAuth/LDAP infrastructure, there is no evidence of re-authentication enforcement for any attribute-changing operations within the application's scope. The architecture relies entirely on ASF's IdP for account attribute protection. If the settings page ever gains functionality for modifying sensitive attributes (or if it already has client-side forms posting to an API not shown in this audit), there's no re-authentication gate.

**Remediation:**

If any sensitive attribute modification is added, implement re-authentication flow. Check if user has recently authenticated via session flag. If not, redirect to re-authentication flow before proceeding with the update. Implement a POST endpoint that verifies `recently_authenticated` session flag and redirects to /reauth if not present.

---

#### FINDING-106: No Additional Verification for Vote Submission

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 7.5.3 |
| **Files** | v3/server/pages.py:417 |
| **Source Reports** | 7.5.3.md |
| **Related Findings** | - |

**Description:**

Vote submission, while not election management, is a sensitive transaction where vote integrity is critical. No additional verification is required beyond the existing session. A session hijacker could cast or modify votes on behalf of the legitimate user without any additional verification. While re-voting is supported (making this reversible), the user may not notice the unauthorized vote submission.

**Remediation:**

Implement step-up authentication or additional verification mechanism for vote submission. Consider requiring re-authentication within a short time window (e.g., 5 minutes) before accepting votes, or implement a confirmation step with CSRF protection.

---

#### FINDING-107: No session lifetime configuration or IdP authentication timestamp tracking

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 7.6.1 |
| **Files** | v3/server/main.py:39-42, v3/server/pages.py:82 |
| **Source Reports** | 7.6.1.md |
| **Related Findings** | - |

**Description:**

No session lifetime configuration, maximum session duration, or IdP authentication timestamp tracking is visible in the codebase. The OAuth configuration only defines URLs for authentication but no timeout or session freshness enforcement. There is no mechanism to require re-authentication when the maximum time between IdP authentication events is reached. Sessions may remain valid indefinitely after initial OAuth authentication. If the IdP revokes user access or the user's LDAP account is disabled, the application session remains valid. During long elections, sessions could persist without validation against the IdP, allowing access after authorization has been revoked.

**Remediation:**

Implement session age checking against IdP maximum authentication time. Track 'auth_time' in the session and enforce maximum session age. Check session age in basic_info() function - if (time.time() - auth_time) > max_session_age, invalidate the session and redirect to login. Configure APP.cfg.session.max_age (e.g., 8 hours) and validate on each session read.

---

#### FINDING-108: Issue KV data (candidate lists) exposed without granular field filtering

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-359 |
| **ASVS Sections** | 8.2.3 |
| **Files** | v3/steve/election.py:235-250 |
| **Source Reports** | 8.2.3.md |
| **Related Findings** | - |

**Description:**

The list_issues() method returns all KV data (candidate lists, seats, labelmap) without filtering based on the caller's context or role. There is no distinction between what fields a voter should see versus what a manager should see. The kv field contains operational data that may be appropriate for voters but the method has no field filtering mechanism based on the consumer's role or access level.

**Remediation:**

Add field-level access control to list_issues() method by introducing an include_management_fields parameter. When called from voter-facing contexts, filter the KV data to only include voter-visible fields (candidates, labelmap, seats). Example: def list_issues(self, include_management_fields=False) with conditional filtering of issue.kv based on the parameter.

---

#### FINDING-109: No adaptive/contextual security controls implemented for authentication or authorization

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 8.2.4 |
| **Files** | v3/server/pages.py:67-93 |
| **Source Reports** | 8.2.4.md |
| **Related Findings** | - |

**Description:**

The application does not implement any adaptive security controls based on IP address changes during session, geolocation anomalies, device fingerprint changes, time-of-day restrictions, concurrent session detection, or unusual access patterns (e.g., managing elections outside business hours). This means a compromised session token can be used from any location, device, or context without triggering additional verification. Session cookie flows to asfquart.session.read() to establish identity with no environmental/contextual validation at session start or during operations.

**Remediation:**

Implement a validate_session_context() function that validates environmental context for the current request. This should include: IP-based session binding (validate request IP against stored session IP and require re-authentication on mismatch), device fingerprinting, time-based restrictions for sensitive operations (flag or require additional auth for off-hours access), geolocation validation, concurrent session detection, and step-up authentication for sensitive operations. Example: async def validate_session_context(session): request_ip = quart.request.remote_addr; stored_ip = session.get('bound_ip'); if stored_ip and request_ip != stored_ip: _LOGGER.warning(f'Session IP mismatch for {session["uid"]}: {stored_ip} → {request_ip}'); raise ContextViolation("IP address changed"); current_hour = datetime.datetime.now().hour; if current_hour < 6 or current_hour > 22: _LOGGER.info(f'Off-hours access by {session["uid"]}'); # Flag for review or require additional auth

---

#### FINDING-110: State enforcement uses Python assert statements which can be disabled at runtime

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1, L2 |
| **CWE** | - |
| **ASVS Sections** | 8.3.1, 2.3.1, 16.5.3 |
| **Files** | v3/steve/election.py:multiple |
| **Source Reports** | 8.3.1.md, 2.3.1.md, 16.5.3.md |
| **Related Findings** | - |

**Description:**

All election state enforcement (preventing modification of opened/closed elections, preventing deletion after opening, preventing voting on non-open elections) relies on Python assert statements. When Python is invoked with the -O (optimize) flag, all assert statements are compiled away and never executed. This is a well-documented Python behavior specified in the language reference. If the application is deployed with python -O or PYTHONOPTIMIZE=1 (common in production for performance), ALL state-based security checks vanish, creating catastrophic fail-open conditions: Elections can be deleted after being opened, Issues can be added to open/closed elections (bypassing tamper detection), Elections can be opened multiple times, Vote types are not validated. Complete bypass of election state integrity controls. An authenticated committer could modify issues in an open election, add votes to closed elections, or delete elections with active votes.

**Remediation:**

Replace all security-critical assert with explicit conditional checks that raise proper exceptions: def delete(self): if not self.is_editable(): raise ElectionBadState(self.eid, self.get_state(), self.S_EDITABLE) ... def add_issue(self, title, description, vtype, kv): if not self.is_editable(): raise ElectionBadState(self.eid, self.get_state(), self.S_EDITABLE) if vtype not in vtypes.TYPES: raise ValueError(f'Invalid vote type: {vtype}') ...

---

#### FINDING-111: No mechanism to invalidate sessions or propagate authorization revocations immediately

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 8.3.2 |
| **Files** | v3/server/pages.py:67-93 |
| **Source Reports** | 8.3.2.md |
| **Related Findings** | - |

**Description:**

If a voter's eligibility is revoked (e.g., removed from mayvote during the editable phase, or LDAP group membership changes), there is no mechanism to: (1) immediately invalidate their active session, (2) alert when they perform actions they're no longer authorized for, or (3) revert changes made after authorization was revoked. Given that the authz LDAP group check is not implemented (AUTH-001), this is a compounding issue—even if authz were checked at login, there's no re-check during the session. Authorization changes are not applied immediately to active sessions.

**Remediation:**

Re-validate authorization on each request (or on sensitive operations). Check if user is still active in LDAP. If not, invalidate the session and abort with 401. Example: async def basic_info(): s = await asfquart.session.read(); if s: uid = s['uid']; if not await validate_user_still_active(uid): await asfquart.session.invalidate(); quart.abort(401, 'Session invalidated - user no longer authorized'). This ensures authorization changes are immediately effective.

---

#### FINDING-112: No device security posture assessment or contextual risk analysis for administrative interfaces

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | CWE-778 |
| **ASVS Sections** | 8.4.2 |
| **Files** | v3/server/pages.py:system-wide |
| **Source Reports** | 8.4.2.md |
| **Related Findings** | FINDING-252 |

**Description:**

ASVS 8.4.2 explicitly requires 'device security posture assessment' and 'contextual risk analysis' for administrative interfaces. The system has no implementation of device fingerprinting, behavioral analysis, geographic/IP risk scoring, session binding to device characteristics, or anomaly detection for administrative operations. Compromised credentials from any network location grant full administrative access with no detection of automated/scripted attacks or anomalous behavior patterns. The requirement states that network location or trusted endpoints should not be the sole factors, but the system has no factors at all.

**Remediation:**

Implement async def assess_admin_risk(uid, operation) that calculates a risk score based on: (1) IP consistency with session, (2) rapid successive admin operations, (3) geographic anomalies, (4) time-of-day patterns. Log risk assessments and require step-up authentication when risk score exceeds threshold. Implement session binding to device characteristics and rate limiting on administrative endpoints. This provides the multiple layers of security required by ASVS 8.4.2.

---

#### FINDING-113: CSRF token validation not implemented despite placeholder

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | CWE-352 |
| **ASVS Sections** | 8.4.2 |
| **Files** | v3/server/pages.py:basic_info function |
| **Source Reports** | 8.4.2.md |
| **Related Findings** | FINDING-025 |

**Description:**

The basic_info() function sets result.csrf_token = 'placeholder' but no actual CSRF token generation or validation is implemented. All POST-based administrative operations are vulnerable to CSRF. An attacker can craft malicious forms that submit administrative actions. Combined with the lack of authorization checks, this enables cross-site administrative attacks. The placeholder creates false confidence that CSRF protection exists.

**Remediation:**

Replace the placeholder with cryptographic CSRF token generation using secrets.token_urlsafe(32) and store it in the session. Implement async def validate_csrf_token(form_data) that uses hmac.compare_digest to validate the token from form submissions against the session token. Apply validation to all POST endpoints including do_add_issue_endpoint, do_edit_issue_endpoint, do_delete_issue_endpoint, and do_create_endpoint.

---

#### FINDING-114: Incomplete function-level access control documentation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 8.1.1 |
| **Files** | v3/docs/schema.md:entire file |
| **Source Reports** | 8.1.1.md |
| **Related Findings** | - |

**Description:**

The authorization documentation partially defines access rules but lacks comprehensive function-level access control specification. While the documentation mentions ownership (owner_pid) and LDAP group authorization (authz), it does not provide a complete mapping of which functions/operations each role can perform. Missing documentation includes: no explicit listing of all protected functions (open, close, add-issue, edit-issue, delete-issue, set-dates, vote, tally), no matrix mapping consumer permissions (owner, authz group member, eligible voter, committer, PMC member) to allowed operations, the authz field format is explicitly marked TBD indicating incomplete design, no documentation of the R.committer vs R.pmc_member distinction for election creation vs management, and no documentation of what committer status grants vs owner status. Without comprehensive function-level authorization documentation, developers cannot consistently implement checks, and testers cannot verify completeness. The current code has numerous 'check authz' TODO comments confirming that the lack of clear documentation has led to incomplete implementation.

**Remediation:**

Create an Authorization Matrix document specifying a complete mapping of operations to roles. The matrix should include: Operation, Owner, Authz Group, Eligible Voter, Any Committer, and PMC Member columns. Operations to document include: Create Election, View Management, Open Election, Close Election, Add Issue, Edit Issue, Delete Issue, Cast Vote, View Tally, and Set Dates. Each cell should clearly indicate Yes/No/- for whether that role can perform that operation.

---

#### FINDING-115: Missing field-level access restriction documentation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 8.1.2 |
| **Files** | v3/docs/schema.md, v3/steve/election.py:165, v3/steve/election.py:179 |
| **Source Reports** | 8.1.2.md |
| **Related Findings** | - |

**Description:**

The authorization documentation does not define field-level access restrictions for read and write operations. While the code implements some field filtering (e.g., get_metadata() excludes salt and opened_key), there is no documentation specifying which fields each consumer type can read or write, nor how access changes based on election state. Missing documentation includes: which fields voters can read (e.g., can a voter see owner_pid? authz group?), which fields are writable based on election state (e.g., title writable only in EDITABLE state), specification that salt, opened_key, and vote_token are system-internal fields never exposed to consumers, and state-dependent field access rules (e.g., the trigger preventing open_at/close_at modification when closed is in SQL but not documented as a field-level policy).

**Remediation:**

Create comprehensive field-level access control documentation. Example table format: ## Field-Level Access Control ### Election Fields | Field | Owner (Read) | Owner (Write) | Voter (Read) | Voter (Write) | State Dependency | |-------------|-------------|---------------|-------------|---------------|------------------| | eid | Yes | Never | Yes | Never | - | | title | Yes | EDITABLE only | Yes | Never | - | | owner_pid | Yes | Never | No | Never | - | | authz | Yes | EDITABLE only | No | Never | - | | salt | Never | Never | Never | Never | System-only | | opened_key | Never | Never | Never | Never | System-only | | closed | Yes | Via close() | Yes | Never | System-managed | | open_at | Yes | Until CLOSED | Yes | Never | Trigger enforced | | close_at | Yes | Until CLOSED | Yes | Never | Trigger enforced |

---

#### FINDING-116: Missing documentation of environmental and contextual security attributes

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 8.1.3 |
| **Files** | v3/docs/schema.md:entire file, v3/server/pages.py:entire file |
| **Source Reports** | 8.1.3.md |
| **Related Findings** | - |

**Description:**

The application's documentation does not define any environmental or contextual attributes used in security decisions. There is no documentation of whether time of day, user location, IP address, device type, or other contextual factors influence authentication or authorization decisions. The open_at and close_at fields exist in the schema, but the SQL comment explicitly states: 'These are purely advisory, for humans, and have no effect upon the actual Election operation.' No IP-based restrictions, geographic restrictions, or device/browser-based security decisions are documented. The @asfquart.auth.require decorator handles authentication but no documentation defines what contextual factors the authentication system evaluates.

**Remediation:**

Document all environmental/contextual attributes (or explicitly state none are used). Example documentation: ## Environmental and Contextual Security Attributes ### Attributes NOT Used (Intentional Design Decisions) - **Time-of-day**: Not used. Elections are opened/closed manually by owners. - **IP Address**: Not used. ASF committers may access from any location. - **Device type**: Not used. Browser-based access is uniform. - **Geographic location**: Not used. ASF is a global organization. ### Attributes Used - **Authentication session**: OAuth session via asfquart, session timeout per ASF IdP. - **LDAP group membership**: Evaluated at request time for authz group checks. - **Election state**: Time-independent state machine (editable/open/closed) controls operations.

---

#### FINDING-117: Missing documentation of environmental and contextual factors in authorization decision-making

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 8.1.4 |
| **Files** | All documentation files |
| **Source Reports** | 8.1.4.md |
| **Related Findings** | - |

**Description:**

There is no documentation defining how environmental and contextual factors are used in authentication and authorization decision-making, including thresholds, risk levels, and actions taken. Since 8.1.3 established that no environmental/contextual attributes are documented, this requirement naturally follows as unmet—there is no documentation of decision logic, evaluated attributes, risk thresholds, or resulting actions (allow/challenge/deny/step-up). Missing documentation includes: no risk scoring model, no step-up authentication triggers, no adaptive authentication rules, no documentation of when 'deny' vs 'challenge' applies, no documentation of how the ASF IdP session interacts with the application's authorization layer, and no documentation of what happens when LDAP group membership changes mid-session.

**Remediation:**

Create comprehensive decision-making framework documentation that includes: ## Decision-Making Framework ### Authentication Decision Flow | Context | Evaluation | Threshold | Action | |---------------------|-------------------|--------------------|--------------------| | Valid session | Session cookie | Present + valid | Allow | | Expired session | Session timeout | Per ASF IdP config | Redirect to login | | No session | Cookie absence | N/A | Redirect to login | ### Authorization Decision Flow | Context | Evaluation | Threshold | Action | |----------------------|---------------------|---------------------|---------------------| | Election management | owner_pid OR authz | Exact match | Allow or Deny (403) | | Vote casting | mayvote entry | Entry exists | Allow or Deny | | Election creation | PMC membership | LDAP group check | Allow or Deny | ### Factors NOT Evaluated (by design) - IP address changes during session: Not evaluated (global user base) - Concurrent sessions: Not restricted - Rate limiting: Delegated to reverse proxy layer

---

#### FINDING-118: User-controlled data interpolated into flash messages without encoding

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1, L2 |
| **CWE** | CWE-79 |
| **ASVS Sections** | 1.1.2, 1.2.1, 16.4.1 |
| **Files** | v3/server/pages.py:393, v3/server/pages.py:440, v3/server/pages.py:502, v3/server/pages.py:527, v3/server/pages.py:547 |
| **Source Reports** | 1.1.2.md, 16.4.1.md |
| **Related Findings** | FINDING-029, FINDING-119, FINDING-133 |

**Description:**

User-controlled data is interpolated into flash messages without encoding. The encoding/escaping should happen at the point closest to the interpreter (the template), but if EZT templates render flash messages as raw HTML (which is typical for flash message systems that support HTML formatting), this constitutes output encoding NOT being performed as the final step. Data flow: User form input (form.title, iid from form keys) → flash message stored in session → rendered in template on next page load.

**Remediation:**

Implement a sanitization function that removes or encodes characters that could enable log injection (newlines, carriage returns, and other control characters). Replace f-string logging with parameterized logging using format strings. Example: python def sanitize_for_log(value: str) -> str: if value is None: return '' return value.replace('\n', '\\n').replace('\r', '\\r').replace('\x00', '') _LOGGER.info( 'ELECTION_CREATED: uid=%s, election=%s, title=%s', sanitize_for_log(result.uid), sanitize_for_log(election.eid), sanitize_for_log(form.title), )

---

#### FINDING-119: Potential reflected XSS in error page rendering via unencoded URL parameters

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-79 |
| **ASVS Sections** | 1.2.1 |
| **Files** | v3/server/pages.py:677-679 |
| **Source Reports** | 1.2.1.md |
| **Related Findings** | FINDING-029, FINDING-118, FINDING-133 |

**Description:**

The raise_404 function in v3/server/pages.py renders error templates with data from URL path parameters (eid and iid) without HTML encoding. Data flows from URL path (/vote-on/&lt;eid&gt;) → Quart URL-decodes → eid assigned to result.eid → passed to EZT template → rendered as HTML. If the EZT error templates (e.g., e_bad_eid.ezt) render these values without HTML encoding, a malicious URL could inject HTML/JavaScript into the error page. This creates reflected XSS in error pages, with severity dependent on template implementation which cannot be verified from provided code.

**Remediation:**

Apply HTML encoding to URL parameters before passing to error templates. Either: (1) Use html.escape(eid) and html.escape(iid) when assigning to result object before raise_404() call; or (2) Sanitize input by validating format (e.g., result.eid = eid if eid.isalnum() else 'invalid') to ensure only safe characters are passed to templates.

---

#### FINDING-120: Path traversal risk due to missing canonicalization in serve_doc

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L1 |
| **CWE** | CWE-22 |
| **ASVS Sections** | 1.1.1, 5.3.2 |
| **Files** | v3/server/pages.py:584-600 |
| **Source Reports** | 1.1.1.md, 5.3.2.md |
| **Related Findings** | - |

**Description:**

The `serve_doc()` function uses the user-supplied `docname` URL parameter directly in `send_from_directory()` without application-level validation. The developer explicitly acknowledged this gap with the comment `### verify the propriety of DOCNAME.` (Type B gap — developer knows validation is needed but has not implemented it). While Quart's `send_from_directory()` internally uses `safe_join()` to prevent path traversal, there is no defense-in-depth validation at the application layer. While Quart's `safe_join` provides framework-level protection, relying solely on framework internals without application-level validation creates risk if: 1) The framework is upgraded and `safe_join` behavior changes, 2) A bypass is discovered in `safe_join`, 3) The code is refactored to use a different file-serving mechanism. The explicit TODO comment indicates the developer considers this incomplete. Standard path parameters in Quart won't match `/` characters, limiting the immediate traversal risk to `..` sequences without slashes.

**Remediation:**

Add an explicit allowlist regex (e.g., `^[a-zA-Z0-9][a-zA-Z0-9._-]*$`) and reject requests with invalid filenames. Example implementation: python import re SAFE_DOCNAME_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*$') @APP.get('/docs/&lt;iid&gt;/&lt;docname&gt;') @asfquart.auth.require async def serve_doc(iid, docname): result = await basic_info() # Validate docname: only safe characters, no traversal if not SAFE_DOCNAME_RE.match(docname) or '..' in docname: quart.abort(400) db = steve.election.Election.open_database(DB_FNAME) row = db.q_get_mayvote.first_row(result.uid, iid) if not row: quart.abort(404) return await quart.send_from_directory(DOCSDIR / iid, docname)

---

#### FINDING-121: Missing SMTP Header Sanitization in Voter Email Data Retrieval

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-93 |
| **ASVS Sections** | 1.3.11 |
| **Files** | v3/steve/election.py:514-520 |
| **Source Reports** | 1.3.11.md |
| **Related Findings** | - |

**Description:**

The method `get_voters_for_email()` retrieves voter names and email addresses for use in email notifications without enforcing sanitization for SMTP header safety. Person data originates from LDAP/external sources via `c_add_person` INSERT/UPSERT. Neither this method nor the `person` table schema enforces sanitization of email addresses or names. If person names or email addresses contain CRLF sequences (\r\n) or SMTP protocol characters, and are used in email headers (To, From, Subject) without sanitization, an attacker who can influence LDAP data or the person import process could inject additional headers or recipients into outgoing emails. The email sending implementation is not present in the provided source code, so this finding is conditional on how the returned data is used downstream.

**Remediation:**

Implement sanitization to remove CRLF and other SMTP-dangerous characters from header values. Add a sanitize_email_field() function that removes CR, LF, and NULL bytes using regex re.sub(r'[\r\n\x00]', '', value). Apply this sanitization to both name and email fields in the get_voters_for_email() method before returning the voter data. Example: sanitize_email_field(row.name) and sanitize_email_field(row.email).

---

#### FINDING-122: No length or character validation on election titles

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L1 |
| **CWE** | - |
| **ASVS Sections** | 1.3.3, 2.2.1 |
| **Files** | v3/server/pages.py:463 |
| **Source Reports** | 1.3.3.md, 2.2.1.md |
| **Related Findings** | - |

**Description:**

User-supplied text fields (election title, issue title, issue description) are passed directly to the database without any validation. Extremely long titles could cause display issues, memory exhaustion, or denial of service. Empty titles violate logical expectations (NOT NULL ≠ non-empty). No character set validation allows control characters or other problematic content. This affects the `gather_election_data()` anti-tamper hash — maliciously crafted titles could cause issues.

**Remediation:**

Implement server-side validation with maximum length limits (title: 200 characters, description: 10,000 characters). Strip whitespace and validate that titles are non-empty. Example: `title = form.get('title', '').strip(); if not title: await flash_danger('Election title is required.'); return quart.redirect('/admin', code=303); if len(title) > MAX_TITLE_LENGTH: await flash_danger(f'Title must be {MAX_TITLE_LENGTH} characters or less.'); return quart.redirect('/admin', code=303)`

---

#### FINDING-123: Potential JavaScript injection via unescaped user-controlled data in templates

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 1.2.3 |
| **Files** | v3/server/pages.py |
| **Source Reports** | 1.2.3.md |
| **Related Findings** | - |

**Description:**

Without access to the EZT templates, we cannot verify how template variables are rendered in JavaScript contexts. However, the application passes user-controlled data (election titles, issue titles, candidate names from labelmap) to templates. If any EZT template embeds these values directly in &lt;script&gt; blocks or JavaScript event handlers without JSON serialization or JavaScript escaping, this would enable JavaScript injection. The labelmap is particularly concerning — it's stored as JSON in the kv field and contains candidate labels and names that are user-provided during election setup. Data flow: form.title/kv.labelmap → DB storage → list_issues() → template data → potential JavaScript context in template.

**Remediation:**

Ensure all data passed to JavaScript contexts uses json.dumps() for serialization. Example: import json; result.issues_json = json.dumps([{'iid': i.iid, 'title': i.title, 'candidates': i.candidates} for i in result.issues])

---

#### FINDING-124: Incomplete documentation of input validation rules for user-supplied text fields

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 2.1.1 |
| **Files** | v3/docs/schema.md, v3/server/pages.py |
| **Source Reports** | 2.1.1.md |
| **Related Findings** | - |

**Description:**

The documentation (schema.md) defines structural rules for internal identifiers (eid, iid as 10-char hex, salt as 16 bytes, etc.) but fails to document validation rules for user-supplied input data including: Election title (max length, allowed characters, format), Issue title (max length, allowed characters), Issue description (max length, allowed characters, format), Vote string (votestring) format per vote type (yna: expected values, stv: ranking format), Person email format validation rules (RFC 5322 compliance), Person name (max length, allowed characters), Date inputs (expected format, range constraints), and Authorization group (authz) allowed values/format. Developers implementing or maintaining the application have no reference for what constitutes valid input. This leads to inconsistent validation (some fields validated, others not), making it difficult to verify correctness or identify gaps.

**Remediation:**

Create an input-validation.md document specifying validation rules for all user input fields. Document Election Title (Type: String, Required: Yes, Max length: 200 characters, Allowed: Unicode printable characters no control characters, Validation: Non-empty after trimming whitespace). Document Vote String for YNA (Type: String, Required: Yes, Allowed values: yes/no/abstain, Case-insensitive). Document Vote String for STV (Type: String, Required: Yes, Format: Comma-separated candidate labels from issue's labelmap, Validation: Each label must exist in issue.kv.labelmap, no duplicates). Include similar specifications for all other user-supplied input fields.

---

#### FINDING-125: No documentation of temporal consistency rules for election dates

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 2.1.2 |
| **Files** | v3/docs/schema.md, v3/server/pages.py |
| **Source Reports** | 2.1.2.md |
| **Related Findings** | - |

**Description:**

The documentation does not define rules for validating the logical consistency between `open_at` and `close_at` fields. The code (`_set_election_date` in pages.py) sets each date independently without any documented cross-field consistency rule. Without documented consistency rules, dates can be set in illogical combinations (close before open), potentially confusing election administrators and voters.

**Remediation:**

Document the expected temporal relationships: close_at must be after open_at if both are set; open_at should be in the future when the election is editable; neither date can be modified once the election is closed (enforced by trigger). Add a Date Consistency Rules section to the documentation.

---

#### FINDING-126: No documentation of election state consistency with voter/issue operations

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 2.1.2 |
| **Files** | v3/docs/schema.md |
| **Source Reports** | 2.1.2.md |
| **Related Findings** | - |

**Description:**

While the code enforces state-based restrictions (e.g., can only add issues when editable, can only vote when open), these rules are not documented in the business logic documentation. Missing documentation includes: adding voters is only valid when election.salt IS NULL (editable state); adding issues is only valid when election.salt IS NULL; voting is only valid when election.salt IS NOT NULL AND closed != 1; tallying is only valid when closed = 1; issue IID must belong to the election's EID when voting; voter PID must have a mayvote entry for the issue IID. Without documented consistency rules, it's unclear what invariants the system maintains, making it harder to verify completeness of implementation.

**Remediation:**

Add a State Transition Rules section documenting which operations are valid in which states and what cross-entity consistency is required.

---

#### FINDING-127: No documentation of per-user or global business logic limits

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 2.1.3 |
| **Files** | schema.md, TODO.md, create-election.py:67, election.py:169 |
| **Source Reports** | 2.1.3.md |
| **Related Findings** | - |

**Description:**

The application documentation does not define any limits on per-user operations (maximum elections a user can create, maximum issues per election, maximum voters per election/issue, rate limiting on vote submissions, rate limiting on election creation) or global limits (maximum concurrent open elections, maximum total elections in the system, maximum title/description field lengths, maximum number of STV candidates, maximum number of STV seats, timeout for election open/close operations). The create-election.py validates STV seats as positive integer but has no upper bound. The election.py has no limits on issue count. Without documented limits, the application is vulnerable to resource exhaustion (creating thousands of issues/elections) and there's no reference for implementing rate limiting or quotas.

**Remediation:**

Create a business limits document that includes: Per-User limits (Max elections created: 50 configurable, Max concurrent open elections owned: 10), Per-Election limits (Max issues: 500, Max eligible voters: 10,000, Max STV candidates per issue: 50, Max STV seats: candidates - 1), and Global limits (Election title max length: 200 characters, Issue title max length: 200 characters, Issue description max length: 10,000 characters).

---

#### FINDING-128: Date validation checks format but not logical business constraints

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 2.2.1 |
| **Files** | v3/server/pages.py:88-110 |
| **Source Reports** | 2.2.1.md |
| **Related Findings** | - |

**Description:**

The date validation in `_set_election_date()` only checks ISO format parsing, not business logic validity. Elections can be set with nonsensical dates (past dates, close before open, far future dates), confusing administrators and potentially breaking UI display logic. No validation is performed to ensure dates are in the future, that close_at is after open_at, or that dates are within a reasonable range.

**Remediation:**

Add business logic validation for dates. Check that dates are not in the past: `if dt < today: quart.abort(400, 'Date cannot be in the past')`. For close dates, verify they are after open dates: `if field == 'close_at': md = election.get_metadata(); if md.open_at: open_date = datetime.date.fromtimestamp(md.open_at); if dt <= open_date: quart.abort(400, 'Close date must be after open date')`

---

#### FINDING-129: Client-side required field validation not replicated server-side

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 2.2.2 |
| **Files** | v3/server/pages.py, v3/server/templates/manage.ezt:92 |
| **Source Reports** | 2.2.2.md |
| **Related Findings** | - |

**Description:**

The HTML form uses client-side required attribute and JavaScript validation for issue title and other fields, but the server-side handler does NOT verify the field is non-empty. The client-side validation can be easily bypassed by submitting a POST request directly with empty values. This is a Type A gap where server-side required-field validation is absent. Proof of concept: POST /do-add-issue/1a2b3c4d5e with title=&description= bypasses client-side required attribute and creates an issue with empty title. Empty or whitespace-only titles can be stored, violating data quality expectations. The database NOT NULL constraint doesn't prevent empty strings.

**Remediation:**

Add server-side validation: async def do_add_issue_endpoint(election): form = edict(await quart.request.form); title = form.get('title', '').strip(); if not title: await flash_danger('Issue title is required.'); return quart.redirect(f'/manage/{election.eid}', code=303)

---

#### FINDING-130: do_vote_endpoint does not verify voter eligibility for each specific issue

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 2.2.3 |
| **Files** | v3/server/pages.py:372-407, v3/steve/election.py |
| **Source Reports** | 2.2.3.md |
| **Related Findings** | - |

**Description:**

The do_vote_endpoint validates that the IID exists in the election's issue list, but does not explicitly verify that the authenticated user (PID) is eligible to vote on that specific issue (has a mayvote entry for it) before calling add_vote. While add_vote does check mayvote, if the entry is None it results in an AttributeError rather than explicit authorization denial. This is accidental error handling rather than explicit validation.

**Remediation:**

Add explicit mayvote NULL check in add_vote() method. If mayvote is None, raise a clear VoterNotEligible exception rather than allowing AttributeError. This provides clear error handling and distinguishes authorization failures from system errors in logs.

---

#### FINDING-131: No validation that STV vote rankings reference valid candidates from issue's labelmap

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 2.2.3 |
| **Files** | v3/steve/election.py:231-244 |
| **Source Reports** | 2.2.3.md |
| **Related Findings** | - |

**Description:**

For STV issues, the votestring should contain a ranking of candidates whose labels exist in the issue's kv.labelmap. This combined data consistency (vote references valid candidates from the issue's metadata) is not validated. The add_vote() method does not check that votestring candidates are in issue.kv.labelmap, that ranking count is valid, or that there are no duplicate candidates in ranking. Invalid candidate references would corrupt STV tallying results or cause tally errors.

**Remediation:**

Validate that each ranked candidate label exists in the issue's kv.labelmap and there are no duplicates. Check that the ranking count does not exceed the number of candidates. Implement this validation before storing the encrypted vote.

---

#### FINDING-132: Missing browser security feature documentation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 3.1.1 |
| **Files** | Application-wide (no documentation file present), config.yaml.example, header.ezt |
| **Source Reports** | 3.1.1.md |
| **Related Findings** | - |

**Description:**

No application documentation exists specifying the expected browser security features (HTTPS, HSTS, CSP, X-Content-Type-Options, etc.) or defining application behavior when these features are unavailable. The config.yaml.example configures TLS certificates but there is no documentation or code that: 1) Specifies that browsers MUST support HTTPS, 2) Defines HSTS requirements, 3) Specifies Content-Security-Policy requirements, 4) Defines behavior when security features are absent (e.g., blocking HTTP access, warning users), 5) Specifies minimum browser version requirements. The header.ezt template contains no &lt;meta&gt; CSP tags and no JavaScript feature detection.

**Remediation:**

1. Create a security documentation file (e.g., SECURITY.md) specifying: Required: HTTPS, HSTS (max-age≥31536000), CSP with script-src restrictions; Required: X-Content-Type-Options: nosniff, X-Frame-Options or frame-ancestors; Behavior: HTTP requests must redirect to HTTPS; unsupported browsers receive a warning page. 2. Implement corresponding middleware in the application.

---

#### FINDING-133: DOM Clobbering via Global Scope Variables and Unsanitized HTML

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | CWE-79 |
| **ASVS Sections** | 3.2.3 |
| **Files** | v3/server/templates/manage.ezt:JavaScript blocks, v3/server/templates/manage-stv.ezt:JavaScript blocks |
| **Source Reports** | 3.2.3.md |
| **Related Findings** | FINDING-029, FINDING-118, FINDING-119 |

**Description:**

The `manage.ezt` and `manage-stv.ezt` templates declare JavaScript variables in the global scope (not wrapped in an IIFE or module). The variables `openModal`, `closeModal`, `csrfToken`, etc. are global. Additionally, `document.getElementById()` is used extensively to access elements, and the issue descriptions (rendered as raw HTML) could potentially introduce elements with crafted `id` attributes. An admin creates an issue with description containing `<form id="csrf-token"><input name="value" value="attacker-controlled"></form>`. When rendered, `document.getElementById('csrf-token')` would resolve to this injected element, and `.value` would access the form's `value` named element, potentially redirecting the CSRF token to an attacker value.

**Remediation:**

1. Wrap all page-level JavaScript in IIFEs: `(function() { 'use strict'; const csrfToken = document.getElementById('csrf-token').value; // ... rest of code })();` 2. Sanitize HTML in issue descriptions to prevent `id` and `name` attribute injection 3. Use more specific selectors that are harder to clobber: `const csrfToken = document.querySelector('input#csrf-token[type="hidden"]').value;`

---

#### FINDING-134: Session cookies lack __Host- prefix

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 3.3.3 |
| **Files** | v3/server/main.py:38, v3/server/pages.py:72 |
| **Source Reports** | 3.3.3.md |
| **Related Findings** | - |

**Description:**

The application uses session cookies managed by the `asfquart` framework (via `asfquart.session.read()`), but there is no visible configuration anywhere in the provided code that sets the `__Host-` prefix for the session cookie name. Without the `__Host-` prefix, the session cookie could potentially be: set by a subdomain attacker (cookie tossing), transmitted over unencrypted connections, or scoped to a different path than intended.

**Remediation:**

Configure the session cookie name with the __Host- prefix in app configuration: `app.config['SESSION_COOKIE_NAME'] = '__Host-steve_session'`. Note that __Host- prefix requires Secure=True, Path=/, and no Domain attribute, which are automatically enforced by compliant browsers when __Host- is used.

#### FINDING-135: Session cookie HttpOnly attribute not explicitly configured

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | |
| ASVS sections | 3.3.4 |
| Files | v3/server/main.py:38, v3/server/pages.py:60-90 |
| Source Reports | 3.3.4.md |
| Related | |

**Description:**

The session cookie configuration is not visible in the provided code. The application stores sensitive session data (uid, fullname, email) via `asfquart.session`, but there is no explicit `SESSION_COOKIE_HTTPONLY = True` configuration or equivalent. While the `asfquart`/Quart framework may default to HttpOnly, the absence of explicit configuration cannot be verified. Data flow: User authenticates via OAuth → session token stored in cookie → cookie potentially readable by client-side JavaScript if HttpOnly not set → XSS could steal session tokens. Without HttpOnly, session tokens could be exfiltrated via XSS attacks. Given the EZT template system lacks auto-escaping (noted in domain context) and the `flashes.ezt` template renders flash messages without explicit escaping, this is a heightened risk.

**Remediation:**

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

---

#### FINDING-136: No CORS configuration is visible in the application code

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | |
| ASVS sections | 3.4.2 |
| Files | v3/server/main.py:entire file, v3/server/pages.py:entire file |
| Source Reports | 3.4.2.md |
| Related | |

**Description:**

No CORS configuration is visible in the application code. While this may be intentional (no cross-origin API access needed), the ASVS requirement states that the CORS policy should be explicitly configured. The absence of CORS headers means the browser's same-origin policy applies by default, which is the most restrictive setting. However, without explicit verification, we cannot confirm that no other middleware (e.g., `asfquart` internals or the reverse proxy mentioned in config) adds permissive CORS headers.

**Remediation:**

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

---

#### FINDING-137: Missing Referrer-Policy header allows leakage of sensitive URL paths to third-party services

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2, L3 |
| CWE | |
| ASVS sections | 3.4.5, 3.7.5 |
| Files | v3/server/main.py:application-wide, v3/server/templates/header.ezt, v3/server/templates/footer.ezt, v3/server/templates/about.ezt |
| Source Reports | 3.4.5.md, 3.7.5.md |
| Related | |

**Description:**

The application does not configure any HTTP security response headers. Without these headers, browsers cannot enforce security features, and there is no mechanism to detect when a browser ignores or doesn't support expected policies. Missing headers include: Content-Security-Policy (restricts script execution, blocks inline scripts, report-uri can detect violations), Strict-Transport-Security (enforces HTTPS, prevents downgrade attacks, browser must support), X-Content-Type-Options: nosniff (prevents MIME sniffing, browser feature enforcement), Permissions-Policy (restricts browser APIs, feature restriction/detection), and Content-Security-Policy-Report-Only (monitors policy violations, detects browsers not enforcing CSP). This results in no defense-in-depth via CSP for XSS prevention, no HSTS means browsers may downgrade to HTTP, no MIME type enforcement means potential content-type attacks, and no visibility into browser security feature support.

**Remediation:**

Add after_request handler in main.py create_app() function to set security headers on all responses. Include Content-Security-Policy with default-src 'self', script-src 'self', style-src 'self', img-src 'self' https://www.apache.org, frame-ancestors 'none', and report-uri /csp-report. Set Strict-Transport-Security to max-age=31536000; includeSubDomains. Add X-Content-Type-Options: nosniff, X-Frame-Options: DENY, Permissions-Policy: camera=(), microphone=(), geolocation=(), and Referrer-Policy: strict-origin-when-cross-origin.

---

#### FINDING-138: Missing Cross-Origin-Opener-Policy header on HTML responses

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | |
| ASVS sections | 3.4.8 |
| Files | v3/server/main.py:application-wide, v3/server/pages.py:all HTML-rendering routes |
| Source Reports | 3.4.8.md |
| Related | |

**Description:**

No Cross-Origin-Opener-Policy header is set on any HTML response. This leaves the application vulnerable to attacks that abuse shared access to Window objects: (1) Tabnabbing - If a user opens a link from the application in a new tab (e.g., the external links in footer.ezt to apache.org), the opened page can manipulate window.opener to redirect the original page. (2) Frame counting - Cross-origin pages can count the number of frames/windows, leaking information about application state. The footer template includes target="_open_privacy_link" which opens new windows, creating opener references.

**Remediation:**

Add an after_request handler to set the Cross-Origin-Opener-Policy header on all HTML responses:

```python
@app.after_request
async def set_security_headers(response):
    if 'text/html' in response.content_type:
        response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    return response
```

---

#### FINDING-139: JSON Endpoints Lack Content-Type Enforcement

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | |
| ASVS sections | 3.5.2 |
| Files | v3/server/pages.py:88 |
| Source Reports | 3.5.2.md |
| Related | |

**Description:**

While get_json() typically requires Content-Type: application/json (which would trigger a CORS preflight), the manage.ezt template's JavaScript sends requests with explicit Content-Type: application/json header. However, if Quart's get_json() has a force=True option or falls back to parsing regardless of content-type, a request with text/plain (CORS-safelisted) could bypass preflight. The server does not explicitly validate the Content-Type header. Additionally, the client-side code sends CSRF token as custom header (X-CSRFToken), which WOULD trigger a CORS preflight, providing a form of protection — however the server never validates this header value, making it defense-in-depth only if the request format changes.

**Remediation:**

Explicitly verify Content-Type to ensure preflight was triggered. Example: In _set_election_date function, add a check: if request.content_type != 'application/json': quart.abort(415, 'Content-Type must be application/json'). This ensures the request format cannot be changed to bypass preflight checks.

---

#### FINDING-140: No Sec-Fetch-* Header Validation on Any Endpoint

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | |
| ASVS sections | 3.5.3 |
| Files | v3/server/pages.py:entire file |
| Source Reports | 3.5.3.md |
| Related | |

**Description:**

The application does not validate Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, or Sec-Fetch-User headers on any endpoint. Modern browsers send these headers automatically and they cannot be forged by JavaScript. Validating them provides an additional layer of cross-origin protection. All state-changing endpoints should reject requests where Sec-Fetch-Site: cross-site or Sec-Fetch-Mode: no-cors. This is a missed opportunity for defense-in-depth. If Sec-Fetch headers were validated, even the GET endpoints would have some protection against cross-origin exploitation.

**Remediation:**

Implement a before_request middleware to validate Sec-Fetch headers. Reject cross-origin requests to sensitive endpoints by checking if Sec-Fetch-Site is 'cross-site' or 'none' for POST/PUT/DELETE/PATCH methods. For GET state-changing endpoints (until fixed), reject requests where Sec-Fetch-Dest is 'image', 'script', or 'style' to prevent resource embedding attacks.

---

#### FINDING-141: External Image Resource Loaded Without Integrity Verification

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3, L2 |
| CWE | |
| ASVS sections | 3.6.1, 3.4.3 |
| Files | v3/server/templates/header.ezt:14 |
| Source Reports | 3.6.1.md, 3.4.3.md |
| Related | |

**Description:**

Browser loads page → fetches SVG from `https://www.apache.org` → no integrity verification → SVG rendered in page. If the external Apache CDN is compromised or DNS is hijacked, a malicious SVG could be served. SVG files can contain embedded JavaScript when loaded via `<object>` or `<embed>`, though `<img>` tags restrict script execution. However, a compromised SVG could still be modified for phishing (e.g., changing the logo to impersonate another entity). While `<img>`-loaded SVGs cannot execute scripts, this represents a dependency on an unverified external resource. A compromised or modified image could affect application trust perception. SRI is not supported on `<img>` tags by browsers, making this a design issue.

**Remediation:**

Option 1: Self-host the image (recommended) - `<img src="/static/images/feather.svg" alt="Logo" width="30" height="30" class="d-inline-block align-text-top">`. Option 2: Document the security decision for this specific resource, noting that img-loaded SVGs cannot execute scripts.

---

#### FINDING-142: OAuth Redirect URI Pattern May Be Susceptible to Open Redirect Without Allowlist Validation

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | |
| ASVS sections | 3.7.2 |
| Files | v3/server/main.py:37-41, v3/server/templates/header.ezt:28, v3/server/templates/header.ezt:37 |
| Source Reports | 3.7.2.md |
| Related | |

**Description:**

User or attacker crafts URL → `/auth?login=https://evil.com` → framework processes login parameter → after authentication, redirects to attacker-controlled URL. An attacker sends a phishing link: `https://steve.example.org/auth?login=https://evil.com/steal-session`. If the `login=` parameter value is used as a post-authentication redirect without validation against an allowlist, the user will be redirected to the attacker's site after authenticating. Open redirect enabling phishing attacks. After legitimate authentication at `oauth.apache.org`, users could be redirected to attacker-controlled sites that mimic the application, potentially capturing credentials or session tokens. The `/auth` endpoint implementation is in the asfquart framework (not provided). This finding is based on the observable pattern that login/logout parameters accept path values, and no allowlist validation is visible in the provided code.

**Remediation:**

In the auth handling (asfquart framework or custom middleware): Add an ALLOWED_REDIRECT_PATHS allowlist containing safe internal paths like {'/voter', '/admin', '/'}. Implement a validate_redirect function that ensures redirect target is a safe internal path by parsing the URL and rejecting any with scheme or netloc, or that don't start with '/'. Return a default safe redirect '/' if validation fails.

---

#### FINDING-143: External Links Navigate Without User Notification or Cancellation Option

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | |
| ASVS sections | 3.7.3 |
| Files | v3/server/templates/footer.ezt:8-12, v3/server/templates/home.ezt:46-49, v3/server/templates/about.ezt:7 |
| Source Reports | 3.7.3.md |
| Related | |

**Description:**

Users are navigated away from the authenticated application without notification. While these specific links go to trusted Apache-controlled domains, there is no architectural pattern in place to handle this for any future external links. This is a Level 3 requirement and the absence of the pattern means it cannot be verified. Data flow: User clicks external link → browser immediately navigates to https://www.apache.org/... or https://steve.apache.org/ → no interstitial warning → no cancel option

**Remediation:**

Add an external redirect interstitial page with validation against allowlist of trusted domains. For untrusted domains, render an interstitial template with cancel option. Implement /external-link endpoint that validates target URLs against TRUSTED_DOMAINS allowlist and renders external_redirect.ezt template with Continue and Cancel buttons for non-trusted domains.

---

#### FINDING-144: Inline JavaScript Without CSP Nonce/Hash Strategy

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | |
| ASVS sections | 3.7.5 |
| Files | v3/server/templates/manage.ezt:all, v3/server/templates/admin.ezt:all, v3/server/templates/vote-on.ezt:all, v3/server/templates/manage-stv.ezt:all, v3/server/templates/voter.ezt:all, v3/server/pages.py:all |
| Source Reports | 3.7.5.md |
| Related | |

**Description:**

Every interactive template contains substantial inline JavaScript. Without CSP headers and a nonce/hash strategy, if CSP were ever added, it would require 'unsafe-inline' which defeats the purpose. The current architecture makes it impossible to implement proper CSP-based browser security feature enforcement. Templates with inline scripts include: manage.ezt (~120 lines inline JS), manage-stv.ezt (~100 lines inline JS), vote-on.ezt (~200 lines inline JS), admin.ezt (~20 lines inline JS), and voter.ezt (~20 lines inline JS). This prevents implementation of strict CSP without 'unsafe-inline', means browsers cannot enforce script source restrictions, gives XSS attacks full access to page context, and prevents CSP violation reporting for these scripts.

**Remediation:**

Generate a CSP nonce per request on the Python side (e.g., result.csp_nonce = secrets.token_hex(16)) and pass to templates. Add nonce attribute to all inline script tags in templates (e.g., &lt;script nonce="[csp_nonce]"&gt;). Update CSP header to include script-src 'self' 'nonce-{csp_nonce}'. Alternatively, refactor inline scripts into external .js files referenced by src attribute to eliminate need for nonces.

---

#### FINDING-145: No Prerequisite Validation Before Election Opening

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | CWE-754 |
| ASVS sections | 2.3.1 |
| Files | v3/steve/election.py:70, v3/server/pages.py:431 |
| Source Reports | 2.3.1.md |
| Related | |

**Description:**

The `open()` method does not validate that an election has the necessary prerequisites (issues and eligible voters) before allowing it to be opened. An attacker can create an election and immediately open it without adding any issues or voters, resulting in a logically invalid and irreversible election state. This represents a skipped step in the business flow (configure → validate → open).

**Remediation:**

Add prerequisite validation in the `open()` method: verify that at least one issue exists (`issues = self.list_issues(); if not issues: raise ValueError('Cannot open election with no issues')`) and that at least one eligible voter is registered (`self.q_voting_persons.perform(self.eid); voters = self.q_voting_persons.fetchall(); if not voters: raise ValueError('Cannot open election with no eligible voters')`).

---

#### FINDING-146: No Logical Constraint Validation on Election Dates

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | CWE-20 |
| ASVS sections | 2.3.2 |
| Files | v3/server/pages.py:88 |
| Source Reports | 2.3.2.md |
| Related | |

**Description:**

The _set_election_date() function validates date format but does not perform logical validation on election dates. It accepts dates in the past and does not verify that close_at is after open_at. This could result in confusing or misleading date information displayed to voters and could be used to manipulate voter behavior, such as showing a close date has passed to discourage voting while the election is still open.

**Remediation:**

Add logical date validation to ensure close_at is after open_at and that dates are not set to unreasonable values in the past. Implement business logic constraints that enforce sensible date ranges for elections.

---

#### FINDING-147: Election Creation Script Has Transaction Code Commented Out

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | CWE-662 |
| ASVS sections | 2.3.3 |
| Files | v3/server/bin/create-election.py:83, v3/server/bin/create-election.py:109 |
| Source Reports | 2.3.3.md |
| Related | FINDING-046, FINDING-047 |

**Description:**

The create-election.py script has transaction wrapping code (BEGIN TRANSACTION, COMMIT, ROLLBACK) commented out with a TODO note. If voter addition fails partway through (e.g., PID not found), the election is left with some but not all eligible voters. No rollback occurs, leaving the election in a partially configured state.

**Remediation:**

Re-enable the transaction wrapping code by uncommenting the BEGIN TRANSACTION, COMMIT, and ROLLBACK statements. Ensure database setup allows for proper transaction support.

---

#### FINDING-148: Vote Table Allows Unlimited Re-Votes Without Locking or Rate Control

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | CWE-770 |
| ASVS sections | 2.3.4 |
| Files | v3/steve/election.py:231, v3/queries.yaml:44 |
| Source Reports | 2.3.4.md |
| Related | |

**Description:**

Each call to add_vote() performs a pure INSERT into the vote table. There's no UPDATE or UPSERT — every submission creates a new row. No limit on how many rows a single vote_token can accumulate. Repeatedly POSTing to /do-vote/&lt;eid&gt; with the same ballot adds a new row for each issue on each submission. After 1000 submissions, there are 1000 rows per vote_token, consuming storage and making tally queries slower. While re-voting is an intended feature (only the latest vote counts), there's no limit on how many times a voter can re-vote, potentially exhausting storage or degrading tally performance.

**Remediation:**

Consider either an UPDATE pattern (replacing the existing vote) or limiting re-votes per voter per issue. Add rate limiting on the /do-vote/&lt;eid&gt; endpoint. Consider implementing vote garbage collection to periodically remove superseded vote rows to prevent unbounded table growth.

---

#### FINDING-149: Irreversible Election State Changes Require Only Single-User Action

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | CWE-863 |
| ASVS sections | 2.3.5 |
| Files | v3/server/pages.py:431, v3/server/pages.py:451 |
| Source Reports | 2.3.5.md |
| Related | FINDING-251 |

**Description:**

Opening an election triggers irreversible cryptographic operations (salt generation, opened_key computation). Closing an election permanently ends voting. Both actions have significant organizational impact — voters may be disenfranchised by premature closure, or an improperly configured election may be opened without review. A single user (or compromised account) can irreversibly alter election state without oversight. For an organization like the ASF where elections determine governance, this represents a high-value operation that should require multi-party approval.

**Remediation:**

Add approval workflow: Create endpoints for requesting state changes (/do-request-open/&lt;eid&gt;) that record the request and notify approvers. Create approval endpoints (/do-approve-open/&lt;eid&gt;) that verify the approver is different from the requester, verify approver has authority, and execute the state change only after approval.

---

#### FINDING-150: No Minimum Time Enforcement in add_vote() Business Logic

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | CWE-799 |
| ASVS sections | 2.4.2 |
| Files | v3/steve/election.py:231 |
| Source Reports | 2.4.2.md |
| Related | |

**Description:**

The business logic layer for vote submission has no concept of vote timing. There is no tracking of when a voter last submitted a vote, no minimum interval enforcement between re-votes, and no defense-in-depth against automated vote submission. The vote table lacks a timestamp column that could enable retroactive timing analysis. Combined with the handler-level lack of rate limiting, there is zero defense-in-depth against automated vote submission.

**Remediation:**

Add timestamp tracking to the vote submission logic. Check time since last vote by the same vote_token and raise VoteTooRapid exception if submitted within minimum revote interval. Implement query to retrieve last vote time and enforce minimum interval at business logic layer.

---

#### FINDING-151: Configuration Template Missing TLS Version Controls

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | |
| ASVS sections | 12.1.1 |
| Files | v3/server/config.yaml.example:6-12 |
| Source Reports | 12.1.1.md |
| Related | |

**Description:**

The configuration template provides no guidance or fields for specifying TLS protocol versions. Administrators deploying this application have no documented mechanism to enforce TLS 1.2+ or prefer TLS 1.3.

**Remediation:**

Add TLS version configuration to the example config: server.certfile, server.keyfile, and server.min_tls_version: "1.2" (Minimum TLS version 1.2 or 1.3)

---

#### FINDING-152: OCSP Stapling Not Configured for TLS Server

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | |
| ASVS sections | 12.1.4 |
| Files | v3/server/main.py:75-82, v3/server/config.yaml.example |
| Source Reports | 12.1.4.md |
| Related | |

**Description:**

No OCSP stapling is configured for the TLS server. If a server certificate is compromised and revoked, clients will not be efficiently informed of the revocation status. Without OCSP stapling: Clients must perform their own OCSP lookups (slower, privacy-leaking), many clients soft-fail OCSP checks meaning revoked certificates may still be accepted, and the development configuration uses self-signed certificates (where OCSP is not applicable), but production deployments need this.

**Remediation:**

For production deployment with Hypercorn, configure OCSP stapling in the SSL context by creating an SSL context with minimum TLS version 1.2, loading the certificate chain, and enabling OCSP stapling if response is available. For Hypercorn-based deployment, add ssl configuration to hypercorn.toml with certfile and keyfile paths, and configure a reverse proxy (nginx/Apache) with OCSP stapling enabled. Note that full OCSP stapling requires periodic refresh of the OCSP response.

---

#### FINDING-153: Self-Signed Certificates Used with No Pathway to Publicly Trusted Certificates for External-Facing Services

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | |
| ASVS sections | 12.2.2 |
| Files | v3/server/config.yaml.example:25-31, v3/docs/quickstart.md:49-53 |
| Source Reports | 12.2.2.md |
| Related | |

**Description:**

The example configuration and documentation exclusively reference self-signed certificates. While the architecture document mentions 'Typical usage is that a proxy sits in front of this server,' there is: 1. No production configuration example with publicly trusted certificates 2. No documentation on deploying with publicly trusted TLS certs 3. No validation that configured certificates are publicly trusted 4. The certs/ directory structure implies certificate storage alongside code. External-facing clients (voters, administrators) connecting directly to this service would encounter certificate warnings or be vulnerable to MITM attacks if self-signed certificates are used in production.

**Remediation:**

Provide a production configuration example using Let's Encrypt or other CA-signed certificates. Add deployment documentation requiring publicly trusted certificates for production. Consider integrating ACME (Let's Encrypt) certificate provisioning. Example production config: server: port: 443, certfile: /etc/letsencrypt/live/voting.example.org/fullchain.pem, keyfile: /etc/letsencrypt/live/voting.example.org/privkey.pem

---

#### FINDING-154: No TLS Enforcement in ASGI Deployment Mode

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | |
| ASVS sections | 12.2.1 |
| Files | v3/server/main.py:88-108 |
| Source Reports | 12.2.1.md |
| Related | |

**Description:**

When running in ASGI mode (production deployment via Hypercorn), TLS configuration is entirely delegated to the external ASGI server. There is no validation or enforcement within the application that TLS is being used. The application code does not verify that the ASGI server has TLS configured, set any TLS-related response headers (HSTS), reject non-HTTPS requests, or check X-Forwarded-Proto when behind a proxy.

**Remediation:**

Add middleware to enforce HTTPS in ASGI mode. Implement @APP.before_request handler to check both quart.request.is_secure and X-Forwarded-Proto header, aborting with 403 if neither indicates HTTPS. Document required TLS configuration for Hypercorn and proxy deployments.

---

#### FINDING-155: No Visible TLS Certificate Validation for Outbound OAuth Connections

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | |
| ASVS sections | 12.3.2 |
| Files | v3/server/main.py:44-49 |
| Source Reports | 12.3.2.md |
| Related | |

**Description:**

The application makes outbound HTTPS connections to oauth.apache.org for authentication. The actual HTTP client implementation is within asfquart (not provided), and there is no visible code confirming: 1. TLS certificate validation is enabled (not verify=False), 2. Certificate chain is validated against system trust store, 3. Hostname verification is performed. While Python's urllib/requests/httpx default to validating certificates, custom HTTP clients or misconfiguration could disable this. If certificate validation is disabled or improperly configured in the asfquart OAuth client, the application would be vulnerable to MITM attacks during the OAuth flow, potentially allowing token theft or session hijacking.

**Remediation:**

Verify that the asfquart library's HTTP client has certificate validation enabled. Add explicit configuration to enforce certificate verification: import httpx; async with httpx.AsyncClient(verify=True) as client: response = await client.get(oauth_url)

---

#### FINDING-156: Self-Signed Certificates for Internal/Development Use with No Trust Management

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | |
| ASVS sections | 12.3.4 |
| Files | v3/docs/quickstart.md:49-53, v3/server/config.yaml.example:25-31 |
| Source Reports | 12.3.4.md |
| Related | |

**Description:**

The system uses self-signed certificates but there is no: 1. Internal CA configuration or documentation 2. Trust store management for consuming services 3. Certificate pinning for internal connections 4. Guidance on which specific self-signed certificates should be trusted by clients/proxies. If the reverse proxy connects to this backend, it would need to trust the self-signed certificate. Without a specific internal CA or pinning configuration, this creates a risk that any self-signed certificate could be accepted. A consuming service (reverse proxy) configured to trust "any" self-signed certificate or to skip validation when connecting to this backend would be vulnerable to MITM attacks on the internal network.

**Remediation:**

Establish an internal CA and document certificate provisioning. Configure the reverse proxy to pin the specific backend certificate or trust only the internal CA. Example nginx proxy configuration: upstream backend { server localhost:58383; } server { location / { proxy_pass https://backend; proxy_ssl_trusted_certificate /etc/nginx/internal-ca.pem; proxy_ssl_verify on; } }

---

#### FINDING-157: Incomplete documentation of application communication needs

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | |
| ASVS sections | 13.1.1 |
| Files | v3/ARCHITECTURE.md, v3/docs/schema.md, v3/server/config.yaml.example, v3/server/main.py:36-40, v3/server/bin/mail-voters.py:67-73, v3/steve/election.py:37, v3/server/pages.py:560-574 |
| Source Reports | 13.1.1.md |
| Related | |

**Description:**

The application communicates with multiple external services, but there is no comprehensive communication inventory document. The following communication channels were identified through code analysis but are not formally documented in a single reference: 1) ASF OAuth Service (external authentication) at oauth.apache.org, 2) SMTP/Email Service (voter notification), 3) SQLite Database (local persistence), 4) LDAP Service (authorization, referenced but not implemented), 5) End-user-provided document filenames (potential SSRF vector). Without comprehensive communication documentation, security teams cannot perform complete threat modeling, firewall rule validation, or network segmentation reviews. Undocumented external dependencies may introduce unmonitored attack surfaces.

**Remediation:**

Create a dedicated COMMUNICATIONS.md or equivalent document that inventories: All external service endpoints (OAuth, SMTP, LDAP), Protocol, port, and authentication method for each, Direction of communication (inbound/outbound), User-controllable endpoints or file references, Network security requirements (TLS versions, cipher suites)

---

#### FINDING-158: No documentation of concurrent connection limits or fallback mechanisms for any service

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | |
| ASVS sections | 13.1.2 |
| Files | v3/ARCHITECTURE.md, v3/steve/election.py:35-44, v3/server/pages.py:165-186, 297 |
| Source Reports | 13.1.2.md |
| Related | |

**Description:**

The application interacts with multiple services (SQLite, OAuth, SMTP) but there is no documentation defining maximum concurrent connections, connection pool limits, or behavior when those limits are reached. Database connections are opened per-operation without pooling. Each Election() instantiation opens a new database connection. Web handlers create new Election/PersonDB instances per request without connection management. ARCHITECTURE.md mentions connections without limits. No documentation exists for maximum concurrent SQLite connections, OAuth service connection timeouts/limits, SMTP connection pooling or rate limits, or fallback behavior if any service becomes unavailable. Under high load or during service outages, the application may exhaust file descriptors, memory, or other resources. Without defined limits and fallback mechanisms, a denial-of-service condition could result from legitimate traffic spikes or upstream service degradation.

**Remediation:**

Document for each service: connection pool size or maximum concurrent connections, queue/backpressure behavior when limits are reached, circuit breaker or fallback patterns. Example configuration: database.max_connections: 10, database.connection_timeout_ms: 5000, database.behavior_at_limit: queue (or reject), oauth.max_concurrent_requests: 5, oauth.timeout_ms: 10000, oauth.fallback: deny_login, smtp.max_concurrent_sends: 3, smtp.retry_on_failure: false

---

#### FINDING-159: No documented resource-management strategies, timeout settings, or retry logic for external services

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | |
| ASVS sections | 13.1.3 |
| Files | v3/ARCHITECTURE.md, v3/steve/election.py, v3/server/main.py:37-40, v3/server/bin/mail-voters.py:67-73, v3/server/pages.py:165-186 |
| Source Reports | 13.1.3.md |
| Related | |

**Description:**

The application documentation does not define resource-management strategies for any external system. Code analysis reveals the following gaps: 1) No timeout settings for database operations (SQLite's default timeout for busy/locked databases is 5 seconds, but this is never explicitly configured or documented). 2) No resource-release procedures documented (Database connections are released in some cases but not others. Connections are closed in delete() method but normal request-serving paths via load_election decorator never explicitly close connections). 3) Email sending has no retry or timeout configuration (The mail-voters.py script sends emails without timeout, retry configuration, or error handling per recipient). 4) OAuth callback has no documented timeout (OAuth callback URL has no timeout or failure handling documented). 5) No retry limits, delays, or back-off algorithms documented anywhere. Without defined resource management strategies: Database locks could cause indefinite hangs under concurrent access, Failed email sends could silently drop voter notifications, OAuth service outages could leave requests hanging, Resource leaks from unclosed connections could degrade availability over time.

**Remediation:**

Create a resource management section in documentation covering: SQLite Database (Timeout: 30 seconds via sqlite3 timeout parameter, Release: Connections closed after each request via context manager, Failure handling: Return 503 if database is locked beyond timeout, Retry: No retries for synchronous operations); OAuth/ASF OAuth (Timeout: 10 seconds for token exchange, Retry: None - redirect user to retry login, Failure handling: Display error page with retry option); SMTP/Email (Timeout: 30 seconds per message, Retry: Up to 2 retries with 5-second delay, Back-off: Not applicable for batch script, Failure handling: Log error, continue to next recipient)

---

#### FINDING-160: No secrets rotation schedule or lifecycle management documentation

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | |
| ASVS sections | 13.1.4 |
| Files | v3/docs/schema.md, v3/steve/crypto.py:27-29, 32-41, v3/server/config.yaml.example, v3/server/pages.py:83 |
| Source Reports | 13.1.4.md |
| Related | |

**Description:**

While the application documents what secrets exist and how they are generated, there is no documentation defining a rotation schedule or lifecycle management for any secret. Secrets identified in the system include: 1) Election salts (16 bytes) generated once at election opening, never rotated; 2) Mayvote salts (16 bytes) generated once at election opening, never rotated; 3) Opened keys (32 bytes) derived once for tamper detection; 4) TLS certificate private keys with path documented but no rotation; 5) Session secrets managed by asfquart, not documented; 6) OAuth client credentials referenced but not documented; 7) CSRF tokens currently placeholder ('placeholder'), not a real secret. What's documented: Salt field purposes and generation method, key derivation algorithm (Argon2), encryption algorithm (Fernet, planned migration to XChaCha20-Poly1305). What's missing: Rotation schedule for TLS certificates, rotation procedures if election salts are compromised, session secret rotation policy, OAuth credential rotation, impact assessment if any secret is compromised, classification of secrets by criticality. Without a defined rotation schedule, compromised secrets may remain in use indefinitely. The placeholder CSRF token represents a complete absence of this security control, which could allow cross-site request forgery attacks.

**Remediation:**

Create a secrets management document with the following structure: Secrets Inventory and Rotation Schedule table including: Secret, Criticality, Rotation Schedule, Rotation Procedure. Specific recommendations: TLS private key (Critical) - Annual or on compromise, re-issue certificate, deploy, restart; Session signing key (High) - Monthly, update config, restart server; OAuth client secret (High) - Annual, coordinate with ASF OAuth team; Election salts (Medium) - N/A (single-use per election lifecycle), cannot rotate once election opened; CSRF tokens (High) - Per-session, automatically generated per session. Include Compromise Response section: If TLS key compromised: Revoke certificate immediately, re-issue; If session key compromised: Rotate key, invalidate all sessions; If election salt compromised: Election integrity may be violated; re-run if possible.

---

#### FINDING-161: All application components use identical full-privilege database access

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | |
| ASVS sections | 13.2.2 |
| Files | v3/steve/election.py:35-37, v3/steve/persondb.py:25-26, v3/server/bin/create-election.py:31, v3/server/bin/mail-voters.py:28, v3/server/pages.py:40 |
| Source Reports | 13.2.2.md |
| Related | |

**Description:**

All application modules — web handlers, business logic, command-line tools — access the SQLite database with the same full read/write permissions. There is no privilege separation. Web request handlers, Election model, PersonDB, and CLI tools all use identical database access patterns with full permissions. Specific concerns include: (1) The mail-voters.py script only needs READ access to election metadata and voter emails, but has full write access to the database, (2) The voter-facing endpoints (e.g., /vote-on/&lt;eid&gt;) can technically invoke any database operation (create elections, delete data) since the same Election class is used, (3) No OS-level service account separation between the web server and CLI tools. If any component is compromised (e.g., through a web vulnerability), the attacker gains full database access including ability to modify election results, delete elections, or alter voter records. The mail-voters.py script could be leveraged to modify data if compromised.

**Remediation:**

1. For SQLite: Implement application-level privilege separation by using different database wrapper classes with restricted query sets (example provided: VoterDB class with read-only access and ALLOWED_QUERIES whitelist). 2. For CLI tools, use read-only database connections where write access is not needed (example: mail-voters.py should use sqlite3.connect with mode=ro). 3. Document the principle of least privilege for each component and its required access level.

---

#### FINDING-162: No allowlist defined for outbound resource access or file system access patterns

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | |
| ASVS sections | 13.2.4 |
| Files | v3/server/pages.py:560-574 |
| Source Reports | 13.2.4.md |
| Related | |

**Description:**

User-supplied docname URL parameter is passed to quart.send_from_directory(DOCSDIR / iid, docname) for file system access with no allowlist of permitted file types or names. While send_from_directory typically prevents path traversal, there is no allowlist of permitted document types/names. The comment '### verify the propriety of DOCNAME.' explicitly acknowledges this gap. Without an allowlist of permitted document types/names, any file placed in the DOCSDIR/iid/ directory could be served, and the intent of the developer (per the TODO comment) was clearly to restrict this further.

**Remediation:**

Implement an allowlist of permitted document extensions (e.g., ALLOWED_DOC_EXTENSIONS = {'.pdf', '.txt', '.md', '.html'}). Validate docname against this allowlist by checking the file extension. Ensure no path separators ('/', '\\', '..') are present in docname. Example code provided in finding validates extension and rejects path separators.

---

#### FINDING-163: Database connections opened without documented configuration for timeouts, connection limits, or retry strategies

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | |
| ASVS sections | 13.2.6 |
| Files | v3/steve/election.py:36, v3/steve/persondb.py:27, v3/server/pages.py:567 |
| Source Reports | 13.2.6.md |
| Related | |

**Description:**

Multiple call sites open database connections through asfpy.db.DB() without timeout, pool limit, or retry configuration. No connection timeout means requests could hang indefinitely if the database file becomes locked. No maximum connection limit means concurrent requests could exhaust file handles. No retry strategy means transient failures (e.g., WAL checkpoint) cause immediate errors. Database connections are opened per-request without pooling.

**Remediation:**

Implement configuration constants for DB_TIMEOUT (30 seconds), DB_MAX_CONNECTIONS (10), DB_RETRY_ATTEMPTS (3), and DB_RETRY_DELAY (0.5 seconds). Set PRAGMA busy_timeout on connections and enable WAL mode for better concurrency. Example: db.conn.execute('PRAGMA busy_timeout = 30000') and db.conn.execute('PRAGMA journal_mode = WAL').

---

#### FINDING-164: Internal _all_metadata() method exposes SALT and OPENED_KEY to any code with Election object access

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | |
| ASVS sections | 13.3.2 |
| Files | v3/steve/election.py:130 |
| Source Reports | 13.3.2.md |
| Related | |

**Description:**

The _all_metadata() method is marked as 'INTERNAL ONLY' by convention (leading underscore and comment), but Python does not enforce access control. Any code with access to an Election instance can call election._all_metadata() to retrieve the salt and opened_key. The __getattr__ proxy method (line 48) further means that query cursors like q_metadata are directly accessible on the Election object. If authorization gaps exist (and they do — multiple ### check authz placeholders), any authenticated user who obtains an Election object could access sensitive cryptographic material through the internal API.

**Remediation:**

Return a wrapper object that prevents serialization of sensitive fields. Example implementation provided in finding creates _InternalMetadata class with __slots__ to prevent accidental exposure and redacted __repr__ for safe logging.

#### FINDING-165: Per-voter-per-issue salt values have no expiration or rotation mechanism

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 13.3.4 |
| Files | v3/schema.sql:130-139, v3/steve/election.py |
| Source Reports | 13.3.4.md |
| Related Findings | - |

**Description:**

Per-voter-per-issue salt values in the mayvote table have no expiration or rotation mechanism. These salts are critical for deriving vote_token and encryption keys. Once set during add_salts(), they remain unchanged for the lifetime of the database. The mayvote table stores salt values (16 bytes) that persist indefinitely with no lifecycle management.

**Remediation:**

Implement a key lifecycle policy that: (1) Documents expected lifetimes for all secret material, (2) Removes or re-encrypts key material after election finalization, (3) Implements automated cleanup of secrets past their useful life. Consider implementing secret rotation for long-running elections or a maximum election duration policy.

---

#### FINDING-166: Static file endpoint serves source control metadata

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Sections | 13.4.1 |
| Files | v3/server/pages.py:577-578 |
| Source Reports | 13.4.1.md |
| Related Findings | - |

**Description:**

The /static/&lt;path:filename&gt; endpoint accepts paths with subdirectories (e.g., .git/config, .svn/entries). If a .git or .svn folder exists within STATICDIR (which could occur from development/deployment practices), it would be served to clients. While send_from_directory should prevent path traversal above the root, it will serve any file within the directory tree including source control metadata.

**Remediation:**

Add explicit blocking of source control metadata paths using a regex pattern to reject requests containing .git, .svn, .hg, or .bzr directory components. Example implementation provided in finding.

---

#### FINDING-167: Debug print() statements expose form data to stdout in production

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 13.4.2, 16.2.3, 16.5.1, 14.2.4 |
| Files | v3/server/pages.py:476, v3/server/pages.py:497 |
| Source Reports | 13.4.2.md, 16.2.3.md, 16.5.1.md, 14.2.4.md |
| Related Findings | - |

**Description:**

Two endpoint handlers dump complete form data to stdout via print() statements. This creates an undocumented log channel that: 1) Bypasses the _LOGGER system and its configured handlers, 2) Is not subject to any log access controls, 3) May output to container stdout (captured by orchestrators), console, or wherever stdout is redirected, 4) Is not mentioned in any logging inventory (which doesn't exist per 16.1.1). Form data containing election titles, descriptions, and potentially sensitive organizational information is broadcast to an uncontrolled output stream. In containerized environments, stdout is typically captured and may be accessible to operators who should not see election configuration details.

**Remediation:**

Remove debug print statements and use structured logging with appropriate level. Example: Remove `print('FORM:', form)` and replace with `_LOGGER.debug(f'Adding issue to election[E:{election.eid}]')` without logging form content.

---

#### FINDING-168: No Server/Framework Version Header Suppression Configured

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 13.4.6 |
| Files | v3/server/main.py:52, v3/server/main.py:94 |
| Source Reports | 13.4.6.md |
| Related Findings | - |

**Description:**

HTTP request → Hypercorn/asfquart server → HTTP response with default Server header → client receives version info. Hypercorn (used in ASGI mode, referenced in comments at line ~117) and the underlying framework typically include a Server header (e.g., Server: hypercorn-h11) in HTTP responses by default. This reveals the specific server technology, enabling targeted attacks against known vulnerabilities in that version. No configuration is present to suppress or override this header.

**Remediation:**

For Hypercorn, in hypercorn.toml or programmatically: server_names = [""]. Or add middleware to strip version headers: @app.after_request async def remove_version_headers(response): response.headers.pop('Server', None); response.headers.pop('X-Powered-By', None); return response

---

#### FINDING-169: Sensitive Files Co-located With Application Without Explicit Web Tier File Extension Filtering

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 13.4.7 |
| Files | v3/server/config.yaml.example, v3/server/main.py:27-28 |
| Source Reports | 13.4.7.md |
| Related Findings | - |

**Description:**

The application directory contains sensitive files including config.yaml (database path, TLS configuration), steve.db (SQLite database with all election data), certs/*.pem (TLS private keys), and *.py (source code). The config comment states 'a proxy sits in front of this server' (line ~23 of config.yaml.example), but no proxy configuration with file extension allowlisting is provided. If the proxy is misconfigured to serve files from the application directory, all these sensitive files become accessible.

**Remediation:**

Provide and enforce proxy configuration with explicit file extension allowlisting. Example nginx configuration: Block direct file access with deny rules for extensions like .yaml, .yml, .db, .sqlite, .pem, .key, .py, .pyc, .cfg, .ini, .env, .git, .log. If static assets are needed, only allow specific extensions like .css, .js, .png, .jpg, .jpeg, .gif, .ico, .svg, .woff, .woff2.

---

#### FINDING-170: Incomplete formal data classification with protection levels

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 14.1.1 |
| Files | v3/docs/schema.md:entire document |
| Source Reports | 14.1.1.md |
| Related Findings | - |

**Description:**

The schema documentation describes individual fields and their cryptographic properties, but does not formally classify data into distinct protection levels. While the document mentions that certain fields are "cryptographic" (salts, opened_key, vote_token, ciphertext), it does not establish a tiered classification system (e.g., Public / Internal / Confidential / Restricted) that maps each data element to a defined protection level. The following sensitive data items are described but not formally classified: Per-voter salts (mayvote.salt), Election salts (election.salt), Opened keys (election.opened_key), Vote ciphertext (vote.ciphertext), Vote tokens (vote.vote_token), Voter identities (mayvote.pid linking to person.pid), Person emails (person.email). Without formal classification, developers cannot consistently apply appropriate protection controls. Data that requires the highest level of protection (e.g., the linkage between voter identity and vote) may be treated identically to lower-sensitivity data (e.g., election titles). Compliance with privacy regulations (GDPR, etc.) requires documented data classification.

**Remediation:**

Create a formal data classification document that: 1. Defines protection levels (e.g., Public, Internal, Confidential, Restricted) 2. Maps each data element to a protection level 3. References applicable regulatory requirements. Example: Create a Data Classification table mapping vote.ciphertext to RESTRICTED level with ballot secrecy laws basis and encryption at rest controls; mayvote.salt to RESTRICTED level never logged or transmitted outside server; election.opened_key to CONFIDENTIAL level never exposed via API; mayvote.pid + iid linkage to CONFIDENTIAL level never exposed post-election with access logging; person.email to INTERNAL level with GDPR/Privacy basis and encryption at rest; election.title to PUBLIC level with standard web protections.

---

#### FINDING-171: No documented protection requirements per data sensitivity level

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 14.1.2 |
| Files | v3/docs/schema.md:entire document |
| Source Reports | 14.1.2.md |
| Related Findings | - |

**Description:**

While the schema documentation describes what cryptographic mechanisms are used, it does not document the required set of protection controls for each sensitivity level. The ASVS requirement explicitly mandates documentation covering: encryption, integrity verification, retention, logging controls, access controls for sensitive data in logs, database-level encryption, privacy and privacy-enhancing technologies. Missing documentation areas include: data retention (NOT DOCUMENTED - no policy for closed elections, old votes, or person data), logging requirements (NOT DOCUMENTED - no specification of what can/cannot be logged), access controls for logs (NOT DOCUMENTED - no mention of log protection), database-level encryption (NOT DOCUMENTED - no requirement for filesystem/disk encryption). General encryption requirements and integrity verification are only partially documented (Fernet mentioned, XChaCha20 planned; opened_key for tamper detection). Privacy-enhancing technologies are partially documented (vote shuffling mentioned in code but not in docs).

**Remediation:**

Create a protection requirements document for each data level. For RESTRICTED data (votes, salts, opened_keys): Encryption using AES-256 equivalent (currently Fernet, migrating to XChaCha20-Poly1305); Integrity via Argon2-based tamper detection via opened_key comparison; Retention of encrypted votes until election results certified + 90 days, then purged; Logging to NEVER log plaintext votes, salts, or decryption keys, log only vote_token existence; Log access restricted to ops team for server logs containing election operations; Database encryption with SQLite database file on encrypted filesystem (LUKS/dm-crypt); Privacy via per-voter salts to prevent vote correlation and votes shuffled before tallying. For CONFIDENTIAL data (voter identities, emails, voter-issue linkages): Encryption protected by TLS in transit, filesystem encryption at rest; Retention of person records while active in LDAP, removed 1 year after LDAP removal; Logging where PIDs may be logged for audit but emails MUST NOT be logged; Access where voter-issue linkages accessible only to election owner during open state.

---

#### FINDING-172: Exception objects logged in error handler may contain sensitive cryptographic context

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 14.2.4 |
| Files | v3/server/pages.py:do_vote_endpoint |
| Source Reports | 14.2.4.md |
| Related Findings | - |

**Description:**

If `election.add_vote()` fails during cryptographic operations (e.g., Fernet encryption, Argon2 hashing, HKDF derivation), the exception object may contain: partial key material in error context, salt values referenced in the traceback, internal state of cryptographic primitives, database query parameters including vote_tokens. This violates the requirement that sensitive data access in logs must be controlled. Data flow: Cryptographic operation failure → Exception message (may contain key material, salt values, or internal state) → `_LOGGER.error()` → server logs

**Remediation:**

Log only sanitized error information. Replace `_LOGGER.error(f'Error adding vote for user[U:{result.uid}] on issue[I:{iid}]: {e}')` with `_LOGGER.error(f'Error adding vote for user[U:{result.uid}] on issue[I:{iid}]: {type(e).__name__}')` and optionally `_LOGGER.debug(f'Vote error details: {e}')` for DEBUG level only, never in production.

---

#### FINDING-173: Authenticated document serving endpoint lacks cache-control headers and content-type validation

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | CWE-524 |
| ASVS Sections | 14.2.5 |
| Files | v3/server/pages.py:605-620 |
| Source Reports | 14.2.5.md |
| Related Findings | - |

**Description:**

The serve_doc() endpoint serves sensitive election documents to authenticated users but does not set cache-control headers or validate content types. If a caching layer (CDN, reverse proxy) sits in front of the application, authenticated responses could be cached and served to unauthorized users. The lack of Content-Type validation means responses may be cached under unexpected content types. Additionally, the docname parameter is not validated, potentially allowing path manipulation.

**Remediation:**

Validate docname parameter to only allow safe filenames using regex pattern. Set Cache-Control: no-store and X-Content-Type-Options: nosniff headers on the response before returning. Example: response.headers['Cache-Control'] = 'no-store' and response.headers['X-Content-Type-Options'] = 'nosniff'.

---

#### FINDING-174: tally_issue() returns full voter PIDs instead of minimum required data

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 14.2.6 |
| Files | v3/steve/election.py:241-270 |
| Source Reports | 14.2.6.md |
| Related Findings | - |

**Description:**

The function returns the complete set of voter PIDs (identities) alongside tally results. Per the domain context, voter identities (mayvote.who) are sensitive data. While knowing who voted (not how they voted) may be acceptable for election monitoring, returning full PIDs exceeds the minimum required data. A count of voters would suffice for most UI purposes.

**Remediation:**

Return voter count instead of full voter identities for general use. Create a separate privileged method for admin use that returns full voter identities. Example: modify tally_issue() to return len(voters) and create tally_issue_with_voters() for admin-only access.

---

#### FINDING-175: get_voters_for_email() returns all voter identities in bulk

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 14.2.6 |
| Files | v3/steve/election.py:433-438 |
| Source Reports | 14.2.6.md |
| Related Findings | - |

**Description:**

This function returns all voter identities (PID, name, email) for an entire election. While this may be needed for sending ballot links, it exposes sensitive voter identity data. Per domain context, voter identities are sensitive and should be minimized. If this data is ever exposed through a page template or API response, it would violate minimum data principles.

**Remediation:**

Ensure this function is only called in strictly necessary contexts (e.g., email sending), and never returned in page templates or API responses. Consider returning only the fields needed for the specific use case, such as creating a get_voter_emails_for_notification() method that returns only email addresses.

---

#### FINDING-176: Authenticated user data persists in browser DOM without cleanup mechanism

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Sections | 14.3.1 |
| Files | v3/server/pages.py:61-87 |
| Source Reports | 14.3.1.md |
| Related Findings | - |

**Description:**

Authenticated user data (uid, name, email) is injected into every page's DOM through template rendering via the basic_info() function. Without a client-side mechanism to clear the DOM or browser cache on session termination, this data persists in browser history, back-forward cache, and potentially in browser developer tools. The ASVS requirement specifically mentions 'browser DOM' should be cleared after session termination.

**Remediation:**

Add session timeout headers and client-side cleanup using after_request middleware: @APP.after_request async def add_security_headers(response): s = await asfquart.session.read(); if s: response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'; response.headers['Pragma'] = 'no-cache'; response.headers['Expires'] = '0'; return response

---

#### FINDING-177: No verification mechanism for dependency source integrity

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 15.1.2 |
| Files | Project-wide |
| Source Reports | 15.1.2.md |
| Related Findings | - |

**Description:**

There is no evidence of hash verification for downloaded packages (e.g., `--require-hashes` in pip, or hash entries in a lock file). While the domain context states dependencies should come from PyPI (a trusted source), there is no cryptographic verification that installed packages match expected artifacts. Supply chain attacks via package repository compromise or typosquatting would not be detected during installation.

**Remediation:**

Use `uv lock` with hash verification or pip's `--require-hashes` with entries like: cryptography==43.0.0 --hash=sha256:abc123...

---

#### FINDING-178: No documentation highlighting risky third-party components despite known risks

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 15.1.4 |
| Files | Project-wide, election.py |
| Source Reports | 15.1.4.md |
| Related Findings | - |

**Description:**

The domain context explicitly notes that "`ezt` is not widely used, which may be a risk factor," yet no formal documentation exists that classifies this or other components according to their risk profile. Based on the ASVS definition of "risky components" (poorly maintained, unsupported, end-of-life, or history of significant vulnerabilities), the following components warrant documented risk assessment: `ezt` (not widely used, small maintainer base, niche templating engine), `easydict` (simple utility, low activity repository), `asfpy` (ASF-internal library, limited community review), and `argon2-cffi` (well-maintained but wraps C library via cffi). Without documented risk assessment, teams cannot make informed decisions about whether additional sandboxing is needed for risky components, whether alternatives should be evaluated, what additional testing is required for these components, and appropriate monitoring for vulnerability disclosures.

**Remediation:**

Create `docs/RISKY_COMPONENTS.md` documenting each risky component with: Risk Level (Critical/High/Medium/Low), Risk Factors (specific indicators like limited community adoption, small maintainer pool), Mitigation strategies (e.g., restrict to rendering pre-validated data only), Review Frequency (quarterly/annual), and Alternatives Considered. For example, document `ezt` as Medium risk due to limited community adoption and small maintainer pool, with mitigation to restrict to rendering pre-validated data only and quarterly review frequency, noting Jinja2 as a more maintained alternative. Document `easydict` as Low risk with infrequent updates, noting it could be replaced with dataclasses. Document `asfpy` as Low-Medium risk as internal ASF library with limited external security review, with trust boundary at organizational level. Include component risk assessment process and alternative evaluation records.

---

#### FINDING-179: No documentation highlighting dangerous functionality used in the application

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 15.1.5 |
| Files | v3/steve/election.py:410, v3/steve/crypto.py:91-101, v3/steve/crypto.py:75-88, v3/server/main.py:40-41, v3/steve/crypto.py:63-70 |
| Source Reports | 15.1.5.md |
| Related Findings | - |

**Description:**

The application contains several instances of "dangerous functionality" as defined by ASVS (deserialization, dynamic code execution, raw data parsing, direct memory manipulation) that are not documented with their risks and mitigations: 1. Deserialization of data (json.loads) in json2kv method - While JSON is safer than pickle/yaml, it still processes structured data from database storage. 2. Low-level cryptographic operations (argon2.low_level) - Direct use of low_level API bypasses safety checks of the high-level argon2 API. 3. Symmetric encryption/decryption with key material handling - create_vote and decrypt_votestring functions handle sensitive cryptographic operations. 4. Dynamic module imports - pages and api modules are dynamically imported. 5. HKDF key derivation with hardcoded info parameter - The info parameter references XChaCha20 but the derived key is used for Fernet, which could confuse auditors or lead to incorrect cryptographic assumptions. Without documentation, developers and auditors cannot quickly identify where the most security-sensitive code resides, what additional review/testing these areas require, what the acceptable input constraints are for dangerous operations, and what the blast radius is if a vulnerability is found in these areas.

**Remediation:**

Create docs/DANGEROUS_FUNCTIONALITY.md documenting: Cryptographic Key Derivation (crypto.py) - Type: Direct memory manipulation (Argon2 low-level), key material handling, Location: v3/steve/crypto.py:_hash(), _b64_vote_key(), gen_opened_key(), Risk: Incorrect parameters could weaken vote encryption, Mitigation: Parameters benchmarked, unit tested, review required for changes, Input Trust: All inputs are system-generated (salts, tokens) — not user-controlled; Vote Encryption/Decryption (crypto.py) - Type: Symmetric encryption with derived keys, Location: v3/steve/crypto.py:create_vote(), decrypt_votestring(), Risk: Key leakage exposes all votes for an election, Mitigation: Keys derived per-voter-per-issue, never stored in plaintext; Data Deserialization (election.py) - Type: JSON deserialization, Location: v3/steve/election.py:json2kv(), Risk: Low (JSON parser, data sourced from database), Mitigation: Data written by application's own kv2json(); no untrusted input; Dynamic Module Loading (main.py) - Type: Dynamic imports at startup, Location: v3/server/main.py:create_app(), Risk: Module injection if filesystem compromised, Mitigation: Imports are hardcoded module names, not user-controlled strings.

---

#### FINDING-180: Default group configuration includes all dependency groups

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 15.2.3 |
| Files | v3/pyproject.toml:36 |
| Source Reports | 15.2.3.md |
| Related Findings | - |

**Description:**

The `default-groups = "all"` setting instructs `uv` to install ALL dependency groups by default, including development and linting tools (`faker`, `python-ldap`, `coverage`, `ruff`, `mypy`). If a production deployment uses `uv install` or `uv sync` without explicitly overriding this setting, development dependencies will be installed in the production environment. Specifically, the following would be present in production: `faker` (test data generation, could expose test utilities), `python-ldap` (if only needed for dev/testing LDAP scenarios), `coverage` (code coverage tool), `ruff`/`mypy` (code analysis tools). Development tools in production expand the attack surface. `faker` could be imported to generate fake data, `coverage` can instrument code for information disclosure, and unnecessary packages increase the supply chain attack surface.

**Remediation:**

Change the default to only include production groups, or remove the `default-groups` directive entirely. For production deployments, ensure the deployment script explicitly excludes dev groups using `uv sync --no-group dev --no-group lint`.

---

#### FINDING-181: ASF-internal packages without explicit repository pinning

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 15.2.4 |
| Files | v3/pyproject.toml:11-12 |
| Source Reports | 15.2.4.md |
| Related Findings | - |

**Description:**

The packages `asfpy` and `asfquart` are Apache Software Foundation internal packages. While they are published on PyPI, there is no explicit configuration pinning these packages to a specific index URL or verifying their integrity via hashes. Key concerns: 1. No lock file visible: No `uv.lock`, `poetry.lock`, or `requirements.txt` with hashes is provided in this audit scope. Without hash pinning, a compromised PyPI package (or a typosquat like `asfppy` or `asfquart2`) could be substituted. 2. No index URL restriction: The `pyproject.toml` does not configure a specific package index for ASF packages. If the organization uses an internal registry alongside PyPI, there's a potential for dependency confusion. 3. No integrity verification: No `[tool.uv.sources]` or equivalent configuration specifying the expected source for these packages. Impact: If an attacker publishes a higher-versioned malicious package with the same name on PyPI (or compromises the existing package), it could be installed in place of the legitimate dependency. This is partially mitigated by the packages being published on PyPI by ASF, but the absence of hash pinning means integrity is not cryptographically verified.

**Remediation:**

1. Maintain a lock file with integrity hashes: `uv lock` to generate uv.lock with cryptographic hashes for all packages. 2. Consider explicit source configuration for ASF packages using `[tool.uv.sources]` to specify index URLs. 3. Use `--require-hashes` or equivalent in CI/CD deployment to enforce integrity verification.

---

#### FINDING-182: EasyDict Dependency Enables Attribute-style Mass Assignment Patterns

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 15.3.3 |
| Files | v3/pyproject.toml:14 |
| Source Reports | 15.3.3.md |
| Related Findings | - |

**Description:**

The `easydict` library converts dictionary keys to object attributes, which can facilitate mass assignment when user-controlled input dictionaries are passed directly to such objects. Without explicit field whitelisting at the controller/action level (which cannot be verified from `pyproject.toml` alone), this dependency introduces an architectural pattern that could enable mass assignment. The domain context explicitly states: 'Mass assignment risks exist in form handling—input should be explicitly mapped to model fields.' This confirms the risk is recognized but mitigation cannot be verified from the available code. An attacker could potentially inject or modify fields not intended for user modification (e.g., `owner_pid`, `is_admin`, election state fields) if request data is mapped to model objects without explicit field filtering.

**Remediation:**

Use explicit field extraction instead of passing request data directly to EasyDict objects. Example: ALLOWED_FIELDS = {"title", "description", "start_date", "end_date"}; form_data = await request.form; election_data = {k: form_data[k] for k in ALLOWED_FIELDS if k in form_data}. Implement explicit field whitelisting at every state-changing endpoint. Add input schema validation (e.g., using `pydantic` or manual whitelists).

---

#### FINDING-183: SQLite Shared Database Access Without Explicit Synchronization in Async Context

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 15.4.1, 15.4.3 |
| Files | v3/pyproject.toml |
| Source Reports | 15.4.1.md, 15.4.3.md |
| Related Findings | - |

**Description:**

The domain context confirms: "No explicit locking mechanisms are visible for the database" and "Thread safety should be considered for shared resources, though Quart's async model reduces some concurrency risks." SQLite has several concurrency constraints: Only one writer at a time (default journal mode), concurrent reads are allowed, and in WAL mode, one writer + multiple readers are allowed. In an async Quart application, multiple coroutines can attempt database writes concurrently (e.g., two voters submitting votes simultaneously to the same election). Without explicit synchronization (e.g., asyncio.Lock), this could result in: database is locked errors, race conditions in read-modify-write patterns (e.g., checking voter eligibility then inserting vote), and TOCTOU vulnerabilities (check if voter has voted → insert vote, where concurrent requests pass the check).

**Remediation:**

Implement an encapsulated database access layer with explicit locking: Create a DatabaseManager class that encapsulates all locking logic for database access with an internal write lock (asyncio.Lock) that is not exposed. Implement an atomic_write context manager that acquires write lock with timeout (5.0 seconds) to prevent deadlocks. Configure SQLite busy_timeout to prevent indefinite blocking during concurrent access. Enable WAL mode with PRAGMA journal_mode = WAL to allow concurrent reads during write operations. Add atomic transaction wrappers ensuring all state-check-then-act patterns use BEGIN IMMEDIATE transactions. Consider using aiosqlite to wrap SQLite access in async-compatible library to properly integrate with Quart's event loop without blocking.

---

#### FINDING-184: Insufficient Evidence of Atomic Operations for Vote State Checks

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 15.4.2 |
| Files | - |
| Source Reports | 15.4.2.md |
| Related Findings | - |

**Description:**

The domain context explicitly states 'No explicit locking mechanisms are visible for the database' and the application uses SQLite with synchronous operations in an async (Quart) framework. In a voting system, critical TOCTOU-susceptible operations include: checking voter eligibility (mayvote) before recording a vote, checking election state (open/closed) before accepting a vote, and checking if a voter has already voted before allowing re-vote. Without the application source code, it is impossible to verify whether these checks and subsequent actions are performed atomically (e.g., within a single SQLite transaction with appropriate isolation level). If election state or voter eligibility checks are not atomic with the dependent action, a race condition could allow votes to be recorded after an election closes or by unauthorized voters during a brief window.

**Remediation:**

Ensure all state-check-then-act patterns are wrapped in SQLite transactions. Example: Atomic eligibility check + vote insertion using BEGIN IMMEDIATE to acquire write lock immediately, then check eligibility and insert vote within the same transaction, with proper ROLLBACK on failure and COMMIT on success. Configure SQLite busy_timeout to prevent indefinite blocking during concurrent access. Enable WAL mode using PRAGMA journal_mode = WAL to allow concurrent reads during write operations. Implement encapsulated database manager to own all locking logic and database connections. Add atomic transaction wrappers for all state-check-then-act patterns. Add concurrency tests that simulate concurrent vote submissions to validate behavior under contention.

---

#### FINDING-185: Mixed logging mechanisms (print vs logger) create undocumented output channels

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 16.1.1 |
| Files | v3/server/pages.py:427, v3/server/pages.py:449, v3/server/bin/tally.py:127, v3/server/bin/tally.py:152, v3/server/bin/tally.py:157 |
| Source Reports | 16.1.1.md |
| Related Findings | - |

**Description:**

Multiple code paths use `print()` statements alongside the formal `_LOGGER` system. These bypass any logging framework configuration (formatters, handlers, filters, destinations) and output to stdout directly, creating undocumented log channels that cannot be inventoried. Security-relevant information (form submissions, tamper detection alerts) exits through channels not covered by any logging policy, potentially being lost or logged without proper access controls.

**Remediation:**

Replace all print statements with proper logging calls. Use `_LOGGER.debug()` for form data logging and `_LOGGER.critical()` for security events like tamper detection. Example: `_LOGGER.debug(f'Form data received for issue creation in election[E:{election.eid}]')` and `_LOGGER.critical(f'TAMPER DETECTED: Election[E:{election_id}] integrity check failed')`.

---

#### FINDING-186: Authorization failure events lack structured metadata

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 16.2.1 |
| Files | v3/server/pages.py:199-201 |
| Source Reports | 16.2.1.md |
| Related Findings | - |

**Description:**

When a user attempts to access an election they are not authorized to vote in, the application returns a 404 but does not log this authorization failure. This is a security event (potential enumeration or unauthorized access attempt) that should include WHO tried, WHAT they tried to access, WHEN, and the outcome. Authorization failures are invisible to security monitoring. Repeated attempts to access unauthorized elections cannot be detected or alerted upon.

**Remediation:**

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

---

#### FINDING-187: Election state change operations in election.py lack logging

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 16.2.1 |
| Files | v3/steve/election.py:110-115, v3/steve/election.py:117-137 |
| Source Reports | 16.2.1.md |
| Related Findings | - |

**Description:**

Critical election lifecycle operations (`close()`, `add_salts()`, `delete()`) do not emit log entries at the library level. While `pages.py` logs the close event when invoked via the web interface, direct library usage (e.g., from `tally.py` or future integration paths) leaves no trace. If the library is used outside the web context, security-critical state changes occur without audit trails.

**Remediation:**

```python
def close(self):
    "Close an election."
    assert self.is_open()
    self.c_close.perform(self.eid)
    _LOGGER.info(f'Election[E:{self.eid}] state changed to CLOSED')
```

---

#### FINDING-188: No logging format configuration enforces UTC timestamps

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 16.2.2 |
| Files | v3/server/bin/tally.py:165, v3/server/pages.py |
| Source Reports | 16.2.2.md |
| Related Findings | - |

**Description:**

The application does not configure a logging format that ensures: 1. Timestamps are present in every log entry 2. Timestamps use UTC (or include explicit timezone offset) 3. Time sources are synchronized across components. The logging.basicConfig(level=logging.INFO) in tally.py uses the default format which does NOT include a timestamp at all (default format is %(levelname)s:%(name)s:%(message)s). The web server's logging configuration is not shown but relies on framework defaults which typically use local time without timezone. Additionally, pages.py uses datetime.datetime.now() (line 571) and datetime.datetime.fromtimestamp() (line 86) without timezone awareness, suggesting a general lack of UTC discipline.

**Remediation:**

Configure UTC timestamps globally:
```python
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S.%fZ',
)
logging.Formatter.converter = time.gmtime  # Force UTC

# Or use a JSON formatter for structured logging
import json_log_formatter
formatter = json_log_formatter.JSONFormatter()
handler = logging.StreamHandler()
handler.setFormatter(formatter)
# Timestamps will be ISO 8601 with timezone
```

---

#### FINDING-189: No structured logging format enables machine parsing and correlation

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 16.2.4 |
| Files | v3/server/pages.py:all logging calls, v3/steve/election.py:all logging calls |
| Source Reports | 16.2.4.md |
| Related Findings | - |

**Description:**

The application uses unstructured f-string log messages that vary in format between modules. While the [U:xxx], [E:xxx], [I:xxx] convention is helpful, the overall format is not machine-parseable without custom regex patterns. Issues include: 1) No common structured format (JSON, CEF, CLF) is used, 2) Inconsistent field ordering: Some messages start with "User[U:]", others with "Created", 3) No correlation ID: No request ID or trace ID to correlate multiple log entries from the same request, 4) Mixed separators: Uses semicolons, commas, and natural language inconsistently, 5) No event type field: Cannot filter by event category without text matching. Log processors (ELK, Splunk, CloudWatch) would require custom parsing rules for each message variant. Automated alerting on patterns like "3 failed access attempts in 5 minutes" becomes difficult without structured fields.

**Remediation:**

Implement structured logging using structlog or python-json-logger to produce JSON log entries with consistent fields. Example: logger.info("election.vote_cast", actor_uid=result.uid, election_id=election.eid, issue_id=iid, event_type="security", action="vote_cast"). Output should be: {"event": "election.vote_cast", "actor_uid": "jdoe", "election_id": "a1b2c3d4e5", ...}

---

#### FINDING-190: Tally output includes full voter identity list without classification controls

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 16.2.5 |
| Files | v3/server/bin/tally.py:129-132 |
| Source Reports | 16.2.5.md |
| Related Findings | - |

**Description:**

The JSON output format includes a complete sorted list of voter PIDs (`voters=sorted(all_voters)`). This reveals which specific individuals voted on each issue, which could be considered sensitive in some election contexts (e.g., someone's participation/non-participation in a controversial vote). The voter list is output without any masking or classification-based control. While knowing WHO voted doesn't reveal HOW they voted (votes are shuffled), participation patterns could be sensitive. The sorted output also enables easy diff-ing between multiple tallies to identify new voters.

**Remediation:**

Option 1: Hash voter identities in output using `hashlib.sha256(v.encode()).hexdigest()[:12]`. Option 2: Only include voter count, not identities, and make voters list available only with --verbose flag.

---

#### FINDING-191: Exception details potentially leak sensitive information into error logs

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 16.2.5 |
| Files | v3/server/pages.py:356 |
| Source Reports | 16.2.5.md |
| Related Findings | - |

**Description:**

The catch-all `Exception` handler logs the full exception message (`{e}`). Depending on the failure mode, this could include: cryptographic operation details (key derivation failures, Fernet errors), database state information (SQLite error messages with table/column names), internal path information, or partial sensitive data that caused the error. The error message is not sanitized before logging. Exception messages could leak internal implementation details into logs. If logs are accessible to a broader audience than the application code, this creates an information disclosure risk.

**Remediation:**

Sanitize exception logging to only include exception type and use exc_info parameter for detailed tracebacks: `_LOGGER.error(f'Vote submission failed for user[U:{result.uid}] on issue[I:{iid}] in election[E:{election.eid}]: {type(e).__name__}', exc_info=True)`

---

#### FINDING-192: No Authentication Metadata Captured in Existing Logs

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 16.3.1 |
| Files | v3/server/pages.py:106-108, v3/server/pages.py:404-407, v3/server/pages.py:440-443 |
| Source Reports | 16.3.1.md |
| Related Findings | - |

**Description:**

The existing log messages record user actions but do not include authentication metadata (authentication type, factors used, session age, IP address). Even where actions are logged, there's insufficient metadata to correlate events with authentication context (OAuth provider, MFA status, source IP).

**Remediation:**

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

---

#### FINDING-193: Election State Assertion Failures Not Logged

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 16.3.3 |
| Files | v3/steve/election.py:multiple |
| Source Reports | 16.3.3.md |
| Related Findings | - |

**Description:**

State validation uses Python assert statements which raise AssertionError without logging. Attempts to bypass election state controls (e.g., voting in a closed election, modifying an open election) produce no audit trail. These are business logic bypass attempts that should be logged per ASVS 16.3.3. Assertions are also disabled when Python runs with optimization (-O flag), making this a potential security bypass. Affected functions: delete, open, close, add_issue, edit_issue, delete_issue, add_voter, add_vote.

**Remediation:**

Replace assert statements with explicit conditional checks that log security events before raising exceptions:
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

---

#### FINDING-194: Assertion Errors Not Caught or Logged at Application Level

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 16.3.4 |
| Files | v3/steve/election.py:48, v3/steve/election.py:69, v3/steve/election.py:115, v3/steve/election.py:178, v3/steve/election.py:197, v3/steve/election.py:211, v3/steve/election.py:238 |
| Source Reports | 16.3.4.md |
| Related Findings | - |

**Description:**

Multiple critical operations use assert for state validation. If assertions fail (indicating an unexpected state or security control failure), no structured logging occurs. Security control failures (election in wrong state) produce unstructured stack traces rather than structured security event logs. When running with -O (optimized mode), these checks are completely disabled.

**Remediation:**

Replace assert statements with proper conditional checks that log security events before raising exceptions

#### FINDING-195: Database Connectivity Failures Not Explicitly Logged

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 16.3.4 |
| Files | v3/steve/election.py:28 |
| Source Reports | 16.3.4.md |
| Related Findings | - |

**Description:**

Database connection failures would produce SQLite exceptions without application-level logging. Backend infrastructure failures (database unavailability, file system issues) would not be captured as structured security events.

**Remediation:**

Wrap database connection logic with try-except block that logs connection failures with _LOGGER.error() before re-raising

---

#### FINDING-196: No Log Protection Configuration

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 16.4.2 |
| Files | v3/server/bin/tally.py:163 |
| Source Reports | 16.4.2.md |
| Related Findings | - |

**Description:**

The logging configuration uses basicConfig with no file protection, access control, or integrity measures. Logs are written to stdout/stderr with no write-once/append-only guarantees, file permissions configuration, log rotation with integrity verification, transmission to a protected centralized system, or digital signatures or checksums on log entries.

**Remediation:**

Implement separate output handling for sensitive audit data. Ensure voter lists and other sensitive information are written to protected storage with appropriate access controls rather than stdout. Consider implementing data classification and handling policies for different types of output.

---

#### FINDING-197: No Centralized Logging Configuration in Web Application

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 16.4.2 |
| Files | v3/server/pages.py |
| Source Reports | 16.4.2.md |
| Related Findings | - |

**Description:**

The web application uses Python's logging module but there is no evidence of log forwarding to a centralized system, log file protection configuration, separate log storage from application server, or log integrity verification. While the infrastructure may provide these protections (e.g., container logging drivers, syslog forwarding), the application code shows no explicit configuration ensuring log protection.

**Remediation:**

Configure centralized log shipping with integrity verification. Implement log forwarding to a protected centralized system. Configure separate log storage from the application server with appropriate access controls. Add explicit log protection configuration in application code rather than relying solely on infrastructure.

---

#### FINDING-198: HTTP 400 responses expose specific validation failure reasons

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 16.5.1 |
| Files | v3/server/pages.py:103-110 |
| Source Reports | 16.5.1.md |
| Related Findings | - |

**Description:**

The `quart.abort()` calls include descriptive messages ('Missing date', 'Invalid date format', 'Invalid field') that are passed to the default Quart error handler, which may render them in the HTTP response body. While these specific messages are not highly sensitive, the pattern establishes a practice that could lead to information disclosure if applied to more sensitive contexts.

**Remediation:**

Return generic validation error: `quart.abort(400)` and let global error handler provide generic message

---

#### FINDING-199: PersonDB failures not handled in admin endpoints

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 16.5.2 |
| Files | v3/server/pages.py:286-287 |
| Source Reports | 16.5.2.md |
| Related Findings | - |

**Description:**

While PersonNotFound is handled gracefully, the PersonDB.open() call itself has no error handling for database connectivity failures. If the database is unavailable, the error propagates unhandled. Admin page becomes completely unavailable if database has connectivity issues, with no graceful degradation or retry.

**Remediation:**

Add exception handling for PersonDB.open() failures:

try:
    pdb = steve.persondb.PersonDB.open(DB_FNAME)
    me = pdb.get_person(result.uid)
except steve.persondb.PersonNotFound:
    raise_404(T_BAD_PID, result)
except (sqlite3.OperationalError, OSError) as e:
    _LOGGER.error(f'PersonDB unavailable: {e}')
    await flash_danger('Service temporarily unavailable. Please try again.')
    return quart.redirect('/', code=303)

---

#### FINDING-200: Partial vote submission without transaction wrapping

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 16.5.3 |
| Files | v3/server/pages.py:400-422 |
| Source Reports | 16.5.3.md |
| Related Findings | - |

**Description:**

When a voter submits votes for multiple issues simultaneously, each vote is processed individually. If an error occurs on the Nth vote, the first N-1 votes have already been committed to the database. There is no transaction wrapping the entire batch. While re-voting is supported (mitigating data loss), the user receives an error message that doesn't clarify which votes succeeded and which failed. Impact: Voter confusion about partial vote state; potential for inconsistent ballot if voter doesn't retry.

**Remediation:**

election.db.conn.execute('BEGIN TRANSACTION'); try: for iid, votestring in votes.items(): election.add_vote(result.uid, iid, votestring); election.db.conn.execute('COMMIT'); except Exception as e: election.db.conn.execute('ROLLBACK'); _LOGGER.error(f'Vote batch failed: {e}'); await flash_danger('Error submitting votes. Please try again.'); return quart.redirect(f'/vote-on/{election.eid}', code=303)

---

#### FINDING-201: CLI tally script has no top-level exception handler

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 16.5.4 |
| Files | v3/server/bin/tally.py:166-180 |
| Source Reports | 16.5.4.md |
| Related Findings | - |

**Description:**

The main() function and entry point have no top-level try/except block. While the function handles is_tampered() and calls sys.exit(1), unexpected exceptions (database corruption, permission denied, memory errors) will print full stack traces to stderr and exit ungracefully. Within tally_election, the raise after catching an exception intentionally fails hard but doesn't ensure the error is logged through the logging system (only print()). Full stack traces with file paths and variable values are printed to stderr; error details may be lost if not captured by a process manager; no structured error logging for operational monitoring exists.

**Remediation:**

Add top-level exception handler to CLI entry point:

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

---

#### FINDING-202: No evidence of header trust boundary enforcement for intermediary headers

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 4.1.3 |
| Files | v3/server/api.py:1-21 |
| Source Reports | 4.1.3.md |
| Related Findings | - |

**Description:**

The file imports and exposes `APP` from `asfquart` without any visible configuration to strip or reject user-supplied intermediary headers (e.g., `X-Forwarded-For`, `X-Real-IP`, `X-User-ID`). While the `asfquart` framework may handle this internally, there is no visible control in the auditable codebase to confirm that end-users cannot inject headers that would be trusted as if set by intermediaries. Data flow: External HTTP request → `X-Forwarded-For` header → `APP` request handling → potential trust of user-supplied value as intermediary-set value. If `asfquart` or downstream handlers trust these headers without validation, an attacker could spoof their IP address or identity for access control bypass or audit log pollution.

**Remediation:**

Configure the application or its framework to explicitly define trusted proxy sources and strip/ignore intermediary headers from untrusted origins. Example: Configure trusted proxies using APP.config['FORWARDED_ALLOW_IPS'] = '127.0.0.1,10.0.0.0/8' or use middleware to strip untrusted headers. Verify that `asfquart` or the reverse proxy configuration strips/overwrites `X-Forwarded-*` and similar headers from untrusted sources.

---

#### FINDING-203: No visible HTTP message boundary validation or Transfer-Encoding/Content-Length conflict handling

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 4.2.1 |
| Files | v3/server/api.py:1-21 |
| Source Reports | 4.2.1.md |
| Related Findings | - |

**Description:**

The file provides no configuration related to HTTP/1.1 request smuggling prevention. There is no visible: rejection of requests with both Transfer-Encoding and Content-Length headers, HTTP/2 DATA frame length validation against Content-Length, or configuration ensuring the application server and reverse proxy agree on message boundaries. If the reverse proxy and Quart/Hypercorn disagree on how to parse the request boundary (e.g., one uses Content-Length while the other uses Transfer-Encoding), an attacker could smuggle a second request that bypasses authentication or access controls.

**Remediation:**

1. Configure the reverse proxy to normalize requests (reject ambiguous requests with both TE and CL). 2. Configure the ASGI server (Hypercorn) to reject malformed requests. 3. Add application-level validation using a before_request handler to reject requests with both Transfer-Encoding and Content-Length headers by returning a 400 error.

---

#### FINDING-204: Missing File Handling Documentation

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 5.1.1 |
| Files | v3/server/pages.py:560-574, v3/docs/schema.md |
| Source Reports | 5.1.1.md |
| Related Findings | - |

**Description:**

The application serves documents from `DOCSDIR/<iid>/` via the `/docs/<iid>/<docname>` endpoint, and issue descriptions can reference documents via `doc:filename` syntax (processed by `rewrite_description`). However, there is no documentation anywhere in the provided codebase that defines: Permitted file types for documents associated with issues, Expected file extensions, Maximum file size (or maximum unpacked size), How the application handles malicious files detected during download/processing. Without documented policies on accepted file types, extensions, and sizes, developers cannot implement consistent file validation. End users downloading served documents have no assurance that files have been vetted for malware or unsafe content (e.g., polyglot files, malicious macros).

**Remediation:**

Create explicit documentation specifying: Permitted File Types for Issue Documents (PDF, plain text, PNG images with MIME types), Maximum File Size (Individual file: 10 MB, Per-issue total: 50 MB), Malicious File Handling (Files are scanned with ClamAV on upload, Files failing validation are rejected with HTTP 415 and logged, Served files include Content-Disposition: attachment header, X-Content-Type-Options: nosniff is set on all responses). Implement file extension allowlist in serve_doc, add security headers (X-Content-Type-Options: nosniff and Content-Disposition: attachment), add symlink check before serving files, implement documented file upload handler with MAX_CONTENT_LENGTH, extension validation, magic bytes verification, and maximum file size enforcement.

---

#### FINDING-205: Missing compressed file validation against size and count limits

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 5.2.3 |
| Files | v3/server/pages.py:entire application scope |
| Source Reports | 5.2.3.md |
| Related Findings | - |

**Description:**

The application has a document serving mechanism (`/docs/<iid>/<docname>`) but no visible handling or validation of compressed files (zip, gz, docx, odt, etc.). There is no code that: 1. Detects if a served or uploaded file is a compressed archive 2. Checks the maximum uncompressed size before extraction 3. Limits the maximum number of files within an archive 4. Prevents zip bomb attacks. Since the upload mechanism is not shown in the provided code, it is impossible to verify that compressed file protections exist upstream. If compressed files (e.g., zip bombs) are placed in `DOCSDIR` through any mechanism, they could be served to users or potentially processed server-side without decompression limits, leading to denial of service.

**Remediation:**

Implement compressed file validation using a function that checks: 1. Whether the file is a compressed archive (using zipfile.is_zipfile or similar) 2. Total uncompressed size against MAX_UNCOMPRESSED_SIZE (e.g., 100 MB) 3. Number of files in archive against MAX_FILES_IN_ARCHIVE (e.g., 100) 4. Compression ratio to detect zip bombs (reject if ratio > 100). Example implementation provided in report includes validation function that raises ValueError for violations.

---

#### FINDING-206: No per-user file quota or maximum file count enforcement

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 5.2.4 |
| Files | v3/server/pages.py, v3/schema.sql |
| Source Reports | 5.2.4.md |
| Related Findings | - |

**Description:**

There is no per-user file quota or maximum file count enforcement anywhere in the provided code or database schema. The database schema (v3/schema.sql) contains tables for elections, issues, persons, mayvotes, and votes — but nothing tracking file storage per user. Documents are served from DOCSDIR/&lt;iid&gt;/ but there is no: 1. Database table or column tracking per-user storage consumption 2. Check limiting the total number of files a user can upload 3. Check limiting total storage bytes per user 4. Any quota enforcement mechanism. A single user (or compromised account) could fill available storage by uploading an unlimited number of files or excessively large files, causing denial of service for all users.

**Remediation:**

Add file tracking table to database schema:
CREATE TABLE user_files (
    file_id  TEXT PRIMARY KEY NOT NULL,
    pid  TEXT NOT NULL,
    iid  TEXT NOT NULL,
    filename  TEXT NOT NULL,
    file_size  INTEGER NOT NULL,
    uploaded_at  INTEGER NOT NULL,
    FOREIGN KEY (pid) REFERENCES person(pid),
    FOREIGN KEY (iid) REFERENCES issue(iid)
) STRICT;

Implement quota checking function:
MAX_FILES_PER_USER = 50
MAX_STORAGE_PER_USER = 500 * 1024 * 1024  # 500 MB

async def check_user_quota(pid):
    db = steve.election.Election.open_database(DB_FNAME)
    file_count = db.q_user_file_count.first_row(pid)
    if file_count and file_count.count >= MAX_FILES_PER_USER:
        return False, 'Maximum number of files reached'
    total_size = db.q_user_total_storage.first_row(pid)
    if total_size and total_size.total >= MAX_STORAGE_PER_USER:
        return False, 'Storage quota exceeded'
    return True, None

---

#### FINDING-207: No Symlink Detection or Prevention in Compressed Files

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 5.2.5 |
| Files | v3/server/pages.py:entire application scope |
| Source Reports | 5.2.5.md |
| Related Findings | - |

**Description:**

There is no handling of compressed files visible in the provided code, and consequently no symlink detection or prevention. If documents placed in DOCSDIR originated from extracted archives, symbolic links within those archives could allow access to sensitive files outside the intended directory. While send_from_directory provides some protection against traversal, symlinks resolved at the filesystem level could bypass this. If an attacker can place a compressed file containing symlinks (e.g., pointing to /etc/passwd or the database file) and it gets extracted into DOCSDIR, the serve_doc endpoint could serve sensitive system files to authorized users.

**Remediation:**

Implement symlink validation for compressed files using the provided validate_no_symlinks and safe_extract functions. Add symlink checking before serving files with filepath.is_symlink() check in serve_doc. Mount DOCSDIR filesystem with nosymfollow or equivalent to prevent symlink resolution at the OS level. Example code provided includes zipfile validation to detect symlinks in external_attr and prevent path traversal during extraction.

---

#### FINDING-208: Missing RFC 6266 Content-Disposition encoding in file serving endpoint

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 5.4.2 |
| Files | v3/server/pages.py:560-574 |
| Source Reports | 5.4.2.md |
| Related Findings | - |

**Description:**

The `serve_doc()` endpoint serves files without explicitly setting a properly-encoded `Content-Disposition` header per RFC 6266. The user-controlled `docname` parameter is not sanitized before being reflected in the response. If the filename on disk contains non-ASCII characters or special characters, the response header may not be properly encoded. Data flow: User-controlled `docname` → no sanitization → `send_from_directory()` → response headers potentially reflecting unsanitized filename. If filenames in the docs directory contain special characters (quotes, newlines, non-ASCII), the response headers may be malformed, potentially enabling: 1. Header injection via CRLF sequences in filename 2. Content-Disposition header parsing issues in browsers 3. Filename display issues or spoofing in download dialogs

**Remediation:**

Sanitize the filename using secure_filename() and explicitly set Content-Disposition with properly encoded filenames. Use as_attachment=True and attachment_filename parameters in send_from_directory(). Add an explicit allowlist regex for docname validation. Set X-Content-Type-Options: nosniff header.

---

#### FINDING-209: No Antivirus Scanning for Documents Served to Users

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 5.4.3 |
| Files | v3/server/pages.py:598-614, v3/server/pages.py:50-57 |
| Source Reports | 5.4.3.md |
| Related Findings | - |

**Description:**

Files placed in the `docs` directory are served directly to authenticated users without malware scanning. While the code does not show an explicit upload mechanism, the infrastructure for serving per-issue documents exists, and the application converts `doc:filename` patterns in issue descriptions into download links, indicating files are expected to be present and served to users. Files placed in the `docs` directory (whether by admin CLI scripts, manual upload, or an upload mechanism not shown in these files) are served directly to authenticated users without malware scanning. A malicious document (e.g., a PDF with embedded exploit, a malware-laden Office document, or an HTML file with scripts) placed in the docs directory would be served to all voters authorized for that issue. Given the election context, a compromised admin or supply-chain attack on candidate documents could distribute malware to all eligible voters with potential for widespread compromise of voter systems in a targeted attack scenario.

**Remediation:**

Implement antivirus scanning using ClamAV/clamdscan either at serving time or at ingestion time. Option 1: Scan at serving time by adding a scan_file() async function that runs clamdscan before send_from_directory, with fail-closed behavior if scanner is unavailable. Validate filename extensions against an allowed whitelist (e.g., .pdf, .txt, .md, .html). Option 2: Scan at ingestion time by implementing a place_document() function that scans files before copying them to the DOCSDIR. Both options should include proper logging and error handling with fail-closed security posture.

---

#### FINDING-210: No Visible Token Signature Validation in Application Code

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Sections | 9.1.1 |
| Files | v3/server/pages.py:75-106, v3/server/main.py:27-42 |
| Source Reports | 9.1.1.md |
| Related Findings | - |

**Description:**

Token/session validation is entirely delegated to the asfquart framework. The application code contains zero explicit signature validation, and no configuration parameters for signature verification keys are provided. If asfquart fails to validate, the application has no defense-in-depth. The application's trust model assumes asfquart.session.read() returns fully validated, trustworthy data. Every endpoint reads session data and uses uid directly for authorization decisions (database queries, ownership checks, logging) without any additional verification layer.

**Remediation:**

Option 1: Add explicit verification that the framework is configured for signature validation:
```python
app = asfquart.construct('steve', app_dir=THIS_DIR, static_folder=None)
assert app.cfg.session.signing_key, "Session signing key must be configured"
assert app.cfg.session.verify_signatures is True, "Signature verification must be enabled"
```

Option 2: If JWTs are used, add application-level verification:
```python
import jwt
def verify_token(token, public_key, algorithms=['RS256', 'ES256']):
    return jwt.decode(token, public_key, algorithms=algorithms,
                      options={"verify_signature": True})
```

Additional recommendations:
1. Audit asfquart framework for compliance with ASVS 9.x requirements
2. Configure audience validation with explicit audience ('steve')
3. Reconsider OIDC avoidance - evaluate if override removes security protections
4. Document algorithm allowlist - explicitly configure permitted algorithms (RS256, ES256)
5. Add issuer validation - configure expected token issuer (https://oauth.apache.org)
6. Implement defense-in-depth for sessions with application-level validation of critical properties
7. Implement or verify JWKS endpoint caching and rotation handling
8. Implement explicit token type checking to prevent cross-purpose token reuse

---

#### FINDING-211: No Algorithm Restriction Configuration Visible

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Sections | 9.1.2 |
| Files | v3/server/main.py:27-42 |
| Source Reports | 9.1.2.md |
| Related Findings | - |

**Description:**

No algorithm allowlist is configured anywhere in the provided application code. If the asfquart framework or any JWT library processes self-contained tokens, there is no explicit restriction to approved algorithms (e.g., RS256, ES256) and no explicit prohibition of the 'None' algorithm. The audit context specifies that only approved algorithms (RS256, ES256) are allowed (not HS256 with shared secrets), but no such restriction is implemented or configured in the visible code. If the underlying framework uses a JWT library that accepts the alg: none header or allows algorithm confusion attacks (e.g., treating an RSA public key as an HMAC secret with HS256), an attacker could forge valid-looking tokens.

**Remediation:**

In create_app() or configuration, explicitly set allowed algorithms. Configure algorithm allowlist for token validation: app.config['TOKEN_ALGORITHMS'] = ['RS256', 'ES256'] (No 'none', no HS256) and app.config['TOKEN_REJECT_NONE_ALG'] = True. If using PyJWT directly, use: ALLOWED_ALGORITHMS = ['RS256', 'ES256'] and jwt.decode(token, key, algorithms=ALLOWED_ALGORITHMS) (Never pass algorithms=None).

---

#### FINDING-212: No Key Material Source Validation Configured

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Sections | 9.1.3 |
| Files | v3/server/main.py:27-42 |
| Source Reports | 9.1.3.md |
| Related Findings | - |

**Description:**

The application does not configure trusted key sources, JKU/x5u/JWK header allowlists, or pinned public keys for the OAuth issuer (oauth.apache.org). If self-contained tokens (JWTs) are used with headers like jku (JSON Web Key URL), an attacker could potentially craft a token pointing to their own key server, causing the application to validate the forged token against attacker-controlled keys. OAuth provider issues tokens → Token may contain jku/x5u/jwk headers → Application/framework processes token → No visible restriction on key source headers.

**Remediation:**

Configure trusted key sources: TRUSTED_JWKS_URLS = ['https://oauth.apache.org/.well-known/jwks.json'] and TRUSTED_ISSUERS = ['https://oauth.apache.org']. In token validation, reject tokens with jku/x5u/jwk headers unless they match the allowlist. Implement validation function to check token headers and raise errors for untrusted jku URLs, x5u headers, and embedded jwk headers. Use pre-configured keys instead of allowing embedded keys.

---

#### FINDING-213: No Token Expiry Verification in Application Code

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Sections | 9.2.1 |
| Files | v3/server/pages.py:75-106 |
| Source Reports | 9.2.1.md |
| Related Findings | - |

**Description:**

The application reads session data and checks only for presence (if s:), not for temporal validity. No exp, nbf, or iat claim verification is visible. If asfquart.session.read() does not internally verify token expiration, expired sessions would be accepted indefinitely. Data flow: asfquart.session.read() returns session dict, application checks only if s: (truthy), accepts claims without time validation. If session tokens or OAuth tokens don't have expiry enforcement, a stolen/leaked token could be used indefinitely, even after a user's access should have been revoked.

**Remediation:**

Verify session hasn't expired at application level. If 'exp' claim exists in session, check if current time exceeds exp value and reject expired sessions. If 'nbf' claim exists, check if current time is before nbf value and reject not-yet-valid sessions. Example: if 'exp' in s: import time; if time.time() > s['exp']: treat as unauthenticated. Similarly check 'nbf' claim if present.

---

#### FINDING-214: No Token Type Differentiation or Verification

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 9.2.2 |
| Files | v3/server/pages.py:75-106, v3/server/main.py:27-42 |
| Source Reports | 9.2.2.md |
| Related Findings | - |

**Description:**

The application explicitly avoids OIDC (which provides standard ID tokens with typ claims and clear access/identity token separation). The plain OAuth flow used does not distinguish between token types. No typ or token_use claim is checked before accepting token contents for authentication decisions. Without token type verification, there is a risk of token misuse. For example, if different token types are issued for different purposes (API access vs. user identity), the absence of type checking could allow an access token to be used where an ID token is expected, potentially granting unintended access.

**Remediation:**

If using OIDC (recommended over plain OAuth), the framework should validate that ID tokens are used for authentication and access tokens for API calls. At the application level, implement token type checking:

```python
async def basic_info():
    s = await asfquart.session.read()
    if s:
        # Verify this is an identity-purpose session/token
        token_type = s.get('token_type', s.get('typ'))
        if token_type not in ('id_token', 'session'):
            # Reject non-identity tokens
            basic.update(uid=None, name=None, email=None)
            return basic
        basic.update(uid=s['uid'], name=s['fullname'], email=s['email'])
```

---

#### FINDING-215: OIDC Explicitly Bypassed Removing Standard Audience Protection

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 9.2.4 |
| Files | v3/server/main.py:29-35 |
| Source Reports | 9.2.4.md |
| Related Findings | - |

**Description:**

The code explicitly overrides the asfquart framework's default OAuth/OIDC configuration (which presumably includes proper OIDC flows with audience validation). The comment 'Avoid OIDC' and the uncertain 'is this really needed right now?' suggest this was done as a quick workaround rather than a deliberate security decision. OIDC provides built-in audience restriction via: ID Token aud claim (MUST contain client_id per spec), Token endpoint client authentication, and Standardized token validation procedures. By bypassing OIDC, the application loses these protections that directly satisfy ASVS 9.2.4. The application deliberately disables a framework-level control that would provide audience restriction, creating a false sense of security since the asfquart.auth.require decorator appears to work but doesn't validate audience claims.

**Remediation:**

Use standard OIDC flow which provides audience validation:

```python
def create_app():
    "Create the asfquart app and its endpoints."
    
    # Use standard OIDC flow which provides audience validation
    # Configure client_id for audience restriction
    app = asfquart.construct('steve', app_dir=THIS_DIR, static_folder=None)
    
    # If custom OAuth is needed, ensure audience is configured
    app.config['OAUTH_CLIENT_ID'] = 'steve-voting-system'
    app.config['OAUTH_EXPECTED_AUDIENCE'] = 'steve-voting-system'
    app.config['OAUTH_EXPECTED_ISSUER'] = 'https://oauth.apache.org'
    
    import pages
    import api
    return app
```

### 3.4 Low

#### FINDING-216: Key Sharing Scope Not Formally Documented

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Section(s)** | 11.1.1 |
| **Affected File(s)** | v3/steve/crypto.py, v3/steve/election.py |
| **Source Report(s)** | 11.1.1.md |
| **Related Finding(s)** | None |

**Description:**

The opened_key in each election effectively acts as a shared secret used by the system to derive per-voter vote tokens. While the key is only accessible to the application server (single entity), the sharing boundaries are not formally documented. The key derivation chain (opened_key → vote_token → vote_key) means compromise of the opened_key enables decryption of all votes in that election. Without formal documentation of key sharing boundaries, there's risk of architectural changes inadvertently exposing keys to additional entities.

**Remediation:**

Formally document key sharing boundaries and access scope for all cryptographic keys, particularly the opened_key. Include this in the overall key management policy document.

---

#### FINDING-217: Misleading HKDF Info Parameter Suggests Incomplete Migration

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | N/A |
| **ASVS Section(s)** | 11.2.2, 11.3.4 |
| **Affected File(s)** | v3/steve/crypto.py:63-67, v3/steve/crypto.py:60-67 |
| **Source Report(s)** | 11.2.2.md, 11.3.4.md |
| **Related Finding(s)** | None |

**Description:**

The HKDF info parameter is set to b'xchacha20_key' but the actual encryption uses Fernet (AES-128-CBC). This is a domain separation label that typically identifies the intended key usage. When the migration to XChaCha20-Poly1305 occurs, this info value must NOT change (or old ciphertext becomes undecryptable), creating a confusing situation where the info label is correct for new data but was technically wrong for historical data.

**Remediation:**

Either use a generic info value like b'vote_encryption_key_v1' or document that the current info value was chosen proactively for the planned migration. Plan migration path for Fernet → XChaCha20-Poly1305 to ensure the HKDF info parameter changes during migration to prevent key reuse across algorithms.

---

#### FINDING-218: BLAKE2b Usage Not NIST FIPS Approved

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 11.4.1 |
| **Affected File(s)** | v3/steve/crypto.py:45 |
| **Source Report(s)** | 11.4.1.md |
| **Related Finding(s)** | None |

**Description:**

BLAKE2b is a modern, secure hash function (RFC 7693) with a 512-bit output, providing strong collision resistance. However, it is not listed in NIST FIPS 180-4 (SHA-2) or FIPS 202 (SHA-3) as an 'approved' hash function. Depending on organizational compliance requirements, this could be a concern. In practice, BLAKE2b is used within Argon2 itself (which is NIST-recognized via SP 800-63B), making this a very low-risk finding.

**Remediation:**

If strict NIST compliance is required, replace with SHA-512: import hashlib; digest = hashlib.sha512(edata).digest()  # 64 bytes, NIST-approved

---

#### FINDING-219: HKDF Usage Lacks Documentation Clarifying Security Model

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Section(s)** | 11.4.4 |
| **Affected File(s)** | v3/steve/crypto.py:60-67 |
| **Source Report(s)** | 11.4.4.md |
| **Related Finding(s)** | None |

**Description:**

HKDF is not a key-stretching function and provides no computational cost against brute-force. However, since the input (vote_token) is already the 32-byte output of Argon2 (which provides the key stretching), HKDF is being used appropriately as a key derivation function to transform already-stretched material into an encryption key. This is acceptable architecture but worth documenting that the stretching occurs upstream.

**Remediation:**

Add a comment clarifying the security model in the _b64_vote_key function documentation explaining that key stretching is provided by Argon2 in gen_vote_token() and HKDF here only transforms the already-stretched token into a key suitable for the encryption algorithm.

---

#### FINDING-220: All Votes Decrypted and Held Simultaneously in Memory During Tally

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Section(s)** | 11.7.2 |
| **Affected File(s)** | v3/steve/election.py:248-294 |
| **Source Report(s)** | 11.7.2.md |
| **Related Finding(s)** | None |

**Description:**

The entire set of decrypted votes exists in cleartext memory simultaneously in the tally_issue() function. All votes for an issue are decrypted simultaneously, stored in a votes list, and remain in memory until garbage collected. For elections with many voters, this creates a larger window where all vote data is exposed. There is no explicit clearing of sensitive variables after use.

**Remediation:**

Process votes through streaming tally where possible. For STV (which requires all votes), minimize exposure window by implementing explicit clearing of sensitive data in a finally block. Clear the votes list by setting each element to None and calling clear(). While Python doesn't guarantee memory zeroing, this reduces the exposure window.

---

#### FINDING-221: Voter Identity Data Accumulated in Cleartext Memory During Election Data Gathering

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Section(s)** | 11.7.2 |
| **Affected File(s)** | v3/steve/election.py:82-107 |
| **Source Report(s)** | 11.7.2.md |
| **Related Finding(s)** | None |

**Description:**

In gather_election_data(), all voter PIDs and emails are assembled in a cleartext string, encoded to bytes, and passed to a hash function, but the original strings remain in memory until garbage collected. Voter identity data (PIDs and email addresses) exists in unencrypted memory longer than necessary. The assembled string is only needed for hashing but persists until garbage collected.

**Remediation:**

Use incremental hashing to avoid accumulating all data in a single string. Create a hash object and update it incrementally as each piece of data is retrieved from the database, encoding each piece before updating the hash. Return the final digest without accumulating all voter data in memory simultaneously.

---

#### FINDING-222: Redirect URI handling delegates validation entirely to external authorization server with no client-side verification

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1, L2 |
| **CWE** | N/A |
| **ASVS Section(s)** | 10.4.1, 6.5.1 |
| **Affected File(s)** | v3/server/main.py:39-42 |
| **Source Report(s)** | 10.4.1.md, 6.5.1.md |
| **Related Finding(s)** | None |

**Description:**

This application is an OAuth CLIENT, not an authorization server. The actual redirect URI validation is the responsibility of `oauth.apache.org`. The code configures the OAuth initiation URL with a `redirect_uri` parameter (populated via `%s`), but: 1. We cannot verify from this codebase how the `redirect_uri` value is constructed by `asfquart` 2. The authorization server at `oauth.apache.org` is responsible for exact string comparison validation 3. The `asfquart.generics` module (not provided) handles the actual redirect_uri construction. If the `asfquart` framework constructs the redirect_uri dynamically from request parameters without validation, it could enable open redirect attacks, but this cannot be confirmed from the available code.

**Remediation:**

Ensure redirect_uri is a hardcoded constant, not derived from user input. Example: OAUTH_REDIRECT_URI = 'https://steve.apache.org/oauth/callback' and use it in the OAuth URL construction as: asfquart.generics.OAUTH_URL_INIT = (f'https://oauth.apache.org/auth?state=%s&redirect_uri={OAUTH_REDIRECT_URI}')

---

#### FINDING-223: OAuth authorization request does not include explicit scope parameter

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Section(s)** | 10.4.11, 9.2.4 |
| **Affected File(s)** | v3/server/main.py:39-40 |
| **Source Report(s)** | 10.4.11.md, 9.2.4.md |
| **Related Finding(s)** | None |

**Description:**

The OAuth authorization URL (OAUTH_URL_INIT) does not include a client_id parameter. In standard OAuth 2.0 (RFC 6749 §4.1.1), the client_id is REQUIRED in the authorization request and is the mechanism by which the authorization server can scope the issued token to a specific audience. Without client_id: 1) The OAuth server cannot issue audience-restricted tokens, 2) If the same OAuth provider's private key signs tokens for multiple relying parties, any token is valid everywhere, 3) A token obtained by visiting another ASF application (sharing the same OAuth server) could be replayed against STeVe. This enables cross-service token replay where a token issued for a less-sensitive ASF service could be used to authenticate to STeVe (the voting system), which has higher security requirements due to election integrity concerns.

**Remediation:**

Include client_id in OAuth requests:

```python
CLIENT_ID = app.cfg.oauth.client_id  # From configuration

asfquart.generics.OAUTH_URL_INIT = (
    'https://oauth.apache.org/auth?client_id=%s&state=%s&redirect_uri=%s'
    % (CLIENT_ID, '%s', '%s')
)
asfquart.generics.OAUTH_URL_CALLBACK = (
    'https://oauth.apache.org/token?code=%s&client_id=%s&client_secret=%s'
)
```

---

#### FINDING-224: Missing response_mode parameter in OAuth authorization request

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Section(s)** | 10.4.12 |
| **Affected File(s)** | v3/server/main.py:39-40 |
| **Source Report(s)** | 10.4.12.md |
| **Related Finding(s)** | None |

**Description:**

The OAuth authorization request does not specify a `response_mode` parameter. There is no enforcement that the authorization server will only use the expected response mode (query for code flow). Without PAR or JAR, the authorization server relies on its own configuration to restrict response modes. Without explicit `response_mode` specification, an attacker modifying the authorization request (e.g., through open redirector or parameter injection) could potentially force the authorization server to return tokens in fragment mode, making them accessible to client-side code. This is a Level 3 requirement and lower risk given the code grant type in use.

**Remediation:**

Explicitly set response_mode for the code flow: asfquart.generics.OAUTH_URL_INIT = ('https://oauth.apache.org/auth?state=%s&redirect_uri=%s&response_type=code&response_mode=query'). Note: This is a Level 3 requirement. The ASF OAuth server should be configured to only allow appropriate response modes for this client. The finding reflects that no client-side enforcement or specification exists.

---

#### FINDING-225: Authorization code replay protection is delegated to external authorization server without client-side verification

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1, L2 |
| **CWE** | N/A |
| **ASVS Section(s)** | 10.4.2, 6.8.3 |
| **Affected File(s)** | v3/server/main.py:41-42 |
| **Source Report(s)** | 10.4.2.md, 6.8.3.md |
| **Related Finding(s)** | None |

**Description:**

This application is an OAuth CLIENT, not an authorization server. The enforcement of single-use authorization codes is the responsibility of the authorization server at oauth.apache.org. From the client side: 1. The code exchanges an authorization code for a token via the callback URL 2. The asfquart framework handles the actual token exchange 3. The authorization server should reject reused codes and revoke associated tokens. The code format 'https://oauth.apache.org/token?code=%s' passes the code as a query parameter in a GET-style URL format, which could lead to code exposure in server logs. If oauth.apache.org does not enforce single-use codes, an intercepted code could be replayed. This is outside the control of this codebase.

**Remediation:**

Use POST for token exchange to avoid code in URL/logs. The token endpoint should accept code in the request body, not query string. Change from: asfquart.generics.OAUTH_URL_CALLBACK = 'https://oauth.apache.org/token?code=%s' to: asfquart.generics.OAUTH_URL_CALLBACK = 'https://oauth.apache.org/token' with code sent as POST body parameter.

---

#### FINDING-226: No Visible Refresh Token Expiration Enforcement on Client Side

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Section(s)** | 10.4.8, 10.5.5, 6.3.3 |
| **Affected File(s)** | v3/server/pages.py:82-91 |
| **Source Report(s)** | 10.4.8.md, 10.5.5.md, 6.3.3.md |
| **Related Finding(s)** | None |

**Description:**

The application uses asfquart.session and asfquart.auth for authentication, operating as an OIDC Relying Party (consuming authentication from ASF's identity infrastructure). However, there is no back-channel logout endpoint or logout token processing visible in the codebase. The application has no route matching /backchannel-logout, /logout, or similar patterns. No JWT parsing of logout tokens (checking typ header for logout+jwt), no verification of the event claim with member http://schemas.openid.net/event/backchannel-logout, no check for absence of nonce claim, no expiration validation on logout tokens. Sessions authenticated via asfquart.session.read() would persist indefinitely after an IdP-initiated logout. If the upstream identity provider (ASF's OIDC system) terminates a user's session, the voting application would continue to honor the stale session. This creates a denial-of-service vector through forced logout attacks, and sessions cannot be revoked remotely. A compromised account cannot be quickly invalidated across all relying parties.

**Remediation:**

Implement a /backchannel-logout endpoint that: (1) Validates typ: logout+jwt in the JWT header, (2) Verifies the events claim contains http://schemas.openid.net/event/backchannel-logout, (3) Rejects tokens containing a nonce claim, (4) Enforces a maximum 2-minute token lifetime (exp - iat ≤ 120s), (5) Invalidates all sessions for the identified subject (sub) or session (sid). Additionally, implement session revocation infrastructure with a session store or blacklist mechanism, implement RP-initiated logout for user-facing logout, register the back-channel logout URI with the IdP, configure session timeouts aligned with IdP token lifetimes, and implement jti-based replay detection cache for logout tokens.

---

#### FINDING-227: Cannot verify ID Token sub claim mapping to session uid

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Section(s)** | 10.5.2 |
| **Affected File(s)** | v3/server/pages.py:82-90 |
| **Source Report(s)** | 10.5.2.md |
| **Related Finding(s)** | None |

**Description:**

The application uses s['uid'] from the session as the unique user identifier throughout the codebase (for authorization checks, vote recording, election ownership, etc.). This maps to the LDAP uid attribute. The uid in ASF LDAP is a stable, non-reassignable identifier (Apache ID), which satisfies the spirit of the requirement. However, we cannot verify from the provided code: 1) That the session uid originates from a validated sub claim in an ID Token (the OAuth callback handler is in asfquart), 2) That the mapping between OAuth identity and LDAP uid is tamper-proof. The architectural pattern is sound — using a stable LDAP identifier — but verification of the token-to-session binding is not possible from the visible code.

**Remediation:**

Verify that the asfquart framework properly validates the ID Token and maps the sub claim to the session uid. Audit the asfquart library OAuth callback handler to ensure: 1) The sub claim from the ID Token is extracted after proper token validation, 2) The mapping between OAuth sub claim and LDAP uid is secure and tamper-proof, 3) The session uid cannot be manipulated by the client. Document this mapping and validation process.

---

#### FINDING-228: No documented context-specific password deny list for the delegated authentication system

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Section(s)** | 6.1.2 |
| **Affected File(s)** | v3/server/main.py, v3/server/pages.py |
| **Source Report(s)** | 6.1.2.md |
| **Related Finding(s)** | None |

**Description:**

The application delegates password management entirely to ASF OAuth. However, ASVS 6.1.2 requires that a list of context-specific words be documented to prevent their use in passwords. For this application, such a list would include: Organization: "apache", "asf", "foundation"; Product: "steve", "voter", "election", "ballot"; System identifiers: Any election IDs, database names; Project codenames: "steve3", "STeVe"; Roles: "committer", "pmc", "member", "admin". Even though password enforcement is delegated, the documentation requirement still applies. The application should document either: 1. That ASF OAuth maintains such a deny list (with reference), OR 2. The recommended deny list for the ASF OAuth system to implement. Impact: Low severity because authentication is fully delegated to ASF OAuth, which likely has its own password policies. However, without documentation, there's no verification that context-specific words are prevented.

**Remediation:**

Create documentation for context-specific password deny list including organization names (apache, asf, foundation, software), product/system names (steve, voter, voting, election, ballot), role names (committer, pmc, member, admin, owner), and project identifiers (steve3, STeVe, apache-steve). Document delegation notice that password policies are enforced by ASF OAuth with link to ASF password policy documentation and date last verified.

---

#### FINDING-229: LDAP bulk import does not filter or flag privileged/default account names

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 6.3.2 |
| **Affected File(s)** | v3/server/bin/asf-load-ldap.py:46-57 |
| **Source Report(s)** | 6.3.2.md |
| **Related Finding(s)** | None |

**Description:**

The LDAP search filter `uid=*` imports every LDAP entry without filtering. If the ASF LDAP directory contains service accounts, test accounts, or accounts with default-like names (e.g., `root`, `admin`, `test`), they would be imported into the person database and potentially eligible for election participation. The application does not validate imported accounts against a blocklist of default/service account names. This is a low severity finding because: 1) ASF LDAP is the authoritative source and likely manages its own account hygiene, 2) The imported accounts still need to pass `mayvote` authorization checks before voting, 3) No evidence that ASF LDAP contains standard default accounts like 'root' or 'sa'.

**Remediation:**

Add filtering for known service/default accounts: BLOCKED_UIDS = {'root', 'admin', 'sa', 'test', 'nobody', 'daemon'}. During LDAP import, skip any uid that matches the blocklist and log a warning.

---

#### FINDING-230: No re-authentication for sensitive election management operations

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Section(s)** | 6.3.3 |
| **Affected File(s)** | v3/server/pages.py:484-520 |
| **Source Report(s)** | 6.3.3.md |
| **Related Finding(s)** | None |

**Description:**

Critical operations like opening and closing elections have no step-up authentication or re-authentication requirement. With single-factor auth as the only mechanism, these high-impact operations proceed with the same assurance level as viewing a profile page. If a session is hijacked, the attacker can perform irreversible election management actions (open/close elections) without additional verification.

**Remediation:**

Implement a re-authentication prompt before critical operations with require_recent_auth(max_age_seconds=300) that checks session.last_auth_at and redirects to /reauth if the session is too old.

---

#### FINDING-231: PersonDB Lookup Reveals User Existence to Authenticated Users

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Section(s)** | 6.3.8 |
| **Affected File(s)** | v3/server/pages.py:303-344 |
| **Source Report(s)** | 6.3.8.md |
| **Related Finding(s)** | None |

**Description:**

When an authenticated committer accesses `/admin` and is NOT found in the PersonDB, they receive a distinct `T_BAD_PID` 404 error page. This differentiates between "user exists in PersonDB" vs. "user doesn't exist in PersonDB." However, this only reveals information to the authenticated user about their OWN account status, the user is already authenticated via OAuth (so their identity is known), and no endpoint allows querying OTHER users' existence. Impact is minimal as the information leak is about the user's own status in an internal database, visible only to authenticated users. This does not enable enumeration of other users' accounts.

**Remediation:**

While the impact is minimal due to mitigating factors (authentication is external via ASF OAuth, no login form exists to enumerate against, no registration or forgot-password functionality exists, and the differentiated response is only visible to the authenticated user about themselves), consider returning a generic error message that does not differentiate between user existence states in PersonDB.

---

#### FINDING-232: No session/token expiration renewal notifications

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Section(s)** | 6.4.5 |
| **Affected File(s)** | v3/server/pages.py:63-93 |
| **Source Report(s)** | 6.4.5.md |
| **Related Finding(s)** | None |

**Description:**

While authentication mechanism expiry (passwords, certificates, tokens) is managed by the external ASF IdP, the application's own session mechanism does not appear to implement any renewal warning. If sessions have a fixed lifetime (configured in the `asfquart` framework), users receive no advance notice before their session expires during an active voting period. Session expiration occurs without warning, and users discover expired sessions only upon their next action. During time-sensitive elections, a voter or administrator could lose their session mid-operation without advance warning.

**Remediation:**

If session timeouts are enforced, consider implementing a client-side warning (e.g., JavaScript timer) or server-side check that alerts users when their session is approaching expiration, particularly during active voting operations.

---

#### FINDING-233: Non-cryptographic random module used for candidate shuffling

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Section(s)** | 6.5.3 |
| **Affected File(s)** | v3/server/pages.py:33, v3/server/pages.py:290 |
| **Source Report(s)** | 6.5.3.md |
| **Related Finding(s)** | None |

**Description:**

The `random` module (non-CSPRNG) is imported and used for shuffling candidate display order. While this is NOT generating lookup secrets, OOB codes, or TOTP seeds (and therefore not a direct violation of 6.5.3), it establishes a pattern of using non-cryptographic randomness. If this module were ever extended to generate authentication-related secrets, the existing `import random` would likely be mistakenly reused. The Mersenne Twister's state can be reconstructed from 624 consecutive outputs, theoretically allowing prediction of shuffle order — but this only affects candidate display bias, not authentication security.

**Remediation:**

Replace `random` module usage with `secrets` or `random.SystemRandom()` for shuffling operations. While not an authentication vulnerability, using cryptographically secure randomness for candidate shuffling prevents any potential bias exploitation and establishes better security patterns.

---

#### FINDING-234: No re-authentication requirement for sensitive election management operations (federated context)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Section(s)** | 7.1.3 |
| **Affected File(s)** | v3/server/pages.py:484-520 |
| **Source Report(s)** | 7.1.3.md |
| **Related Finding(s)** | None |

**Description:**

Sensitive operations such as opening elections (do_open_endpoint) and closing elections (do_close_endpoint) do not require re-authentication. In a federated identity system, re-authentication for high-privilege operations ensures the current operator is still the authenticated principal. A stolen session token could be used to open or close elections without any step-up authentication challenge.

**Remediation:**

Implement re-authentication requirement for sensitive operations (election open/close/create) as a step-up authentication mechanism.

---

#### FINDING-235: Session token generation cannot be verified from provided code — delegated to asfquart framework

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 7.2.3 |
| **Affected File(s)** | v3/server/pages.py:82, v3/server/main.py:45 |
| **Source Report(s)** | 7.2.3.md |
| **Related Finding(s)** | None |

**Description:**

Session token generation is fully delegated to the `asfquart` framework, which is not included in the audited codebase. It is not possible to verify from the provided source files whether session tokens meet the 128-bit entropy requirement or are generated using a CSPRNG. The `asfquart.session` module handles all token creation internally. If the framework uses insufficient entropy (e.g., predictable tokens, < 128 bits), session tokens could be brute-forced or predicted, leading to session hijacking in the voting system.

**Remediation:**

Verify the `asfquart` framework's session token generation: 1. Audit `asfquart.session` module for CSPRNG usage (e.g., `secrets.token_hex(16)` or equivalent) 2. Verify token length provides ≥ 128 bits of entropy 3. Document the verification in security architecture documentation.

---

#### FINDING-236: No logout functionality visible in audited code

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 7.2.4 |
| **Affected File(s)** | v3/server/pages.py |
| **Source Report(s)** | 7.2.4.md |
| **Related Finding(s)** | None |

**Description:**

The provided `pages.py` file defines no logout endpoint or session termination route. While this may exist in the `asfquart` framework or in the imported but not provided `api.py` module, the absence means we cannot verify that session tokens are properly terminated on logout. The file defines routes for `/`, `/voter`, `/admin`, `/manage/<eid>`, `/profile`, `/settings`, `/about`, and various `/do-*` action endpoints, but no `/logout` or `/do-logout` endpoint.

**Remediation:**

Implement or verify logout functionality that terminates the session token server-side. Add explicit logout endpoint (e.g., /logout or /do-logout) that destroys the session and invalidates the session token to prevent session theft after logout.

---

#### FINDING-237: OAuth callback session creation handler not visible for verification

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Section(s)** | 7.6.2 |
| **Affected File(s)** | v3/server/main.py:39-42 |
| **Source Report(s)** | 7.6.2.md |
| **Related Finding(s)** | None |

**Description:**

The OAuth flow configuration is present, but the actual callback handler that creates the session is not visible in the audited code (it's likely in the `asfquart` framework). The OAuth flow inherently requires user interaction (browser redirect to OAuth provider, user approves). However, without seeing the callback handler, it's impossible to verify that: 1. Silent re-authentication doesn't create new sessions without user interaction 2. The callback validates that the user actively initiated the flow (state parameter). If the `asfquart` framework's OAuth callback creates sessions without proper state validation, it could be possible to forge session creation. However, the `state=%s` parameter in the OAuth URL suggests state parameter usage, which is a positive indicator.

**Remediation:**

Audit the `asfquart` framework OAuth callback handler to verify: 1. State parameter is properly validated to prevent CSRF attacks and ensure user-initiated flow 2. Silent re-authentication does not create new sessions without explicit user interaction 3. Callback validates that the user actively initiated the OAuth flow. Document the session creation logic and ensure it aligns with ASVS 7.6.2 requirements.

---

#### FINDING-238: Election state changes are immediately effective but no notification mechanism exists

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Section(s)** | 8.3.2 |
| **Affected File(s)** | v3/steve/election.py |
| **Source Report(s)** | 8.3.2.md |
| **Related Finding(s)** | None |

**Description:**

When an election is closed, any voter with the voting page already loaded can still submit their form, which will fail with a state error. The authorization change (election closed = no more voting) IS applied immediately in the database (add_vote checks self.S_OPEN), but there's no mitigating control to alert voters mid-session. This is partially mitigated by _all_metadata(self.S_OPEN) in add_vote which validates state on every vote submission.

**Remediation:**

Implement a real-time notification mechanism to alert active voters when an election state changes (e.g., when an election closes). Consider using WebSockets or polling to notify users that voting is no longer possible.

---

#### FINDING-239: No evidence of token propagation architecture, but session identity is correctly used for all operations

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Section(s)** | 8.3.3 |
| **Affected File(s)** | v3/server/pages.py, v3/steve/election.py |
| **Source Report(s)** | 8.3.3.md |
| **Related Finding(s)** | None |

**Description:**

The application is a monolithic server with direct database access. There are no service-to-service calls, no intermediary services, and no token forwarding patterns. All operations use result.uid (from the authenticated session) directly. No findings detected for this requirement in the current architecture. The application correctly uses the originating subject's identity for all permission decisions.

**Remediation:**

No remediation required. The application correctly uses the originating subject's identity for all permission decisions. Continue to maintain this pattern as the architecture evolves.

---

#### FINDING-240: User-controlled values in flash messages and log entries via f-strings

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Section(s)** | 1.3.10 |
| **Affected File(s)** | v3/server/pages.py:423, v3/server/pages.py:490, v3/server/pages.py:399 |
| **Source Report(s)** | 1.3.10.md |
| **Related Finding(s)** | None |

**Description:**

User-controlled values are included in flash messages and log entries via f-strings. While f-strings themselves are safe from format string attacks, the user data (election titles, issue IDs) flows into contexts that could be misinterpreted in future refactoring. Data flow: User form input (form.title, iid from form keys) → f-string evaluation → flash message stored in session → rendered in template. Impact is minimal for format string attacks specifically (f-strings prevent this). The concern is defensive: if logging or flash code were refactored to use deferred formatting (e.g., logging.info with %s or Python's .format() on a template variable), the lack of explicit sanitization could introduce vulnerabilities. Current code is safe.

**Remediation:**

No immediate action needed. Document as secure-by-convention and add input validation (length limits, character restrictions) for election titles as defense-in-depth.

---

#### FINDING-241: SVG files served without script execution prevention

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Section(s)** | 1.3.4 |
| **Affected File(s)** | v3/server/pages.py:586 |
| **Source Report(s)** | 1.3.4.md |
| **Related Finding(s)** | None |

**Description:**

The serve_doc endpoint serves arbitrary files from the docs directory without file-type restrictions. If SVG files are placed in the docs directory (by trusted administrators), they would be served with their native image/svg+xml Content-Type, potentially containing embedded scripts. If a compromised or malicious election administrator places an SVG file with embedded JavaScript, it would be served to voters who click links generated by rewrite_description(). Mitigating factors include: files are placed by trusted administrators (filesystem access required), not directly uploadable through the web interface, and the user writing doc:filename in a description cannot create the actual file.

**Remediation:**

Add Content-Disposition header to force download for non-safe types. Create a SAFE_INLINE_TYPES allowlist containing only safe extensions like .pdf, .txt, .png, .jpg, .jpeg, .gif. For files not in the allowlist, set Content-Disposition to attachment. Additionally, add Content-Security-Policy header with script-src 'none' to prevent SVG script execution even if served inline.

---

#### FINDING-242: Deserialized JSON `kv` data lacks schema validation before use in vote tallying

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Section(s)** | 1.5.2 |
| **Affected File(s)** | v3/steve/election.py:292, v3/steve/election.py:368 |
| **Source Report(s)** | 1.5.2.md |
| **Related Finding(s)** | None |

**Description:**

Database `issue.kv` column (TEXT) is deserialized via `json.loads()` and passed directly to `vtypes` module `tally()` function without structural validation. While `json.loads()` is inherently safe from code execution (only produces basic Python types: dict, list, str, int, float, bool, None), the deserialized structure is passed to vote-type-specific modules without validation against an expected schema. If the `kv` data were corrupted or maliciously set (e.g., via an authorization bypass — the code inventory notes multiple `### check authz` placeholders are unimplemented), unexpected data structures could cause logic errors in tallying. Mitigating factors include: data originates from authorized election administrators (write path is `add_issue`/`edit_issue` which assert `is_editable()`), `json.loads()` cannot instantiate arbitrary objects, `issue.type` is validated against `vtypes.TYPES` at creation time, and risk is LOW because exploitation requires bypassing multiple controls.

**Remediation:**

Add schema validation to the `json2kv()` function to ensure the deserialized result is a dict (expected schema). Additionally, each `vtypes` module should validate the `kv` structure it receives in its `tally()` function. Example implementation:
```python
@staticmethod
def json2kv(j):
    "Convert the KV JSON string back into its structured value."
    if not j:
        return None
    parsed = json.loads(j)
    # Validate that parsed result is a dict (expected schema)
    if not isinstance(parsed, dict):
        raise ValueError(f"Expected dict for kv, got {type(parsed).__name__}")
    return parsed
```

---

#### FINDING-243: Vote type enumeration not documented outside of code

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 2.1.1 |
| **Affected File(s)** | v3/docs/schema.md |
| **Source Report(s)** | 2.1.1.md |
| **Related Finding(s)** | None |

**Description:**

The schema documentation mentions yna and stv as vote types but does not document the complete set of valid values, how they are validated, or their expected input/output formats. The schema.md states that type column supports yna (Yes/No/Abstain voting) and stv (Single Transferable Vote) with additional types potentially added in the future, but the validation rules for each type's vote data are not documented. The enumeration exists partially in documentation and is enforced in code (vtypes.TYPES), but the validation rules for each type's vote input format are not documented.

**Remediation:**

Document the expected vote input format for each type and the validation rules that apply. Include complete enumeration of valid vote types, input format specifications, and validation criteria for each type's vote data.

---

#### FINDING-244: Server can operate without TLS with no documentation or warning

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Section(s)** | 3.1.1 |
| **Affected File(s)** | v3/server/main.py:53-90 |
| **Source Report(s)** | 3.1.1.md |
| **Related Finding(s)** | None |

**Description:**

The server can be configured without TLS (blank certfile/keyfile fields in config.yaml), serving plain HTTP with no documentation stating this is only acceptable for development. The application silently falls back to plain HTTP if TLS is not configured, with no warning or documentation about security implications.

**Remediation:**

Add explicit warning logging when TLS is not configured, and document that production deployments MUST use TLS (either directly or via reverse proxy).

---

#### FINDING-245: Global Scope Functions Without Namespace Isolation or Type Checking

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Section(s)** | 3.2.3 |
| **Affected File(s)** | v3/server/templates/admin.ezt |
| **Source Report(s)** | 3.2.3.md |
| **Related Finding(s)** | None |

**Description:**

Functions are defined in global scope without namespace isolation in `admin.ezt`. The `showModal`, `validateRequiredField`, and `submitFormWithLoading` functions (presumably from `steve.js`) are also global. No strict type checking is performed on DOM element retrieval results. Low risk since this page requires admin authentication and doesn't render user-controlled HTML. However, it represents a pattern that could become exploitable if combined with other vulnerabilities.

**Remediation:**

Move to module pattern or IIFE with explicit null checks: `(function() { 'use strict'; window.openCreateElectionModal = function() { const el = document.getElementById('electionTitle'); if (!(el instanceof HTMLInputElement)) return; el.value = ''; el.classList.remove('is-invalid'); showModal('createElectionModal'); }; })();`

#### FINDING-246: CSRF token embedded in HTML body rather than Set-Cookie header

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 3.3.4 |
| Files | v3/server/pages.py:87 |
| Source Reports | 3.3.4.md |
| Related Findings | - |

**Description:**

The CSRF token (currently a placeholder `'placeholder'`) is embedded in template output as a hidden form field value. While it's intended to be accessible to client-side JavaScript for AJAX requests (see `manage.ezt` line with `document.getElementById('csrf-token').value`), the current implementation transmits this value in HTML body content rather than exclusively via `Set-Cookie`. However, since CSRF tokens are by definition meant to be used by client-side forms, this is an architectural note rather than a vulnerability. The real risk is that this token is never validated (acknowledged in known false positives as work-in-progress).

**Remediation:**

CSRF tokens are typically embedded in page HTML by design. The primary remediation is to implement actual CSRF token validation rather than changing the transmission mechanism.

---

#### FINDING-247: No validation that session cookie size stays within 4096 bytes

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 3.3.5 |
| Files | v3/server/pages.py:60-90 |
| Source Reports | 3.3.5.md |
| Related Findings | - |

**Description:**

The application stores flash messages in the session (which is cookie-based in Quart by default). Flash messages are user-visible strings that accumulate in the session until displayed. While individual flash messages are short predefined strings, there is no validation that the total session/cookie size stays within 4096 bytes. Data flow: User performs actions → flash messages accumulate in session → session serialized to cookie → if cookie exceeds 4096 bytes → browser silently drops cookie → user loses session. Low practical risk as flash messages are cleared on page load, and the session data (uid, fullname, email) is typically short. The form.title in flash messages could be long but is transient.

**Remediation:**

Add middleware to validate cookie size before setting:
```python
@APP.after_request
async def check_cookie_size(response):
    for header_name, header_value in response.headers:
        if header_name.lower() == 'set-cookie':
            # Parse cookie name and value
            cookie_content = header_value.split(';')[0]  # name=value part
            if len(cookie_content.encode('utf-8')) > 4096:
                _LOGGER.warning(f'Cookie exceeds 4096 bytes: {len(cookie_content)} bytes')
                # Truncate or handle gracefully
    return response
```

---

#### FINDING-248: Single Hostname Configuration With No Evidence of Multi-Application Separation

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 3.5.4 |
| Files | v3/server/config.yaml.example:entire file |
| Source Reports | 3.5.4.md |
| Related Findings | - |

**Description:**

The configuration shows a single server on a single port with TLS certificates for a single hostname. While no multi-application hosting is evident (suggesting this is a standalone application), there is no explicit configuration or documentation that would prevent deployment on a shared hostname with other applications. The OAuth integration references oauth.apache.org as a separate hostname, which is correct practice. The application serves dynamic pages (elections, voting), static files (/static/), document files (/docs/), and authentication flows (/auth) all under a single origin. If co-hosted with other ASF applications on the same hostname, the Same-Origin Policy would not provide separation.

**Remediation:**

Ensure deployment configuration uses a dedicated hostname (e.g., steve.apache.org) rather than a path-based virtual host. Document this requirement.

---

#### FINDING-249: Candidate Data Embedded in Inline Script Within Authenticated HTML Page

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 3.5.7 |
| Files | v3/server/templates/vote-on.ezt:JavaScript section near bottom |
| Source Reports | 3.5.7.md |
| Related Findings | - |

**Description:**

Election data (candidate names, issue titles, seat counts, issue IDs) is embedded in an inline &lt;script&gt; block within the HTML response of an authenticated page. This is NOT a separate .js resource file — it's rendered directly in the HTML document body. This is not a XSSI vulnerability because: (1) The data is in the HTML page itself, not in a separate script resource that could be loaded via &lt;script src="..."&gt;; (2) The page requires authentication (@asfquart.auth.require({R.committer})); (3) Cross-origin script loading would not include session cookies for this inline content; (4) Quart does not set Access-Control-Allow-Origin headers that would permit cross-origin reading. However, if any separate .js endpoint were added in the future that serves this data dynamically, it could become exploitable.

**Remediation:**

No immediate action required. As a defense-in-depth measure, add X-Content-Type-Options to prevent MIME sniffing: @APP.after_request async def security_headers(response): response.headers['X-Content-Type-Options'] = 'nosniff'; return response

---

#### FINDING-250: SRI Integrity Attributes Incomplete

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 3.7.5, 3.6.1 |
| Files | v3/server/templates/header.ezt:7, v3/server/templates/footer.ezt:14 |
| Source Reports | 3.7.5.md, 3.6.1.md |
| Related Findings | - |

**Description:**

SRI (Subresource Integrity) is applied to Bootstrap CSS and JS, and to SortableJS, but NOT to the application's own scripts and stylesheets. While SRI on CDN resources is good practice, the inconsistency means there's no documented behavior for what happens when SRI fails. Missing integrity attributes on bootstrap-icons.css, steve.css, and steve.js mean no integrity verification on application resources. If SRI check fails on resources that do have integrity attributes, the browser blocks loading but the application provides no user-visible explanation. There is no fallback behavior documented or implemented when critical scripts fail to load.

**Remediation:**

Add integrity attributes to all script and style resources including steve.css and steve.js with computed SHA-384 hashes. Implement a global error event handler that listens for error events on SCRIPT and LINK elements, and when detected, replaces document.body.innerHTML with a user-friendly error message stating 'A required resource failed integrity verification. This may indicate a security issue. Please reload the page or contact support.'

---

#### FINDING-251: Election Creation Has No Secondary Approval

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | CWE-863 |
| ASVS Sections | 2.3.5 |
| Files | v3/server/pages.py:410 |
| Source Reports | 2.3.5.md |
| Related Findings | FINDING-149 |

**Description:**

While creation itself is not destructive, it's the entry point for the entire election lifecycle. A PMC member could create elections without organizational awareness. This is lower severity as elections must still be opened and closed, and the `R.pmc_member` requirement provides some gatekeeping.

**Remediation:**

Implement multi-user approval workflow for election creation to ensure organizational awareness and oversight before elections enter the lifecycle.

---

#### FINDING-252: Vote Table Schema Lacks Timestamp for Timing Analysis

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | CWE-778 |
| ASVS Sections | 2.4.2 |
| Files | v3/docs/schema.md:148 |
| Source Reports | 2.4.2.md |
| Related Findings | FINDING-112 |

**Description:**

The vote table schema lacks a timestamp column, preventing any timing-based analysis or enforcement. This makes it impossible to retroactively detect automated voting patterns or implement minimum interval checks at the database level. The AUTOINCREMENT VID provides ordering but not timing information. Audit logs may have timing info, but it's separated from the vote data.

**Remediation:**

Add created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')) column to vote table. Create database trigger to prevent rapid re-voting by checking if vote_token has voted within last 10 seconds and raising ABORT if so.

---

#### FINDING-253: Encrypted Client Hello (ECH) Not Configured

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 12.1.5 |
| Files | v3/server/main.py, v3/server/config.yaml.example |
| Source Reports | 12.1.5.md |
| Related Findings | - |

**Description:**

No ECH (Encrypted Client Hello) configuration exists anywhere in the codebase. Without ECH, the Server Name Indication (SNI) field in the TLS ClientHello is transmitted in plaintext. This allows network observers (ISPs, network administrators, or attackers performing passive surveillance) to determine which hostname the client is connecting to, even though the payload is encrypted. This is a metadata privacy issue. ECH is a TLS 1.3 extension (RFC 9578, formerly ESNI) that is still relatively new and requires DNS infrastructure support, server-side TLS library support, and Python's ssl module does not natively support ECH configuration as of Python 3.12.

**Remediation:**

This is a Level 3 requirement. Implementation requires: 1. Deploy behind a reverse proxy that supports ECH (e.g., Cloudflare, nginx with ECH patches) 2. Publish ECH keys via DNS HTTPS records 3. Document ECH configuration in deployment guides. Example DNS record for ECH support: _443._https.steve.apache.org. IN HTTPS 1 . ech="&lt;base64-encoded ECH config&gt;"

---

#### FINDING-254: LDAP Connection Security Not Verified in Architecture

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 12.3.1 |
| Files | v3/docs/quickstart.md:38-44, v3/ARCHITECTURE.md |
| Source Reports | 12.3.1.md |
| Related Findings | - |

**Description:**

The system connects to an LDAP server for user data loading via the asf-load-ldap.py script. There is no documentation indicating whether: (1) LDAPS (LDAP over TLS) or StartTLS is used, (2) Certificate validation is performed, or (3) Credentials in bind.txt are transmitted securely. If LDAP connections use plaintext LDAP (port 389) without StartTLS, credentials and user data are transmitted unencrypted.

**Remediation:**

Ensure the LDAP loading script uses LDAPS (port 636) or StartTLS with certificate validation enabled. Document this requirement in the deployment and quickstart guides. Verify the asf-load-ldap.py script implementation to confirm secure LDAP connection configuration.

---

#### FINDING-255: No Documented Enforcement of TLS Between Application and Reverse Proxy

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2, L3 |
| CWE | - |
| ASVS Sections | 12.3.3, 12.3.5 |
| Files | v3/ARCHITECTURE.md, v3/server/config.yaml.example:22 |
| Source Reports | 12.3.3.md, 12.3.5.md |
| Related Findings | - |

**Description:**

The architecture is primarily a monolithic application (Quart web server + SQLite file database) with minimal service-to-service communication. However, there are identifiable communication paths: 1. Reverse proxy → Application server: No mutual TLS; the proxy authenticates to the backend only via network connectivity (no client certificate) 2. Application → OAuth provider (oauth.apache.org): Standard TLS, no client certificate authentication 3. Application → LDAP server: Authentication via bind credentials in bind.txt, no evidence of mTLS. The system does not implement: TLS client certificate authentication, Service mesh, API keys or tokens for service-to-service authentication, Replay attack prevention for internal calls. At Level 3, the absence of mutual TLS means internal services cannot cryptographically verify each other's identity. An attacker with network access could potentially impersonate internal services. However, given the monolithic architecture with SQLite (no network database), the attack surface is limited.

**Remediation:**

For a Level 3 deployment, add mTLS support in main.py: import ssl; ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH); ssl_context.load_cert_chain(certfile=CERTS_DIR / 'server.pem', keyfile=CERTS_DIR / 'server-key.pem'); ssl_context.load_verify_locations(cafile=CERTS_DIR / 'internal-ca.pem'); ssl_context.verify_mode = ssl.CERT_REQUIRED; app.runx(port=app.cfg.server.port, ssl=ssl_context). Or consider a service mesh (e.g., Istio, Linkerd) if the architecture evolves to microservices.

---

#### FINDING-256: SQLite database access lacks authentication mechanism

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 13.2.1 |
| Files | v3/steve/election.py:35-37, v3/steve/persondb.py:25-26 |
| Source Reports | 13.2.1.md |
| Related Findings | - |

**Description:**

Communications between application components and the SQLite database do not use any authentication mechanism. The database is accessed via file path with no credentials. SQLite is a file-based database and does not natively support user authentication. Access control depends entirely on file system permissions. This is classified as LOW because SQLite's embedded nature means it runs in-process and is not a network service. However, the requirement applies to 'data layers' which includes databases. The application relies solely on OS file permissions rather than cryptographic authentication. Data Flow: Application process → file system → steve.db → no authentication layer. If the file system permissions are misconfigured, any process on the same host could read or modify election data, cryptographic salts, and encrypted votes.

**Remediation:**

For SQLite specifically: Document that file system permissions serve as the authentication mechanism; Ensure the database file has restrictive permissions (e.g., 0600, owned by the application service account); Consider SQLite encryption extensions (e.g., SQLCipher) for data-at-rest protection; If migrating to a networked database, implement service account authentication with short-term credentials

---

#### FINDING-257: Email service communication lacks documented authentication configuration

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 13.2.1 |
| Files | v3/server/bin/mail-voters.py:67-73 |
| Source Reports | 13.2.1.md |
| Related Findings | - |

**Description:**

The email sending function does not show explicit SMTP authentication. The comment '# Add other parameters as needed (e.g., auth, headers)' suggests authentication is not yet configured. The asfpy.messaging library may handle this internally, but it is not documented or visible in this codebase. If SMTP authentication is not configured, the application may be relying on network-level trust (e.g., sending from within the same network as the mail relay) which could be spoofed or abused.

**Remediation:**

Document SMTP authentication method and ensure it uses short-term tokens or certificate-based authentication rather than static passwords.

---

#### FINDING-258: CLI scripts run without documented privilege requirements

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 13.2.2 |
| Files | v3/server/bin/create-election.py, v3/server/bin/mail-voters.py |
| Source Reports | 13.2.2.md |
| Related Findings | - |

**Description:**

Command-line utilities that directly modify the database or send emails have no documented OS-level privilege requirements or access controls. create-election.py can create elections and add voters, while mail-voters.py can read voter emails and send messages. These scripts have the same database privileges as the web server but no authentication or authorization layer. Anyone with shell access to the server can create elections, modify voter rolls, or send emails to voters without audit trail beyond system-level logging.

**Remediation:**

Document required OS permissions and consider adding authentication checks or restricted execution contexts for CLI tools.

---

#### FINDING-259: No evidence of server-level allowlist configuration for outbound requests or file access

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 13.2.5 |
| Files | Application-wide (configuration gap), election.py:445 |
| Source Reports | 13.2.5.md |
| Related Findings | - |

**Description:**

The codebase does not contain any server-level configuration defining which resources or systems the server can send requests to or load data from. While the application primarily uses local SQLite databases and local file system access, there is no evidence of: Web server configuration restricting outbound connections, Application-level configuration restricting file system access paths, or Network-level allowlist documentation. If the application is extended to make outbound requests (e.g., for email notifications as suggested by the get_voters_for_email() method in election.py line 445), there would be no allowlist to prevent SSRF or unauthorized outbound communication.

**Remediation:**

In application configuration, define ALLOWED_FILE_PATHS dictionary containing 'database', 'templates', 'static', and 'docs' paths. At server-level, configure reverse proxy (e.g., nginx) to restrict outbound connections. Add iptables/firewall rules to whitelist only necessary outbound destinations.

---

#### FINDING-260: Ad-hoc database connections opened in request handlers without connection lifecycle management

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 13.2.6 |
| Files | v3/server/pages.py:233, v3/server/pages.py:295, v3/server/pages.py:435, v3/server/pages.py:567 |
| Source Reports | 13.2.6.md |
| Related Findings | - |

**Description:**

Multiple database connections are opened per request without explicit closing or connection pooling. Comments in the code acknowledge this issue with '### should open/keep a PersonDB instance in the APP'. Connections are opened at lines 233, 295, 435, and 567 in pages.py without proper lifecycle management.

**Remediation:**

Implement a connection pool or application-level singleton for database access with proper lifecycle management. Replace ad-hoc open_database() calls with an application-level connection pool with documented configuration for timeouts, max connections, and retry behavior.

---

#### FINDING-261: Commented-out debug print statements expose critical key material if uncommented

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 13.4.2 |
| Files | v3/steve/election.py:79, v3/steve/election.py:83 |
| Source Reports | 13.4.2.md |
| Related Findings | - |

**Description:**

While these debug print statements are currently commented out, their presence indicates a pattern of uncommenting for debugging. If accidentally uncommented in production, they would expose critical key material (salt, opened_key, election data) to stdout/logs.

**Remediation:**

Remove all commented-out debug print statements. Use structured logging with appropriate log levels that can be configured per environment.

---

#### FINDING-262: Directory Listing Protection Depends on Deployment Configuration

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 13.4.3 |
| Files | v3/server/pages.py:560-574, v3/server/pages.py:577-578 |
| Source Reports | 13.4.3.md |
| Related Findings | - |

**Description:**

While Quart's send_from_directory() does NOT generate directory listings by default (it requires a specific filename), the application does not explicitly configure or document that directory listing is disabled at the web server level if deployed behind a reverse proxy (nginx, Apache). If the application is deployed behind a web server that has autoindex enabled, directories could be listed. This is a LOW finding because: 1. Quart/Flask's send_from_directory does not serve directory listings, 2. Requests without a filename would not match these route patterns, 3. The actual risk depends on the deployment infrastructure (reverse proxy configuration)

**Remediation:**

Document deployment requirements to ensure directory listing is disabled at all levels. Add explicit handling for directory access attempts with a 404 error handler, or add middleware to reject requests ending in / for static and docs paths. Example: Add @APP.errorhandler(404) handler or @APP.before_request middleware to block directory requests that end with '/' for /static/ and /docs/ paths.

---

#### FINDING-263: No Explicit HTTP TRACE Method Blocking

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 13.4.4 |
| Files | v3/server/pages.py:125-583 |
| Source Reports | 13.4.4.md |
| Related Findings | - |

**Description:**

The application uses Quart framework route decorators (@APP.get(), @APP.post()) which only respond to explicitly specified HTTP methods. There is no explicit TRACE handler defined, and Quart (built on Werkzeug routing) will respond with 405 Method Not Allowed for unsupported methods. However, there is no explicit middleware or configuration to block TRACE at the application level. If deployed behind a reverse proxy that passes TRACE through, or if future framework changes alter default behavior, TRACE could become available. The risk is LOW because the framework's default behavior is correct.

**Remediation:**

Add explicit TRACE blocking for defense-in-depth: Add a before_request handler to block TRACE method explicitly (@APP.before_request async def block_trace(): if quart.request.method == 'TRACE': quart.abort(405)). Or configure at the reverse proxy level (preferred) using nginx configuration: if ($request_method = TRACE) { return 405; }

---

#### FINDING-264: No Explicit Framework Endpoint Restriction Visible for asfquart Built-in Routes

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 13.4.5 |
| Files | v3/server/main.py:34 |
| Source Reports | 13.4.5.md |
| Related Findings | - |

**Description:**

Application startup sets root logger and app logger to DEBUG level in all modes, including production ASGI. Debug-level logging in production ASGI mode may expose internal state, request parameters, framework internals, and cryptographic operation details to log collectors or monitoring systems that aggregate logs. While not an endpoint per se, log aggregation systems (ELK, Splunk, CloudWatch) often expose search interfaces that become de facto monitoring endpoints. Any request processed by the server will generate DEBUG-level log entries containing internal processing details, framework routing decisions, and potentially session data.

**Remediation:**

After app construction, explicitly verify registered routes and remove any unintended ones. If framework exposes introspection: app.config['EXPLAIN_TEMPLATE_LOADING'] = False; Remove any health/status endpoints not intended for public access. Audit asfquart framework for any built-in documentation, debugging, or monitoring endpoints that may be registered by default.

---

#### FINDING-265: Internal Code Comments Reveal Migration Plans and Technology Stack

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 13.4.6 |
| Files | v3/steve/crypto.py:58-69 |
| Source Reports | 13.4.6.md |
| Related Findings | - |

**Description:**

Source code → if exposed (e.g., via .git directory, backup file, or error page with stack trace) → attacker learns cryptographic implementation details and migration timeline. The comments explicitly state the current encryption scheme (Fernet), planned future scheme (XChaCha20-Poly1305), and that it hasn't been migrated yet. If source code is inadvertently exposed, this provides cryptographic implementation intelligence. The info=b'xchacha20_key' parameter is also a technology indicator embedded in the ciphertext derivation chain. This is LOW severity because it requires source code exposure first, which is addressed by other controls.

**Remediation:**

Ensure deployment processes strip comments and that no source files are accessible via the web tier (see 13.4.7). Review whether info=b'xchacha20_key' should be updated to a non-descriptive value like b'vote_key_v1'.

---

#### FINDING-266: State-changing operations using GET requests expose operation context in URL history

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Sections | 14.2.1 |
| Files | v3/server/pages.py:do_open_endpoint, v3/server/pages.py:do_close_endpoint |
| Source Reports | 14.2.1.md |
| Related Findings | - |

**Description:**

While EIDs are not themselves highly sensitive data (they're designed as semi-public identifiers with authorization checks), performing state-changing operations via GET means: 1. The operation URL appears in browser history 2. Proxy/CDN logs record the action with the EID 3. Browser prefetching or link scanners could inadvertently trigger the operation 4. Referer headers may leak the EID to subsequent navigation targets. The EIDs themselves are 40-bit entropy identifiers protected by authorization (per known false positive patterns), so the actual data exposure risk is low. However, using GET for state-changing operations is architecturally inappropriate.

**Remediation:**

Convert to POST requests: @APP.post('/do-open/&lt;eid&gt;') @asfquart.auth.require({R.committer}) @load_election async def do_open_endpoint(election): ...

---

#### FINDING-267: Non-cryptographic PRNG used for candidate ordering in voting interface

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 14.2.4 |
| Files | v3/server/pages.py:vote_on_page |
| Source Reports | 14.2.4.md |
| Related Findings | - |

**Description:**

The application uses `random.shuffle()` (Mersenne Twister, predictable) instead of the available cryptographically secure `crypto.shuffle()` function for shuffling candidates in the voting interface. While candidate names are public information, the ordering presented to voters can influence voting behavior (primacy/recency effects). Using a predictable PRNG means: 1. An attacker who knows the random seed could predict candidate ordering 2. The shuffle quality is lower than the cryptographic alternative already available 3. Inconsistency in security posture — the tally code uses `crypto.shuffle()` but the presentation code uses `random.shuffle()`. Data flow: Candidate list → `random.shuffle()` (Mersenne Twister, predictable) → Presented to voter → Potential ordering bias. Gap Type: Type B — Control EXISTS (`crypto.shuffle`) but NOT CALLED (uses `random.shuffle` instead)

**Remediation:**

Replace `random.shuffle(issue.candidates)` with `steve.crypto.shuffle(issue.candidates)`

---

#### FINDING-268: No data retention controls implemented for closed elections

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2, L3 |
| CWE | - |
| ASVS Sections | 14.2.4, 14.2.7 |
| Files | v3/steve/election.py, v3/schema.sql, v3/docs/schema.md |
| Source Reports | 14.2.4.md, 14.2.7.md |
| Related Findings | - |

**Description:**

There is no mechanism to enforce data retention policies for: closed elections and their associated votes, superseded votes (re-votes where old vote records are retained), person records for individuals no longer in LDAP, decrypted vote data after tallying. The schema documentation states 'Older votes are retained for auditing' but provides no retention limit or purge mechanism. Without retention controls: encrypted vote data persists indefinitely, increasing the risk window for future cryptographic breaks; per-voter salts persist indefinitely, maintaining the ability to link voters to votes; the database grows unboundedly; compliance with privacy regulations requiring data minimization cannot be demonstrated.

**Remediation:**

Implement retention lifecycle with methods such as `purge_old_votes()` to remove superseded votes (keep only latest per vote_token), and `archive_and_purge(retention_days=90)` to archive and purge closed election data after retention period, including removing salts and vote_tokens. Additionally, document retention policy in schema.md covering superseded votes, election salts and keys, closed election data, and person records.

---

#### FINDING-269: User email included in every page template context

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 14.2.6 |
| Files | v3/server/pages.py:87 |
| Source Reports | 14.2.6.md |
| Related Findings | - |

**Description:**

User's email is included in every page's template context via basic_info() which is called for every page. If templates render this data, it appears on every page even where not needed. This is a minor over-exposure of personal data.

**Remediation:**

Only include email in template context where it's specifically needed (e.g., profile page). Remove email from the basic_info() function and add it selectively to page contexts that require it.

---

#### FINDING-270: No Data Lifecycle Management Function for Closed Elections

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 14.2.7 |
| Files | v3/steve/election.py:441-451 |
| Source Reports | 14.2.7.md |
| Related Findings | - |

**Description:**

While the function list_closed_election_ids() exists to list closed elections (potentially for administrative purposes), there is no corresponding deletion or archival function. The function supports identifying elections but provides no lifecycle management capability to enforce data retention schedules.

**Remediation:**

Implement a companion function for data lifecycle management: @classmethod def archive_old_elections(cls, db_fname, max_age_days=365): """Archive and delete elections older than max_age_days after closing.""" # Export to archive, then delete pass

---

#### FINDING-271: Documents Served Without Metadata Stripping

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 14.2.8 |
| Files | v3/server/pages.py:605-620 |
| Source Reports | 14.2.8.md |
| Related Findings | - |

**Description:**

Documents served from DOCSDIR are returned without any metadata stripping. If these documents were originally submitted by users (e.g., election administrators uploading issue descriptions, candidate information), they may contain: EXIF data with GPS coordinates, device info, timestamps; Office document metadata (author name, revision history, internal paths); PDF metadata (author, creation tool, modification dates). However, the provided code does not show a file upload mechanism—documents appear to be admin-placed. If there is a separate upload mechanism not shown here, this is more critical.

**Remediation:**

Implement metadata stripping for uploaded files before storing. Use exiftool or similar libraries to remove metadata from images, PDFs, and office documents. Example: Use subprocess to call exiftool with '-all=' flag for JPG, PNG, GIF, TIFF, and PDF files. Add handlers for other file types as needed. Additionally, implement user consent mechanism for metadata storage if metadata needs to be retained.

---

#### FINDING-272: Flash Messages in Session Cookie May Expose Election Titles

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 14.3.3 |
| Files | v3/server/pages.py:443, v3/server/pages.py:466, v3/server/pages.py:485, v3/server/pages.py:510, v3/server/pages.py:534, v3/server/pages.py:554 |
| Source Reports | 14.3.3.md |
| Related Findings | - |

**Description:**

Flash messages containing election and issue titles are stored in the session, which in Quart/Flask typically means they are stored in client-side session cookies. While election titles are not strictly sensitive data, they could reveal information about private or confidential elections. Flash messages include election creation, opening, closing, and issue management operations.

**Remediation:**

Replace flash messages containing election/issue titles with generic success messages that do not include potentially sensitive details. For example, use 'Election created successfully.' instead of 'Created election: {form.title}'.

---

#### FINDING-273: No resource management or resilience dependencies declared

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 15.2.2 |
| Files | v3/pyproject.toml:10-17 |
| Source Reports | 15.2.2.md |
| Related Findings | - |

**Description:**

The dependency list contains no libraries providing resource management controls such as async task timeouts (e.g., asyncio-timeout, async-timeout), connection pooling with limits, circuit breakers (e.g., circuitbreaker, tenacity with limits), or request size limiting middleware. The cryptography library and argon2-cffi are CPU-intensive by design (particularly Argon2 hashing). Without documented resource constraints at the application level, repeated invocation of these operations could degrade availability. Per the known false positive patterns, lack of rate limiting on vote submission is intentional since voters are authenticated ASF committers. This finding is limited to noting the absence of any resource-bounding library in the dependency manifest. The actual application code (not provided) may implement timeouts or resource limits natively via asyncio.

**Remediation:**

Document the security decision regarding resource-demanding functionality (Argon2 hashing, Fernet encryption/decryption). If not already present, consider adding application-level timeouts using asyncio.timeout to wrap resource-intensive operations with a 5-second timeout or similar appropriate limit.

---

#### FINDING-274: Version constraints allow wide range of acceptable versions

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 15.2.4 |
| Files | v3/pyproject.toml:10-17 |
| Source Reports | 15.2.4.md |
| Related Findings | - |

**Description:**

Four of six dependencies (`asfpy`, `asfquart`, `ezt`, `easydict`) have no upper version bound. While this is common practice, it means a future major version with breaking changes or a compromised release could be automatically pulled. The security-critical packages (`cryptography`, `argon2-cffi`) are properly bounded, which is a positive pattern. Impact: Low — primarily a supply chain management concern. A lock file (if maintained outside this audit scope) would mitigate this.

**Remediation:**

Add upper bounds to all dependencies or ensure a lock file is maintained and committed. Example: `asfpy>=0.56,<1`, `asfquart>=0.1.12,<1`, `ezt>=1.1,<2`, `easydict>=1.13,<2`.

---

#### FINDING-275: No evidence of isolation mechanisms for cryptographic operations

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 15.2.5 |
| Files | v3/pyproject.toml |
| Source Reports | 15.2.5.md |
| Related Findings | - |

**Description:**

From the pyproject.toml alone, there is no evidence of containerization configuration (no Dockerfile reference, no container dependencies), sandboxing libraries (no seccomp, apparmor, or namespace isolation tools), network isolation configuration, or process isolation for cryptographic operations. The application uses cryptography (Fernet encryption) and argon2-cffi (hashing) which are critical security components. Per ASVS 15.2.5, these should be isolated to limit blast radius if compromised. This is a LOW finding because: 1. The pyproject.toml may not be the appropriate place for this configuration (Docker/K8s configs not in scope), 2. The domain context notes that the application does not use dangerous functionality like eval() or deserialization of untrusted data, 3. The cryptographic libraries themselves are well-maintained and considered safe. If a vulnerability is discovered in a dependency, there are no visible architectural barriers preventing lateral movement within the application.

**Remediation:**

Document the security architecture decisions regarding component isolation. Consider: 1. Running cryptographic operations in a separate process/service, 2. Adding a Dockerfile with minimal base image and non-root user, 3. Documenting network isolation in deployment configuration

#### FINDING-276: Potential use of requests library without explicit redirect prevention configuration

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Section(s)** | 15.3.2 |
| **Files** | v3/pyproject.toml |
| **Source Reports** | 15.3.2.md |
| **Related Findings** | - |

**Description:**

The presence of `types-requests>=2.32.4,<3` in the lint dependency group strongly suggests that the `requests` library is used in the codebase (type stubs are only useful if the library is imported). The `requests` library follows redirects by default (`allow_redirects=True` for GET/OPTIONS, `True` for POST/PUT/PATCH/DELETE since 2.x). Additionally, `asfpy` (a transitive dependency) may make HTTP calls internally. Without source code review, it cannot be confirmed whether: 1. The application makes backend calls to external URLs 2. Whether `allow_redirects=False` is set on such calls 3. Whether the `asfpy`/`asfquart` libraries handle OAuth callbacks with redirect following. Data Flow: Application backend → `requests.get(url)` → follows redirect → SSRF to internal resource. Impact: Cannot be confirmed from dependency manifest alone. If backend HTTP calls exist without `allow_redirects=False`, an attacker could exploit open redirects to reach internal services.

**Remediation:**

If the application makes backend HTTP calls, ensure redirects are disabled: import requests; response = requests.get(url, allow_redirects=False, timeout=10); Or use a session with redirect disabled: session = requests.Session(); session.max_redirects = 0

---

#### FINDING-277: EasyDict May Suppress Type Errors Through Permissive Attribute Access

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Section(s)** | 15.3.5 |
| **Files** | v3/pyproject.toml:14 |
| **Source Reports** | 15.3.5.md |
| **Related Findings** | - |

**Description:**

EasyDict converts dictionaries to objects with attribute access. This can mask type issues when user input (always strings from HTTP forms) is compared against expected types without explicit conversion/validation. In Python, while strict equality (==) is used by default (no === vs == distinction), type juggling risks exist when: String values from forms are compared to integers (e.g., "1" == 1 is False in Python, but int("1") == 1 is True — inconsistent handling); Boolean coercion is relied upon (e.g., empty string vs. None vs. False). Without seeing the actual application logic, this is a dependency-level risk indicator only.

**Remediation:**

Implement explicit type validation at input boundaries. Example: from typing import TypedDict; class VoteInput(TypedDict): election_id: str; candidate_id: str; def validate_vote_input(form_data: dict) -> VoteInput: if not isinstance(form_data.get("election_id"), str): raise ValueError("election_id must be a string"); if not isinstance(form_data.get("candidate_id"), str): raise ValueError("candidate_id must be a string"); return VoteInput(election_id=form_data["election_id"], candidate_id=form_data["candidate_id"])

---

#### FINDING-278: Quart/Werkzeug Multi-Value Parameter Handling Not Verifiably Constrained

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Section(s)** | 15.3.7 |
| **Files** | v3/pyproject.toml:12 |
| **Source Reports** | 15.3.7.md |
| **Related Findings** | - |

**Description:**

Quart (built on Werkzeug) uses MultiDict for query parameters and form data, meaning duplicate parameter keys result in multi-valued entries. By default: request.args.get("key") returns the first value and request.args.getlist("key") returns all values. If the application code inconsistently uses .get() vs .getlist() or passes raw parameter dictionaries to downstream functions, HTTP Parameter Pollution could allow an attacker to inject unexpected values. Additionally, if request.values (which merges query string and form body) is used, parameters from different sources could conflict. Without the actual route handler code, the specific exposure cannot be confirmed. This is an architectural risk based on the framework choice.

**Remediation:**

Always use explicit parameter source. Use request.form or request.args specifically, never request.values. Reject duplicate parameters explicitly by checking if len(request.form.getlist("parameter_name")) > 1 and returning a 400 error. Example: from quart import request; @app.route("/vote", methods=["POST"]); async def submit_vote(): election_id = request.form.get("election_id", type=str); if len(request.form.getlist("election_id")) > 1: return "Duplicate parameter not allowed", 400

---

#### FINDING-279: No Thread Pool or Fair Scheduling Configuration Visible

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Section(s)** | 15.4.4 |
| **Files** | v3/pyproject.toml |
| **Source Reports** | 15.4.4.md |
| **Related Findings** | - |

**Description:**

The project configuration does not reference any thread pool management, worker configuration, or fair scheduling mechanisms. The application relies on Quart's default async event loop (single-threaded by default) and SQLite's built-in locking (which uses a simple busy-wait/retry mechanism). Without explicit configuration of sqlite3 busy timeout, thread pool executor for blocking SQLite operations, or worker/request queue fairness policies, lower-priority or later-arriving requests could starve if SQLite's lock is held by a long-running operation (e.g., vote tallying with decryption). During election tallying (which involves decryption of all votes), write locks could block new vote submissions indefinitely if no busy timeout or fair scheduling is configured. This is a denial-of-service risk during critical voting periods.

**Remediation:**

Configure SQLite busy timeout to prevent indefinite waiting (e.g., conn.execute('PRAGMA busy_timeout = 5000')). Enable WAL mode for concurrent read access (conn.execute('PRAGMA journal_mode = WAL')). For longer operations like tallying, use a dedicated ThreadPoolExecutor with max_workers=2 to run CPU-intensive operations without blocking the event loop. Implement async wrapper: async def tally_votes(election_id): loop = asyncio.get_event_loop(); return await loop.run_in_executor(_executor, _sync_tally, election_id).

---

#### FINDING-280: Date/time operations use naive datetimes without timezone awareness

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Section(s)** | 16.2.2 |
| **Files** | v3/server/pages.py:86, v3/server/pages.py:571, v3/server/bin/tally.py:86 |
| **Source Reports** | 16.2.2.md |
| **Related Findings** | - |

**Description:**

All datetime operations use naive (timezone-unaware) datetime objects. While not directly a logging issue, this indicates that the application lacks UTC discipline, making it likely that log timestamps (when configured) would also use local time.

**Remediation:**

```python
from datetime import datetime, timezone

# Use UTC-aware datetimes
datetime.now(timezone.utc)
datetime.fromtimestamp(ts, tz=timezone.utc)
```

---

#### FINDING-281: Tally script outputs decrypted vote results to stdout without log governance

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Section(s)** | 16.2.3 |
| **Files** | v3/server/bin/tally.py:129-135 |
| **Source Reports** | 16.2.3.md |
| **Related Findings** | - |

**Description:**

The tally script outputs decrypted election results (including voter identities and vote tallies) directly to stdout. While this is the intended functionality of a CLI tool, it represents sensitive data being output to an undocumented channel. There is no logging of WHERE this output goes or who captures it. Without documentation of how tally outputs should be secured, results could be inadvertently captured in shell history, piped to insecure files, or logged by terminal multiplexers.

**Remediation:**

Add audit logging when results are output: _LOGGER.info(f'TALLY_OUTPUT election_id={election.eid} format={output_format} issues={len(results)} voters={len(all_voters)}'). Document in logging inventory that tally output is to stdout and must be handled per data classification policy.

---

#### FINDING-282: No request/correlation ID for tracing multi-step operations

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Section(s)** | 16.2.4 |
| **Files** | v3/server/pages.py:all endpoint handlers |
| **Source Reports** | 16.2.4.md |
| **Related Findings** | - |

**Description:**

When a user submits votes for multiple issues in a single request, each vote generates a separate log entry with no shared correlation ID. A log processor cannot determine that these entries belong to the same HTTP request without temporal proximity heuristics. This creates minor correlation difficulty for multi-issue vote submissions and could complicate forensic investigation of specific voting sessions.

**Remediation:**

Generate request-scoped correlation IDs using uuid. Example: request_id = str(uuid.uuid4())[:8]; for iid, votestring in votes.items(): _LOGGER.info(f'request_id={request_id} User[U:{result.uid}] voted on issue[I:{iid}] in election[E:{election.eid}]'). Better approach: Use Quart middleware to generate per-request IDs and use contextvars to propagate them.

---

#### FINDING-283: PersonDB Lookup Failure Handling

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Section(s)** | 16.3.4 |
| **Files** | v3/server/pages.py:303-313 |
| **Source Reports** | 16.3.4.md |
| **Related Findings** | - |

**Description:**

When a PersonNotFound exception occurs, the handler returns a 404 but doesn't log this unexpected condition. An authenticated user not found in PersonDB is an anomalous condition that could indicate a configuration issue or data integrity problem.

**Remediation:**

Add _LOGGER.warning() call when PersonNotFound exception occurs for authenticated users, including uid and context information

---

#### FINDING-284: No explicit HTTP method restrictions visible

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Section(s)** | 4.1.4 |
| **Files** | v3/server/api.py:1-21 |
| **Source Reports** | 4.1.4.md |
| **Related Findings** | - |

**Description:**

The file defines no routes and contains no method restriction configuration. While the `asfquart` framework likely provides method-specific routing (e.g., `@app.route('/path', methods=['GET', 'POST'])`), there is no visible global rejection of unexpected methods (e.g., TRACE, TRACK, DELETE on endpoints that shouldn't support them) nor a catch-all handler to return 405 for undefined methods. If the framework's default behavior allows arbitrary HTTP methods on endpoints (e.g., TRACE for XST attacks, or unexpected method handling), unused methods may be accessible.

**Remediation:**

Add global method restriction or verify Quart/asfquart defaults reject unsupported methods with 405. Example implementation: Add a `@APP.before_request` handler that checks if `request.method` is in an allowed set `{'GET', 'POST', 'OPTIONS', 'HEAD'}` and returns 405 otherwise. Classified as LOW because Quart (like Flask) typically returns 405 automatically for methods not registered on a route. This finding is primarily about confirming that behavior and ensuring TRACE/TRACK are blocked at the server level.

---

#### FINDING-285: No per-message digital signature mechanism observed for highly sensitive transactions

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Section(s)** | 4.1.5 |
| **Files** | v3/server/api.py:1-21 |
| **Source Reports** | 4.1.5.md |
| **Related Findings** | - |

**Description:**

For a voting application handling highly sensitive transactions (vote casting, election management), there is no visible implementation of per-message digital signatures (e.g., HTTP Message Signatures RFC 9421, JWS, or HMAC-based request signing) that would provide integrity assurance beyond transport-layer TLS. Without per-message signatures, if TLS is terminated at a proxy and internal traffic is unencrypted, or if there are intermediary systems, message integrity cannot be independently verified. For a voting system, this means vote submissions could theoretically be tampered with in transit between internal components.

**Remediation:**

For highly sensitive operations (vote submission, election state changes), implement request signing using HMAC or digital signatures. Example implementation: Add a before_request handler that verifies X-Signature header using HMAC with a signing key, comparing against the expected signature of the request body using constant-time comparison. Consider implementing HTTP Message Signatures RFC 9421, JWS, or HMAC-based request signing for vote submission and election state changes.

### 3.5 Informational

#### FINDING-286: Coverage Gap - LDAP Operations Not Available for Review

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Informational |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 1.2.6 |
| **Files** | asf-load-ldap.py (N/A - file not provided), asfquart.auth (N/A - external module not provided), asfquart.session (N/A - external module not provided) |
| **Source Reports** | 1.2.6.md |
| **Related** | None |

**Description:**

The domain context explicitly identifies `asf-load-ldap.py` as containing LDAP operations, but this file is not included in the provided source code. Additionally, the authentication layer (`asfquart.auth`, `asfquart.session`) likely interfaces with ASF LDAP for user authentication, but the implementation details are not available for review. No LDAP operations were found in the provided code files (`queries.yaml`, `api.py`, `pages.py`, `election.py`). The application relies on `asfquart` for authentication which presumably handles LDAP interactions internally.

**Remediation:**

Request and review `asf-load-ldap.py` and the `asfquart.auth` module's LDAP query construction. Verify that LDAP filters use proper escaping (e.g., `ldap.filter.escape_filter_chars()`) for any user-derived values.

---

---

# 4. Positive Security Controls

| Control | Evidence | Files | Domain |
|---------|----------|-------|--------|
| Cryptographically secure salt generation | Keys are generated using secrets.token_bytes() (CSPRNG) | v3/steve/crypto.py:gen_salt() | Vote Encryption & Cryptography |
| Key derivation from election data | Well-designed multi-level key derivation chain: election_data → BLAKE2b → Argon2 → opened_key | v3/steve/crypto.py:gen_opened_key() | Vote Encryption & Cryptography |
| Per-voter key derivation | Separate vote tokens derived per voter, limiting blast radius per key compromise | v3/steve/crypto.py:gen_vote_token() | Vote Encryption & Cryptography |
| Key length constraints in schema | Database CHECK constraints enforce 16-byte salt, 32-byte opened_key, 32-byte vote_token | v3/steve/schema.sql | Vote Encryption & Cryptography |
| Key confidentiality protection | The opened_key is never exposed via public API (get_metadata() explicitly excludes it) | v3/steve/election.py | Vote Encryption & Cryptography |
| Centralized cryptographic operations | All cryptographic operations centralized in crypto module for auditability | v3/steve/crypto.py | Vote Encryption & Cryptography |
| No custom/homebrew cryptographic primitives | All cryptographic operations use well-known, peer-reviewed libraries (cryptography, argon2-cffi, hashlib, secrets) | v3/steve/crypto.py | Vote Encryption & Cryptography |
| Library versions pinned with upper bounds | Versions constrained (e.g., cryptography>=46.0.5,&lt;47, argon2-cffi&gt;=25.1.0,<26) | pyproject.toml | Vote Encryption & Cryptography |
| Fernet encrypt-then-MAC design prevents Padding Oracle attacks | The cryptography.fernet.Fernet class verifies HMAC-SHA256 before attempting AES-CBC decryption | v3/steve/crypto.py | Vote Encryption & Cryptography |
| No insecure block modes | Fernet uses AES-128-CBC with PKCS7 + HMAC-SHA256, not ECB or weak padding | v3/steve/crypto.py:create_vote() | Vote Encryption & Cryptography |
| Random IV generation per encrypt | Fernet library guarantees a fresh 128-bit random IV for every encryption call | cryptography.fernet.Fernet.encrypt() (internal) | Vote Encryption & Cryptography |
| Unique salt per mayvote row | Each person-issue pair gets unique salt from secrets.token_bytes() | v3/steve/election.py:116 | Vote Encryption & Cryptography |
| Immediate vote encryption | Votes encrypted immediately upon submission in add_vote() function | v3/steve/election.py:231 | Vote Encryption & Cryptography |
| Vote shuffling before return | crypto.shuffle(votes) ensures decrypted vote order doesn't correlate to database insertion order | v3/steve/election.py | Vote Encryption & Cryptography |
| Python secrets module with os.urandom() backing | Uses OS-level CSPRNG (/dev/urandom on Linux) which never blocks | v3/steve/crypto.py | Vote Encryption & Cryptography |
| Server-side only token handling | The application reads session server-side and only passes display-safe attributes to templates | pages.py:68 | Authentication & Session Management |
| No token in template variables | All .ezt templates do not contain access_token or refresh_token variables | All .ezt templates | Authentication & Session Management |
| Metadata filtering | get_metadata() explicitly excludes salt and opened_key from returned data | election.py:144 | Authentication & Session Management |
| Query-level protection | SQL queries for external-facing data explicitly select only safe columns, excluding cryptographic secrets | queries.yaml:q_open_to_me, q_owned, q_upcoming_to_me | Authentication & Session Management |
| Template-level CSRF field inclusion | All forms include CSRF token hidden input field ready for proper implementation | manage.ezt, admin.ezt, vote-on.ezt | Authentication & Session Management |
| Fetch header CSRF inclusion | JavaScript includes X-CSRFToken header in fetch requests, ready for validation | manage.ezt | Authentication & Session Management |
| POST method for most mutations | Most state-changing endpoints correctly use POST (voting, creating elections, adding/editing/deleting issues, setting dates) | v3/server/pages.py | Authentication & Session Management |
| Single authorization server architecture | The application uses only ASF's authentication infrastructure (R.committer, R.pmc_member) | pages.py | Authentication & Session Management |
| Differentiated authorization levels | The application uses at minimum two different authorization levels (R.committer for general access, R.pmc_member for election creation) | pages.py | Authentication & Session Management |
| Per-endpoint authorization | Each endpoint explicitly declares its required authorization level via decorators | pages.py | Authentication & Session Management |
| Defense-in-depth authorization | Beyond authentication, the application performs additional authorization checks verifying voter eligibility and document access | v3/server/pages.py:236, 567 | Authentication & Session Management |
| @asfquart.auth.require decorator | Applied to all protected endpoints to verify committer role and elevated roles | v3/server/pages.py:multiple endpoints | Authentication & Session Management |
| Voter eligibility verification | vote_on_page endpoint verifies user has mayvote entries before displaying voting interface | v3/server/pages.py:267 | Authentication & Session Management |
| Document access authorization | serve_doc endpoint implements fine-grained per-document authorization checking mayvote records | v3/server/pages.py:630 | Authentication & Session Management |
| Role differentiation | Distinct role requirements between committer and pmc_member for election creation | v3/server/pages.py:multiple endpoints | Authentication & Session Management |
| Consistent use of uid as unique user identifier | The application consistently uses uid (Apache ID) as the unique user identifier across all operations | v3/server/pages.py:85 | Authentication & Session Management |
| LDAP uid as stable, non-reassignable identifier | The LDAP uid attribute is organizationally controlled by ASF and not reassignable | asf-load-ldap.py:53 | Authentication & Session Management |
| PersonDB mapping maintains identity consistency | The PersonDB maps the LDAP uid to local records, maintaining identity consistency | asf-load-ldap.py:56 | Authentication & Session Management |
| Server-side TLS enabled | Application uses TLS for server communication with ldaps:// for LDAP and https:// for OAuth URLs | v3/server/main.py:76-79 | Authentication & Session Management |
| OAuth URLs use HTTPS | OAuth initialization and callback URLs configured with HTTPS protocol | v3/server/main.py:39-42 | Authentication & Session Management |
| State parameter included in OAuth initiation URL | state parameter present in OAUTH_URL_INIT configuration, protecting against CSRF on the callback | v3/server/main.py:39-42 | Authentication & Session Management |
| Server-side backchannel token exchange | Token exchange uses server-side backchannel (not implicit flow) | v3/server/main.py:39-42 | Authentication & Session Management |
| Authorization code flow usage | The application uses authorization code flow (not implicit), which inherently uses query response mode as default | main.py:38-42 | Authentication & Session Management |
| Hardcoded OAuth URLs providing implicit issuer pinning | Hardcoding of oauth.apache.org URLs provides implicit issuer pinning, reducing attack surface | v3/server/main.py:39-42 | Authentication & Session Management |
| Client uses Authorization Code grant flow only | The client uses the Authorization Code grant flow exclusively via oauth.apache.org | main.py:38-42 | Authentication & Session Management |
| No implicit flow usage | No evidence of response_type=token anywhere in codebase | - | Authentication & Session Management |
| No Resource Owner Password Credentials flow usage | No ROPC flow configured or used in the codebase | - | Authentication & Session Management |
| Static OAuth configuration with hardcoded endpoints | The application uses a static OAuth configuration with hardcoded endpoints to oauth.apache.org | main.py:39-42 | Authentication & Session Management |
| Organizationally unique UIDs from ASF LDAP | The uid values come from ASF LDAP, ensuring they are organizationally unique | asf-load-ldap.py | Authentication & Session Management |
| Non-reassignable committer IDs | LDAP UIDs are inherently non-reassignable within the ASF organization (committer IDs are permanent) | - | Authentication & Session Management |
| OAuth-based authentication (no local passwords) | Authentication is entirely delegated to ASF's OAuth infrastructure. No local password management implemented. | main.py:39-42 | Authentication & Session Management |
| No local password storage | CORRECTLY ABSENT - application does not implement local password authentication | - | Authentication & Session Management |
| Parameterized queries | SQL queries use parameterized queries throughout, preventing SQL injection | v3/steve/election.py | Injection Prevention |
| OS Command Injection Prevention | No evidence of os.system(), subprocess without shell=False, or eval() of OS commands | - | Injection Prevention |
| XPath Injection Prevention | No XPath query construction from user input observed | - | Injection Prevention |
| LaTeX Injection Prevention | No LaTeX template generation observed | - | Injection Prevention |
| Regex Special Character Escaping | No user input directly interpolated into regex patterns | - | Injection Prevention |
| CSV and Formula Injection Prevention | No CSV generation endpoints observed | - | Injection Prevention |
| Dynamic Code Execution | No eval(), exec(), or compile() with user input observed | - | Injection Prevention |
| Format String Protection | Python f-strings are not vulnerable to format string attacks in the same way as C printf | - | Injection Prevention |
| ReDoS Protection | No complex user-controlled regex patterns observed | - | Injection Prevention |
| SSRF Protection | No user-controlled URL fetching observed | - | Injection Prevention |
| Template Injection Protection | EZT templates use [variable] syntax which is not executable | - | Injection Prevention |
| Memory-Safe String and Pointer Operations | Python's memory management prevents buffer overflows and pointer arithmetic vulnerabilities | - | Memory Safety |
| Integer Overflow Prevention | Python 3 has arbitrary precision integers preventing overflow | - | Memory Safety |
| Memory and Resource Release | Python's garbage collection automatically manages memory | - | Memory Safety |
| XML Parser Restrictive Configuration | No XML parsing observed in application code | - | Injection Prevention |
| Parser Consistency | Single database driver (sqlite3) used throughout | - | Injection Prevention |
| Supported Client-Side Technologies | Application uses modern, supported web technologies (HTML5, JavaScript ES6+) | - | Web Frontend Security |
| postMessage Validation | No postMessage usage observed | - | Web Frontend Security |
| JSONP Not Enabled | No JSONP endpoints observed | - | Web Frontend Security |
| Authorization Data Not in Script Resources | No authorization tokens embedded in JavaScript resources | - | Web Frontend Security |
| HTTP to HTTPS Redirect Behavior | Application supports HTTPS configuration | v3/server/main.py | HTTP Security |
| HTTP/2 and HTTP/3 Connection-Specific Header Fields | Framework (Quart) handles HTTP/2 connection management | - | HTTP Security |
| Default Credentials for Service Authentication | No default credentials shipped with application | - | Backend Communications |
| Web Servers Do Not Expose Directory Listings | Static file serving uses explicit file paths, not directory listings | - | Configuration & Deployment |
| Zip Slip Protection | No zip file extraction observed | - | File Handling |

---

# 5. ASVS Compliance Summary

| ASVS ID | Title | Status |
|---------|-------|--------|
| **11. Cryptography** |
| 11.1.1 | Cryptographic Key Management Policy | ❌ Fail |
| 11.1.2 | Cryptographic Inventory | ❌ Fail |
| 11.1.3 | Cryptographic Discovery Mechanisms | ❌ Fail |
| 11.1.4 | Cryptographic Inventory with PQC Migration Plan | ❌ Fail |
| 11.2.1 | Industry-Validated Cryptographic Implementations | ⚠️ Partial |
| 11.2.2 | Crypto Agility | ❌ Fail |
| 11.2.3 | Minimum 128-bits of Security | ⚠️ Partial |
| 11.2.4 | Constant-Time Operations | ❌ Fail |
| 11.2.5 | Secure Cryptographic Failure | ⚠️ Partial |
| 11.3.1 | No Insecure Block Modes or Weak Padding | ✅ Pass |
| 11.3.2 | Approved Ciphers and Modes | ⚠️ Partial |
| 11.3.3 | Protection Against Unauthorized Modification | ✅ Pass |
| 11.3.4 | Nonces, IVs, and Single-Use Numbers | ✅ Pass |
| 11.3.5 | Encrypt-then-MAC Mode | ✅ Pass |
| 11.4.1 | Approved Hash Functions | ⚠️ Partial |
| 11.4.2 | Password Storage with Approved KDF | ⚠️ Partial |
| 11.4.3 | Hash Functions for Digital Signatures / Data Integrity | ✅ Pass |
| 11.4.4 | Approved KDF with Key Stretching for Key Derivation from Passwords | ⚠️ Partial |
| 11.5.1 | Random Values - CSPRNG with 128-bit Entropy | ❌ Fail |
| 11.5.2 | Random Number Generation Under Heavy Demand | ✅ Pass |
| 11.6.1 | Approved Cryptographic Algorithms and Modes | ⚠️ Partial |
| 11.6.2 | Approved Key Exchange Algorithms with Secure Parameters | N/A |
| 11.7.1 | Full Memory Encryption for Sensitive Data In-Use | ❌ Fail |
| 11.7.2 | Data Minimization and Immediate Encryption | ⚠️ Partial |
| **10. OAuth & OIDC** |
| 10.1.1 | Token Restriction to Required Components | ⚠️ Partial |
| 10.1.2 | Transaction Binding and Client-Generated Secrets | ❌ Fail |
| 10.2.1 | CSRF Protection for OAuth Code Flow | ❌ Fail |
| 10.2.2 | Mix-Up Attack Defense | N/A |
| 10.2.3 | Minimal Scope Requests | N/A |
| 10.3.1 | Access Token Audience Validation | ⚠️ Partial |
| 10.3.2 | OAuth Resource Server — Delegated Authorization Enforcement | ❌ Fail |
| 10.3.3 | OAuth Resource Server — Unique User Identification | ⚠️ Partial |
| 10.3.4 | OAuth Resource Server — Authentication Strength Verification | ❌ Fail |
| 10.3.5 | OAuth Resource Server — Sender-Constrained Access Tokens | ❌ Fail |
| 10.4.1 | OAuth Authorization Server — Redirect URI Validation | N/A |
| 10.4.2 | OAuth Authorization Server — Authorization Code Single Use | N/A |
| 10.4.3 | Authorization Code Short-Lived | N/A |
| 10.4.4 | Only Allow Required Grants Per Client | ✅ Pass |
| 10.4.5 | Refresh Token Replay Mitigation | ⚠️ Partial |
| 10.4.6 | PKCE Required for Code Grant | ❌ Fail |
| 10.4.7 | Mitigate Risk of Dynamic Client Registration | N/A |
| 10.4.8 | Refresh Token Absolute Expiration | ⚠️ Partial |
| 10.4.9 | Token Revocation UI | ❌ Fail |
| 10.4.10 | Confidential Client Authentication for Backchannel Requests | ⚠️ Partial |
| 10.4.11 | Required Scopes Only | ⚠️ Partial |
| 10.4.12 | Response Mode Validation | ❌ Fail |
| 10.4.13 | Code Grant with PAR | ❌ Fail |
| 10.4.14 | Sender-Constrained Access Tokens | ❌ Fail |
| 10.4.15 | OAuth Authorization Server - authorization_details integrity via PAR/JAR | ❌ Fail |
| 10.4.16 | OAuth Authorization Server - Strong Client Authentication | ❌ Fail |
| 10.5.1 | OIDC Client - ID Token Replay Attack Mitigation (nonce) | ❌ Fail |
| 10.5.2 | OIDC Client - Unique User Identification from ID Token | ⚠️ Partial |
| 10.5.3 | OIDC Client - Issuer Validation Against Pre-configured URL | ❌ Fail |
| 10.5.4 | OIDC Client - Audience (aud) Validation in ID Token | ❌ Fail |
| 10.5.5 | OIDC Back-Channel Logout | ❌ Fail |
| 10.6.1 | OpenID Provider Response Modes | N/A |
| 10.6.2 | OpenID Provider DoS Mitigation via Forced Logout | N/A |
| 10.7.1 | User Consent for Authorization Requests | N/A |
| 10.7.2 | Consent Information Presentation | N/A |
| 10.7.3 | User Consent Review, Modification, and Revocation | N/A |
| **6. Authentication** |
| 6.1.1 | Authentication Documentation - Rate Limiting and Anti-Automation | ❌ Fail |
| 6.1.2 | Authentication Documentation - Context-Specific Password Deny List | ❌ Fail |
| 6.1.3 | Authentication Documentation - Multiple Authentication Pathways | ❌ Fail |
| 6.2.1 | Password Security - Minimum Length | ✅ Pass |
| 6.2.2 | Password Security - Password Change Capability | ✅ Pass |
| 6.2.3 | Password Security - Password Change Requires Current Password | N/A |
| 6.2.4 | Password Blocklist Check | N/A |
| 6.2.5 | No Password Composition Rules | ✅ Pass |
| 6.2.6 | Password Field Masking (type=password) | N/A |
| 6.2.7 | Paste and Password Manager Support | ✅ Pass |
| 6.2.8 | No Password Modification Before Verification | ✅ Pass |
| 6.2.9 | Support Passwords of 64+ Characters | N/A |
| 6.2.10 | Password Validity (No Periodic Rotation) | ✅ Pass |
| 6.2.11 | Context-Specific Word List for Password Prevention | N/A |
| 6.2.12 | Breached Password Checking | N/A |
| 6.3.1 | Controls Against Credential Stuffing and Brute Force | ⚠️ Partial |
| 6.3.2 | Default User Accounts | ⚠️ Partial |
| 6.3.3 | Multi-Factor Authentication | ⚠️ Partial |
| 6.3.4 | Multiple Authentication Pathways Consistency | ❌ Fail |
| 6.3.5 | Suspicious Authentication Attempt Notifications | ❌ Fail |
| 6.3.6 | Email Not Used as Authentication Mechanism | ✅ Pass |
| 6.3.7 | Notification After Authentication Detail Updates | ❌ Fail |
| 6.3.8 | User Enumeration Prevention | ✅ Pass |
| 6.4.1 | System Generated Initial Passwords/Activation Codes | ✅ Pass |
| 6.4.2 | Password Hints and Knowledge-Based Authentication | ✅ Pass |
| 6.4.3 | Secure Password Reset Process | N/A |
| 6.4.4 | MFA Factor Loss Identity Proofing | N/A |
| 6.4.5 | Authentication Mechanism Renewal Instructions | ⚠️ Partial |
| 6.4.6 | Administrative Password Reset Without Knowledge | N/A |
| 6.5.1 | Single-Use Authentication Codes | ⚠️ Partial |
| 6.5.2 | Lookup Secret Storage Hashing | N/A |
| 6.5.3 | CSPRNG for Secret Generation | ✅ Pass |
| 6.5.4 | Minimum Entropy for Lookup Secrets and OOB Codes | N/A |
| 6.5.5 | Defined Lifetime for OOB and TOTP | N/A |
| 6.5.6 | Revocability of Authentication Factors | ⚠️ Partial |
| 6.5.7 | Biometric Authentication as Secondary Only | ✅ Pass |
| 6.5.8 | Time-based One-time Passwords Time Source | N/A |
| 6.6.1 | PSTN/SMS OTP Restrictions | N/A |
| 6.6.2 | Out-of-Band Code Binding to Original Request | ✅ Pass |
| 6.6.3 | Rate Limiting for Code-based Out-of-Band Auth | N/A |
| 6.6.4 | Push Notification Rate Limiting | N/A |
| 6.7.1 | Certificate Storage Protection for Cryptographic Auth | N/A |
| 6.7.2 | Challenge Nonce Requirements for Cryptographic Authentication | N/A |
| 6.8.1 | Identity Spoofing Across Multiple IdPs | ⚠️ Partial |
| 6.8.2 | Digital Signature Validation on Authentication Assertions | ❌ Fail |
| 6.8.3 | SAML Assertion Replay Prevention | ⚠️ Partial |
| 6.8.4 | Authentication Strength Verification from IdP | ❌ Fail |
| **7. Session Management** |
| 7.1.1 | Session Inactivity Timeout and Maximum Lifetime Documentation | ❌ Fail |
| 7.1.2 | Concurrent Session Limits Documentation | ❌ Fail |
| 7.1.3 | Federated Identity Management Documentation | ❌ Fail |
| 7.2.1 | Backend Session Token Verification | ✅ Pass |
| 7.2.2 | Dynamic Session Tokens | ✅ Pass |
| 7.2.3 | Reference Token Entropy (128 bits, CSPRNG) | ⚠️ Partial |
| 7.2.4 | New Session Token on Authentication | ❌ Fail |
| 7.3.1 | Session Inactivity Timeout | ❌ Fail |
| 7.3.2 | Absolute Maximum Session Lifetime | ❌ Fail |
| 7.4.1 | Session Termination Enforcement | ❌ Fail |
| 7.4.2 | Session Termination on Account Disable/Delete | ❌ Fail |
| 7.4.3 | Session Termination After Authentication Factor Change | ❌ Fail |
| 7.4.4 | Visible Logout Functionality | ❌ Fail |
| 7.4.5 | Session Termination by Administrators | ❌ Fail |
| 7.5.1 | Re-authentication Before Sensitive Account Changes | ⚠️ Partial |
| 7.5.2 | Users Can View and Terminate Active Sessions | ❌ Fail |
| 7.5.3 | Further Authentication for Sensitive Transactions | ❌ Fail |
| 7.6.1 | Session Lifetime and Termination Between RPs and IdPs | ❌ Fail |
| 7.6.2 | Session Creation Requires User Consent or Explicit Action | ⚠️ Partial |
| **8. Authorization** |
| 8.1.1 | Authorization Documentation - Function-level and Data-specific Access | ⚠️ Partial |
| 8.1.2 | Authorization Documentation - Field-level Access Restrictions | ❌ Fail |
| 8.1.3 | Authorization Documentation - Environmental and Contextual Attributes | ❌ Fail |
| 8.1.4 | Authorization Documentation - Environmental Factors in Decision-Making | ❌ Fail |
| 8.2.1 | General Authorization Design - Function-level Access | ❌ Fail |
| 8.2.2 | General Authorization Design - Data-specific Access (IDOR/BOLA) | ❌ Fail |
| 8.2.3 | Field-Level Access Control (BOPLA) | ❌ Fail |
| 8.2.4 | Adaptive Security Controls | ❌ Fail |
| 8.3.1 | Server-Side Authorization Enforcement | ❌ Fail |
| 8.3.2 | Immediate Authorization Change Application | ❌ Fail |
| 8.3.3 | Subject-Based Permissions (Not Intermediary) | ✅ Pass |
| 8.4.1 | Multi-Tenant Cross-Tenant Controls | ❌ Fail |
| 8.4.2 | Administrative Interface Multi-Layer Security | ❌ Fail |
| **1. Injection Prevention** |
| 1.1.1 | Encoding and Sanitization Architecture - Canonical Decoding | ⚠️ Partial |
| 1.1.2 | Encoding and Sanitization Architecture - Output Encoding as Final Step | ❌ Fail |
| 1.2.1 | Injection Prevention - Context-Appropriate Output Encoding | ❌ Fail |
| 1.2.2 | Injection Prevention - URL Encoding for Dynamic URLs | ❌ Fail |
| 1.2.3 | Injection Prevention - JavaScript Content Encoding | ❌ Fail |
| 1.2.4 | Injection Prevention - Parameterized Queries | ✅ Pass |
| 1.2.5 | OS Command Injection Prevention | ✅ Pass |
| 1.2.6 | LDAP Injection Prevention | ⚠️ Partial |
| 1.2.7 | XPath Injection Prevention | ✅ Pass |
| 1.2.8 | LaTeX Injection Prevention | ✅ Pass |
| 1.2.9 | Regex Special Character Escaping | ✅ Pass |
| 1.2.10 | CSV and Formula Injection Prevention | ✅ Pass |
| 1.3.1 | HTML Sanitization | ❌ Fail |
| 1.3.2 | Dynamic Code Execution | ✅ Pass |
| 1.3.3 | Dangerous Context Sanitization | ❌ Fail |
| 1.3.4 | SVG Content Sanitization | ⚠️ Partial |
| 1.3.5 | Scriptable/Expression Template Language Content | ❌ Fail |
| 1.3.6 | SSRF Protection | ✅ Pass |
| 1.3.7 | Template Injection Protection | ✅ Pass |
| 1.3.8 | JNDI Injection Protection | N/A |
| 1.3.9 | Memcache Injection Protection | N/A |
| 1.3.10 | Format String Protection | ✅ Pass |
| 1.3.11 | SMTP/IMAP Injection Protection | ⚠️ Partial |
| 1.3.12 | ReDoS Protection | ✅ Pass |
| 1.4.1 | Memory-Safe String and Pointer Operations | ✅ Pass |
| 1.4.2 | Integer Overflow Prevention | ✅ Pass |
| 1.4.3 | Memory and Resource Release | ✅ Pass |
| 1.5.1 | XML Parser Restrictive Configuration | ✅ Pass |
| 1.5.2 | Safe Deserialization | ⚠️ Partial |
| 1.5.3 | Parser Consistency | ✅ Pass |
| **2. Validation & Business Logic** |
| 2.1.1 | Validation and Business Logic Documentation - Input Validation Rules | ⚠️ Partial |
| 2.1.2 | Validation and Business Logic Documentation - Contextual Consistency | ❌ Fail |
| 2.1.3 | Validation and Business Logic Documentation - Business Logic Limits | ❌ Fail |
| 2.2.1 | Input Validation | ❌ Fail |
| 2.2.2 | Input Validation at Trusted Service Layer | ❌ Fail |
| 2.2.3 | Combinations of Related Data Items | ❌ Fail |
| 2.3.1 | Business Logic Sequential Step Order | ❌ Fail |
| 2.3.2 | Business Logic Limits | ❌ Fail |
| 2.3.3 | Transaction Usage at Business Logic Level | ❌ Fail |
| 2.3.4 | Business Logic Locking (Double-Booking Prevention) | ❌ Fail |
| 2.3.5 | Multi-User Approval for High-Value Operations | ❌ Fail |
| 2.4.1 | Anti-Automation Controls | ❌ Fail |
| 2.4.2 | Anti-Automation: Realistic Human Timing Controls | ❌ Fail |
| **3. Web Frontend Security** |
| 3.1.1 | Web Frontend Security Documentation | ❌ Fail |
| 3.2.1 | Unintended Content Interpretation | ❌ Fail |
| 3.2.2 | Unintended Content Interpretation - Safe Text Rendering | ❌ Fail |
| 3.2.3 | DOM Clobbering Prevention | ⚠️ Partial |
| 3.3.1 | Cookie Secure Attribute | ❌ Fail |
| 3.3.2 | Cookie SameSite Attribute | ❌ Fail |
| 3.3.3 | Cookie __Host- Prefix | ❌ Fail |
| 3.3.4 | Cookie HttpOnly Attribute | ❌ Fail |
| 3.3.5 | Cookie Size Limit (≤ 4096 bytes) | ⚠️ Partial |
| 3.4.1 | Strict-Transport-Security (HSTS) Header | ❌ Fail |
| 3.4.2 | CORS Access-Control-Allow-Origin Header | ⚠️ Partial |
| 3.4.3 | Content-Security-Policy Header | ❌ Fail |
| 3.4.4 | X-Content-Type-Options: nosniff | ❌ Fail |
| 3.4.5 | Referrer-Policy | ❌ Fail |
| 3.4.6 | Content-Security-Policy frame-ancestors | ❌ Fail |
| 3.4.7 | CSP report-uri/report-to | ❌ Fail |
| 3.4.8 | Cross-Origin-Opener-Policy | ❌ Fail |
| 3.5.1 | CSRF / Browser Origin Separation | ❌ Fail |
| 3.5.2 | CORS Preflight Mechanism | ❌ Fail |
| 3.5.3 | HTTP Methods for Sensitive Functionality | ❌ Fail |
| 3.5.4 | Separate Applications on Different Hostnames | ⚠️ Partial |
| 3.5.5 | postMessage Validation | ✅ Pass |
| 3.5.6 | JSONP Not Enabled | ✅ Pass |
| 3.5.7 | Authorization Data Not in Script Resources | ✅ Pass |
| 3.5.8 | Browser Origin Separation | ❌ Fail |
| 3.6.1 | External Resource Integrity | ⚠️ Partial |
| 3.7.1 | Supported Client-Side Technologies | ✅ Pass |
| 3.7.2 | Redirect Allowlist for External Domains | ❌ Fail |
| 3.7.3 | Notification for External URL Navigation | ❌ Fail |
| 3.7.4 | HSTS Preload | ❌ Fail |
| 3.7.5 | Browser Security Feature Detection | ❌ Fail |
| **12. TLS** |
| 12.1.1 | General TLS Security Guidance - TLS Protocol Versions | ❌ Fail |
| 12.1.2 | General TLS Security Guidance - Cipher Suites | ❌ Fail |
| 12.1.3 | General TLS Security Guidance - mTLS Client Certificate Validation | N/A |
| 12.1.4 | General TLS Security Guidance - Certificate Revocation (OCSP Stapling) | ❌ Fail |
| 12.1.5 | General TLS Security Guidance - Encrypted Client Hello (ECH) | ❌ Fail |
| 12.2.1 | HTTPS Communication with External Facing Services | ❌ Fail |
| 12.2.2 | HTTPS Communication with External Facing Services | ❌ Fail |
| 12.3.1 | General Service to Service Communication Security | ❌ Fail |
| 12.3.2 | TLS Certificate Validation by Clients | ⚠️ Partial |
| 12.3.3 | TLS for Internal HTTP-based Services | ⚠️ Partial |
| 12.3.4 | Trusted Certificates for Internal Service TLS | ❌ Fail |
| 12.3.5 | Strong Authentication for Intra-Service Communications | ❌ Fail |
| **13. Configuration & Deployment** |
| 13.1.1 | Communication Needs Documentation | ❌ Fail |
| 13.1.2 | Connection Pool Limits and Fallback | ❌ Fail |
| 13.1.3 | Resource Management Strategies | ❌ Fail |
| 13.1.4 | Secrets Documentation and Rotation | ⚠️ Partial |
| 13.2.1 | Backend Communication Authentication | ⚠️ Partial |
| 13.2.2 | Least Privilege for Backend Communications | ❌ Fail |
| 13.2.3 | Default Credentials for Service Authentication | ✅ Pass |
| 13.2.4 | Allowlist for External Resources | ⚠️ Partial |
| 13.2.5 | Server Allowlist Configuration | ❌ Fail |
| 13.2.6 | Connection Configuration | ❌ Fail |
| 13.3.1 | Secrets Management Solution | ❌ Fail |
| 13.3.2 | Least Privilege Access to Secrets | ⚠️ Partial |
| 13.3.3 | Cryptographic Operations Using Isolated Security Module | ❌ Fail |
| 13.3.4 | Secret Expiration and Rotation | ❌ Fail |
| 13.4.1 | No Source Control Metadata Deployed | ❌ Fail |
| 13.4.2 | Debug Modes Disabled in Production | ❌ Fail |
| 13.4.3 | Web Servers Do Not Expose Directory Listings | ✅ Pass |
| 13.4.4 | HTTP TRACE Method Not Supported | ⚠️ Partial |
| 13.4.5 | Unintended Information Leakage — Documentation and Monitoring Endpoints | ⚠️ Partial |
| 13.4.6 | Unintended Information Leakage — Version Information | ❌ Fail |
| 13.4.7 | Unintended Information Leakage — File Extension Filtering | ⚠️ Partial |
| **14. Data Protection** |
| 14.1.1 | Sensitive Data Classification | ⚠️ Partial |
| 14.1.2 | Documented Protection Requirements | ❌ Fail |
| 14.2.1 | Sensitive Data Only in HTTP Body/Headers | ⚠️ Partial |
| 14.2.2 | Prevent Sensitive Data Caching | ❌ Fail |
| 14.2.3 | Sensitive Data Not Sent to Untrusted Parties | ✅ Pass |
| 14.2.4 | Protection Controls Implementation | ⚠️ Partial |
| 14.2.5 | Web Cache Deception Prevention | ❌ Fail |
| 14.2.6 | Minimum Sensitive Data Return | ❌ Fail |
| 14.2.7 | Data Retention Classification | ❌ Fail |
| 14.2.8 | File Metadata Stripping | ❌ Fail |
| 14.3.1 | Client Storage Clearing | ❌ Fail |
| 14.3.2 | Anti-Caching Headers for Sensitive Data | ❌ Fail |
| 14.3.3 | Browser Storage Does Not Contain Sensitive Data | ⚠️ Partial |
| **15. Supply Chain & Dependencies** |
| 15.1.1 | Risk-Based Remediation Timeframes | ❌ Fail |
| 15.1.2 | SBOM and Inventory Catalog | ❌ Fail |
| 15.1.3 | Documentation of Resource-Demanding Functionality | ❌ Fail |
| 15.1.4 | Documentation of Risky Components | ❌ Fail |
| 15.1.5 | Documentation of Dangerous Functionality | ❌ Fail |
| 15.2.1 | Components Within Remediation Timeframes | ❌ Fail |
| 15.2.2 | Defenses Against Loss of Availability | ⚠️ Partial |
| 15.2.3 | No Extraneous Functionality in Production | ❌ Fail |
| 15.2.4 | No Dependency Confusion Risk | ⚠️ Partial |
| 15.2.5 | Protections Around Dangerous Functionality | ⚠️ Partial |
| 15.3.1 | Return Only Required Data Fields | N/A |
| 15.3.2 | Backend Calls to External URLs Do Not Follow Redirects | ⚠️ Partial |
| 15.3.3 | Mass Assignment Protection | ⚠️ Partial |
| 15.3.4 | IP Address Handling Through Proxies | N/A |
| 15.3.5 | Type Safety and Strict Comparisons | ⚠️ Partial |
| 15.3.6 | Prototype Pollution Prevention | N/A |
| 15.3.7 | HTTP Parameter Pollution Defense | ⚠️ Partial |
| 15.4.1 | Safe Concurrency for Shared Objects | ❌ Fail |
| 15.4.2 | TOCTOU Race Condition Prevention | ⚠️ Partial |
| 15.4.3 | Consistent Lock Usage and Encapsulation | ❌ Fail |
| 15.4.4 | Thread Starvation Prevention | ⚠️ Partial |
| **16. Logging & Error Handling** |
| 16.1.1 | Security Logging Documentation | ❌ Fail |
| 16.2.1 | General Logging - Metadata Requirements | ❌ Fail |
| 16.2.2 | Time Synchronization and UTC Timestamps | ❌ Fail |
| 16.2.3 | Logs Only to Documented Destinations | ❌ Fail |
| 16.2.4 | Logs Readable and Correlatable by Log Processor | ⚠️ Partial |
| 16.2.5 | Sensitive Data Protection in Logs | ❌ Fail |
| 16.3.1 | Authentication Operations Logging | ❌ Fail |
| 16.3.2 | Authorization Failure Logging | ❌ Fail |
| 16.3.3 | Security Events and Bypass Attempts Logging | ❌ Fail |
| 16.3.4 | Unexpected Errors and Security Control Failures Logging | ❌ Fail |
| 16.4.1 | Log Injection Prevention | ❌ Fail |
| 16.4.2 | Log Protection from Unauthorized Access and Modification | ❌ Fail |
| 16.4.3 | Log Protection - Secure Transmission | ❌ Fail |
| 16.5.1 | Error Handling - Generic Messages | ⚠️ Partial |
| 16.5.2 | Error Handling - External Resource Failure | ❌ Fail |
| 16.5.3 | Error Handling - Fail Gracefully and Securely | ❌ Fail |
| 16.5.4 | Error Handling - Last Resort Error Handler | ❌ Fail |
| **4. HTTP Security** |
| 4.1.1 | Content-Type Header Verification | N/A |
| 4.1.2 | HTTP to HTTPS Redirect Behavior | ✅ Pass |
| 4.1.3 | Intermediary Header Override Protection | ⚠️ Partial |
| 4.1.4 | HTTP Method Restriction | ⚠️ Partial |
| 4.1.5 | Per-Message Digital Signatures | ❌ Fail |
| 4.2.1 | HTTP Request Smuggling Prevention | ⚠️ Partial |
| 4.2.2 | Content-Length Header Validation | N/A |
| 4.2.3 | HTTP/2 and HTTP/3 Connection-Specific Header Fields | ✅ Pass |
| 4.2.4 | CR/LF/CRLF Injection in HTTP/2 and HTTP/3 Headers | N/A |
| 4.2.5 | URI and Header Field Length Validation | N/A |
| 4.3.1 | GraphQL DoS Prevention | N/A |
| 4.3.2 | GraphQL Introspection Disabled in Production | N/A |
| 4.4.1 | WebSocket over TLS (WSS) | N/A |
| 4.4.2 | Origin Header Validation on WebSocket Handshake | N/A |
| 4.4.3 | Dedicated WebSocket Session Tokens | N/A |
| 4.4.4 | WebSocket Token Validation via Authenticated HTTPS | N/A |
| **5. File Handling** |
| 5.1.1 | File Handling Documentation | ❌ Fail |
| 5.2.1 | File Size Limits | ❌ Fail |
| 5.2.2 | File Extension and Content Validation | ❌ Fail |
| 5.2.3 | Compressed File Checks | ❌ Fail |
| 5.2.4 | File Size Quota and Maximum File Count Per User | ❌ Fail |
| 5.2.5 | Symlink Prevention in Compressed Files | ❌ Fail |
| 5.2.6 | Pixel Flood Attack Prevention | N/A |
| 5.3.1 | Uploaded Files Not Executed as Server-Side Code | ⚠️ Partial |
| 5.3.2 | Path Traversal Protection | ⚠️ Partial |
| 5.3.3 | Zip Slip Protection | ✅ Pass |
| 5.4.1 | Filename Validation in Downloads | ❌ Fail |
| 5.4.2 | Filename Encoding/Sanitization in Responses | ❌ Fail |
| 5.4.3 | Antivirus Scanning | ❌ Fail |
| **17. Real-Time Communications** |
| 17.1.1 | TURN Service IP Address Filtering | N/A |
| 17.1.2 | TURN Service Resource Exhaustion Protection | N/A |
| 17.2.1 | DTLS certificate key management and protection | N/A |
| 17.2.2 | DTLS cipher suites and DTLS-SRTP configuration | N/A |
| 17.2.3 | Secure Real-time Transport Protocol (SRTP) authentication | N/A |
| 17.2.4 | Media server SRTP malformed packet handling | N/A |
| 17.2.5 | Media Server SRTP Flood Resilience | N/A |
| 17.2.6 | DTLS ClientHello Race Condition Vulnerability | N/A |
| 17.2.7 | Recording Mechanism SRTP Flood Resilience | N/A |
| 17.2.8 | DTLS Certificate Verification Against SDP Fingerprint | N/A |
| 17.3.1 | Signaling Server Flood Resilience with Rate Limiting | N/A |
| 17.3.2 | Signaling Server Malformed Message Resilience | N/A |
| **9. Token-Based Session Management** |
| 9.1.1 | Token Signature Validation | ⚠️ Partial |
| 9.1.2 | Algorithm Allowlist for Token Verification | ❌ Fail |
| 9.1.3 | Key Material from Trusted Pre-configured Sources | ❌ Fail |
| 9.2.1 | Token Validity Time Span Verification | ⚠️ Partial |
| 9.2.2 | Token Type Verification | ❌ Fail |
| 9.2.3 | Token Audience Validation | ❌ Fail |
| 9.2.4 | Token Audience Restriction | ❌ Fail |

---

# 6. Cross-Reference Matrix

## Finding → ASVS Mapping

| Finding ID | ASVS Requirements |
|------------|-------------------|
| | 10.1.2, 10.2.1, 2.2.2, 3.5.1, 3.5.3, 13.3.1, 13.4.2, 2.4.1 |
| | 7.4.1 |
| | 8.2.2, 8.4.1, 8.2.3, 8.4.2 |
| | 1.1.2, 1.2.1, 1.3.1, 3.2.2, 1.3.7 |
| | 3.5.8 |
| | 2.4.1, 2.4.2, 16.3.3 |
| | 16.3.2 |
| FINDING-008 | 11.2.2 |
| FINDING-009 | 11.2.4 |
| FINDING-010 | 10.3.2 |
| FINDING-011 | 10.3.2, 8.2.1, 8.3.1, 8.4.2, 8.2.2, 2.3.2 |
| FINDING-012 | 10.4.6 |
| FINDING-013 | 10.5.1 |
| FINDING-014 | 10.5.4, 9.2.3 |
| FINDING-015 | 6.3.4 |
| FINDING-016 | 6.8.2 |
| FINDING-017 | 6.8.4 |
| FINDING-018 | 7.1.1 |
| FINDING-019 | 7.3.1 |
| FINDING-020 | 7.3.2 |
| FINDING-021 | 7.4.2 |
| FINDING-022 | 7.4.4 |
| FINDING-023 | 7.5.2 |
| FINDING-024 | 7.5.3 |
| FINDING-025 | 8.2.1, 8.3.1, 8.4.2, 6.3.4, 2.3.1 |
| FINDING-026 | 8.2.2, 8.3.1 |
| FINDING-027 | 8.4.1 |
| FINDING-028 | 8.4.2 |
| FINDING-029 | 1.2.1, 1.3.1, 1.2.2, 5.3.2, 5.4.2 |
| FINDING-030 | 1.3.3, 2.2.1, 2.3.2, 16.5.3 |
| FINDING-031 | 1.3.5 |
| FINDING-032 | 2.2.1 |
| FINDING-033 | 2.2.3 |
| FINDING-034 | 3.2.1, 5.4.1 |
| FINDING-035 | 3.2.2 |
| FINDING-036 | 3.2.2 |
| FINDING-037 | 3.3.1, 3.3.2 |
| FINDING-038 | 3.4.1 |
| FINDING-039 | 3.4.3, 3.4.7 |
| FINDING-040 | 3.4.4, 13.4.7 |
| FINDING-041 | 3.4.6 |
| FINDING-042 | 3.5.2 |
| FINDING-043 | 3.5.8 |
| FINDING-044 | 3.7.4, 3.7.5 |
| FINDING-045 | 3.7.5 |
| FINDING-046 | 2.3.3 |
| FINDING-047 | 2.3.3 |
| FINDING-048 | 2.3.4 |
| FINDING-049 | 12.1.1 |
| FINDING-050 | 12.1.2 |
| FINDING-051 | 12.2.1, 12.2.2, 12.3.1, 3.7.4 |
| FINDING-052 | 13.3.1 |
| FINDING-053 | 13.3.3 |
| FINDING-054 | 13.3.3 |
| FINDING-055 | 13.3.4 |
| FINDING-056 | 14.2.2, 14.3.2, 14.2.5, 14.3.3 |
| FINDING-057 | 15.1.1 |
| FINDING-058 | 15.1.2 |
| FINDING-059 | 15.1.3 |
| FINDING-060 | 15.2.1 |
| FINDING-061 | 16.1.1 |
| FINDING-062 | 16.2.1 |
| FINDING-063 | 16.2.1, 16.4.3 |
| FINDING-064 | 16.2.5 |
| FINDING-065 | 16.3.1 |
| FINDING-066 | 16.3.3, 16.3.4 |
| FINDING-067 | 16.3.3 |
| FINDING-068 | 16.4.3 |
| FINDING-069 | 16.5.2 |
| FINDING-070 | 16.5.3 |
| FINDING-071 | 16.5.4 |
| FINDING-072 | 5.2.1 |
| FINDING-073 | 5.2.2, 5.3.1, 1.3.3 |
| FINDING-074 | 9.2.4 |
| FINDING-075 | 11.1.1 |
| FINDING-076 | 11.1.2 |
| FINDING-077 | 11.1.3 |
| FINDING-078 | 11.1.4, 15.1.1 |
| FINDING-079 | 11.2.1, 11.2.4, 11.4.2, 11.4.4, 11.6.1, 15.2.1 |
| FINDING-080 | 11.2.3, 11.5.1 |
| FINDING-081 | 11.2.5 |
| FINDING-082 | 11.3.2 |
| FINDING-083 | 11.7.1 |
| FINDING-084 | 10.1.1 |
| FINDING-085 | 10.3.1 |
| FINDING-086 | 10.3.3 |
| FINDING-087 | 10.3.4 |
| FINDING-088 | 10.3.5, 10.4.14 |
| FINDING-089 | 10.4.10, 10.4.16 |
| FINDING-090 | 10.4.13, 10.4.15 |
| FINDING-091 | 10.4.5 |
| FINDING-092 | 10.4.9, 6.1.1, 7.4.5, 14.3.1 |
| FINDING-093 | 10.5.3 |
| FINDING-094 | 6.1.1, 6.3.1 |
| FINDING-095 | 6.1.3 |
| FINDING-096 | 6.3.5 |
| FINDING-097 | 6.3.7 |
| FINDING-098 | 6.5.6 |
| FINDING-099 | 6.8.1 |
| FINDING-100 | 6.8.4 |
| FINDING-101 | 7.1.2 |
| FINDING-102 | 7.1.3 |
| FINDING-103 | 7.2.4 |
| FINDING-104 | 7.4.3 |
| FINDING-105 | 7.5.1 |
| FINDING-106 | 7.5.3 |
| FINDING-107 | 7.6.1 |
| FINDING-108 | 8.2.3 |
| FINDING-109 | 8.2.4 |
| FINDING-110 | 8.3.1, 2.3.1, 16.5.3 |
| FINDING-111 | 8.3.2 |
| FINDING-112 | 8.4.2 |
| FINDING-113 | 8.4.2 |
| FINDING-114 | 8.1.1 |
| FINDING-115 | 8.1.2 |
| FINDING-116 | 8.1.3 |
| FINDING-117 | 8.1.4 |
| FINDING-118 | 1.1.2, 1.2.1, 16.4.1 |
| FINDING-119 | 1.2.1 |
| FINDING-120 | 1.1.1, 5.3.2 |
| FINDING-121 | 1.3.11 |
| FINDING-122 | 1.3.3, 2.2.1 |
| FINDING-123 | 1.2.3 |
| FINDING-124 | 2.1.1 |
| FINDING-125 | 2.1.2 |
| FINDING-126 | 2.1.2 |
| FINDING-127 | 2.1.3 |
| FINDING-128 | 2.2.1 |
| FINDING-129 | 2.2.2 |
| FINDING-130 | 2.2.3 |
| FINDING-131 | 2.2.3 |
| FINDING-132 | 3.1.1 |
| FINDING-133 | 3.2.3 |
| FINDING-134 | 3.3.3 |
| FINDING-135 | 3.3.4 |
| FINDING-136 | 3.4.2 |
| FINDING-137 | 3.4.5, 3.7.5 |
| FINDING-138 | 3.4.8 |
| FINDING-139 | 3.5.2 |
| FINDING-140 | 3.5.3 |
| FINDING-141 | 3.6.1, 3.4.3 |
| FINDING-142 | 3.7.2 |
| FINDING-143 | 3.7.3 |
| FINDING-144 | 3.7.5 |
| FINDING-145 | 2.3.1 |
| FINDING-146 | 2.3.2 |
| FINDING-147 | 2.3.3 |
| FINDING-148 | 2.3.4 |
| FINDING-149 | 2.3.5 |
| FINDING-150 | 2.4.2 |
| FINDING-151 | 12.1.1 |
| FINDING-152 | 12.1.4 |
| FINDING-153 | 12.2.2 |
| FINDING-154 | 12.2.1 |
| FINDING-155 | 12.3.2 |
| FINDING-156 | 12.3.4 |
| FINDING-157 | 13.1.1 |
| FINDING-158 | 13.1.2 |
| FINDING-159 | 13.1.3 |
| FINDING-160 | 13.1.4 |
| FINDING-161 | 13.2.2 |
| FINDING-162 | 13.2.4 |
| FINDING-163 | 13.2.6 |
| FINDING-164 | 13.3.2 |
| FINDING-165 | 13.3.4 |
| FINDING-166 | 13.4.1 |
| FINDING-167 | 13.4.2, 16.2.3, 16.5.1, 14.2.4 |
| FINDING-168 | 13.4.6 |
| FINDING-169 | 13.4.7 |
| FINDING-170 | 14.1.1 |
| FINDING-171 | 14.1.2 |
| FINDING-172 | 14.2.4 |
| FINDING-173 | 14.2.5 |
| FINDING-174 | 14.2.6 |
| FINDING-175 | 14.2.6 |
| FINDING-176 | 14.3.1 |
| FINDING-177 | 15.1.2 |
| FINDING-178 | 15.1.4 |
| FINDING-179 | 15.1.5 |
| FINDING-180 | 15.2.3 |
| FINDING-181 | 15.2.4 |
| FINDING-182 | 15.3.3 |
| FINDING-183 | 15.4.1, 15.4.3 |
| FINDING-184 | 15.4.2 |
| FINDING-185 | 16.1.1 |
| FINDING-186 | 16.2.1 |
| FINDING-187 | 16.2.1 |
| FINDING-188 | 16.2.2 |
| FINDING-189 | 16.2.4 |
| FINDING-190 | 16.2.5 |
| FINDING-191 | 16.2.5 |
| FINDING-192 | 16.3.1 |
| FINDING-193 | 16.3.3 |
| FINDING-194 | 16.3.4 |
| FINDING-195 | 16.3.4 |
| FINDING-196 | 16.4.2 |
| FINDING-197 | 16.4.2 |
| FINDING-198 | 16.5.1 |
| FINDING-199 | 16.5.2 |
| FINDING-200 | 16.5.3 |
| FINDING-201 | 16.5.4 |
| FINDING-202 | 4.1.3 |
| FINDING-203 | 4.2.1 |
| FINDING-204 | 5.1.1 |
| FINDING-205 | 5.2.3 |
| FINDING-206 | 5.2.4 |
| FINDING-207 | 5.2.5 |
| FINDING-208 | 5.4.2 |
| FINDING-209 | 5.4.3 |
| FINDING-210 | 9.1.1 |
| FINDING-211 | 9.1.2 |
| FINDING-212 | 9.1.3 |
| FINDING-213 | 9.2.1 |
| FINDING-214 | 9.2.2 |
| FINDING-215 | 9.2.4 |

## ASVS → Finding Mapping

| ASVS ID | Related Findings |
|---------|------------------|
| 1.1.1 | FINDING-120 |
| 1.1.2 | FINDING-118 |
| 1.2.1 | FINDING-029, FINDING-118, FINDING-119 |
| 1.2.2 | FINDING-029 |
| 1.2.3 | FINDING-123 |
| 1.2.4 | ✅ Pass |
| 1.2.5 | ✅ Pass |
| 1.2.6 | FINDING-286 |
| 1.2.7 | ✅ Pass |
| 1.2.8 | ✅ Pass |
| 1.2.9 | ✅ Pass |
| 1.2.10 | ✅ Pass |
| 1.3.1 | FINDING-029 |
| 1.3.2 | ✅ Pass |
| 1.3.3 | FINDING-030, FINDING-073, FINDING-122 |
| 1.3.4 | FINDING-241 |
| 1.3.5 | FINDING-031 |
| 1.3.6 | ✅ Pass |
| 1.3.7 | ✅ Pass |
| 1.3.10 | FINDING-240, ✅ Pass |
| 1.3.11 | FINDING-121 |
| 1.3.12 | ✅ Pass |
| 1.4.1 | ✅ Pass |
| 1.4.2 | ✅ Pass |
| 1.4.3 | ✅ Pass |
| 1.5.1 | ✅ Pass |
| 1.5.2 | FINDING-242 |
| 1.5.3 | ✅ Pass |
| 2.1.1 | FINDING-124, FINDING-243 |
| 2.1.2 | FINDING-125, FINDING-126 |
| 2.1.3 | FINDING-127 |
| 2.2.1 | FINDING-030, FINDING-032, FINDING-122, FINDING-128 |
| 2.2.2 | FINDING-129 |
| 2.2.3 | FINDING-033, FINDING-130, FINDING-131 |
| 2.3.1 | FINDING-025, FINDING-110, FINDING-145 |
| 2.3.2 | FINDING-011, FINDING-030, FINDING-146 |
| 2.3.3 | FINDING-046, FINDING-047, FINDING-147 |
| 2.3.4 | FINDING-048, FINDING-148 |
| 2.3.5 | FINDING-149, FINDING-251 |
| 2.4.1 | |
| 2.4.2 | FINDING-150, FINDING-252 |
| 3.1.1 | FINDING-132, FINDING-244 |
| 3.2.1 | FINDING-034 |
| 3.2.2 | FINDING-035, FINDING-036 |
| 3.2.3 | FINDING-133, FINDING-245 |
| 3.3.1 | FINDING-037 |
| 3.3.2 | FINDING-037 |
| 3.3.3 | FINDING-134 |
| 3.3.4 | FINDING-135, FINDING-246 |
| 3.3.5 | FINDING-247 |
| 3.4.1 | FINDING-038 |
| 3.4.2 | FINDING-136 |
| 3.4.3 | FINDING-039, FINDING-141 |
| 3.4.4 | FINDING-040 |
| 3.4.5 | FINDING-137 |
| 3.4.6 | FINDING-041 |
| 3.4.7 | FINDING-039 |
| 3.4.8 | FINDING-138 |
| 3.5.1 | |
| 3.5.2 | FINDING-042, FINDING-139 |
| 3.5.3 | FINDING-140 |
| 3.5.4 | FINDING-248 |
| 3.5.5 | ✅ Pass |
| 3.5.6 | ✅ Pass |
| 3.5.7 | FINDING-249, ✅ Pass |
| 3.5.8 | FINDING-043 |
| 3.6.1 | FINDING-141, FINDING-250 |
| 3.7.1 | ✅ Pass |
| 3.7.2 | FINDING-142 |
| 3.7.3 | FINDING-143 |
| 3.7.4 | FINDING-044, FINDING-051 |
| 3.7.5 | FINDING-044, FINDING-045, FINDING-137, FINDING-144, FINDING-250 |
| 4.1.2 | ✅ Pass |
| 4.1.3 | FINDING-202 |
| 4.1.4 | FINDING-284 |
| 4.1.5 | FINDING-285 |
| 4.2.1 | FINDING-203 |
| 4.2.3 | ✅ Pass |
| 5.1.1 | FINDING-204 |
| 5.2.1 | FINDING-072 |
| 5.2.2 | FINDING-073 |
| 5.2.3 | FINDING-205 |
| 5.2.4 | FINDING-206 |
| 5.2.5 | FINDING-207 |
| 5.3.1 | FINDING-073 |
| 5.3.2 | FINDING-029, FINDING-120 |
| 5.3.3 | ✅ Pass |
| 5.4.1 | FINDING-034 |
| 5.4.2 | FINDING-029, FINDING-208 |
| 5.4.3 | FINDING-209 |
| 6.1.1 | FINDING-092, FINDING-094 |
| 6.1.2 | FINDING-228 |
| 6.1.3 | FINDING-095 |
| 6.2.1 | ✅ Pass |
| 6.2.2 | ✅ Pass |
| 6.2.5 | ✅ Pass |
| 6.2.7 | ✅ Pass |
| 6.2.8 | ✅ Pass |
| 6.2.10 | ✅ Pass |
| 6.3.1 | FINDING-094 |
| 6.3.2 | FINDING-229 |
| 6.3.3 | FINDING-226, FINDING-230 |
| 6.3.4 | FINDING-015, FINDING-025 |
| 6.3.5 | FINDING-096 |
| 6.3.6 | ✅ Pass |
| 6.3.7 | FINDING-097 |
| 6.3.8 | FINDING-231, ✅ Pass |
| 6.4.1 | ✅ Pass |
| 6.4.2 | ✅ Pass |
| 6.4.5 | FINDING-232 |
| 6.5.1 | FINDING-222 |
| 6.5.3 | FINDING-233, ✅ Pass |
| 6.5.6 | FINDING-098 |
| 6.5.7 | ✅ Pass |
| 6.6.2 | ✅ Pass |
| 6.8.1 | FINDING-099 |
| 6.8.2 | FINDING-016 |
| 6.8.3 | FINDING-225 |
| 6.8.4 | FINDING-017, FINDING-100 |
| 7.1.1 | FINDING-018 |
| 7.1.2 | FINDING-101 |
| 7.1.3 | FINDING-102, FINDING-234 |
| 7.2.1 | ✅ Pass |
| 7.2.2 | ✅ Pass |
| 7.2.3 | FINDING-235 |
| 7.2.4 | FINDING-103, FINDING-236 |
| 7.3.1 | FINDING-019 |
| 7.3.2 | FINDING-020 |
| 7.4.1 | |
| 7.4.2 | FINDING-021 |
| 7.4.3 | FINDING-104 |
| 7.4.4 | FINDING-022 |
| 7.4.5 | FINDING-092 |
| 7.5.1 | FINDING-105 |
| 7.5.2 | FINDING-023 |
| 7.5.3 | FINDING-024, FINDING-106 |
| 7.6.1 | FINDING-107 |
| 7.6.2 | FINDING-237 |
| 8.1.1 | FINDING-114 |
| 8.1.2 | FINDING-115 |
| 8.1.3 | FINDING-116 |
| 8.1.4 | FINDING-117 |
| 8.2.1 | FINDING-011, FINDING-025 |
| 8.2.2 | FINDING-011, FINDING-026 |
| 8.2.3 | FINDING-108 |
| 8.2.4 | FINDING-109 |
| 8.3.1 | FINDING-011, FINDING-025, FINDING-026, FINDING-110 |
| 8.3.2 | FINDING-111, FINDING-238 |
| 8.3.3 | FINDING-239, ✅ Pass |
| 8.4.1 | FINDING-027 |
| 8.4.2 | FINDING-011, FINDING-025, FINDING-028, FINDING-112, FINDING-113 |
| 9.1.1 | FINDING-210 |
| 9.1.2 | FINDING-211 |
| 9.1.3 | FINDING-212 |
| 9.2.1 | FINDING-213 |
| 9.2.2 | FINDING-214 |
| 9.2.3 | FINDING-014 |
| 9.2.4 | FINDING-074, FINDING-215, FINDING-223 |
| 10.1.1 | FINDING-084 |
| 10.1.2 | |
| 10.2.1 | |
| 10.3.1 | FINDING-085 |
| 10.3.2 | FINDING-010, FINDING-011 |
| 10.3.3 | FINDING-086 |
| 10.3.4 | FINDING-087 |
| 10.3.5 | FINDING-088 |
| 10.4.1 | FINDING-222 |
| 10.4.2 | FINDING-225 |
| 10.4.4 | ✅ Pass |
| 10.4.5 | FINDING-091 |
| 10.4.6 | FINDING-012 |
| 10.4.8 | FINDING-226 |
| 10.4.9 | FINDING-092 |
| 10.4.10 | FINDING-089 |
| 10.4.11 | FINDING-223 |
| 10.4.12 | FINDING-224 |
| 10.4.13 | FINDING-090 |
| 10.4.14 | FINDING-088 |
| 10.4.15 | FINDING-090 |
| 10.4.16 | FINDING-089 |
| 10.5.1 | FINDING-013 |
| 10.5.2 | FINDING-227 |
| 10.5.3 | FINDING-093 |
| 10.5.4 | FINDING-014 |
| 10.5.5 | FINDING-226 |
| 11.1.1 | FINDING-075, FINDING-216 |
| 11.1.2 | FINDING-076 |
| 11.1.3 | FINDING-077 |
| 11.1.4 | FINDING-078 |
| 11.2.1 | FINDING-079 |
| 11.2.2 | FINDING-008, FINDING-217 |
| 11.2.3 | FINDING-080 |
| 11.2.4 | FINDING-009, FINDING-079 |
| 11.2.5 | FINDING-081 |
| 11.3.1 | ✅ Pass |
| 11.3.2 | FINDING-082 |
| 11.3.3 | ✅ Pass |
| 11.3.4 | FINDING-217, ✅ Pass |
| 11.3.5 | ✅ Pass |
| 11.4.1 | FINDING-218 |
| 11.4.2 | FINDING-079 |
| 11.4.3 | ✅ Pass |
| 11.4.4 | FINDING-079, FINDING-219 |
| 11.5.1 | FINDING-080 |
| 11.5.2 | ✅ Pass |
| 11.6.1 | FINDING-079 |
| 11.7.1 | FINDING-083 |
| 11.7.2 | FINDING-220, FINDING-221 |
| 12.1.1 | FINDING-049, FINDING-151 |
| 12.1.2 | FINDING-050 |
| 12.1.4 | FINDING-152 |
| 12.1.5 | FINDING-253 |
| 12.2.1 | FINDING-051, FINDING-154 |
| 12.2.2 | FINDING-051, FINDING-153 |
| 12.3.1 | FINDING-051, FINDING-254 |
| 12.3.2 | FINDING-155 |
| 12.3.3 | FINDING-255 |
| 12.3.4 | FINDING-156 |
| 12.3.5 | FINDING-255 |
| 13.1.1 | FINDING-157 |
| 13.1.2 | FINDING-158 |
| 13.1.3 | FINDING-159 |
| 13.1.4 | FINDING-160 |
| 13.2.1 | FINDING-256, FINDING-257 |
| 13.2.2 | FINDING-161, FINDING-258 |
| 13.2.3 | ✅ Pass |
| 13.2.4 | FINDING-162 |
| 13.2.5 | FINDING-259 |
| 13.2.6 | FINDING-163 |
| 13.3.1 | FINDING-052 |
| 13.3.2 | FINDING-164 |
| 13.3.3 | FINDING-053, FINDING-054 |
| 13.3.4 | FINDING-055, FINDING-165 |
| 13.4.1 | FINDING-166 |
| 13.4.2 | FINDING-167, FINDING-261 |
| 13.4.3 | FINDING-262, ✅ Pass |
| 13.4.4 | FINDING-263 |
| 13.4.5 | FINDING-264 |
| 13.4.6 | FINDING-168, FINDING-265 |
| 13.4.7 | FINDING-040, FINDING-169 |
| 14.1.1 | FINDING-170 |
| 14.1.2 | FINDING-171 |
| 14.2.1 | FINDING-266 |
| 14.2.2 | FINDING-056 |
| 14.2.3 | ✅ Pass |
| 14.2.4 | FINDING-167, FINDING-172, FINDING-267, FINDING-268 |
| 14.2.5 | FINDING-056, FINDING-173 |
| 14.2.6 | FINDING-174, FINDING-175, FINDING-269 |
| 14.2.7 | FINDING-268, FINDING-270 |
| 14.2.8 | FINDING-271 |
| 14.3.1 | FINDING-092, FINDING-176 |
| 14.3.2 | FINDING-056 |
| 14.3.3 | FINDING-056, FINDING-272 |
| 15.1.1 | FINDING-057, FINDING-078 |
| 15.1.2 | FINDING-058, FINDING-177 |
| 15.1.3 | FINDING-059 |
| 15.1.4 | FINDING-178 |
| 15.1.5 | FINDING-179 |
| 15.2.1 | FINDING-060, FINDING-079 |
| 15.2.2 | FINDING-273 |
| 15.2.3 | FINDING-180 |
| 15.2.4 | FINDING-181, FINDING-274 |
| 15.2.5 | FINDING-275 |
| 15.3.2 | FINDING-276 |
| 15.3.3 | FINDING-182 |
| 15.3.5 | FINDING-277 |
| 15.3.7 | FINDING-278 |
| 15.4.1 | FINDING-183 |
| 15.4.2 | FINDING-184 |
| 15.4.3 | FINDING-183 |
| 15.4.4 | FINDING-279 |
| 16.1.1 | FINDING-061, FINDING-185 |
| 16.2.1 | FINDING-062, FINDING-063, FINDING-186, FINDING-187 |
| 16.2.2 | FINDING-188, FINDING-280 |
| 16.2.3 | FINDING-167, FINDING-281 |
| 16.2.4 | FINDING-189, FINDING-282 |
| 16.2.5 | FINDING-064, FINDING-190, FINDING-191 |
| 16.3.1 | FINDING-065, FINDING-192 |
| 16.3.2 | |
| 16.3.3 | FINDING-066, FINDING-067, FINDING-193 |
| 16.3.4 | FINDING-066, FINDING-194, FINDING-195, FINDING-283 |
| 16.4.1 | FINDING-118 |
| 16.4.2 | FINDING-196, FINDING-197 |
| 16.4.3 | FINDING-063, FINDING-068 |
| 16.5.1 | FINDING-167, FINDING-198 |
| 16.5.2 | FINDING-069, FINDING-199 |
| 16.5.3 | FINDING-030, FINDING-070, FINDING-110, FINDING-200 |
| 16.5.4 | FINDING-071, FINDING-201 |

## 7. Level Coverage Analysis


**Audit scope:** up to L3

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 60 |
| L2 | 183 | 171 |
| L3 | 92 | 97 |

**Total consolidated findings: 286**

*End of Consolidated Security Audit Report*